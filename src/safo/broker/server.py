# SPDX-License-Identifier: Apache-2.0
"""The broker's socket server (docs/gemini-broker.md, "The socket protocol"; issue #259).

One request, one reply, then close. The server takes the listening descriptor systemd passes (`adopt_listener`),
accepts connections, checks the peer's uid with `SO_PEERCRED` against a root-owned list, reads one frame under a
whole-frame deadline, parses it with `safo.broker.protocol`, and dispatches to the phase 2 pipeline. It never
authorizes by who is calling (the hardware-key signature does that), and it never holds the ledger lock or the paid-call
slot while it writes a reply.

Fail closed: every error before the pipeline is a fixed reply code with no state change and no vendor call. Every
failure after it is `internal`, and the ledger already says what happened (settled, or ambiguous with the reservation
counted). The server logs numbers and enumerated words only: no prompt, no client string, no exception message.

Nothing here reads a key, a clock, an environment variable or a file on its own: the pipeline, the monotonic clock,
the switch and key checks, and the peer-credential reader are all parameters. Root's `clear` is not on the socket.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import errno
import itertools
import logging
import os
import re
import select
import socket
import struct
import threading
import time
from collections import deque
from collections.abc import Callable, MutableMapping
from pathlib import Path
from typing import Any

import yaml

from safo import __version__, geminisign
from safo.broker import protocol
from safo.broker.approval import verify_dryrun
from safo.broker.errors import BrokerError, Refused
from safo.broker.money import MoneyError, format_usd, parse_usd
from safo.broker.pipeline import CallResult, Pipeline, Receipt
from safo.broker.policy import BLOCK_MICRO, BrokerRequest
from safo.broker.protocol import ProtocolError, Request
from safo.errors import ConfigError
from safo.gemini import RefusedError

SD_LISTEN_FDS_START = 3
LOG_NAME = "safo.broker"
_PLAIN_UID = 2**31 - 1
_DIGITS = re.compile(r"(?:0|[1-9][0-9]{0,9})")
_TOKEN = re.compile(r"[a-z0-9_]{1,32}")
_CLASS = re.compile(r"[A-Za-z0-9_]{1,64}")
_LOG_FIELDS = frozenset(
    {"rid", "op", "code", "uid", "pid", "bytes_in", "bytes_out", "model", "kind", "count", "reserved", "actual", "ms"}
    | {"nonce8", "exc", "tag", "open", "abandoned", "attachments"}
)
_NONCE8 = re.compile(r"[0-9a-f]{8}")
_DRAIN_BYTES = 65_536


class ListenError(BrokerError):
    """The descriptor systemd was supposed to pass is not the one expected. The message is a fixed sentence."""

    exit_code = 4


class DeadlineExceeded(Exception):
    """A read or a write missed its deadline: the connection is dropped and the rest of the reply with it."""


# -- the configuration ---------------------------------------------------------------------------------------------


def _count(value: object, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ConfigError(f"broker server: {name} is a whole number from {low} to {high}")
    return value


def _seconds(value: object, name: str, low: float, high: float) -> float:
    if type(value) not in (int, float) or not low <= float(value) <= high:  # type: ignore[arg-type]  # checked just above
        raise ConfigError(f"broker server: {name} is a number of seconds from {low} to {high}")
    return float(value)  # type: ignore[arg-type]  # a plain int or float, checked above


@dataclasses.dataclass(frozen=True)
class ServerConfig:
    """Numbers from the design (connections, deadlines, limits). `allowed_uids` is the only one without a default."""

    allowed_uids: frozenset[int]
    max_connections: int = 8
    max_per_uid: int = 2
    read_deadline: float = 5.0  # the whole request frame
    write_json_deadline: float = 5.0  # the whole JSON reply frame
    write_progress: float = 10.0  # each write of an attachment must make progress within this
    write_frame_total: float = 60.0  # the whole of one attachment frame
    max_concurrent_calls: int = 1  # paid vendor calls in flight; a second `call` is `busy`, not queued
    begin_per_minute: int = 6
    call_per_minute: int = 10  # call attempts, including ones that fail verification
    other_per_minute: int = 30  # status, check and dryrun, per peer
    max_calls_per_minute: int = 5  # vendor calls actually started, from the ledger
    max_calls_per_day: int = 20
    slot_wait: float = 0.0  # how long a second `call` waits for the slot before it is told `busy` (0: at once)
    grace_seconds: float = 150.0  # how long a stop waits for calls in flight before it records them as interrupted

    def __post_init__(self) -> None:
        uids = self.allowed_uids
        if type(uids) is not frozenset or not uids or any(type(u) is not int or not 0 <= u <= _PLAIN_UID for u in uids):
            raise ConfigError("broker server: allowed_uids is a non-empty list of user ids")
        _count(self.max_connections, "max_connections", 1, 64)
        _count(self.max_per_uid, "max_per_uid", 1, 64)
        _count(self.max_concurrent_calls, "max_concurrent_calls", 1, 2)  # 512 MiB unit: two image calls at most
        for name in ("begin_per_minute", "call_per_minute", "other_per_minute"):
            _count(getattr(self, name), name, 1, 10_000)
        _count(self.max_calls_per_minute, "max_calls_per_minute", 1, 1_000)
        _count(self.max_calls_per_day, "max_calls_per_day", 1, 100_000)
        for name in ("read_deadline", "write_json_deadline", "write_progress", "write_frame_total"):
            _seconds(getattr(self, name), name, 0.001, 3_600.0)
        _seconds(self.grace_seconds, "grace_seconds", 0.0, 3_600.0)
        _seconds(self.slot_wait, "slot_wait", 0.0, 60.0)

    @classmethod
    def from_mapping(cls, data: object) -> ServerConfig:
        """The `server:` section of broker.yaml. An unknown key is an error, not ignored."""
        if type(data) is not dict:
            raise ConfigError("broker server: the section is a mapping")
        names = {f.name for f in dataclasses.fields(cls)}
        if set(data) - names or "allowed_uids" not in data:
            raise ConfigError("broker server: the section has an unknown key or lacks allowed_uids")
        uids = data["allowed_uids"]
        if type(uids) is not list:
            raise ConfigError("broker server: allowed_uids is a list of user ids")
        values = {k: v for k, v in data.items() if k != "allowed_uids"}
        return cls(frozenset(uids), **values)


class _StrictLoader(yaml.SafeLoader):
    """Safe YAML that refuses a repeated key (PyYAML keeps the last), aliases and merge keys."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if key in seen or key == "<<":
                raise ConfigError("broker server: a repeated key or a merge key in the config")
            seen.add(key)
        return super().construct_mapping(node, deep)


def read_config(path: Path, trust_uid: int = 0) -> dict[str, Any]:
    """The root-owned broker.yaml as a mapping (the same ownership walk as the trust files; safe YAML with no alias,
    merge key or repeated key). The caller reads the sections it owns."""
    try:
        raw = geminisign.read_trust_file(path, trust_uid, "broker config")
        text = raw.decode("utf-8")
        for event in yaml.parse(text):
            if isinstance(event, yaml.events.AliasEvent):
                raise ConfigError("broker server: aliases are not allowed in the config")
        data = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - a SafeLoader subclass that only adds refusals
    except (RefusedError, OSError, UnicodeError, yaml.YAMLError):
        raise ConfigError("broker server: the config cannot be read, or is not safe YAML") from None
    if type(data) is not dict:
        raise ConfigError("broker server: the config is a mapping")
    return data


def load_config(path: Path, trust_uid: int = 0) -> ServerConfig:
    """The `server:` section of the root-owned config."""
    data = read_config(path, trust_uid)
    if "server" not in data:
        raise ConfigError("broker server: the config has no server section")
    return ServerConfig.from_mapping(data["server"])


# -- peers and the inherited descriptor ----------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class PeerCred:
    pid: int
    uid: int
    gid: int


_CRED = struct.Struct("3i")  # struct ucred: pid, uid, gid


def peer_credentials(sock: socket.socket) -> PeerCred:
    """The kernel's record of the peer at connect time. The pid is for the log only and is never trusted."""
    if sock.family != socket.AF_UNIX:
        raise OSError(errno.EAFNOSUPPORT, "peer credentials need a unix socket")
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _CRED.size)
    pid, uid, gid = _CRED.unpack(raw)
    return PeerCred(pid, uid, gid)


def adopt_listener(
    environ: MutableMapping[str, str], pid: int, *, first_fd: int = SD_LISTEN_FDS_START
) -> socket.socket:
    """The one listening unix stream socket systemd passed (`LISTEN_PID` must be this process, `LISTEN_FDS` exactly
    `1`, and the descriptor a unix stream socket that is listening). The three variables are removed from `environ`
    whatever the outcome, so no child process sees them; the descriptor is made non-inheritable. Anything else
    raises `ListenError`: the broker never creates its own socket."""
    listen_pid = environ.pop("LISTEN_PID", None)
    listen_fds = environ.pop("LISTEN_FDS", None)
    environ.pop("LISTEN_FDNAMES", None)
    if listen_pid is None or _DIGITS.fullmatch(listen_pid) is None or int(listen_pid) != pid:
        raise ListenError("the listening descriptor was not passed to this process")
    if listen_fds != "1":
        raise ListenError("exactly one listening descriptor is expected")
    try:
        sock = socket.socket(fileno=first_fd)
    except OSError:
        raise ListenError("the inherited descriptor is not a socket") from None
    try:
        listening = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
        if sock.family != socket.AF_UNIX or sock.type != socket.SOCK_STREAM or not listening:
            raise ListenError("the inherited descriptor is not a listening unix stream socket")
        os.set_inheritable(sock.fileno(), False)
        sock.setblocking(False)
    except BaseException:
        sock.detach()  # not ours to close: the process exits
        raise
    return sock


# -- limits and the log --------------------------------------------------------------------------------------------


class RateLimiter:
    """At most `limit` events per (peer, bucket) in any `window` seconds, by an injected monotonic clock."""

    def __init__(self, mono: Callable[[], float], window: float = 60.0) -> None:
        self._mono = mono
        self._window = window
        self._hits: dict[tuple[int, str], deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, uid: int, bucket: str, limit: int) -> bool:
        now = self._mono()
        with self._lock:
            hits = self._hits.setdefault((uid, bucket), deque())
            while hits and now - hits[0] >= self._window:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True


class AuditLog:
    """One line per event, from an allowlist of field names; a value is a number or a short enumerated word. Anything
    else becomes `?`. A client's text cannot reach the log because no field takes free text."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger(LOG_NAME)

    @staticmethod
    def _value(name: str, value: object) -> str:
        if type(value) is bool:
            return "true" if value else "false"
        if type(value) is int:
            return str(value)
        if type(value) is str:
            pattern = _NONCE8 if name == "nonce8" else _CLASS if name == "exc" else _TOKEN
            if pattern.fullmatch(value):
                return value
        return "?"

    def event(self, event: str, **fields: object) -> None:
        parts = [self._value("tag", event)] + [
            f"{name}={self._value(name, value)}" for name, value in fields.items() if name in _LOG_FIELDS
        ]
        self._logger.info(" ".join(parts))


# -- what a handler produces ---------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Outcome:
    body: bytes
    code: str  # `ok` or a reply code
    attachments: tuple[bytes, ...] = ()
    model: str = ""
    nonce8: str = ""
    reserved: int | None = None
    actual: int | None = None


def _fail(code: str, extra: dict[str, Any] | None = None) -> Outcome:
    return Outcome(protocol.error_body(code, extra), code)


def receipt_fields(receipt: Receipt) -> dict[str, Any]:
    """The receipt as the client sees it: money as USD text, no prompt, no quote, no key."""
    return {
        "call_id": receipt.call_id,
        "nonce": receipt.nonce,
        "epoch": receipt.epoch,
        "model": receipt.model,
        "kind": receipt.kind,
        "count": receipt.count,
        "image_size": receipt.image_size,
        "prompt_sha256": receipt.prompt_sha256,
        "tokens_in": receipt.tokens_in,
        "tokens_out": receipt.tokens_out,
        "reserved_usd": format_usd(receipt.reserved_micro),
        "actual_usd": format_usd(receipt.actual_micro),
        "released_usd": format_usd(receipt.released_micro),
        "breach": receipt.breach,
        "cap_breach": receipt.cap_breach,
        "estimated": receipt.estimated,
        "extra_images": receipt.extra_images,
        "images": [{"index": i, "mime": m, "bytes": n, "sha256": h} for i, m, n, h in receipt.images],
        "month_spent_after": format_usd(receipt.month_spent_micro),
        "ledger_head_after": receipt.ledger_head,
        "broker_version": __version__,
        "ts": receipt.ts,
    }


class Server:
    def __init__(
        self,
        pipeline: Pipeline,
        config: ServerConfig,
        *,
        switch: Callable[[], bool],
        key_loaded: Callable[[], bool],
        peer_cred: Callable[[socket.socket], PeerCred] = peer_credentials,
        mono: Callable[[], float] = time.monotonic,
        logger: logging.Logger | None = None,
    ) -> None:
        self.pipeline = pipeline
        self.cfg = config
        self.switch = switch
        self.key_loaded = key_loaded
        self.peer_cred = peer_cred
        self.mono = mono
        self.log = AuditLog(logger)
        pipeline.spend_gate = self._spend_gate
        self._limits = RateLimiter(mono)
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._open = 0
        self._per_uid: dict[int, int] = {}
        self._threads: set[threading.Thread] = set()
        self._slots = threading.BoundedSemaphore(config.max_concurrent_calls)
        self._in_flight = 0
        self._stopping = False
        self._wake_r, self._wake_w = socket.socketpair()
        self._wake_r.setblocking(False)
        self._wake_w.setblocking(False)
        self.peak_open = 0

    def _spend_gate(self) -> None:
        """Run by the pipeline under the ledger lock, just before the spend: root may have switched paid use off while
        the approval was being verified (a slow `ssh-keygen`)."""
        if self._stopping:
            raise Refused("busy", "the broker is stopping")
        if not self.switch():
            raise Refused("disabled", "paid use is disabled")

    # -- observers (for the tests and the log)

    @property
    def calls_in_flight(self) -> int:
        with self._lock:
            return self._in_flight

    @property
    def open_connections(self) -> int:
        with self._lock:
            return self._open

    # -- the accept loop

    def stop(self) -> None:
        """Stop accepting. Safe from a signal handler: it sets a flag and writes one byte to a pipe."""
        self._stopping = True
        with contextlib.suppress(OSError):
            self._wake_w.send(b"x")

    def serve(self, listener: socket.socket) -> int:
        """Accept until `stop`, then wait for the calls in flight (up to `grace_seconds`) and return how many were
        abandoned. The listener is not closed: under socket activation it belongs to systemd."""
        listener.setblocking(False)
        while not self._stopping:
            ready, _, _ = select.select([listener, self._wake_r], [], [])
            if self._stopping or listener not in ready:
                continue
            try:
                conn, _ = listener.accept()
            except (BlockingIOError, InterruptedError):
                continue
            except OSError as err:
                if err.errno in (errno.EBADF, errno.EINVAL, errno.ENOTSOCK):
                    break
                self.log.event("accept_failed", tag="accept", code="internal")
                time.sleep(0.05)  # a descriptor or memory shortage: do not spin
                continue
            self.admit(conn)
        return self._shutdown()

    def admit(self, conn: socket.socket) -> None:
        """Peer check and the connection bounds; then a thread for the connection. Never raises."""
        try:
            cred = self.peer_cred(conn)
        except Exception as exc:
            self.log.event("peer_unknown", exc=type(exc).__name__)
            self._close(conn)
            return
        if cred.uid not in self.cfg.allowed_uids:
            self.log.event("refused", code="unauthorized_peer", uid=cred.uid, pid=cred.pid)
            with contextlib.suppress(OSError, ProtocolError):
                conn.setblocking(False)
                conn.send(protocol.frame(protocol.error_body("unauthorized_peer"), protocol.MAX_REPLY_FRAME))
            self._finish(conn)
            return
        with self._lock:
            full = self._open >= self.cfg.max_connections or self._per_uid.get(cred.uid, 0) >= self.cfg.max_per_uid
            if not full:
                self._open += 1
                self._per_uid[cred.uid] = self._per_uid.get(cred.uid, 0) + 1
                self.peak_open = max(self.peak_open, self._open)
        if full:
            self.log.event("refused", code="busy", uid=cred.uid, pid=cred.pid)
            self._close(conn)  # unread
            return
        worker = threading.Thread(target=self._run, args=(conn, cred), daemon=True)
        with self._lock:
            self._threads.add(worker)
        try:
            worker.start()
        except RuntimeError:
            self._release(cred, worker)
            self._close(conn)

    def _run(self, conn: socket.socket, cred: PeerCred) -> None:
        try:
            self.handle_connection(conn, cred)
        finally:
            self._release(cred, threading.current_thread())

    def _release(self, cred: PeerCred, worker: threading.Thread) -> None:
        with self._lock:
            self._open -= 1
            left = self._per_uid.get(cred.uid, 1) - 1
            if left > 0:
                self._per_uid[cred.uid] = left
            else:
                self._per_uid.pop(cred.uid, None)
            self._threads.discard(worker)

    def _shutdown(self) -> int:
        end = time.monotonic() + self.cfg.grace_seconds
        with self._lock:
            workers = list(self._threads)
        for worker in workers:
            worker.join(timeout=max(0.0, end - time.monotonic()))
        alive = [w for w in workers if w.is_alive()]
        if alive:
            self._record_interrupted()
        self.log.event("stopped", abandoned=len(alive))
        return len(alive)

    def _record_interrupted(self) -> None:
        """Calls still open when the grace ran out end ambiguous now: the full reservation stays counted and the model
        is stopped. A call that settles in the same instant wins (the ledger refuses the second transition)."""
        try:
            now = self.pipeline.wall()
            for rec in self.pipeline.ledger.view().open_calls():
                with contextlib.suppress(Exception):
                    self.pipeline.ledger.mark_ambiguous(rec.call_id, "crash_recovery", now)
        except Exception as exc:
            self.log.event("error", tag="shutdown", exc=type(exc).__name__)

    # -- one connection

    def handle_connection(self, conn: socket.socket, cred: PeerCred) -> None:
        """Read one request, answer it once, close. Exceptions from the work are logged by class and answered with
        `internal`; a missed deadline or a broken connection drops the connection silently."""
        rid = next(self._ids)
        started = self.mono()
        try:
            self._handle(conn, cred, rid, started)
        except (DeadlineExceeded, OSError) as exc:
            self.log.event("dropped", rid=rid, uid=cred.uid, pid=cred.pid, exc=type(exc).__name__)
        except Exception as exc:  # a bug: nothing of the message is logged
            self.log.event("error", rid=rid, tag="handler", exc=type(exc).__name__)
        finally:
            self._finish(conn)

    def _handle(self, conn: socket.socket, cred: PeerCred, rid: int, started: float) -> None:
        try:
            body = protocol.read_frame(self._reader(conn, started + self.cfg.read_deadline), protocol.MAX_REQUEST_FRAME)
            request = protocol.parse_request(body)
        except ProtocolError as err:
            self.log.event("refused", rid=rid, code=err.code, uid=cred.uid, pid=cred.pid)
            self._reply(conn, _fail(err.code))
            return
        try:
            outcome = self._dispatch(request, cred.uid)
        except Refused as err:
            code = err.code if err.code in protocol.REPLY_CODES else "internal"
            outcome = _fail(code)
        except Exception as exc:  # the ledger or the pipeline failed; the ledger says what is recorded
            self.log.event("error", rid=rid, tag="dispatch", exc=type(exc).__name__)
            outcome = _fail("internal")
        self.log.event(
            "done",
            rid=rid,
            op=request.op,
            code=outcome.code,
            uid=cred.uid,
            pid=cred.pid,
            bytes_in=len(body),
            bytes_out=len(outcome.body) + sum(len(a) for a in outcome.attachments),
            model=outcome.model,
            nonce8=outcome.nonce8,
            reserved=outcome.reserved,
            actual=outcome.actual,
            ms=int((self.mono() - started) * 1000),
        )
        self._reply(conn, outcome)

    # -- the work

    def _dispatch(self, request: Request, uid: int) -> Outcome:
        op = request.op
        if self._stopping and op in ("begin", "call"):  # a connection admitted before the stop cannot start new work
            return _fail("busy")
        if op not in ("status", "dryrun") and not self.switch():
            return _fail("disabled")
        limits = {
            "begin": self.cfg.begin_per_minute,
            "call": self.cfg.call_per_minute,
        }
        if not self._limits.allow(uid, op, limits.get(op, self.cfg.other_per_minute)):
            return _fail("busy")
        fields = request.fields
        if op == "status":
            return self._status()
        if op == "begin":
            return self._begin(fields)
        if op == "call":
            return self._call(fields)
        if op == "check":
            return self._check(fields)
        return self._dryrun(fields)

    def _quota_line(self, spent: int) -> str:
        return f"{format_usd(spent)} of {format_usd(self.pipeline.policy.caps.month_micro)} USD used this month"

    def _status(self) -> Outcome:
        pipe = self.pipeline
        now = pipe.wall()
        view = pipe.ledger.view()
        spent = view.month_spent(now)
        try:
            loaded = bool(self.key_loaded())
        except Exception:
            loaded = False
        fields = {
            "enabled": bool(self.switch()),
            "key_loaded": loaded,
            "epoch": pipe.epoch,
            "ledger_head": view.head,
            "month_spent": format_usd(spent),
            "month_cap": format_usd(pipe.policy.caps.month_micro),
            "block": format_usd(BLOCK_MICRO),
            "prices_valid_through": min(m.valid_through for m in pipe.policy.prices.models.values()).isoformat(),
            "suspended": sorted(view.suspended),
            "line": self._quota_line(spent),
        }
        return Outcome(protocol.ok_body(fields), "ok")

    def _shape(self, f: dict[str, Any], *, prompt: str) -> BrokerRequest:
        price = self.pipeline.policy.allowed(f["model"])
        return BrokerRequest(
            model=f["model"],
            kind=f["kind"],
            job=f["job"],
            prompt=prompt,
            max_output_tokens=f["max_output_tokens"],
            thinking_level=price.thinking_level_sent,
            count=f.get("count", 0),
            image_size=f.get("image_size", ""),
            aspect_ratio=f.get("aspect_ratio", ""),
        )

    def _begin(self, f: dict[str, Any]) -> Outcome:
        pipe = self.pipeline
        try:
            limit = parse_usd(f["max_usd"])
        except MoneyError:
            raise Refused("bad_request", "the maximum cost is out of range") from None
        req = self._shape(f, prompt="")
        now = pipe.wall()
        offer = pipe.issuer.begin(req, prompt_bytes=f["prompt_bytes"], max_micro=limit, now=now)
        spent = pipe.ledger.view().month_spent(now)
        fields = {
            "nonce": offer.nonce,
            "epoch": offer.epoch,
            "expires_at": offer.expires_at.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ledger_head": offer.ledger_head,
            "estimate_usd": format_usd(offer.estimate_micro),
            "reserve_usd": format_usd(offer.reserve_micro),
            "thinking_level": offer.thinking_level,
            "beyond_ceiling": offer.beyond_ceiling,
            "line": f"reserves {format_usd(offer.reserve_micro)} USD; {self._quota_line(spent)}",
        }
        return Outcome(
            protocol.ok_body(fields), "ok", model=req.model, nonce8=offer.nonce[:8], reserved=offer.reserve_micro
        )

    def _check(self, f: dict[str, Any]) -> Outcome:
        state = self.pipeline.issuer.state(f["nonce"], self.pipeline.wall())
        return Outcome(protocol.ok_body({"state": state}), "ok", nonce8=f["nonce"][:8])

    def _dryrun(self, f: dict[str, Any]) -> Outcome:
        who = verify_dryrun(
            f["approval"]["payload"],
            f["approval"]["signature"],
            self.pipeline.trust,
            now=self.pipeline.wall(),
            verifier=self.pipeline.verifier,
        )
        fields = {
            "principal": who.label,
            "fingerprint": who.fingerprint,
            "hardware": who.hardware,
            "touch": who.user_present,
            "pin": who.user_verified,
            "enabled": bool(self.switch()),
        }
        return Outcome(protocol.ok_body(fields), "ok")

    def _call(self, f: dict[str, Any]) -> Outcome:
        req = self._shape(f, prompt=f["prompt"])
        if not self._slots.acquire(timeout=self.cfg.slot_wait):
            raise Refused("busy", "a paid call is already in flight")
        admitted = False
        try:
            with self._lock:  # the count and the entry are one step: nobody else is counted in between
                self._check_call_budget(self._in_flight)
                self._in_flight += 1
                admitted = True
            result = self.pipeline.call(req, f["approval"]["payload"], f["approval"]["signature"])
        finally:
            if admitted:
                with self._lock:
                    self._in_flight -= 1
            self._slots.release()  # before the reply is written
        return self._call_outcome(result)

    def _check_call_budget(self, pending: int) -> None:
        """Vendor calls started in the last minute and the last day (read from the ledger, so a restart does not
        reset them), plus `pending`: the calls already past this check whose reservation may not be written yet (one
        that has been written is counted twice, which only makes the budget stricter, never looser). The caller holds
        the budget lock from this count until the call is entered, and never across the vendor call."""
        now = self.pipeline.wall()
        started = [c.started for c in self.pipeline.ledger.view().calls.values()]
        if pending + sum(1 for s in started if now - s < dt.timedelta(minutes=1)) >= self.cfg.max_calls_per_minute:
            raise Refused("busy", "too many paid calls this minute")
        if pending + sum(1 for s in started if now - s < dt.timedelta(days=1)) >= self.cfg.max_calls_per_day:
            raise Refused("busy", "too many paid calls today")

    def _call_outcome(self, result: CallResult) -> Outcome:
        receipt = result.receipt

        def make(body: bytes, code: str, attachments: tuple[bytes, ...] = ()) -> Outcome:
            return Outcome(
                body,
                code,
                attachments,
                model=receipt.model,
                nonce8=receipt.nonce[:8],
                reserved=receipt.reserved_micro,
                actual=receipt.actual_micro,
            )

        fields = receipt_fields(receipt)
        if result.code == "ok":
            described = [
                {"index": i.index, "mime": i.mime, "bytes": len(i.data), "sha256": i.sha256} for i in result.images
            ]
            try:
                body = protocol.ok_body({"receipt": fields, "text": result.text, "attachments": described})
                for image in result.images:
                    protocol.frame(image.data, protocol.MAX_ATTACHMENT_FRAME)
            except ProtocolError:  # the answer cannot be carried; it was paid for and is not kept
                return make(protocol.error_body("internal", {"receipt": fields}), "internal")
            return make(body, "ok", tuple(i.data for i in result.images))
        if result.code not in protocol.CALL_CODES:
            return make(protocol.error_body("internal", {"receipt": fields}), "internal")
        extra: dict[str, Any] = {"receipt": fields}
        if result.code == "rate_limited" and result.retry_after is not None:
            extra["retry_after"] = result.retry_after
        return make(protocol.error_body(result.code, extra), result.code)

    # -- the connection's bytes

    def _reader(self, conn: socket.socket, end: float) -> Callable[[int], bytes]:
        def recv(count: int) -> bytes:
            left = end - self.mono()
            if left <= 0:
                raise DeadlineExceeded
            conn.settimeout(left)
            try:
                return conn.recv(count)
            except TimeoutError:
                raise DeadlineExceeded from None

        return recv

    def _send_parts(self, conn: socket.socket, parts: list[bytes], *, progress: float, total: float) -> None:
        end = self.mono() + total
        for part in parts:
            view = memoryview(part)
            sent = 0
            while sent < len(view):
                left = end - self.mono()
                if left <= 0:
                    raise DeadlineExceeded
                conn.settimeout(min(progress, left))
                try:
                    count = conn.send(view[sent : sent + protocol.READ_CHUNK])
                except TimeoutError:
                    raise DeadlineExceeded from None
                if count <= 0:
                    raise OSError(errno.EPIPE, "the peer stopped reading")
                sent += count

    def _reply(self, conn: socket.socket, outcome: Outcome) -> None:
        """One JSON frame, then one frame per attachment, each under its own deadline. A failure drops the rest."""
        try:
            head = protocol.frame(outcome.body, protocol.MAX_REPLY_FRAME)
            self._send_parts(conn, [head], progress=self.cfg.write_json_deadline, total=self.cfg.write_json_deadline)
            for data in outcome.attachments:
                header = protocol.HEADER.pack(len(data))
                self._send_parts(
                    conn, [header, data], progress=self.cfg.write_progress, total=self.cfg.write_frame_total
                )
        except (DeadlineExceeded, OSError, ProtocolError) as exc:
            self.log.event("dropped", tag="write", exc=type(exc).__name__)

    # -- closing

    @staticmethod
    def _close(conn: socket.socket) -> None:
        with contextlib.suppress(OSError):
            conn.close()

    def _finish(self, conn: socket.socket) -> None:
        """Half-close, discard what the peer already sent (so unread bytes cannot turn the close into a reset that eats
        the reply), then close."""
        with contextlib.suppress(OSError):
            conn.shutdown(socket.SHUT_WR)
        with contextlib.suppress(OSError):
            conn.setblocking(False)
            conn.recv(_DRAIN_BYTES)
        self._close(conn)


def install_signal_handlers(server: Server, signals: tuple[int, ...]) -> Callable[[], None]:
    """Make each signal call `server.stop`. Returns a function that puts the previous handlers back."""
    import signal

    previous = {s: signal.getsignal(s) for s in signals}
    for number in signals:
        signal.signal(number, lambda *_: server.stop())

    def restore() -> None:
        for number, handler in previous.items():
            signal.signal(number, handler)

    return restore
