# SPDX-License-Identifier: Apache-2.0
"""The broker's spend ledger and the reserve, send, settle sequence (docs/gemini-broker.md, "A call, step by step").

Spend is recorded BEFORE the vendor call. `reserve` writes `approval_used` and `call_start` (with the worst-case
reservation) in one append, fsyncs, then creates `used/NONCE` with O_EXCL and fsyncs it and its directory. Either record
alone marks the nonce spent. Whatever happens after that, a restart reads the call back as settled or ambiguous (the
whole reservation stays counted and the model is suspended); there is no state in which the reserved amount is free.

The ledger is the repository's hash-chained `gemini.Ledger` (chain, head file, height record), pointed at the broker's
state directory, with strict row parsing on top. Everything runs under one `flock` on the ledger's lock file: the
checks (nonce, suspension, caps) and the append are one critical section, so two reservers cannot both see room.
Money is integer micro-dollars. `now` is always a parameter; nothing here reads the clock.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import hashlib
import json
import os
import secrets
import stat
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

from safo import gemini
from safo.bounded import MAX_FILE_BYTES, loads, read_bounded
from safo.broker.errors import BrokerError, IllegalTransition, LedgerError, Refused
from safo.broker.money import MAX_MICRO
from safo.broker.policy import BrokerRequest, Policy, canonical_broker_request
from safo.broker.records import (
    CALL_ID,
    MONTH,
    NONCE,
    REASON,
    SCHEMA_VERSION,
    UID_MAX,
    ApprovalV3,
    check_binding,
    parse_stamp,
    validate_row,
)
from safo.broker.states import CallState, advance
from safo.guardlog import ensure_dir, file_lock, write_text

GENESIS = "0" * 64  # the ledger head before any row exists
LEDGER_NAME = "ledger.jsonl"
FLOOR_NAME = "schema_version"
USED_DIR = "used"
MARKER_BYTES = 4096
FAULT_POINTS = ("before_append", "after_append", "after_marker", "after_sent", "before_settle")
Faults = Callable[[str], None]
MARKER_KEYS = {
    "v",
    "ts",
    "nonce",
    "call_id",
    "model",
    "kind",
    "job",
    "reserved_micro",
    "prompt_sha256",
    "prompt_bytes",
    "image_size",
    "count",
}


# -- the folded view -----------------------------------------------------------------------------------------------


@dataclasses.dataclass
class CallRecord:
    call_id: str
    nonce: str
    model: str
    job: str
    kind: str
    reserved_micro: int
    started: dt.datetime
    state: CallState
    actual_micro: int | None = None
    resolved_micro: int | None = None
    ambiguous: bool = False
    breach: bool = False

    @property
    def month(self) -> str:
        return self.started.strftime("%Y-%m")

    @property
    def counted_micro(self) -> int:
        """What this call counts against the month: the real figure once known, otherwise the whole reservation."""
        if self.resolved_micro is not None:
            return self.resolved_micro
        if self.actual_micro is not None:
            return self.actual_micro
        return self.reserved_micro

    @property
    def unresolved(self) -> bool:
        return self.ambiguous and self.resolved_micro is None


@dataclasses.dataclass(frozen=True)
class LedgerView:
    calls: dict[str, CallRecord]
    spent_nonces: frozenset[str]
    suspended: dict[str, tuple[str, ...]]  # model -> the call ids that suspended it and are not yet cleared
    last_ts: dt.datetime | None
    head: str
    rows: int
    hashes: frozenset[str] = frozenset()  # the hash of every chained row: a signed `ledger_head` must be one of them
    adjusted: Mapping[str, int] = dataclasses.field(default_factory=dict)  # month -> what root added (reconcile)

    def month_total(self, key: str) -> int:
        """What a month counts: every call at its counted figure, plus what root added for it. Only ever grows."""
        return sum(c.counted_micro for c in self.calls.values() if c.month == key) + self.adjusted.get(key, 0)

    def month_spent(self, now: dt.datetime) -> int:
        return self.month_total(now.astimezone(dt.UTC).strftime("%Y-%m"))

    def open_calls(self) -> list[CallRecord]:
        return [c for c in self.calls.values() if c.state in (CallState.RESERVED, CallState.SENT)]


def _corrupt() -> LedgerError:
    return LedgerError("the broker ledger is not consistent with the call state machine; root must look at it")


def fold(rows: list[dict[str, Any]], head: str = "") -> LedgerView:
    """Read verified chain rows into calls, strictly. Every row is shape-checked, times and schema versions must not go
    backward, and every call moves only by a legal transition. Anything else is a LedgerError: a counter that skips or
    guesses could undercount spend."""
    calls: dict[str, CallRecord] = {}
    nonces: set[str] = set()
    used: dict[str, dict[str, Any]] = {}
    suspended: dict[str, list[str]] = {}
    adjusted: dict[str, int] = {}
    pending: str | None = None  # a breach or an ambiguity whose `suspended` row must come next
    last: dt.datetime | None = None
    version = 0
    for row in rows:
        kind = validate_row(row)
        when = parse_stamp(row["ts"])
        if when is None or (last is not None and when < last):
            raise _corrupt()
        last = when
        if kind == "chain_start":
            continue
        if row["v"] < version:
            raise LedgerError("the broker ledger schema version goes backward; it was rolled back or mixed")
        version = row["v"]
        if pending is not None and (kind != "suspended" or row["call_id"] != pending):
            raise _corrupt()
        if used and kind != "call_start":
            raise _corrupt()
        if kind == "admin_action":
            _fold_admin(row, when, adjusted)
            continue
        cid = row.get("call_id", "")
        rec = calls.get(cid)
        try:
            if kind == "approval_used":
                if row["nonce"] in nonces or cid in calls or cid in used:
                    raise _corrupt()
                used[cid] = row
                nonces.add(row["nonce"])
            elif kind == "call_start":
                first = used.pop(cid, None)
                if first is None or any(first[k] != row[k] for k in ("nonce", "model", "job")):
                    raise _corrupt()
                calls[cid] = CallRecord(
                    cid,
                    row["nonce"],
                    row["model"],
                    row["job"],
                    row["kind"],
                    row["reserved_micro"],
                    when,
                    CallState.RESERVED,
                )
            elif rec is None:
                if kind != "suspension_cleared":
                    raise _corrupt()
            elif kind == "call_sent":
                rec.state = advance(rec.state, CallState.SENT)
            elif kind == "call_end":
                _end(rec, row)
                pending = cid if rec.breach else None
            elif kind == "ambiguous_call":
                if row["model"] != rec.model or row["reserved_micro"] != rec.reserved_micro:
                    raise _corrupt()
                rec.state = advance(rec.state, CallState.AMBIGUOUS)
                rec.ambiguous = True
                pending = cid
            elif kind == "suspended":
                if row["model"] != rec.model or row["reason"] != ("breach" if rec.breach else "ambiguous"):
                    raise _corrupt()
                rec.state = advance(rec.state, CallState.SUSPENDED)
                suspended.setdefault(rec.model, []).append(cid)
                pending = None
            elif kind == "ambiguous_resolved":
                if not rec.unresolved or rec.state not in (CallState.AMBIGUOUS, CallState.SUSPENDED):
                    raise _corrupt()
                rec.resolved_micro = row["actual_micro"]
            if kind == "suspension_cleared":
                ids = suspended.pop(row["model"], None)
                if not ids or any(calls[i].unresolved for i in ids):
                    raise _corrupt()
                for i in ids:
                    calls[i].state = advance(calls[i].state, CallState.CLEARED)
        except IllegalTransition:
            raise _corrupt() from None
    if pending is not None or used:
        raise _corrupt()
    hashes = frozenset(row["hash"] for row in rows)
    return LedgerView(
        calls, frozenset(nonces), {m: tuple(v) for m, v in suspended.items()}, last, head, len(rows), hashes, adjusted
    )


def _fold_admin(row: dict[str, Any], when: dt.datetime, adjusted: dict[str, int]) -> None:
    """An `admin_action` row is root's record. A `clear` names a model and adds nothing; an `adjust` names a month that
    is not in the future and adds a positive amount to it. Any other pairing of the fields is corruption."""
    if row["action"] == "clear":
        if row["model"] == "" or row["month"] != "" or row["add_micro"] != 0:
            raise _corrupt()
        return
    if row["model"] != "" or row["month"] == "" or row["add_micro"] <= 0 or row["month"] > when.strftime("%Y-%m"):
        raise _corrupt()
    adjusted[row["month"]] = adjusted.get(row["month"], 0) + row["add_micro"]


def _end(rec: CallRecord, row: dict[str, Any]) -> None:
    actual, status = row["actual_micro"], row["status"]
    if status == "not_sent":
        if rec.state is not CallState.RESERVED:
            raise _corrupt()
    elif rec.state is not CallState.SENT:
        raise _corrupt()
    if status != "ok" and (actual != 0 or row["breach"]):
        raise _corrupt()
    # an actual above the reservation is always a breach; a breach inside the reservation is an output-cap breach
    if (actual > rec.reserved_micro and not row["breach"]) or row["released_micro"] != max(
        rec.reserved_micro - actual, 0
    ):
        raise _corrupt()
    rec.state = advance(rec.state, CallState.SETTLED)
    rec.actual_micro = actual
    rec.breach = row["breach"]


# -- the ledger on disk --------------------------------------------------------------------------------------------


class _BrokerLedger(gemini.Ledger):
    """`gemini.Ledger` with its height record in the state directory and no sibling-ledger search."""

    def __init__(self, path: Path, height_file: Path) -> None:
        super().__init__(path)
        self._height_file = height_file

    @property
    def height_file(self) -> Path:
        return self._height_file

    def _absent(self) -> gemini.LedgerState:
        return gemini.LedgerState([], False, "", 0, hashlib.sha256(b"").hexdigest())

    def lock_for(self, seconds: float) -> contextlib.AbstractContextManager[None]:
        return file_lock(self.path.with_name(self.path.name + ".lock"), timeout=seconds)


@dataclasses.dataclass(frozen=True)
class Ticket:
    call_id: str
    nonce: str
    model: str
    reserved_micro: int


@dataclasses.dataclass(frozen=True)
class AdminWho:
    """Who ran an administration step: the real uid of the process and the uid sudo says it came from (-1: none)."""

    uid: int
    sudo_uid: int


@dataclasses.dataclass(frozen=True)
class Cleared:
    model: str
    calls: tuple[tuple[str, int, int], ...]  # (call id, counted before, counted after)


@dataclasses.dataclass(frozen=True)
class Settlement:
    call_id: str
    reserved_micro: int
    actual_micro: int
    released_micro: int
    breach: bool


class CallLedger:
    """One state directory. `reserve`, `mark_sent`, `settle` and `mark_ambiguous` are the broker's steps; `recover` runs
    once at start, before anything is served; `resolve` and `clear` are root's (the client never gets them)."""

    def __init__(self, state_dir: Path, *, faults: Faults | None = None, lock_seconds: float = 10.0) -> None:
        self.dir = Path(state_dir)
        self.faults: Faults = faults or (lambda point: None)
        self.lock_seconds = lock_seconds
        self.ledger = _BrokerLedger(self.dir / LEDGER_NAME, self.dir / "height")

    # -- plumbing

    def _fault(self, point: str) -> None:
        self.faults(point)

    def open(self) -> None:
        """Create the directory (0700) if it is missing; refuse one that is not ours alone."""
        try:
            ensure_dir(self.dir)
        except (PermissionError, OSError):
            raise LedgerError("the broker state directory cannot be made or is not private to this user") from None
        self._check_tree()

    def _check_private(self, path: Path, *, directory: bool) -> None:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return
        except OSError:
            raise LedgerError("a broker state file cannot be inspected") from None
        wanted = stat.S_ISDIR if directory else stat.S_ISREG
        if not wanted(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise LedgerError("a broker state file is a link, the wrong kind, not ours, or open to other users")

    def _check_tree(self) -> None:
        self._check_private(self.dir, directory=True)
        for name in (LEDGER_NAME, LEDGER_NAME + ".head", "height", FLOOR_NAME, LEDGER_NAME + ".lock"):
            self._check_private(self.dir / name, directory=False)
        self._check_private(self.dir / USED_DIR, directory=True)

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        try:
            with self.ledger.lock_for(self.lock_seconds):
                yield
        except TimeoutError:
            raise Refused("busy", "another operation holds the ledger") from None
        except PermissionError:
            raise LedgerError("the broker state directory is not private to this user") from None

    def _view(self) -> LedgerView:
        self._check_tree()
        self._check_floor()
        try:
            state = self.ledger.state()
        except gemini.RefusedError as err:
            raise LedgerError(str(err)) from None
        if state.rows and not state.started:
            raise LedgerError("the broker ledger has rows before its chain; it is not a broker ledger")
        return fold(state.rows, state.head)

    def _check_floor(self) -> None:
        """The schema version only goes up: a state directory marked with a newer version is not read by older code."""
        path = self.dir / FLOOR_NAME
        try:
            text = read_bounded(path, 16).decode("ascii").strip()
        except FileNotFoundError:
            return
        except (OSError, UnicodeError):
            raise LedgerError("the schema version record cannot be read") from None
        if not text.isdigit() or int(text) < 1:
            raise LedgerError("the schema version record is malformed")
        if int(text) > SCHEMA_VERSION:
            raise LedgerError("this state directory was written by a newer version of the broker; refusing to run")

    def _raise_floor(self) -> None:
        path = self.dir / FLOOR_NAME
        try:
            current = int(read_bounded(path, 16).decode("ascii").strip())
        except (OSError, UnicodeError, ValueError):
            current = 0
        if current < SCHEMA_VERSION:
            write_text(path, f"{SCHEMA_VERSION}\n")

    @staticmethod
    def _now(now: object) -> dt.datetime:
        try:
            return gemini.plain_time(now, "now")
        except gemini.RefusedError:
            raise Refused("bad_request", "the time is not a plain time with a time zone") from None

    def _stamp(self, now: dt.datetime, view: LedgerView, *, strict: bool) -> str:
        """The row time. A clock that went backward would move a spend into an earlier month, so a reservation refuses;
        recovery, which must run anyway, uses the last row's time instead."""
        if view.last_ts is not None and now < view.last_ts:
            if strict:
                raise Refused("internal", "the clock is earlier than the last ledger row")
            now = view.last_ts
        return gemini.stamp(now)

    # -- markers

    def _marker_path(self, nonce: str) -> Path:
        if NONCE.fullmatch(nonce) is None:
            raise LedgerError("a nonce is a short lowercase hex string")
        return self.dir / USED_DIR / nonce

    def marker_exists(self, nonce: str) -> bool:
        return os.path.lexists(self._marker_path(nonce))

    def _write_marker(self, data: dict[str, Any]) -> None:
        folder = self.dir / USED_DIR
        ensure_dir(folder)
        path = self._marker_path(data["nonce"])
        body = (json.dumps(data, sort_keys=True) + "\n").encode()
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            raise Refused("used", "this approval was already used") from None
        try:
            if os.write(fd, body) != len(body):
                raise LedgerError("a used marker took a short write")
            os.fsync(fd)
        finally:
            os.close(fd)
        directory = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _read_marker(self, nonce: str) -> dict[str, Any] | None:
        """The marker's content if it is whole and strict, else None (a partial marker still marks the nonce spent)."""
        path = self._marker_path(nonce)
        self._check_private(path, directory=False)
        try:
            data = loads(read_bounded(path, MARKER_BYTES))
        except (OSError, ValueError, UnicodeError, RecursionError):
            return None
        if (
            not isinstance(data, dict)
            or set(data) != MARKER_KEYS
            or data["nonce"] != nonce
            or data["v"] != SCHEMA_VERSION
        ):
            return None
        try:
            rows = [
                {"type": "call_start", "ts": data["ts"], "v": data["v"], "prev_hash": "0" * 64, "hash": "0" * 64}
                | {k: data[k] for k in data if k not in ("v", "ts")}
            ]
            validate_row(rows[0])
        except BrokerError:
            return None
        return data

    def _marker_names(self) -> list[str]:
        folder = self.dir / USED_DIR
        self._check_private(folder, directory=True)
        try:
            names = os.listdir(folder)
        except FileNotFoundError:
            return []
        except OSError:
            raise LedgerError("the used folder cannot be read") from None
        for name in names:
            if NONCE.fullmatch(name) is None:
                raise LedgerError("the used folder holds a file that is not a nonce")
        return sorted(names)

    # -- the steps

    def view(self) -> LedgerView:
        """The ledger as it is now (read under the lock, so never half an append)."""
        with self._locked():
            return self._view()

    def reserve(
        self,
        req: BrokerRequest,
        approval: ApprovalV3,
        policy: Policy,
        *,
        epoch: str,
        now: dt.datetime,
        pre_spend: Callable[[], None] | None = None,
    ) -> Ticket:
        """Check, then spend first. Everything from the nonce check to the markers is one critical section.
        `pre_spend` runs inside it, after the replay and suspension checks and just before the spend is written: the
        pipeline uses it to check revocation and the issued nonce at the last moment. It raises to refuse."""
        now = self._now(now)
        req = canonical_broker_request(req)
        check_binding(approval, req, epoch=epoch, now=now)
        priced = policy.price(req, now)
        reserved = priced.reservation.total_micro
        with self._locked():
            view = self._view()
            stamp = self._stamp(now, view, strict=True)
            if approval.ledger_head != GENESIS and approval.ledger_head not in view.hashes:
                # a head the ledger never had (forged, or from another ledger); the genesis sentinel is the chain start
                raise Refused("bad_approval", "this approval was made for another ledger state; ask for a fresh one")
            if approval.nonce in view.spent_nonces or self.marker_exists(approval.nonce):
                raise Refused("used", "this approval was already used")
            if req.model in view.suspended:
                raise Refused("model_suspended", "this model is stopped until root clears it")
            policy.check_caps(
                reserved,
                max_micro=approval.max_micro,
                beyond_ceiling=approval.beyond_ceiling,
                month_spent_micro=view.month_spent(now),
            )
            if pre_spend is not None:
                pre_spend()
            call_id = secrets.token_hex(16)
            rows = _spend_rows(
                stamp, call_id, approval.nonce, epoch, req, priced.prompt_sha256, priced.prompt_bytes, reserved
            )
            self._fault("before_append")
            self.ledger.append_many(rows, ts=stamp)
            self._fault("after_append")
            self._write_marker(_marker(rows[1], stamp))
            self._fault("after_marker")
            self._raise_floor()
        return Ticket(call_id, approval.nonce, req.model, reserved)

    def mark_sent(self, call_id: str, now: dt.datetime) -> None:
        """Written, and fsynced, before the connection to the vendor is opened."""
        now = self._now(now)
        with self._locked():
            view = self._view()
            rec = _call(view, call_id)
            advance(rec.state, CallState.SENT)
            self.ledger.append_many([_row("call_sent", self._stamp(now, view, strict=False), call_id=call_id)])
            self._fault("after_sent")

    def settle(
        self, call_id: str, status: str, actual_micro: int, now: dt.datetime, *, cap_breach: bool = False
    ) -> Settlement:
        """Record the outcome against the reservation the LEDGER holds (never a figure the caller supplies for it).
        An actual above the reservation is a breach: it is counted in full and the model is suspended in one append.
        `cap_breach` is the same outcome for a reply that went over the signed output cap while the money stayed inside
        the reservation (decision 13): the call is recorded as a breach and the model is suspended all the same."""
        if status not in ("ok", "not_sent", "rate_limited", "vendor_refused") or type(actual_micro) is not int:
            raise IllegalTransition("a call ends with ok, not_sent, rate_limited or vendor_refused and a whole amount")
        if not 0 <= actual_micro <= MAX_MICRO or (status != "ok" and actual_micro != 0):
            raise IllegalTransition("a call that was refused or limited cost nothing, and an amount is within range")
        now = self._now(now)
        self._fault("before_settle")
        with self._locked():
            view = self._view()
            rec = _call(view, call_id)
            advance(rec.state, CallState.SETTLED)
            if (status == "not_sent") != (rec.state is CallState.RESERVED):
                raise IllegalTransition(
                    "only a call that never left ends as not_sent, and a sent call is never not_sent"
                )
            stamp = self._stamp(now, view, strict=False)
            if cap_breach and status != "ok":
                raise IllegalTransition("only a call that returned an answer can breach the output cap")
            breach = actual_micro > rec.reserved_micro or cap_breach
            released = max(rec.reserved_micro - actual_micro, 0)
            rows = [
                _row(
                    "call_end",
                    stamp,
                    call_id=call_id,
                    status=status,
                    actual_micro=actual_micro,
                    released_micro=released,
                    breach=breach,
                )
            ]
            if breach:
                rows.append(_row("suspended", stamp, call_id=call_id, model=rec.model, reason="breach"))
            self.ledger.append_many(rows)
        return Settlement(call_id, rec.reserved_micro, actual_micro, released, breach)

    def mark_ambiguous(self, call_id: str, reason: str, now: dt.datetime) -> None:
        """The request left (or may have) and the outcome is unknown: the whole reservation stays counted and the model
        is suspended, in one append."""
        now = self._now(now)
        with self._locked():
            view = self._view()
            rec = _call(view, call_id)
            advance(rec.state, CallState.AMBIGUOUS)
            self.ledger.append_many(_ambiguous_rows(self._stamp(now, view, strict=False), rec, reason))

    def recover(self, now: dt.datetime) -> list[str]:
        """Run once at start, before serving, and never while a call of this process is in flight. Repairs a torn last
        line, makes every open call ambiguous, and makes the ledger and the used markers agree; either record alone
        marks a nonce spent. Returns the call ids it made ambiguous. Safe to run again (it then changes nothing)."""
        now = self._now(now)
        with self._locked():
            self._check_tree()
            self._repair_tail()
            self._complete_breach(now)
            view = self._view()
            stamp = self._stamp(now, view, strict=False)
            rows: list[dict[str, Any]] = []
            handled: list[str] = []
            known = {c.nonce for c in view.calls.values()}
            for nonce in self._marker_names():
                if nonce in known:
                    self._marker_agrees(view, nonce)
                    continue
                data = self._read_marker(nonce)
                if data is None:
                    raise LedgerError("a used marker has no ledger row and cannot be read; root must look at it")
                if data["ts"][:7] != stamp[:7]:  # rebuilding it now would move the charge into another month
                    raise LedgerError("a used marker from an earlier month has no ledger row; root must reconcile it")
                cid, model = data["call_id"], data["model"]
                start = _row("call_start", stamp, **{k: data[k] for k in data if k not in ("v", "ts")})
                used = _row(
                    "approval_used", stamp, nonce=nonce, call_id=cid, model=model, job=data["job"], epoch="0" * 32
                )
                shell = CallRecord(
                    cid,
                    nonce,
                    model,
                    data["job"],
                    data["kind"],
                    data["reserved_micro"],
                    parse_stamp(stamp) or dt.datetime.min.replace(tzinfo=dt.UTC),
                    CallState.RESERVED,
                )
                rows += [used, start, *_ambiguous_rows(stamp, shell, "marker_only")]
                handled.append(cid)
            for rec in view.open_calls():
                rows += _ambiguous_rows(stamp, rec, "crash_recovery")
                handled.append(rec.call_id)
            if rows:
                self.ledger.append_many(rows, ts=stamp)
            view = self._view()
            for rec in view.calls.values():
                self._ensure_marker(rec)
            self._raise_floor()
        return handled

    def _complete_breach(self, now: dt.datetime) -> None:
        """A breach `call_end` is whole but its `suspended` companion was cut off: the actual cost is known and must
        stay counted, so the missing row is written (never the whole breach dropped back to its lower reservation)."""
        try:
            rows = self.ledger.state().rows
        except gemini.RefusedError as err:
            raise LedgerError(str(err)) from None
        if not rows or rows[-1].get("type") != "call_end" or rows[-1].get("breach") is not True:
            return
        end = rows[-1]
        start = next(
            (r for r in rows if r.get("type") == "call_start" and r.get("call_id") == end.get("call_id")), None
        )
        last = parse_stamp(end.get("ts"))
        if start is None or last is None:
            raise LedgerError("the broker ledger is not consistent with the call state machine; root must look at it")
        when = gemini.stamp(max(now, last))
        suspended = _row("suspended", when, call_id=end["call_id"], model=start["model"], reason="breach")
        self.ledger.append_many([suspended])

    def _marker_agrees(self, view: LedgerView, nonce: str) -> None:
        """A whole marker must say what the ledger says about the same call (a marker is not a place to hide a lower
        figure, nor a different call). A partial marker is rewritten from the ledger later."""
        data = self._read_marker(nonce)
        if data is None:
            return
        rec = view.calls.get(data["call_id"])
        same = rec is not None and (rec.nonce, rec.model, rec.job, rec.reserved_micro) == (
            nonce,
            data["model"],
            data["job"],
            data["reserved_micro"],
        )
        if not same:
            raise LedgerError("a used marker disagrees with the ledger; root must look at it")

    def _ensure_marker(self, rec: CallRecord) -> None:
        if not self.marker_exists(rec.nonce):
            self._write_marker(_marker_from(rec))
        elif self._read_marker(rec.nonce) is None:  # a partial marker: the ledger is the authority, so rewrite it whole
            body = (json.dumps(_marker_from(rec), sort_keys=True) + "\n").encode()
            fd = os.open(self._marker_path(rec.nonce), os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
            try:
                os.write(fd, body)
                os.fsync(fd)
            finally:
                os.close(fd)

    def _repair_tail(self) -> None:
        """An append is one write and then one fsync, and a vendor call follows only after both. A crash during the
        write can leave a last line that is cut short, or a group of rows whose first row is whole and whose second is
        missing: `approval_used` and `call_start`, a breach `call_end` and its `suspended`, or an `ambiguous_call` and
        its `suspended`. Neither can have been followed by a vendor call, so removing them frees nothing (a breach
        `call_end` is the exception: it is kept and its `suspended` is written by `_complete_breach`). Only an
        unreadable unterminated last line and a dangling first row of a group are removed; damage anywhere else stays
        a LedgerError."""
        path = self.dir / LEDGER_NAME
        try:
            raw = read_bounded(path, MAX_FILE_BYTES + 1)
        except FileNotFoundError:
            return
        except OSError:
            raise LedgerError("the broker ledger is not a plain readable file") from None
        cut = raw.rfind(b"\n") + 1
        body, tail = raw[:cut], raw[cut:]
        if tail and _whole_row(
            tail
        ):  # a complete row that only lost its newline: keep it (counting it is the safe side)
            body, tail = raw + b"\n", b""
        lines = body.splitlines(keepends=True)
        while lines and _dangling(lines[-1]):
            lines.pop()
        fixed = b"".join(lines)
        if fixed == raw:
            return
        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
        try:
            if len(fixed) > len(raw):
                os.pwrite(fd, fixed[len(raw) :], len(raw))
            else:
                os.ftruncate(fd, len(fixed))
            os.fsync(fd)
        finally:
            os.close(fd)

    # -- root's steps

    def resolve(self, call_id: str, actual_micro: int, now: dt.datetime) -> None:
        """Root enters the real amount (read from the vendor's billing page) for an ambiguous call."""
        if type(actual_micro) is not int or not 0 <= actual_micro <= MAX_MICRO:
            raise Refused("bad_request", "the amount is out of range")
        now = self._now(now)
        with self._locked():
            view = self._view()
            rec = _call(view, call_id)
            if not rec.unresolved:
                raise IllegalTransition("only an ambiguous call without a real amount can be resolved")
            self.ledger.append_many(
                [
                    _row(
                        "ambiguous_resolved",
                        self._stamp(now, view, strict=False),
                        call_id=call_id,
                        actual_micro=actual_micro,
                    )
                ]
            )

    def clear(self, model: str, now: dt.datetime) -> None:
        """Root clears a model's suspension, only once every ambiguous call that caused it has its real amount."""
        now = self._now(now)
        with self._locked():
            view = self._view()
            ids = view.suspended.get(model)
            if not ids:
                raise IllegalTransition("this model is not suspended")
            if any(view.calls[i].unresolved for i in ids):
                raise IllegalTransition("enter the real amount for the ambiguous call before clearing the suspension")
            self.ledger.append_many([_row("suspension_cleared", self._stamp(now, view, strict=False), model=model)])

    # -- root's administration steps (src/safo/broker/admin.py runs these as the service user, after the privilege drop)

    def floor(self) -> int | None:
        """The schema version recorded in the state directory, or None when none has been written yet."""
        with self._locked():
            self._check_tree()
            self._check_floor()
            try:
                return int(read_bounded(self.dir / FLOOR_NAME, 16).decode("ascii").strip())
            except FileNotFoundError:
                return None
            except (OSError, UnicodeError, ValueError):
                raise LedgerError("the schema version record cannot be read") from None

    def admin_clear(
        self,
        model: str,
        confirm: Sequence[str],
        actuals: Mapping[str, int],
        reason: str,
        who: AdminWho,
        now: dt.datetime,
    ) -> Cleared:
        """Root clears a model's suspension in ONE append: its own record, the figure for each ambiguous call, and the
        clearing. The confirmation must repeat every call id that suspended the model, judged against the ledger as it
        is under the lock. An ambiguous call is settled at its whole reservation unless root names a verified actual
        for it (with a reason), and an actual is never below the usage already recorded for that call. A breach is
        already counted at its recorded actual and takes no figure. Nothing here lowers a call below what it counts
        unless root names such a figure; a cut write leaves the model suspended or cleared, never half of each."""
        _check_who(who)
        _check_reason(reason, required=bool(actuals))
        for call_id, amount in actuals.items():
            if type(call_id) is not str or type(amount) is not int or not 0 <= amount <= MAX_MICRO:
                raise IllegalTransition("a verified amount is a whole number in range for a named call")
        now = self._now(now)
        with self._locked():
            view = self._view()
            ids = view.suspended.get(model)
            if not ids:
                raise IllegalTransition("this model is not suspended")
            if sorted(confirm) != sorted(ids):
                raise IllegalTransition("the confirmation must repeat every call id that suspended this model")
            for call_id, amount in actuals.items():
                rec = view.calls.get(call_id)
                if call_id not in ids or rec is None or not rec.unresolved:
                    raise IllegalTransition(
                        "a verified amount can only be given for an ambiguous call of this suspension"
                    )
                if amount < (rec.actual_micro or 0):
                    raise IllegalTransition("a verified amount cannot be below the usage already recorded for the call")
            stamp = self._stamp(now, view, strict=False)
            rows = [_admin_row(stamp, "clear", who, reason, model=model)]
            settled: list[tuple[str, int, int]] = []
            for call_id in ids:
                rec = view.calls[call_id]
                if rec.unresolved:
                    amount = actuals.get(call_id, rec.reserved_micro)
                    rows.append(_row("ambiguous_resolved", stamp, call_id=call_id, actual_micro=amount))
                    settled.append((call_id, rec.counted_micro, amount))
                else:
                    settled.append((call_id, rec.counted_micro, rec.counted_micro))
            rows.append(_row("suspension_cleared", stamp, model=model))
            self._fault("admin_before_append")
            self.ledger.append_many(rows, ts=stamp)
            self._fault("admin_after_append")
        return Cleared(model, tuple(settled))

    def admin_adjust(self, month: str, billing_micro: int, reason: str, who: AdminWho, now: dt.datetime) -> int:
        """Root enters the vendor's billed figure for a month. The ledger adds the difference when the figure is higher
        than the month counts and does nothing when it is not: this can only raise a month. Returns what was added."""
        _check_who(who)
        _check_reason(reason, required=True)
        if type(billing_micro) is not int or not 0 <= billing_micro <= MAX_MICRO:
            raise IllegalTransition("the billing figure is a whole number of micro-dollars in range")
        if type(month) is not str or MONTH.fullmatch(month) is None:
            raise IllegalTransition("a month is written YYYY-MM")
        now = self._now(now)
        with self._locked():
            view = self._view()
            stamp = self._stamp(now, view, strict=False)
            if month > stamp[:7]:
                raise IllegalTransition("a month that has not started cannot be adjusted")
            gap = billing_micro - view.month_total(month)
            if gap <= 0:
                return 0
            self._fault("admin_before_append")
            self.ledger.append_many([_admin_row(stamp, "adjust", who, reason, month=month, add_micro=gap)], ts=stamp)
            self._fault("admin_after_append")
        return gap

    def audit(self, now: dt.datetime) -> list[str]:
        """Read-only: where the ledger, the used markers and the clock disagree. Raises LedgerError if the ledger or
        the used folder cannot be trusted at all. Each line is a fixed sentence plus an id."""
        now = self._now(now)
        found: list[str] = []
        with self._locked():
            view = self._view()
            known = {c.nonce: c for c in view.calls.values()}
            names = set(self._marker_names())
            for nonce in sorted(names):
                rec = known.get(nonce)
                if rec is None:
                    found.append(f"marker {nonce} has no ledger row")
                    continue
                data = self._read_marker(nonce)
                if data is None:
                    found.append(f"marker {nonce} is partial or unreadable")
                elif (rec.call_id, rec.model, rec.job, rec.reserved_micro) != (
                    data["call_id"],
                    data["model"],
                    data["job"],
                    data["reserved_micro"],
                ):
                    found.append(f"marker {nonce} disagrees with the ledger")
            for rec in view.calls.values():
                if rec.nonce not in names:
                    found.append(f"call {rec.call_id} has no marker")
            for rec in view.open_calls():
                found.append(f"open call {rec.call_id} ({rec.state.value}): start-up recovery makes it ambiguous")
            for rec in view.calls.values():
                if rec.unresolved:
                    found.append(f"ambiguous call {rec.call_id} has no real amount yet (unresolved)")
            if view.last_ts is not None and view.last_ts > now:
                found.append("the newest ledger row is newer than the clock")
        return found


# -- row builders --------------------------------------------------------------------------------------------------


def _row(row_type: str, stamp: str, /, **fields: Any) -> dict[str, Any]:
    return {"type": row_type, "ts": stamp, "v": SCHEMA_VERSION, **fields}


def _check_who(who: AdminWho) -> None:
    if (
        type(who) is not AdminWho
        or type(who.uid) is not int
        or type(who.sudo_uid) is not int
        or not 0 <= who.uid <= UID_MAX
        or not -1 <= who.sudo_uid <= UID_MAX
    ):
        raise IllegalTransition("an administration step names the uid that ran it")


def _check_reason(reason: str, *, required: bool) -> None:
    if type(reason) is not str or REASON.fullmatch(reason) is None or (required and not reason.strip()):
        raise IllegalTransition("a reason is up to 120 printable characters, and is required here")


def _admin_row(
    stamp: str, action: str, who: AdminWho, reason: str, *, model: str = "", month: str = "", add_micro: int = 0
) -> dict[str, Any]:
    return _row(
        "admin_action",
        stamp,
        action=action,
        uid=who.uid,
        sudo_uid=who.sudo_uid,
        model=model,
        month=month,
        add_micro=add_micro,
        reason=reason,
    )


def _call(view: LedgerView, call_id: str) -> CallRecord:
    if type(call_id) is not str or CALL_ID.fullmatch(call_id) is None or call_id not in view.calls:
        raise IllegalTransition("there is no such call")
    return view.calls[call_id]


def _spend_rows(
    stamp: str, call_id: str, nonce: str, epoch: str, req: BrokerRequest, digest: str, size: int, reserved: int
) -> list[dict[str, Any]]:
    return [
        _row("approval_used", stamp, nonce=nonce, call_id=call_id, model=req.model, job=req.job, epoch=epoch),
        _row(
            "call_start",
            stamp,
            call_id=call_id,
            nonce=nonce,
            model=req.model,
            kind=req.kind,
            job=req.job,
            reserved_micro=reserved,
            prompt_sha256=digest,
            prompt_bytes=size,
            image_size=req.image_size,
            count=req.count,
        ),
    ]


def _marker(start: dict[str, Any], stamp: str) -> dict[str, Any]:
    keep = {k: start[k] for k in MARKER_KEYS - {"v", "ts"}}
    return {"v": SCHEMA_VERSION, "ts": stamp, **keep}


def _marker_from(rec: CallRecord) -> dict[str, Any]:
    """A marker rebuilt from the ledger. The prompt fields are not kept in the folded record, so recovery writes zeros
    there: the marker's job is to mark the nonce spent, and the ledger row holds the digest."""
    return {
        "v": SCHEMA_VERSION,
        "ts": gemini.stamp(rec.started),
        "nonce": rec.nonce,
        "call_id": rec.call_id,
        "model": rec.model,
        "kind": rec.kind,
        "job": rec.job,
        "reserved_micro": rec.reserved_micro,
        "prompt_sha256": "0" * 64,
        "prompt_bytes": 0,
        "image_size": "",
        "count": 0,
    }


def _ambiguous_rows(stamp: str, rec: CallRecord, reason: str) -> list[dict[str, Any]]:
    return [
        _row(
            "ambiguous_call",
            stamp,
            call_id=rec.call_id,
            model=rec.model,
            reserved_micro=rec.reserved_micro,
            reason=reason,
        ),
        _row("suspended", stamp, call_id=rec.call_id, model=rec.model, reason="ambiguous"),
    ]


def _whole_row(line: bytes) -> bool:
    try:
        row = loads(line)
    except (ValueError, UnicodeError, RecursionError):
        return False
    return isinstance(row, dict) and row.get("hash") == gemini._chain_hash(row)


def _dangling(line: bytes) -> bool:
    """A row that is the first of a group appended together and so cannot be the last row of a finished append."""
    try:
        row = loads(line)
    except (ValueError, UnicodeError, RecursionError):
        return False
    if not isinstance(row, dict):
        return False
    kind = row.get("type")
    return kind in ("approval_used", "ambiguous_call")
