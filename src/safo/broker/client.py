# SPDX-License-Identifier: Apache-2.0
"""The thin client of the paid Gemini broker (docs/gemini-broker.md, "The client"; issue #260).

The client holds no key and no authoritative state. For one paid call it:

1. checks everything it can check alone (names, amounts, the prompt: at most 4000 characters, no secret shape, no
   private term) and, for an image, that the output folder is usable, before it opens a socket;
2. asks the broker for `begin` and checks the offer it gets back;
3. builds the signed text from the offer and shows the person that very text: every signed field, the cost fields,
   and the WHOLE prompt, escaped, with its digest. The screen is rendered from the text that is signed, not from the
   inputs, so the two cannot differ;
4. waits for the person to type the confirmation phrase, then signs with `ssh-keygen -Y sign` through
   `geminisign.sign` (fixed argument vector, absolute path, no shell, a small environment, the touch prompt on the
   terminal);
5. sends ONE `call` request on a new connection and reads exactly one reply (a JSON frame, then the attachment frame
   the JSON names). Anything that goes wrong after the request frame may have left is an unknown outcome: it is
   reported as possibly charged and is never repeated, and no other tier is tried.

A reply is believed only when its receipt names this request (nonce, epoch, model, shape and the SHA-256 of the exact
prompt bytes); otherwise it is discarded. Text from the broker is printed only through `safo.output`, which writes out
every control and format character. Nothing in this module logs, prints a prompt or an answer to a diagnostic stream,
reads a key, opens an image, or imports the free-tier call. The wire format is `safo.broker.protocol`, used unchanged.

Run it as `python3 -I -m safo.broker.client ...` (see `main`), or through the paid entries of the Gemini command group,
`safo gemini paid ...` and `safo gemini paid-dryrun` (#287): they call `run_paid` and `run_dryrun` below, and there is
no other paid path in the program. `run_dryrun` asks the broker's `dryrun` operation to check one throw-away
signature, so the signer, the enrollment and the broker's switch are tested without a call or a charge.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import hashlib
import importlib
import json
import os
import pwd
import re
import socket
import stat
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol, TextIO

from safo import gemini, geminisign, output
from safo.bounded import loads, read_bounded
from safo.broker import protocol
from safo.broker.errors import Refused
from safo.broker.money import MoneyError, format_usd, parse_usd
from safo.broker.protocol import ProtocolError
from safo.broker.records import EPOCH, HEAD, NONCE, STAMP, parse_approval, parse_stamp
from safo.errors import EXIT_INTERRUPTED, EXIT_OK, SafoError
from safo.schema import Reader, _safe_load
from safo.trust import read_trusted_regular_file

DEFAULT_SOCKET = "/run/safo-broker.sock"
ROOT_CONFIG = "/etc/safo/broker-client.yaml"
BROKER_UID = 0  # the account that must own the socket: the socket unit is root's
EXIT_REFUSED = 2
EXIT_UNKNOWN_OUTCOME = 4
BEGIN_SECONDS = 30.0
SEND_SECONDS = 10.0
DEFAULT_REPLY_SECONDS = 240.0  # the broker's call deadline is 180 seconds by default, then up to 60 for an image
APPROVAL_TTL = dt.timedelta(minutes=gemini.DEFAULT_TTL_MINUTES)
CHARGED = "THE CALL MAY HAVE BEEN CHARGED"
NO_FALLBACK = "the call was not retried and the free tier was not used"
SIGNING_MISSING = "signing is not set up (signing.key and signing.principal in broker-client.yaml)"

_SAFE_LINE = re.compile(r"[ -~]{1,200}")
_LEVEL = re.compile(r"[A-Za-z0-9_-]{1,16}")
_VERSION = re.compile(r"[0-9A-Za-z.+-]{1,32}")
_PRINCIPAL = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_KINDS = {"png": "image/png", "jpeg": "image/jpeg", "webp": "image/webp"}
_EXTENSION = {"png": "png", "jpeg": "jpg", "webp": "webp"}
_PNG = b"\x89PNG\r\n\x1a\n"


class ClientError(SafoError):
    """A problem the person can read: one fixed sentence, never a prompt, an answer or a vendor string."""

    def __init__(self, message: str, exit_code: int = EXIT_REFUSED) -> None:
        super().__init__(message)
        self.exit_code = exit_code


# -- configuration -----------------------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ClientConfig:
    socket: str = DEFAULT_SOCKET
    signing_key: str = ""
    principal: str = ""
    image_dir: str = ""
    private_terms: str = "default"
    reply_seconds: float = DEFAULT_REPLY_SECONDS


def user_config_path(home: Path) -> Path:
    return home / ".config" / "safo" / "broker-client.yaml"


def _absolute(r: Reader, value: object, name: str) -> str:
    text = r.string(value, name)
    if not text.startswith("/") or "\x00" in text or len(text) > 4096:
        raise r.fail(name, "expected an absolute path")
    return text


def _socket(r: Reader, value: object) -> str:
    return _absolute(r, value, "socket")


def _version(r: Reader, top: Mapping[str, Any]) -> None:
    if type(top["version"]) is not int or top["version"] != 1:
        raise r.fail("version", "only version 1 is supported")


def _parse_root(data: object) -> str | None:
    r = Reader("broker client settings (root)")
    top = r.mapping(data, "", {"version", "socket"}, {"version"})
    _version(r, top)
    return _socket(r, top["socket"]) if "socket" in top else None


def _parse_user(data: object) -> ClientConfig:
    r = Reader("broker client settings")
    top = r.mapping(
        data,
        "",
        {"version", "socket", "signing", "image_output_dir", "private_terms", "reply_seconds"},
        {"version"},
    )
    _version(r, top)
    signing = r.mapping(top.get("signing", {}), "signing", {"key", "principal"})
    key = _absolute(r, signing["key"], "signing.key") if "key" in signing else ""
    principal = r.string(signing["principal"], "signing.principal") if "principal" in signing else ""
    if principal and _PRINCIPAL.fullmatch(principal) is None:
        raise r.fail("signing.principal", "expected the label of an enrolled key, such as yubikey-a")
    terms = r.string(top.get("private_terms", "default"), "private_terms")
    if terms not in ("none", "default"):
        terms = _absolute(r, terms, "private_terms")
    seconds = top.get("reply_seconds", DEFAULT_REPLY_SECONDS)
    if type(seconds) not in (int, float) or not 10 <= seconds <= 900:
        raise r.fail("reply_seconds", "expected a number from 10 to 900")
    return ClientConfig(
        socket=_socket(r, top["socket"]) if "socket" in top else DEFAULT_SOCKET,
        signing_key=key,
        principal=principal,
        image_dir=_absolute(r, top["image_output_dir"], "image_output_dir") if "image_output_dir" in top else "",
        private_terms=terms,
        reply_seconds=float(seconds),
    )


def parse_user_config(text: str) -> ClientConfig:
    """The user's client settings from text, through the same strict parser `load_client_config` uses."""
    return _parse_user(_safe_load(text, "broker client"))


def load_client_config(
    *, home: Path, user_path: Path | None = None, root_path: Path = Path(ROOT_CONFIG), root_uid: int = BROKER_UID
) -> ClientConfig:
    """The client's settings: the user's file (private to the account), with the socket taken from the root-owned file
    when that exists. No environment variable is read, so nothing a wrapper strips can name the socket."""
    cfg = ClientConfig()
    where = user_path if user_path is not None else user_config_path(home)
    if os.path.lexists(where):
        cfg = parse_user_config(read_trusted_regular_file(where, 65_536).decode("utf-8", "replace"))
    if os.path.lexists(root_path):
        text = geminisign.read_trust_file(root_path, root_uid, "broker client settings").decode("utf-8", "replace")
        chosen = _parse_root(_safe_load(text, "broker client settings (root)"))
        if chosen is not None:
            cfg = dataclasses.replace(cfg, socket=chosen)
    return cfg


# -- the socket --------------------------------------------------------------------------------------------------------


class Channel(Protocol):
    def sendall(self, data: bytes, /) -> None: ...

    def recv(self, count: int, /) -> bytes: ...

    def settimeout(self, value: float | None, /) -> None: ...

    def close(self) -> None: ...


def connect_unix(path: str, *, owner: int = BROKER_UID, seconds: float = 10.0) -> socket.socket:
    """A connection to the broker's socket, but only to a socket owned by `owner`. The path is opened without following
    a link, judged on the descriptor, and connected through /proc/self/fd, so the thing checked is the thing connected
    to even if the path is swapped meanwhile. An account that is not `owner` cannot make such a socket."""
    if not path.startswith("/") or "\x00" in path:
        raise ClientError("the broker socket path must be absolute")
    try:
        fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise ClientError("the broker is not reachable (no socket); nothing was sent") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISSOCK(info.st_mode):
            raise ClientError("the broker path is not a socket; nothing was sent")
        if info.st_uid != owner:
            raise ClientError("the broker socket is not owned by the account that must own it; nothing was sent")
        if info.st_mode & stat.S_IWOTH:
            raise ClientError("the broker socket is writable by everyone; nothing was sent")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        try:
            sock.settimeout(seconds)
            sock.connect(f"/proc/self/fd/{fd}")
        except OSError:
            sock.close()
            raise ClientError("the broker is not reachable (nothing listens); nothing was sent") from None
        return sock
    finally:
        os.close(fd)


# -- the image writer --------------------------------------------------------------------------------------------------

ImageWriter = Callable[[bytes, str, str, int], str]


def sniff_image_type(data: bytes) -> str | None:
    """The type the first bytes name, and nothing else about the bytes: png, jpeg, webp or None."""
    if data.startswith(_PNG):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def _private_folder(directory: str) -> int:
    """A descriptor for the folder: absolute, not a link, ours, mode 0700 (nobody else can list or change it)."""
    if not directory.startswith("/") or "\x00" in directory:
        raise ClientError("the image folder must be an absolute path")
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise ClientError("the image folder cannot be opened (missing, a link, or no permission)") from None
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        raise ClientError("the image folder must be owned by this account and mode 0700")
    return fd


def check_image_dir(directory: str) -> None:
    os.close(_private_folder(directory))


def _write_new(directory: str, name: str, data: bytes) -> str:
    """Create `name` in the folder with O_EXCL and mode 0600, never overwriting, never following a link."""
    fd = _private_folder(directory)
    try:
        out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(out, view) :]
            os.fsync(out)
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(name, dir_fd=fd)
            raise
        finally:
            os.close(out)
    except FileExistsError:
        raise ClientError("a file with that name already exists; nothing was overwritten") from None
    except OSError:
        raise ClientError("the file could not be written") from None
    finally:
        os.close(fd)
    return os.path.join(directory, name)


def adapter_write_image(data: bytes, directory: str, stem: str, max_bytes: int) -> str:
    """ADAPTER, used only while `safo.broker.imagewrite` (phase 4a, #260) is not in the tree: the same signature as its
    `write_image`, and the same rules in a smaller form. Replace by deleting this function once 4a has merged."""
    kind = sniff_image_type(data)
    if kind is None or not 0 < len(data) <= max_bytes:
        raise ClientError("the image is empty, too large, or not a PNG, JPEG or WebP")
    clean = re.sub(r"[^A-Za-z0-9_-]", "_", stem)[:48].lstrip("-") or "image"
    return _write_new(directory, f"{clean}.{_EXTENSION[kind]}", data)


def adapter_write_sidecar(image_path: str, data: bytes) -> str:
    """The receipt file beside an image: `NAME.receipt.json`, exclusive and private like the image."""
    return _write_new(os.path.dirname(image_path), os.path.basename(image_path) + ".receipt.json", data)


def default_writer() -> ImageWriter:
    """`safo.broker.imagewrite.write_image` when phase 4a is in the tree, else the adapter above."""
    try:
        module = importlib.import_module("safo.broker.imagewrite")
    except ModuleNotFoundError as err:
        if err.name != "safo.broker.imagewrite":
            raise
        return adapter_write_image
    writer: ImageWriter = module.write_image
    return writer


def default_sidecar() -> Callable[[str, bytes], str]:
    """`safo.broker.imagewrite.write_receipt_file` (exclusive, mode 0600, `reviewed: false`, the image's directory
    rules); the adapter above stays only as a fallback and for tests."""
    try:
        module = importlib.import_module("safo.broker.imagewrite")
    except ModuleNotFoundError as err:
        if err.name != "safo.broker.imagewrite":
            raise
        return adapter_write_sidecar
    sidecar: Callable[[str, bytes], str] = module.write_receipt_file
    return sidecar


# -- the signer --------------------------------------------------------------------------------------------------------


def default_signer(cfg: ClientConfig, env: Mapping[str, str]) -> Callable[[bytes], str]:
    """`ssh-keygen -Y sign` in the approval namespace, by `geminisign.sign`: an absolute system binary, a fixed argument
    vector, no shell, the message on standard input, a small environment, and standard error left on the terminal so
    the key's touch prompt is seen."""
    if not cfg.signing_key:
        raise ClientError(SIGNING_MISSING)
    key = cfg.signing_key

    def sign(payload: bytes) -> str:
        return geminisign.sign(key, payload, geminisign.NAMESPACE, env)

    return sign


def default_dry_signer(cfg: ClientConfig, env: Mapping[str, str]) -> Callable[[bytes], str]:
    """The same signer in the dry-run namespace: a signature made for a dry run cannot approve a call, and the other
    way round."""
    if not cfg.signing_key:
        raise ClientError(SIGNING_MISSING)
    key = cfg.signing_key

    def sign(payload: bytes) -> str:
        return geminisign.sign(key, payload, geminisign.DRYRUN_NAMESPACE, env)

    return sign


def default_terms(cfg: ClientConfig, terms_path: Path) -> Callable[[str], None]:
    def check(text: str) -> None:
        terms = gemini.load_private_terms(cfg.private_terms, terms_path)
        if gemini.private_term_hit(terms, [text]):
            raise gemini.RefusedError("the prompt matches a private term, so nothing was sent")

    return check


# -- dependencies and parameters ---------------------------------------------------------------------------------------


@dataclasses.dataclass
class Deps:
    """Everything the flow touches outside itself, so a test can stand in for each: no clock, socket, key, terminal or
    folder is reached any other way."""

    connect: Callable[[], Channel]
    sign: Callable[[bytes], str]
    now: Callable[[], dt.datetime]
    mono: Callable[[], float]
    writer: ImageWriter
    sidecar: Callable[[str, bytes], str]
    check_dir: Callable[[str], None]
    terms: Callable[[str], None]
    confirm: Callable[[str], str]
    interactive: bool
    dry_sign: Callable[[bytes], str] | None = None  # the signer for the dry-run namespace; None where no key is set


@dataclasses.dataclass(frozen=True)
class PaidParams:
    model: str
    job: str
    kind: str
    prompt: str
    max_output_tokens: int
    max_usd: str
    quote: str
    quoted_at: str
    issue: str = ""
    count: int = 0
    image_size: str = ""
    aspect_ratio: str = ""


@dataclasses.dataclass(frozen=True)
class Checked:
    """The parameters after every check, in plain types: what the rest of the flow reads."""

    model: str
    job: str
    kind: str
    prompt: str
    digest: str
    size: int
    max_output_tokens: int
    max_micro: int
    quote: str
    quoted_at: str
    issue: str
    count: int
    image_size: str
    aspect_ratio: str

    def shape(self) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "model": self.model,
            "job": self.job,
            "kind": self.kind,
            "max_output_tokens": self.max_output_tokens,
        }
        if self.kind == "image":
            fields |= {"count": self.count, "image_size": self.image_size, "aspect_ratio": self.aspect_ratio}
        return fields


def check_params(p: PaidParams) -> Checked:
    """Refuse a bad name, amount, quote or image field before any socket is opened. The prompt is made into plain text
    once here (`canonical_request`), and everything later reads that copy."""
    if not gemini.MODEL_NAME.fullmatch(p.model):
        raise ClientError("the model is not a plain model name")
    if not gemini.JOB_NAME.fullmatch(p.job):
        raise ClientError("the job is a plain name (letters, digits, . _ -)")
    if p.kind not in ("text", "image"):
        raise ClientError("the kind is text or image")
    if type(p.max_output_tokens) is not int or not 1 <= p.max_output_tokens <= protocol.MAX_TOKENS:
        raise ClientError("the output limit is a whole number of tokens from 1 to 10000000")
    try:
        max_micro = parse_usd(p.max_usd)
    except MoneyError:
        raise ClientError("the maximum cost is whole dollars with up to six decimals, such as 2.5") from None
    if max_micro == 0:
        raise ClientError("the maximum cost must be more than zero")
    if type(p.quote) is not str or not gemini.valid_quote(p.quote):
        raise ClientError("the quote is one line of 1 to 500 characters with no control characters")
    if parse_stamp(p.quoted_at) is None:
        raise ClientError("the quote time is UTC, written YYYY-MM-DDTHH:MM:SSZ")
    if type(p.issue) is not str or len(p.issue) > 80 or not p.issue.isprintable():
        raise ClientError("the issue reference is at most 80 printable characters")
    if p.kind == "image":
        if type(p.count) is not int or not 1 <= p.count <= 16:
            raise ClientError("an image request names 1 to 16 images")
        if protocol.IMAGE_SIZE.fullmatch(p.image_size) is None or protocol.ASPECT.fullmatch(p.aspect_ratio) is None:
            raise ClientError("an image request names a size such as 1K and an aspect ratio such as 1:1")
    elif p.count or p.image_size or p.aspect_ratio:
        raise ClientError("a text request has no image count, size or aspect ratio")
    plain = gemini.canonical_request(
        gemini.Request(p.model, p.prompt, "paid", p.job, "", p.max_output_tokens)
    )  # a lone surrogate or a non-text prompt is refused here
    text = plain.prompt
    if not text.strip():
        raise ClientError("the prompt is empty")
    if len(text) > gemini.MAX_APPROVED_PROMPT_CHARS:
        raise gemini.RefusedError(gemini.too_long(len(text)))
    if gemini.has_secret_shape(text):
        raise gemini.RefusedError("the prompt holds something shaped like a secret or a private key; nothing was sent")
    digest, size = gemini.prompt_binding(text)
    return Checked(
        plain.model,
        plain.job,
        p.kind,
        text,
        digest,
        size,
        plain.max_output_tokens,
        max_micro,
        p.quote,
        p.quoted_at,
        p.issue,
        p.count,
        p.image_size,
        p.aspect_ratio,
    )


# -- the wire ----------------------------------------------------------------------------------------------------------


class _Lost(Exception):
    """The reply to a request did not arrive in a usable form. `reason` is one of a few fixed words."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclasses.dataclass
class Reply:
    body: dict[str, Any]
    attachments: list[bytes]
    problem: str | None = None  # the attachment frame did not arrive whole or did not match its description


def _recv_by(chan: Channel, end: float, mono: Callable[[], float]) -> Callable[[int], bytes]:
    def recv(count: int) -> bytes:
        left = end - mono()
        if left <= 0:
            raise _Lost("timeout")
        try:
            chan.settimeout(left)
            return chan.recv(count)
        except TimeoutError:
            raise _Lost("timeout") from None
        except OSError:
            raise _Lost("connection lost") from None

    return recv


def send_request(chan: Channel, body: bytes) -> None:
    try:
        framed = protocol.frame(body, protocol.MAX_REQUEST_FRAME)
    except ProtocolError:
        raise ClientError("the request is larger than the broker accepts; nothing was sent") from None
    try:
        chan.settimeout(SEND_SECONDS)
        chan.sendall(framed)
    except OSError:
        raise _Lost("connection lost") from None


def read_reply(chan: Channel, end: float, mono: Callable[[], float]) -> Reply:
    """Exactly one reply: a JSON frame, then the attachment frame the JSON names. A missing, cut, oversize or malformed
    JSON frame is `_Lost`. An attachment that fails is recorded in `problem`: the JSON (and its receipt) did arrive."""
    recv = _recv_by(chan, end, mono)
    try:
        body = protocol.read_frame(recv, protocol.MAX_REPLY_FRAME)
        data = protocol.parse_reply(body)
    except protocol.Truncated:
        raise _Lost("short reply") from None
    except ProtocolError as err:
        raise _Lost("oversize reply" if err.code == "too_large" else "malformed reply") from None
    frames: list[bytes] = []
    problem: str | None = None
    for item in data.get("attachments", []) if data["ok"] is True else []:
        try:
            part = protocol.read_frame(recv, item["bytes"])
        except (_Lost, ProtocolError):
            problem = "the attachment frame did not arrive whole"
            break
        if len(part) != item["bytes"] or hashlib.sha256(part).hexdigest() != item["sha256"]:
            problem = "the attachment did not match its description"
            break
        frames.append(part)
    return Reply(data, frames, problem)


# -- reading what the broker said --------------------------------------------------------------------------------------


def _usd(v: object) -> bool:
    return type(v) is str and protocol.USD.fullmatch(v) is not None


def _count(v: object) -> bool:
    return type(v) is int and 0 <= v <= 10**12


def _tokens(v: object) -> bool:
    return v is None or _count(v)  # the broker reports no figure when the vendor gave none


def _flag(v: object) -> bool:
    return type(v) is bool


def _description(v: object) -> bool:
    return (
        type(v) is dict
        and set(v) == {"index", "mime", "bytes", "sha256"}
        and type(v["index"]) is int
        and v["index"] == 0
        and v["mime"] in _KINDS.values()
        and type(v["bytes"]) is int
        and 1 <= v["bytes"] <= protocol.MAX_ATTACHMENT_FRAME
        and type(v["sha256"]) is str
        and protocol.SHA256.fullmatch(v["sha256"]) is not None
    )


def _images(v: object) -> bool:
    return type(v) is list and len(v) <= protocol.MAX_ATTACHMENTS and all(_description(x) for x in v)


def _hex(pattern: re.Pattern[str]) -> Callable[[object], bool]:
    return lambda v: type(v) is str and pattern.fullmatch(v) is not None


_RECEIPT: dict[str, Callable[[object], bool]] = {
    "call_id": _hex(re.compile(r"[0-9a-f]{16,64}")),
    "nonce": _hex(NONCE),
    "epoch": _hex(EPOCH),
    "model": _hex(gemini.MODEL_NAME),
    "kind": lambda v: v in ("text", "image") and type(v) is str,
    "count": lambda v: type(v) is int and 0 <= v <= 16,
    "image_size": lambda v: type(v) is str and re.fullmatch(r"[0-9A-Za-z]{0,8}", v) is not None,
    "prompt_sha256": _hex(protocol.SHA256),
    "tokens_in": _tokens,
    "tokens_out": _tokens,
    "reserved_usd": _usd,
    "actual_usd": _usd,
    "released_usd": _usd,
    "breach": _flag,
    "cap_breach": _flag,
    "estimated": _flag,
    "extra_images": lambda v: type(v) is int and 0 <= v <= 100,
    "images": _images,
    "month_spent_after": _usd,
    "ledger_head_after": _hex(HEAD),
    "broker_version": _hex(_VERSION),
    "ts": _hex(STAMP),
}


def valid_receipt(raw: object) -> dict[str, Any] | None:
    """The receipt when every field the client reads has the right shape, else None. Unknown extra fields are dropped,
    so nothing the broker adds can reach the screen."""
    if type(raw) is not dict:
        return None
    if not all(name in raw and check(raw[name]) for name, check in _RECEIPT.items()):
        return None
    return {name: raw[name] for name in _RECEIPT}


@dataclasses.dataclass(frozen=True)
class Offer:
    nonce: str
    epoch: str
    expires_at: dt.datetime
    ledger_head: str
    estimate_micro: int
    reserve_micro: int
    thinking_level: str
    beyond_ceiling: bool
    line: str


def parse_offer(body: Mapping[str, Any], max_micro: int) -> Offer:
    """The numbers the approval must carry, checked field by field. The worst case must fit what the person named."""
    bad = ClientError("the broker's offer is not well formed; nothing was signed")
    try:
        nonce, epoch, head, level = body["nonce"], body["epoch"], body["ledger_head"], body["thinking_level"]
        beyond, line = body["beyond_ceiling"], body.get("line", "")
        expires = parse_stamp(body["expires_at"])
        estimate, reserve = parse_usd(body["estimate_usd"]), parse_usd(body["reserve_usd"])
    except (KeyError, MoneyError):
        raise bad from None
    if not (
        _hex(NONCE)(nonce)
        and _hex(EPOCH)(epoch)
        and _hex(HEAD)(head)
        and _hex(_LEVEL)(level)
        and type(beyond) is bool
        and expires is not None
    ):
        raise bad
    if reserve > max_micro:
        raise ClientError("the broker's worst case is over the amount you named; nothing was signed")
    safe = line if type(line) is str and _SAFE_LINE.fullmatch(line) else ""
    return Offer(nonce, epoch, expires, head, estimate, reserve, level, beyond, safe)


# -- what is shown -----------------------------------------------------------------------------------------------------


def say(stream: TextIO, text: str) -> None:
    output.write(stream, text)


def build_payload(c: Checked, offer: Offer, principal: str, now: dt.datetime) -> str:
    """The canonical text that is signed. The expiry is the offer's, or ten minutes, whichever is sooner."""
    created = now.replace(microsecond=0)
    expires = min(created + APPROVAL_TTL, offer.expires_at)
    if expires <= created:
        raise ClientError("the broker's offer has expired; nothing was signed, start again")
    data: dict[str, Any] = {
        "version": 3,
        "nonce": offer.nonce,
        "epoch": offer.epoch,
        "model": c.model,
        "kind": c.kind,
        "max_output_tokens": c.max_output_tokens,
        "thinking_level": offer.thinking_level,
        "max_usd": format_usd(c.max_micro),
        "job": c.job,
        "prompt_sha256": c.digest,
        "prompt_bytes": c.size,
        "quote": c.quote,
        "quoted_at": c.quoted_at,
        "created": gemini.stamp(created),
        "expires_at": gemini.stamp(expires),
        "beyond_ceiling": offer.beyond_ceiling,
        "ledger_head": offer.ledger_head,
        "issue": c.issue,
        "principal": principal,
    }
    if c.kind == "image":
        data |= {"count": c.count, "image_size": c.image_size, "aspect_ratio": c.aspect_ratio}
    text = geminisign.canonical(data)
    try:
        parse_approval(text)  # the broker's own parser must accept what is about to be signed
    except Refused:
        raise ClientError("the approval text would not be accepted by the broker; nothing was signed") from None
    return text


def show_approval(out: TextIO, text: str, c: Checked, offer: Offer) -> None:
    """The approval screen, rendered from the SIGNED text itself: every field, then the cost, the digest and the whole
    prompt. A field cannot be signed without being listed, because the list is made from the signed text."""
    signed = loads(text)
    if offer.line:
        say(out, offer.line)
    rows = ["the approval you are about to sign (every line below is part of the signature):"]
    for name in sorted(signed):
        value = signed[name]
        rows.append(f"  {name}: {value if isinstance(value, str) else json.dumps(value)}")
    rows.append(f"quote of his message ({c.quoted_at}): {c.quote}")
    output.block(out, rows)  # verbatim (no `::` rewriting): the person must see exactly what is signed
    say(
        out,
        f"cost: typical estimate {format_usd(offer.estimate_micro)} USD, "
        f"worst case {format_usd(offer.reserve_micro)} USD (what the caps check), "
        f"you approve up to {format_usd(c.max_micro)} USD",
    )
    say(out, f"prompt: {len(c.prompt)} characters, {c.size} bytes, SHA-256 {c.digest}")
    say(out, "--- the WHOLE prompt starts (line by line; non-ASCII and control characters are escaped) ---")
    output.block(out, [f"{number:4d}| {row!a}" for number, row in enumerate(c.prompt.split("\n"), 1)])
    say(out, "--- the prompt ends ---")
    say(
        out,
        f"you are approving up to {format_usd(c.max_micro)} USD on {c.model} for job {c.job}"
        + (" and it PASSES the monthly ceiling" if offer.beyond_ceiling else ""),
    )
    say(
        out,
        "your security key will blink next. Touch it only because you have just read every field, the cost, the whole "
        "prompt and its digest above and they are right; the signature covers that exact text and no other. "
        "If you did not start this, do not touch it.",
    )


def _figure(value: int | None) -> str:
    return "unknown" if value is None else str(value)


def receipt_lines(r: Mapping[str, Any]) -> list[str]:
    lines = [
        f"receipt: call {r['call_id']} model {r['model']} reserved {r['reserved_usd']} USD "
        f"actual {r['actual_usd']} USD released {r['released_usd']} USD",
        f"tokens: {_figure(r['tokens_in'])} in, {_figure(r['tokens_out'])} out",
        f"month: {r['month_spent_after']} USD used after this call",
    ]
    if r["breach"] or r["cap_breach"]:
        lines.append("note: the cost passed the reservation or the output cap; the broker stopped this model")
    if r["estimated"]:
        lines.append("note: the cost is an estimate (the vendor's usage figures were missing or implausible)")
    if r["extra_images"]:
        lines.append(f"note: the broker dropped {r['extra_images']} extra images")
    return lines


# -- the call ----------------------------------------------------------------------------------------------------------

_NOTES = {
    "rate_limited": "the vendor refused the call as rate limited; the broker records no charge, see the receipt below",
    "vendor_refused": "the vendor refused the call; the broker records the cost its usage figures show, if any",
    "outcome_unknown": (
        "the request may have reached the vendor and its result is unknown; the broker counted the full reservation as "
        "spent and this model is stopped until root clears it"
    ),
    "internal": "the broker failed after it accepted the call; its ledger holds the real state",
}
_CHARGE_CODES = frozenset(_NOTES)


@dataclasses.dataclass(frozen=True)
class Want:
    """What a reply to this request must say about itself."""

    nonce: str
    epoch: str
    model: str
    kind: str
    count: int
    image_size: str
    digest: str


def belongs(r: Mapping[str, Any], want: Want) -> bool:
    return (
        gemini.digests_equal(r["prompt_sha256"], want.digest)
        and r["nonce"] == want.nonce
        and r["epoch"] == want.epoch
        and r["model"] == want.model
        and r["kind"] == want.kind
        and r["count"] == want.count
        and r["image_size"] == want.image_size
    )


def _unknown(err: TextIO, want: Want, why: str) -> int:
    say(err, f"{why}. {CHARGED}: the request had been sent when this happened. {NO_FALLBACK}.")
    say(
        err,
        f"to check: nonce {want.nonce[:8]}, prompt SHA-256 {want.digest}; "
        "see the vendor billing page and the broker ledger",
    )
    return EXIT_UNKNOWN_OUTCOME


def _failure(err: TextIO, reply: Reply, want: Want) -> int:
    code = reply.body["code"]
    status, sentence = protocol.REPLY_CODES[code]
    if code not in _CHARGE_CODES:
        say(err, f"{code}: {sentence}")
        say(err, "no receipt was issued: the broker refused this before any vendor call")
        say(err, NO_FALLBACK)
        return status
    raw = reply.body.get("receipt")
    r = valid_receipt(raw)
    if raw is not None and (r is None or not belongs(r, want)):
        return _unknown(err, want, "the reply does not belong to this request and was discarded")
    say(err, f"{code}: {sentence}")
    say(err, f"{CHARGED}: {_NOTES[code]}")
    if r is None:
        say(err, "no receipt arrived; the broker ledger and the vendor billing page say what was charged")
    else:
        for line in receipt_lines(r):
            say(err, line)
    hint = reply.body.get("retry_after")
    if (
        code == "rate_limited" and type(hint) is int
    ):  # the shared parser already refuses a hint that is not an int from 0 to 86400
        say(err, f"retry hint from the vendor: {hint} seconds (information only; nothing was repeated)")
    say(err, NO_FALLBACK)
    return status


class _NotSaved(Exception):
    pass


def _success(out: TextIO, err: TextIO, reply: Reply, want: Want, c: Checked, cfg: ClientConfig, deps: Deps) -> int:
    text = reply.body.get("text")
    described = reply.body.get("attachments", [])
    r = valid_receipt(reply.body.get("receipt"))
    if (
        r is None
        or type(text) is not str
        or not belongs(r, want)
        or (want.kind == "text" and (described or r["images"]))
        or (want.kind == "image" and described and r["images"] != described)
    ):
        return _unknown(err, want, "the reply does not belong to this request and was discarded")
    if want.kind == "text":
        output.block(out, text.splitlines() or [""])
        for line in receipt_lines(r):
            say(out, line)
        return EXIT_OK
    if text:
        output.block(out, text.splitlines())
    try:
        _save_image(out, err, reply, r, c, cfg, deps)
    except _NotSaved as why:
        for line in receipt_lines(r):
            say(err, line)
        say(err, f"{CHARGED}: the image was NOT saved ({why}).")
        if described:
            say(err, f"image: {described[0]['bytes']} bytes, sha256 {described[0]['sha256']}")
        return EXIT_UNKNOWN_OUTCOME
    for line in receipt_lines(r):
        say(out, line)
    return EXIT_OK


def _save_image(
    out: TextIO, err: TextIO, reply: Reply, r: Mapping[str, Any], c: Checked, cfg: ClientConfig, deps: Deps
) -> None:
    if reply.problem is not None:
        raise _NotSaved(reply.problem)
    if not reply.attachments:
        raise _NotSaved("the reply carried no image")
    data = reply.attachments[0]
    described = reply.body["attachments"][0]
    kind = sniff_image_type(data)
    if kind is None or _KINDS[kind] != described["mime"]:
        raise _NotSaved("the bytes are not the type the broker named")
    if (
        hashlib.sha256(data).hexdigest() != described["sha256"]
    ):  # the receipt's digest, checked again just before writing
        raise _NotSaved("the bytes do not match the digest in the receipt")
    stamp = deps.now().astimezone(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    stem = f"{stamp}-{c.job}-{r['nonce'][:8]}-{described['index']}"
    try:
        path = deps.writer(data, cfg.image_dir, stem, protocol.MAX_ATTACHMENT_FRAME)
    except (SafoError, OSError, ValueError):
        raise _NotSaved("the folder refused it") from None
    say(out, f"image: {path} ({len(data)} bytes, type {kind})")
    side = json.dumps(
        {"reviewed": False, "job": c.job, "receipt": r, "image": described}, sort_keys=True, indent=2
    ).encode("ascii")
    try:
        say(out, f"receipt file: {deps.sidecar(path, side)}")
    except (SafoError, OSError, ValueError):
        say(err, "warning: the receipt file was not written (the image is saved)")


def _open(deps: Deps, nothing: str) -> Channel:
    try:
        return deps.connect()
    except ClientError:
        raise
    except OSError:
        raise ClientError(f"the broker is not reachable; {nothing} and the free tier was not used") from None


def _body(op: str, **fields: Any) -> bytes:
    try:
        return protocol.request_body(op, **fields)
    except ProtocolError:
        raise ClientError("the request is not one the broker's wire format allows; nothing was sent") from None


def _begin(c: Checked, deps: Deps) -> Offer:
    body = _body("begin", prompt_bytes=c.size, max_usd=format_usd(c.max_micro), **c.shape())
    chan = _open(deps, "nothing was sent")
    begun = deps.mono()
    try:
        try:
            send_request(chan, body)
            reply = read_reply(chan, begun + BEGIN_SECONDS, deps.mono)
        except (_Lost, KeyboardInterrupt):
            raise ClientError("no usable reply to begin arrived; nothing was spent, nothing was signed") from None
    finally:
        chan.close()
    if reply.body["ok"] is not True:
        code = reply.body["code"]
        status, sentence = protocol.REPLY_CODES[code]
        raise ClientError(f"{code}: {sentence}; nothing was spent and the free tier was not used", status)
    if "attachments" in reply.body:
        raise ClientError("the broker's offer is not well formed; nothing was signed")
    return parse_offer(reply.body, c.max_micro)


class _Unknown(Exception):
    """The call request may have left and no usable reply came back. Never retried."""


@dataclasses.dataclass
class _Progress:
    """How far a call got, so an unexpected failure is reported as what it is: nothing sent, or possibly charged."""

    want: Want | None = None
    connected: bool = False


def _call(c: Checked, approval: dict[str, str], cfg: ClientConfig, deps: Deps, progress: _Progress) -> Reply:
    body = _body("call", prompt=c.prompt, approval=approval, **c.shape())
    chan = _open(deps, "nothing was sent (the signed approval is unused)")
    progress.connected = True  # from here on the request may have left
    begun = deps.mono()  # the wait covers the send as well as the reply
    try:
        send_request(chan, body)
        return read_reply(chan, begun + cfg.reply_seconds, deps.mono)
    except _Lost as lost:
        raise _Unknown(lost.reason) from None
    except KeyboardInterrupt:
        raise _Unknown("interrupted") from None
    finally:
        chan.close()


def run_paid(params: PaidParams, cfg: ClientConfig, deps: Deps, out: TextIO, err: TextIO) -> int:
    """One paid call, start to finish. Returns the exit status; nothing is retried and no other tier is tried."""
    progress = _Progress()
    try:
        return _run(params, cfg, deps, out, err, progress)
    except SafoError as problem:
        say(err, f"error: {problem}")
        return problem.exit_code
    except KeyboardInterrupt:
        if progress.connected and progress.want is not None:
            return _unknown(err, progress.want, "the client was interrupted after the request was sent")
        say(err, "interrupted; nothing was sent")
        return EXIT_INTERRUPTED
    except Exception as failure:  # a bug: say only its class, never its text (which could quote the prompt)
        if progress.connected and progress.want is not None:
            why = f"the client failed after the request was sent ({type(failure).__name__})"
            return _unknown(err, progress.want, why)
        say(err, f"error: the client failed ({type(failure).__name__}); nothing was sent")
        return EXIT_REFUSED


def _run(params: PaidParams, cfg: ClientConfig, deps: Deps, out: TextIO, err: TextIO, progress: _Progress) -> int:
    c = check_params(params)
    if not cfg.signing_key or not cfg.principal:
        raise ClientError(SIGNING_MISSING)
    if c.kind == "image":
        if not cfg.image_dir:
            raise ClientError(
                "image_output_dir is not set in broker-client.yaml, so there is nowhere to write the image"
            )
        deps.check_dir(cfg.image_dir)  # before the call is asked for: a full disk must not discard a paid image
    if not deps.interactive:
        raise ClientError("approval needs a person at a terminal: standard input and output must both be one")
    deps.terms(c.prompt)
    offer = _begin(c, deps)
    text = build_payload(c, offer, cfg.principal, gemini.plain_time(deps.now(), "now"))
    show_approval(out, text, c, offer)
    if (
        deps.confirm(f"type exactly `approve {c.job}` to approve, anything else cancels: ").strip()
        != f"approve {c.job}"
    ):
        raise ClientError("not confirmed; nothing was signed and nothing was sent")
    try:
        armor = deps.sign(text.encode("ascii"))
        if (
            type(armor) is not str
            or not armor.isascii()
            or len(armor) > geminisign.SIGNATURE_BYTES
            or geminisign.parse_signature(armor).namespace != geminisign.NAMESPACE
        ):
            raise ClientError("the signer returned something that is not an approval signature")
    except ClientError:
        raise
    except (SafoError, OSError, ValueError):
        raise ClientError(
            "the security key did not sign (not attached, not touched in time, or cancelled); nothing was sent"
        ) from None
    if gemini.plain_time(deps.now(), "now") >= parse_approval(text).expires_at:
        raise ClientError("the approval expired before it could be sent; nothing was sent, start again")
    deps.terms(c.prompt)  # again, on the same bytes, just before they leave
    want = Want(offer.nonce, offer.epoch, c.model, c.kind, c.count, c.image_size, c.digest)
    progress.want = want
    try:
        reply = _call(c, {"payload": text, "signature": armor}, cfg, deps, progress)
    except _Unknown as lost:
        return _unknown(err, want, f"no usable reply arrived after the request was sent ({lost})")
    if reply.body["ok"] is True:
        return _success(out, err, reply, want, c, cfg, deps)
    return _failure(err, reply, want)


# -- the dry run -------------------------------------------------------------------------------------------------------

DRYRUN_JOB = re.compile(r"[A-Za-z0-9._-]{1,64}")
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")


def _dryrun_answer(body: Mapping[str, Any]) -> dict[str, Any] | None:
    """The broker's dry-run answer, or None when it is not exactly the shape the broker sends."""
    if set(body) != {"v", "ok", "principal", "fingerprint", "hardware", "touch", "pin", "enabled"}:
        return None
    if type(body["principal"]) is not str or _PRINCIPAL.fullmatch(body["principal"]) is None:
        return None
    if type(body["fingerprint"]) is not str or _FINGERPRINT.fullmatch(body["fingerprint"]) is None:
        return None
    if any(type(body[k]) is not bool for k in ("hardware", "touch", "pin", "enabled")):
        return None
    return dict(body)


def run_dryrun(cfg: ClientConfig, deps: Deps, out: TextIO, err: TextIO, job: str = "signer-check") -> int:
    """Test the whole signing chain against the broker without a call, a reservation or a charge: sign one throw-away
    text in the dry-run namespace (a touch), send it with the `dryrun` operation and print what the broker made of it.
    The broker spends and records nothing, and a dry-run signature cannot approve a call."""
    try:
        if DRYRUN_JOB.fullmatch(job) is None:
            raise ClientError("the job is a plain name (letters, digits, . _ -)")
        if not cfg.signing_key or not cfg.principal or deps.dry_sign is None:
            raise ClientError(SIGNING_MISSING)
        if not deps.interactive:
            raise ClientError("the dry run needs a person at a terminal: standard input and output must both be one")
        text = geminisign.canonical({"dry_run": True, "job": job})
        say(out, f"dry run: you are about to sign this throw-away text, which approves nothing: {text}")
        phrase = f"dryrun {job}"
        if deps.confirm(f"type exactly `{phrase}` to continue, anything else cancels: ").strip() != phrase:
            raise ClientError("not confirmed; nothing was signed")
        try:
            armor = deps.dry_sign(text.encode("ascii"))
            if (
                type(armor) is not str
                or not armor.isascii()
                or len(armor) > geminisign.SIGNATURE_BYTES
                or geminisign.parse_signature(armor).namespace != geminisign.DRYRUN_NAMESPACE
            ):
                raise ClientError("the signer returned something that is not a dry-run signature")
        except ClientError:
            raise
        except (SafoError, OSError, ValueError):
            raise ClientError(
                "the security key did not sign (not attached, not touched in time, or cancelled)"
            ) from None
        body = _body("dryrun", approval={"payload": text, "signature": armor})
        chan = _open(deps, "nothing was signed for a call")
        begun = deps.mono()
        try:
            try:
                send_request(chan, body)
                reply = read_reply(chan, begun + BEGIN_SECONDS, deps.mono)
            except (_Lost, KeyboardInterrupt):
                raise ClientError("no usable reply to the dry run arrived; nothing was spent") from None
        finally:
            chan.close()
        if reply.body["ok"] is not True:
            code = reply.body["code"]
            status, sentence = protocol.REPLY_CODES[code]
            raise ClientError(f"{code}: {sentence}; nothing was spent", status)
        answer = _dryrun_answer(reply.body)
        if answer is None:
            raise ClientError("the broker's dry-run answer is not well formed")
        say(
            out,
            f"dry run: the broker verified the signature. principal {answer['principal']}, {answer['fingerprint']}, "
            f"{'hardware key' if answer['hardware'] else 'SOFTWARE key'}, "
            f"touch {'seen' if answer['touch'] else 'not shown'}, PIN {'seen' if answer['pin'] else 'not shown'}.",
        )
        say(
            out,
            "paid use is enabled in the broker"
            if answer["enabled"]
            else "paid use is DISABLED in the broker (the switch)",
        )
        say(out, "No call was made, nothing was reserved or spent, and no approval was recorded.")
        return EXIT_OK
    except SafoError as problem:
        say(err, f"error: {problem}")
        return problem.exit_code
    except KeyboardInterrupt:
        say(err, "interrupted; nothing was spent")
        return EXIT_INTERRUPTED


# -- the command line --------------------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -I -m safo.broker.client",
        description="Ask the paid Gemini broker for one call: shows the whole approval, asks for the touch, sends once",
        allow_abbrev=False,
    )
    add = parser.add_argument
    add("--model", required=True)
    add("--job", required=True, help="the job name an approval is for")
    add("--kind", choices=["text", "image"], default="text")
    add("--prompt-file", required=True, help="the prompt, from a file (never argv)")
    add("--max-output-tokens", type=int, required=True, help="a hard output limit, part of the signed text")
    add("--max-usd", required=True, help="the most this call may cost, part of the signed text")
    add("--quote", required=True, help="the maintainer's message, as he wrote it")
    add("--quoted-at", required=True, help="when he wrote it, UTC, YYYY-MM-DDTHH:MM:SSZ")
    add("--issue", default="", help="the tracking issue, owner/repo#N")
    add("--count", type=int, default=None, help="image: how many images (default 1)")
    add("--image-size", default="", help="image: the size, such as 1K")
    add("--aspect-ratio", default="", help="image: the ratio, such as 1:1 (default 1:1)")
    return parser


def _prompt(path: str) -> str:
    try:
        raw = read_bounded(Path(path), protocol.MAX_PROMPT_BYTES + 1)
    except OSError:
        raise ClientError("cannot read the prompt file") from None
    if len(raw) > protocol.MAX_PROMPT_BYTES:
        raise ClientError(f"the prompt file is larger than {protocol.MAX_PROMPT_BYTES} bytes; cut it down")
    try:
        return raw.decode("utf-8")
    except UnicodeError:
        raise ClientError("the prompt file is not UTF-8 text") from None


def _tty(stream: object) -> bool:
    check = getattr(stream, "isatty", None)
    try:
        return bool(check()) if callable(check) else False
    except (OSError, ValueError):
        return False


def default_deps(cfg: ClientConfig, env: Mapping[str, str], stdin: TextIO, out: TextIO, home: Path) -> Deps:
    def confirm(prompt: str) -> str:
        say(out, prompt)
        return stdin.readline()

    return Deps(
        connect=lambda: connect_unix(cfg.socket),
        sign=default_signer(cfg, env),
        dry_sign=default_dry_signer(cfg, env),
        now=lambda: dt.datetime.now(dt.UTC),
        mono=time.monotonic,
        writer=default_writer(),
        sidecar=default_sidecar(),
        check_dir=check_image_dir,
        terms=default_terms(cfg, home / ".config" / "safo" / "privacy-terms.txt"),
        confirm=confirm,
        interactive=_tty(stdin) and _tty(out),
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    stdin: TextIO | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
    deps: Deps | None = None,
    cfg: ClientConfig | None = None,
) -> int:
    env = os.environ if env is None else env
    stdin, out, err = stdin or sys.stdin, out or sys.stdout, err or sys.stderr
    args = build_parser().parse_args(argv)
    try:
        if args.kind == "text" and (args.count is not None or args.image_size or args.aspect_ratio):
            raise ClientError("a text request has no image count, size or aspect ratio")
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)  # the account database: $HOME is the caller's to set
        settings = cfg if cfg is not None else load_client_config(home=home)
        wired = deps if deps is not None else default_deps(settings, env, stdin, out, home)
        image = args.kind == "image"
        params = PaidParams(
            model=args.model,
            job=args.job,
            kind=args.kind,
            prompt=_prompt(args.prompt_file),
            max_output_tokens=args.max_output_tokens,
            max_usd=args.max_usd,
            quote=args.quote,
            quoted_at=args.quoted_at,
            issue=args.issue,
            count=(1 if args.count is None else args.count) if image else 0,
            image_size=args.image_size,
            aspect_ratio=(args.aspect_ratio or "1:1") if image else "",
        )
    except SafoError as problem:
        say(err, f"error: {problem}")
        return problem.exit_code
    return run_paid(params, settings, wired, out, err)


if __name__ == "__main__":
    raise SystemExit(main())
