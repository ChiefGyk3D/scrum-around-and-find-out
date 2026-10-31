# SPDX-License-Identifier: Apache-2.0
"""The broker's wire format, version 1 (docs/gemini-broker.md, "The socket protocol").

This module is shared by the server and by the thin client, and is written so a client can import it unchanged: the
standard library and `safo.bounded` (the repository's hostile-input JSON loader) are the only imports, and it opens no
socket, reads no clock, no file and no environment. The client and the server cannot disagree about a frame, a field
table or a reply code, because both read them here.

* A frame is a 4-byte big-endian length `N` followed by `N` bytes. A request is exactly one frame of `1..1 MiB`; a
  reply is one JSON frame of `1..256 KiB`, then one attachment frame (`1..24 MiB`) for each attachment the JSON names.
* A request is a JSON object parsed by the bounded loader (size and depth limits, no duplicate key, no NaN), carrying
  `"v": 1` and an `"op"`. A version that is not 1 is `unsupported_version`. An unknown key, a missing key, a value of
  the wrong type or shape, or a key that does not belong to the operation is `bad_request`: nothing is ignored.
* A reply is `{"v": 1, "ok": true, ...}` or `{"v": 1, "ok": false, "code": CODE, "message": TEXT, "exit": N}`. The
  message is one fixed sentence per code and never echoes anything a client sent.

Nothing here puts client text into an error: a `ProtocolError` carries a reply code and nothing else.
"""

from __future__ import annotations

import json
import re
import struct
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from safo.bounded import loads

VERSION = 1
SUPPORTED = (1,)

HEADER = struct.Struct(">I")
MAX_REQUEST_FRAME = 1_048_576  # 1 MiB
MAX_REPLY_FRAME = 262_144  # 256 KiB, the JSON frame of a reply
MAX_ATTACHMENT_FRAME = 25_165_824  # 24 MiB, one image
MAX_ATTACHMENTS = 1  # decision 7: one image per call
READ_CHUNK = 65_536

MAX_PROMPT_BYTES = 200_000  # the limit the wrapper has today; repeated here so this module needs nothing else
MAX_APPROVAL_TEXT = 16_384  # the signed text (records.MAX_APPROVAL_BYTES)
MAX_SIGNATURE_TEXT = 4_096  # the signature armor (geminisign.SIGNATURE_BYTES)
MAX_TOKENS = 10_000_000

# the patterns the signed approval uses for names (safo.gemini.MODEL_NAME and JOB_NAME), kept equal by a test
MODEL_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
JOB_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}")
NONCE = re.compile(r"[0-9a-f]{16,64}")
IMAGE_SIZE = re.compile(r"[0-9A-Za-z]{1,8}")
ASPECT = re.compile(r"[0-9]{1,2}:[0-9]{1,2}")
USD = re.compile(r"(0|[1-9][0-9]{0,8})(?:\.[0-9]{1,6})?")
SHA256 = re.compile(r"[0-9a-f]{64}")
MIME = re.compile(r"[a-z]{1,16}/[a-z0-9.+-]{1,32}")

# -- reply codes ---------------------------------------------------------------------------------------------------

# code -> (exit status, the one sentence). The sentences are fixed: no client string, prompt, vendor text or key.
REPLY_CODES: dict[str, tuple[int, str]] = {
    "bad_request": (2, "the request is not well formed"),
    "too_large": (2, "the request is larger than the broker accepts"),
    "unsupported_version": (2, "the broker does not speak this protocol version"),
    "unauthorized_peer": (2, "this account may not use the broker"),
    "disabled": (2, "paid use is disabled by the root-owned switch"),
    "bad_approval": (2, "the approval is not valid for this request"),
    "revoked": (2, "the key that signed this approval has been revoked"),
    "expired": (2, "the approval has expired; ask for a fresh one"),
    "used": (2, "this approval has already been used"),
    "digest_mismatch": (2, "the prompt is not the one the approval covers"),
    "model_mismatch": (2, "the model is not the one the approval covers"),
    "job_mismatch": (2, "the job is not the one the approval covers"),
    "over_job_cap": (2, "the worst case is over the per-job cap"),
    "over_approved": (2, "the worst case is over the approved maximum"),
    "needs_block_approval": (2, "this call needs an approval that covers the monthly ceiling"),
    "month_cap": (2, "the monthly cap stops this call"),
    "model_suspended": (2, "this model is stopped until root clears it"),
    "model_refused": (2, "the broker will not call this model"),
    "prices_expired": (2, "the broker's price table has expired"),
    "busy": (2, "the broker is busy or a rate limit applies; try again later"),
    "rate_limited": (3, "the vendor refused the call as rate limited; it is final and was not repeated"),
    "vendor_refused": (2, "the vendor refused the call; it was not repeated"),
    "outcome_unknown": (4, "the call may have been billed and its result is unknown; it was not repeated"),
    "internal": (4, "the broker failed; the call state is in the broker ledger"),
}

# the three codes a finished call returns beyond `ok` (CallResult.code); the reply carries the receipt for each
CALL_CODES = ("rate_limited", "vendor_refused", "outcome_unknown")


class ProtocolError(Exception):
    """A frame or message is refused. It holds a reply code and nothing else: no text of the input."""

    def __init__(self, code: str) -> None:
        if code not in REPLY_CODES:
            raise ValueError("unknown reply code")
        super().__init__(code)
        self.code = code


class Truncated(ProtocolError):
    """The peer closed in the middle of a frame (or before one)."""

    def __init__(self) -> None:
        super().__init__("bad_request")


# -- frames --------------------------------------------------------------------------------------------------------

Recv = Callable[[int], bytes]


def frame(body: bytes, limit: int) -> bytes:
    """`body` with its length prefix, or `too_large`/`bad_request`. A frame is never empty."""
    if type(body) is not bytes or len(body) == 0:
        raise ProtocolError("bad_request")
    if len(body) > limit:
        raise ProtocolError("too_large")
    return HEADER.pack(len(body)) + body


def _read_exact(recv: Recv, count: int) -> bytes:
    parts: list[bytes] = []
    left = count
    while left:
        chunk = recv(min(READ_CHUNK, left))
        if type(chunk) is not bytes or len(chunk) > left:
            raise ProtocolError("bad_request")
        if not chunk:
            raise Truncated
        parts.append(chunk)
        left -= len(chunk)
    return b"".join(parts)


def read_frame(recv: Recv, limit: int) -> bytes:
    """One frame from `recv` (which returns up to n bytes, and b"" at end of stream). A declared length over `limit` is
    refused without reading the body; a zero length is refused; a stream that ends early is `Truncated`."""
    (length,) = HEADER.unpack(_read_exact(recv, HEADER.size))
    if length > limit:
        raise ProtocolError("too_large")
    if length == 0:
        raise ProtocolError("bad_request")
    return _read_exact(recv, length)


# -- requests ------------------------------------------------------------------------------------------------------

_IMAGE_ONLY = ("count", "image_size", "aspect_ratio")
_SHAPE = ("model", "job", "kind", "max_output_tokens")


@dataclass(frozen=True)
class Operation:
    required: tuple[str, ...]
    optional: tuple[str, ...] = ()  # for `kind` = `image`, the image fields below are required; for `text`, absent


OPERATIONS: dict[str, Operation] = {
    "status": Operation(()),
    "begin": Operation((*_SHAPE, "prompt_bytes", "max_usd"), _IMAGE_ONLY),
    "call": Operation((*_SHAPE, "prompt", "approval"), _IMAGE_ONLY),
    "check": Operation(("nonce",)),
    "dryrun": Operation(("approval",)),
}
SHAPED = ("begin", "call")  # the operations whose image fields depend on `kind`


@dataclass(frozen=True)
class Request:
    op: str
    fields: dict[str, Any]


def _is_int(value: object, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def _matches(value: object, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _text(value: object, limit: int, *, codec: str) -> bool:
    """A plain string of at most `limit` bytes that encodes (no lone surrogate, and ASCII where the codec says so)."""
    if type(value) is not str:
        return False
    try:
        return 0 < len(value.encode(codec)) <= limit
    except UnicodeError:
        return False


def _approval(value: object) -> bool:
    return (
        type(value) is dict
        and set(value) == {"payload", "signature"}
        and _text(value["payload"], MAX_APPROVAL_TEXT, codec="ascii")
        and _text(value["signature"], MAX_SIGNATURE_TEXT, codec="ascii")
    )


_CHECKS: dict[str, Callable[[object], bool]] = {
    "model": lambda v: _matches(v, MODEL_NAME),
    "job": lambda v: _matches(v, JOB_NAME),
    "kind": lambda v: v in ("text", "image") and type(v) is str,
    "max_output_tokens": lambda v: _is_int(v, 1, MAX_TOKENS),
    "prompt_bytes": lambda v: _is_int(v, 0, MAX_PROMPT_BYTES),
    "max_usd": lambda v: _matches(v, USD),
    "count": lambda v: _is_int(v, 1, 16),
    "image_size": lambda v: _matches(v, IMAGE_SIZE),
    "aspect_ratio": lambda v: _matches(v, ASPECT),
    "prompt": lambda v: _text(v, MAX_PROMPT_BYTES, codec="utf-8"),
    "approval": _approval,
    "nonce": lambda v: _matches(v, NONCE),
}


def parse_request(body: bytes) -> Request:
    """The request in `body`, or a `ProtocolError`. Strict: see the module text. Nothing is changed or defaulted."""
    if type(body) is not bytes:
        raise ProtocolError("bad_request")
    if len(body) > MAX_REQUEST_FRAME:
        raise ProtocolError("too_large")
    try:
        data = loads(body)
    except (ValueError, RecursionError):  # includes bad UTF-8, a duplicate key, NaN, depth, size
        raise ProtocolError("bad_request") from None
    if type(data) is not dict:
        raise ProtocolError("bad_request")
    version = data.get("v")
    if type(version) is not int:
        raise ProtocolError("bad_request")
    if version not in SUPPORTED:
        raise ProtocolError("unsupported_version")
    op = data.get("op")
    if type(op) is not str or op not in OPERATIONS:
        raise ProtocolError("bad_request")
    spec = OPERATIONS[op]
    fields = {k: v for k, v in data.items() if k not in ("v", "op")}
    wanted = set(spec.required)
    if op in SHAPED:
        kind = fields.get("kind")
        if kind == "image" and type(kind) is str:
            wanted |= set(_IMAGE_ONLY)
    if set(fields) != wanted:
        raise ProtocolError("bad_request")
    for name, value in fields.items():
        if not _CHECKS[name](value):
            raise ProtocolError("bad_request")
    return Request(op, fields)


def request_body(op: str, **fields: Any) -> bytes:
    """What a client sends: the JSON body of a request, validated by the same parser the server uses."""
    body = json.dumps(
        {"v": VERSION, "op": op, **fields}, ensure_ascii=True, separators=(",", ":"), sort_keys=True, allow_nan=False
    ).encode("ascii")
    parse_request(body)
    return body


# -- replies -------------------------------------------------------------------------------------------------------


def _dump(data: Mapping[str, Any]) -> bytes:
    body = json.dumps(data, ensure_ascii=True, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("ascii")
    if len(body) > MAX_REPLY_FRAME:
        raise ProtocolError("too_large")
    return body


def ok_body(fields: Mapping[str, Any]) -> bytes:
    """A success reply. `ProtocolError("too_large")` when it would not fit the reply frame."""
    if {"v", "ok", "code", "message", "exit"} & set(fields):
        raise ValueError("a success reply does not set the envelope keys")
    return _dump({"v": VERSION, "ok": True, **fields})


def error_body(code: str, extra: Mapping[str, Any] | None = None) -> bytes:
    """A failure reply for `code`: the fixed sentence and the exit status for it, plus the named extra fields."""
    if code not in REPLY_CODES:
        raise ValueError("unknown reply code")
    status, message = REPLY_CODES[code]
    extra = dict(extra or {})
    if {"v", "ok", "code", "message", "exit"} & set(extra):
        raise ValueError("an error reply does not set the envelope keys")
    if code == "unsupported_version":
        extra["supported"] = list(SUPPORTED)
    return _dump({"v": VERSION, "ok": False, "code": code, "message": message, "exit": status, **extra})


def _attachment_ok(item: object) -> bool:
    return (
        type(item) is dict
        and set(item) == {"index", "mime", "bytes", "sha256"}
        and _is_int(item["index"], 0, MAX_ATTACHMENTS)
        and _matches(item["mime"], MIME)
        and _is_int(item["bytes"], 1, MAX_ATTACHMENT_FRAME)
        and _matches(item["sha256"], SHA256)
    )


def parse_reply(body: bytes) -> dict[str, Any]:
    """What a client reads: the reply object, or `ProtocolError("bad_request")` when it is not a well-formed version 1
    reply. A failure reply must carry a known code with its own exit status and sentence; a success reply's
    `attachments`, when present, must be a short list of well-formed descriptions."""
    if type(body) is not bytes or len(body) == 0 <= MAX_REPLY_FRAME:
        raise ProtocolError("bad_request")
    try:
        data = loads(body)
    except (ValueError, RecursionError):
        raise ProtocolError("bad_request") from None
    if type(data) is not dict or type(data.get("v")) is not int or data["v"] not in SUPPORTED:
        raise ProtocolError("bad_request")
    if data.get("ok") is True:
        if {"code", "message", "exit"} & set(data):
            raise ProtocolError("bad_request")
        attachments = data.get("attachments", [])
        if type(attachments) is not list or len(attachments) > MAX_ATTACHMENTS:
            raise ProtocolError("bad_request")
        if not all(_attachment_ok(item) for item in attachments):
            raise ProtocolError("bad_request")
        return data
    code = data.get("code")
    if data.get("ok") is not False or type(code) is not str or code not in REPLY_CODES:
        raise ProtocolError("bad_request")
    status, message = REPLY_CODES[code]
    if data.get("exit") != status or type(data["exit"]) is not int or data.get("message") != message:
        raise ProtocolError("bad_request")
    return data


def attachment_count(reply: Mapping[str, Any]) -> int:
    """How many attachment frames follow this (already parsed) success reply."""
    attachments = reply.get("attachments", [])
    return len(attachments) if type(attachments) is list else 0
