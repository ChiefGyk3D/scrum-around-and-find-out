# SPDX-License-Identifier: Apache-2.0
"""Schema version 3: the signed approval text and the ledger rows, parsed strictly.

An approval is the canonical JSON `safo gemini approve` signs (docs/gemini-broker.md, "What a signed approval binds").
Version 2 (text only, from #217) and version 1 are refused with a message to ask for a fresh approval. A ledger row
carries `v` (the schema version); a row must be exactly the keys its type lists, with the types and ranges below.
Parsing uses the repository's bounded loader (size cap, depth cap, duplicate keys, no NaN) and never echoes input.

Signature verification (`geminisign.verify` against the root-owned signers) is not here: it needs the service's trust
files and arrives with the socket phase. A parsed `ApprovalV3` is a statement, not yet an authorization.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from safo import gemini, geminisign
from safo.bounded import loads
from safo.broker.errors import LedgerError, Refused
from safo.broker.money import MAX_MICRO, MoneyError, format_usd, parse_usd
from safo.broker.policy import BrokerRequest

SCHEMA_VERSION = 3
SUPPORTED_VERSIONS = (3,)
MAX_APPROVAL_BYTES = 16_384
NONCE = re.compile(r"[0-9a-f]{16,64}")
EPOCH = re.compile(r"[0-9a-f]{16,64}")
CALL_ID = re.compile(r"[0-9a-f]{16,64}")
HEAD = re.compile(r"[0-9a-f]{64}")
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
MONTH = re.compile(r"[0-9]{4}-(?:0[1-9]|1[0-2])")
MAX_ISSUE = 80
MAX_PRINCIPAL = 64

TEXT_ONLY = {"kind", "model", "job", "nonce", "epoch", "max_output_tokens", "thinking_level", "max_usd"}


def parse_stamp(text: object) -> dt.datetime | None:
    """A UTC time written exactly as `gemini.stamp` writes it, or None."""
    if type(text) is not str or STAMP.fullmatch(text) is None:
        return None
    try:
        when = dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    except ValueError:
        return None
    return when if gemini.stamp(when) == text else None


@dataclass(frozen=True)
class ApprovalV3:
    nonce: str
    epoch: str
    model: str
    kind: str
    count: int
    image_size: str
    aspect_ratio: str
    max_output_tokens: int
    thinking_level: str
    max_micro: int
    job: str
    prompt_sha256: str
    prompt_bytes: int
    quote: str
    quoted_at: dt.datetime
    created: dt.datetime
    expires_at: dt.datetime
    beyond_ceiling: bool
    ledger_head: str
    issue: str
    principal: str


_COMMON = {
    "version",
    "nonce",
    "epoch",
    "model",
    "kind",
    "max_output_tokens",
    "thinking_level",
    "max_usd",
    "job",
    "prompt_sha256",
    "prompt_bytes",
    "quote",
    "quoted_at",
    "created",
    "expires_at",
    "beyond_ceiling",
    "ledger_head",
    "issue",
    "principal",
}
_IMAGE = {"count", "image_size", "aspect_ratio"}


def _bad() -> Refused:
    return Refused("bad_approval", "the approval is not a well formed version 3 approval; ask for a fresh one")


def parse_approval(text: object) -> ApprovalV3:
    """The signed text as an ApprovalV3, or `bad_approval`. The text must be the canonical form (the bytes that were
    signed), so two spellings of the same approval cannot both exist."""
    if type(text) is not str or len(text) > MAX_APPROVAL_BYTES:
        raise _bad()
    try:
        data = loads(text)
    except (ValueError, UnicodeError, RecursionError):
        raise _bad() from None
    if not isinstance(data, dict):
        raise _bad()
    version = data.get("version")
    if type(version) is int and version in (1, 2):
        raise Refused("bad_approval", "this approval is in an older format with no cost binding; ask for a fresh one")
    if type(version) is not int or version != SCHEMA_VERSION:
        raise Refused("bad_approval", "this approval is of a version the broker does not accept; ask for a fresh one")
    kind = data.get("kind")
    expected = _COMMON | _IMAGE if kind == "image" else _COMMON
    if kind not in ("text", "image") or set(data) != expected:
        raise _bad()
    try:
        if geminisign.canonical(data) != text:
            raise _bad()
    except (TypeError, ValueError):
        raise _bad() from None
    s = _Fields(data)
    quoted_at, created, expires_at = s.stamp("quoted_at"), s.stamp("created"), s.stamp("expires_at")
    if not created < expires_at <= created + dt.timedelta(minutes=gemini.MAX_TTL_MINUTES):
        raise _bad()
    quote = s.string("quote", 1, gemini.MAX_QUOTE)
    if not gemini.valid_quote(quote):
        raise _bad()
    try:
        max_micro = parse_usd(data["max_usd"])
        if format_usd(max_micro) != data["max_usd"] or max_micro == 0:
            raise _bad()
    except MoneyError:
        raise _bad() from None
    return ApprovalV3(
        nonce=s.pattern("nonce", NONCE),
        epoch=s.pattern("epoch", EPOCH),
        model=s.pattern("model", gemini.MODEL_NAME),
        kind=str(kind),
        count=s.integer("count", 1, 4) if kind == "image" else 0,
        image_size=s.string("image_size", 2, 5) if kind == "image" else "",
        aspect_ratio=s.pattern("aspect_ratio", re.compile(r"[0-9]{1,2}:[0-9]{1,2}")) if kind == "image" else "",
        max_output_tokens=s.integer("max_output_tokens", 1, 10_000_000),
        thinking_level=s.string("thinking_level", 1, 16),
        max_micro=max_micro,
        job=s.pattern("job", gemini.JOB_NAME),
        prompt_sha256=s.pattern("prompt_sha256", gemini.PROMPT_DIGEST),
        prompt_bytes=s.integer("prompt_bytes", 0, gemini.MAX_PROMPT_BYTES),
        quote=quote,
        quoted_at=quoted_at,
        created=created,
        expires_at=expires_at,
        beyond_ceiling=s.boolean("beyond_ceiling"),
        ledger_head=s.pattern("ledger_head", HEAD),
        issue=s.string("issue", 0, MAX_ISSUE),
        principal=s.string("principal", 1, MAX_PRINCIPAL),
    )


class _Fields:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    def string(self, name: str, low: int, high: int) -> str:
        value = self.data[name]
        if type(value) is not str or not low <= len(value) <= high:
            raise _bad()
        return value

    def pattern(self, name: str, pattern: re.Pattern[str]) -> str:
        value = self.data[name]
        if type(value) is not str or pattern.fullmatch(value) is None:
            raise _bad()
        return value

    def integer(self, name: str, low: int, high: int) -> int:
        value = self.data[name]
        if type(value) is not int or not low <= value <= high:
            raise _bad()
        return value

    def boolean(self, name: str) -> bool:
        value = self.data[name]
        if type(value) is not bool:
            raise _bad()
        return value

    def stamp(self, name: str) -> dt.datetime:
        when = parse_stamp(self.data[name])
        if when is None:
            raise _bad()
        return when


def check_binding(approval: ApprovalV3, req: BrokerRequest, *, epoch: str, now: dt.datetime) -> None:
    """What the approval must say about the request the broker is about to price (a canonical request): the epoch, the
    expiry and every field that changes the cost or the content. The prompt digest is recomputed from the prompt
    received, never taken from the client."""
    if approval.epoch != epoch:
        raise Refused("bad_approval", "this approval was made for another broker state; ask for a fresh one")
    if now >= approval.expires_at:
        raise Refused("expired", "this approval has expired; ask for a fresh one")
    if now < approval.created - dt.timedelta(minutes=1):
        raise Refused("bad_approval", "this approval is dated in the future")
    digest, size = gemini.prompt_binding(req.prompt)
    if not gemini.digests_equal(approval.prompt_sha256, digest) or approval.prompt_bytes != size:
        raise Refused("digest_mismatch", "this approval was signed for different prompt bytes; ask for a fresh one")
    if approval.model != req.model:
        raise Refused("model_mismatch", "this approval is for another model")
    if approval.job != req.job:
        raise Refused("job_mismatch", "this approval is for another job")
    same = (
        approval.kind == req.kind
        and approval.count == req.count
        and approval.image_size == req.image_size
        and approval.aspect_ratio == req.aspect_ratio
        and approval.max_output_tokens == req.max_output_tokens
        and approval.thinking_level == req.thinking_level
    )
    if not same:
        raise Refused("bad_approval", "this approval does not cover the kind, size, count or limits of this request")


# -- ledger rows ---------------------------------------------------------------------------------------------------

Check = Callable[[Any], bool]


def _pat(pattern: re.Pattern[str]) -> Check:
    return lambda v: type(v) is str and pattern.fullmatch(v) is not None


def _int(low: int, high: int) -> Check:
    return lambda v: type(v) is int and low <= v <= high


def _enum(*values: str) -> Check:
    return lambda v: type(v) is str and v in values


def _bool(v: Any) -> bool:
    return type(v) is bool


def _stamp(v: Any) -> bool:
    return parse_stamp(v) is not None


_MODEL = _pat(gemini.MODEL_NAME)
_JOB = _pat(gemini.JOB_NAME)
_MICRO = _int(0, MAX_MICRO)
_BASE: dict[str, Check] = {"type": _enum(), "ts": _stamp, "v": _int(1, 99), "prev_hash": _pat(HEAD), "hash": _pat(HEAD)}

ROWS: dict[str, dict[str, Check]] = {
    "approval_used": {
        "nonce": _pat(NONCE),
        "call_id": _pat(CALL_ID),
        "model": _MODEL,
        "job": _JOB,
        "epoch": _pat(EPOCH),
    },
    "call_start": {
        "call_id": _pat(CALL_ID),
        "nonce": _pat(NONCE),
        "model": _MODEL,
        "kind": _enum("text", "image"),
        "job": _JOB,
        "reserved_micro": _int(1, MAX_MICRO),
        "prompt_sha256": _pat(gemini.PROMPT_DIGEST),
        "prompt_bytes": _int(0, gemini.MAX_PROMPT_BYTES),
        "image_size": _enum("", "512px", "1K", "2K", "4K"),
        "count": _int(0, 4),
    },
    "call_sent": {"call_id": _pat(CALL_ID)},
    "call_end": {
        "call_id": _pat(CALL_ID),
        "status": _enum("ok", "not_sent", "rate_limited", "vendor_refused"),
        "actual_micro": _MICRO,
        "released_micro": _MICRO,
        "breach": _bool,
    },
    "ambiguous_call": {
        "call_id": _pat(CALL_ID),
        "model": _MODEL,
        "reserved_micro": _int(1, MAX_MICRO),
        "reason": _enum("crash_recovery", "timeout", "connection", "status", "unreadable", "usage", "marker_only"),
    },
    "suspended": {"call_id": _pat(CALL_ID), "model": _MODEL, "reason": _enum("breach", "ambiguous")},
    "ambiguous_resolved": {"call_id": _pat(CALL_ID), "actual_micro": _MICRO},
    "suspension_cleared": {"model": _MODEL},
}
CHAIN_ROWS = frozenset({"chain_start"})


def validate_row(row: dict[str, Any]) -> str:
    """The type of a ledger row if it is exactly the shape its type lists, else LedgerError. `chain_start` belongs to
    the shared chain code and is accepted as that module writes it."""
    kind = row.get("type")
    if kind == "chain_start":
        if set(row) != {"type", "ts", "legacy_rows", "prev_hash", "hash"} or not _stamp(row["ts"]):
            raise LedgerError("the broker ledger has a malformed chain_start row")
        if row["legacy_rows"] != 0 or type(row["legacy_rows"]) is not int:
            raise LedgerError("the broker ledger has rows before its chain; it is not a broker ledger")
        return "chain_start"
    if type(kind) is not str or kind not in ROWS:
        raise LedgerError("the broker ledger has a row of an unknown type")
    spec = ROWS[kind]
    if set(row) != set(spec) | {"type", "ts", "v", "prev_hash", "hash"}:
        raise LedgerError("the broker ledger has a row with missing or extra fields")
    for name, check in spec.items():
        if not check(row[name]):
            raise LedgerError("the broker ledger has a row with a bad field value")
    for name in ("ts", "v", "prev_hash", "hash"):
        if not _BASE[name](row[name]):
            raise LedgerError("the broker ledger has a row with a bad field value")
    if row["v"] not in SUPPORTED_VERSIONS:
        raise LedgerError("the broker ledger has a row of a schema version this program does not read")
    return kind
