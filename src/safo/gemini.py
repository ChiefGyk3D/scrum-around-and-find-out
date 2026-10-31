# SPDX-License-Identifier: Apache-2.0
"""The free-tier Gemini client, for public-material research (#200, #195, #196, #287).

Gemini here is free-only. The free tier may train on prompts and be read by people, so nothing private goes to it. The
gates sit in code, never in a model:

* the free tier follows the maintainer's own rate limits (requests and input tokens per minute, requests per day, the
  day ending at midnight Pacific), counted from a local, append-only ledger; a 429 stops the job and never falls
  through to a paid call;
* the free key is read by name from the secret store at call time and held only for the one request;
* a paid request cannot be made here at all: `ask` refuses one before it reads anything. The paid path exists only
  through the broker (`safo.broker`, docs/gemini-broker.md), which alone holds the paid key.

A request is sent once. After the request leaves, a timeout, a 5xx, a closed connection, a redirect or an unreadable
answer is UNKNOWN, not failed: it is recorded as ambiguous and never repeated. There is no retry and so no backoff to
bound.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import hashlib
import hmac
import http.client
import importlib
import json
import math
import os
import pwd
import re
import secrets
import subprocess
import sys
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import yaml

from safo import netguard, termsearch
from safo.bounded import MAX_BYTES, MAX_FILE_BYTES, count, loads, read_bounded
from safo.credentials import find_executable
from safo.errors import ConfigError, SafoError
from safo.guardlog import ensure_dir, file_lock, write_text
from safo.schema import Reader, _safe_load
from safo.termsearch import TERMS_CHUNK as TERMS_CHUNK  # re-exported for the tests
from safo.trust import read_trusted_regular_file

VENDOR_HOST = "generativelanguage.googleapis.com"
JOB_CAP = Decimal("2")  # the most a brief may declare for a paid step (the guard grammar); the broker enforces its own
PACIFIC = ZoneInfo("America/Los_Angeles")
TIERS = ("free", "paid")
MODEL_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
RECORD_ID = re.compile(r"[A-Za-z0-9_-]{8,64}")
JOB_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}")
PLAIN_KEY = re.compile(r"[\x21-\x7e]{16,512}")
MAX_PROMPT_BYTES = 200_000
PROMPT_DIGEST = re.compile(r"[0-9a-f]{64}")
MAX_QUOTE = 500
MAX_TTL_MINUTES = 60  # a signed approval is short-lived: the touch happens just before the job
DEFAULT_TTL_MINUTES = 10  # the default; the window in which a replay against a rewound ledger could work
MAX_RETRY_AFTER = 86_400.0
SECRET_TOOL_TIMEOUT = 20.0
SECRET_SHAPES = (
    re.compile(r"AIza[0-9A-Za-z_-]{30,}"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{30,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bdp\.(?:pt|st|sa|ct)\.[A-Za-z0-9]{20,}"),
)


class GeminiError(SafoError):
    """Anything the Gemini wrapper reports."""


class RefusedError(GeminiError):
    """Nothing was sent (or the vendor definitely rejected it): the message says which gate stopped it."""


class RateLimitStopError(GeminiError):
    """The vendor answered 429. The job stops; nothing is retried and nothing falls through to the paid tier."""

    exit_code = 3


class OutcomeUnknownError(GeminiError):
    """The request left and its outcome is unknown. It is recorded, never repeated."""

    exit_code = 4


# -- small helpers -------------------------------------------------------------------------------------------------


def money(value: Decimal) -> str:
    """At least two decimals, at most six, so a tenth of a cent never prints as 0.00."""
    text = f"{value.quantize(Decimal('0.000001'), rounding=ROUND_HALF_UP):f}".rstrip("0")
    whole, _, frac = text.partition(".")
    return f"{whole}.{frac.ljust(2, '0')}"


def fixed(value: Decimal) -> str:
    return f"{value.quantize(Decimal('0.000001'), rounding=ROUND_HALF_UP):f}"


def _decimal(value: object, where: str, *, maximum: Decimal = Decimal(10**9)) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, int | float | str | Decimal):
        raise ConfigError(f"{where}: expected a number")
    try:
        number = Decimal(str(value))
    except InvalidOperation:
        raise ConfigError(f"{where}: expected a number") from None
    if not number.is_finite() or number < 0 or number > maximum:
        raise ConfigError(f"{where}: expected a number from 0 to {maximum}")
    return number


def usd_amount(text: str, flag: str) -> Decimal:
    """A finite, positive amount of USD from the command line, or a clean error (never a traceback)."""
    try:
        value = Decimal(text)
    except InvalidOperation:
        raise ConfigError(f"{flag}: expected a number of USD") from None
    if not value.is_finite() or value <= 0:
        raise ConfigError(f"{flag}: expected a finite number of USD above 0")
    return value


def stamp(when: dt.datetime) -> str:
    return when.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_stamp(text: object) -> dt.datetime | None:
    if not isinstance(text, str):
        return None
    try:
        return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    except ValueError:
        return None


def valid_quote(quote: str) -> bool:
    """The maintainer's quote in an approval: 1 to MAX_QUOTE characters, one line, no control or format marks."""
    return not (
        not quote.strip()
        or len(quote) > MAX_QUOTE
        or any(ord(c) < 32 or unicodedata.category(c) in ("Cf", "Cc", "Zl", "Zp") for c in quote)
    )


def has_secret_shape(text: str) -> bool:
    return any(shape.search(text) for shape in SECRET_SHAPES)


def estimate_input_tokens(prompt: str) -> int:
    """A deliberate overestimate (three bytes a token) so a limit is never passed on a guess that was too low."""
    return math.ceil(len(prompt.encode("utf-8")) / 3)


# -- configuration -------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class FreeLimits:
    rpm: int
    tpm: int
    rpd: int


@dataclass(frozen=True)
class GeminiConfig:
    endpoint: str
    project: str
    free_config: str
    key_name: str
    ledger: Path
    timeout_seconds: float
    max_output_tokens: int
    free: Mapping[str, FreeLimits]
    image_models: frozenset[str] = frozenset()  # paid-only models: the free tier refuses them by name
    private_terms: str = "default"  # none, default (the fixed privacy-terms.txt) or an absolute path


def _endpoint(r: Reader, value: object) -> str:
    text = r.string(value, "endpoint").rstrip("/")
    parts = urlsplit(text)
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
        raise r.fail("endpoint", "expected a scheme, host and port only")
    host = parts.hostname or ""
    loopback = netguard.literal(host)
    if parts.scheme == "https" and host == VENDOR_HOST and parts.port in (None, 443):
        return text
    if parts.scheme == "http" and loopback is not None and loopback.is_loopback:
        return text
    raise r.fail("endpoint", f"the key may only go to https://{VENDOR_HOST} (or loopback http, for tests)")


def default_ledger(home: Path) -> Path:
    """The one default place for the ledger, under the account's home. If the ledger is missing here while another
    `gemini-spend-ledger.jsonl` sits in a sibling folder, every call is refused (see `Ledger.read`)."""
    return home / ".local" / "share" / "safo" / "gemini-spend-ledger.jsonl"


def parse_config(data: object, source: str = "gemini config", home: Path | None = None) -> GeminiConfig:
    r = Reader(source)
    top = r.mapping(
        data,
        "",
        {
            "version",
            "endpoint",
            "secrets",
            "ledger",
            "timeout_seconds",
            "max_output_tokens",
            "free",
            "image_models",
            "private_terms",
        },
        {"version", "endpoint", "secrets", "free"},
    )
    if top["version"] != 1:
        raise r.fail("version", "only version 1 is supported")
    # The free key only. The paid key is not named here or anywhere outside the broker's own credential (#287), so a
    # `paid_config` setting is refused as an unknown key.
    sec = r.mapping(
        top["secrets"],
        "secrets",
        {"project", "free_config", "key_name"},
        {"project", "free_config", "key_name"},
    )
    names = {k: r.string(sec[k], f"secrets.{k}") for k in sec}
    for key, name in names.items():
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            raise r.fail(f"secrets.{key}", "expected a plain name (letters, digits, . _ -)")
    images: set[str] = set()
    raw_images = top.get("image_models", [])
    if not isinstance(raw_images, list):
        raise r.fail("image_models", "expected a list of model names")
    for position, model in enumerate(raw_images):
        name = r.string(model, f"image_models[{position}]")
        if not MODEL_NAME.fullmatch(name):
            raise r.fail(f"image_models[{position}]", "not a model name")
        images.add(name)
    free: dict[str, FreeLimits] = {}
    for model, raw in r.mapping(top["free"], "free", set(top["free"] or {})).items():
        where = f"free.{model}"
        if not MODEL_NAME.fullmatch(str(model)):
            raise r.fail(where, "not a model name")
        if str(model) in images:
            raise r.fail(where, "image generation is paid-only: its free quota is zero")
        m = r.mapping(raw, where, {"rpm", "tpm", "rpd"}, {"rpm", "tpm", "rpd"})
        free[str(model)] = FreeLimits(
            r.integer(m["rpm"], f"{where}.rpm", minimum=1),
            r.integer(m["tpm"], f"{where}.tpm", minimum=1),
            r.integer(m["rpd"], f"{where}.rpd", minimum=1),
        )
    ledger_text = top.get("ledger")
    ledger = (
        Path(r.string(ledger_text, "ledger"))
        if ledger_text is not None
        else default_ledger(home or fixed_locations().home)
    )
    terms = r.string(top.get("private_terms", "default"), "private_terms")
    if terms not in ("none", "default") and not (terms.startswith("/") and "\x00" not in terms):
        raise r.fail("private_terms", "expected none, default or an absolute path")
    if not ledger.is_absolute():
        raise r.fail("ledger", "expected an absolute path")
    timeout = top.get("timeout_seconds", 60)
    if isinstance(timeout, bool) or not isinstance(timeout, int | float) or not 1 <= timeout <= 300:
        raise r.fail("timeout_seconds", "expected a number from 1 to 300")
    return GeminiConfig(
        _endpoint(r, top["endpoint"]),
        names["project"],
        names["free_config"],
        names["key_name"],
        ledger,
        float(timeout),
        r.integer(top.get("max_output_tokens", 2048), "max_output_tokens", minimum=1),
        free,
        frozenset(images),
        terms,
    )


def load_config(path: Path | str, home: Path | None = None) -> GeminiConfig:
    """A private file: owned by the user, not writable by others (it names where the key is sent)."""
    p = Path(path)
    try:
        raw = read_trusted_regular_file(p, 262_144)
        text = raw.decode("utf-8")
        for event in yaml.parse(text):
            if isinstance(event, yaml.events.AliasEvent) or (
                isinstance(event, yaml.events.ScalarEvent) and event.value == "<<"
            ):
                raise ConfigError("gemini config: aliases and merge keys are not allowed")
        data = _safe_load(text, "gemini config")
    except yaml.YAMLError:
        raise ConfigError("gemini config: not valid YAML") from None
    except UnicodeError:
        raise ConfigError("gemini config: not UTF-8 text") from None
    return parse_config(data, "gemini config", home)


# -- the ledger ----------------------------------------------------------------------------------------------------


def _chain_hash(row: Mapping[str, Any]) -> str:
    """The hash of a chained row: canonical JSON of every field except `hash` itself (it covers `prev_hash`)."""
    body = {k: v for k, v in row.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class LedgerState:
    rows: list[dict[str, Any]]
    started: bool  # a chain_start row exists
    head: str  # the hash of the last chained row, "" before the chain starts
    chained: int  # how many chained rows
    prefix_hash: str  # sha256 of every byte before chain_start (the legacy rows)


class Ledger:
    """Append-only JSON lines, outside git, hash-chained from a `chain_start` row on. A line it cannot read stops every
    call: a counter that skips a line could undercount spend. After `chain_start` every row carries `prev_hash` and its
    own `hash`; deleting, editing, reordering or truncating a row is found and named by line number. The rows before
    `chain_start` are never edited: `chain_start` records the hash of their exact bytes."""

    def __init__(self, path: Path) -> None:
        self.path = path

    @property
    def head_file(self) -> Path:
        return self.path.with_name(self.path.name + ".head")

    @property
    def height_file(self) -> Path:
        """The highest chain height this wrapper has seen, kept in the fixed state folder and not beside the ledger."""
        key = hashlib.sha256(str(self.path.absolute()).encode()).hexdigest()[:16]
        return fixed_locations().height_dir / f"{key}.height"

    def state(self) -> LedgerState:
        """The ledger as it is, verified: the chain, the head file and the height record. Every refusal is a
        RefusedError that names what was found."""
        state = self._load()
        self._check_height(state, [r for r in state.rows if isinstance(r.get("hash"), str)])
        return state

    def _absent(self) -> LedgerState:
        """The ledger file does not exist: an empty state, unless a sibling ledger of the same name suggests the real
        one is elsewhere. A subclass with a fixed home may override it."""
        others = sorted(p for p in self.path.parent.parent.glob(f"*/{self.path.name}") if p != self.path)
        if others:
            raise RefusedError(
                "this ledger does not exist yet, but another ledger with the same name does: starting an empty "
                "one would read 0 spent. Move the real one here, or point `ledger:` in gemini.yaml at it"
            ) from None
        return LedgerState([], False, "", 0, hashlib.sha256(b"").hexdigest())

    def _load(self) -> LedgerState:
        try:
            raw = read_bounded(self.path, MAX_FILE_BYTES + 1)
        except FileNotFoundError:
            return self._absent()
        except OSError:
            raise RefusedError(
                "the spend ledger is not a plain readable file (a link, a pipe or no permission)"
            ) from None
        if len(raw) > MAX_FILE_BYTES:
            raise RefusedError("the spend ledger is larger than the reader allows; archive it by hand first")
        rows: list[dict[str, Any]] = []
        numbers: list[int] = []
        offsets: list[int] = []
        at = 0
        for number, line in enumerate(raw.splitlines(keepends=True), 1):
            start, at = at, at + len(line)
            if not line.strip():
                continue
            try:
                row = loads(line)
            except (ValueError, UnicodeError):
                row = None
            if not isinstance(row, dict):
                raise RefusedError(f"the spend ledger has an unreadable line ({number}); fix it by hand")
            rows.append(row)
            numbers.append(number)
            offsets.append(start)
        first = next((i for i, row in enumerate(rows) if row.get("type") == "chain_start"), None)
        if first is None:
            for i, row in enumerate(rows):
                if "prev_hash" in row or "hash" in row:
                    raise RefusedError(
                        f"the spend ledger has a chained row (line {numbers[i]}) but no chain_start: rows were removed"
                    )
            return LedgerState(rows, False, "", 0, hashlib.sha256(raw).hexdigest())
        prefix_hash = hashlib.sha256(raw[: offsets[first]]).hexdigest()
        previous = prefix_hash
        for i in range(first, len(rows)):
            row, line_no = rows[i], numbers[i]
            if row.get("type") == "chain_start" and i != first:
                raise RefusedError(f"the spend ledger starts its chain twice (line {line_no})")
            if row.get("prev_hash") != previous:
                raise RefusedError(
                    f"the spend ledger chain is broken at line {line_no}: a row before it was removed, "
                    "reordered or edited"
                )
            if not isinstance(row.get("hash"), str) or row["hash"] != _chain_hash(row):
                raise RefusedError(f"the spend ledger chain is broken at line {line_no}: this row was edited")
            previous = row["hash"]
        if rows[first].get("legacy_rows") != first:
            raise RefusedError(f"the spend ledger chain is broken at line {numbers[first]}: legacy rows were removed")
        state = LedgerState(rows, True, previous, len(rows) - first, prefix_hash)
        self._check_head_file(state, rows[first:], numbers[first:])
        return state

    def _check_height(self, state: LedgerState, chained: list[dict[str, Any]]) -> None:
        """The height record (see `height_file`) is the second copy that is not beside the ledger. A chain shorter than
        it, or one whose row at that height has another hash, was rewound or rewritten."""
        try:
            text = read_bounded(self.height_file, 256).decode("ascii").strip()
        except FileNotFoundError:
            return
        except (OSError, UnicodeError):
            raise RefusedError("the height record of the spend ledger cannot be read") from None
        count_text, _, digest = text.partition(" ")
        if not count_text.isdigit() or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RefusedError("the height record of the spend ledger is malformed")
        count = int(count_text)
        if count > state.chained:
            raise RefusedError(
                f"the spend ledger is shorter than the height record kept apart from it (recorded height {count}, "
                f"chain has {state.chained} rows): it was rewound"
            )
        if count and chained[count - 1]["hash"] != digest:
            raise RefusedError("the spend ledger does not match the height record kept apart from it: it was rewritten")

    def _record_height(self, count: int, digest: str) -> None:
        try:
            current = int(read_bounded(self.height_file, 256).decode("ascii").split()[0])
        except (OSError, UnicodeError, ValueError, IndexError):
            current = 0
        if count > current:
            write_text(self.height_file, f"{count} {digest}\n")

    def _check_head_file(self, state: LedgerState, chained: list[dict[str, Any]], numbers: list[int]) -> None:
        """The head file is a second copy of the newest hash. An editor that truncates the tail but leaves it is caught;
        one that also rewrites it is not (see docs/gemini.md)."""
        try:
            text = read_bounded(self.head_file, 256).decode("ascii").strip()
        except FileNotFoundError:
            return
        except (OSError, UnicodeError):
            raise RefusedError("the spend ledger's head file cannot be read") from None
        count_text, _, digest = text.partition(" ")
        if not count_text.isdigit() or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RefusedError("the spend ledger's head file is malformed")
        count = int(count_text)
        if count > state.chained:
            raise RefusedError(
                f"the spend ledger is shorter than its head file says ({state.chained} chained rows, "
                f"{count} expected): rows at the end were removed"
            )
        if count and chained[count - 1]["hash"] != digest:
            raise RefusedError("the spend ledger does not match its head file: it was rewritten")

    def read(self) -> list[dict[str, Any]]:
        return self.state().rows

    def append(self, row: dict[str, Any], *, ts: str = "") -> str:
        """Append one chained row (starting the chain first when it has not begun) and return its hash. The caller holds
        `lock()`; the chain is checked before anything is written, so a broken ledger takes no new rows."""
        return self.append_many([row], ts=ts)

    def append_many(self, rows: list[dict[str, Any]], *, ts: str = "") -> str:
        """Append chained rows in ONE write and one fsync (all of them are on disk or, after a crash, a torn last line
        that holds none of them whole), and return the hash of the last. The caller holds `lock()`."""
        if not rows:
            raise ValueError("no rows to append")
        state = self.state()
        lines: list[dict[str, Any]] = []
        previous = state.head
        if not state.started:
            start = {
                "type": "chain_start",
                "ts": ts or stamp(dt.datetime.now(dt.UTC)),
                "legacy_rows": len(state.rows),
                "prev_hash": state.prefix_hash,
            }
            start["hash"] = _chain_hash(start)
            lines.append(start)
            previous = str(start["hash"])
        for row in rows:
            full = {**row, "prev_hash": previous}
            full["hash"] = _chain_hash(full)
            lines.append(full)
            previous = str(full["hash"])
        self._write_lines(lines, state.chained + len(lines))
        return previous

    def _write_lines(self, lines: list[dict[str, Any]], count: int) -> None:
        try:
            ensure_dir(self.height_file.parent)  # fail before a row is written if the height record cannot be kept
        except (ConfigError, OSError):
            raise RefusedError("the folder for the ledger height record cannot be used; nothing was written") from None
        data = "".join(json.dumps(r, sort_keys=True) + "\n" for r in lines).encode()
        try:
            ensure_dir(self.path.parent)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        except OSError:
            raise RefusedError("the spend ledger cannot be opened for appending") from None
        try:
            if os.write(fd, data) != len(data):
                raise RefusedError("the spend ledger took a short write")
            os.fsync(fd)
        except OSError:
            raise RefusedError("the spend ledger could not be written") from None
        finally:
            os.close(fd)
        with contextlib.suppress(GeminiError, ConfigError, OSError):
            write_text(self.head_file, f"{count} {lines[-1]['hash']}\n")
        with contextlib.suppress(GeminiError, ConfigError, OSError):
            self._record_height(count, str(lines[-1]["hash"]))

    def ensure_chain(self, ts: str = "") -> str:
        """Start the chain if it has not begun; return the hash of the newest row. The caller holds `lock()`."""
        state = self.state()
        if state.started:
            return state.head
        start = {
            "type": "chain_start",
            "ts": ts or stamp(dt.datetime.now(dt.UTC)),
            "legacy_rows": len(state.rows),
            "prev_hash": state.prefix_hash,
        }
        start["hash"] = _chain_hash(start)
        self._write_lines([start], 1)
        return str(start["hash"])

    def lock(self) -> contextlib.AbstractContextManager[None]:
        return file_lock(self.path.with_name(self.path.name + ".lock"), timeout=10.0)


@dataclass(frozen=True)
class Call:
    call_id: str
    when: dt.datetime
    tier: str
    model: str
    est_tokens: int
    est_usd: Decimal
    prompt_tokens: int | None = None
    actual_usd: Decimal | None = None
    status: str = ""

    @property
    def tokens(self) -> int:
        return self.prompt_tokens if self.prompt_tokens is not None else self.est_tokens

    @property
    def spent(self) -> Decimal:
        """The measured cost, else the estimate: a call whose end is missing or unknown counts as spent."""
        return self.actual_usd if self.actual_usd is not None else self.est_usd


@dataclass(frozen=True)
class Snapshot:
    calls: tuple[Call, ...]
    manual: tuple[tuple[str, Decimal], ...]  # (YYYY-MM-DD, USD) the maintainer wrote as `usage` rows
    heads: frozenset[str] = frozenset()  # the hash of every chained row: an approval's ledger_head must be one of them
    order: tuple[str, ...] = ()  # those hashes, oldest first
    issued: tuple[
        tuple[str, str, int], ...
    ] = ()  # (nonce, principal, position in `order`) of every approval_issued row
    used: tuple[tuple[str, str], ...] = ()  # (nonce, principal) of every approval a call has spent
    issued_prompts: tuple[
        tuple[str, int], ...
    ] = ()  # (prompt digest, prompt bytes) of each approval_issued row, same order as `issued`; ("", -1) when absent


def _bad(number: int) -> RefusedError:
    return RefusedError(f"the spend ledger has a malformed row (record {number}); fix it by hand")


def snapshot(rows: list[dict[str, Any]]) -> Snapshot:
    starts: dict[str, Call] = {}
    ends: dict[str, dict[str, Any]] = {}
    manual: list[tuple[str, Decimal]] = []
    used: list[tuple[str, str]] = []
    order = tuple(str(row["hash"]) for row in rows if isinstance(row.get("hash"), str))
    heads = frozenset(order)
    issued: list[tuple[str, str, int]] = []
    issued_prompts: list[tuple[str, int]] = []
    for number, row in enumerate(rows, 1):
        kind = row.get("type")
        try:
            if kind == "call_start":
                call_id = row["call_id"]
                when = _parse_stamp(row["ts"])
                tokens = count(row["est_input_tokens"])
                if not isinstance(call_id, str) or when is None or call_id in starts:
                    raise ValueError("start")
                if row["tier"] not in TIERS or not isinstance(row["model"], str):
                    raise ValueError("tier")
                starts[call_id] = Call(
                    call_id, when, row["tier"], row["model"], tokens, _decimal(row["est_usd"], "est_usd")
                )
            elif kind == "call_end":
                call_id = row["call_id"]
                if not isinstance(call_id, str) or call_id in ends:
                    raise ValueError("end")
                ends[call_id] = row
            elif kind in ("funding", "chain_start"):
                continue
            elif kind == "approval_issued":
                nonce, principal = row["nonce"], row["principal"]
                if not isinstance(nonce, str) or not isinstance(principal, str):
                    raise ValueError("issued")
                issued.append((nonce, principal, order.index(row["hash"]) if row.get("hash") in heads else -1))
                digest, size = row.get("prompt_sha256"), row.get("prompt_bytes")  # a row from before #217 has neither
                issued_prompts.append(
                    (digest if type(digest) is str else "", size if type(size) is int and size >= 0 else -1)
                )
            elif kind == "approval_used":
                nonce, principal = row["nonce"], row["principal"]
                if not isinstance(nonce, str) or not isinstance(principal, str) or any(n == nonce for n, _ in used):
                    raise ValueError("used")
                used.append((nonce, principal))
            elif kind == "usage":
                date = row["date"]
                if not isinstance(date, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
                    raise ValueError("date")
                manual.append((date, _decimal(row["amount_usd"], "amount_usd")))
            else:
                raise RefusedError(f"the spend ledger has a row of unknown type (record {number}); fix it by hand")
        except (KeyError, ValueError, ConfigError):
            raise _bad(number) from None
    calls: list[Call] = []
    for call_id, call in starts.items():
        end = ends.pop(call_id, None)
        if end is not None:
            try:
                actual = end.get("actual_usd")
                call = dataclasses.replace(
                    call,
                    prompt_tokens=count(end["prompt_tokens"]) if end.get("prompt_tokens") is not None else None,
                    actual_usd=_decimal(actual, "actual_usd") if actual is not None else None,
                    status=str(end.get("status", "")),
                )
            except (KeyError, ValueError, ConfigError):
                raise _bad(0) from None
        calls.append(call)
    if ends:
        raise _bad(0)  # an end with no start
    return Snapshot(tuple(calls), tuple(manual), heads, order, tuple(issued), tuple(used), tuple(issued_prompts))


# -- quota lines and the free-tier gate ----------------------------------------------------------------------------


def pacific_day(now: dt.datetime) -> tuple[dt.datetime, dt.datetime]:
    """Midnight Pacific that began `now`'s day, and the next one (the reset), as UTC instants."""
    local = now.astimezone(PACIFIC)
    start = dt.datetime.combine(local.date(), dt.time.min, tzinfo=PACIFIC)
    end = dt.datetime.combine(local.date() + dt.timedelta(days=1), dt.time.min, tzinfo=PACIFIC)
    return start, end


@dataclass(frozen=True)
class FreeQuota:
    model: str
    limits: FreeLimits
    rpm: int
    rpd: int
    tpm: int
    reset: dt.datetime

    def line(self) -> str:
        reset = self.reset.astimezone(PACIFIC).isoformat(timespec="minutes")
        return (
            f"QUOTA free {self.model}: requests per minute {self.rpm} of {self.limits.rpm}; "
            f"requests per day {self.rpd} of {self.limits.rpd}; "
            f"input tokens per minute {self.tpm} of {self.limits.tpm}; "
            f"day window: midnight Pacific, resets {reset}; minute window: rolling 60 s; "
            "limits are the maintainer's, from AI Studio; the vendor's 429 is the authority"
        )


def free_quota(cfg: GeminiConfig, snap: Snapshot, model: str, now: dt.datetime) -> FreeQuota:
    limits = cfg.free.get(model)
    if limits is None:
        raise RefusedError(
            f"the quota line cannot be produced: no free-tier limits are configured for {model} "
            "(copy them from AI Studio into the free: table; they are never guessed)"
        )
    day_start, day_end = pacific_day(now)
    minute = now - dt.timedelta(seconds=60)
    mine = [c for c in snap.calls if c.tier == "free" and c.model == model]
    return FreeQuota(
        model,
        limits,
        sum(1 for c in mine if c.when > minute),
        sum(1 for c in mine if c.when >= day_start),
        sum(c.tokens for c in mine if c.when > minute),
        day_end,
    )


@dataclass(frozen=True)
class Request:
    model: str
    prompt: str
    tier: str
    job: str = ""
    approval: str = ""
    max_output_tokens: int = 0


MAX_APPROVED_PROMPT_CHARS = 4000  # the signer reads the whole prompt, so an approval covers no more than this


def too_long(characters: int) -> str:
    return (
        f"the prompt is {characters} characters; an approval covers at most {MAX_APPROVED_PROMPT_CHARS}, because the "
        "person signing must be able to read all of it. Shorten the prompt or split the job"
    )


def prompt_bytes(prompt: str) -> bytes:
    """The one snapshot of a prompt: its strict UTF-8 bytes (a lone surrogate is a refusal)."""
    if type(prompt) is not str:
        raise RefusedError("the prompt is not plain text, so nothing was sent")
    try:
        return str.encode(prompt, "utf-8")
    except UnicodeEncodeError:
        raise RefusedError("the prompt is not valid text (a lone surrogate), so nothing was approved or sent") from None


def prompt_binding(prompt: str) -> tuple[str, int]:
    """What a signed approval covers: the lowercase hex SHA-256 of the exact UTF-8 bytes of the prompt the wrapper
    sends, and their count. No normalization, no trimming: a changed byte, a trailing newline or another Unicode form
    of the same text is a different prompt (docs/gemini.md)."""
    try:
        raw = str.encode(prompt, "utf-8")
    except UnicodeEncodeError:
        raise RefusedError("the prompt is not valid text (a lone surrogate), so nothing was approved or sent") from None
    return hashlib.sha256(raw).hexdigest(), len(raw)


def plain_str(value: object, name: str) -> str:
    """A caller's string as a plain `str`: exact type only, copied through bytes so nothing of the caller's object is
    left. The refusal names the field and never echoes the value."""
    if type(value) is not str:
        raise RefusedError(f"{name} is not a plain text value, so nothing was done")
    try:
        return bytes.decode(str.encode(value, "utf-8"), "utf-8")
    except UnicodeEncodeError:
        raise RefusedError(f"{name} is not valid text, so nothing was done") from None


def plain_int(value: object, name: str) -> int:
    """A caller's integer as a plain `int`: exact type (a bool or a subclass is refused), copied through bytes."""
    if type(value) is not int:
        raise RefusedError(f"{name} is not a plain whole number, so nothing was done")
    try:
        return int.from_bytes(int.to_bytes(value, 8, "big", signed=True), "big", signed=True)
    except OverflowError:
        raise RefusedError(f"{name} is out of range, so nothing was done") from None


def plain_time(value: object, name: str) -> dt.datetime:
    """A caller's time as a plain UTC `datetime`: exact type and a plain fixed-offset zone."""
    if type(value) is not dt.datetime or type(value.tzinfo) is not dt.timezone:
        raise RefusedError(f"{name} is not a plain time with a time zone, so nothing was done")
    return dt.datetime.astimezone(value, dt.UTC)


def canonical_request(req: Request) -> Request:
    """The one entry copy of a request, built from base types only. Every later use reads this copy and never the
    caller's object (a frozen dataclass can still be altered, and a `str` or `int` subclass can lie in ==, !=, hash,
    format, str, bool, len and index). Anything but the exact expected types is refused (#217)."""
    if type(req) is not Request:
        raise RefusedError("the request is not a plain request, so nothing was done")
    fields = {name: object.__getattribute__(req, name) for name in ("model", "prompt", "tier", "job", "approval")}
    out_tokens = object.__getattribute__(req, "max_output_tokens")
    return Request(
        model=plain_str(fields["model"], "model"),
        prompt=bytes.decode(prompt_bytes(fields["prompt"]), "utf-8"),
        tier=plain_str(fields["tier"], "tier"),
        job=plain_str(fields["job"], "job"),
        approval=plain_str(fields["approval"], "approval"),
        max_output_tokens=plain_int(out_tokens, "max_output_tokens"),
    )


def digests_equal(left: object, right: object) -> bool:
    """Equality for the prompt digest: both sides must be exactly `str` (not a subclass that can bend ==, != or
    encode), compared as bytes through the base type's own methods and a constant-time compare."""
    if type(left) is not str or type(right) is not str:
        return False
    try:
        return hmac.compare_digest(str.encode(left, "utf-8"), str.encode(right, "utf-8"))
    except UnicodeEncodeError:
        return False


def _check_request(cfg: GeminiConfig, req: Request) -> None:
    if req.tier not in TIERS:
        raise RefusedError("the tier is free or paid")
    if not MODEL_NAME.fullmatch(req.model):
        raise RefusedError("the model name is not a plain model name")
    try:
        size = len(req.prompt.encode("utf-8"))
    except UnicodeEncodeError:
        raise RefusedError("the prompt is not valid text (a lone surrogate), so nothing was sent") from None
    if size > MAX_PROMPT_BYTES:
        raise RefusedError(f"the prompt is larger than {MAX_PROMPT_BYTES} bytes; cut it down")
    if has_secret_shape(req.prompt):
        raise RefusedError("the prompt holds something shaped like a secret or a private key; nothing was sent")
    if req.max_output_tokens < 0:
        raise RefusedError("max output tokens cannot be negative")


def quota_line(cfg: GeminiConfig, req: Request, now: dt.datetime) -> str:
    """The line printed before any approval and before any call. It cannot be produced without the numbers."""
    req = canonical_request(req)
    now = plain_time(now, "now")
    _check_request(cfg, req)
    snap = snapshot(Ledger(cfg.ledger).read())
    if req.tier != "free":
        raise RefusedError(PAID_ELSEWHERE)
    return free_quota(cfg, snap, req.model, now).line()


# -- locations -----------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Locations:
    """Where the config, the approval records and the private-terms file live. Fixed: no flag and no environment
    variable moves them (a test points them into a temporary directory through the `fixed_locations` seam)."""

    home: Path
    config: Path
    approvals: Path
    terms: Path
    # public keys, root-owned and maintainer-edited; this code never writes to them
    signers: Path = Path("/etc/safo/gemini-allowed-signers")
    revoked: Path = Path("/etc/safo/gemini-revoked-signers")  # public keys or fingerprints that may no longer approve
    trust_uid: int = 0  # the owner the two files above must have
    require_hardware: bool = True  # only sk keys, unless a key carries the written opt-in; a test may turn this off
    revocation_required: bool = True  # a missing revocation list refuses every approval; a test may turn this off

    @property
    def height_dir(self) -> Path:
        """Where the highest ledger height ever seen is kept, apart from the ledger (beside the approvals)."""
        return self.approvals.parent / "heights"


PAID_ELSEWHERE = (
    "paid use exists only through the broker: run `safo gemini paid` (docs/gemini-broker.md); "
    "this command sends free-tier requests only"
)


class PaidOnlyThroughBroker:
    """What the dispatch guard is given for every paid step: refused, with the reason. A brief cannot carry a paid step
    at all, because a paid call needs a person's touch on a security key at a terminal, in the broker client."""

    disabled = PAID_ELSEWHERE

    def __call__(self, record_id: str) -> str | None:
        return PAID_ELSEWHERE


def fixed_locations() -> Locations:
    """From the account database, never from $HOME or an XDG variable, which a caller can set."""
    try:
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    except KeyError:
        raise ConfigError("this account has no home directory in the account database") from None
    return Locations(
        home,
        home / ".config" / "safo" / "gemini.yaml",
        home / ".local" / "state" / "safo" / "gemini" / "approvals",
        home / ".config" / "safo" / "privacy-terms.txt",
    )


def _gate_free(cfg: GeminiConfig, snap: Snapshot, req: Request, now: dt.datetime) -> None:
    if req.model in cfg.image_models:
        raise RefusedError("image generation is paid-only: its free quota is zero")
    quota = free_quota(cfg, snap, req.model, now)
    tokens = estimate_input_tokens(req.prompt)
    if quota.rpm >= quota.limits.rpm:
        raise RefusedError(f"free tier: {quota.rpm} of {quota.limits.rpm} requests per minute used; wait a minute")
    if quota.rpd >= quota.limits.rpd:
        raise RefusedError(
            f"free tier: {quota.rpd} of {quota.limits.rpd} requests per day used; "
            f"the day resets at midnight Pacific ({quota.reset.astimezone(PACIFIC).isoformat(timespec='minutes')})"
        )
    if quota.tpm + tokens > quota.limits.tpm:
        raise RefusedError(
            f"free tier: input tokens per minute would pass {quota.limits.tpm} ({quota.tpm} used, about {tokens} more)"
        )


# -- private terms --------------------------------------------------------------------------------------------------

TERMS_FILE_BYTES = 65_536
TERMS_LINE_CAP = 200
TERMS_COUNT_CAP = 500
TERMS_REPEAT_CAP = 99  # one repeat in a term is bounded: {1,40}, never + or *
TERMS_WORK_CAP = 10_000  # the product of every repeat's upper bound in one term
TERMS_SECONDS = 5.0  # a term search that runs longer than this is killed and counts as a denial

_RE_PARSER = importlib.import_module("re._parser")  # private, but the only way to read a pattern's shape (3.11+)
_RE_CONSTANTS = importlib.import_module("re._constants")

_LETTERS = {
    # Cyrillic, lower and upper case
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0456": "i", "\u0458": "j",
    "\u0455": "s", "\u0501": "d", "\u043a": "k", "\u043c": "m", "\u0445": "x", "\u0443": "y", "\u04bb": "h",
    "\u051b": "q", "\u051d": "w", "\u04cf": "l",
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M", "\u041d": "H", "\u041e": "O",
    "\u0420": "P", "\u0421": "C", "\u0422": "T", "\u0425": "X", "\u0406": "I", "\u0408": "J", "\u0405": "S",
    "\u0423": "Y",
    # Greek, lower and upper case
    "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03b9": "i", "\u03ba": "k", "\u03c1": "p", "\u03bd": "v",
    "\u03c4": "t", "\u0475": "v",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H", "\u0399": "I", "\u039a": "K",
    "\u039c": "M", "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X",
    # Armenian, Latin extensions and small capitals
    "\u0585": "o", "\u057d": "u", "\u0578": "n", "\u0581": "g", "\u0251": "a", "\u0261": "g", "\u0192": "f",
    "\ua731": "s", "\u1d00": "a", "\ua730": "f", "\u1d0f": "o", "\u1d0d": "m", "\u1d07": "e", "\u026a": "i",
    "\u0274": "n", "\u1d18": "p", "\u1d0b": "k", "\u029f": "l", "\u0280": "r", "\u1d05": "d", "\u0262": "g",
}  # fmt: skip
# letters and symbols that draw nothing: Hangul fillers and the braille blank
_BLANKS = {0x3164: None, 0x115F: None, 0x1160: None, 0xFFA0: None, 0x2800: None}
_HOMOGLYPHS = str.maketrans({**_LETTERS, **{chr(k): v for k, v in _BLANKS.items()}})


def fold(text: str) -> str:
    """What a reader would see: NFKD, combining marks, format and control characters (zero-width, tag, variation
    selector, NUL) and the invisible letters (Hangul fillers, braille blank) removed except tab and newline, NFKC, and
    common Cyrillic, Greek, Armenian and small-capital look-alikes, upper and lower case, mapped to Latin."""
    stripped = "".join(
        c
        for c in unicodedata.normalize("NFKD", text)
        if c in "\t\n" or (unicodedata.category(c) not in ("Mn", "Cf", "Cc") and ord(c) not in _BLANKS)
    )
    return unicodedata.normalize("NFKC", stripped).translate(_HOMOGLYPHS)


class TermsCheckError(RefusedError):
    """The private-terms search could not finish: it counts as a hit."""


TERMS_OPTIONAL_CAP = 8  # optional parts and alternatives in one term, together


def _is_wildcard_repeat(op: Any, av: Any) -> bool:
    """A repeat of `.`, `\\w`, `\\s`, `\\S`, a negated or category class: the kind whose neighbours multiply."""
    c = _RE_CONSTANTS
    if op not in (c.MAX_REPEAT, c.MIN_REPEAT, c.POSSESSIVE_REPEAT):
        return False
    _low, high, sub = av
    if high <= 1 or len(sub) != 1:
        return False
    inner, value = sub[0]
    if inner in (c.ANY, c.NOT_LITERAL, c.CATEGORY):
        return True
    return inner == c.IN and any(kind in (c.CATEGORY, c.NEGATE) for kind, _ in value)


def _unsafe_shape(pattern: str) -> str | None:
    """Why a term could run for a long time or match nothing, or None. Terms are plain words with a few bounded
    repeats: no repeat whose body can match nothing or holds another repeat, no alternation inside a repeat, no back
    reference, no pattern that can match the empty string, at most TERMS_OPTIONAL_CAP optional parts and alternatives
    together (each doubles the work), no two wildcard repeats next to each other, and a product of repeat bounds under
    TERMS_WORK_CAP."""
    try:
        tree = _RE_PARSER.parse(pattern, re.IGNORECASE)
    except (re.error, RecursionError, OverflowError):
        return "an invalid expression"
    c = _RE_CONSTANTS
    if tree.getwidth()[0] == 0:
        return "an expression that can match the empty string"
    work = [1]
    optional = [0]
    crowded = "too many optional parts, alternatives or repeats multiplying together"

    def walk(items: Any, in_repeat: bool) -> str | None:
        previous_wild = False
        for op, av in items:
            wild = _is_wildcard_repeat(op, av)
            if wild and previous_wild:
                return "two wildcard repeats next to each other"
            previous_wild = wild
            if op in (c.MAX_REPEAT, c.MIN_REPEAT, c.POSSESSIVE_REPEAT):
                low, high, sub = av
                if high == c.MAXREPEAT or high > TERMS_REPEAT_CAP:
                    return "an unbounded repeat (use {1,40} instead of + or *)"
                if in_repeat:
                    return "a repeat inside a repeat"
                if sub.getwidth()[0] == 0:
                    return "a repeat of something that can match nothing"
                if low == 0 and high == 1:
                    optional[0] += 1
                    work[0] *= 2
                else:
                    work[0] *= max(high, 1)
                if work[0] > TERMS_WORK_CAP or optional[0] > TERMS_OPTIONAL_CAP:
                    return crowded
                found = walk(sub, True)
            elif op == c.SUBPATTERN:
                found = walk(av[3], in_repeat)
            elif op == c.BRANCH:
                if in_repeat:
                    return "an alternation inside a repeat"
                optional[0] += len(av[1]) - 1
                work[0] *= len(av[1])
                if work[0] > TERMS_WORK_CAP or optional[0] > TERMS_OPTIONAL_CAP:
                    return crowded
                found = next((r for r in (walk(branch, in_repeat) for branch in av[1]) if r), None)
            elif op in (c.GROUPREF, c.GROUPREF_EXISTS):
                return "a back reference"
            elif op in (c.ASSERT, c.ASSERT_NOT):
                found = walk(av[1], in_repeat)
            elif op == c.ATOMIC_GROUP:
                found = walk(av, in_repeat)
            else:
                found = None
            if found:
                return found
        return None

    found = walk(tree, False)
    if found:
        return found
    if termsearch.reach(pattern, re.IGNORECASE) > termsearch.TERMS_OVERLAP:
        return f"an expression too wide (a match, with any look-around, must fit {termsearch.TERMS_OVERLAP} characters)"
    return None


def load_private_terms(setting: str, default: Path | None = None) -> tuple[re.Pattern[str], ...]:
    """The maintainer's private terms (one expression a line), strictly, and the one loader the wrapper and the dispatch
    guard both use: a file that is missing, unreadable, too large, over the count or the line cap, or holds an invalid,
    empty-matching or slow-looking expression stops the call, because a list that failed to load would let a private
    term through. `none` is the explicit, written-down opt-out."""
    if setting == "none":
        return ()
    path = default if setting == "default" and default is not None else Path(setting)
    try:
        text = read_bounded(path, TERMS_FILE_BYTES).decode("utf-8")
    except (OSError, UnicodeError):
        raise RefusedError(
            "the private terms file cannot be read, so nothing was sent (set private_terms: none to opt out)"
        ) from None
    if len(text.encode("utf-8")) >= TERMS_FILE_BYTES:
        raise RefusedError("the private terms file is too large, so nothing was sent")
    found: list[re.Pattern[str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if len(line) > TERMS_LINE_CAP or len(found) >= TERMS_COUNT_CAP:
            raise RefusedError(f"the private terms file has a line or a count over the limit (line {number})")
        problem = _unsafe_shape(line)
        if problem:
            raise RefusedError(f"the private terms file has {problem} (line {number}), so nothing was sent")
        found.append(re.compile(line, re.IGNORECASE))
    return tuple(found)


def private_term_hit(terms: tuple[re.Pattern[str], ...], texts: list[str], timeout: float = TERMS_SECONDS) -> bool:
    """True when any term matches any text. The search runs in a child process that is killed at `timeout`; a child
    that does not answer in time, or fails, raises TermsCheckError, which callers treat as a hit."""
    if not terms:
        return False
    if any("\n" in t.pattern for t in terms):
        raise TermsCheckError("a private term spans lines, so it cannot be checked and counts as a match")
    body = "\x00".join(t.replace("\x00", " ") for t in texts)
    payload = "".join(f"{t.flags}\t{t.pattern}\n" for t in terms) + "\n" + body
    try:
        done = subprocess.run(  # noqa: S603 - this interpreter and the worker file beside the package, no shell
            [sys.executable, "-I", termsearch.__file__, str(math.ceil(timeout) + 2)],
            start_new_session=True,
            input=payload,
            capture_output=True,
            text=True,
            check=False,
            timeout=max(timeout, 0.1),
        )
    except subprocess.TimeoutExpired:
        raise TermsCheckError("the private terms check ran out of time, so it counts as a match") from None
    except (OSError, UnicodeError):  # the worker could not start, or a text cannot be encoded (a lone surrogate)
        raise TermsCheckError("the private terms check could not run, so it counts as a match") from None
    answer = done.stdout.strip()
    if done.returncode != 0 or answer not in ("0", "1"):
        raise TermsCheckError("the private terms check failed, so it counts as a match")
    return answer == "1"


# -- the key -------------------------------------------------------------------------------------------------------

KeyProvider = Callable[[str], str]


def doppler_key_provider(cfg: GeminiConfig, env: Mapping[str, str]) -> KeyProvider:
    """The FREE key, read by NAME from Doppler at call time. The value comes back on a pipe: it is never in argv,
    never in a file and never in a message. Only the names are on the command line. There is no paid key to read here:
    the paid key exists only in the broker's own credential (#287), so any other tier is refused."""

    def read(tier: str) -> str:
        if tier != "free":
            raise RefusedError(PAID_ELSEWHERE)
        exe = find_executable("doppler", env)
        if exe is None:
            raise RefusedError("the secret tool (doppler) was not found on PATH; no key was read")
        config = cfg.free_config
        argv = [exe, "secrets", "get", cfg.key_name, "--plain", "--project", cfg.project, "--config", config]
        child = {
            k: v for k, v in env.items() if k in ("PATH", "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME")
        }
        child.update({k: v for k, v in env.items() if k.startswith("DOPPLER_")})
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv of names, absolute executable, no shell, stdin closed
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=SECRET_TOOL_TIMEOUT,
                env=child,
            )
        except (OSError, subprocess.TimeoutExpired, UnicodeError):
            raise RefusedError("the secret store did not answer; no key was read") from None
        value = done.stdout.strip("\n")
        if done.returncode != 0:
            raise RefusedError(f"the secret store refused the read (exit {done.returncode}); no key was read")
        if not PLAIN_KEY.fullmatch(value):
            raise RefusedError("the secret store returned something that is not a plain API key")
        return value

    return read


# -- the call ------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Reply:
    text: str
    prompt_tokens: int | None
    output_tokens: int | None
    cost_usd: Decimal
    estimated: bool
    quota_line: str = ""
    note: str = ""


def _connection(cfg: GeminiConfig) -> http.client.HTTPConnection:
    parts = urlsplit(cfg.endpoint)
    if parts.scheme == "https":
        return netguard.PinnedHTTPSConnection(parts.hostname or "", parts.port or 443, timeout=cfg.timeout_seconds)
    return netguard.PinnedHTTPConnection(parts.hostname or "", parts.port or 80, timeout=cfg.timeout_seconds)


def _retry_after(value: str | None) -> str:
    try:
        seconds = float(value or "")
    except ValueError:
        return ""
    return f" Retry-After {seconds:g} s." if math.isfinite(seconds) and 0 < seconds <= MAX_RETRY_AFTER else ""


def _reason(body: object) -> str:
    error = body.get("error") if isinstance(body, dict) else None
    status = error.get("status") if isinstance(error, dict) else None
    return f" {status}" if isinstance(status, str) and re.fullmatch(r"[A-Z_]{3,40}", status) else ""


def _post(cfg: GeminiConfig, req: Request, key: str, prompt: bytes) -> tuple[int, Mapping[str, str], bytes]:
    """One POST of a free-tier request. A failure before the request leaves is RefusedError; after it, the caller
    treats it as unknown.

    `prompt` is the one snapshot of the prompt bytes taken at the start of `ask`; the body is built from it and from
    nothing else."""
    body = json.dumps(
        {
            "contents": [{"role": "user", "parts": [{"text": bytes.decode(prompt, "utf-8")}]}],
            "generationConfig": {"maxOutputTokens": req.max_output_tokens or cfg.max_output_tokens},
        }
    ).encode()
    conn = _connection(cfg)
    try:
        try:
            conn.connect()
        except (OSError, netguard.BlockedDestinationError):
            raise RefusedError("could not connect to the Gemini endpoint; nothing was sent") from None
        conn.request(
            "POST",
            f"/v1beta/models/{req.model}:generateContent",
            body=body,
            headers={"Content-Type": "application/json", "x-goog-api-key": key},
        )
        response = conn.getresponse()
        data = response.read(MAX_BYTES + 1)
        return response.status, {k.lower(): v for k, v in response.getheaders()}, data
    finally:
        conn.close()


def _unknown(cfg: GeminiConfig, what: str, quota: str) -> OutcomeUnknownError:
    return OutcomeUnknownError(
        f"outcome unknown ({what}): the request left and its result cannot be told, so it is recorded and "
        f"not repeated; check the vendor dashboard before deciding. {quota}"
    )


def ask(
    cfg: GeminiConfig,
    req: Request,
    *,
    key_for: KeyProvider,
    now: dt.datetime,
) -> Reply:
    """Send one free-tier request, once, or say which gate stopped it. A paid request is refused first of all: the
    paid path exists only through the broker."""
    # One plain copy of every field, taken once at the entry. Nothing below reads the caller's object again, and the
    # body is built from the prompt bytes snapshotted here (#217).
    req = canonical_request(req)
    now = plain_time(now, "now")
    if req.tier != "free":
        raise RefusedError(PAID_ELSEWHERE)  # before anything else: no gate is run and no key is read for it
    prompt_raw = str.encode(req.prompt, "utf-8")
    _check_request(cfg, req)
    terms = load_private_terms(cfg.private_terms, fixed_locations().terms if cfg.private_terms == "default" else None)
    if private_term_hit(terms, [req.prompt, fold(req.prompt)]):
        raise RefusedError("the prompt matches one of the maintainer's private terms; nothing was sent")
    ledger = Ledger(cfg.ledger)
    snap = snapshot(ledger.read())
    if req.model not in cfg.free:
        raise RefusedError(f"the model {req.model} is not configured for the free tier")
    _gate_free(cfg, snap, req, now)
    key = key_for("free")  # only now: a refused call never reads a key
    call_id = secrets.token_hex(6)
    with ledger.lock():
        snap = snapshot(ledger.read())  # again, under the lock: another caller may have used the room
        _gate_free(cfg, snap, req, now)
        ledger.append(
            {
                "type": "call_start",
                "call_id": call_id,
                "ts": stamp(now),
                "date": stamp(now)[:10],
                "tier": "free",
                "model": req.model,
                "est_input_tokens": estimate_input_tokens(req.prompt),
                "est_usd": 0.0,
                "job": req.job,
                "approval": "",
            }
        )

    def finish(
        status: str, http_status: int | None, prompt: int | None, out: int | None, actual: Decimal | None
    ) -> None:
        row = {
            "type": "call_end",
            "call_id": call_id,
            "ts": stamp(now),
            "status": status,
            "http": http_status,
            "prompt_tokens": prompt,
            "output_tokens": out,
            "actual_usd": None if actual is None else float(actual),
        }
        with ledger.lock():
            ledger.append(row)

    def line_now() -> str:
        try:
            return free_quota(cfg, snapshot(ledger.read()), req.model, now).line()
        except (GeminiError, ConfigError):
            return "(the quota line could not be rebuilt)"

    try:
        status, headers, raw = _post(cfg, req, key, prompt_raw)
    except RefusedError:
        finish("not_sent", None, None, None, Decimal(0))
        raise
    except (OSError, http.client.HTTPException):
        finish("ambiguous", None, None, None, None)
        raise _unknown(cfg, "no answer", line_now()) from None
    finally:
        key = ""
    if status == 429:
        finish("rate_limited", 429, None, None, Decimal(0))
        try:
            reason = _reason(loads(raw))
        except (ValueError, UnicodeError):
            reason = ""
        raise RateLimitStopError(
            f"Gemini answered 429{reason}: the job is stopped, not retried, and never falls through to a paid call."
            f"{_retry_after(headers.get('retry-after'))} {line_now()}"
        )
    if 300 <= status < 400 or status >= 500 or status == 408 or len(raw) > MAX_BYTES:
        finish("ambiguous", status, None, None, None)
        raise _unknown(cfg, f"HTTP {status}", line_now())
    if status >= 400:
        try:
            reason = _reason(loads(raw))
        except (ValueError, UnicodeError):
            reason = ""
        finish("http_error", status, None, None, Decimal(0))
        raise RefusedError(f"Gemini rejected the request with {status}{reason}; it was not repeated. {line_now()}")
    try:
        answer = loads(raw)
        parts = answer["candidates"][0]["content"]["parts"] if answer.get("candidates") else []
        text = "".join(p["text"] for p in parts if isinstance(p, dict) and isinstance(p.get("text"), str))
        usage = answer.get("usageMetadata")
        prompt_tokens = out_tokens = None
        if isinstance(usage, dict) and "promptTokenCount" in usage:
            prompt_tokens = count(usage["promptTokenCount"])
            out_tokens = count(usage.get("candidatesTokenCount", 0)) + count(usage.get("thoughtsTokenCount", 0))
    except (ValueError, UnicodeError, KeyError, IndexError, TypeError, AttributeError):
        finish("ambiguous", status, None, None, None)
        raise _unknown(cfg, "unreadable answer", line_now()) from None
    finish("ok", status, prompt_tokens, out_tokens, Decimal(0))
    note = "" if text else "the answer held no text (the vendor may have blocked it)"
    return Reply(text, prompt_tokens, out_tokens, Decimal(0), False, line_now(), note)
