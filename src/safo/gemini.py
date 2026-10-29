# SPDX-License-Identifier: Apache-2.0
"""A Gemini client that cannot spend money on its own (#200, #195, #196).

Gemini is a free-only provider for public-material research. The free tier may train on prompts and be read by people,
so nothing private goes to it. Three gates sit in code, never in a model:

* the free tier follows the maintainer's own rate limits (requests and input tokens per minute, requests per day, the
  day ending at midnight Pacific), counted from a local, append-only ledger; a 429 stops the job and never falls
  through to the paid tier;
* a paid call needs its own approval record (a quote of the maintainer's message and its time), single use, bound to a
  model and a job, expiring with the job; the estimate must fit 2 USD per job and 10 USD per month, and past the month
  the record must say so;
* the key is read by name from the secret store at call time and held only for the one request.

A request is sent once. After the request leaves, a timeout, a 5xx, a closed connection, a redirect or an unreadable
answer is UNKNOWN, not failed: it is recorded as ambiguous (a paid one counts its estimate as spent) and never
repeated. There is no retry and so no backoff to bound.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import http.client
import importlib
import json
import math
import os
import pwd
import re
import secrets
import subprocess
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import ROUND_CEILING, ROUND_HALF_UP, Decimal, InvalidOperation
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import yaml

from safo import netguard
from safo.bounded import MAX_BYTES, MAX_FILE_BYTES, count, loads, read_bounded
from safo.credentials import find_executable
from safo.errors import ConfigError, SafoError
from safo.guardlog import ensure_dir, file_lock, write_text
from safo.schema import Reader, _safe_load
from safo.trust import read_trusted_regular_file

VENDOR_HOST = "generativelanguage.googleapis.com"
JOB_CAP = Decimal("2")  # per job, in USD: a configuration may lower it, never raise it
MONTH_CAP = Decimal("10")  # per month, in USD; past it every further block needs its own approval
BLOCK = Decimal("2")
PACIFIC = ZoneInfo("America/Los_Angeles")
TIERS = ("free", "paid")
MODEL_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
RECORD_ID = re.compile(r"[A-Za-z0-9_-]{8,64}")
JOB_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}")
PLAIN_KEY = re.compile(r"[\x21-\x7e]{16,512}")
MAX_PROMPT_BYTES = 200_000
MAX_QUOTE = 500
MAX_TTL_MINUTES = 24 * 60
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
class Price:
    input_per_mtok: Decimal
    output_per_mtok: Decimal
    valid_through: dt.date
    image: bool = False


@dataclass(frozen=True)
class GeminiConfig:
    endpoint: str
    price_source: str
    price_checked: dt.date
    project: str
    free_config: str
    paid_config: str
    key_name: str
    job_cap: Decimal
    month_cap: Decimal
    block: Decimal
    ledger: Path
    timeout_seconds: float
    max_output_tokens: int
    free: Mapping[str, FreeLimits]
    prices: Mapping[str, Price]
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
            "price_source",
            "price_checked",
            "secrets",
            "caps",
            "ledger",
            "timeout_seconds",
            "max_output_tokens",
            "free",
            "paid",
            "private_terms",
        },
        {"version", "endpoint", "price_source", "price_checked", "secrets", "free", "paid"},
    )
    if top["version"] != 1:
        raise r.fail("version", "only version 1 is supported")
    sec = r.mapping(
        top["secrets"],
        "secrets",
        {"project", "free_config", "paid_config", "key_name"},
        {"project", "free_config", "paid_config", "key_name"},
    )
    names = {k: r.string(sec[k], f"secrets.{k}") for k in sec}
    for key, name in names.items():
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            raise r.fail(f"secrets.{key}", "expected a plain name (letters, digits, . _ -)")
    caps = r.mapping(top.get("caps", {}), "caps", {"job_usd", "month_usd", "block_usd"})
    job = _decimal(caps.get("job_usd", JOB_CAP), "caps.job_usd")
    month = _decimal(caps.get("month_usd", MONTH_CAP), "caps.month_usd")
    block = _decimal(caps.get("block_usd", BLOCK), "caps.block_usd")
    for label, amount, ceiling in (
        ("job_usd", job, JOB_CAP),
        ("month_usd", month, MONTH_CAP),
        ("block_usd", block, BLOCK),
    ):
        if amount <= 0 or amount > ceiling:
            raise r.fail(f"caps.{label}", f"a cap may be lowered, never raised: it is at most {ceiling} USD")
    prices: dict[str, Price] = {}
    for model, raw in r.mapping(top["paid"], "paid", set(top["paid"] or {})).items():
        where = f"paid.{model}"
        if not MODEL_NAME.fullmatch(str(model)):
            raise r.fail(where, "not a model name")
        m = r.mapping(
            raw,
            where,
            {"input_per_mtok", "output_per_mtok", "valid_through", "modality"},
            {"input_per_mtok", "output_per_mtok", "valid_through"},
        )
        prices[str(model)] = Price(
            _decimal(m["input_per_mtok"], f"{where}.input_per_mtok", maximum=Decimal(1000)),
            _decimal(m["output_per_mtok"], f"{where}.output_per_mtok", maximum=Decimal(1000)),
            r.date(m["valid_through"], f"{where}.valid_through"),
            r.choice(m.get("modality", "text"), f"{where}.modality", ("text", "image")) == "image",
        )
    free: dict[str, FreeLimits] = {}
    for model, raw in r.mapping(top["free"], "free", set(top["free"] or {})).items():
        where = f"free.{model}"
        if not MODEL_NAME.fullmatch(str(model)):
            raise r.fail(where, "not a model name")
        if prices.get(str(model), Price(Decimal(0), Decimal(0), dt.date.min)).image:
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
        r.string(top["price_source"], "price_source"),
        r.date(top["price_checked"], "price_checked"),
        names["project"],
        names["free_config"],
        names["paid_config"],
        names["key_name"],
        job,
        month,
        block,
        ledger,
        float(timeout),
        r.integer(top.get("max_output_tokens", 2048), "max_output_tokens", minimum=1),
        free,
        prices,
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


class Ledger:
    """Append-only JSON lines, outside git. A line it cannot read stops every call: a counter that skips a line could
    undercount spend."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> list[dict[str, Any]]:
        try:
            raw = read_bounded(self.path, MAX_FILE_BYTES + 1)
        except FileNotFoundError:
            others = sorted(p for p in self.path.parent.parent.glob(f"*/{self.path.name}") if p != self.path)
            if others:
                raise RefusedError(
                    "this ledger does not exist yet, but another ledger with the same name does: starting an empty "
                    "one would read 0 spent. Move the real one here, or point `ledger:` in gemini.yaml at it"
                ) from None
            return []
        except OSError:
            raise RefusedError(
                "the spend ledger is not a plain readable file (a link, a pipe or no permission)"
            ) from None
        if len(raw) > MAX_FILE_BYTES:
            raise RefusedError("the spend ledger is larger than the reader allows; archive it by hand first")
        rows: list[dict[str, Any]] = []
        for number, line in enumerate(raw.splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = loads(line)
            except (ValueError, UnicodeError):
                row = None
            if not isinstance(row, dict):
                raise RefusedError(f"the spend ledger has an unreadable line ({number}); fix it by hand")
            rows.append(row)
        return rows

    def append(self, row: dict[str, Any]) -> None:
        data = (json.dumps(row, sort_keys=True) + "\n").encode()
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


def _bad(number: int) -> RefusedError:
    return RefusedError(f"the spend ledger has a malformed row (record {number}); fix it by hand")


def snapshot(rows: list[dict[str, Any]]) -> Snapshot:
    starts: dict[str, Call] = {}
    ends: dict[str, dict[str, Any]] = {}
    manual: list[tuple[str, Decimal]] = []
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
            elif kind == "funding":
                continue
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
    return Snapshot(tuple(calls), tuple(manual))


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
class PaidQuota:
    model: str
    spent: Decimal
    estimate: Decimal
    job_cap: Decimal
    month_cap: Decimal

    @property
    def after(self) -> Decimal:
        return self.spent + self.estimate

    @property
    def beyond(self) -> bool:
        return self.after > self.month_cap

    def line(self) -> str:
        return (
            f"QUOTA paid {self.model}: spent {money(self.spent)} of {money(self.month_cap)} USD this month "
            f"(UTC calendar month); this job's estimate {money(self.estimate)} USD of the {money(self.job_cap)} USD "
            f"job cap; running total after this job {money(self.after)} of {money(self.month_cap)}; "
            f"beyond ceiling: {'YES' if self.beyond else 'no'}"
        )


def month_spent(snap: Snapshot, now: dt.datetime) -> Decimal:
    key = now.astimezone(dt.UTC).strftime("%Y-%m")
    total = sum((c.spent for c in snap.calls if c.tier == "paid" and c.when.strftime("%Y-%m") == key), Decimal(0))
    return total + sum((amount for date, amount in snap.manual if date[:7] == key), Decimal(0))


@dataclass(frozen=True)
class Request:
    model: str
    prompt: str
    tier: str
    job: str = ""
    approval: str = ""
    max_output_tokens: int = 0


def estimate_usd(cfg: GeminiConfig, req: Request, now: dt.datetime) -> Decimal:
    """An upper bound: the prompt overestimated, and every output token the request allows."""
    price = cfg.prices.get(req.model)
    if price is None:
        raise RefusedError(f"the quota line cannot be produced: no price is configured for {req.model}")
    if price.valid_through < now.astimezone(dt.UTC).date():
        raise RefusedError(
            f"the price table for {req.model} is out of date (valid through {price.valid_through}); "
            f"re-read {cfg.price_source} and update the table before any paid call"
        )
    out = req.max_output_tokens or cfg.max_output_tokens
    total = Decimal(estimate_input_tokens(req.prompt)) * price.input_per_mtok + Decimal(out) * price.output_per_mtok
    return (total / Decimal(1_000_000)).quantize(Decimal("0.000001"), rounding=ROUND_CEILING)


def paid_quota(cfg: GeminiConfig, snap: Snapshot, req: Request, now: dt.datetime) -> PaidQuota:
    return PaidQuota(req.model, month_spent(snap, now), estimate_usd(cfg, req, now), cfg.job_cap, cfg.month_cap)


def _check_request(cfg: GeminiConfig, req: Request) -> None:
    if req.tier not in TIERS:
        raise RefusedError("the tier is free or paid")
    if not MODEL_NAME.fullmatch(req.model):
        raise RefusedError("the model name is not a plain model name")
    if len(req.prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
        raise RefusedError(f"the prompt is larger than {MAX_PROMPT_BYTES} bytes; cut it down")
    if has_secret_shape(req.prompt):
        raise RefusedError("the prompt holds something shaped like a secret or a private key; nothing was sent")
    if req.max_output_tokens < 0:
        raise RefusedError("max output tokens cannot be negative")


def quota_line(cfg: GeminiConfig, req: Request, now: dt.datetime) -> str:
    """The line printed before any approval and before any call. It cannot be produced without the numbers."""
    _check_request(cfg, req)
    snap = snapshot(Ledger(cfg.ledger).read())
    if req.tier == "free":
        return free_quota(cfg, snap, req.model, now).line()
    return paid_quota(cfg, snap, req, now).line()


# -- approvals -----------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Locations:
    """Where the config, the approval records and the private-terms file live. Fixed: no flag and no environment
    variable moves them (a test points them into a temporary directory through the `fixed_locations` seam)."""

    home: Path
    config: Path
    approvals: Path
    terms: Path


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


@dataclass(frozen=True)
class Approval:
    id: str
    model: str
    max_usd: Decimal
    job: str
    quote: str
    quoted_at: dt.datetime
    created: dt.datetime
    expires_at: dt.datetime
    beyond_ceiling: bool
    issue: str = ""


class ApprovalStore:
    """One JSON file per approval, mode 0600, in a private folder; a `.used` marker beside it spends it exactly once.

    A record is evidence of what the maintainer said, written by whoever ran `safo gemini approve`: it is not proof
    that he said it, and the quote is there so he can check it afterwards.
    """

    def __init__(self, folder: Path) -> None:
        self.folder = folder

    def issue(
        self,
        *,
        model: str,
        max_usd: Decimal,
        job: str,
        quote: str,
        quoted_at: dt.datetime,
        now: dt.datetime,
        ttl_minutes: int,
        beyond_ceiling: bool,
        issue_ref: str = "",
    ) -> Approval:
        if not MODEL_NAME.fullmatch(model):
            raise ConfigError("approval: the model name is not a plain model name")
        if not JOB_NAME.fullmatch(job):
            raise ConfigError("approval: the job is a plain name (letters, digits, . _ -), at most 64 characters")
        if not max_usd.is_finite() or not 0 < max_usd <= JOB_CAP:
            raise ConfigError(f"approval: the amount is above 0 and at most the {money(JOB_CAP)} USD job cap")
        if (
            not quote.strip()
            or len(quote) > MAX_QUOTE
            or any(ord(c) < 32 or unicodedata.category(c) in ("Cf", "Cc", "Zl", "Zp") for c in quote)
        ):
            raise ConfigError(f"approval: the quote is the maintainer's message, 1 to {MAX_QUOTE} characters, one line")
        if quoted_at > now + dt.timedelta(minutes=1) or quoted_at < now - dt.timedelta(hours=24):
            raise ConfigError("approval: the quote's time is in the future or more than a day old; ask again")
        if not 1 <= ttl_minutes <= MAX_TTL_MINUTES:
            raise ConfigError(f"approval: the record lives 1 to {MAX_TTL_MINUTES} minutes")
        record = Approval(
            secrets.token_hex(8),
            model,
            max_usd,
            job,
            quote,
            quoted_at,
            now,
            now + dt.timedelta(minutes=ttl_minutes),
            beyond_ceiling,
            issue_ref[:80],
        )
        data = {
            "id": record.id,
            "model": model,
            "max_usd": str(max_usd),
            "job": job,
            "quote": quote,
            "quoted_at": stamp(quoted_at),
            "created": stamp(now),
            "expires_at": stamp(record.expires_at),
            "beyond_ceiling": beyond_ceiling,
            "issue": record.issue,
        }
        write_text(self.folder / f"{record.id}.json", json.dumps(data, sort_keys=True) + "\n")
        return record

    def load(self, record_id: str) -> Approval:
        if not RECORD_ID.fullmatch(record_id):
            raise RefusedError("a paid call needs an approval record: pass its id")
        try:
            data = loads(read_bounded(self.folder / f"{record_id}.json", 8192))
            if not isinstance(data, dict) or data.get("id") != record_id:
                raise ValueError("record")
            quoted = _parse_stamp(data["quoted_at"])
            created = _parse_stamp(data["created"])
            expires = _parse_stamp(data["expires_at"])
            if quoted is None or created is None or expires is None or not isinstance(data["beyond_ceiling"], bool):
                raise ValueError("record")
            return Approval(
                record_id,
                str(data["model"]),
                _decimal(data["max_usd"], "max_usd"),
                str(data["job"]),
                str(data["quote"]),
                quoted,
                created,
                expires,
                data["beyond_ceiling"],
                str(data.get("issue", "")),
            )
        except FileNotFoundError:
            raise RefusedError("there is no approval record with that id; a paid call needs one") from None
        except (OSError, ValueError, KeyError, ConfigError):
            raise RefusedError("the approval record cannot be read; ask for a fresh one") from None

    def is_used(self, record_id: str) -> bool:
        return os.path.lexists(self.folder / f"{record_id}.used")

    def consume(self, record_id: str) -> None:
        """Atomic: the marker is created exclusively, so two callers cannot both spend one record."""
        ensure_dir(self.folder)
        try:
            fd = os.open(self.folder / f"{record_id}.used", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            raise RefusedError("this approval record was already used; each paid call needs a fresh one") from None
        except OSError:
            raise RefusedError("the approval record cannot be marked used; nothing was sent") from None
        os.close(fd)


def approval_problem(store: ApprovalStore, record_id: str, now: dt.datetime) -> str | None:
    """Why a record cannot be used now, or None when it is live. For the dispatch guard; it spends nothing."""
    try:
        record = store.load(record_id)
    except GeminiError as err:
        return str(err)
    if store.is_used(record_id):
        return "this approval record was already used"
    if now >= record.expires_at:
        return "this approval record has expired"
    return None


def _gate_paid(
    cfg: GeminiConfig, store: ApprovalStore, snap: Snapshot, req: Request, now: dt.datetime
) -> tuple[Approval, Decimal]:
    if not req.approval:
        raise RefusedError("a paid call needs an approval record (--approval ID); none was given")
    record = store.load(req.approval)
    if store.is_used(record.id):
        raise RefusedError("this approval record was already used; each paid call needs a fresh one")
    if now >= record.expires_at:
        raise RefusedError("this approval record has expired; ask for a fresh one")
    if record.model != req.model:
        raise RefusedError(f"this approval record is for another model than {req.model}")
    if not req.job or record.job != req.job:
        raise RefusedError("this approval record is for another job; an approval is not inherited")
    quota = paid_quota(cfg, snap, req, now)
    if quota.estimate > cfg.job_cap:
        raise RefusedError(
            f"the estimate {money(quota.estimate)} USD is over the {money(cfg.job_cap)} USD job cap; "
            "lower the output limit"
        )
    if quota.estimate > record.max_usd:
        raise RefusedError(
            f"the estimate {money(quota.estimate)} USD is over the approved {money(record.max_usd)} USD; ask again"
        )
    if quota.beyond and not record.beyond_ceiling:
        raise RefusedError(
            f"this job would pass the {money(cfg.month_cap)} USD monthly ceiling ({money(quota.after)} in all); "
            f"past it every further {money(cfg.block)} USD needs its own approval that says so (--beyond-ceiling)"
        )
    return record, quota.estimate


def _gate_free(cfg: GeminiConfig, snap: Snapshot, req: Request, now: dt.datetime) -> None:
    price = cfg.prices.get(req.model)
    if price is not None and price.image:
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
TERMS_CHUNK = 4000  # characters one term sees at a time
TERMS_REPEAT_CAP = 99  # a repeat in a term is bounded: {1,40}, never + or *

_RE_PARSER = importlib.import_module("re._parser")  # private, but the only way to read a pattern's shape (3.11+)
_RE_CONSTANTS = importlib.import_module("re._constants")


def _unsafe_shape(pattern: str) -> str | None:
    """Why a term could run for a long time, or None. Terms are plain words with bounded repeats: no unbounded repeat,
    no repeat inside a repeat, no alternation inside a repeat, no back reference."""
    try:
        tree = _RE_PARSER.parse(pattern, re.IGNORECASE)
    except (re.error, RecursionError, OverflowError):
        return "an invalid expression"
    c = _RE_CONSTANTS

    def walk(items: Any, in_repeat: bool) -> str | None:
        for op, av in items:
            if op in (c.MAX_REPEAT, c.MIN_REPEAT, c.POSSESSIVE_REPEAT):
                _, high, sub = av
                if high == c.MAXREPEAT or high > TERMS_REPEAT_CAP:
                    return "an unbounded repeat (use {1,40} instead of + or *)"
                if in_repeat and high > 1:
                    return "a repeat inside a repeat"
                found = walk(sub, in_repeat or high > 1)
            elif op == c.SUBPATTERN:
                found = walk(av[3], in_repeat)
            elif op == c.BRANCH:
                if in_repeat:
                    return "an alternation inside a repeat"
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

    return walk(tree, False)


def load_private_terms(setting: str, default: Path | None = None) -> tuple[re.Pattern[str], ...]:
    """The maintainer's private terms (one expression a line), strictly, and the one loader the wrapper and the dispatch
    guard both use: a file that is missing, unreadable, too large, over the count or the line cap, or holds an invalid
    or dangerous expression stops the call, because a list that failed to load would let a private term through.
    `none` is the explicit, written-down opt-out."""
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


def private_term_hit(terms: tuple[re.Pattern[str], ...], text: str, tick: Callable[[], None] | None = None) -> bool:
    """True when any term matches. Each term sees at most TERMS_CHUNK characters at a time (chunks overlap by 200),
    and `tick` may raise to stop the work."""
    step = TERMS_CHUNK - 200
    for start in range(0, max(len(text), 1), step):
        chunk = text[start : start + TERMS_CHUNK]
        for term in terms:
            if tick is not None:
                tick()
            if term.search(chunk):
                return True
    return False


# -- the key -------------------------------------------------------------------------------------------------------

KeyProvider = Callable[[str], str]


def doppler_key_provider(cfg: GeminiConfig, env: Mapping[str, str]) -> KeyProvider:
    """The key for a tier, read by NAME from Doppler at call time. The value comes back on a pipe: it is never in
    argv, never in a file and never in a message. Only the names are on the command line."""

    def read(tier: str) -> str:
        exe = find_executable("doppler", env)
        if exe is None:
            raise RefusedError("the secret tool (doppler) was not found on PATH; no key was read")
        config = cfg.free_config if tier == "free" else cfg.paid_config
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


def _post(cfg: GeminiConfig, req: Request, key: str) -> tuple[int, Mapping[str, str], bytes]:
    """One POST. A failure before the request leaves is RefusedError; after it, the caller treats it as unknown."""
    body = json.dumps(
        {
            "contents": [{"role": "user", "parts": [{"text": req.prompt}]}],
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
    store: ApprovalStore,
    key_for: KeyProvider,
    now: dt.datetime,
) -> Reply:
    """Send one request, once, or say which gate stopped it."""
    _check_request(cfg, req)
    terms = load_private_terms(cfg.private_terms, fixed_locations().terms if cfg.private_terms == "default" else None)
    if private_term_hit(terms, req.prompt):
        raise RefusedError("the prompt matches one of the maintainer's private terms; nothing was sent")
    ledger = Ledger(cfg.ledger)
    snap = snapshot(ledger.read())
    if req.tier == "paid":
        _gate_paid(cfg, store, snap, req, now)
    else:
        if req.model not in cfg.free:
            raise RefusedError(f"the model {req.model} is not configured for the free tier")
        _gate_free(cfg, snap, req, now)
    key = key_for(req.tier)  # only now: a refused call never reads a key
    call_id = secrets.token_hex(6)
    with ledger.lock():
        snap = snapshot(ledger.read())  # again, under the lock: another caller may have used the room
        record: Approval | None = None
        est = Decimal(0)
        if req.tier == "paid":
            record, est = _gate_paid(cfg, store, snap, req, now)
            store.consume(record.id)  # spent before the request leaves, so a crash can never allow a replay
        else:
            _gate_free(cfg, snap, req, now)
        ledger.append(
            {
                "type": "call_start",
                "call_id": call_id,
                "ts": stamp(now),
                "date": stamp(now)[:10],
                "tier": req.tier,
                "model": req.model,
                "est_input_tokens": estimate_input_tokens(req.prompt),
                "est_usd": float(est),
                "job": req.job,
                "approval": record.id if record else "",
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
            current = snapshot(ledger.read())
            if req.tier == "free":
                return free_quota(cfg, current, req.model, now).line()
            return paid_quota(cfg, current, req, now).line()
        except (GeminiError, ConfigError):
            return "(the quota line could not be rebuilt)"

    try:
        status, headers, raw = _post(cfg, req, key)
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
            f"Gemini answered 429{reason}: the job is stopped, not retried, and never falls through to the paid tier."
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
    actual: Decimal | None
    price = cfg.prices.get(req.model)
    if req.tier == "free":
        actual = Decimal(0)
    elif prompt_tokens is not None and out_tokens is not None and price is not None:
        # What was reported, never less than a floor from the sizes of what was sent and received, and when the
        # reported counts are implausibly low for those sizes the estimate (an upper bound) stands instead.
        prompt_floor = len(req.prompt.encode("utf-8")) // 8
        out_floor = len(text.encode("utf-8")) // 8
        low = prompt_tokens < prompt_floor or out_tokens < out_floor
        used_in, used_out = max(prompt_tokens, prompt_floor), max(out_tokens, out_floor)
        actual = (Decimal(used_in) * price.input_per_mtok + Decimal(used_out) * price.output_per_mtok) / Decimal(
            1_000_000
        )
        if low:
            actual = max(actual, est)
    else:
        actual = None  # no usage in the answer: the estimate stands as the spend
    finish("ok", status, prompt_tokens, out_tokens, actual)
    note = "" if text else "the answer held no text (the vendor may have blocked it)"
    if req.tier == "paid" and actual is None:
        note = (note + "; " if note else "") + "no usage came back, so the estimate counts as spent"
    return Reply(
        text, prompt_tokens, out_tokens, actual if actual is not None else est, actual is None, line_now(), note
    )
