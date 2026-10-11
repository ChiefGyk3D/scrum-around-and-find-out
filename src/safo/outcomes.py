# SPDX-License-Identifier: MIT
"""The outcomes log: one JSON line per finished task, so routing can be judged by what happened, not by feeling.

A record: date, card (a GitHub URL or null), agent, shape, review_rounds (review passes, the passing one included),
findings by severity, tokens and requests when known, and a note. Optional `model` (the underlying model of the
run) and `credits_used` (credits or premium requests consumed) make agents comparable on cost against rework; a record
without them stays valid and is written without those keys. Appended one line at a time.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Any

from safo.bounded import DuplicateKeyError, loads
from safo.bounded import month as valid_month
from safo.errors import ConfigError
from safo.guardlog import bounded_read, file_lock, write_text

SEVERITIES = ("critical", "important", "minor", "unrated")
CARD = re.compile(r"https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9._-]+/(?:issues|pull)/[0-9]{1,9}")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
COUNT = re.compile(r"[0-9]{1,9}")
NOTE_FORBIDDEN = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")  # any control or line-break character
NOTE_LIMIT = 500
MAX_COUNT = 10**12
MAX_ROUNDS = 1000
OPTIONAL_KEYS = ("model", "credits_used")
MAX_LOG_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class Outcome:
    date: str
    card: str | None
    agent: str
    shape: str
    review_rounds: int
    findings: dict[str, int] = field(default_factory=dict)
    tokens: int | None = None
    requests: int | None = None
    note: str = ""
    model: str | None = None
    credits_used: int | None = None

    def to_json(self) -> str:
        data = {k: v for k, v in self.__dict__.items() if v is not None or k not in OPTIONAL_KEYS}  # unset: no key
        return json.dumps(data, sort_keys=True)  # ASCII only: no Unicode line break can split a record

    @property
    def finding_count(self) -> int:
        return sum(self.findings.values())

    @property
    def needed_fixes(self) -> bool:
        return self.review_rounds > 1 or self.finding_count > 0


def parse_findings(text: str) -> dict[str, int]:
    """`critical=0,important=1,minor=2`"""
    out: dict[str, int] = {}
    for part in filter(None, (x.strip() for x in text.split(","))):
        key, _, value = part.partition("=")
        if key not in SEVERITIES or key in out or not COUNT.fullmatch(value):
            raise ConfigError(
                f"findings {part!r} must be <severity>=<count> with severity one of {', '.join(SEVERITIES)}"
            )
        out[key] = int(value)
    return out


def validate(raw: Any, where: str = "outcome") -> Outcome:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: expected a JSON object")
    allowed = {
        "date",
        "card",
        "agent",
        "shape",
        "review_rounds",
        "findings",
        "tokens",
        "requests",
        "note",
        *OPTIONAL_KEYS,
    }
    for key in raw:
        if key not in allowed:
            raise ConfigError(f"{where}.{key}: unknown key")
    try:
        date = raw["date"]
        if not isinstance(date, str) or not DATE.fullmatch(date):
            raise ValueError("noncanonical date")
        dt.date.fromisoformat(date)
    except (KeyError, ValueError):
        raise ConfigError(f"{where}.date: expected YYYY-MM-DD") from None
    card = raw.get("card")
    if card is not None and not (isinstance(card, str) and CARD.fullmatch(card)):
        raise ConfigError(f"{where}.card: expected a https://github.com/<owner>/<repo>/issues|pull/<n> URL, or null")
    for key in ("agent", "shape"):
        if not isinstance(raw.get(key), str) or not IDENTIFIER.fullmatch(raw[key]):
            raise ConfigError(f"{where}.{key}: expected a non-empty string of letters, digits, . _ - (at most 64)")
    rounds = raw.get("review_rounds")
    if isinstance(rounds, bool) or not isinstance(rounds, int) or not 0 <= rounds <= MAX_ROUNDS:
        raise ConfigError(f"{where}.review_rounds: expected an integer >= 0")
    findings = raw.get("findings", {})
    if not isinstance(findings, dict) or any(
        k not in SEVERITIES or isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= MAX_COUNT
        for k, v in findings.items()
    ):
        raise ConfigError(f"{where}.findings: expected counts keyed by {', '.join(SEVERITIES)}")
    for key in ("tokens", "requests"):
        value = raw.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_COUNT):
            raise ConfigError(f"{where}.{key}: expected an integer >= 0 or null")
    model = raw.get("model")
    if model is not None and not (isinstance(model, str) and IDENTIFIER.fullmatch(model)):
        raise ConfigError(f"{where}.model: expected a string of letters, digits, . _ - (at most 64), or null")
    credits = raw.get("credits_used")
    if credits is not None and (
        isinstance(credits, bool) or not isinstance(credits, int) or not 0 <= credits <= MAX_COUNT
    ):
        raise ConfigError(f"{where}.credits_used: expected an integer >= 0 or null")
    note = raw.get("note", "")
    if not isinstance(note, str) or NOTE_FORBIDDEN.search(note) or len(note) > NOTE_LIMIT:
        raise ConfigError(f"{where}.note: expected one line of text (printable, at most 500 characters)")
    return Outcome(
        str(raw["date"]),
        card,
        raw["agent"],
        raw["shape"],
        rounds,
        dict(findings),
        raw.get("tokens"),
        raw.get("requests"),
        note,
        model,
        credits,
    )


def _read(path: Path) -> bytes:
    """The whole log, or ConfigError. Opened without following a symlink or waiting on a FIFO, size-capped."""
    try:
        return bounded_read(path, MAX_LOG_BYTES)
    except (OSError, ValueError):
        raise ConfigError("cannot read outcomes log within resource limits (a regular file, not a link)") from None


def append(path: Path, outcome: Outcome, check_dir: bool = False) -> None:
    """One line, appended under a lock by rewriting the file atomically (mode 0600). The record is validated first,
    so a bad one never reaches the file; a symlinked, special or oversize log is refused, never followed. `check_dir` is
    True for SAFO's own default directory (it must be private to the user); a path the user chose is theirs."""
    validate(json.loads(outcome.to_json()))
    line = (outcome.to_json() + "\n").encode("utf-8")
    try:
        with file_lock(path.with_name(path.name + ".lock"), check_dir=check_dir):
            try:
                existing = _read(path)
            except ConfigError:
                if path.is_symlink() or path.exists():
                    raise
                existing = b""
            if existing and not existing.endswith(b"\n"):
                existing += b"\n"
            if len(existing) + len(line) > MAX_LOG_BYTES:
                raise ConfigError("outcomes log would exceed its size limit")
            write_text(path, (existing + line).decode("utf-8"), check_dir=check_dir)
    except (OSError, TimeoutError, ValueError):
        raise ConfigError("cannot write outcomes log (is it locked, or not a regular file?)") from None


def parse_log(raw: bytes, source: str) -> list[Outcome]:
    """The records of a log already read (and size-capped) by the caller; `source` only labels errors."""
    out: list[Outcome] = []
    for number, line in enumerate(raw.split(b"\n"), 1):
        if not line.strip():
            continue
        try:
            record = loads(line)
        except DuplicateKeyError as err:
            raise ConfigError(f"{source}:{number}: {err}") from None
        except (ValueError, UnicodeError):
            raise ConfigError(f"{source}:{number}: not valid bounded JSON") from None
        out.append(validate(record, f"{source}:{number}"))
    return out


def load(path: Path) -> list[Outcome]:
    return parse_log(_read(path), str(path))


@dataclass(frozen=True)
class AgentSummary:
    agent: str
    tasks: int
    needed_fixes: int
    review_rounds: int
    findings: dict[str, int]
    tokens: int
    requests: int


def summarise(outcomes: list[Outcome], month: str) -> list[AgentSummary]:
    """Per agent, for the outcomes dated in `month` (YYYY-MM)."""
    try:
        valid_month(month)
    except ValueError:
        raise ConfigError("month: expected YYYY-MM") from None
    groups: dict[str, list[Outcome]] = defaultdict(list)
    for o in outcomes:
        if o.date.startswith(month):
            groups[o.agent].append(o)
    out = []
    for agent, rows in sorted(groups.items()):
        findings: dict[str, int] = {}
        for o in rows:
            for k, v in o.findings.items():
                findings[k] = findings.get(k, 0) + v
        out.append(
            AgentSummary(
                agent,
                len(rows),
                sum(1 for o in rows if o.needed_fixes),
                sum(o.review_rounds for o in rows),
                findings,
                sum(o.tokens or 0 for o in rows),
                sum(o.requests or 0 for o in rows),
            )
        )
    return out


UNKNOWN_MODEL = "unknown"


@dataclass(frozen=True)
class ModelSummary:
    """One agent + model group. Credit averages use only runs whose credits are known; None when there are none."""

    agent: str
    model: str
    runs: int
    review_rounds: int
    rounds_per_run: float
    needed_fixes: int
    fix_share: float
    findings: dict[str, int]
    credits_total: int
    credits_known: int
    credits_per_run: float | None
    credits_per_clean_run: float | None
    credits_per_fixed_run: float | None


def _mean(values: list[int]) -> float | None:
    return sum(values) / len(values) if values else None


def summarise_models(outcomes: list[Outcome], month: str) -> list[ModelSummary]:
    """Per agent and model (unknown model grouped as `unknown`), for the outcomes dated in `month`. Sorted by agent,
    then model, so the output does not depend on log order."""
    try:
        valid_month(month)
    except ValueError:
        raise ConfigError("month: expected YYYY-MM") from None
    groups: dict[tuple[str, str], list[Outcome]] = defaultdict(list)
    for o in outcomes:
        if o.date.startswith(month):
            groups[(o.agent, o.model or UNKNOWN_MODEL)].append(o)
    out = []
    for (agent, model), rows in sorted(groups.items()):
        findings: dict[str, int] = {}
        for o in rows:
            for k, v in o.findings.items():
                findings[k] = findings.get(k, 0) + v
        known = [o for o in rows if o.credits_used is not None]
        fixed = sum(1 for o in rows if o.needed_fixes)
        rounds = sum(o.review_rounds for o in rows)
        out.append(
            ModelSummary(
                agent,
                model,
                len(rows),
                rounds,
                rounds / len(rows),
                fixed,
                fixed / len(rows),
                findings,
                sum(o.credits_used or 0 for o in known),
                len(known),
                _mean([o.credits_used or 0 for o in known]),
                _mean([o.credits_used or 0 for o in known if not o.needed_fixes]),
                _mean([o.credits_used or 0 for o in known if o.needed_fixes]),
            )
        )
    return out


# -- queries across months (the evidence resolver and `qualify` read these; summarise_models is untouched) ---------

METRICS = (
    "runs",
    "fix_share",
    "rounds_per_run",
    "credits_per_run",
    "findings.critical",
    "findings.important",
    "findings.minor",
    "findings.unrated",
)
OPERATORS = (">=", "<=", ">", "<", "=")
NUMBER = re.compile(r"[0-9]{1,12}(?:\.[0-9]{1,6})?")
MAX_SPAN_MONTHS = 12


def month_span(span: str) -> tuple[str, str]:
    """`YYYY-MM` or `YYYY-MM..YYYY-MM` as (first, last) months, at most 12 months long, or ConfigError."""
    months = span.split("..")
    try:
        if len(months) > 2:
            raise ValueError
        for m in months:
            valid_month(m)
    except ValueError:
        raise ConfigError("outcomes range: expected YYYY-MM or YYYY-MM..YYYY-MM") from None
    first, last = months[0], months[-1]
    length = (int(last[:4]) - int(first[:4])) * 12 + int(last[5:]) - int(first[5:]) + 1
    if length < 1:
        raise ConfigError("outcomes range: ends before it starts")
    if length > MAX_SPAN_MONTHS:
        raise ConfigError(f"outcomes range: at most {MAX_SPAN_MONTHS} months")
    return first, last


@dataclass(frozen=True)
class OutcomeQuery:
    """What a range of the log says about one agent (or one agent and model). A metric with no data is None:
    unsupported, which is not zero and not false."""

    records: int
    values: dict[str, Fraction | None]

    def value(self, metric: str) -> Fraction | None:
        if metric not in METRICS:
            raise ConfigError(f"unknown outcomes metric {metric!r} (metrics: {', '.join(METRICS)})")
        return self.values[metric]


def query_outcomes(outcomes: list[Outcome], span: str, agent: str, model: str | None = None) -> OutcomeQuery:
    """The metrics over every record of `agent` (and `model`, when given) dated within the months of `span`.

    With no records every metric is None. `credits_per_run` is the mean over the runs whose credits are known, and None
    when none are. The result does not depend on the order of the log.
    """
    first, last = month_span(span)
    rows = [
        o for o in outcomes if o.agent == agent and (model is None or o.model == model) and first <= o.date[:7] <= last
    ]
    values: dict[str, Fraction | None] = dict.fromkeys(METRICS)
    if rows:
        known = [o.credits_used for o in rows if o.credits_used is not None]
        values["runs"] = Fraction(len(rows))
        values["fix_share"] = Fraction(sum(1 for o in rows if o.needed_fixes), len(rows))
        values["rounds_per_run"] = Fraction(sum(o.review_rounds for o in rows), len(rows))
        values["credits_per_run"] = Fraction(sum(known), len(known)) if known else None
        for severity in SEVERITIES:
            values[f"findings.{severity}"] = Fraction(sum(o.findings.get(severity, 0) for o in rows))
    return OutcomeQuery(len(rows), values)


def compare(value: Fraction, op: str, number: str) -> bool:
    """`value op number`, exactly (no floating point)."""
    if op not in OPERATORS or NUMBER.fullmatch(number) is None:
        raise ConfigError(f"outcomes comparison: expected one of {' '.join(OPERATORS)} and a plain decimal number")
    n = Fraction(number)
    return {
        ">=": value >= n,
        "<=": value <= n,
        ">": value > n,
        "<": value < n,
        "=": value == n,
    }[op]
