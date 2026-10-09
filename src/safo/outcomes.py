# SPDX-License-Identifier: MIT
"""The outcomes log: one JSON line per finished task, so routing can be judged by what happened, not by feeling.

A record: date, card (a GitHub URL or null), agent, shape, review_rounds (review passes, the passing one included),
findings by severity, tokens and requests when known, and a note. Appended one line at a time.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from safo.bounded import loads
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

    def to_json(self) -> str:
        return json.dumps(self.__dict__, sort_keys=True)  # ASCII only: no Unicode line break can split a record

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
    allowed = {"date", "card", "agent", "shape", "review_rounds", "findings", "tokens", "requests", "note"}
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
    )


def _read(path: Path) -> bytes:
    """The whole log, or ConfigError. Opened without following a symlink or waiting on a FIFO, size-capped."""
    try:
        return bounded_read(path, MAX_LOG_BYTES)
    except (OSError, ValueError):
        raise ConfigError("cannot read outcomes log within resource limits (a regular file, not a link)") from None


def append(path: Path, outcome: Outcome) -> None:
    """One line, appended under a lock by rewriting the file atomically (mode 0600). The record is validated first,
    so a bad one never reaches the file; a symlinked, special or oversize log is refused, never followed."""
    validate(json.loads(outcome.to_json()))
    line = (outcome.to_json() + "\n").encode("utf-8")
    try:
        with file_lock(path.with_name(path.name + ".lock")):
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
            write_text(path, (existing + line).decode("utf-8"))
    except (OSError, TimeoutError, ValueError):
        raise ConfigError("cannot write outcomes log (is it locked, or not a regular file?)") from None


def load(path: Path) -> list[Outcome]:
    out: list[Outcome] = []
    for number, line in enumerate(_read(path).split(b"\n"), 1):
        if not line.strip():
            continue
        try:
            raw = loads(line)
        except (ValueError, UnicodeError):
            raise ConfigError(f"{path}:{number}: not valid bounded JSON") from None
        out.append(validate(raw, f"{path}:{number}"))
    return out


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
