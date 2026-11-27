# SPDX-License-Identifier: Apache-2.0
"""spend: the weekly token-spend report every token-savings lever is measured by (#510). Read-only, counts only.

It reads the Claude transcripts, the Codex sessions (counted apart, never added), the llm-local calls log, the hook log
and the safo-draft local-share log, and prints sums and counts. No prompt text, title, path or label from a file is
printed: pools, sections and outcome names come from fixed lists in this module. Every input is opened without
following a symlink and without waiting on a FIFO, must be a regular file as the descriptor says, and is read under a
cap on files, bytes per file, bytes per line and run time; a bound that is hit stops the run with a message, never a
partial report. JSON is parsed with `safo.bounded`. The one thing written is a new report file (`--json`) and a new
baseline (`--baseline`), each created exclusively with mode 0600 and never over an existing file.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import stat
import statistics
import time
from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from safo.bounded import NotRegularFileError, count, loads, number, read_bounded
from safo.context import LocalContext
from safo.errors import EXIT_OK, ConfigError
from safo.localfiles import refuse_workspace
from safo.modes import LocalMode, register_local

# The price ratios, in input-token equivalents (INFERRED from the published ratios; the same for every model, so the
# weighted numbers rank patterns inside one meter and do not compare models in dollars).
WEIGHT_INPUT = 1.0
WEIGHT_OUTPUT = 5.0
WEIGHT_CACHE_READ = 0.1
WEIGHT_CACHE_WRITE = 1.25
CHARS_PER_TOKEN = 3.5  # INFERRED mid-point of the 2.4 to 4.4 range measured for the fixed prefix (#489)

# Bounds. A bound that is hit stops the run (fail closed).
MAX_FILES = 50_000  # transcript or session files per folder
MAX_DEPTH = 8  # directory levels below a folder
MAX_FILE_BYTES = 512 * 1024 * 1024  # one transcript or session file
MAX_LINE_BYTES = 8 * 1024 * 1024  # one line; a longer one is counted and skipped
MAX_LOG_BYTES = 64 * 1024 * 1024  # one log file
MAX_LOG_LINES = 1_000_000
MAX_META_BYTES = 64 * 1024
MAX_MERGE_BYTES = 1024 * 1024
MAX_BASELINE_BYTES = 1024 * 1024
MAX_SECONDS = 900.0  # the whole run
MAX_BASELINE_METRICS = 500
LEAD_TURN_MARKS = (200, 400)

POOL_LEAD = "lead"
AGENT_POOLS = ("implementer", "general-purpose", "reviewer", "other")
AGENT_POOL_OF = {
    "implementer": "implementer",
    "general-purpose": "general-purpose",
    "reviewer": "reviewer",
    "adversarial-reviewer": "reviewer",
}
OUTCOMES = ("accepted", "rewritten", "discarded", "fact-error")
NA_CLASSES = ("code", "state-change", "security", "credentials", "verbatim", "other")
WEEK_SHAPE = re.compile(r"[0-9]{4}-W[0-9]{2}")
DATE_SHAPE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
STAMP_SHAPE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T")
USAGE_KEYS = ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
ALL = "all"
BASELINE_VERSION = 1

NOT_SAFE = "{what} is a symlink, not a regular file or folder, or cannot be opened"


class Bound(ConfigError):
    """A cap was reached; the message says which one, never which file."""


@dataclass
class Clock:
    started: float = field(default_factory=time.monotonic)

    def check(self) -> None:
        if time.monotonic() - self.started > MAX_SECONDS:
            raise Bound(f"spend: the run took longer than {MAX_SECONDS:g} seconds; narrow it with --week")


@dataclass
class Skips:
    """What could not be used, as counts."""

    malformed: int = 0  # a line that did not parse or whose usage was not a bounded count
    oversize: int = 0  # a line over MAX_LINE_BYTES
    refused: int = 0  # a symlink or special file inside a folder
    stale: int = 0  # a file older than the week asked for, never opened


def weighted(inp: int, out: int, cache_read: int, cache_write: int) -> float:
    return inp * WEIGHT_INPUT + out * WEIGHT_OUTPUT + cache_read * WEIGHT_CACHE_READ + cache_write * WEIGHT_CACHE_WRITE


@dataclass
class Tally:
    """Token sums of one pool: input, output, cache read, cache write (creation), and messages."""

    inp: int = 0
    out: int = 0
    read: int = 0
    write: int = 0
    messages: int = 0

    def add(self, vals: tuple[int, int, int, int]) -> None:
        self.inp += vals[0]
        self.out += vals[1]
        self.read += vals[2]
        self.write += vals[3]
        self.messages += 1

    def merge(self, other: Tally) -> None:
        self.inp += other.inp
        self.out += other.out
        self.read += other.read
        self.write += other.write
        self.messages += other.messages

    @property
    def weight(self) -> float:
        return weighted(self.inp, self.out, self.read, self.write)

    @property
    def raw(self) -> int:
        return self.inp + self.out + self.read + self.write


# --- safe file access ---------------------------------------------------------------------------------------------


def open_regular(path: Path) -> tuple[BinaryIO, int]:
    """Open a regular file read-only without following a last-component symlink or waiting on a FIFO."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise NotRegularFileError(0, "not a regular file")
        return os.fdopen(fd, "rb"), info.st_size
    except BaseException:
        os.close(fd)
        raise


def lines_of(handle: BinaryIO, skips: Skips, clock: Clock, limit: int) -> Iterator[bytes]:
    """Complete lines, each at most MAX_LINE_BYTES; a longer one is counted and skipped. At most `limit` bytes."""
    total = 0
    seen = 0
    while True:
        line = handle.readline(MAX_LINE_BYTES + 1)
        if not line:
            return
        total += len(line)
        if total > limit:
            raise Bound("spend: a file grew past the size cap while it was read; nothing was reported")
        seen += 1
        if seen % 2000 == 0:
            clock.check()
        if len(line) > MAX_LINE_BYTES and not line.endswith(b"\n"):
            while True:  # drop the rest of the line without keeping it
                rest = handle.readline(MAX_LINE_BYTES)
                total += len(rest)
                if not rest or rest.endswith(b"\n"):
                    break
            skips.oversize += 1
            continue
        yield line


def parsed(line: bytes, skips: Skips) -> dict[str, Any] | None:
    try:
        row = loads(line)
    except (ValueError, UnicodeError, RecursionError):
        skips.malformed += 1
        return None
    if not isinstance(row, dict):
        skips.malformed += 1
        return None
    return row


@dataclass
class Found:
    path: Path
    agent: bool
    mtime: float


def walk(root: Path, limit: int, skips: Skips, clock: Clock) -> list[Found]:
    """Every `.jsonl` file under `root`, symlinks and special files refused (counted), in a stable order.

    The root itself is opened without following a symlink, so a linked folder is refused outright."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    os.close(fd)
    found: list[Found] = []
    stack: list[tuple[Path, int, bool]] = [(root, 0, False)]
    while stack:
        folder, depth, in_subagents = stack.pop()
        clock.check()
        try:
            with os.scandir(folder) as entries:
                listing = sorted(entries, key=lambda e: e.name)
        except OSError:
            skips.refused += 1
            continue
        for entry in listing:
            try:
                if entry.is_symlink():
                    skips.refused += 1
                elif entry.is_dir(follow_symlinks=False):
                    if depth + 1 > MAX_DEPTH:
                        raise Bound(f"spend: folders nest deeper than {MAX_DEPTH} levels; nothing was reported")
                    stack.append((Path(entry.path), depth + 1, entry.name == "subagents"))
                elif entry.is_file(follow_symlinks=False):
                    if entry.name.endswith(".jsonl"):
                        found.append(
                            Found(
                                Path(entry.path),
                                in_subagents and entry.name.startswith("agent-"),
                                entry.stat(follow_symlinks=False).st_mtime,
                            )
                        )
                        if len(found) > limit:
                            raise Bound(f"spend: more than {limit} transcript files; nothing was reported")
                else:
                    skips.refused += 1
            except OSError:
                skips.refused += 1
    return sorted(found, key=lambda f: str(f.path))


# --- weeks --------------------------------------------------------------------------------------------------------


def week_key(day: dt.date) -> str:
    iso = day.isocalendar()
    return f"{iso.year}-W{iso.week:02d}"


def utc_day(stamp: Any) -> dt.date | None:
    """The UTC date of an ISO timestamp such as `2026-11-26T09:00:00.123Z`; None when it is not one."""
    if type(stamp) is not str or len(stamp) > 40 or not STAMP_SHAPE.match(stamp):
        return None
    try:
        moment = dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        return moment.date()
    return moment.astimezone(dt.UTC).date()


def local_day(stamp: Any) -> dt.date | None:
    """The date of a log timestamp (local time, with or without a zone); no conversion."""
    if type(stamp) is not str or len(stamp) > 40 or not STAMP_SHAPE.match(stamp):
        return None
    try:
        return dt.date.fromisoformat(stamp[:10])
    except ValueError:
        return None


def week_start(week: str) -> dt.date:
    return dt.date.fromisocalendar(int(week[:4]), int(week[6:]), 1)


def valid_week(text: str) -> str:
    if text == ALL:
        return text
    if not WEEK_SHAPE.fullmatch(text):
        raise ConfigError("--week must be YYYY-Www (an ISO week) or all")
    try:
        week_start(text)
    except ValueError:
        raise ConfigError("--week is not a real ISO week") from None
    return text


def before_week(week: str, mtime: float) -> bool:
    """True when a file was last written a day or more before the week began: it holds no message of the week."""
    if week == ALL:
        return False
    return dt.datetime.fromtimestamp(mtime, dt.UTC).date() < week_start(week) - dt.timedelta(days=1)


# --- Claude transcripts -------------------------------------------------------------------------------------------


@dataclass
class Message:
    vals: tuple[int, int, int, int]
    day: dt.date | None


@dataclass
class ClaudeResult:
    messages: list[Message]  # in order of first appearance, de-duplicated by message id
    first_day: dt.date | None
    instruction_chars: int = 0
    skill_chars: int = 0
    first_context: int = 0


def usage_of(message: Mapping[str, Any]) -> tuple[int, int, int, int] | None:
    raw = message.get("usage")
    if not isinstance(raw, dict):
        return None
    try:
        inp, out, read, write = (count(raw.get(key, 0)) for key in USAGE_KEYS)
    except ValueError:
        return None
    return inp, out, read, write


def attachment_chars(row: Mapping[str, Any]) -> tuple[int, int]:
    """(instruction characters, skill-listing characters) of an attachment row; sizes only, never the text."""
    att = row.get("attachment")
    if not isinstance(att, dict):
        return 0, 0
    kind = att.get("type")
    if kind == "instructions":
        files = att.get("files")
        if isinstance(files, list):
            return sum(len(f["content"]) for f in files if isinstance(f, dict) and type(f.get("content")) is str), 0
    elif kind == "skill_listing":
        return 0, len(json.dumps(att, ensure_ascii=False))
    return 0, 0


def read_claude_file(path: Path, agent: bool, skips: Skips, clock: Clock) -> ClaudeResult:
    handle, size = open_regular(path)
    with handle:
        if size > MAX_FILE_BYTES:
            raise Bound("spend: a transcript is larger than the size cap; nothing was reported")
        best: dict[str, tuple[int, Message]] = {}  # id -> (order, latest message by output tokens)
        result = ClaudeResult([], None)
        seen_assistant = False
        for line in lines_of(handle, skips, clock, MAX_FILE_BYTES):
            if agent and not seen_assistant and (b'"instructions"' in line or b'"skill_listing"' in line):
                row = parsed(line, skips)
                if row is not None and row.get("type") == "attachment":
                    ins, skill = attachment_chars(row)
                    result.instruction_chars += ins
                    result.skill_chars += skill
                continue
            if b'"usage"' not in line or b'"assistant"' not in line:
                continue
            row = parsed(line, skips)
            if row is None or row.get("type") != "assistant":
                continue
            message = row.get("message")
            if not isinstance(message, dict):
                continue
            vals = usage_of(message)
            model = message.get("model")
            if vals is None or type(model) is not str or not model or model.startswith("<"):
                continue  # no usage, or a synthetic message that carries no real use
            seen_assistant = True
            day = utc_day(row.get("timestamp"))
            if result.first_day is None:
                result.first_day = day
            ident = message.get("id")
            key = ident if type(ident) is str and ident else f"line-{len(best)}"
            previous = best.get(key)
            if previous is None:
                best[key] = (len(best), Message(vals, day))
            elif vals[1] >= previous[1].vals[1]:
                best[key] = (previous[0], Message(vals, day or previous[1].day))
        result.messages = [m for _, m in sorted(best.values(), key=lambda pair: pair[0])]
    if result.messages:
        first = result.messages[0].vals
        result.first_context = first[0] + first[2] + first[3]
    return result


def agent_pool(meta_path: Path) -> str:
    """The pool of an agent from its `.meta.json` sibling; anything unreadable or unknown is `other`."""
    try:
        meta = loads(read_bounded(meta_path, MAX_META_BYTES))
    except (OSError, ValueError, UnicodeError, RecursionError):
        return "other"
    kind = meta.get("agentType") if isinstance(meta, dict) else None
    return AGENT_POOL_OF.get(kind, "other") if type(kind) is str else "other"


@dataclass
class ClaudeSection:
    files: int = 0
    lead_files: int = 0
    agent_files: int = 0
    pools: dict[str, Tally] = field(default_factory=lambda: {p: Tally() for p in (POOL_LEAD, *AGENT_POOLS)})
    by_week: dict[str, dict[str, float]] = field(default_factory=dict)
    lead_turns: int = 0
    lead_weight: float = 0.0
    past: dict[int, int] = field(default_factory=lambda: {m: 0 for m in LEAD_TURN_MARKS})
    past_weight: dict[int, float] = field(default_factory=lambda: {m: 0.0 for m in LEAD_TURN_MARKS})
    first_contexts: list[int] = field(default_factory=list)
    instruction_shares: list[float] = field(default_factory=list)
    skill_shares: list[float] = field(default_factory=list)
    both_shares: list[float] = field(default_factory=list)


def scan_claude(root: Path, week: str, skips: Skips, clock: Clock) -> ClaudeSection:
    section = ClaudeSection()
    for entry in walk(root, MAX_FILES, skips, clock):
        clock.check()
        if before_week(week, entry.mtime):
            skips.stale += 1
            continue
        try:
            result = read_claude_file(entry.path, entry.agent, skips, clock)
        except OSError:
            skips.refused += 1
            continue
        pool = agent_pool(entry.path.with_suffix(".meta.json")) if entry.agent else POOL_LEAD
        section.files += 1
        section.lead_files += not entry.agent
        section.agent_files += entry.agent
        fallback = result.first_day or dt.datetime.fromtimestamp(entry.mtime, dt.UTC).date()
        for turn, message in enumerate(result.messages, 1):
            key = week_key(message.day or fallback)
            cell = section.by_week.setdefault(key, {"lead": 0.0, "agents": 0.0})
            w = weighted(*message.vals)
            cell["agents" if entry.agent else "lead"] += w
            if week != ALL and key != week:
                continue
            section.pools[pool].add(message.vals)
            if not entry.agent:
                section.lead_turns += 1
                section.lead_weight += w
                for mark in LEAD_TURN_MARKS:
                    if turn > mark:
                        section.past[mark] += 1
                        section.past_weight[mark] += w
        if not (entry.agent and result.first_context):
            continue
        first_key = week_key(result.messages[0].day or fallback)
        if week != ALL and first_key != week:
            continue
        section.first_contexts.append(result.first_context)
        if result.instruction_chars or result.skill_chars:
            budget = CHARS_PER_TOKEN * result.first_context
            section.instruction_shares.append(min(1.0, result.instruction_chars / budget))
            section.skill_shares.append(min(1.0, result.skill_chars / budget))
            section.both_shares.append(min(1.0, (result.instruction_chars + result.skill_chars) / budget))
    return section


# --- Codex sessions -----------------------------------------------------------------------------------------------


@dataclass
class CodexSection:
    files: int = 0
    sessions: int = 0  # sessions of the week that carry a usage record
    uncached_input: int = 0
    cached_input: int = 0
    output: int = 0

    @property
    def weight(self) -> float:
        return weighted(self.uncached_input, self.output, self.cached_input, 0)


def read_codex_file(path: Path, skips: Skips, clock: Clock) -> tuple[dt.date | None, dict[str, Any] | None]:
    handle, size = open_regular(path)
    with handle:
        if size > MAX_FILE_BYTES:
            raise Bound("spend: a session file is larger than the size cap; nothing was reported")
        day: dt.date | None = None
        usage: dict[str, Any] | None = None
        for line in lines_of(handle, skips, clock, MAX_FILE_BYTES):
            is_meta = b'"session_meta"' in line
            if not is_meta and b'"token_count"' not in line:
                continue
            row = parsed(line, skips)
            if row is None:
                continue
            payload = row.get("payload")
            if not isinstance(payload, dict):
                continue
            if is_meta and row.get("type") == "session_meta" and day is None:
                day = utc_day(payload.get("timestamp") or row.get("timestamp"))
            elif payload.get("type") == "token_count":
                info = payload.get("info")
                total = info.get("total_token_usage") if isinstance(info, dict) else None
                if isinstance(total, dict):
                    usage = total
    return day, usage


def scan_codex(root: Path, week: str, skips: Skips, clock: Clock) -> CodexSection:
    section = CodexSection()
    for entry in walk(root, MAX_FILES, skips, clock):
        clock.check()
        if before_week(week, entry.mtime):
            skips.stale += 1
            continue
        try:
            day, usage = read_codex_file(entry.path, skips, clock)
        except OSError:
            skips.refused += 1
            continue
        section.files += 1
        day = day or dt.datetime.fromtimestamp(entry.mtime, dt.UTC).date()
        if usage is None or (week != ALL and week_key(day) != week):
            continue
        try:
            total_in = count(usage.get("input_tokens", 0))
            cached = min(count(usage.get("cached_input_tokens", 0)), total_in)
            out = count(usage.get("output_tokens", 0))
        except ValueError:
            skips.malformed += 1
            continue
        section.sessions += 1
        section.uncached_input += total_in - cached
        section.cached_input += cached
        section.output += out
    return section


# --- logs ---------------------------------------------------------------------------------------------------------


@dataclass
class LogRows:
    found: bool = False
    rows: list[dict[str, Any]] = field(default_factory=list)


def read_log(path: Path, skips: Skips, clock: Clock) -> LogRows:
    try:
        handle, size = open_regular(path)
    except FileNotFoundError:
        return LogRows()
    except OSError:
        raise ConfigError(NOT_SAFE.format(what="a log file")) from None
    out = LogRows(found=True)
    with handle:
        if size > MAX_LOG_BYTES:
            raise Bound("spend: a log file is larger than the size cap; nothing was reported")
        for line in lines_of(handle, skips, clock, MAX_LOG_BYTES):
            if not line.strip():
                continue
            if len(out.rows) >= MAX_LOG_LINES:
                raise Bound("spend: a log file has more lines than the cap; nothing was reported")
            row = parsed(line, skips)
            if row is not None:
                out.rows.append(row)
    return out


def in_week(week: str, day: dt.date | None) -> bool:
    return day is not None and (week == ALL or week_key(day) == week)


def ratio(part: float, whole: float) -> float | None:
    return round(part / whole, 4) if whole else None


def llm_local_section(log: LogRows, week: str) -> dict[str, Any]:
    real = eval_calls = no_project = failed = outcome_rows = 0
    by_outcome: Counter[str] = Counter()
    for row in log.rows:
        if not in_week(week, local_day(row.get("ts"))):
            continue
        kind = row.get("kind", "call")
        if kind == "outcome":
            outcome_rows += 1
            if row.get("outcome") in OUTCOMES:
                by_outcome[row["outcome"]] += 1
            continue
        if kind != "call":
            continue
        if row.get("status", "ok") != "ok":
            failed += 1
            continue
        task = row.get("task")
        if type(task) is str and task.startswith("eval-"):
            eval_calls += 1
            continue
        real += 1
        project = row.get("project")
        no_project += project is None or project == "none"
    return {
        "found": log.found,
        "real_calls": real,
        "eval_calls": eval_calls,
        "failed_or_busy": failed,
        "calls_project_none": no_project,
        "outcome_rows": outcome_rows,
        "by_outcome": {k: by_outcome[k] for k in OUTCOMES if by_outcome[k]},
    }


def hook_section(log: LogRows, week: str) -> dict[str, Any]:
    dispatches = steps = marked_na = with_class = 0
    classes: Counter[str] = Counter()
    for row in log.rows:
        if not in_week(week, local_day(row.get("ts"))):
            continue
        dispatches += 1
        steps += row.get("local_step") is True
        marked_na += row.get("na") is True
        found = row.get("na_reason_class")
        if found is not None:
            with_class += 1
            classes[found if type(found) is str and found in NA_CLASSES else "invalid"] += 1
    return {
        "found": log.found,
        "dispatches": dispatches,
        "local_step": steps,
        "marked_na": marked_na,
        "with_na_reason_class": with_class,
        "local_step_share": ratio(steps, dispatches),
        "na_reason_class_share": ratio(with_class, dispatches),
        "by_na_reason_class": dict(sorted(classes.items())),
    }


def share_section(log: LogRows, week: str) -> dict[str, Any]:
    calls = ok = with_outcome = no_project = 0
    for row in log.rows:
        if not in_week(week, local_day(row.get("ts"))):
            continue
        calls += 1
        ok += row.get("exit") == 0
        with_outcome += row.get("outcome") in OUTCOMES
        project = row.get("project")
        no_project += project is None or project == "none"
    return {
        "found": log.found,
        "calls": calls,
        "exit_ok": ok,
        "with_outcome": with_outcome,
        "calls_project_none": no_project,
    }


def read_merges(path: Path, skips: Skips) -> list[dt.date]:
    try:
        raw = read_bounded(path, MAX_MERGE_BYTES + 1)
    except OSError:
        raise ConfigError(NOT_SAFE.format(what="the merge list")) from None
    if len(raw) > MAX_MERGE_BYTES:
        raise Bound("spend: the merge list is larger than the size cap; nothing was reported")
    days = []
    for entry in raw.decode("utf-8", "replace").splitlines():
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        try:
            if not DATE_SHAPE.fullmatch(entry):
                raise ValueError
            days.append(dt.date.fromisoformat(entry))
        except ValueError:
            skips.malformed += 1
    return days


# --- the report ---------------------------------------------------------------------------------------------------


def median(values: list[int] | list[float]) -> float | None:
    return round(statistics.median(values), 4) if values else None


def claude_report(claude: ClaudeSection) -> dict[str, Any]:
    agents = Tally()
    for pool in AGENT_POOLS:
        agents.merge(claude.pools[pool])
    lead = claude.pools[POOL_LEAD]
    total = lead.weight + agents.weight
    named = ((POOL_LEAD, lead), *((p, claude.pools[p]) for p in AGENT_POOLS))
    return {
        "files": claude.files,
        "lead_files": claude.lead_files,
        "agent_files": claude.agent_files,
        "weighted_total": round(total, 2),
        "pools": {
            name: {"weighted": round(t.weight, 2), "share": ratio(t.weight, total), "messages": t.messages}
            for name, t in named
        },
        "agents_weighted": round(agents.weight, 2),
        "agents_share": ratio(agents.weight, total),
        "cache_read_share_of_weighted": {
            "lead": ratio(lead.read * WEIGHT_CACHE_READ, lead.weight),
            "agents": ratio(agents.read * WEIGHT_CACHE_READ, agents.weight),
        },
        "cache_read_share_of_tokens": {"lead": ratio(lead.read, lead.raw), "agents": ratio(agents.read, agents.raw)},
        "output_share_of_weighted": {
            "lead": ratio(lead.out * WEIGHT_OUTPUT, lead.weight),
            "agents": ratio(agents.out * WEIGHT_OUTPUT, agents.weight),
        },
        "lead_turns": {
            "turns": claude.lead_turns,
            "weighted_per_turn": round(claude.lead_weight / claude.lead_turns, 2) if claude.lead_turns else None,
            **{f"share_past_{m}": ratio(claude.past[m], claude.lead_turns) for m in LEAD_TURN_MARKS},
            **{f"weighted_share_past_{m}": ratio(claude.past_weight[m], claude.lead_weight) for m in LEAD_TURN_MARKS},
        },
        "agent_first_turn": {
            "agents": len(claude.first_contexts),
            "median_context_tokens": median(claude.first_contexts),
            "agents_showing_instructions_or_skills": len(claude.both_shares),
            "median_instruction_share": median(claude.instruction_shares),
            "median_skill_listing_share": median(claude.skill_shares),
            "median_instruction_and_skill_share": median(claude.both_shares),
            "chars_per_token": CHARS_PER_TOKEN,
        },
        "by_week_weighted": {
            k: {n: round(v, 2) for n, v in cell.items()} for k, cell in sorted(claude.by_week.items())
        },
    }


def build(
    week: str,
    claude: ClaudeSection | None,
    codex: CodexSection | None,
    logs: Mapping[str, LogRows],
    merges: list[dt.date] | None,
    skips: Skips,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "week": week,
        "weights": {
            "input": WEIGHT_INPUT,
            "output": WEIGHT_OUTPUT,
            "cache_read": WEIGHT_CACHE_READ,
            "cache_write": WEIGHT_CACHE_WRITE,
        },
        "skipped": {
            "malformed_lines": skips.malformed,
            "oversize_lines": skips.oversize,
            "refused_entries": skips.refused,
            "stale_files": skips.stale,
        },
    }
    if claude is not None:
        report["claude"] = claude_report(claude)
        if merges is None:
            report["per_merged_pr"] = {"given": False}
        else:
            merged = sum(1 for d in merges if week == ALL or week_key(d) == week)
            total = report["claude"]["weighted_total"]
            report["per_merged_pr"] = {
                "given": True,
                "merged_prs": merged,
                "weighted_per_pr": round(total / merged, 2) if merged else None,
            }
    if codex is not None:
        report["codex"] = {
            "note": "counted apart; never added to the Claude numbers",
            "files": codex.files,
            "sessions": codex.sessions,
            "uncached_input": codex.uncached_input,
            "cached_input": codex.cached_input,
            "output": codex.output,
            "weighted": round(codex.weight, 2),
        }
    local: dict[str, Any] = {}
    if "llm_local" in logs:
        local["llm_local"] = llm_local_section(logs["llm_local"], week)
    if "hook" in logs:
        local["dispatches"] = hook_section(logs["hook"], week)
    if "share" in logs:
        local["safo_draft"] = share_section(logs["share"], week)
    if local:
        report["local"] = local
    return report


def metrics_of(report: Mapping[str, Any]) -> dict[str, float]:
    """The flat, numeric view of a report: the lines a baseline stores and later reports are compared on."""
    out: dict[str, float] = {}

    def put(name: str, value: Any) -> None:
        if type(value) in (int, float):
            out[name] = float(value)

    c = report.get("claude")
    if c:
        put("claude.weighted_total", c["weighted_total"])
        for pool, cell in c["pools"].items():
            put(f"claude.pool.{pool}.weighted", cell["weighted"])
            put(f"claude.pool.{pool}.share", cell["share"])
        put("claude.agents.share", c["agents_share"])
        for who in ("lead", "agents"):
            put(f"claude.cache_read_share_of_weighted.{who}", c["cache_read_share_of_weighted"][who])
            put(f"claude.output_share_of_weighted.{who}", c["output_share_of_weighted"][who])
        for name, value in c["lead_turns"].items():
            put(f"claude.lead_turns.{name}", value)
        for name, value in c["agent_first_turn"].items():
            put(f"claude.agent_first_turn.{name}", value)
        pr = report.get("per_merged_pr", {})
        put("claude.per_merged_pr.merged_prs", pr.get("merged_prs"))
        put("claude.per_merged_pr.weighted_per_pr", pr.get("weighted_per_pr"))
    x = report.get("codex")
    if x:
        put("codex.sessions", x["sessions"])
        put("codex.weighted", x["weighted"])
    for section, cell in report.get("local", {}).items():
        for name, value in cell.items():
            put(f"local.{section}.{name}", value)
    return out


def pct(value: float | None) -> str:
    return "not available" if value is None else f"{value * 100:.1f}%"


def num(value: float | None) -> str:
    return "not available" if value is None else f"{value:,.0f}"


def claude_lines(report: Mapping[str, Any]) -> list[str]:
    c = report["claude"]
    out = ["", "## Weighted spend by pool", ""]
    out.append(
        f"- Claude total {num(c['weighted_total'])} ({c['lead_files']} lead files, {c['agent_files']} agent files)"
    )
    for name, cell in c["pools"].items():
        out.append(f"- {name}: {num(cell['weighted'])} ({pct(cell['share'])}, {cell['messages']} messages)")
    out.append(f"- all agents: {num(c['agents_weighted'])} ({pct(c['agents_share'])})")
    out += ["", "## Shares", ""]
    for key, label in (
        ("cache_read_share_of_weighted", "cache read, share of weighted spend"),
        ("cache_read_share_of_tokens", "cache read, share of all tokens"),
        ("output_share_of_weighted", "output, share of weighted spend"),
    ):
        out.append(f"- {label}: lead {pct(c[key]['lead'])}, agents {pct(c[key]['agents'])}")
    t = c["lead_turns"]
    out += ["", "## Lead turns", ""]
    out.append(f"- {t['turns']} turns, {num(t['weighted_per_turn'])} weighted tokens per turn")
    for m in LEAD_TURN_MARKS:
        out.append(
            f"- past turn {m}: {pct(t[f'share_past_{m}'])} of turns, "
            f"{pct(t[f'weighted_share_past_{m}'])} of lead weighted spend"
        )
    pr = report["per_merged_pr"]
    out += ["", "## Per merged PR", ""]
    if not pr["given"]:
        out.append("- merged PRs: not given (pass --merges FILE, one YYYY-MM-DD per line)")
    else:
        out.append(f"- {pr['merged_prs']} merged PRs, {num(pr['weighted_per_pr'])} weighted tokens per PR")
    f = c["agent_first_turn"]
    out += ["", "## Agent first-turn context", ""]
    out.append(f"- {f['agents']} agents, median {num(f['median_context_tokens'])} tokens")
    if f["agents_showing_instructions_or_skills"]:
        out.append(
            f"- instruction files and skill listing: median {pct(f['median_instruction_and_skill_share'])} of the "
            f"first turn (instructions {pct(f['median_instruction_share'])}, "
            f"skills {pct(f['median_skill_listing_share'])}; "
            f"estimated at {f['chars_per_token']:g} characters per token, "
            f"{f['agents_showing_instructions_or_skills']} agents)"
        )
    else:
        out.append("- instruction files and skill listing: not shown by these transcripts")
    return out


def local_lines(local: Mapping[str, Any]) -> list[str]:
    out = ["", "## Local use", ""]
    ll = local.get("llm_local")
    if ll is not None:
        if not ll["found"]:
            out.append("- llm-local calls log: not found")
        else:
            outcomes = ", ".join(f"{k} {v}" for k, v in ll["by_outcome"].items()) or "none"
            out.append(
                f"- llm-local: {ll['real_calls']} real calls ({ll['eval_calls']} eval- calls not counted), "
                f"{ll['calls_project_none']} with project none, {ll['failed_or_busy']} failed or busy, "
                f"{ll['outcome_rows']} outcome rows ({outcomes})"
            )
    d = local.get("dispatches")
    if d is not None:
        if not d["found"]:
            out.append("- hook log: not found")
        else:
            out.append(
                f"- dispatches: {d['dispatches']}; local step {d['local_step']} ({pct(d['local_step_share'])}), "
                f"n/a reason class {d['with_na_reason_class']} ({pct(d['na_reason_class_share'])}), "
                f"marked n/a {d['marked_na']}"
            )
    s = local.get("safo_draft")
    if s is not None:
        if not s["found"]:
            out.append("- safo-draft local-share log: not found")
        else:
            out.append(
                f"- safo-draft: {s['calls']} calls, {s['exit_ok']} exit 0, {s['with_outcome']} with an outcome, "
                f"{s['calls_project_none']} with project none"
            )
    return out


def text(report: Mapping[str, Any]) -> list[str]:
    w = report["weights"]
    out = [
        f"# Spend report, {report['week']}",
        "",
        f"Weighted tokens: input x{w['input']:g}, output x{w['output']:g}, cache read x{w['cache_read']:g}, "
        f"cache write x{w['cache_write']:g}.",
    ]
    if "claude" in report:
        out += claude_lines(report)
    x = report.get("codex")
    if x:
        out += ["", "## Codex (counted apart, never added to Claude)", ""]
        out.append(
            f"- {x['sessions']} sessions: uncached input {x['uncached_input']:,}, cached input {x['cached_input']:,}, "
            f"output {x['output']:,}, weighted {num(x['weighted'])}"
        )
    if report.get("local"):
        out += local_lines(report["local"])
    k = report["skipped"]
    out += [
        "",
        f"Skipped: {k['malformed_lines']} malformed lines, {k['oversize_lines']} oversize lines, "
        f"{k['refused_entries']} refused entries (symlinks or special files), "
        f"{k['stale_files']} files older than the week.",
    ]
    return out


# --- baseline and output files ------------------------------------------------------------------------------------


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]


def write_new(path: Path, body: str, what: str) -> None:
    """Create `path` exclusively, mode 0600, never following a symlink; remove it again if the write fails."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, stat.S_IRUSR | stat.S_IWUSR)
    except FileExistsError:
        raise ConfigError(f"{what} already exists; it is never overwritten") from None
    except OSError:
        raise ConfigError(f"{what} cannot be created there") from None
    try:
        write_all(fd, body.encode("utf-8"))
    except BaseException:
        os.close(fd)
        path.unlink(missing_ok=True)  # the file was created by this call, an instant ago
        raise
    os.close(fd)


def exists(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        raise ConfigError("an output path cannot be examined") from None
    return True


def read_baseline(path: Path) -> dict[str, float]:
    try:
        data = loads(read_bounded(path, MAX_BASELINE_BYTES + 1))
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise ConfigError("the baseline cannot be read or is not valid JSON") from None
    metrics = data.get("metrics") if isinstance(data, dict) else None
    if not isinstance(data, dict) or data.get("version") != BASELINE_VERSION or not isinstance(metrics, dict):
        raise ConfigError("the baseline is not a spend baseline of this version")
    if len(metrics) > MAX_BASELINE_METRICS:
        raise ConfigError("the baseline has more metrics than the cap")
    out: dict[str, float] = {}
    for key, value in metrics.items():
        got = number(value)
        if got is None:
            raise ConfigError("the baseline holds a metric that is not a number")
        out[key] = got
    return out


def change_lines(now: Mapping[str, float], base: Mapping[str, float]) -> list[str]:
    out = []
    for name in sorted(now):
        value = now[name]
        if name not in base:
            out.append(f"- {name}: {value:g} (not in the baseline)")
            continue
        was = base[name]
        delta = value - was
        rel = f", {delta / was * 100:+.1f}%" if was else ""
        out.append(f"- {name}: {value:g} (baseline {was:g}, change {delta:+g}{rel})")
    return out


# --- the mode -----------------------------------------------------------------------------------------------------


def chosen(ctx: LocalContext, given: str, default: Path, what: str) -> tuple[Path, bool]:
    """(path, explicit): a path given on the command line is refused inside the checkout under Actions."""
    path = refuse_workspace(Path(given), ctx.env, what, explicit=True) if given else default
    return path, bool(given)


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    week = valid_week(args.week or week_key(ctx.now.astimezone(dt.UTC).date()))
    home = ctx.home
    clock = Clock()
    skips = Skips()
    json_path = baseline_path = None
    if args.json:
        json_path = refuse_workspace(Path(args.json), ctx.env, "the JSON output file")
        if exists(json_path):
            raise ConfigError("the JSON output file already exists; it is never overwritten")
    base: dict[str, float] | None = None
    if args.baseline:
        baseline_path = refuse_workspace(Path(args.baseline), ctx.env, "the baseline file")
        if exists(baseline_path):
            base = read_baseline(baseline_path)
    merges = None
    if args.merges:
        merges = read_merges(refuse_workspace(Path(args.merges), ctx.env, "the merge list"), skips)
    claude = codex = None
    path, explicit = chosen(ctx, args.claude, home / ".claude" / "projects", "the Claude transcripts folder")
    try:
        claude = scan_claude(path, week, skips, clock)
    except FileNotFoundError:
        if explicit:
            raise ConfigError("the Claude transcripts folder was not found") from None
    except OSError:
        raise ConfigError(NOT_SAFE.format(what="the Claude transcripts folder")) from None
    path, explicit = chosen(ctx, args.codex, home / ".codex" / "sessions", "the Codex sessions folder")
    try:
        codex = scan_codex(path, week, skips, clock)
    except FileNotFoundError:
        if explicit:
            raise ConfigError("the Codex sessions folder was not found") from None
    except OSError:
        raise ConfigError(NOT_SAFE.format(what="the Codex sessions folder")) from None
    logs: dict[str, LogRows] = {}
    for key, given, default, what in (
        ("llm_local", args.llm_local, home / ".local/share/llm-local/calls.jsonl", "the llm-local calls log"),
        ("hook", args.hook_log, home / ".local/state/safo/hooks/log.jsonl", "the hook log"),
        ("share", args.share_log, home / ".local/state/safo/local-share.jsonl", "the local-share log"),
    ):
        path, explicit = chosen(ctx, given, default, what)
        log = read_log(path, skips, clock)
        if explicit and not log.found:
            raise ConfigError(f"{what} was not found")
        logs[key] = log
    report = build(week, claude, codex, logs, merges, skips)
    now = metrics_of(report)
    lines = text(report)
    if base is not None:
        lines += ["", "## Change since the baseline", "", *change_lines(now, base)]
    for line in lines:
        ctx.say(line)
    if json_path is not None:
        write_new(json_path, json.dumps(report, indent=1, sort_keys=True) + "\n", "the JSON output file")
    if baseline_path is not None and base is None:
        document = {"version": BASELINE_VERSION, "week": week, "metrics": now}
        write_new(baseline_path, json.dumps(document, indent=1, sort_keys=True) + "\n", "the baseline file")
        ctx.say("")
        ctx.say("Baseline written; later runs with the same --baseline print the change per line.")
    return EXIT_OK


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--week", default="", help="an ISO week such as 2026-W48, or all (default: this week)")
    parser.add_argument("--claude", default="", help="the Claude transcripts folder (default: ~/.claude/projects)")
    parser.add_argument("--codex", default="", help="the Codex sessions folder (default: ~/.codex/sessions)")
    parser.add_argument(
        "--llm-local", default="", help="the llm-local calls log (default: ~/.local/share/llm-local/calls.jsonl)"
    )
    parser.add_argument("--hook-log", default="", help="the hook log (default: ~/.local/state/safo/hooks/log.jsonl)")
    parser.add_argument(
        "--share-log",
        default="",
        help="the safo-draft local-share log (default: ~/.local/state/safo/local-share.jsonl)",
    )
    parser.add_argument("--merges", default="", help="a text file of merge dates, one YYYY-MM-DD per line")
    parser.add_argument(
        "--baseline", default="", help="write the first report here; later runs print the change against it"
    )
    parser.add_argument("--json", default="", help="also write the numbers to this new file (mode 0600)")


register_local(
    LocalMode("spend", "a weekly token-spend report with a stored baseline (local, read-only)", add_arguments, run)
)
