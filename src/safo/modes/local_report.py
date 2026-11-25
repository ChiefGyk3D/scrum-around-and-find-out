# SPDX-License-Identifier: Apache-2.0
"""local report: how often briefs and sessions really use the local model, counted by code from local logs (#372).

Read-only on every input and bounded: a file is opened without following a symlink or waiting on a FIFO, at most the
last MAX_FILE_BYTES bytes and MAX_LINES lines are read, an over-long or malformed line is counted and skipped. No model
is called and nothing is written; every printed value goes through the output writer (`LocalContext.say`).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import stat
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from safo import guardlog
from safo.bounded import MAX_BYTES, loads, read_bounded
from safo.context import LocalContext
from safo.errors import EXIT_OK, ConfigError

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_LINES = 100_000
MAX_LINE_BYTES = 4096
MAX_LABELS = 200  # distinct task labels or models kept; the rest are counted as "(other)"
MAX_LABEL = 64
MAX_DAYS = 3660
DEFAULT_DAYS = 28
OTHER = "(other)"

# What cannot be counted today, and the one-line change that would record it.
MISSING = (
    (
        "reason text of `local-llm: n/a` lines",
        "the guard log keeps only the boolean `na`; add `na_reason` (first 120 characters, controls escaped) to the "
        "guard's log record",
    ),
    (
        "which brief or issue made each llm-local call",
        "calls.jsonl has task, model and tokens only; have `llm-local` also record `$LLM_LOCAL_BRIEF` (the brief's "
        "`issue:` line) as `brief`",
    ),
    (
        "whether a brief that named a local step really called the model",
        "the guard log has no brief id; add `brief` (the issue ref) to the guard's log record so it can be joined "
        "with calls.jsonl",
    ),
    (
        "accepted, rewritten or discarded outcome of a local draft",
        "nothing records it; add an `--outcome accepted|rewritten|discarded` option to `safo outcome add` (or the "
        "outcomes row) for local drafts",
    ),
    (
        "admit and busy counts per day",
        "state.json keeps cumulative counters only; have `llm-local` append one snapshot row per day to a "
        "counters.jsonl",
    ),
    (
        "tokens saved on the paid model by a local draft",
        "no field relates a draft to the paid tokens it replaced; record `replaces_tokens` (estimate) on the call row",
    ),
)


class Source:
    """One input file: its rows, and what could not be used. `found` is False when it is absent or not readable."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.found = False
        self.truncated = False
        self.malformed = 0
        self.lines: list[bytes] = []


def read_lines(path: Path) -> Source:
    """The last MAX_LINES complete lines of at most the last MAX_FILE_BYTES bytes of a regular file."""
    src = Source(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return src  # absent, a symlink or unreadable: nothing is read
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return src
        src.found = True
        start = max(0, info.st_size - MAX_FILE_BYTES)
        os.lseek(fd, start, os.SEEK_SET)
        chunks: list[bytes] = []
        total = 0
        while total < MAX_FILE_BYTES:
            chunk = os.read(fd, min(65_536, MAX_FILE_BYTES - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError:
        src.found = False
        return src
    finally:
        os.close(fd)
    raw = b"".join(chunks).splitlines(keepends=True)
    if start > 0:
        src.truncated = True
        raw = raw[1:]  # the first line is cut in the middle
    if len(raw) > MAX_LINES:
        src.truncated = True
        raw = raw[-MAX_LINES:]
    for line in raw:
        if not line.strip():
            continue
        if not line.endswith(b"\n") or len(line) > MAX_LINE_BYTES:
            src.malformed += 1  # a torn last line, or one too long to trust
            continue
        src.lines.append(line)
    return src


def json_rows(src: Source) -> list[dict[str, Any]]:
    rows = []
    for line in src.lines:
        try:
            row = loads(line)
        except (ValueError, UnicodeError):
            row = None
        if isinstance(row, dict):
            rows.append(row)
        else:
            src.malformed += 1
    return rows


def day_of(row: Mapping[str, Any]) -> dt.date | None:
    ts = row.get("ts")
    if not isinstance(ts, str):
        return None
    try:
        return dt.datetime.fromisoformat(ts[:19]).date()
    except ValueError:
        return None


def week_of(day: dt.date) -> str:
    iso = day.isocalendar()
    return f"{iso.year}-W{iso.week:02d}"


def label(value: Any) -> str:
    return value[:MAX_LABEL] if isinstance(value, str) and value else "(none)"


def bump(counter: Counter[str], key: str) -> None:
    counter[key if key in counter or len(counter) < MAX_LABELS else OTHER] += 1


def dispatch_flags(row: Mapping[str, Any]) -> dict[str, int]:
    step = row.get("local_step") is True
    line = row.get("local_line") is True
    return {
        "dispatches": 1,
        "reachable": int(row.get("local_reachable") is True),
        "local_step": int(step),
        "local_line": int(line),
        "neither": int(not step and not line),
    }


def dispatch_section(path: Path, since: dt.date) -> dict[str, Any]:
    src = read_lines(path)
    by_day: dict[str, Counter[str]] = {}
    by_week: dict[str, Counter[str]] = {}
    by_model: dict[str, Counter[str]] = {}
    rows = 0
    for row in json_rows(src):
        day = day_of(row)
        if day is None:
            src.malformed += 1
            continue
        if day < since:
            continue
        rows += 1
        flags = dispatch_flags(row)
        model = label(row.get("model"))
        if model not in by_model and len(by_model) >= MAX_LABELS:
            model = OTHER
        for table, key in ((by_day, day.isoformat()), (by_week, week_of(day)), (by_model, model)):
            table.setdefault(key, Counter()).update(flags)
    return {
        "found": src.found,
        "rows": rows,
        "malformed": src.malformed,
        "truncated": src.truncated,
        "by_day": {k: dict(by_day[k]) for k in sorted(by_day)},
        "by_week": {k: dict(by_week[k]) for k in sorted(by_week)},
        "by_model": {k: dict(by_model[k]) for k in sorted(by_model)},
    }


def hooks_section(env: Mapping[str, str], since: dt.date) -> dict[str, Any]:
    folder = guardlog.state_dir(env)
    rows = guardlog.read_log(folder / guardlog.LOG_NAME if folder else None)  # the code `safo hooks status` uses
    rows = [r for r in rows if (day_of(r) or since) >= since]
    counts = guardlog.summarise(rows)
    return {
        "found": bool(rows),
        "total": counts.total,
        "since": counts.since,
        "decisions": dict(counts.decisions),
        "models": dict(counts.models),
        "rules": dict(counts.rules),
        "local_steps": counts.local_steps,
        "marked_na": counts.marked_na,
    }


def _dir(env: Mapping[str, str], xdg: str, fallback: tuple[str, ...]) -> Path | None:
    chosen = env.get(xdg, "")
    if chosen and Path(chosen).is_absolute():
        return Path(chosen) / "llm-local"
    home = env.get("HOME", "")
    return Path(home).joinpath(*fallback, "llm-local") if home else None


def counters_of(path: Path) -> dict[str, int]:
    try:
        data = loads(read_bounded(path, MAX_BYTES + 1))
    except (OSError, ValueError, UnicodeError):
        return {}
    raw = data.get("counters") if isinstance(data, dict) else None
    out: dict[str, int] = {}
    if isinstance(raw, dict):
        for key, value in list(raw.items())[:MAX_LABELS]:
            if isinstance(key, str) and type(value) is int and 0 <= value <= 10**12:
                out[key[:MAX_LABEL]] = value
    return out


def llm_local_section(env: Mapping[str, str], since: dt.date) -> dict[str, Any]:
    state, share = _dir(env, "XDG_STATE_HOME", (".local", "state")), _dir(env, "XDG_DATA_HOME", (".local", "share"))
    src = Source(Path("calls.jsonl"))
    for folder in (state, share):  # the first calls log that exists; never both, so no call is counted twice
        if folder is not None:
            src = read_lines(folder / "calls.jsonl")
            if src.found:
                break
    by_task: Counter[str] = Counter()
    by_model: Counter[str] = Counter()
    by_day: Counter[str] = Counter()
    by_week: Counter[str] = Counter()
    calls = tokens = 0
    for row in json_rows(src):
        day = day_of(row)
        if day is None:
            src.malformed += 1
            continue
        if day < since:
            continue
        calls += 1
        bump(by_task, label(row.get("task")))
        bump(by_model, label(row.get("model")))
        by_day[day.isoformat()] += 1
        by_week[week_of(day)] += 1
        for field in ("prompt_tokens", "eval_tokens"):
            value = row.get(field)
            if type(value) is int and 0 <= value <= 10**9:
                tokens += value
    return {
        "found": src.found,
        "calls": calls,
        "tokens": tokens,
        "malformed": src.malformed,
        "truncated": src.truncated,
        "by_task": dict(sorted(by_task.items())),
        "by_model": dict(sorted(by_model.items())),
        "by_day": dict(sorted(by_day.items())),
        "by_week": dict(sorted(by_week.items())),
        "counters": counters_of(state / "state.json") if state else {},
    }


def build(env: Mapping[str, str], today: dt.date, days: int) -> dict[str, Any]:
    since = today - dt.timedelta(days=days - 1)
    home = env.get("HOME", "")
    base = _dir(env, "XDG_STATE_HOME", (".local", "state"))
    state_root = base.parent if base else (Path(home) / ".local" / "state" if home else Path("."))
    dispatch = dispatch_section(state_root / "agent-dispatch-guard" / "log.jsonl", since)
    missing = [{"what": what, "change": change} for what, change in MISSING]
    return {
        "generated": today.isoformat(),
        "days": days,
        "since": since.isoformat(),
        "dispatch": dispatch,
        "hooks": hooks_section(env, since),
        "llm_local": llm_local_section(env, since),
        "missing": missing,
    }


def _flags_line(name: str, c: Mapping[str, int]) -> str:
    return (
        f"  {name}  dispatches {c['dispatches']}  reachable {c['reachable']}  local step {c['local_step']}  "
        f"local-llm line {c['local_line']}  neither {c['neither']}"
    )


def text(report: Mapping[str, Any]) -> list[str]:
    d, h, ll = report["dispatch"], report["hooks"], report["llm_local"]
    out = [f"Local-model use, {report['since']} to {report['generated']} ({report['days']} days)", ""]
    out.append("Dispatch guard log (agent-dispatch-guard/log.jsonl)")
    if not d["found"]:
        out.append("  no dispatch log found")
    else:
        out.append(f"  {d['rows']} dispatches in the window; malformed lines skipped: {d['malformed']}")
        if d["truncated"]:
            out.append("  only the newest part of the file was read (size or line cap)")
        out.append(" by day")
        out += [_flags_line(k, v) for k, v in d["by_day"].items()]
        out.append(" by week")
        out += [_flags_line(k, v) for k, v in d["by_week"].items()]
        out.append(" by model")
        out += [_flags_line(k, v) for k, v in d["by_model"].items()]
    out += ["", "Routing guard (safo hooks status counts)"]
    if not h["total"]:
        out.append("  no hooks guard rows in the window")
    else:
        out.append(
            f"  {h['total']} dispatches since {h['since']}: " + ", ".join(f"{k} {v}" for k, v in h["decisions"].items())
        )
        out.append(f"  briefs with a local step {h['local_steps']}, marked n/a {h['marked_na']}")
        out.append("  models: " + ", ".join(f"{k} {v}" for k, v in h["models"].items()))
        if h["rules"]:
            out.append("  rules flagged: " + ", ".join(f"{k} {v}" for k, v in h["rules"].items()))
    out += ["", "llm-local"]
    if not ll["found"]:
        out.append("  no llm-local calls log found")
    else:
        out.append(
            f"  {ll['calls']} calls, {ll['tokens']:,} tokens in the window; malformed lines skipped: {ll['malformed']}"
        )
        if ll["truncated"]:
            out.append("  only the newest part of the file was read (size or line cap)")
        out.append("  by task: " + (", ".join(f"{k} {v}" for k, v in ll["by_task"].items()) or "none"))
        out.append("  by model: " + (", ".join(f"{k} {v}" for k, v in ll["by_model"].items()) or "none"))
        out.append("  by day: " + (", ".join(f"{k} {v}" for k, v in ll["by_day"].items()) or "none"))
        out.append("  by week: " + (", ".join(f"{k} {v}" for k, v in ll["by_week"].items()) or "none"))
    c = ll["counters"]
    out.append("  admission (all time): " + ("  ".join(f"{k} {v}" for k, v in sorted(c.items())) or "no state.json"))
    out += ["", "MISSING DATA (cannot be counted today; the one-line change that would record it)"]
    for item in report["missing"]:
        out.append(f"  - {item['what']}: {item['change']}")
    return out


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    if not (0 < args.days <= MAX_DAYS):
        raise ConfigError(f"--days must be above 0 and at most {MAX_DAYS}")
    report = build(ctx.env, ctx.now.date(), args.days)
    if args.json:
        # one line, ASCII only; `::` is written as a JSON escape so no value can start a workflow command
        ctx.say(json.dumps(report, separators=(",", ":")).replace("::", ":\\u003a"))
    else:
        for line in text(report):
            ctx.say(line)
    return EXIT_OK
