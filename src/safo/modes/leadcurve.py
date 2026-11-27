# SPDX-License-Identifier: Apache-2.0
"""lead-curve: how lead-session cost grows with turn position, and what a handoff costs (#556, phase 1). Read-only.

It reads the Claude lead-session transcripts and prints counts and sums only: per session the turn count, the context
tokens (input + cache read + cache write) at the first and last turn and summed over the turns, and the weighted spend
by turn bucket (1-100, 101-200, 201-300, 301+); across sessions the share of turns and of spend past turn 200 and 400,
and, side by side and labeled, the first turn at which the marginal weighted spend per turn passes 1.5 times the median
of turns 1-20, the turn after which 50 and 80 percent of a session's weighted spend has been reached (median across
sessions), and the same threshold from the median of turns 1-100 (the old definition, weak: spend rises with context).
A handoff is a session whose first user message contains the word handoff (a yes or no found while reading, never
printed), paired with the latest earlier session of the same project folder. Its cost is the successor's first three
turns, MEASURED, and the note, ESTIMATED as the largest single reply (output tokens x5) in the predecessor's last five
turns. Nothing from a transcript is printed except numbers: no text, title, path or label. It writes nothing. It reads
files the way `safo spend` does and reuses its parser bounds and weights.
"""

from __future__ import annotations

import argparse
import datetime as dt
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from safo.context import LocalContext
from safo.errors import EXIT_OK, ConfigError
from safo.modes import LocalMode, register_local
from safo.modes.spend import (
    MAX_FILE_BYTES,
    MAX_FILES,
    NOT_SAFE,
    WEIGHT_OUTPUT,
    Bound,
    Clock,
    Skips,
    before_week,
    chosen,
    lines_of,
    open_regular,
    parsed,
    usage_of,
    utc_day,
    valid_week,
    walk,
    week_key,
    weighted,
)

BUCKETS = ((1, 100), (101, 200), (201, 300), (301, 0))  # 0 means no upper end
BUCKET_KEYS = ("w_0_100", "w_100_200", "w_200_300", "w_300_plus")
MARKS = (200, 400)
FACTOR = 1.5
WINDOW = 10  # turns in the rolling mean of the marginal spend
EARLY = 100
EARLY_SHORT = 20
CUMULATIVE_SHARES = (0.5, 0.8)
SUCCESSOR_TURNS = 3
NOTE_TURNS = 5
MAX_SESSIONS_SHOWN = 25
HANDOFF_WORDS = (b"handoff", b"hand-off", b"handover")


@dataclass
class Turn:
    vals: tuple[int, int, int, int]
    weight: float
    context: int
    week: str


@dataclass
class Session:
    project: str
    start: dt.datetime
    end: dt.datetime
    turns: list[Turn] = field(default_factory=list)  # every turn, numbered from the start of the file
    handoff: bool = False


def moment(stamp: Any) -> dt.datetime | None:
    if utc_day(stamp) is None:
        return None
    try:
        value = dt.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def read_session(path: Path, project: str, mtime: float, skips: Skips, clock: Clock) -> Session | None:
    handle, size = open_regular(path)
    with handle:
        if size > MAX_FILE_BYTES:
            raise Bound("lead-curve: a transcript is larger than the size cap; nothing was reported")
        best: dict[str, tuple[int, Turn]] = {}
        stamps: list[dt.datetime] = []
        handoff = False
        seen_user = False
        for line in lines_of(handle, skips, clock, MAX_FILE_BYTES):
            is_user = b'"user"' in line and not seen_user
            is_assistant = b'"usage"' in line and b'"assistant"' in line
            if not is_user and not is_assistant:
                continue
            row = parsed(line, skips)
            if row is None:
                continue
            if row.get("type") == "user":
                if is_user:
                    seen_user = True
                    handoff = any(word in line.lower() for word in HANDOFF_WORDS)
                continue
            if row.get("type") != "assistant":
                continue
            message = row.get("message")
            if not isinstance(message, dict):
                continue
            vals = usage_of(message)
            model = message.get("model")
            if vals is None or type(model) is not str or not model or model.startswith("<"):
                continue
            when = moment(row.get("timestamp"))
            if when is not None:
                stamps.append(when)
            day = utc_day(row.get("timestamp")) or dt.datetime.fromtimestamp(mtime, dt.UTC).date()
            item = Turn(vals, weighted(*vals), vals[0] + vals[2] + vals[3], week_key(day))
            ident = message.get("id")
            key = ident if type(ident) is str and ident else f"line-{len(best)}"
            previous = best.get(key)
            if previous is None:
                best[key] = (len(best), item)
            elif vals[1] >= previous[1].vals[1]:
                best[key] = (previous[0], item)
    if not best:
        return None
    turns = [t for _, t in sorted(best.values(), key=lambda pair: pair[0])]
    fallback = dt.datetime.fromtimestamp(mtime, dt.UTC)
    return Session(project, min(stamps, default=fallback), max(stamps, default=fallback), turns, handoff)


def scan(root: Path, week: str, skips: Skips, clock: Clock) -> list[Session]:
    sessions: list[Session] = []
    for entry in walk(root, MAX_FILES, skips, clock):
        clock.check()
        if entry.agent:
            continue
        if before_week(week, entry.mtime):
            skips.stale += 1
            continue
        try:
            session = read_session(entry.path, entry.path.parent.name, entry.mtime, skips, clock)
        except OSError:
            skips.refused += 1
            continue
        if session is not None:
            sessions.append(session)
    return sorted(sessions, key=lambda s: (s.start, s.end))


def in_window(week: str, item: Turn) -> bool:
    return week == "all" or item.week == week


def bucket_of(number: int) -> int:
    for index, (low, high) in enumerate(BUCKETS):
        if number >= low and (high == 0 or number <= high):
            return index
    return len(BUCKETS) - 1


def pct(part: float, whole: float) -> str:
    return "n/a" if whole <= 0 else f"{100.0 * part / whole:.1f}%"


def threshold(sessions: list[list[tuple[int, Turn]]], early: int) -> tuple[float | None, int | None]:
    """(median weight of turns 1..early, first turn after `early` where a 10-turn mean of the per-turn mean spend
    passes 1.5x it)."""
    base = [t.weight for turns in sessions for n, t in turns if n <= early]
    if not base:
        return None, None
    baseline = statistics.median(base)
    per_turn: dict[int, list[float]] = {}
    for turns in sessions:
        for n, t in turns:
            per_turn.setdefault(n, []).append(t.weight)
    means = {n: statistics.fmean(v) for n, v in per_turn.items()}
    for n in range(early + 1, max(means, default=0) + 1):
        window = [means[k] for k in range(n - WINDOW + 1, n + 1) if k in means]
        if len(window) == WINDOW and statistics.fmean(window) > FACTOR * baseline:
            return baseline, n
    return baseline, None


def reached(turns: list[tuple[int, Turn]], share: float) -> int | None:
    """The turn number at which the running weighted spend of a session first reaches `share` of its total."""
    total = sum(t.weight for _, t in turns)
    if total <= 0:
        return None
    running = 0.0
    for n, t in turns:
        running += t.weight
        if running >= share * total:
            return n
    return None


def threshold_line(label: str, sessions: list[list[tuple[int, Turn]]], early: int) -> str:
    baseline, first = threshold(sessions, early)
    base = "n/a" if baseline is None else f"{baseline:.1f}"
    limit = "n/a" if baseline is None else f"{FACTOR * baseline:.1f}"
    where = "not reached" if first is None else str(first)
    return (
        f"marginal threshold [{label}]: baseline_median={base} limit={limit} first_turn={where} "
        f"(first turn past {early} where the {WINDOW}-turn mean of the per-turn mean spend "
        f"passes {FACTOR}x the baseline)"
    )


def cumulative_line(sessions: list[list[tuple[int, Turn]]]) -> str:
    parts = []
    for share in CUMULATIVE_SHARES:
        found = [n for n in (reached(turns, share) for turns in sessions) if n is not None]
        value = "n/a" if not found else f"{statistics.median(found):.1f}"
        parts.append(f"turn_at_{round(share * 100)}pct={value}")
    return f"cumulative spend [median across {len(sessions)} sessions]: " + " ".join(parts)


def session_line(index: int, turns: list[tuple[int, Turn]]) -> str:
    buckets = [0.0] * len(BUCKETS)
    for n, t in turns:
        buckets[bucket_of(n)] += t.weight
    parts = " ".join(f"{key}={value:.1f}" for key, value in zip(BUCKET_KEYS, buckets, strict=True))
    cumulative = sum(t.context for _, t in turns)
    return (
        f"session {index}: turns={turns[-1][0]} in_window={len(turns)} ctx_first={turns[0][1].context} "
        f"ctx_last={turns[-1][1].context} ctx_cumulative={cumulative} {parts}"
    )


def handoff_lines(sessions: list[Session]) -> list[str]:
    lines: list[str] = []
    for index, session in enumerate(sessions):
        if not session.handoff:
            continue
        earlier = [s for s in sessions[:index] if s.project == session.project and s.end <= session.start]
        if not earlier:
            continue
        before = earlier[-1]
        note = max((t.vals[1] for t in before.turns[-NOTE_TURNS:]), default=0) * WEIGHT_OUTPUT
        first = sum(t.weight for t in session.turns[:SUCCESSOR_TURNS])
        lines.append(
            f"handoff {len(lines) + 1}: write_note_weighted={note:.1f} (estimate) "
            f"successor_first_{SUCCESSOR_TURNS}_turns_weighted={first:.1f} (measured) "
            f"predecessor_turns={len(before.turns)}"
        )
    return lines


def report(sessions: list[Session], week: str, skips: Skips) -> list[str]:
    windowed: list[list[tuple[int, Turn]]] = []
    for session in sessions:
        kept = [(n, t) for n, t in enumerate(session.turns, 1) if in_window(week, t)]
        if kept:
            windowed.append(kept)
    total = sum(len(turns) for turns in windowed)
    spend = sum(t.weight for turns in windowed for _, t in turns)
    label = "all weeks" if week == "all" else week
    lines = [f"# Lead-session curve ({label}); weights input 1, output 5, cache read 0.1, cache write 1.25", ""]
    lines.append(f"lead sessions: {len(windowed)}, lead turns: {total}, weighted spend: {spend:.1f}")
    for mark in MARKS:
        count = sum(1 for turns in windowed for n, _ in turns if n > mark)
        past = sum(t.weight for turns in windowed for n, t in turns if n > mark)
        lines.append(f"past turn {mark}: {pct(count, total)} of lead turns, {pct(past, spend)} of weighted spend")
    lines.append(threshold_line("baseline turns 1-20", windowed, EARLY_SHORT))
    lines.append(cumulative_line(windowed))
    lines.append(threshold_line("baseline turns 1-100, old definition", windowed, EARLY))
    shown = sorted(windowed, key=lambda turns: -turns[-1][0])[:MAX_SESSIONS_SHOWN]
    lines += ["", f"## Sessions (the {len(shown)} longest of {len(windowed)}; context tokens and weighted spend)", ""]
    lines += [session_line(i, turns) for i, turns in enumerate(shown, 1)]
    inside = [s for s in sessions if any(in_window(week, t) for t in s.turns[:SUCCESSOR_TURNS])]
    marks = handoff_lines(inside)
    lines += [
        "",
        "## Handoffs (first user message names a handoff; paired with the project's latest earlier session)",
        "",
    ]
    lines += marks
    lines.append(f"handoffs: {len(marks)}")
    lines += [
        "",
        f"skipped: malformed {skips.malformed}, oversize {skips.oversize}, "
        f"refused {skips.refused}, stale {skips.stale}",
    ]
    return lines


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    week = valid_week(args.week or week_key(ctx.now.astimezone(dt.UTC).date()))
    clock = Clock()
    skips = Skips()
    path, explicit = chosen(ctx, args.claude, ctx.home / ".claude" / "projects", "the Claude transcripts folder")
    sessions: list[Session] = []
    try:
        sessions = scan(path, week, skips, clock)
    except FileNotFoundError:
        if explicit:
            raise ConfigError("the Claude transcripts folder was not found") from None
    except OSError:
        raise ConfigError(NOT_SAFE.format(what="the Claude transcripts folder")) from None
    for line in report(sessions, week, skips):
        ctx.say(line)
    return EXIT_OK


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--week", default="", help="an ISO week such as 2026-W48, or all (default: this week)")
    parser.add_argument("--claude", default="", help="the Claude transcripts folder (default: ~/.claude/projects)")


register_local(
    LocalMode(
        "lead-curve",
        "how lead-session cost grows with turn position, and handoff cost (local, read-only)",
        add_arguments,
        run,
    )
)
