# SPDX-License-Identifier: Apache-2.0
"""local report: how often briefs and sessions really use the local model, counted by code from local logs (#372).

Read-only on every input and bounded: a file is opened without following a symlink or waiting on a FIFO, at most the
last MAX_FILE_BYTES bytes and MAX_LINES lines are read, an over-long or malformed line is counted and skipped. No model
is called and nothing is written; every printed value goes through the output writer (`LocalContext.say`).
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from safo import guardlog
from safo.bounded import MAX_BYTES, loads
from safo.context import LocalContext
from safo.errors import EXIT_OK, ConfigError

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_LINES = 100_000
MAX_LINE_BYTES = 4096
MAX_LABELS = 200  # distinct task labels or models kept; the rest are counted as "(other)"
MAX_DAYS = 3660
TS_SHAPE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}")  # exactly what the writers log
DEFAULT_DAYS = 28
OTHER = "other"

# The typed llm-local records (kind call or outcome) and the guard's na_reason_class now provide outcomes, failures,
# the reason class and load-fresh, so only what they still lack is listed here, with the one-line change.
MISSING = (
    (
        "which brief or issue made each llm-local call",
        "calls carry an id but no brief; have `llm-local` also record `$LLM_LOCAL_BRIEF` (the brief's `issue:` line) "
        "as `brief`",
    ),
    (
        "whether a brief that names llm-local really called the model",
        "the dispatch guard log has no brief id; add `brief` (the issue ref) to its log record so it can be joined "
        "with the calls log",
    ),
    (
        "tokens saved on the paid model by a local draft",
        "no field relates a draft to the paid tokens it replaced; record `replaces_tokens` (estimate) on the call row",
    ),
    (
        "outcomes for calls made before the typed records",
        "rows written by the old tool have no kind or id, so they can never get an outcome; nothing to change, they "
        "leave the window with time",
    ),
)
OUTCOMES = ("accepted", "rewritten", "discarded", "fact-error")
NA_CLASSES = ("code", "state-change", "security", "credentials", "verbatim", "other")
INVALID = "(invalid)"
MAX_ID = 64


class Source:
    """One input file: its rows, and what could not be used. `found` is False when it is absent or not readable."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.found = False
        self.refused = ""  # why the file was not opened (a fixed phrase, never the path)
        self.truncated = False
        self.malformed = 0
        self.future = 0  # rows dated after today; they are also counted in `malformed`
        self.lines: list[bytes] = []


class Refused(Exception):
    """A directory or file on the way is not safe to read; the text is a fixed phrase, never part of the path."""


REFUSED_WALK = "a directory on the path is a symlink, not a directory, not yours or writable by others"
REFUSED_FILE = "the file is a symlink, not a regular file, not yours or writable by others"


def current_uid() -> int:
    return os.geteuid()


def current_gid() -> int:
    return os.getegid()


def unsafe(info: os.stat_result) -> bool:
    """Not owned by this user, or writable by anyone else (a group write is allowed only for the user's own group)."""
    if info.st_uid != current_uid() or info.st_mode & stat.S_IWOTH:
        return True
    return bool(info.st_mode & stat.S_IWGRP) and info.st_gid != current_gid()


def open_confined(anchor: Path, parts: tuple[str, ...]) -> int:
    """Open anchor/parts for reading, walking the directories with openat and O_NOFOLLOW at every component.

    FileNotFoundError when something is absent; Refused when a directory is a symlink or not a directory, a directory
    or the file is not owned by this user or is group or world writable, or the file is not a regular file. The anchor
    (the home directory) is the user's own and is opened as it is.
    """
    dfd = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in parts[:-1]:
            try:
                nfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd)
            except (FileNotFoundError, NotADirectoryError) as err:
                if isinstance(err, FileNotFoundError):
                    raise
                raise Refused(REFUSED_WALK) from None
            except OSError:
                raise Refused(REFUSED_WALK) from None  # ELOOP: a symlink
            os.close(dfd)
            dfd = nfd
            if unsafe(os.fstat(dfd)):
                raise Refused(REFUSED_WALK)
        try:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        except FileNotFoundError:
            raise
        except OSError:
            raise Refused(REFUSED_FILE) from None
    finally:
        os.close(dfd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or unsafe(info):
            raise Refused(REFUSED_FILE)
    except BaseException:
        os.close(fd)
        raise
    return fd


def read_lines(anchor: Path, *parts: str) -> Source:
    """The last MAX_LINES complete lines of at most the last MAX_FILE_BYTES bytes of a regular file."""
    src = Source(anchor.joinpath(*parts))
    try:
        fd = open_confined(anchor, parts)
    except Refused as why:
        src.refused = str(why)
        return src
    except OSError:
        return src  # absent or unreadable: nothing is read
    try:
        info = os.fstat(fd)
        src.found = True
        start = max(0, info.st_size - MAX_FILE_BYTES)
        cut = start > 0 and os.pread(fd, 1, start - 1) != b"\n"  # the first line starts before the window
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
        if cut:
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
    if not isinstance(ts, str) or not TS_SHAPE.fullmatch(ts):
        return None
    try:
        return dt.date.fromisoformat(ts[:10]) if dt.time.fromisoformat(ts[11:]) is not None else None
    except ValueError:
        return None


def in_window(src: Source, row: Mapping[str, Any], since: dt.date, today: dt.date) -> dt.date | None:
    """The row's day when it is inside the window; None otherwise. A bad timestamp or a future row is counted."""
    day = day_of(row)
    if day is None:
        src.malformed += 1
        return None
    if day > today:
        src.malformed += 1
        src.future += 1
        return None
    return day if day >= since else None


def week_of(day: dt.date) -> str:
    iso = day.isocalendar()
    return f"{iso.year}-W{iso.week:02d}"


SAFE_LABEL = re.compile(r"[a-z0-9._:-]{1,40}")
MAX_UNKNOWN = 10_000  # distinct unknown labels remembered, only to count them
# The task labels the tool documents (docs/usage.md); any other task text may be prompt text, so it is classed `other`.
KNOWN_TASKS = frozenset(
    {
        "smoke",
        "triage",
        "summary",
        "digest",
        "classify",
        "draft",
        "outline",
        "pr-body",
        "issue-draft",
        "ci-summary",
        "lesson-draft",
        "alert-triage",
        "bots-triage",
        "dotsync-summary",
        "idle-classify",
        "kind-effort-draft",
        "pack-summary",
        "standards-digest",
        "gap-issue",
    }
)


class Labels:
    """Classifies free text from a log into a fixed safe set. The text of an unknown label is never kept: only how
    many distinct ones were seen."""

    def __init__(self, known: frozenset[str] | None = None) -> None:
        self.known = known
        self.unknown: set[str] = set()

    def __call__(self, value: Any) -> str:
        if not isinstance(value, str) or not value:
            return "(none)"
        if SAFE_LABEL.fullmatch(value) and (self.known is None or value in self.known):
            return value
        if len(self.unknown) < MAX_UNKNOWN:
            self.unknown.add(hashlib.sha256(value.encode("utf-8", "replace")).hexdigest())
        return OTHER


def safe_key(key: str) -> str:
    return key if SAFE_LABEL.fullmatch(key) else OTHER


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


def dispatch_section(src: Source, since: dt.date, today: dt.date) -> dict[str, Any]:
    models = Labels()
    by_day: dict[str, Counter[str]] = {}
    by_week: dict[str, Counter[str]] = {}
    by_model: dict[str, Counter[str]] = {}
    class_day: dict[str, Counter[str]] = {}
    class_week: dict[str, Counter[str]] = {}
    class_total: Counter[str] = Counter()
    rows = 0
    for row in json_rows(src):
        day = in_window(src, row, since, today)
        if day is None:
            continue
        rows += 1
        flags = dispatch_flags(row)
        found = row.get("na_reason_class")
        if found is not None:  # null and an absent field (an older row) are not counted
            name = found if isinstance(found, str) and found in NA_CLASSES else INVALID
            class_total[name] += 1
            class_day.setdefault(day.isoformat(), Counter())[name] += 1
            class_week.setdefault(week_of(day), Counter())[name] += 1
        model = models(row.get("model"))
        if model not in by_model and len(by_model) >= MAX_LABELS:
            model = OTHER
        for table, key in ((by_day, day.isoformat()), (by_week, week_of(day)), (by_model, model)):
            table.setdefault(key, Counter()).update(flags)
    return {
        "found": src.found,
        "refused": src.refused,
        "unknown_labels": {"model": len(models.unknown)},
        "rows": rows,
        "malformed": src.malformed,
        "future": src.future,
        "truncated": src.truncated,
        "by_day": {k: dict(by_day[k]) for k in sorted(by_day)},
        "by_week": {k: dict(by_week[k]) for k in sorted(by_week)},
        "by_model": {k: dict(by_model[k]) for k in sorted(by_model)},
        "na_reason_class": {
            "by_day": {k: dict(sorted(class_day[k].items())) for k in sorted(class_day)},
            "by_week": {k: dict(sorted(class_week[k].items())) for k in sorted(class_week)},
            "total": dict(sorted(class_total.items())),
        },
    }


def hooks_section(env: Mapping[str, str], since: dt.date, today: dt.date) -> dict[str, Any]:
    """The `safo hooks status` counts (guardlog.summarise), from rows read here without taking the log's lock."""
    folder = guardlog.state_dir(env)  # the hooks log honors XDG_STATE_HOME, as the guard that writes it does
    src = Source(Path(guardlog.LOG_NAME))
    if folder is not None and guardlog.trusted_dir(folder):
        src = read_lines(folder, guardlog.LOG_NAME)
    rows = []
    for row in json_rows(src):
        if not guardlog.valid_record(row):
            src.malformed += 1
        elif in_window(src, row, since, today) is not None:
            rows.append(row)
    counts = guardlog.summarise(rows)
    return {
        "found": src.found,
        "refused": src.refused,
        "total": counts.total,
        "since": counts.since,
        "malformed": src.malformed,
        "future": src.future,
        "truncated": src.truncated,
        "decisions": dict(counts.decisions),
        "models": dict(counts.models),
        "rules": dict(counts.rules),
        "local_steps": counts.local_steps,
        "marked_na": counts.marked_na,
    }


def home_read(env: Mapping[str, str], *parts: str) -> Source:
    """Under HOME only (the guard and llm-local write there and ignore the XDG variables), every directory checked."""
    home = env.get("HOME", "")
    return read_lines(Path(home), *parts) if home else Source(Path(parts[-1]))


def counters_of(env: Mapping[str, str], *parts: str) -> dict[str, int]:
    """The admission counters; a key that is not a safe label is added to `other`."""
    home = env.get("HOME", "")
    if not home:
        return {}
    try:
        fd = open_confined(Path(home), parts)
    except (Refused, OSError):
        return {}
    try:
        data = loads(os.read(fd, MAX_BYTES + 1))
    except (OSError, ValueError, UnicodeError):
        return {}
    finally:
        os.close(fd)
    raw = data.get("counters") if isinstance(data, dict) else None
    out: dict[str, int] = {}
    if isinstance(raw, dict):
        for key, value in list(raw.items())[:MAX_LABELS]:
            if isinstance(key, str) and type(value) is int and 0 <= value <= 10**12:
                name = safe_key(key)
                out[name] = min(out.get(name, 0) + value, 10**12)
    return out


def llm_local_section(env: Mapping[str, str], since: dt.date, today: dt.date) -> dict[str, Any]:
    state = (".local", "state", "llm-local")
    src = Source(Path("calls.jsonl"))
    for folder in (state, (".local", "share", "llm-local")):
        src = home_read(env, *folder, "calls.jsonl")  # the first calls log that exists; never both
        if src.found or src.refused:
            break
    tasks, models, reasons = Labels(KNOWN_TASKS), Labels(), Labels()
    by_task: Counter[str] = Counter()
    by_model: Counter[str] = Counter()
    by_day: Counter[str] = Counter()
    by_week: Counter[str] = Counter()
    failed: Counter[str] = Counter()
    busy: Counter[str] = Counter()
    calls = tokens = 0
    known: dict[str, tuple[str, str]] = {}  # call id -> (task, model), from every call row, in or out of the window
    answered: dict[str, str] = {}  # call id -> its latest outcome in the window
    ok_ids: list[str | None] = []
    for row in json_rows(src):
        kind = row.get("kind", "call")
        cid = row.get("id")
        status = row.get("status", "ok")
        stamp = day_of(row)
        # a call id is known only from a row that validates (kind, timestamp, status); the first row of an id wins
        if (
            kind == "call"
            and status in ("ok", "failed", "busy")
            and stamp is not None
            and stamp <= today
            and isinstance(cid, str)
            and len(cid) <= MAX_ID
            and len(known) < MAX_LINES
        ):
            known.setdefault(cid, (tasks(row.get("task")), models(row.get("model"))))
        day = in_window(src, row, since, today)
        if day is None:
            continue
        if kind == "outcome":
            if isinstance(cid, str) and len(cid) <= MAX_ID and row.get("outcome") in OUTCOMES:
                answered[cid] = row["outcome"]  # the file is in time order: the latest outcome of a call wins
            else:
                src.malformed += 1
            continue
        if kind != "call" or status not in ("ok", "failed", "busy"):
            src.malformed += 1  # an unknown kind or status is counted, never guessed at
            continue
        if status != "ok":
            bump(failed if status == "failed" else busy, reasons(row.get("reason")))
            continue
        calls += 1
        ok_ids.append(cid if isinstance(cid, str) else None)
        bump(by_task, tasks(row.get("task")))
        bump(by_model, models(row.get("model")))
        by_day[day.isoformat()] += 1
        by_week[week_of(day)] += 1
        for field in ("prompt_tokens", "eval_tokens"):
            value = row.get(field)
            if type(value) is int and 0 <= value <= 10**9:
                tokens += value
    joined = {cid: what for cid, what in answered.items() if cid in known}
    by_outcome = Counter(joined.values())
    totals: dict[str, Counter[str]] = {"task": Counter(), "model": Counter()}
    accepted: dict[str, Counter[str]] = {"task": Counter(), "model": Counter()}
    for cid, what in joined.items():
        for axis, name in zip(("task", "model"), known[cid], strict=True):
            totals[axis][name] += 1
            accepted[axis][name] += what == "accepted"
    return {
        "found": src.found,
        "refused": src.refused,
        "unknown_labels": {"task": len(tasks.unknown), "model": len(models.unknown), "reason": len(reasons.unknown)},
        "calls": calls,
        "tokens": tokens,
        "malformed": src.malformed,
        "future": src.future,
        "truncated": src.truncated,
        "by_task": dict(sorted(by_task.items())),
        "by_model": dict(sorted(by_model.items())),
        "by_day": dict(sorted(by_day.items())),
        "by_week": dict(sorted(by_week.items())),
        "failed": {"total": sum(failed.values()), "by_reason": dict(sorted(failed.items()))},
        "busy": {"total": sum(busy.values()), "by_reason": dict(sorted(busy.items()))},
        "outcomes": {
            "by_outcome": dict(sorted(by_outcome.items())),
            "joined": len(joined),
            "orphans": len(answered) - len(joined),
            "calls_without_outcome": sum(1 for cid in ok_ids if cid is None or cid not in answered),
            "accept_rate": {
                f"by_{axis}": {
                    name: round(accepted[axis][name] / total, 3) for name, total in sorted(totals[axis].items())
                }
                for axis in ("task", "model")
            },
        },
        "counters": counters_of(env, *state, "state.json"),
    }


def build(env: Mapping[str, str], today: dt.date, days: int) -> dict[str, Any]:
    """`today` is the local date: the logs carry local time without a zone."""
    since = today - dt.timedelta(days=days - 1)
    dispatch = dispatch_section(home_read(env, ".local", "state", "agent-dispatch-guard", "log.jsonl"), since, today)
    return {
        "generated": today.isoformat(),
        "days": days,
        "since": since.isoformat(),
        "dispatch": dispatch,
        "hooks": hooks_section(env, since, today),
        "llm_local": llm_local_section(env, since, today),
        "missing": [{"what": what, "change": change} for what, change in MISSING],
    }


def _flags_line(name: str, c: Mapping[str, int]) -> str:
    return (
        f"  {name}  dispatches {c['dispatches']}  reachable {c['reachable']}  names llm-local {c['local_step']}  "
        f"local-llm line {c['local_line']}  neither {c['neither']}"
    )


def skipped(section: Mapping[str, Any]) -> str:
    future = f" ({section['future']} dated in the future)" if section["future"] else ""
    return f"malformed lines skipped: {section['malformed']}{future}"


def pairs(table: Mapping[str, Any]) -> str:
    return ", ".join(f"{k} {v}" for k, v in table.items())


def llm_extra_lines(ll: Mapping[str, Any]) -> list[str]:
    out = []
    for name in ("failed", "busy"):
        if ll[name]["total"]:
            out.append(f"  {name} {ll[name]['total']}: {pairs(ll[name]['by_reason'])}")
    o = ll["outcomes"]
    if o["by_outcome"] or o["orphans"]:
        out.append(
            f"  outcomes: {pairs(o['by_outcome']) or 'none'}; {o['joined']} joined to a call, "
            f"{o['calls_without_outcome']} calls without an outcome"
        )
        if o["orphans"]:
            plural = "outcome has" if o["orphans"] == 1 else "outcomes have"
            out.append(f"  {o['orphans']} {plural} no call (orphan)")
        for axis in ("task", "model"):
            rates = o["accept_rate"][f"by_{axis}"]
            if rates:
                out.append(
                    f"  accept rate by {axis}: " + ", ".join(f"{k} {round(v * 100):g}%" for k, v in rates.items())
                )
    return out


def text(report: Mapping[str, Any]) -> list[str]:
    d, h, ll = report["dispatch"], report["hooks"], report["llm_local"]
    out = [f"Local-model use, {report['since']} to {report['generated']} ({report['days']} days)", ""]
    out.append("Dispatch guard log (agent-dispatch-guard/log.jsonl)")
    if d["refused"]:
        out.append(f"  not read: {d['refused']}")
    elif not d["found"]:
        out.append("  no dispatch log found")
    else:
        out.append(f"  {d['rows']} dispatches in the window; {skipped(d)}")
        if d["unknown_labels"]["model"]:
            out.append(f"  models classed as other (text never shown): {d['unknown_labels']['model']} distinct")
        if d["truncated"]:
            out.append("  only the newest part of the file was read (size or line cap)")
        out.append(" by day")
        out += [_flags_line(k, v) for k, v in d["by_day"].items()]
        out.append(" by week")
        out += [_flags_line(k, v) for k, v in d["by_week"].items()]
        out.append(" by model")
        out += [_flags_line(k, v) for k, v in d["by_model"].items()]
        nc = d["na_reason_class"]
        if nc["total"]:
            out.append(" n/a reason class (by the guard, from the `local-llm: n/a` line)")
            out += [f"  {k}  " + ", ".join(f"{n} {c}" for n, c in v.items()) for k, v in nc["by_day"].items()]
            out += [f"  {k}  " + ", ".join(f"{n} {c}" for n, c in v.items()) for k, v in nc["by_week"].items()]
    out += ["", "Routing guard (safo hooks status counts)"]
    if h["refused"]:
        out.append(f"  not read: {h['refused']}")
    elif not h["total"]:
        out.append("  no hooks guard rows in the window")
    else:
        out.append(
            f"  {h['total']} dispatches since {h['since']}: " + ", ".join(f"{k} {v}" for k, v in h["decisions"].items())
        )
        out.append(f"  briefs with a local step {h['local_steps']}, marked n/a {h['marked_na']}; {skipped(h)}")
        out.append("  models: " + ", ".join(f"{k} {v}" for k, v in h["models"].items()))
        if h["rules"]:
            out.append("  rules flagged: " + ", ".join(f"{k} {v}" for k, v in h["rules"].items()))
    out += ["", "llm-local"]
    if ll["refused"]:
        out.append(f"  not read: {ll['refused']}")
    elif not ll["found"]:
        out.append("  no llm-local calls log found")
    else:
        out.append(f"  {ll['calls']} calls, {ll['tokens']:,} tokens in the window; {skipped(ll)}")
        if ll["truncated"]:
            out.append("  only the newest part of the file was read (size or line cap)")
        out.append("  by task: " + (", ".join(f"{k} {v}" for k, v in ll["by_task"].items()) or "none"))
        out.append("  by model: " + (", ".join(f"{k} {v}" for k, v in ll["by_model"].items()) or "none"))
        out.append("  by day: " + (", ".join(f"{k} {v}" for k, v in ll["by_day"].items()) or "none"))
        out.append("  by week: " + (", ".join(f"{k} {v}" for k, v in ll["by_week"].items()) or "none"))
        out += llm_extra_lines(ll)
        unknown = {k: v for k, v in ll["unknown_labels"].items() if v}
        if unknown:
            out.append("  classed as other (text never shown), distinct labels: " + pairs(unknown))
    c = ll["counters"]
    out.append("  admission (all time): " + ("  ".join(f"{k} {v}" for k, v in sorted(c.items())) or "no state.json"))
    out += ["", "MISSING DATA (cannot be counted today; the one-line change that would record it)"]
    for item in report["missing"]:
        out.append(f"  - {item['what']}: {item['change']}")
    return out


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    days = DEFAULT_DAYS if args.days is None else args.days
    if not (0 < days <= MAX_DAYS):
        raise ConfigError(f"--days must be above 0 and at most {MAX_DAYS}")
    # the logs carry local time without a zone, so the window ends on the local date of the clock
    report = build(ctx.env, ctx.now.astimezone().date(), days)
    if args.json:
        # one line, ASCII only; `::` is written as a JSON escape so no value can start a workflow command
        ctx.say(json.dumps(report, separators=(",", ":")).replace("::", ":\\u003a"))
    else:
        for line in text(report):
            ctx.say(line)
    return EXIT_OK
