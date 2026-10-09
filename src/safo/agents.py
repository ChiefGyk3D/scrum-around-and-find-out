# SPDX-License-Identifier: MIT
"""What the agent team is doing, read-only: Codex sessions and plan limits, Copilot agent tasks.

Ported from the maintainer's `agents-status` shell script. Claude subagents live inside a Claude Code
session and cannot be listed from a shell; the report says so. Nothing here starts, stops or edits anything.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from safo.bounded import MAX_FILE_BYTES, loads, number, read_bounded
from safo.credentials import find_gh

STALLED_AFTER_SECONDS = 900  # a session that says "running" but has written nothing for 15 minutes
MAX_SESSIONS = 100  # the newest this many session files inside the window are read
MAX_NAME = 32
MAX_TASKS = 10
MAX_TASK_CHARS = 200
_PLAN = re.compile(r"[A-Za-z0-9_-]{1,20}")


@dataclass(frozen=True)
class CodexSession:
    when: float  # the file's mtime
    cwd: str
    state: str  # running | done | stalled? (...)
    last: str


@dataclass(frozen=True)
class CodexLimits:
    plan: str
    five_hour_percent: str
    five_hour_resets: str
    weekly_percent: str
    weekly_resets: str


@dataclass(frozen=True)
class CodexReport:
    sessions: tuple[CodexSession, ...]
    limits: CodexLimits | None


def _session_files(root: Path, cutoff: float) -> list[tuple[Path, float]]:
    """Regular session files (never a symlink, FIFO or directory) touched since `cutoff`, oldest first."""
    found: list[tuple[Path, float]] = []
    # Codex writes ~/.codex/sessions/YYYY/MM/DD/<session>.jsonl
    for path in root.glob("*/*/*/*.jsonl"):
        try:
            info = path.lstat()
        except OSError:
            continue  # gone between the listing and now
        if stat.S_ISREG(info.st_mode) and info.st_mtime >= cutoff:
            found.append((path, info.st_mtime))
    found.sort(key=lambda entry: entry[1])
    return found[-MAX_SESSIONS:]


def _rows(path: Path) -> Iterator[Any]:
    """The JSON objects of one session file; a line that does not parse is skipped. OSError/ValueError: unreadable."""
    raw = read_bounded(path, MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("session file exceeds size limit")
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            yield loads(line)
        except (ValueError, UnicodeError):
            continue


def _percent(value: Any) -> str:
    result = number(value)
    return "?" if result is None or result > 100_000 else f"{result:g}"


def _name(text: str) -> str:
    """A working-directory name that is safe to show: printable, one line, short."""
    cleaned = "".join(ch if ch.isprintable() else "?" for ch in text)
    return cleaned[:MAX_NAME] or "?"


def _reset(window: Mapping[str, Any]) -> str:
    at = number(window.get("resets_at")) if isinstance(window, Mapping) else None
    if at is not None and at > 253402300799:
        at = None
    if not at:
        return "?"
    try:
        return time.strftime("%a %H:%M", time.localtime(float(at)))
    except (OverflowError, OSError, ValueError):
        return "?"


def read_codex(root: Path, hours: float, now: float) -> CodexReport:
    """Sessions touched in the last `hours`, and the newest plan limits any of them reported."""
    sessions: list[CodexSession] = []
    limits: CodexLimits | None = None
    if not root.is_dir():
        return CodexReport((), None)
    for path, mtime in _session_files(root, now - hours * 3600):
        cwd, state, last = "?", "running", ""
        try:
            rows = list(_rows(path))
        except (OSError, ValueError):
            continue
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("payload"), dict):
                continue
            payload = row["payload"]
            if row.get("type") == "session_meta":
                cwd = str(payload.get("cwd", "?"))
            kind = payload.get("type")
            if kind == "task_started":
                state = "running"
            elif kind == "task_complete":
                state = "done"
                last = ""  # Completion text may contain credentials; never print it.
            elif kind == "token_count" and payload.get("rate_limits"):  # the newest report wins
                raw = payload["rate_limits"]
                if not isinstance(raw, dict):
                    continue
                primary, secondary = raw.get("primary") or {}, raw.get("secondary") or {}
                if not isinstance(primary, dict) or not isinstance(secondary, dict):
                    continue
                plan = raw.get("plan_type")
                limits = CodexLimits(
                    plan if isinstance(plan, str) and _PLAN.fullmatch(plan) else "?",
                    _percent(primary.get("used_percent")),
                    _reset(primary),
                    _percent(secondary.get("used_percent")),
                    _reset(secondary),
                )
        idle = now - mtime
        if state == "running" and idle > STALLED_AFTER_SECONDS:
            state = f"stalled? (no output for {int(idle // 60)} min)"
        sessions.append(CodexSession(mtime, _name(Path(cwd).name or cwd), state, last))
    return CodexReport(tuple(sessions), limits)


def _gh_on_path(name: str) -> str | None:
    return find_gh(os.environ) if name == "gh" else None


def read_copilot(
    run: Callable[..., Any] = subprocess.run, which: Callable[[str], str | None] = _gh_on_path
) -> list[str] | None:
    """`gh agent-task list`, or None when gh is absent, too old or the account has no Copilot plan."""
    gh = which("gh")
    if gh is None:
        return None
    try:
        done = run(
            [gh, "agent-task", "list", "-L", str(MAX_TASKS)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError):
        return None
    if done.returncode != 0 or not isinstance(done.stdout, str):
        return None
    lines = [line.strip()[:MAX_TASK_CHARS] for line in done.stdout.splitlines() if line.strip()]
    return lines[:MAX_TASKS]
