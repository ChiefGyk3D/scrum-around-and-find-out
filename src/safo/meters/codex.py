# SPDX-License-Identifier: MIT
"""Codex: plan windows and token totals from ~/.codex/sessions/**/*.jsonl.

A `token_count` row carries `rate_limits` (`plan_type`, `primary` the 5-hour window, `secondary` the weekly one,
each with `used_percent` and `resets_at`) and `info.total_token_usage`, the running total for the session.
Sessions are written while we read them, so a half-written last line is skipped, never an error.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from safo.bounded import count, json_lines, number


@dataclass(frozen=True)
class CodexSessionUsage:
    name: str
    cwd: str
    last_seen: float
    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    total_tokens: int


@dataclass(frozen=True)
class CodexUsage:
    found: bool
    plan: str | None
    five_hour_percent: float | None
    five_hour_resets_at: int | None
    weekly_percent: float | None
    weekly_resets_at: int | None
    sessions: tuple[CodexSessionUsage, ...]
    unreadable_files: int = 0

    @property
    def input_tokens(self) -> int:
        return sum(s.input_tokens for s in self.sessions)


def _number(value: Any) -> float | None:
    return number(value)


def _window(raw: Any, now: float) -> tuple[float | None, int | None]:
    """(percent used, reset time). A reading whose window has already reset says nothing about the new one."""
    if not isinstance(raw, dict):
        return None, None
    percent, resets = _number(raw.get("used_percent")), _number(raw.get("resets_at"))
    if percent is not None and percent > 100:
        percent = None
    if resets is not None and resets > 253402300799:
        resets = None
    if resets is not None and resets <= now:
        return None, int(resets)
    return percent, int(resets) if resets is not None else None


def read_codex_usage(home: Path, since: dt.datetime, now: dt.datetime) -> CodexUsage:
    """Sessions touched since `since` and the newest plan windows any session reported."""
    root = home / ".codex" / "sessions"
    if not root.is_dir():
        return CodexUsage(False, None, None, None, None, None, ())
    cutoff, clock = since.timestamp(), now.timestamp()
    sessions: list[CodexSessionUsage] = []
    plan: str | None = None
    primary: Any = None
    secondary: Any = None
    unreadable = 0
    for path in sorted(root.glob("*/*/*/*.jsonl"), key=lambda p: p.stat().st_mtime):
        mtime = path.stat().st_mtime
        if mtime < cutoff:
            continue
        try:
            rows = json_lines(path)
        except (OSError, ValueError):
            unreadable += 1
            continue
        cwd, totals = "?", {}
        for _, row in rows:
            if row is None:
                continue
            payload = row.get("payload") if isinstance(row, dict) else None
            if not isinstance(payload, dict):
                continue
            if row.get("type") == "session_meta":
                cwd = str(payload.get("cwd", "?"))
            if payload.get("type") == "token_count":
                limits = payload.get("rate_limits")
                if isinstance(limits, dict):
                    plan = str(limits.get("plan_type", plan or "?"))
                    primary, secondary = limits.get("primary"), limits.get("secondary")
                info = payload.get("info")
                if isinstance(info, dict) and isinstance(info.get("total_token_usage"), dict):
                    totals = info["total_token_usage"]
        try:
            totals = {k: count(v) for k, v in totals.items()}
        except ValueError:
            unreadable += 1
            continue
        sessions.append(
            CodexSessionUsage(
                path.stem,
                Path(cwd).name or cwd,
                mtime,
                int(totals.get("input_tokens", 0) or 0),
                int(totals.get("cached_input_tokens", 0) or 0),
                int(totals.get("output_tokens", 0) or 0),
                int(totals.get("total_tokens", 0) or 0),
            )
        )
    five, five_reset = _window(primary, clock)
    week, week_reset = _window(secondary, clock)
    return CodexUsage(True, plan, five, five_reset, week, week_reset, tuple(sessions), unreadable)
