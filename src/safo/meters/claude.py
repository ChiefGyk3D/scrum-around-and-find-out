# SPDX-License-Identifier: MIT
"""Claude Code: token use per model family from ~/.claude/projects/**/*.jsonl, subagent transcripts included.

An assistant message is written to the transcript once per content block, each row repeating the message id and
its usage, so rows are de-duplicated by message id (the largest output count wins) or every reply would be
counted several times.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from safo.bounded import count, json_lines

FAMILIES = ("opus", "sonnet", "haiku")


@dataclass(frozen=True)
class ModelUsage:
    family: str
    messages: int
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_creation_tokens: int


@dataclass(frozen=True)
class ClaudeUsage:
    found: bool
    files: int
    by_family: dict[str, ModelUsage]


def family_of(model: str) -> str:
    lowered = model.lower()
    return next((f for f in FAMILIES if f in lowered), "other")


def _when(row: dict[str, Any], fallback: float) -> float:
    raw = row.get("timestamp")
    if isinstance(raw, str):
        try:
            return dt.datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return fallback


def read_claude_usage(home: Path, since: dt.datetime) -> ClaudeUsage:
    root = home / ".claude" / "projects"
    if not root.is_dir():
        return ClaudeUsage(False, 0, {})
    cutoff = since.timestamp()
    best: dict[str, tuple[str, dict[str, Any]]] = {}
    files = 0
    for path in sorted(root.rglob("*.jsonl")):
        mtime = path.stat().st_mtime
        if mtime < cutoff:
            continue
        files += 1
        try:
            lines = json_lines(path)
        except (OSError, ValueError):
            continue
        for number, row in lines:
            if row is None:
                continue
            message = row.get("message") if isinstance(row, dict) else None
            if not isinstance(message, dict) or not isinstance(message.get("usage"), dict):
                continue
            model = str(message.get("model", ""))
            if not model or model.startswith("<"):
                continue  # a synthetic message carries no real use
            if _when(row, mtime) < cutoff:
                continue
            key = str(message.get("id") or f"{path}:{number}")
            try:
                usage = {k: count(v) for k, v in message["usage"].items()}
            except ValueError:
                continue
            previous = best.get(key)
            if previous is None or int(usage.get("output_tokens", 0) or 0) >= int(
                previous[1].get("output_tokens", 0) or 0
            ):
                best[key] = (model, usage)
    totals: dict[str, list[int]] = {}
    for model, usage in best.values():
        row = totals.setdefault(family_of(model), [0, 0, 0, 0, 0])
        row[0] += 1
        row[1] += int(usage.get("input_tokens", 0) or 0)
        row[2] += int(usage.get("output_tokens", 0) or 0)
        row[3] += int(usage.get("cache_read_input_tokens", 0) or 0)
        row[4] += int(usage.get("cache_creation_input_tokens", 0) or 0)
    return ClaudeUsage(True, files, {f: ModelUsage(f, *v) for f, v in sorted(totals.items())})
