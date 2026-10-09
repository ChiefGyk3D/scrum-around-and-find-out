# SPDX-License-Identifier: MIT
"""Synthetic session files for the meter tests. Nothing here is read from, or shaped by, a real home directory."""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

NOW = dt.datetime(2026, 10, 7, 12, 0, tzinfo=dt.UTC)


def touch(path: Path, age_hours: float) -> None:
    stamp = (NOW - dt.timedelta(hours=age_hours)).timestamp()
    os.utime(path, (stamp, stamp))


def codex_session(
    home: Path, name: str, rows: list[dict[str, Any]], *, age_hours: float = 1, raw_tail: str = ""
) -> Path:
    day = home / ".codex" / "sessions" / "2026" / "10" / "07"
    day.mkdir(parents=True, exist_ok=True)
    path = day / f"{name}.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n" + raw_tail)
    touch(path, age_hours)
    return path


def token_count(five: float, week: float, *, tokens: int = 1000, resets_in_hours: float = 3) -> dict[str, Any]:
    reset = int((NOW + dt.timedelta(hours=resets_in_hours)).timestamp())
    return {
        "type": "event_msg",
        "payload": {
            "type": "token_count",
            "info": {
                "total_token_usage": {
                    "input_tokens": tokens,
                    "cached_input_tokens": tokens // 2,
                    "output_tokens": tokens // 10,
                    "total_tokens": tokens + tokens // 10,
                }
            },
            "rate_limits": {
                "plan_type": "plus",
                "primary": {"used_percent": five, "resets_at": reset},
                "secondary": {"used_percent": week, "resets_at": reset + 86400},
            },
        },
    }


def claude_transcript(home: Path, rel: str, messages: list[dict[str, Any]], *, age_hours: float = 1) -> Path:
    path = home / ".claude" / "projects" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(m) for m in messages) + "\n")
    touch(path, age_hours)
    return path


def assistant(
    msg_id: str, model: str, out: int, *, inp: int = 10, when_hours_ago: float = 1, cache_read: int = 0
) -> dict[str, Any]:
    stamp = (NOW - dt.timedelta(hours=when_hours_ago)).isoformat().replace("+00:00", "Z")
    return {
        "type": "assistant",
        "timestamp": stamp,
        "message": {
            "id": msg_id,
            "model": model,
            "usage": {
                "input_tokens": inp,
                "output_tokens": out,
                "cache_read_input_tokens": cache_read,
                "cache_creation_input_tokens": 0,
            },
        },
    }
