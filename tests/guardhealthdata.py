# SPDX-License-Identifier: Apache-2.0
"""Support for the guard-health tests (#615): a Bash event, a guard run, and a valid log row."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hooksdata import hooks


def event(command: str) -> str:
    return json.dumps(
        {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": command}}
    )


def guard(agents: Path, home: Path, payload: str) -> str:
    return hooks("guard", "--agents", str(agents), home=home, stdin=payload)[1]


def row(diagnostic: str, **extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "ts": "2026-11-07T09:00:00",
        "decision": "error",
        "mode": "warn",
        "model": None,
        "local_reachable": False,
        "local_step": False,
        "na": False,
        "rules": [],
        "health": "degraded",
        "diagnostic": diagnostic,
    }
    return {**base, **extra}
