# SPDX-License-Identifier: MIT
"""Local meters: what each agent has used, read from files and commands on this machine.

Read-only, and nothing leaves the machine: no network call is made here (the one optional Copilot billing read
goes through `gh`, and only when asked for). Every reader takes the home directory it is given and never looks
up the real one.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from safo.agentsfile import Endpoint
from safo.context import LocalContext
from safo.meters.claude import ClaudeUsage, read_claude_usage
from safo.meters.codex import CodexUsage, read_codex_usage
from safo.meters.copilot import CopilotUsage, read_copilot_usage
from safo.ollama import Probe, probe


@dataclass(frozen=True)
class Meters:
    codex: CodexUsage
    claude: ClaudeUsage
    copilot: CopilotUsage
    ollama: tuple[Probe, ...] = ()

    def headroom(self) -> dict[str, float | None]:
        """Percent used per meter name, None where it is unknown. These are the names thresholds use."""
        return {
            "five_hour": self.codex.five_hour_percent,
            "weekly": self.codex.weekly_percent,
            "monthly_percent": self.copilot.monthly_percent,
        }


def collect(
    ctx: LocalContext,
    *,
    days: float = 7.0,
    billing: bool = False,
    allowance: int | None = None,
    month: str = "",
    endpoints: Sequence[Endpoint] = (),
) -> Meters:
    since = ctx.now - dt.timedelta(days=days)
    return Meters(
        read_codex_usage(ctx.home, since, ctx.now),
        read_claude_usage(ctx.home, since),
        read_copilot_usage(
            ctx.run, ctx.which, month or ctx.now.strftime("%Y-%m"), billing=billing, allowance=allowance
        ),
        tuple(probe(e) for e in endpoints),
    )


def as_json(value: Any) -> Any:
    """Plain data for --json."""
    if hasattr(value, "__dataclass_fields__"):
        return {k: ("[redacted]" if k == "url" else as_json(getattr(value, k))) for k in value.__dataclass_fields__}
    if isinstance(value, dict):
        return {str(k): as_json(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [as_json(v) for v in value]
    return value
