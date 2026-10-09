# SPDX-License-Identifier: MIT
"""usage: what each agent has used and has left, from local meters only. Read-only; nothing leaves the machine."""

from __future__ import annotations

import argparse
import datetime as dt
import json

from safo.agentsfile import Endpoint
from safo.bounded import month as valid_month
from safo.context import LocalContext
from safo.errors import EXIT_OK, ConfigError
from safo.localfiles import add_agents_arguments, agents_path, load_agents_for
from safo.meters import Meters, as_json, collect
from safo.meters.codex import CodexUsage
from safo.modes import LocalMode, register_local


def _reset(epoch: int | None) -> str:
    return dt.datetime.fromtimestamp(epoch, dt.UTC).strftime("%a %H:%M UTC") if epoch else "?"


def _pct(value: float | None) -> str:
    return f"{value:g}%" if value is not None else "unknown"


def codex_lines(c: CodexUsage) -> list[str]:
    if not c.found:
        return ["Codex: no session files found"]
    lines = [
        f"Codex ({c.plan or '?'} plan): "
        f"5-hour window {_pct(c.five_hour_percent)} (resets {_reset(c.five_hour_resets_at)}), "
        f"weekly {_pct(c.weekly_percent)} (resets {_reset(c.weekly_resets_at)})",
        f"  {len(c.sessions)} sessions in the window, {c.input_tokens:,} input tokens",
    ]
    lines += [f"  {s.name[:24]:<24} {s.cwd:<24} in {s.input_tokens:,} out {s.output_tokens:,}" for s in c.sessions]
    return lines


def text(m: Meters, days: float, month: str) -> list[str]:
    lines = codex_lines(m.codex)
    if not m.claude.found:
        lines.append("Claude Code: no transcripts found")
    else:
        lines.append(f"Claude Code, last {days:g} days ({m.claude.files} transcripts, subagents included):")
        for u in m.claude.by_family.values():
            lines.append(
                f"  {u.family:<7} {u.messages:>5} messages  in {u.input_tokens:,}  out {u.output_tokens:,}  "
                f"cache read {u.cache_read_tokens:,}  cache write {u.cache_creation_tokens:,}"
            )
    c = m.copilot
    if not c.available:
        lines.append("Copilot: gh is not available")
    else:
        sessions = "unknown" if c.sessions is None else str(c.sessions)
        scope = month if c.sessions_exact else "all listed (the listing carries no dates)"
        used = (
            "unknown (pass --billing if your token may read it)"
            if c.premium_requests is None
            else f"{c.premium_requests:g}"
        )
        lines.append(
            f"Copilot: {sessions} sessions in {scope}; premium requests {used}; month {_pct(c.monthly_percent)}"
        )
    for p in m.ollama:
        state = "unreachable" if not p.reachable else f"reachable, loaded: {', '.join(p.loaded) or 'nothing'}"
        lines.append(f"Local LLM {p.endpoint_id}: {state}")
    return lines


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    month = args.month or ctx.now.strftime("%Y-%m")
    try:
        valid_month(month)
    except ValueError:
        raise ConfigError("month: expected YYYY-MM") from None
    allowance = None
    endpoints: tuple[Endpoint, ...] = ()
    if agents_path(ctx, args).is_file():
        doc = load_agents_for(ctx, args)
        allowance = doc.monthly_allowance()
        endpoints = () if args.no_local else tuple(e for a in doc.agents for e in a.endpoints)
    meters = collect(ctx, days=args.days, billing=args.billing, allowance=allowance, month=month, endpoints=endpoints)
    if args.json:
        document = {"generated": ctx.now.isoformat(), "days": args.days, "month": month, **as_json(meters)}
        # one line, ASCII only; `::` is written as a JSON escape so no value can start a workflow command
        ctx.say(json.dumps(document, separators=(",", ":")).replace("::", ":\\u003a"))
    else:
        for line in text(meters, args.days, month):
            ctx.say(line)
    return EXIT_OK


def add_arguments(parser: argparse.ArgumentParser) -> None:
    add_agents_arguments(parser)
    parser.add_argument("--days", type=float, default=7.0, help="the window for Codex sessions and Claude transcripts")
    parser.add_argument("--month", default="", help="YYYY-MM for Copilot and --report (default: this month)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--billing", action="store_true", help="also try the billing read for exact Copilot premium requests"
    )
    parser.add_argument("--no-local", action="store_true", help="do not probe the local LLM endpoints")


register_local(LocalMode("usage", "what each agent has used and has left (local, read-only)", add_arguments, run))
