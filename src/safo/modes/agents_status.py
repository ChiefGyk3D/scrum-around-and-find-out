# SPDX-License-Identifier: MIT
"""agents-status: one read-only view of what Claude, Codex and Copilot are doing for the board."""

from __future__ import annotations

import argparse
import time
from collections import defaultdict
from pathlib import Path

from safo.agents import read_codex, read_copilot
from safo.context import Context
from safo.errors import EXIT_OK, ConfigError, MalformedDataError
from safo.guardlog import guard_lines
from safo.live import load_live
from safo.modes import Mode, register

HOURS_MAX = 24 * 366

Q_AGENT_ITEMS = """query AgentItems(
  $id: ID!, $statusField: String!, $agentField: String!, $endCursor: String
) {
  node(id: $id) { ... on ProjectV2 { items(first: 100, after: $endCursor) {
    pageInfo { hasNextPage endCursor }
    nodes {
      status: fieldValueByName(name: $statusField) { ... on ProjectV2ItemFieldSingleSelectValue { name } }
      agent: fieldValueByName(name: $agentField) { ... on ProjectV2ItemFieldSingleSelectValue { name } }
      content {
        __typename
        ... on Issue { number title state url repository { nameWithOwner } }
        ... on PullRequest { number title state url repository { nameWithOwner } }
      }
    }
  } } }
}"""


def run(ctx: Context, args: argparse.Namespace) -> int:
    board = ctx.board
    if not (0 < args.hours <= HOURS_MAX):
        raise ConfigError(f"--hours must be above 0 and at most {HOURS_MAX:g}")
    live = load_live(ctx.client, board.project)
    variables = {"id": live.id, "statusField": board.rules.status_field, "agentField": board.agents.field}
    waiting: list[str] = []
    working: dict[str, list[str]] = defaultdict(list)
    for node in ctx.client.nodes(Q_AGENT_ITEMS, variables, ("node", "items")):
        content = node.get("content") or {}
        if content.get("__typename") not in ("Issue", "PullRequest") or content.get("state") != "OPEN":
            continue
        status = (node.get("status") or {}).get("name") or ""
        agent = (node.get("agent") or {}).get("name") or "unassigned"
        repo, number = (content.get("repository") or {}).get("nameWithOwner"), content.get("number")
        if not isinstance(repo, str) or not isinstance(number, int) or isinstance(number, bool):
            raise MalformedDataError("agents-status: a card has no repository or number")
        ref = f"{repo}#{number}"
        if status in board.agents.waiting:
            waiting.append(f"  {ref}  {str(content['title'])[:80]}  {content['url']}")
        if status in board.agents.working:
            working[agent].append(f"  {agent:<12} {status:<12} {ref}  {str(content['title'])[:70]}")

    ctx.say(f"Waiting on you (Status = {', '.join(board.agents.waiting)})")
    for line in sorted(waiting) or ["  nothing"]:
        ctx.say(line)
    ctx.say(f"\nBoard: {', '.join(board.agents.working)}, by agent ({board.project.owner}/{board.project.number})")
    for agent in sorted(working):
        for line in sorted(working[agent]):
            ctx.say(line)
    if not working:
        ctx.say("  nothing")

    if not args.no_guard:
        ctx.say()
        for line in guard_lines(ctx.env):
            ctx.say(line)

    if not args.no_codex:
        try:
            root = Path(args.codex_dir).expanduser()
        except RuntimeError:  # no home directory to expand ~ against
            root = Path(args.codex_dir)
        report = read_codex(root, args.hours, time.time())
        ctx.say(f"\nCodex: sessions active in the last {args.hours:g} h, and plan limits")
        if not report.sessions:
            ctx.say("  no Codex sessions in that window")
        for s in report.sessions:
            ctx.say(f"  {time.strftime('%H:%M', time.localtime(s.when))}  {s.state:<10} {s.cwd:<32} {s.last}")
        if report.limits:
            lim = report.limits
            ctx.say(
                f"  plan {lim.plan}: 5-hour window {lim.five_hour_percent}% (resets {lim.five_hour_resets}), "
                f"weekly {lim.weekly_percent}% (resets {lim.weekly_resets})"
            )
    if not args.no_copilot:
        ctx.say("\nCopilot coding agent: recent tasks")
        tasks = read_copilot()
        if tasks is None:
            ctx.say("  (gh agent-task unavailable: needs gh >= 2.80 and a Copilot plan)")
        for line in tasks or []:
            ctx.say(f"  {line}")
    ctx.say("\nClaude")
    ctx.say("  Subagents run inside the Claude Code session and cannot be listed from a shell: watch its panel.")
    ctx.say(f"  Their tasks are the board cards with {board.agents.field} = Claude above.")
    return EXIT_OK


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--hours", type=float, default=12.0, help="Codex sessions active in the last N hours")
    parser.add_argument("--codex-dir", default="~/.codex/sessions", help="where Codex writes its session files")
    parser.add_argument("--no-guard", action="store_true", help="skip the routing-guard counts")
    parser.add_argument("--no-codex", action="store_true", help="skip the Codex section")
    parser.add_argument("--no-copilot", action="store_true", help="skip the Copilot section")


register(Mode("agents-status", "what Claude, Codex and Copilot are doing (read-only)", add_arguments, run))
