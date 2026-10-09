# SPDX-License-Identifier: MIT
"""Where the local-only files are: agents.yaml, its git-ignored local override, and the outcomes log."""

from __future__ import annotations

import argparse
from pathlib import Path

from safo.agentsfile import AgentsFile, load_agents_merged
from safo.context import LocalContext


def add_agents_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agents", default="", help="agents.yaml (default: $SAFO_AGENTS, else ./agents.yaml)")
    parser.add_argument(
        "--agents-local",
        default="",
        help="a local file merged over agents.yaml, where real endpoints live "
        "(default: $SAFO_AGENTS_LOCAL, else ~/.config/safo/agents.local.yaml)",
    )


def agents_path(ctx: LocalContext, args: argparse.Namespace) -> Path:
    return Path(args.agents or ctx.env.get("SAFO_AGENTS", "") or "agents.yaml")


def local_path(ctx: LocalContext, args: argparse.Namespace) -> Path:
    given = args.agents_local or ctx.env.get("SAFO_AGENTS_LOCAL", "")
    return Path(given) if given else ctx.home / ".config" / "safo" / "agents.local.yaml"


def load_agents_for(ctx: LocalContext, args: argparse.Namespace) -> AgentsFile:
    return load_agents_merged(agents_path(ctx, args), local_path(ctx, args))


def outcomes_path(ctx: LocalContext, args: argparse.Namespace) -> Path:
    return Path(args.log or ctx.env.get("SAFO_OUTCOMES", "") or "outcomes.jsonl")
