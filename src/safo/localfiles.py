# SPDX-License-Identifier: MIT
"""Where the local-only files are: agents.yaml, its git-ignored local override, and the outcomes log.

None of them is ever found in the current directory: a checkout can plant an `agents.yaml` naming endpoints to probe.
The agents file is `--agents`, `$SAFO_AGENTS`, or the user-level `~/.config/safo/agents.yaml`; under GitHub Actions a
path that resolves (symlinks followed) inside `$GITHUB_WORKSPACE` is refused.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Mapping
from pathlib import Path

from safo.agentsfile import AgentsFile, load_agents_merged
from safo.context import LocalContext
from safo.errors import ConfigError


def add_agents_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--agents",
        default="",
        help="agents.yaml (default: $SAFO_AGENTS, else ~/.config/safo/agents.yaml; never the current directory)",
    )
    parser.add_argument(
        "--agents-local",
        default="",
        help="a local file merged over agents.yaml, where real endpoints live "
        "(default: $SAFO_AGENTS_LOCAL, else ~/.config/safo/agents.local.yaml)",
    )


def refuse_workspace(path: Path, env: Mapping[str, str], what: str) -> Path:
    """Under GitHub Actions a file inside the checked-out workspace is attacker-controllable: refuse it."""
    workspace = env.get("GITHUB_WORKSPACE", "")
    if env.get("GITHUB_ACTIONS") == "true" and workspace:
        root = os.path.realpath(workspace)
        real = os.path.realpath(path)
        if os.path.commonpath([real, root]) == root:
            raise ConfigError(
                f"{what} resolves inside GITHUB_WORKSPACE; under Actions it must come from outside the checkout"
            )
    return path


def agents_path(ctx: LocalContext, args: argparse.Namespace) -> Path:
    given = args.agents or ctx.env.get("SAFO_AGENTS", "")
    path = Path(given) if given else ctx.home / ".config" / "safo" / "agents.yaml"
    return refuse_workspace(path, ctx.env, "the agents file")


def local_path(ctx: LocalContext, args: argparse.Namespace) -> Path:
    given = args.agents_local or ctx.env.get("SAFO_AGENTS_LOCAL", "")
    path = Path(given) if given else ctx.home / ".config" / "safo" / "agents.local.yaml"
    return refuse_workspace(path, ctx.env, "the local agents file")


def load_agents_for(ctx: LocalContext, args: argparse.Namespace) -> AgentsFile:
    return load_agents_merged(agents_path(ctx, args), local_path(ctx, args))


def outcomes_path(ctx: LocalContext, args: argparse.Namespace) -> Path:
    given = args.log or ctx.env.get("SAFO_OUTCOMES", "")
    path = Path(given) if given else ctx.home / ".local" / "state" / "safo" / "outcomes.jsonl"
    return refuse_workspace(path, ctx.env, "the outcomes log")
