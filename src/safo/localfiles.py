# SPDX-License-Identifier: MIT
"""Where the local-only files are: agents.yaml, its git-ignored local override, and the outcomes log.

None of them is ever found in the current directory: a checkout can plant an `agents.yaml` naming endpoints to probe.
The agents file is `--agents`, `$SAFO_AGENTS`, or the user-level `~/.config/safo/agents.yaml`; under GitHub Actions a
path inside `$GITHUB_WORKSPACE`, lexically or after symlinks, is refused, and with no workspace set only the home
defaults are used.
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


def _inside(path: str, root: str) -> bool:
    return os.path.commonpath([path, root]) == root


def refuse_workspace(path: Path, env: Mapping[str, str], what: str, *, explicit: bool = True) -> Path:
    """Under GitHub Actions a file inside the checked-out workspace is attacker-controllable: refuse it.

    Both forms of the path are compared with both forms of the workspace: the lexical one (made absolute and
    normalised, no symlink followed) catches a workspace symlink that points out, and the resolved one catches a
    path outside that points in. With no `GITHUB_WORKSPACE` under Actions the boundary cannot be drawn, so it fails
    closed: an explicit path (flag or environment) is refused and only the home defaults remain.

    Accepted residual: outside Actions, an explicit `--agents`, `--log` or `$SAFO_AGENTS` naming a file in the
    current directory is the user's own deliberate choice and is allowed; the current directory is never searched.
    """
    if env.get("GITHUB_ACTIONS") != "true":
        return path
    workspace = env.get("GITHUB_WORKSPACE", "")
    if not workspace:
        if explicit:
            raise ConfigError(
                f"{what} was given, but GITHUB_WORKSPACE is not set under Actions, so the checkout cannot be "
                "told apart; use the default location in the home directory"
            )
        return path
    roots = {os.path.normpath(os.path.abspath(workspace)), os.path.realpath(workspace)}
    forms = {os.path.normpath(os.path.abspath(path)), os.path.realpath(path)}
    if any(_inside(form, root) for form in forms for root in roots):
        raise ConfigError(
            f"{what} is inside GITHUB_WORKSPACE (by its path or where its links lead); "
            "under Actions it must come from outside the checkout"
        )
    return path


def agents_path(ctx: LocalContext, args: argparse.Namespace) -> Path:
    given = args.agents or ctx.env.get("SAFO_AGENTS", "")
    path = Path(given) if given else ctx.home / ".config" / "safo" / "agents.yaml"
    return refuse_workspace(path, ctx.env, "the agents file", explicit=bool(given))


def local_path(ctx: LocalContext, args: argparse.Namespace) -> Path:
    given = args.agents_local or ctx.env.get("SAFO_AGENTS_LOCAL", "")
    path = Path(given) if given else ctx.home / ".config" / "safo" / "agents.local.yaml"
    return refuse_workspace(path, ctx.env, "the local agents file", explicit=bool(given))


def load_agents_for(ctx: LocalContext, args: argparse.Namespace) -> AgentsFile:
    return load_agents_merged(agents_path(ctx, args), local_path(ctx, args))


def outcomes_path(ctx: LocalContext, args: argparse.Namespace) -> Path:
    given = args.log or ctx.env.get("SAFO_OUTCOMES", "")
    path = Path(given) if given else ctx.home / ".local" / "state" / "safo" / "outcomes.jsonl"
    return refuse_workspace(path, ctx.env, "the outcomes log", explicit=bool(given))


def outcomes_is_default(ctx: LocalContext, args: argparse.Namespace) -> bool:
    """True when the outcomes log is SAFO's own default path: its directory is trust-checked. A path the user supplied
    (--log or $SAFO_OUTCOMES) is their choice and is not."""
    return not (args.log or ctx.env.get("SAFO_OUTCOMES", ""))
