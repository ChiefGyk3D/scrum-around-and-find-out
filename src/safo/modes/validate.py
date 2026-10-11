# SPDX-License-Identifier: MIT
"""Offline board validation. The command line answers it before any credential is looked for; registering it keeps
it in `--help` and the Action's mode list."""

from __future__ import annotations

import argparse

from safo.context import Context, LocalContext
from safo.evidence import load_verified_agents
from safo.localfiles import add_agents_arguments, agents_path, local_path
from safo.modes import Mode, register

MESSAGE = "configuration valid (offline; live board not audited)"


AGENTS_MESSAGE = "agents file valid (profiles and evidence resolved)"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    add_agents_arguments(parser)


def check_agents(ctx: LocalContext, args: argparse.Namespace) -> str | None:
    """Load an agents file through the verified path when one is named (--agents, $SAFO_AGENTS) or sits in the home
    default; a profile or evidence error is a ConfigError. None when there is no agents file to check."""
    explicit = bool(args.agents or ctx.env.get("SAFO_AGENTS"))
    if not explicit and not ctx.env.get("HOME"):
        return None
    path = agents_path(ctx, args)
    if not explicit and not path.is_file():
        return None
    load_verified_agents(path, local_path(ctx, args)).require_clean()
    return AGENTS_MESSAGE


def run(ctx: Context, args: argparse.Namespace) -> int:
    del args
    ctx.say(MESSAGE)
    return 0


register(Mode("validate", "check the board configuration offline; reads nothing from GitHub", add_arguments, run))
