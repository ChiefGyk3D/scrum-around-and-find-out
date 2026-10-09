# SPDX-License-Identifier: MIT
"""Offline board validation. The command line answers it before any credential is looked for; registering it keeps
it in `--help` and the Action's mode list."""

from __future__ import annotations

import argparse

from safo.context import Context
from safo.modes import Mode, register

MESSAGE = "configuration valid (offline; live board not audited)"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    del parser


def run(ctx: Context, args: argparse.Namespace) -> int:
    del args
    ctx.say(MESSAGE)
    return 0


register(Mode("validate", "check the board configuration offline; reads nothing from GitHub", add_arguments, run))
