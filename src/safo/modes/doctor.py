# SPDX-License-Identifier: Apache-2.0
"""doctor: is each prerequisite present, missing or too old? Read-only; see docs/prerequisites.md.

Exit 0 when every REQUIRED prerequisite is present (python, git, gh at their minimums); 1 otherwise. Optional tools,
plugins and skill packs are reported and never change the code. The only thing run is `<tool> --version`; no value of
the environment is printed or passed on.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from safo import prereqs
from safo.context import LocalContext
from safo.errors import EXIT_DRIFT, EXIT_OK
from safo.modes import LocalMode, register_local
from safo.prereqs import Result


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.description = __doc__


def describe(r: Result) -> str:
    level = "required" if r.required else "optional"
    have = prereqs.dotted(r.version)
    need = f">= {prereqs.dotted(r.minimum)}" if r.minimum else ""
    detail = " ".join(x for x in (have, need, level, r.note) if x)
    return f"{r.status:<10} {r.name:<28} {detail}"


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    home_value = ctx.env.get("HOME", "")
    home = Path(home_value) if home_value else None
    results = [prereqs.check_python()]
    results += [prereqs.check_tool(t, ctx.env, ctx.run) for t in prereqs.TOOLS]
    results += prereqs.check_extras(home)
    for r in results:
        ctx.say(describe(r))
    failing = [r.name for r in results if r.failing]
    if failing:
        ctx.say(f"FAIL: required and not satisfied: {', '.join(failing)}. See docs/prerequisites.md")
        return EXIT_DRIFT
    ctx.say("OK: every required prerequisite is present")
    return EXIT_OK


register_local(
    LocalMode("doctor", "Check that each prerequisite is present and new enough (read-only)", add_arguments, run)
)
