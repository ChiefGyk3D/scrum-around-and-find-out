# SPDX-License-Identifier: Apache-2.0
"""ratebudget: the shared GitHub API budget, from the ledger `ghw` keeps (local, read-only unless --refresh).

Prints one status line (the worst counter per bucket), and with --by-caller the calls and writes each caller made.
--refresh first reads the free `rate_limit` endpoint into the ledger. Exit 0 when every bucket is under the warning
line, 1 when one is at WARN or THROTTLE, so a script can act on it.
"""

from __future__ import annotations

import argparse
import json

from safo import ratebudget
from safo.context import LocalContext
from safo.errors import EXIT_DRIFT, EXIT_OK
from safo.modes import LocalMode, register_local


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    ledger = ratebudget.Budget(ratebudget.state_dir(ctx.env), lambda: ctx.now.timestamp())
    if args.refresh:
        count = ratebudget.refresh(ledger, ctx.env, ctx.run, ctx.which("gh"))
        if not count:
            ctx.say("ratebudget: rate_limit gave no usable counters")
    line = ledger.status_line()
    worst = EXIT_OK
    if "WARN" in line or "THROTTLE" in line:
        worst = EXIT_DRIFT
    if args.json:
        report = ledger.by_caller() if args.by_caller else {}
        ctx.say(json.dumps({"line": line, "by_caller": report}, separators=(",", ":")).replace("::", ":\\u003a"))
        return worst
    ctx.say(line)
    if args.by_caller:
        report = ledger.by_caller()
        if not report:
            ctx.say("  no calls recorded")
        for caller, buckets in sorted(report.items()):
            cells = ", ".join(f"{b} {c['calls']} calls ({c['writes']} writes)" for b, c in sorted(buckets.items()))
            ctx.say(f"  {caller:<24} {cells}")
    return worst


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--by-caller", action="store_true", help="also report calls and writes per caller")
    parser.add_argument(
        "--refresh", action="store_true", help="read the free rate_limit endpoint into the ledger first"
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")


register_local(
    LocalMode("ratebudget", "the shared GitHub API budget and who spent it (ghw ledger)", add_arguments, run)
)
