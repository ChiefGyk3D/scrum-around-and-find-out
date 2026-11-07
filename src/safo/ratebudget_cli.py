# SPDX-License-Identifier: Apache-2.0
"""safo-ratebudget: the shared GitHub API budget, from the ledger `ghw` keeps (local, read-only unless --refresh).

Prints one status line (the worst counter per bucket), and with --by-caller the calls and writes each caller made.
--refresh first reads the free `rate_limit` endpoint into the ledger. Exit 0 when every bucket is under the warning
line, 1 when one is at WARN or THROTTLE, so a script can act on it.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from collections.abc import Mapping, Sequence
from typing import TextIO

from safo import ratebudget
from safo.context import LocalContext
from safo.errors import EXIT_DRIFT, EXIT_OK, SafoError
from safo.modes.reconcile import safe


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    directory = ratebudget.state_dir(ctx.env)
    scope = ratebudget.scope_for(ctx.env, [], ctx.run, ctx.which("gh"), directory, lambda: ctx.now.timestamp())
    ledger = ratebudget.Budget(
        directory,
        lambda: ctx.now.timestamp(),
        scope.name,
        unknown=scope.unknown,
    )
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
        ctx.say(
            json.dumps({"line": line, "by_caller": report, "note": scope.note}, separators=(",", ":")).replace(
                "::", ":\\u003a"
            )
        )
        return worst
    ctx.say(line)
    if scope.note:
        ctx.say(scope.note)
    if args.by_caller:
        report = ledger.by_caller()
        if not report:
            ctx.say("  no calls recorded")
        for caller, buckets in sorted(report.items()):
            cells = ", ".join(f"{b} {c['calls']} calls ({c['writes']} writes)" for b, c in sorted(buckets.items()))
            ctx.say(f"  {caller:<24} {cells}")
    return worst


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="safo-ratebudget", description="the shared GitHub API budget and who spent it")
    p.add_argument("--by-caller", action="store_true", help="also report calls and writes per caller")
    p.add_argument("--refresh", action="store_true", help="read the free rate_limit endpoint into the ledger first")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    return p


def main(
    argv: Sequence[str], *, env: Mapping[str, str], out: TextIO, err: TextIO, now: dt.datetime | None = None
) -> int:
    args = parser().parse_args(argv)
    ctx = LocalContext(out, env, now or dt.datetime.now(dt.UTC))
    try:
        return run(ctx, args)
    except SafoError as problem:
        err.write(f"safo-ratebudget: {safe(str(problem))}\n")
        return problem.exit_code


def entry() -> None:
    raise SystemExit(main(sys.argv[1:], env=os.environ, out=sys.stdout, err=sys.stderr))
