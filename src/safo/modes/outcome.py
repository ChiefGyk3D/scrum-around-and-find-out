# SPDX-License-Identifier: MIT
"""outcome add: append one finished task to the outcomes log."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from safo import outcomes
from safo.context import LocalContext
from safo.errors import EXIT_OK, ConfigError
from safo.localfiles import add_agents_arguments, agents_path, load_agents_for, outcomes_path
from safo.modes import LocalMode, register_local


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    if args.action != "add":
        raise ConfigError("the only outcome action is `add`")
    if agents_path(ctx, args).is_file():
        doc = load_agents_for(ctx, args)  # an agent or shape agents.yaml does not know is a typo
        doc.agent(args.agent)
        doc.shape(args.shape)
    record = outcomes.Outcome(
        args.date or ctx.now.date().isoformat(),
        args.card or None,
        args.agent,
        args.shape,
        args.review_rounds,
        outcomes.parse_findings(args.findings),
        args.tokens,
        args.requests,
        args.note,
    )
    outcomes.validate(json.loads(record.to_json()), "outcome")
    path: Path = outcomes_path(ctx, args)
    if ctx.dry_run:
        ctx.say("dry run: would append outcome; nothing written")
        return EXIT_OK
    outcomes.append(path, record)
    ctx.say(f"recorded {record.agent} / {record.shape} in {path}")
    return EXIT_OK


def add_arguments(parser: argparse.ArgumentParser) -> None:
    add_agents_arguments(parser)
    parser.add_argument("action", choices=["add"])
    parser.add_argument("--agent", required=True, help="an agent id from agents.yaml")
    parser.add_argument("--shape", required=True, help="a task shape from agents.yaml")
    parser.add_argument("--card", default="", help="the issue or pull request URL")
    parser.add_argument("--date", default="", help="YYYY-MM-DD (default: today)")
    parser.add_argument("--review-rounds", type=int, default=1, help="review passes, the passing one included")
    parser.add_argument("--findings", default="", help="critical=0,important=1,minor=2,unrated=0")
    parser.add_argument("--tokens", type=int, default=None)
    parser.add_argument("--requests", type=int, default=None)
    parser.add_argument("--note", default="")
    parser.add_argument(
        "--log", default="", help="the outcomes log (default: $SAFO_OUTCOMES, else ~/.local/state/safo/outcomes.jsonl)"
    )


register_local(LocalMode("outcome", "append a finished task to the outcomes log", add_arguments, run))
