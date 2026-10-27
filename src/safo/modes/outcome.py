# SPDX-License-Identifier: Apache-2.0
"""outcome add: append one finished task to the outcomes log."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from safo import outcomes
from safo.context import LocalContext
from safo.errors import EXIT_OK, ConfigError
from safo.localfiles import add_agents_arguments, agents_path, load_agents_for, outcomes_is_default, outcomes_path
from safo.modes import LocalMode, register_local

ASCII_COUNT = re.compile(r"[0-9]+")
MAX_FLAG_DIGITS = 13  # one past the largest count the log accepts (10**12): longer input is refused unparsed


def count(text: str) -> int:
    """An integer flag: ASCII digits only. `type=int` would take Unicode digits, a `+`, and surrounding spaces, which
    strict JSON and `parse_findings` refuse. The text is never echoed raw (it may be hostile)."""
    if not isinstance(text, str) or not ASCII_COUNT.fullmatch(text) or len(text) > MAX_FLAG_DIGITS:
        raise argparse.ArgumentTypeError(
            f"expected whole decimal digits 0-9 only, at most {MAX_FLAG_DIGITS} (got {len(text)} characters)"
        )
    return int(text)


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
        (0 if args.outcome == "abandoned" else 1) if args.review_rounds is None else args.review_rounds,
        outcomes.parse_findings(args.findings),
        args.tokens,
        args.requests,
        args.note,
        args.model,
        args.credits_used,
        args.outcome,
        args.attempts,
        args.intervention_minutes,
        args.defects_after_approval,
    )
    outcomes.validate(json.loads(record.to_json()), "outcome")
    path: Path = outcomes_path(ctx, args)
    if ctx.dry_run:
        ctx.say("dry run: would append outcome; nothing written")
        return EXIT_OK
    outcomes.append(path, record, check_dir=outcomes_is_default(ctx, args))
    ctx.say(f"recorded {record.agent} / {record.shape} in {path}")
    return EXIT_OK


def add_arguments(parser: argparse.ArgumentParser) -> None:
    add_agents_arguments(parser)
    parser.add_argument("action", choices=["add"])
    parser.add_argument("--agent", required=True, help="an agent id from agents.yaml")
    parser.add_argument("--shape", required=True, help="a task shape from agents.yaml")
    parser.add_argument("--card", default="", help="the issue or pull request URL")
    parser.add_argument("--date", default="", help="YYYY-MM-DD (default: today)")
    parser.add_argument(
        "--review-rounds",
        type=count,
        default=None,
        help="review passes, the passing one included (default: 1; 0 if abandoned: no passing pass)",
    )
    parser.add_argument("--findings", default="", help="critical=0,important=1,minor=2,unrated=0")
    parser.add_argument("--tokens", type=count, default=None)
    parser.add_argument("--requests", type=count, default=None)
    parser.add_argument(
        "--model", default=None, help="the underlying model of the run, e.g. gpt-5.4 (default: unknown)"
    )
    parser.add_argument(
        "--credits-used", type=count, default=None, help="credits or premium requests the run consumed, when known"
    )
    parser.add_argument(
        "--outcome",
        default=None,
        help="accepted or abandoned (default: not recorded, which reads as accepted); an abandoned task still counts",
    )
    parser.add_argument("--attempts", type=count, default=None, help="how many tries the task took, 1 to 100")
    parser.add_argument(
        "--intervention-minutes",
        type=count,
        default=None,
        help="minutes you spent steering or fixing it, self-reported at acceptance (0 to 10080)",
    )
    parser.add_argument(
        "--defects-after-approval", type=count, default=None, help="defects found after the work was approved"
    )
    parser.add_argument("--note", default="")
    parser.add_argument(
        "--log", default="", help="the outcomes log (default: $SAFO_OUTCOMES, else ~/.local/state/safo/outcomes.jsonl)"
    )


register_local(LocalMode("outcome", "append a finished task to the outcomes log", add_arguments, run))
