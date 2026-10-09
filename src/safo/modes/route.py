# SPDX-License-Identifier: MIT
"""route: rules plus live headroom give a recommended agent and the reason. It dispatches nothing."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from safo.context import LocalContext
from safo.errors import EXIT_OK
from safo.localfiles import add_agents_arguments, load_agents_for
from safo.meters import as_json, collect
from safo.meters.copilot import cached_percent
from safo.modes import LocalMode, register_local
from safo.routing import Recommendation, probes_by_id, recommend


def lines(r: Recommendation) -> list[str]:
    out = [f"shape: {r.shape}"]
    if r.agent is None:
        out += [f"recommended: nobody ({r.why})"]
    else:
        out.append(f"recommended: {r.agent} (put Agent = {r.card_label} on the card)")
        out.append(f"why: {r.why}")
    if r.endpoint and r.local_role != "embedding":
        out.append(
            f"local: endpoint {r.endpoint}, model {r.model}; "
            f"run it with `safo local run --shape {r.shape} --prompt-file FILE`"
        )
    if r.endpoint and r.local_role == "embedding":
        out.append("embedding/search requires a separate executor; local run supports generation only")
    for gate in r.reviews:
        out.append(f"required review: {gate.reviewer}: {'ready' if gate.available else 'unavailable'} ({gate.reason})")
    if r.needs_approval:
        out.append("needs the maintainer's OK before it is used")
    if r.reviewer:
        out.append(f"reviewer: {r.reviewer} ({r.reviewer_why})")
    elif r.reviewer_why:
        out.append(f"reviewer: nobody ({r.reviewer_why})")
    if r.skipped and r.agent is None:
        out += [f"skipped: {x}" for x in r.skipped]
    if r.unknown:
        out.append(f"headroom unknown for: {', '.join(r.unknown)} (not blocking)")
    if r.note:
        out.append(f"note: {r.note}")
    out.append(f"chain: {' -> '.join(r.fallback_chain)}")
    out.append("safo route only recommends: the lead sets the card and hands the work out.")
    return out


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    doc = load_agents_for(ctx, args)
    if not args.json:
        for warning in doc.warnings:
            ctx.say(f"warning: {warning}")
    if args.list:
        for s in doc.shapes:
            ctx.say(f"{s.name:<26} {s.description}")
        return EXIT_OK
    headroom: dict[str, float | None] = {}
    probes = {}
    if not args.no_usage:
        endpoints = tuple(e for a in doc.agents for e in a.endpoints)
        meters = collect(ctx, days=args.days, allowance=doc.monthly_allowance(), endpoints=endpoints)
        headroom = meters.headroom()
        probes = probes_by_id(meters.ollama)
    if args.copilot_meter:
        headroom["monthly_percent"] = cached_percent(
            Path(args.copilot_meter), ctx.now.strftime("%Y-%m"), doc.monthly_allowance()
        )
    rec = recommend(doc, args.shape, headroom, probes, model=args.model, num_ctx=args.num_ctx)
    if args.json:
        document = {**as_json(rec), "warnings": list(doc.warnings)}
        # one line, ASCII only; `::` is written as a JSON escape so no value can start a workflow command
        ctx.say(json.dumps(document, separators=(",", ":")).replace("::", ":\\u003a"))
    else:
        for line in lines(rec):
            ctx.say(line)
    return EXIT_OK


def add_arguments(parser: argparse.ArgumentParser) -> None:
    add_agents_arguments(parser)
    parser.add_argument("shape", nargs="?", default="", help="a task shape from agents.yaml (see --list)")
    parser.add_argument("--list", action="store_true", help="list the task shapes")
    parser.add_argument("--days", type=float, default=7.0)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--copilot-meter", default="", help="validated current-month AI-credit JSON meter")
    parser.add_argument("--no-usage", action="store_true", help="apply the rules without reading any meter or endpoint")
    parser.add_argument("--model", default="", help="for a local shape: a specific model")
    parser.add_argument(
        "--num-ctx", type=int, default=None, help="for a local shape: the context size you intend to use"
    )


register_local(
    LocalMode("route", "recommend an agent for a task shape from the rules and live headroom", add_arguments, run)
)
