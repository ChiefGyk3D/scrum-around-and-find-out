# SPDX-License-Identifier: MIT
"""profiles verify: every profile claim beside what its evidence says, the CODEOWNERS check and promotion information.

Local and read-only; no network. Exit 0 when every pointer resolves and CODEOWNERS covers the profile paths, 1 when
either does not, 2 when the file cannot be read or fails its form checks (the codes of `safo` everywhere else).

With `--agents FILE` the file is a repository checkout: its files belong to whoever checked them out, so the trust
policy for private files does not apply and the control is review, which is what CODEOWNERS is checked for. Without
it the file is the user's private ~/.config/safo/agents.yaml and must pass `trusted_regular_file`.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from safo import codeowners
from safo.context import LocalContext
from safo.errors import EXIT_DRIFT, EXIT_OK, ConfigError
from safo.evidence import VerifiedAgents, iter_evidence, load_verified_agents, read_outcomes
from safo.localfiles import add_agents_arguments, agents_path, local_path
from safo.modes import LocalMode, register_local
from safo.qualify import Qualification, qualify

ACTIONS = ("verify",)


def _claims(ctx: LocalContext, v: VerifiedAgents) -> None:
    resolved = {r.field: r for r in v.resolutions}
    for agent in v.agents.agents:
        if agent.kind == "human":
            continue
        ctx.say(f"agent {agent.id}: {v.status_of(agent.id)}")
        problems = {x.split(": ", 1)[0]: x.split(": ", 1)[1] for x in v.errors_by_agent.get(agent.id, ())}
        for item in iter_evidence(agent):
            r = resolved.get(item.field)
            if r is not None:
                ctx.say(f"{item.field}: {item.text} [{r.kind}] => {r.subject}")
            else:
                ctx.say(
                    f"{item.field}: {item.text} [{item.evidence.kind}] => UNRESOLVED: {problems.get(item.field, '')}"
                )


def _owners(ctx: LocalContext, v: VerifiedAgents, root: Path) -> int:
    templates = [
        a.profile.brief.template for a in v.agents.agents if a.profile and a.profile.brief and a.profile.brief.template
    ]
    required = codeowners.required_paths(v.agents.evidence_sources.lessons, templates)
    try:
        rules = codeowners.parse_rules(codeowners.find_codeowners(root))
    except ConfigError as err:
        ctx.say(f"CODEOWNERS: {err}")
        return 1
    missing = codeowners.uncovered(rules, required)
    for path in missing:
        ctx.say(f"not covered by CODEOWNERS: {path}")
    if not missing:
        ctx.say(f"CODEOWNERS covers the {len(required)} profile paths")
    return len(missing)


def _line(q: Qualification, need: tuple[int, int]) -> str:
    text = f"{q.counted} counted of {need[0]} needed, {q.distinct_dates} distinct dates of {need[1]} needed"
    return text + "".join(f"; rejected {reason}: {n}" for reason, n in q.rejected)


def _promotion(ctx: LocalContext, v: VerifiedAgents, root: Path) -> None:
    doc = v.agents
    if not doc.evidence_sources.outcomes:
        return
    rows = read_outcomes(root, doc)
    if isinstance(rows, str):
        ctx.say(f"promotion: not computed: {rows}")
        return
    need = (doc.promotion.min_outcomes, doc.promotion.min_distinct_dates)
    today = ctx.now.date()
    for agent in doc.agents:
        p = agent.profile
        if p is None or agent.id in v.errors_by_agent:
            continue
        subjects: list[tuple[str, str | None, str]] = [(agent.id, None, p.status)]
        subjects += [(f"{agent.id}/{m}", m, layer.status) for m, layer in p.models]
        for name, model, status in subjects:
            if status != "profiled":
                continue
            q = qualify(rows, doc, agent.id, model, today=today)
            if q.qualified:
                ctx.say(f"promotion: {name}: qualifies ({_line(q, need)})")
            else:
                ctx.say(f"warning: {name} is profiled but does not qualify ({_line(q, need)})")


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    if args.action != "verify":
        raise ConfigError("the only profiles action is `verify`")
    repository = bool(args.agents)
    path = agents_path(ctx, args)
    local = local_path(ctx, args) if not repository or args.agents_local else None
    v = load_verified_agents(path, local, trusted=not repository)
    _claims(ctx, v)
    problems = 0
    try:
        v.require_clean()
    except ConfigError:
        problems += sum(len(x) for x in v.errors_by_agent.values())
    if repository:
        problems += _owners(ctx, v, path.parent)
    else:
        ctx.say("CODEOWNERS: not checked (a private file outside a repository checkout)")
    _promotion(ctx, v, path.parent)
    if problems:
        ctx.say(f"FAILED: {problems} problem(s)")
        return EXIT_DRIFT
    ctx.say("ok: every claim resolves")
    return EXIT_OK


def add_arguments(parser: argparse.ArgumentParser) -> None:
    add_agents_arguments(parser)
    parser.add_argument("action", choices=ACTIONS)


register_local(
    LocalMode(
        "profiles", "check agent profiles: every claim beside its evidence, and who owns the files", add_arguments, run
    )
)
