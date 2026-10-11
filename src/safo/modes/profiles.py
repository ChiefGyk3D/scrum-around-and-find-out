# SPDX-License-Identifier: MIT
"""profiles verify and profiles brief.

`verify`: every profile claim beside what its evidence says, the CODEOWNERS check and promotion information.

Local and read-only; no network. Exit 0 when every pointer resolves and CODEOWNERS covers the profile paths, 1 when
either does not, 2 when the file cannot be read or fails its form checks (the codes of `safo` everywhere else).

With `--agents FILE` the file is a repository checkout: its files belong to whoever checked them out, so the trust
policy for private files does not apply and the control is review, which is what CODEOWNERS is checked for. Without
it the file is the user's private ~/.config/safo/agents.yaml and must pass `trusted_regular_file`.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from safo import brief, codeowners, output
from safo.context import LocalContext
from safo.errors import EXIT_DRIFT, EXIT_OK, ConfigError
from safo.evidence import VerifiedAgents, iter_evidence, load_verified_agents, read_outcomes
from safo.localfiles import add_agents_arguments, agents_path, local_path
from safo.modes import LocalMode, register_local
from safo.qualify import Qualification, qualify

ACTIONS = ("verify", "brief")
VALUE_ARGS = {name: flag[2:].replace("-", "_") for name, flag in brief.FLAGS.items()}  # placeholder -> args attribute


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
        text = codeowners.find_codeowners(root)
    except ConfigError as err:
        ctx.say(f"CODEOWNERS: {err}")
        return 1
    rules = codeowners.parse_rules(text)  # a rule it cannot evaluate raises: exit 2, never a rule left out
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


def _load(ctx: LocalContext, args: argparse.Namespace, *, strict_workspace: bool) -> tuple[VerifiedAgents, Path]:
    repository = bool(args.agents)
    # `verify` may look at an explicit checkout file inside the CI workspace (read-only, and it never trusts the file);
    # `brief` may not: its output is read by a model, so under Actions the file must come from outside the checkout.
    path = Path(args.agents) if repository and not strict_workspace else agents_path(ctx, args)
    local = local_path(ctx, args) if not repository or args.agents_local else None
    return load_verified_agents(path, local, trusted=not repository), path


def _given(args: argparse.Namespace) -> dict[str, str]:
    return {name: getattr(args, attr) for name, attr in VALUE_ARGS.items() if getattr(args, attr) is not None}


def _values(ctx: LocalContext, args: argparse.Namespace) -> dict[str, str]:
    """Each value the command line gave, read under the rules of brief.py. Standard input may carry only one."""
    values: dict[str, str] = {}
    stdin_user = ""
    for name, given in _given(args).items():
        if name in ("test_command", "card"):
            values[name] = given  # the value itself, on the command line
        elif given == "-":
            if stdin_user:
                both = f"{stdin_user} and {brief.FLAGS[name]}"
                raise ConfigError(f"standard input can carry one value, not both {both}")
            stdin_user = brief.FLAGS[name]
            values[name] = brief.read_stdin(name, ctx.stdin if ctx.stdin is not None else sys.stdin)
        else:
            values[name] = brief.read_file(name, given)
    return values


def _emit(ctx: LocalContext, text: str) -> None:
    """The brief, exactly. A document is not a log line (no escaping that would change the data) except under GitHub
    Actions, where a line that starts with `::` would be a workflow command: there it sits in a stop-commands block."""
    if ctx.env.get("GITHUB_ACTIONS") == "true":
        output.block(ctx.out, text.rstrip("\n").split("\n"))
    else:
        ctx.out.write(text)


def _brief(ctx: LocalContext, args: argparse.Namespace) -> int:
    if not args.agent:
        raise ConfigError("profiles brief needs --agent ID")
    v, _ = _load(ctx, args, strict_workspace=True)
    v.require_clean()  # one dangling pointer anywhere stops it: there is no second, unverified load path
    agent = v.agents.agent(args.agent)
    profile = agent.profile
    if profile is None:
        raise ConfigError(f"{agent.id} has no profile, so there is no brief to fill")
    chosen = profile.brief
    if chosen is None:
        raise ConfigError(f"{agent.id} has no brief (its profile names a persona or the harness owns the form)")
    given = _given(args)
    if chosen.inline:
        if given:
            flags = ", ".join(brief.FLAGS[n] for n in given)
            raise ConfigError(
                f"the brief of {agent.id} is inline text with no placeholders, so it takes no values ({flags}); "
                "use a template for a brief that carries task data"
            )
        _emit(ctx, chosen.inline + "\n")
        return EXIT_OK
    _emit(ctx, brief.fill(chosen.template_text, _values(ctx, args)))
    return EXIT_OK


def _verify(ctx: LocalContext, args: argparse.Namespace) -> int:
    repository = bool(args.agents)
    v, path = _load(ctx, args, strict_workspace=False)
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


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    if args.action == "brief":
        return _brief(ctx, args)
    if args.agent or _given(args):
        raise ConfigError("--agent and the value flags belong to `safo profiles brief`")
    return _verify(ctx, args)


HELP = (
    "verify: print every profile claim beside what its evidence says, check CODEOWNERS and report promotion. "
    "brief: print an agent's brief template with the task data in fences. Each value goes between a start line "
    "<<<UNTRUSTED-TASK-DATA name=NAME id=HEX>>> and an end line <<<END-UNTRUSTED-TASK-DATA id=HEX>>>, where HEX is "
    "128 random bits drawn per call. A value that holds the delimiter text, a NUL or another control character, "
    "a directional embedding, override or isolate (U+202A to U+202E, U+2066 to U+2069), or "
    "is larger than 65536 bytes is refused (exit 2), and so is a template whose placeholders break the placement "
    "rules (a placeholder is a whole line between blank lines, once, outside code fences and HTML). Line endings "
    "are normalised. A file flag takes a path (a regular file, no symbolic link, at most 65536 bytes) or - for "
    "standard input, for one value only. The guarantee is about structure only: where a value starts and ends in "
    "the output. It does not make a model ignore instructions written inside a fence. Pasting task text into a "
    "template by hand is outside the guarantee."
)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.description = HELP
    add_agents_arguments(parser)
    parser.add_argument("action", choices=ACTIONS)
    parser.add_argument("--agent", default="", help="brief: the agent whose brief template to fill")
    parser.add_argument("--task-file", default=None, help="brief: the task text, {{task}} (- is standard input)")
    parser.add_argument("--files-file", default=None, help="brief: the files in scope, {{files_in_scope}} (- too)")
    parser.add_argument(
        "--acceptance-file", default=None, help="brief: the acceptance criteria, {{acceptance_criteria}} (- too)"
    )
    parser.add_argument("--test-command", default=None, help="brief: the test command as text, {{test_command}}")
    parser.add_argument("--card", default=None, help="brief: the issue or pull request URL as text, {{card}}")


register_local(
    LocalMode(
        "profiles", "check agent profiles: every claim beside its evidence, and who owns the files", add_arguments, run
    )
)
