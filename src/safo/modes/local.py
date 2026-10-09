# SPDX-License-Identifier: MIT
"""local run: send one prompt to the local LLM that routing picks, print the answer, log the outcome.

Routing decides first (`resolve_endpoint`): a reachable endpoint, an allowed model, a context size under the cap, and
never a model that could evict a protected one. If nothing fits, or the endpoint goes away mid-request, nothing is sent
elsewhere: it names the fallback so the lead can hand the work to it. The answer is a draft; a Claude model reviews it
before anything lands.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from safo import outcomes, output
from safo.agentsfile import AgentsFile
from safo.bounded import read_bounded
from safo.context import LocalContext
from safo.errors import EXIT_DRIFT, EXIT_OK, ConfigError
from safo.localfiles import add_agents_arguments, load_agents_for, outcomes_path
from safo.modes import LocalMode, register_local
from safo.ollama import EndpointUnreachableError, generate, probe
from safo.routing import probes_by_id, resolve_endpoint

MAX_PROMPT_BYTES = 1_048_576


def fallback_of(doc: AgentsFile, shape_name: str) -> str:
    chain = doc.shape(shape_name).chain
    return next((a for a in chain if doc.agent(a).kind != "ollama"), "the lead")


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    if args.action != "run":
        raise ConfigError("the only local action is `run`")
    doc = load_agents_for(ctx, args)
    for warning in doc.warnings:
        ctx.say(f"warning: {warning}")
    shape = doc.shape(args.shape)
    if shape.local_role == "embedding":
        raise ConfigError("local run supports generation only; embedding/search needs a separate executor")
    agent = next((doc.agent(a) for a in shape.chain if doc.agent(a).kind == "ollama"), None)
    if agent is None:
        raise ConfigError(f"shape {shape.name!r} has no local agent in its chain; see `safo route --list`")
    path = Path(args.prompt_file)
    try:  # no symlink followed, no FIFO waited on, never more than the cap plus one byte
        prompt = read_bounded(path, MAX_PROMPT_BYTES + 1)
    except OSError as err:
        raise ConfigError(f"cannot read the prompt file {path}: {err.strerror}") from None
    if len(prompt) > MAX_PROMPT_BYTES:
        raise ConfigError(f"the prompt file is larger than {MAX_PROMPT_BYTES} bytes; summarise it first")
    log = outcomes_path(ctx, args)  # refused here, before anything is sent, if it is not somewhere we may write
    if ctx.dry_run:
        ctx.say("dry run: prompt validated; no probes, generation or outcome writes")
        return EXIT_OK
    probes = probes_by_id([probe(e) for e in agent.endpoints])  # two GETs each; never a generate
    endpoint, model, skipped = resolve_endpoint(
        agent, shape, probes, model=args.model, num_ctx=args.num_ctx, endpoint_id=args.endpoint
    )
    fallback = fallback_of(doc, shape.name)
    if endpoint is None:
        for line in skipped:
            ctx.say(f"skipped: {line}")
        ctx.say(f"no local endpoint can take this: hand it to {fallback} instead (nothing was sent)")
        return EXIT_DRIFT
    think = endpoint.think if args.think is None else args.think
    num_ctx = args.num_ctx or endpoint.ctx_for(model)
    try:
        result = generate(
            endpoint,
            model,
            prompt.decode("utf-8", "replace"),
            think=think,
            num_ctx=num_ctx,
            timeout=args.timeout,
            keep_alive=endpoint.keep_alive_for(model),
        )
    except EndpointUnreachableError as err:
        ctx.say(f"{err}: hand it to {fallback} instead")
        return EXIT_DRIFT
    output.block(ctx.out, result.response.rstrip("\n").split("\n"))  # untrusted text: inside a stop-commands block
    speed = f"{result.tokens_per_second:g} tok/s" if result.tokens_per_second else "speed unknown"
    note = (
        f"{endpoint.id} {model} think={str(think).lower()} num_ctx={num_ctx}: "
        f"{result.eval_count} eval tokens, {speed}; "
        "a draft until a Claude model reviews it"
    )
    outcomes.append(
        log,
        outcomes.Outcome(
            ctx.now.date().isoformat(),
            args.card or None,
            agent.id,
            shape.name,
            0,
            {},
            result.eval_count + result.prompt_eval_count,
            1,
            note,
        ),
    )
    ctx.say(f"-- {note}")
    return EXIT_OK


def add_arguments(parser: argparse.ArgumentParser) -> None:
    add_agents_arguments(parser)
    parser.add_argument("action", choices=["run"])
    parser.add_argument("--shape", required=True, help="a local task shape from agents.yaml")
    parser.add_argument("--prompt-file", required=True)
    parser.add_argument("--endpoint", default="", help="insist on one endpoint id")
    parser.add_argument("--model", default="", help="a model; it must be one the endpoint allows")
    parser.add_argument("--num-ctx", type=int, default=None, help="exactly the num_ctx the model is loaded with")
    parser.add_argument(
        "--think", action=argparse.BooleanOptionalAction, default=None, help="default: the endpoint's setting"
    )
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--card", default="", help="the issue or pull request URL, for the outcomes log")
    parser.add_argument(
        "--log", default="", help="the outcomes log (default: $SAFO_OUTCOMES, else ~/.local/state/safo/outcomes.jsonl)"
    )


register_local(LocalMode("local", "send one prompt to the local LLM routing picks (Ollama)", add_arguments, run))
