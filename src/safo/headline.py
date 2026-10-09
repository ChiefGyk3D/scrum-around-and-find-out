# SPDX-License-Identifier: MIT
"""An optional approved prose clause for a status update. It sees four counts and nothing else.

`safo status --post` groups and counts the cards in code. Here a local model (the `status-headline` shape in
agents.yaml) is asked for a single sentence over those counts. It is given no card titles, so a title cannot steer
it, and the caller uses the line only if `headline_acceptable` passes. Configuration, transport, decoding and
response-validation failures return None. Programmer defects such as
AssertionError are not hidden. Code always renders the count sentence; only a fixed, validated prose clause may follow.
"""

from __future__ import annotations

import argparse
import datetime as dt
import io
from collections.abc import Mapping

from safo.context import LocalContext
from safo.errors import SafoError
from safo.localfiles import load_agents_for
from safo.ollama import generate, probe
from safo.routing import probes_by_id, resolve_endpoint
from safo.statusgroups import Groups, headline_acceptable

SHAPE = "status-headline"
TIMEOUT_SECONDS = 30.0


def prompt_for(groups: Groups) -> str:
    c = groups.counts()
    return (
        "Reply with exactly one of: A steady week. | A quiet week. | Work continues. "
        "Use the exact spelling and punctuation, or reply with nothing. "
        f"Cards done since {groups.since.isoformat()}: {c['done']}. In progress: {c['progress']}. "
        f"Waiting on the maintainer: {c['waiting']}. Next: {c['next']}."
    )


def local_headline(env: Mapping[str, str], args: argparse.Namespace, groups: Groups) -> str | None:
    """A validated prose clause, or None for defined operational failures."""
    if env.get("GITHUB_ACTIONS") == "true":
        return None  # a runner has no local model, and an agents file there could only have come from the checkout
    try:
        ctx = LocalContext(io.StringIO(), env, dt.datetime.now(dt.UTC))  # for the shared agents.yaml path rules
        doc = load_agents_for(ctx, args)
        shape = doc.shape(SHAPE)
        agent = next((doc.agent(a) for a in shape.chain if doc.agent(a).kind == "ollama"), None)
        if agent is None:
            return None
        probes = probes_by_id([probe(e) for e in agent.endpoints])  # two GETs each; never a generate
        endpoint, model, _ = resolve_endpoint(agent, shape, probes)
        if endpoint is None:
            return None
        answer = generate(
            endpoint,
            model,
            prompt_for(groups),
            think=False,
            num_ctx=endpoint.ctx_for(model),
            timeout=TIMEOUT_SECONDS,
            keep_alive=endpoint.keep_alive_for(model),
        )
    except (SafoError, OSError, TimeoutError, UnicodeError, ValueError):
        return None
    # Validate the entire response. Embedded CR/LF, quoting and Markdown are not removed.
    text = answer.response.strip(" ")
    return text if headline_acceptable(text, groups) else None
