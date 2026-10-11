# SPDX-License-Identifier: MIT
"""Spec test 3: the claim-by-evidence-kind table, cell by cell, at parse time and again when the pointer is resolved."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from profiledata import LESSON, OUTCOMES, claim, doc, profile, rejects
from safo.agentsfile import parse_agents
from safo.evidence import EvidenceError, resolve_config

POINTERS = {
    "lessons": LESSON,
    "outcomes": OUTCOMES,
    "config": "config:/agents/ollama/endpoints/0/think",
}
CEILING_CONFIG = "config:/agents/ollama/endpoints/0/num_ctx_max"


def put_do(d: dict[str, Any], ev: str) -> None:
    profile(d, "codex")["do"] = [claim("A claim.", ev)]


def put_dont(d: dict[str, Any], ev: str) -> None:
    profile(d, "codex")["dont"] = [claim("A different claim.", ev)]


def put_must(d: dict[str, Any], ev: str) -> None:
    profile(d, "codex")["must_not_get"] = [{"shape": "ops-runbook", "evidence": ev}]


def put_check(d: dict[str, Any], ev: str) -> None:
    profile(d, "copilot")["review_gate"] = {
        "required": True,
        "reviewer_differs": True,
        "checks": [{"code": "test_vs_behaviour", "evidence": ev}],
    }


def put_ceiling(d: dict[str, Any], ev: str) -> None:
    profile(d, "ollama")["context_ceiling"] = {"value": 1024, "evidence": ev}


def put_cap(d: dict[str, Any], ev: str) -> None:
    profile(d, "codex")["output_cap"] = {"value": 512, "evidence": ev}


def put_thinking(d: dict[str, Any], ev: str) -> None:
    profile(d, "ollama")["thinking"] = {"value": "off", "evidence": ev}


# claim kind -> (writer, evidence kinds the table allows, the pointer to use for a config cell)
TABLE: dict[str, tuple[Callable[[dict[str, Any], str], None], tuple[str, ...], str]] = {
    "do": (put_do, ("lessons", "outcomes"), POINTERS["config"]),
    "dont": (put_dont, ("lessons", "outcomes"), POINTERS["config"]),
    "must_not_get": (put_must, ("lessons", "outcomes"), POINTERS["config"]),
    "review check": (put_check, ("lessons", "outcomes"), POINTERS["config"]),
    "context_ceiling": (put_ceiling, ("config", "lessons", "outcomes"), CEILING_CONFIG),
    "output_cap": (put_cap, ("lessons", "outcomes"), CEILING_CONFIG),
    "thinking": (put_thinking, ("config", "lessons", "outcomes"), POINTERS["config"]),
}


@pytest.mark.parametrize("kind", ["lessons", "outcomes", "config"])
@pytest.mark.parametrize("claim_kind", list(TABLE))
def test_every_cell_of_the_compatibility_table(claim_kind: str, kind: str) -> None:
    writer, allowed, config_pointer = TABLE[claim_kind]
    d = doc()
    writer(d, config_pointer if kind == "config" else POINTERS[kind])
    if kind in allowed:
        parse_agents(d)
    else:
        rejects(d, rf"evidence: a {kind} pointer cannot support a .* claim \(allowed: {', '.join(allowed)}\)")


def test_a_config_pointer_on_a_behavioural_claim_fails_even_when_it_resolves() -> None:
    d = doc()
    ep = d["agents"]["ollama"]["endpoints"][0]
    assert ep["think"] is False  # the pointer is real
    put_dont(d, POINTERS["config"])
    rejects(d, r"profile\.dont\[0\]\.evidence: a config pointer cannot support a dont claim")


def test_lessons_on_a_ceiling_passes() -> None:
    d = doc()
    profile(d, "codex")["context_ceiling"] = {"value": 4096, "evidence": LESSON}
    parse_agents(d)


def test_a_ceiling_citing_the_thinking_field_fails_and_so_does_the_reverse() -> None:
    d = doc()
    put_ceiling(d, "config:/agents/ollama/endpoints/0/think")
    rejects(d, r"context_ceiling\.evidence: a config pointer for context_ceiling must address one of")
    d = doc()
    put_thinking(d, "config:/agents/ollama/endpoints/0/num_ctx_max")
    rejects(d, r"thinking\.evidence: a config pointer for thinking must address one of")


@pytest.mark.parametrize("ref", ["/version", "/agents/ollama/kind", "/agents/ollama/endpoints/0/url", "/agents/ollama/endpoints/0/note"])
def test_a_pointer_outside_the_allowlist_fails_at_parse_and_at_resolution(ref: str) -> None:
    d = doc()
    put_ceiling(d, f"config:{ref}")
    rejects(d, r"context_ceiling\.evidence")
    with pytest.raises(EvidenceError, match="allowlist"):
        resolve_config(doc(), ref, "context_ceiling", "ollama")
