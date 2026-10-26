# SPDX-License-Identifier: Apache-2.0
"""Spec test 8, the schema part: review_gate is {required, reviewer_differs, checks:[{code, evidence}]}."""

from __future__ import annotations

from typing import Any

import pytest

from profiledata import LESSON, OTHER_LESSON, doc, need, prof, profile, rejects
from safo.agentsfile import parse_agents


def gated(gate: Any) -> dict[str, Any]:
    d = doc()
    profile(d, "copilot")["review_gate"] = gate
    return d


def good() -> dict[str, Any]:
    return {
        "required": True,
        "reviewer_differs": True,
        "checks": [
            {"code": "test_vs_behaviour", "evidence": OTHER_LESSON},
            {"code": "workflow_permissions", "evidence": LESSON},
        ],
    }


def test_a_well_formed_gate_loads_with_its_checks_in_order() -> None:
    gate = need(prof(parse_agents(gated(good())), "copilot").review_gate)
    assert (gate.required, gate.reviewer_differs) == (True, True)
    assert [(c.code, c.evidence.raw) for c in gate.checks] == [
        ("test_vs_behaviour", OTHER_LESSON),
        ("workflow_permissions", LESSON),
    ]


def test_every_check_is_an_object_with_a_code_and_its_own_evidence() -> None:
    g = good()
    g["checks"][0].pop("evidence")
    rejects(gated(g), r"review_gate\.checks\[0\]\.evidence: required")
    g = good()
    g["checks"][1].pop("code")
    rejects(gated(g), r"review_gate\.checks\[1\]\.code: required")
    g = good()
    g["checks"][0]["evidence"] = "config:/agents/ollama/endpoints/0/think"
    rejects(gated(g), r"review_gate\.checks\[0\]\.evidence: a config pointer cannot support")
    g = good()
    g["checks"][0]["evidence"] = "nonsense"
    rejects(gated(g), r"review_gate\.checks\[0\]\.evidence")
    g = good()
    g["checks"][0]["note"] = "x"
    rejects(gated(g), r"review_gate\.checks\[0\]\.note: unknown key")


def test_a_bare_string_check_is_refused() -> None:
    g = good()
    g["checks"] = ["test_vs_behaviour"]
    rejects(gated(g), r"review_gate\.checks\[0\]: expected a mapping")
    g["checks"] = "test_vs_behaviour"
    rejects(gated(g), r"review_gate\.checks: expected a list")


def test_an_unknown_or_duplicate_code_is_refused() -> None:
    g = good()
    g["checks"][0]["code"] = "vibes"
    rejects(gated(g), r"review_gate\.checks\[0\]\.code: 'vibes' is not one of test_vs_behaviour, workflow_permissions")
    g = good()
    g["checks"][1]["code"] = "test_vs_behaviour"
    rejects(gated(g), r"review_gate\.checks\[1\]\.code: duplicate of checks\[0\]")


@pytest.mark.parametrize("key", ["required", "reviewer_differs"])
@pytest.mark.parametrize("value", [False, "true", 1, None])
def test_required_and_reviewer_differs_must_be_literally_true(key: str, value: Any) -> None:
    g = good()
    g[key] = value
    rejects(gated(g), rf"review_gate\.{key}: expected true")


@pytest.mark.parametrize("key", ["required", "reviewer_differs", "checks"])
def test_all_three_keys_are_required_and_nothing_else_is_allowed(key: str) -> None:
    g = good()
    del g[key]
    rejects(gated(g), rf"review_gate\.{key}: required")
    g = good()
    g["profile_evidence"] = [LESSON]
    rejects(gated(g), r"review_gate\.profile_evidence: unknown key")


def test_a_gate_must_be_a_mapping_and_checks_are_capped() -> None:
    rejects(gated(["required"]), r"review_gate: expected a mapping")
    g = good()
    g["checks"] = [{"code": "test_vs_behaviour", "evidence": LESSON}] * 3
    rejects(gated(g), r"review_gate\.checks\[1\]\.code: duplicate")


def test_a_gate_is_only_for_a_gated_kind() -> None:
    d = doc()
    profile(d, "codex")["review_gate"] = good()
    rejects(d, r"agents\.codex\.profile\.review_gate: only copilot has a review gate")


def test_a_model_layer_cannot_override_the_harness_gate() -> None:
    d = gated(good())
    profile(d, "copilot")["status"] = "profiled"
    profile(d, "copilot")["do"] = [{"text": "Give it small single-repo pull requests.", "evidence": LESSON}]
    profile(d, "copilot")["models"] = {"gpt-x": {"status": "unmeasured", "review_gate": good()}}
    rejects(d, r"models\.gpt-x\.review_gate: unknown key")
