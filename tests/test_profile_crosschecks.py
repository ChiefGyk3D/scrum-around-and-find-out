# SPDX-License-Identifier: MIT
"""Spec test 7: a profile is checked against the shapes, the endpoints and the kind it sits on."""

from __future__ import annotations

from typing import Any

import pytest

from profiledata import LESSON, claim, doc, need, prof, profile, rejects
from safo.agentsfile import parse_agents


def gate() -> dict[str, Any]:
    return {"required": True, "reviewer_differs": True, "checks": [{"code": "test_vs_behaviour", "evidence": LESSON}]}


def test_a_must_not_get_shape_must_exist() -> None:
    d = doc()
    profile(d, "codex")["must_not_get"] = [{"shape": "no-such-shape", "evidence": LESSON}]
    rejects(d, r"agents\.codex\.profile\.must_not_get\[0\]\.shape: 'no-such-shape' is not a shape")
    profile(d, "codex")["must_not_get"][0]["shape"] = "ops-runbook"
    assert prof(parse_agents(d), "codex").must_not_get[0].shape == "ops-runbook"


def test_a_shape_that_prefers_the_agent_is_an_error_and_one_that_falls_back_to_it_is_a_warning() -> None:
    d = doc()
    profile(d, "codex")["must_not_get"] = [{"shape": "research", "evidence": LESSON}]  # prefer: [codex]
    rejects(d, r"must_not_get\[0\]\.shape: shape 'research' prefers codex")
    d = doc()
    profile(d, "codex")["must_not_get"] = [{"shape": "integration-code", "evidence": LESSON}]  # fallback: [codex]
    parsed = parse_agents(d)
    assert any("integration-code" in w and "codex" in w and "must_not_get" in w for w in parsed.warnings)
    d = doc()
    profile(d, "codex")["must_not_get"] = [{"shape": "ops-runbook", "evidence": LESSON}]
    assert parse_agents(d).warnings == ()


# the example local file gives ollama two endpoints: num_ctx_max 131072 and 8192; loaded 131072, 8192, 8192 and 2048
def test_an_ollama_ceiling_is_at_most_the_minimum_over_every_endpoint_and_loaded_context() -> None:
    d = doc()
    p = profile(d, "ollama")
    p["context_ceiling"] = {"value": 2048, "evidence": LESSON}
    assert need(prof(parse_agents(d), "ollama").context_ceiling).value == 2048
    p["context_ceiling"]["value"] = 2049
    rejects(d, r"agents\.ollama\.profile\.context_ceiling\.value: 2049 is above 2048")
    d = doc()
    d["agents"]["ollama"]["endpoints"][1]["loaded_num_ctx"]["embed-small"] = 4096
    profile(d, "ollama")["context_ceiling"] = {"value": 4096, "evidence": LESSON}
    parse_agents(d)  # the minimum is now 4096 (instance-b loaded safety model 8192, embed 4096)
    profile(d, "ollama")["context_ceiling"]["value"] = 4097
    rejects(d, r"context_ceiling\.value: 4097 is above 4096")


def test_the_ceiling_is_checked_against_num_ctx_max_when_no_context_is_pinned() -> None:
    d = doc()
    d["agents"]["ollama"]["endpoints"] = [
        {"id": "bare", "url": "http://127.0.0.1:11434", "roles": ["general"], "models": ["m"], "num_ctx_max": 4096}
    ]
    profile(d, "ollama")["context_ceiling"] = {"value": 4096, "evidence": LESSON}
    parse_agents(d)
    profile(d, "ollama")["context_ceiling"]["value"] = 4097
    rejects(d, r"context_ceiling\.value: 4097 is above 4096")


@pytest.mark.parametrize(
    ("think_a", "think_b", "value", "ok"),
    [
        (False, False, "off", True),
        (False, False, "on", False),
        (True, True, "on", True),
        (True, True, "off", False),
        (False, True, "off", False),
        (False, True, "on", False),
        (True, False, "on", False),
        (False, False, "default", False),
        (True, True, "default", False),
    ],
)
def test_ollama_thinking_must_match_every_endpoints_default_and_default_is_forbidden(
    think_a: bool, think_b: bool, value: str, ok: bool
) -> None:
    d = doc()
    d["agents"]["ollama"]["endpoints"][0]["think"] = think_a
    d["agents"]["ollama"]["endpoints"][1]["think"] = think_b
    profile(d, "ollama")["thinking"] = {"value": value, "evidence": LESSON}
    if ok:
        parse_agents(d)
    elif value == "default":
        rejects(d, r"agents\.ollama\.profile\.thinking\.value: 'default' is not allowed for an ollama agent")
    else:
        rejects(d, r"agents\.ollama\.profile\.thinking\.value: .* every endpoint's think")


def test_the_ollama_rules_apply_with_one_endpoint_too() -> None:
    d = doc()
    d["agents"]["ollama"]["endpoints"] = d["agents"]["ollama"]["endpoints"][:1]
    profile(d, "ollama")["context_ceiling"] = {"value": 8192, "evidence": LESSON}
    parse_agents(d)
    profile(d, "ollama")["context_ceiling"]["value"] = 8193
    rejects(d, r"context_ceiling\.value: 8193 is above 8192")


def test_a_non_ollama_agent_is_not_bound_by_endpoint_rules() -> None:
    d = doc()
    profile(d, "codex")["context_ceiling"] = {"value": 500_000, "evidence": LESSON}
    profile(d, "codex")["thinking"] = {"value": "default", "evidence": LESSON}
    parse_agents(d)


def test_a_gated_agent_in_a_shape_needs_a_reviewer_that_is_not_itself() -> None:
    d = doc()
    profile(d, "copilot")["review_gate"] = gate()
    parsed = parse_agents(d)
    assert need(prof(parsed, "copilot").review_gate).required is True
    d["shapes"]["small-mechanical-pr"]["reviewer"] = []
    rejects(d, r"shapes\.small-mechanical-pr\.reviewer: needs a reviewer because copilot has a review_gate")
    d["shapes"]["small-mechanical-pr"]["reviewer"] = ["copilot"]
    rejects(d, r"shapes\.small-mechanical-pr\.reviewer: copilot cannot review its own work")
    d["shapes"]["small-mechanical-pr"]["reviewer"] = ["claude-sonnet", "copilot"]
    rejects(d, r"cannot review its own work")


def test_a_gated_agent_in_a_fallback_chain_is_checked_too() -> None:
    d = doc()
    profile(d, "copilot")["review_gate"] = gate()
    d["shapes"]["research"]["fallback"] = ["claude-sonnet", "copilot"]
    d["shapes"]["research"]["reviewer"] = []
    rejects(d, r"shapes\.research\.reviewer: needs a reviewer because copilot has a review_gate")


def test_an_agent_without_a_gate_imposes_no_reviewer_rule() -> None:
    d = doc()
    d["shapes"]["small-mechanical-pr"]["reviewer"] = []
    parse_agents(d)


def test_models_are_allowed_only_on_a_layered_kind() -> None:
    d = doc()
    profile(d, "copilot")["status"] = "profiled"
    profile(d, "copilot")["do"] = [claim("Give it small single-repo pull requests.")]
    profile(d, "copilot")["models"] = {"gpt-x": {"status": "unmeasured"}}
    got = parse_agents(d).agent("copilot").profile
    assert got is not None and [m for m, _ in got.models] == ["gpt-x"]
    for agent in ("codex", "ollama", "claude-haiku"):
        d = doc()
        profile(d, agent)["status"] = "profiled"
        profile(d, agent).setdefault("do", [claim("Some claim about the agent.")])
        profile(d, agent)["models"] = {"gpt-x": {"status": "unmeasured"}}
        rejects(d, rf"agents\.{agent}\.profile\.models: only copilot has model layers")


def test_a_model_layer_takes_only_its_own_keys_and_follows_the_same_status_rules() -> None:
    def with_models(models: Any) -> dict[str, Any]:
        d = doc()
        profile(d, "copilot").update(status="profiled", do=[claim("Give it small single-repo pull requests.")])
        profile(d, "copilot")["models"] = models
        return d

    rejects(
        with_models({"gpt-x": {"status": "unmeasured", "review_gate": {}}}), r"models\.gpt-x\.review_gate: unknown key"
    )
    rejects(
        with_models({"gpt-x": {"status": "unmeasured", "brief": {"inline": "x"}}}), r"models\.gpt-x\.brief: unknown key"
    )
    rejects(with_models({"gpt-x": {}}), r"models\.gpt-x\.status: required")
    rejects(
        with_models({"gpt-x": {"status": "unmeasured", "do": [claim()]}}), r"models\.gpt-x\.do: an unmeasured agent"
    )
    rejects(with_models({"gpt-x": {"status": "profiled"}}), r"models\.gpt-x: a profiled agent needs at least one")
    rejects(with_models({"bad id": {"status": "unmeasured"}}), r"models: 'bad id' is not a model id")
    rejects(
        with_models({"gpt-x": {"status": "unmeasured", "thinking": {"value": "on"}}}),
        r"gpt-x\.thinking\.evidence: required",
    )
    rejects(with_models([]), r"models: expected a mapping")
    ok = with_models(
        {
            "gpt-x": {
                "status": "profiled",
                "thinking": {"value": "on", "evidence": LESSON},
                "dont": [claim("A model-level claim.")],
            }
        }
    )
    layer = dict(prof(parse_agents(ok), "copilot").models)["gpt-x"]
    assert layer.status == "profiled" and need(layer.thinking).value == "on"
    assert layer.dont[0].text == "A model-level claim."


def test_a_human_with_a_profile_is_refused_by_the_cross_check_too() -> None:
    d = doc()
    d["agents"]["maintainer"]["profile"] = {"status": "unmeasured"}
    rejects(d, r"agents\.maintainer\.profile: a human takes no profile")
