# SPDX-License-Identifier: MIT
"""safo.routing: rules plus headroom give an agent and a reason; a local agent never evicts a protected model."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsdata import A_MODELS, B_MODELS, agents_dict, agents_with
from safo.agentsfile import parse_agents
from safo.errors import ConfigError
from safo.ollama import Probe
from safo.routing import recommend

ROOT = Path(__file__).parent.parent
DOC = agents_with()


def probe(endpoint_id: str, *, loaded: tuple[str, ...] = (), up: bool = True) -> Probe:
    return Probe(endpoint_id, "http://127.0.0.1:9", up, loaded, ())


UP = {
    "instance-a": probe("instance-a", loaded=tuple(A_MODELS)),
    "instance-b": probe("instance-b", loaded=tuple(B_MODELS[:1])),
}


def test_with_headroom_the_preferred_agent_wins_and_the_reviewer_is_someone_else() -> None:
    r = recommend(DOC, "research", {"five_hour": 20.0, "weekly": 5.0})
    assert (r.agent, r.card_label, r.reviewer) == ("codex", "Codex", "claude-sonnet")
    assert r.fallback_chain == ("codex", "claude-sonnet")


def test_codex_above_80_percent_of_its_5_hour_window_goes_to_sonnet_and_says_why() -> None:
    r = recommend(DOC, "research", {"five_hour": 83.0, "weekly": 10.0})
    assert r.agent == "claude-sonnet" and r.card_label == "Claude"
    assert "codex: the 5-hour window is at 83%, above 80%" in r.why
    assert r.reviewer is None and "no other reviewer has headroom" in r.reviewer_why


def test_the_weekly_threshold_and_the_copilot_month_threshold() -> None:
    assert recommend(DOC, "research", {"weekly": 95.0}).agent == "claude-sonnet"
    r = recommend(DOC, "small-mechanical-pr", {"monthly_percent": 75.0})
    assert r.agent == "claude-haiku" and r.reviewer == "claude-sonnet"
    assert recommend(DOC, "small-mechanical-pr", {"monthly_percent": 70.0}).agent == "copilot"


def test_unknown_headroom_never_blocks_and_is_reported() -> None:
    r = recommend(DOC, "research", {"five_hour": None, "weekly": None})
    assert r.agent == "codex" and r.unknown == ("five_hour", "weekly")


def test_nobody_has_headroom_is_said_plainly() -> None:
    data = agents_dict()
    data["thresholds"].append({"agent": "claude-lead", "meter": "weekly", "above": 10, "then": "claude-lead"})
    r = recommend(parse_agents(data), "security-sensitive-design", {"weekly": 50.0})
    assert r.agent is None and "short of headroom" in r.why


def test_an_agent_that_needs_approval_says_so() -> None:
    data = agents_dict()
    data["shapes"]["research"]["prefer"] = ["claude-opus"]
    r = recommend(parse_agents(data), "research", {})
    assert r.agent == "claude-opus" and r.needs_approval


def test_an_unknown_shape_lists_the_real_ones() -> None:
    with pytest.raises(ConfigError, match=r"has no shape 'nope' .*research"):
        recommend(DOC, "nope", {})


def test_the_local_agent_is_used_when_reachable_and_the_guard_endpoint_is_never_routed_to() -> None:
    r = recommend(DOC, "ci-log-summary", {}, UP)
    assert (r.agent, r.endpoint, r.model) == ("ollama", "instance-a", "small-4b-agent"), "short text: the 4B model"
    assert r.reviewer == "claude-sonnet", "a local draft is always reviewed by a Claude model"
    assert recommend(DOC, "issue-triage", {}, UP).model == "resident-12b-thinking", "long text: the 12B model"
    r = recommend(DOC, "issue-triage", {}, UP, model="resident-safety")
    assert r.agent == "claude-haiku", "the safety model is a guard for a production bot, never a general-purpose model"
    assert any("instance-b: not a general endpoint" in s for s in r.skipped)


def test_the_small_resident_model_is_used_when_it_is_asked_for_at_its_own_context() -> None:
    r = recommend(DOC, "changelog-draft", {}, UP, model="small-4b-agent", num_ctx=8192)
    assert (r.endpoint, r.model) == ("instance-a", "small-4b-agent")


def test_both_endpoints_unreachable_falls_back_and_says_which() -> None:
    probes = {"instance-a": probe("instance-a", up=False), "instance-b": probe("instance-b", up=False)}
    r = recommend(DOC, "ci-log-summary", {}, probes)
    assert r.agent == "claude-haiku" and any("instance-a: unreachable" in s for s in r.skipped)


def test_a_request_that_would_load_another_model_on_the_protected_endpoint_is_refused() -> None:
    """Review focus: asking the shared server for a model it does not hold evicts a resident one."""
    probes = {"instance-a": UP["instance-a"], "instance-b": probe("instance-b", up=False)}
    r = recommend(DOC, "ci-log-summary", {}, probes, model="small-7b")
    assert r.agent == "claude-haiku"
    assert any("could evict a protected one" in s for s in r.skipped)


def test_a_context_above_the_cap_is_refused_on_an_endpoint_with_no_protected_models() -> None:
    data = agents_dict()
    data["agents"]["ollama"]["endpoints"][0].update(protected_models=[], loaded_num_ctx={}, num_ctx_max=8192)
    r = recommend(parse_agents(data), "ci-log-summary", {}, {"instance-a": UP["instance-a"]}, num_ctx=16384)
    assert r.agent == "claude-haiku" and any("above the cap of 8192" in s for s in r.skipped)


def test_a_protected_model_that_is_not_resident_right_now_is_not_requested() -> None:
    probes = {"instance-a": probe("instance-a", loaded=()), "instance-b": probe("instance-b", up=False)}
    r = recommend(DOC, "ci-log-summary", {}, probes)
    assert r.agent == "claude-haiku" and any("not resident now" in s for s in r.skipped)


def test_a_context_other_than_the_loaded_one_is_refused_even_when_it_is_smaller() -> None:
    """Measured: a client sending 65536 to a model loaded at 131072 made Ollama reload it, which can evict another."""
    r = recommend(DOC, "issue-triage", {}, UP, num_ctx=65536)
    assert r.agent == "claude-haiku"
    assert any("num_ctx 65536 is not the 131072 resident-12b-thinking is loaded with" in s for s in r.skipped)
    assert recommend(DOC, "issue-triage", {}, UP, num_ctx=131072).model == "resident-12b-thinking"
    assert recommend(DOC, "ci-log-summary", {}, UP, num_ctx=8192).model == "small-4b-agent"
    assert recommend(DOC, "ci-log-summary", {}, UP, num_ctx=131072).agent == "claude-haiku"


def test_duplicate_search_loads_the_embedding_model_on_demand_beside_the_guard() -> None:
    r = recommend(DOC, "duplicate-issue-search", {}, UP)
    assert (r.endpoint, r.model) == ("instance-b", "embed-small"), "not resident, but allowed on demand"
    assert recommend(DOC, "duplicate-issue-search", {}, UP, num_ctx=2048).model == "embed-small"
    r = recommend(DOC, "duplicate-issue-search", {}, UP, num_ctx=8192)
    assert r.agent == "claude-haiku", "the guard's context is never sent for an embedding request"
    assert any("num_ctx 8192 is not the 2048 embed-small is loaded with" in s for s in r.skipped)
    r = recommend(DOC, "duplicate-issue-search", {}, UP, model="resident-safety")
    assert r.agent == "claude-haiku" and any("is a guard model" in s for s in r.skipped)
    down = {"instance-a": UP["instance-a"], "instance-b": probe("instance-b", up=False)}
    assert recommend(DOC, "duplicate-issue-search", {}, down).agent == "claude-haiku"


def test_security_shape_keeps_both_required_reviews_even_when_unavailable() -> None:
    r = recommend(DOC, "security-sensitive-code", {"five_hour": 99, "weekly": 99}, UP)
    assert {gate.reviewer for gate in r.reviews} == {"claude-sonnet", "codex"}
    assert all(gate.reason for gate in r.reviews)
    assert any(not gate.available for gate in r.reviews)
