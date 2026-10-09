# SPDX-License-Identifier: MIT
"""safo.routing against the hostile list: each case is a configuration or request that must not loosen a rule."""

from __future__ import annotations

from typing import Any

from agentsdata import B_MODELS, agents_dict
from safo.agentsfile import AgentsFile, parse_agents
from safo.ollama import Probe
from safo.routing import recommend


def probe(endpoint_id: str, loaded: tuple[str, ...] = (), up: bool = True) -> Probe:
    return Probe(endpoint_id, "http://127.0.0.1:9", up, loaded, ())


def open_endpoint() -> tuple[AgentsFile, dict[str, Any]]:
    """instance-a with no protected models, so only the allow-list and the cap decide."""
    data = agents_dict()
    data["agents"]["ollama"]["endpoints"][0].update(protected_models=[], loaded_num_ctx={}, num_ctx_max=8192)
    return parse_agents(data), data


def test_an_embedding_shape_gets_the_embedding_model_and_never_a_general_one() -> None:
    doc = parse_agents(agents_dict())
    up = {
        "instance-a": probe("instance-a", ("resident-12b-thinking", "small-4b-agent")),
        "instance-b": probe("instance-b"),
    }
    r = recommend(doc, "duplicate-issue-search", {}, up)
    assert (r.endpoint, r.model) == ("instance-b", "embed-small")
    r = recommend(doc, "duplicate-issue-search", {}, up, model="small-4b-agent")
    assert r.agent == "claude-haiku", "a general model is never asked to embed"


def test_a_model_that_is_not_allowed_on_an_open_endpoint_is_skipped_with_that_reason() -> None:
    doc, _ = open_endpoint()
    r = recommend(doc, "ci-log-summary", {}, {"instance-a": probe("instance-a")}, model="small-7b")
    assert r.agent == "claude-haiku" and any("not an allowed model" in s for s in r.skipped)


def test_a_context_equal_to_the_cap_is_allowed_and_one_above_it_is_not() -> None:
    doc, _ = open_endpoint()
    up = {"instance-a": probe("instance-a")}
    assert recommend(doc, "ci-log-summary", {}, up, num_ctx=8192).agent == "ollama"
    r = recommend(doc, "ci-log-summary", {}, up, num_ctx=8193)
    assert r.agent == "claude-haiku" and any("above the cap of 8192" in s for s in r.skipped)


def test_a_tripped_threshold_inserts_its_replacement_right_after_it_and_says_why() -> None:
    doc = parse_agents(agents_dict())
    r = recommend(doc, "research", {"five_hour": 85.0})
    assert r.fallback_chain[:2] == ("codex", "claude-sonnet")
    assert r.agent == "claude-sonnet" and any("85%" in s for s in r.skipped)


def test_the_author_is_never_their_own_reviewer() -> None:
    doc = parse_agents(agents_dict())
    r = recommend(doc, "research", {})
    assert r.agent == "codex" and r.reviewer not in (None, "codex")
    data = agents_dict()
    data["shapes"]["research"]["prefer"] = ["claude-sonnet"]
    data["shapes"]["research"]["reviewer"] = ["claude-sonnet"]
    r = recommend(parse_agents(data), "research", {})
    assert r.reviewer is None and "no other reviewer" in r.reviewer_why


def test_a_shape_with_no_reviewers_says_no_review_is_defined() -> None:
    data = agents_dict()
    data["shapes"]["research"]["reviewer"] = []
    r = recommend(parse_agents(data), "research", {})
    assert r.reviewer is None and "no review is defined" in r.reviewer_why


def test_a_blank_model_on_a_general_shape_takes_the_endpoints_first_model() -> None:
    doc, data = open_endpoint()
    data["shapes"]["ci-log-summary"]["local"].pop("model", None)
    doc = parse_agents(data)
    r = recommend(doc, "ci-log-summary", {}, {"instance-a": probe("instance-a")}, model="")
    assert (r.endpoint, r.model) == ("instance-a", "resident-12b-thinking")


def test_headroom_for_a_meter_nobody_has_a_threshold_for_blocks_nothing_and_is_not_reported() -> None:
    doc = parse_agents(agents_dict())
    r = recommend(doc, "research", {"mystery": 99.0, "five_hour": 1.0, "weekly": 1.0})
    assert r.agent == "codex" and r.unknown == ()


def test_an_endpoint_with_no_probe_at_all_counts_as_unreachable() -> None:
    doc = parse_agents(agents_dict())
    r = recommend(doc, "ci-log-summary", {}, {})
    assert r.agent == "claude-haiku" and any("unreachable" in s for s in r.skipped)


def test_an_empty_embedding_model_name_is_not_guessed() -> None:
    doc = parse_agents(agents_dict())
    data = agents_dict()
    data["shapes"]["duplicate-issue-search"]["local"].pop("model", None)
    r = recommend(
        parse_agents(data), "duplicate-issue-search", {}, {"instance-b": probe("instance-b", tuple(B_MODELS[:1]))}
    )
    assert r.agent == "claude-haiku" and any("needs a model named" in s for s in r.skipped)
    assert doc  # the unmodified file still parses
