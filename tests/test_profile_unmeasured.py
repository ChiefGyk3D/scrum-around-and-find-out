# SPDX-License-Identifier: MIT
"""Spec test 2 and the evidence rules of 1.6: an unmeasured agent has no traits; a profiled one has at least one."""

from __future__ import annotations

from typing import Any

import pytest

from profiledata import LESSON, OTHER_LESSON, OUTCOMES, claim, doc, prof, profile, rejects
from safo.agentsfile import parse_agents


@pytest.mark.parametrize(
    "extra",
    [
        {"do": [claim()]},
        {"dont": [claim()]},
        {"must_not_get": [{"shape": "research", "evidence": LESSON}]},
    ],
    ids=["do", "dont", "must_not_get"],
)
def test_traits_on_an_unmeasured_profile_fail(extra: dict[str, Any]) -> None:
    d = doc()
    profile(d, "codex").pop("dont")
    profile(d, "codex").update(extra, status="unmeasured")
    key = next(iter(extra))
    rejects(d, rf"agents\.codex\.profile\.{key}: an unmeasured agent has no traits")


def test_models_on_an_unmeasured_profile_fail_before_the_kind_check() -> None:
    d = doc()
    profile(d, "copilot")["models"] = {"gpt-x": {"status": "unmeasured"}}
    rejects(d, r"agents\.copilot\.profile\.models: an unmeasured agent has no traits")


def test_an_unmeasured_profile_may_set_persona_brief_settings_and_a_review_gate() -> None:
    d = doc()
    p = profile(d, "copilot")
    p["brief"] = {"inline": "One extra block for the issue form."}
    p["context_ceiling"] = {"value": 2048, "evidence": LESSON}
    p["output_cap"] = {"value": 512, "evidence": LESSON}
    p["thinking"] = {"value": "off", "evidence": LESSON}
    p["review_gate"] = {
        "required": True,
        "reviewer_differs": True,
        "checks": [{"code": "test_vs_behaviour", "evidence": OTHER_LESSON}],
    }
    got = parse_agents(d).agent("copilot").profile
    assert got is not None and got.status == "unmeasured" and got.review_gate is not None


def test_a_profiled_profile_needs_at_least_one_trait() -> None:
    d = doc()
    p = profile(d, "codex")
    p.pop("dont")
    rejects(d, r"agents\.codex\.profile: a profiled agent needs at least one do, dont or must_not_get entry")
    p["do"] = []
    rejects(d, r"a profiled agent needs at least one")
    p["do"] = [claim("Space its jobs against the window.")]
    parse_agents(d)
    del p["do"]
    p["must_not_get"] = [{"shape": "ops-runbook", "evidence": LESSON}]
    parse_agents(d)


def test_a_settings_only_profiled_profile_is_still_refused() -> None:
    d = doc()
    p = profile(d, "codex")
    p.pop("dont")
    p["context_ceiling"] = {"value": 4096, "evidence": LESSON}
    rejects(d, r"a profiled agent needs at least one")


@pytest.mark.parametrize("key", ["do", "dont"])
def test_a_list_entry_needs_evidence(key: str) -> None:
    d = doc()
    p = profile(d, "codex")
    p.pop("dont")
    p[key] = [{"text": "Some claim about the agent."}]
    rejects(d, rf"profile\.{key}\[0\]\.evidence: required")


def test_a_scalar_setting_needs_evidence() -> None:
    d = doc()
    profile(d, "codex")["thinking"] = {"value": "off"}
    rejects(d, r"profile\.thinking\.evidence: required")


@pytest.mark.parametrize(
    "pointer",
    [
        "",
        "   ",
        "lessons:",
        "lessons",
        "lessons:Has Capital",
        "lessons:has space",
        "lessons:" + "a" * 201,
        "lessons:../escape",
        "outcomes:v1:2026-10:codex",
        "outcomes:v2:2026-10:codex:runs>=1",
        "outcomes:v1:2026-13:codex:runs>=1",
        "outcomes:v1:2026-00:codex:runs>=1",
        "outcomes:v1:2026-10..2026-09:codex:runs>=1",
        "outcomes:v1:2026-01..2027-01:codex:runs>=1",
        "outcomes:v1:2026-10:codex:speed>=1",
        "outcomes:v1:2026-10:codex:runs!=1",
        "outcomes:v1:2026-10:codex:runs>=",
        "outcomes:v1:2026-10:codex:runs>=1e5",
        "outcomes:v1:2026-10:codex:runs>=-1",
        "outcomes:v1:2026-01..2026-02..2026-03:codex:runs>=1",
        "outcomes:v1:2026-10:codex/:runs>=1",
        "outcomes:v1:2026-10:co dex:runs>=1",
        "outcomes:v1:2026-10:a/b/c:runs>=1",
        "unknown:thing",
        "https://example.com/proof",
    ],
)
def test_a_malformed_pointer_is_refused_naming_entry_and_path(pointer: str) -> None:
    d = doc()
    profile(d, "codex")["dont"] = [claim(), claim("A second claim for the index.", pointer)]
    rejects(d, r"agents\.codex\.profile\.dont\[1\]\.evidence")


@pytest.mark.parametrize(
    "pointer",
    [
        LESSON,
        "lessons:a",
        "lessons:code-does-the-grouping-and-the-counting-the-model-writes-prose-2026-10-07",
        OUTCOMES,
        "outcomes:v1:2026-10..2027-09:codex:fix_share<=0.5",
        "outcomes:v1:2026-10:copilot/gpt-5.1:rounds_per_run>1.25",
        "outcomes:v1:2026-10:codex:findings.critical=0",
        "outcomes:v1:2026-10:codex:credits_per_run<12",
        "outcomes:v1:2026-10:codex:findings.unrated<=3",
    ],
)
def test_well_formed_pointers_are_accepted_without_touching_any_file(pointer: str) -> None:
    d = doc()
    profile(d, "codex")["dont"] = [claim("Some claim.", pointer)]
    assert prof(parse_agents(d), "codex").dont[0].evidence.raw == pointer


@pytest.mark.parametrize(
    ("pointer", "message"),
    [
        ("unknown:thing", r"expected lessons:<slug>, outcomes"),
        ("lessons:", r"expected lessons:<slug>, outcomes"),
        ("outcomes:", r"expected lessons:<slug>, outcomes"),
        ("outcomes:v1:2026-01..2026-02..2026-03:codex:runs>=1", r"range is YYYY-MM or YYYY-MM"),
        ("lessons:" + "a" * 300, r"printable characters, at most 300"),
        ("lessons:caf\u00e9", r"printable characters, at most 300"),
        ("lessons:two words", r"printable characters, at most 300"),
        ("lessons:tab\there", r"printable characters, at most 300"),
    ],
)
def test_the_pointer_error_says_which_rule_refused_it(pointer: str, message: str) -> None:
    d = doc()
    profile(d, "codex")["dont"] = [claim("Some claim.", pointer)]
    rejects(d, rf"dont\[0\]\.evidence: .*{message}")


@pytest.mark.parametrize("model", ["bad model", "caf\u00e9", "a\nb", "m" * 300])
def test_a_config_pointer_with_an_unprintable_or_overlong_segment_is_refused_by_the_character_rule(model: str) -> None:
    d = doc()
    profile(d, "codex")["context_ceiling"] = {
        "value": 4096,
        "evidence": f"config:/agents/ollama/endpoints/0/loaded_num_ctx/{model}",
    }
    rejects(d, r"context_ceiling\.evidence: .*printable characters, at most 300")


def test_the_pointer_length_edge_is_three_hundred_characters() -> None:
    head = "config:/agents/ollama/endpoints/0/loaded_num_ctx/"
    d = doc()
    profile(d, "codex")["context_ceiling"] = {"value": 4096, "evidence": head + "m" * (300 - len(head))}
    parse_agents(d)
    profile(d, "codex")["context_ceiling"]["evidence"] += "m"
    rejects(d, r"context_ceiling\.evidence: .*printable characters, at most 300")


def test_a_config_pointer_is_refused_on_every_behavioural_claim() -> None:
    pointer = "config:/agents/ollama/endpoints/0/think"
    for key in ("do", "dont"):
        d = doc()
        p = profile(d, "codex")
        p.pop("dont")
        p[key] = [claim("Some claim.", pointer)]
        rejects(d, rf"profile\.{key}\[0\]\.evidence: a config pointer cannot support a {key} claim")
    d = doc()
    profile(d, "codex")["must_not_get"] = [{"shape": "research", "evidence": pointer}]
    rejects(d, r"must_not_get\[0\]\.evidence: a config pointer cannot support")
    d = doc()
    profile(d, "codex")["output_cap"] = {"value": 512, "evidence": pointer}
    rejects(d, r"output_cap\.evidence: a config pointer cannot support")


@pytest.mark.parametrize(
    ("setting", "pointer", "ok"),
    [
        ("context_ceiling", "config:/agents/ollama/endpoints/0/num_ctx_max", True),
        ("context_ceiling", "config:/agents/ollama/endpoints/1/loaded_num_ctx/embed-small", True),
        ("context_ceiling", "config:/agents/ollama/endpoints/0/loaded_num_ctx/a~1b~0c", True),
        ("context_ceiling", "config:/agents/ollama/endpoints/0/think", False),
        ("thinking", "config:/agents/ollama/endpoints/0/think", True),
        ("thinking", "config:/agents/ollama/endpoints/0/num_ctx_max", False),
        ("thinking", "config:/agents/ollama/endpoints/0/url", False),
        ("context_ceiling", "config:/version", False),
        ("context_ceiling", "config:/agents/ollama/endpoints/x/num_ctx_max", False),
        ("context_ceiling", "config:/agents/ollama/endpoints/01/num_ctx_max", False),
        ("context_ceiling", "config:/agents/ollama/endpoints/0/loaded_num_ctx/bad~2escape", False),
        ("context_ceiling", "config:/agents/ollama/endpoints/0/loaded_num_ctx/", False),
        ("context_ceiling", "config:agents/ollama/endpoints/0/num_ctx_max", False),
        ("context_ceiling", "config:", False),
    ],
)
def test_a_config_pointer_is_valid_only_for_the_setting_its_row_names(setting: str, pointer: str, ok: bool) -> None:
    d = doc()
    value: Any = 4096 if setting == "context_ceiling" else "off"
    profile(d, "codex")[setting] = {"value": value, "evidence": pointer}
    if ok:
        parse_agents(d)
    else:
        rejects(d, rf"profile\.{setting}\.evidence")


def test_the_same_text_twice_in_one_list_or_across_do_and_dont_is_refused() -> None:
    d = doc()
    profile(d, "codex")["dont"] = [claim("Same text."), claim("  SAME   text. ", OTHER_LESSON)]
    rejects(d, r"profile\.dont\[1\]: duplicate of dont\[0\]")
    d = doc()
    profile(d, "codex")["do"] = [claim("Same text.")]
    profile(d, "codex")["dont"] = [claim("same text.")]
    rejects(d, r"profile\.dont\[0\]: duplicate of do\[0\]")
    d = doc()
    profile(d, "codex")["must_not_get"] = [
        {"shape": "research", "evidence": LESSON},
        {"shape": "research", "evidence": OTHER_LESSON},
    ]
    rejects(d, r"must_not_get\[1\]: duplicate of must_not_get\[0\]")


def test_the_same_pointer_may_support_two_different_claims() -> None:
    d = doc()
    profile(d, "codex")["do"] = [claim("First claim.")]
    profile(d, "codex")["dont"] = [claim("Second claim.")]
    parse_agents(d)
