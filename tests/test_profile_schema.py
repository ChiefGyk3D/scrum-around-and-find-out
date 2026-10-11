# SPDX-License-Identifier: MIT
"""Spec test 1: the profile block's shape, types, bounds, requiredness and counts."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from profiledata import LESSON, MINIMAL_CLAUDE, claim, doc, loads, need, prof, profile, rejects
from safo.agentsfile import parse_agents


def test_the_two_minimal_profiles_of_the_spec_load() -> None:
    d = doc()
    d["agents"]["claude-sonnet"]["profile"] = copy.deepcopy(MINIMAL_CLAUDE)
    d["profile_migration"]["agents"] = ["claude-lead", "claude-opus"]
    parsed = parse_agents(d)
    assert prof(parsed, "claude-sonnet").status == "unmeasured"
    codex = parsed.agent("codex").profile
    assert codex is not None and codex.status == "profiled"
    assert codex.brief is not None and codex.brief.inline.startswith("Work from this prompt")
    assert codex.dont[0].text.startswith("Expect it") and codex.dont[0].evidence.kind == "lessons"


def test_an_agent_without_a_profile_block_has_none() -> None:
    assert parse_agents(doc()).agent("claude-lead").profile is None


def test_a_file_with_no_profile_at_all_still_loads_as_in_version_zero_point_one() -> None:
    d = doc()
    for agent in d["agents"].values():
        agent.pop("profile", None)
    del d["profile_migration"]
    assert all(a.profile is None for a in parse_agents(d).agents)


def test_unknown_keys_are_refused_with_the_dotted_path() -> None:
    d = doc()
    profile(d, "codex")["traits"] = []
    rejects(d, r"agents\.codex\.profile\.traits: unknown key")
    d = doc()
    profile(d, "codex")["dont"][0]["why"] = "x"
    rejects(d, r"agents\.codex\.profile\.dont\[0\]\.why: unknown key")
    d = doc()
    profile(d, "codex")["brief"]["extra"] = "x"
    rejects(d, r"agents\.codex\.profile\.brief\.extra: unknown key")


def test_a_duplicate_key_inside_a_list_entry_is_refused_by_the_shared_reader(tmp_path: Any) -> None:
    import re

    import yaml

    from profiledata import write
    from safo.agentsfile import load_agents
    from safo.errors import ConfigError

    path = write(tmp_path / "agents.yaml", doc())
    text = path.read_text()
    assert yaml.safe_load(text)
    marked = re.sub(r"( +)text: Expect it to commit inside a git worktree\.", r"\1text: a\n\1text: b", text)
    assert marked != text
    path.write_text(marked)
    with pytest.raises(ConfigError, match="duplicate key 'text'"):
        load_agents(path)


@pytest.mark.parametrize(
    ("setter", "pattern"),
    [
        (lambda p: p.update(status=1), r"profile\.status: 1 is not one of unmeasured, profiled"),
        (lambda p: p.update(status="measured"), r"profile\.status"),
        (lambda p: p.pop("status"), r"profile\.status: required"),
        (lambda p: p.update(dont="not a list"), r"profile\.dont: expected a list"),
        (lambda p: p.update(dont=["bare string"]), r"profile\.dont\[0\]: expected a mapping"),
        (lambda p: p["dont"][0].update(text=7), r"profile\.dont\[0\]\.text: expected a non-empty string"),
        (lambda p: p["dont"][0].update(text="   "), r"profile\.dont\[0\]\.text"),
        (lambda p: p["dont"][0].pop("evidence"), r"profile\.dont\[0\]\.evidence: required"),
        (lambda p: p["dont"][0].update(evidence=3), r"profile\.dont\[0\]\.evidence"),
        (lambda p: p.update(brief="text"), r"profile\.brief: expected a mapping"),
        (lambda p: p.update(brief={}), r"profile\.brief: needs exactly one of template or inline"),
        (
            lambda p: p.update(brief={"inline": "x", "template": "a.md"}),
            r"profile\.brief: needs exactly one of template or inline",
        ),
        (lambda p: p.update(brief={"inline": 5}), r"profile\.brief\.inline"),
        (lambda p: p.update(brief={"inline": "x" * 4001}), r"profile\.brief\.inline: .*4000"),
        (lambda p: p.update(context_ceiling=4096), r"profile\.context_ceiling: expected a mapping"),
        (lambda p: p.update(context_ceiling={"value": 4096}), r"profile\.context_ceiling\.evidence: required"),
        (lambda p: p.update(persona="x"), r"profile\.persona: only a claude agent has a persona"),
        (lambda p: p.update(do=[]), None),
    ],
)
def test_wrong_types_and_shapes_name_the_dotted_path(setter: Any, pattern: str | None) -> None:
    d = doc()
    setter(profile(d, "codex"))
    if pattern is None:
        parse_agents(d)
    else:
        rejects(d, pattern)


def test_the_brief_inline_edge_is_four_thousand_characters() -> None:
    d = doc()
    profile(d, "codex")["brief"] = {"inline": "x" * 4000}
    assert need(prof(parse_agents(d), "codex").brief).inline == "x" * 4000


CEILING = {"value": 4096, "evidence": LESSON}


@pytest.mark.parametrize(
    ("key", "value", "ok"),
    [
        ("context_ceiling", 1023, False),
        ("context_ceiling", 1024, True),
        ("context_ceiling", 2_000_000, True),
        ("context_ceiling", 2_000_001, False),
        ("context_ceiling", True, False),
        ("context_ceiling", 4096.0, False),
        ("context_ceiling", "4096", False),
        ("output_cap", 63, False),
        ("output_cap", 64, True),
        ("output_cap", 200_000, True),
        ("output_cap", 200_001, False),
        ("output_cap", False, False),
    ],
)
def test_ceiling_and_cap_bounds_and_the_bool_trap(key: str, value: Any, ok: bool) -> None:
    d = doc()
    profile(d, "codex")[key] = {"value": value, "evidence": LESSON}
    if ok:
        assert getattr(parse_agents(d).agent("codex").profile, key).value == value
    else:
        rejects(d, rf"profile\.{key}\.value: expected an integer")


def test_the_output_cap_may_not_exceed_the_context_ceiling() -> None:
    d = doc()
    p = profile(d, "codex")
    p["context_ceiling"] = {"value": 4096, "evidence": LESSON}
    p["output_cap"] = {"value": 4097, "evidence": LESSON}
    rejects(d, r"profile\.output_cap\.value: .* at most the context_ceiling")
    p["output_cap"]["value"] = 4096
    assert need(prof(parse_agents(d), "codex").output_cap).value == 4096


def test_thinking_takes_only_off_default_or_on() -> None:
    d = doc()
    for value in ("off", "default", "on"):
        profile(d, "codex")["thinking"] = {"value": value, "evidence": LESSON}
        assert need(prof(parse_agents(d), "codex").thinking).value == value
    profile(d, "codex")["thinking"]["value"] = "high"
    rejects(d, r"profile\.thinking\.value")
    profile(d, "codex")["thinking"]["value"] = True
    rejects(d, r"profile\.thinking\.value")


def test_every_list_is_capped_at_eight_entries() -> None:
    d = doc()
    p = profile(d, "codex")
    p["dont"] = [claim(f"Entry number {i} is distinct.") for i in range(8)]
    assert len(prof(parse_agents(d), "codex").dont) == 8
    p["dont"].append(claim("Entry number eight is distinct."))
    rejects(d, r"profile\.dont: at most 8 entries")
    d = doc()
    profile(d, "codex")["do"] = [claim(f"Entry number {i} is distinct.") for i in range(9)]
    rejects(d, r"profile\.do: at most 8 entries")
    d = doc()
    profile(d, "codex")["must_not_get"] = [{"shape": "research", "evidence": LESSON}] * 9
    rejects(d, r"profile\.must_not_get: at most 8 entries")


def _full(d: dict[str, Any]) -> None:
    for agent in ("codex", "claude-haiku", "copilot", "ollama"):
        p = profile(d, agent)
        p["status"] = "profiled"
        p["do"] = [claim(f"{agent} do entry {i}.") for i in range(8)]
        p["dont"] = [claim(f"{agent} dont entry {i}.") for i in range(8)]


def test_the_whole_file_is_capped_at_sixty_four_entries() -> None:
    d = doc()
    _full(d)
    parse_agents(d)  # exactly 64: four agents with 16 each
    d["agents"]["claude-sonnet"]["profile"] = {"status": "profiled", "persona": "reviewer", "do": [claim("Extra.")]}
    d["profile_migration"]["agents"] = ["claude-lead", "claude-opus"]
    rejects(d, r"profiles: at most 64 entries in the file")


@pytest.mark.parametrize(
    ("agent", "status", "brief_ok"),
    [
        ("claude-haiku", "unmeasured", False),
        ("claude-haiku", "profiled", False),
        ("codex", "unmeasured", False),
        ("codex", "profiled", False),
        ("ollama", "unmeasured", False),
        ("ollama", "profiled", False),
        ("copilot", "unmeasured", True),
        ("copilot", "profiled", True),
    ],
)
def test_brief_requiredness_by_harness_and_status(agent: str, status: str, brief_ok: bool) -> None:
    d = doc()
    p = profile(d, agent)
    p.pop("brief", None)
    p["status"] = status
    if status == "profiled":
        p["dont"] = [claim()]
    else:
        p.pop("dont", None)
    if brief_ok:
        parse_agents(d)
    else:
        rejects(d, rf"agents\.{agent}\.profile\.brief: required")


def test_a_claude_profile_may_name_a_persona_instead_of_a_brief_and_other_kinds_may_not() -> None:
    d = doc()
    p = profile(d, "claude-haiku")
    p.pop("brief")
    rejects(d, r"profile\.brief: required")
    p["persona"] = "transcriber"
    assert prof(parse_agents(d), "claude-haiku").persona == "transcriber"
    p["persona"] = "../escape"
    rejects(d, r"profile\.persona")
    p["persona"] = ""
    rejects(d, r"profile\.persona")
    p["persona"] = "Has Space"
    rejects(d, r"profile\.persona")
    d = doc()
    profile(d, "codex")["persona"] = "transcriber"
    rejects(d, r"agents\.codex\.profile\.persona: only a claude agent has a persona")


def test_a_human_takes_no_profile() -> None:
    d = doc()
    d["agents"]["maintainer"]["profile"] = {"status": "unmeasured", "brief": {"inline": "x"}}
    rejects(d, r"agents\.maintainer\.profile: a human takes no profile")


def test_the_profile_block_must_be_a_mapping() -> None:
    d = doc()
    d["agents"]["codex"]["profile"] = ["status"]
    rejects(d, r"agents\.codex\.profile: expected a mapping")
    d["agents"]["codex"]["profile"] = None
    rejects(d, r"agents\.codex\.profile: expected a mapping")


def test_the_promotion_block_defaults_validates_and_has_bounds() -> None:
    assert (lambda p: (p.min_outcomes, p.min_distinct_dates, p.window_days))(parse_agents(doc()).promotion) == (
        10,
        3,
        180,
    )
    for key, low, high in (("min_outcomes", 3, 1000), ("min_distinct_dates", 1, 30), ("window_days", 30, 730)):
        for value, ok in ((low - 1, False), (low, True), (high, True), (high + 1, False), (True, False), ("5", False)):
            d = doc()
            d["promotion"] = {key: value}
            if ok:
                assert getattr(parse_agents(d).promotion, key) == value
            else:
                rejects(d, rf"promotion\.{key}: expected an integer")
    d = doc()
    d["promotion"] = {"min_outcomes": 10, "extra": 1}
    rejects(d, r"promotion\.extra: unknown key")
    d["promotion"] = [10]
    rejects(d, r"promotion: expected a mapping")


def test_the_loaded_file_carries_the_same_profile_as_the_parsed_dict(tmp_path: Any) -> None:
    from_file = loads(tmp_path, doc())
    assert from_file.agent("codex").profile == parse_agents(doc()).agent("codex").profile
