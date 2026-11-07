# SPDX-License-Identifier: Apache-2.0
"""research-route and research-ladder (#353): the dispatch guard's research discipline. Warn only, never deny.

A research brief that goes to an agent type without a search tool, or that names no `research:` ladder, is flagged.
Every rule has a test that fails when the rule is removed, a brief that must stay clean, and a switch that turns it off.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from hooksdata import agents_file, dispatch, hooks, read_log, set_mode, state_folder
from safo.agentsfile import load_agents
from safo.errors import ConfigError
from safo.guardlog import RULE_IDS, summarise
from safo.guardlog import read_log as read_guard_log
from test_hooks import guard, read_after, reason

TUXEDO = "Find what Tuxedo says about the Intel ME in its own press release."
LADDER = "research: prior art, vendor page, web search (query: tuxedo computers intel me), archive, live system"


@pytest.fixture
def agents(tmp_path: Path) -> Path:
    return agents_file(tmp_path / "agents.yaml")


def rules(home: Path, agents: Path, **kw: Any) -> list[str]:
    prompt = kw.pop("prompt")
    return list(
        read_after(home, agents, dispatch(prompt=prompt + "\nlocal-llm: n/a - no text work here", **kw))["rules"]
    )


def test_research_to_a_type_without_search_warns_with_a_route_message(_private_home: Path, agents: Path) -> None:
    payload = dispatch(prompt=TUXEDO + "\n" + LADDER + "\nlocal-llm: n/a - x", subagent_type="implementer")
    code, out, _ = guard(_private_home, agents, payload)
    assert code == 0 and "research-route" in reason(out) and "route the research" in reason(out).lower()
    assert read_log(_private_home)[-1]["rules"] == ["research-route"]


def test_research_routed_to_a_type_with_search_passes_cleanly(_private_home: Path, agents: Path) -> None:
    for kind in ("general-purpose", "Explore", "codex:codex-rescue", "claude-code-guide"):
        got = rules(_private_home, agents, prompt=TUXEDO + "\n" + LADDER, subagent_type=kind)
        assert got == [], kind


def test_a_verified_brief_with_a_research_line_passes(_private_home: Path, agents: Path) -> None:
    prompt = "Verify the vendor page against the advisory.\n" + LADDER
    assert rules(_private_home, agents, prompt=prompt) == []


def test_an_implementer_brief_asking_to_verify_a_vendor_claim_warns(_private_home: Path, agents: Path) -> None:
    got = rules(
        _private_home, agents, prompt="Check against the vendor page that the fix shipped.", subagent_type="implementer"
    )
    assert got == ["research-route", "research-ladder"]


def test_the_na_escape_with_a_reason_silences_both_rules(_private_home: Path, agents: Path) -> None:
    prompt = "Check against the vendor page.\nresearch: n/a - the page text is pasted below"
    assert rules(_private_home, agents, prompt=prompt, subagent_type="implementer") == []


def test_the_na_escape_needs_a_reason(_private_home: Path, agents: Path) -> None:
    prompt = "Check against the vendor page.\nresearch: n/a -"
    got = rules(_private_home, agents, prompt=prompt, subagent_type="implementer")
    assert "research-route" in got and "research-ladder" in got


def test_a_research_line_under_four_characters_does_not_count(_private_home: Path, agents: Path) -> None:
    got = rules(_private_home, agents, prompt="Find what the vendor says.\nresearch: yes")
    assert got == ["research-ladder"]


def test_the_ladder_message_names_every_rung_and_the_stop_rule(_private_home: Path, agents: Path) -> None:
    _, out, _ = guard(_private_home, agents, dispatch(prompt=TUXEDO + "\nlocal-llm: n/a - r"))
    text = reason(out)
    for rung in ("prior art", "vendor page", "web search", "archive", "live system", "two distinct web search queries"):
        assert rung in text, rung


def test_an_unknown_type_warns_but_is_allowed(_private_home: Path, agents: Path) -> None:
    code, out, _ = guard(
        _private_home, agents, dispatch(prompt=TUXEDO + "\n" + LADDER + "\nlocal-llm: n/a - r", subagent_type="mystery")
    )
    assert code == 0 and "unknown subagent type" in reason(out) and "deny" not in out.split("systemMessage")[0]
    assert read_log(_private_home)[-1]["decision"] == "warn"


def test_a_missing_type_is_the_general_purpose_default(_private_home: Path, agents: Path) -> None:
    assert rules(_private_home, agents, prompt=TUXEDO + "\n" + LADDER, subagent_type=None) == []


def test_block_mode_never_denies_a_research_rule(_private_home: Path, agents: Path) -> None:
    set_mode(_private_home, "block")
    payload = dispatch(prompt=TUXEDO + "\nlocal-llm: n/a - r", subagent_type="implementer")
    code, out, _ = guard(_private_home, agents, payload)
    assert code == 0 and '"permissionDecision": "deny"' not in out and "warn mode" in out
    assert read_log(_private_home)[-1]["decision"] == "warn"


def test_a_block_mode_rule_still_denies_next_to_a_research_rule(_private_home: Path, agents: Path) -> None:
    set_mode(_private_home, "block")
    payload = dispatch(model=None, prompt=TUXEDO + "\nlocal-llm: n/a - r", subagent_type="implementer")
    assert '"permissionDecision": "deny"' in guard(_private_home, agents, payload)[1]


def test_each_rule_has_its_own_switch(_private_home: Path, tmp_path: Path) -> None:
    prompt = TUXEDO + "\nlocal-llm: n/a - r"
    off_route = agents_file(tmp_path / "a.yaml", research={"route": False})
    assert read_after(_private_home, off_route, dispatch(prompt=prompt, subagent_type="implementer"))["rules"] == [
        "research-ladder"
    ]
    off_ladder = agents_file(tmp_path / "b.yaml", research={"ladder": False})
    assert read_after(_private_home, off_ladder, dispatch(prompt=prompt, subagent_type="implementer"))["rules"] == [
        "research-route"
    ]


def test_the_keywords_and_the_search_types_come_from_agents_yaml(_private_home: Path, tmp_path: Path) -> None:
    path = agents_file(
        tmp_path / "a.yaml", research={"intent_keywords": ["consult the oracle"], "search_types": ["oracle-agent"]}
    )
    plain = "Consult the oracle about it.\nlocal-llm: n/a - r"
    assert read_after(_private_home, path, dispatch(prompt=plain, subagent_type="implementer"))["rules"] == [
        "research-route",
        "research-ladder",
    ]
    assert (
        read_after(_private_home, path, dispatch(prompt=plain + "\n" + LADDER, subagent_type="oracle-agent"))["rules"]
        == []
    )
    assert read_after(_private_home, path, dispatch(prompt=TUXEDO + "\nlocal-llm: n/a - r"))["rules"] == []


def test_bad_research_config_is_refused(tmp_path: Path) -> None:
    bad_configs: list[dict[str, Any]] = [{"route": "yes"}, {"intent_keywords": []}, {"search_types": "x"}, {"nope": 1}]
    for bad in bad_configs:
        with pytest.raises(ConfigError):
            load_agents(agents_file(tmp_path / "bad.yaml", research=bad))


ORDINARY = [
    "Summarise it. safo local run --shape ci-log-summary",
    "Triage these issues and write the summary.",
    "Pipe the log through llm-local for the digest.",
    "Run safo local run --shape issue-triage first.",
    "Refactor the loader, update the docs and add tests; make check must pass.",
]


@pytest.mark.parametrize("brief", ORDINARY)
def test_this_repos_ordinary_implementer_briefs_are_not_flagged(_private_home: Path, agents: Path, brief: str) -> None:
    assert rules(_private_home, agents, prompt=brief, subagent_type="implementer") == []


def test_the_new_rules_are_counted_by_the_status_summary(_private_home: Path, agents: Path) -> None:
    assert "research-route" in RULE_IDS and "research-ladder" in RULE_IDS
    guard(_private_home, agents, dispatch(prompt=TUXEDO + "\nlocal-llm: n/a - r", subagent_type="implementer"))
    counts = summarise(read_guard_log(state_folder(_private_home) / "log.jsonl"))
    assert dict(counts.rules) == {"research-ladder": 1, "research-route": 1}
    assert "research-route 1" in hooks("status", home=_private_home)[1]
