# SPDX-License-Identifier: MIT
"""Spec test 20: the migration cohort and deadline are pinned in code; the file can only shrink the list."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from profiledata import COHORT, doc, rejects
from safo import agentsfile
from safo.agentsfile import MIGRATION_COHORT, MIGRATION_UNTIL, load_agents, parse_agents


def test_the_cohort_and_the_deadline_are_the_values_the_maintainer_approved() -> None:
    assert MIGRATION_COHORT == ("claude-lead", "claude-sonnet", "claude-opus")
    assert dt.date(2026, 12, 31) == MIGRATION_UNTIL


def test_the_shipped_file_lists_the_whole_cohort_and_loads() -> None:
    shipped = load_agents(Path(__file__).parent.parent / "agents.yaml")
    assert shipped.profile_migration == MIGRATION_COHORT
    for agent_id in MIGRATION_COHORT:
        assert shipped.agent(agent_id).profile is None


def test_the_file_list_is_exposed_in_file_order_as_a_tuple() -> None:
    d = doc()
    d["profile_migration"]["agents"] = ["claude-opus", "claude-lead", "claude-sonnet"]
    assert parse_agents(d).profile_migration == ("claude-opus", "claude-lead", "claude-sonnet")


def test_an_agent_outside_the_cohort_without_a_profile_fails_even_when_added_to_the_list() -> None:
    d = doc()
    d["agents"]["new-agent"] = {"name": "New", "kind": "codex", "role": "Something new."}
    rejects(d, r"agents\.new-agent: needs a profile; only claude-lead, claude-sonnet, claude-opus may be unprofiled")
    d["profile_migration"]["agents"].append("new-agent")
    rejects(d, r"profile_migration\.agents\[3\]: 'new-agent' is not in the migration cohort")


def test_a_swapped_id_fails() -> None:
    d = doc()
    d["profile_migration"]["agents"] = ["claude-lead", "claude-sonnet", "codex"]
    rejects(d, r"profile_migration\.agents\[2\]: 'codex' is not in the migration cohort")
    d = doc()
    d["profile_migration"]["agents"] = ["claude-lead", "claude-sonnet", "claude-haiku"]
    rejects(d, r"profile_migration\.agents\[2\]: 'claude-haiku' is not in the migration cohort")


def test_a_cohort_agent_missing_from_the_list_must_have_a_profile() -> None:
    d = doc()
    d["profile_migration"]["agents"] = ["claude-lead", "claude-sonnet"]
    rejects(d, r"agents\.claude-opus: needs a profile")
    d["agents"]["claude-opus"]["profile"] = {"status": "unmeasured", "persona": "reviewer"}
    parse_agents(d)


def test_the_list_shrunk_to_a_subset_loads() -> None:
    d = doc()
    d["agents"]["claude-sonnet"]["profile"] = {"status": "unmeasured", "persona": "reviewer"}
    for subset in (["claude-lead", "claude-opus"], ["claude-opus"], []):
        d["agents"]["claude-lead"].pop("profile", None)
        d["agents"]["claude-opus"].pop("profile", None)
        for gone in set(COHORT) - set(subset) - {"claude-sonnet"}:
            d["agents"][gone]["profile"] = {"status": "unmeasured", "persona": "reviewer"}
        d["profile_migration"]["agents"] = subset
        assert parse_agents(d).profile_migration == tuple(subset)


def test_a_duplicate_or_non_string_entry_and_a_wrong_shape_are_refused() -> None:
    d = doc()
    d["profile_migration"]["agents"] = ["claude-lead", "claude-lead", "claude-sonnet", "claude-opus"]
    rejects(d, r"profile_migration\.agents\[1\]: 'claude-lead' is listed twice")
    d["profile_migration"]["agents"] = [3]
    rejects(d, r"profile_migration\.agents\[0\]: expected a non-empty string")
    d["profile_migration"] = ["claude-lead"]
    rejects(d, r"profile_migration: expected a mapping")
    d["profile_migration"] = {"agents": "claude-lead"}
    rejects(d, r"profile_migration\.agents: expected a list")
    d["profile_migration"] = {"agents": [], "until": "2099-01-01"}
    rejects(d, r"profile_migration\.until: unknown key")
    d["profile_migration"] = {}
    rejects(d, r"profile_migration\.agents: required")


def test_an_expired_deadline_fails_with_the_injected_clock() -> None:
    d = doc()
    parse_agents(d, today=dt.date(2026, 12, 31))  # the last day is still inside
    rejects(
        d,
        r"profile_migration: migration expired: profile these agents or mark them unmeasured",
        today=dt.date(2027, 1, 1),
    )
    rejects(d, r"migration expired", today=dt.date(2030, 6, 1))


def test_an_expired_deadline_does_not_matter_once_the_list_is_empty() -> None:
    d = doc()
    for agent_id in COHORT:
        d["agents"][agent_id]["profile"] = {"status": "unmeasured", "persona": "reviewer"}
    d["profile_migration"]["agents"] = []
    parse_agents(d, today=dt.date(2030, 1, 1))


def test_the_default_clock_is_the_real_date(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agentsfile, "_today", lambda: dt.date(2027, 3, 1))
    rejects(doc(), r"migration expired")


def test_an_agent_listed_and_profiled_loads_because_the_list_is_only_an_exemption() -> None:
    d = doc()
    d["agents"]["claude-sonnet"]["profile"] = {"status": "unmeasured", "persona": "reviewer"}
    assert parse_agents(d).agent("claude-sonnet").profile is not None


def test_a_profile_bearing_file_with_an_unprofiled_codex_agent_is_refused() -> None:
    d = doc()
    del d["agents"]["codex"]["profile"]
    rejects(d, r"agents\.codex: needs a profile")
    d = doc()
    del d["agents"]["ollama"]["profile"]
    rejects(d, r"agents\.ollama: needs a profile")
    d = doc()
    del d["agents"]["copilot"]["profile"]
    rejects(d, r"agents\.copilot: needs a profile")


def test_a_human_needs_no_profile_and_is_never_in_the_cohort() -> None:
    parse_agents(doc())  # maintainer has none
    d = doc()
    d["profile_migration"]["agents"].append("maintainer")
    rejects(d, r"profile_migration\.agents\[3\]: 'maintainer' is not in the migration cohort")


def test_without_the_migration_list_the_cohort_needs_profiles_too() -> None:
    d = doc()
    del d["profile_migration"]
    rejects(d, r"agents\.claude-lead: needs a profile")
