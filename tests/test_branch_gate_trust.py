# SPDX-License-Identifier: Apache-2.0
"""The branch gate (SAFO #180, round 2): what app pinning does not prove, and whose bypass list can be believed.

1. An app id proves the producing app, not the workflow: every workflow of a repository shares the Actions app, so a
   check pinned to it still passes but always says so in a NOTE. Required workflows are not interpreted.
2. A ruleset inherited from an organization or enterprise is administered there: an empty bypass list read from the
   repository is never believed, whatever the viewer's permission on the repository.
3. `gate_check_app_id` is a GraphQL Int.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from fakegh import FakeGitHub
from safo.errors import ConfigError
from safo.gate import Q_BRANCH_GATE
from safo.graphql import Client
from test_branch_gate import ACTIONS, WIDGETS, classic, gate, lines, repo, ruleset, with_rules
from test_branch_gate_source import load, only_widgets, unknown
from test_branch_gate_strict import RS, clean_raw, drop_path, exit_code, serve, set_path
from world import build_world, load_test_board

LIMIT = "required check is pinned to the Actions app, which every workflow in the repository can use"


def pin_notes(text: list[str]) -> list[str]:
    return [t for t in text if t.startswith("NOTE") and "pinned to" in t and "every workflow" in t]


# -- 1. the producing app is not the workflow ----


def read_failure(fake: FakeGitHub, client: Client, raw: dict[str, Any]) -> bool:
    """Exit 2 with the audit's own refusal text, and not the catch-all for an unexpected error."""
    if not fake.projects:
        build_world(fake)
    serve(fake, raw)
    code, text = gate(fake, client)
    found = [t for t in text if t.startswith("UNKNOWN") and WIDGETS in t]
    return code == 2 and len(found) == 1 and "unexpected answer" not in found[0]


def test_the_query_asks_for_the_ruleset_source_and_does_not_select_required_workflows() -> None:
    assert "source { __typename }" in Q_BRANCH_GATE
    assert "WorkflowsParameters" not in Q_BRANCH_GATE and "workflows" not in Q_BRANCH_GATE


def test_a_lookalike_workflow_pinned_to_the_actions_app_still_passes_but_says_so(
    fake: FakeGitHub, client: Client
) -> None:
    """The Codex fixture: any workflow of the repository can post `evil / CI green` as the Actions app."""
    only_widgets(fake, rulesets=[ruleset("evil / CI green")], perm="ADMIN")
    code, text = gate(fake, client)
    assert code == 0, text
    (note,) = [t for t in pin_notes(text) if WIDGETS in t]
    assert note.startswith(f"NOTE    NO-GATE {WIDGETS}: {LIMIT}"), note
    assert "docs/no-hidden-work.md" in note


def test_the_note_is_printed_for_a_classic_pin_too(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    code, text = gate(fake, client)
    assert code == 0 and len(pin_notes(text)) == 2  # both listed repositories are held only by the app pin


def test_the_note_names_a_configured_app_that_is_not_actions(fake: FakeGitHub, client: Client) -> None:
    only_widgets(fake, protection=classic("CI green", app=99), perm="ADMIN")
    repo(fake, "acme/manuals").protection = classic("CI green", app=99)
    code, text = gate(fake, client, with_rules(load_test_board(), gate_check_app_id=99))
    (note,) = [t for t in pin_notes(text) if WIDGETS in t]
    assert code == 0 and "app 99" in note and "Actions app" not in note, note


# Required workflows are not interpreted: a WORKFLOWS rule of any shape changes neither the verdict nor the NOTE.
WORKFLOW_RULES: list[Any] = [
    {"type": "WORKFLOWS", "parameters": {}},  # what GitHub answers when no fragment of the union is selected
    {"type": "WORKFLOWS", "parameters": None},
    {"type": "WORKFLOWS", "parameters": {"workflows": []}},
    {
        "type": "WORKFLOWS",  # Codex's fixture: unrelated file, another repository, mutable ref, not enforced on create
        "parameters": {
            "workflows": [{"path": "noop.yml", "ref": "refs/heads/mutable", "repositoryId": 999}],
            "doNotEnforceOnCreate": True,
        },
    },
    {"type": "WORKFLOWS", "parameters": {"workflows": [{"path": "ci.yml", "ref": None, "repositoryId": 7}] * 2}},
    {"type": "WORKFLOWS", "parameters": {"workflows": "not even a list"}},
]


@pytest.mark.parametrize("rule", WORKFLOW_RULES, ids=range(len(WORKFLOW_RULES)))
def test_a_required_workflows_rule_of_any_shape_does_not_remove_the_note(
    fake: FakeGitHub, client: Client, rule: Any
) -> None:
    node = ruleset("evil / CI green")
    node["rules"]["nodes"].append(rule)
    node["rules"]["totalCount"] += 1
    only_widgets(fake, rulesets=[node], perm="ADMIN")
    code, text = gate(fake, client)
    assert code == 0, text
    assert len([t for t in pin_notes(text) if WIDGETS in t]) == 1, text


def test_a_required_workflows_rule_alone_is_not_the_gate_check(fake: FakeGitHub, client: Client) -> None:
    node = ruleset(no_force=True)
    node["rules"]["nodes"].append(WORKFLOW_RULES[3])
    node["rules"]["totalCount"] += 1
    only_widgets(fake, rulesets=[node], perm="ADMIN")
    code, text = gate(fake, client)
    assert code == 1 and "does not require the check 'CI green'" in lines(text, WIDGETS)[0]
    assert not [t for t in pin_notes(text) if WIDGETS in t]


# -- 2. an inherited ruleset's bypass list is not seen from the repository ----


@pytest.mark.parametrize("source", ["Organization", "Enterprise"])
@pytest.mark.parametrize("perm", ["ADMIN", "READ"])
def test_an_empty_bypass_list_of_an_inherited_ruleset_is_cannot_tell_even_for_an_administrator(
    fake: FakeGitHub, client: Client, source: str, perm: str
) -> None:
    only_widgets(fake, rulesets=[ruleset("CI green", source=source)], perm=perm)
    code, text = gate(fake, client)
    assert code == 2, text
    (found,) = unknown(text)
    assert source.lower() in found.lower() and "bypass" in found, found
    assert not lines(text, WIDGETS)


def test_an_inherited_ruleset_that_blocks_force_pushes_alone_is_cannot_tell_too(
    fake: FakeGitHub, client: Client
) -> None:
    only_widgets(fake, protection=classic("CI green"), rulesets=[ruleset(source="Organization")], perm="ADMIN")
    code, text = gate(fake, client)
    assert code == 2 and unknown(text)


def test_a_repository_ruleset_keeps_the_administrator_rule(fake: FakeGitHub, client: Client) -> None:
    only_widgets(fake, rulesets=[ruleset("CI green", source="Repository")], perm="ADMIN")
    assert gate(fake, client)[0] == 0


def test_a_listed_actor_of_an_inherited_ruleset_is_still_a_finding(fake: FakeGitHub, client: Client) -> None:
    node = ruleset("CI green", source="Organization") | {
        "bypassActors": {"totalCount": 1, "nodes": [{"bypassMode": "ALWAYS"}]}
    }
    only_widgets(fake, rulesets=[node], perm="ADMIN")
    code, text = gate(fake, client)
    assert code == 1 and "has 1 bypass actor" in lines(text, WIDGETS)[0]


def test_an_inherited_ruleset_that_does_not_decide_the_verdict_is_not_asked(fake: FakeGitHub, client: Client) -> None:
    inherited = ruleset("lint", no_force=False, source="Organization")
    only_widgets(fake, rulesets=[ruleset("CI green"), inherited], perm="ADMIN")
    assert gate(fake, client)[0] == 0


SOURCE = [*RS, "source"]


@pytest.mark.parametrize(
    "bad",
    [
        "absent",
        None,
        {},
        "Repository",
        5,
        [],
        {"__typename": None},
        {"__typename": "User"},
        {"__typename": "repository"},
    ],
    ids=repr,
)
def test_an_absent_or_unknown_ruleset_source_is_cannot_tell(fake: FakeGitHub, client: Client, bad: Any) -> None:
    assert exit_code(fake, client, clean_raw()) == 0
    raw = drop_path(clean_raw(), SOURCE) if bad == "absent" else set_path(clean_raw(), SOURCE, bad)
    assert read_failure(fake, client, raw)
    # also when the list is not empty, so the owner is not read only to decide about an empty list
    raw = drop_path(clean_raw(), SOURCE) if bad == "absent" else set_path(clean_raw(), SOURCE, bad)
    raw["rulesets"]["nodes"][0]["bypassActors"] = {"totalCount": 1, "nodes": [{"bypassMode": "ALWAYS"}]}
    assert read_failure(fake, client, raw)


def test_the_source_is_typed_on_a_ruleset_that_does_not_count(fake: FakeGitHub, client: Client) -> None:
    raw = clean_raw()
    raw["rulesets"] = {
        "totalCount": 2,
        "nodes": [raw["rulesets"]["nodes"][0], ruleset("CI green", enforcement="DISABLED")],
    }
    del raw["rulesets"]["nodes"][1]["source"]
    assert exit_code(fake, client, raw) == 2


# -- 3. gate_check_app_id is a 32-bit Int ----


def test_the_largest_graphql_int_is_accepted(tmp_path: Path) -> None:
    assert load(tmp_path, "  gate_check_app_id: 2147483647\n").rules.gate_check_app_id == 2147483647


def test_a_larger_app_id_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as info:
        load(tmp_path, "  gate_check_app_id: 2147483648\n")
    assert "rules.gate_check_app_id" in str(info.value) and "2147483647" in str(info.value)


def test_an_answer_with_an_app_id_beyond_the_int_range_is_cannot_tell(fake: FakeGitHub, client: Client) -> None:
    rs = ruleset("CI green", integration=2147483648)
    assert exit_code(fake, client, clean_raw() | {"rulesets": {"totalCount": 1, "nodes": [rs]}}) == 2
    assert ACTIONS == 15368


# -- 4. a non-fast-forward ruleset is asked about its bypass list only when force pushes are forbidden ----


def force_only(fake: FakeGitHub, perm: str, source: str) -> None:
    """A classic rule nobody can bypass holds the check; the ruleset only blocks force pushes (empty bypass list)."""
    only_widgets(
        fake, protection=classic("CI green", force=True), rulesets=[ruleset(no_force=True, source=source)], perm=perm
    )


SOURCES = ["Repository", "Organization", "Enterprise"]


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("perm", ["READ", "WRITE", "ADMIN"])
def test_a_force_block_ruleset_is_not_asked_when_force_pushes_are_not_forbidden(
    fake: FakeGitHub, client: Client, perm: str, source: str
) -> None:
    force_only(fake, perm, source)
    code, text = gate(fake, client, with_rules(load_test_board(), gate_forbid_force_push=False))
    assert code == 0 and not unknown(text), text


@pytest.mark.parametrize(
    "source,perm,code",
    [
        ("Repository", "ADMIN", 0),
        ("Repository", "READ", 2),
        ("Repository", "WRITE", 2),
        ("Organization", "ADMIN", 2),
        ("Enterprise", "ADMIN", 2),
        ("Organization", "READ", 2),
    ],
)
def test_the_same_ruleset_is_asked_when_force_pushes_are_forbidden(
    fake: FakeGitHub, client: Client, source: str, perm: str, code: int
) -> None:
    force_only(fake, perm, source)
    got, text = gate(fake, client)
    assert got == code, text
    assert bool(unknown(text)) == (code == 2)


def test_an_inherited_force_block_next_to_a_repository_check_does_not_matter_when_not_forbidden(
    fake: FakeGitHub, client: Client
) -> None:
    only_widgets(
        fake,
        rulesets=[ruleset("CI green", no_force=False), ruleset(source="Organization")],
        perm="ADMIN",
    )
    code, text = gate(fake, client, with_rules(load_test_board(), gate_forbid_force_push=False))
    assert code == 0 and not unknown(text), text


# -- 5. a missing field is refused with the audit's own text, not the catch-all for an unexpected error ----


def refusal(fake: FakeGitHub, client: Client, raw: dict[str, Any]) -> str:
    if not fake.projects:
        build_world(fake)
    serve(fake, raw)
    _, text = gate(fake, client)
    (found,) = [t for t in text if t.startswith("UNKNOWN") and WIDGETS in t]
    return found


def classic_answer() -> dict[str, Any]:
    raw = clean_raw()
    raw["rulesets"] = {"totalCount": 0, "nodes": []}
    raw["defaultBranchRef"]["branchProtectionRule"] = classic("CI green")
    return raw


def absent_integration_id() -> dict[str, Any]:
    raw = clean_raw()
    del raw["rulesets"]["nodes"][0]["rules"]["nodes"][0]["parameters"]["requiredStatusChecks"][0]["integrationId"]
    return raw


def absent_app() -> dict[str, Any]:
    raw = classic_answer()
    del raw["defaultBranchRef"]["branchProtectionRule"]["requiredStatusChecks"][0]["app"]
    return raw


def absent_rule_parameters() -> dict[str, Any]:
    raw = clean_raw()
    del raw["rulesets"]["nodes"][0]["rules"]["nodes"][0]["parameters"]
    return raw


def absent_default_branch_ref() -> dict[str, Any]:
    raw = clean_raw()
    del raw["defaultBranchRef"]
    return raw


def absent_protection_rule() -> dict[str, Any]:
    raw = clean_raw()
    del raw["defaultBranchRef"]["branchProtectionRule"]
    return raw


ABSENCES = {
    "integrationId": (absent_integration_id, "lacks integrationId"),
    "app": (absent_app, "lacks app"),
    "rule parameters": (absent_rule_parameters, "rule parameters: GitHub's answer lacks them"),
    "defaultBranchRef": (absent_default_branch_ref, "defaultBranchRef: GitHub's answer lacks it"),
    "branchProtectionRule": (absent_protection_rule, "branchProtectionRule: GitHub's answer lacks it"),
}


@pytest.mark.parametrize("name", sorted(ABSENCES))
def test_an_absent_field_is_refused_with_the_audits_own_text(fake: FakeGitHub, client: Client, name: str) -> None:
    make, expected = ABSENCES[name]
    found = refusal(fake, client, make())
    assert expected in found, found
    assert "unexpected answer" not in found
