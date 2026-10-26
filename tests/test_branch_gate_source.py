# SPDX-License-Identifier: Apache-2.0
"""The branch gate (SAFO #180): hidden bypass data is never "no bypass", and a required check must come from the CI app.

1. GitHub shows bypass actors and allowances only to a token that can administer the repository, so an empty list or a
   zero count read with a lower permission may hide a bypass: cannot tell, unless the token reports ADMIN.
2. A required status check with no source restriction can be satisfied by any app that posts a status with that name,
   and one tied to another app is not the CI app: a finding, unless the check is pinned to `rules.gate_check_app_id`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from fakegh import FakeGitHub
from safo.errors import ConfigError
from safo.gate import Q_BRANCH_GATE
from safo.graphql import Client
from safo.schema import Board, load_board
from test_branch_gate import ACTIONS, WIDGETS, classic, gate, lines, repo, ruleset, with_rules
from world import DATA, build_world, load_test_board

OTHER = 99
SRC = (DATA / "board.yaml").read_text(encoding="utf-8")


def unknown(text: list[str]) -> list[str]:
    return [t for t in text if t.startswith("UNKNOWN") and WIDGETS in t]


def only_widgets(fake: FakeGitHub, *, protection: Any = None, rulesets: list[Any] | None = None, perm: str) -> None:
    build_world(fake)
    repo(fake).protection = protection
    repo(fake).rulesets = rulesets or []
    repo(fake).viewer_permission = perm


# -- 1. an empty bypass list or a zero allowance count is trusted only from an administrator ---------------------------

LOWER = ["MAINTAIN", "WRITE", "TRIAGE", "READ"]


@pytest.mark.parametrize("perm", LOWER)
def test_an_empty_ruleset_bypass_list_from_a_non_admin_is_cannot_tell(
    fake: FakeGitHub, client: Client, perm: str
) -> None:
    only_widgets(fake, rulesets=[ruleset("CI green")], perm=perm)
    code, text = gate(fake, client)
    assert code == 2, text
    (found,) = unknown(text)
    assert "bypass" in found and perm in found and "ADMIN" in found, found
    assert not lines(text, WIDGETS)


def test_an_empty_ruleset_bypass_list_from_an_administrator_is_none(fake: FakeGitHub, client: Client) -> None:
    only_widgets(fake, rulesets=[ruleset("CI green")], perm="ADMIN")
    code, text = gate(fake, client)
    assert code == 0 and text[-1] == "clean"


def test_a_bypass_actor_that_is_listed_is_a_finding_whatever_the_permission(fake: FakeGitHub, client: Client) -> None:
    actors = {"totalCount": 1, "nodes": [{"bypassMode": "ALWAYS"}]}
    only_widgets(fake, rulesets=[ruleset("CI green") | {"bypassActors": actors}], perm="READ")
    code, text = gate(fake, client)
    assert code == 1 and not unknown(text)
    assert "has 1 bypass actor" in lines(text, WIDGETS)[0]


def test_a_ruleset_that_holds_nothing_the_gate_needs_is_not_blamed_for_its_empty_list(
    fake: FakeGitHub, client: Client
) -> None:
    only_widgets(fake, rulesets=[ruleset("lint", no_force=False)], perm="READ")
    code, text = gate(fake, client)
    assert code == 1 and not unknown(text)  # a missing check is still a finding: it does not depend on a hidden list
    assert "does not require the check 'CI green'" in lines(text, WIDGETS)[0]


def test_an_empty_list_on_the_force_rule_alone_is_cannot_tell_when_force_pushes_are_forbidden(
    fake: FakeGitHub, client: Client
) -> None:
    only_widgets(fake, protection=classic("CI green"), rulesets=[ruleset(no_force=True)], perm="READ")
    # classic holds the check and the force block with zero allowances (hidden), so the verdict is cannot tell
    code, text = gate(fake, client)
    assert code == 2 and unknown(text)


def test_a_check_whose_ruleset_list_is_empty_is_cannot_tell_even_if_force_pushes_are_not_forbidden(
    fake: FakeGitHub, client: Client
) -> None:
    only_widgets(fake, rulesets=[ruleset("CI green", no_force=False)], perm="READ")
    board = with_rules(load_test_board(), gate_forbid_force_push=False)
    code, text = gate(fake, client, board)
    assert code == 2 and unknown(text)


def test_a_zero_force_push_allowance_count_from_a_non_admin_is_cannot_tell(fake: FakeGitHub, client: Client) -> None:
    only_widgets(fake, protection=classic("CI green"), perm="READ")
    code, text = gate(fake, client)
    assert code == 2, text
    (found,) = unknown(text)
    assert "bypass" in found and "ADMIN" in found, found


def test_a_zero_allowance_count_from_an_administrator_is_none(fake: FakeGitHub, client: Client) -> None:
    only_widgets(fake, protection=classic("CI green"), perm="ADMIN")
    code, text = gate(fake, client)
    assert code == 0 and text[-1] == "clean"


def test_the_zero_count_does_not_matter_when_force_pushes_are_not_forbidden(fake: FakeGitHub, client: Client) -> None:
    only_widgets(fake, protection=classic("CI green"), perm="READ")
    code, text = gate(fake, client, with_rules(load_test_board(), gate_forbid_force_push=False))
    assert code == 0 and text[-1] == "clean"  # the pull-request allowances never touch a required check


def test_a_listed_force_push_allowance_from_a_non_admin_is_a_finding(fake: FakeGitHub, client: Client) -> None:
    rule = classic("CI green") | {"bypassForcePushAllowances": {"totalCount": 2}}
    only_widgets(fake, protection=rule, perm="READ")
    code, text = gate(fake, client)
    assert code == 1 and not unknown(text)
    assert "2 actors may bypass the block" in lines(text, WIDGETS)[0]


# -- 2. the query asks for the source of each required check -----------------------------------------------------------


def test_the_query_asks_for_the_source_of_both_kinds_of_required_check() -> None:
    assert "requiredStatusChecks { context app { databaseId } }" in Q_BRANCH_GATE
    assert "requiredStatusChecks { context integrationId }" in Q_BRANCH_GATE


# -- 3. a check not pinned to the CI app is a finding ----


def test_a_check_pinned_to_the_ci_app_is_clean_in_both_mechanisms(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = classic("ci / CI green")
    repo(fake, "acme/manuals").protection = None
    repo(fake, "acme/manuals").rulesets = [ruleset("CI green")]
    code, text = gate(fake, client)
    assert code == 0 and text[-1] == "clean"


@pytest.mark.parametrize("app", [None, OTHER])
def test_a_classic_check_not_pinned_to_the_ci_app_is_a_finding(
    fake: FakeGitHub, client: Client, app: int | None
) -> None:
    build_world(fake)
    repo(fake).protection = classic("CI green", app=app)
    code, text = gate(fake, client)
    assert code == 1
    (found,) = lines(text, WIDGETS)
    assert f"does not require the check 'CI green' from app {ACTIONS}" in found, found
    assert ("classic protection accepts it from any app" if app is None else f"takes it from app {app}") in found


@pytest.mark.parametrize("integration", [None, -1, OTHER])
def test_a_ruleset_check_not_pinned_to_the_ci_app_is_a_finding(
    fake: FakeGitHub, client: Client, integration: int | None
) -> None:
    build_world(fake)
    repo(fake).protection = None
    repo(fake).rulesets = [ruleset("CI green", integration=integration)]
    code, text = gate(fake, client)
    assert code == 1
    (found,) = lines(text, WIDGETS)
    assert f"from app {ACTIONS}" in found, found
    expected = (
        "ruleset 'protect' accepts it from any app" if integration in (None, -1) else f"takes it from app {OTHER}"
    )
    assert expected in found, found


def test_a_lookalike_context_from_another_source_is_not_accepted(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = classic("ci / CI green", "evil / CI green", app=OTHER)
    code, text = gate(fake, client)
    assert code == 1 and "from app" in lines(text, WIDGETS)[0]


def test_the_ci_app_entry_counts_when_another_source_has_the_same_name(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    rule = classic("CI green")
    rule["requiredStatusChecks"].append({"context": "evil / CI green", "app": None})
    repo(fake).protection = rule
    code, _ = gate(fake, client)
    assert code == 0


def test_a_pinned_check_in_one_mechanism_holds_even_if_the_other_is_unpinned(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = classic("CI green", app=None)
    repo(fake).rulesets = [ruleset("CI green")]
    code, _ = gate(fake, client)
    assert code == 0


def test_the_expected_app_is_configurable(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = classic("CI green", app=OTHER)
    repo(fake, "acme/manuals").protection = classic("CI green", app=OTHER)
    board = with_rules(load_test_board(), gate_check_app_id=OTHER)
    code, text = gate(fake, client, board)
    assert code == 0 and text[-1] == "clean"
    code, text = gate(fake, client, with_rules(load_test_board(), gate_check_app_id=ACTIONS))
    assert code == 1 and f"from app {ACTIONS}" in lines(text, WIDGETS)[0]


def test_the_finding_is_one_line_in_the_findings_grammar(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = classic("CI green", app=None)
    _, text = gate(fake, client)
    (found,) = lines(text, WIDGETS)
    assert found.startswith(f"DRIFT   NO-GATE {WIDGETS}: default branch 'main' is protected but ")


# -- 4. strict reading: the source field is typed, never defaulted ----

CLASSIC = ["defaultBranchRef", "branchProtectionRule", "requiredStatusChecks", 0]


def served(fake: FakeGitHub, client: Client, rule: Any = None, rulesets: list[Any] | None = None) -> int:
    only_widgets(fake, protection=rule, rulesets=rulesets, perm="ADMIN")
    return gate(fake, client)[0]


BAD_APPS: list[Any] = ["absent", "x", 5, [], {}, {"databaseId": None}, {"databaseId": "15368"}, {"databaseId": True}]
BAD_APPS += [{"databaseId": 0}, {"databaseId": -2}, {"databaseId": 1.5}, {}]


@pytest.mark.parametrize("bad", BAD_APPS, ids=repr)
def test_a_classic_source_that_is_absent_or_mistyped_is_cannot_tell(fake: FakeGitHub, client: Client, bad: Any) -> None:
    rule = classic("CI green")
    if bad == "absent":
        del rule["requiredStatusChecks"][0]["app"]
    else:
        rule["requiredStatusChecks"][0]["app"] = bad
    assert served(fake, client, rule) == 2


@pytest.mark.parametrize("bad", ["absent", "15368", True, 0, -2, 1.5, [], {}], ids=repr)
def test_a_ruleset_source_that_is_absent_or_mistyped_is_cannot_tell(fake: FakeGitHub, client: Client, bad: Any) -> None:
    rs = ruleset("CI green")
    check = rs["rules"]["nodes"][0]["parameters"]["requiredStatusChecks"][0]
    if bad == "absent":
        del check["integrationId"]
    else:
        check["integrationId"] = bad
    assert served(fake, client, rulesets=[rs]) == 2


def test_the_source_is_typed_on_a_check_that_is_not_the_gate_and_on_a_disabled_ruleset(
    fake: FakeGitHub, client: Client
) -> None:
    rule = classic("lint", "CI green")
    rule["requiredStatusChecks"][0]["app"] = "x"
    assert served(fake, client, rule) == 2
    rs = ruleset("lint", enforcement="DISABLED")
    rs["rules"]["nodes"][0]["parameters"]["requiredStatusChecks"][0].pop("integrationId")
    assert served(fake, client, ruleset("CI green"), [rs]) == 2


# -- 5. rules.gate_check_app_id ---------------------------------------------------------------------------------------


def load(tmp_path: Path, lines_: str) -> Board:
    path = tmp_path / "b.yaml"
    path.write_text(SRC.replace("\nrules:\n", "\nrules:\n" + lines_, 1), encoding="utf-8")
    return load_board(path)


def test_the_default_app_is_github_actions(tmp_path: Path) -> None:
    assert load(tmp_path, "").rules.gate_check_app_id == 15368


def test_a_positive_integer_is_accepted(tmp_path: Path) -> None:
    assert load(tmp_path, "  gate_check_app_id: 99\n").rules.gate_check_app_id == 99


@pytest.mark.parametrize("value", ["0", "-1", "'15368'", "true", "1.5", "null", "[1]", "{a: 1}", "''"])
def test_anything_else_is_rejected_naming_the_key(tmp_path: Path, value: str) -> None:
    with pytest.raises(ConfigError) as info:
        load(tmp_path, f"  gate_check_app_id: {value}\n")
    assert "rules.gate_check_app_id" in str(info.value) and "integer" in str(info.value), str(info.value)
