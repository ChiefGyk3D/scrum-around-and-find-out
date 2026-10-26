# SPDX-License-Identifier: Apache-2.0
"""The branch gate: the default branch of every listed repository must require the gate check. Read-only."""

from __future__ import annotations

import argparse
import dataclasses
from collections.abc import Iterator
from typing import Any

import pytest

from fakegh import FakeGitHub
from fakegh.core import FRepo
from safo.graphql import Client
from safo.modes.audit import run
from safo.schema import Board, Rules
from world import build_world, load_test_board, make_context

WIDGETS = "acme/widgets"
ACTIONS = 15368  # GitHub Actions' app id, the default for rules.gate_check_app_id


@pytest.fixture(autouse=True)
def _gate_sends_no_mutations(fake: FakeGitHub) -> Iterator[None]:
    yield
    assert fake.mutations == [], "the gate read must never mutate"


def classic(*contexts: str, force: bool = False, app: int | None = ACTIONS) -> dict[str, Any]:
    """A classic rule; `app` is the app each required check is pinned to (None: any source)."""
    return {
        "requiresStatusChecks": bool(contexts),
        "requiredStatusChecks": [{"context": c, "app": None if app is None else {"databaseId": app}} for c in contexts],
        "allowsForcePushes": force,
        "isAdminEnforced": True,
        "bypassForcePushAllowances": {"totalCount": 0},
        "bypassPullRequestAllowances": {"totalCount": 0},
    }


def ruleset(
    *contexts: str,
    include: tuple[str, ...] = ("~DEFAULT_BRANCH",),
    exclude: tuple[str, ...] = (),
    enforcement: str = "ACTIVE",
    target: str = "BRANCH",
    no_force: bool = True,
    integration: int | None = ACTIONS,
) -> dict[str, Any]:
    """A ruleset; `integration` is the integration id each required check is pinned to (None: any source)."""
    rules: list[dict[str, Any]] = []
    if contexts:
        rules.append(
            {
                "type": "REQUIRED_STATUS_CHECKS",
                "parameters": {
                    "requiredStatusChecks": [{"context": c, "integrationId": integration} for c in contexts]
                },
            }
        )
    if no_force:
        rules.append({"type": "NON_FAST_FORWARD", "parameters": None})
    return {
        "name": "protect",
        "enforcement": enforcement,
        "target": target,
        "bypassActors": {"totalCount": 0, "nodes": []},
        "conditions": {"refName": {"include": list(include), "exclude": list(exclude)}},
        "rules": {"totalCount": len(rules), "nodes": rules},
    }


def with_rules(board: Board, **changes: Any) -> Board:
    return dataclasses.replace(board, rules=dataclasses.replace(board.rules, **changes))


def gate(fake: FakeGitHub, client: Client, board: Board | None = None) -> tuple[int, list[str]]:
    ctx, out = make_context(fake, board or load_test_board(), client)
    code = run(ctx, argparse.Namespace())
    return code, out.getvalue().splitlines()


def lines(text: list[str], word: str) -> list[str]:
    return [t for t in text if t.startswith("DRIFT") and "NO-GATE" in t and word in t]


def repo(fake: FakeGitHub, name: str = WIDGETS) -> FRepo:
    return fake.repos[name]


def test_protected_with_the_check_is_clean(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    code, text = gate(fake, client)
    assert code == 0 and text[-1] == "clean"
    assert not [t for t in text if "NO-GATE" in t]


def test_a_workflow_prefix_does_not_matter_and_a_different_check_does(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = classic("ci / CI green")
    repo(fake, "acme/manuals").protection = classic("lint")
    code, text = gate(fake, client)
    assert code == 1
    assert not lines(text, "acme/widgets")
    (found,) = lines(text, "acme/manuals")
    assert "default branch 'main' is protected but does not require the check 'CI green'" in found


@pytest.mark.parametrize(
    "context",
    [
        "CI green ",  # trailing space
        " CI green",
        "\u0421I green",  # a Cyrillic capital Es for the C
        "ci green",  # case
        "CI Green",
        "ci /CI green",  # the prefix separator is exactly " / "
        "x/ CI green",
        "CI green / extra",
    ],
)
def test_a_lookalike_context_does_not_satisfy_the_check(fake: FakeGitHub, client: Client, context: str) -> None:
    build_world(fake)
    repo(fake).protection = classic(context)
    code, text = gate(fake, client)
    assert code == 1 and "does not require the check" in lines(text, WIDGETS)[0]


def test_a_name_that_only_ends_the_same_way_is_not_the_gate(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = classic("not CI green", "ci/CI green")
    code, text = gate(fake, client)
    assert code == 1 and lines(text, "acme/widgets")


def test_protection_without_the_check_is_named(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = classic()
    code, text = gate(fake, client)
    assert code == 1
    (found,) = lines(text, WIDGETS)
    assert found.startswith("DRIFT   NO-GATE acme/widgets") and "does not require the check" in found


def test_ruleset_only_protection_counts(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = None
    repo(fake).rulesets = [ruleset("ci / CI green")]
    code, text = gate(fake, client)
    assert code == 0 and text[-1] == "clean"


def test_a_ruleset_that_does_not_apply_does_not_count(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = None
    for other in (
        ruleset("CI green", enforcement="DISABLED"),
        ruleset("CI green", enforcement="EVALUATE"),
        ruleset("CI green", target="TAG"),
        ruleset("CI green", include=("refs/heads/release",)),
        ruleset("CI green", exclude=("~DEFAULT_BRANCH",)),
        ruleset("CI green", exclude=("refs/heads/ma*",), include=("~ALL",)),
    ):
        repo(fake).rulesets = [other]
        code, text = gate(fake, client)
        assert code == 1, other
        assert "has no branch protection and no active ruleset" in lines(text, WIDGETS)[0]


def test_a_ruleset_naming_the_branch_or_all_branches_applies(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = None
    for include in (("refs/heads/main",), ("~ALL",), ("refs/heads/ma*",)):
        repo(fake).rulesets = [ruleset("CI green", include=include)]
        code, _ = gate(fake, client)
        assert code == 0, include


def test_unprotected_with_no_rule_and_no_ruleset_is_a_finding_for_each_repository(
    fake: FakeGitHub, client: Client
) -> None:
    build_world(fake)
    for name in (WIDGETS, "acme/manuals"):
        repo(fake, name).protection = None
    code, text = gate(fake, client)
    assert code == 1
    assert len([t for t in text if "NO-GATE" in t]) == 2
    assert "has no branch protection and no active ruleset" in lines(text, "acme/manuals")[0]
    assert text[-1] == "2 drift, 0 unknown"


def test_force_pushes_allowed_is_named_and_a_ruleset_can_forbid_them(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = classic("CI green", force=True)
    code, text = gate(fake, client)
    assert code == 1 and "allows force pushes" in lines(text, WIDGETS)[0]
    repo(fake).rulesets = [ruleset(no_force=True)]
    code, _ = gate(fake, client)
    assert code == 0
    repo(fake).protection = None
    repo(fake).rulesets = [ruleset("CI green", no_force=False)]
    code, text = gate(fake, client)
    assert code == 1 and "allows force pushes" in lines(text, WIDGETS)[0]


def test_both_problems_in_one_finding(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = classic("lint", force=True)
    _, text = gate(fake, client)
    (found,) = lines(text, WIDGETS)
    assert "does not require the check" in found and "allows force pushes" in found


def test_the_force_push_rule_can_be_turned_off(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = classic("CI green", force=True)
    code, _ = gate(fake, client, with_rules(load_test_board(), gate_forbid_force_push=False))
    assert code == 0


def test_the_check_name_is_configurable_and_empty_turns_the_rule_off_with_a_note(
    fake: FakeGitHub, client: Client
) -> None:
    build_world(fake)
    repo(fake).protection = repo(fake, "acme/manuals").protection = classic("ci / build")
    code, text = gate(fake, client, with_rules(load_test_board(), gate_check="build"))
    assert code == 0
    code, text = gate(fake, client, with_rules(load_test_board(), gate_check=""))
    assert code == 0 and not [t for t in text if t.startswith(("DRIFT", "UNKNOWN")) and "NO-GATE" in t]
    assert any(t.startswith("NOTE") and "NO-GATE (all repositories)" in t for t in text)


def test_a_default_branch_other_than_main_is_read_and_named(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).default_branch = "trunk"
    repo(fake).protection = None
    repo(fake).rulesets = [ruleset("CI green", include=("refs/heads/main",))]  # protects main, not trunk
    code, text = gate(fake, client)
    assert code == 1 and "default branch 'trunk'" in lines(text, WIDGETS)[0]
    repo(fake).rulesets = [ruleset("CI green", include=("refs/heads/trunk",))]
    code, _ = gate(fake, client)
    assert code == 0


def test_permission_denied_is_cannot_tell_never_a_pass(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).viewer_permission = "NONE"
    code, text = gate(fake, client)
    assert code == 2
    (found,) = [t for t in text if t.startswith("UNKNOWN") and WIDGETS in t and "protection" in t]
    assert "Administration: read" in found


def test_http_403_is_cannot_tell(fake: FakeGitHub, client: Client) -> None:
    from fakegh.core import Fault

    build_world(fake)
    fake.faults.append(Fault(403, body='{"message":"Resource not accessible by integration"}', op="RepoBranchGate"))
    code, text = gate(fake, client)
    assert code == 2 and any(t.startswith("UNKNOWN") and "branch protection" in t for t in text)


def test_an_empty_answer_without_admin_is_cannot_tell_but_with_admin_is_unprotected(
    fake: FakeGitHub, client: Client
) -> None:
    """GraphQL hides rules from a token that cannot see them: an empty read proves nothing unless the token is admin."""
    build_world(fake)
    repo(fake).protection = None
    repo(fake).viewer_permission = "WRITE"
    code, text = gate(fake, client)
    assert code == 2 and not lines(text, WIDGETS)
    assert any(t.startswith("UNKNOWN") and WIDGETS in t and "Administration: read" in t for t in text)
    repo(fake).viewer_permission = "ADMIN"
    code, text = gate(fake, client)
    assert code == 1 and lines(text, WIDGETS)


def test_a_positive_finding_needs_no_admin_but_a_clean_pass_does(fake: FakeGitHub, client: Client) -> None:
    """A bypass that is listed is evidence whoever reads it; "no bypass" is believed only from an ADMIN token (#180)."""
    build_world(fake)
    repo(fake).viewer_permission = "READ"
    assert gate(fake, client)[0] == 2
    repo(fake).protection = classic("CI green") | {"bypassForcePushAllowances": {"totalCount": 1}}
    assert gate(fake, client)[0] == 1
    repo(fake).viewer_permission = "ADMIN"
    repo(fake).protection = classic("CI green")
    assert gate(fake, client)[0] == 0


def test_an_unknown_outranks_a_finding_in_the_exit_code(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = None
    repo(fake, "acme/manuals").viewer_permission = "NONE"
    code, text = gate(fake, client)
    assert code == 2 and lines(text, WIDGETS)


def test_an_archived_repository_is_skipped_with_a_note(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = None
    repo(fake).archived = True
    code, text = gate(fake, client)
    assert code == 0
    assert any(t.startswith("NOTE") and WIDGETS in t and "archived" in t for t in text)


def test_a_repository_with_no_default_branch_yet_is_a_note(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).default_branch = None
    code, text = gate(fake, client)
    assert code == 0 and any(t.startswith("NOTE") and WIDGETS in t and "no default branch" in t for t in text)


def test_an_exempt_repository_is_not_read(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = None
    code, _ = gate(fake, client, with_rules(load_test_board(), gate_exempt_repos=(WIDGETS,)))
    assert code == 0
    assert fake.requests.count("RepoBranchGate") == 1  # acme/manuals only


def test_a_repository_the_token_cannot_see_is_cannot_tell(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).installed = False
    code, text = gate(fake, client)
    assert code == 2 and any(t.startswith("UNKNOWN") and WIDGETS in t for t in text)


def test_a_truncated_ruleset_list_is_cannot_tell(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = None
    repo(fake).rulesets = [ruleset("CI green")]

    def lying(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        from fakegh.gate_ops import branch_gate

        data = branch_gate(f, v)
        data["repository"]["rulesets"]["totalCount"] = 99
        return data

    fake.handlers["RepoBranchGate"] = lying
    code, text = gate(fake, client)
    assert code == 2 and any(t.startswith("UNKNOWN") and "rulesets" in t for t in text)


def test_a_malformed_answer_is_cannot_tell(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    fake.handlers["RepoBranchGate"] = lambda f, v: {"repository": {"defaultBranchRef": 7}}
    code, _ = gate(fake, client)
    assert code == 2


def test_the_rule_defaults_and_parses(tmp_path: Any) -> None:
    from safo.errors import ConfigError
    from safo.schema import load_board

    assert Rules().gate_check == "CI green" and Rules().gate_forbid_force_push is True
    src = (load_test_board_path()).read_text(encoding="utf-8")
    ok = tmp_path / "b.yaml"
    ok.write_text(src + "\n", encoding="utf-8")  # unchanged board: defaults apply
    assert load_board(ok).rules.gate_check == "CI green"
    bad = tmp_path / "bad.yaml"
    bad.write_text(src.replace("\nrules:\n", "\nrules:\n  gate_forbid_force_push: maybe\n", 1), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_board(bad)
    bad.write_text(src.replace("\nrules:\n", "\nrules:\n  gate_exempt_repos: [nope]\n", 1), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_board(bad)
    bad.write_text(src.replace("\nrules:\n", "\nrules:\n  gate_check: ' CI green'\n", 1), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_board(bad)


def load_test_board_path() -> Any:
    from world import DATA

    return DATA / "board.yaml"
