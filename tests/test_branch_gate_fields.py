# SPDX-License-Identifier: Apache-2.0
"""The branch gate checks the type of every field it asks for, in every record it reads, relevant or not."""

from __future__ import annotations

import math
from typing import Any

import pytest

from fakegh import FakeGitHub
from safo.graphql import Client
from test_branch_gate import WIDGETS, classic, gate, lines, repo, ruleset, with_rules
from test_branch_gate_strict import RS, clean_raw, drop_path, exit_code, set_path
from world import build_world, load_test_board

CLASSIC = ["defaultBranchRef", "branchProtectionRule"]


def classic_raw(**changes: Any) -> dict[str, Any]:
    raw = clean_raw()
    raw["defaultBranchRef"]["branchProtectionRule"] = classic("CI green") | changes
    raw["rulesets"] = {"totalCount": 0, "nodes": []}
    return raw


# -- 1. requiresStatusChecks is a real boolean ----


@pytest.mark.parametrize("bad", [None, "false", "true", 0, 1, -1, 1.5, math.nan, [], {}, ["CI green"]], ids=repr)
def test_requires_status_checks_must_be_a_real_boolean(fake: FakeGitHub, client: Client, bad: Any) -> None:
    assert exit_code(fake, client, classic_raw(requiresStatusChecks=bad)) == 2


def test_requires_status_checks_true_is_accepted_and_false_is_the_drift(fake: FakeGitHub, client: Client) -> None:
    assert exit_code(fake, client, classic_raw(requiresStatusChecks=True)) == 0
    raw = classic_raw(requiresStatusChecks=False)
    assert exit_code(fake, client, raw) == 1  # drift, not cannot-tell


def test_allows_force_pushes_must_be_a_real_boolean(fake: FakeGitHub, client: Client) -> None:
    bads: list[Any] = [None, "false", 0, 1, [], {}]
    for bad in bads:
        assert exit_code(fake, client, classic_raw(allowsForcePushes=bad)) == 2, bad
    assert exit_code(fake, client, classic_raw(allowsForcePushes=False)) == 0


# -- 2. an administrator exception is visible ----


def unenforced(fake: FakeGitHub) -> None:
    for name in (WIDGETS, "acme/manuals"):
        repo(fake, name).protection = classic("CI green") | {"isAdminEnforced": False}


def notes(text: list[str]) -> list[str]:
    return [t for t in text if t.startswith("NOTE") and "gated for everyone except administrators" in t]


def test_admins_accepted_by_default_is_clean_but_noted_per_repository(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    unenforced(fake)
    code, text = gate(fake, client)
    assert code == 0 and text[-1] == "clean"
    got = notes(text)
    assert len(got) == 2
    assert any(WIDGETS in t and "rules.gate_require_admin_enforced is off" in t for t in got)


def test_the_note_is_not_printed_when_administrators_are_enforced(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    code, text = gate(fake, client)
    assert code == 0 and not notes(text)


def test_the_requirement_on_gives_the_finding_and_no_note(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    unenforced(fake)
    code, text = gate(fake, client, with_rules(load_test_board(), gate_require_admin_enforced=True))
    assert code == 1 and not notes(text) and lines(text, WIDGETS)


def test_an_accepted_repository_under_the_requirement_is_noted_with_its_reason(
    fake: FakeGitHub, client: Client
) -> None:
    build_world(fake)
    unenforced(fake)
    board = with_rules(load_test_board(), gate_require_admin_enforced=True, gate_admin_exempt_repos=(WIDGETS,))
    code, text = gate(fake, client, board)
    got = [t for t in notes(text) if WIDGETS in t]
    assert code == 1 and len(got) == 1 and "rules.gate_admin_exempt_repos" in got[0]


def test_no_note_when_another_rule_nobody_can_bypass_holds_the_check(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    unenforced(fake)
    repo(fake).rulesets = [ruleset("CI green", no_force=True)]
    code, text = gate(fake, client)
    assert code == 0 and not [t for t in notes(text) if WIDGETS in t]


# -- 3. every queried field is typed, whether or not the record counts ----


def test_name_with_owner_must_be_text_and_name_the_repository_asked_for(fake: FakeGitHub, client: Client) -> None:
    from fakegh.gate_ops import branch_gate

    build_world(fake)

    def answer(change: Any) -> Any:
        def handler(f: FakeGitHub, v: dict[str, Any]) -> Any:
            data = branch_gate(f, v)
            change(data["repository"], v)
            return data

        return handler

    fake.handlers["RepoBranchGate"] = answer(lambda r, v: r.pop("nameWithOwner"))
    assert gate(fake, client)[0] == 2
    fake.handlers["RepoBranchGate"] = answer(lambda r, v: r.update(nameWithOwner=None))
    assert gate(fake, client)[0] == 2
    fake.handlers["RepoBranchGate"] = answer(lambda r, v: r.update(nameWithOwner=7))
    assert gate(fake, client)[0] == 2
    fake.handlers["RepoBranchGate"] = answer(lambda r, v: r.update(nameWithOwner="acme/other"))
    assert gate(fake, client)[0] == 2
    fake.handlers["RepoBranchGate"] = answer(lambda r, v: r.update(nameWithOwner=f"{v['owner']}/{v['name']}".upper()))
    assert gate(fake, client)[0] == 0  # case does not matter


@pytest.mark.parametrize("bad", [None, 7, ["a"], {}], ids=repr)
def test_a_ruleset_name_must_be_text(fake: FakeGitHub, client: Client, bad: Any) -> None:
    assert exit_code(fake, client, set_path(clean_raw(), [*RS, "name"], bad)) == 2


def test_an_absent_ruleset_name_is_cannot_tell(fake: FakeGitHub, client: Client) -> None:
    assert exit_code(fake, client, drop_path(clean_raw(), [*RS, "name"])) == 2


@pytest.mark.parametrize("bad", [None, "", "SUPERUSER", "admin", "NONE", 7, ["ADMIN"]], ids=repr)
def test_viewer_permission_must_be_one_of_githubs_values(fake: FakeGitHub, client: Client, bad: Any) -> None:
    assert exit_code(fake, client, set_path(clean_raw(), ["viewerPermission"], bad)) == 2


@pytest.mark.parametrize("good", ["ADMIN", "MAINTAIN", "WRITE", "TRIAGE", "READ"])
def test_each_documented_permission_is_accepted(fake: FakeGitHub, client: Client, good: str) -> None:
    assert exit_code(fake, client, set_path(clean_raw(), ["viewerPermission"], good)) == 0


def disabled(**changes: Any) -> dict[str, Any]:
    return ruleset("CI green", enforcement="DISABLED") | changes


def with_second(raw: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    raw["rulesets"] = {"totalCount": 2, "nodes": [raw["rulesets"]["nodes"][0], node]}
    return raw


SKIPPED_BAD: dict[str, dict[str, Any]] = {
    "conditions null": {"conditions": None},
    "refName null": {"conditions": {"refName": None}},
    "include null": {"conditions": {"refName": {"include": None, "exclude": []}}},
    "exclude text": {"conditions": {"refName": {"include": [], "exclude": "x"}}},
    "bypassActors nodes null": {"bypassActors": {"totalCount": 0, "nodes": None}},
    "bypassActors absent": {"bypassActors": None},
    "bypass mode null": {"bypassActors": {"totalCount": 1, "nodes": [{"bypassMode": None}]}},
    "rules nodes null": {"rules": {"totalCount": 0, "nodes": None}},
    "rule type null": {"rules": {"totalCount": 1, "nodes": [{"type": None, "parameters": None}]}},
    "name null": {"name": None},
}


@pytest.mark.parametrize("enforcement", ["DISABLED", "EVALUATE"])
@pytest.mark.parametrize("what", sorted(SKIPPED_BAD))
def test_a_ruleset_that_does_not_count_is_still_validated(
    fake: FakeGitHub, client: Client, enforcement: str, what: str
) -> None:
    node = ruleset("CI green", enforcement=enforcement) | SKIPPED_BAD[what]
    assert exit_code(fake, client, with_second(clean_raw(), node)) == 2


@pytest.mark.parametrize("what", sorted(SKIPPED_BAD))
def test_a_tag_ruleset_is_still_validated(fake: FakeGitHub, client: Client, what: str) -> None:
    node = ruleset("CI green", target="TAG") | SKIPPED_BAD[what]
    assert exit_code(fake, client, with_second(clean_raw(), node)) == 2


def test_a_good_ruleset_that_does_not_count_is_clean(fake: FakeGitHub, client: Client) -> None:
    assert exit_code(fake, client, with_second(clean_raw(), disabled())) == 0


@pytest.mark.parametrize("target", ["PUSH", "REPOSITORY"])
def test_push_and_repository_rulesets_may_have_no_ref_conditions(fake: FakeGitHub, client: Client, target: str) -> None:
    """GitHub gives those targets no refName condition; null there is normal, not malformed."""
    node = ruleset("CI green", target=target) | {"conditions": None}
    assert exit_code(fake, client, with_second(clean_raw(), node)) == 0
    node = ruleset("CI green", target=target) | {"conditions": {"refName": {"include": "x", "exclude": []}}}
    assert exit_code(fake, client, with_second(clean_raw(), node)) == 2  # present, so it must be well-formed


@pytest.mark.parametrize("bad", [7, "x", [], True], ids=repr)
def test_parameters_of_a_rule_that_does_not_count_are_validated(fake: FakeGitHub, client: Client, bad: Any) -> None:
    raw = clean_raw()
    nff = next(r for r in raw["rulesets"]["nodes"][0]["rules"]["nodes"] if r["type"] == "NON_FAST_FORWARD")
    nff["parameters"] = bad
    assert exit_code(fake, client, raw) == 2


def test_required_status_checks_of_a_classic_rule_that_is_off_are_validated(fake: FakeGitHub, client: Client) -> None:
    bads: list[Any] = [None, "x", 5, {}, [None], ["x"], [{"context": None}]]
    for bad in bads:
        raw = classic_raw(requiresStatusChecks=False, requiredStatusChecks=bad)
        assert exit_code(fake, client, raw) == 2, bad


def test_an_archived_repository_still_has_its_own_fields_validated(fake: FakeGitHub, client: Client) -> None:
    ok = clean_raw() | {"isArchived": True}
    assert exit_code(fake, client, ok) == 0
    changes: list[dict[str, Any]] = [{"viewerPermission": "SUPERUSER"}, {"isArchived": "true"}, {"nameWithOwner": None}]
    for change in changes:
        assert exit_code(fake, client, ok | change) == 2, change
    assert exit_code(fake, client, {k: v for k, v in ok.items() if k != "defaultBranchRef"}) == 2
    assert exit_code(fake, client, ok | {"defaultBranchRef": 7}) == 2
    assert exit_code(fake, client, ok | {"rulesets": {"totalCount": 0, "nodes": None}}) == 2


def test_an_empty_default_branch_still_has_its_own_fields_validated(fake: FakeGitHub, client: Client) -> None:
    ok = clean_raw() | {"defaultBranchRef": None}
    assert exit_code(fake, client, ok) == 0
    changes: list[dict[str, Any]] = [{"viewerPermission": "SUPERUSER"}, {"isArchived": None}, {"nameWithOwner": 5}]
    for change in changes:
        assert exit_code(fake, client, ok | change) == 2, change
    assert exit_code(fake, client, ok | {"rulesets": {"totalCount": 0, "nodes": None}}) == 2
    assert exit_code(fake, client, ok | {"rulesets": {"totalCount": 1, "nodes": []}}) == 2


# -- 4 and 5. what was not evaluated is said ----


def test_an_exempt_repository_is_noted_not_skipped_silently(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = None
    code, text = gate(fake, client, with_rules(load_test_board(), gate_exempt_repos=(WIDGETS,)))
    assert code == 0
    assert "NOTE    NO-GATE acme/widgets: exempt by rules.gate_exempt_repos (not evaluated)" in text
    assert not [t for t in text if "NO-GATE acme/manuals" in t and t.startswith("NOTE")]


def test_an_empty_gate_check_says_so_on_the_summary_line(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = None
    code, text = gate(fake, client, with_rules(load_test_board(), gate_check=""))
    assert code == 0
    assert text[-1] != "clean"
    assert "branch gate NOT checked" in text[-1] and "rules.gate_check is empty" in text[-1]
    assert any(t.startswith("NOTE") and "Branch gate check not configured" in t for t in text)


# -- identity, ruleset targets, permission enum, intersections ----------------------------------------------


def _judged(name_with_owner: Any, requested: str = "acme/K") -> Any:
    from safo.gate import judge_repository

    raw = clean_raw() | {"nameWithOwner": name_with_owner}
    return judge_repository(raw, "CI green", True, requested=requested)


@pytest.mark.parametrize(
    "returned",
    [
        "acme/" + chr(0x212A),  # Kelvin sign: lower() is an ASCII k
        "acme/" + chr(0x0131),  # dotless i
        "acme/" + chr(0x017F),  # long s
        chr(0xFF41) + "cme/K",  # fullwidth a
        "acme/" + chr(0xFF2B),  # fullwidth K
        "acme/K ",  # trailing space
        " acme/K",
        "acme/K\n",
        "acme/K/x",  # extra slash
        "acme//K",
        "/K",  # empty owner
        "acme/",  # empty repo
        "",
        "acme",
        "acme/other",  # a different ASCII repository
        "other/K",
    ],
    ids=ascii,
)
def test_a_returned_identity_that_is_not_exactly_the_one_asked_for_is_malformed(returned: str) -> None:
    from safo.errors import MalformedDataError

    with pytest.raises(MalformedDataError):
        _judged(returned)


@pytest.mark.parametrize("returned", ["acme/K", "ACME/k", "Acme/K"])
def test_an_ascii_case_difference_in_the_returned_identity_is_accepted(returned: str) -> None:
    got = _judged(returned)
    assert not got.problems and not got.unknown


def test_the_returned_identity_is_checked_even_without_a_requested_name() -> None:
    from safo.errors import MalformedDataError
    from safo.gate import judge_repository

    with pytest.raises(MalformedDataError):
        judge_repository(clean_raw() | {"nameWithOwner": "acme/" + chr(0x212A)}, "CI green", True)


@pytest.mark.parametrize(
    "target", ["branch", "Branch", "FUTURE", "", " BRANCH", "BRANCH ", "tag", "push", "repository"]
)
def test_an_unknown_ruleset_target_is_cannot_tell(fake: FakeGitHub, client: Client, target: str) -> None:
    assert exit_code(fake, client, with_second(clean_raw(), ruleset("CI green", target=target))) == 2


@pytest.mark.parametrize("target", ["BRANCH", "TAG", "PUSH", "REPOSITORY"])
def test_each_documented_ruleset_target_is_accepted(fake: FakeGitHub, client: Client, target: str) -> None:
    node = ruleset("CI green", target=target)
    if target in ("PUSH", "REPOSITORY"):
        node["conditions"] = None
    assert exit_code(fake, client, with_second(clean_raw(), node)) == 0


@pytest.mark.parametrize("target", ["PUSH", "REPOSITORY", "TAG"])
@pytest.mark.parametrize("conditions", ["refname", "none"])
def test_a_ruleset_of_another_target_is_never_the_only_source_of_the_gate(
    fake: FakeGitHub, client: Client, target: str, conditions: str
) -> None:
    """Even one that names the default branch and holds the check and the force-push block."""
    node = ruleset("CI green", target=target)
    if conditions == "none" and target != "TAG":
        node["conditions"] = None
    elif conditions == "none":
        pytest.skip("a tag ruleset always carries a ref condition")
    raw = clean_raw() | {"viewerPermission": "ADMIN", "rulesets": {"totalCount": 1, "nodes": [node]}}
    assert exit_code(fake, client, raw) == 1  # unprotected: a finding, never clean
    raw["viewerPermission"] = "READ"
    assert exit_code(fake, client, raw) == 2  # a non-admin token sees nothing counted: cannot tell, never clean


@pytest.mark.parametrize("good", ["ADMIN", "MAINTAIN", "WRITE", "TRIAGE_PLUS", "TRIAGE", "READ"])
def test_each_permission_in_githubs_schema_is_accepted(fake: FakeGitHub, client: Client, good: str) -> None:
    """Checked against RepositoryPermission by read-only introspection on 2026-10-26."""
    assert exit_code(fake, client, set_path(clean_raw(), ["viewerPermission"], good)) == 0


def test_none_is_not_a_repository_permission_value(fake: FakeGitHub, client: Client) -> None:
    assert exit_code(fake, client, set_path(clean_raw(), ["viewerPermission"], "NONE")) == 2


def test_admin_note_when_the_check_is_held_only_by_an_open_classic_rule_and_the_block_by_a_ruleset(
    fake: FakeGitHub, client: Client
) -> None:
    build_world(fake)
    for name in (WIDGETS, "acme/manuals"):
        repo(fake, name).protection = classic("CI green", force=True) | {"isAdminEnforced": False}
        repo(fake, name).rulesets = [ruleset(no_force=True)]  # a ruleset that blocks force pushes, nobody bypasses
    code, text = gate(fake, client)
    assert code == 0 and len(notes(text)) == 2


def test_admin_note_when_the_block_is_held_only_by_an_open_classic_rule_and_the_check_by_a_ruleset(
    fake: FakeGitHub, client: Client
) -> None:
    build_world(fake)
    for name in (WIDGETS, "acme/manuals"):
        repo(fake, name).protection = classic("lint") | {"isAdminEnforced": False}
        repo(fake, name).rulesets = [ruleset("CI green", no_force=False)]
    code, text = gate(fake, client)
    assert code == 0 and len(notes(text)) == 2


def test_one_repository_raising_does_not_hide_a_finding_or_skip_the_next(
    monkeypatch: pytest.MonkeyPatch, fake: FakeGitHub, client: Client
) -> None:
    import dataclasses

    import safo.gate as g
    from safo.schema import Repository

    build_world(fake)
    fake.add_repo("acme/third")
    repo(fake, "acme/manuals").protection = None  # repository 2: a finding
    board = load_test_board()
    board = dataclasses.replace(board, repositories=(*board.repositories, Repository("acme", "third")))
    real = g.judge_repository

    def boom(raw: Any, *a: Any, **k: Any) -> Any:
        if raw.get("nameWithOwner") == WIDGETS:  # repository 1: an unexpected error
            raise RuntimeError("secret")
        return real(raw, *a, **k)

    monkeypatch.setattr(g, "judge_repository", boom)
    code, text = gate(fake, client, board)
    assert code == 2  # unknown outranks drift
    assert any(t.startswith("UNKNOWN") and WIDGETS in t and "secret" not in t for t in text)
    assert lines(text, "acme/manuals")
    assert fake.requests.count("RepoBranchGate") == 3  # the third was read and judged too
    assert not [t for t in text if "acme/third" in t and t.startswith(("DRIFT", "UNKNOWN"))]
