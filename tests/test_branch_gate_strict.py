# SPDX-License-Identifier: Apache-2.0
"""The branch gate reads GitHub's answer strictly: null, absent, mistyped or inconsistent is cannot tell.

Each case serves one repository answer through the fake for both listed repositories and expects exit 2 (or a stated
verdict). The clean baseline is checked first so a case cannot go red for another reason.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from fakegh import FakeGitHub, GqlError
from fakegh.core import Fault
from safo import output
from safo.errors import ApiError
from safo.gate import Q_BRANCH_GATE, gate_findings
from safo.graphql import Client
from test_branch_gate import WIDGETS, classic, gate, lines, repo, ruleset
from world import build_world, load_test_board

Raw = dict[str, Any]


def clean_raw() -> Raw:
    """Protected by an active ruleset nobody can bypass; a non-admin token (so an empty read would be cannot tell)."""
    return {
        "nameWithOwner": WIDGETS,
        "isArchived": False,
        "viewerPermission": "READ",
        "defaultBranchRef": {"name": "main", "branchProtectionRule": None},
        "rulesets": {"totalCount": 1, "nodes": [ruleset("CI green")]},
    }


def serve(fake: FakeGitHub, raw: Raw) -> None:
    fake.handlers["RepoBranchGate"] = lambda f, v: {"repository": copy.deepcopy(raw)}


def exit_code(fake: FakeGitHub, client: Client, raw: Raw) -> int:
    if not fake.projects:
        build_world(fake)
    serve(fake, raw)
    code, _ = gate(fake, client)
    return code


def test_the_baseline_answer_is_clean(fake: FakeGitHub, client: Client) -> None:
    assert exit_code(fake, client, clean_raw()) == 0


# -- 1. a connection or list that is null, absent or the wrong type is malformed, never empty ----

WRONG: list[Any] = [None, {}, "x", 1, True]


def set_path(raw: Raw, path: list[Any], value: Any) -> Raw:
    node: Any = raw
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return raw


def drop_path(raw: Raw, path: list[Any]) -> Raw:
    node: Any = raw
    for key in path[:-1]:
        node = node[key]
    del node[path[-1]]
    return raw


RS: list[Any] = ["rulesets", "nodes", 0]
LISTS: dict[str, list[Any]] = {
    "rulesets.nodes": ["rulesets", "nodes"],
    "rules.nodes": [*RS, "rules", "nodes"],
    "bypassActors.nodes": [*RS, "bypassActors", "nodes"],
    "include": [*RS, "conditions", "refName", "include"],
    "exclude": [*RS, "conditions", "refName", "exclude"],
    "ruleset requiredStatusChecks": [*RS, "rules", "nodes", 0, "parameters", "requiredStatusChecks"],
}


@pytest.mark.parametrize("name", sorted(LISTS))
@pytest.mark.parametrize("wrong", WRONG, ids=repr)
def test_a_list_that_is_not_a_real_list_is_cannot_tell(fake: FakeGitHub, client: Client, name: str, wrong: Any) -> None:
    assert exit_code(fake, client, set_path(clean_raw(), LISTS[name], wrong)) == 2


@pytest.mark.parametrize("name", sorted(LISTS))
def test_a_list_that_is_absent_is_cannot_tell(fake: FakeGitHub, client: Client, name: str) -> None:
    assert exit_code(fake, client, drop_path(clean_raw(), LISTS[name])) == 2


@pytest.mark.parametrize("wrong", WRONG, ids=repr)
def test_a_classic_required_checks_list_that_is_not_a_list_is_cannot_tell(
    fake: FakeGitHub, client: Client, wrong: Any
) -> None:
    raw = clean_raw()
    raw["defaultBranchRef"]["branchProtectionRule"] = classic("CI green")
    raw["rulesets"] = {"totalCount": 0, "nodes": []}
    assert (
        exit_code(
            fake, client, set_path(raw, ["defaultBranchRef", "branchProtectionRule", "requiredStatusChecks"], wrong)
        )
        == 2
    )


def test_a_real_empty_list_is_still_an_empty_list(fake: FakeGitHub, client: Client) -> None:
    raw = clean_raw()
    raw["rulesets"] = {"totalCount": 0, "nodes": []}
    raw["viewerPermission"] = "ADMIN"
    assert exit_code(fake, client, raw) == 1  # an admin token and nothing found: unprotected, a finding


@pytest.mark.parametrize("element", [None, "x", 1, []])
def test_a_list_element_that_is_not_an_object_is_cannot_tell(fake: FakeGitHub, client: Client, element: Any) -> None:
    for path in (["rulesets", "nodes"], [*RS, "rules", "nodes"], [*RS, "bypassActors", "nodes"]):
        raw = clean_raw()
        set_path(raw, path, [element])
        set_path(raw, [*path[:-1], "totalCount"], 1)  # consistent, so only the element is wrong
        assert exit_code(fake, client, raw) == 2, path


def test_a_ref_pattern_or_context_that_is_not_text_is_cannot_tell(fake: FakeGitHub, client: Client) -> None:
    assert exit_code(fake, client, set_path(clean_raw(), [*LISTS["include"], 0], 5)) == 2
    assert exit_code(fake, client, set_path(clean_raw(), [*LISTS["include"], 0], None)) == 2
    bad_context = [*LISTS["ruleset requiredStatusChecks"], 0, "context"]
    assert exit_code(fake, client, set_path(clean_raw(), bad_context, None)) == 2
    assert exit_code(fake, client, drop_path(clean_raw(), bad_context)) == 2


# -- 2. the default branch name ----


@pytest.mark.parametrize(
    "name",
    [
        None,
        "",
        123,
        ["main"],
        "ma\nin",
        "ma\x00in",
        "ma\x1bin",
        "a//b",
        "/a",
        "a/",
        "a..b",
        "a b",
        "a:b",
        "x/",
        "@",
        "a.lock",
        "a.",
        "a‮b",
    ],
    ids=repr,
)
def test_a_default_branch_name_that_is_not_a_plausible_name_is_cannot_tell(
    fake: FakeGitHub, client: Client, name: Any
) -> None:
    raw = clean_raw()
    raw["defaultBranchRef"]["name"] = name
    assert exit_code(fake, client, raw) == 2


def test_the_name_key_absent_is_cannot_tell(fake: FakeGitHub, client: Client) -> None:
    raw = clean_raw()
    del raw["defaultBranchRef"]["name"]
    assert exit_code(fake, client, raw) == 2


@pytest.mark.parametrize("name", ["main", "feature/x", "release/1.2", "v2-beta", "ünï"])
def test_ordinary_default_branch_names_are_accepted(fake: FakeGitHub, client: Client, name: str) -> None:
    raw = clean_raw()
    raw["defaultBranchRef"]["name"] = name
    assert exit_code(fake, client, raw) == 0


@pytest.mark.parametrize(
    ("key", "wrong"),
    [
        ("isArchived", None),
        ("isArchived", 1),
        ("isArchived", "yes"),
        ("viewerPermission", None),
        ("viewerPermission", 1),
    ],
    ids=repr,
)
def test_a_repository_flag_that_is_absent_or_mistyped_is_cannot_tell(
    fake: FakeGitHub, client: Client, key: str, wrong: Any
) -> None:
    raw = clean_raw()
    raw[key] = wrong
    assert exit_code(fake, client, raw) == 2
    raw = clean_raw()
    del raw[key]
    assert exit_code(fake, client, raw) == 2


# -- 3. totalCount must equal the number of nodes, in both directions ----

COUNTS: dict[str, list[Any]] = {
    "rulesets": ["rulesets"],
    "rules": [*RS, "rules"],
    "bypassActors": [*RS, "bypassActors"],
}


@pytest.mark.parametrize("name", sorted(COUNTS))
@pytest.mark.parametrize("total", [0, 3, 99])
def test_a_total_that_disagrees_with_the_nodes_is_cannot_tell(
    fake: FakeGitHub, client: Client, name: str, total: int
) -> None:
    raw = clean_raw()
    node: Any = raw
    for key in COUNTS[name]:
        node = node[key]
    if name == "bypassActors":
        node["nodes"] = [{"bypassMode": "ALWAYS"}]  # one real actor
    expected = len(node["nodes"])
    assert total != expected
    node["totalCount"] = total
    assert exit_code(fake, client, raw) == 2


@pytest.mark.parametrize("name", sorted(COUNTS))
@pytest.mark.parametrize("total", [None, "1", -1, True, 1.5])
def test_a_total_that_is_not_a_count_is_cannot_tell(fake: FakeGitHub, client: Client, name: str, total: Any) -> None:
    raw = clean_raw()
    node: Any = raw
    for key in COUNTS[name]:
        node = node[key]
    node["totalCount"] = total
    assert exit_code(fake, client, raw) == 2


# -- 4. a malformed answer for one repository never crashes the audit or hides the others ----


@pytest.mark.parametrize(
    "data", [[], "x", 1, {"repository": None}, {"repository": []}, {"repository": "x"}, {}], ids=repr
)
def test_a_malformed_data_object_is_cannot_tell_for_that_repository_only(
    fake: FakeGitHub, client: Client, data: Any
) -> None:
    build_world(fake)
    repo(fake, "acme/manuals").protection = None  # a real finding on the second repository
    repo(fake, "acme/manuals").rulesets = []

    def answer(f: FakeGitHub, v: dict[str, Any]) -> Any:
        if v["name"] == "widgets":
            return data
        from fakegh.gate_ops import branch_gate

        return branch_gate(f, v)

    fake.handlers["RepoBranchGate"] = answer
    code, text = gate(fake, client)
    assert code == 2
    assert any(t.startswith("UNKNOWN") and WIDGETS in t for t in text)
    assert lines(text, "acme/manuals")  # still evaluated and reported


def test_data_that_is_not_an_object_is_an_api_error_in_the_client(fake: FakeGitHub, client: Client) -> None:
    for body in ('{"data": []}', '{"data": "x"}', '{"data": 1}'):
        fake.faults.append(Fault(200, body=body, op="RepoBranchGate"))
        with pytest.raises(ApiError):
            client.execute(Q_BRANCH_GATE, {"owner": "acme", "name": "widgets"})


def test_any_unexpected_exception_from_one_repository_is_cannot_tell_with_fixed_text(
    monkeypatch: pytest.MonkeyPatch, fake: FakeGitHub, client: Client
) -> None:
    import safo.gate as g

    build_world(fake)
    real = g.judge_repository

    def boom(raw: Any, *a: Any, **k: Any) -> Any:
        if raw.get("nameWithOwner") == WIDGETS:
            raise RuntimeError("secret\nDRIFT forged")
        return real(raw, *a, **k)

    monkeypatch.setattr(g, "judge_repository", boom)
    drift, unknown, _ = gate_findings(client, load_test_board())
    assert drift == [] and len(unknown) == 1  # the other repository was still judged (clean)
    assert "secret" not in unknown[0] and "forged" not in unknown[0] and WIDGETS in unknown[0]


# -- 5. GitHub-supplied text is escaped, single-line ----

HOSTILE = "denied\nDRIFT forged\x1b[31m ::error::boom ‮⁦ end"


def test_error_text_from_github_cannot_forge_a_line_or_a_workflow_command(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)

    def refuse(f: FakeGitHub, v: dict[str, Any]) -> Any:
        raise GqlError("FORBIDDEN", HOSTILE)

    fake.handlers["RepoBranchGate"] = refuse
    _, unknown, _ = gate_findings(client, load_test_board())
    assert unknown
    for text in unknown:
        assert output.line(text) == text, "the finding is already safe to print"
        for bad in ("\n", "\r", "\x1b", "::", "‮", "⁦"):
            assert bad not in text
    code, out = gate(fake, client)
    assert code == 2 and not [t for t in out if t.startswith("DRIFT forged")]


def test_ruleset_and_check_names_from_github_are_escaped(fake: FakeGitHub, client: Client) -> None:
    raw = clean_raw()
    raw["rulesets"]["nodes"][0]["name"] = HOSTILE
    raw["rulesets"]["nodes"][0]["bypassActors"] = {"totalCount": 1, "nodes": [{"bypassMode": HOSTILE}]}
    build_world(fake)
    serve(fake, raw)
    drift, _, _ = gate_findings(client, load_test_board())
    assert drift
    for text in drift:
        assert output.line(text) == text
        assert "\n" not in text and "\x1b" not in text and "::" not in text and "‮" not in text
