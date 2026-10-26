# SPDX-License-Identifier: Apache-2.0
"""The branch gate's two fail-open risks: ref patterns that are not Python's fnmatch, and rules someone can bypass."""

from __future__ import annotations

from typing import Any

import pytest

from fakegh import FakeGitHub
from safo.gate import ref_matches
from safo.graphql import Client
from test_branch_gate import WIDGETS, classic, gate, lines, repo, ruleset, with_rules
from world import build_world, load_test_board

# -- GitHub's ref patterns: Ruby File.fnmatch with FNM_PATHNAME ------------------------------------------------------
# https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule
# https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository


@pytest.mark.parametrize(
    ("pattern", "ref", "want"),
    [
        ("refs/heads/main", "refs/heads/main", True),
        ("refs/heads/main", "refs/heads/trunk", False),
        ("refs/heads/*", "refs/heads/main", True),
        ("refs/heads/*", "refs/heads/feature/x", False),  # `*` does not cross a slash
        ("refs/heads/release/*", "refs/heads/release/1", True),
        ("refs/heads/release/*", "refs/heads/release/1/2", False),
        ("refs/heads/release/**/*", "refs/heads/release/1/2", True),  # `**/` spans directories
        ("refs/heads/release/**/*", "refs/heads/release/1", True),  # and may span none
        ("refs/heads/**/*", "refs/heads/feature/x", True),
        ("refs/heads/feat*", "refs/heads/feature/x", False),
        ("refs/heads/feat*/*", "refs/heads/feature/x", True),
        ("refs/heads/ma?n", "refs/heads/main", True),
        ("refs/heads/ma?n", "refs/heads/ma/n", False),
        ("refs/heads/[mt]*", "refs/heads/main", True),
        ("refs/heads/[a-l]*", "refs/heads/main", False),
        ("refs/heads/m.in", "refs/heads/main", False),  # a dot is a dot, not a regex wildcard
        ("~ALL", "refs/heads/feature/x", True),
        ("~DEFAULT_BRANCH", "refs/heads/feature/x", True),
    ],
)
def test_ref_patterns_follow_github_not_python_fnmatch(pattern: str, ref: str, want: bool) -> None:
    assert ref_matches(pattern, ref) is want


@pytest.mark.parametrize(
    ("pattern", "ref"),
    [
        ("refs/heads/release**", "refs/heads/release/1"),  # `**` not as a whole directory: not documented
        ("refs/heads/**", "refs/heads/feature/x"),  # a trailing bare `**`: not documented
        ("refs/heads/[^m]*", "refs/heads/main"),  # GitHub does not support `[^...]`
        ("refs/heads/[!m]*", "refs/heads/main"),
        ("refs/heads/ma\\in", "refs/heads/main"),  # no backslash quoting
        ("refs/heads/[m", "refs/heads/main"),  # unterminated set
        ("~SOMETHING_NEW", "refs/heads/main"),  # a variable this code does not know
        ("refs/heads/*", "refs/heads/.hidden"),  # whether `*` matches a leading dot is not documented
    ],
)
def test_a_pattern_whose_meaning_is_not_documented_is_cannot_tell_not_a_guess(pattern: str, ref: str) -> None:
    assert ref_matches(pattern, ref) is None


def test_the_literal_text_of_a_branch_is_never_a_pattern() -> None:
    assert ref_matches("refs/heads/a+b", "refs/heads/a+b") is True
    assert ref_matches("refs/heads/a+b", "refs/heads/aab") is False
    assert ref_matches("refs/heads/(x)", "refs/heads/x") is False


def test_release_star_does_not_protect_a_nested_default_branch(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).default_branch = "release/1/2"
    repo(fake).protection = None
    repo(fake).rulesets = [ruleset("CI green", include=("refs/heads/release/*",))]
    code, text = gate(fake, client)
    assert code == 1 and "has no branch protection and no active ruleset" in lines(text, WIDGETS)[0]
    repo(fake).rulesets = [ruleset("CI green", include=("refs/heads/release/**/*",))]
    code, _ = gate(fake, client)
    assert code == 0


def test_a_default_branch_with_a_slash_and_a_star_pattern(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).default_branch = "feature/x"
    repo(fake).protection = None
    repo(fake).rulesets = [ruleset("CI green", include=("refs/heads/*",))]  # does not cover feature/x
    code, text = gate(fake, client)
    assert code == 1 and "default branch 'feature/x'" in lines(text, WIDGETS)[0]
    for include in (("~DEFAULT_BRANCH",), ("~ALL",), ("refs/heads/*/*",), ("refs/heads/feature/x",)):
        repo(fake).rulesets = [ruleset("CI green", include=include)]
        code, _ = gate(fake, client)
        assert code == 0, include


def test_an_exclude_pattern_uses_the_same_semantics(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).default_branch = "feature/x"
    repo(fake).protection = None
    repo(fake).rulesets = [ruleset("CI green", include=("~ALL",), exclude=("refs/heads/*",))]
    code, _ = gate(fake, client)
    assert code == 0  # `*` does not reach feature/x, so the exclude does not remove it
    repo(fake).rulesets = [ruleset("CI green", include=("~ALL",), exclude=("refs/heads/*/*",))]
    code, text = gate(fake, client)
    assert code == 1 and lines(text, WIDGETS)


def test_an_unclear_pattern_is_exit_2_when_it_decides_the_answer(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = None
    repo(fake).rulesets = [ruleset("CI green", include=("refs/heads/[^x]*",))]
    code, text = gate(fake, client)
    assert code == 2 and any(t.startswith("UNKNOWN") and WIDGETS in t and "pattern" in t for t in text)
    # an unclear pattern beside one that definitely covers the branch does not matter
    repo(fake).rulesets = [ruleset("CI green", include=("refs/heads/[^x]*", "~DEFAULT_BRANCH"))]
    code, _ = gate(fake, client)
    assert code == 0


# -- bypass ----------------------------------------------------------------------------------------------------------


def actors(*modes: str) -> dict[str, Any]:
    return {"totalCount": len(modes), "nodes": [{"bypassMode": m} for m in modes]}


def unenforced(fake: FakeGitHub) -> None:
    repo(fake).protection = classic("CI green") | {"isAdminEnforced": False}
    repo(fake, "acme/manuals").protection = classic("CI green") | {"isAdminEnforced": False}


def test_admins_not_enforced_is_not_a_finding_by_default(fake: FakeGitHub, client: Client) -> None:
    """The maintainer's baseline sets enforce_admins=false on purpose, so the default must not flag it."""
    build_world(fake)
    unenforced(fake)
    code, text = gate(fake, client)
    assert code == 0 and not [t for t in text if "NO-GATE" in t]


def test_admins_not_enforced_is_a_finding_when_asked_for(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    unenforced(fake)
    code, text = gate(fake, client, with_rules(load_test_board(), gate_require_admin_enforced=True))
    assert code == 1
    found = lines(text, WIDGETS)[0]
    assert "can be bypassed" in found and "administrators are not included (enforce_admins is off)" in found
    assert lines(text, "acme/manuals")


def test_admins_not_enforced_can_be_accepted_per_repository_when_asked_for(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    unenforced(fake)
    board = with_rules(load_test_board(), gate_require_admin_enforced=True, gate_admin_exempt_repos=(WIDGETS,))
    code, text = gate(fake, client, board)
    assert code == 1
    assert not lines(text, WIDGETS) and lines(text, "acme/manuals")


def test_the_default_for_admin_enforcement_is_off() -> None:
    from safo.schema import Rules

    assert Rules().gate_require_admin_enforced is False


def test_a_force_push_bypass_allowance_is_a_finding_only_when_force_pushes_are_forbidden(
    fake: FakeGitHub, client: Client
) -> None:
    build_world(fake)
    repo(fake).protection = classic("CI green") | {"bypassForcePushAllowances": {"totalCount": 2}}
    code, text = gate(fake, client)
    assert code == 1 and "force pushes are blocked but 2 actors may bypass the block" in lines(text, WIDGETS)[0]
    code, _ = gate(fake, client, with_rules(load_test_board(), gate_forbid_force_push=False))
    assert code == 0


def test_a_pull_request_bypass_allowance_does_not_touch_the_check_and_is_not_a_finding(
    fake: FakeGitHub, client: Client
) -> None:
    """It bypasses the review requirement, not required status checks; the admin flag covers the check."""
    build_world(fake)
    repo(fake).protection = classic("CI green") | {"bypassPullRequestAllowances": {"totalCount": 3}}
    code, _ = gate(fake, client)
    assert code == 0


@pytest.mark.parametrize("mode", ["ALWAYS", "PULL_REQUEST", "EXEMPT"])
def test_a_ruleset_with_bypass_actors_is_a_finding_for_every_mode(fake: FakeGitHub, client: Client, mode: str) -> None:
    build_world(fake)
    repo(fake).protection = None
    repo(fake).rulesets = [ruleset("CI green") | {"bypassActors": actors(mode)}]
    code, text = gate(fake, client)
    assert code == 1
    found = lines(text, WIDGETS)[0]
    assert "can be bypassed" in found and "ruleset 'protect' has 1 bypass actor" in found and mode in found


def test_a_ruleset_with_no_bypass_actors_passes(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = None
    repo(fake).rulesets = [ruleset("CI green") | {"bypassActors": actors()}]
    code, _ = gate(fake, client)
    assert code == 0


def test_an_unbypassable_source_is_enough(fake: FakeGitHub, client: Client) -> None:
    """The check is held by a ruleset nobody can bypass, so a bypassable second ruleset adds no hole."""
    build_world(fake)
    repo(fake).protection = None
    repo(fake).rulesets = [
        ruleset("CI green") | {"bypassActors": actors()},
        ruleset("CI green") | {"name": "loose", "bypassActors": actors("ALWAYS")},
    ]
    code, _ = gate(fake, client)
    assert code == 0


def test_a_bypassable_ruleset_does_not_hide_behind_a_classic_rule_that_lacks_the_check(
    fake: FakeGitHub, client: Client
) -> None:
    build_world(fake)
    repo(fake).protection = classic("lint")
    repo(fake).rulesets = [ruleset("CI green") | {"bypassActors": actors("ALWAYS")}]
    code, text = gate(fake, client)
    assert code == 1 and "can be bypassed" in lines(text, WIDGETS)[0]


def test_a_force_push_block_held_by_a_bypassable_ruleset_is_reported(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = classic("CI green", force=True)
    repo(fake).rulesets = [ruleset(no_force=True) | {"bypassActors": actors("ALWAYS")}]
    code, text = gate(fake, client)
    assert code == 1 and "force pushes are blocked but" in lines(text, WIDGETS)[0]


def test_a_truncated_bypass_list_is_cannot_tell(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = None
    cut = actors("PULL_REQUEST") | {"totalCount": 75}
    repo(fake).rulesets = [ruleset("CI green") | {"bypassActors": cut}]
    code, text = gate(fake, client)
    assert code == 2 and any(t.startswith("UNKNOWN") and "bypass" in t for t in text)


def test_a_missing_bypass_field_is_cannot_tell_never_a_pass(fake: FakeGitHub, client: Client) -> None:
    """A token or schema that hides the bypass data must not read as 'no bypass'."""
    build_world(fake)
    rule = classic("CI green")
    del rule["isAdminEnforced"]
    repo(fake).protection = rule
    code, _ = gate(fake, client)
    assert code == 2


def test_the_bypass_fields_are_in_the_query() -> None:
    from safo.gate import Q_BRANCH_GATE

    for name in ("isAdminEnforced", "bypassForcePushAllowances", "bypassActors", "bypassMode"):
        assert name in Q_BRANCH_GATE


def test_the_admin_exempt_rule_parses(tmp_path: Any) -> None:
    from safo.errors import ConfigError
    from safo.schema import load_board
    from world import DATA

    src = (DATA / "board.yaml").read_text(encoding="utf-8")
    ok = tmp_path / "b.yaml"
    ok.write_text(
        src.replace("\nrules:\n", "\nrules:\n  gate_admin_exempt_repos: [acme/widgets]\n", 1), encoding="utf-8"
    )
    assert load_board(ok).rules.gate_admin_exempt_repos == ("acme/widgets",)
    ok.write_text(src.replace("\nrules:\n", "\nrules:\n  gate_require_admin_enforced: true\n", 1), encoding="utf-8")
    assert load_board(ok).rules.gate_require_admin_enforced is True
    ok.write_text(
        src.replace("\nrules:\n", "\nrules:\n  gate_require_admin_enforced: yes please\n", 1), encoding="utf-8"
    )
    with pytest.raises(ConfigError):
        load_board(ok)
    ok.write_text(src.replace("\nrules:\n", "\nrules:\n  gate_admin_exempt_repos: [nope]\n", 1), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_board(ok)


# -- the admin flag, straight at the function (a pass-through here would silently hide every unenforced admin) --------


def test_classic_bypass_unenforced_and_not_accepted_is_a_finding() -> None:
    from safo.gate import _classic_bypass

    got = _classic_bypass({"isAdminEnforced": False}, False)
    assert got == "administrators are not included (enforce_admins is off)"


def test_classic_bypass_unenforced_but_accepted_is_none() -> None:
    from safo.gate import _classic_bypass

    assert _classic_bypass({"isAdminEnforced": False}, True) is None


def test_classic_bypass_enforced_is_none() -> None:
    from safo.gate import _classic_bypass

    assert _classic_bypass({"isAdminEnforced": True}, False) is None


@pytest.mark.parametrize("bad", [None, "true", 1, 0, [], {}])
def test_classic_bypass_a_missing_or_non_bool_answer_fails_closed(bad: object) -> None:
    from safo.errors import MalformedDataError
    from safo.gate import _classic_bypass

    with pytest.raises(MalformedDataError):
        _classic_bypass({"isAdminEnforced": bad}, True)
    with pytest.raises(MalformedDataError):
        _classic_bypass({}, True)
