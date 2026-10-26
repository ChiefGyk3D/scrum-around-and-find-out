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


# -- bracket expressions: only unambiguous plain sets are read; everything else is cannot tell ------------------------
# Oracle: Ruby 3.3.8 File.fnmatch("refs/heads/" + pattern, "refs/heads/" + name, File::FNM_PATHNAME), run locally; the
# results are written out below as literals. Ruby is the oracle for the plain sets only. For everything else Ruby either
# differs from what GitHub documents (`[!a]` and `[^a]` complement the set in Ruby, but GitHub's docs say "you cannot
# currently complement a set with the ^ operator"), or Python's re reads the text differently (`[]a]` is the set `]` or
# `a` in Python but matches nothing in Ruby; `[c-a]` and `[z-a]` match their two ends in Ruby and raise in Python), or
# the docs are silent (empty class, a leading or trailing `-`, POSIX `[[:alpha:]]`, a backslash). Silence is "cannot
# tell", never a guess. Docs relied on: the two pages cited above ("You can specify character sets within square
# brackets ([]), but you cannot currently complement a set with the ^ operator"; "You cannot use the backslash (\)
# character as a quoting character").

PLAIN_SETS = [
    ("[a]", {"a": True, "b": False, "]": False, "-": False}),
    ("[ab]", {"a": True, "b": True, "c": False, "]": False}),
    ("[a-c]", {"a": True, "b": True, "c": True, "z": False, "-": False, "1": False}),
    ("[0-9]", {"1": True, "a": False, "-": False}),
    ("[a-c0-9]", {"a": True, "c": True, "1": True, "z": False, "-": False}),
]


@pytest.mark.parametrize(("pattern", "name", "want"), [(p, n, w) for p, cases in PLAIN_SETS for n, w in cases.items()])
def test_plain_bracket_sets_match_like_ruby(pattern: str, name: str, want: bool) -> None:
    assert ref_matches(f"refs/heads/{pattern}", f"refs/heads/{name}") is want


@pytest.mark.parametrize(
    "pattern",
    [
        "[]a]",  # Ruby: matches nothing; Python re: `]` or `a`. The reported false pass.
        "[]",
        "[",
        "[!a]",
        "[^a]",
        "[[:alpha:]]",
        "[a-]",
        "[-a]",
        "[c-a]",  # Ruby: a and c
        "[z-a]",  # Ruby: a and z; Python re: error
        "[a\\]]",
        "[a-c-e]",
        "[*]",
        "[?]",
        "[/]",
        "[a/b]",
        "[.-z]",  # a range whose end is not a letter or digit
        "[0-z]",  # a range across kinds
        "[a-Z]",
        "[a[b]",
        "[a-c",
        "[:alpha:]",
    ],
)
@pytest.mark.parametrize("name", ["a", "b", "]", "z"])
def test_every_other_bracket_expression_is_cannot_tell(pattern: str, name: str) -> None:
    assert ref_matches(f"refs/heads/{pattern}", f"refs/heads/{name}") is None


def test_the_reported_false_pass_is_now_unknown(fake: FakeGitHub, client: Client) -> None:
    """A default branch `a` and the include `[]a]`: Python's re would cover it, Ruby does not. Never a clean verdict."""
    from safo.gate import judge_repository

    build_world(fake)
    repo(fake).default_branch = "a"
    repo(fake).protection = None
    repo(fake).rulesets = [ruleset("CI green", include=("refs/heads/[]a]",))]
    code, text = gate(fake, client)
    assert code == 2 and any(t.startswith("UNKNOWN") and WIDGETS in t and "pattern" in t for t in text)
    raw = {
        "isArchived": False,
        "viewerPermission": "READ",
        "defaultBranchRef": {"name": "a", "branchProtectionRule": None},
        "rulesets": {"totalCount": 1, "nodes": [ruleset("CI green", include=("refs/heads/[]a]",))]},
    }
    got = judge_repository(raw, "CI green", True)
    assert got.unknown and not got.problems


def test_a_regex_compile_error_is_cannot_tell_not_a_crash(
    monkeypatch: pytest.MonkeyPatch, fake: FakeGitHub, client: Client
) -> None:
    import safo.gate as g

    monkeypatch.setattr(g, "_segment", lambda part, wide: "[z-a]")  # what the old parser emitted for `[z-a]`
    assert ref_matches("refs/heads/x*", "refs/heads/z") is None
    build_world(fake)
    repo(fake).protection = None
    repo(fake).rulesets = [ruleset("CI green", include=("refs/heads/x*",))]
    code, text = gate(fake, client)
    assert code == 2 and any(t.startswith("UNKNOWN") and "pattern" in t for t in text)


# -- allowance data: only an integer count means "none" ----------------------------------------------------------------


@pytest.mark.parametrize("key", ["bypassForcePushAllowances", "bypassPullRequestAllowances"])
@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("hide", ["absent", "null", "count_null", "count_text", "count_negative", "count_bool"])
def test_an_absent_or_null_allowance_count_is_cannot_tell_not_zero(
    fake: FakeGitHub, client: Client, key: str, force: bool, hide: str
) -> None:
    build_world(fake)
    rule = classic("CI green", force=force)
    if hide == "absent":
        del rule[key]
    else:
        rule[key] = {
            "null": None,
            "count_null": {"totalCount": None},
            "count_text": {"totalCount": "0"},
            "count_negative": {"totalCount": -1},
            "count_bool": {"totalCount": False},
        }[hide]
    repo(fake).protection = rule
    repo(fake).viewer_permission = "READ"
    code, text = gate(fake, client)
    assert code == 2 and any(t.startswith("UNKNOWN") and WIDGETS in t for t in text)


def test_an_integer_zero_allowance_count_from_a_non_admin_is_a_pass(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).viewer_permission = "READ"
    code, _ = gate(fake, client)
    assert code == 0
