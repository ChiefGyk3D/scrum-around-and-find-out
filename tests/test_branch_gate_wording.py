# SPDX-License-Identifier: Apache-2.0
"""The branch gate's output reads as sentences, in one grammar, and a bypass is named once."""

from __future__ import annotations

import re
from typing import Any

import pytest

from fakegh import FakeGitHub
from safo.graphql import Client
from test_branch_gate import WIDGETS, classic, gate, lines, repo, ruleset, with_rules
from world import build_world, load_test_board

REPO = r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+"
FINDING = re.compile(
    rf"^DRIFT   NO-GATE {REPO}: default branch '[^']+' "
    r"(has no branch protection and no active ruleset"
    r"|is protected but does not require the check '[^']+'( from app [0-9]+ \(.+\))?"
    r"|requires the check '[^']+'(, but it can be bypassed \(.+\)"
    r"| and blocks force pushes, but both can be bypassed \(.+\))"
    r"|blocks force pushes, but it can be bypassed \(.+\)"
    r"|allows force pushes)"
    r"( and (allows force pushes|blocks force pushes, but it can be bypassed \(.+\)))?$"
)
NOTE = re.compile(rf"^NOTE    NO-GATE (\(all repositories\)|{REPO}): \S.*$")


def actors(*modes: str) -> dict[str, Any]:
    return {"totalCount": len(modes), "nodes": [{"bypassMode": m} for m in modes]}


def test_one_ruleset_that_causes_both_bypasses_is_named_once(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = None
    repo(fake).rulesets = [ruleset("CI green") | {"bypassActors": actors("ALWAYS")}]
    code, text = gate(fake, client)
    (found,) = lines(text, WIDGETS)
    assert code == 1
    assert found.count("ruleset 'protect' has 1 bypass actor") == 1
    assert "requires the check 'CI green' and blocks force pushes, but both can be bypassed (" in found
    assert FINDING.match(found), found


def test_different_ways_round_each_requirement_are_two_clauses(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = classic("lint") | {"bypassForcePushAllowances": {"totalCount": 2}}
    repo(fake).rulesets = [ruleset("CI green", no_force=False) | {"bypassActors": actors("PULL_REQUEST")}]
    code, text = gate(fake, client)
    (found,) = lines(text, WIDGETS)
    assert code == 1
    assert "requires the check 'CI green', but it can be bypassed (ruleset 'protect' has 1 bypass actor" in found
    assert "blocks force pushes, but it can be bypassed (2 actors may bypass the block)" in found
    assert FINDING.match(found), found


def test_a_check_bypass_and_missing_force_block_read_as_one_sentence(fake: FakeGitHub, client: Client) -> None:
    build_world(fake)
    repo(fake).protection = None
    repo(fake).rulesets = [ruleset("CI green", no_force=False) | {"bypassActors": actors("ALWAYS")}]
    _, text = gate(fake, client)
    (found,) = lines(text, WIDGETS)
    assert "requires the check 'CI green', but it can be bypassed (" in found and found.endswith("allows force pushes")
    assert FINDING.match(found), found


@pytest.mark.parametrize(
    "setup",
    ["none", "no_check", "force", "both", "bypass_check", "bypass_force"],
)
def test_every_finding_matches_one_grammar(fake: FakeGitHub, client: Client, setup: str) -> None:
    build_world(fake)
    if setup == "none":
        repo(fake).protection = None
    elif setup == "no_check":
        repo(fake).protection = classic("lint")
    elif setup == "force":
        repo(fake).protection = classic("CI green", force=True)
    elif setup == "both":
        repo(fake).protection = classic("lint", force=True)
    elif setup == "bypass_check":
        repo(fake).protection = classic("CI green") | {"isAdminEnforced": False}
    else:
        repo(fake).protection = classic("CI green") | {"bypassForcePushAllowances": {"totalCount": 1}}
    board = with_rules(load_test_board(), gate_require_admin_enforced=setup == "bypass_check")
    _, text = gate(fake, client, board)
    (found,) = lines(text, WIDGETS)
    assert FINDING.match(found), found


@pytest.mark.parametrize("kind", ["archived", "empty", "exempt", "administrators", "not_configured"])
def test_every_gate_note_has_one_form(fake: FakeGitHub, client: Client, kind: str) -> None:
    """Archived, empty, exempt, administrator-exception and not-configured notes all read `NO-GATE <who>: <text>`."""
    build_world(fake)
    board = load_test_board()
    if kind == "archived":
        repo(fake).archived = True
    elif kind == "empty":
        repo(fake).default_branch = None
    elif kind == "exempt":
        board = with_rules(board, gate_exempt_repos=(WIDGETS,))
    elif kind == "administrators":
        repo(fake).protection = classic("CI green") | {"isAdminEnforced": False}
    else:
        board = with_rules(board, gate_check="")
    _, text = gate(fake, client, board)
    notes = [t for t in text if t.startswith("NOTE") and "NO-GATE" in t]
    assert len(notes) == 1, notes
    assert NOTE.match(notes[0]), notes[0]
