# SPDX-License-Identifier: Apache-2.0
"""audit: open pull requests that are CONFLICTING are drift, BEHIND ones a note, and a count is always printed."""

from __future__ import annotations

import argparse
from collections.abc import Iterator
from typing import Any

import pytest

from fakegh import FakeGitHub
from safo.graphql import Client
from safo.modes.audit import run
from world import build_world, load_test_board, make_context


@pytest.fixture(autouse=True)
def _audit_sends_no_mutations(fake: FakeGitHub) -> Iterator[None]:
    yield
    assert fake.mutations == []


def audit(fake: FakeGitHub, client: Client) -> tuple[int, str]:
    ctx, out = make_context(fake, load_test_board(), client)
    return run(ctx, argparse.Namespace()), out.getvalue()


def add_pr(fake: FakeGitHub, project: Any, number: int, **kw: Any) -> None:
    pr = fake.add_content("acme/widgets", "PullRequest", number, body="Closes #1", **kw)
    fake.add_item(project, pr, Status="In progress", Area="Core", Priority="P2 later")


def test_a_conflicting_pull_request_is_drift_and_counted(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    add_pr(fake, project, 2, mergeable="CONFLICTING", merge_state="DIRTY")
    add_pr(fake, project, 3)
    code, text = audit(fake, client)
    assert code == 1
    assert "DRIFT   CONFLICT acme/widgets#2 has merge conflicts with its base" in text
    assert "CONFLICT acme/widgets#3" not in text
    assert "NOTE    mergeability: 2 open pull requests, 1 conflicting, 0 behind, 0 not yet computed" in text


def test_a_behind_pull_request_is_a_note_not_drift(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    add_pr(fake, project, 2, merge_state="BEHIND")
    code, text = audit(fake, client)
    assert code == 0 and text.splitlines()[-1] == "clean"
    assert "NOTE    BEHIND acme/widgets#2 is behind its base" in text
    assert "1 conflicting" not in text and "0 conflicting, 1 behind" in text


def test_a_pull_request_that_is_both_conflicting_and_behind_is_counted_once(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    add_pr(fake, project, 2, mergeable="CONFLICTING", merge_state="BEHIND")
    code, text = audit(fake, client)
    assert code == 1 and "1 conflicting, 0 behind" in text and "BEHIND acme" not in text


@pytest.mark.parametrize("mergeable", ["UNKNOWN", None])
def test_a_mergeable_that_is_still_being_computed_is_unknown_not_drift(
    fake: FakeGitHub, client: Client, mergeable: Any
) -> None:
    _, project = build_world(fake)
    add_pr(fake, project, 2, mergeable=mergeable, merge_state="UNKNOWN")
    code, text = audit(fake, client)
    assert code == 0 and text.splitlines()[-1] == "clean"
    assert "0 conflicting, 0 behind, 1 not yet computed" in text and "CONFLICT acme" not in text


def test_a_merged_or_closed_pull_request_is_not_checked(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    pr = fake.add_content(
        "acme/widgets", "PullRequest", 2, state="CLOSED", closed_at="2026-10-05T00:00:00Z", mergeable="CONFLICTING"
    )
    fake.add_item(project, pr, Status="Done", Area="Core", Priority="P2 later", Done_on="2026-10-05")
    _, text = audit(fake, client)
    assert "CONFLICT acme" not in text and "0 open pull requests" in text


def test_a_malformed_mergeable_is_unknown_to_the_audit_and_exits_2(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    add_pr(fake, project, 2, mergeable=7)
    code, text = audit(fake, client)
    assert code == 2 and "UNKNOWN " in text and "mergeable" in text


def test_the_check_reads_one_query_per_repository_and_never_the_whole_project(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    add_pr(fake, project, 2)
    audit(fake, client)
    assert sum("RepoPullMergeable" in r for r in fake.requests) == len(load_test_board().repositories)
