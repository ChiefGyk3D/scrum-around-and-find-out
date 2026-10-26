# SPDX-License-Identifier: Apache-2.0
"""A report is fresh only if it was posted no earlier than the moment its commit became the pull request head.

Equal head SHAs are not enough: a report written while the head was elsewhere, followed by a force-push to the
reported commit, must not read as fresh. Times come from the PR timeline (force-pushes, base changes) and, with no
force-push, from the head commit's committedDate, which the author controls: it is a floor, not proof.
"""

from __future__ import annotations

import functools
from typing import Any

import pytest

from fakegh import FakeGitHub
from test_handoff_check import A, B, C, comment, report, run

T1 = "2026-10-10T10:00:00Z"
T2 = "2026-10-12T10:00:00Z"
T3 = "2026-10-14T10:00:00Z"
T4 = "2026-10-16T10:00:00Z"
T5 = "2026-10-18T10:00:00Z"


def force(oid: Any, when: Any = T3) -> dict[str, Any]:
    return {"__typename": "HeadRefForcePushedEvent", "createdAt": when, "afterCommit": {"oid": oid}}


def base(when: Any = T3) -> dict[str, Any]:
    return {"__typename": "BaseRefChangedEvent", "createdAt": when}


def with_timeline(fake: FakeGitHub, comments: list[Any], **pull: Any) -> tuple[int, str]:
    code, out, _ = run(fake, comments, pull=pull)
    return code, out


# -- the replay: a report that predates the push ----------------------------------------------------------------


def test_a_report_posted_before_a_force_push_to_the_reported_commit_is_not_fresh(fake: FakeGitHub) -> None:
    # head was B, a trusted commenter posts a report naming A, the PR is then force-pushed to A
    code, out = with_timeline(fake, [comment(report(A), T2)], events=[force(A, T3)])
    assert code == 1 and out.startswith("STALE") and "before" in out and "FRESH" not in out


def test_a_report_posted_after_the_push_is_fresh(fake: FakeGitHub) -> None:
    assert with_timeline(fake, [comment(report(A), T4)], events=[force(A, T3)])[0] == 0


def test_a_report_posted_exactly_when_the_head_arrived_is_fresh(fake: FakeGitHub) -> None:
    assert with_timeline(fake, [comment(report(A), T3)], events=[force(A, T3)])[0] == 0
    assert with_timeline(fake, [comment(report(A), T2)], events=[force(A, T3)])[0] == 1  # one tick earlier is not


def test_an_edit_after_the_push_counts_as_the_later_time(fake: FakeGitHub) -> None:
    edited = comment(report(A), T2, edited=T4)
    assert with_timeline(fake, [edited], events=[force(A, T3)])[0] == 0
    assert with_timeline(fake, [comment(report(A), T2, edited=T2)], events=[force(A, T3)])[0] == 1


def test_a_force_push_back_to_an_earlier_reviewed_commit_needs_a_newer_report(fake: FakeGitHub) -> None:
    events = [force(A, T1), force(B, T2), force(A, T4)]  # A, then B, then back to A
    assert with_timeline(fake, [comment(report(A), T1)], events=events)[0] == 1  # the old review of A
    assert with_timeline(fake, [comment(report(A), T3)], events=events)[0] == 1  # posted while B was the head
    assert with_timeline(fake, [comment(report(A), T4)], events=events)[0] == 0
    assert with_timeline(fake, [comment(report(A), T5)], events=events)[0] == 0


def test_only_force_pushes_to_this_head_set_the_time(fake: FakeGitHub) -> None:
    events = [force(A, T1), force(C, T2)]  # a push of C later does not move the time A became the head
    assert with_timeline(fake, [comment(report(A), T1)], events=events)[0] == 0


# -- no force-push: the head commit's committedDate is the floor ------------------------------------------------


def test_without_a_force_push_the_commit_date_is_the_floor(fake: FakeGitHub) -> None:
    assert with_timeline(fake, [comment(report(A), T4)], pushed=T3)[0] == 0
    assert with_timeline(fake, [comment(report(A), T3)], pushed=T3)[0] == 0
    code, out = with_timeline(fake, [comment(report(A), T2)], pushed=T3)
    assert code == 1 and "before" in out


def test_a_head_commit_that_cannot_be_found_or_dated_is_unknown(fake: FakeGitHub) -> None:
    bad: list[Any] = [{"oid": B, "committedDate": T1}, {"oid": A, "committedDate": None}]
    bad += [{"oid": A, "committedDate": "soon"}, {"oid": A}, "x", {"committedDate": T1}, [], 7]
    for last in bad:
        code, out = with_timeline(fake, [comment(report(A), T4)], last_commit=last)
        assert code == 2 and "FRESH" not in out, last


def test_a_missing_commit_list_is_unknown(fake: FakeGitHub) -> None:
    fake.handlers["HandoffTimeline"] = lambda f, v: {
        "repository": {"pullRequest": {"timelineItems": {"pageInfo": {"hasPreviousPage": False}, "nodes": []},
                                       "commits": {"nodes": []}}}
    }  # fmt: skip
    assert run(fake, [comment(report(A), T4)])[0] == 2


# -- the base branch --------------------------------------------------------------------------------------------


def test_a_base_change_after_the_report_makes_it_stale(fake: FakeGitHub) -> None:
    code, out = with_timeline(fake, [comment(report(A), T2)], events=[base(T3)], pushed=T1)
    assert code == 1 and "base" in out


def test_a_base_change_before_or_at_the_report_is_fine(fake: FakeGitHub) -> None:
    assert with_timeline(fake, [comment(report(A), T3)], events=[base(T2)], pushed=T1)[0] == 0
    assert with_timeline(fake, [comment(report(A), T3)], events=[base(T3)], pushed=T1)[0] == 0


def test_the_latest_base_change_counts(fake: FakeGitHub) -> None:
    assert with_timeline(fake, [comment(report(A), T3)], events=[base(T1), base(T4)], pushed=T1)[0] == 1


# -- strict reading ---------------------------------------------------------------------------------------------


def test_a_truncated_timeline_is_unknown(fake: FakeGitHub) -> None:
    code, out = with_timeline(fake, [comment(report(A), T4)], events=[force(A, T3)], more_events=True)
    assert code == 2 and "truncated" in out and "FRESH" not in out


@pytest.mark.parametrize("flag", [None, "no", 0, 1])
def test_a_non_boolean_truncation_flag_is_unknown(fake: FakeGitHub, flag: Any) -> None:
    assert with_timeline(fake, [comment(report(A), T4)], more_events=flag)[0] == 2


@pytest.mark.parametrize(
    "event",
    [
        None,
        "x",
        {},
        {"__typename": "ReopenedEvent", "createdAt": T3},
        {"__typename": "ReopenedEvent", "createdAt": T3, "afterCommit": {"oid": A}},
        {"__typename": "HeadRefForcePushedEvent", "createdAt": T3},
        {"__typename": "HeadRefForcePushedEvent", "createdAt": T3, "afterCommit": None},
        {"__typename": "HeadRefForcePushedEvent", "createdAt": T3, "afterCommit": {"oid": "abc"}},
        {"__typename": "HeadRefForcePushedEvent", "createdAt": None, "afterCommit": {"oid": A}},
        {"__typename": "HeadRefForcePushedEvent", "createdAt": "later", "afterCommit": {"oid": A}},
        {"__typename": "BaseRefChangedEvent"},
        {"__typename": "BaseRefChangedEvent", "createdAt": 5},
    ],
)
def test_a_bad_timeline_event_is_unknown(fake: FakeGitHub, event: Any) -> None:
    code, out = with_timeline(fake, [comment(report(A), T5)], events=[event], pushed=T1)
    assert code == 2 and "FRESH" not in out


def test_a_null_timeline_is_unknown(fake: FakeGitHub) -> None:
    answers: list[dict[str, Any]] = [
        {"repository": {"pullRequest": {"timelineItems": None, "commits": {"nodes": []}}}},
        {"repository": {"pullRequest": None}},
        {"repository": None},
        {"repository": {"pullRequest": {"commits": {"nodes": []}}}},
    ]
    for answer in answers:
        fake.handlers["HandoffTimeline"] = functools.partial(lambda f, v, a: a, a=answer)
        assert run(fake, [comment(report(A))])[0] == 2


def test_the_timeline_is_read_only_when_the_shas_match(fake: FakeGitHub) -> None:
    run(fake, [comment(report(A))], head=B)
    assert "HandoffTimeline" not in fake.requests
    fake.requests.clear()
    run(fake, [comment(report(A))])
    assert fake.requests == ["HandoffPr", "HandoffComments", "HandoffTimeline", "HandoffPr"]


def test_the_timeline_query_asks_for_only_the_events_it_uses() -> None:
    from safo.modes import handoff

    assert (
        "HEAD_REF_FORCE_PUSHED_EVENT" in handoff.TIMELINE_QUERY and "BASE_REF_CHANGED_EVENT" in handoff.TIMELINE_QUERY
    )
    assert "last: 50" in handoff.TIMELINE_QUERY and "mutation" not in handoff.TIMELINE_QUERY.lower()
