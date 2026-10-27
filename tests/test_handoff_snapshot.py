# SPDX-License-Identifier: Apache-2.0
"""The verdict is decided from one consistent state: everything it depends on is read again at the end.

Each test lets one read answer differently the second time, as if the pull request changed in between. Any difference
from the first reads is unknown, never fresh and never stale.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from fakegh import FakeGitHub
from fakegh.core import HANDLERS
from test_handoff_check import A, B, comment, report, run

T3 = "2026-10-14T10:00:00Z"
T4 = "2026-10-16T10:00:00Z"
T5 = "2026-10-18T10:00:00Z"
T6 = "2026-10-20T10:00:00Z"
CHANGED = "changed while it was being read"
PUSH = {"__typename": "HeadRefForcePushedEvent", "createdAt": T3, "afterCommit": {"oid": A}}


def drift(fake: FakeGitHub, op: str, change: Callable[[dict[str, Any]], None], from_call: int = 2) -> None:
    """Make `op` answer as usual, then apply `change` to the answer from its `from_call`-th request on."""
    calls: list[int] = []
    original = HANDLERS[op]

    def handler(f: FakeGitHub, v: dict[str, Any]) -> dict[str, Any]:
        calls.append(1)
        data: dict[str, Any] = original(f, v)
        if len(calls) >= from_call:
            change(data)
        return data

    fake.handlers[op] = handler


def pull(data: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = data["repository"]["pullRequest"]
    return result


def go(fake: FakeGitHub) -> tuple[int, str]:
    code, out, _ = run(fake, [comment(report(A), T4)], pull={"events": [PUSH]})
    return code, out


def test_without_any_drift_the_same_pull_request_is_fresh(fake: FakeGitHub) -> None:
    code, out = go(fake)
    assert code == 0 and out.startswith("FRESH")


def test_the_base_changing_after_the_timeline_was_read_is_unknown(fake: FakeGitHub) -> None:
    """The repro: report at T4, force-push at T3, the base changes at T5, the head is still A at the end."""
    drift(fake, "HandoffPr", lambda d: pull(d).update(baseRefOid="e" * 40))
    code, out = go(fake)
    assert code == 2 and CHANGED in out and "FRESH" not in out


def test_the_base_branch_being_renamed_is_unknown(fake: FakeGitHub) -> None:
    drift(fake, "HandoffPr", lambda d: pull(d).update(baseRefName="release"))
    assert go(fake)[0] == 2


def test_a_base_change_event_that_appears_at_the_end_is_unknown(fake: FakeGitHub) -> None:
    drift(
        fake,
        "HandoffTimeline",
        lambda d: pull(d)["timelineItems"]["nodes"].append({"__typename": "BaseRefChangedEvent", "createdAt": T5}),
    )
    code, out = go(fake)
    assert code == 2 and CHANGED in out and "STALE" not in out


def test_a_force_push_after_the_report_between_the_reads_is_unknown(fake: FakeGitHub) -> None:
    later = {"__typename": "HeadRefForcePushedEvent", "createdAt": T6, "afterCommit": {"oid": B}}
    drift(fake, "HandoffTimeline", lambda d: pull(d)["timelineItems"]["nodes"].append(later))
    code, out = go(fake)
    # the second timeline read is itself unknown (the head would have left after its force-push), before any comparison
    assert code == 2 and "FRESH" not in out and "STALE" not in out


def test_a_force_push_to_the_same_head_again_between_the_reads_is_unknown(fake: FakeGitHub) -> None:
    again = {"__typename": "HeadRefForcePushedEvent", "createdAt": T6, "afterCommit": {"oid": A}}
    drift(fake, "HandoffTimeline", lambda d: pull(d)["timelineItems"]["nodes"].append(again))
    assert go(fake)[0] == 2


def test_a_comment_edited_between_the_reads_is_unknown(fake: FakeGitHub) -> None:
    def edit(data: dict[str, Any]) -> None:
        node = pull(data)["comments"]["nodes"][0]
        node["lastEditedAt"] = T6
        node["bodyHTML"] = node["bodyHTML"].replace("reviewer", "adversarial-reviewer", 1)

    drift(fake, "HandoffComments", edit)
    code, out = go(fake)
    assert code == 2 and CHANGED in out


def test_a_new_report_between_the_reads_is_unknown(fake: FakeGitHub) -> None:
    drift(fake, "HandoffComments", lambda d: pull(d)["comments"]["nodes"].append(comment(report(B), T6)))
    assert go(fake)[0] == 2


def test_a_report_that_gets_minimized_between_the_reads_is_unknown(fake: FakeGitHub) -> None:
    drift(fake, "HandoffComments", lambda d: pull(d)["comments"]["nodes"][0].update(isMinimized=True))
    assert go(fake)[0] == 2


def test_the_head_state_changing_between_the_reads_is_unknown(fake: FakeGitHub) -> None:
    drift(fake, "HandoffPr", lambda d: pull(d).update(state="CLOSED"))
    assert go(fake)[0] == 2
    drift(fake, "HandoffPr", lambda d: pull(d).update(isDraft=True))
    assert go(fake)[0] == 2


def test_a_stale_answer_is_also_checked_for_drift(fake: FakeGitHub) -> None:
    """A report naming an older head is stale only if the pull request held still while it was read."""
    drift(fake, "HandoffPr", lambda d: pull(d).update(baseRefOid="e" * 40))
    code, out, _ = run(fake, [comment(report(A), T4)], head=B)
    assert code == 2 and CHANGED in out


def test_the_pull_request_read_is_the_final_request_of_a_fresh_run(fake: FakeGitHub) -> None:
    """A push after the last read cannot be seen, so the head must be the last thing read: a normal push leaves no
    timeline event and no comment, and only the head read can show it."""
    go(fake)
    assert fake.requests[-1] == "HandoffPr" and fake.requests.count("HandoffPr") == 2


def test_the_pull_request_read_is_also_the_final_request_of_a_stale_run(fake: FakeGitHub) -> None:
    run(fake, [comment(report(A), T4)], head=B)
    assert fake.requests[-1] == "HandoffPr" and fake.requests == [
        "HandoffPr",
        "HandoffComments",
        "HandoffComments",
        "HandoffPr",
    ]


def test_a_head_that_changes_after_the_final_timeline_and_comments_reads_is_unknown(fake: FakeGitHub) -> None:
    """The repro: both timeline reads and both comment reads agree, a normal push to B lands, then the final head
    read answers B. Nothing queried before it shows the push."""
    drift(fake, "HandoffPr", lambda d: pull(d).update(headRefOid=B))
    code, out = go(fake)
    assert code == 2 and CHANGED in out and "FRESH" not in out


def test_the_second_round_of_reads_comes_after_the_first(fake: FakeGitHub) -> None:
    go(fake)
    assert fake.requests == [
        "HandoffPr",
        "HandoffComments",
        "HandoffTimeline",
        "HandoffTimeline",
        "HandoffComments",
        "HandoffPr",
    ]


@pytest.mark.parametrize(
    ("name", "oid"), [(None, "d" * 40), ("", "d" * 40), (5, "d" * 40), ("main", None), ("main", "abc"), ("main", 7)]
)
def test_a_missing_or_mistyped_base_is_unknown(fake: FakeGitHub, name: Any, oid: Any) -> None:
    code, out, _ = run(fake, [comment(report(A), T4)], pull={"events": [PUSH], "base_name": name, "base_oid": oid})
    assert code == 2 and "FRESH" not in out
