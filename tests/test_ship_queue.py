# SPDX-License-Identifier: Apache-2.0
"""safo-ship --queue (issue #586): one PR at a time, head lag, update-branch, named stops. Fake gh, no network."""

from __future__ import annotations

from typing import Any

import pytest

from safo import ship
from test_ship import GREEN, HEAD, MOVED, REPO, Rig, check, merges, rig, threads, view  # noqa: F401 (rig is a fixture)

NEW = "c" * 40


def sv(status: str, mergeable: str = "MERGEABLE", **kw: Any) -> dict[str, Any]:
    data = view(kw.pop("rollup", GREEN), **kw)
    data["mergeStateStatus"], data["mergeable"] = status, mergeable
    return data


def updates(calls: list[list[str]]) -> list[list[str]]:
    return [c for c in calls if len(c) > 2 and c[1] == "api" and "update-branch" in c[2]]


def test_queue_merges_each_pr_in_order_one_at_a_time(rig: Rig) -> None:  # noqa: F811
    done = sv("CLEAN", state="MERGED")
    rig.state["views"] = [sv("CLEAN"), sv("CLEAN"), sv("CLEAN"), done, sv("CLEAN"), sv("CLEAN"), sv("CLEAN"), done]
    code, out, calls = rig.go("--queue", "5", "6", "--repo", REPO, "--interval", "1")
    assert code == 0, out
    assert [ln.split()[0] for ln in out.strip().splitlines()] == ["MERGED", "MERGED"]
    assert [c[3] for c in merges(calls)] == ["5", "6"]


def test_queue_stops_at_the_first_failure_and_does_not_touch_later_prs(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("DIRTY", "CONFLICTING")]
    code, out, calls = rig.go("--queue", "5", "6", "--repo", REPO, "--interval", "1")
    lines = out.strip().splitlines()
    assert code == ship.EXIT_CONFLICT and lines[0].startswith("CONFLICT") and "#5" in lines[0]
    assert lines[1].startswith("SKIPPED") and "#6" in lines[1]
    assert merges(calls) == [] and not any(c[3:4] == ["6"] for c in calls if c[1:3] == ["pr", "view"])


def test_head_lag_is_retried_until_the_pinned_head_shows(rig: Rig) -> None:  # noqa: F811
    old = sv("CLEAN", head=MOVED)
    rig.state["views"] = [old, old, sv("CLEAN"), sv("CLEAN"), sv("CLEAN"), sv("CLEAN", state="MERGED")]
    code, out, calls = rig.go("--queue", "5", "--repo", REPO, "--pin", f"5={HEAD}", "--interval", "1")
    assert code == 0, out
    assert merges(calls)[0][merges(calls)[0].index("--match-head-commit") + 1] == HEAD


def test_head_that_never_catches_up_is_head_moved_after_a_bounded_wait(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN", head=MOVED)]
    code, out, calls = rig.go("--queue", "5", "--repo", REPO, "--pin", f"5={HEAD}", "--interval", "1")
    assert code == ship.EXIT_HEAD_MOVED and MOVED in out and merges(calls) == []
    assert 1 <= len(rig.slept) <= ship.HEAD_LAG_POLLS


def test_a_head_that_moves_after_it_was_seen_is_not_treated_as_lag(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN"), sv("CLEAN", head=MOVED)]
    code, _out, calls = rig.go("--queue", "5", "--repo", REPO, "--pin", f"5={HEAD}", "--interval", "1")
    assert code == ship.EXIT_HEAD_MOVED and merges(calls) == []


def test_behind_calls_update_branch_once_repins_and_merges_the_new_head(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [
        sv("BEHIND"),
        sv("BEHIND"),  # update accepted, head not yet changed
        sv("BEHIND", head=NEW),
        sv("CLEAN", head=NEW),
        sv("CLEAN", head=NEW),
        sv("CLEAN", head=NEW, state="MERGED"),
    ]
    code, out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code == 0, out
    (up,) = updates(calls)
    assert f"expected_head_sha={HEAD}" in up
    (merge,) = merges(calls)
    assert merge[merge.index("--match-head-commit") + 1] == NEW
    assert NEW[:12] in out


def test_still_behind_after_one_update_stops_instead_of_looping(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("BEHIND"), sv("BEHIND", head=NEW), sv("BEHIND", head=NEW)]
    code, _out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert len(updates(calls)) == 1 and merges(calls) == [] and code != 0


def test_update_branch_that_never_moves_the_head_times_out(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("BEHIND")]
    code, _out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_TIMEOUT and len(updates(calls)) == 1 and merges(calls) == []
    assert len(rig.slept) <= ship.UPDATE_WAIT_POLLS


def test_update_branch_conflict_is_a_conflict_stop(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("BEHIND")]
    rig.state["update"] = {"rc": 1, "err": "gh: merge conflict between base and head (HTTP 422)"}
    code, out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_CONFLICT and out.startswith("CONFLICT") and merges(calls) == []


def test_update_branch_failure_otherwise_is_an_error(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("BEHIND")]
    rig.state["update"] = {"rc": 1, "err": "HTTP 500"}
    code, _out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_ERROR and merges(calls) == []


def test_behind_found_only_after_green_updates_then_waits_for_ci_again(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [
        sv("CLEAN"),  # pin read
        sv("CLEAN"),  # wait_ci green
        sv("BEHIND"),  # post-green check
        sv("BEHIND", head=NEW),  # head moved
        sv("CLEAN", head=NEW),
        sv("CLEAN", head=NEW),
        sv("CLEAN", head=NEW, state="MERGED"),
    ]
    code, out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code == 0, out
    assert len(updates(calls)) == 1 and merges(calls)[0][merges(calls)[0].index("--match-head-commit") + 1] == NEW


def test_conflicting_pr_names_the_stop_and_never_merges(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("DIRTY", "CONFLICTING")]
    code, out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_CONFLICT and out.startswith("CONFLICT") and merges(calls) == [] and updates(calls) == []


def test_unresolved_threads_list_the_count_in_queue_mode(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["threads"] = [threads("a.py", "b.py")]
    code, out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_THREADS and "2 unresolved review thread(s)" in out and merges(calls) == []


def test_a_failing_check_is_named_and_never_merged(rig: Rig) -> None:  # noqa: F811
    bad = [check("lint", conclusion="FAILURE", run=9, job=99), check("CI green", conclusion="FAILURE")]
    rig.state["views"] = [sv("BLOCKED", rollup=bad)]
    code, out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_CI_FAILED and "CI-FAILED" in out and "lint=FAILURE" in out and merges(calls) == []


def test_branch_protection_refusal_has_its_own_code_and_word(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["merges"] = [
        {"rc": 1, "err": "Pull request is not mergeable: the base branch policy prohibits the merge"}
    ]
    code, out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_PROTECTED and out.startswith("PROTECTED") and len(merges(calls)) == 1


def test_plain_mode_does_not_use_the_queue_behaviors(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("BEHIND")]
    rig.state["merges"] = [{"rc": 1, "err": "the base branch policy prohibits the merge"}]
    code, out, calls = rig.go("5", "--repo", REPO)
    assert updates(calls) == [] and code == ship.EXIT_MERGE_REFUSED and out.startswith("MERGE-REFUSED")


def test_queue_arguments_are_validated(rig: Rig) -> None:  # noqa: F811
    for argv in (
        ["--queue"],
        ["--pin", f"5={HEAD}", "5"],
        ["--queue", "5", "--pin", "6=" + HEAD],
        ["--queue", "5", "--pin", "5=zz"],
    ):
        with pytest.raises(SystemExit) as stop:
            rig.go(*argv, "--repo", REPO)
        assert stop.value.code == 2
