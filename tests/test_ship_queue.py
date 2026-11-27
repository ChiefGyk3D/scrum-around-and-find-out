# SPDX-License-Identifier: Apache-2.0
"""safo-ship --queue (issue #586): one PR at a time, head lag, update-branch, named stops. Fake gh, no network."""

from __future__ import annotations

import json
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


def test_a_head_change_that_is_not_the_update_commit_is_head_moved(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("BEHIND"), sv("BEHIND", head=NEW)]
    rig.state["parents"] = [MOVED, "d" * 40]  # a push by someone else: the pin is not a parent
    code, out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_HEAD_MOVED and NEW in out and merges(calls) == []


def test_a_conflict_found_at_merge_time_is_a_conflict_stop(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["merges"] = [{"rc": 1, "err": "Pull request is not mergeable: merge conflict between base and head"}]
    code, out, _calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_CONFLICT and out.startswith("CONFLICT")


def test_update_wait_and_ci_wait_share_one_per_pr_timeout(rig: Rig) -> None:  # noqa: F811
    pending = [check("CI green", status="IN_PROGRESS")]
    rig.state["views"] = [
        sv("BEHIND"),
        sv("BEHIND"),
        sv("BEHIND"),
        sv("BEHIND", head=NEW),
        sv("CLEAN", head=NEW, rollup=pending),
    ]
    code, _out, _calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1", "--timeout", "5")
    assert code == ship.EXIT_TIMEOUT and sum(rig.slept) <= 5


# Daybreak round 1 (PR #594)


def test_a_commit_status_named_like_the_gate_never_satisfies_it(rig: Rig) -> None:  # noqa: F811
    spoof = [check("test"), {"context": "CI green", "state": "SUCCESS"}]
    rig.state["views"] = [sv("CLEAN", rollup=spoof)]
    code, _out, calls = rig.go("5", "--repo", REPO, "--max-polls", "3", "--interval", "1")
    assert code == ship.EXIT_TIMEOUT and merges(calls) == []


def test_a_check_run_from_the_wrong_app_never_satisfies_the_gate(rig: Rig) -> None:  # noqa: F811
    other = [dict(check("CI green"), app_id=999)]
    rig.state["views"] = [sv("CLEAN", rollup=other)]
    code, out, calls = rig.go("5", "--repo", REPO, "--max-polls", "3", "--interval", "1")
    assert code == ship.EXIT_TIMEOUT and "999" not in out and merges(calls) == []


def test_the_app_id_in_branch_protection_is_the_one_required(rig: Rig) -> None:  # noqa: F811
    rig.state["protection"] = {
        "rc": 0,
        "out": json.dumps({"contexts": [], "checks": [{"context": "ci / x", "app_id": 7}]}),
    }
    roll = [check("CI green"), dict(check("ci / x"), app_id=8)]
    rig.state["views"] = [sv("CLEAN", rollup=roll)]
    code, _out, calls = rig.go("5", "--repo", REPO, "--max-polls", "3", "--interval", "1")
    assert code == ship.EXIT_TIMEOUT and merges(calls) == []
    roll = [check("CI green"), dict(check("ci / x"), app_id=7)]
    rig.state["views"] = [sv("CLEAN", rollup=roll), sv("CLEAN", rollup=roll, state="MERGED")]
    rig.state["calls"] = []
    code, _out, calls = rig.go("5", "--repo", REPO, "--max-polls", "3", "--interval", "1")
    assert code == 0


def test_check_runs_are_read_with_pagination(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN"), sv("CLEAN"), sv("CLEAN", state="MERGED")]
    _code, _out, calls = rig.go("5", "--repo", REPO)
    runs = [c for c in calls if len(c) > 2 and c[1] == "api" and "/check-runs" in c[2]]
    assert runs and all("--paginate" in c for c in runs)


def test_an_update_commit_must_be_a_verified_web_flow_merge_of_pin_and_base_tip(rig: Rig) -> None:  # noqa: F811
    for key, value in (("parents", [HEAD, "f" * 40]), ("committer", "someone"), ("verified", False)):
        rig.state.update({"parents": [HEAD, "e" * 40], "committer": "web-flow", "verified": True})
        rig.state[key] = value
        rig.state["views"] = [sv("BEHIND"), sv("BEHIND", head=NEW)]
        rig.state["calls"] = []
        code, out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
        assert code == ship.EXIT_HEAD_MOVED and merges(calls) == [], (key, out)


def test_the_thread_check_warns_when_protection_does_not_require_resolution(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["conv"] = {"enabled": False}
    _code, out, _calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert "NOTICE" in out and "best-effort" in out


def test_no_notice_when_protection_requires_resolution(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    _code, out, _calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert "NOTICE" not in out


def test_threads_are_read_right_before_the_merge_call(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    _code, _out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    names = [" ".join(c[1:3]) for c in calls]
    assert names.index("pr merge") - names.index("api graphql") == 1


def test_head_lag_wait_respects_the_per_pr_timeout(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN", head=MOVED)]
    code, _out, _calls = rig.go(
        "--queue", "5", "--repo", REPO, "--pin", f"5={HEAD}", "--interval", "300", "--timeout", "1"
    )
    assert code == ship.EXIT_HEAD_MOVED and sum(rig.slept) <= 1


def test_ci_wait_sleeps_no_longer_than_the_remaining_time(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN", rollup=[])]
    code, _out, _calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "300", "--timeout", "2")
    assert code == ship.EXIT_TIMEOUT and sum(rig.slept) <= 2


def test_a_total_deadline_bounds_the_whole_queue(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN", rollup=[])]
    code, out, _calls = rig.go(
        "--queue", "5", "6", "7", "--repo", REPO, "--interval", "1", "--timeout", "1000", "--total-timeout", "3"
    )
    words = [ln.split()[0] for ln in out.strip().splitlines()]
    assert code == ship.EXIT_TIMEOUT and words == ["TIMEOUT", "SKIPPED", "SKIPPED"] and sum(rig.slept) <= 3


def test_each_gh_call_gets_no_more_time_than_remains() -> None:
    seen: list[float] = []

    def fake(argv: list[str], **kw: Any) -> Any:
        seen.append(kw["timeout"])
        return type("R", (), {"returncode": 0, "stdout": "{}", "stderr": ""})()

    gh = ship.Gh("gh", "git", {}, fake, None, clock=lambda: 10.0, limit=14.0)
    gh.gh_call("x")
    gh.limit = None
    gh.gh_call("x")
    assert seen == [4.0, ship.CALL_TIMEOUT]


@pytest.mark.parametrize(
    ("protection", "word"),
    [
        ({"rc": 1, "err": "HTTP 500: upstream request 404 failed", "http": 500}, "ERROR"),
        ({"rc": 1, "err": "gh: Not Found", "http": 403}, "ERROR"),
        ({"rc": 1, "err": "oops", "http": 404}, "CI-FAILED"),
    ],
)
def test_protection_is_judged_by_the_http_status_not_by_stderr_text(
    rig: Rig,  # noqa: F811
    protection: dict[str, Any],
    word: str,
) -> None:
    rig.state["protection"] = protection
    rig.state["views"] = [sv("CLEAN", rollup=[check("CI green", conclusion="FAILURE")])]
    code, out, calls = rig.go("5", "--repo", REPO, "--max-polls", "2")
    assert out.startswith(word) and merges(calls) == []
    assert (code == ship.EXIT_ERROR) == (word == "ERROR")


def test_the_fake_server_refuses_a_merge_whose_pin_is_not_the_head(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["head_at_merge"] = MOVED  # the head moved after the last read
    code, out, _calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code != 0 and "MERGED" not in out.split()[0]
    assert rig.state_path.exists() and json.loads(rig.state_path.read_text())["merge_attempts"] == [[HEAD]]


def test_a_conflict_is_taken_from_structured_state_not_the_error_text(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN"), sv("CLEAN"), sv("CLEAN"), sv("DIRTY", "CONFLICTING")]
    rig.state["merges"] = [{"rc": 1, "err": "refused"}]
    code, _out, _calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_CONFLICT


def test_blocked_state_is_a_protection_stop_without_help_from_the_text(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN"), sv("CLEAN"), sv("CLEAN"), sv("BLOCKED")]
    rig.state["merges"] = [{"rc": 1, "err": "refused"}]
    code, _out, _calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_PROTECTED


def test_hostile_words_in_the_error_text_alone_do_not_name_a_stop_in_plain_mode(rig: Rig) -> None:  # noqa: F811
    rig.state["merges"] = [{"rc": 1, "err": "blocked conflict policy"}]
    code, out, _calls = rig.go("5", "--repo", REPO)
    assert code == ship.EXIT_MERGE_REFUSED and out.startswith("MERGE-REFUSED")


@pytest.mark.parametrize(
    "block",
    [
        {"nodes": None, "pageInfo": {"hasNextPage": False, "endCursor": ""}},
        {"nodes": [{"isResolved": False, "comments": []}], "pageInfo": {"hasNextPage": False, "endCursor": ""}},
        {"nodes": [{"isResolved": False, "comments": {"nodes": ["x"]}}], "pageInfo": {"hasNextPage": False}},
        {"nodes": "abc", "pageInfo": {"hasNextPage": False, "endCursor": ""}},
    ],
)
def test_malformed_thread_output_is_exit_7_not_a_traceback(rig: Rig, block: dict[str, Any]) -> None:  # noqa: F811
    rig.state["threads"] = [{"data": {"repository": {"pullRequest": {"reviewThreads": block}}}}]
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == ship.EXIT_ERROR and out.startswith("ERROR") and merges(calls) == []


def test_non_positive_pull_request_numbers_are_a_usage_error(rig: Rig) -> None:  # noqa: F811
    for argv in (["--queue", "0"], ["0"], ["--queue", "5", "-3"]):
        with pytest.raises(SystemExit) as stop:
            rig.go(*argv, "--repo", REPO)
        assert stop.value.code == 2
