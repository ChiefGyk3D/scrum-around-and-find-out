# SPDX-License-Identifier: Apache-2.0
"""safo-ship --queue (issue #586): one PR at a time, head lag, update-branch, named stops. Fake gh, no network."""

from __future__ import annotations

import json
from typing import Any

import pytest

from safo import ship
from test_ship import (  # noqa: F401 (rig is a fixture)
    CLEAN,
    GREEN,
    HEAD,
    MOVED,
    REPO,
    Rig,
    check,
    merges,
    rig,
    threads,
    view,
)

NEW = "c" * 40


def sv(status: str, mergeable: str = "MERGEABLE", **kw: Any) -> dict[str, Any]:
    data = view(kw.pop("rollup", GREEN), **kw)
    data["mergeStateStatus"], data["mergeable"] = status, mergeable
    return data


def updates(calls: list[list[str]]) -> list[list[str]]:
    return [c for c in calls if len(c) > 2 and c[1] == "api" and "update-branch" in c[2]]


def test_queue_merges_each_pr_in_order_one_at_a_time(rig: Rig) -> None:  # noqa: F811
    done = sv("CLEAN", state="MERGED")
    rig.state["views"] = [*[sv("CLEAN")] * 5, done, *[sv("CLEAN")] * 5, done]
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
    rig.state["views"] = [view(GREEN)]
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
    rig.state["views"] = [view(GREEN)]  # no merge state: the text is the only evidence
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


def test_threads_are_read_right_before_the_merge_call(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    _code, _out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    names = [" ".join(c[1:3]) for c in calls]
    read = names.index("api graphql")
    protection = next(i for i, c in enumerate(calls) if c[1] == "api" and c[2].endswith("/protection"))
    assert (
        read < protection < names.index("pr merge")
    )  # the protection is read after the threads, just before the merge


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


def test_no_merge_starts_after_the_deadline(rig: Rig) -> None:  # noqa: F811
    pending = sv("CLEAN", rollup=[])
    rig.state["views"] = [pending, pending, pending, sv("CLEAN"), sv("CLEAN")]
    code, out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1", "--timeout", "2")
    assert code == ship.EXIT_TIMEOUT and out.startswith("TIMEOUT") and merges(calls) == []


# Daybreak round 2 (PR #594)


def run_of(name: str, run: int, app_id: int = 15368) -> dict[str, Any]:
    return {
        "name": name,
        "status": "completed",
        "conclusion": "success",
        "app_id": app_id,
        "details_url": f"https://github.com/o/r/actions/runs/{run}/job/{run}",
    }


def test_a_same_app_same_name_job_from_another_workflow_does_not_count(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["check_runs"] = [run_of("CI green", 1)]
    rig.state["run_api"] = {"1": {"path": ".github/workflows/evil.yml"}}
    code, _out, calls = rig.go("5", "--repo", REPO, "--max-polls", "3", "--interval", "1")
    assert code == ship.EXIT_TIMEOUT and merges(calls) == []


def test_only_the_trusted_workflows_job_counts_beside_an_impostor(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN"), sv("CLEAN"), sv("CLEAN", state="MERGED")]
    rig.state["check_runs"] = [run_of("CI green", 1), run_of("CI green", 2)]
    rig.state["run_api"] = {"1": {"path": ".github/workflows/evil.yml"}}
    code, out, _calls = rig.go("5", "--repo", REPO, "--max-polls", "3", "--interval", "1")
    assert code == 0, out


@pytest.mark.parametrize(
    "change",
    [
        {"head_sha": "f" * 40},
        {"event": "pull_request_target"},
        {"event": "workflow_dispatch"},
        {"conclusion": "failure"},
        {"status": "in_progress"},
        {"repository": {"full_name": "evil/r"}},
        {"path": ".github/workflows/ci.yml.evil"},
    ],
)
def test_the_gate_run_must_match_sha_event_repo_and_conclusion(
    rig: Rig,  # noqa: F811
    change: dict[str, Any],
) -> None:
    rig.state["views"] = [sv("CLEAN")]
    rig.state["check_runs"] = [run_of("CI green", 1)]
    rig.state["run_api"] = {"1": change}
    code, _out, calls = rig.go("5", "--repo", REPO, "--max-polls", "3", "--interval", "1")
    assert code == ship.EXIT_TIMEOUT and merges(calls) == []


def test_a_check_run_with_no_workflow_run_cannot_be_verified(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["check_runs"] = [dict(run_of("CI green", 1), details_url="https://example.com/x")]
    code, _out, calls = rig.go("5", "--repo", REPO, "--max-polls", "3", "--interval", "1")
    assert code == ship.EXIT_TIMEOUT and merges(calls) == []


def test_the_gate_workflow_flag_names_the_expected_path(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["run_api"] = {"777": {"path": ".github/workflows/build.yml"}}
    code, _out, calls = rig.go("5", "--repo", REPO, "--max-polls", "2", "--interval", "1")
    assert code == ship.EXIT_TIMEOUT and merges(calls) == []
    rig.state["views"] = [sv("CLEAN"), sv("CLEAN"), sv("CLEAN", state="MERGED")]
    code, out, _calls = rig.go(
        "5", "--repo", REPO, "--max-polls", "3", "--interval", "1", "--gate-workflow", ".github/workflows/build.yml"
    )
    assert code == 0, out


def test_without_a_derivable_gate_workflow_it_stops_with_an_error(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["workflows"] = [".github/workflows/a.yml", ".github/workflows/b.yml"]
    code, out, calls = rig.go("5", "--repo", REPO, "--max-polls", "2", "--interval", "1")
    assert code == ship.EXIT_ERROR and "--gate-workflow" in out and merges(calls) == []


@pytest.mark.parametrize("queue", [False, True])
@pytest.mark.parametrize("changed", [[".github/workflows/x.yml"], ["docs/a.md", ".github/workflows/ci.yml"]])
def test_a_pr_that_changes_workflow_files_is_not_merged_automatically(
    rig: Rig,  # noqa: F811
    queue: bool,
    changed: list[str],
) -> None:
    rig.state["views"] = [sv("CLEAN")]
    rig.state["changed"] = changed
    code, out, calls = rig.go(*(["--queue"] if queue else []), "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_NEEDS_HUMAN == 10 and out.startswith("NEEDS-HUMAN") and merges(calls) == []
    assert ".github/workflows" in out


def test_other_paths_do_not_trigger_the_workflow_stop(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN"), sv("CLEAN"), sv("CLEAN", state="MERGED")]
    rig.state["changed"] = ["docs/.github/workflows/x.yml", "scriptsX/a.sh", "src/a.py"]
    code, out, _calls = rig.go("5", "--repo", REPO, "--interval", "1")
    assert code == 0, out


def test_a_huge_file_list_fails_closed_and_is_read_with_pagination(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["changed"] = [f"f{i}.txt" for i in range(300)]
    code, _out, calls = rig.go("5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_NEEDS_HUMAN and merges(calls) == []
    compare = [c for c in calls if len(c) > 2 and c[1] == "api" and "/compare/" in c[2]]
    assert compare and all("--paginate" in c for c in compare)


def test_every_gh_call_is_capped_by_the_per_pr_deadline_and_none_starts_after_it(rig: Rig) -> None:  # noqa: F811
    rig.tick = 2.0
    rig.state["views"] = [sv("CLEAN", rollup=[])]
    code, _out, _calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1", "--timeout", "5")
    assert code == ship.EXIT_TIMEOUT and rig.timeouts
    assert all(now < 5 and now + (t or 0) <= 5 + 1e-9 for now, t in rig.timeouts), rig.timeouts


def test_the_total_deadline_also_caps_every_call(rig: Rig) -> None:  # noqa: F811
    rig.tick = 2.0
    rig.state["views"] = [sv("CLEAN", rollup=[])]
    code, _out, _calls = rig.go(
        "--queue", "5", "--repo", REPO, "--interval", "1", "--timeout", "1000", "--total-timeout", "3"
    )
    assert code == ship.EXIT_TIMEOUT
    assert all(now < 3 and now + (t or 0) <= 3 + 1e-9 for now, t in rig.timeouts), rig.timeouts


def test_a_call_is_not_started_after_the_deadline() -> None:
    seen: list[float] = []

    def blocking(argv: list[str], **kw: Any) -> Any:
        seen.append(kw["timeout"])
        raise AssertionError("must not start")

    gh = ship.Gh("gh", "git", {}, blocking, None, clock=lambda: 20.0, limit=14.0)
    with pytest.raises(ship.ShipError) as stop:
        gh.gh_call("x")
    assert stop.value.code == ship.EXIT_TIMEOUT and seen == []


def test_a_merge_retry_is_not_started_after_the_deadline(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["merges"] = [{"rc": 1, "err": "Base branch was modified"}]
    code, _out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1", "--timeout", "1")
    assert len(merges(calls)) <= 1 and code != 0


def test_required_check_apps_do_not_leak_between_queued_prs(rig: Rig) -> None:  # noqa: F811
    pinned = {"rc": 0, "out": json.dumps({"contexts": [], "checks": [{"context": "CI green", "app_id": 7}]})}
    rig.state["protection_by_base"] = {"main": pinned, "other": {"rc": 1, "err": "x", "http": 404}}
    first = sv("CLEAN", rollup=[dict(check("CI green"), app_id=7)])
    second = sv("CLEAN", rollup=[dict(check("CI green"), app_id=7)])
    second["baseRefName"] = "other"
    done = dict(first, state="MERGED")
    rig.state["views"] = [first, first, first, first, first, done, second]
    code, out, _calls = rig.go("--queue", "5", "6", "--repo", REPO, "--interval", "1", "--max-polls", "2")
    lines = out.strip().splitlines()
    assert lines[0].startswith("MERGED") and lines[1].startswith("TIMEOUT") and code == ship.EXIT_TIMEOUT


def test_clean_structured_state_beats_hostile_error_text(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["merges"] = [{"rc": 1, "err": "temporary backend conflict while applying policy"}]
    code, out, _calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_MERGE_REFUSED and out.startswith("MERGE-REFUSED")


def test_unknown_structured_state_falls_back_to_the_text(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("UNKNOWN", "UNKNOWN")]
    rig.state["merges"] = [{"rc": 1, "err": "merge conflict between base and head"}]
    code, _out, _calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_CONFLICT


# review of the round-2 commit


def with_runs(rig: Rig, change: dict[str, Any], runs: list[dict[str, Any]] | None = None) -> None:  # noqa: F811
    rig.state["check_runs"] = runs or [run_of("CI green", 1)]
    rig.state["run_api"] = {"1": change, "2": {}}


def test_a_gate_run_for_another_pr_with_the_same_sha_does_not_count(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    with_runs(rig, {"pull_requests": [{"number": 99, "base": {"ref": "main"}}]})
    code, _out, calls = rig.go("5", "--repo", REPO, "--max-polls", "3", "--interval", "1")
    assert code == ship.EXIT_TIMEOUT and merges(calls) == []


def test_a_gate_run_for_another_base_does_not_count(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    with_runs(rig, {"pull_requests": [{"number": 5, "base": {"ref": "other"}}]})
    code, _out, calls = rig.go("5", "--repo", REPO, "--max-polls", "3", "--interval", "1")
    assert code == ship.EXIT_TIMEOUT and merges(calls) == []


def test_a_push_run_counts_only_for_the_pr_head_branch(rig: Rig) -> None:  # noqa: F811
    push = {"event": "push", "pull_requests": [], "head_branch": "feat/x"}
    one = sv("CLEAN")
    one["headRefName"] = "feat/other"
    rig.state["views"] = [one]
    with_runs(rig, push)
    code, _out, calls = rig.go("5", "--repo", REPO, "--max-polls", "3", "--interval", "1")
    assert code == ship.EXIT_TIMEOUT and merges(calls) == []
    mine = sv("CLEAN")
    mine["headRefName"] = "feat/x"
    rig.state["views"] = [mine, mine, dict(mine, state="MERGED")]
    code, out, _calls = rig.go("5", "--repo", REPO, "--max-polls", "3", "--interval", "1")
    assert code == 0, out


def test_a_failed_gate_run_is_a_failure_not_something_to_ignore(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    with_runs(rig, {"conclusion": "failure"}, [run_of("CI green", 1), run_of("CI green", 2)])
    code, _out, calls = rig.go("5", "--repo", REPO, "--max-polls", "3", "--interval", "1")
    assert code == ship.EXIT_TIMEOUT and merges(calls) == []


def test_a_gate_definition_that_differs_between_base_and_pin_needs_a_human(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["blob_by_ref"] = {"main": "aaa", HEAD: "bbb"}
    code, out, calls = rig.go("5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_NEEDS_HUMAN and out.startswith("NEEDS-HUMAN") and merges(calls) == []


@pytest.mark.parametrize("changed", [[".github/actions/setup/action.yml"], [".github/CODEOWNERS"]])
def test_any_change_under_dot_github_needs_a_human(rig: Rig, changed: list[str]) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["changed"] = changed
    code, _out, calls = rig.go("--queue", "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_NEEDS_HUMAN and merges(calls) == []


def test_protected_paths_fail_closed_by_directory_boundary(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["changed"] = ["scripts/run.sh"]
    code, out, calls = rig.go(
        "5", "--repo", REPO, "--interval", "1", "--protect-path", "scripts", "--protect-path", "a/b.py"
    )
    assert code == ship.EXIT_NEEDS_HUMAN and "scripts/run.sh" in out and merges(calls) == []
    rig.state["views"] = [sv("CLEAN"), sv("CLEAN"), sv("CLEAN", state="MERGED")]
    rig.state["changed"] = ["scripts2/run.sh", "a/b.pyc"]
    code, out, _calls = rig.go(
        "5", "--repo", REPO, "--interval", "1", "--protect-path", "scripts", "--protect-path", "a/b.py"
    )
    assert code == 0, out


def test_bad_protected_paths_are_a_usage_error(rig: Rig) -> None:  # noqa: F811
    for bad in ("/etc", "../x", "a/../b", ""):
        with pytest.raises(SystemExit) as stop:
            rig.go("5", "--repo", REPO, "--protect-path", bad)
        assert stop.value.code == 2


@pytest.mark.parametrize("queue", [False, True])
def test_a_base_retarget_before_the_workflow_check_stops_the_merge(rig: Rig, queue: bool) -> None:  # noqa: F811
    ok = sv("CLEAN")
    moved = dict(ok, baseRefName="release")
    rig.state["views"] = [ok, ok, *([ok] if queue else []), moved]
    code, out, calls = rig.go(*(["--queue"] if queue else []), "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_MERGE_REFUSED and "base" in out and merges(calls) == []


@pytest.mark.parametrize("queue", [False, True])
def test_a_base_retarget_right_before_the_merge_stops_it(rig: Rig, queue: bool) -> None:  # noqa: F811
    ok = sv("CLEAN")
    moved = dict(ok, baseRefName="release")
    rig.state["views"] = [ok, ok, *([ok] if queue else []), ok, moved]
    code, out, calls = rig.go(*(["--queue"] if queue else []), "5", "--repo", REPO, "--interval", "1")
    assert code == ship.EXIT_MERGE_REFUSED and "base" in out and merges(calls) == []


# Daybreak round 3 (PR #594)

OFF = {"out": json.dumps({"required_conversation_resolution": {"enabled": False}})}
PINNED = "a" * 40
HOSTILE = "bad\n::error::forged\x1b[31m"


def args(queue: bool, *more: str) -> list[str]:
    return [*(["--queue"] if queue else []), "5", "--repo", REPO, "--interval", "1", *more]


@pytest.mark.parametrize("queue", [False, True])
@pytest.mark.parametrize(
    "protection",
    [
        OFF,
        {"out": json.dumps({})},
        {"out": json.dumps({"required_conversation_resolution": {"enabled": "true"}})},
        {"out": "not json"},
        {"rc": 1, "err": "HTTP 403"},
    ],
)
def test_without_required_conversation_resolution_nothing_is_merged(
    rig: Rig,  # noqa: F811
    queue: bool,
    protection: dict[str, Any],
) -> None:
    rig.state["views"] = [sv("CLEAN")]
    rig.state["full_protection"] = protection
    code, out, calls = rig.go(*args(queue))
    assert code == ship.EXIT_PROTECTED and out.startswith("PROTECTED")
    assert "conversation resolution is not required by branch protection" in out and merges(calls) == []


@pytest.mark.parametrize("queue", [False, True])
def test_the_opt_in_flag_merges_with_a_notice_naming_the_race(rig: Rig, queue: bool) -> None:  # noqa: F811
    rig.state["views"] = [*[sv("CLEAN")] * (5 if queue else 4), sv("CLEAN", state="MERGED")]
    rig.state["full_protection"] = OFF
    code, out, calls = rig.go(*args(queue, "--best-effort-threads"))
    assert code == 0 and "NOTICE" in out and "best-effort" in out and len(merges(calls)) == 1


def test_required_resolution_merges_without_a_notice(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [*[sv("CLEAN")] * 4, sv("CLEAN", state="MERGED")]
    code, out, _calls = rig.go(*args(False))
    assert code == 0 and "NOTICE" not in out


def test_the_refusal_text_is_escaped_with_a_hostile_base_name(rig: Rig) -> None:  # noqa: F811
    hostile = dict(sv("CLEAN"), baseRefName=HOSTILE)
    rig.state["views"] = [hostile]
    rig.state["protection_by_base"] = {}
    rig.state["full_protection"] = OFF
    code, out, _calls = rig.go(*args(True))
    assert code == ship.EXIT_PROTECTED and "\x1b" not in out and "::error" not in out and len(out.splitlines()) == 1


@pytest.mark.parametrize(
    "text",
    [
        "jobs:\n  a:\n    uses: actions/checkout@v4\n",
        "jobs:\n  a:\n    steps:\n      - uses: owner/repo/.github/workflows/x.yml@main\n",
        "jobs:\n  a:\n    steps:\n      - uses: 'owner/repo@v1' # pinned later\n",
        "jobs:\n  a:\n    steps:\n      - uses: docker://alpine:3\n",
    ],
)
def test_a_remote_reference_in_the_gate_must_be_pinned_by_sha(rig: Rig, text: str) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["gate_text"] = text
    code, out, calls = rig.go(*args(False))
    assert code == ship.EXIT_NEEDS_HUMAN and "unpinned" in out and merges(calls) == []


def test_pinned_remote_references_are_accepted(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [*[sv("CLEAN")] * 4, sv("CLEAN", state="MERGED")]
    rig.state["gate_text"] = (
        f"jobs:\n  a:\n    uses: o/x/.github/workflows/w.yml@{PINNED} # v1.2\n"
        f"    steps:\n      - uses: actions/checkout@{PINNED}\n      - uses: docker://a/b@sha256:{'c' * 64}\n"
    )
    code, out, _calls = rig.go(*args(False))
    assert code == 0, out


def test_a_local_action_the_gate_uses_must_be_the_same_on_base_and_head(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["gate_text"] = "jobs:\n  a:\n    steps:\n      - uses: ./tools/act\n"
    rig.state["local_by_ref"] = {"main": "one", HEAD: "two"}
    code, out, calls = rig.go(*args(False))
    assert code == ship.EXIT_NEEDS_HUMAN and "./tools/act" in out and merges(calls) == []


def test_a_nested_local_workflow_is_followed_and_its_remote_uses_are_checked(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["gate_text"] = "jobs:\n  a:\n    uses: ./ci/w.yml\n"
    rig.state["texts"] = {"ci/w.yml": "jobs:\n  b:\n    steps:\n      - uses: a/b@v1\n"}
    code, out, _calls = rig.go(*args(False))
    assert code == ship.EXIT_NEEDS_HUMAN and "unpinned" in out


def test_plain_mode_caps_every_call_by_the_per_pr_deadline(rig: Rig) -> None:  # noqa: F811
    rig.tick = 2.0
    rig.state["views"] = [sv("CLEAN", rollup=[])]
    code, _out, _calls = rig.go("5", "--repo", REPO, "--interval", "1", "--timeout", "5")
    assert code == ship.EXIT_TIMEOUT and rig.timeouts
    assert all(now < 5 and now + (t or 0) <= 5 + 1e-9 for now, t in rig.timeouts), rig.timeouts


def only_one_safe_line(out: str) -> bool:
    return len(out.strip().splitlines()) == 1 and "\x1b" not in out and "::error" not in out


def test_a_hostile_check_name_is_printed_as_one_safe_line(rig: Rig) -> None:  # noqa: F811
    bad = [check(HOSTILE, conclusion="FAILURE", run=9, job=99), check("CI green", conclusion="FAILURE")]
    rig.state["views"] = [sv("CLEAN", rollup=bad)]
    code, out, _calls = rig.go(*args(True))
    assert code == ship.EXIT_CI_FAILED and "forged" in out and only_one_safe_line(out)


def test_a_hostile_branch_name_is_printed_as_one_safe_line(rig: Rig) -> None:  # noqa: F811
    ok = sv("CLEAN")
    rig.state["views"] = [ok, ok, ok, dict(ok, baseRefName=HOSTILE)]
    code, out, _calls = rig.go(*args(True))
    assert code == ship.EXIT_MERGE_REFUSED and only_one_safe_line(out)


def test_a_hostile_gh_error_is_printed_as_one_safe_line(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("BEHIND")]
    rig.state["update"] = {"rc": 1, "err": HOSTILE}
    code, out, _calls = rig.go(*args(True))
    assert code == ship.EXIT_ERROR and only_one_safe_line(out)


def test_a_merge_call_that_times_out_is_a_timeout_naming_the_call(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.raise_on = "pr merge"
    code, out, _calls = rig.go(*args(True))
    assert code == ship.EXIT_TIMEOUT and out.startswith("TIMEOUT") and "pr merge" in out and "may" in out


def test_a_timed_out_read_is_a_timeout_not_an_error(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.raise_on = "pr view"
    code, out, _calls = rig.go(*args(False))
    assert code == ship.EXIT_TIMEOUT and out.startswith("TIMEOUT") and "pr view" in out


def test_with_no_derived_evidence_nothing_merges_and_explicit_evidence_does(rig: Rig) -> None:  # noqa: F811
    rig.state["derive_evidence"] = False
    rig.state["views"] = [sv("CLEAN")]
    code, _out, calls = rig.go(*args(False, "--max-polls", "2"))
    assert code == ship.EXIT_TIMEOUT and merges(calls) == []
    rig.state["check_runs"] = [run_of("CI green", 1)]
    rig.state["run_api"] = {
        "1": {
            "path": ".github/workflows/ci.yml",
            "head_sha": HEAD,
            "event": "pull_request",
            "status": "completed",
            "conclusion": "success",
            "repository": {"full_name": "o/r"},
            "pull_requests": [{"number": 5, "base": {"ref": "main"}}],
        }
    }
    rig.state["views"] = [*[sv("CLEAN")] * 4, sv("CLEAN", state="MERGED")]
    code, out, _calls = rig.go(*args(False))
    assert code == 0, out


# the structured scan of the gate workflow


def step(ref: str) -> str:
    return f"      - uses: {ref}\n"


def gate_with(rig: Rig, text: str) -> tuple[int, str, list[list[str]]]:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["gate_text"] = text
    return rig.go(*args(False))


def test_51_references_in_one_file_need_a_human(rig: Rig) -> None:  # noqa: F811
    text = "jobs:\n  a:\n    steps:\n" + "".join(step(f"o/r@{PINNED}") for _ in range(51))
    code, out, calls = gate_with(rig, text)
    assert code == ship.EXIT_NEEDS_HUMAN and "too many references or nesting too deep to verify" in out
    assert merges(calls) == []


def test_50_references_are_still_read(rig: Rig) -> None:  # noqa: F811
    text = "jobs:\n  a:\n    steps:\n" + "".join(step(f"o/r@{PINNED}") for _ in range(50))
    rig.state["views"] = [*[sv("CLEAN")] * 4, sv("CLEAN", state="MERGED")]
    rig.state["gate_text"] = text
    code, out, _calls = rig.go(*args(False))
    assert code == 0, out


def test_local_workflows_nested_too_deep_need_a_human(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["gate_text"] = "jobs:\n  a:\n    uses: ./w1.yml\n"
    rig.state["texts"] = {
        "w1.yml": "jobs:\n  a:\n    uses: ./w2.yml\n",
        "w2.yml": "jobs:\n  a:\n    uses: ./w3.yml\n",
        "w3.yml": "jobs:\n  a:\n    uses: ./w4.yml\n",
        "w4.yml": "jobs:\n  a:\n    runs-on: x\n",
    }
    code, out, calls = rig.go(*args(False))
    assert code == ship.EXIT_NEEDS_HUMAN and "too many references or nesting too deep to verify" in out
    assert merges(calls) == []


def test_three_levels_of_local_workflows_are_followed(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [*[sv("CLEAN")] * 4, sv("CLEAN", state="MERGED")]
    rig.state["gate_text"] = "jobs:\n  a:\n    uses: ./w1.yml\n"
    rig.state["texts"] = {
        "w1.yml": "jobs:\n  a:\n    uses: ./w2.yml\n",
        "w2.yml": "jobs:\n  a:\n    uses: ./w3.yml\n",
        "w3.yml": "jobs:\n  a:\n    runs-on: x\n",
    }
    code, out, _calls = rig.go(*args(False))
    assert code == 0, out


@pytest.mark.parametrize(
    "text",
    [
        "jobs:\n  a:\n    steps:\n      - run: |\n          echo uses: evil/x@v1\n",
        "jobs:\n  a:\n    strategy:\n      uses: evil/x@v1\n    steps: []\n",
        "jobs:\n  a:\n    steps:\n      - {uses: 'evil/x@v1'}\n      - uses: o/r@"
        + PINNED
        + "\n    uses: ./x\n    uses: o/y@v2\n",
        "jobs:\n  a:\n    steps:\n      - uses: o/r@" + PINNED + "\n      - name: uses the cache\n",
        "uses: o/r@v1\njobs: {}\n",
    ],
)
def test_a_uses_the_parse_did_not_account_for_needs_a_human(rig: Rig, text: str) -> None:  # noqa: F811
    code, out, calls = gate_with(rig, text)
    assert code == ship.EXIT_NEEDS_HUMAN and merges(calls) == [], out


@pytest.mark.parametrize(
    "text",
    [
        "jobs: [unclosed",
        "- just\n- a list\n",
        "jobs: 5\n",
        "jobs:\n  a: 5\n",
        "jobs:\n  a:\n    steps: nope\n",
        "jobs:\n  a:\n    steps:\n      - 5\n",
        "jobs:\n  a:\n    uses: 5\n",
        "x: &anchor\n  y: 1\njobs:\n  a:\n    <<: *anchor\n",
        "jobs:\n  a:\n    runs-on: " + "x" * 300000 + "\n",
    ],
)
def test_an_unparsable_or_oddly_shaped_gate_file_needs_a_human(rig: Rig, text: str) -> None:  # noqa: F811
    code, out, calls = gate_with(rig, text)
    assert code == ship.EXIT_NEEDS_HUMAN and merges(calls) == [], out


def test_a_comment_with_the_word_uses_does_not_trip_the_scan(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [*[sv("CLEAN")] * 4, sv("CLEAN", state="MERGED")]
    rig.state["gate_text"] = (
        "# this file uses the shared jobs\njobs:\n  a:\n    steps:\n      - uses: o/r@" + PINNED + " # uses a pin\n"
    )
    code, out, _calls = rig.go(*args(False))
    assert code == 0, out


# local references are untrusted text: they never reach a URL as anything but one safe path


@pytest.mark.parametrize(
    "local",
    [
        "a?ref=other",
        "a#x",
        "%2e%2e/x",
        "a/%2e%2e/x",
        "a b/c.yml",
        "   ",
        "a\\x07b.yml",  # a YAML escape: the parsed reference holds a real control character
        "a\\\\b.yml",
        "a//b.yml",
        "a/./b.yml",
        "a/../b.yml",
        "x" * 250 + ".yml",
        "é.yml",
    ],
)
def test_a_local_reference_with_odd_characters_needs_a_human(rig: Rig, local: str) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["gate_text"] = f'jobs:\n  a:\n    steps:\n      - uses: "./{local}"\n'
    code, out, calls = rig.go(*args(False))
    assert code == ship.EXIT_NEEDS_HUMAN and "local workflow reference has unsupported characters" in out
    assert merges(calls) == []
    assert not [c for c in calls if len(c) > 3 and any(local in part for part in c[1:])], "it must never reach a call"


def test_contents_are_asked_for_with_a_quoted_path_and_a_ref_field(rig: Rig) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["gate_text"] = "jobs:\n  a:\n    steps:\n      - uses: ./tools/act\n"
    rig.state["local_by_ref"] = {"main": "one", HEAD: "two"}
    code, _out, calls = rig.go(*args(False))
    assert code == ship.EXIT_NEEDS_HUMAN
    reads = [c for c in calls if "/contents/" in " ".join(c)]
    assert reads and all(
        c[c.index("-X") + 1] == "GET" and not any("?" in a for a in c[1:] if "/contents/" in a) for c in reads
    )
    assert all(any(a.startswith("ref=") for a in c) for c in reads)


def test_contents_args_quote_each_segment_and_pass_the_ref_as_a_field() -> None:
    assert ship.contents_args("o/r", "a b/c", "main?x=1#") == [
        "api",
        "-X",
        "GET",
        "repos/o/r/contents/a%20b/c",
        "-f",
        "ref=main?x=1#",
    ]


@pytest.mark.parametrize("asked", ["tools/act", ".github/workflows/ci.yml"])
def test_an_answer_about_another_path_is_an_error_not_a_comparison(rig: Rig, asked: str) -> None:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["gate_text"] = "jobs:\n  a:\n    steps:\n      - uses: ./tools/act\n"
    rig.state["path_override"] = {asked: "somewhere/else"}
    code, out, calls = rig.go(*args(False))
    assert code == ship.EXIT_ERROR and "not about" in out and merges(calls) == []


# Daybreak round 4: base, gate and protection move while the checks run


E_TIP, F_TIP, G_TIP = "e" * 40, "f" * 40, "1" * 40


def count(calls: list[list[str]], needle: str) -> int:
    return len([c for c in calls if needle in " ".join(c)])


def test_a_base_tip_that_moves_before_the_merge_restarts_every_check(rig: Rig) -> None:  # noqa: F811
    rig.state["base_tips"] = [E_TIP, E_TIP, F_TIP]  # pinned, first check, second check (moved)
    rig.state["views"] = [*[sv("CLEAN")] * 7, sv("CLEAN", state="MERGED")]
    code, out, calls = rig.go(*args(False))
    assert code == 0, out
    assert len(merges(calls)) == 1
    assert (
        count(calls, "/check-runs") >= 4 and count(calls, "required_status_checks") == 2
    )  # CI and protection read on both passes
    assert count(calls, "/compare/") == 2 and count(calls, "graphql") == 2


def test_a_base_that_keeps_moving_is_refused_without_a_merge(rig: Rig) -> None:  # noqa: F811
    rig.state["base_tips"] = [E_TIP, E_TIP, F_TIP, F_TIP, G_TIP]
    rig.state["views"] = [sv("CLEAN")]
    code, out, calls = rig.go(*args(False))
    assert code == ship.EXIT_MERGE_REFUSED and "moved again" in out and merges(calls) == []


def test_base_modified_at_merge_time_runs_the_whole_chain_again_before_the_second_merge(rig: Rig) -> None:  # noqa: F811
    rig.state["merges"] = [{"rc": 1, "err": "Base branch was modified"}, {"rc": 0}]
    rig.state["changed_seq"] = [[], [".github/workflows/new.yml"]]  # the new base brings a workflow change
    rig.state["views"] = [sv("CLEAN")]
    code, out, calls = rig.go(*args(True))
    assert code == ship.EXIT_NEEDS_HUMAN and len(merges(calls)) == 1, out


def test_base_modified_then_a_new_thread_is_found_by_the_second_pass(rig: Rig) -> None:  # noqa: F811
    rig.state["merges"] = [{"rc": 1, "err": "Base branch was modified"}, {"rc": 0}]
    rig.state["threads"] = [CLEAN, threads("late.py")]
    rig.state["views"] = [sv("CLEAN")]
    code, _out, calls = rig.go(*args(True))
    assert code == ship.EXIT_THREADS and len(merges(calls)) == 1


def test_base_modified_then_protection_switched_off_is_refused(rig: Rig) -> None:  # noqa: F811
    rig.state["merges"] = [{"rc": 1, "err": "Base branch was modified"}, {"rc": 0}]
    on = {"out": json.dumps({"required_conversation_resolution": {"enabled": True}})}
    rig.state["full_protection_seq"] = [on, OFF]
    rig.state["views"] = [sv("CLEAN")]
    code, out, calls = rig.go(*args(True))
    assert code == ship.EXIT_PROTECTED and "conversation resolution" in out and len(merges(calls)) == 1


def test_a_gate_that_turns_red_after_it_was_verified_is_not_merged(rig: Rig) -> None:  # noqa: F811
    good = [run_of("CI green", 1)]
    bad = [dict(run_of("CI green", 1), conclusion="failure")]
    rig.state["check_runs_seq"] = [good, bad]
    rig.state["views"] = [sv("CLEAN")]
    code, out, calls = rig.go(*args(False))
    assert code == ship.EXIT_CI_FAILED and "after it was verified" in out and merges(calls) == []


def test_the_protection_is_read_again_for_every_queued_pr(rig: Rig) -> None:  # noqa: F811
    on = {"out": json.dumps({"required_conversation_resolution": {"enabled": True}})}
    rig.state["full_protection_seq"] = [on, OFF]  # switched off while the first PR merges
    rig.state["views"] = [*[sv("CLEAN")] * 5, sv("CLEAN", state="MERGED"), sv("CLEAN")]
    code, out, calls = rig.go("--queue", "5", "6", "--repo", REPO, "--interval", "1")
    words = [ln.split()[0] for ln in out.strip().splitlines()]
    assert words == ["MERGED", "PROTECTED"] and code == ship.EXIT_PROTECTED and len(merges(calls)) == 1


def test_the_merge_readback_may_pass_the_deadline_but_only_by_the_recovery_allowance(rig: Rig) -> None:  # noqa: F811
    rig.tick_by = {"pr merge": 100.0}
    rig.state["views"] = [*[sv("CLEAN")] * 5, sv("CLEAN", state="MERGED")]
    code, out, calls = rig.go(*args(True, "--timeout", "50"))
    assert code == 0 and out.startswith("MERGED"), out
    after = [t for now, t in rig.timeouts if now >= 50]
    assert after and all((t or 0) <= ship.RECOVERY_SECONDS for t in after), rig.timeouts
    assert len(merges(calls)) == 1


def test_no_second_merge_call_starts_after_the_deadline(rig: Rig) -> None:  # noqa: F811
    rig.tick_by = {"pr merge": 100.0}
    rig.state["merges"] = [{"rc": 1, "err": "Base branch was modified"}, {"rc": 0}]
    rig.state["views"] = [sv("CLEAN")]
    code, _out, calls = rig.go(*args(True, "--timeout", "50"))
    assert len(merges(calls)) == 1 and code != 0


def test_a_retry_pass_is_still_capped_call_by_call(rig: Rig) -> None:  # noqa: F811
    rig.tick = 1.0
    rig.state["merges"] = [{"rc": 1, "err": "Base branch was modified"}, {"rc": 0}]
    rig.state["views"] = [sv("CLEAN")]
    rig.go(*args(True, "--timeout", "40"))
    assert all(now < 40 and now + (t or 0) <= 40 + 1e-9 for now, t in rig.timeouts), rig.timeouts


# the files a gate's run steps execute: a strict grammar (safo.shipscan), compared base vs head (#586 round 4)


def gate(*lines: str, runs_on: str = "ubuntu-latest", extra: str = "") -> str:
    body = "".join(f"          {line}\n" for line in lines)
    head = f"    runs-on: {runs_on}\n" if runs_on else ""
    return f"jobs:\n  a:\n{head}{extra}    steps:\n      - run: |\n{body}"


def merges_through(rig: Rig, gate_text: str, *more: str, **state: Any) -> tuple[int, str, list[list[str]]]:  # noqa: F811
    rig.state["views"] = [*[sv("CLEAN")] * 4, sv("CLEAN", state="MERGED")]
    rig.state["gate_text"] = gate_text
    rig.state.update(state)
    return rig.go(*args(False, *more))


def stops_on(rig: Rig, gate_text: str, **state: Any) -> tuple[int, str, list[list[str]]]:  # noqa: F811
    rig.state["views"] = [sv("CLEAN")]
    rig.state["gate_text"] = gate_text
    rig.state.update(state)
    return rig.go(*args(False))


def test_a_changed_script_the_gate_runs_needs_a_human(rig: Rig) -> None:  # noqa: F811
    changed = {"ci/gate.sh@main": "one", f"ci/gate.sh@{HEAD}": "two"}
    code, out, calls = stops_on(rig, gate("bash ci/gate.sh"), local_by_path=changed)
    assert code == ship.EXIT_NEEDS_HUMAN and "ci/gate.sh" in out and "differs" in out and merges(calls) == []


def test_an_unchanged_script_the_gate_runs_is_fine(rig: Rig) -> None:  # noqa: F811
    code, out, _calls = merges_through(rig, gate("bash ci/gate.sh", "./ci/other.sh --x"))
    assert code == 0, out


def test_every_script_of_every_line_is_compared(rig: Rig) -> None:  # noqa: F811
    changed = {f"ci/b.sh@{HEAD}": "two", "ci/b.sh@main": "one"}
    code, out, _calls = stops_on(rig, gate("bash ci/a.sh", "cd ci", "bash b.sh"), local_by_path=changed)
    assert code == ship.EXIT_NEEDS_HUMAN and "ci/b.sh" in out


@pytest.mark.parametrize(
    "line",
    [
        "eval x",
        "sudo ./x.sh",
        "bash ci/g.sh | tee out",
        "bash ci/g.sh > out",
        "bash ci/g.sh && bash ci/h.sh",
        "bash $X",
        "make test",
        "bash -c ci/g.sh",
        "python -m ci.gate",
        "set -e",
    ],
)
def test_a_line_outside_the_grammar_needs_a_human_and_is_named(rig: Rig, line: str) -> None:  # noqa: F811
    code, out, calls = stops_on(rig, gate("bash ci/ok.sh", line))
    assert code == ship.EXIT_NEEDS_HUMAN and "not in the allowed grammar" in out and "line 2" in out
    assert merges(calls) == []


def test_a_listed_gate_command_is_allowed_but_never_followed_to_a_file(rig: Rig) -> None:  # noqa: F811
    code, out, _calls = merges_through(rig, gate("make test -j4"), "--gate-command", "make")
    assert code == 0, out
    code, out, _calls = stops_on(rig, gate("make test"))  # not listed
    assert code == ship.EXIT_NEEDS_HUMAN


@pytest.mark.parametrize("name", ["bash", "python3", "/usr/bin/make", "-j", "a b", "$X"])
def test_a_gate_command_must_be_a_plain_command_name(rig: Rig, name: str) -> None:  # noqa: F811
    with pytest.raises(SystemExit) as stop:
        rig.go("5", "--repo", REPO, "--gate-command", name)
    assert stop.value.code == 2


@pytest.mark.parametrize(
    "text",
    [
        gate("bash ci/g.sh", extra="    defaults:\n      run:\n        working-directory: ci\n"),
        "defaults:\n  run:\n    working-directory: ci\n" + gate("bash g.sh"),
        gate("bash g.sh").replace("      - run: |", "      - working-directory: ci\n        run: |"),
        gate("bash ci/g.sh", extra="    defaults:\n      run:\n        shell: pwsh\n"),
        "defaults:\n  run:\n    shell: python\n" + gate("bash ci/g.sh", runs_on="ubuntu-latest"),
        gate("bash ci/g.sh").replace("      - run: |", "      - shell: pwsh\n        run: |"),
        gate("bash ci/g.sh", runs_on="windows-latest"),
        gate("bash ci/g.sh", runs_on=""),
        gate("bash ci/g.sh", runs_on="self-hosted"),
        gate("bash ci/g.sh", runs_on="${{ matrix.os }}"),
        gate("bash ci/g.sh", runs_on="[ubuntu-latest]"),
    ],
)
def test_a_step_that_is_not_plain_bash_from_the_root_needs_a_human(rig: Rig, text: str) -> None:  # noqa: F811
    code, _out, calls = stops_on(rig, text)
    assert code == ship.EXIT_NEEDS_HUMAN and merges(calls) == []


@pytest.mark.parametrize(
    "text",
    [
        gate("bash ci/g.sh", runs_on="macos-14"),
        gate("bash ci/g.sh", runs_on="", extra="    defaults:\n      run:\n        shell: bash\n"),
        "defaults:\n  run:\n    shell: bash\n" + gate("bash ci/g.sh", runs_on=""),
        "defaults:\n  run:\n    shell: pwsh\n"
        + gate("bash ci/g.sh", extra="    defaults:\n      run:\n        shell: sh\n"),  # the job's own default wins
        gate("bash ci/g.sh").replace("      - run: |", "      - shell: bash\n        run: |"),
        gate("bash ci/g.sh", runs_on="ubuntu-22.04", extra="    defaults:\n      run:\n        working-directory: .\n"),
    ],
)
def test_the_shell_and_directory_rules_have_these_accepted_forms(rig: Rig, text: str) -> None:  # noqa: F811
    code, out, _calls = merges_through(rig, text)
    assert code == 0, out


COMPOSITE = "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: bash ci/gate.sh\n"


def test_the_run_steps_of_a_local_composite_action_are_analyzed(rig: Rig) -> None:  # noqa: F811
    text = "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./ci/action\n"
    changed = {"ci/gate.sh@main": "one", f"ci/gate.sh@{HEAD}": "two"}
    code, out, calls = stops_on(rig, text, texts={"ci/action/action.yml": COMPOSITE}, local_by_path=changed)
    assert code == ship.EXIT_NEEDS_HUMAN and "ci/gate.sh" in out and merges(calls) == []
    code, out, _calls = merges_through(rig, text, texts={"ci/action/action.yml": COMPOSITE}, local_by_path={})
    assert code == 0, out


@pytest.mark.parametrize(
    "action",
    [
        "runs:\n  using: composite\n  steps:\n    - run: bash ci/gate.sh\n",  # no shell named
        "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: bash ci/g.sh | tee out\n",
        "runs:\n  using: composite\n  steps:\n    - shell: pwsh\n      run: ./ci/g.ps1\n",
    ],
)
def test_a_composite_step_outside_the_grammar_needs_a_human(rig: Rig, action: str) -> None:  # noqa: F811
    text = "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./ci/action\n"
    code, _out, calls = stops_on(rig, text, texts={"ci/action/action.yml": action})
    assert code == ship.EXIT_NEEDS_HUMAN and merges(calls) == []


ACTION_USE = "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./ci/action\n"


def test_only_a_clear_404_means_a_missing_action_file(rig: Rig) -> None:  # noqa: F811
    code, out, _calls = stops_on(rig, ACTION_USE, error_files=["ci/action/action.yml"])  # a 500 that says "404" in text
    assert code == ship.EXIT_ERROR and "HTTP status 500" in out
    code, out, _calls = merges_through(
        rig,
        ACTION_USE,
        missing_files=["ci/action/action.yml"],  # a clear 404: the .yaml spelling is tried
        texts={"ci/action/action.yaml": COMPOSITE},
    )
    assert code == 0, out


def test_a_local_action_without_any_action_file_needs_a_human(rig: Rig) -> None:  # noqa: F811
    code, out, calls = stops_on(rig, ACTION_USE, missing_files=["ci/action/action.yml", "ci/action/action.yaml"])
    assert code == ship.EXIT_NEEDS_HUMAN and "without action.yml" in out and merges(calls) == []


def test_a_local_action_directory_that_does_not_exist_is_an_error(rig: Rig) -> None:  # noqa: F811
    code, out, calls = stops_on(rig, ACTION_USE, missing=["ci/action"])
    assert code == ship.EXIT_ERROR and "cannot read" in out and merges(calls) == []


def test_a_workflow_file_that_cannot_be_read_is_an_error_not_a_pass(rig: Rig) -> None:  # noqa: F811
    code, out, calls = stops_on(rig, gate("bash ci/g.sh"), error_files=[".github/workflows/ci.yml"])
    assert code == ship.EXIT_ERROR and "HTTP status 500" in out and merges(calls) == []


def test_what_a_script_itself_reads_is_outside_the_derivation(rig: Rig) -> None:  # noqa: F811
    """Documented residual: a script's own text is not read, so what it sources is only covered by --protect-path."""
    code, out, _calls = merges_through(rig, gate("bash ci/gate.sh"), texts={"ci/gate.sh": "source ci/lib.sh\n"})
    assert code == 0, out


def test_a_file_that_exists_at_neither_ref_is_a_generated_one_and_is_left_alone(rig: Rig) -> None:  # noqa: F811
    code, out, _calls = merges_through(rig, gate("./build/gen.sh"), missing=["build/gen.sh"])
    assert code == 0, out


def test_a_file_that_exists_on_only_one_side_differs(rig: Rig) -> None:  # noqa: F811
    code, _out, calls = stops_on(
        rig,
        gate("./ci/new.sh"),
        local_by_path={f"ci/new.sh@{HEAD}": "added"},
        missing_at=["ci/new.sh@main"],
    )
    assert code == ship.EXIT_NEEDS_HUMAN and merges(calls) == []
