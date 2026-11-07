# SPDX-License-Identifier: Apache-2.0
"""safo-ship against a fake `gh` and `git` on PATH (issue #85). Nothing reaches the network or a real repository."""

from __future__ import annotations

import io
import json
import stat
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from safo import ship

HEAD = "a" * 40
MOVED = "b" * 40
REPO = "o/r"

STUB = textwrap.dedent(
    """\
    #!{python}
    # fake gh and git: answers come from $FAKE_STATE (a JSON file); every call is appended to its "calls" list
    import json, os, sys
    path = os.environ["FAKE_STATE"]
    state = json.load(open(path))
    argv = os.path.basename(sys.argv[0]), *sys.argv[1:]
    state["calls"].append(list(argv))

    def pop(key):
        queue = state[key]
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        return item

    def reply(item):
        json.dump(state, open(path, "w"))
        sys.stdout.write(item.get("out", ""))
        sys.stderr.write(item.get("err", ""))
        sys.exit(item.get("rc", 0))

    tool, rest = argv[0], argv[1:]
    if tool == "git":
        reply(state["git"].get(rest[0], {{}}))
    key = " ".join(rest[:2])
    if key == "pr view":
        reply({{"out": json.dumps(pop("views"))}})
    if key == "pr merge":
        reply(pop("merges"))
    if key == "api graphql":
        reply({{"out": json.dumps(pop("threads"))}})
    if rest[0] == "api":
        reply(state["protection"])
    if key == "run view":
        reply({{"out": json.dumps(state["runs"][rest[2]])}})
    if key == "run rerun":
        reply(state.get("rerun", {{}}))
    if key == "pr list":
        reply({{"out": json.dumps(state.get("existing", []))}})
    if key == "pr create":
        reply(state["create"])
    if key == "repo view":
        reply({{"out": json.dumps({{"nameWithOwner": "o/r"}})}})
    reply({{"rc": 1, "err": "fake gh: unscripted call " + key}})
    """
)


def check(
    name: str, status: str = "COMPLETED", conclusion: str = "SUCCESS", run: int = 0, job: int = 0
) -> dict[str, Any]:
    url = f"https://github.com/o/r/actions/runs/{run}/job/{job}" if run else ""
    return {
        "__typename": "CheckRun",
        "name": name,
        "workflowName": "ci",
        "status": status,
        "conclusion": conclusion if status == "COMPLETED" else "",
        "detailsUrl": url,
    }


def view(rollup: list[dict[str, Any]], head: str = HEAD, state: str = "OPEN") -> dict[str, Any]:
    return {"state": state, "headRefOid": head, "baseRefName": "main", "statusCheckRollup": rollup, "url": ""}


GREEN = [check("test"), check("CI green")]
CLEAN: dict[str, Any] = {
    "data": {
        "repository": {
            "pullRequest": {"reviewThreads": {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": ""}}}
        }
    }
}


def threads(*unresolved: str) -> dict[str, Any]:
    nodes = [
        {
            "isResolved": False,
            "path": p,
            "line": 3,
            "comments": {"nodes": [{"author": {"login": "x"}, "url": f"https://x/{p}"}]},
        }
        for p in unresolved
    ] + [{"isResolved": True, "path": "done.py", "line": 1, "comments": {"nodes": []}}]
    return {
        "data": {
            "repository": {
                "pullRequest": {"reviewThreads": {"nodes": nodes, "pageInfo": {"hasNextPage": False, "endCursor": ""}}}
            }
        }
    }


class Rig:
    def __init__(self, tmp: Path, monkeypatch: pytest.MonkeyPatch):
        self.bin = tmp / "bin"
        self.bin.mkdir()
        for name in ("gh", "git"):
            f = self.bin / name
            f.write_text(STUB.format(python=sys.executable), encoding="utf-8")
            f.chmod(f.stat().st_mode | stat.S_IXUSR)
        self.state_path = tmp / "state.json"
        self.state: dict[str, Any] = {
            "calls": [],
            "views": [view(GREEN)],
            "protection": {"rc": 0, "out": json.dumps({"contexts": [], "checks": []})},
            "threads": [CLEAN],
            "merges": [{"rc": 0}],
            "runs": {"9": {"jobs": [{"databaseId": 99, "steps": [{"name": "gate", "conclusion": "failure"}]}]}},
            "git": {"rev-parse": {"out": HEAD + "\n"}, "push": {}},
        }
        self.slept: list[float] = []
        self.now = 0.0
        monkeypatch.setenv("FAKE_STATE", str(self.state_path))

    def go(self, *argv: str) -> tuple[int, str, list[list[str]]]:
        self.state_path.write_text(json.dumps(self.state), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()

        def sleep(seconds: float) -> None:
            self.slept.append(seconds)
            self.now += seconds

        code = ship.main(
            [*argv],
            env={"PATH": str(self.bin), "FAKE_STATE": str(self.state_path)},
            out=out,
            err=err,
            sleep=sleep,
            clock=lambda: self.now,
        )
        calls = json.loads(self.state_path.read_text(encoding="utf-8"))["calls"]
        return code, out.getvalue() + err.getvalue(), calls


@pytest.fixture
def rig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Rig:
    return Rig(tmp_path, monkeypatch)


def merges(calls: list[list[str]]) -> list[list[str]]:
    return [c for c in calls if c[1:3] == ["pr", "merge"]]


def test_green_merges_the_pinned_head_and_reads_it_back(rig: Rig) -> None:
    rig.state["views"] = [view(GREEN), view(GREEN), view(GREEN, state="MERGED")]
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == 0, out
    assert out.strip().splitlines() == [f"MERGED {REPO}#5 head={HEAD[:12]}"]
    (merge,) = merges(calls)
    assert merge[merge.index("--match-head-commit") + 1] == HEAD and "--squash" in merge


def test_an_empty_rollup_keeps_waiting_and_never_merges(rig: Rig) -> None:
    rig.state["views"] = [view([])]
    code, out, calls = rig.go("5", "--repo", REPO, "--max-polls", "4")
    assert code == ship.EXIT_TIMEOUT
    assert out.startswith("TIMEOUT") and "no checks registered" in out
    assert merges(calls) == [] and len(rig.slept) == 4


def test_a_half_filled_rollup_is_pending_even_with_nothing_running(rig: Rig) -> None:
    # every entry is complete and green, but the named gate has not registered yet: still pending
    rig.state["views"] = [view([check("test")])]
    code, out, calls = rig.go("5", "--repo", REPO, "--max-polls", "3")
    assert code == ship.EXIT_TIMEOUT and "required check not present yet: CI green" in out
    assert merges(calls) == []


def test_a_running_job_beside_a_green_gate_is_pending(rig: Rig) -> None:
    rig.state["views"] = [view([check("CI green"), check("slow", status="IN_PROGRESS")])]
    code, out, calls = rig.go("5", "--repo", REPO, "--max-polls", "2")
    assert code == ship.EXIT_TIMEOUT and "not complete" in out and merges(calls) == []


def test_it_waits_through_a_filling_rollup_then_merges(rig: Rig) -> None:
    rig.state["views"] = [
        view([]),
        view([]),
        view([check("test")]),
        view([check("test", status="QUEUED"), check("CI green", status="QUEUED")]),
        view(GREEN),
        view(GREEN, state="MERGED"),
    ]
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == 0, out
    assert len(rig.slept) == 3 and len(merges(calls)) == 1


def test_the_wait_is_bounded_by_time_too(rig: Rig) -> None:
    rig.state["views"] = [view([])]
    code, _out, _calls = rig.go("5", "--repo", REPO, "--timeout", "50", "--interval", "20", "--max-polls", "1000")
    assert code == ship.EXIT_TIMEOUT and len(rig.slept) == 3


def test_every_required_context_from_branch_protection_must_be_present(rig: Rig) -> None:
    rig.state["protection"] = {
        "rc": 0,
        "out": json.dumps({"contexts": ["ci / CI green", "ci / extra"], "checks": [{"context": "other"}]}),
    }
    rig.state["views"] = [view(GREEN)]  # the gate is there, "ci / extra" and "other" are not
    code, out, calls = rig.go("5", "--repo", REPO, "--max-polls", "2")
    assert code == ship.EXIT_TIMEOUT and "ci / extra" in out and merges(calls) == []
    rig2 = view([*GREEN, check("extra"), check("other")])
    rig.state["views"] = [rig2, rig2, view(GREEN, state="MERGED")]
    rig.state["calls"] = []
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == 0, out


def test_an_unprotected_branch_still_requires_the_named_gate(rig: Rig) -> None:
    rig.state["protection"] = {"rc": 1, "err": "gh: Branch not protected (HTTP 404)"}
    rig.state["views"] = [view([check("test")])]
    code, _out, calls = rig.go("5", "--repo", REPO, "--max-polls", "2")
    assert code == ship.EXIT_TIMEOUT and merges(calls) == []


def test_an_unreadable_protection_answer_fails_closed(rig: Rig) -> None:
    rig.state["protection"] = {"rc": 1, "err": "HTTP 500"}
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == ship.EXIT_ERROR and out.startswith("ERROR") and merges(calls) == []


def test_a_head_that_moves_aborts_and_reports_the_new_head(rig: Rig) -> None:
    rig.state["views"] = [view([]), view([], head=MOVED)]
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == ship.EXIT_HEAD_MOVED and MOVED in out and merges(calls) == []


def test_a_head_that_moves_after_green_never_merges_the_old_one(rig: Rig) -> None:
    rig.state["views"] = [view(GREEN), view(GREEN, head=MOVED)]
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == ship.EXIT_HEAD_MOVED and MOVED in out and merges(calls) == []


def test_expect_head_pins_a_commit_the_caller_chose(rig: Rig) -> None:
    rig.state["views"] = [view(GREEN, head=MOVED)]
    code, out, calls = rig.go("5", "--repo", REPO, "--expect-head", HEAD)
    assert code == ship.EXIT_HEAD_MOVED and MOVED in out and merges(calls) == []


def test_unresolved_threads_stop_with_the_list_and_their_own_code(rig: Rig) -> None:
    rig.state["threads"] = [threads("a.py", "b.py")]
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == ship.EXIT_THREADS != ship.EXIT_CI_FAILED
    assert "2 unresolved review thread(s)" in out and "a.py:3" in out and "b.py:3" in out and "done.py" not in out
    assert merges(calls) == []


def test_threads_on_a_second_page_are_still_found(rig: Rig) -> None:
    page1 = threads()
    page1["data"]["repository"]["pullRequest"]["reviewThreads"]["pageInfo"] = {"hasNextPage": True, "endCursor": "c1"}
    rig.state["threads"] = [page1, threads("late.py")]
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == ship.EXIT_THREADS and "late.py" in out and merges(calls) == []


def test_base_branch_modified_is_retried_once(rig: Rig) -> None:
    rig.state["merges"] = [
        {"rc": 1, "err": "Pull request is not mergeable: Base branch was modified. Review and try the merge again."},
        {"rc": 0},
    ]
    rig.state["views"] = [view(GREEN), view(GREEN), view(GREEN), view(GREEN, state="MERGED")]
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == 0, out
    assert len(merges(calls)) == 2 and all(HEAD in m for m in merges(calls))


def test_base_branch_modified_twice_is_a_refusal(rig: Rig) -> None:
    rig.state["merges"] = [{"rc": 1, "err": "Base branch was modified"}]
    code, _out, calls = rig.go("5", "--repo", REPO)
    assert code == ship.EXIT_MERGE_REFUSED and len(merges(calls)) == 2


def test_another_merge_refusal_is_not_retried(rig: Rig) -> None:
    rig.state["merges"] = [{"rc": 1, "err": "head commit mismatch"}]
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == ship.EXIT_MERGE_REFUSED and len(merges(calls)) == 1 and "head commit mismatch" in out


def test_a_merge_that_reads_back_open_is_not_reported_merged(rig: Rig) -> None:
    code, out, _calls = rig.go("5", "--repo", REPO)  # views never say MERGED
    assert code == ship.EXIT_MERGE_REFUSED and "read-back" in out


def reruns(calls: list[list[str]]) -> list[list[str]]:
    return [c for c in calls if c[1:3] == ["run", "rerun"]]


def test_a_cancelled_job_is_rerun_once_then_merges(rig: Rig) -> None:
    cancelled = view(
        [check("test", conclusion="CANCELLED", run=9, job=91), check("CI green", conclusion="FAILURE", run=9, job=99)]
    )
    rig.state["views"] = [
        cancelled,
        cancelled,
        view([check("test", status="IN_PROGRESS", run=9, job=92), check("CI green", status="QUEUED")]),
        view(GREEN),
        view(GREEN, state="MERGED"),
    ]
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == 0, out
    (rerun,) = reruns(calls)
    assert rerun[-2:] == ["--job", "91"]


def test_a_job_cancelled_again_after_its_rerun_fails(rig: Rig) -> None:
    again = view(
        [check("test", conclusion="CANCELLED", run=9, job=93), check("CI green", conclusion="FAILURE", run=9, job=99)]
    )
    first = view(
        [check("test", conclusion="CANCELLED", run=9, job=91), check("CI green", conclusion="FAILURE", run=9, job=99)]
    )
    rig.state["views"] = [
        first,
        first,
        again,
    ]
    code, _out, calls = rig.go("5", "--repo", REPO)
    assert code == ship.EXIT_CI_FAILED and len(reruns(calls)) == 1 and merges(calls) == []


def test_a_stale_failure_right_after_a_rerun_is_not_counted_twice(rig: Rig) -> None:
    stale = view(
        [check("test", conclusion="CANCELLED", run=9, job=91), check("CI green", conclusion="FAILURE", run=9, job=99)]
    )
    rig.state["views"] = [*[stale] * 5, view(GREEN), view(GREEN, state="MERGED")]
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == 0, out
    assert len(reruns(calls)) == 1


def test_a_failed_gate_alone_is_a_real_failure(rig: Rig) -> None:
    rig.state["views"] = [view([check("test"), check("CI green", conclusion="FAILURE", run=9, job=99)])]
    code, _out, calls = rig.go("5", "--repo", REPO)
    assert code == ship.EXIT_CI_FAILED and reruns(calls) == [] and merges(calls) == []


def test_a_real_failure_is_never_rerun(rig: Rig) -> None:
    rig.state["views"] = [
        view(
            [check("test", conclusion="FAILURE", run=9, job=91), check("CI green", conclusion="FAILURE", run=9, job=92)]
        )
    ]
    rig.state["runs"] = {
        "9": {
            "jobs": [
                {"databaseId": 91, "steps": [{"name": "pytest", "conclusion": "failure"}]},
                {"databaseId": 92, "steps": [{"name": "gate", "conclusion": "failure"}]},
            ]
        }
    }
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == ship.EXIT_CI_FAILED and out.startswith("CI-FAILED") and "test=FAILURE" in out
    assert reruns(calls) == [] and merges(calls) == []


def test_a_failure_with_the_canary_and_another_failed_step_is_real(rig: Rig) -> None:
    rig.state["views"] = [
        view([check("test", conclusion="FAILURE", run=9, job=91), check("CI green", conclusion="SUCCESS")])
    ]
    rig.state["runs"] = {
        "9": {
            "jobs": [
                {
                    "databaseId": 91,
                    "steps": [
                        {"name": "Egress canary (EX-0001)", "conclusion": "failure"},
                        {"name": "pytest", "conclusion": "failure"},
                    ],
                }
            ]
        }
    }
    code, _out, calls = rig.go("5", "--repo", REPO)
    assert code == ship.EXIT_CI_FAILED and reruns(calls) == []


def canary_world(rig: Rig, job: int) -> dict[str, Any]:  # the gate itself is green here
    rig.state["runs"] = {
        "9": {
            "jobs": [
                {
                    "databaseId": job,
                    "steps": [
                        {"name": "Egress canary (EX-0001)", "conclusion": "failure"},
                        {"name": "later", "conclusion": "skipped"},
                    ],
                }
            ]
        }
    }
    return view([check("test", conclusion="FAILURE", run=9, job=job), check("CI green", conclusion="SUCCESS")])


def test_a_canary_only_failure_is_rerun_and_then_merges(rig: Rig) -> None:
    world = canary_world(rig, 91)
    rig.state["views"] = [world, world, view(GREEN), view(GREEN, state="MERGED")]
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == 0, out
    assert len(reruns(calls)) == 1


def test_a_canary_is_rerun_at_most_twice_per_run(rig: Rig) -> None:
    first = canary_world(rig, 91)
    rig.state["views"] = [first, first, first, first, first, first, first, first]
    code, _out, calls = rig.go("5", "--repo", REPO, "--max-polls", "30")
    assert code == ship.EXIT_CI_FAILED and len(reruns(calls)) == 2 and merges(calls) == []


def test_closed_pull_request_is_refused(rig: Rig) -> None:
    rig.state["views"] = [view(GREEN, state="CLOSED")]
    code, out, calls = rig.go("5", "--repo", REPO)
    assert code == ship.EXIT_MERGE_REFUSED and "CLOSED" in out and merges(calls) == []


def test_several_pull_requests_print_one_result_line_each_and_the_worst_code_wins(rig: Rig) -> None:
    rig.state["views"] = [
        view(GREEN),
        view(GREEN),
        view(GREEN, state="MERGED"),
        view([]),
    ]
    rig.state["threads"] = [CLEAN]
    code, out, _calls = rig.go("5", "6", "--repo", REPO, "--max-polls", "2")
    lines = out.strip().splitlines()
    assert [ln.split()[0] for ln in lines] == ["MERGED", "TIMEOUT"] and "#5" in lines[0] and "#6" in lines[1]
    assert code == ship.EXIT_TIMEOUT


def test_open_pr_pushes_opens_and_merges_the_pushed_commit(rig: Rig) -> None:
    rig.state["create"] = {"out": "https://github.com/o/r/pull/42\n"}
    rig.state["views"] = [view(GREEN), view(GREEN, state="MERGED")]
    code, out, calls = rig.go("--open-pr", "--repo", REPO, "--branch", "feat/x", "--title", "Add x", "--issue", "85")
    assert code == 0, out
    assert ["git", "push", "-u", "origin", "feat/x"] in calls and not any(
        "--force" in c or "-f" in c for c in calls if c[0] == "git"
    )
    create = next(c for c in calls if c[1:3] == ["pr", "create"])
    assert create[create.index("--title") + 1] == "Add x" and create[create.index("--body") + 1] == "Closes #85"
    assert f"{REPO}#42" in out and merges(calls)[0][-1] == HEAD


def test_open_pr_reuses_an_open_pull_request_for_the_branch(rig: Rig) -> None:
    rig.state["existing"] = [{"number": 7}]
    rig.state["views"] = [view(GREEN), view(GREEN, state="MERGED")]
    code, out, calls = rig.go("--open-pr", "--repo", REPO, "--branch", "feat/x", "--title", "t", "--issue", "o/r#85")
    assert code == 0 and not any(c[1:3] == ["pr", "create"] for c in calls) and f"{REPO}#7" in out


def test_open_pr_pins_the_pushed_commit_so_a_later_push_aborts(rig: Rig) -> None:
    rig.state["existing"] = [{"number": 7}]
    rig.state["views"] = [view(GREEN, head=MOVED)]
    code, _out, calls = rig.go("--open-pr", "--repo", REPO, "--branch", "feat/x", "--title", "t", "--issue", "85")
    assert code == ship.EXIT_HEAD_MOVED and merges(calls) == []


def test_open_pr_refuses_the_base_branch_and_a_failed_push(rig: Rig) -> None:
    code, out, calls = rig.go("--open-pr", "--repo", REPO, "--branch", "main", "--title", "t", "--issue", "85")
    assert code == ship.EXIT_ERROR and not any(c[0] == "git" and c[1] == "push" for c in calls)
    rig.state["git"]["push"] = {"rc": 1, "err": "rejected"}
    code, out, calls = rig.go("--open-pr", "--repo", REPO, "--branch", "feat/x", "--title", "t", "--issue", "85")
    assert code == ship.EXIT_ERROR and "push failed" in out


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["5", "--interval", "0"],
        ["5", "--timeout", "99999"],
        ["5", "--max-polls", "0"],
        ["5", "--repo", "not a repo"],
        ["5", "--expect-head", "abc"],
        ["--open-pr", "--title", "t"],
        ["--open-pr", "5", "--title", "t", "--issue", "1"],
    ],
)
def test_bad_arguments_are_a_usage_error(rig: Rig, argv: list[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        rig.go(*argv)
    assert stop.value.code == 2


def test_a_missing_gh_is_an_error_not_a_crash(tmp_path: Path) -> None:
    out, err = io.StringIO(), io.StringIO()
    assert ship.main(["5", "--repo", REPO], env={"PATH": ""}, out=out, err=err) == ship.EXIT_ERROR


def test_the_entry_point_is_declared() -> None:
    import tomllib

    meta = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["project"]["scripts"]["safo-ship"] == "safo.ship:run"
