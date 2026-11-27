# SPDX-License-Identifier: Apache-2.0
"""safo-idle-check (#578): block the end of a turn when running workers < floor and ready work exists."""

from __future__ import annotations

import io
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from safo import idlecheck

SESSION = "sess1"


def make_subagent(root: Path, name: str, text: str, age: float = 5.0, finished: bool = False) -> Path:
    folder = root / SESSION / "subagents"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"agent-{name}.jsonl"
    first = {"type": "user", "message": {"role": "user", "content": text}}
    lines = [json.dumps(first)]
    last = {"type": "assistant", "message": {"stop_reason": "end_turn" if finished else None, "content": []}}
    lines.append(json.dumps(last))
    path.write_text("\n".join(lines) + "\n")
    stamp = time.time() - age
    os.utime(path, (stamp, stamp))
    return path


def make_proc(root: Path, pid: int, ppid: int, cmd: str) -> None:
    folder = root / str(pid)
    folder.mkdir(parents=True)
    (folder / "cmdline").write_bytes(cmd.replace(" ", "\0").encode() + b"\0")
    (folder / "stat").write_text(f"{pid} (x) S {ppid} 1 1 0 0\n")


def pr(number: int, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "number": number,
        "title": f"pr {number}",
        "headRefName": f"branch-{number}",
        "isDraft": False,
        "mergeable": "MERGEABLE",
        "reviewDecision": "APPROVED",
        "statusCheckRollup": [{"conclusion": "SUCCESS"}],
    }
    base.update(kw)
    return base


class Env:
    def __init__(self, tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.tmp = tmp
        self.projects = tmp / "proj"
        self.proc = tmp / "proc"
        self.proc.mkdir()
        self.queue = tmp / "QUEUE.md"
        self.queue.write_text("")
        self.log = tmp / "idle.log"
        self.prs: dict[str, Any] = {}
        self.transcript = self.projects / f"{SESSION}.jsonl"
        self.projects.mkdir()
        self.transcript.write_text("")
        self.vars = {
            "HOME": str(tmp),
            "SAFO_IDLE_QUEUE": str(self.queue),
            "SAFO_IDLE_LOG": str(self.log),
            "SAFO_IDLE_REPOS": "o/r",
            "SAFO_IDLE_PROC": str(self.proc),
        }

    def runner(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        repo = argv[argv.index("--repo") + 1]
        value = self.prs.get(repo, [])
        if isinstance(value, Exception):
            raise value
        return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

    def run(self, payload: dict[str, Any] | None = None, **extra: str) -> tuple[int, dict[str, Any] | None]:
        data = {"transcript_path": str(self.transcript), "session_id": SESSION, "stop_hook_active": False}
        data.update(payload or {})
        out = io.StringIO()
        code = idlecheck.main_with(io.StringIO(json.dumps(data)), out, {**self.vars, **extra}, runner=self.runner)
        text = out.getvalue().strip()
        return code, (json.loads(text) if text else None)

    def rows(self) -> list[dict[str, Any]]:
        return [json.loads(x) for x in self.log.read_text().splitlines()] if self.log.exists() else []


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    return Env(tmp_path, monkeypatch)


TABLE = """# Work queue
| item | depends on | state |
|---|---|---|
| alpha job | none | ready |
| beta job | alpha applied | running (agent) |
| gamma job | none | BLOCKED on owner |
| delta job | none | done |
| eps job | B1 applied | waits |
| zeta job | none | |
READY: one thing; two things
"""


def test_queue_parse_picks_only_ready_rows() -> None:
    items = idlecheck.parse_queue(TABLE)
    assert items == ["alpha job", "zeta job", "one thing", "two things"]


def test_queue_parse_collects_something_and_ignores_prose() -> None:
    assert idlecheck.parse_queue("RUNNING: x\nNEXT: y; z\nBLOCKED (owner): w\n") == []


def test_blocks_when_below_floor_and_work_ready(env: Env) -> None:
    env.queue.write_text(TABLE)
    code, out = env.run()
    assert code == 0 and out is not None and out["decision"] == "block"
    assert "alpha job" in out["reason"] and "0 of 6" in out["reason"]
    assert env.rows()[-1]["decision"] == "block"


def test_allows_at_floor(env: Env) -> None:
    env.queue.write_text(TABLE)
    for n in range(6):
        make_subagent(env.projects, f"a{n}", "work")
    code, out = env.run()
    assert code == 0 and out is None
    assert env.rows()[-1]["decision"] == "allow" and env.rows()[-1]["running"] == 6


def test_allows_when_nothing_ready(env: Env) -> None:
    code, out = env.run()
    assert code == 0 and out is None


def test_stale_and_finished_subagents_do_not_count(env: Env) -> None:
    env.queue.write_text(TABLE)
    make_subagent(env.projects, "old", "work", age=4000)
    make_subagent(env.projects, "done", "work", finished=True)
    make_subagent(env.projects, "live", "work")
    _, out = env.run()
    assert out is not None and "1 of 6" in out["reason"]


def test_floor_is_configurable(env: Env) -> None:
    env.queue.write_text(TABLE)
    make_subagent(env.projects, "a", "work")
    _, out = env.run(SAFO_IDLE_FLOOR="1")
    assert out is None
    _, out = env.run(SAFO_IDLE_FLOOR="2")
    assert out is not None and out["decision"] == "block"


def test_stop_hook_active_allows(env: Env) -> None:
    env.queue.write_text(TABLE)
    code, out = env.run({"stop_hook_active": True})
    assert code == 0 and out is None
    assert env.rows()[-1]["decision"] == "active"


def test_warn_mode_never_blocks(env: Env) -> None:
    env.queue.write_text(TABLE)
    _, out = env.run(SAFO_IDLE_MODE="warn")
    assert out is not None and "decision" not in out and "alpha job" in out["systemMessage"]


def test_processes_count_once_per_chain(env: Env) -> None:
    env.queue.write_text(TABLE)
    make_proc(env.proc, 10, 1, "bash -c run daybreak-run /x/prompt")
    make_proc(env.proc, 11, 10, "timeout 1700 codex.js exec --skip-git-repo-check")
    make_proc(env.proc, 12, 11, "codex exec deep")
    make_proc(env.proc, 20, 1, "timeout 3300 codex exec --skip-git-repo-check")
    make_proc(env.proc, 30, 1, "vim notes.txt")
    _, out = env.run()
    assert out is not None and "2 of 6" in out["reason"]


def test_pr_failing_conflicting_unreviewed_are_ready(env: Env) -> None:
    env.prs["o/r"] = [
        pr(1, statusCheckRollup=[{"conclusion": "FAILURE"}]),
        pr(2, mergeable="CONFLICTING"),
        pr(3, reviewDecision="REVIEW_REQUIRED"),
        pr(4),  # green, approved, mergeable: not ready work
        pr(5, isDraft=True, reviewDecision="REVIEW_REQUIRED"),  # an unreviewed draft is not asked for review
    ]
    _, out = env.run()
    assert out is not None
    reason = out["reason"]
    assert "o/r#1" in reason and "o/r#2" in reason and "o/r#3" in reason
    assert "o/r#4" not in reason and "o/r#5" not in reason


def test_pr_with_a_running_agent_is_not_ready(env: Env) -> None:
    env.prs["o/r"] = [pr(7, mergeable="CONFLICTING"), pr(8, mergeable="CONFLICTING", headRefName="feat/x-8")]
    make_subagent(env.projects, "a", "fix PR #7 please")
    make_subagent(env.projects, "b", "work on branch feat/x-8")
    _code, out = env.run()
    assert out is None and env.rows()[-1]["ready"] == 0


def test_pr_number_match_is_not_a_substring(env: Env) -> None:
    env.prs["o/r"] = [pr(5, mergeable="CONFLICTING")]
    make_subagent(env.projects, "a", "see issue #57 and pull/500")
    _, out = env.run()
    assert out is not None and "o/r#5" in out["reason"]


def test_exempt_pr_is_skipped(env: Env, tmp_path: Path) -> None:
    env.prs["o/r"] = [pr(9, mergeable="CONFLICTING")]
    cfg = tmp_path / ".config" / "safo"
    cfg.mkdir(parents=True)
    (cfg / "idle-check.json").write_text(json.dumps({"exempt": ["o/r#9"]}))
    _code, out = env.run()
    assert out is None


def test_gh_failure_is_loud_but_other_sources_still_decide(env: Env) -> None:
    env.queue.write_text(TABLE)
    env.prs["o/r"] = subprocess.TimeoutExpired("gh", 10)
    _, out = env.run()
    assert out is not None and out["decision"] == "block"
    assert "DEGRADED" in out["reason"] and "o/r" in out["reason"]
    assert env.rows()[-1]["degraded"]


def test_gh_failure_alone_allows_with_a_notice(env: Env) -> None:
    env.prs["o/r"] = OSError("no gh")
    code, out = env.run()
    assert code == 0 and out is not None and "decision" not in out
    assert "DEGRADED" in out["systemMessage"]
    assert env.rows()[-1]["decision"] == "degraded"


def test_unreadable_queue_is_loud(env: Env) -> None:
    env.vars["SAFO_IDLE_QUEUE"] = str(env.tmp / "missing.md")
    _, out = env.run()
    assert out is not None and "DEGRADED" in out["systemMessage"] and "queue" in out["systemMessage"]


def test_unreadable_registry_fails_open_loudly(env: Env) -> None:
    env.queue.write_text(TABLE)
    _, out = env.run({"transcript_path": ""})
    assert out is not None and "decision" not in out and "DEGRADED" in out["systemMessage"]
    assert env.rows()[-1]["decision"] == "degraded"


def test_bad_input_fails_open_loudly(env: Env) -> None:
    out = io.StringIO()
    code = idlecheck.main_with(io.StringIO("not json"), out, env.vars, runner=env.runner)
    assert code == 0 and "DEGRADED" in out.getvalue() and "decision" not in out.getvalue()


def test_unexpected_exception_fails_open_loudly(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("x")

    monkeypatch.setattr(idlecheck, "count_processes", boom)
    env.queue.write_text(TABLE)
    _, out = env.run()
    assert out is not None and "decision" not in out and "DEGRADED" in out["systemMessage"]


def test_stats_counts_blocks_per_day(env: Env) -> None:
    env.log.write_text(
        "\n".join(
            json.dumps({"ts": f"2026-11-2{d}T10:00:00", "decision": k})
            for d, k in ((6, "block"), (6, "block"), (7, "block"), (7, "allow"))
        )
        + "\n"
    )
    out = io.StringIO()
    assert idlecheck.stats(env.vars, out) == 0
    text = out.getvalue()
    assert "2026-11-26 blocks=2" in text and "2026-11-27 blocks=1" in text


def test_reason_lists_are_capped(env: Env) -> None:
    env.queue.write_text("READY: " + "; ".join(f"item{n}" for n in range(40)) + "\n")
    _, out = env.run()
    assert out is not None and "item0" in out["reason"] and "item39" not in out["reason"] and "more" in out["reason"]


def test_negative_guard_bites_with_floor_zero(env: Env) -> None:
    env.queue.write_text(TABLE)
    _, out = env.run(SAFO_IDLE_FLOOR="0")
    assert out is None  # a floor of 0 can never block: proves the floor comparison is the decision
