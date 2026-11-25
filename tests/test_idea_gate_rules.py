# SPDX-License-Identifier: Apache-2.0
"""safo-file rules added in round 2: advisory scope, ledger safety, display escaping, fences, names (issue #443)."""

from __future__ import annotations

import io
import os
from pathlib import Path

from safo import idea_gate
from safo.errors import SafoError
from test_idea_gate import WORK, Fakes, go


def issue(f: Fakes, repo: str, body: str, *extra: str, working: str = WORK) -> tuple[int, str, str]:
    return go(f, "issue", "--repo", repo, "--working-repo", working, "--title", "t", "--body", body, *extra)


def test_the_gate_is_advisory_for_same_repo_filing_by_design(tmp_path: Path) -> None:
    f = Fakes(tmp_path)  # no `check` was ever run
    assert issue(f, WORK, "plain")[0] == 0 and len(f.created) == 1
    assert issue(f, "o/other", "plain")[0] == idea_gate.EXIT_REFUSED and len(f.created) == 1
    assert "advisory" in (idea_gate.__doc__ or "").lower()


def test_ledger_that_cannot_be_written_stops_before_the_issue_is_created(tmp_path: Path) -> None:
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        f = Fakes(tmp_path)
        code, _, err = issue(f, WORK, "b", "--ledger", str(ro / "sub" / "l.jsonl"))
    finally:
        ro.chmod(0o700)
    assert code == 2 and "ledger" in err and f.created == []


def test_symlinked_ledger_is_refused_before_the_issue_is_created(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("")
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)
    f = Fakes(tmp_path)
    code, _, err = issue(f, WORK, "b", "--ledger", str(link))
    assert code == 2 and "ledger" in err and f.created == [] and target.read_text() == ""


def test_fifo_ledger_is_refused_before_the_issue_is_created(tmp_path: Path) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)  # a reader, so a plain open would succeed
    try:
        f = Fakes(tmp_path)
        code, _, err = issue(f, WORK, "b", "--ledger", str(fifo))
    finally:
        os.close(reader)
    assert code == 2 and "ledger" in err and f.created == []


def test_report_skips_corrupt_lines_with_a_warning_and_still_counts(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    issue(f, "o/other", "cross-project: why")
    with f.ledger.open("a") as h:
        h.write("not json\n[1]\n\n")
    code, out, err = go(f, "report")
    assert code == 0 and "cross-project issues: 1 of 1" in out
    assert "2 corrupt" in err


def test_report_refuses_a_symlink_a_fifo_and_an_oversize_ledger(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    target = tmp_path / "t"
    target.write_text("")
    f.ledger.symlink_to(target)
    assert go(f, "report")[0] == 2
    f.ledger.unlink()
    os.mkfifo(f.ledger)
    assert go(f, "report")[0] == 2
    f.ledger.unlink()
    with f.ledger.open("wb") as h:
        h.truncate(idea_gate.LEDGER_LIMIT + 1)
    f.ledger.chmod(0o600)
    assert go(f, "report")[0] == 2


def test_a_failed_create_leaves_no_ledger_line(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    deps = f.deps()

    def boom(repo: str, title: str, body: str) -> str:
        raise SafoError("gh down")

    deps.create_issue = boom
    argv = ["issue", "--repo", WORK, "--working-repo", WORK, "--title", "t", "--body", "b"]
    assert idea_gate.main(argv, deps=deps, out=io.StringIO(), err=io.StringIO()) == 2
    assert not f.ledger.exists() or f.ledger.read_text() == ""


def test_hostile_idea_is_shown_escaped_and_posted_raw(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    idea = "red \x1b[31mtext\n::error::boom"
    code, out, _ = go(f, "check", idea, "--working-repo", WORK, "--answer", "tangent", "--parking", "o/park#7")
    assert code == 0
    assert "\x1b" not in out and not any(ln.startswith("::") for ln in out.splitlines())
    assert "::error::" not in out
    assert "\x1b[31m" in f.comments[0][2] and "\n::error::boom" in f.comments[0][2]


def test_cross_project_line_inside_a_code_fence_does_not_count(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    assert issue(f, "o/other", "```\ncross-project: sneaky\n```")[0] == idea_gate.EXIT_REFUSED
    assert issue(f, "o/other", "~~~\ncross-project: sneaky\n")[0] == idea_gate.EXIT_REFUSED  # unclosed fence
    assert issue(f, "o/other", "```\ncode\n```\ncross-project: real reason")[0] == 0


def test_dot_segments_are_not_repo_names(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    for bad in ("o/.", "o/..", "./x"):
        assert issue(f, bad, "cross-project: r")[0] == 2
        assert issue(f, WORK, "b", working=bad)[0] == 2
    assert f.created == []


def test_other_owner_needs_an_explicit_flag(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    body = "cross-project: reason"
    code, _, err = issue(f, "x/other", body)
    assert code == idea_gate.EXIT_REFUSED and "--allow-other-owner" in err and f.created == []
    assert issue(f, "x/other", body, "--allow-other-owner")[0] == 0
