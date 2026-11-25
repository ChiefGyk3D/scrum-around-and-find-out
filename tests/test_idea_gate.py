# SPDX-License-Identifier: Apache-2.0
"""safo-file: the idea gate and the cross-project line (issue #443). Every gh and memory call is a fake; no network."""

from __future__ import annotations

import io
import json
from pathlib import Path

from safo import idea_gate

WORK = "o/reach-around"
TRACKED = ("o/reach-around", "o/proxmox-templates")


class Fakes:
    def __init__(self, tmp: Path, *, memory: list[str] | None = None) -> None:
        self.created: list[tuple[str, str, str]] = []
        self.comments: list[tuple[str, int, str]] = []
        self.calls: list[str] = []
        self.ledger = tmp / "ledger.jsonl"
        self.memory = memory if memory is not None else []

    def deps(self) -> idea_gate.Deps:
        def repos() -> list[tuple[str, str]]:
            self.calls.append("gh repo list")
            return [("o/agent-box", "golden image for agent machines"), ("o/other", "unrelated")]

        def create(repo: str, title: str, body: str) -> str:
            self.created.append((repo, title, body))
            return f"https://github.com/{repo}/issues/{len(self.created)}"

        def comment(repo: str, number: int, body: str) -> None:
            self.comments.append((repo, number, body))

        return idea_gate.Deps(
            tracking=lambda: TRACKED,
            gh_repos=repos,
            memory=lambda idea: self.memory,
            create_issue=create,
            comment=comment,
            ledger=self.ledger,
        )


def go(fakes: Fakes, *argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = idea_gate.main(list(argv), deps=fakes.deps(), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_no_answer_shows_hits_from_all_three_sources_and_decides_nothing(tmp_path: Path) -> None:
    f = Fakes(tmp_path, memory=["note: proxmox golden image plan"])
    code, out, _ = go(f, "check", "proxmox golden image", "--working-repo", WORK)
    assert code == idea_gate.EXIT_NEEDS_ANSWER
    assert "o/proxmox-templates" in out  # tracking_repos hit
    assert "o/agent-box" in out  # gh repo list hit
    assert "proxmox golden image plan" in out  # memory hit
    assert "extends:<repo>" in out and "new-project" in out and "tangent" in out
    assert f.created == [] and f.comments == []


def test_two_answers_or_a_bad_answer_is_refused(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    assert go(f, "check", "x", "--working-repo", WORK, "--answer", "tangent", "--answer", "new-project")[0] == 2
    assert go(f, "check", "x", "--working-repo", WORK, "--answer", "maybe")[0] == 2
    assert go(f, "check", "x", "--working-repo", WORK, "--answer", "extends:")[0] == 2
    assert go(f, "check", "x", "--working-repo", WORK, "--answer", "extends:o/unknown")[0] == 2


def test_extends_a_known_repo_is_accepted(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    code, out, _ = go(f, "check", "x", "--working-repo", WORK, "--answer", "extends:o/agent-box")
    assert code == 0 and "extends o/agent-box" in out
    assert f.created == []


def test_new_project_needs_the_owner_ok_flag(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    code, _, err = go(f, "check", "x", "--working-repo", WORK, "--answer", "new-project")
    assert code == idea_gate.EXIT_REFUSED and "owner" in err
    code, out, _ = go(f, "check", "x", "--working-repo", WORK, "--answer", "new-project", "--owner-ok")
    assert code == 0 and "new-project" in out
    assert f.created == []  # the gate approves; it never creates a repo, epic or card


def test_tangent_writes_one_parking_lot_body_with_a_time_box_and_creates_nothing(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    code, out, _ = go(f, "check", "rabbit hole", "--working-repo", WORK, "--answer", "tangent", "--timebox", "20m")
    assert code == 0
    assert "rabbit hole" in out and "time box: 20m" in out.lower().replace("time-box", "time box")
    assert f.created == [] and f.comments == []


def test_tangent_can_post_to_the_one_parking_lot_issue(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    code, _, _ = go(f, "check", "rabbit hole", "--working-repo", WORK, "--answer", "tangent", "--parking", "o/park#7")
    assert code == 0
    assert len(f.comments) == 1 and f.comments[0][:2] == ("o/park", 7) and f.created == []


def test_same_repo_issue_needs_no_reason(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    code, out, _ = go(f, "issue", "--repo", WORK, "--working-repo", WORK, "--title", "t", "--body", "b")
    assert code == 0 and len(f.created) == 1 and "issues/1" in out


def test_other_repo_without_cross_project_line_is_refused(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    code, _, err = go(f, "issue", "--repo", "o/other", "--working-repo", WORK, "--title", "t", "--body", "b")
    assert code == idea_gate.EXIT_REFUSED and "cross-project:" in err
    assert f.created == []
    for empty in ("cross-project:", "cross-project:   "):
        code, _, _ = go(f, "issue", "--repo", "o/other", "--working-repo", WORK, "--title", "t", "--body", empty)
        assert code == idea_gate.EXIT_REFUSED
    assert f.created == []


def test_other_repo_with_a_reason_is_filed_and_ledgered(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    body = "text\ncross-project: agent-box work found while in reach-around\n"
    code, _, _ = go(f, "issue", "--repo", "o/other", "--working-repo", WORK, "--title", "t", "--body", body)
    assert code == 0 and len(f.created) == 1
    assert json.loads(f.ledger.read_text().splitlines()[0])["repo"] == "o/other"


def test_report_counts_only_mismatches_in_code(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    ok = "cross-project: because"
    go(f, "issue", "--repo", WORK, "--working-repo", WORK, "--title", "a", "--body", "b")
    go(f, "issue", "--repo", "o/other", "--working-repo", WORK, "--title", "a", "--body", ok)
    go(f, "issue", "--repo", "o/agent-box", "--working-repo", WORK, "--title", "a", "--body", ok)
    go(f, "issue", "--repo", "o/other", "--working-repo", "o/x", "--title", "a", "--body", ok)
    code, out, _ = go(f, "report", "--working-repo", WORK)
    assert code == 0 and "cross-project issues: 2 of 3" in out
    code, out, _ = go(f, "report")
    assert "cross-project issues: 3 of 4" in out


def test_report_with_no_ledger_is_zero(tmp_path: Path) -> None:
    code, out, _ = go(Fakes(tmp_path), "report")
    assert code == 0 and "cross-project issues: 0 of 0" in out


def test_bad_repo_names_are_refused(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    code, _, _ = go(f, "issue", "--repo", "not a repo", "--working-repo", WORK, "--title", "t", "--body", "b")
    assert code == 2 and f.created == []
