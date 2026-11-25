# SPDX-License-Identifier: Apache-2.0
"""safo-file's live dependencies against a fake `gh` and fake memory commands on PATH. No network (issue #443)."""

from __future__ import annotations

import argparse
import datetime as dt
import io
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from hooksdata import agents_file
from safo import idea_gate, idea_gate_io
from safo.errors import SafoError

NOW = dt.datetime(2026, 11, 25, tzinfo=dt.UTC)

GH = """#!/bin/sh
echo "$@" >> "@LOG@/argv"
env >> "@LOG@/env"
if [ "$1 $2" = "repo list" ]; then echo '[{"nameWithOwner":"o/agent-box","description":null}]'; exit 0; fi
if [ -e "@LOG@/sleep" ]; then sleep 30; fi
if [ -e "@LOG@/fail" ]; then echo nope >&2; exit 1; fi
if [ "$1" = "api" ]; then echo true; exit 0; fi
cat > "@LOG@/stdin"
echo https://github.com/o/r/issues/9
"""


def script(path: Path, text: str) -> Path:
    path.write_text(text)
    path.chmod(0o700)
    return path


class Box:
    def __init__(self, tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.home = tmp / "home"
        self.bin = tmp / "bin"
        self.log = tmp / "log"
        for d in (self.home, self.bin, self.log):
            d.mkdir()
        # hermetic: the fallback PATH (used when no trusted PATH entry is left) holds nothing, so a gh installed on the
        # machine (a CI runner has one in /usr/bin) can never be found or run by a test
        self.fallback = tmp / "fallback"
        self.fallback.mkdir()
        monkeypatch.setattr(idea_gate_io, "FALLBACK_PATH", str(self.fallback))
        script(self.bin / "gh", GH.replace("@LOG@", str(self.log)))
        self.env = {"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.home)}

    def deps(self, **env: str) -> idea_gate.Deps:
        args = argparse.Namespace(working_repo="o/r", ledger=str(self.log / "ledger.jsonl"))
        return idea_gate.real_deps(args, {**self.env, **env}, NOW)

    def flag(self, name: str) -> None:
        (self.log / name).write_text("")

    def agents(self, **hooks: Any) -> None:
        d = self.home / ".config" / "safo"
        d.mkdir(parents=True, mode=0o700)
        agents_file(d / "agents.yaml", **hooks)


@pytest.fixture
def box(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Box:
    return Box(tmp_path, monkeypatch)


def test_issue_and_comment_bodies_go_over_stdin_never_argv(box: Box) -> None:
    d = box.deps(GH_TOKEN="ambient-token-value")
    body = "BODY-TEXT-MARKER cross-project: why"
    assert d.create_issue("o/r", "title", body).endswith("/9")
    assert (box.log / "stdin").read_text() == body
    d.comment("o/park", 7, body)
    argv = (box.log / "argv").read_text()
    assert "BODY-TEXT-MARKER" not in argv and "--body-file -" in argv
    assert "ambient-token-value" not in (box.log / "env").read_text()  # the ambient token is scrubbed


def test_gh_repos_reads_the_owner_list(box: Box) -> None:
    assert box.deps().gh_repos() == [("o/agent-box", "")]


def test_gh_failure_missing_and_timeout_are_clean_errors(box: Box, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SafoError, match="failed"):
        box.flag("fail")
        box.deps().create_issue("o/r", "t", "b")
    monkeypatch.setattr(idea_gate, "CALL_TIMEOUT", 0.5)
    with pytest.raises(SafoError, match="timed out"):
        box.flag("sleep")
        box.deps().create_issue("o/r", "t", "b")
    missing = idea_gate.real_deps(argparse.Namespace(working_repo="o/r", ledger=""), {"PATH": "/nonexistent"}, NOW)
    with pytest.raises(SafoError, match="gh"):
        missing.gh_repos()


def test_main_exits_2_when_gh_times_out(box: Box, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(idea_gate, "CALL_TIMEOUT", 0.5)
    box.flag("sleep")
    env = box.env
    ledger = str(box.log / "l.jsonl")
    argv = ["issue", "--repo", "o/r", "--working-repo", "o/r", "--title", "t", "--body", "b", "--ledger", ledger]
    err = io.StringIO()
    assert idea_gate.main(argv, env=env, out=io.StringIO(), err=err) == 2 and "timed out" in err.getvalue()


def test_tracking_repos_come_from_the_agents_file_and_a_repeat_is_harmless(box: Box) -> None:
    box.agents(tracking_repos=["o/a", "o/b", "o/a"])
    assert list(box.deps().tracking()) == ["o/a", "o/b"]  # a list: a repeat must be dropped by the code


def test_a_duplicate_key_in_the_agents_file_is_exit_2(box: Box) -> None:
    box.agents(tracking_repos=["o/a"])
    path = box.home / ".config" / "safo" / "agents.yaml"
    path.write_text(path.read_text() + yaml.safe_dump({"hooks": {"tracking_repos": ["o/z"]}}))
    err = io.StringIO()
    argv = ["check", "idea", "--working-repo", "o/r"]
    assert idea_gate.main(argv, env=box.env, out=io.StringIO(), err=err) == 2
    assert "safo-file:" in err.getvalue()


def memory(box: Box, body: str, idea: str = "idea") -> list[str]:
    script(box.bin / "mem", f"#!/bin/sh\n{body}\n")
    return list(box.deps(SAFO_MEMORY_SEARCH=str(box.bin / "mem")).memory(idea))


def test_memory_passes_the_idea_after_double_dash(box: Box) -> None:
    assert memory(box, 'echo "$1|$2|$#"', "-rf --help") == ["--|-rf --help|2"]


def test_memory_unset_is_no_hits_and_blank_or_missing_or_unexecutable_is_refused(box: Box) -> None:
    assert box.deps().memory("x") == []
    for bad in ("   ", str(box.bin / "nope")):
        with pytest.raises(SafoError):
            box.deps(SAFO_MEMORY_SEARCH=bad).memory("x")
    plain = box.bin / "plain"
    plain.write_text("#!/bin/sh\n")  # not executable
    with pytest.raises(SafoError):
        box.deps(SAFO_MEMORY_SEARCH=str(plain)).memory("x")


def test_memory_hang_is_cut_off(box: Box, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(idea_gate, "MEMORY_TIMEOUT", 0.5)
    start = time.monotonic()
    with pytest.raises(SafoError, match="timed out"):
        memory(box, "sleep 30")
    assert time.monotonic() - start < 10


def test_memory_huge_output_is_capped_and_the_child_stopped(box: Box) -> None:
    start = time.monotonic()
    hits = memory(box, "yes 'a hit line'")
    assert time.monotonic() - start < 10
    assert 0 < sum(len(h) for h in hits) <= idea_gate.MEMORY_CAP


def test_gh_error_text_and_a_returned_url_are_shown_escaped_and_bounded(box: Box) -> None:
    script(box.bin / "gh", '#!/bin/sh\nprintf "\\033[31m::error::boom\\n" >&2\nexit 1\n')
    argv = ["issue", "--repo", "o/r", "--working-repo", "o/r", "--title", "t", "--body", "b"]
    argv += ["--ledger", str(box.log / "l.jsonl")]
    err = io.StringIO()
    assert idea_gate.main(argv, env=box.env, out=io.StringIO(), err=err) == 2
    assert "\x1b" not in err.getvalue() and "::error::" not in err.getvalue()
    long_line = "[ \"$1\" = api ] && echo true && exit 0\ncat > /dev/null\nprintf '\\033[31m::error::x'\n"
    long_line += "head -c 200000 /dev/zero | tr '\\0' 'u'\n"
    script(box.bin / "gh", "#!/bin/sh\n" + long_line)
    out = io.StringIO()
    argv[-1] = str(box.log / "l2.jsonl")
    assert idea_gate.main(argv, env=box.env, out=out, err=io.StringIO()) == 0
    assert "\x1b" not in out.getvalue() and "::error::" not in out.getvalue()
    assert len(out.getvalue()) < idea_gate.URL_SHOWN + 200


def test_memory_failure_exit_is_an_error(box: Box) -> None:
    with pytest.raises(SafoError):
        memory(box, "exit 3")
