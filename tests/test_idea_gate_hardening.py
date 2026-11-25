# SPDX-License-Identifier: Apache-2.0
"""safo-file round 3: executable trust, environment allowlist, bounded gh, ledger trust and protocol (issue #443)."""

from __future__ import annotations

import io
import json
import os
import stat
import time
from pathlib import Path
from typing import Any

import pytest

from hooksdata import agents_file
from safo import idea_gate, idea_gate_io
from safo.errors import SafoError
from test_idea_gate import WORK, Fakes, go
from test_idea_gate_real import Box, script


@pytest.fixture
def box(tmp_path: Path) -> Box:
    return Box(tmp_path)


SECRETS = {
    "SAFO_TOKEN": "s1",
    "AWS_SECRET_ACCESS_KEY": "s2",
    "GITHUB_TOKEN": "s3",
    "FOO_SECRET": "s4",
    "GH_TOKEN": "s5",
    "SSH_PRIVATE_KEY": "s6",
}
ALLOWED = {"USER": "u", "LANG": "C", "LC_ALL": "C", "TERM": "xterm", "TZ": "UTC"}


def mem_exe(box: Box, name: str = "mem", body: str = "echo hit") -> Path:
    return script(box.bin / name, f"#!/bin/sh\n{body}\n")


def mem_with(box: Box, command: str) -> list[str]:
    return list(box.deps(SAFO_MEMORY_SEARCH=command).memory("idea"))


# ---- 1. executables ----------------------------------------------------------------------------------------------


def test_memory_relative_path_is_refused(box: Box, monkeypatch: pytest.MonkeyPatch) -> None:
    mem_exe(box)
    monkeypatch.chdir(box.bin)
    with pytest.raises(SafoError, match="absolute"):
        mem_with(box, "./mem")


def test_memory_inside_the_working_directory_is_refused(box: Box, monkeypatch: pytest.MonkeyPatch) -> None:
    exe = mem_exe(box)
    monkeypatch.chdir(box.bin)
    with pytest.raises(SafoError, match="current directory"):
        mem_with(box, str(exe))


def test_memory_group_writable_file_or_parent_is_refused(box: Box) -> None:
    exe = mem_exe(box)
    exe.chmod(0o770)
    with pytest.raises(SafoError, match="writable"):
        mem_with(box, str(exe))
    exe.chmod(0o700)
    box.bin.chmod(0o775)
    with pytest.raises(SafoError, match="writable"):
        mem_with(box, str(exe))
    with pytest.raises(SafoError, match="writable"):
        mem_with(box, "mem")  # found on PATH: the same checks


def foreign(info: os.stat_result) -> os.stat_result:
    """The same stat result, owned by a user that is neither the caller nor root."""
    fields = list(info)
    fields[4] = os.geteuid() + 1
    return os.stat_result(fields)


def test_memory_file_owned_by_another_user_is_refused(box: Box, monkeypatch: pytest.MonkeyPatch) -> None:
    exe = mem_exe(box)
    real_stat = os.stat

    def stat_(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        info = real_stat(path, *args, **kwargs)
        return foreign(info) if str(path) == str(exe) else info  # only the file; every directory is still fine

    monkeypatch.setattr(idea_gate_io.os, "stat", stat_)
    with pytest.raises(SafoError, match="mem is owned by another user"):
        mem_with(box, str(exe))


def test_memory_trusted_path_and_bare_name_are_accepted(box: Box) -> None:
    # guards against a false refusal (the hardening must not reject a normal install); it does not test the hardening
    exe = mem_exe(box)
    assert mem_with(box, str(exe)) == ["hit"]
    assert mem_with(box, "mem") == ["hit"]


def test_gh_in_a_group_writable_directory_is_exit_2(box: Box) -> None:
    box.bin.chmod(0o775)
    only = {"PATH": str(box.bin)}  # no other gh on PATH: the real one must never run in a test
    with pytest.raises(SafoError, match="writable"):
        box.deps(**only).gh_repos()
    err = io.StringIO()
    argv = ["issue", "--repo", "o/r", "--working-repo", "o/r", "--title", "t", "--body", "b"]
    argv += ["--ledger", str(box.log / "l.jsonl")]
    env = {**box.env, **only}
    assert idea_gate.main(argv, env=env, out=io.StringIO(), err=err) == 2 and "writable" in err.getvalue()


# ---- 2. environment ----------------------------------------------------------------------------------------------


def test_only_allowlisted_variables_reach_gh_and_the_memory_command(box: Box) -> None:
    env = {**SECRETS, **ALLOWED, "GH_HOST": "evil.example", "PATH": f":rel/bin:{box.bin}:/usr/bin"}
    box.deps(**env).create_issue("o/r", "t", "b")
    seen = dict(x.split("=", 1) for x in (box.log / "env").read_text().splitlines() if "=" in x)
    mem_exe(box, "mem", "env")
    got = dict(x.split("=", 1) for x in box.deps(SAFO_MEMORY_SEARCH="mem", **env).memory("i") if "=" in x)
    for child in (seen, got):
        for name in (*SECRETS, "GH_HOST"):
            assert name not in child, name
        for name, value in ALLOWED.items():
            assert child[name] == value
        assert child["HOME"] == str(box.home)
        assert child["PATH"] == f"{box.bin}:/usr/bin"  # empty and relative entries dropped


# ---- 4. gh output and descendants --------------------------------------------------------------------------------


def test_gh_endless_output_is_capped(box: Box) -> None:
    for body in ("yes", "yes >&2"):
        script(box.bin / "gh", f"#!/bin/sh\n{body}\n")
        start = time.monotonic()
        with pytest.raises(SafoError, match="more output than the limit"):
            box.deps().create_issue("o/r", "t", "b")
        assert time.monotonic() - start < 20


def alive(pid: int) -> bool:
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def test_gh_descendant_holding_the_pipes_is_killed(box: Box, monkeypatch: pytest.MonkeyPatch) -> None:
    pidfile = box.log / "pid"
    script(box.bin / "gh", f"#!/bin/sh\nsleep 60 &\necho $! > {pidfile}\necho url\n")
    monkeypatch.setattr(idea_gate, "CALL_TIMEOUT", 0.5)
    start = time.monotonic()
    with pytest.raises(SafoError, match="timed out"):
        box.deps().create_issue("o/r", "t", "b")
    assert time.monotonic() - start < 20
    pid = int(pidfile.read_text())
    for _ in range(30):
        if not alive(pid):
            break
        time.sleep(0.1)
    assert not alive(pid)


# ---- 3 and 5. the ledger -----------------------------------------------------------------------------------------


def issue(f: Fakes, ledger: Path) -> tuple[int, str, str]:
    argv = ["issue", "--repo", WORK, "--working-repo", WORK, "--title", "t", "--body", "b", "--ledger", str(ledger)]
    return go(f, *argv)


def test_ledger_parent_component_symlink_is_refused(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    f = Fakes(tmp_path)
    code, _, err = issue(f, tmp_path / "link" / "l.jsonl")
    assert code == 2 and "ledger" in err and f.created == []
    assert not (tmp_path / "real" / "l.jsonl").exists()


def test_ledger_owned_by_another_user_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = tmp_path / "l.jsonl"
    ledger.write_text("")
    ledger.chmod(0o600)
    real_fstat = os.fstat

    def fstat_(fd: int) -> os.stat_result:
        info = real_fstat(fd)
        return foreign(info) if stat.S_ISREG(info.st_mode) else info  # only the file; the directories stay fine

    monkeypatch.setattr(idea_gate_io.os, "fstat", fstat_)
    f = Fakes(tmp_path)
    code, _, err = issue(f, ledger)
    assert code == 2 and "ledger is not owned" in err and f.created == []


def test_group_writable_ledger_or_parent_is_refused(tmp_path: Path) -> None:
    ledger = tmp_path / "l.jsonl"
    ledger.write_text("")
    ledger.chmod(0o660)
    f = Fakes(tmp_path)
    code, _, err = issue(f, ledger)
    assert code == 2 and "writable" in err and f.created == []
    ledger.chmod(0o600)
    tmp_path.chmod(0o770)
    try:
        code, _, err = issue(f, ledger)
    finally:
        tmp_path.chmod(0o700)
    assert code == 2 and "writable" in err and f.created == []


def test_new_ledger_is_created_0600_whatever_the_umask(tmp_path: Path) -> None:
    # guards against a false refusal of a fresh ledger (and its 0600 mode); the refusals are the tests around it
    old = os.umask(0)
    try:
        f = Fakes(tmp_path)
        assert issue(f, tmp_path / "sub" / "l.jsonl")[0] == 0
    finally:
        os.umask(old)
    assert (tmp_path / "sub" / "l.jsonl").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "sub").stat().st_mode & 0o777 == 0o700


def states(f: Fakes) -> list[str]:
    return [json.loads(line)["state"] for line in f.ledger.read_text().splitlines()]


def test_pending_is_written_before_and_committed_after_the_issue(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    seen: list[list[str]] = []
    deps = f.deps()
    inner = deps.create_issue

    def create(repo: str, title: str, body: str) -> str:
        seen.append(states(f))  # what the ledger held when the issue was created
        return inner(repo, title, body)

    deps.create_issue = create
    argv = ["issue", "--repo", WORK, "--working-repo", WORK, "--title", "t", "--body", "b"]
    assert idea_gate.main(argv, deps=deps, out=io.StringIO(), err=io.StringIO()) == 0
    assert seen == [["pending"]] and states(f) == ["pending", "committed"]
    assert json.loads(f.ledger.read_text().splitlines()[1])["url"].endswith("/1")


def test_short_writes_are_looped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def short(fd: int, data: bytes | memoryview) -> int:
        return os.write(fd, bytes(data[:3]))

    monkeypatch.setattr(idea_gate, "write_fd", short)
    f = Fakes(tmp_path)
    assert issue(f, f.ledger)[0] == 0
    assert states(f) == ["pending", "committed"]  # every line whole and parseable


def test_commit_failure_after_creation_names_the_url_and_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []

    def flaky(fd: int, data: bytes | memoryview) -> int:
        calls.append(1)
        if len(calls) > 1:
            raise OSError("disk full")
        return os.write(fd, data)

    monkeypatch.setattr(idea_gate, "write_fd", flaky)
    f = Fakes(tmp_path)
    code, _, err = issue(f, f.ledger)
    assert code == 2 and len(f.created) == 1
    assert "created but not recorded" in err and "issues/1" in err


def test_failed_create_leaves_a_pending_record_only(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    deps = f.deps()

    def boom(repo: str, title: str, body: str) -> str:
        raise SafoError("gh down")

    deps.create_issue = boom
    argv = ["issue", "--repo", WORK, "--working-repo", WORK, "--title", "t", "--body", "b"]
    assert idea_gate.main(argv, deps=deps, out=io.StringIO(), err=io.StringIO()) == 2
    assert states(f) == ["pending"]


def test_report_counts_committed_and_names_pending_without_commit(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    issue(f, f.ledger)
    with f.ledger.open("a") as h:
        h.write(json.dumps({"state": "pending", "id": "zz", "repo": "o/x", "working_repo": WORK}) + "\n")
    code, out, err = go(f, "report")
    assert code == 0 and "cross-project issues: 0 of 1" in out
    assert "1 pending" in err


# ---- 6. fences ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "ok"),
    [
        ("````\ncode\n```\ncross-project: early\n", False),  # a shorter closer does not close
        ("````\ncode\n````\ncross-project: late\n", True),
        ("````\ncode\n`````\ncross-project: late\n", True),  # a longer closer closes
        ("~~~\ncode\n```\ncross-project: x\n", False),  # another character does not close
        ("~~~\ncode\n~~~\ncross-project: x\n", True),
        ("   ```\ncross-project: x\n   ```\ncross-project: real\n", True),  # indent up to 3
        ("    ```\ncross-project: x\n", True),  # four spaces is code, not a fence
        ("```\ncode\n``` trailing\ncross-project: x\n", False),  # a closer carries nothing after it
    ],
)
def test_fences_close_only_by_same_char_and_length(tmp_path: Path, body: str, ok: bool) -> None:
    f = Fakes(tmp_path)
    argv = ["issue", "--repo", "o/other", "--working-repo", WORK, "--title", "t", "--body", body]
    assert (go(f, *argv)[0] == 0) is ok


# ---- 7. the agents file ------------------------------------------------------------------------------------------


def tree(path: Path) -> dict[str, tuple[int, int]]:
    return {str(p.relative_to(path)): (p.stat().st_mtime_ns, p.stat().st_size) for p in sorted(path.rglob("*"))}


def test_check_reads_only_the_fixed_agents_file_and_writes_nothing(box: Box, tmp_path: Path) -> None:
    box.agents(tracking_repos=["o/alpha-fixed"])
    cfg = box.home / ".config" / "safo"
    agents_file(tmp_path / "other.yaml", tracking_repos=["o/alpha-other"])
    agents_file(tmp_path / "other-local.yaml", tracking_repos=["o/alpha-localvar"])
    agents_file(cfg / "agents.local.yaml", tracking_repos=["o/alpha-merged"])
    before = tree(cfg)
    other, other_local = str(tmp_path / "other.yaml"), str(tmp_path / "other-local.yaml")
    env = {**box.env, "SAFO_AGENTS": other, "SAFO_AGENTS_LOCAL": other_local}
    out = io.StringIO()
    assert idea_gate.main(["check", "alpha", "--working-repo", "o/r"], env=env, out=out, err=io.StringIO()) == 3
    shown = out.getvalue()
    assert "o/alpha-fixed" in shown
    assert "alpha-other" not in shown and "alpha-localvar" not in shown and "alpha-merged" not in shown
    argv = ["issue", "--repo", "o/r", "--working-repo", "o/r", "--title", "t", "--body", "b"]
    argv += ["--ledger", str(box.log / "l.jsonl")]
    idea_gate.main(argv, env=env, out=io.StringIO(), err=io.StringIO())
    assert tree(cfg) == before


# ---- 8 and 9. identity and names ---------------------------------------------------------------------------------


def test_repo_identity_is_case_insensitive_and_spelling_is_kept(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    argv = ["issue", "--repo", "O/Reach-Around", "--working-repo", WORK, "--title", "t", "--body", "no reason"]
    assert go(f, *argv)[0] == 0  # the same repository: no reason needed
    out = go(f, "report", "--working-repo", "O/REACH-AROUND")[1]
    assert "cross-project issues: 0 of 1" in out
    assert "O/Reach-Around" in f.ledger.read_text()  # the spelling it was filed with
    code, out, _ = go(f, "check", "x", "--working-repo", WORK, "--answer", "extends:O/Proxmox-Templates")
    assert code == 0 and "extends O/Proxmox-Templates" in out


@pytest.mark.parametrize("bad", ["o-/r", "-o/r", "o--x/r", f"{'a' * 40}/r", "o/", "/r", "o/..", "o/."])
def test_names_github_rejects_are_rejected(tmp_path: Path, bad: str) -> None:
    f = Fakes(tmp_path)
    argv = ["issue", f"--repo={bad}", "--working-repo", WORK, "--title", "t", "--body", "cross-project: r"]
    assert go(f, *argv)[0] == 2 and f.created == []


@pytest.mark.parametrize("good", [f"{'a' * 39}/r", "a-b-c/x.y_z", "9/9"])
def test_names_github_accepts_are_accepted(tmp_path: Path, good: str) -> None:
    # guards against a false refusal of valid GitHub names, not the hardening
    f = Fakes(tmp_path)
    argv = ["issue", "--repo", good, "--working-repo", good, "--title", "t", "--body", "b"]
    assert go(f, *argv)[0] == 0
