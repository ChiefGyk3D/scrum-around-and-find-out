# SPDX-License-Identifier: Apache-2.0
"""safo-file round 5: resolved PATH targets, trusted lookup, configuration roots, bounded ledger lock (#443)."""

from __future__ import annotations

import fcntl
import io
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from safo import idea_gate, idea_gate_io
from safo.errors import SafoError
from test_idea_gate import WORK, Fakes, go
from test_idea_gate_real import GH, Box, script


@pytest.fixture
def box(tmp_path: Path) -> Box:
    return Box(tmp_path)


def loose_dir(parent: Path, name: str) -> Path:
    path = parent / name
    path.mkdir()
    path.chmod(0o777)
    return path


# ---- 1. PATH symlinks --------------------------------------------------------------------------------------------


def test_a_path_symlink_whose_target_sits_under_a_writable_parent_is_dropped(tmp_path: Path) -> None:
    loose = loose_dir(tmp_path, "loose")
    target = loose / "bin"
    target.mkdir()
    target.chmod(0o755)
    trusted = tmp_path / "ok"
    trusted.mkdir()
    link = trusted / "entry"
    link.symlink_to(target)
    good = tmp_path / "good"
    good.mkdir()
    for kind in ("gh", "memory"):
        assert idea_gate_io.child_env({"PATH": f"{link}:{good}"}, kind)["PATH"] == str(good)
    assert idea_gate_io.child_env({"PATH": str(good)}, "gh")["PATH"] == str(good)  # the control: a plain entry stays


# ---- 2. lookup on the trusted PATH -------------------------------------------------------------------------------


def test_an_untrusted_earlier_gh_does_not_mask_a_trusted_later_one(box: Box, tmp_path: Path) -> None:
    bad = loose_dir(tmp_path, "bad")
    script(bad / "gh", "#!/bin/sh\ntouch " + str(box.log / "bad-ran") + "\nexit 1\n")
    env = {"PATH": f"{bad}:{box.bin}:/usr/bin"}
    assert box.deps(**env).create_issue("o/r", "t", "b").endswith("/9")
    assert not (box.log / "bad-ran").exists()


def test_a_gh_only_in_an_untrusted_directory_is_named_and_exit_2(box: Box, tmp_path: Path) -> None:
    bad = loose_dir(tmp_path, "bad")
    script(bad / "gh", GH.replace("@LOG@", str(box.log)))
    (box.bin / "gh").unlink()
    env = {**box.env, "PATH": str(bad)}
    err = io.StringIO()
    argv = ["issue", "--repo", "o/r", "--working-repo", "o/r", "--title", "t", "--body", "b"]
    argv += ["--ledger", str(box.log / "l.jsonl")]
    assert idea_gate.main(argv, env=env, out=io.StringIO(), err=err) == 2
    assert "only in" in err.getvalue() and "bad" in err.getvalue() and "writable" in err.getvalue()


def test_the_memory_bare_name_skips_an_untrusted_directory_and_names_it(box: Box, tmp_path: Path) -> None:
    bad = loose_dir(tmp_path, "bad")
    script(bad / "mem", "#!/bin/sh\necho bad\n")
    script(box.bin / "mem", "#!/bin/sh\necho good\n")
    env = {"PATH": f"{bad}:{box.bin}:/usr/bin", "SAFO_MEMORY_SEARCH": "mem"}
    assert list(box.deps(**env).memory("i")) == ["good"]
    (box.bin / "mem").unlink()
    with pytest.raises(SafoError, match=r"only in .*bad.*writable"):
        box.deps(**env).memory("i")


# ---- 3. configuration roots --------------------------------------------------------------------------------------


def dump(box: Box, **env: str) -> dict[str, str]:
    box.deps(**env).create_issue("o/r", "t", "b")
    return dict(x.split("=", 1) for x in (box.log / "env").read_text().splitlines() if "=" in x)


def test_an_untrusted_gh_config_root_is_dropped_and_a_trusted_one_passes(box: Box, tmp_path: Path) -> None:
    good = box.home / "gh-config"
    good.mkdir(mode=0o700)
    bad = loose_dir(tmp_path, "bad-config")
    seen = dump(box, GH_CONFIG_DIR=str(bad), XDG_CONFIG_HOME=str(good), XDG_CACHE_HOME="relative/dir")
    assert "GH_CONFIG_DIR" not in seen and "XDG_CACHE_HOME" not in seen
    assert seen["XDG_CONFIG_HOME"] == str(good)
    (box.log / "env").unlink()
    assert dump(box, GH_CONFIG_DIR=str(good))["GH_CONFIG_DIR"] == str(good)


def test_a_config_root_reached_through_a_symlink_is_dropped(box: Box) -> None:
    real = box.home / "real"
    real.mkdir(mode=0o700)
    (box.home / "link").symlink_to(real)
    assert "GH_CONFIG_DIR" not in dump(box, GH_CONFIG_DIR=str(box.home / "link"))


def test_an_untrusted_home_stops_gh_with_exit_2(box: Box) -> None:
    box.home.chmod(0o777)
    with pytest.raises(SafoError, match="HOME"):
        box.deps().create_issue("o/r", "t", "b")
    err = io.StringIO()
    argv = ["issue", "--repo", "o/r", "--working-repo", "o/r", "--title", "t", "--body", "b"]
    argv += ["--ledger", str(box.log / "l.jsonl")]
    assert idea_gate.main(argv, env=box.env, out=io.StringIO(), err=err) == 2 and "HOME" in err.getvalue()


def test_a_home_owned_by_another_user_stops_gh(box: Box, monkeypatch: pytest.MonkeyPatch) -> None:
    real_stat = os.stat

    def stat_(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        info = real_stat(path, *args, **kwargs)
        if str(path) != str(box.home):
            return info
        fields = list(info)
        fields[4] = os.geteuid() + 1  # only HOME itself: its parents stay trusted
        return os.stat_result(fields)

    monkeypatch.setattr(os, "stat", stat_)
    with pytest.raises(SafoError, match="HOME is not owned by this user"):
        box.deps().create_issue("o/r", "t", "b")


def test_an_untrusted_home_is_dropped_for_the_memory_command(box: Box) -> None:
    script(box.bin / "mem", "#!/bin/sh\nenv\n")
    box.home.chmod(0o777)
    got = box.deps(SAFO_MEMORY_SEARCH="mem").memory("i")
    assert not any(x.startswith("HOME=") for x in got)
    box.home.chmod(0o755)
    assert f"HOME={box.home}" in box.deps(SAFO_MEMORY_SEARCH="mem").memory("i")


# ---- 4. the bounded ledger lock ----------------------------------------------------------------------------------

HOLDER = """
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
print("locked", flush=True)
sys.stdin.read()
"""


def test_a_ledger_lock_held_by_another_process_times_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(idea_gate_io, "LOCK_SECONDS", 0.3)
    ledger = tmp_path / "l.jsonl"
    holder = subprocess.Popen(  # noqa: S603 - this interpreter and a fixed program text
        [sys.executable, "-I", "-c", HOLDER, str(ledger)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
    )
    try:
        assert holder.stdout is not None and holder.stdout.readline().strip() == "locked"
        f = Fakes(tmp_path)
        start = time.monotonic()
        argv = ["issue", "--repo", WORK, "--working-repo", WORK, "--title", "t", "--body", "b", "--ledger", str(ledger)]

        def hung(*_: Any) -> None:
            raise AssertionError("the ledger lock wait is not bounded")

        signal.signal(signal.SIGALRM, hung)
        signal.alarm(20)  # a regression must fail, not hang the run
        try:
            code, _, err = go(f, *argv)
        finally:
            signal.alarm(0)
        assert time.monotonic() - start < 10
    finally:
        assert holder.stdin is not None
        holder.stdin.close()
        holder.wait(timeout=10)
    assert code == 2 and "lock" in err and f.created == []  # nothing was filed: the pending record could not be written


def test_a_lock_that_times_out_after_creation_still_prints_the_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(idea_gate_io, "LOCK_SECONDS", 0.3)
    f = Fakes(tmp_path)
    deps = f.deps()
    inner = deps.create_issue
    blocker = os.open(f.ledger, os.O_WRONLY | os.O_CREAT, 0o600)

    def create(repo: str, title: str, body: str) -> str:
        url = inner(repo, title, body)
        fcntl.flock(blocker, fcntl.LOCK_EX)  # another holder appears after the pending record
        return url

    deps.create_issue = create
    argv = ["issue", "--repo", WORK, "--working-repo", WORK, "--title", "t", "--body", "b"]
    out, err = io.StringIO(), io.StringIO()
    try:
        assert idea_gate.main(argv, deps=deps, out=out, err=err) == 2
    finally:
        os.close(blocker)
    assert "created but not recorded" in err.getvalue() and "issues/1" in err.getvalue() and "lock" in err.getvalue()
