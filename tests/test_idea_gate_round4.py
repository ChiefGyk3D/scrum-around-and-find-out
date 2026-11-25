# SPDX-License-Identifier: Apache-2.0
"""safo-file round 4: PATH trust, the sticky rule, separate environments, killpg order, ledger write safety (#443)."""

from __future__ import annotations

import errno
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from safo import idea_gate, idea_gate_io
from test_idea_gate_real import Box, script


@pytest.fixture
def box(tmp_path: Path) -> Box:
    return Box(tmp_path)


# ---- 1. PATH -----------------------------------------------------------------------------------------------------


def test_a_writable_path_directory_is_dropped_for_both_children(box: Box, tmp_path: Path) -> None:
    loose = tmp_path / "loose"
    loose.mkdir()
    loose.chmod(0o777)
    env = {"PATH": f"{loose}:{box.bin}:/usr/bin"}
    script(box.bin / "mem", "#!/bin/sh\nenv\n")
    box.deps(**env).create_issue("o/r", "t", "b")
    seen = [x for x in (box.log / "env").read_text().splitlines() if x.startswith("PATH=")]
    got = [x for x in box.deps(SAFO_MEMORY_SEARCH="mem", **env).memory("i") if x.startswith("PATH=")]
    assert seen == got == [f"PATH={box.bin}:/usr/bin"]


def test_a_path_with_no_trusted_directory_falls_back(tmp_path: Path) -> None:
    loose = tmp_path / "loose"
    loose.mkdir()
    loose.chmod(0o777)
    for kind in ("gh", "memory"):
        assert idea_gate_io.child_env({"PATH": f"{loose}:rel"}, kind)["PATH"] == "/usr/bin:/bin"


# ---- 2. the sticky exemption is for directories only -------------------------------------------------------------


def test_root_sticky_applies_to_directories_not_files() -> None:
    info = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o1777)
    assert "writable" in idea_gate_io._untrusted(info, directory=False)  # a file at 01777 is refused
    assert idea_gate_io._untrusted(SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o1777), directory=True) == ""
    assert "writable" in idea_gate_io._untrusted(
        SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o777), directory=True
    )


# ---- 3. separate environments ------------------------------------------------------------------------------------

GH_DIRS = ("GH_CONFIG_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR")
COMMON = {"USER": "u", "LOGNAME": "u", "LANG": "C", "LC_ALL": "C", "TERM": "xterm", "TZ": "UTC"}


def parsed(lines: list[str]) -> dict[str, str]:
    return dict(x.split("=", 1) for x in lines if "=" in x)


def test_memory_gets_the_small_environment_and_gh_never_gets_gh_host(box: Box) -> None:
    dirs = {}
    for name in GH_DIRS:
        dirs[name] = str(box.home / name.lower())
        Path(dirs[name]).mkdir(mode=0o700)
    gh_only = {**dirs, "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/x/bus"}
    env = {**COMMON, **gh_only, "GH_HOST": "evil.example", "PATH": f"{box.bin}:/usr/bin"}
    box.deps(**env).create_issue("o/r", "t", "b")
    gh_saw = parsed((box.log / "env").read_text().splitlines())
    script(box.bin / "mem", "#!/bin/sh\nenv\n")
    mem_saw = parsed(box.deps(SAFO_MEMORY_SEARCH="mem", **env).memory("i"))
    assert "GH_HOST" not in gh_saw
    for name, value in {**COMMON, **gh_only}.items():
        assert gh_saw[name] == value
    for name, value in COMMON.items():
        assert mem_saw[name] == value
    assert gh_saw["HOME"] == mem_saw["HOME"] == str(box.home)
    for name in (*gh_only, "GH_HOST"):
        assert name not in mem_saw, name


# ---- 4. process group --------------------------------------------------------------------------------------------


def test_a_normal_completion_never_signals_a_group(box: Box, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    monkeypatch.setattr(os, "killpg", lambda pgid, sig: calls.append(pgid))
    assert box.deps().create_issue("o/r", "t", "b").endswith("/9")
    script(box.bin / "mem", "#!/bin/sh\necho hit\n")
    assert box.deps(SAFO_MEMORY_SEARCH="mem").memory("i") == ["hit"]
    assert calls == []


def test_a_timeout_kills_the_group_before_the_leader_is_reaped(box: Box, monkeypatch: pytest.MonkeyPatch) -> None:
    script(box.bin / "gh", "#!/bin/sh\nsleep 60 &\necho url\n")  # the leader exits; a descendant holds the pipes
    monkeypatch.setattr(idea_gate, "CALL_TIMEOUT", 0.5)
    real = os.killpg
    seen: list[bool] = []

    def spy(pgid: int, sig: int) -> None:
        seen.append(Path(f"/proc/{pgid}/stat").exists())  # a zombie still has an entry; a reaped leader has none
        real(pgid, sig)

    monkeypatch.setattr(os, "killpg", spy)
    with pytest.raises(Exception, match="timed out"):
        box.deps().create_issue("o/r", "t", "b")
    assert seen == [True]


# ---- 5. ledger writes --------------------------------------------------------------------------------------------


def test_an_interrupted_write_is_retried_without_advancing(tmp_path: Path) -> None:
    fd = idea_gate_io.open_ledger(tmp_path / "l.jsonl")
    calls: list[int] = []

    def flaky(handle: int, data: bytes | memoryview) -> int:
        calls.append(1)
        if len(calls) == 1:
            raise InterruptedError(errno.EINTR, "interrupted")
        return os.write(handle, data)

    try:
        idea_gate_io.write_all(fd, b'{"a": 1}\n', flaky)
    finally:
        os.close(fd)
    assert (tmp_path / "l.jsonl").read_bytes() == b'{"a": 1}\n' and len(calls) == 2


def test_two_processes_appending_large_records_leave_whole_lines(tmp_path: Path) -> None:
    ledger, start = tmp_path / "l.jsonl", tmp_path / "go"
    here = Path(__file__).parent
    env = {**os.environ, "PYTHONPATH": f"{here.parent / 'src'}:{here}"}
    argv = [sys.executable, str(here / "idea_gate_appender.py"), str(ledger), str(start)]
    kids = [subprocess.Popen([*argv, tag, "6"], env=env) for tag in ("a", "b")]  # noqa: S603 - this interpreter, a helper
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and not all((tmp_path / f"ready-{t}").exists() for t in ("a", "b")):
        time.sleep(0.01)  # a barrier: both writers are open, each holds its whole record, neither has written
    assert all((tmp_path / f"ready-{t}").exists() for t in ("a", "b"))
    start.write_text("")
    assert [k.wait(timeout=120) for k in kids] == [0, 0]
    rows = [json.loads(x) for x in ledger.read_text().splitlines()]  # a torn line would not parse
    assert len(rows) == 12 and all(len(r["pad"]) == 200_000 and set(r["pad"]) == {r["tag"]} for r in rows)
    assert stat.S_ISREG(ledger.stat().st_mode)
