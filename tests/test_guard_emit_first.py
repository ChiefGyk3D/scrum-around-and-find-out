# SPDX-License-Identifier: Apache-2.0
"""The guard writes its decision FIRST and persists afterwards, on both the Agent and the Bash path.

The host kills the hook at GUARD_TIMEOUT_SECONDS, so nothing that can wait (config load, the log lock, the append) may
sit between the computed decision and the line on standard output; and once a decision was attempted nothing else may
follow it. Order tests use a real descriptor pipe (a buffered text stream whose bytes reach the pipe only on flush), not
a StringIO whose content is visible before any flush. The wall-time tests run the guard as a real process.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import io
import json
import os
import select
import signal
import stat
import sys
import threading
import time
import types
from pathlib import Path
from typing import Any, cast

import pytest

import safo as safo_package
from hooksdata import (
    agents_file,
    block_reprobe,
    dispatch,
    hooks,
    probe_file,
    read_log,
    set_mode,
    set_probe,
    state_folder,
)
from meterdata import NOW
from safo import hooks as core
from safo.context import LocalContext
from safo.guardlog import APPEND_LOCK_TIMEOUT, WARNING, file_lock
from safo.hooks import append_log, log_record, notice_path
from safo.localfiles import load_agents_for
from safo.modes import hooks as mod

GOOD = "acme/widgets#12"
CHILD = Path(__file__).parent / "guard_child.py"
CHILD_BUDGET = 5.0  # GUARD_TIMEOUT_SECONDS in the real-process children: decide_by 3 s, post-delivery hard limit 4 s
PRE_BUDGET = 10.0  # the real timeout, for the children that need room for a re-probe: decide_by 8 s


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now


class Pipe:
    """A real descriptor pipe with a block-buffered text writer: bytes arrive only when the writer flushes."""

    def __init__(self) -> None:
        read_end, write_end = os.pipe()
        os.set_blocking(read_end, False)
        self.read_end = read_end
        self.out = os.fdopen(write_end, "w")

    def read(self) -> str:
        try:
            return os.read(self.read_end, 1 << 20).decode()
        except BlockingIOError:
            return ""

    def close(self) -> None:
        for step in (self.out.close, lambda: os.close(self.read_end)):
            with contextlib.suppress(OSError):
                step()


class Stream(io.StringIO):
    """A stream that counts what the guard tries, and can fail on write or on flush."""

    def __init__(self, write_fails: str = "", flush_fails: bool = False) -> None:
        super().__init__()
        self.write_fails = write_fails
        self.flush_fails = flush_fails
        self.writes: list[str] = []
        self.buffered = ""

    def write(self, text: str) -> int:
        self.writes.append(text)
        if self.write_fails == "partial" and len(self.writes) == 1:
            self.buffered += text[: len(text) // 2]
            raise OSError("broken pipe after half")
        if self.write_fails == "always":
            raise OSError("closed")
        if self.write_fails == "closed":
            raise ValueError("I/O operation on closed file")
        self.buffered += text
        return len(text)

    def flush(self) -> None:
        if self.flush_fails:
            raise BrokenPipeError("flush")


def bash(command: str) -> str:
    return json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "session_id": "session-a",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }
    )


def context(home: Path, stdin: str, out: Any, **extra: Any) -> LocalContext:
    return LocalContext(out, {"HOME": str(home), "PATH": ""}, NOW, stdin=io.StringIO(stdin), **extra)


def namespace(agents: Path) -> argparse.Namespace:
    return argparse.Namespace(agents=str(agents), agents_local="")


def lines(text: str) -> list[dict[str, Any]]:
    assert text == "" or text.endswith("\n"), "a decision line ends with a newline"
    return [json.loads(row) for row in text.splitlines()]


@pytest.fixture
def agents(tmp_path: Path) -> Path:
    return agents_file(tmp_path / "agents.yaml")


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    fake = Clock()
    monkeypatch.setattr(mod, "time", types.SimpleNamespace(monotonic=fake.monotonic, sleep=time.sleep))
    return fake


def denied(data: dict[str, Any]) -> bool:
    return bool(data["hookSpecificOutput"].get("permissionDecision") == "deny")


def marker(home: Path) -> Path:
    return state_folder(home) / mod.LOG_FAILED_NAME


# -- B4: a real wall-clock bound on the configuration load ---------------------------------------------------


def spawn(mode: str, home: Path, agents: Path, fifo: Path, body: Path, stderr_fd: int | None = None) -> tuple[int, int]:
    """Start tests/guard_child.py as a real process; returns (pid, read end of its standard output). Standard error is
    discarded unless `stderr_fd` is given (a test where what stderr does matters passes its own pipe)."""
    read_end, write_end = os.pipe()
    actions: list[tuple[Any, ...]] = [(os.POSIX_SPAWN_DUP2, write_end, 1), (os.POSIX_SPAWN_CLOSE, read_end)]
    if stderr_fd is None:
        actions.append((os.POSIX_SPAWN_OPEN, 2, os.devnull, os.O_WRONLY, 0))
    else:
        actions.append((os.POSIX_SPAWN_DUP2, stderr_fd, 2))
    argv = [sys.executable, str(CHILD), mode, str(home), str(agents), str(fifo), str(body)]
    pid = os.posix_spawn(sys.executable, argv, os.environ, file_actions=actions)
    os.close(write_end)
    return pid, read_end


def wait_exit(pid: int, stop: float) -> int:
    """The child's exit status (negative for a signal). A child that has not ended within `stop` seconds fails the
    test with a clear message; a timeout never comes back as a value that a later comparison could misread."""
    end = time.monotonic() + stop
    while time.monotonic() < end:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            return os.waitstatus_to_exitcode(status)
        time.sleep(0.05)
    raise AssertionError(f"child {pid} did not exit within {stop} s")


class Arrival:
    """When the first complete line arrived in the last read_until (monotonic), so a test can assert the decision came
    BEFORE a boundary and not merely eventually."""

    at = 0.0


def read_until(fd: int, stop: float, first_line: bool = False) -> bytes:
    """What the child wrote: to end of file, or (first_line) to the first newline, within `stop` seconds."""
    data = b""
    seen_line = False
    end = time.monotonic() + stop
    while time.monotonic() < end and not (first_line and b"\n" in data):
        if select.select([fd], [], [], 0.1)[0]:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data += chunk
            if b"\n" in data and not seen_line:
                seen_line = True
                Arrival.at = time.monotonic()
    return data


@pytest.mark.parametrize("payload", ["agent", "bash"])
def test_a_loader_that_wedges_for_any_reason_still_prints_a_decision_inside_the_budget_in_a_real_process(
    _private_home: Path, agents: Path, tmp_path: Path, payload: str
) -> None:
    fifo = tmp_path / "agents.fifo"
    os.mkfifo(fifo)
    body = tmp_path / "payload.json"
    body.write_text(dispatch(model=None) if payload == "agent" else bash("sleep 60"))
    set_mode(_private_home, "block")
    started = time.monotonic()
    pid, fd = spawn("synthetic-wedge", _private_home, agents, fifo, body)
    try:
        raw = read_until(fd, 15)
        status = wait_exit(pid, CHILD_BUDGET)
    finally:
        os.close(fd)
        with contextlib.suppress(ProcessLookupError, ChildProcessError):
            os.kill(pid, 9)
            os.waitpid(pid, 0)
    elapsed = Arrival.at - started
    assert status == 0, "the process ends by itself, with the load still blocked"
    rows = lines(raw.decode())
    assert len(rows) == 1
    assert mod.CONFIG_TIMEOUT_NOTICE in rows[0]["hookSpecificOutput"]["additionalContext"]
    # SYNTHETIC: the loader is replaced by a call that never returns (a wedged mount or kernel read, which cannot be
    # made without privilege). The clock starts with the PROCESS, so start-up is inside the budget: the line must
    # ARRIVE before the host's (scaled) timeout, not merely eventually.
    assert elapsed < CHILD_BUDGET, f"{elapsed:.1f} s: the decision must land before the scaled host timeout"


def test_a_fifo_as_the_agents_file_is_refused_at_once_by_the_production_loader_not_waited_on(
    _private_home: Path, tmp_path: Path
) -> None:
    """The REAL loader (no patch): it opens with O_NONBLOCK and refuses a non-regular file, so a planted FIFO is an
    immediate degraded allow, not a hang and not even a timeout."""
    fifo = tmp_path / "agents.fifo"
    os.mkfifo(fifo)
    body = tmp_path / "payload.json"
    body.write_text(dispatch(model=None))
    set_mode(_private_home, "block")
    started = time.monotonic()
    pid, fd = spawn("real-loader", _private_home, fifo, fifo, body)
    try:
        raw = read_until(fd, 15)
    finally:
        os.close(fd)
        os.kill(pid, 9)
        os.waitpid(pid, 0)
    rows = lines(raw.decode())
    assert len(rows) == 1
    context = rows[0]["hookSpecificOutput"]["additionalContext"]
    assert '"diagnostic": "config"' in context and mod.CONFIG_TIMEOUT_NOTICE not in context
    assert time.monotonic() - started < 3, "refused at once: no wait on the FIFO"


@pytest.mark.parametrize("what", ["pending", "first-notice", "marker-dir"])
@pytest.mark.parametrize("payload", ["agent", "bash"])
def test_a_wedged_state_folder_cannot_hold_a_computed_deny_back_in_a_real_process(
    _private_home: Path, agents: Path, tmp_path: Path, what: str, payload: str
) -> None:
    if what == "first-notice" and payload == "bash":
        pytest.skip("the Bash path has no first-notice flag")
    body = tmp_path / "payload.json"
    body.write_text(dispatch(model=None) if payload == "agent" else bash("sleep 60"))
    set_mode(_private_home, "block")
    started = time.monotonic()
    pid, fd = spawn(f"slow-{what}", _private_home, agents, tmp_path / "x", body)
    try:
        raw = read_until(fd, 15)
    finally:
        os.close(fd)
        os.kill(pid, 9)
        os.waitpid(pid, 0)
    elapsed = Arrival.at - started
    [row] = lines(raw.decode())
    assert denied(row) and mod.NOTICES_SKIPPED in row["hookSpecificOutput"]["additionalContext"]
    assert elapsed < CHILD_BUDGET, f"{elapsed:.1f} s: the deny must land before the scaled host timeout"


def test_a_process_killed_after_the_decision_leaves_exactly_one_complete_json_line(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    body = tmp_path / "payload.json"
    body.write_text(bash("sleep 60"))
    set_mode(_private_home, "block")
    pid, fd = spawn("hang-append", _private_home, agents, tmp_path / "x", body)
    first = read_until(fd, 8, first_line=True)
    alive = os.waitpid(pid, os.WNOHANG) == (0, 0)
    os.kill(pid, 9)
    status = wait_exit(pid, 5)
    rest = read_until(fd, 2)
    os.close(fd)
    assert status == -9, "the kill (SIGKILL) is what ended it; the test does not depend on any cleanup"
    assert alive, "the process is still inside the hanging append when the decision is already out"
    assert first.endswith(b"\n") and first.count(b"\n") == 1 and rest == b""
    assert denied(json.loads(first))


def test_a_config_load_that_finishes_late_skips_the_lookups_and_says_so(
    _private_home: Path, agents: Path, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False, agents=agents)

    def late_load(*a: Any, **k: Any) -> Any:
        clock.now += (
            7.5  # the load returned after the lookup deadline (7 s) but before decide_by (8 s), on the injected clock
        )
        return load_agents_for(*a, **k)

    def must_not_be_asked(ref: Any) -> str:
        raise AssertionError("the issue lookup must be skipped with no budget left")

    monkeypatch.setattr(mod, "load_agents_for", late_load)
    out = Stream()
    ctx = context(_private_home, dispatch(prompt=f"issue: {GOOD}", tracked=False), out, issue_lookup=must_not_be_asked)
    assert mod.run_guard(ctx, namespace(agents)) == 0
    [row] = lines(out.buffered)
    assert denied(row) and mod.BUDGET_NOTICE in row["hookSpecificOutput"]["additionalContext"]
    assert not marker(_private_home).exists(), "the clock was still before the hard limit (9 s): the append went ahead"


# -- B1 / B2: the emit is an explicit step with a result -------------------------------------------------------


def test_a_flush_that_raises_is_not_a_delivered_decision_and_nothing_else_is_done(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_mode(_private_home, "block")
    calls: list[str] = []
    monkeypatch.setattr(mod, "append_log", lambda *a, **k: calls.append("append"))
    out = Stream(flush_fails=True)
    code = mod.run_guard(context(_private_home, bash("sleep 60"), out), namespace(agents))
    assert code == mod.EXIT_BLOCK, "a denial that was not delivered blocks (exit 2) instead of failing open"
    assert calls == [] and len(out.writes) == 1, "no append and no second line after a failed delivery"


def test_a_non_denial_that_cannot_be_delivered_exits_one(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = Stream(flush_fails=True)
    code = mod.run_guard(context(_private_home, dispatch(model=None), out), namespace(agents))  # warn mode: no deny
    assert code == mod.EXIT_NOT_DELIVERED and len(out.writes) == 1


@pytest.mark.parametrize("fails", ["partial", "always", "closed"])
def test_a_write_that_fails_part_way_is_never_followed_by_a_second_object(
    _private_home: Path, agents: Path, fails: str
) -> None:
    set_mode(_private_home, "block")
    out = Stream(write_fails=fails)
    code = mod.run_guard(context(_private_home, bash("sleep 60"), out), namespace(agents))
    assert code == mod.EXIT_BLOCK
    assert len(out.writes) == 1, "one attempt at the decision, then silence"
    assert "\n" not in out.buffered, "no complete line, and nothing after the truncated one"


def test_closed_standard_output_neither_raises_nor_emits_a_diagnostic(_private_home: Path, agents: Path) -> None:
    set_mode(_private_home, "block")
    out = Stream(write_fails="closed")
    assert mod.run_guard(context(_private_home, bash("sleep 60"), out), namespace(agents)) == mod.EXIT_BLOCK
    broken = Stream(write_fails="closed")
    # an input failure: the diagnostic itself cannot be written; the handler must not let that escape
    assert mod.run_guard(context(_private_home, "not json", broken), namespace(agents)) == mod.EXIT_NOT_DELIVERED
    assert len(out.writes) == 1 and len(broken.writes) == 1


def test_the_decision_is_in_the_pipe_before_the_append_starts(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A buffered fd stream shows nothing in the pipe until it is flushed: deleting the flush turns this red."""
    set_mode(_private_home, "block")
    pipe = Pipe()
    seen: list[str] = []
    waits: list[float] = []

    def fake_append(path: Path, record: dict[str, Any], limit: int = 0, lock_timeout: float = 0.0) -> None:
        seen.append(pipe.read())
        waits.append(lock_timeout)

    monkeypatch.setattr(mod, "append_log", fake_append)
    try:
        assert mod.run_guard(context(_private_home, bash("sleep 60"), pipe.out), namespace(agents)) == 0
    finally:
        pipe.close()
    [row] = lines(seen[0])
    assert denied(row), "the complete decision was already readable when the append began"
    assert 0 < waits[0] <= APPEND_LOCK_TIMEOUT


# -- B3: persistence is best effort whatever it raises ---------------------------------------------------------


@pytest.mark.parametrize("error", [UnicodeDecodeError("utf-8", b"\xff", 0, 1, "x"), TypeError("t"), RuntimeError("r")])
def test_persistence_raising_anything_after_the_decision_adds_no_line_and_leaves_the_marker(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    set_mode(_private_home, "block")

    def boom(*a: Any, **k: Any) -> None:
        raise error

    monkeypatch.setattr(mod, "append_log", boom)
    out = Stream()
    assert mod.run_guard(context(_private_home, bash("sleep 60"), out), namespace(agents)) == 0
    [row] = lines(out.buffered)
    assert denied(row) and len(out.writes) == 1
    assert marker(_private_home).exists()


def test_a_corrupt_log_tail_is_rotated_not_raised_and_the_deny_is_one_line(_private_home: Path, agents: Path) -> None:
    set_mode(_private_home, "block")
    folder = state_folder(_private_home)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "log.jsonl").write_bytes(b"\xff\npartial")
    (folder / "log.jsonl").chmod(0o600)
    code, out, _ = hooks("guard", "--agents", str(agents), home=_private_home, stdin=bash("sleep 60"))
    assert code == 0
    [row] = lines(out)
    assert denied(row)
    assert [f.read_bytes() for f in corrupt_files(folder)] == [b"\xff\npartial"], "kept as corruption"
    assert not (folder / "log.jsonl.1").exists(), "no archive was made or overwritten"
    assert read_log(_private_home)[-1]["rules"] == ["lead-waits"]
    assert not marker(_private_home).exists(), "the append worked after the rotation"


# -- ordering and budget on the Bash path, as before ------------------------------------------------------------


def test_a_held_log_lock_costs_the_bash_deny_no_time_and_the_wait_ends_inside_the_budget(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mod, "GUARD_TIMEOUT_SECONDS", 3)
    monkeypatch.setattr(mod, "APPEND_LOCK_TIMEOUT", 5.0)
    set_mode(_private_home, "block")
    folder = state_folder(_private_home)
    folder.mkdir(parents=True, exist_ok=True)
    stamps: list[float] = []

    class Stamped(Stream):
        def flush(self) -> None:
            if self.buffered and not stamps:
                stamps.append(time.monotonic())

    out = Stamped()
    started = time.monotonic()
    with file_lock(folder / "log.jsonl.lock"):
        mod.run_guard(context(_private_home, bash("sleep 60"), out), namespace(agents))
    ended = time.monotonic()
    assert denied(lines(out.buffered)[0])
    assert stamps[0] - started < 0.5, "the deny is out before any lock wait"
    assert ended - started < 3, "and the bounded wait still ends before the hook's timeout"
    assert marker(_private_home).exists()


def test_a_computed_deny_is_printed_when_the_append_hangs(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_mode(_private_home, "block")
    release, reached = threading.Event(), threading.Event()

    def append(*a: Any, **k: Any) -> None:
        reached.set()
        release.wait(10)

    monkeypatch.setattr(mod, "append_log", append)
    pipe = Pipe()
    worker = threading.Thread(
        target=mod.run_guard, args=(context(_private_home, bash("sleep 60"), pipe.out), namespace(agents)), daemon=True
    )
    worker.start()
    try:
        assert reached.wait(5)
        assert denied(lines(pipe.read())[0]), "the deny is already in the pipe while the append is still blocked"
    finally:
        release.set()
        worker.join(10)
        pipe.close()
    assert not worker.is_alive()


def test_event_input_stops_at_the_shared_clock_not_at_its_own_five_seconds() -> None:
    read_end, write_end = os.pipe()
    stream = os.fdopen(read_end, "r")
    try:
        ctx = LocalContext(io.StringIO(), {}, NOW, stdin=stream)
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            mod.event_input(ctx, until=started + 0.2)
        assert time.monotonic() - started < 1.5
    finally:
        stream.close()
        os.close(write_end)


def test_the_append_wait_is_the_setting_or_what_is_left_and_nothing_past_the_hard_limit(
    _private_home: Path, agents: Path, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    waits: list[float] = []
    monkeypatch.setattr(mod, "append_log", lambda p, r, limit=0, lock_timeout=0.0: waits.append(lock_timeout))
    folder = state_folder(_private_home)
    folder.mkdir(parents=True, exist_ok=True)
    record = log_record("2026-01-01T00:00:00", "allow", "warn", None, False, "healthy", "")
    ctx = context(_private_home, "", io.StringIO())
    for hard in (clock.now + 100, clock.now + 0.4, clock.now - 0.01, clock.now + 0.01):
        mod.emit_then_persist(ctx, mod.Run(hard=hard), None, folder, record)
    assert waits == [APPEND_LOCK_TIMEOUT, pytest.approx(0.4)], "past hard or under the floor: no attempt, no stretch"
    assert marker(_private_home).exists()


# -- I1 / I2: the marker cannot be blocked, hidden or faked by what sits at its name ------------------------


def plant(kind: str, home: Path, tmp_path: Path) -> Path:
    folder = state_folder(home)
    folder.mkdir(parents=True, exist_ok=True)
    where = folder / mod.LOG_FAILED_NAME
    if kind == "directory":
        where.mkdir()
    elif kind == "fifo":
        os.mkfifo(where)
    elif kind == "symlink":
        where.symlink_to(tmp_path / "elsewhere")
    elif kind == "loose":
        where.write_text("x")
        where.chmod(0o666)
    return where


@pytest.mark.parametrize("kind", ["directory", "fifo", "symlink", "loose"])
def test_junk_at_the_marker_name_is_replaced_by_a_regular_marker_without_blocking(
    _private_home: Path, tmp_path: Path, kind: str
) -> None:
    where = plant(kind, _private_home, tmp_path)
    result: list[bool] = []
    worker = threading.Thread(
        target=lambda: result.append(mod.write_log_failed(state_folder(_private_home))), daemon=True
    )
    worker.start()
    worker.join(5)
    assert not worker.is_alive(), "a FIFO with no reader must not block the open"
    assert result == [True]
    info = os.lstat(where)
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022
    assert not (tmp_path / "elsewhere").exists(), "a link is never followed"


@pytest.mark.parametrize("kind", ["directory", "fifo", "symlink", "loose"])
def test_junk_found_at_dispatch_is_removed_and_reported_as_unusable_once(
    _private_home: Path, agents: Path, tmp_path: Path, kind: str
) -> None:
    set_probe(_private_home, reachable=True, agents=agents)
    where = plant(kind, _private_home, tmp_path)
    out = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), out), namespace(agents))
    [row] = lines(out.buffered)
    assert mod.LOG_MARKER_UNUSABLE in row["hookSpecificOutput"]["additionalContext"]
    assert not os.path.lexists(where)
    again = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), again), namespace(agents))
    assert mod.LOG_MARKER_UNUSABLE not in again.buffered


def test_a_quiet_bash_call_leaves_an_existing_marker_untouched(_private_home: Path, agents: Path) -> None:
    folder = state_folder(_private_home)
    folder.mkdir(parents=True, exist_ok=True)
    mod.write_log_failed(folder)
    out = Stream()
    assert mod.run_guard(context(_private_home, bash("ls -la"), out), namespace(agents)) == 0
    assert out.writes == [] and marker(_private_home).exists()


def test_the_marker_is_found_by_directory_descriptor_so_a_swapped_folder_name_is_not_followed(
    _private_home: Path, tmp_path: Path
) -> None:
    folder = state_folder(_private_home)
    folder.mkdir(parents=True, exist_ok=True)
    dfd = mod.marker_dir(folder)
    try:
        moved = tmp_path / "moved"
        folder.rename(moved)
        folder.mkdir()  # the pathname now names a different directory
        fd = os.open(mod.LOG_FAILED_NAME, os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=dfd)
        os.close(fd)
        assert (moved / mod.LOG_FAILED_NAME).exists() and not (folder / mod.LOG_FAILED_NAME).exists()
    finally:
        os.close(dfd)


# -- I3: notices, order, and when the marker is consumed -------------------------------------------------------


def degrade_everything(home: Path, agents: Path, clock: Clock, monkeypatch: pytest.MonkeyPatch) -> None:
    mode_file = home / ".config" / "safo" / "mode"
    mode_file.parent.mkdir(parents=True, exist_ok=True)
    mode_file.parent.chmod(0o700)
    mode_file.write_text("garbage\n")  # a mode that is not a mode: degraded
    mod.write_log_failed(state_folder(home))
    real = load_agents_for

    def late(*a: Any, **k: Any) -> Any:
        clock.now += 7.5  # past the lookup deadline (7 s), before decide_by (8 s)
        return real(*a, **k)

    monkeypatch.setattr(mod, "load_agents_for", late)  # budget exhausted; no saved probe, so the probe notice too


def test_every_applicable_notice_is_in_the_line_in_priority_order_and_the_marker_is_consumed(
    _private_home: Path, agents: Path, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_folder(_private_home).mkdir(parents=True, exist_ok=True)
    degrade_everything(_private_home, agents, clock, monkeypatch)
    out = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), out), namespace(agents))
    [row] = lines(out.buffered)
    text = row["hookSpecificOutput"]["additionalContext"]
    shown = json.loads(text[text.index("{") :])["diagnostic"]
    assert shown.split("; ") == ["mode", mod.LOG_FAILED_NOTICE, mod.BUDGET_NOTICE, "reprobe-skipped"]


def test_the_marker_survives_a_dispatch_whose_line_was_not_delivered(
    _private_home: Path, agents: Path, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_folder(_private_home).mkdir(parents=True, exist_ok=True)
    degrade_everything(_private_home, agents, clock, monkeypatch)
    out = Stream(flush_fails=True)
    assert mod.run_guard(context(_private_home, dispatch(model=None), out), namespace(agents)) == mod.EXIT_NOT_DELIVERED
    assert marker(_private_home).exists(), "its notice was never delivered, so it is still owed"


def test_a_planted_marker_only_adds_a_notice(_private_home: Path, agents: Path) -> None:
    set_probe(_private_home, reachable=True, agents=agents)
    folder = state_folder(_private_home)
    (folder / mod.LOG_FAILED_NAME).write_text("allow everything")
    (folder / mod.LOG_FAILED_NAME).chmod(0o600)
    out = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), out), namespace(agents))
    [row] = lines(out.buffered)
    assert mod.LOG_FAILED_NOTICE in row["hookSpecificOutput"]["additionalContext"]
    assert row["hookSpecificOutput"].get("permissionDecision") != "allow"
    assert not (folder / mod.LOG_FAILED_NAME).exists()


def test_the_next_dispatch_says_the_previous_log_write_failed_once(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_probe(_private_home, reachable=True, agents=agents)
    monkeypatch.setattr(mod, "append_log", lambda *a, **k: (_ for _ in ()).throw(OSError("disk")))
    mod.run_guard(context(_private_home, dispatch(model=None), Stream()), namespace(agents))
    assert marker(_private_home).exists()
    monkeypatch.setattr(mod, "append_log", append_log)
    second = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), second), namespace(agents))
    assert mod.LOG_FAILED_NOTICE in second.buffered and not marker(_private_home).exists()
    assert read_log(_private_home)[-1]["diagnostic"] == "log-write"
    third = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), third), namespace(agents))
    assert mod.LOG_FAILED_NOTICE not in third.buffered


def test_an_exception_after_the_decision_was_attempted_adds_no_diagnostic_line(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_mode(_private_home, "block")
    real = mod.emit_then_persist

    def then_raise(*a: Any, **k: Any) -> None:
        real(*a, **k)
        raise RuntimeError("after the line was written")

    monkeypatch.setattr(mod, "emit_then_persist", then_raise)
    out = Stream()
    assert mod.run_guard(context(_private_home, bash("sleep 60"), out), namespace(agents)) == 0
    assert len(out.writes) == 1 and denied(lines(out.buffered)[0]), "the decision, and nothing after it"


def test_notice_io_that_does_not_finish_is_skipped_and_leaves_the_marker_and_flag_untouched(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_mode(_private_home, "block")
    folder = state_folder(_private_home)
    folder.mkdir(parents=True, exist_ok=True)
    mod.write_log_failed(folder)
    before = os.lstat(folder / mod.LOG_FAILED_NAME)
    monkeypatch.setattr(mod, "NOTICE_IO_CAP_SECONDS", 0.3)
    monkeypatch.setattr(mod, "log_failure_pending", lambda f: time.sleep(5))
    out = Stream()
    started = time.monotonic()
    assert mod.run_guard(context(_private_home, dispatch(model=None), out), namespace(agents)) == 0
    assert time.monotonic() - started < 3
    [row] = lines(out.buffered)
    assert denied(row) and mod.NOTICES_SKIPPED in row["hookSpecificOutput"]["additionalContext"]
    after = os.lstat(folder / mod.LOG_FAILED_NAME)
    assert (before.st_ino, before.st_mtime_ns) == (after.st_ino, after.st_mtime_ns), "left untouched"


# -- the marker's clear is identity-checked ------------------------------------------------------------------


def test_a_failure_written_between_the_read_and_the_clear_survives_and_is_reported_next(
    _private_home: Path, agents: Path
) -> None:
    set_probe(_private_home, reachable=True, agents=agents)
    folder = state_folder(_private_home)
    mod.write_log_failed(folder)

    class Racy(Stream):
        raced = False

        def flush(self) -> None:
            if not self.raced:
                self.raced = True
                mod.write_log_failed(folder)  # run B's failure lands after run A read the marker, before A clears

    first = Racy()
    mod.run_guard(context(_private_home, dispatch(model=None), first), namespace(agents))
    assert mod.LOG_FAILED_NOTICE in first.buffered
    assert marker(_private_home).exists(), "the newer failure was not erased by the older run's clear"
    second = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), second), namespace(agents))
    assert mod.LOG_FAILED_NOTICE in second.buffered and not marker(_private_home).exists()


def test_every_new_failure_gives_the_marker_a_new_identity(_private_home: Path) -> None:
    folder = state_folder(_private_home)
    folder.mkdir(parents=True, exist_ok=True)
    mod.write_log_failed(folder)
    one = os.lstat(folder / mod.LOG_FAILED_NAME)
    mod.write_log_failed(folder)
    two = os.lstat(folder / mod.LOG_FAILED_NAME)
    assert (one.st_ino, one.st_mtime_ns, one.st_size) != (two.st_ino, two.st_mtime_ns, two.st_size)


# -- the corrupt-log archive policy ----------------------------------------------------------------------------


def corrupt_files(folder: Path) -> list[Path]:
    return sorted(folder.glob("log.jsonl.corrupt-*"))


def record() -> dict[str, Any]:
    return log_record("2026-01-01T00:00:00", "allow", "warn", None, False, "healthy", "")


@pytest.mark.parametrize("bad", [b"\xff\npartial", b"\xff\n"], ids=["bad-tail", "fully-terminated"])
def test_a_corrupt_log_is_kept_under_a_new_name_and_the_existing_archive_is_never_touched(
    tmp_path: Path, bad: bytes
) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / "log.jsonl"
    path.write_bytes(bad)
    path.chmod(0o600)
    archive = tmp_path / "log.jsonl.1"
    archive.write_bytes(b'{"older":"history"}\n')
    append_log(path, record())
    assert archive.read_bytes() == b'{"older":"history"}\n', "the only archive is preserved byte for byte"
    [kept] = corrupt_files(tmp_path)
    assert kept.read_bytes() == bad and stat.S_IMODE(kept.stat().st_mode) == 0o600
    assert json.loads(path.read_text())["decision"] == "allow", "a fresh log was started"


def test_at_most_five_corrupt_files_are_kept_and_the_oldest_go_first(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    for day in range(1, 8):
        old = tmp_path / f"log.jsonl.corrupt-2025010{day}T000000-1"
        old.write_bytes(b"x")
        old.chmod(0o600)
    path = tmp_path / "log.jsonl"
    path.write_bytes(b"\xff\n")
    path.chmod(0o600)
    append_log(path, record())
    names = [f.name for f in corrupt_files(tmp_path)]
    assert len(names) == 5
    assert "log.jsonl.corrupt-20250101T000000-1" not in names and "log.jsonl.corrupt-20250102T000000-1" not in names
    assert "log.jsonl.corrupt-20250107T000000-1" in names


# -- junk removal is identity-checked, on both branches ---------------------------------------------------------


def test_junk_replaced_by_a_valid_marker_after_it_was_observed_is_not_removed(
    _private_home: Path, agents: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_probe(_private_home, reachable=True, agents=agents)
    folder = state_folder(_private_home)
    plant("symlink", _private_home, tmp_path)
    real = mod.remove_junk
    results: list[bool] = []

    def seam(dfd: int, seen: Any) -> bool:
        mod.write_log_failed(folder)  # another run's failure lands between the observation and the removal
        results.append(real(dfd, seen))
        return results[-1]

    monkeypatch.setattr(mod, "remove_junk", seam)
    first = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), first), namespace(agents))
    assert mod.LOG_MARKER_UNUSABLE in first.buffered
    assert results == [False], "a different thing sat there by then: nothing was removed"
    assert stat.S_ISREG(os.lstat(marker(_private_home)).st_mode), "the newer failure's marker survived"
    monkeypatch.setattr(mod, "remove_junk", real)
    second = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), second), namespace(agents))
    assert mod.LOG_FAILED_NOTICE in second.buffered and not marker(_private_home).exists()


def test_a_newer_marker_that_replaced_the_blocker_is_never_overwritten_by_the_retry(
    _private_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = state_folder(_private_home)
    where = plant("directory", _private_home, tmp_path)
    real = mod.remove_junk
    results: list[bool] = []
    newer: list[os.stat_result] = []

    def seam(dfd: int, seen: Any) -> bool:
        where.rmdir()  # the blocker is replaced by a newer run's valid marker before it is removed
        where.write_text("newer failure\n")
        where.chmod(0o600)
        newer.append(os.lstat(where))
        results.append(real(dfd, seen))
        return results[-1]

    monkeypatch.setattr(mod, "remove_junk", seam)
    assert mod.write_log_failed(folder) is True, "a failure marker exists, so the failure is recorded"
    assert results == [False]
    now = os.lstat(where)
    assert (now.st_ino, now.st_mtime_ns) == (newer[0].st_ino, newer[0].st_mtime_ns)
    assert where.read_text() == "newer failure\n", "the newer marker survived: nothing was renamed over it"
    assert not [f for f in folder.iterdir() if f.name.startswith(".log-failed.")], "this run's temp file is dropped"


# -- the probe notice is claimed after delivery, by the calling thread only --------------------------------------


def fd_count() -> int:
    """Open descriptors among 0..255, counted with fstat: portable, no /proc."""
    count = 0
    for number in range(256):
        try:
            os.fstat(number)
        except OSError:
            continue
        count += 1
    return count


def unhealthy(home: Path, agents: Path) -> Path:
    state_folder(home).mkdir(parents=True, exist_ok=True)
    block_reprobe(home, agents, age=1.0)  # an attempt a second ago: no re-probe, health stays unknown
    return notice_path(probe_file(home, agents))


class Gated:
    """The REAL notice check, held at a gate; `done` is set when it has finished, so a test waits for THAT worker."""

    def __init__(self) -> None:
        self.gate = threading.Event()
        self.done = threading.Event()

    def check(self, path: Path) -> bool:
        self.gate.wait(10)
        try:
            return core.notice_unclaimed(path)
        finally:
            self.done.set()


def run_with_held_check(home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Gated, Path, str]:
    flag = unhealthy(home, agents)
    held = Gated()
    monkeypatch.setattr(mod, "NOTICE_IO_CAP_SECONDS", 0.3)
    monkeypatch.setattr(mod, "notice_unclaimed", held.check)
    out = Stream()
    mod.run_guard(context(home, dispatch(model=None), out), namespace(agents))
    return held, flag, out.buffered


def test_a_notice_check_left_running_that_finishes_late_creates_nothing(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    held, flag, line = run_with_held_check(_private_home, agents, monkeypatch)
    assert mod.NOTICES_SKIPPED in line and not flag.exists()
    held.gate.set()  # the real check resumes late, in a thread that was left running
    assert held.done.wait(10)
    assert not flag.exists(), "a worker that finishes late creates nothing"


def test_a_notice_check_left_running_that_finishes_late_leaves_no_descriptor_open(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    unhealthy(_private_home, agents)
    before = fd_count()
    held, _, _ = run_with_held_check(_private_home, agents, monkeypatch)
    held.gate.set()
    assert held.done.wait(10)
    deadline = time.monotonic() + 5  # the worker returns its value right after `done`: poll, do not guess
    while fd_count() != before and time.monotonic() < deadline:
        time.sleep(0.01)
    assert fd_count() == before


def test_the_probe_notice_is_claimed_only_after_a_delivered_line(_private_home: Path, agents: Path) -> None:
    flag = unhealthy(_private_home, agents)
    lost = Stream(flush_fails=True)
    mod.run_guard(context(_private_home, dispatch(model=None), lost), namespace(agents))
    assert not flag.exists(), "an undelivered line leaves the notice unclaimed"
    shown = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), shown), namespace(agents))
    assert WARNING in shown.buffered and flag.exists()
    quiet = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), quiet), namespace(agents))
    assert WARNING not in quiet.buffered, "claimed: the notice is once per session"


def test_a_skipped_check_leaves_the_flag_so_the_next_dispatch_shows_the_specific_notice(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with monkeypatch.context() as patch:
        held, flag, line = run_with_held_check(_private_home, agents, patch)
    assert mod.NOTICES_SKIPPED in line and not flag.exists()
    held.gate.set()
    assert held.done.wait(10)
    nxt = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), nxt), namespace(agents))
    assert mod.NOTICES_SKIPPED not in nxt.buffered and WARNING in nxt.buffered and flag.exists()


# -- two real processes appending to one corrupt log ---------------------------------------------------------


def test_two_processes_appending_to_one_corrupt_log_quarantine_it_once_and_lose_no_record(tmp_path: Path) -> None:
    """A real barrier: each child announces itself in a shared directory and then waits for the OTHER's announcement, so
    neither starts appending until both are running and they contend for the log lock on the corrupt log."""
    tmp_path.chmod(0o700)
    log = tmp_path / "log.jsonl"
    log.write_bytes(b"\xff\n")
    log.chmod(0o600)
    barrier = tmp_path / "barrier"
    barrier.mkdir()
    actions = [
        (os.POSIX_SPAWN_OPEN, 1, os.devnull, os.O_WRONLY, 0),
        (os.POSIX_SPAWN_OPEN, 2, os.devnull, os.O_WRONLY, 0),
    ]
    child = Path(__file__).parent / "append_child.py"
    pids = [
        os.posix_spawn(
            sys.executable,
            [sys.executable, str(child), str(log), "5", str(barrier), me, other],
            os.environ,
            file_actions=actions,
        )
        for me, other in (("a", "b"), ("b", "a"))
    ]
    codes = [wait_exit(pid, 30) for pid in pids]
    assert codes == [0, 0]
    assert sorted(f.name for f in barrier.iterdir()) == ["a", "b"], "both reached the barrier"
    assert len(corrupt_files(tmp_path)) == 1, "the corrupt log is moved once, under the lock"
    assert len(log.read_text().splitlines()) == 10, "every record of both processes is in the fresh log"


# -- the touch is after delivery -----------------------------------------------------------------------------------


@pytest.mark.parametrize("payload", ["agent", "bash"])
def test_the_bound_repository_refresh_is_made_after_delivery_not_before(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch, payload: str
) -> None:
    set_probe(_private_home, reachable=True, agents=agents)
    repo_file = probe_file(_private_home, agents)
    repo_file = repo_file.with_name(repo_file.name + ".repo")
    repo_file.write_text('{"repo": "acme/widgets"}')
    repo_file.chmod(0o600)
    set_mode(_private_home, "block")
    events: list[tuple[str, int]] = []

    class Ordered(Stream):
        def flush(self) -> None:
            events.append(("stdout", threading.get_ident()))

    monkeypatch.setattr(core, "touch", lambda path: events.append(("touch", threading.get_ident())))
    body = dispatch(model=None) if payload == "agent" else bash("sleep 60")
    mod.run_guard(context(_private_home, body, Ordered()), namespace(agents))
    assert [name for name, _ in events] == ["stdout", "touch"], "the refresh comes after the line, not before it"


# -- the mode file read is bounded and fails closed ------------------------------------------------------------


@pytest.mark.parametrize("payload", ["agent", "bash"])
def test_a_wedged_mode_file_read_fails_closed_and_cannot_hold_back_the_verdict(
    _private_home: Path, agents: Path, tmp_path: Path, payload: str
) -> None:
    """No mode file, so the default is warn and the same brief would only be warned about; the read wedges, so the
    verdict is computed in block mode (fail closed on a slow mode file) and the brief is denied."""
    body = tmp_path / "payload.json"
    body.write_text(dispatch(model=None) if payload == "agent" else bash("sleep 60"))
    started = time.monotonic()
    pid, fd = spawn("pre-mode", _private_home, agents, tmp_path / "x", body)
    try:
        raw = read_until(fd, 15)
        status = wait_exit(pid, 4)
    finally:
        os.close(fd)
        with contextlib.suppress(ProcessLookupError, ChildProcessError):
            os.kill(pid, 9)
            os.waitpid(pid, 0)
    [row] = lines(raw.decode())
    assert denied(row) and mod.MODE_SLOW_NOTICE in row["hookSpecificOutput"]["additionalContext"]
    assert status == 0
    assert Arrival.at - started < PRE_BUDGET - 2.0, "before decide_by (the real timeout less 2 s), start-up included"


# -- remove_junk reports what really happened; side objects are capped ------------------------------------------


def test_a_non_empty_directory_is_not_reported_removed_and_the_side_objects_stay_capped(
    _private_home: Path, tmp_path: Path
) -> None:
    folder = state_folder(_private_home)
    where = plant("directory", _private_home, tmp_path)
    dfd = mod.marker_dir(folder)
    try:
        for _ in range(20):
            if not where.exists():
                where.mkdir()
            (where / "keep").write_text("x")  # not empty: rmdir cannot remove it
            assert mod.remove_junk(dfd, mod.marker_ident(os.lstat(where))) is False
    finally:
        os.close(dfd)
    sides = [f for f in folder.iterdir() if ".junk." in f.name]
    assert 0 < len(sides) <= mod.MAX_SIDE_OBJECTS, f"{len(sides)} side objects after 20 attempts"
    assert where.is_dir(), "once the cap is reached nothing more is moved aside"


# -- a full or unread stderr cannot matter: the guard writes nothing to it ----------------------------------


@pytest.mark.parametrize("payload", ["agent", "bash"])
def test_a_full_unread_stderr_pipe_cannot_hold_back_a_deny_or_keep_the_process_open(
    _private_home: Path, agents: Path, tmp_path: Path, payload: str
) -> None:
    """Standard error is a pipe that is already full and never read: a blocking write would hang the process."""
    plant("symlink", _private_home, tmp_path)  # a junk marker: once there was a stderr line to write for it
    body = tmp_path / "payload.json"
    body.write_text(dispatch(model=None) if payload == "agent" else bash("sleep 60"))
    set_mode(_private_home, "block")
    jam_read, jam_write = os.pipe()
    os.set_blocking(jam_write, False)
    with contextlib.suppress(BlockingIOError):
        while True:
            os.write(jam_write, b"x" * 65536)
    os.set_blocking(jam_write, True)  # the child's writes would now BLOCK
    started = time.monotonic()
    pid, fd = spawn("plain", _private_home, agents, tmp_path / "x", body, stderr_fd=jam_write)
    try:
        raw = read_until(fd, 15)
        status = wait_exit(pid, 6)
    finally:
        os.close(fd)
        os.close(jam_write)
        os.close(jam_read)
        with contextlib.suppress(ProcessLookupError, ChildProcessError):
            os.kill(pid, 9)
            os.waitpid(pid, 0)
    [row] = lines(raw.decode())
    assert denied(row) and mod.LOG_MARKER_UNUSABLE in row["hookSpecificOutput"]["additionalContext"]
    assert status == 0, "the process ended by itself: it does not write to stderr at all"
    assert Arrival.at - started < CHILD_BUDGET, "before the scaled host timeout, start-up included"


@pytest.mark.parametrize("payload", ["agent", "bash"])
def test_an_unexpected_exception_between_computing_a_deny_and_emitting_it_exits_two(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch, payload: str
) -> None:
    set_mode(_private_home, "block")

    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("after the verdict, before the emit")

    monkeypatch.setattr(mod, "read_notices", boom)
    out = Stream()
    body = dispatch(model=None) if payload == "agent" else bash("sleep 60")
    assert mod.run_guard(context(_private_home, body, out), namespace(agents)) == mod.EXIT_BLOCK
    assert out.writes == [], "nothing was delivered, so the host must block on the exit code"


def test_an_unexpected_exception_before_a_non_deny_decision_is_still_a_visible_diagnostic(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mod, "read_notices", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    out = Stream()  # warn mode: the computed decision is not a denial
    assert mod.run_guard(context(_private_home, dispatch(model=None), out), namespace(agents)) == 0
    assert WARNING in lines(out.buffered)[0]["systemMessage"]


# -- remove_junk looks once and removes what it moved, not whatever sits there now ------------------------------


class Seam:
    """A stand-in for the `os` module inside safo.modes.hooks. It can run a hook after the n-th call of a function
    (`after`) and make a function fail with an errno (`refuse`); every call is recorded."""

    def __init__(self, after: dict[tuple[str, int], Any] | None = None, refuse: dict[str, int] | None = None) -> None:
        self.after = after or {}
        self.refuse = refuse or {}
        self.calls: list[str] = []

    def __getattr__(self, name: str) -> Any:
        real = getattr(os, name)
        if name not in ("lstat", "rename", "unlink", "rmdir", "link"):
            return real

        def call(*args: Any, **kwargs: Any) -> Any:
            self.calls.append(name)
            if name in self.refuse:
                raise OSError(self.refuse[name], os.strerror(self.refuse[name]))
            try:
                return real(*args, **kwargs)
            finally:  # the hook runs after the call, whether it returned or raised (a look at a missing name raises)
                hook = self.after.pop((name, self.calls.count(name)), None)
                if hook is not None:
                    hook()

        return call


def swap_for(where: Path, kind: str) -> None:
    if where.is_symlink() or where.is_file():
        where.unlink()
    elif where.is_dir():
        where.rmdir()
    if kind == "marker":
        where.write_text("newer failure\n")
        where.chmod(0o600)
    else:
        where.mkdir()


@pytest.mark.parametrize("junk", ["symlink", "directory"])
def test_a_replacement_installed_after_the_look_survives_the_removal(
    _private_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, junk: str
) -> None:
    where = plant(junk, _private_home, tmp_path)
    dfd = mod.marker_dir(state_folder(_private_home))
    seen = mod.marker_ident(os.lstat(where))
    survivor: list[os.stat_result] = []

    def swap() -> None:
        swap_for(where, "marker")
        survivor.append(os.lstat(where))

    seam = Seam({("lstat", 1): swap})  # right after remove_junk's one look
    monkeypatch.setattr(mod, "os", seam)
    try:
        assert mod.remove_junk(dfd, seen) is False
    finally:
        os.close(dfd)
    now = os.lstat(where)
    assert (now.st_ino, now.st_mtime_ns) == (survivor[0].st_ino, survivor[0].st_mtime_ns)
    assert where.read_text() == "newer failure\n"
    assert not [f for f in where.parent.iterdir() if ".junk." in f.name], "nothing left under a side name"
    assert seam.calls.count("lstat") == 2, "one look, then one check of the moved object: no third"


def test_a_directory_swapped_in_for_a_link_is_never_deleted(
    _private_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    where = plant("symlink", _private_home, tmp_path)
    dfd = mod.marker_dir(state_folder(_private_home))
    seen = mod.marker_ident(os.lstat(where))
    seam = Seam({("lstat", 1): lambda: swap_for(where, "directory")})
    monkeypatch.setattr(mod, "os", seam)
    try:
        assert mod.remove_junk(dfd, seen) is False
    finally:
        os.close(dfd)
    survivors = [f for f in where.parent.iterdir() if f.is_dir() and f.name.startswith(".log-failed")]
    assert where.is_dir() or survivors, "the swapped-in directory still exists, at its name or under a side name"
    assert "rmdir" not in seam.calls and "unlink" not in seam.calls


def test_removal_of_the_observed_junk_works_when_nothing_changed(_private_home: Path, tmp_path: Path) -> None:
    where = plant("directory", _private_home, tmp_path)
    dfd = mod.marker_dir(state_folder(_private_home))
    try:
        assert mod.remove_junk(dfd, mod.marker_ident(os.lstat(where))) is True
    finally:
        os.close(dfd)
    assert not os.path.lexists(where)
    assert not [f for f in where.parent.iterdir() if ".junk." in f.name]


# -- the decision does not wait on state writes; they only set health --------------------------------------------


@pytest.mark.parametrize(
    ("what", "payload"),
    [("read-state", "agent"), ("claim", "agent"), ("save-state", "agent"), ("touch", "agent"), ("touch", "bash")],
)
def test_a_wedged_state_write_cannot_hold_back_a_computed_deny_in_a_real_process(
    _private_home: Path, agents: Path, tmp_path: Path, what: str, payload: str
) -> None:
    folder = state_folder(_private_home)
    folder.mkdir(parents=True, exist_ok=True)
    repo_file = probe_file(_private_home, agents).with_name(probe_file(_private_home, agents).name + ".repo")
    repo_file.write_text('{"repo": "acme/widgets"}')
    repo_file.chmod(0o600)
    body = tmp_path / "payload.json"
    body.write_text(dispatch(model=None) if payload == "agent" else bash("sleep 60"))
    set_mode(_private_home, "block")
    started = time.monotonic()
    pid, fd = spawn(f"pre-{what}", _private_home, agents, tmp_path / "x", body)
    try:
        raw = read_until(fd, 15)
        status = wait_exit(pid, PRE_BUDGET + 2)  # a wedged utime after the line is left behind at the hard limit
    finally:
        os.close(fd)
        with contextlib.suppress(ProcessLookupError, ChildProcessError):
            os.kill(pid, 9)
            os.waitpid(pid, 0)
    elapsed = Arrival.at - started
    [row] = lines(raw.decode())
    assert denied(row), "the verdict does not depend on the state work"
    if what != "touch":  # a wedged utime is after the line now: no slow notice, and the process still ends by itself
        assert mod.STATE_SLOW_NOTICE in row["hookSpecificOutput"]["additionalContext"]
    assert status == 0
    assert elapsed < PRE_BUDGET - 2.0, f"{elapsed:.1f} s: before decide_by (8 s), start-up included"


# -- the once-per-session probe notice does not come back with every unrelated notice -------------------------


def test_a_claimed_probe_notice_is_not_repeated_because_another_notice_exists(
    _private_home: Path, agents: Path
) -> None:
    flag = unhealthy(_private_home, agents)
    mode_file = _private_home / ".config" / "safo" / "mode"
    mode_file.parent.mkdir(parents=True, exist_ok=True)
    mode_file.parent.chmod(0o700)
    mode_file.write_text("garbage\n")  # a persistent, unrelated notice: the mode is degraded on every dispatch
    first = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), first), namespace(agents))
    assert flag.exists(), "the probe notice was claimed with the first line"
    second = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), second), namespace(agents))
    [row] = lines(second.buffered)
    text = row["hookSpecificOutput"]["additionalContext"]
    assert json.loads(text[text.index("{") :])["diagnostic"] == "mode", "only the persistent notice; no probe notice"


# -- a process that dies between the emit and the claim or clear loses nothing ---------------------------------


def test_a_process_killed_between_the_emit_and_the_claim_shows_the_notice_again_next_time(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    flag = unhealthy(_private_home, agents)
    body = tmp_path / "payload.json"
    body.write_text(dispatch(model=None))
    pid, fd = spawn("die-at-claim", _private_home, agents, tmp_path / "x", body)
    raw = read_until(fd, 15)
    status = wait_exit(pid, 5)
    os.close(fd)
    assert status == -9 and lines(raw.decode()), "the line was delivered, then the process died before the claim"
    assert not flag.exists()
    nxt = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), nxt), namespace(agents))
    assert WARNING in nxt.buffered and flag.exists(), "the notice repeats: it was never lost"


def test_a_process_killed_between_the_emit_and_the_clear_leaves_the_marker_for_the_next_dispatch(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    set_probe(_private_home, reachable=True, agents=agents)
    mod.write_log_failed(state_folder(_private_home))
    body = tmp_path / "payload.json"
    body.write_text(dispatch(model=None))
    pid, fd = spawn("die-at-clear", _private_home, agents, tmp_path / "x", body)
    raw = read_until(fd, 15)
    status = wait_exit(pid, 5)
    os.close(fd)
    assert status == -9 and mod.LOG_FAILED_NOTICE in raw.decode()
    assert marker(_private_home).exists()
    nxt = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), nxt), namespace(agents))
    assert mod.LOG_FAILED_NOTICE in nxt.buffered and not marker(_private_home).exists()


# -- the emit checks how much was written ---------------------------------------------------------------------------


class Counted(io.StringIO):
    """A text stream whose write() returns a count of its own choosing: `stuck` takes one character and then nothing,
    `trickle` takes one character per call, `none` stores everything and returns None."""

    def __init__(self, how: str) -> None:
        super().__init__()
        self.how = how
        self.calls = 0
        self.stored = ""

    def write(self, text: str) -> Any:
        self.calls += 1
        if self.how == "none":
            self.stored += text
            return None  # deliberately breaks the contract: some streams do
        if self.how == "stuck" and self.calls > 1:
            return 0
        self.stored += text[:1]
        return 1


@pytest.mark.parametrize("how", ["stuck", "none"])
def test_a_short_or_unreported_write_is_an_undelivered_decision_and_blocks(
    _private_home: Path, agents: Path, how: str
) -> None:
    set_mode(_private_home, "block")
    out = Counted(how)
    assert mod.run_guard(context(_private_home, bash("sleep 60"), out), namespace(agents)) == mod.EXIT_BLOCK
    if how == "stuck":
        assert len(out.stored) == 1, "the host got a truncated line, so the exit code has to block"


def test_a_stream_that_takes_one_character_per_call_still_gets_the_whole_line(
    _private_home: Path, agents: Path
) -> None:
    set_mode(_private_home, "block")
    out = Counted("trickle")
    assert mod.run_guard(context(_private_home, bash("sleep 60"), out), namespace(agents)) == 0
    assert denied(json.loads(out.stored)) and out.stored.endswith("\n")


# -- stderr: the guard writes nothing to it ----------------------------------------------------------------------


def test_the_guard_writes_nothing_to_standard_error_whatever_fails(
    _private_home: Path, agents: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    writes: list[str] = []

    class Recording(io.StringIO):
        def write(self, text: str) -> int:
            writes.append(text)
            return super().write(text)

    monkeypatch.setattr(sys, "stderr", Recording())
    set_mode(_private_home, "block")
    plant("symlink", _private_home, tmp_path)  # junk marker
    mod.run_guard(context(_private_home, bash("sleep 60"), Stream()), namespace(agents))
    mod.run_guard(context(_private_home, bash("sleep 60"), Stream(flush_fails=True)), namespace(agents))
    monkeypatch.setattr(mod, "append_log", lambda *a, **k: (_ for _ in ()).throw(OSError("disk")))
    mod.run_guard(context(_private_home, dispatch(model=None), Stream()), namespace(agents))
    assert writes == []


# -- no hard link: nothing is ever renamed over a marker -----------------------------------------------------------


@pytest.mark.parametrize("code", [errno.EPERM, errno.EOPNOTSUPP, errno.EXDEV, errno.ENOSYS, errno.EEXIST])
def test_without_a_usable_hard_link_nothing_is_renamed_over_a_marker_that_appears(
    _private_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    folder = state_folder(_private_home)
    where = plant("directory", _private_home, tmp_path)

    def newer() -> None:
        where.write_text("newer failure\n")  # a newer marker lands right after the last look at the name
        where.chmod(0o600)

    # lstat calls: 1 the blocker, 2 and 3 inside remove_junk, 4 the check after the refused link
    seam = Seam({("lstat", 4): newer}, refuse={"link": code})
    monkeypatch.setattr(mod, "os", seam)
    mod.write_log_failed(folder)
    assert where.read_text() == "newer failure\n"
    assert seam.calls.count("rename") == 2, "the first install and remove_junk's move aside; no third rename"


# -- a replacement that was moved aside is kept when it cannot be put back ------------------------------------------


def test_a_replacement_moved_aside_is_not_deleted_when_the_name_is_taken_again(
    _private_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = state_folder(_private_home)
    where = plant("symlink", _private_home, tmp_path)
    dfd = mod.marker_dir(folder)
    seen = mod.marker_ident(os.lstat(where))

    def take_the_name_again() -> None:
        where.write_text("C\n")  # another run installs its marker while B sits under the side name
        where.chmod(0o600)

    seam = Seam({("lstat", 1): lambda: swap_for(where, "marker"), ("rename", 1): take_the_name_again})
    monkeypatch.setattr(mod, "os", seam)
    try:
        assert mod.remove_junk(dfd, seen) is False
    finally:
        os.close(dfd)
    assert where.read_text() == "C\n"
    kept = [f for f in folder.iterdir() if f.name.startswith(mod.SIDE_PREFIX)]
    assert [f.read_text() for f in kept] == ["newer failure\n"], "B was kept under its side name, not unlinked"


# -- pruning side objects: only old ones that we made, never one a live run is about to put back -----------------------


def side_name(tag: str = "abcdef012345") -> str:
    return f"{mod.SIDE_PREFIX}{os.getpid()}-{tag}"


def test_fresh_side_objects_are_never_pruned(_private_home: Path) -> None:
    folder = state_folder(_private_home)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / side_name("aaaaaaaaaaaa")).write_text("x")
    (folder / side_name("bbbbbbbbbbbb")).mkdir()
    dfd = mod.marker_dir(folder)
    try:
        mod.prune_side_objects(dfd)
    finally:
        os.close(dfd)
    assert len([f for f in folder.iterdir() if f.name.startswith(mod.SIDE_PREFIX)]) == 2, "younger than the age gate"


def test_old_side_objects_that_we_made_are_pruned_and_nothing_else(
    _private_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mod, "SIDE_PRUNE_AGE_SECONDS", -1.0)  # every object counts as old
    folder = state_folder(_private_home)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / side_name("aaaaaaaaaaaa")).write_text("x")  # ours: a regular file
    (folder / side_name("bbbbbbbbbbbb")).mkdir()  # ours: an empty directory
    (folder / f"{mod.SIDE_PREFIX}old0").write_text("x")  # the prefix, but not a name we make
    (folder / side_name("cccccccccccc")).symlink_to(tmp_path / "elsewhere")  # a link is never followed or removed
    os.mkfifo(folder / side_name("dddddddddddd"))  # a FIFO is not ours to remove
    full = folder / side_name("eeeeeeeeeeee")
    full.mkdir()
    (full / "keep").write_text("x")  # a directory with content stays
    dfd = mod.marker_dir(folder)
    try:
        mod.prune_side_objects(dfd)
    finally:
        os.close(dfd)
    left = sorted(f.name for f in folder.iterdir() if f.name.startswith(mod.SIDE_PREFIX))
    assert left == sorted([f"{mod.SIDE_PREFIX}old0", side_name("cccccccccccc"), side_name("dddddddddddd"), full.name])
    assert not (tmp_path / "elsewhere").exists()


def test_a_prune_by_another_run_cannot_delete_the_object_being_restored(
    _private_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = state_folder(_private_home)
    where = plant("symlink", _private_home, tmp_path)
    dfd = mod.marker_dir(folder)
    seen = mod.marker_ident(os.lstat(where))
    pruned: list[int] = []

    def other_run_prunes() -> None:
        mod.prune_side_objects(dfd)
        pruned.append(1)

    seam = Seam(
        {
            ("lstat", 1): lambda: swap_for(where, "marker"),
            ("rename", 1): other_run_prunes,  # the other run, in between
        }
    )
    monkeypatch.setattr(mod, "os", seam)
    try:
        assert mod.remove_junk(dfd, seen) is False
    finally:
        os.close(dfd)
    assert pruned == [1]
    assert where.read_text() == "newer failure\n", "the moved object was put back; the other run's prune left it alone"


def test_side_entries_that_are_links_or_fifos_count_toward_the_cap_and_are_never_followed(
    _private_home: Path, tmp_path: Path
) -> None:
    folder = state_folder(_private_home)
    where = plant("directory", _private_home, tmp_path)
    for n in range(4):
        (folder / side_name(f"{n:012x}")).symlink_to(tmp_path / "elsewhere")
        os.mkfifo(folder / side_name(f"{n + 4:012x}"))
    dfd = mod.marker_dir(folder)
    try:
        assert mod.remove_junk(dfd, mod.marker_ident(os.lstat(where))) is False
    finally:
        os.close(dfd)
    assert where.is_dir(), "at the cap nothing more is moved aside"
    assert not (tmp_path / "elsewhere").exists()


# -- the guard is a short-lived process: whatever overruns is cut off by the process ENDING ---------------------------


def spawn_seam(
    home: Path,
    agents: Path,
    body: Path,
    *,
    mode: str,
    barrier: Path,
    block: str = "",
    fail: str = "",
    nondaemon: bool = False,
    stdout_fd: int | None = None,
    stderr_fd: int | None = None,
    extra_env: dict[str, str] | None = None,
    new_group: bool = False,
) -> tuple[int, int]:
    """Start tests/guard_child.py with seams from its environment. Returns (pid, read end of its stdout), or (pid, -1)
    when `stdout_fd` is given (the test then owns the child's standard output). Standard error goes to /dev/null: the
    guard writes nothing to it."""
    read_end = write_end = -1
    actions: list[tuple[Any, ...]] = []
    if stderr_fd is None:
        actions.append((os.POSIX_SPAWN_OPEN, 2, os.devnull, os.O_WRONLY, 0))
    else:
        actions.append((os.POSIX_SPAWN_DUP2, stderr_fd, 2))
    if stdout_fd is None:
        read_end, write_end = os.pipe()
        actions += [(os.POSIX_SPAWN_DUP2, write_end, 1), (os.POSIX_SPAWN_CLOSE, read_end)]
    else:
        actions.append((os.POSIX_SPAWN_DUP2, stdout_fd, 1))
    env = {**os.environ, "SAFO_CHILD_BARRIER": str(barrier), "SAFO_CHILD_BLOCK": block, "SAFO_CHILD_FAIL": fail}
    env.update(extra_env or {})
    if nondaemon:
        env["SAFO_CHILD_NONDAEMON"] = "1"
    argv = [sys.executable, str(CHILD), mode, str(home), str(agents), str(barrier), str(body)]
    group = 0 if new_group else os.getpgrp()  # a process group of its own, so a watchdog can kill the whole tree
    pid = os.posix_spawn(sys.executable, argv, env, file_actions=actions, setpgroup=group)
    if write_end >= 0:
        os.close(write_end)
    return pid, read_end


def run_seam(
    home: Path, agents: Path, tmp_path: Path, payload: str, **options: Any
) -> tuple[list[dict[str, Any]], int, float, float]:
    """Run the child to its end. Returns (lines, exit status, seconds to the first line, seconds to the exit)."""
    body = tmp_path / "payload.json"
    body.write_text(payload)
    barrier = tmp_path / "barrier"
    started = time.monotonic()
    pid, fd = spawn_seam(home, agents, body, barrier=barrier, **options)
    try:
        raw = read_until(fd, 20)  # to end of file: the child's standard output closes when the process is gone
        exited = time.monotonic() - started
        status = wait_exit(pid, 5)
    finally:
        os.close(fd)
        with contextlib.suppress(ProcessLookupError, ChildProcessError):
            os.kill(pid, 9)
            os.waitpid(pid, 0)
    return lines(raw.decode()), status, Arrival.at - started, exited


def state_snapshot(folder: Path) -> dict[str, tuple[int, ...]]:
    """Every path under the state folder (and the folder itself) with mode, mtime_ns, size, inode and link count: a
    utime, a rewrite, a rename or a new file all change it."""
    snapshot: dict[str, tuple[int, ...]] = {}
    for path in [folder, *sorted(folder.rglob("*"))]:
        info = os.lstat(path)
        key = "." if path == folder else str(path.relative_to(folder))
        snapshot[key] = (info.st_mode, info.st_mtime_ns, info.st_size, info.st_ino, info.st_nlink)
    return snapshot


def release_and_compare(folder: Path, tmp_path: Path) -> None:
    """The process is gone. Let every blocked step go and give a would-be survivor a second: nothing may change."""
    before = state_snapshot(folder)
    (tmp_path / "barrier").write_text("go")
    time.sleep(1.0)
    assert state_snapshot(folder) == before, "something wrote to the state folder after the process ended"


POST_STEPS = {
    "refresh": ("mod.refresh_bound_repo", ""),
    "clear": ("mod.clear_log_failure", ""),
    "claim": ("mod.claim_notice", ""),
    "append": ("mod.append_log", ""),
    "marker-write": ("mod.write_log_failed", "mod.append_log"),
    "quarantine": ("core.quarantine_log", ""),
}


@pytest.mark.parametrize("step", list(POST_STEPS))
def test_a_blocked_post_delivery_step_ends_the_process_and_nothing_is_written_afterwards(
    _private_home: Path, agents: Path, tmp_path: Path, step: str
) -> None:
    """One real process per step: the step blocks until a barrier file appears. The line is already out; the process
    must end by itself at the deadline with the right exit code, and when the barrier is created afterwards nothing
    (no append, marker, claim, clear, utime, quarantine) may happen, because there is no process left to do it."""
    folder = state_folder(_private_home)
    folder.mkdir(parents=True, exist_ok=True)
    if step == "claim":
        unhealthy(_private_home, agents)  # an unclaimed probe notice: a claim is due after the line
    else:
        set_probe(_private_home, reachable=True, agents=agents)
    if step == "refresh":
        repo_file = probe_file(_private_home, agents)
        repo_file = repo_file.with_name(repo_file.name + ".repo")
        repo_file.write_text('{"repo": "acme/widgets"}')
        repo_file.chmod(0o600)
    if step == "clear":
        mod.write_log_failed(folder)
    if step == "quarantine":
        (folder / "log.jsonl").write_bytes(b"\xff\n")
        (folder / "log.jsonl").chmod(0o600)
    set_mode(_private_home, "block")
    block, fail = POST_STEPS[step]
    rows, status, arrived, exited = run_seam(
        _private_home, agents, tmp_path, dispatch(model=None), mode="seam", block=block, fail=fail
    )
    [row] = rows
    assert denied(row), "the decision was delivered before the blocked step"
    assert status == 0, "and the process ended by itself with the delivered decision's exit code"
    assert arrived < CHILD_BUDGET and exited < CHILD_BUDGET, f"line at {arrived:.1f} s, exit at {exited:.1f} s"
    release_and_compare(folder, tmp_path)


PRE_STEPS = {
    "ensure-dir": "guardlog.ensure_dir",
    "lock-open": "guardlog.os.open_lock",
    "attempt-write": "core.write_text",
    "save-state": "core.save_state",
}


@pytest.mark.parametrize("step", list(PRE_STEPS))
def test_a_blocked_pre_decision_step_does_not_delay_the_decision_and_nothing_is_written_afterwards(
    _private_home: Path, agents: Path, tmp_path: Path, step: str
) -> None:
    """The re-probe's directory setup, lock-file creation, attempt marker and state save each block in a real process.
    The decision still goes out on time (verdict from the configuration alone, with the slow-state notice), the process
    ends at once after it, and a late release changes nothing."""
    folder = state_folder(_private_home)
    folder.mkdir(parents=True, exist_ok=True)
    set_mode(_private_home, "block")
    rows, status, arrived, exited = run_seam(
        _private_home, agents, tmp_path, dispatch(model=None), mode="pre-seam", block=PRE_STEPS[step]
    )
    [row] = rows
    assert denied(row) and mod.STATE_SLOW_NOTICE in row["hookSpecificOutput"]["additionalContext"]
    assert status == 0
    assert arrived < PRE_BUDGET - 2.0, f"{arrived:.1f} s: before decide_by (8 s), start-up included"
    assert exited - arrived < 1.5, "an overrun makes the process end right after the line, with no post-delivery work"
    release_and_compare(folder, tmp_path)


def test_a_full_stdout_pipe_with_a_reader_that_never_drains_cannot_hold_back_the_exit(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    """The decision is written in a worker thread that the main thread waits for until the deadline. A reader that keeps
    the pipe open but never reads blocks that write for ever; the process must still end, with exit 2 for a denial
    that could not be delivered."""
    set_probe(_private_home, reachable=True, agents=agents)
    set_mode(_private_home, "block")
    body = tmp_path / "payload.json"
    body.write_text(dispatch(model=None))
    jam_read, jam_write = os.pipe()
    os.set_blocking(jam_write, False)
    with contextlib.suppress(BlockingIOError):
        while True:
            os.write(jam_write, b"x" * 65536)
    os.set_blocking(jam_write, True)  # the child's write would now BLOCK
    started = time.monotonic()
    pid, _ = spawn_seam(_private_home, agents, body, mode="seam", barrier=tmp_path / "barrier", stdout_fd=jam_write)
    os.close(jam_write)
    try:
        status = wait_exit(pid, CHILD_BUDGET + 3)
        elapsed = time.monotonic() - started
    finally:
        os.close(jam_read)
        with contextlib.suppress(ProcessLookupError, ChildProcessError):
            os.kill(pid, 9)
            os.waitpid(pid, 0)
    assert status == 2, "an undelivered denial exits 2, which the host reads as a block"
    assert elapsed < CHILD_BUDGET, f"{elapsed:.1f} s: exit 2 at the decision deadline, before the scaled host timeout"


def test_a_wedged_non_daemon_thread_cannot_keep_the_process_alive_after_the_decision(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    """A normal return would wait at interpreter exit for a non-daemon thread (a library's, say). The process ends
    through os._exit instead."""
    set_probe(_private_home, reachable=True, agents=agents)
    set_mode(_private_home, "block")
    rows, status, _arrived, exited = run_seam(
        _private_home, agents, tmp_path, dispatch(model=None), mode="seam", nondaemon=True
    )
    [row] = rows
    assert denied(row) and status == 0
    assert exited < CHILD_BUDGET, f"{exited:.1f} s"


# -- a host watchdog: the guard must have answered BEFORE the host kills it ------------------------------------------


def jam_pipe() -> tuple[int, int]:
    """A pipe that is already full, blocking again for its writer, with the reader held open and never read."""
    read_end, write_end = os.pipe()
    os.set_blocking(write_end, False)
    with contextlib.suppress(BlockingIOError):
        while True:
            os.write(write_end, b"x" * 65536)
    os.set_blocking(write_end, True)
    return read_end, write_end


class Watched:
    """What happened to a guard process that a host would kill at `host_timeout` seconds after it was started."""

    def __init__(self, status: int, killed: bool, elapsed: float, arrived: float, raw: bytes) -> None:
        self.status, self.killed, self.elapsed, self.arrived, self.raw = status, killed, elapsed, arrived, raw


def run_watched(
    home: Path,
    agents: Path,
    tmp_path: Path,
    payload: str,
    *,
    host_timeout: float = CHILD_BUDGET,
    jam_stdout: bool = False,
    jam_stderr: bool = False,
    **options: Any,
) -> Watched:
    """Run the guard in its own process group. A watchdog thread SIGKILLs the whole group at EXACTLY `host_timeout`
    seconds after the process was started, as the host would. The result says whether the guard got out in time."""
    body = tmp_path / "payload.json"
    body.write_text(payload)
    jam: list[int] = []
    stdout_fd = stderr_fd = None
    if jam_stdout:
        read_end, stdout_fd = jam_pipe()
        jam += [read_end]
    if jam_stderr:
        read_end, stderr_fd = jam_pipe()
        jam += [read_end]
    done, killed = threading.Event(), threading.Event()
    started = time.monotonic()
    pid, fd = spawn_seam(
        home,
        agents,
        body,
        barrier=tmp_path / "barrier",
        stdout_fd=stdout_fd,
        stderr_fd=stderr_fd,
        new_group=True,
        **options,
    )

    def watchdog() -> None:
        if not done.wait(max(0.0, host_timeout - (time.monotonic() - started))):
            killed.set()
            with contextlib.suppress(ProcessLookupError):
                os.killpg(pid, signal.SIGKILL)

    thread = threading.Thread(target=watchdog, daemon=True)
    thread.start()
    raw = b""
    try:
        if fd >= 0:
            raw = read_until(fd, host_timeout + 5)
        status = wait_exit(pid, host_timeout + 5)
        elapsed = time.monotonic() - started
    finally:
        done.set()
        thread.join(2)
        if fd >= 0:
            os.close(fd)
        for number in (
            *jam,
            *([stdout_fd] if stdout_fd is not None else []),
            *([stderr_fd] if stderr_fd is not None else []),
        ):
            with contextlib.suppress(OSError):
                os.close(number)
        with contextlib.suppress(ProcessLookupError, ChildProcessError):
            os.killpg(pid, signal.SIGKILL)
    return Watched(status, killed.is_set(), elapsed, Arrival.at - started, raw)


def test_a_full_stdout_pipe_is_answered_with_exit_two_before_the_host_kills_the_guard(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    set_probe(_private_home, reachable=True, agents=agents)
    set_mode(_private_home, "block")
    result = run_watched(_private_home, agents, tmp_path, dispatch(model=None), mode="seam", jam_stdout=True)
    assert not result.killed and result.status == 2, f"status {result.status}, killed {result.killed}"
    assert result.elapsed < CHILD_BUDGET


def test_an_invalid_lock_timeout_and_a_full_stderr_pipe_cannot_stop_the_guard_importing_or_deciding(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    """Importing the package used to print a warning for an invalid SAFO_APPEND_LOCK_TIMEOUT: into a full stderr pipe
    that blocked for ever, before any deadline existed."""
    set_probe(_private_home, reachable=True, agents=agents)
    set_mode(_private_home, "block")
    result = run_watched(
        _private_home,
        agents,
        tmp_path,
        dispatch(model=None),
        mode="seam",
        jam_stderr=True,
        extra_env={"SAFO_APPEND_LOCK_TIMEOUT": "not-a-number"},
    )
    assert not result.killed, "the host would have killed a guard that was stuck at import"
    [row] = lines(result.raw.decode())
    assert denied(row) and result.status == 0
    assert result.elapsed < CHILD_BUDGET


def test_a_slow_cold_start_and_a_full_stdout_pipe_still_get_exit_two_before_the_host_kills_the_guard(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    """The child sleeps before it imports safo, as a slow disk would. The budget is counted from the start of the
    PROCESS, so the decision deadline (8 s of the real 10) falls inside the host timeout; a clock that started after
    the imports and the 5 s sleep would put it past the timeout and the host would kill the guard first. (The real
    10 s budget, so the verdict is still computed after the cold start and the exit code is the denial's 2.)"""
    set_probe(_private_home, reachable=True, agents=agents)
    set_mode(_private_home, "block")
    result = run_watched(
        _private_home,
        agents,
        tmp_path,
        dispatch(model=None),
        mode="pre-seam",
        host_timeout=PRE_BUDGET,
        jam_stdout=True,
        extra_env={"SAFO_CHILD_COLD_START": "5.0"},
    )
    assert not result.killed and result.status == 2, f"status {result.status}, killed {result.killed}"
    assert result.elapsed < PRE_BUDGET


def test_the_process_start_is_found_early_enough_to_include_the_interpreter_and_the_cold_start(tmp_path: Path) -> None:
    """safo.PROCESS_STARTED is the process's start on the monotonic clock: a child that sleeps before importing safo
    sees an age that includes the sleep (Linux; elsewhere it is the import time, and the test only checks sanity)."""
    read_end, write_end = os.pipe()
    code = "import time; time.sleep(0.8); import safo; print(time.monotonic() - safo.PROCESS_STARTED)"
    actions: list[tuple[Any, ...]] = [(os.POSIX_SPAWN_DUP2, write_end, 1), (os.POSIX_SPAWN_CLOSE, read_end)]
    pid = os.posix_spawn(sys.executable, [sys.executable, "-c", code], os.environ, file_actions=actions)
    os.close(write_end)
    try:
        age = float(read_until(read_end, 20).decode().strip())
    finally:
        os.close(read_end)
    assert wait_exit(pid, 10) == 0
    assert 0.0 <= age < 30.0
    if Path("/proc/self/stat").exists():
        assert age >= 0.7, f"{age:.2f} s: the start-up before the import is counted"


def test_importing_everything_on_the_guard_path_writes_nothing_even_with_an_invalid_lock_timeout(
    tmp_path: Path,
) -> None:
    code = (
        "import safo.cli, safo.hooks, safo.guardlog, safo.leadwait, safo.tracking, safo.modes.hooks;"
        " safo.cli.build_parser()"
    )
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    actions: list[tuple[Any, ...]] = [
        (os.POSIX_SPAWN_DUP2, out_w, 1),
        (os.POSIX_SPAWN_DUP2, err_w, 2),
        (os.POSIX_SPAWN_CLOSE, out_r),
        (os.POSIX_SPAWN_CLOSE, err_r),
    ]
    env = {**os.environ, "SAFO_APPEND_LOCK_TIMEOUT": "not-a-number"}
    pid = os.posix_spawn(sys.executable, [sys.executable, "-c", code], env, file_actions=actions)
    os.close(out_w)
    os.close(err_w)
    try:
        out, err = read_until(out_r, 20), read_until(err_r, 20)
    finally:
        os.close(out_r)
        os.close(err_r)
    assert wait_exit(pid, 10) == 0
    assert out == b"" and err == b"", f"import wrote {out!r} / {err!r}"


@pytest.mark.parametrize("route", ["allow", "deny", "crash", "interrupt", "exit", "deny-then-crash"])
def test_guard_process_ends_the_process_exactly_once_on_every_route(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch, hard_exits: list[int], route: str
) -> None:
    if route in ("allow", "deny"):
        set_mode(_private_home, "block" if route == "deny" else "warn")
        out = Stream()
        assert mod.guard_process(context(_private_home, dispatch(model=None), out), namespace(agents)) == 0
        assert hard_exits == [0], "a delivered decision, allowed or denied, ends with 0"
        return

    def broken(ctx: Any, args: Any, begun: Any = None, run: Any = None) -> int:
        if route == "deny-then-crash":
            run.deny = True
        if route == "interrupt":
            raise KeyboardInterrupt
        if route == "exit":
            raise SystemExit(3)
        raise RuntimeError("the guard itself failed")

    monkeypatch.setattr(mod, "run_guard", broken)
    expected = {
        "crash": RuntimeError,
        "interrupt": KeyboardInterrupt,
        "exit": SystemExit,
        "deny-then-crash": RuntimeError,
    }
    with pytest.raises(expected[route]):
        mod.guard_process(context(_private_home, "{}", Stream()), namespace(agents))
    assert hard_exits == [2 if route == "deny-then-crash" else 1], "once, with the code of an undelivered decision"


# -- the real entry point: a hook command line never reaches argparse's writing paths ---------------------------------


def jam_pipe_counted() -> tuple[int, int, int]:
    """Like jam_pipe, and also how many bytes it holds."""
    read_end, write_end = os.pipe()
    os.set_blocking(write_end, False)
    filled = 0
    with contextlib.suppress(BlockingIOError):
        while True:
            filled += os.write(write_end, b"x" * 65536)
    os.set_blocking(write_end, True)
    return read_end, write_end, filled


def run_entry(
    home: Path, argv: list[str], *, payload: str = "", jam_stderr: bool = True, host_timeout: float = CHILD_BUDGET
) -> tuple[Watched, bool]:
    """Run `python -m safo ARGV` (the real entry point) under a watchdog that kills its process group at the scaled host
    timeout. Standard input is a pipe holding `payload`; standard error is, by default, a FULL pipe nobody reads.
    Returns the outcome and whether the blocked pipe still holds exactly what it held (nothing was written to it)."""
    in_read, in_write = os.pipe()
    os.write(in_write, payload.encode())
    os.close(in_write)
    out_read, out_write = os.pipe()
    err_read = err_write = -1
    filled = 0
    actions: list[tuple[Any, ...]] = [(os.POSIX_SPAWN_DUP2, in_read, 0), (os.POSIX_SPAWN_DUP2, out_write, 1)]
    if jam_stderr:
        err_read, err_write, filled = jam_pipe_counted()
        actions.append((os.POSIX_SPAWN_DUP2, err_write, 2))
    else:
        actions.append((os.POSIX_SPAWN_OPEN, 2, os.devnull, os.O_WRONLY, 0))
    actions += [(os.POSIX_SPAWN_CLOSE, out_read)]
    env = {**os.environ, "HOME": str(home)}
    done, killed = threading.Event(), threading.Event()
    started = time.monotonic()
    pid = os.posix_spawn(sys.executable, [sys.executable, "-m", "safo", *argv], env, file_actions=actions, setpgroup=0)
    for number in (in_read, out_write, err_write):
        if number >= 0:
            os.close(number)

    def watchdog() -> None:
        if not done.wait(max(0.0, host_timeout - (time.monotonic() - started))):
            killed.set()
            with contextlib.suppress(ProcessLookupError):
                os.killpg(pid, signal.SIGKILL)

    thread = threading.Thread(target=watchdog, daemon=True)
    thread.start()
    untouched = True
    try:
        raw = read_until(out_read, host_timeout + 5)
        status = wait_exit(pid, host_timeout + 5)
        elapsed = time.monotonic() - started
        if jam_stderr:
            os.set_blocking(err_read, False)
            held = 0
            with contextlib.suppress(BlockingIOError):
                while chunk := os.read(err_read, 65536):
                    held += len(chunk)
            untouched = held == filled
    finally:
        done.set()
        thread.join(2)
        for number in (out_read, err_read):
            if number >= 0:
                with contextlib.suppress(OSError):
                    os.close(number)
        with contextlib.suppress(ProcessLookupError, ChildProcessError):
            os.killpg(pid, signal.SIGKILL)
    return Watched(status, killed.is_set(), elapsed, Arrival.at - started, raw), untouched


@pytest.mark.parametrize(
    "argv",
    [
        ["hooks", "guard", "--no-such-flag"],
        ["hooks", "guard", "--agents"],
        ["hooks", "guard", "--help"],
        ["hooks", "guard", "--agents", "a", "--agents", "b"],
        ["hooks", "probe", "--no-such-flag"],
    ],
    ids=["unknown-flag", "missing-value", "help", "repeated-flag", "probe-unknown-flag"],
)
def test_a_hook_command_line_argparse_would_complain_about_writes_nothing_to_a_full_stderr_pipe(
    _private_home: Path, argv: list[str]
) -> None:
    """argparse prints usage and the error to stderr before it exits 2; into a full pipe that blocks until
    the host kills the hook. The real entry point must answer with the visible degraded allow instead (exit 0,
    never 2), on stdout, and write nothing to the blocked stderr."""
    result, untouched = run_entry(_private_home, argv)
    assert not result.killed, "argparse's own write to the blocked stderr would have held it until the host killed it"
    assert result.status == 0, "exit 0 with the degraded line: a configuration error is not a policy decision"
    [row] = lines(result.raw.decode())
    assert WARNING in row["systemMessage"]
    assert untouched, "nothing was written to the blocked stderr pipe"
    assert result.elapsed < CHILD_BUDGET


def test_the_real_entry_runs_the_guard_with_the_command_line_the_installer_writes(
    _private_home: Path, agents: Path
) -> None:
    set_probe(_private_home, reachable=True, agents=agents)
    set_mode(_private_home, "block")
    result, untouched = run_entry(
        _private_home, ["hooks", "guard", "--agents", str(agents)], payload=dispatch(model=None)
    )
    assert not result.killed and result.status == 0 and untouched
    [row] = lines(result.raw.decode())
    assert denied(row)


def test_the_hand_parser_accepts_what_the_installer_writes_and_nothing_else() -> None:
    parsed = mod.guard_argv(["--agents", "a.yaml", "--agents-local", "b.yaml"])
    assert parsed is not None and (parsed.agents, parsed.agents_local) == ("a.yaml", "b.yaml")
    assert mod.guard_argv([]) is not None
    assert mod.guard_argv(["--agents-local", "b"]) is not None
    for bad in (["--agents"], ["--bogus", "x"], ["--agents", "a", "--agents", "b"], ["a.yaml"], ["--agents=a"]):
        assert mod.guard_argv(bad) is None, bad


# -- every guard-shaped command line reaches the guard, never argparse -------------------------------------------------

GUARD_SHAPED = [
    pytest.param(["hooks", "guard"], id="plain"),
    pytest.param(["hooks", "guard", "--agents", "a.yaml"], id="installer-line"),
    pytest.param(["--help", "hooks", "guard"], id="help-before"),
    pytest.param(["--version", "hooks", "guard"], id="version-before"),
    pytest.param(["--board", "x", "hooks", "guard"], id="global-option-before"),
    pytest.param(["--board=x", "--dry-run", "hooks", "guard"], id="global-options-before-equals-form"),
    pytest.param(["--gh-user", "guard", "hooks", "guard"], id="option-value-named-guard-before"),
    pytest.param(["--board", "x", "hooks", "guard", "--bogus"], id="global-option-and-bogus-flag"),
    pytest.param(["--help", "hooks", "guard", "--help"], id="help-both-sides"),
    pytest.param(["hooks", "gua"], id="near-miss-truncated"),
    pytest.param(["hooks", "--guard"], id="near-miss-flag"),
    pytest.param(["hooks", "guard=value"], id="near-miss-equals"),
    pytest.param(["hooks", "gua", "--agents", "a.yaml"], id="near-miss-with-installer-flags"),
    pytest.param(["hooks", "--version", "guard"], id="hooks-then-version-then-guard"),
    pytest.param(["hooks", "\udcff"], id="surrogate-word"),
    pytest.param(["\udcff", "hooks", "guard"], id="leading-surrogate"),
    pytest.param(["", "hooks", "guard"], id="leading-empty-word"),
    pytest.param(["--board", "hooks", "guard"], id="board-lost-its-value"),
    pytest.param(["--gh-user", "hooks", "guard", "--agents", "a.yaml"], id="gh-user-lost-its-value"),
    pytest.param(["\udcff", "hooks", "gua", "--agents", "a.yaml"], id="leading-surrogate-and-near-miss"),
    pytest.param(["--", "hooks", "guard"], id="double-dash-terminator-stays-conservative"),
]

# Command lines with the words hooks and guard in them that are NOT the guard: they belong to argparse.
NOT_GUARD = [
    ["hooks", "probe"],
    ["--version"],
    ["hooks", "install", "--agents", "guard"],
    ["hooks", "install", "--settings", "guard"],
    ["--board", "hooks", "hooks", "status", "guard"],
    ["--board", "hooks", "hooks", "status", "--agents", "guard"],
    ["hooks", "mode", "guard"],
    ["hooks", "status", "hooks", "guard"],
    ["guard", "hooks"],
    ["--version", "guard", "x", "hooks"],
    ["hooks-x", "guard"],
    ["install", "hooks", "guard"],
    ["--gh-user", "hooks", "validate", "hooks", "guard"],
    ["hooks"],
    ["hooks", "-h"],
    ["hooks", "--help"],
    ["--board", "hooks", "install", "hooks", "guard"],
    ["--board", "x", "validate", "hooks", "guard"],
    ["\udcff", "hooks", "install"],
    ["", "hooks", "status", "guard"],
]


@pytest.fixture
def entry(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Any:
    """cli.run() as the host reaches it: no terminal, the given command line, standard input empty."""
    from safo import cli  # local: the module imports the whole CLI

    monkeypatch.setattr(cli, "person_at_a_terminal", lambda: False)
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))

    def go(argv: list[str]) -> int:
        # cli.run() arms the budget clock from the process start; a test process is not a fresh one, so each call
        # starts its own budget now (pytest's own age would otherwise starve a run inside the first seconds).
        # arm_process_clock() stores the result in the module, so the test restores it: a start left armed would shorten
        # the budget of whatever guard test runs next in this worker.
        monkeypatch.setattr(mod, "process_started", None)
        monkeypatch.setattr(safo_package, "PROCESS_STARTED", time.monotonic())
        monkeypatch.setattr(sys, "argv", ["safo", *argv])
        with pytest.raises(SystemExit) as stop:
            cli.run()
        return int(stop.value.code or 0)

    return go


@pytest.mark.parametrize("argv", GUARD_SHAPED)
def test_cli_run_routes_every_guard_shaped_argv_to_the_hand_parser_and_ends_once(
    entry: Any, monkeypatch: pytest.MonkeyPatch, hard_exits: list[int], argv: list[str]
) -> None:
    from safo import cli

    seen: list[list[str]] = []
    real = mod.guard_command

    def spy_command(words: Any) -> int:
        seen.append(list(words))
        return real(words)

    monkeypatch.setattr(mod, "guard_command", spy_command)
    monkeypatch.setattr(cli, "main", lambda *a, **k: pytest.fail("argparse was reached by a guard-shaped command line"))
    processes: list[bool] = []
    real_process = mod.guard_process

    def spy_process(ctx: Any, args: Any) -> int:
        processes.append(True)
        return real_process(ctx, args)

    monkeypatch.setattr(mod, "guard_process", spy_process)
    code = entry(argv)
    assert len(seen) == 1, "the hand-parser path took it"
    assert len(hard_exits) == 1, "and the process was ended exactly once"
    assert code == hard_exits[0], "the entry returns the code the guard ended with"
    assert processes == [True], (
        "every guard-shaped line reaches guard_process: it reads the event, it computes a verdict"
    )


def test_a_guard_shaped_command_line_never_ends_with_argparse_exit_zero_silently(entry: Any, capsys: Any) -> None:
    """The bypass: `--version hooks guard` used to exit 0 inside argparse with nothing on any stream."""
    entry(["--version", "hooks", "guard"])
    assert capsys.readouterr().out != "", "the guard answered (a decision or the visible degraded notice)"


@pytest.mark.parametrize("argv", NOT_GUARD, ids=lambda argv: " ".join(argv))
def test_a_command_line_that_is_not_the_guard_reaches_argparse_even_with_the_words_in_it(
    entry: Any, monkeypatch: pytest.MonkeyPatch, hard_exits: list[int], argv: list[str]
) -> None:
    """The negative case: routing is by position, so an option VALUE or a later word named
    hooks or guard is argparse's."""
    from safo import cli

    called: list[bool] = []

    def fake_main(*_: Any, **__: Any) -> int:
        called.append(True)
        return 0

    monkeypatch.setattr(cli, "main", fake_main)
    monkeypatch.setattr(mod, "guard_command", lambda words: pytest.fail("not a guard command line"))
    assert entry(argv) == 0 and called == [True]
    assert hard_exits == []


def test_the_routing_is_decided_by_position_not_membership() -> None:
    assert mod.guard_words(["hooks", "install", "--agents", "guard"]) is None
    assert mod.guard_words(["--board", "hooks", "hooks", "status", "guard"]) is None
    assert mod.guard_words(["--board", "hooks", "hooks", "guard", "--agents", "p"]) == ["--agents", "p"]
    assert mod.guard_words(["hooks", "guard"]) == []
    for near in (["hooks", "gua"], ["hooks", "--guard"], ["hooks", "guard=v"], ["hooks", "\udcff"]):
        words = mod.guard_words(near)
        assert words == ["?"] and mod.guard_argv(words) is None, near
    assert mod.guard_words(["hooks", "gua", "--agents", "p"]) == ["?", "--agents", "p"]
    for helpful in (["hooks"], ["hooks", "-h"], ["hooks", "--help"]):
        assert mod.guard_words(helpful) is None, helpful


def test_corruption_in_front_of_a_real_hooks_guard_is_still_the_guard() -> None:
    assert mod.guard_words(["\udcff", "hooks", "guard"]) == []
    assert mod.guard_words(["", "hooks", "guard", "--agents", "p"]) == ["--agents", "p"]
    assert mod.guard_words(["--board", "hooks", "guard"]) == []
    assert mod.guard_words(["--board", "hooks", "guard", "--agents", "p"]) == ["--agents", "p"]
    assert mod.guard_words(["\udcff", "hooks", "gua", "--agents", "p"]) == ["?", "--agents", "p"]
    assert mod.guard_words(["--", "hooks", "guard"]) == [], "the -- terminator is deliberately skipped: the guard"


def test_corruption_scan_leaves_every_legitimate_argparse_line_alone() -> None:
    for line in NOT_GUARD:
        assert mod.guard_words(line) is None, line


# -- a guard-shaped line the parser refuses still gets a verdict: a denyable event is DENIED ---------------------------

MALFORMED = [
    ["hooks", "guard", "--agents"],
    ["hooks", "guard", "--bogus"],
    ["hooks", "guard", "--help"],
    ["hooks", "gua"],
    ["hooks", "--guard"],
    ["hooks", "guard=value"],
    ["hooks", "\udcff"],
    ["--version", "hooks", "guard", "--bogus"],
    ["hooks", "--version", "guard"],
]


@pytest.fixture
def block_home(_private_home: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Default configuration discovery finds an agents file under HOME and the mode file says block."""
    (_private_home / ".config" / "safo").mkdir(parents=True, exist_ok=True)
    (_private_home / ".config" / "safo").chmod(0o700)
    agents_file(_private_home / ".config" / "safo" / "agents.yaml")
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=True, agents=_private_home / ".config" / "safo" / "agents.yaml")
    monkeypatch.setenv("HOME", str(_private_home))
    for name in ("SAFO_AGENTS", "SAFO_AGENTS_LOCAL"):
        monkeypatch.delenv(name, raising=False)
    return _private_home


@pytest.mark.parametrize("argv", MALFORMED, ids=lambda argv: " ".join(argv))
def test_malformed_guard_argv_with_a_denyable_event_exits_two_and_never_zero(
    entry: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any, hard_exits: list[int], block_home: Path, argv: list[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(dispatch(model=None)))
    code = entry(argv)
    assert hard_exits == [code], "ended exactly once"
    out = capsys.readouterr().out
    # Delivered, a denial is the deny line (exit 0 by the host's protocol); undelivered it is exit 2. The bypass was a
    # degraded-allow line with exit 0, which has neither.
    assert code == 2 or (code == 0 and denied(lines(out)[-1])), (code, out)
    assert "permissionDecision" not in out or denied(lines(out)[-1])


@pytest.mark.parametrize("argv", MALFORMED, ids=lambda argv: " ".join(argv))
def test_malformed_guard_argv_with_an_allowable_event_is_allowed_with_a_verdict(
    entry: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any, hard_exits: list[int], block_home: Path, argv: list[str]
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(dispatch()))
    assert entry(argv) == 0
    assert hard_exits == [0]
    data = lines(capsys.readouterr().out)
    assert not any(denied(row) for row in data), "an allowable event is not denied"
    assert "degraded" not in json.dumps(data), "a verdict was computed, not a cannot-tell notice"


@pytest.mark.parametrize("stdin", ["", "not json", "{"])
def test_malformed_guard_argv_with_no_readable_event_takes_the_cannot_tell_path(
    entry: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any, hard_exits: list[int], block_home: Path, stdin: str
) -> None:
    """The only case that may degrade: there is no event to judge. Visible degraded allow, exit 0, ended once."""
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    assert entry(["hooks", "gua"]) == 0
    assert hard_exits == [0]
    assert "degraded" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        ["hooks", "gua"],
        ["hooks", "--guard"],
        ["hooks", "guard=value"],
        ["hooks", "\udcff"],
        ["hooks", "guard", "--bogus"],
    ],
    ids=["truncated", "flag", "equals", "non-utf8", "bogus-flag"],
)
def test_a_real_process_with_a_full_stderr_pipe_and_a_near_miss_denies_promptly(
    block_home: Path, argv: list[str]
) -> None:
    """Argparse would print usage to the full pipe and block until the host kills it (fail-open, SAFO #130), or exit 2
    with no verdict. The guard writes nothing to stderr, reads the event, and blocks the denyable one at once."""
    result, untouched = run_entry(block_home, argv, payload=dispatch(model=None))
    assert not result.killed and untouched, "nothing was written to the blocked stderr, so nothing blocked on it"
    [row] = lines(result.raw.decode())
    assert result.status == 0 and denied(row), "a denyable event is denied by the deny line, not a degraded allow"
    assert result.elapsed < CHILD_BUDGET


def test_a_real_process_with_a_full_stderr_pipe_and_a_near_miss_allows_an_allowable_event(block_home: Path) -> None:
    result, untouched = run_entry(block_home, ["hooks", "gua"], payload=dispatch())
    assert not result.killed and untouched and result.status == 0
    assert WARNING not in result.raw.decode(), "a verdict, not the cannot-tell notice"


def test_install_with_an_option_value_named_guard_is_not_swallowed(
    block_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`safo hooks install --settings guard` with no terminal used to print guard JSON and exit 0 with nothing done."""
    monkeypatch.chdir(tmp_path)  # a relative settings path named `guard` lands here, not in the repository
    for argv in (
        ["hooks", "install", "--settings", str(tmp_path / "s.json"), "--agents", "guard"],
        ["hooks", "install", "--settings", "guard"],
        ["--board", "hooks", "hooks", "status", "guard"],
    ):
        result, _ = run_entry(block_home, argv, payload=dispatch(model=None), jam_stderr=False)
        assert b"hookSpecificOutput" not in result.raw, (argv, result.raw)
        assert WARNING not in result.raw.decode(), argv
    assert (tmp_path / "guard").is_file(), "`--settings guard` installed into a file named guard; it was no guard run"


# -- a refused line keeps the explicit paths it carries: the strict file is judged, never dropped ----------------------

SALVAGE_SHAPES = [
    pytest.param(["hooks", "gua", "--agents", "{agents}"], id="near-miss-word"),
    pytest.param(["hooks", "guard", "--bogus", "--agents", "{agents}"], id="unknown-flag-before"),
    pytest.param(["hooks", "guard", "--agents", "{agents}", "--bogus"], id="unknown-flag-after"),
    pytest.param(["hooks", "guard", "--bogus", "--agents={agents}"], id="equals-form"),
    pytest.param(["hooks", "guard", "--agents", "{agents}", "--agents-local"], id="missing-value-after"),
    pytest.param(["hooks", "guard", "--agents-local", "--agents", "{agents}"], id="missing-value-before"),
    pytest.param(["hooks", "guard", "--agents=", "--agents", "{agents}"], id="empty-equals-then-real"),
    pytest.param(["hooks", "guard", "--agents", "{agents}", "--agents="], id="real-then-empty-equals"),
    pytest.param(["hooks", "guard", "--agents", "{agents}", "--agents", "--bogus"], id="real-then-flag-value"),
    pytest.param(["hooks", "guard", "stray", "--agents", "{agents}", "stray2"], id="stray-words"),
    pytest.param(["\udcff", "hooks", "guard", "--agents", "{agents}"], id="leading-surrogate"),
    pytest.param(["", "hooks", "guard", "--agents", "{agents}"], id="leading-empty-word"),
    pytest.param(["--board", "hooks", "guard", "--agents", "{agents}"], id="board-missing-value"),
    pytest.param(["hooks", "guard", "--agents", "/first/wrong.yaml", "--agents", "{agents}"], id="repeated-last-wins"),
]


@pytest.fixture
def strict_only(_private_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """No default configuration anywhere under HOME (so a lost explicit path means the degraded allow); the strict
    agents file is elsewhere. The mode file says block."""
    assert not (_private_home / ".config" / "safo" / "agents.yaml").exists()
    strict = agents_file(tmp_path / "strict-agents.yaml")
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=True, agents=strict)
    for name in ("SAFO_AGENTS", "SAFO_AGENTS_LOCAL"):
        monkeypatch.delenv(name, raising=False)
    return strict


def fill(argv: list[str], strict: Path) -> list[str]:
    return [word.replace("{agents}", str(strict)) for word in argv]


@pytest.mark.parametrize("argv", SALVAGE_SHAPES)
def test_a_refused_guard_line_keeps_the_explicit_agents_path_and_denies(
    entry: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
    hard_exits: list[int],
    strict_only: Path,
    argv: list[str],
) -> None:
    """No default config exists: a dropped --agents would be the degraded allow (exit 0, no deny line)."""
    monkeypatch.setattr(sys, "stdin", io.StringIO(dispatch(model=None)))
    code = entry(fill(argv, strict_only))
    out = capsys.readouterr().out
    assert hard_exits == [code]
    assert code == 2 or (code == 0 and denied(lines(out)[-1])), (code, out)
    assert "degraded" not in out


def test_salvage_reads_both_options_in_both_spellings_last_one_wins_and_ignores_the_rest() -> None:
    ns = mod.salvage_argv(["?", "--bogus", "--agents", "a", "--agents-local=b", "junk", "--agents=c"])
    assert (ns.agents, ns.agents_local) == ("c", "b")
    for words in (["--agents"], ["--agents="], ["--agents", ""], ["--agents", "-x"], ["--agents=-x"], ["?"], []):
        ns = mod.salvage_argv(words)
        assert (ns.agents, ns.agents_local) == ("", ""), words
    ns = mod.salvage_argv(["--agents", "--agents-local", "l"])
    assert (ns.agents, ns.agents_local) == ("", "l"), "a flag in the value place is absent, and read as a flag"


def test_dropping_every_explicit_argument_when_one_word_is_malformed_is_caught(
    entry: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any, hard_exits: list[int], strict_only: Path
) -> None:
    """Mutant killer: the old behavior (a refused line becomes an empty Namespace) must fail here."""
    original = mod.salvage_argv
    seen: list[argparse.Namespace] = []

    def spy(words: Any) -> argparse.Namespace:
        ns = original(words)
        seen.append(ns)
        return ns

    monkeypatch.setattr(mod, "salvage_argv", spy)
    monkeypatch.setattr(sys, "stdin", io.StringIO(dispatch(model=None)))
    entry(["hooks", "guard", "--bogus", "--agents", str(strict_only)])
    assert [ns.agents for ns in seen] == [str(strict_only)], "the explicit path reached the guard"
    assert "degraded" not in capsys.readouterr().out


# -- corruption in front of a real `hooks guard` never reaches argparse (real process, full stderr pipe) ---------------


@pytest.mark.parametrize(
    "argv",
    [
        ["\udcff", "hooks", "guard", "--agents", "{agents}"],
        ["", "hooks", "guard", "--agents", "{agents}"],
        ["--board", "hooks", "guard", "--agents", "{agents}"],
        ["hooks", "gua", "--agents", "{agents}"],
        ["hooks", "guard", "--bogus", "--agents", "{agents}"],
        ["hooks", "guard", "--agents="],
    ],
    ids=["leading-surrogate", "leading-empty", "board-missing-value", "near-miss-and-path", "bogus-and-path", "empty"],
)
def test_a_real_process_with_a_corrupted_front_and_a_full_stderr_pipe_denies_promptly(
    _private_home: Path, strict_only: Path, argv: list[str]
) -> None:
    result, untouched = run_entry(_private_home, fill(argv, strict_only), payload=dispatch(model=None))
    assert not result.killed and untouched, "argparse would have written usage to the blocked stderr"
    [row] = lines(result.raw.decode())
    if argv[-1] == "--agents=":
        assert result.status == 0 and WARNING in row["systemMessage"], "no path survives: the visible degraded allow"
    else:
        assert result.status == 0 and denied(row), "the salvaged strict file denied the denyable event"
    assert result.elapsed < CHILD_BUDGET


@pytest.mark.parametrize("argv", [["hooks"], ["hooks", "-h"], ["hooks", "--help"]], ids=" ".join)
def test_a_real_process_asking_for_hooks_help_gets_help_without_reading_stdin(
    _private_home: Path, strict_only: Path, argv: list[str]
) -> None:
    """Non-tty, with a denyable event waiting on stdin: help is argparse's, exit 0 (bare `hooks` exits per argparse),
    and no guard line is written."""
    result, _ = run_entry(_private_home, argv, payload=dispatch(model=None), jam_stderr=False)
    assert not result.killed
    assert b"hookSpecificOutput" not in result.raw and WARNING not in result.raw.decode(), result.raw
    assert result.status == (2 if argv == ["hooks"] else 0), result.status


# -- no minimum wait once decide_by has passed ----------------------------------------------------------------------


def blocked_until_released() -> tuple[threading.Event, Any]:
    release = threading.Event()

    def block(*_: Any, **__: Any) -> Any:
        release.wait(5)
        return None

    return release, block


@pytest.mark.parametrize("floor", ["NOTICE_IO_MIN_SECONDS"])
def test_io_budget_is_zero_after_decide_by_whatever_the_minimum_constants_say(
    monkeypatch: pytest.MonkeyPatch, floor: str
) -> None:
    monkeypatch.setattr(mod, floor, 10.0)
    run = mod.Run()
    run.decide_by = time.monotonic() - 0.001
    assert mod.io_budget(run) == 0.0


def test_a_computed_denial_is_not_held_by_a_blocked_notice_read_after_decide_by(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mod, "NOTICE_IO_MIN_SECONDS", 10.0)  # raised: a honored minimum would hold the worker's join
    release, block = blocked_until_released()
    monkeypatch.setattr(mod, "notice_unclaimed", block)
    monkeypatch.setattr(mod, "log_failure_pending", block)
    run = mod.Run()
    run.deny = True  # the verdict exists before the notices are read
    run.decide_by = time.monotonic() - 0.001
    run.limit = time.monotonic() + 9.0
    started = time.monotonic()
    try:
        seen = mod.read_notices(Path("/nonexistent-state"), Path("/nonexistent-state/x"), True, run)
        assert time.monotonic() - started < 0.2, "the denial did not wait for the blocked read"
        assert seen.skipped and run.overran
    finally:
        release.set()


def test_the_whole_guard_exits_two_at_once_when_the_notice_read_blocks_after_decide_by(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch, hard_exits: list[int]
) -> None:
    set_mode(_private_home, "block")
    monkeypatch.setattr(mod, "NOTICE_IO_MIN_SECONDS", 10.0)
    release, block = blocked_until_released()
    monkeypatch.setattr(mod, "log_failure_pending", block)
    monkeypatch.setattr(mod, "notice_unclaimed", block)
    # The load and the lookups are early enough; the decision point is already behind us when the notices are read.
    monkeypatch.setattr(mod, "budget_points", lambda begun: (begun + 7.0, begun + 8.0, begun + 9.0))
    real_notices = mod.read_notices

    def late(folder: Any, path: Any, wants_first: bool, run: Any) -> Any:
        assert run.deny, "the denial is computed before the notices are read"
        run.decide_by = time.monotonic() - 0.001  # time passed while the verdict was computed
        return real_notices(folder, path, wants_first, run)

    monkeypatch.setattr(mod, "read_notices", late)
    out = Stream()
    started = time.monotonic()
    try:
        assert mod.run_guard(context(_private_home, dispatch(model=None), out), namespace(agents)) == 2
        assert time.monotonic() - started < 2.0, "exit 2 at once, not after a minimum wait"
        assert out.writes == []
    finally:
        release.set()


def test_bounded_reprobe_grants_no_minimum_after_decide_by(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mod, "NOTICE_IO_MIN_SECONDS", 10.0)
    release, block = blocked_until_released()
    run = mod.Run()
    run.decide_by = time.monotonic() - 0.001
    run.limit = time.monotonic() + 9.0
    monkeypatch.setattr(mod, "reprobe", block)
    started = time.monotonic()
    try:
        fresh, slow = mod.bounded_reprobe(cast(Any, None), Path("p"), 0.0, 0.5, time.monotonic() + 5.0, run)
        assert fresh is None and slow and time.monotonic() - started < 0.2
    finally:
        release.set()


# -- a decision whose deadline has already passed waits for nothing ----------------------------------------------------


@pytest.mark.parametrize(("mode", "code"), [("block", 2), ("warn", 0)])
def test_a_decision_whose_deadline_has_passed_is_not_waited_for_or_written(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch, mode: str, code: int
) -> None:
    """Late start: decide_by is already behind us when the verdict exists. A denial is an exit 2 with nothing
    written (the host blocks on the code); anything else is a silent allow. No minimum wait is granted."""
    set_mode(_private_home, mode)
    monkeypatch.setattr(mod, "CONFIG_MIN_WAIT_SECONDS", 10.0)
    monkeypatch.setattr(mod, "budget_points", lambda begun: (begun - 3.0, begun - 0.001, begun + 9.0))
    out = Stream()
    started = time.monotonic()
    assert mod.run_guard(context(_private_home, bash("sleep 60"), out), namespace(agents)) == code
    assert out.writes == [], "nothing was written"
    assert time.monotonic() - started < 2.0, "and nothing was waited for"


@pytest.mark.parametrize("mode", ["block", "warn"])
def test_a_configuration_load_that_blocks_is_cut_at_the_limit_whatever_the_floor_says(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    """The floor (CONFIG_MIN_WAIT_SECONDS) is real only when a load really blocks: it is raised far past the limit and
    the load is held, and the guard still returns at the limit, not after the floor and not when the load ends."""
    set_mode(_private_home, mode)
    monkeypatch.setattr(mod, "CONFIG_MIN_WAIT_SECONDS", 10.0)
    monkeypatch.setattr(mod, "limit_point", lambda begun: time.monotonic() + 0.6)
    release, block = blocked_until_released()
    monkeypatch.setattr(mod, "load_agents_for", block)
    started = time.monotonic()
    try:
        # No verdict exists (the load never finished): the degraded notice is delivered (0) or, when the limit already
        # passed, undelivered (1). Never a block (2), and never later than the limit.
        code = mod.run_guard(context(_private_home, bash("sleep 60"), Stream()), namespace(agents))
        assert code in (0, 1), code
        assert time.monotonic() - started < 1.5, "cut at the limit, with the load still blocked"
    finally:
        release.set()


def test_no_wait_ends_after_the_limit_measured_from_the_process_start(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    waits: list[float] = []
    real = threading.Thread.join

    def watch(self: threading.Thread, timeout: float | None = None) -> None:
        if self.name == "safo-bounded":
            waits.append(-1.0 if timeout is None else timeout)
        real(self, timeout)

    monkeypatch.setattr(threading.Thread, "join", watch)
    set_mode(_private_home, "block")
    # The decision and post-delivery deadlines are far away (8 s, 9 s), but the limit is half a second from now: every
    # wait the guard asks a thread for must be cut to it, whoever asked.
    monkeypatch.setattr(mod, "limit_point", lambda begun: time.monotonic() + 0.5)
    mod.run_guard(context(_private_home, bash("sleep 60"), Stream()), namespace(agents))
    assert len(waits) >= 4 and all(0.0 <= wait <= 0.51 for wait in waits), waits


def test_a_start_older_than_the_whole_budget_is_not_trusted(monkeypatch: pytest.MonkeyPatch) -> None:
    now = time.monotonic()
    monkeypatch.setattr(mod, "process_started", now - 9.9)
    assert mod.process_begun(now) == now - 9.9, "recent: inside one budget"
    monkeypatch.setattr(mod, "process_started", now - 10.1)
    assert mod.process_begun(now) == now, "older than the budget: the process is not a fresh hook"
    monkeypatch.setattr(mod, "process_started", None)
    assert mod.process_begun(now) == now, "never armed (a test process): now"


def test_a_late_start_after_decide_by_still_exits_two_before_the_host_kills_the_guard(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    """The child reaches guard_process about 3.8 s into a 5 s budget: after decide_by (3 s), before the limit (4.75 s).
    The pipe is full. There is no time to wait for it: exit 2, at once."""
    set_probe(_private_home, reachable=True, agents=agents)
    set_mode(_private_home, "block")
    result = run_watched(
        _private_home,
        agents,
        tmp_path,
        dispatch(model=None),
        mode="seam",
        jam_stdout=True,
        extra_env={"SAFO_CHILD_COLD_START": "3.3", "SAFO_CHILD_CONFIG_FLOOR": "0.7"},
    )
    assert not result.killed and result.status == 2, f"status {result.status}, killed {result.killed}"
    assert result.elapsed < CHILD_BUDGET


# -- the process age: what is trusted, and the fallback ----------------------------------------------------------


def proc_stat(starttime_ticks: int) -> str:
    return "123 (safo hooks) S " + " ".join(["0"] * 18 + [str(starttime_ticks)] + ["0"] * 10)


def test_the_process_age_is_read_from_proc_and_distrusted_when_it_does_not_look_fresh() -> None:
    import safo

    ticks = 100.0
    uptime = "1000.00 4000.00"  # seconds since boot; the process started at tick 95000 = 950 s: 50 s old
    assert safo._process_age(proc_stat(95000), uptime, ticks) == pytest.approx(50.0)
    assert safo._process_age(proc_stat(99400), uptime, ticks) == pytest.approx(6.0)
    assert safo._process_age(proc_stat(94010), uptime, ticks) == pytest.approx(59.9)
    assert safo._process_age(proc_stat(93990), uptime, ticks) is None, "over the sanity clamp (60 s): not trusted"
    assert safo._process_age(proc_stat(100010), uptime, ticks) is None, "started after 'now': the clocks disagree"
    for garbage in ("", "no parenthesis", "1 (x) S 1 2"):
        assert safo._process_age(garbage, uptime, ticks) is None
    assert safo._process_age(proc_stat(95000), "", ticks) is None
    assert safo._process_age(proc_stat(95000), uptime, 0.0) is None


def test_an_untrusted_age_falls_back_to_now(monkeypatch: pytest.MonkeyPatch) -> None:
    import safo

    monkeypatch.setattr(safo, "_process_age", lambda *a: None)
    before = time.monotonic()
    assert before <= safo._process_started() <= time.monotonic(), "the fallback is the time of the import, i.e. now"


# -- the emit worker completes just after the join times out ---------------------------------------------------------


@pytest.mark.parametrize("offset", [2.5, 2.9, 3.0, 3.1, 3.3])
def test_a_blocked_write_that_completes_around_the_deadline_gives_at_most_one_line_and_never_a_wrong_exit(
    _private_home: Path, agents: Path, tmp_path: Path, offset: float
) -> None:
    """Real process, full stdout pipe. The reader starts draining `offset` seconds after the start, around decide_by
    (3 s of 5): the emit worker's write finishes just before, at, or just after the main thread gave up on it.
    Whatever the order: at most ONE complete JSON line, exit 2 when it was not delivered in time, 0 when it was."""
    set_probe(_private_home, reachable=True, agents=agents)
    set_mode(_private_home, "block")
    body = tmp_path / "payload.json"
    body.write_text(dispatch(model=None))
    jam_read, jam_write, filled = jam_pipe_counted()
    started = time.monotonic()
    pid, _ = spawn_seam(
        _private_home, agents, body, mode="seam", barrier=tmp_path / "barrier", stdout_fd=jam_write, new_group=True
    )
    os.close(jam_write)  # only the child keeps the writing end: the drain sees end of file when it is gone
    collected: list[bytes] = []

    def drain() -> None:
        time.sleep(max(0.0, offset - (time.monotonic() - started)))
        while chunk := os.read(jam_read, 65536):
            collected.append(chunk)

    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    killer = threading.Timer(CHILD_BUDGET, lambda: os.killpg(pid, signal.SIGKILL))
    killer.start()
    try:
        status = wait_exit(pid, CHILD_BUDGET + 5)
        thread.join(5)
    finally:
        killed = not killer.is_alive()
        killer.cancel()
        os.close(jam_read)
        with contextlib.suppress(ProcessLookupError, ChildProcessError):
            os.killpg(pid, signal.SIGKILL)
    tail = b"".join(collected)[filled:]
    complete = [row for row in tail.split(b"\n") if row]
    assert not killed and status in (0, 2), f"status {status}, killed {killed}"
    assert len(complete) <= 1 and tail.count(b"\n") <= 1, f"{len(complete)} lines: {tail[:200]!r}"
    if complete:
        assert denied(json.loads(complete[0]))
    if status == 0:
        assert len(complete) == 1 and tail.endswith(b"\n"), "exit 0 means the line was delivered whole"
    if offset <= 2.5:
        assert status == 0 and len(complete) == 1, "drained well before the deadline: delivered"
