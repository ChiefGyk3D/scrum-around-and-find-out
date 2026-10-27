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
import stat
import sys
import threading
import time
import types
from pathlib import Path
from typing import Any

import pytest

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
    assert status == 0, "the process ends by itself, with the abandoned load still blocked"
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
        clock.now += 10.1  # the load returned, but after the whole budget (on the injected clock)
        return load_agents_for(*a, **k)

    def must_not_be_asked(ref: Any) -> str:
        raise AssertionError("the issue lookup must be skipped with no budget left")

    monkeypatch.setattr(mod, "load_agents_for", late_load)
    out = Stream()
    ctx = context(_private_home, dispatch(prompt=f"issue: {GOOD}", tracked=False), out, issue_lookup=must_not_be_asked)
    assert mod.run_guard(ctx, namespace(agents)) == 0
    [row] = lines(out.buffered)
    assert denied(row) and mod.BUDGET_NOTICE in row["hookSpecificOutput"]["additionalContext"]
    assert marker(_private_home).exists(), "the append was skipped: the clock was past the hard limit"


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
        clock.now += 10.1
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


def run_with_abandoned_check(home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Gated, Path, str]:
    flag = unhealthy(home, agents)
    held = Gated()
    monkeypatch.setattr(mod, "NOTICE_IO_CAP_SECONDS", 0.3)
    monkeypatch.setattr(mod, "notice_unclaimed", held.check)
    out = Stream()
    mod.run_guard(context(home, dispatch(model=None), out), namespace(agents))
    return held, flag, out.buffered


def test_an_abandoned_notice_check_that_finishes_late_creates_nothing(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    held, flag, line = run_with_abandoned_check(_private_home, agents, monkeypatch)
    assert mod.NOTICES_SKIPPED in line and not flag.exists()
    held.gate.set()  # the real check resumes late, in its abandoned thread
    assert held.done.wait(10)
    assert not flag.exists(), "a worker that finishes late creates nothing"


def test_an_abandoned_notice_check_that_finishes_late_leaves_no_descriptor_open(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    unhealthy(_private_home, agents)
    before = fd_count()
    held, _, _ = run_with_abandoned_check(_private_home, agents, monkeypatch)
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
        held, flag, line = run_with_abandoned_check(_private_home, agents, patch)
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
) -> tuple[int, int]:
    """Start tests/guard_child.py with seams from its environment. Returns (pid, read end of its stdout), or (pid, -1)
    when `stdout_fd` is given (the test then owns the child's standard output). Standard error goes to /dev/null: the
    guard writes nothing to it."""
    read_end = write_end = -1
    actions: list[tuple[Any, ...]] = [(os.POSIX_SPAWN_OPEN, 2, os.devnull, os.O_WRONLY, 0)]
    if stdout_fd is None:
        read_end, write_end = os.pipe()
        actions += [(os.POSIX_SPAWN_DUP2, write_end, 1), (os.POSIX_SPAWN_CLOSE, read_end)]
    else:
        actions.append((os.POSIX_SPAWN_DUP2, stdout_fd, 1))
    env = {**os.environ, "SAFO_CHILD_BARRIER": str(barrier), "SAFO_CHILD_BLOCK": block, "SAFO_CHILD_FAIL": fail}
    if nondaemon:
        env["SAFO_CHILD_NONDAEMON"] = "1"
    argv = [sys.executable, str(CHILD), mode, str(home), str(agents), str(barrier), str(body)]
    pid = os.posix_spawn(sys.executable, argv, env, file_actions=actions)
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
