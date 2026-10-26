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


def spawn(mode: str, home: Path, agents: Path, fifo: Path, body: Path) -> tuple[int, int]:
    """Start tests/guard_child.py as a real process; returns (pid, read end of its standard output)."""
    read_end, write_end = os.pipe()
    actions = [
        (os.POSIX_SPAWN_DUP2, write_end, 1),
        (os.POSIX_SPAWN_OPEN, 2, os.devnull, os.O_WRONLY, 0),
        (os.POSIX_SPAWN_CLOSE, read_end),
    ]
    argv = [sys.executable, str(CHILD), mode, str(home), str(agents), str(fifo), str(body)]
    pid = os.posix_spawn(sys.executable, argv, os.environ, file_actions=actions)
    os.close(write_end)
    return pid, read_end


def read_until(fd: int, stop: float, first_line: bool = False) -> bytes:
    """What the child wrote: to end of file, or (first_line) to the first newline, within `stop` seconds."""
    data = b""
    end = time.monotonic() + stop
    while time.monotonic() < end and not (first_line and b"\n" in data):
        if select.select([fd], [], [], 0.1)[0]:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data += chunk
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
    finally:
        os.close(fd)
        os.kill(pid, 9)
        os.waitpid(pid, 0)
    elapsed = time.monotonic() - started
    rows = lines(raw.decode())
    assert len(rows) == 1
    assert mod.CONFIG_TIMEOUT_NOTICE in rows[0]["hookSpecificOutput"]["additionalContext"]
    # SYNTHETIC: the loader is replaced by a call that never returns (a wedged mount or kernel read, which cannot be
    # made without privilege). The budget is 3 s here (deadline 1 s, hard 2 s); the interpreter start is the slack.
    assert elapsed < 3 + 1.5, f"{elapsed:.1f} s: the decision must land inside the (scaled) budget"


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
    elapsed = time.monotonic() - started
    [row] = lines(raw.decode())
    assert denied(row) and mod.NOTICES_SKIPPED in row["hookSpecificOutput"]["additionalContext"]
    assert elapsed < 3 + 1.5, f"{elapsed:.1f} s: the deny must land inside the (scaled) budget"


def test_a_process_killed_after_the_decision_leaves_exactly_one_complete_json_line(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    body = tmp_path / "payload.json"
    body.write_text(bash("sleep 60"))
    set_mode(_private_home, "block")
    pid, fd = spawn("hang-append", _private_home, agents, tmp_path / "x", body)
    try:
        first = read_until(fd, 8, first_line=True)
        alive = os.waitpid(pid, os.WNOHANG) == (0, 0)
    finally:
        os.kill(pid, 9)
    rest = read_until(fd, 2)
    os.close(fd)
    with contextlib.suppress(ChildProcessError):
        os.waitpid(pid, 0)
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
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    set_mode(_private_home, "block")
    calls: list[str] = []
    monkeypatch.setattr(mod, "append_log", lambda *a, **k: calls.append("append"))
    out = Stream(flush_fails=True)
    code = mod.run_guard(context(_private_home, bash("sleep 60"), out), namespace(agents))
    assert code == mod.EXIT_BLOCK, "a denial that was not delivered blocks (exit 2) instead of failing open"
    assert calls == [] and len(out.writes) == 1, "no append and no second line after a failed delivery"
    assert mod.EMIT_FAILED_TEXT in capsys.readouterr().err


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


def test_a_blocker_replaced_after_the_failed_rename_is_not_removed(
    _private_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = state_folder(_private_home)
    where = plant("directory", _private_home, tmp_path)
    real = mod.remove_junk
    results: list[bool] = []

    def seam(dfd: int, seen: Any) -> bool:
        where.rmdir()  # the blocker is replaced by a valid marker before it is removed
        with open(where, "w") as handle:
            handle.write("newer failure\n")
        where.chmod(0o600)
        results.append(real(dfd, seen))
        return results[-1]

    monkeypatch.setattr(mod, "remove_junk", seam)
    assert mod.write_log_failed(folder) is True
    assert results == [False]
    assert stat.S_ISREG(os.lstat(where).st_mode)


# -- the probe notice is claimed after delivery, by the calling thread only --------------------------------------


def fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


def abandoned_workers() -> None:
    for worker in threading.enumerate():
        if worker.name == "safo-bounded":
            worker.join(10)


def unhealthy(home: Path, agents: Path) -> Path:
    state_folder(home).mkdir(parents=True, exist_ok=True)
    block_reprobe(home, agents, age=1.0)  # an attempt a second ago: no re-probe, health stays unknown
    return notice_path(probe_file(home, agents))


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="needs /proc to count descriptors (Linux)")
def test_an_abandoned_notice_check_that_finishes_late_creates_nothing_and_leaks_no_descriptor(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    flag = unhealthy(_private_home, agents)
    gate = threading.Event()
    monkeypatch.setattr(mod, "NOTICE_IO_CAP_SECONDS", 0.3)
    monkeypatch.setattr(
        mod, "notice_unclaimed", lambda p: (gate.wait(10), core.notice_unclaimed(p))[1]
    )  # the REAL check
    before = fd_count()
    out = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), out), namespace(agents))
    assert mod.NOTICES_SKIPPED in out.buffered and not flag.exists()
    gate.set()  # the real check resumes late, in its abandoned thread
    abandoned_workers()
    assert not flag.exists(), "a worker that finishes late creates nothing"
    assert fd_count() == before, "and leaves no descriptor open"


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
    flag = unhealthy(_private_home, agents)
    with monkeypatch.context() as patch:
        patch.setattr(mod, "NOTICE_IO_CAP_SECONDS", 0.3)
        patch.setattr(mod, "notice_unclaimed", lambda p: time.sleep(2))
        skipped = Stream()
        mod.run_guard(context(_private_home, dispatch(model=None), skipped), namespace(agents))
    assert mod.NOTICES_SKIPPED in skipped.buffered and not flag.exists()
    abandoned_workers()
    nxt = Stream()
    mod.run_guard(context(_private_home, dispatch(model=None), nxt), namespace(agents))
    assert mod.NOTICES_SKIPPED not in nxt.buffered and WARNING in nxt.buffered and flag.exists()


# -- two real processes appending to one corrupt log ---------------------------------------------------------


def test_two_processes_appending_to_one_corrupt_log_quarantine_it_once_and_lose_no_record(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    log = tmp_path / "log.jsonl"
    log.write_bytes(b"\xff\n")
    log.chmod(0o600)
    actions = [
        (os.POSIX_SPAWN_OPEN, 1, os.devnull, os.O_WRONLY, 0),
        (os.POSIX_SPAWN_OPEN, 2, os.devnull, os.O_WRONLY, 0),
    ]
    child = Path(__file__).parent / "append_child.py"
    pids = [
        os.posix_spawn(sys.executable, [sys.executable, str(child), str(log), "5"], os.environ, file_actions=actions)
        for _ in range(2)
    ]
    codes = [os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]) for pid in pids]
    assert codes == [0, 0]
    assert len(corrupt_files(tmp_path)) == 1, "the corrupt log is moved once, under the lock"
    assert len(log.read_text().splitlines()) == 10, "every record of both processes is in the fresh log"
