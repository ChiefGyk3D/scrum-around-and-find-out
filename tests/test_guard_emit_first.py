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

from hooksdata import agents_file, dispatch, hooks, read_log, set_mode, set_probe, state_folder
from meterdata import NOW
from safo.context import LocalContext
from safo.guardlog import APPEND_LOCK_TIMEOUT, file_lock
from safo.hooks import append_log, log_record
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
def test_a_config_load_blocked_on_a_fifo_still_prints_a_decision_inside_the_budget_in_a_real_process(
    _private_home: Path, agents: Path, tmp_path: Path, payload: str
) -> None:
    fifo = tmp_path / "agents.fifo"
    os.mkfifo(fifo)
    body = tmp_path / "payload.json"
    body.write_text(dispatch(model=None) if payload == "agent" else bash("sleep 60"))
    set_mode(_private_home, "block")
    started = time.monotonic()
    pid, fd = spawn("fifo-load", _private_home, agents, fifo, body)
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
    # The budget is 3 s here (deadline 1 s, hard 2 s); the interpreter start is the slack. The load blocked for ever.
    assert elapsed < 3 + 1.5, f"{elapsed:.1f} s: the decision must land inside the (scaled) budget"


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
    assert (folder / "log.jsonl.1").read_bytes() == b"\xff\npartial", "undecodable bytes are kept as corruption"
    assert read_log(_private_home)[-1]["rules"] == ["lead-waits"]
    assert not marker(_private_home).exists(), "the append worked after the rotation"


def test_append_log_treats_undecodable_retained_bytes_as_corruption(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    path.write_bytes(b"\xff\npartial")
    path.chmod(0o600)
    tmp_path.chmod(0o700)
    record = log_record("2026-01-01T00:00:00", "allow", "warn", None, False, "healthy", "")
    append_log(path, record)
    assert path.with_name("log.jsonl.1").read_bytes() == b"\xff\npartial"
    assert json.loads(path.read_text())["decision"] == "allow"


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
