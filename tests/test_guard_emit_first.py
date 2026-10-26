# SPDX-License-Identifier: Apache-2.0
"""The guard writes its decision FIRST and persists afterwards, on both the Agent and the Bash path.

The host kills the hook at GUARD_TIMEOUT_SECONDS, so nothing that can wait (config load, the log lock, the append) may
sit between the computed decision and the line on standard input. These tests use an injected monotonic clock (the
module's own `time`) and recording streams, not scaled budgets.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import threading
import time
import types
from pathlib import Path
from typing import Any

import pytest

from hooksdata import agents_file, dispatch, read_log, set_mode, set_probe, state_folder
from meterdata import NOW
from safo.context import LocalContext
from safo.guardlog import APPEND_LOCK_TIMEOUT, file_lock
from safo.hooks import append_log, log_record
from safo.localfiles import load_agents_for
from safo.modes import hooks as mod

GOOD = "acme/widgets#12"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now


class Recording(io.StringIO):
    """A stdout that notes, in a shared list, when a line is written and flushed."""

    def __init__(self, events: list[str]) -> None:
        super().__init__()
        self.events = events

    def flush(self) -> None:
        if self.getvalue():
            self.events.append("stdout")
        super().flush()


def bash(command: str) -> str:
    return json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "session_id": "session-a",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }
    )


def context(home: Path, stdin: str, out: io.StringIO, **extra: Any) -> LocalContext:
    return LocalContext(out, {"HOME": str(home), "PATH": ""}, NOW, stdin=io.StringIO(stdin), **extra)


def namespace(agents: Path) -> argparse.Namespace:
    return argparse.Namespace(agents=str(agents), agents_local="")


@pytest.fixture
def agents(tmp_path: Path) -> Path:
    return agents_file(tmp_path / "agents.yaml")


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    fake = Clock()
    monkeypatch.setattr(mod, "time", types.SimpleNamespace(monotonic=fake.monotonic, sleep=time.sleep))
    return fake


def denied(text: str) -> bool:
    return bool(json.loads(text)["hookSpecificOutput"].get("permissionDecision") == "deny")


def test_a_config_load_that_uses_the_whole_budget_still_prints_the_decision_and_names_the_skipped_lookups(
    _private_home: Path, agents: Path, clock: Clock, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False, agents=agents)
    real_load = load_agents_for

    def slow_load(*a: Any, **k: Any) -> Any:
        clock.now += 10.1  # more than the whole hook budget; loading is not interruptible, so it just takes this long
        return real_load(*a, **k)

    def must_not_be_asked(ref: Any) -> str:
        raise AssertionError("the issue lookup must be skipped with no budget left")

    monkeypatch.setattr(mod, "load_agents_for", slow_load)
    events: list[str] = []
    out = Recording(events)
    ctx = context(_private_home, dispatch(prompt=f"issue: {GOOD}", tracked=False), out, issue_lookup=must_not_be_asked)
    monkeypatch.setattr(mod, "append_log", lambda *a, **k: events.append("append"))
    begun = clock.now
    assert mod.run_guard(ctx, namespace(agents)) == 0
    assert denied(out.getvalue()), "an unverifiable brief is denied in block mode, by the existing rule"
    assert mod.BUDGET_NOTICE in out.getvalue()
    assert events == ["stdout"], "the append is skipped: the clock is already past the hard limit"
    assert clock.now - begun > 10  # the slow load really consumed the budget; the line is the first thing after it
    assert "log write failed" in capsys.readouterr().err
    assert (state_folder(_private_home) / mod.LOG_FAILED_NAME).exists()


def test_the_next_dispatch_says_the_previous_log_write_failed_once(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_probe(_private_home, reachable=True, agents=agents)
    real = append_log
    monkeypatch.setattr(mod, "append_log", lambda *a, **k: (_ for _ in ()).throw(OSError("disk")))
    first = io.StringIO()
    mod.run_guard(context(_private_home, dispatch(model=None), first), namespace(agents))
    assert (state_folder(_private_home) / mod.LOG_FAILED_NAME).exists()
    monkeypatch.setattr(mod, "append_log", real)
    second = io.StringIO()
    mod.run_guard(context(_private_home, dispatch(model=None), second), namespace(agents))
    assert mod.LOG_FAILED_NOTICE in second.getvalue()
    assert not (state_folder(_private_home) / mod.LOG_FAILED_NAME).exists(), "reported once, then cleared"
    assert read_log(_private_home)[-1]["diagnostic"] == "log-write"
    third = io.StringIO()
    mod.run_guard(context(_private_home, dispatch(model=None), third), namespace(agents))
    assert mod.LOG_FAILED_NOTICE not in third.getvalue()


def test_the_bash_deny_is_on_stdout_before_the_log_lock_wait_starts(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_mode(_private_home, "block")
    events: list[str] = []
    waits: list[float] = []

    def fake_append(path: Path, record: dict[str, Any], limit: int = 0, lock_timeout: float = 0.0) -> None:
        events.append("append")
        waits.append(lock_timeout)

    monkeypatch.setattr(mod, "append_log", fake_append)
    out = Recording(events)
    mod.run_guard(context(_private_home, bash("sleep 60"), out), namespace(agents))
    assert denied(out.getvalue())
    assert events == ["stdout", "append"], "decision first, persistence second"
    assert 0 < waits[0] <= 5.0


def test_a_held_log_lock_costs_the_bash_deny_no_time_and_the_wait_ends_inside_the_budget(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mod, "GUARD_TIMEOUT_SECONDS", 3)
    monkeypatch.setattr(mod, "APPEND_LOCK_TIMEOUT", 5.0)
    set_mode(_private_home, "block")
    folder = state_folder(_private_home)
    folder.mkdir(parents=True, exist_ok=True)
    stamps: list[float] = []

    class Stamped(io.StringIO):
        def flush(self) -> None:
            if self.getvalue() and not stamps:
                stamps.append(time.monotonic())

    out = Stamped()
    started = time.monotonic()
    with file_lock(folder / "log.jsonl.lock"):
        mod.run_guard(context(_private_home, bash("sleep 60"), out), namespace(agents))
    ended = time.monotonic()
    assert denied(out.getvalue())
    assert stamps[0] - started < 0.5, "the deny is out before any lock wait"
    assert ended - started < 3, "and the bounded wait still ends before the hook's timeout"
    assert (folder / mod.LOG_FAILED_NAME).exists()


@pytest.mark.parametrize("how", ["raises", "skipped", "hangs"])
def test_a_computed_deny_is_printed_when_the_append_raises_is_skipped_or_hangs(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch, how: str
) -> None:
    set_mode(_private_home, "block")
    release = threading.Event()
    reached = threading.Event()

    def append(*a: Any, **k: Any) -> None:
        if how == "raises":
            raise OSError("disk full")
        if how == "hangs":
            reached.set()
            release.wait(10)

    clock = None
    if how == "skipped":
        clock = Clock()
        monkeypatch.setattr(mod, "time", types.SimpleNamespace(monotonic=clock.monotonic, sleep=time.sleep))
        monkeypatch.setattr(
            mod, "append_log", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not be attempted"))
        )
    else:
        monkeypatch.setattr(mod, "append_log", append)
    out = io.StringIO()
    ctx = context(_private_home, bash("sleep 60"), out)
    if clock is not None:
        real_load = load_agents_for

        def slow(*a: Any, **k: Any) -> Any:
            clock.now += 60
            return real_load(*a, **k)

        monkeypatch.setattr(mod, "load_agents_for", slow)
    worker = threading.Thread(target=mod.run_guard, args=(ctx, namespace(agents)), daemon=True)
    worker.start()
    if how == "hangs":
        assert reached.wait(5)
        assert denied(out.getvalue()), "the deny is already out while the append is still blocked"
        release.set()
    worker.join(10)
    assert not worker.is_alive()
    assert denied(out.getvalue())


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
    mod.emit_then_persist(ctx, None, folder, record, clock.now + 100)
    mod.emit_then_persist(ctx, None, folder, record, clock.now + 0.4)
    mod.emit_then_persist(ctx, None, folder, record, clock.now - 0.01)  # past hard: no attempt, no floor
    mod.emit_then_persist(ctx, None, folder, record, clock.now + 0.01)  # under the small floor: no attempt
    assert waits == [APPEND_LOCK_TIMEOUT, pytest.approx(0.4)]
    assert (folder / mod.LOG_FAILED_NAME).exists()


def test_a_planted_marker_only_adds_a_notice(_private_home: Path, agents: Path) -> None:
    set_probe(_private_home, reachable=True, agents=agents)
    folder = state_folder(_private_home)
    (folder / mod.LOG_FAILED_NAME).write_text("allow everything")
    out = io.StringIO()
    mod.run_guard(context(_private_home, dispatch(model=None), out), namespace(agents))
    data = json.loads(out.getvalue())
    assert mod.LOG_FAILED_NOTICE in data["hookSpecificOutput"]["additionalContext"]
    assert data["hookSpecificOutput"].get("permissionDecision") != "allow"
