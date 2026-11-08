# SPDX-License-Identifier: Apache-2.0
"""A signal at every point between "ghw starts" and "ghw is waiting for the child" (round 6, the window review).

A driver process runs `ratebudget.main` with a stand-in gh. A hook pauses it at one named point (file handshake), the
test sends the signal there, then lets it go on. Whatever the point: the wrapper reports (exit 128+N), a child that
exists is gone with its group, a pending signal cannot leave an applied call unreported, and the handlers that were
installed before are back afterwards.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from safo import ratebudget as rb

SRC = str(Path(rb.__file__).resolve().parent.parent)

DRIVER = """
import os, signal, subprocess, sys, time
from pathlib import Path
from safo import ratebudget as rb

STAGE = {stage!r}
DIR = Path({dir!r})


def pause(name):
    (DIR / f"ready-{{name}}").write_text("1")
    deadline = time.monotonic() + 30
    while not (DIR / f"go-{{name}}").exists() and time.monotonic() < deadline:
        time.sleep(0.01)


def custom(signum, frame):
    sys.stderr.write("PREEXISTING-HANDLER-RAN\\n")


for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(s, custom)

real_popen = subprocess.Popen


def popen(*args, **kwargs):
    is_the_call = "--include" in args[0]  # not the account lookup that comes first
    if STAGE == "in-popen" and is_the_call:
        pause(STAGE)
    process = real_popen(*args, **kwargs)
    if is_the_call:
        (DIR / "popen.pid").write_text(str(process.pid))
        if STAGE == "after-popen":
            pause(STAGE)
    return process


subprocess.Popen = popen

if STAGE == "before-launcher":
    real_init = rb._Child.__init__

    def init(self, *args, **kwargs):
        pause(STAGE)
        real_init(self, *args, **kwargs)

    rb._Child.__init__ = init

if STAGE == "recording":
    real_apply = rb.Budget._apply

    def apply(self, state, counters, block, slot, launched=None):
        if launched is not None:
            pause(STAGE)
        return real_apply(self, state, counters, block, slot, launched)

    rb.Budget._apply = apply

if STAGE == "between":
    real_wait = rb._Child.wait

    def wait(self):
        pause(STAGE)
        return real_wait(self)

    rb._Child.wait = wait

if STAGE == "install":
    real_signal = signal.signal
    calls = []

    def counting(number, handler):
        calls.append(number)
        result = real_signal(number, handler)
        if len(calls) == 2:
            pause(STAGE)
        return result

    rb.signal.signal = counting

code = rb.main(
    ["api", "-X", "PATCH", "x/y", "-f", "a=b"], env={env!r}, out=sys.stdout, err=sys.stderr, gh={gh!r}
)
if STAGE == "install":
    rb.signal.signal = real_signal
back = all(signal.getsignal(s) is custom for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP))
sys.stderr.write("HANDLERS-RESTORED=" + str(back) + "\\n")
sys.exit(code)
"""


def gone(pid: int, within: float = 5.0) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.02)
    return False


def wait_for(path: Path, within: float = 15.0) -> None:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"{path.name} never appeared")


def run_stage(tmp_path: Path, stage: str, sig: signal.Signals) -> tuple[int, str, str, int | None]:
    gh = tmp_path / "fake-gh"
    gh.write_text(
        '#!/bin/sh\ncase "$2" in user) echo octocat; exit 0;; esac\n'
        f"echo applied > {tmp_path}/applied\nsleep 60 &\nwait\n"
    )
    gh.chmod(0o755)
    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin", "GH_TOKEN": "tok", "SAFO_CALLER": "win"}
    code = DRIVER.format(stage=stage, dir=str(tmp_path), env=env, gh=str(gh))
    process = subprocess.Popen(  # noqa: S603 - this interpreter, a fixed driver, test-only
        [sys.executable, "-c", code],
        env={"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    wait_for(tmp_path / f"ready-{stage}")
    process.send_signal(sig)
    time.sleep(0.2)  # let the signal reach the process before it is released
    (tmp_path / f"go-{stage}").write_text("1")
    try:
        out, err = process.communicate(timeout=40)
    except subprocess.TimeoutExpired:
        process.kill()
        out, err = process.communicate()
        raise AssertionError(f"the driver hung after the signal: stdout={out!r} stderr={err!r}") from None
    pid_file = tmp_path / "popen.pid"
    pid = int(pid_file.read_text()) if pid_file.exists() else None
    return process.returncode, out, err, pid


SIGNALS = [(signal.SIGINT, 130), (signal.SIGTERM, 143), (signal.SIGHUP, 129)]


@pytest.mark.parametrize(("sig", "code"), SIGNALS)
@pytest.mark.parametrize("stage", ["in-popen", "after-popen", "recording", "between"])
def test_a_signal_after_the_spawn_reports_an_unknown_outcome_and_ends_the_group(
    tmp_path: Path, stage: str, sig: signal.Signals, code: int
) -> None:
    rc, out, err, pid = run_stage(tmp_path, stage, sig)
    assert rc == code
    assert "outcome unknown" in err
    assert "HANDLERS-RESTORED=True" in err
    assert "PREEXISTING-HANDLER-RAN" not in err  # ours ran, not the one from before
    assert out == ""
    assert pid is not None
    assert gone(pid)
    ledger = tmp_path / ".local" / "state" / "safo" / "ratebudget" / "ledger.jsonl"
    assert '"status":0' in ledger.read_text()


@pytest.mark.parametrize(("sig", "code"), SIGNALS)
def test_a_signal_before_the_launcher_starts_sends_nothing(tmp_path: Path, sig: signal.Signals, code: int) -> None:
    rc, _out, err, pid = run_stage(tmp_path, "before-launcher", sig)
    assert rc == code
    assert "nothing was sent" in err
    assert "HANDLERS-RESTORED=True" in err
    assert not (tmp_path / "applied").exists()
    assert pid is None  # the launcher never started a child


@pytest.mark.parametrize(("sig", "code"), SIGNALS)
def test_a_signal_while_the_handlers_are_being_installed_is_held_until_all_are_in(
    tmp_path: Path, sig: signal.Signals, code: int
) -> None:
    rc, _out, err, pid = run_stage(tmp_path, "install", sig)
    assert rc == code
    assert "HANDLERS-RESTORED=True" in err
    assert "PREEXISTING-HANDLER-RAN" not in err
    assert "nothing was sent" in err
    assert not (tmp_path / "applied").exists()
    assert pid is None


def test_a_child_is_not_started_once_a_signal_is_pending(monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[int] = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: started.append(1))
    guard = rb._SignalGuard()
    guard.pending = signal.SIGTERM
    monkeypatch.setattr(rb, "_ACTIVE", guard)
    with pytest.raises(rb.Interrupted):
        rb._Child(["true"], None)
    assert started == []
