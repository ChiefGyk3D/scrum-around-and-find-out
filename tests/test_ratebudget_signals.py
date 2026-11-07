# SPDX-License-Identifier: Apache-2.0
"""A signal sent to ghw while its gh child runs: the whole child group goes, and the outcome is reported unknown.

Real processes: a driver runs `ratebudget.main` against a stand-in gh script that records its own pid and that of a
background grandchild, then waits. The test signals the driver and checks both pids are gone.
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
import sys
from safo import ratebudget as rb
code = rb.main(
    ["api", "-X", "PATCH", "x/y", "-f", "a=b"], env={env!r}, out=sys.stdout, err=sys.stderr, gh={gh!r}
)
sys.exit(code)
"""


def gone(pid: int, within: float = 3.0) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.02)
    return False


def read_pid(path: Path, within: float = 10.0) -> int:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        if path.exists() and path.read_text().strip().isdigit():
            return int(path.read_text())
        time.sleep(0.02)
    raise AssertionError(f"{path.name} never appeared")


def start_driver(tmp_path: Path, gh_body: str) -> tuple[subprocess.Popen[str], Path, Path]:
    gh = tmp_path / "fake-gh"
    pid_child, pid_grandchild = tmp_path / "child.pid", tmp_path / "grandchild.pid"
    gh.write_text(
        "#!/bin/sh\n"
        'case "$2" in user) echo octocat; exit 0;; esac\n'
        f"echo $$ > {pid_child}.tmp && mv {pid_child}.tmp {pid_child}\n"
        f"{gh_body}\n"
    )
    gh.chmod(0o755)
    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin", "GH_TOKEN": "tok", "SAFO_CALLER": "sig"}
    code = DRIVER.format(env=env, gh=str(gh))
    process = subprocess.Popen(  # noqa: S603 - this interpreter, a fixed driver script, test-only
        [sys.executable, "-c", code],
        env={"PYTHONPATH": SRC, "PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return process, pid_child, pid_grandchild


@pytest.mark.parametrize(
    ("sig", "code"),
    [(signal.SIGINT, 130), (signal.SIGTERM, 143), (signal.SIGHUP, 129)],
)
def test_a_signal_ends_the_whole_child_group_and_reports_an_unknown_outcome(
    tmp_path: Path, sig: signal.Signals, code: int
) -> None:
    body = f"sleep 60 & echo $! > {tmp_path}/grandchild.pid\nwait"
    process, pid_child, pid_grandchild = start_driver(tmp_path, body)
    child = read_pid(pid_child)
    grandchild = read_pid(pid_grandchild)
    sent = time.monotonic()
    process.send_signal(sig)
    out, err = process.communicate(timeout=20)
    assert (
        time.monotonic() - sent < rb.SIGNAL_GRACE_SECONDS - 1
    )  # forwarded, so the child ended at once, not at SIGKILL
    assert process.returncode == code
    assert "outcome unknown" in err
    assert "not retried" in err
    assert gone(child)
    assert gone(grandchild)
    ledger = tmp_path / ".local" / "state" / "safo" / "ratebudget" / "ledger.jsonl"
    assert '"status":0' in ledger.read_text()  # recorded as an unknown outcome, not as a result
    assert out == ""


def test_a_child_that_ignores_the_signal_is_killed_after_the_grace_period(
    tmp_path: Path,
) -> None:
    body = f"trap '' INT TERM HUP\nsleep 60 & echo $! > {tmp_path}/grandchild.pid\nwhile :; do wait; done"
    process, pid_child, pid_grandchild = start_driver(tmp_path, body)
    child = read_pid(pid_child)
    grandchild = read_pid(pid_grandchild)
    started = time.monotonic()
    process.send_signal(signal.SIGTERM)
    _out, err = process.communicate(timeout=30)
    assert time.monotonic() - started < rb.SIGNAL_GRACE_SECONDS + 10
    assert process.returncode == 143
    assert "outcome unknown" in err
    assert gone(child)
    assert gone(grandchild)


def test_the_handlers_are_restored_after_a_normal_run(tmp_path: Path) -> None:
    gh = tmp_path / "fake-gh"
    gh.write_text('#!/bin/sh\ncase "$2" in user) echo octocat;; *) printf "HTTP/2.0 200 OK\\r\\n\\r\\nok";; esac\n')
    gh.chmod(0o755)
    before = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    from io import StringIO

    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin", "GH_TOKEN": "tok"}
    assert rb.main(["api", "-X", "PATCH", "x/y", "-f", "a=b"], env=env, out=StringIO(), err=StringIO(), gh=str(gh)) == 0
    assert {s: signal.getsignal(s) for s in before} == before
