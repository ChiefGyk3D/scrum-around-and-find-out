# SPDX-License-Identifier: Apache-2.0
"""Run `safo hooks guard` as a real process for the wall-clock tests (support file, not a test).

usage: guard_child.py MODE HOME AGENTS FIFO PAYLOAD_FILE
  MODE synthetic-wedge  the loader is replaced by a call that never returns (a wedged mount or kernel read)
  MODE real-loader      the production loader, untouched (AGENTS may be a FIFO: refused at once)
  MODE hang-append      the log append blocks for a minute, after the decision is out
  MODE slow-pending / slow-first-notice / slow-marker-dir
                        that one state-folder operation blocks for 30 s, before the decision is emitted
  MODE pre-read-state / pre-claim / pre-save-state / pre-touch
                        a state READ or WRITE before the verdict (probe state, re-probe lock and .attempt, probe-state
                        save, the bound-repository utime) blocks for 30 s; a 6 s budget leaves room for a re-probe
  MODE die-at-claim / die-at-clear
                        the process kills itself (SIGKILL) at the claim of the probe notice / the clear of the marker
  MODE plain            nothing patched
The budget is scaled down to 3 s (GUARD_TIMEOUT_SECONDS), so a decision is due well inside 3 s.
"""

from __future__ import annotations

import datetime as dt
import io
import os
import signal
import sys
import time
from pathlib import Path

import safo.hooks as core
from safo.cli import main
from safo.modes import hooks as mod

mode, home, agents, fifo, payload_file = sys.argv[1:6]
mod.__dict__["GUARD_TIMEOUT_SECONDS"] = 6 if mode.startswith("pre-") else 3
if mode.startswith("pre-"):
    mod.__dict__["REPROBE_TIMEOUT_SECONDS"] = 0.5
    mod.__dict__["CONFIG_REPROBE_TIMEOUT_SECONDS"] = 0.5


def blocked(ctx: object, args: object) -> None:
    os.close(os.open(fifo, os.O_RDONLY))  # blocks until a writer opens the FIFO: never


def hang(*a: object, **k: object) -> None:
    time.sleep(60)


def sleeps(*a: object, **k: object) -> None:
    time.sleep(30)


def die(*a: object, **k: object) -> None:
    os.kill(os.getpid(), signal.SIGKILL)


if mode == "synthetic-wedge":
    mod.__dict__["load_agents_for"] = blocked  # a runtime patch of the module attribute, in a test child
elif mode == "hang-append":
    mod.__dict__["append_log"] = hang
elif mode == "slow-pending":
    mod.__dict__["log_failure_pending"] = sleeps
elif mode == "slow-first-notice":
    mod.__dict__["notice_unclaimed"] = sleeps
elif mode == "slow-marker-dir":
    mod.__dict__["marker_dir"] = sleeps
elif mode == "pre-read-state":
    mod.__dict__["read_state"] = sleeps
elif mode == "pre-claim":
    core.__dict__["claim_reprobe"] = sleeps
elif mode == "pre-save-state":
    core.__dict__["save_state"] = sleeps
elif mode == "pre-touch":
    core.__dict__["touch"] = sleeps
elif mode == "die-at-claim":
    mod.__dict__["claim_notice"] = die
elif mode == "die-at-clear":
    mod.__dict__["clear_log_failure"] = die
code = main(
    ["hooks", "guard", "--agents", agents],
    env={"HOME": home, "PATH": ""},
    out=sys.stdout,
    err=sys.stderr,
    now=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
    stdin=io.StringIO(Path(payload_file).read_text()),
)
sys.stdout.flush()
sys.exit(code)
