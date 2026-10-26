# SPDX-License-Identifier: Apache-2.0
"""Run `safo hooks guard` as a real process for the wall-clock tests (support file, not a test).

usage: guard_child.py MODE HOME AGENTS FIFO PAYLOAD_FILE
  MODE synthetic-wedge  the loader is replaced by a call that never returns (a wedged mount or kernel read)
  MODE real-loader      the production loader, untouched (AGENTS may be a FIFO: refused at once)
  MODE hang-append      the log append blocks for a minute, after the decision is out
  MODE slow-pending / slow-first-notice / slow-marker-dir
                        that one state-folder operation blocks for 30 s, before the decision is emitted
The budget is scaled down to 3 s (GUARD_TIMEOUT_SECONDS), so a decision is due well inside 3 s.
"""

from __future__ import annotations

import datetime as dt
import io
import os
import sys
import time
from pathlib import Path

from safo.cli import main
from safo.modes import hooks as mod

mode, home, agents, fifo, payload_file = sys.argv[1:6]
mod.__dict__["GUARD_TIMEOUT_SECONDS"] = 3


def blocked(ctx: object, args: object) -> None:
    os.close(os.open(fifo, os.O_RDONLY))  # blocks until a writer opens the FIFO: never


def hang(*a: object, **k: object) -> None:
    time.sleep(60)


def sleeps(*a: object, **k: object) -> None:
    time.sleep(30)


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
