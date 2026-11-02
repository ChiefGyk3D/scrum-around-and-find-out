# SPDX-License-Identifier: Apache-2.0
"""Run `safo hooks guard` as a real process for the wall-clock tests (support file, not a test).

usage: guard_child.py MODE HOME AGENTS FIFO PAYLOAD_FILE
  MODE synthetic-wedge  the loader is replaced by a call that never returns (a wedged mount or kernel read)
  MODE real-loader      the production loader, untouched (AGENTS may be a FIFO: refused at once)
  MODE hang-append      the log append blocks for good, after the decision is out
  MODE slow-pending / slow-first-notice / slow-marker-dir
                        that one state-folder operation blocks for good, before the decision is emitted
  MODE pre-read-state / pre-claim / pre-save-state / pre-touch
                        a state READ or WRITE before the verdict (probe state, re-probe lock and .attempt, probe-state
                        save, the bound-repository utime) blocks for good; the budget leaves room for a re-probe
  MODE pre-mode         the mode-file read wedges (the real function stays reachable)
  MODE die-at-claim / die-at-clear
                        the process kills itself (SIGKILL) at the claim of the probe notice / the clear of the marker
  MODE plain            nothing patched
  MODE seam             nothing patched: the seams below pick what blocks or fails
  MODE pre-seam         nothing patched, a 0.5 s re-probe request time (a re-probe fits)
Seams (environment): SAFO_CHILD_BARRIER is a path; a BLOCK target waits until that file exists and then runs the real
function. SAFO_CHILD_BLOCK / SAFO_CHILD_FAIL are comma lists of targets `mod.NAME`, `core.NAME` or `guardlog.NAME`
(guardlog.os.open_lock blocks the creation of a lock file); FAIL raises OSError. SAFO_CHILD_NONDAEMON=1 starts a
non-daemon thread that waits for the barrier (a library thread that would keep a normal exit from finishing).
SAFO_CHILD_WITNESS is an existing directory: a file named after each post-delivery step (refresh_bound_repo,
clear_log_failure, claim_notice, append_log, write_log_failed) is created there when that step is entered.
SAFO_CHILD_COLD_START=SECONDS sleeps before safo is imported. SAFO_CHILD_CONFIG_FLOOR=SECONDS sets the least time a
configuration load is given. SAFO_CHILD_ARRIVE_AT=SECONDS waits, after the imports, until the process is that old,
so the guard is reached at that age however slow the interpreter and the imports were (a loaded runner); if it is
already older it does not wait.
The budget is scaled (GUARD_TIMEOUT_SECONDS): SAFO_CHILD_BUDGET seconds when the test gives it (the tests give a
generous one, so a loaded machine cannot eat it), else 5 s, or 10 s (the real one) for the pre-* modes (re-probe room).
SAFO_CHILD_AGE_LOG is a path: every budget computation appends how old the process was at that moment (the cold start
included), so a test can prove the budget counts from the process start with a lower bound, not a race.
Every blocking seam waits for good (an Event with no timeout), so "the decision was delivered" proves the guard did not
wait for it, whatever the speed of the machine.
SAFO_CHILD_NOW is the guard's wall-clock "now" as a Unix timestamp (the tests give meterdata.NOW, the "now" their state
files are written against, so "an attempt a second ago" really rate-limits a re-probe in the child; without it the child
believes it is 2026-01-01 and the whole of a test's state is in its future).
The cold-start seam (SAFO_CHILD_COLD_START) sleeps before safo is imported, as a slow interpreter or disk would.
"""

from __future__ import annotations

import datetime as dt
import importlib
import io
import os
import signal
import sys
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

# A slow cold start (a slow disk or interpreter) happens BEFORE safo is imported, as it would in the real hook; the
# guard's clock must still count it. The imports are therefore made after the sleep.
time.sleep(float(os.environ.get("SAFO_CHILD_COLD_START", "0")))
guardlog = importlib.import_module("safo.guardlog")
core = importlib.import_module("safo.hooks")
mod = importlib.import_module("safo.modes.hooks")
main = importlib.import_module("safo.cli").main
real_mode_health: Callable[..., Any] = guardlog.mode_health

mode, home, agents, fifo, payload_file = sys.argv[1:6]
mod.arm_process_clock()  # what cli.run() does in the real entry: the budget counts from the start of the process
if os.environ.get("SAFO_CHILD_ARRIVE_AT"):  # the age comes from /proc, so waiting here is a late start
    arrive_at = float(os.environ["SAFO_CHILD_ARRIVE_AT"])
    while time.monotonic() - sys.modules["safo"].PROCESS_STARTED < arrive_at:
        time.sleep(0.01)
if os.environ.get("SAFO_CHILD_CONFIG_FLOOR"):  # the subject is a late start, not how fast a loaded box parses YAML
    mod.__dict__["CONFIG_MIN_WAIT_SECONDS"] = float(os.environ["SAFO_CHILD_CONFIG_FLOOR"])
# the scaled budget: the test passes SAFO_CHILD_BUDGET; without it the old defaults (5 s, 10 s for the pre-* modes)
mod.__dict__["GUARD_TIMEOUT_SECONDS"] = float(
    os.environ.get("SAFO_CHILD_BUDGET") or (10 if mode.startswith("pre-") else 5)
)
if os.environ.get("SAFO_CHILD_AGE_LOG"):  # one line per budget computation: how old the process was by then
    age_log = os.environ["SAFO_CHILD_AGE_LOG"]
    real_budget_points = mod.budget_points

    def logged_budget_points(begun: float) -> tuple[float, float, float]:
        with open(age_log, "a") as handle:
            handle.write(f"{time.monotonic() - begun!r}\n")
        points: tuple[float, float, float] = real_budget_points(begun)
        return points

    mod.__dict__["budget_points"] = logged_budget_points
if mode.startswith("pre-"):
    mod.__dict__["REPROBE_TIMEOUT_SECONDS"] = 0.5
    mod.__dict__["CONFIG_REPROBE_TIMEOUT_SECONDS"] = 0.5


def blocked(ctx: object, args: object) -> None:
    os.close(os.open(fifo, os.O_RDONLY))  # blocks until a writer opens the FIFO: never


def hang(*a: object, **k: object) -> None:
    threading.Event().wait()  # wedged for good: only the end of the process (or a kill) frees it


def sleeps(*a: object, **k: object) -> None:
    threading.Event().wait()  # wedged for good, like hang()


def slow_mode_health(env: Mapping[str, str]) -> tuple[str, str]:
    threading.Event().wait()  # wedged: nothing releases this
    result: tuple[str, str] = real_mode_health(env)
    return result


def die(*a: object, **k: object) -> None:
    os.kill(os.getpid(), signal.SIGKILL)


BARRIER = os.environ.get("SAFO_CHILD_BARRIER", "")


def wait_for_barrier() -> None:
    while not os.path.exists(BARRIER):
        time.sleep(0.01)


def blocks(real: Callable[..., Any]) -> Callable[..., Any]:
    def call(*a: Any, **k: Any) -> Any:
        wait_for_barrier()
        return real(*a, **k)

    return call


def fails(*a: Any, **k: Any) -> None:
    raise OSError("injected failure")


class LockCreationBlocks:
    """The `os` module as guardlog sees it, except that creating a lock file waits for the barrier."""

    def __getattr__(self, name: str) -> Any:
        real = getattr(os, name)
        if name != "open":
            return real

        def opened(path: Any, flags: int, *a: Any, **k: Any) -> int:
            if flags & os.O_CREAT and str(path).endswith(".lock"):
                wait_for_barrier()
            return os.open(path, flags, *a, **k)

        return opened


TARGETS: dict[str, Any] = {"mod": mod, "core": core, "guardlog": guardlog}
for target in filter(None, os.environ.get("SAFO_CHILD_BLOCK", "").split(",")):
    if target == "guardlog.os.open_lock":
        guardlog.__dict__["os"] = LockCreationBlocks()
    else:
        owner, name = target.split(".", 1)
        TARGETS[owner].__dict__[name] = blocks(TARGETS[owner].__dict__[name])
for target in filter(None, os.environ.get("SAFO_CHILD_FAIL", "").split(",")):
    owner, name = target.split(".", 1)
    TARGETS[owner].__dict__[name] = fails
WITNESS = os.environ.get("SAFO_CHILD_WITNESS", "")
POST_DELIVERY_STEPS = ("refresh_bound_repo", "clear_log_failure", "claim_notice", "append_log", "write_log_failed")


def witnessed(name: str, real: Callable[..., Any]) -> Callable[..., Any]:
    def call(*a: Any, **k: Any) -> Any:
        Path(WITNESS, name).touch()  # entered, whether or not it then blocks or fails
        return real(*a, **k)

    return call


if WITNESS:  # which post-delivery steps were STARTED: a step that never started cannot have been waited for
    for step in POST_DELIVERY_STEPS:
        mod.__dict__[step] = witnessed(step, mod.__dict__[step])
if os.environ.get("SAFO_CHILD_NONDAEMON"):
    threading.Thread(target=wait_for_barrier, daemon=False).start()


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
elif mode == "pre-mode":
    mod.__dict__["mode_health"] = slow_mode_health
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
    now=dt.datetime.fromtimestamp(float(os.environ["SAFO_CHILD_NOW"]), dt.UTC)
    if os.environ.get("SAFO_CHILD_NOW")
    else dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
    stdin=io.StringIO(Path(payload_file).read_text()),
)
# `safo hooks guard` ends the process through hard_exit (os._exit) on every route, so this line is never reached. If it
# is, the guard returned instead of ending the process, which is a defect: fail loudly, with a distinctive status.
raise SystemExit(f"guard_process returned {code!r} instead of ending the process through hard_exit")
