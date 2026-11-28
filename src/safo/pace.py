# SPDX-License-Identifier: Apache-2.0
"""Weekly pace reader: the routing mode (`normal` ... `lockdown`, or `unknown`) from the Claude usage cache.

The status line writes `~/.cache/safo/claude-usage.json`: `windows: [{label, used_percent, resets_at, captured_at}]`.
This module reads that file and turns the `weekly` row into numbers and a mode. It never touches the network and never
decides anything about security work: `route` returns Daybreak (`D`) for `security-review` before it looks at the mode.

    elapsed_pct = 100 * (now - (resets_at - 7 days)) / 7 days      clamped to 0..100
    pace        = used_percent / max(elapsed_pct, 5)               1.0 is exactly even

Modes, entered at once and left one level at a time (two readings at least 10 minutes apart below the leave line):

    shift    enter pace >= 0.90        leave pace < 0.80
    lean     enter pace >= 1.00        leave pace < 0.92
    hard     enter pace >= 1.30 or used >= 85      leave pace < 1.15 and used < 80
    lockdown enter any window at 100 percent       leave when no window is at 100 percent

In the first 5 percent of the week the mode is capped at `shift` unless used >= 15 percent. A missing, unreadable,
invalid, stale (over 30 minutes) or rolled-over cache gives `unknown`: the reason is reported, never a guess.
The CLI prints one line and always exits 0, so a broken reader can never block a caller.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from safo import bounded, output

WEEK_SECONDS = 7 * 24 * 3600
STALE_SECONDS = 30 * 60
FUTURE_SKEW_SECONDS = 5 * 60
STEP_DOWN_GAP_SECONDS = 10 * 60
ELAPSED_FLOOR_PCT = 5.0
EARLY_WEEK_USED_PCT = 15.0
CAP_PCT = 100.0

LADDER = ("normal", "shift", "lean", "hard", "lockdown")
MODES = (*LADDER, "unknown")

SHIFT_ENTER = 0.90
SHIFT_LEAVE = 0.80
LEAN_ENTER = 1.00
LEAN_LEAVE = 0.92
HARD_ENTER = 1.30
HARD_ENTER_USED = 85.0
HARD_LEAVE = 1.15
HARD_LEAVE_USED = 80.0

SECURITY_REVIEW = "security-review"
# Routes: L local model, X Codex general model, D Codex Daybreak tier, C Claude, S script (design section 4.1).
_ROUTES: dict[str, tuple[str, str, str, str, str]] = {  # normal, shift, lean, hard, lockdown
    "public-copy": ("X", "X", "X", "X", "X"),
    "text-local": ("L", "L", "L", "L", "L"),
    "implementer-specified": ("C", "X", "X", "X", "X"),
    "second-review": ("C", "X", "X", "X", "X"),
    "mechanical": ("C", "C", "C", "L", "X"),
    "design-judgment": ("C", "C", "C", "C", "C"),
    "merge-ci-wait": ("S", "S", "S", "S", "S"),
}


def route(task_class: str, mode: object) -> str:
    """The engine for one task class. The security class returns D before the mode is looked at, in any mode."""
    if task_class == SECURITY_REVIEW:
        return "D"
    row = _ROUTES.get(task_class)
    if row is None:
        raise ValueError(f"unknown task class: {task_class!r}")
    return row[LADDER.index(mode)] if mode in LADDER else row[0]  # unknown routes like normal (design section 6)


@dataclass(frozen=True)
class Decision:
    mode: str
    reason: str  # "ok" or why the mode is unknown
    pace: float | None = None
    used: float | None = None
    elapsed: float | None = None
    age: float | None = None


def _num(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        return None
    return float(value)


def _pick_weekly(data: object) -> tuple[dict[str, Any] | None, list[float]]:
    """The newest `weekly` row (highest captured_at; several sessions share one account), and every window's used%."""
    if not isinstance(data, Mapping) or not isinstance(data.get("windows"), Sequence):
        return None, []
    rows = [w for w in data["windows"] if isinstance(w, Mapping)]
    used_all = [u for u in (_num(w.get("used_percent")) for w in rows) if u is not None]
    weekly = [w for w in rows if w.get("label") == "weekly" and _num(w.get("captured_at")) is not None]
    if not weekly:
        return None, used_all
    return dict(max(weekly, key=lambda w: float(w["captured_at"]))), used_all


def _raw_mode(pace: float, used: float, elapsed: float, any_full: bool) -> str:
    if any_full:
        return "lockdown"
    if pace >= HARD_ENTER or used >= HARD_ENTER_USED:
        mode = "hard"
    elif pace >= LEAN_ENTER:
        mode = "lean"
    elif pace >= SHIFT_ENTER:
        mode = "shift"
    else:
        mode = "normal"
    if elapsed < ELAPSED_FLOOR_PCT and used < EARLY_WEEK_USED_PCT and LADDER.index(mode) > 1:
        mode = "shift"  # early-week cap: a spike in the first hours is not a trend
    return mode


def _leave_ok(mode: str, pace: float, used: float, any_full: bool) -> bool:
    if mode == "shift":
        return pace < SHIFT_LEAVE
    if mode == "lean":
        return pace < LEAN_LEAVE
    if mode == "hard":
        return pace < HARD_LEAVE and used < HARD_LEAVE_USED
    if mode == "lockdown":
        return not any_full
    return False


def _unknown(reason: str, age: float | None = None) -> Decision:
    return Decision("unknown", reason, age=age)


def decide(data: object, now: float, state: Mapping[str, Any] | None = None) -> tuple[Decision, dict[str, Any]]:
    """Pure: the cache content, the time and the saved state in; the decision and the new state out."""
    state = dict(state or {})
    row, used_all = _pick_weekly(data)
    if row is None:
        return _unknown("no-weekly-row"), state
    captured, resets, used = _num(row.get("captured_at")), _num(row.get("resets_at")), _num(row.get("used_percent"))
    if captured is None or resets is None or used is None:
        return _unknown("bad-field"), state
    age = now - captured
    if age < -FUTURE_SKEW_SECONDS:
        return _unknown("captured-in-future"), state
    if not 0.0 <= used <= CAP_PCT:
        return _unknown("used-out-of-range", age), state
    if now >= resets:
        return _unknown("rolled-over", age), {}  # last week's hysteresis must not carry into the new window
    if resets - now > WEEK_SECONDS:
        return _unknown("resets-too-far", age), state
    if age > STALE_SECONDS:
        return _unknown("stale", age), state
    age = max(age, 0.0)
    elapsed = min(max(100.0 * (now - (resets - WEEK_SECONDS)) / WEEK_SECONDS, 0.0), 100.0)
    pace = round(used / max(elapsed, ELAPSED_FLOOR_PCT), 9)
    any_full = any(u >= CAP_PCT for u in used_all)
    raw = _raw_mode(pace, used, elapsed, any_full)
    cur = state.get("mode")
    pending = _num(state.get("pending_since"))
    if cur not in LADDER or LADDER.index(raw) >= LADDER.index(cur):
        mode, pending = raw, None  # step up immediately
    elif _leave_ok(cur, pace, used, any_full):
        if pending is None:
            mode, pending = cur, now  # first reading below the leave line
        elif now - pending >= STEP_DOWN_GAP_SECONDS:
            mode, pending = LADDER[LADDER.index(cur) - 1], None  # second one, far enough apart: one level down
        else:
            mode = cur
    else:
        mode, pending = cur, None
    new_state = {"mode": mode, "pending_since": pending, "updated": now}
    return Decision(mode, "ok", pace, used, elapsed, age), new_state


def default_cache_path() -> Path:
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "safo" / "claude-usage.json"


def default_state_path() -> Path:
    return Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "safo" / "pace-mode.json"


def read_json(path: Path) -> object:
    """The parsed file, or None when it is missing, unreadable or not JSON (the caller reads that as unknown)."""
    try:
        return bounded.read_json(path)
    except (OSError, ValueError):
        return None


def save_state(path: Path, state: Mapping[str, Any]) -> None:
    """Atomic replace, mode 0600. A failure to save is ignored: hysteresis is lost, the mode is still right."""
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle)
        os.replace(tmp, path)
    except OSError:
        tmp.unlink(missing_ok=True)


def format_line(d: Decision) -> str:
    def fmt(value: float | None, spec: str) -> str:
        return "-" if value is None else format(value, spec)

    line = (
        f"mode={d.mode} pace={fmt(d.pace, '.2f')}{'' if d.pace is None else 'x'} used={fmt(d.used, '.0f')}"
        f" elapsed={fmt(d.elapsed, '.1f')} age={fmt(d.age, '.0f')}"
    )
    return line if d.reason == "ok" else f"{line} reason={d.reason}"


def run(argv: Sequence[str] | None = None, now: float | None = None) -> int:
    parser = argparse.ArgumentParser(prog="safo-pace", description="Print the weekly pace routing mode on one line.")
    parser.add_argument("--json", action="store_true", help="print the decision as one JSON object")
    parser.add_argument(
        "--cache", type=Path, default=None, help="usage cache (default ~/.cache/safo/claude-usage.json)"
    )
    parser.add_argument("--state", type=Path, default=None, help="hysteresis state (default ~/.local/state/safo)")
    parser.add_argument("--no-state", action="store_true", help="do not read or write the hysteresis state")
    try:
        args = parser.parse_args(argv)
        t = time.time() if now is None else now
        data = read_json(args.cache or default_cache_path())
        state_path = None if args.no_state else (args.state or default_state_path())
        saved = read_json(state_path) if state_path else None
        decision, new_state = decide(data, t, saved if isinstance(saved, Mapping) else None)
        if state_path is not None and new_state != (saved if isinstance(saved, Mapping) else {}):
            save_state(state_path, new_state)
        output.write(sys.stdout, json.dumps(decision.__dict__) if args.json else format_line(decision))
    except SystemExit:
        raise
    except Exception:  # a broken reader must never block its caller: report unknown, exit 0
        output.write(sys.stdout, "mode=unknown pace=- used=- elapsed=- age=- reason=error")
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
