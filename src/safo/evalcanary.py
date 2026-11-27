# SPDX-License-Identifier: Apache-2.0
"""safo-eval-canary: catch a silent drop in local-model quality (#540).

    safo-eval-canary [--baseline PATH] [--threshold 0.10] [--tasks all] [--repeats 1] [--update-baseline]

Runs the safo-eval fixtures on both configured local models (the two `safo-draft` models; no name is repeated here),
scores each model as its pass rate, and compares it with a stored baseline. Exit codes:

    0  every score is within the threshold of its baseline (or the baseline was written)
    1  a score dropped by more than the threshold: one `ALERT` line on stderr
    2  usage, baseline or fixture problem (a hostile or missing baseline is never read as a pass)
    3  a server was unreachable: reported, never scored as zero, never written to the baseline
    75 the queue stayed busy: retried, then reported; never read as a drop

The baseline is written only with `--update-baseline`, and only when every model produced a score.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import re
import stat
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from safo import bounded, localdraft, output
from safo import localeval as le

EXIT_OK, EXIT_DROP, EXIT_USAGE, EXIT_UNREACHABLE, EXIT_BUSY = 0, 1, 2, 3, 75
DEFAULT_THRESHOLD = 0.10  # an absolute drop in pass rate (0.10 = ten points)
DEFAULT_BASELINE = Path.home() / ".local/share/safo/eval-canary-baseline.json"
MAX_BASELINE_BYTES = 64 * 1024
MAX_MODELS = 16
BASELINE_VERSION = 1
BUSY_SLEEP = 30.0
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}")
_MODEL_FAILURES = ("exit 3", "exit 4")  # the model's own failure (truncated, over the cap): counted as not passed

Runner = Callable[[Any, str], dict[str, Any]]


class CanaryError(Exception):
    """A usage or baseline problem: shown, exit 2."""


def canary_models() -> tuple[str, ...]:
    """The two configured local models, read from the safo-draft config constants."""
    return tuple(dict.fromkeys((localdraft.DRAFT_MODEL, localdraft.DIGEST_MODEL)))


def _score_value(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise CanaryError("baseline: a score is not a number")
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise CanaryError("baseline: a score is outside 0 to 1")
    return float(value)


def read_baseline(path: Path) -> dict[str, float]:
    try:
        raw = bounded.read_bounded(path, MAX_BASELINE_BYTES + 1)
    except FileNotFoundError as exc:
        raise CanaryError("no baseline file; run once with --update-baseline") from exc
    except OSError as exc:  # a symlink (ELOOP), a FIFO or other special file, a permission error
        raise CanaryError("baseline is a symlink, not a regular file, or cannot be opened") from exc
    if len(raw) > MAX_BASELINE_BYTES:
        raise CanaryError("baseline is over the size cap")
    try:
        doc = bounded.loads(raw, MAX_BASELINE_BYTES)
    except ValueError as exc:  # includes duplicate keys, bad constants, bad UTF-8, depth
        raise CanaryError("baseline is not valid JSON") from exc
    if not isinstance(doc, dict) or doc.get("version") != BASELINE_VERSION or set(doc) != {"version", "scores"}:
        raise CanaryError("baseline has the wrong shape or version")
    scores = doc["scores"]
    if not isinstance(scores, dict) or not 0 < len(scores) <= MAX_MODELS:
        raise CanaryError("baseline scores are not a small object")
    out: dict[str, float] = {}
    for name, value in scores.items():
        if not isinstance(name, str) or not _MODEL.fullmatch(name) or ".." in name:
            raise CanaryError("baseline holds a bad model name")
        out[name] = _score_value(value)
    return out


def write_baseline(path: Path, scores: dict[str, float]) -> None:
    """Replace the baseline atomically with mode 0600; never through a symlink, never over a special file."""
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        mode = None
    if mode is not None and not stat.S_ISREG(mode):
        raise CanaryError("refusing to replace a baseline that is a symlink or not a regular file")
    parent = path.parent
    if parent.is_symlink():
        raise CanaryError("refusing to write the baseline through a symlinked folder")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = parent / f".{path.name}.{os.getpid()}.tmp"
    text = json.dumps({"version": BASELINE_VERSION, "scores": scores}, indent=1, sort_keys=True) + "\n"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise CanaryError(f"cannot write the baseline: {exc.strerror}") from exc


def _classify(records: Sequence[dict[str, Any]]) -> tuple[str, float | None]:
    """('ok', score) | ('unreachable', None) | ('busy', None). Busy runs are left out of the rate."""
    passed = scored = busy = 0
    for rec in records:
        status = rec.get("status")
        if status == "busy":
            busy += 1
        elif status == "ok":
            scored += 1
            passed += 1 if rec.get("score", {}).get("passed") is True else 0
        elif status == "failed" and str(rec.get("error", "")).startswith(_MODEL_FAILURES):
            scored += 1
        else:  # any other failure: the server, the wrapper or the call did not work; not a quality signal
            return "unreachable", None
    if scored == 0:
        return ("busy" if busy else "unreachable"), None
    return "ok", passed / scored


def measure(
    model: str, fixtures: Sequence[Any], repeats: int, runner: Runner, busy_retries: int, sleep: Callable[[float], None]
) -> tuple[str, float | None]:
    state: tuple[str, float | None] = ("busy", None)
    for attempt in range(busy_retries + 1):
        records = [runner(fx, model) for _ in range(repeats) for fx in fixtures]
        state = _classify(records)
        if state[0] != "busy":
            return state
        if attempt < busy_retries:
            sleep(BUSY_SLEEP * 2**attempt)
    return state


def _default_runner(wait: int) -> Runner:
    return lambda fx, model: le.run_one(fx, model, wait=wait)


def _threshold(text: str) -> float:
    try:
        value = float(text)
    except ValueError as exc:
        raise CanaryError("--threshold is not a number") from exc
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise CanaryError("--threshold must be between 0 and 1")
    return value


def entry(argv: Sequence[str] | None = None, *, runner: Runner | None = None, sleep: Any = time.sleep) -> int:
    ap = argparse.ArgumentParser(prog="safo-eval-canary", description="Alert when local-model quality drops.")
    ap.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    ap.add_argument("--threshold", default=str(DEFAULT_THRESHOLD), help="largest allowed drop in pass rate (0 to 1)")
    ap.add_argument("--tasks", default="all")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--fixtures", type=Path, default=le.FIXTURES_DEFAULT)
    ap.add_argument("--wait", type=int, default=120)
    ap.add_argument("--busy-retries", type=int, default=3)
    ap.add_argument("--update-baseline", action="store_true", help="write the new scores as the baseline")
    args = ap.parse_args(argv)
    try:
        threshold = _threshold(args.threshold)
        if args.repeats < 1 or args.busy_retries < 0 or args.wait < 0:
            raise CanaryError("--repeats must be at least 1; --busy-retries and --wait at least 0")
        tasks = None if args.tasks == "all" else [t.strip() for t in args.tasks.split(",")]
        bad = [t for t in tasks or [] if t not in le.TASKS]
        if bad:
            raise CanaryError("unknown task name")
        baseline = {} if args.update_baseline else read_baseline(args.baseline)
        models = canary_models()
        if not args.update_baseline and not set(models) <= set(baseline):
            raise CanaryError("baseline has no score for a configured model; run with --update-baseline")
        try:
            fixtures = le.load_fixtures(args.fixtures, tasks)
        except le.EvalError as exc:
            raise CanaryError(str(exc)) from exc
        call = runner or _default_runner(args.wait)
        results = {m: measure(m, fixtures, args.repeats, call, args.busy_retries, sleep) for m in models}
        unreachable = [m for m, (s, _) in results.items() if s == "unreachable"]
        busy = [m for m, (s, _) in results.items() if s == "busy"]
        if args.update_baseline:
            if unreachable or busy:
                output.write(sys.stderr, _problem_line(unreachable, busy) + " (baseline not written)")
                return EXIT_UNREACHABLE if unreachable else EXIT_BUSY
            write_baseline(args.baseline, {m: round(float(results[m][1] or 0.0), 4) for m in models})
            output.write(sys.stdout, "eval-canary: baseline written for " + ", ".join(models))
            return EXIT_OK
        drops = [
            f"{m} {baseline[m]:.2f} -> {score:.2f} (-{baseline[m] - score:.2f})"
            for m, (state, score) in results.items()
            if state == "ok" and score is not None and baseline[m] - score > threshold
        ]
        if unreachable or busy:
            output.write(sys.stderr, _problem_line(unreachable, busy))
        if drops:
            output.write(sys.stderr, f"ALERT eval-canary: quality drop over {threshold:.2f}: " + "; ".join(drops))
            return EXIT_DROP
        if unreachable:
            return EXIT_UNREACHABLE
        if busy:
            return EXIT_BUSY
        output.write(
            sys.stdout, "eval-canary: ok " + ", ".join(f"{m} {s:.2f}" for m, (_, s) in results.items() if s is not None)
        )
        return EXIT_OK
    except CanaryError as exc:
        output.write(sys.stderr, f"safo-eval-canary: {exc}")
        return EXIT_USAGE


def _problem_line(unreachable: Sequence[str], busy: Sequence[str]) -> str:
    parts = []
    if unreachable:
        parts.append("unreachable (no score): " + ", ".join(unreachable))
    if busy:
        parts.append("busy after retries (no score): " + ", ".join(busy))
    return "eval-canary: " + "; ".join(parts)


def run() -> None:
    sys.exit(entry())


if __name__ == "__main__":
    run()
