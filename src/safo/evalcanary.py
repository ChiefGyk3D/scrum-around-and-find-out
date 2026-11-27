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

`--truncation-probe` (#569) also sends one long prompt to the model that truncates silently (the `safo-draft` digest
model) and alerts (exit 1) when the token count the server reports for it is no longer the known cut (`--expected-cap`,
default 4098): a server setting changed, in either direction. `--probe-only` runs just the probe and needs no baseline.
When both run, the exit code is the worst of the two in the order 3, 75, 1, 2: unreachable over busy over drop.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import json
import math
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from decimal import Decimal
from pathlib import Path
from typing import Any

from safo import bounded, localdraft, output
from safo import localeval as le

EXIT_OK, EXIT_DROP, EXIT_USAGE, EXIT_UNREACHABLE, EXIT_BUSY = 0, 1, 2, 3, 75
DEFAULT_THRESHOLD = 0.10  # an absolute drop in pass rate (0.10 = ten points)
DEFAULT_BASELINE = Path.home() / ".local/share/safo/eval-canary-baseline.json"
MAX_BASELINE_BYTES = 64 * 1024
MAX_MODELS = 16
BASELINE_VERSION = 2
BUSY_SLEEP = 30.0
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}")
_MODEL_FAILURE = re.compile(r"exit [34]:.*", re.DOTALL)  # the model's own failure (truncated, over the cap): not passed

Runner = Callable[[Any, str], dict[str, Any]]
ProbeRunner = Callable[[str, str], tuple[int, str]]  # (model, prompt) -> (llm-local exit code, its stderr)

PROBE_EXPECTED_CAP = 4098  # the prompt token count qwen3.5:4b is silently cut to once a prompt passes its 8K context
PROBE_MIN_CHARS = 30_000  # about 8,000 to 10,000 tokens of prose: past the 8K loaded context, over the 4098 cut
PROBE_TIMEOUT = 300.0
# llm-local's own truncation line (counts only, never prompt text); the whole line must match, so a line quoted inside
# other text is not a cut
_CUT_LINE = re.compile(r"llm-local: prompt truncated by the server: estimate [0-9]+ tokens, reported ([0-9]+);.*")


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


def _open_dir(path: Path, *, create: bool) -> int:
    """A descriptor for the folder `path`, walked one component at a time with no symlink followed anywhere.

    Every component is opened relative to the one before it with O_NOFOLLOW | O_DIRECTORY, so a symlink in any ancestor
    (not only the last) is refused and the folder cannot be swapped after the walk: later work uses the descriptor.
    """
    parts = Path(os.path.abspath(path)).parts
    fd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[1:]:
            try:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=fd)
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_at(dir_fd: int, name: str) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise bounded.NotRegularFileError(errno.EINVAL, "not a regular file")
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_BASELINE_BYTES:
            chunk = os.read(fd, min(65_536, MAX_BASELINE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def population_id(fixtures: Sequence[Any]) -> str:
    """A digest of the exact fixtures scored (task, id and content), so a score is only compared with its own kind."""
    digest = hashlib.sha256()
    for text in sorted(repr(fx) for fx in fixtures):
        digest.update(text.encode("utf-8") + b"\0")
    return digest.hexdigest()


def read_baseline(path: Path) -> dict[str, float]:
    """The stored scores (see read_baseline_doc for the population they were measured on)."""
    return read_baseline_doc(path)[0]


def read_baseline_doc(path: Path) -> tuple[dict[str, float], str]:
    try:
        dir_fd = _open_dir(path.parent, create=False)
        try:
            raw = _read_at(dir_fd, path.name)
        finally:
            os.close(dir_fd)
    except FileNotFoundError as exc:
        raise CanaryError("no baseline file; run once with --update-baseline") from exc
    except OSError as exc:  # a symlink anywhere in the path, a FIFO or other special file, a permission error
        raise CanaryError("baseline is behind a symlink, not a regular file, or cannot be opened") from exc
    if len(raw) > MAX_BASELINE_BYTES:
        raise CanaryError("baseline is over the size cap")
    try:
        doc = bounded.loads(raw, MAX_BASELINE_BYTES)
    except ValueError as exc:  # includes duplicate keys, bad constants, bad UTF-8, depth
        raise CanaryError("baseline is not valid JSON") from exc
    if (
        not isinstance(doc, dict)
        or doc.get("version") != BASELINE_VERSION
        or set(doc) != {"version", "scores", "population"}
    ):
        raise CanaryError("baseline has the wrong shape or version")
    scores = doc["scores"]
    pop = doc["population"]
    if not isinstance(pop, str) or not re.fullmatch(r"[0-9a-f]{64}", pop):
        raise CanaryError("baseline has a bad population id")
    if not isinstance(scores, dict) or not 0 < len(scores) <= MAX_MODELS:
        raise CanaryError("baseline scores are not a small object")
    out: dict[str, float] = {}
    for name, value in scores.items():
        if not isinstance(name, str) or not _MODEL.fullmatch(name) or ".." in name:
            raise CanaryError("baseline holds a bad model name")
        out[name] = _score_value(value)
    return out, pop


def write_baseline(path: Path, scores: dict[str, float], population: str) -> None:
    """Replace the baseline atomically with mode 0600, all relative to one folder descriptor.

    No symlink is followed in any component, a non-regular file is never replaced, and the temporary file and the
    rename both go through the descriptor, so the folder cannot be swapped between the check and the write.
    """
    text = (
        json.dumps({"version": BASELINE_VERSION, "scores": scores, "population": population}, indent=1, sort_keys=True)
        + "\n"
    )
    tmp = f".{path.name}.{os.getpid()}.tmp"
    try:
        dir_fd = _open_dir(path.parent, create=True)
    except OSError as exc:
        raise CanaryError("refusing to write the baseline through a symlink or an unusable folder") from exc
    try:
        try:
            try:
                mode: int | None = os.stat(path.name, dir_fd=dir_fd, follow_symlinks=False).st_mode
            except FileNotFoundError:
                mode = None
            if mode is not None and not stat.S_ISREG(mode):
                raise CanaryError("refusing to replace a baseline that is a symlink or not a regular file")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            os.rename(tmp, path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            os.fsync(dir_fd)
        except OSError as exc:
            with contextlib.suppress(OSError):
                os.unlink(tmp, dir_fd=dir_fd)
            raise CanaryError(f"cannot write the baseline: {exc.strerror}") from exc
    finally:
        os.close(dir_fd)


def _classify(records: Sequence[dict[str, Any]]) -> tuple[str, float | None]:
    """('ok', score) | ('unreachable', None) | ('busy', None). Any busy record makes the whole attempt busy."""
    passed = scored = busy = 0
    for rec in records:
        if not isinstance(rec, dict):  # a buggy runner: not a quality signal
            return "unreachable", None
        status = rec.get("status")
        if status == "busy":
            busy += 1
        elif status == "ok":
            score = rec.get("score")
            if not isinstance(score, dict):
                return "unreachable", None
            scored += 1
            passed += 1 if score.get("passed") is True else 0
        elif status == "failed" and _MODEL_FAILURE.fullmatch(str(rec.get("error", ""))):
            scored += 1
        else:  # any other failure: the server, the wrapper or the call did not work; not a quality signal
            return "unreachable", None
    if busy:  # a busy server must not choose which fixtures count: the whole attempt is retried
        return "busy", None
    if scored == 0:
        return "unreachable", None
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


def dropped(base: float, score: float, threshold: float) -> bool:
    """True when the drop is more than the threshold, compared as four-decimal fixed point (no binary float noise)."""
    quantum = Decimal("0.0001")
    drop = Decimal(repr(base)).quantize(quantum) - Decimal(repr(score)).quantize(quantum)
    return drop > Decimal(repr(threshold)).quantize(quantum)


def _default_runner(wait: int) -> Runner:
    return lambda fx, model: le.run_one(fx, model, wait=wait)


def _default_probe_runner(wait: int) -> ProbeRunner:
    """One llm-local call. No `--num-ctx` (llm-local sends the loaded context itself) and the truncation guard stays on
    (it is what reports the count); `--force-size` only lifts the route cap that would refuse the long prompt."""

    def call(model: str, prompt: str) -> tuple[int, str]:
        argv = ["llm-local", "--task", "eval-truncation-probe", "--model", model, "--wait", str(wait), "--force-size"]
        try:
            proc = le._run_cmd([*argv, prompt], PROBE_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 2, f"{type(exc).__name__}"
        return proc.returncode, proc.stderr

    return call


def probe_prompt(nonce: str) -> str:
    """Long, deterministic prose with a per-run nonce first, so a server prefix cache cannot hide a cut."""
    lines = [f"Run {nonce}. Background text for a length check; read it, then follow the last line."]
    lines += [f"Line {i}: the quick brown fox jumps over the lazy dog." for i in range(1, 701)]
    lines.append("Reply with the single word OK.")
    text = "\n".join(lines)
    if len(text) <= PROBE_MIN_CHARS:  # cannot happen with the constants above; a guard against an edit
        raise CanaryError("probe prompt is too short to pass the context")
    return text


def classify_probe(code: int, stderr: str, expected: int) -> tuple[str, str]:
    """('ok'|'changed'|'unreachable'|'busy', detail). llm-local exit 3 is the cut: the expected answer."""
    if code == EXIT_BUSY:
        return "busy", ""
    if code == 0:  # the guard saw a full prompt: the server no longer cuts it
        return "changed", "no cut reported (the server now takes the whole prompt)"
    if code == 3:
        for line in stderr.splitlines():
            m = _CUT_LINE.fullmatch(line.strip())
            if m:
                n = int(m.group(1))
                return ("ok", f"cut at {n}") if n == expected else ("changed", f"cut at {n}, expected {expected}")
    return "unreachable", ""


def measure_probe(
    model: str, expected: int, runner: ProbeRunner, busy_retries: int, sleep: Callable[[float], None], nonce: str
) -> tuple[str, str]:
    state = ("busy", "")
    prompt = probe_prompt(nonce)
    for attempt in range(busy_retries + 1):
        state = classify_probe(*runner(model, prompt), expected)
        if state[0] != "busy":
            return state
        if attempt < busy_retries:
            sleep(BUSY_SLEEP * 2**attempt)
    return state


def _worst(codes: Sequence[int]) -> int:
    for code in (EXIT_UNREACHABLE, EXIT_BUSY, EXIT_DROP, EXIT_USAGE):
        if code in codes:
            return code
    return EXIT_OK


def _expected_cap(text: str) -> int:
    if not re.fullmatch(r"[0-9]{1,7}", text) or int(text) < 1:
        raise CanaryError("--expected-cap must be a whole number from 1 to 9999999")
    return int(text)


def _threshold(text: str) -> float:
    try:
        value = float(text)
    except ValueError as exc:
        raise CanaryError("--threshold is not a number") from exc
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise CanaryError("--threshold must be between 0 and 1")
    return value


def entry(
    argv: Sequence[str] | None = None,
    *,
    runner: Runner | None = None,
    sleep: Any = time.sleep,
    probe_runner: ProbeRunner | None = None,
    nonce: str | None = None,
) -> int:
    ap = argparse.ArgumentParser(prog="safo-eval-canary", description="Alert when local-model quality drops.")
    ap.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    ap.add_argument("--threshold", default=str(DEFAULT_THRESHOLD), help="largest allowed drop in pass rate (0 to 1)")
    ap.add_argument("--tasks", default="all")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--fixtures", type=Path, default=le.FIXTURES_DEFAULT)
    ap.add_argument("--wait", type=int, default=120)
    ap.add_argument("--busy-retries", type=int, default=3)
    ap.add_argument("--update-baseline", action="store_true", help="write the new scores as the baseline")
    ap.add_argument("--truncation-probe", action="store_true", help="also check the silent prompt cut (#569)")
    ap.add_argument("--probe-only", action="store_true", help="run only the truncation probe; no baseline is read")
    ap.add_argument("--expected-cap", default=str(PROBE_EXPECTED_CAP), help="the token count the cut is expected at")
    args = ap.parse_args(argv)
    codes: list[int] = []
    try:
        if args.probe_only and args.update_baseline:
            raise CanaryError("--probe-only and --update-baseline cannot be combined")
        if args.truncation_probe and args.update_baseline:
            raise CanaryError("--truncation-probe cannot be combined with --update-baseline")
        expected = _expected_cap(args.expected_cap)
        if args.probe_only:
            if args.repeats < 1 or args.busy_retries < 0 or args.wait < 0:
                raise CanaryError("--repeats must be at least 1; --busy-retries and --wait at least 0")
            return _probe(args, expected, probe_runner, sleep, nonce)
    except CanaryError as exc:
        output.write(sys.stderr, f"safo-eval-canary: {exc}")
        return EXIT_USAGE
    codes.append(_score(args, runner, sleep))
    if args.truncation_probe:
        try:
            codes.append(_probe(args, expected, probe_runner, sleep, nonce))
        except CanaryError as exc:
            output.write(sys.stderr, f"safo-eval-canary: {exc}")
            codes.append(EXIT_USAGE)
    return _worst(codes)


def _probe(
    args: argparse.Namespace, expected: int, probe_runner: ProbeRunner | None, sleep: Any, nonce: str | None
) -> int:
    call = probe_runner or _default_probe_runner(args.wait)
    model = localdraft.DIGEST_MODEL
    state, detail = measure_probe(model, expected, call, args.busy_retries, sleep, nonce or secrets.token_hex(8))
    if state == "unreachable":
        output.write(sys.stderr, f"eval-canary: truncation probe: unreachable or failed (no verdict): {model}")
        return EXIT_UNREACHABLE
    if state == "busy":
        output.write(sys.stderr, f"eval-canary: truncation probe: busy after retries (no verdict): {model}")
        return EXIT_BUSY
    if state == "changed":
        output.write(sys.stderr, f"ALERT eval-canary: truncation probe: {model} {detail}; a server setting changed")
        return EXIT_DROP
    output.write(sys.stdout, f"eval-canary: truncation probe ok: {model} {detail}")
    return EXIT_OK


def _score(args: argparse.Namespace, runner: Runner | None, sleep: Any) -> int:
    try:
        threshold = _threshold(args.threshold)
        if args.repeats < 1 or args.busy_retries < 0 or args.wait < 0:
            raise CanaryError("--repeats must be at least 1; --busy-retries and --wait at least 0")
        tasks = None if args.tasks == "all" else [t.strip() for t in args.tasks.split(",")]
        bad = [t for t in tasks or [] if t not in le.TASKS]
        if bad:
            raise CanaryError("unknown task name")
        baseline, stored_pop = ({}, "") if args.update_baseline else read_baseline_doc(args.baseline)
        models = canary_models()
        if not args.update_baseline and not set(models) <= set(baseline):
            raise CanaryError("baseline has no score for a configured model; run with --update-baseline")
        try:
            fixtures = le.load_fixtures(args.fixtures, tasks)
        except le.EvalError as exc:
            raise CanaryError(str(exc)) from exc
        pop = population_id(fixtures)
        if not args.update_baseline and pop != stored_pop:
            raise CanaryError("baseline was made from a different task or fixture set; run with --update-baseline")
        call = runner or _default_runner(args.wait)
        results = {m: measure(m, fixtures, args.repeats, call, args.busy_retries, sleep) for m in models}
        unreachable = [m for m, (s, _) in results.items() if s == "unreachable"]
        busy = [m for m, (s, _) in results.items() if s == "busy"]
        if args.update_baseline:
            if unreachable or busy:
                output.write(sys.stderr, _problem_line(unreachable, busy) + " (baseline not written)")
                return EXIT_UNREACHABLE if unreachable else EXIT_BUSY
            write_baseline(args.baseline, {m: round(float(results[m][1] or 0.0), 4) for m in models}, pop)
            output.write(sys.stdout, "eval-canary: baseline written for " + ", ".join(models))
            return EXIT_OK
        if unreachable or busy:  # an incomplete run never turns into a verdict, in either direction
            output.write(sys.stderr, _problem_line(unreachable, busy))
            return EXIT_UNREACHABLE if unreachable else EXIT_BUSY
        drops = [
            f"{m} {baseline[m]:.2f} -> {score:.2f} (-{baseline[m] - score:.2f})"
            for m, (_, score) in results.items()
            if score is not None and dropped(baseline[m], score, threshold)
        ]
        if drops:
            output.write(sys.stderr, f"ALERT eval-canary: quality drop over {threshold:.2f}: " + "; ".join(drops))
            return EXIT_DROP
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
