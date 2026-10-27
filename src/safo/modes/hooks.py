# SPDX-License-Identifier: Apache-2.0
"""hooks: install, run and inspect the Claude Code hooks that enforce the routing rules in agents.yaml.

    safo hooks install [--settings PATH] [--mode warn|block]   add the probe and the guard to a settings.json
    safo hooks probe                                           SessionStart: is the local LLM reachable?
    safo hooks guard                                           PreToolUse (Agent, Bash): check the brief, or the wait
    safo hooks mode warn|block                                 warn reports; block denies a dispatch that breaks a rule
    safo hooks status                                          the mode and the counts

`probe` and `guard` fail open on hook errors. A fixed warning and bounded diagnostic visibly report degradation.
The guard writes its decision first and persists afterwards (best effort, bounded), so a logging failure cannot lose it.
"""

from __future__ import annotations

import argparse
import codecs
import contextlib
import itertools
import json
import os
import re
import select
import shlex
import stat
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from time import time as wall_clock  # immune to the monotonic-clock stand-in some tests install
from typing import Any, TypeVar

from safo import gemini, geminibrief, guardlog, leadwait, output, tracking
from safo.agentsfile import AgentsFile
from safo.bounded import MAX_BYTES, loads
from safo.context import LocalContext
from safo.errors import EXIT_OK, ConfigError
from safo.gemini import approval_problem
from safo.geminibrief import ApprovalCheck, findings
from safo.guardlog import (
    APPEND_LOCK_TIMEOUT,
    MODES,
    WARNING,
    bounded_read,
    config_dir,
    file_lock,
    guard_lines,
    mode_health,
    read_mode,
    state_dir,
)
from safo.hooks import (
    AGENT_TOOLS,
    BASH_TOOL,
    COMMAND,
    CONFIG_REPROBE_TIMEOUT_SECONDS,
    GUARD_MARGIN_SECONDS,
    GUARD_TIMEOUT_SECONDS,
    LEAD_WAITS,
    REPROBE_SLACK_SECONDS,
    REPROBE_TIMEOUT_SECONDS,
    Verdict,
    append_log,
    attempt_path,
    bind_repo,
    check_dispatch,
    claim_notice,
    decide,
    guard_output,
    is_safo_path,
    log_record,
    merge_settings,
    notice_unclaimed,
    probe_all,
    probe_state,
    prune_state,
    read_bound_repo,
    read_state,
    refresh_bound_repo,
    reprobe,
    save_state,
    session_message,
    session_output,
    state_health,
    state_path,
    write_text,
)
from safo.localfiles import add_agents_arguments, load_agents_for
from safo.modes import LocalMode, register_local

LOOKUP_RESERVE_SECONDS = 2.0  # a re-probe leaves at least this much of the hook's budget for the issue lookup
MIN_REPROBE_TIMEOUT_SECONDS = 0.5  # below this per request a re-probe is skipped, not attempted
LOG_MARGIN_SECONDS = 1.0  # the log wait ends this long before the host's timeout
MIN_LOG_WAIT_SECONDS = 0.05  # with less than this left before that, the append is skipped, never stretched past it
LOG_FAILED_NAME = "log-failed"  # presence marker: the last best-effort log write failed; the next guard run reports it
LOG_FAILED_NOTICE = "previous log write failed"
LOG_MARKER_UNUSABLE = "log-failed marker unusable"  # a directory, FIFO, link or foreign file sat where the marker goes
CONFIG_TIMEOUT_NOTICE = "budget exceeded: configuration load timed out, rules disabled"
NOTICES_SKIPPED = "notices skipped: state folder slow"  # fixed text: learning it needs no filesystem call
MODE_SLOW_NOTICE = "state folder slow: mode file skipped"  # the mode read did not finish: fail closed (block)
STATE_SLOW_NOTICE = "state folder slow: probe state skipped"  # a pre-decision state operation did not finish
NOTICE_IO_CAP_SECONDS = 1.0  # first-notice flag and marker inspection together get at most this long before the emit
MAX_SIDE_OBJECTS = 8  # `.log-failed.junk.*` entries kept in the state folder; at the cap nothing more is moved aside
SIDE_PREFIX = ".log-failed.junk."
SIDE_NAME = re.compile(re.escape(SIDE_PREFIX) + r"[0-9]+-[0-9a-f]{12}")  # exactly what remove_junk names a side object
SIDE_PRUNE_AGE_SECONDS = 300.0  # an object younger than this (by ctime, which a rename updates) is never pruned
POST_GRACE_SECONDS = 0.5  # after the hard limit the post-delivery work gets this long, still inside the host timeout
NOTICE_IO_MIN_SECONDS = 0.25  # and at least this long, even when the clock is already past its limit
_T = TypeVar("_T")
Ident = tuple[int, int, int, int, int]  # st_dev, st_ino, st_mode, st_mtime_ns, st_size: what sat at the name
CONFIG_MIN_WAIT_SECONDS = 0.25  # a load is always given this long, even when the clock is already past its deadline
EXIT_BLOCK = 2  # the host reads exit 2 from a PreToolUse hook as "block this call"
EXIT_NOT_DELIVERED = 1  # any other non-zero exit is a non-blocking error to the host
BUDGET_NOTICE = "budget exceeded: lookups skipped"
TERMINAL_WAIT_SECONDS = 0.25  # how long a terminal on standard input gets to deliver an event before it is a person
STDIN_TIMEOUT_SECONDS = 5.0  # a host writes the event at once; a silent standard input is a hung host, not a slow one


HARD_LIMIT_BYTES = 8 * 1024 * 1024  # the most of an oversized event that is read and checked for Gemini markers
ISOLATED_CHECK_SECONDS = 1.5  # the separate Gemini check run when another rule raised
DRAIN_SECONDS = 4.0  # the most time reading and checking the rest of an oversized event may take
_COMMAND_EXPANSION = re.compile(
    r"(?m)(?:^|[;&|(`]|\b(?:env|exec|eval|do|then|else|command|nohup|sudo)\s)\s*[\"']?\$[\w{(@*#?!\\\\-]"
)  # an expansion where a command word would stand
MAX_REFERENCED = 50_000  # referenced names remembered while scanning an event; more is treated as a marker
_JSON_ESCAPE = re.compile(r'\\(?:u([0-9a-fA-F]{4})|([nrtbf"\\/]))')
_JSON_SIMPLE = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f"}


class EventStream:
    """Standard input as the guard reads it: a real descriptor with `select` (so a writer that never writes or never
    closes cannot hold the hook), anything else (a test's StringIO) with plain bounded reads."""

    def __init__(self, ctx: LocalContext) -> None:
        self.stream = ctx.stdin if ctx.stdin is not None else sys.stdin
        try:
            self.fd: int | None = self.stream.fileno()
        except (AttributeError, OSError, ValueError):  # io.UnsupportedOperation is both OSError and ValueError
            self.fd = None

    def read(self, size: int, deadline: float) -> bytes:
        """Up to `size` bytes, b"" at the end of the stream; TimeoutError when none arrive before `deadline`."""
        if self.fd is None:
            data = self.stream.read(size)
            return data.encode("utf-8", "replace") if isinstance(data, str) else data
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([self.fd], [], [], left)[0]:
            raise TimeoutError("no event on standard input")
        return os.read(self.fd, size)


class EventTimeout(TimeoutError):
    """No event arrived in time. `partial` is whatever bytes had arrived, so they can still be checked."""

    def __init__(self, partial: bytes) -> None:
        super().__init__("no event on standard input")
        self.partial = partial


class GeminiEventDeny(Exception):
    """The Gemini rules deny a dispatch whose event or agents file could not be used. `code` is the diagnostic."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


def _json_unescape(m: re.Match[str]) -> str:
    return chr(int(m.group(1), 16)) if m.group(1) else _JSON_SIMPLE.get(m.group(2), m.group(2))


class EventScan:
    """Bounded, stateful marker detection over a stream of bytes, for an event that cannot be parsed. Each chunk is
    checked together with the end of the one before (a marker cannot hide across a boundary), after the same
    normalization the brief scan uses: JSON `\\uXXXX` escapes decoded, the text folded (fullwidth and look-alike
    letters, invisible characters), quotes and backslashes removed. It reports a marker when the words `safo` and
    `gemini` have both been seen, or the vendor host, an SDK name or the paid config name, or a decode-to-shell form."""

    OVERLAP = 160

    def __init__(self, deadline: float) -> None:
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.tail = ""
        self.safo = self.gemini = self.hit = self.conceal = self.capped = False
        self.risk = self.command_expansion = self.expansion = False
        self.assigned: set[str] = set()
        self.referenced: set[str] = set()
        self.deadline = deadline

    def feed(self, chunk: bytes) -> None:
        if time.monotonic() > self.deadline:
            raise TimeoutError("the event could not be checked in time")
        window = self.tail + self.decoder.decode(chunk)
        self.tail = window[-self.OVERLAP :]
        text = _JSON_ESCAPE.sub(_json_unescape, window) if "\\" in window else window
        lowered = text.lower()
        views = [lowered]
        stripped = geminibrief._strip(lowered)
        if stripped != lowered:
            views.append(stripped)
        if text != window or not window.isascii():
            folded = gemini.fold(text).lower()
            if folded != lowered:
                views.append(folded)
            folded_stripped = geminibrief._strip(folded)
            if folded_stripped != folded and folded_stripped not in views:
                views.append(folded_stripped)
        for view in views:
            self.safo = self.safo or "safo" in view
            self.gemini = self.gemini or "gemini" in view
            # each pattern runs only when its cheap precondition holds, so a long plain stream stays cheap
            if "\\" in view or "$'" in view or "printf" in view:
                self.conceal = self.conceal or bool(geminibrief.CONCEAL.search(view))
                if geminibrief._ANSI_ESCAPE.search(view) or (
                    self.conceal and "printf" in view and re.search(r"printf\s+-v\b", view) is not None
                ):
                    self.hit = True
            if not self.capped:
                if "=" in view:
                    self.assigned.update(m.group(1) for m in geminibrief._ASSIGNED.finditer(view))
                if "printf" in view:
                    self.assigned.update(m.group(1) for m in geminibrief._PRINTF_NAME.finditer(view))
                if "for" in view:
                    self.assigned.update(m.group(1) for m in geminibrief._LOOP_NAME.finditer(view))
                if "read" in view:
                    self.assigned.update(m.group(1) for m in geminibrief._READ_NAME.finditer(view))
                if "$" in view:
                    self.referenced.update(m.group(1) for m in geminibrief._REFERENCE.finditer(view))
                # the brief scan's own policy: more assigned names than it follows is unreadable, and so is a stream
                # with more referenced names than are remembered; never a silent stop
                if len(self.assigned) > geminibrief.MAX_VARIABLES or len(self.referenced) > MAX_REFERENCED:
                    self.capped = True
                    self.hit = True
            if "--" in view or "approve" in view or "{" in view:
                self.risk = (
                    self.risk or bool(geminibrief._RISK_OPTION.search(view)) or geminibrief._brace_word_risk(view)
                )
            if "$" in view:
                self.expansion = self.expansion or bool(geminibrief._DOLLAR.search(view))
                self.command_expansion = self.command_expansion or bool(_COMMAND_EXPANSION.search(view))
            if (
                geminibrief.PAID_CONFIG.search(view)
                or gemini.VENDOR_HOST in view
                or geminibrief.SDK.search(view)
                or (
                    ("base64" in view or "xxd" in view or "openssl" in view or "rev" in view or "printf" in view)
                    and (geminibrief.DECODE.search(view) and geminibrief.SINK_RE.search(view))
                )
            ):
                self.hit = True
        # the brief scan's flow rule, without lines: a name assigned anywhere and referenced anywhere, with the Gemini
        # surface (safo, gemini or escape-built words) named somewhere in the stream
        surface = self.safo or self.gemini or self.conceal
        # a Gemini option or action beside an expansion where a command word stands needs no named surface
        self.hit = (
            self.hit
            or (self.risk and (self.expansion or self.command_expansion))
            or (self.safo and self.gemini)
            or (surface and bool(self.assigned & self.referenced))
        )


def read_event(source: EventStream, until: float | None = None) -> tuple[bytes, bool]:
    """(the event as read, whether it is over the cap). At most MAX_BYTES + 1 bytes are kept; EventTimeout when the
    event stalls for STDIN_TIMEOUT_SECONDS, or sooner at the monotonic time `until` (the guard's shared clock)."""
    deadline = time.monotonic() + STDIN_TIMEOUT_SECONDS if source.fd is not None else 0.0
    if until is not None and source.fd is not None:
        deadline = min(deadline, until)
    chunks: list[bytes] = []
    total = 0
    while total <= MAX_BYTES:
        try:
            chunk = source.read(min(65_536, MAX_BYTES + 1 - total), deadline)
        except TimeoutError:
            raise EventTimeout(b"".join(chunks)) from None
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks), total > MAX_BYTES


def scan_event(source: EventStream | None, prefix: bytes) -> str:
    """Check `prefix` and, for an oversized event (`source` given), the rest of the stream up to HARD_LIMIT_BYTES and
    DRAIN_SECONDS. Returns "marker", "clean" (the whole stream was scanned), "limit" (it is longer than the hard limit)
    or "slow" (it did not finish arriving, or could not be checked, in time)."""
    deadline = time.monotonic() + DRAIN_SECONDS
    scan = EventScan(deadline)
    total = len(prefix)
    try:
        for i in range(0, len(prefix), 65_536):
            scan.feed(prefix[i : i + 65_536])
            if scan.hit:
                return "marker"
        while source is not None:
            chunk = source.read(262_144, deadline)
            if not chunk:
                break
            total += len(chunk)
            if total > HARD_LIMIT_BYTES:
                return "limit"
            scan.feed(chunk)
            if scan.hit:
                return "marker"
    except TimeoutError:
        return "slow"
    return "marker" if scan.hit else "clean"


def event_input(ctx: LocalContext) -> dict[str, Any]:
    """The event as a mapping. Reads at most MAX_BYTES + 1 bytes and gives up after STDIN_TIMEOUT_SECONDS.

    A real descriptor is read with `select`, so a writer that never writes or never closes cannot hold the hook until
    the host kills it; a stream with no descriptor (a test's StringIO) is read in one bounded call.
    """
    raw, oversize = read_event(EventStream(ctx))
    if oversize:
        raise ValueError("oversized event")
    payload = loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("invalid event")
    return payload


def session_id(payload: dict[str, Any]) -> str:
    value = payload.get("session_id")
    if not isinstance(value, str) or not value or len(value) > 256 or any(ord(c) < 32 for c in value):
        raise ValueError("invalid session identity")
    return value


@dataclass
class Run:
    """What one guard run has done on the host's channel. `attempted` is set BEFORE the first byte of a decision is
    written: from then on nothing else is ever written there, whatever fails."""

    hard: float | None = None
    attempted: bool = False
    failed: bool = False  # the decision could not be delivered (write or flush failed)
    deny: bool = False  # the decision that was attempted was a denial
    overran: bool = False  # a bounded worker did not finish and was left running: leave as soon as the line is out


hard_exit: Callable[[int], None] = os._exit
"""How the guard process ENDS. `os._exit` stops every thread at once and runs no Python-level clean-up, so nothing that
is blocked in a call can ever resume and nothing can be started after it. Tests replace this name (the test suite's
conftest makes it a no-op that returns, so a pytest process is not killed)."""


def exit_code(run: Run) -> int:
    """0 normally. A decision that could not be delivered must not look like an allow: a denial then exits 2, which the
    host treats as a block; anything else exits 1, a non-blocking error."""
    if not run.failed:
        return EXIT_OK
    return EXIT_BLOCK if run.deny else EXIT_NOT_DELIVERED


def write_all(stream: Any, text: str) -> bool:
    """Write every character of `text`, however the stream chops it. A text stream's write() returns the number of
    characters taken: a short count is written again from where it stopped, and no progress (0, a negative or larger
    count, None or anything that is not an int) is a failure. Text streams only; the guard's output is one JSON line."""
    view = text
    while view:
        taken = stream.write(view)
        if not isinstance(taken, int) or isinstance(taken, bool) or not 0 < taken <= len(view):
            return False
        view = view[taken:]
    return True


def emit(ctx: LocalContext, run: Run, data: dict[str, Any]) -> bool:
    """Write the whole line and flush it, in a worker thread that the main thread waits for until the decision deadline
    (the hard limit plus POST_GRACE_SECONDS). A reader that never drains a full pipe cannot hold the decision past the
    host's timeout: at the deadline the process ENDS through hard_exit with the exit code of an undelivered decision (2
    for a denial, which the host reads as a block; 1 otherwise). A failed or short write is the same undelivered
    decision. After the first attempt nothing else is ever written, so a truncated line is never followed by a second
    object. The guard writes nothing to standard error and never changes flags on a shared file description."""
    text = output.line(json.dumps(data)) + "\n"
    run.attempted = True
    run.deny = data.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

    def write() -> bool:
        delivered = write_all(ctx.out, text)
        ctx.out.flush()
        return delivered

    left = (run.hard - time.monotonic()) if run.hard is not None else APPEND_LOCK_TIMEOUT + 1.0
    try:
        done, delivered = run_bounded(write, max(0.0, left) + POST_GRACE_SECONDS)
    except Exception:
        done, delivered = True, False
    if not done:
        run.failed = True
        hard_exit(EXIT_BLOCK if run.deny else EXIT_NOT_DELIVERED)
        return False
    if not delivered:
        run.failed = True
    return bool(delivered)


def diagnostic(
    ctx: LocalContext,
    code: str,
    event: str = "PreToolUse",
    run: Run | None = None,
    shown: str | None = None,
    deny: str = "",
) -> None:
    """Fixed visible warning plus a bounded enum-only record; no exception text or input values. The warning is written
    first; the record is best effort (see emit_then_persist). `shown` replaces the enum in the visible line only."""
    run = run or Run()
    folder = state_dir(ctx.env)
    when = ctx.now.strftime("%Y-%m-%dT%H:%M:%S")
    record = log_record(when, "error", read_mode(ctx.env), None, False, "degraded", code)
    data: dict[str, Any] = {
        "systemMessage": WARNING,
        "hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": WARNING + " " + json.dumps({"health": "degraded", "diagnostic": shown or code}),
        },
    }
    if deny:  # the Gemini rules deny even when the rest is degraded; the diagnostic stays in the same answer
        data["hookSpecificOutput"]["permissionDecision"] = "deny"
        data["hookSpecificOutput"]["permissionDecisionReason"] = "safo hooks guard: " + deny
    emit_then_persist(ctx, run, data, folder, record)


def emit_then_persist(
    ctx: LocalContext,
    run: Run,
    data: dict[str, Any] | None,
    folder: Path | None,
    record: dict[str, Any],
    clear_marker: Ident | None = None,
    claim: Path | None = None,
    refresh: Path | None = None,
) -> None:
    """The one tail of every guard path. The decision (`data`, or nothing to say) is written and flushed FIRST. If that
    fails nothing else is done; the caller turns it into the exit code. After the line is out:

    - if a pre-decision worker overran and was left running (`run.overran`), the process ENDS at once through hard_exit:
      nothing more is started, so the left-behind worker cannot resume and write anything;
    - otherwise the audit and decision writes (refresh the binding's age, clear the marker whose notice was in the
      line, claim the probe notice, append the log, record a failed append) run in ONE worker that the main thread waits
      for only until just past the hard limit; if it is not done by then the process ENDS through hard_exit. A call
      that is blocked then can never resume, and none is started after the exit. The append waits no longer than the
      setting and never past `run.hard`. A failed or skipped append leaves a marker that the next guard run reports; it
      can never change or follow the line already written."""
    if data is not None and not emit(ctx, run, data):
        return
    if run.overran:
        hard_exit(exit_code(run))
        return
    delivered = data is not None

    def after() -> None:
        if refresh is not None:  # keep the binding out of the prune: a hint
            with contextlib.suppress(Exception):
                refresh_bound_repo(refresh)
        if delivered and clear_marker is not None:  # its notice was in the delivered line
            with contextlib.suppress(Exception):
                clear_log_failure(folder, clear_marker)
        if delivered and claim is not None:  # the probe notice was in the delivered line
            with contextlib.suppress(Exception):
                claim_notice(claim)
        try:
            if folder is None:
                raise OSError("log unavailable")
            wait = APPEND_LOCK_TIMEOUT if run.hard is None else min(APPEND_LOCK_TIMEOUT, run.hard - time.monotonic())
            if wait < MIN_LOG_WAIT_SECONDS:
                raise TimeoutError("out of time")
            append_log(folder / guardlog.LOG_NAME, record, lock_timeout=wait)
        except Exception:
            with contextlib.suppress(Exception):
                write_log_failed(folder)

    left = (run.hard - time.monotonic()) if run.hard is not None else APPEND_LOCK_TIMEOUT + 1.0
    done = False
    with contextlib.suppress(Exception):
        done, _ = run_bounded(after, max(0.0, left) + POST_GRACE_SECONDS)
    if not done:
        hard_exit(exit_code(run))


# -- the log-failed marker: opened relative to the state folder's descriptor, never by a second path lookup -----------


def marker_dir(folder: Path | None) -> int:
    """A descriptor for the state folder, checked on the descriptor itself: ours, and not writable by others."""
    if folder is None:
        raise OSError("no state folder")
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise PermissionError("state folder not trusted")
    except BaseException:
        os.close(fd)
        raise
    return fd


def sane_marker(info: os.stat_result) -> bool:
    return stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022


def marker_ident(info: os.stat_result) -> Ident:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_mtime_ns, info.st_size)


def side_objects(dfd: int) -> list[str]:
    return [name for name in os.listdir(dfd) if name.startswith(SIDE_PREFIX)]


def prune_side_objects(dfd: int) -> None:
    """Clean up what earlier removals left aside, and only that: an object named exactly as remove_junk names them
    (pid, a random id), older than SIDE_PRUNE_AGE_SECONDS by ctime (a rename updates it, so an object a live run has
    just moved aside and is about to put back is never old), and either an empty directory or a regular file that is
    ours. Looked at with lstat only, never followed; links, FIFOs, other names and directories with content stay."""
    for name in side_objects(dfd):
        if not SIDE_NAME.fullmatch(name):
            continue
        with contextlib.suppress(OSError):
            info = os.lstat(name, dir_fd=dfd)
            if wall_clock() - info.st_ctime < SIDE_PRUNE_AGE_SECONDS:
                continue
            if stat.S_ISDIR(info.st_mode):
                os.rmdir(name, dir_fd=dfd)  # fails (and is kept) unless empty
            elif stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid():
                os.unlink(name, dir_fd=dfd)


def install_no_clobber(dfd: int, source: str, *, keep_on_failure: bool, follow_symlinks: bool = True) -> bool:
    """Give `source` the marker name WITHOUT overwriting anything: a hard link, then drop the source name. Any failure
    (the name is taken: EEXIST; the filesystem has no hard links: EPERM, EOPNOTSUPP, EXDEV, ENOSYS, ...) means it was
    not installed, and nothing else is tried: there is no rename fallback, because a rename would overwrite a newer
    marker. With `keep_on_failure` the source stays where it is (it is somebody's object); otherwise it is removed
    (it is this run's own temp file). True if installed."""
    try:
        os.link(source, LOG_FAILED_NAME, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=follow_symlinks)
    except OSError:
        if not keep_on_failure:
            with contextlib.suppress(OSError):
                os.unlink(source, dir_fd=dfd)
        return False
    with contextlib.suppress(OSError):
        os.unlink(source, dir_fd=dfd)
    return True


def remove_junk(dfd: int, seen: Ident) -> bool:
    """Remove whatever sits at the marker name (a directory, FIFO, link or file) ONLY if it is what was observed, and
    return True ONLY if it really is gone.

    One look (lstat) compares it with `seen`. A match is then renamed to a unique side name inside the state folder
    (atomic: it moves whatever is at the name at that instant), and the MOVED object is looked at once more: only if it
    still has the observed identity is it deleted, by its side name, with rmdir or unlink chosen from that same lstat.
    If the deletion fails (a directory that is not empty) the object stays under its side name and the answer is
    False. At most MAX_SIDE_OBJECTS side objects are kept: empty ones are pruned first, and at the cap nothing more is
    moved aside (False). If something else was moved (a replacement slipped in between the look and the rename), it is
    put back with install_no_clobber; if it cannot be put back it stays under its side name. A non-matching object is
    never deleted. Remaining window: between the look and the rename a replacement is briefly moved aside, so a
    concurrent reader can miss a marker for a moment; the identity tuple is best effort (a recycled inode, or a
    coarse-timestamp filesystem, can repeat it). Both are inside the same-user residual (#61)."""
    side = f"{SIDE_PREFIX}{os.getpid()}-{os.urandom(6).hex()}"
    try:
        prune_side_objects(dfd)
        if len(side_objects(dfd)) >= MAX_SIDE_OBJECTS:
            return False
        if marker_ident(os.lstat(LOG_FAILED_NAME, dir_fd=dfd)) != seen:
            return False
        os.rename(LOG_FAILED_NAME, side, src_dir_fd=dfd, dst_dir_fd=dfd)
        moved = os.lstat(side, dir_fd=dfd)
    except OSError:
        return False
    if marker_ident(moved) != seen:
        install_no_clobber(dfd, side, keep_on_failure=True, follow_symlinks=False)
        return False
    try:
        if stat.S_ISDIR(moved.st_mode):
            os.rmdir(side, dir_fd=dfd)
        else:
            os.unlink(side, dir_fd=dfd)
    except OSError:
        return False
    return True


def marker_present(dfd: int) -> bool:
    try:
        return sane_marker(os.lstat(LOG_FAILED_NAME, dir_fd=dfd))
    except OSError:
        return False


def write_log_failed(folder: Path | None) -> bool:
    """Record a failure. The first install is an atomic rename of a fresh file (new token, new inode) over the marker,
    so every failure has its own identity and an older run's clear cannot erase it. The marker name itself is never
    opened for writing. If the rename fails because something (a directory) is in the way, only that observed blocker is
    removed, and only if that removal really happened is the install retried, and then with a hard link, which
    never overwrites: if a newer marker arrived meanwhile it wins, this run's temp file is dropped, and the failure
    counts as recorded because a marker exists. On a filesystem without hard links the retry cannot install: the
    failure is then not recorded (False) until the blocker is gone; the decision is unaffected."""
    if folder is not None:
        guardlog.ensure_dir(folder)  # a fresh install whose first append failed has no folder yet
    dfd = marker_dir(folder)
    try:
        for attempt in (0, 1):
            temp = f".{LOG_FAILED_NAME}.{os.urandom(6).hex()}"
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
            try:
                os.write(fd, f"{os.getpid()} {os.urandom(8).hex()}\n".encode())
            finally:
                os.close(fd)
            if attempt:  # the retry never overwrites: a newer marker wins; no hard links: not recorded
                return install_no_clobber(dfd, temp, keep_on_failure=False) or marker_present(dfd)
            try:
                os.rename(temp, LOG_FAILED_NAME, src_dir_fd=dfd, dst_dir_fd=dfd)
                return True
            except OSError:
                with contextlib.suppress(OSError):
                    os.unlink(temp, dir_fd=dfd)
                try:
                    blocker = marker_ident(os.lstat(LOG_FAILED_NAME, dir_fd=dfd))
                except OSError:
                    continue  # nothing is in the way any more: try again
                if not remove_junk(dfd, blocker):
                    return marker_present(dfd)  # replaced meanwhile: leave whatever is there, do not rename over it
        return False
    finally:
        os.close(dfd)


def log_failure_pending(folder: Path | None) -> tuple[str, Ident | None] | None:
    """READ-ONLY observation of the marker: (notice, identity) or None. A usable marker gives LOG_FAILED_NOTICE; junk at
    its name (directory, FIFO, link, foreign or loose-mode file) gives LOG_MARKER_UNUSABLE. The identity is what was
    observed (from the descriptor, for an opened file). Nothing is changed here, so an abandoned worker cannot
    change anything later: the caller clears or removes it AFTER the line that carries the notice is delivered, and
    only if it is still what was observed. The marker is same-user writable like the rest of the state: it can only add
    a notice, never grant anything."""
    try:
        dfd = marker_dir(folder)
    except OSError:
        return None
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        try:
            fd = os.open(LOG_FAILED_NAME, flags, dir_fd=dfd)
        except FileNotFoundError:
            return None
        except OSError:
            fd = -1  # a link, or something that cannot be opened: judged by lstat below
        try:
            info = os.fstat(fd) if fd >= 0 else os.lstat(LOG_FAILED_NAME, dir_fd=dfd)
        except OSError:
            return None
        finally:
            if fd >= 0:
                os.close(fd)
        return (LOG_FAILED_NOTICE if sane_marker(info) else LOG_MARKER_UNUSABLE, marker_ident(info))
    finally:
        os.close(dfd)


def clear_log_failure(folder: Path | None, seen: Ident) -> None:
    """Remove the marker (or the junk) only if it is still what was observed: a failure written since has another
    identity and stays for the next dispatch to report."""
    dfd = marker_dir(folder)
    try:
        remove_junk(dfd, seen)
    finally:
        os.close(dfd)


def run_bounded(work: Callable[[], _T], timeout: float, run: Run | None = None) -> tuple[bool, _T | None]:
    """Run `work()` in a daemon thread and wait at most `timeout` seconds. (True, result), or (False, None) when it did
    not finish: the thread is LEFT RUNNING (a thread cannot be cancelled) and `run.overran` is set, which makes the
    guard end the process through hard_exit as soon as its decision is out. An exception in `work` is re-raised. This
    is how the guard bounds filesystem calls that cannot be interrupted (a wedged mount, a kernel read).

    The invariant, true by construction because the guard is a short-lived process: nothing a left-behind thread does
    can matter after the process ends, and the process ends right after the decision is delivered. What a left-behind
    pre-decision worker can still do in the short time between the overrun and that exit is limited to probe and
    health caches (the re-probe's lock file, `.attempt` marker and saved probe state): hints that can change the
    NEXT dispatch's notice or health, never a verdict. A system call already entered at the moment of the exit may
    complete; nothing is started after it."""
    box: list[tuple[_T | None, BaseException | None]] = []

    def target() -> None:
        try:
            box.append((work(), None))
        except BaseException as error:
            box.append((None, error))

    worker = threading.Thread(target=target, daemon=True, name="safo-bounded")
    worker.start()
    worker.join(max(0.0, timeout))
    if worker.is_alive() or not box:
        if run is not None:
            run.overran = True
        return False, None
    value, error = box[0]
    if error is not None:
        raise error
    return True, value


@dataclass
class Seen:
    """What the notice I/O found: the first-notice flag, the marker (notice, identity), or that it was skipped."""

    first: bool = False
    marker: tuple[str, Ident | None] | None = None
    skipped: bool = False


def io_budget(run: Run) -> float:
    """How long one batch of state-folder work may hold the hook: at most NOTICE_IO_CAP_SECONDS, at least
    NOTICE_IO_MIN_SECONDS, and not past the hard limit less a margin."""
    hard = run.hard if run.hard is not None else time.monotonic() + NOTICE_IO_CAP_SECONDS + 0.5
    return max(NOTICE_IO_MIN_SECONDS, min(NOTICE_IO_CAP_SECONDS, hard - time.monotonic() - 0.5))


def read_mode_bounded(ctx: LocalContext, run: Run) -> tuple[str, str]:
    """(mode, state) with the mode-file read under a bound. If it does not finish, the mode is unknown. The documented
    fallback for an unreadable mode file is warn, and warn would let a violation of an explicit rule through as a
    warning; so for a TIMEOUT the verdict is computed in BLOCK mode (fail closed on a slow mode file), and the line says
    so with MODE_SLOW_NOTICE."""
    done, got = run_bounded(lambda: mode_health(ctx.env), io_budget(run), run)
    return got if done and got is not None else ("block", "slow")


def bounded_reprobe(
    doc: AgentsFile, path: Path, now: float, timeout: float, deadline: float, run: Run
) -> tuple[dict[str, Any] | None, bool]:
    """The re-probe (its lock, its .attempt marker, the probe, the save of the state) under one bound: the probe's own
    total (twice the per-request time plus its slack) plus a file-work allowance, and never past the deadline.
    (state or None, slow): slow is True when the batch did not finish; its worker is left running and the process
    ends right after the decision is out (see run_bounded)."""
    budget = max(
        NOTICE_IO_MIN_SECONDS,
        min(2 * timeout + REPROBE_SLACK_SECONDS + NOTICE_IO_CAP_SECONDS, deadline - time.monotonic()),
    )
    done, fresh = run_bounded(lambda: reprobe(doc, path, now, timeout), budget, run)
    return (fresh if done else None), not done


def read_notices(folder: Path | None, path: Path | None, wants_first: bool, run: Run) -> Seen:
    """The two state-folder operations that sit between a computed decision and its emit, under a bound: the
    first-notice flag (only when the probe is not healthy) and the marker inspection. Neither may hold a deny back
    past NOTICE_IO_CAP_SECONDS (and not past the hard limit, but never under NOTICE_IO_MIN_SECONDS). If they do not
    finish they are skipped: the decision goes out without those notices, with NOTICES_SKIPPED in the line, and the
    flag and the marker are left as they were."""
    budget = io_budget(run)

    def work() -> Seen:
        first = bool(wants_first and (path is None or notice_unclaimed(path)))
        return Seen(first, log_failure_pending(folder))

    done, result = run_bounded(work, budget, run)
    return result if done and result is not None else Seen(skipped=True)


def load_config(ctx: LocalContext, args: argparse.Namespace, deadline: float, run: Run) -> AgentsFile:
    """Load agents.yaml under a wall-clock bound (see run_bounded): the load is joined for the time left (at least
    CONFIG_MIN_WAIT_SECONDS) and ABANDONED if it is still going; the guard goes on without a configuration. The limit:
    an abandoned load keeps its blocked read until the process exits (it only reads). The realistic cause is a wedged
    filesystem or kernel read: the production reader opens with O_NONBLOCK and refuses a non-regular file, so a planted
    FIFO is rejected at once and does not reach this timeout."""
    done, doc = run_bounded(
        lambda: load_agents_for(ctx, args), max(CONFIG_MIN_WAIT_SECONDS, deadline - time.monotonic()), run
    )
    if not done or doc is None:
        raise TimeoutError("configuration load exceeded the budget")
    return doc


def load_or_degrade(
    ctx: LocalContext, args: argparse.Namespace, deadline: float, run: Run, tool_input: dict[str, Any]
) -> AgentsFile | None:
    """The configuration, or None after the visible degraded allow: every rule else is off without a configuration.
    The Gemini rules need nothing from agents.yaml, so a brief that violates them is still denied."""
    try:
        return load_config(ctx, args, deadline, run)
    except TimeoutError:
        timed_out = True
    except Exception:
        timed_out = False
    reasons = gemini_reasons(
        ctx, tool_input, time.monotonic() + ISOLATED_CHECK_SECONDS if timed_out else deadline
    )
    if reasons:
        raise GeminiEventDeny("config", reasons)
    if timed_out:
        diagnostic(ctx, "timeout", run=run, shown=CONFIG_TIMEOUT_NOTICE)
    else:
        diagnostic(ctx, "config", run=run)
    return None


def finish(
    ctx: LocalContext,
    run: Run,
    folder: Path | None,
    out_text: str,
    notices: list[tuple[str, str]],
    record: dict[str, Any],
    note: str = "",
    clear: Ident | None = None,
    claim: Path | None = None,
    refresh: Path | None = None,
) -> None:
    """The shared tail of the Agent and Bash paths: build the one line (the decision plus every applicable notice, in
    priority order) and hand it to emit_then_persist. `notices` are (visible text, log code)."""
    data: dict[str, Any] = json.loads(out_text) if out_text else {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}
    if notices:
        # Keep any rule denial. A persistence failure cannot erase a computed denial.
        data["systemMessage"] = WARNING + (" " + data.get("systemMessage", "") if out_text else "")
        shown = "; ".join(text for text, _ in notices)
        data["hookSpecificOutput"]["additionalContext"] = (
            WARNING + " " + json.dumps({"health": "degraded", "diagnostic": shown})
        )
    elif note:
        context = data["hookSpecificOutput"].get("additionalContext")
        data["hookSpecificOutput"]["additionalContext"] = f"{context} {note}" if context else note
    emit_then_persist(ctx, run, data if out_text or notices or note else None, folder, record, clear, claim, refresh)


def hook_event(argv: Sequence[str] | None) -> str | None:
    """The host event a command line serves (`hooks probe` is SessionStart, `hooks guard` PreToolUse), else None."""
    words = list(argv or [])
    for first, second in itertools.pairwise(words):
        if first == "hooks" and second in ("probe", "guard"):
            return "SessionStart" if second == "probe" else "PreToolUse"
    return None


PROBE_USAGE = (
    "safo hooks probe is the SessionStart hook: Claude Code pipes the event (JSON) to it on standard input. "
    "Run by hand there is no payload to read, so nothing was probed. Try: "
    'echo \'{"session_id": "test"}\' | safo hooks probe'
)


def terminal_without_event(ctx: LocalContext) -> bool:
    """True when standard input is a terminal and no event arrives on it within a moment: a person ran the command.

    A terminal alone proves nothing (a wrapper may give the hook a pty and write the event to it), so a terminal gets a
    short wait first, and anything that does arrive is read as an event. A stream that cannot answer (no isatty, a
    closed one, no descriptor) is read as before.
    """
    stream = ctx.stdin if ctx.stdin is not None else sys.stdin
    try:
        if not stream.isatty():
            return False
        fd = stream.fileno()
    except (AttributeError, OSError, ValueError):
        return False
    try:
        return not select.select([fd], [], [], TERMINAL_WAIT_SECONDS)[0]
    except (OSError, ValueError):
        return False


def run_probe(ctx: LocalContext, args: argparse.Namespace) -> int:
    if terminal_without_event(ctx):
        ctx.say(PROBE_USAGE)  # a usage line, not a fault: no log entry, so it cannot count toward degraded health
        return EXIT_OK
    code = "input"
    try:
        payload = event_input(ctx)
        session = session_id(payload)
        code = "config"
        doc = load_agents_for(ctx, args)
        code = "probe"
        started = time.monotonic()
        results = probe_all(doc)
        # Completion time, even when the injected test clock is fixed; no start-time stamp.
        state = probe_state(results, ctx.now.timestamp() + time.monotonic() - started)
        folder = state_dir(ctx.env)
        if folder is None:
            raise OSError("state unavailable")
        code = "state-write"
        path = state_path(folder, session, doc)
        save_state(path, state)
        cwd = payload.get("cwd")
        found = None
        if isinstance(cwd, str):
            found = ctx.repo_lookup(cwd) if ctx.repo_lookup else tracking.cwd_repo(ctx.run, ctx.env, cwd)
        bound = bind_repo(path, found, payload.get("source"))
        if bound == "changed":
            code = "repo-changed"
            raise ValueError("the session's repository changed after it was bound")
        if bound == "unbound" and doc.hooks.tracking_exempt_repos:
            code = "repo-unbound"  # a resumed session whose binding is gone: no exemption until a fresh startup
            raise ValueError("the session has no bound repository")
        code = "state-write"
        prune_state(folder, ctx.now.timestamp())
        ctx.say(session_output(session_message(doc, state)))
    except TimeoutError:
        diagnostic(ctx, "timeout" if code == "input" else code, "SessionStart")
    except Exception:
        diagnostic(ctx, code, "SessionStart")
    return EXIT_OK


def private_terms_provider() -> tuple[re.Pattern[str], ...]:
    """The guard reads the private terms the way the wrapper does: the fixed config's setting and the one strict loader.
    Called only when a brief names a Gemini step; any failure to load blocks that step."""
    loc = gemini.fixed_locations()
    return gemini.load_private_terms(gemini.load_config(loc.config, loc.home).private_terms, loc.terms)


def approval_checker(ctx: LocalContext) -> ApprovalCheck | None:
    """How the guard asks whether a Gemini approval record is live. None when the folder cannot be named, which the
    rule treats as no record (a paid step is then blocked). While paid use is switched off, every paid step is refused
    with that reason."""
    try:
        enabled = gemini.paid_enabled()
    except Exception:  # a switch check that fails is "disabled": the hook never fails open
        enabled = False
    if not enabled:
        return gemini.DisabledCheck()
    try:
        loc = gemini.fixed_locations()
        store = gemini.open_store(loc, gemini.load_config(loc.config, loc.home).ledger)
    except ConfigError:
        return None
    now = ctx.now
    return lambda record_id: approval_problem(store, record_id, now)


_TOO_LARGE = (
    "gemini-material: the dispatch event is too large to check (over 8 MiB), so it is denied; "
    "shorten the brief or remove the Gemini step"
)
_UNVERIFIABLE = (
    "gemini-material: the dispatch event is too large or incomplete to check (it did not finish arriving in time), so "
    "it is denied; shorten the brief or remove the Gemini step"
)
_UNREADABLE = (
    "gemini-material: the dispatch event could not be read (too large, not valid JSON or not complete) and it names "
    "Gemini, so it is denied; shorten the brief or remove the Gemini step"
)


def gemini_reasons(ctx: LocalContext, tool_input: dict[str, Any], deadline: float) -> str:
    """The Gemini rules' findings for a brief as one string, "" when it is clean. Any failure of the check blocks."""
    prompt = tool_input.get("prompt")
    try:
        found = findings(
            prompt if isinstance(prompt, str) else "", approval_checker(ctx), private_terms_provider, deadline
        )
    except Exception:
        return "gemini-paid: the Gemini check failed, so the brief is blocked"
    return "; ".join(f"{rule}: {why}" for rule, why in found)


def guard(ctx: LocalContext, args: argparse.Namespace, started: float | None = None, run: Run | None = None) -> None:
    # The hook's whole budget is GUARD_TIMEOUT_SECONDS from the start of the process; lookups get what is left of it
    # less a margin, so the decision is always written before the host gives up on the hook.
    begun = time.monotonic() if started is None else started
    deadline = begun + GUARD_TIMEOUT_SECONDS - GUARD_MARGIN_SECONDS
    # One clock for the whole hook: the re-probe, the lookup and the log wait all draw on it, and the log wait ends
    # before the host's own timeout, so a decision is written however slow the endpoint, the tracker or the lock is.
    hard = begun + GUARD_TIMEOUT_SECONDS - LOG_MARGIN_SECONDS
    run = run or Run()
    run.hard = hard

    def probe_timeout(wanted: float) -> float:
        """Per request: what is wanted, or less when two requests and the lookup would not fit in what is left."""
        return min(wanted, (deadline - time.monotonic() - LOOKUP_RESERVE_SECONDS) / 2)

    source = EventStream(ctx)
    raw = b""
    try:
        raw, oversize = read_event(source, deadline)
        if oversize:
            raise ValueError("oversized event")
        payload = loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("invalid event")
    except EventTimeout as err:
        if not err.partial:
            raise  # nothing arrived at all: the degraded allow, as before
        found = scan_event(None, err.partial)
        raise GeminiEventDeny("timeout", _UNREADABLE if found == "marker" else _UNVERIFIABLE) from None
    except (ValueError, UnicodeError):
        # Never decided from a prefix: an oversized event is read to the end (up to the hard limit) and checked whole.
        found = scan_event(source if len(raw) > MAX_BYTES else None, raw)
        if found == "marker":
            raise GeminiEventDeny("input", _UNREADABLE) from None
        if found == "limit":
            raise GeminiEventDeny("input", _TOO_LARGE) from None
        if found == "slow":
            raise GeminiEventDeny("input", _UNVERIFIABLE) from None
        raise
    if not isinstance(payload.get("tool_name"), str):
        raise ValueError("missing tool name")
    if payload.get("tool_name") == BASH_TOOL:
        lead_wait(ctx, args, payload, deadline, run)
        return
    if payload.get("tool_name") not in AGENT_TOOLS:
        return
    if payload.get("hook_event_name") != "PreToolUse" or not isinstance(payload.get("tool_input"), dict):
        raise ValueError("invalid dispatch")
    session = session_id(payload)
    mode, mode_state = read_mode_bounded(ctx, run)
    when = ctx.now.strftime("%Y-%m-%dT%H:%M:%S")
    folder = state_dir(ctx.env)
    doc = load_or_degrade(ctx, args, deadline, run, payload["tool_input"])  # None after the visible degraded allow
    if doc is None:
        return
    # A load that finished but used the budget leaves no time for the optional lookups: they are skipped (the re-probe
    # and the issue lookup both refuse to start with no time left) and the notice says so; the decision still follows
    # the usual rules for a brief that could not be verified.
    over_budget = time.monotonic() > deadline
    path = state_path(folder, session, doc) if folder else None
    now = ctx.now.timestamp()

    # The verdict never depends on state writes: probe state, the re-probe's lock and .attempt marker, the save of the
    # state, and the bound-repository read (with its utime) only decide HEALTH and the repository binding. They run
    # under a bound; if one does not finish, health is unknown, the binding is "not bound" (the existing fallback: no
    # exemption), no more state work is done in this dispatch, and the verdict is computed from the config alone.
    def read_phase() -> tuple[dict[str, Any] | None, bool, str | None]:
        attempted_before = path is not None and os.path.lexists(attempt_path(path))
        return read_state(path), attempted_before, read_bound_repo(path, refresh=False)  # a pure read

    done, got = run_bounded(read_phase, io_budget(run), run)
    slow = not done or got is None
    state, attempted, bound = got if got is not None else (None, True, None)
    health = "unknown" if slow else state_health(state, doc.hooks.max_state_age_seconds, now)
    first_probe = False  # no state for this configuration, so the first dispatch under it probed at once
    probe_code = "probe"  # what the visible notice says; the log keeps its fixed enum
    needs_probe = not slow and path is not None and (health == "stale" or state is None)
    if needs_probe and probe_timeout(REPROBE_TIMEOUT_SECONDS) < MIN_REPROBE_TIMEOUT_SECONDS:
        # Too little of the hook's budget is left to ask an endpoint: skip the re-probe (nothing is claimed, so the
        # next dispatch may still try) and say so in the notice rather than risk the host killing the hook.
        probe_code = "reprobe-skipped"
    elif needs_probe and path is not None and health == "stale":
        # The configured age ran out mid-session: ask again, bounded and at most once a minute, and keep the answer.
        fresh, slow = bounded_reprobe(doc, path, now, probe_timeout(REPROBE_TIMEOUT_SECONDS), deadline, run)
        if fresh is not None:
            state, health = fresh, "healthy"
    elif needs_probe and path is not None:
        # Editing agents.yaml changes the state key and orphans the saved state. With no attempt recorded for the new
        # key, the claim succeeds at once (the one-a-minute limit has nothing to count from) and the probe gets longer;
        # a key that already has an attempt, however it got there, is retried only at the usual rate.
        first_probe = not attempted
        wanted = CONFIG_REPROBE_TIMEOUT_SECONDS if first_probe else REPROBE_TIMEOUT_SECONDS
        fresh, slow = bounded_reprobe(doc, path, now, probe_timeout(wanted), deadline, run)
        if fresh is not None and not (first_probe and not fresh["reachable"]):
            state, health = fresh, "healthy"
        elif first_probe:
            # The re-probe found nothing: a real outage or a miss, never reported as the edit it followed.
            probe_code = "reprobe-timeout"
            first_probe = False
    if slow:
        state, health, first_probe = None, "unknown", False
    # A stale (not refreshed) or unknown state disables ONLY the local-step rule, keeping model/approval checks.
    reachable = health == "healthy" and state is not None and state["reachable"] is True

    def remaining() -> float:
        return deadline - time.monotonic()

    resolve = ctx.issue_lookup or tracking.gh_resolver(ctx.run, ctx.which, ctx.env, remaining)
    # `bound` was read above (bound at SessionStart; never read from the working tree here)

    def repo() -> str | None:
        return bound

    try:
        verdict = check_dispatch(
            doc,
            payload["tool_input"],
            reachable,
            resolve,
            repo,
            approval_check=approval_checker(ctx),
            terms=private_terms_provider,
            deadline=deadline,
        )
    except Exception:
        # Another rule failed (tracking, the lookup, anything). The Gemini rules get their own fresh, short check, so a
        # failure elsewhere can never cancel a denial: a violation is denied, a clean brief is the degraded allow.
        reasons = gemini_reasons(ctx, payload["tool_input"], time.monotonic() + ISOLATED_CHECK_SECONDS)
        if reasons:
            raise GeminiEventDeny("unexpected", reasons) from None
        raise
    decision = decide(verdict, mode)
    run.deny = decision == "deny"  # known from here on: an unexpected failure before the emit must still block
    # One visible notice per session for a probe that cannot be trusted; every dispatch is still logged with its health.
    # No state I/O at all after a slow state folder.
    seen = Seen() if slow else read_notices(folder, path, health != "healthy", run)
    marker = seen.marker
    # Every applicable notice goes in the line, highest priority first; the marker is cleared only once its notice is
    # in a delivered line, so a higher-priority notice never consumes it.
    notices: list[tuple[str, str]] = []
    if mode_state == "slow":
        notices.append((MODE_SLOW_NOTICE, "timeout"))
    elif mode_state != "healthy":
        notices.append(("mode", "mode"))
    if slow:
        notices.append((STATE_SLOW_NOTICE, "timeout"))
    if seen.skipped:
        notices.append((NOTICES_SKIPPED, "timeout"))
    if marker:
        notices.append((marker[0], "log-write"))
    if over_budget:
        notices.append((BUDGET_NOTICE, "timeout"))
    if health != "healthy" and seen.first:  # the probe notice is once per session: only while it is unclaimed
        notices.append((probe_code, "probe"))  # the log's enum has one probe code; the notice is specific
    output = guard_output(decision, verdict)
    note = ""
    if first_probe and not notices:
        note = (
            "SAFO: no saved probe for this configuration (agents.yaml was edited mid-session, or this session has no "
            "probe yet), so the local LLM was probed now. A tracking_exempt_repos binding does not carry over to a new "
            "configuration: until the next session start no repository is exempt, and a brief without an open issue "
            "line is flagged."
        )
    code = notices[0][1] if notices else ""
    record = log_record(
        when, decision, mode, verdict, reachable, "degraded" if mode_state != "healthy" else health, code
    )
    finish(
        ctx,
        run,
        folder,
        output,
        notices,
        record,
        note,
        marker[1] if marker else None,
        path if seen.first else None,
        path if bound else None,
    )


def lead_wait(
    ctx: LocalContext,
    args: argparse.Namespace,
    payload: dict[str, Any],
    deadline: float,
    run: Run,
) -> None:
    """The lead-never-waits rule for one Bash call. Quiet and cheap for the usual call: nothing is read, logged or
    printed unless the command could wait, it is not run in the background and the session is the lead's."""
    if payload.get("agent_id") is not None:
        return  # the host adds agent_id to events raised inside a sub-agent; a monitor agent is allowed to watch
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(tool_input, dict) or not isinstance(command, str):
        raise ValueError("invalid command")
    if tool_input.get("run_in_background") is True or not leadwait.may_wait(command, deadline):
        return
    if payload.get("hook_event_name") != "PreToolUse":
        raise ValueError("invalid command event")
    doc = load_or_degrade(ctx, args, deadline, run)
    if doc is None:
        return
    setting = doc.hooks.lead_wait
    if setting.mode == "off":
        return
    kinds = leadwait.find_waits(command, setting.sleep_threshold_seconds, deadline)
    if not kinds:
        return
    session = session_id(payload)
    mode, mode_state = read_mode_bounded(ctx, run)
    effective = mode if setting.mode == "follow" else setting.mode
    folder = state_dir(ctx.env)
    path = state_path(folder, session, doc) if folder else None
    # Two exemptions, both with a stated reason: a comment on the call itself, or a repository listed with its reason in
    # agents.yaml (matched against the repository bound at SessionStart, never the working tree).
    # The bound-repository read (it also touches the file) runs under a bound. If it does not finish the repository
    # counts as not bound, the existing fallback: no exemption, so the wait is judged by the rule.
    done, bound_repo = run_bounded(lambda: read_bound_repo(path, refresh=False), io_budget(run), run)
    slow = not done
    exempt = bool(leadwait.marker_reason(command, deadline)) or tracking.exempt(
        bound_repo if done else None, tuple(e.repo for e in setting.exempt_repos)
    )
    verdict = Verdict((LEAD_WAITS,), (leadwait.message(kinds),), "", False, False)
    decision = "allow" if exempt else decide(verdict, effective)
    run.deny = decision == "deny"
    seen = Seen() if slow else read_notices(folder, path, False, run)  # bounded; none after a slow state folder
    marker = seen.marker
    notices: list[tuple[str, str]] = []
    if mode_state == "slow":
        notices.append((MODE_SLOW_NOTICE, "timeout"))
    elif mode_state != "healthy":
        notices.append(("mode", "mode"))
    if slow:
        notices.append((STATE_SLOW_NOTICE, "timeout"))
    if seen.skipped:
        notices.append((NOTICES_SKIPPED, "timeout"))
    if marker:
        notices.append((marker[0], "log-write"))
    output = guard_output(decision, verdict, "Delegate the wait; do not hold the lead's thread.")
    when = ctx.now.strftime("%Y-%m-%dT%H:%M:%S")
    health = "degraded" if mode_state != "healthy" else "healthy"
    record = log_record(when, decision, effective, verdict, False, health, notices[0][1] if notices else "")
    finish(
        ctx, run, folder, output, notices, record, "", marker[1] if marker else None, None, path if bound_repo else None
    )


def run_guard(ctx: LocalContext, args: argparse.Namespace) -> int:
    begun = time.monotonic()
    run = Run(hard=begun + GUARD_TIMEOUT_SECONDS - LOG_MARGIN_SECONDS)
    code = ""
    deny = ""
    try:
        guard(ctx, args, begun, run)
    except GeminiEventDeny as err:
        code, deny = err.code, err.reason
    except TimeoutError:
        code = "timeout"
    except (ValueError, UnicodeError):
        code = "input"
    except Exception:
        code = "unexpected"
    if code and not run.attempted:  # once any byte of a decision was attempted, nothing else is ever written
        if run.deny:
            run.failed = True  # a denial was computed but cannot be delivered: block on the exit code, say nothing else
        else:
            try:
                diagnostic(ctx, code, run=run, deny=deny)
            except Exception:
                run.failed = True
    return exit_code(run)


def guard_process(ctx: LocalContext, args: argparse.Namespace) -> int:
    """`safo hooks guard` as a process: run the guard, then END the process through hard_exit with its exit code, even
    when everything finished normally. Interpreter shutdown would otherwise wait for any non-daemon thread and could
    let a left-behind worker run on; os._exit cannot. (Where hard_exit is replaced, as in tests, the code is
    returned.)"""
    code = run_guard(ctx, args)
    with contextlib.suppress(Exception):
        ctx.out.flush()
    hard_exit(code)
    return code


def settings_bytes(path: Path) -> bytes | None:
    try:
        return bounded_read(path)
    except FileNotFoundError:
        return None


def identity(path: Path) -> tuple[int, int, int, int] | None:
    """Which file this is, not only what it says: device, inode, size and modification time. None when absent."""
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return None
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def read_settings(path: Path) -> Any:
    try:
        raw = settings_bytes(path)
        return loads(raw) if raw is not None else {}
    except (OSError, ValueError, UnicodeError):
        raise ConfigError("settings: invalid JSON, nonregular or oversized file; fix it by hand first") from None


def install_settings(target: Path, probe_command: str, guard_command: str, dry_run: bool = False) -> bool:
    try:
        return _install_locked(target, probe_command, guard_command, dry_run)
    except TimeoutError:
        raise ConfigError("settings: another installer holds the lock; nothing changed, try again") from None


def _install_locked(target: Path, probe_command: str, guard_command: str, dry_run: bool) -> bool:
    with (
        contextlib.nullcontext()
        if dry_run
        else file_lock(target.with_name(target.name + ".safo.lock"), check_dir=False)
    ):
        try:
            seen = identity(target)
            original = settings_bytes(target)
            if identity(target) != seen:
                raise ConfigError("settings changed while installing; nothing replaced")
            settings = loads(original) if original is not None else {}
            settings, changed = merge_settings(settings, probe_command, guard_command)
            if not changed or dry_run:
                return changed
            mode = target.stat().st_mode & 0o777 if original is not None else 0o600
            backup: Path | None = None
            if original is not None:
                # A retained private random backup precedes replacement; never truncate a pre-existing name.
                fd, name = tempfile.mkstemp(prefix=f".{target.name}.backup-", dir=target.parent)
                backup = Path(name)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(original)
                    handle.flush()
                    os.fsync(handle.fileno())

            # Cooperating installers share the lock. External writers must not change the originally read bytes.
            # A conflict replaces nothing, so the backup it would have protected is removed; a failed write keeps it.
            # The identity is checked as well as the bytes: a writer that swaps in a new file with the same bytes
            # (an editor's rename, a dotfiles sync) passes a bytes-only check and would then be overwritten.
            def unchanged() -> None:
                if settings_bytes(target) != original:
                    if backup is not None:
                        backup.unlink(missing_ok=True)
                    raise ConfigError("settings: concurrent edit detected; nothing replaced")
                if identity(target) != seen:
                    if backup is not None:
                        backup.unlink(missing_ok=True)
                    raise ConfigError("settings changed while installing; nothing replaced")

            unchanged()
            write_text(target, json.dumps(settings, indent=2) + "\n", mode, before_replace=unchanged, check_dir=False)
            return True
        except (OSError, ValueError, UnicodeError):
            raise ConfigError("settings: invalid JSON, nonregular file or write failure; nothing replaced") from None


def hook_command(args: argparse.Namespace, subcommand: str) -> str:
    if not COMMAND.fullmatch(args.command):
        raise ConfigError("--command: expected a program and arguments of letters, digits and . _ / - only")
    launcher = tuple(shlex.split(args.command))
    if launcher not in (("safo",), ("python3", "-m", "safo")):
        if len(launcher) != 1 or not is_safo_path(launcher[0]):
            raise ConfigError(
                "--command: supported launchers are safo, python3 -m safo, or the absolute path of a safo executable"
            )
        try:
            regular = stat.S_ISREG(os.stat(launcher[0]).st_mode)  # follows a pipx symlink to the real script
        except OSError:
            regular = False
        if not regular or not os.access(launcher[0], os.X_OK):
            raise ConfigError("--command: the safo path is not an existing regular executable file")
    command = f"{args.command} hooks {subcommand}"
    for flag, value in (("--agents", args.agents), ("--agents-local", args.agents_local)):
        if value:
            command += f" {flag} {shlex.quote(str(Path(value).resolve()))}"
    return command


def write_mode(ctx: LocalContext, value: str) -> None:
    folder = config_dir(ctx.env)
    if folder is None:
        raise ConfigError("HOME is not set, so there is nowhere to keep the guard mode")
    try:
        write_text(folder / guardlog.MODE_NAME, value + "\n")
    except PermissionError as exc:
        raise ConfigError(
            f"the guard mode cannot be kept in {folder.name}: {exc}; make it private with chmod 700 on that directory"
        ) from exc


def run_install(ctx: LocalContext, args: argparse.Namespace) -> int:
    given = Path(args.settings) if args.settings else ctx.home / ".claude" / "settings.json"
    target = given.resolve()  # a settings.json that is a symlink into a dotfiles repo stays a symlink
    probe_command, guard_command = hook_command(args, "probe"), hook_command(args, "guard")
    if args.guard_mode and not ctx.dry_run:
        write_mode(ctx, args.guard_mode)  # first: a refused config directory must leave settings.json untouched
    changed = install_settings(target, probe_command, guard_command, ctx.dry_run)
    if not changed:
        ctx.say(f"already installed in {given}: nothing changed")
    elif ctx.dry_run:
        ctx.say(f"dry run: would add the SessionStart probe and the PreToolUse (Agent and Bash) guard to {given}")
    else:
        ctx.say(f"installed the SessionStart probe and the PreToolUse (Agent and Bash) guard in {given}")
    if args.guard_mode and not ctx.dry_run:
        ctx.say(f"guard mode: {args.guard_mode}")
    ctx.say(
        f"The guard is in {read_mode(ctx.env)} mode. Start with warn, read `safo hooks status`, "
        "then switch with `safo hooks mode block`."
    )
    return EXIT_OK


def run_mode(ctx: LocalContext, args: argparse.Namespace) -> int:
    if ctx.dry_run:
        ctx.say(f"dry run: would set the guard mode to {args.value}")
        return EXIT_OK
    write_mode(ctx, args.value)
    what = "denies a dispatch that breaks a rule" if args.value == "block" else "reports a broken rule and allows it"
    ctx.say(f"guard mode: {args.value} ({what})")
    return EXIT_OK


def run_status(ctx: LocalContext, args: argparse.Namespace) -> int:
    for line in guard_lines(ctx.env):
        ctx.say(line)
    # No session supplied: report unknown; never pick another session's cached state.
    if not args.session:
        ctx.say("  local LLM probe: unknown (supply --session and matching --agents)")
        return EXIT_OK
    try:
        doc = load_agents_for(ctx, args)
        folder = state_dir(ctx.env)
        state = read_state(state_path(folder, args.session, doc)) if folder else None
        health = state_health(state, doc.hooks.max_state_age_seconds, ctx.now.timestamp())
    except (OSError, ValueError, ConfigError):
        state, health = None, "unknown"
    if health == "healthy" and state is not None:
        minutes = int((ctx.now.timestamp() - state["ts"]) // 60)
        ctx.say(
            f"  local LLM probe: {'reachable' if state['reachable'] else 'unreachable'}, {minutes} min ago (healthy)"
        )
    else:
        issue = (
            "expired" if health == "stale" else ("future/clock rollback" if state is not None else "missing or invalid")
        )
        ctx.say(f"  local LLM probe: {health} ({issue}; local-step rule disabled)")
    return EXIT_OK


ACTIONS = {
    "install": run_install,
    "probe": run_probe,
    "guard": guard_process,
    "mode": run_mode,
    "status": run_status,
}


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    return ACTIONS[args.action](ctx, args)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="action", required=True)
    install = sub.add_parser("install", help="add the probe and the guard to a Claude Code settings.json")
    add_agents_arguments(install)
    install.add_argument("--settings", default="", help="the settings file (default: ~/.claude/settings.json)")
    install.add_argument(
        "--mode", dest="guard_mode", choices=MODES, default="", help="also set the guard mode (default: leave it)"
    )
    install.add_argument(
        "--command",
        default="safo",
        help="how the hooks run safo: safo, python3 -m safo, or the absolute path of a safo executable (default: safo)",
    )
    probe = sub.add_parser("probe", help="SessionStart hook: is the local LLM reachable?")
    add_agents_arguments(probe)
    guard_help = "PreToolUse hook on the Agent and Bash tools: check the brief, or a foreground wait (JSON on stdin)"
    guard_parser = sub.add_parser("guard", help=guard_help, description=guard_help)
    add_agents_arguments(guard_parser)
    mode = sub.add_parser("mode", help="warn (report) or block (deny) a dispatch that breaks a rule")
    mode.add_argument("value", choices=MODES)
    status = sub.add_parser("status", help="the guard mode and retained counts")
    add_agents_arguments(status)
    status.add_argument("--session", default="", help="session identity for the matching probe state")


register_local(
    LocalMode("hooks", "enforce the routing rules in Claude Code (session probe, dispatch guard)", add_arguments, run)
)
