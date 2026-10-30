# SPDX-License-Identifier: Apache-2.0
"""hooks: install, run and inspect the Claude Code hooks that enforce the routing rules in agents.yaml.

    safo hooks install [--settings PATH] [--mode warn|block]   add the probe and the guard to a settings.json
    safo hooks probe                                           SessionStart: is the local LLM reachable?
    safo hooks guard                                           PreToolUse (Agent, Bash): check the brief, or the wait
    safo hooks mode warn|block                                 warn reports; block denies a dispatch that breaks a rule
    safo hooks status                                          the mode and the counts

`probe` and `guard` fail open on hook errors. A fixed warning and bounded diagnostic visibly report degradation.
A computed block-mode denial is retained if only logging fails.
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
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from safo import gemini, geminibrief, guardlog, leadwait, tracking
from safo.bounded import MAX_BYTES, loads
from safo.context import LocalContext
from safo.errors import EXIT_OK, ConfigError
from safo.gemini import approval_problem
from safo.geminibrief import ApprovalCheck, findings
from safo.guardlog import (
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
    GUARD_MARGIN_SECONDS,
    GUARD_TIMEOUT_SECONDS,
    LEAD_WAITS,
    Verdict,
    append_log,
    bind_repo,
    check_dispatch,
    decide,
    first_notice,
    guard_output,
    is_safo_path,
    log_record,
    merge_settings,
    probe_all,
    probe_state,
    prune_state,
    read_bound_repo,
    read_state,
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
        self.risk = self.command_expansion = False
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
            if "\\" in view or "$'" in view:
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
                if "for " in view:
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
            if "--" in view or "approve" in view:
                self.risk = self.risk or bool(geminibrief._RISK_OPTION.search(view))
            if "$" in view:
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
            or (self.risk and self.command_expansion)
            or (self.safo and self.gemini)
            or (surface and bool(self.assigned & self.referenced))
        )


def read_event(source: EventStream) -> tuple[bytes, bool]:
    """(the event as read, whether it is over the cap). At most MAX_BYTES + 1 bytes are kept; EventTimeout when the
    event stalls for STDIN_TIMEOUT_SECONDS."""
    deadline = time.monotonic() + STDIN_TIMEOUT_SECONDS if source.fd is not None else 0.0
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


def diagnostic(ctx: LocalContext, code: str, event: str = "PreToolUse", deny: str = "") -> None:
    """Fixed visible warning plus a bounded enum-only record; no exception text or input values."""
    folder = state_dir(ctx.env)
    if folder is not None:
        with contextlib.suppress(OSError, ValueError):
            append_log(
                folder / guardlog.LOG_NAME,
                log_record(
                    ctx.now.strftime("%Y-%m-%dT%H:%M:%S"),
                    "error",
                    read_mode(ctx.env),
                    None,
                    False,
                    "degraded",
                    code,
                ),
            )
    data: dict[str, Any] = {
        "systemMessage": WARNING,
        "hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": WARNING + " " + json.dumps({"health": "degraded", "diagnostic": code}),
        },
    }
    if deny:  # the Gemini rules deny even when the rest is degraded; the diagnostic stays in the same answer
        data["hookSpecificOutput"]["permissionDecision"] = "deny"
        data["hookSpecificOutput"]["permissionDecisionReason"] = "safo hooks guard: " + deny
    ctx.say(json.dumps(data))


def hook_event(argv: Sequence[str] | None) -> str | None:
    """The host event a command line serves (`hooks probe` is SessionStart, `hooks guard` PreToolUse), else None."""
    words = list(argv or [])
    for first, second in itertools.pairwise(words):
        if first == "hooks" and second in ("probe", "guard"):
            return "SessionStart" if second == "probe" else "PreToolUse"
    return None


def run_probe(ctx: LocalContext, args: argparse.Namespace) -> int:
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


def guard(ctx: LocalContext, args: argparse.Namespace, started: float | None = None) -> None:
    # The hook's whole budget is GUARD_TIMEOUT_SECONDS from the start of the process; lookups get what is left of it
    # less a margin, so the decision is always written before the host gives up on the hook.
    deadline = (time.monotonic() if started is None else started) + GUARD_TIMEOUT_SECONDS - GUARD_MARGIN_SECONDS
    source = EventStream(ctx)
    raw = b""
    try:
        raw, oversize = read_event(source)
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
        lead_wait(ctx, args, payload, deadline)
        return
    if payload.get("tool_name") not in AGENT_TOOLS:
        return
    if payload.get("hook_event_name") != "PreToolUse" or not isinstance(payload.get("tool_input"), dict):
        raise ValueError("invalid dispatch")
    session = session_id(payload)
    mode, mode_state = mode_health(ctx.env)
    when = ctx.now.strftime("%Y-%m-%dT%H:%M:%S")
    folder = state_dir(ctx.env)
    try:
        doc = load_agents_for(ctx, args)
    except Exception:
        # The other rules are off (visible degraded allow), but the Gemini rules need nothing from agents.yaml.
        reasons = gemini_reasons(ctx, payload["tool_input"], deadline)
        if reasons:
            raise GeminiEventDeny("config", reasons) from None
        diagnostic(ctx, "config")
        return
    path = state_path(folder, session, doc) if folder else None
    state = read_state(path)
    now = ctx.now.timestamp()
    health = state_health(state, doc.hooks.max_state_age_seconds, now)
    if health == "stale" and path is not None:
        # The configured age ran out mid-session: ask again, bounded and at most once a minute, and keep the answer.
        fresh = reprobe(doc, path, now)
        if fresh is not None:
            state, health = fresh, "healthy"
    # A stale (not refreshed) or unknown state disables ONLY the local-step rule, keeping model/approval checks.
    reachable = health == "healthy" and state is not None and state["reachable"] is True

    def remaining() -> float:
        return deadline - time.monotonic()

    resolve = ctx.issue_lookup or tracking.gh_resolver(ctx.run, ctx.which, ctx.env, remaining)
    bound = read_bound_repo(path)  # bound at SessionStart; never read from the working tree here

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
    # One visible notice per session for a probe that cannot be trusted; every dispatch is still logged with its health.
    notice = health != "healthy" and (path is None or first_notice(path))
    degraded = mode_state != "healthy" or notice
    code = "mode" if mode_state != "healthy" else ("probe" if health != "healthy" else "")
    try:
        if folder is None:
            raise OSError("log unavailable")
        append_log(
            folder / guardlog.LOG_NAME,
            log_record(
                when, decision, mode, verdict, reachable, "degraded" if mode_state != "healthy" else health, code
            ),
        )
    except (OSError, ValueError):
        degraded = True
        code = "log-write"
    output = guard_output(decision, verdict)
    data: dict[str, Any] = json.loads(output) if output else {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}
    if degraded:
        # Keep any rule denial. A persistence failure cannot erase a computed denial.
        data["systemMessage"] = WARNING + (" " + data.get("systemMessage", "") if output else "")
        data["hookSpecificOutput"]["additionalContext"] = (
            WARNING + " " + json.dumps({"health": "degraded", "diagnostic": code})
        )
    if output or degraded:
        ctx.say(json.dumps(data))


def lead_wait(ctx: LocalContext, args: argparse.Namespace, payload: dict[str, Any], deadline: float) -> None:
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
    try:
        doc = load_agents_for(ctx, args)
    except Exception:
        diagnostic(ctx, "config")
        return
    setting = doc.hooks.lead_wait
    if setting.mode == "off":
        return
    kinds = leadwait.find_waits(command, setting.sleep_threshold_seconds, deadline)
    if not kinds:
        return
    session = session_id(payload)
    mode, mode_state = mode_health(ctx.env)
    effective = mode if setting.mode == "follow" else setting.mode
    folder = state_dir(ctx.env)
    path = state_path(folder, session, doc) if folder else None
    # Two exemptions, both with a stated reason: a comment on the call itself, or a repository listed with its reason in
    # agents.yaml (matched against the repository bound at SessionStart, never the working tree).
    exempt = bool(leadwait.marker_reason(command, deadline)) or tracking.exempt(
        read_bound_repo(path), tuple(e.repo for e in setting.exempt_repos)
    )
    verdict = Verdict((LEAD_WAITS,), (leadwait.message(kinds),), "", False, False)
    decision = "allow" if exempt else decide(verdict, effective)
    degraded = mode_state != "healthy"
    code = "mode" if degraded else ""
    try:
        if folder is None:
            raise OSError("log unavailable")
        when = ctx.now.strftime("%Y-%m-%dT%H:%M:%S")
        append_log(
            folder / guardlog.LOG_NAME,
            log_record(when, decision, effective, verdict, False, "degraded" if degraded else "healthy", code),
        )
    except (OSError, ValueError):
        degraded, code = True, "log-write"
    output = guard_output(decision, verdict, "Delegate the wait; do not hold the lead's thread.")
    data: dict[str, Any] = json.loads(output) if output else {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}
    if degraded:
        data["systemMessage"] = WARNING + (" " + data.get("systemMessage", "") if output else "")
        data["hookSpecificOutput"]["additionalContext"] = (
            WARNING + " " + json.dumps({"health": "degraded", "diagnostic": code})
        )
    if output or degraded:
        ctx.say(json.dumps(data))


def run_guard(ctx: LocalContext, args: argparse.Namespace) -> int:
    try:
        guard(ctx, args, time.monotonic())
    except GeminiEventDeny as err:
        diagnostic(ctx, err.code, deny=err.reason)
    except TimeoutError:
        diagnostic(ctx, "timeout")
    except (ValueError, UnicodeError):
        diagnostic(ctx, "input")
    except Exception:
        diagnostic(ctx, "unexpected")
    return EXIT_OK


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
    "guard": run_guard,
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
