# SPDX-License-Identifier: MIT
"""hooks: install, run and inspect the Claude Code hooks that enforce the routing rules in agents.yaml.

    safo hooks install [--settings PATH] [--mode warn|block]   add the probe and the guard to a settings.json
    safo hooks probe                                           SessionStart: is the local LLM reachable?
    safo hooks guard                                           PreToolUse (Agent): check the brief, read from stdin
    safo hooks mode warn|block                                 warn reports; block denies a dispatch that breaks a rule
    safo hooks status                                          the mode and the counts

`probe` and `guard` fail open on hook errors. A fixed warning and bounded diagnostic visibly report degradation.
A computed block-mode denial is retained if only logging fails.
"""

from __future__ import annotations

import argparse
import contextlib
import itertools
import json
import os
import select
import shlex
import stat
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from safo import guardlog
from safo.bounded import MAX_BYTES, loads
from safo.context import LocalContext
from safo.errors import EXIT_OK, ConfigError
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
    COMMAND,
    append_log,
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


def event_input(ctx: LocalContext) -> dict[str, Any]:
    """The event as a mapping. Reads at most MAX_BYTES + 1 bytes and gives up after STDIN_TIMEOUT_SECONDS.

    A real descriptor is read with `select`, so a writer that never writes or never closes cannot hold the hook until
    the host kills it; a stream with no descriptor (a test's StringIO) is read in one bounded call.
    """
    stream = ctx.stdin if ctx.stdin is not None else sys.stdin
    try:
        fd = stream.fileno()
    except (AttributeError, OSError, ValueError):  # io.UnsupportedOperation is both OSError and ValueError
        raw: str | bytes = stream.read(MAX_BYTES + 1)
    else:
        deadline = time.monotonic() + STDIN_TIMEOUT_SECONDS
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_BYTES:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([fd], [], [], left)[0]:
                raise TimeoutError("no event on standard input")
            chunk = os.read(fd, min(65_536, MAX_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
    payload = loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("invalid event")
    return payload


def session_id(payload: dict[str, Any]) -> str:
    value = payload.get("session_id")
    if not isinstance(value, str) or not value or len(value) > 256 or any(ord(c) < 32 for c in value):
        raise ValueError("invalid session identity")
    return value


def diagnostic(ctx: LocalContext, code: str, event: str = "PreToolUse") -> None:
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
    ctx.say(
        json.dumps(
            {
                "systemMessage": WARNING,
                "hookSpecificOutput": {
                    "hookEventName": event,
                    "additionalContext": WARNING + " " + json.dumps({"health": "degraded", "diagnostic": code}),
                },
            }
        )
    )


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
        save_state(state_path(folder, session, doc), state)
        prune_state(folder, ctx.now.timestamp())
        ctx.say(session_output(session_message(doc, state)))
    except TimeoutError:
        diagnostic(ctx, "timeout" if code == "input" else code, "SessionStart")
    except Exception:
        diagnostic(ctx, code, "SessionStart")
    return EXIT_OK


def guard(ctx: LocalContext, args: argparse.Namespace) -> None:
    payload = event_input(ctx)
    if not isinstance(payload.get("tool_name"), str):
        raise ValueError("missing tool name")
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
        diagnostic(ctx, "config")  # all rules disabled, visible degraded allow
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
    verdict = check_dispatch(doc, payload["tool_input"], reachable)
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


def run_guard(ctx: LocalContext, args: argparse.Namespace) -> int:
    try:
        guard(ctx, args)
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
    write_text(folder / guardlog.MODE_NAME, value + "\n")


def run_install(ctx: LocalContext, args: argparse.Namespace) -> int:
    given = Path(args.settings) if args.settings else ctx.home / ".claude" / "settings.json"
    target = given.resolve()  # a settings.json that is a symlink into a dotfiles repo stays a symlink
    changed = install_settings(target, hook_command(args, "probe"), hook_command(args, "guard"), ctx.dry_run)
    if not changed:
        ctx.say(f"already installed in {given}: nothing changed")
    elif ctx.dry_run:
        ctx.say(f"dry run: would add the SessionStart probe and the PreToolUse (Agent) guard to {given}")
    else:
        ctx.say(f"installed the SessionStart probe and the PreToolUse (Agent) guard in {given}")
    if args.guard_mode and not ctx.dry_run:
        write_mode(ctx, args.guard_mode)
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
    guard_parser = sub.add_parser("guard", help="PreToolUse hook on the Agent tool: check the brief (JSON on stdin)")
    add_agents_arguments(guard_parser)
    mode = sub.add_parser("mode", help="warn (report) or block (deny) a dispatch that breaks a rule")
    mode.add_argument("value", choices=MODES)
    status = sub.add_parser("status", help="the guard mode and retained counts")
    add_agents_arguments(status)
    status.add_argument("--session", default="", help="session identity for the matching probe state")


register_local(
    LocalMode("hooks", "enforce the routing rules in Claude Code (session probe, dispatch guard)", add_arguments, run)
)
