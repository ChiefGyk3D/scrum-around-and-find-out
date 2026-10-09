# SPDX-License-Identifier: MIT
"""Claude Code hooks that enforce the routing rules: a session probe and a dispatch guard.

The probe runs when a session starts. It asks every Ollama endpoint in agents.yaml which models are loaded (two short
GETs, never a generate), saves the answer and tells the session whether the local LLM is reachable. The guard runs
before every Agent tool call and checks the brief against the rules in agents.yaml: an explicit model, the approval
token for a model that needs the maintainer's OK, and, while the local LLM is reachable, a named local step or a stated
reason for none.

A hook must never break the session it serves, so every function the guard calls either returns a verdict or the caller
fails open. The log records the verdict and never the brief, the description or any other prompt text.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import shlex
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from safo.agentsfile import Agent, AgentsFile, Endpoint
from safo.bounded import loads
from safo.errors import ConfigError
from safo.guardlog import (
    FILE_CAP,
    RECORD_CAP,
    bounded_read,
    ensure_dir,
    file_lock,
    finite_time,
    trusted_dir,
    valid_record,
)
from safo.guardlog import (
    write_text as write_text,
)
from safo.ollama import Probe, probe

AGENT_TOOLS = ("Agent", "Task")  # the tool is Agent today and was called Task before
FORK_TYPES = ("fork",)  # a fork inherits its parent's model, so it has none to name
LOG_LIMIT_BYTES = 4 * 1024 * 1024  # past this the log moves to log.jsonl.1 and starts again
PROBE_TIMEOUT_SECONDS = 15
GUARD_TIMEOUT_SECONDS = 10  # room for one lazy re-probe: two requests per endpoint at REPROBE_TIMEOUT_SECONDS
REPROBE_INTERVAL_SECONDS = 60  # a stale state is refreshed at most this often per session and configuration
REPROBE_TIMEOUT_SECONDS = 1.5  # per request; the guard sits in front of every dispatch, so this stays short

NO_MODEL = "no-model"
APPROVAL = "approval"
NO_LOCAL_STEP = "no-local-step"
UNKNOWN_MODEL = "unknown-model"
RULES = (NO_MODEL, UNKNOWN_MODEL, APPROVAL, NO_LOCAL_STEP)


# -- the probe -------------------------------------------------------------------------------------


def probe_all(doc: AgentsFile, probe_one: Callable[[Endpoint], Probe] = probe) -> list[tuple[Endpoint, Probe]]:
    """Every endpoint asked at once, so a session start waits for the slowest one and not for the sum."""
    endpoints = [e for a in doc.agents for e in a.endpoints]
    if not endpoints:
        return []
    with ThreadPoolExecutor(max_workers=len(endpoints)) as pool:
        return list(zip(endpoints, pool.map(probe_one, endpoints), strict=True))


def probe_state(results: list[tuple[Endpoint, Probe]], when: float) -> dict[str, Any]:
    """What the guard needs later. Reachable means a general endpoint answered; a guard-only server is not routed to."""
    rows = [{"general": "general" in e.roles, "reachable": p.reachable} for e, p in results]
    return {"ts": when, "reachable": any(r["general"] and r["reachable"] for r in rows), "endpoints": rows}


def unprobed_state(when: float) -> dict[str, Any]:
    return {"ts": when, "reachable": False, "endpoints": []}


def session_message(doc: AgentsFile | None, state: dict[str, Any]) -> str:
    """The one line the session starts with: whether the local LLM is there, and what the briefs must then say."""
    if doc is None:
        return "Local LLM: not checked (agents.yaml could not be read); treat it as unreachable."
    if not state["reachable"]:
        return (
            "Local LLM: UNREACHABLE from this session (off the network it lives on, or the server is down). "
            "Route text work to Haiku or Sonnet instead; the local-step line is not required in briefs."
        )
    return (
        "Local LLM: REACHABLE. Text work goes local first; grouping and counting are done in code. "
        "Every Agent brief must name a configured local step or give the configured not-applicable marker and reason."
    )


def session_output(message: str) -> str:
    return json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": message}})


def read_state(path: Path | None) -> dict[str, Any] | None:
    if path is not None and not trusted_dir(path.parent):
        return None  # a folder another user could have written holds no state we trust
    try:
        raw = bounded_read(path) if path else b""
        state = loads(raw)
    except (OSError, ValueError, UnicodeError):
        return None
    ok = isinstance(state, dict) and isinstance(state.get("reachable"), bool)
    return state if ok and finite_time(state.get("ts")) else None


def state_health(state: dict[str, Any] | None, max_age: int, now: float) -> str:
    if state is None or not finite_time(now):
        return "unknown"
    age = now - state["ts"]
    if age < 0:
        return "unknown"  # clock rollback/future state, never described as zero minutes old
    return "stale" if age > max_age else "healthy"  # the configured age, as given: no clamp


def local_reachable(state: dict[str, Any] | None, max_age: int, now: float) -> bool:
    return bool(state and state["reachable"] and state_health(state, max_age, now) == "healthy")


def state_key(session: str, doc: AgentsFile) -> str:
    # Fingerprint the parsed merged configuration, including overrides, never serialize it to disk.
    data = dataclasses.asdict(doc)
    data.pop("source", None)
    data["agents"] = sorted(data["agents"], key=lambda row: row["id"])
    data["shapes"] = sorted(data["shapes"], key=lambda row: row["name"])
    for agent in data["agents"]:
        agent["limits"] = sorted(agent["limits"])
        for endpoint in agent["endpoints"]:
            endpoint["loaded_num_ctx"] = sorted(endpoint["loaded_num_ctx"])
    raw = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256((session + "\0" + raw).encode()).hexdigest()


def state_path(folder: Path, session: str, doc: AgentsFile) -> Path:
    return folder / ("probe-" + state_key(session, doc) + ".json")


def save_state(path: Path, state: dict[str, Any]) -> bool:
    with file_lock(path.with_name(path.name + ".lock")):
        previous = read_state(path)
        if previous and previous["ts"] > state["ts"]:
            return False
        try:
            write_text(path, json.dumps(state, sort_keys=True))
        except (OSError, ValueError):
            # Never leave a formerly reachable result active after a failed refresh.
            path.unlink(missing_ok=True)
            raise
    return True


STATE_FILE = re.compile(r"probe-[0-9a-f]{64}\.json(?:\.lock|\.attempt|\.attempt\.lock|\.notice)?")
STATE_KEEP_SECONDS = 7 * 86400  # a probe file nobody has touched for a week belongs to a session that is long over
PRUNE_SCAN_LIMIT = 2000  # entries looked at per call, so a folder full of files cannot make a session start slow


def prune_state(folder: Path, now: float) -> None:
    """Remove stale per-session probe files, only ones that are ours by name and regular files. Never raises."""
    try:
        with os.scandir(folder) as entries:
            for seen, entry in enumerate(entries):
                if seen >= PRUNE_SCAN_LIMIT:
                    break
                try:
                    ours = STATE_FILE.fullmatch(entry.name) and entry.is_file(follow_symlinks=False)
                    if ours and now - entry.stat(follow_symlinks=False).st_mtime > STATE_KEEP_SECONDS:
                        os.unlink(entry.path)
                except OSError:
                    continue
    except OSError:
        return


def attempt_path(path: Path) -> Path:
    return path.with_name(path.name + ".attempt")


def notice_path(path: Path) -> Path:
    return path.with_name(path.name + ".notice")


def claim_reprobe(path: Path, now: float) -> bool:
    """True when this call may re-probe: once per REPROBE_INTERVAL_SECONDS for a session and configuration, whether or
    not the previous attempt worked. The attempt is recorded before the probe runs, so a slow or failing endpoint is
    asked once a minute and not once per dispatch."""
    marker = attempt_path(path)
    with file_lock(marker.with_name(marker.name + ".lock")):
        try:
            recorded = loads(bounded_read(marker, 64))
        except (OSError, ValueError, UnicodeError):
            recorded = None
        last = recorded.get("ts") if isinstance(recorded, dict) else None
        if isinstance(last, (int, float)) and finite_time(last) and 0 <= now - last < REPROBE_INTERVAL_SECONDS:
            return False
        write_text(marker, json.dumps({"ts": now}))
    return True


def reprobe(doc: AgentsFile, path: Path, now: float) -> dict[str, Any] | None:
    """Refresh a stale state in place, bounded and rate limited. Never raises: None means the state could not be
    refreshed (rate limited, a probe or storage failure, or a newer result already stored), and the caller treats local
    reachability as unknown."""
    try:
        if not claim_reprobe(path, now):
            return None
        started = time.monotonic()
        results = probe_all(doc, lambda endpoint: probe(endpoint, REPROBE_TIMEOUT_SECONDS))
        state = probe_state(results, now + time.monotonic() - started)  # completion time, as at SessionStart
        return state if save_state(path, state) else None
    except Exception:
        return None


def first_notice(path: Path) -> bool:
    """True once per session and configuration. Later dispatches in the same degraded state stay quiet; the decision
    log still records every one of them. When the marker cannot be made, say it: a repeated warning beats a hidden
    one."""
    marker = notice_path(path)
    try:
        ensure_dir(marker.parent)
        os.close(os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600))
    except FileExistsError:
        return False
    except OSError:
        return True
    return True


# -- the guard -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Verdict:
    rules: tuple[str, ...]
    reasons: tuple[str, ...]
    model: str
    local_step: bool
    na: bool


FULL_MODEL_ID = re.compile(r"claude-([a-z]+)-[0-9][0-9a-z.-]*")  # claude-opus-5-5: a full id of a named family
APPROVAL_NOTE = (
    "the token is a speed bump against accidents, not proof of approval: text a prompt injected into the session can "
    "write it too"
)


def known_agents(doc: AgentsFile, model: str) -> list[Agent]:
    """Every agent a model value names: an exact (case-insensitive) agent model or id, or a full id of that model's
    family. Two agents may share a model, so all of them count. Anything else, `inherit` and a fork's missing model
    included, names none."""
    lowered = model.lower()
    family = FULL_MODEL_ID.fullmatch(lowered)
    wanted = {lowered, family.group(1)} if family else {lowered}
    return [a for a in doc.agents if a.model and (a.model.lower() in wanted or a.id.lower() in wanted)]


def needs_approval(doc: AgentsFile, model: str) -> bool:
    """True when `model` names an agent that agents.yaml marks approval_required (Opus, in the shipped file); with
    several agents on one model, any one of them is enough, so the order of agents.yaml never decides."""
    return any(a.approval_required for a in known_agents(doc, model))


def check_dispatch(doc: AgentsFile, tool_input: Mapping[str, Any], reachable: bool) -> Verdict:
    """Apply the routing rules to one Agent tool call."""
    raw_prompt, raw_model = tool_input.get("prompt"), tool_input.get("model")
    prompt = raw_prompt if isinstance(raw_prompt, str) else ""
    raw = raw_model.strip() if isinstance(raw_model, str) else ""
    # A model is explicit only when it names a known agent. `inherit`, garbage and a fork's missing model resolve to
    # the parent's model, which the hook cannot see, so they are treated as if they might be an approval-required one.
    agents = known_agents(doc, raw) if raw else []
    unknown = (bool(raw) and not agents) or (not raw and tool_input.get("subagent_type") in FORK_TYPES)
    model = raw.lower() if raw.lower() in ("sonnet", "haiku", "opus") else ("unknown" if raw or unknown else "")
    hooks = doc.hooks
    lowered = prompt.lower()
    local_step = any(marker in lowered for marker in hooks.local_step_markers)
    # The marker's own words may be separated by any whitespace; a reason (a non-blank character) must follow it.
    na = re.search(r"\s+".join(re.escape(word) for word in hooks.na_marker.split()) + r"\s*\S", lowered) is not None
    rules: list[str] = []
    reasons: list[str] = []
    # The token is typed by hand, so it is found however it is cased or wrapped: [TOKEN], (token), a line of its own.
    token = hooks.approval_token.lower() in lowered
    if not raw and not unknown:
        rules.append(NO_MODEL)
        reasons.append("no explicit `model` (set one: sonnet by default, haiku for mechanical work)")
    if unknown and not token:
        rules.append(UNKNOWN_MODEL)
        reasons.append(
            "unknown-model: the model is not a known agent (a placeholder, a fork or an unrecognised name), "
            "so it may be one that needs the maintainer's OK; name sonnet or haiku, or add the approval token "
            "from agents.yaml "
            f"(hooks.approval_token) only once he has said yes; {APPROVAL_NOTE}"
        )
    if any(a.approval_required for a in agents) and not token:
        rules.append(APPROVAL)
        reasons.append(
            f"model {model} needs the maintainer's recorded OK: add the approval token from agents.yaml "
            f"(hooks.approval_token) to the brief, with his reason, only once he has said yes; {APPROVAL_NOTE}"
        )
    if reachable and not local_step and not na:
        rules.append(NO_LOCAL_STEP)
        reasons.append("the local LLM is reachable but the brief names no local step and gives no reason for none")
    return Verdict(tuple(rules), tuple(reasons), model, local_step, na)


def decide(verdict: Verdict, mode: str) -> str:
    """allow when nothing is wrong; otherwise deny in block mode and warn (allow, but say so) in warn mode."""
    if not verdict.rules:
        return "allow"
    return "deny" if mode == "block" else "warn"


def guard_output(decision: str, verdict: Verdict) -> str:
    """The JSON the hook prints, or nothing for a clean dispatch."""
    if decision == "allow":
        return ""
    reason = "safo hooks guard: " + "; ".join(verdict.reasons)
    if decision == "deny":
        return json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        )
    return json.dumps(
        {
            "systemMessage": f"{reason} (warn mode: allowed)",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": f"{reason}. Fix the brief next time.",
            },
        }
    )


def log_record(
    when: str,
    decision: str,
    mode: str,
    verdict: Verdict | None,
    reachable: bool,
    health: str = "healthy",
    diagnostic: str = "",
) -> dict[str, Any]:
    """One log line. No brief, no description: only the verdict and the model name."""
    return {
        "ts": when,
        "decision": decision,
        "mode": mode,
        "model": (verdict.model or None) if verdict else None,
        "local_reachable": reachable,
        "local_step": verdict.local_step if verdict else False,
        "na": verdict.na if verdict else False,
        "rules": list(verdict.rules) if verdict else [],
        "health": health,
        "diagnostic": diagnostic,
    }


def append_log(path: Path, record: dict[str, Any], limit: int = LOG_LIMIT_BYTES) -> None:
    raw = (json.dumps(record, sort_keys=True) + "\n").encode()
    if not valid_record(record) or len(raw) > RECORD_CAP or len(raw) > limit:
        raise ValueError("invalid or oversized record")
    with file_lock(path.with_name(path.name + ".lock")):
        try:
            old = bounded_read(path, FILE_CAP)
        except FileNotFoundError:
            old = b""
        # Recover only the incomplete tail; preserve complete retained records.
        complete = old[: old.rfind(b"\n") + 1]
        if complete != old:
            write_text(path, complete.decode("utf-8"))
        if len(complete) + len(raw) > limit:
            archive = path.with_name(path.name + ".1")
            os.replace(path, archive)  # one private archive; oldest retained history is deliberately discarded
            archive.chmod(0o600)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb", buffering=0) as handle:
            os.fchmod(handle.fileno(), 0o600)
            if handle.write(raw) != len(raw):
                raise OSError("short log write")
            os.fsync(handle.fileno())


# -- install ---------------------------------------------------------------------------------------

COMMAND = re.compile(r"[A-Za-z0-9_./-]+(?: [A-Za-z0-9_./-]+)*")


def is_safo_path(word: str) -> bool:
    """An absolute, normalized path whose last component is safo (a venv or pipx install). Existence is checked at
    install time, where the operator can be told; ownership of an already installed hook needs only the shape."""
    return os.path.isabs(word) and os.path.normpath(word) == word and os.path.basename(word) == "safo"


def hook_entry(command: str, timeout: int, message: str = "") -> dict[str, Any]:
    entry: dict[str, Any] = {"type": "command", "command": command, "timeout": timeout}
    if message:
        entry["statusMessage"] = message
    return entry


def command_signature(command: str, subcommand: str) -> tuple[str, ...] | None:
    try:
        words = shlex.split(command)
    except ValueError:
        return None
    # Only these explicit launch forms are owned: safo, python3 -m safo, or one absolute safo path. A changed
    # launcher needs manual migration.
    launches: tuple[tuple[str, ...], ...] = (("safo",), ("python3", "-m", "safo"))
    if words and is_safo_path(words[0]):
        launches = (*launches, (words[0],))
    for launch in launches:
        prefix = (*launch, "hooks", subcommand)
        if tuple(words[: len(prefix)]) != prefix:
            continue
        tail = words[len(prefix) :]
        if len(tail) % 2 or any(tail[i] not in ("--agents", "--agents-local") for i in range(0, len(tail), 2)):
            return None
        flags = tail[::2]
        if len(set(flags)) != len(flags) or any(not Path(v).is_absolute() for v in tail[1::2]):
            return None
        return launch
    return None


def _ensure(hooks: dict[str, Any], event: str, matcher: str, entry: dict[str, Any], subcommand: str) -> bool:
    groups = hooks.setdefault(event, [])
    if not isinstance(groups, list) or not all(isinstance(g, dict) for g in groups):
        raise ConfigError("settings: invalid hook groups; fix by hand")
    expected = command_signature(entry["command"], subcommand)
    kept: list[dict[str, Any]] = []
    slot: int | None = None  # where our hook already sits: it is put back there, so a rerun reorders nothing
    for group in groups:
        inner = group.get("hooks", [])
        if not isinstance(inner, list):
            raise ConfigError("settings: invalid hooks list; fix by hand")
        remaining = []
        for existing in inner:
            command = existing.get("command") if isinstance(existing, dict) else None
            sig = command_signature(command, subcommand) if isinstance(command, str) else None
            exact = command == entry["command"]
            if sig is not None or exact:
                if group.get("matcher", "") != matcher or existing.get("type") != "command":
                    raise ConfigError("settings: ambiguous SAFO hook event/matcher/type; fix by hand")
                if sig != expected:
                    raise ConfigError("settings: changed invocation; migrate by hand")
                # Normalize all owned fields and collapse duplicates, leaving siblings untouched.
                if slot is None:
                    slot = len(kept)
            else:
                remaining.append(existing)
        if remaining:
            kept.append({**group, "hooks": remaining})
    canonical: dict[str, Any] = {"hooks": [entry]}
    if matcher:
        canonical["matcher"] = matcher
    kept.insert(len(kept) if slot is None else slot, canonical)
    changed = groups != kept
    hooks[event] = kept
    return changed


def merge_settings(settings: Any, probe_command: str, guard_command: str) -> tuple[dict[str, Any], bool]:
    if not isinstance(settings, dict):
        raise ConfigError("settings: the top level is not a JSON object; fix it by hand first")
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ConfigError("settings: hooks is not an object; fix it by hand first")
    changed = _ensure(
        hooks,
        "SessionStart",
        "",
        hook_entry(probe_command, PROBE_TIMEOUT_SECONDS, "Checking the local LLM..."),
        "probe",
    )
    changed = (
        _ensure(hooks, "PreToolUse", "Agent|Task", hook_entry(guard_command, GUARD_TIMEOUT_SECONDS), "guard") or changed
    )
    return settings, changed
