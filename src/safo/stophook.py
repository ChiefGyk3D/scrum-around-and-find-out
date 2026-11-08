# SPDX-License-Identifier: Apache-2.0
"""`safo hooks stop`: the Stop hook, and its first rule `research-lead` (#84). Warn only; it never blocks anything.

At the end of a turn the host pipes the Stop event to this hook. The check reads the final assistant message and the
tool calls of that turn. It flags a message that relays a negative or deferred result about an EXTERNAL fact ("not
found", "no statement found", "needs your decision", ...) when the turn made no web search or documentation lookup. The
measured case (2026-11-07): the lead told the maintainer a vendor statement did not exist, after a delegated agent
with no search tool had said "no statement found"; one web search found the vendor's press release.

What the hook may say, per the Claude Code hooks documentation (read 2026-11-07): a top-level `decision: "block"` or
`hookSpecificOutput.additionalContext` on Stop makes Claude CONTINUE, so this hook never emits either. It emits the
universal `systemMessage` ("warning message shown to the user") and writes the guard log. It honors `stop_hook_active`
(true means a stop hook already continued this turn: do nothing). It fails open: any error is an allow, with the same
fixed degraded notice the other hooks use (as a `systemMessage` only).

Further Stop heuristics from #84 (done claims, click-path text) are NOT built. A new check is one function that takes a
`Turn` and the config and returns `Finding`s; add it to CHECKS.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from safo import output
from safo.agentsfile import Research
from safo.bounded import loads
from safo.errors import EXIT_OK, ConfigError
from safo.guardlog import WARNING, read_mode, state_dir

if TYPE_CHECKING:
    import argparse
    from collections.abc import Callable

    from safo.context import LocalContext

RESEARCH_LEAD = "research-lead"
TAIL_BYTES = 1_048_576  # the most of the transcript's end that is ever read
MAX_LINES = 2_000  # the most lines of that tail that are looked at
MAX_LINE_BYTES = 262_144  # a longer line (a tool result, an API blob) is skipped unparsed
MAX_MESSAGE_CHARS = 20_000  # the most of the final message that is examined
MAX_TOOL_NAMES = 5_000

ADVICE = (
    "research-lead: this turn's final message relays {hits} about an external fact, but the turn ran no web search. "
    'Run a web search (list the query in your reply) before relaying "not found" or asking for a decision about an '
    "external fact. (warn only)"
)

FENCE = re.compile(r"(?s)(```|~~~).*?(?:\1|\Z)")
INLINE_CODE = re.compile(r"`[^`\n]*`")
QUOTED = re.compile(r"\"[^\"\n]{0,300}\"|“[^”\n]{0,300}”")
BLOCKQUOTE = re.compile(r"(?m)^[ \t]*>.*$")
# A line that talks about a local file, a path, an HTTP 404 of our own page or a missing local command is not an
# external fact. Deliberately coarse; see docs/hooks.md for what it does not catch.
LOCAL_LINE = re.compile(
    r"(?i)(?:^|[\s(\[])(?:~|\.{1,2})?/[\w.\-@]+(?:/[\w.\-@]*)*"  # /abs, ./rel, ~/home, ../up paths
    r"|\b[\w\-]+\.(?:py|yaml|yml|md|json|jsonl|txt|toml|sh|log|lock|cfg|ini|toml|js|ts|html|css)\b"
    r"|\b404\b|no such file|command not found|\bmodule(?:notfound)?error\b|file not found|path not found"
)


@dataclass(frozen=True)
class Turn:
    """What a check sees: the final message and the names of the tools called in the turn (lower case)."""

    message: str
    tools: tuple[str, ...]


@dataclass(frozen=True)
class Finding:
    rule: str
    text: str


def strip_noise(text: str) -> str:
    """The message without code blocks, inline code and block quotes (quoted text is handled per match)."""
    for pattern in (FENCE, BLOCKQUOTE, INLINE_CODE):
        text = pattern.sub(" ", text)
    return text


def phrase_pattern(phrase: str) -> re.Pattern[str]:
    parts = [re.escape(p) for p in phrase.lower().split("*")]
    return re.compile(r"[^\n.!?]{1,40}".join(parts), re.IGNORECASE)


def matched_phrases(message: str, phrases: tuple[str, ...]) -> list[str]:
    """The configured phrases the message relays outside code, quotes and local-file talk. Each phrase once."""
    text = strip_noise(message[:MAX_MESSAGE_CHARS])
    quoted = [(m.start(), m.end()) for m in QUOTED.finditer(text)]
    hits: list[str] = []
    for phrase in phrases:
        for m in phrase_pattern(phrase).finditer(text):
            if any(a <= m.start() < b for a, b in quoted):
                continue  # a quoted phrase is being discussed, not relayed
            start = text.rfind("\n", 0, m.start()) + 1
            end = text.find("\n", m.end())
            if LOCAL_LINE.search(text[start : end if end >= 0 else len(text)]):
                continue
            hits.append(phrase)
            break
    return hits


def searched(tools: tuple[str, ...], search_tools: tuple[str, ...]) -> bool:
    for name in tools:
        for want in search_tools:
            if name == want or (want.endswith("*") and name.startswith(want[:-1])):
                return True
    return False


def research_lead(turn: Turn, cfg: Research) -> list[Finding]:
    if not cfg.lead_check:
        return []
    hits = matched_phrases(turn.message, cfg.lead_phrases)
    if not hits or searched(turn.tools, cfg.search_tools):
        return []
    return [Finding(RESEARCH_LEAD, ADVICE.format(hits=", ".join(f'"{h}"' for h in hits)))]


CHECKS: tuple[Callable[[Turn, Research], list[Finding]], ...] = (research_lead,)


# -- the transcript -------------------------------------------------------------------------------


class TranscriptError(Exception):
    """The transcript could not be read or understood (the hook then fails open, visibly)."""


def read_tail(path: str) -> list[bytes]:
    """The last complete lines of the transcript: at most TAIL_BYTES read, MAX_LINES kept. Never the whole file."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as err:
        raise TranscriptError("open") from err
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise TranscriptError("not a regular file")
        start = max(0, info.st_size - TAIL_BYTES)
        os.lseek(fd, start, os.SEEK_SET)
        data = b""
        while len(data) < TAIL_BYTES:
            chunk = os.read(fd, TAIL_BYTES - len(data))
            if not chunk:
                break
            data += chunk
    except OSError as err:
        raise TranscriptError("read") from err
    finally:
        os.close(fd)
    lines = data.split(b"\n")
    if start > 0:
        lines = lines[1:]  # the first line is cut at the window edge
    return lines[-MAX_LINES:]


def is_real_prompt(entry: dict[str, Any]) -> bool:
    """A user entry that starts a turn: text or an image from the person, not a tool result."""
    if entry.get("type") != "user" or entry.get("isSidechain") is True:
        return False
    message = entry.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        return True
    if isinstance(content, list):
        return any(isinstance(b, dict) and b.get("type") != "tool_result" for b in content)
    return False


def turn_from_lines(lines: list[bytes]) -> tuple[str, tuple[str, ...]]:
    """(last assistant text, tool names) of the last turn in `lines`. A tail that does not reach the turn's start is
    treated as the whole turn."""
    tools: list[str] = []
    text = ""
    for raw in reversed(lines):
        if not raw.strip() or len(raw) > MAX_LINE_BYTES:
            continue
        try:
            entry = loads(raw)
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        if is_real_prompt(entry):
            break
        if entry.get("type") != "assistant" or entry.get("isSidechain") is True:
            continue
        message = entry.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use" and isinstance(block.get("name"), str) and len(tools) < MAX_TOOL_NAMES:
                tools.append(block["name"].lower())
            elif block.get("type") == "text" and not text and isinstance(block.get("text"), str):
                text = block["text"]  # lines are walked newest first: the first text seen is the final one
    return text, tuple(tools)


# -- the hook -------------------------------------------------------------------------------------


def final_message(payload: dict[str, Any]) -> str:
    """The `last_assistant_message` field (the docs prefer it to the transcript for the current turn), or ''."""
    value = payload.get("last_assistant_message")
    return value[:MAX_MESSAGE_CHARS] if isinstance(value, str) else ""


def evaluate(payload: dict[str, Any], cfg: Research) -> list[Finding]:
    """The findings for one Stop event. Raises TranscriptError when a flaggable message cannot be judged."""
    if payload.get("stop_hook_active") is True:
        return []
    message = final_message(payload)
    if not cfg.lead_check or not matched_phrases(message, cfg.lead_phrases):
        return []  # nothing worth a transcript read: the common, silent path
    path = payload.get("transcript_path")
    if not isinstance(path, str) or not path:
        raise TranscriptError("no transcript_path")
    path = os.path.expanduser(path)
    text, tools = turn_from_lines(read_tail(path))
    turn = Turn(message or text, tools)
    findings: list[Finding] = []
    for check in CHECKS:
        findings.extend(check(turn, cfg))
    return findings


def say(ctx: LocalContext, data: dict[str, Any]) -> None:
    ctx.out.write(output.line(json.dumps(data)) + "\n")
    ctx.out.flush()


def log_row(ctx: LocalContext, decision: str, rules: list[str], diagnostic: str) -> None:
    """Best effort: a hook that cannot log still answers. Only flagged or degraded turns are logged."""
    from safo.hooks import append_log, log_record

    folder = state_dir(ctx.env)
    if folder is None:
        return
    when = ctx.now.strftime("%Y-%m-%dT%H:%M:%S")
    record = log_record(
        when, decision, read_mode(ctx.env), None, False, "degraded" if diagnostic else "healthy", diagnostic
    )
    record["rules"] = rules
    with contextlib.suppress(Exception):  # the answer is already out; a lost row is the documented cost
        append_log(folder / "log.jsonl", record)


def run_stop(ctx: LocalContext, args: argparse.Namespace) -> int:
    from safo.localfiles import load_agents_for
    from safo.modes.hooks import event_input

    try:
        payload = event_input(ctx)
        if payload.get("stop_hook_active") is True:
            return EXIT_OK
        cfg = load_agents_for(ctx, args).hooks.research
        findings = evaluate(payload, cfg)
    except Exception as err:
        # Fail open and say so: a fixed notice and an enum-only record, never the error text or any message text.
        diag = (
            "config"
            if isinstance(err, ConfigError)
            else "input"
            if isinstance(err, (ValueError, TranscriptError))
            else "unexpected"
        )
        try:
            say(ctx, {"systemMessage": WARNING})
        finally:
            log_row(ctx, "error", [], diag)
        return EXIT_OK
    if findings:
        try:
            say(ctx, {"systemMessage": " ".join(f.text for f in findings)})
        finally:
            log_row(ctx, "warn", sorted({f.rule for f in findings}), "")
    return EXIT_OK
