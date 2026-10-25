# SPDX-License-Identifier: Apache-2.0
"""The lead never waits: find the Bash commands whose job is to wait.

The lead session is the project manager. A wait (a CI run, a runner, a deploy, a review) goes to `run_in_background`
or to a Sonnet monitor agent; a foreground `gh run watch` or polling loop holds the main thread while the maintainer's
messages sit unanswered. This module decides, from the text of one command, whether it waits. It does not decide who
is running it (the hook does that) and it never runs anything.

What counts, in the text that is left after quoted strings, heredoc bodies and comments are removed:

- `gh run watch`                                    -> gh-run-watch
- `gh pr checks` with `--watch` or `-w`             -> gh-pr-checks-watch
- a `while`, `until` or `for` loop that has a sleep -> sleep-loop (any duration: the loop is the poll)
- a `sleep` of at least the threshold seconds       -> long-sleep (default 10; an argument it cannot read counts)

Removing quoted text is what keeps the words "gh run watch" in a commit message or a documentation heredoc from
tripping the rule. It is a scanner for the common shapes, not a shell parser: see "Known limits" in docs/hooks.md.
"""

from __future__ import annotations

import re

DEFAULT_SLEEP_THRESHOLD_SECONDS = 10
MAX_SLEEP_THRESHOLD_SECONDS = 3600
MIN_REASON_CHARS = 12  # "lead-wait: ok - <reason>": a reason shorter than this is a placeholder, not a reason
MAX_DEPTH = 3  # command substitutions inside double quotes are scanned this deep, then ignored

GH_RUN_WATCH = "gh-run-watch"
GH_PR_CHECKS_WATCH = "gh-pr-checks-watch"
SLEEP_LOOP = "sleep-loop"
LONG_SLEEP = "long-sleep"
KINDS = (GH_RUN_WATCH, GH_PR_CHECKS_WATCH, SLEEP_LOOP, LONG_SLEEP)

MARKER = "lead-wait: ok -"
_MARKER = re.compile(r"lead-wait:[ \t]*ok[ \t]*-[ \t]*(\S[^\n]*)", re.IGNORECASE)

_HEREDOC = re.compile(r"<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_.-]*)\2")
_SEPARATORS = r";&|\n"
_RUN_WATCH = re.compile(r"(?<![\w./-])gh[ \t]+run[ \t]+watch(?![\w-])")
_PR_CHECKS = re.compile(r"(?<![\w./-])gh[ \t]+pr[ \t]+checks(?![\w-])")
_WATCH_FLAG = re.compile(r"(?:^|[ \t])(?:--watch(?!=(?:false|0)\b)(?:=\S*)?|-[A-Za-z]*w[A-Za-z]*)(?=[ \t]|$)")
_LOOP = re.compile(rf"(?:^|[{_SEPARATORS}({{])[ \t]*(?:while|until|for)(?=[ \t(\[])")
_SLEEP = re.compile(rf"(?<![\w./-])sleep(?![\w-])([^{_SEPARATORS})]*)")
_DURATION = re.compile(r"(\d+(?:\.\d+)?)([smhd]?)")
_UNIT = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def marker_reason(command: str) -> str:
    """The stated reason of a `lead-wait: ok - <reason>` marker, or "" when there is none or it is a placeholder."""
    found = _MARKER.search(command)
    reason = found.group(1).strip() if found else ""
    return reason if len(reason) >= MIN_REASON_CHARS else ""


def _balanced(text: str, start: int) -> int:
    """Index just past the `)` that closes a `$(` whose body begins at `start`; the end of the text if none."""
    depth = 1
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


def strip_literals(command: str, depth: int = 0) -> str:
    """The command without text that is data: single and double quoted strings, heredoc bodies and comments.

    Code that runs inside a double quoted string (`"$(sleep 300)"`) is kept, because it is not data.
    """
    out: list[str] = []
    pending: list[tuple[str, bool]] = []  # heredoc delimiters whose body starts after the next newline
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if c == "\\":
            out.append(" ")
            i += 2
        elif c == "'":
            end = command.find("'", i + 1)
            out.append(" ")
            i = n if end < 0 else end + 1
        elif c == '"':
            out.append(" ")
            i += 1
            while i < n and command[i] != '"':
                if command[i] == "\\":
                    i += 2
                elif command.startswith("$(", i):
                    end = _balanced(command, i + 2)
                    if depth < MAX_DEPTH:
                        out.append(" ; " + strip_literals(command[i + 2 : end - 1], depth + 1) + " ; ")
                    i = end
                else:
                    i += 1
            i += 1
        elif c == "#" and (i == 0 or command[i - 1] in " \t\n;&|("):
            end = command.find("\n", i)
            i = n if end < 0 else end
        elif command.startswith("<<", i) and not command.startswith("<<<", i) and (m := _HEREDOC.match(command, i)):
            pending.append((m.group(3), m.group(1) == "-"))
            out.append(" ")
            i = m.end()
        elif c == "\n":
            out.append("\n")
            i += 1
            for delimiter, strip_tabs in pending:
                while i < n:
                    end = command.find("\n", i)
                    line = command[i : n if end < 0 else end]
                    i = n if end < 0 else end + 1
                    if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                        break
            pending.clear()
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _sleep_seconds(args: str) -> float | None:
    """Total seconds of a sleep's arguments (GNU sleep adds them), or None when any argument cannot be read."""
    words = args.split()
    if not words:
        return None
    total = 0.0
    for word in words:
        m = _DURATION.fullmatch(word)
        if not m:
            return None
        total += float(m.group(1)) * _UNIT[m.group(2)]
    return total


def find_waits(command: str, threshold: int = DEFAULT_SLEEP_THRESHOLD_SECONDS) -> tuple[str, ...]:
    """The kinds of wait a command contains, in a fixed order; empty when it does not wait."""
    code = strip_literals(command)
    found: set[str] = set()
    if _RUN_WATCH.search(code):
        found.add(GH_RUN_WATCH)
    for segment in re.split(rf"[{_SEPARATORS}]+", code):
        if _PR_CHECKS.search(segment) and _WATCH_FLAG.search(segment):
            found.add(GH_PR_CHECKS_WATCH)
    sleeps = [_sleep_seconds(m.group(1)) for m in _SLEEP.finditer(code)]
    if sleeps and _LOOP.search(code):
        found.add(SLEEP_LOOP)
    # The sleeps of one command add up: `sleep 5; sleep 6` holds the thread for 11 seconds.
    if any(s is None for s in sleeps) or sum(s for s in sleeps if s is not None) >= threshold:
        found.add(LONG_SLEEP)
    return tuple(k for k in KINDS if k in found)


def may_wait(command: str) -> bool:
    """A cheap test before any configuration is read: could this command contain a wait at all?"""
    return "sleep" in command or "watch" in command or "checks" in command


def message(kinds: tuple[str, ...]) -> str:
    """The text the hook shows. Fixed wording per kind: nothing of the command or its arguments is echoed."""
    what = {
        GH_RUN_WATCH: "`gh run watch`",
        GH_PR_CHECKS_WATCH: "`gh pr checks --watch`",
        SLEEP_LOOP: "a sleep loop",
        LONG_SLEEP: "a long sleep",
    }
    names = ", ".join(what[k] for k in kinds)
    return (
        f"lead never waits: this foreground Bash call is {names}. The lead session is the project manager, so the "
        "wait goes elsewhere: rerun it with run_in_background and read the result when it exits, or dispatch a "
        "read-only Sonnet monitor agent (brief template: docs/orchestrator.md). A wait that is genuinely short and "
        f"has no one to delegate to may carry the comment `# {MARKER} <reason>` with a real reason"
    )
