# SPDX-License-Identifier: Apache-2.0
"""The lead never waits: find the Bash commands whose job is to wait.

The lead session is the project manager. A wait (a CI run, a runner, a deploy, a review) goes to `run_in_background`
or to a Sonnet monitor agent; a foreground `gh run watch` or polling loop holds the main thread while the maintainer's
messages sit unanswered. This module decides, from the text of one command, whether it waits. It does not decide who
is running it (the hook does that) and it never runs anything.

The command is split by a small tokenizer into simple commands, and a wait counts only at COMMAND POSITION (the first
word after leading `VAR=value` assignments, shell keywords and the transparent wrappers in `WRAPPERS`):

- `gh run watch`                                    -> gh-run-watch
- `gh pr checks` with `--watch` or `-w`             -> gh-pr-checks-watch
- a `sleep` inside the body (`do` ... `done`) of a
  `while`, `until` or `for` loop                    -> sleep-loop (any duration: the loop is the poll)
- a `sleep` of at least the threshold seconds       -> long-sleep (default 10; an argument it cannot read counts)

Arguments are data: `echo gh run watch`, a commit message, a single-quoted string, a heredoc body and a comment never
count. Code inside `$(...)` and backticks does count, also when it sits inside double quotes. The bodies of
`bash -c '...'`, `sh -c '...'` and `eval ...` are scanned too (they are code the call runs). The exemption marker
`# lead-wait: ok - <reason>` counts only in a real comment token. It is a tokenizer for the common shapes, not a shell
parser: see "Known limits" in docs/hooks.md.
"""

from __future__ import annotations

import functools
import re

DEFAULT_SLEEP_THRESHOLD_SECONDS = 10
MAX_SLEEP_THRESHOLD_SECONDS = 3600
MIN_REASON_CHARS = 12  # "lead-wait: ok - <reason>": a reason shorter than this is a placeholder, not a reason
MAX_DEPTH = 3  # substitutions, backticks, `bash -c` bodies and `eval` are scanned this deep, then ignored

GH_RUN_WATCH = "gh-run-watch"
GH_PR_CHECKS_WATCH = "gh-pr-checks-watch"
SLEEP_LOOP = "sleep-loop"
LONG_SLEEP = "long-sleep"
KINDS = (GH_RUN_WATCH, GH_PR_CHECKS_WATCH, SLEEP_LOOP, LONG_SLEEP)

MARKER = "lead-wait: ok -"
_MARKER = re.compile(r"lead-wait:[ \t]*ok[ \t]*-[ \t]*(\S[^\n]*)", re.IGNORECASE)

_HEREDOC = re.compile(r"<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_.-]*)\2")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
_REDIRECT_OP = re.compile(r"(?:\d*|&)(?:>>?|<)&?")  # a redirection operator whose target is the NEXT word
_REDIRECT_ATTACHED = re.compile(r"(?:\d*|&)(?:>>?|<)&?\S")  # `2>&1`, `>file`: the target is part of the word
_WATCH_FLAG = re.compile(r"--watch(?:=(?!(?:false|0)$).*)?|-[A-Za-z]*w[A-Za-z]*")
_DURATION = re.compile(r"(\d+(?:\.\d+)?)([smhd]?)")
_UNIT = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}

# Words that open or continue a command without being the command: `do sleep 1`, `then gh run watch`, `! sleep 60`.
_KEYWORDS = frozenset({"do", "then", "else", "elif", "if", "!", "{", "}"})
_LOOP_HEADS = frozenset({"while", "until", "for", "select"})
# Transparent wrappers: the command they run is the one that counts. Value = the options that take a separate value.
WRAPPERS: dict[str, frozenset[str]] = {
    "time": frozenset({"-f", "--format", "-o", "--output"}),
    "nohup": frozenset(),
    "command": frozenset(),
    "exec": frozenset({"-a"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "env": frozenset({"-u", "--unset", "-C", "--chdir"}),
    "sudo": frozenset(
        {"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "--user", "--group", "--host", "--prompt"}
    ),
    "timeout": frozenset({"-s", "--signal", "-k", "--kill-after"}),
}
_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh"})
_SHELL_C = re.compile(r"-[A-Za-z]*c[A-Za-z]*")
_PLACEHOLDER = "$()"  # stands in a word for a substitution: it is never a readable number


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


Word = tuple[str, bool]  # (text with quotes removed and substitutions replaced, whether any part was quoted)


class _Scan:
    """One pass over a command: what waits it holds and which real comments it carries."""

    def __init__(self) -> None:
        self.found: set[str] = set()
        self.sleeps: list[float | None] = []
        self.comments: list[str] = []
        self.loops: list[bool] = []  # one entry per open loop: has its `do` been seen (are we in the body)

    # -- the tokenizer ------------------------------------------------------------------------------------------

    def walk(self, text: str, i: int, sub: bool, depth: int, top: bool) -> int:
        """Scan `text` from `i`. With `sub` it stops after the `)` that closes a `$(`. Returns where it stopped."""
        n = len(text)
        words: list[Word] = []
        cur: list[str] = []
        has = False  # a word is open (it may be empty: '')
        quoted = False
        pending: list[tuple[str, bool]] = []  # heredoc delimiters whose body starts after the next newline
        parens = 0

        def flush() -> None:
            nonlocal has, quoted
            if has:
                words.append(("".join(cur), quoted))
            cur.clear()
            has = quoted = False

        def end_command() -> None:
            flush()
            if words:
                self.command(tuple(words), depth)
                words.clear()

        def substitution(at: int) -> int:
            """`text[at:]` begins a `$(`/`<(`/`>(` body; scan it as code and return the index past its `)`."""
            if depth >= MAX_DEPTH:
                return _balanced(text, at)
            return self.walk(text, at, True, depth + 1, False)

        while i < n:
            c = text[i]
            if c == "\\":
                if i + 1 < n and text[i + 1] == "\n":
                    i += 2  # a line continuation joins the lines
                    continue
                if i + 1 < n:
                    cur.append(text[i + 1])
                    has = quoted = True
                i += 2
            elif c == "'":
                end = text.find("'", i + 1)
                cur.append(text[i + 1 : n if end < 0 else end])
                has = quoted = True
                i = n if end < 0 else end + 1
            elif c == '"':
                has = quoted = True
                i += 1
                while i < n and text[i] != '"':
                    ch = text[i]
                    if ch == "\\" and i + 1 < n:
                        if text[i + 1] != "\n":
                            cur.append(text[i + 1] if text[i + 1] in '$`"\\' else "\\" + text[i + 1])
                        i += 2
                    elif text.startswith("$((", i):
                        i = _balanced(text, i + 2)
                        cur.append(_PLACEHOLDER)
                    elif text.startswith("$(", i):
                        i = substitution(i + 2)
                        cur.append(_PLACEHOLDER)
                    elif ch == "`":
                        i = self.backticks(text, i, depth)
                        cur.append(_PLACEHOLDER)
                    else:
                        cur.append(ch)
                        i += 1
                i += 1
            elif text.startswith("$((", i):
                i = _balanced(text, i + 2)
                cur.append(_PLACEHOLDER)
                has = True
            elif text.startswith("$(", i):
                i = substitution(i + 2)
                cur.append(_PLACEHOLDER)
                has = True
            elif text.startswith("${", i):
                end = i + 2
                level = 1
                while end < n and level:
                    level += {"{": 1, "}": -1}.get(text[end], 0)
                    end += 1
                cur.append(_PLACEHOLDER)
                has = True
                i = end
            elif c == "`":
                i = self.backticks(text, i, depth)
                cur.append(_PLACEHOLDER)
                has = True
            elif c == "#" and not has:
                end = text.find("\n", i)
                if top:
                    self.comments.append(text[i + 1 : n if end < 0 else end])
                i = n if end < 0 else end
            elif c in " \t":
                flush()
                i += 1
            elif c == "\n":
                end_command()
                i += 1
                for delimiter, strip_tabs in pending:
                    while i < n:
                        end = text.find("\n", i)
                        line = text[i : n if end < 0 else end]
                        i = n if end < 0 else end + 1
                        if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                            break
                pending.clear()
            elif c in ";|":
                end_command()
                i += 1
            elif c == "&":
                if (cur and cur[-1] in "<>") or text.startswith("&>", i):
                    cur.append(c)  # `2>&1`, `>&2`, `&>file` are redirections, not a background operator
                    has = True
                else:
                    end_command()
                i += 1
            elif c == "(":
                if cur and cur[-1] in "<>":  # process substitution `<(...)`
                    i = substitution(i + 1)
                    cur.append(_PLACEHOLDER)
                else:
                    end_command()
                    parens += 1
                    i += 1
            elif c == ")":
                end_command()
                i += 1
                if parens == 0 and sub:
                    return i
                parens = max(parens - 1, 0)
            elif (
                c == "<"
                and text.startswith("<<", i)
                and not text.startswith("<<<", i)
                and (m := _HEREDOC.match(text, i))
            ):
                flush()
                pending.append((m.group(3), m.group(1) == "-"))
                i = m.end()
            else:
                cur.append(c)
                has = True
                i += 1
        end_command()
        return n

    def backticks(self, text: str, i: int, depth: int) -> int:
        """`text[i]` is a backtick: scan the command inside as code and return the index past the closing one."""
        j = i + 1
        while j < len(text) and text[j] != "`":
            j += 2 if text[j] == "\\" else 1
        if depth < MAX_DEPTH:
            self.nested(text[i + 1 : j].replace("\\`", "`"), depth)
        return j + 1

    def nested(self, script: str, depth: int) -> None:
        """Scan a script given as a string (a `bash -c` body, an `eval`, a backtick body) in the same loop context."""
        if depth >= MAX_DEPTH:
            return
        base = len(self.loops)
        self.walk(script, 0, False, depth + 1, False)
        del self.loops[base:]  # whatever loop the string left open ends with the string

    # -- one simple command -------------------------------------------------------------------------------------

    def command(self, words: tuple[Word, ...], depth: int) -> None:
        # Redirections are not arguments: `sleep 5 > /dev/null 2>&1` is `sleep 5`.
        kept: list[Word] = []
        skip = False
        for text, was_quoted in words:
            if skip:
                skip = False
            elif was_quoted or not (_REDIRECT_OP.fullmatch(text) or _REDIRECT_ATTACHED.match(text)):
                kept.append((text, was_quoted))
            elif _REDIRECT_OP.fullmatch(text):
                skip = True
        i = 0
        while i < len(kept):
            text, was_quoted = kept[i]
            if was_quoted:
                break
            if text in _LOOP_HEADS:
                self.loops.append(False)
                if text in ("for", "select"):
                    return  # the rest is the header: `for i in 1 2 3`
            elif text == "do":
                if False in self.loops:
                    self.loops[len(self.loops) - 1 - self.loops[::-1].index(False)] = True
            elif text == "done":
                if self.loops:
                    self.loops.pop()
                return  # what follows is a redirection or a pipe, not a command
            elif text not in _KEYWORDS:
                break
            i += 1
        while i < len(kept) and _ASSIGNMENT.match(kept[i][0]):
            i += 1
        while i < len(kept) and kept[i][0].rsplit("/", 1)[-1] in WRAPPERS:
            i = self.unwrap(kept, i)
        if i >= len(kept):
            return
        name = kept[i][0].rsplit("/", 1)[-1]
        args = [w for w, _ in kept[i + 1 :]]
        if name == "sleep":
            self.sleeps.append(_sleep_seconds(args))
            if any(self.loops):
                self.found.add(SLEEP_LOOP)
        elif name == "gh" and args[:2] == ["run", "watch"]:
            self.found.add(GH_RUN_WATCH)
        elif name == "gh" and args[:2] == ["pr", "checks"] and any(_WATCH_FLAG.fullmatch(a) for a in args[2:]):
            self.found.add(GH_PR_CHECKS_WATCH)
        elif name in _SHELLS:
            for k, arg in enumerate(args[:-1]):
                if _SHELL_C.fullmatch(arg):
                    self.nested(args[k + 1], depth)
                    break
        elif name == "eval":
            self.nested(" ".join(args), depth)

    @staticmethod
    def unwrap(kept: list[Word], i: int) -> int:
        """Index of the command a wrapper at `i` runs (len(kept) when it runs none)."""
        wrapper = kept[i][0].rsplit("/", 1)[-1]
        valued = WRAPPERS[wrapper]
        j = i + 1
        duration_pending = wrapper == "timeout"
        while j < len(kept):
            text = kept[j][0]
            if wrapper == "command" and text in ("-v", "-V"):
                return len(kept)  # `command -v sleep` looks a name up; it runs nothing
            if text.startswith("-") and text != "-":
                j += 2 if text in valued else 1
            elif wrapper in ("env", "sudo") and _ASSIGNMENT.match(text):
                j += 1
            elif duration_pending:
                duration_pending = False
                j += 1
            else:
                break
        return j


@functools.lru_cache(maxsize=16)
def _scan(command: str) -> _Scan:
    scan = _Scan()
    scan.walk(command, 0, False, 0, True)
    return scan


def marker_reason(command: str) -> str:
    """The stated reason of a `lead-wait: ok - <reason>` marker in a real comment of the command, or "" when there
    is none, it is a placeholder, or the text only sits inside a string, a heredoc body or an argument.

    The marker may be in any comment of the call, on the wait's line or another; the call is one decision.
    """
    for comment in _scan(command).comments:
        found = _MARKER.search(comment)
        reason = found.group(1).strip() if found else ""
        if len(reason) >= MIN_REASON_CHARS:
            return reason
    return ""


def _sleep_seconds(words: list[str]) -> float | None:
    """Total seconds of a sleep's arguments (GNU sleep adds them), or None when any argument cannot be read."""
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
    scan = _scan(command)
    found = set(scan.found)
    # The sleeps of one command add up: `sleep 5; sleep 6` holds the thread for 11 seconds.
    if any(s is None for s in scan.sleeps) or sum(s for s in scan.sleeps if s is not None) >= threshold:
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
        f"has no one to delegate to may carry the comment `# {MARKER} <reason>`; a real reason is required "
        f"(at least {MIN_REASON_CHARS} characters)"
    )
