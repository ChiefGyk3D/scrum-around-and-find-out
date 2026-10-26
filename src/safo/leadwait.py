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
- executable syntax nested deeper than MAX_DEPTH    -> unscannable-depth (an explicit verdict, never a silent pass)

Arguments are data: `echo gh run watch`, a commit message, a single-quoted string, a quoted heredoc body and a comment
never count. Code inside `$(...)`, backticks, `${...}` and an unquoted heredoc body does count, also when it sits
inside double quotes. The strings given to `bash -c`, `sh -c`, `eval` and `env -S`, and the command that `xargs` and
`find -exec` run, are code the call runs, so they are scanned too. A function defined in the call is scanned only if
the call later invokes it. The exemption marker `# lead-wait: ok - <reason>` counts only in a real comment token. It is
a tokenizer for the common shapes, not a shell parser: see "Known limits" in docs/hooks.md.
"""

from __future__ import annotations

import re
import time
import unicodedata
from collections.abc import Callable
from typing import NamedTuple

DEFAULT_SLEEP_THRESHOLD_SECONDS = 10
MAX_SLEEP_THRESHOLD_SECONDS = 3600
MIN_REASON_CHARS = 12  # "lead-wait: ok - <reason>": a reason shorter than this is a placeholder, not a reason
MIN_REASON_ALNUM = 8  # ...and so is twelve characters of punctuation: at least this many letters or digits
CACHE_MAX_CHARS = 8192  # only inputs this small are cached
CACHE_ENTRIES = 16
MAX_DEPTH = 3  # substitutions, backticks, ${...}, `bash -c` bodies and `eval` are scanned this deep, then UNSCANNABLE

GH_RUN_WATCH = "gh-run-watch"
GH_PR_CHECKS_WATCH = "gh-pr-checks-watch"
SLEEP_LOOP = "sleep-loop"
LONG_SLEEP = "long-sleep"
WATCH = "watch"  # the `watch` command: it re-runs something until you stop it
UNSCANNABLE = "unscannable-depth"  # nested deeper than MAX_DEPTH
UNSCANNABLE_BRACE = "unscannable-brace"  # a brace expansion builds the command word
UNSCANNABLE_TIMEOUT = "unscannable-timeout"  # the scan ran out of its deadline
UNSCANNABLE_INDIRECT = "unscannable-indirect"  # a function exists and a variable names the command
KINDS = (
    GH_RUN_WATCH,
    GH_PR_CHECKS_WATCH,
    WATCH,
    SLEEP_LOOP,
    LONG_SLEEP,
    UNSCANNABLE,
    UNSCANNABLE_BRACE,
    UNSCANNABLE_INDIRECT,
    UNSCANNABLE_TIMEOUT,
)

MARKER = "lead-wait: ok -"
_MARKER = re.compile(r"lead-wait:[ \t]*ok[ \t]*-[ \t]*(\S[^\n]*)", re.IGNORECASE)

_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
_REDIRECT_OP = re.compile(r"(?:\d*|&)(?:>>?|<<<|<)&?")  # a redirection operator whose target is the NEXT word
_REDIRECT_ATTACHED = re.compile(r"(?:\d*|&)(?:>>?|<)&?\S")  # `2>&1`, `>file`: the target is part of the word
_WATCH_FLAG = re.compile(r"--watch(?:=(?!(?:false|0)$).*)?|-[A-Za-z]*w[A-Za-z]*")
_DURATION = re.compile(r"(\d+(?:\.\d+)?)([smhd]?)")
_UNIT = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}
_BRACE_EXPANSION = re.compile(r"\{[^{}]*(?:,|\.\.)[^{}]*\}")
_FUNC_PARENS = re.compile(r"\([ \t]*\)")
_FUNC_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.:+-]*")

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
    "stdbuf": frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}),
    "setsid": frozenset(),
    "flock": frozenset({"-w", "--timeout", "--wait", "-E", "--conflict-exit-code"}),
    "ionice": frozenset({"-c", "--class", "-n", "--classdata"}),
    "taskset": frozenset(),
    "chrt": frozenset(),
    "unbuffer": frozenset(),
    "parallel": frozenset(
        {
            "-j",
            "--jobs",
            "-n",
            "--max-args",
            "-N",
            "-P",
            "--max-procs",
            "-L",
            "-l",
            "--max-lines",
            "-a",
            "--arg-file",
            "-d",
            "--delimiter",
            "-E",
            "--eof",
            "--halt",
            "--joblog",
            "--results",
            "--colsep",
            "--retries",
            "--timeout",
            "--delay",
            "--workdir",
            "--tmpdir",
            "--env",
            "--header",
            "--load",
            "--memfree",
            "--nice",
            "--trc",
            "--return",
            "--tag-string",
            "--shebang-wrap",
        }
    ),
    "xargs": frozenset(
        {
            "-a",
            "-d",
            "-E",
            "-I",
            "-L",
            "-n",
            "-P",
            "-s",
            "--arg-file",
            "--delimiter",
            "--eof",
            "--max-args",
            "--max-lines",
            "--max-procs",
            "--max-chars",
            "--process-slot-var",
        }
    ),
}
# Operands that come between a wrapper's options and the command it runs: `timeout 5 cmd`, `flock file cmd`.
WRAPPER_OPERANDS = {"timeout": 1, "flock": 1, "taskset": 1, "chrt": 1}
_PARALLEL_FLAGS = frozenset(
    {
        "-k",
        "-v",
        "-t",
        "-u",
        "-q",
        "-m",
        "-g",
        "--keep-order",
        "--verbose",
        "--tag",
        "--ungroup",
        "--group",
        "--pipe",
        "--bar",
        "--eta",
        "--progress",
        "--link",
        "--dry-run",
        "--shuf",
        "--plus",
        "--no-notice",
        "--quote",
        "--citation",
        "--silent",
        "--lb",
        "--line-buffer",
    }
)  # parallel options that take no value; any other option makes the command unknowable here
_REPLACEMENT_STRING = re.compile(r"\{[^{}]*\}")
_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh"})
_SHELL_C = re.compile(r"-[A-Za-z]*c[A-Za-z]*")
_FIND_EXEC = frozenset({"-exec", "-execdir", "-ok", "-okdir"})
_PLACEHOLDER = "$()"  # stands in a word for a substitution: it is never a readable number
_ANSI_SIMPLE = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "a": "\a",
    "b": "\b",
    "e": "\x1b",
    "E": "\x1b",
    "f": "\f",
    "v": "\v",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "?": "?",
}


def _no_tick() -> None:
    """The default deadline check: none."""


_tick: Callable[[], None] = _no_tick  # set by `_build` to the running scan's deadline check; the helper loops call it


def _find_dq(text: str, i: int) -> int:
    """Index just past the `"` that closes a double quoted string whose body begins at `i`."""
    n = len(text)
    while i < n:
        _tick()
        c = text[i]
        if c == "\\":
            i += 2
        elif c == '"':
            return i + 1
        elif text.startswith("$(", i):
            i = _find_close(text, i + 2, ")")
        elif text.startswith("${", i):
            i = _find_close(text, i + 2, "}")
        elif c == "`":
            i = _find_backtick(text, i + 1)
        else:
            i += 1
    return n


def _find_backtick(text: str, i: int) -> int:
    """Index just past the closing backtick of a body that begins at `i`."""
    n = len(text)
    while i < n and text[i] != "`":
        _tick()
        i += 2 if text[i] == "\\" else 1
    return min(i + 1, n)


def _find_close(text: str, i: int, close: str) -> int:
    """Index just past the `close` ( `)` or `}` ) of a group whose body begins at `i`, skipping quoted text and nested
    substitutions; the end of the text if there is none."""
    opener = {")": "(", "}": "{", "]": "["}[close]
    level, n = 1, len(text)
    while i < n:
        _tick()
        c = text[i]
        if c == "\\":
            i += 2
        elif c == "'":
            end = text.find("'", i + 1)
            i = n if end < 0 else end + 1
        elif c == '"':
            i = _find_dq(text, i + 1)
        elif c == "`":
            i = _find_backtick(text, i + 1)
        elif text.startswith("$(", i):
            i = _find_close(text, i + 2, ")")
        elif text.startswith("${", i):
            i = _find_close(text, i + 2, "}")
        else:
            if c == opener:
                level += 1
            elif c == close:
                level -= 1
                if level == 0:
                    return i + 1
            i += 1
    return n


def _ansi_c(text: str, i: int) -> tuple[str, int]:
    """Decode the body of a `$'...'` string that begins at `i`; returns the text and the index past its end."""
    out: list[str] = []
    n = len(text)
    while i < n and text[i] != "'":
        _tick()
        c = text[i]
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        nxt = text[i + 1]
        if nxt in _ANSI_SIMPLE:
            out.append(_ANSI_SIMPLE[nxt])
            i += 2
        elif nxt == "x" and (m := re.compile(r"[0-9A-Fa-f]{1,2}").match(text, i + 2)):
            out.append(chr(int(m.group(), 16)))
            i = m.end()
        elif nxt in "01234567" and (m := re.compile(r"[0-7]{1,3}").match(text, i + 1)):
            out.append(chr(int(m.group(), 8)))
            i = m.end()
        else:
            out.append(c + nxt)
            i += 2
    return "".join(out), min(i + 1, n)


def _heredoc_word(text: str, i: int) -> tuple[str, bool, int] | None:
    """The COMPLETE shell word that follows `<<` at `i`, quote-removed: (delimiter, any part quoted, end index).

    Bash joins unquoted and quoted segments (`E'OF'`, `EO\\F`, `$'EOF'`, `"E"OF`) into one delimiter and quote-removes
    it; the body is expanded only if no part of the word was quoted.
    """
    out: list[str] = []
    quoted = False
    n = len(text)
    j = i
    while j < n and text[j] not in " \t\n;&|()<>":
        _tick()
        c = text[j]
        if c == "\\":
            if j + 1 < n and text[j + 1] != "\n":  # backslash-newline is removed before bash tokenizes
                out.append(text[j + 1])
                quoted = True
            j += 2
        elif c == "'":
            end = text.find("'", j + 1)
            out.append(text[j + 1 : n if end < 0 else end])
            quoted = True
            j = n if end < 0 else end + 1
        elif c == "$" and text.startswith("$'", j):
            decoded, j = _ansi_c(text, j + 2)
            out.append(decoded)
            quoted = True
        elif c == '"' or text.startswith('$"', j):
            j += 1 if c == '"' else 2
            while j < n and text[j] != '"':
                _tick()
                if text[j] == "\\" and j + 1 < n and text[j + 1] == "\n":
                    j += 2
                    continue
                if text[j] == "\\" and j + 1 < n and text[j + 1] in '$`"\\':
                    j += 1
                out.append(text[j])
                j += 1
            j += 1
            quoted = True
        else:
            out.append(c)
            j += 1
    if j == i:
        return None
    return "".join(out), quoted, min(j, n)


def _drop_continuations(span: str) -> str:
    """`span` without its backslash-newline pairs (an escaped backslash before a newline is not one)."""
    out: list[str] = []
    i, n = 0, len(span)
    while i < n:
        _tick()
        if span[i] == "\\" and i + 1 < n:
            if span[i + 1] != "\n":
                out.append(span[i : i + 2])
            i += 2
        else:
            out.append(span[i])
            i += 1
    return "".join(out)


def _join_continuations(text: str, tick: Callable[[], None]) -> str:
    """The command as bash sees it after it removes every backslash-newline, so each later stage reads the same text.

    Not removed, because bash keeps them: inside single quotes and `$'...'`, in a comment (which ends at its newline)
    and in the body of a heredoc whose delimiter is quoted. Removed inside double quotes and in an unquoted heredoc
    body, where a line that ends in a backslash is joined to the next one BEFORE it is compared with the delimiter.
    """
    out: list[str] = []
    last = "\n"
    i, n = 0, len(text)
    pending: list[tuple[str, bool, bool]] = []  # heredocs whose body starts after the next newline

    def put(piece: str) -> None:
        nonlocal last
        if piece:
            out.append(piece)
            last = piece[-1]

    while i < n:
        tick()
        c = text[i]
        if c == "\\":
            if text.startswith("\\\n", i):
                i += 2
                continue
            put(text[i : i + 2])
            i += 2
        elif c == "'":
            end = text.find("'", i + 1)
            end = n if end < 0 else end + 1
            put(text[i:end])
            i = end
        elif text.startswith("$'", i):
            j = i + 2
            while j < n and text[j] != "'":
                tick()
                j += 2 if text[j] == "\\" else 1
            put(text[i : j + 1])
            i = j + 1
        elif c == '"':
            end = _find_dq(text, i + 1)
            put(_drop_continuations(text[i:end]))
            i = end
        elif c == "#" and last in " \t\n;&|()<>":
            end = text.find("\n", i)
            end = n if end < 0 else end
            put(text[i:end])  # a comment ends at its newline: a trailing backslash does not continue it
            i = end
        elif text.startswith("$((", i) or (text.startswith("((", i) and last in " \t\n;&|()"):
            end = _find_close(text, i + (2 if c == "$" else 1), ")")
            put(_drop_continuations(text[i:end]))  # arithmetic: `1 << 2` there is a shift, not a heredoc
            i = end
        elif text.startswith("<\\\n<", i):
            text = text[: i + 1] + text[i + 3 :]  # `<` backslash-newline `<` is the operator `<<`
            n = len(text)
        elif text.startswith("<<<", i):
            put("<<<")
            i += 3
        elif text.startswith("<<", i):
            j = i + 2
            strip_tabs = text.startswith("-", j)
            j += 1 if strip_tabs else 0
            while j < n and text[j] in " \t":
                tick()
                j += 1
            word = _heredoc_word(text, j)
            if word is None:
                put("<<")
                i += 2
            else:
                put(_drop_continuations(text[i : word[2]]))
                pending.append((word[0], strip_tabs, word[1]))
                i = word[2]
        elif c == "\n":
            put("\n")
            i += 1
            for delimiter, strip_tabs, was_quoted in pending:
                while i < n:
                    tick()
                    end = text.find("\n", i)
                    line = text[i : n if end < 0 else end]
                    had_newline = end >= 0
                    i = n if end < 0 else end + 1
                    while not was_quoted and had_newline and (len(line) - len(line.rstrip("\\"))) % 2 == 1:
                        tick()
                        end = text.find("\n", i)  # an unquoted body: a trailing backslash joins the next line
                        line = line[:-1] + text[i : n if end < 0 else end]
                        had_newline = end >= 0
                        i = n if end < 0 else end + 1
                    put(line + ("\n" if had_newline else ""))
                    if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                        break
            pending.clear()
        else:
            put(c)
            i += 1
    return "".join(out)


class Word(NamedTuple):
    """One word of a simple command, quotes removed and substitutions replaced by a placeholder."""

    text: str
    quoted: bool  # any part of it was quoted or escaped
    brace: bool = False  # it holds an UNQUOTED brace expansion: `{a,b}` or `{1..3}`
    expands: bool = False  # it holds a `$` expansion (a variable or a substitution): its value is unknown


class _Clock:
    """The deadline check shared by a scan's loops: every 256th call it gives up when the deadline has passed."""

    def __init__(self, deadline: float | None) -> None:
        self.deadline = deadline
        self.ticks = 0

    def tick(self) -> None:
        if self.deadline is not None and self.ticks % 256 == 0 and time.monotonic() > self.deadline:
            raise _Timeout
        self.ticks += 1


class _Unscannable(Exception):
    """A wrapper's words cannot be resolved with confidence; `kind` is the verdict."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


class _Timeout(Exception):
    """The scan ran past its deadline."""


class _Body(NamedTuple):
    """What a function body holds, kept apart until the call invokes the function."""

    found: set[str]
    sleeps: list[float | None]
    comments: list[str]


class _Capture:
    """A function body being read."""

    def __init__(self, name: str, saved: tuple[set[str], list[float | None], list[bool], list[str]]) -> None:
        self.name = name
        self.saved = saved
        self.braces = 0
        self.started = False
        self.done = False


class _Scan:
    """One pass over a command: what waits it holds and which real comments it carries."""

    def __init__(self, deadline: float | None = None) -> None:
        self.clock = _Clock(deadline)
        self.found: set[str] = set()
        self.sleeps: list[float | None] = []
        self.comments: list[str] = []
        self.bodies: list[tuple[str, bool]] = []  # (heredoc body as the shell delivers it, delimiter was quoted)
        self.loops: list[bool] = []  # one entry per open loop: has its `do` been seen (are we in the body)
        self.funcs: dict[str, _Body] = {}
        self.caps: list[_Capture] = []  # function bodies being read, innermost last (a function can nest in another)
        self.defined_any = False  # the call defines a function somewhere
        self.indirect = False  # the call runs a variable-expanded word at command position

    @property
    def cap(self) -> _Capture | None:
        return self.caps[-1] if self.caps else None

    def tick(self) -> None:
        """Called from every scanning loop; see `_Clock`."""
        self.clock.tick()

    def run(self, command: str) -> None:
        self.walk(_join_continuations(command, self.tick), 0, False, 0, True)

    # -- expansions: code that hides in what looks like data ------------------------------------------------------

    def too_deep(self) -> None:
        self.found.add(UNSCANNABLE)

    def expansion(self, text: str, i: int, depth: int) -> int:
        """If an expansion that can run code (`$(`, a backtick, `${`) begins at `i`, scan it and return the index past
        it; otherwise -1."""
        if text.startswith("$((", i) or text.startswith("$[", i):
            end = self.arithmetic_end(text, i)
            if end >= 0:  # arithmetic: its words are not commands, but a substitution inside it runs
                skip = 3 if text.startswith("$((", i) else 2
                if depth >= MAX_DEPTH:
                    self.too_deep()
                else:
                    self.scan_data(text[i + skip : end - (2 if skip == 3 else 1)], depth + 1, True)
                return end
        if text.startswith("$(", i):
            if depth >= MAX_DEPTH:
                self.too_deep()
                return _find_close(text, i + 2, ")")
            return self.walk(text, i + 2, True, depth + 1, False)
        if text[i] == "`":
            return self.backticks(text, i, depth)
        if text.startswith("${", i):
            end = _find_close(text, i + 2, "}")
            if depth >= MAX_DEPTH:
                self.too_deep()
            else:
                self.scan_data(text[i + 2 : end - 1], depth + 1, True)
            return end
        return -1

    @staticmethod
    def arithmetic_end(text: str, i: int) -> int:
        """Index past the end of the `$((...))` or `$[...]` at `i`, or -1 if it is not arithmetic. `$((a); (b))` is a
        command substitution around two subshells: the first inner parenthesis closes before the pair does."""
        if text.startswith("$[", i):
            end = _find_close(text, i + 2, "]")
            return end if text[end - 1 : end] == "]" else -1
        j, n, level = i + 3, len(text), 0
        while j < n:
            _tick()
            c = text[j]
            if c == "\\":
                j += 2
            elif c == "'":
                end = text.find("'", j + 1)
                j = n if end < 0 else end + 1
            elif c == '"':
                j = _find_dq(text, j + 1)
            elif c == "`":
                j = _find_backtick(text, j + 1)
            elif text.startswith("$(", j):
                j = _find_close(text, j + 2, ")")
            elif c == "(":
                level += 1
                j += 1
            elif c == ")":
                if level == 0:
                    return j + 2 if text.startswith("))", j) else -1
                level -= 1
                j += 1
            else:
                j += 1
        return -1

    def scan_data(self, text: str, depth: int, honor_quotes: bool) -> None:
        """Scan text that is data except for its expansions: the inside of `${...}` (quotes matter: single quotes keep
        text literal) and an unquoted heredoc body (quotes are plain characters there)."""
        i, n = 0, len(text)
        in_dq = False
        while i < n:
            self.tick()
            c = text[i]
            if c == "\\":
                i += 2
            elif honor_quotes and c == "'" and not in_dq:
                end = text.find("'", i + 1)
                i = n if end < 0 else end + 1
            elif honor_quotes and c == '"':
                in_dq = not in_dq
                i += 1
            else:
                j = self.expansion(text, i, depth)
                i = j if j >= 0 else i + 1

    def backticks(self, text: str, i: int, depth: int) -> int:
        """`text[i]` is a backtick: scan the command inside as code and return the index past the closing one."""
        end = _find_backtick(text, i + 1)
        self.nested(text[i + 1 : max(end - 1, i + 1)].replace("\\`", "`"), depth)
        return end

    def nested(self, script: str, depth: int) -> None:
        """Scan a script given as a string (a `bash -c` body, an `eval`, a backtick body) in the same loop context."""
        if depth >= MAX_DEPTH:
            self.too_deep()
            return
        base = len(self.loops)
        self.walk(_join_continuations(script, self.tick), 0, False, depth + 1, False)
        del self.loops[base:]  # whatever loop the string left open ends with the string

    # -- the tokenizer ------------------------------------------------------------------------------------------

    def walk(self, text: str, i: int, sub: bool, depth: int, top: bool) -> int:
        """Scan `text` from `i`. With `sub` it stops after the `)` that closes a `$(`. Returns where it stopped."""
        n = len(text)
        words: list[Word] = []
        cur: list[str] = []
        has = False  # a word is open (it may be empty: '')
        quoted = False
        unquoted: list[str] = []  # the characters of the open word that are not quoted or escaped
        expands = False
        pending: list[tuple[str, bool, bool]] = []  # heredocs whose body starts after the next newline
        parens = 0

        def flush() -> None:
            nonlocal has, quoted, expands
            if has:
                brace = bool(_BRACE_EXPANSION.search("".join(unquoted)))
                words.append(Word("".join(cur), quoted, brace, expands))
            cur.clear()
            unquoted.clear()
            has = quoted = expands = False

        def end_command() -> None:
            flush()
            if words:
                self.command(tuple(words), depth)
                words.clear()

        while i < n:
            self.tick()
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
            elif c == '"' or text.startswith('$"', i):
                has = quoted = True
                i += 1 if c == '"' else 2
                while i < n and text[i] != '"':
                    self.tick()
                    ch = text[i]
                    if ch == "\\" and i + 1 < n:
                        if text[i + 1] != "\n":
                            cur.append(text[i + 1] if text[i + 1] in '$`"\\' else "\\" + text[i + 1])
                        i += 2
                    elif (j := self.expansion(text, i, depth)) >= 0:
                        cur.append(_PLACEHOLDER)
                        expands = True
                        i = j
                    else:
                        cur.append(ch)
                        expands = expands or ch == "$"
                        i += 1
                i += 1
            elif text.startswith("$'", i):
                decoded, i = _ansi_c(text, i + 2)
                cur.append(decoded)
                has = quoted = True
            elif (c == "$" or c == "`") and (j := self.expansion(text, i, depth)) >= 0:
                cur.append(_PLACEHOLDER)
                has = expands = True
                i = j
            elif c == "#" and not has:
                end_command()  # whatever precedes the comment on its line is complete (`}` closes a body)
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
                for delimiter, strip_tabs, was_quoted in pending:
                    i = self.heredoc_body(text, i, delimiter, strip_tabs, was_quoted, depth)
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
                    if depth >= MAX_DEPTH:
                        self.too_deep()
                        i = _find_close(text, i + 1, ")")
                    else:
                        i = self.walk(text, i + 1, True, depth + 1, False)
                    cur.append(_PLACEHOLDER)
                    expands = True
                elif (m := _FUNC_PARENS.match(text, i)) and (header := self.header_name(words, cur, has)):
                    name, lead = header
                    if lead:
                        self.command(tuple(words[:lead]), depth)
                    words.clear()
                    cur.clear()
                    has = quoted = False
                    self.begin_function(name)
                    i = m.end()
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
            elif c == "<" and text.startswith("<<<", i):
                flush()  # a here-string: the three characters are one operator, the next word is its (scanned) text
                words.append(Word("<<<", False))
                i += 3
            elif c == "<" and text.startswith("<<", i):
                j = i + 2
                strip_tabs = text.startswith("-", j)
                j += 1 if strip_tabs else 0
                while j < n and text[j] in " \t":
                    j += 1
                word = _heredoc_word(text, j)
                if word is None:
                    cur.append(c)
                    unquoted.append(c)
                    has = True
                    i += 1
                else:
                    flush()
                    pending.append((word[0], strip_tabs, word[1]))
                    i = word[2]
            else:
                cur.append(c)
                unquoted.append(c)
                has = True
                expands = expands or c == "$"
                i += 1
        end_command()
        return n

    def heredoc_body(self, text: str, i: int, delimiter: str, strip_tabs: bool, was_quoted: bool, depth: int) -> int:
        """Read the body that starts at `i` up to the line that is exactly the delimiter; returns the index past it."""
        n = len(text)
        lines: list[str] = []
        while i < n:
            self.tick()
            end = text.find("\n", i)
            line = text[i : n if end < 0 else end]
            i = n if end < 0 else end + 1
            if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                break
            lines.append(line.lstrip("\t") if strip_tabs else line)
        body = "".join(line + "\n" for line in lines)
        self.bodies.append((body, was_quoted))
        if not was_quoted:
            self.scan_data(body, depth, False)  # an unquoted body still undergoes expansion
        return i

    # -- functions: defined here, waiting only if invoked ---------------------------------------------------------

    @staticmethod
    def header_name(words: list[Word], cur: list[str], has: bool) -> tuple[str, int] | None:
        """(name, leading keyword words) if the words before a `()` are `[keywords] name` or `[keywords] function name`;
        the keywords (`{`, `do`, `then`...) belong to the command that holds the definition."""
        texts = [w.text for w in words] + (["".join(cur)] if has else [])
        lead = 0
        while lead < len(texts) - 1 and texts[lead] in (_KEYWORDS - {"}"}):
            lead += 1
        pending = texts[lead:]
        if len(pending) == 2 and pending[0] == "function":
            pending = pending[1:]
        if len(pending) == 1 and _FUNC_NAME.fullmatch(pending[0]) and pending[0] not in _KEYWORDS | _LOOP_HEADS:
            return pending[0], lead
        return None

    def begin_function(self, name: str) -> None:
        self.defined_any = True
        self.caps.append(_Capture(name, (self.found, self.sleeps, self.loops, self.comments)))
        self.found, self.sleeps, self.loops, self.comments = set(), [], [], []

    def end_function(self, register: bool) -> None:
        cap = self.cap
        if cap is None:
            return
        if register:
            self.funcs[cap.name] = _Body(self.found, self.sleeps, self.comments)
        self.found, self.sleeps, self.loops, self.comments = cap.saved
        self.caps.pop()

    def finish(self) -> None:
        """The call ended inside a function body: it was defined and never invoked, so it is dormant."""
        while self.caps:
            self.end_function(register=True)
        if self.defined_any and self.indirect:
            self.found.add(UNSCANNABLE_INDIRECT)  # a variable-expanded command word could name any function

    # -- one simple command -------------------------------------------------------------------------------------

    def command(self, words: tuple[Word, ...], depth: int) -> None:
        if words[0][:2] == ("function", False) and len(words) >= 2:
            self.begin_function(words[1][0])  # `function name { ... }`
            words = words[2:]
            if not words:
                return
        if self.cap is not None and not self.cap.started and words[0][:2] != ("{", False):
            self.end_function(register=False)  # the body is not a brace group: read it as live code
        self.simple(words, depth)
        if self.cap is not None and self.cap.done:
            self.end_function(register=True)

    def brace(self, text: str) -> None:
        cap = self.cap
        if cap is None:
            return
        if text == "{":
            cap.braces += 1
            cap.started = True
        else:
            cap.braces -= 1
            if cap.started and cap.braces <= 0:
                cap.done = True

    def simple(self, words: tuple[Word, ...], depth: int) -> None:
        # Redirections are not arguments: `sleep 5 > /dev/null 2>&1` is `sleep 5`.
        kept: list[Word] = []
        skip = False
        for word in words:
            text, was_quoted = word.text, word.quoted
            if skip:
                skip = False
            elif was_quoted or not (_REDIRECT_OP.fullmatch(text) or _REDIRECT_ATTACHED.match(text)):
                kept.append(word)
            elif _REDIRECT_OP.fullmatch(text):
                skip = True
        i = 0
        while i < len(kept):
            text, was_quoted = kept[i].text, kept[i].quoted
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
            elif text in ("{", "}"):
                self.brace(text)
            elif text not in _KEYWORDS:
                break
            i += 1
        while i < len(kept) and _ASSIGNMENT.match(kept[i][0]):
            i += 1
        while i < len(kept) and kept[i][0].rsplit("/", 1)[-1] in WRAPPERS:
            try:
                i, script = self.unwrap(kept, i)
            except _Unscannable as unresolved:
                self.found.add(unresolved.kind)
                return
            if script is not None:
                self.nested(script, depth)  # `env -S 'sleep 60'`: the split string is a command line
                return
        if i >= len(kept):
            return
        if kept[i].brace:
            self.found.add(UNSCANNABLE_BRACE)  # `{sleep,60}`, `sl{e..e}ep`: the command is built at run time
            return
        name = kept[i][0].rsplit("/", 1)[-1]
        args = [w.text for w in kept[i + 1 :]]
        if kept[i].expands:
            self.indirect = True
        if name in self.funcs:
            body = self.funcs[name]
            self.found |= body.found
            self.sleeps += body.sleeps
            self.comments += body.comments  # an invoked body's comments are part of the call
            if body.sleeps and self.loops:
                self.found.add(SLEEP_LOOP)
        elif name == "sleep":
            self.sleeps.append(_sleep_seconds(args))
            if self.loops:  # in a loop body OR its condition: a poll either way
                self.found.add(SLEEP_LOOP)
        elif name == "watch":
            self.found.add(WATCH)
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
        elif name == "find":
            k = 0
            rest = kept[i + 1 :]
            while k < len(args):
                if args[k] in _FIND_EXEC:
                    run: list[Word] = []
                    k += 1
                    while k < len(args) and args[k] not in (";", "+"):
                        run.append(rest[k])  # keeps the quoted and brace flags of each word
                        k += 1
                    if run:
                        self.simple(tuple(run), depth)
                k += 1

    @staticmethod
    def parallel(kept: list[Word], i: int) -> tuple[int, str | None]:
        """`parallel [options] template ::: arguments`: the template is the command line to scan. When it is empty or
        its first word is a replacement string (`{}`), the commands come from the arguments or from input, and an option
        that is not in the recognized lists may take a value that hides the command: fail closed."""
        valued = WRAPPERS["parallel"]
        j = i + 1
        while j < len(kept):
            word = kept[j]
            text = word.text
            if word.brace:
                raise _Unscannable(UNSCANNABLE_BRACE)
            if text.startswith(":::") or not text.startswith("-") or text == "-":
                break
            if text == "--":
                j += 1
                break
            name = text.split("=", 1)[0] if text.startswith("--") else text
            if name in valued:
                takes_next = not (text.startswith("--") and "=" in text)
                if takes_next and j + 1 < len(kept) and kept[j + 1].brace:
                    raise _Unscannable(UNSCANNABLE_BRACE)
                j += 2 if takes_next else 1
            elif name in _PARALLEL_FLAGS or (not text.startswith("--") and text[:2] in valued and len(text) > 2):
                j += 1
            else:
                raise _Unscannable(UNSCANNABLE_INDIRECT)
        template: list[Word] = []
        while j < len(kept) and not kept[j].text.startswith(":::"):
            template.append(kept[j])
            j += 1
        if not template or _REPLACEMENT_STRING.search(template[0].text):
            raise _Unscannable(UNSCANNABLE_INDIRECT)
        return len(kept), " ".join(w.text for w in template)

    @staticmethod
    def unwrap(kept: list[Word], i: int) -> tuple[int, str | None]:
        """Index of the command a wrapper at `i` runs (len(kept) when it runs none). For `env -S 'string'` the second
        value is the string (with the words after it), which is a command line to scan."""
        wrapper = kept[i][0].rsplit("/", 1)[-1]
        if wrapper == "parallel":
            return _Scan.parallel(kept, i)
        valued = WRAPPERS[wrapper]
        j = i + 1
        operands = WRAPPER_OPERANDS.get(wrapper, 0)
        while j < len(kept):
            text = kept[j][0]
            if kept[j].brace and not (wrapper in ("env", "sudo") and _ASSIGNMENT.match(text)):
                # A brace expansion in an option, an option value or an operand changes how many words the wrapper
                # takes, so which word is the wrapped command is unknown: fail closed.
                raise _Unscannable(UNSCANNABLE_BRACE)
            if wrapper == "command" and text in ("-v", "-V"):
                return len(kept), None  # `command -v sleep` looks a name up; it runs nothing
            if wrapper == "env" and (text in ("-S", "--split-string") or text.startswith(("--split-string=", "-S"))):
                if text in ("-S", "--split-string"):
                    if j + 1 < len(kept) and kept[j + 1].brace:
                        raise _Unscannable(UNSCANNABLE_BRACE)
                    split, j = (kept[j + 1][0] if j + 1 < len(kept) else ""), j + 2
                else:
                    split, j = (text.split("=", 1)[1] if text.startswith("--") else text[2:]), j + 1
                return len(kept), " ".join([split, *(w.text for w in kept[j:])])
            if wrapper == "flock" and text in ("-c", "--command"):
                if j + 1 < len(kept) and kept[j + 1].brace:
                    raise _Unscannable(UNSCANNABLE_BRACE)
                return len(kept), kept[j + 1].text if j + 1 < len(kept) else ""  # flock FILE -c 'command line'
            if text.startswith("-") and text != "-":
                if text in valued and j + 1 < len(kept) and kept[j + 1].brace:
                    raise _Unscannable(UNSCANNABLE_BRACE)
                j += 2 if text in valued else 1
            elif wrapper in ("env", "sudo") and _ASSIGNMENT.match(text):
                j += 1
            elif operands:
                operands -= 1
                j += 1
            else:
                break
        return j, None


_SMALL_CACHE: dict[str, _Scan] = {}  # at most CACHE_ENTRIES inputs of at most CACHE_MAX_CHARS characters
_last_large: list[tuple[str, _Scan]] = []  # the one large input of the current call, matched by identity


def _build(command: str, deadline: float | None) -> _Scan:
    global _tick
    scan = _Scan(deadline)
    _tick = scan.tick  # the module-level helper loops check the same deadline
    try:
        scan.run(command)
        scan.finish()
    except RecursionError:
        scan.too_deep()  # pathological nesting that outruns even the depth limit: an explicit verdict, not a crash
    except _Timeout:
        scan.found.add(UNSCANNABLE_TIMEOUT)  # out of time: fail closed
    finally:
        _tick = _no_tick
    return scan


def _scan(command: str, deadline: float | None = None) -> _Scan:
    """One pass per command. Small inputs are cached (bounded); a large one is remembered for the current call only,
    by identity, so the three questions the hook asks cost one scan. A scan that timed out is never remembered."""
    if len(command) <= CACHE_MAX_CHARS:
        if command in _SMALL_CACHE:
            return _SMALL_CACHE[command]
    elif _last_large and _last_large[0][0] is command:
        return _last_large[0][1]
    scan = _build(command, deadline)
    if UNSCANNABLE_TIMEOUT not in scan.found:
        if len(command) <= CACHE_MAX_CHARS:
            if len(_SMALL_CACHE) >= CACHE_ENTRIES:
                del _SMALL_CACHE[next(iter(_SMALL_CACHE))]
            _SMALL_CACHE[command] = scan
        else:
            _last_large[:] = [(command, scan)]
    return scan


def real_reason(text: str, tick: Callable[[], None] = _no_tick) -> bool:
    """Is this a stated reason?

    With combining marks and zero-width or other format characters removed, it must be MIN_REASON_CHARS long, and at
    least MIN_REASON_ALNUM of its characters must be Unicode letters (category L*) or ASCII digits. Combining marks,
    zero-width padding, non-ASCII digits (full-width, Arabic-Indic, circled) and punctuation do not count. `tick` is
    called once per character so a huge reason cannot outrun the deadline.
    """
    kept: list[str] = []
    for ch in text:
        tick()
        if unicodedata.category(ch) not in ("Mn", "Mc", "Me", "Cf"):
            kept.append(ch)
    cleaned = "".join(kept).strip()
    counted = 0
    for ch in cleaned:
        tick()
        counted += unicodedata.category(ch).startswith("L") or ch in "0123456789"
    return len(cleaned) >= MIN_REASON_CHARS and counted >= MIN_REASON_ALNUM


def marker_reason(command: str, deadline: float | None = None) -> str:
    """The stated reason of a `lead-wait: ok - <reason>` marker in a real comment of the command, or "" when there
    is none, it is a placeholder, or the text only sits inside a string, a heredoc body or an argument.

    The marker may be in any comment of the call, on the wait's line or another; the call is one decision. Out of
    time (the scan timed out, or checking a reason ran past the deadline) it returns "": a marker that was not
    verified never exempts anything, so the call is judged as the wait or unscannable-timeout it is.
    """
    scan = _scan(command, deadline)
    if UNSCANNABLE_TIMEOUT in scan.found:
        return ""
    clock = _Clock(deadline)
    try:
        for comment in scan.comments:
            found = _MARKER.search(comment)
            reason = found.group(1).strip() if found else ""
            if real_reason(reason, clock.tick):
                return reason
    except _Timeout:
        return ""
    return ""


def heredoc_bodies(command: str) -> tuple[str, ...]:
    """The heredoc bodies the scanner skipped as data, as the shell delivers them (for the bash differential test)."""
    return tuple(body for body, _ in _scan(command).bodies)


def heredoc_quoted(command: str) -> tuple[bool, ...]:
    """For each heredoc, whether any part of its delimiter was quoted (so its body is not expanded)."""
    return tuple(was_quoted for _, was_quoted in _scan(command).bodies)


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


def find_waits(
    command: str, threshold: int = DEFAULT_SLEEP_THRESHOLD_SECONDS, deadline: float | None = None
) -> tuple[str, ...]:
    """The kinds of wait a command contains, in a fixed order; empty when it does not wait."""
    scan = _scan(command, deadline)
    found = set(scan.found)
    # The sleeps of one command add up: `sleep 5; sleep 6` holds the thread for 11 seconds.
    if any(s is None for s in scan.sleeps) or sum(s for s in scan.sleeps if s is not None) >= threshold:
        found.add(LONG_SLEEP)
    return tuple(k for k in KINDS if k in found)


def may_wait(command: str, deadline: float | None = None) -> bool:
    """A cheap test before any configuration is read: could this command contain a wait at all?

    A command with none of the three words and no character that can build a word out of pieces (a quote, a
    backslash, `$` or a backtick: `sl''eep 60`) cannot. Anything else is tokenized, which reads no configuration.
    """
    if not any(w in command for w in ("sleep", "watch", "checks", "parallel")) and not any(
        c in command for c in "'\"\\$`{"
    ):
        return False
    scan = _scan(command, deadline)
    return bool(scan.found or scan.sleeps)


def message(kinds: tuple[str, ...]) -> str:
    """The text the hook shows. Fixed wording per kind: nothing of the command or its arguments is echoed."""
    what = {
        GH_RUN_WATCH: "`gh run watch`",
        GH_PR_CHECKS_WATCH: "`gh pr checks --watch`",
        WATCH: "`watch`",
        SLEEP_LOOP: "a sleep loop",
        LONG_SLEEP: "a long sleep",
        UNSCANNABLE_BRACE: f"a command built by brace expansion ({UNSCANNABLE_BRACE}), so it cannot be shown not to "
        "wait",
        UNSCANNABLE_TIMEOUT: f"too large or tangled to check in time ({UNSCANNABLE_TIMEOUT}), so it cannot be shown "
        "not to wait",
        UNSCANNABLE_INDIRECT: f"a call that defines a function and runs a command named by a variable "
        f"({UNSCANNABLE_INDIRECT}), so it cannot be shown not to wait",
        UNSCANNABLE: f"nested too deeply to check ({UNSCANNABLE}: more than {MAX_DEPTH} levels), so it cannot be shown "
        "not to wait",
    }
    names = ", ".join(what[k] for k in kinds)
    return (
        f"lead never waits: this foreground Bash call is {names}. The lead session is the project manager, so the "
        "wait goes elsewhere: rerun it with run_in_background and read the result when it exits, or dispatch a "
        "read-only Sonnet monitor agent (brief template: docs/orchestrator.md). A wait that is genuinely short and "
        f"has no one to delegate to may carry the comment `# {MARKER} <reason>`; a real reason is required "
        f"(at least {MIN_REASON_CHARS} characters, {MIN_REASON_ALNUM} of them letters or digits)"
    )
