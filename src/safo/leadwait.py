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

import functools
import re

DEFAULT_SLEEP_THRESHOLD_SECONDS = 10
MAX_SLEEP_THRESHOLD_SECONDS = 3600
MIN_REASON_CHARS = 12  # "lead-wait: ok - <reason>": a reason shorter than this is a placeholder, not a reason
MIN_REASON_ALNUM = 8  # ...and so is twelve characters of punctuation: at least this many letters or digits
MAX_DEPTH = 3  # substitutions, backticks, ${...}, `bash -c` bodies and `eval` are scanned this deep, then UNSCANNABLE

GH_RUN_WATCH = "gh-run-watch"
GH_PR_CHECKS_WATCH = "gh-pr-checks-watch"
SLEEP_LOOP = "sleep-loop"
LONG_SLEEP = "long-sleep"
UNSCANNABLE = "unscannable-depth"
KINDS = (GH_RUN_WATCH, GH_PR_CHECKS_WATCH, SLEEP_LOOP, LONG_SLEEP, UNSCANNABLE)

MARKER = "lead-wait: ok -"
_MARKER = re.compile(r"lead-wait:[ \t]*ok[ \t]*-[ \t]*(\S[^\n]*)", re.IGNORECASE)

_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
_REDIRECT_OP = re.compile(r"(?:\d*|&)(?:>>?|<)&?")  # a redirection operator whose target is the NEXT word
_REDIRECT_ATTACHED = re.compile(r"(?:\d*|&)(?:>>?|<)&?\S")  # `2>&1`, `>file`: the target is part of the word
_WATCH_FLAG = re.compile(r"--watch(?:=(?!(?:false|0)$).*)?|-[A-Za-z]*w[A-Za-z]*")
_DURATION = re.compile(r"(\d+(?:\.\d+)?)([smhd]?)")
_UNIT = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}
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


def _find_dq(text: str, i: int) -> int:
    """Index just past the `"` that closes a double quoted string whose body begins at `i`."""
    n = len(text)
    while i < n:
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
        i += 2 if text[i] == "\\" else 1
    return min(i + 1, n)


def _find_close(text: str, i: int, close: str) -> int:
    """Index just past the `close` ( `)` or `}` ) of a group whose body begins at `i`, skipping quoted text and nested
    substitutions; the end of the text if there is none."""
    opener = "(" if close == ")" else "{"
    level, n = 1, len(text)
    while i < n:
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
        c = text[j]
        if c == "\\":
            if j + 1 < n:
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


Word = tuple[str, bool]  # (text with quotes removed and substitutions replaced, whether any part was quoted)


class _Capture:
    """A function body being read: its waits are kept apart until the call invokes the function."""

    def __init__(self, name: str, saved: tuple[set[str], list[float | None], list[bool]]) -> None:
        self.name = name
        self.saved = saved
        self.braces = 0
        self.started = False
        self.done = False


class _Scan:
    """One pass over a command: what waits it holds and which real comments it carries."""

    def __init__(self) -> None:
        self.found: set[str] = set()
        self.sleeps: list[float | None] = []
        self.comments: list[str] = []
        self.bodies: list[tuple[str, bool]] = []  # (heredoc body as the shell delivers it, delimiter was quoted)
        self.loops: list[bool] = []  # one entry per open loop: has its `do` been seen (are we in the body)
        self.funcs: dict[str, tuple[set[str], list[float | None]]] = {}
        self.cap: _Capture | None = None

    # -- expansions: code that hides in what looks like data ------------------------------------------------------

    def too_deep(self) -> None:
        self.found.add(UNSCANNABLE)

    def expansion(self, text: str, i: int, depth: int) -> int:
        """If an expansion that can run code (`$(`, a backtick, `${`) begins at `i`, scan it and return the index past
        it; otherwise -1."""
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

    def scan_data(self, text: str, depth: int, honor_quotes: bool) -> None:
        """Scan text that is data except for its expansions: the inside of `${...}` (quotes matter: single quotes keep
        text literal) and an unquoted heredoc body (quotes are plain characters there)."""
        i, n = 0, len(text)
        in_dq = False
        while i < n:
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
        self.walk(script, 0, False, depth + 1, False)
        del self.loops[base:]  # whatever loop the string left open ends with the string

    # -- the tokenizer ------------------------------------------------------------------------------------------

    def walk(self, text: str, i: int, sub: bool, depth: int, top: bool) -> int:
        """Scan `text` from `i`. With `sub` it stops after the `)` that closes a `$(`. Returns where it stopped."""
        n = len(text)
        words: list[Word] = []
        cur: list[str] = []
        has = False  # a word is open (it may be empty: '')
        quoted = False
        pending: list[tuple[str, bool, bool]] = []  # heredocs whose body starts after the next newline
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
            elif c == '"' or text.startswith('$"', i):
                has = quoted = True
                i += 1 if c == '"' else 2
                while i < n and text[i] != '"':
                    ch = text[i]
                    if ch == "\\" and i + 1 < n:
                        if text[i + 1] != "\n":
                            cur.append(text[i + 1] if text[i + 1] in '$`"\\' else "\\" + text[i + 1])
                        i += 2
                    elif (j := self.expansion(text, i, depth)) >= 0:
                        cur.append(_PLACEHOLDER)
                        i = j
                    else:
                        cur.append(ch)
                        i += 1
                i += 1
            elif text.startswith("$'", i):
                decoded, i = _ansi_c(text, i + 2)
                cur.append(decoded)
                has = quoted = True
            elif (c == "$" or c == "`") and (j := self.expansion(text, i, depth)) >= 0:
                cur.append(_PLACEHOLDER)
                has = True
                i = j
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
                elif (m := _FUNC_PARENS.match(text, i)) and (name := self.header_name(words, cur, has)):
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
            elif c == "<" and text.startswith("<<", i) and not text.startswith("<<<", i):
                j = i + 2
                strip_tabs = text.startswith("-", j)
                j += 1 if strip_tabs else 0
                while j < n and text[j] in " \t":
                    j += 1
                word = _heredoc_word(text, j)
                if word is None:
                    cur.append(c)
                    has = True
                    i += 1
                else:
                    flush()
                    pending.append((word[0], strip_tabs, word[1]))
                    i = word[2]
            else:
                cur.append(c)
                has = True
                i += 1
        end_command()
        return n

    def heredoc_body(self, text: str, i: int, delimiter: str, strip_tabs: bool, was_quoted: bool, depth: int) -> int:
        """Read the body that starts at `i` up to the line that is exactly the delimiter; returns the index past it."""
        n = len(text)
        lines: list[str] = []
        while i < n:
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
    def header_name(words: list[Word], cur: list[str], has: bool) -> str | None:
        """The function name if the words before a `()` are `name` or `function name`."""
        pending = [w for w, _ in words] + (["".join(cur)] if has else [])
        if len(pending) == 2 and pending[0] == "function":
            pending = pending[1:]
        if len(pending) == 1 and _FUNC_NAME.fullmatch(pending[0]) and pending[0] not in _KEYWORDS | _LOOP_HEADS:
            return pending[0]
        return None

    def begin_function(self, name: str) -> None:
        if self.cap is not None:
            return  # a function defined inside a function body: read as part of the outer body
        self.cap = _Capture(name, (self.found, self.sleeps, self.loops))
        self.found, self.sleeps, self.loops = set(), [], []

    def end_function(self, register: bool) -> None:
        cap = self.cap
        if cap is None:
            return
        if register:
            self.funcs[cap.name] = (self.found, self.sleeps)
        self.found, self.sleeps, self.loops = cap.saved
        self.cap = None

    def finish(self) -> None:
        """The call ended inside a function body: it was defined and never invoked, so it is dormant."""
        self.end_function(register=True)

    # -- one simple command -------------------------------------------------------------------------------------

    def command(self, words: tuple[Word, ...], depth: int) -> None:
        if words[0] == ("function", False) and len(words) >= 2 and self.cap is None:
            self.begin_function(words[1][0])  # `function name { ... }`
            words = words[2:]
            if not words:
                return
        if self.cap is not None and not self.cap.started and words[0] != ("{", False):
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
            elif text in ("{", "}"):
                self.brace(text)
            elif text not in _KEYWORDS:
                break
            i += 1
        while i < len(kept) and _ASSIGNMENT.match(kept[i][0]):
            i += 1
        while i < len(kept) and kept[i][0].rsplit("/", 1)[-1] in WRAPPERS:
            i, script = self.unwrap(kept, i)
            if script is not None:
                self.nested(script, depth)  # `env -S 'sleep 60'`: the split string is a command line
                return
        if i >= len(kept):
            return
        name = kept[i][0].rsplit("/", 1)[-1]
        args = [w for w, _ in kept[i + 1 :]]
        if name in self.funcs:
            found, sleeps = self.funcs[name]
            self.found |= found
            self.sleeps += sleeps
            if sleeps and any(self.loops):
                self.found.add(SLEEP_LOOP)
        elif name == "sleep":
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
        elif name == "find":
            k = 0
            while k < len(args):
                if args[k] in _FIND_EXEC:
                    run: list[Word] = []
                    k += 1
                    while k < len(args) and args[k] not in (";", "+"):
                        run.append((args[k], False))
                        k += 1
                    if run:
                        self.simple(tuple(run), depth)
                k += 1

    @staticmethod
    def unwrap(kept: list[Word], i: int) -> tuple[int, str | None]:
        """Index of the command a wrapper at `i` runs (len(kept) when it runs none). For `env -S 'string'` the second
        value is the string (with the words after it), which is a command line to scan."""
        wrapper = kept[i][0].rsplit("/", 1)[-1]
        valued = WRAPPERS[wrapper]
        j = i + 1
        duration_pending = wrapper == "timeout"
        while j < len(kept):
            text = kept[j][0]
            if wrapper == "command" and text in ("-v", "-V"):
                return len(kept), None  # `command -v sleep` looks a name up; it runs nothing
            if wrapper == "env" and (text in ("-S", "--split-string") or text.startswith(("--split-string=", "-S"))):
                if text in ("-S", "--split-string"):
                    split, j = (kept[j + 1][0] if j + 1 < len(kept) else ""), j + 2
                else:
                    split, j = (text.split("=", 1)[1] if text.startswith("--") else text[2:]), j + 1
                return len(kept), " ".join([split, *(w for w, _ in kept[j:])])
            if text.startswith("-") and text != "-":
                j += 2 if text in valued else 1
            elif wrapper in ("env", "sudo") and _ASSIGNMENT.match(text):
                j += 1
            elif duration_pending:
                duration_pending = False
                j += 1
            else:
                break
        return j, None


@functools.lru_cache(maxsize=16)
def _scan(command: str) -> _Scan:
    scan = _Scan()
    try:
        scan.walk(command, 0, False, 0, True)
        scan.finish()
    except RecursionError:
        scan.too_deep()  # pathological nesting that outruns even the depth limit: an explicit verdict, not a crash
    return scan


def real_reason(text: str) -> bool:
    """Is this a stated reason? Long enough AND mostly not punctuation: twelve characters of `!!!!` say nothing."""
    stripped = text.strip()
    return len(stripped) >= MIN_REASON_CHARS and sum(ch.isalnum() for ch in stripped) >= MIN_REASON_ALNUM


def marker_reason(command: str) -> str:
    """The stated reason of a `lead-wait: ok - <reason>` marker in a real comment of the command, or "" when there
    is none, it is a placeholder, or the text only sits inside a string, a heredoc body or an argument.

    The marker may be in any comment of the call, on the wait's line or another; the call is one decision.
    """
    for comment in _scan(command).comments:
        found = _MARKER.search(comment)
        reason = found.group(1).strip() if found else ""
        if real_reason(reason):
            return reason
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


def find_waits(command: str, threshold: int = DEFAULT_SLEEP_THRESHOLD_SECONDS) -> tuple[str, ...]:
    """The kinds of wait a command contains, in a fixed order; empty when it does not wait."""
    scan = _scan(command)
    found = set(scan.found)
    # The sleeps of one command add up: `sleep 5; sleep 6` holds the thread for 11 seconds.
    if any(s is None for s in scan.sleeps) or sum(s for s in scan.sleeps if s is not None) >= threshold:
        found.add(LONG_SLEEP)
    return tuple(k for k in KINDS if k in found)


def may_wait(command: str) -> bool:
    """A cheap test before any configuration is read: could this command contain a wait at all?

    A command with none of the three words and no character that can build a word out of pieces (a quote, a
    backslash, `$` or a backtick: `sl''eep 60`) cannot. Anything else is tokenized, which reads no configuration.
    """
    if not any(w in command for w in ("sleep", "watch", "checks")) and not any(c in command for c in "'\"\\$`"):
        return False
    scan = _scan(command)
    return bool(scan.found or scan.sleeps)


def message(kinds: tuple[str, ...]) -> str:
    """The text the hook shows. Fixed wording per kind: nothing of the command or its arguments is echoed."""
    what = {
        GH_RUN_WATCH: "`gh run watch`",
        GH_PR_CHECKS_WATCH: "`gh pr checks --watch`",
        SLEEP_LOOP: "a sleep loop",
        LONG_SLEEP: "a long sleep",
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
