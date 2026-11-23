# SPDX-License-Identifier: Apache-2.0
"""Shared-directory guard: `safo-rmguard`, a PreToolUse hook for Bash (#422).

On 2026-11-23 a reviewer agent ran `rm -rf ... *.py *.log` inside `~/.local/share/reach-around-dev` and deleted another
session's logs and helper scripts. Brief text is instruction only, so this is a check on the command itself.

It is its own entry point and its own module on purpose: the dispatch guard (`safo.guard`, `safo.modes.hooks`,
`safo.geminibrief`) is frozen (owner decision 2026-10-30), so nothing here touches it. The installed hook list gets one
more PreToolUse entry for Bash (docs/rmguard.md); nothing installs it for you.

PROGRAM FAMILIES JUDGED (and only these; docs/rmguard.md has the table): `rm`, `rmdir`, `unlink`, `shred`; `find` with
`-delete` or an `-exec` of anything not read-only (after the GNU global options `-H -L -P -O -D`); `git clean`;
`truncate`; `rsync` with `--delete*` or `--remove-*-files`; `tar --remove-files`; `mv`; `cp /dev/null`; `dd of=`; `tee`
without `-a`; and truncating redirections (`>`, `>|`, `&>`, `: > file`). Not covered: any other program, a script,
`python -c shutil.rmtree`, `git reset --hard`, a container bind mount, an alias or a function.

WHAT IS EVALUATED: when the working directory is inside a shared zone, every command. Elsewhere, a command whose text
(backslash-newline pairs removed) holds a delete word (`rm`, `rmdir`, `unlink`, `shred`, a whole-word `-delete`, `find`
with `-exec`/`-execdir`/`-ok`/`-okdir`; quotes and backslashes removed first, so `r''m` counts), a character that can
build one (`$`, a backtick, `?`, `*`, `[`, `{`: `r?`, `r[m]`, `/bin/r*`, `$RM`, `r$'m'`), or a shared zone (`-dev`,
`/tmp/claude`, `.local`). Every other command (`ls`, `git status`) returns allow at once, unparsed.

MODE: `safo-rmguard --mode enforce` (the default, and what any other value means) or `--mode warn`. The mode lives in
the hook command in the settings entry the owner controls, never in an environment variable an agent could set. In warn
mode nothing is ever blocked; each would-be block is appended, redacted, to
`~/.local/share/reach-around-lead/rmguard-warn.log` (folder 0700, file 0600, written through directory descriptors with
no symlink followed).

SHARED ZONES (where the rule applies):

* `~/.local/share/<anything>-dev` (the folder itself and everything below it), and the parents above it
  (`~/.local/share`, `~/.local`, `~`), since removing a parent removes the zone;
* the harness scratchpad parent `/tmp/claude-*` (and `/tmp`, `/`, for the same reason).

WHAT IS ALLOWED: an exact path (no glob, no expansion) STRICTLY BELOW `<dev>/agents/<name>/` (files, and recursive
removal of a subfolder), or strictly below a session's `/tmp/claude-*/<project>/<session>/scratchpad`. DENIED in a zone:
any glob, a zone or its parent, any other path, and the agent folder root `<dev>/agents/<name>` itself, recursive or
not: the hook cannot tell whose folder it is, so agent folder roots are removed by the owner in a batch. A target that
cannot be resolved is denied (an expansion other than `$HOME`/`~` or a literal variable, in a recursive delete or
unquoted; a quoted one when a zone is in sight or the cwd is unknown or inside one).

FAIL CLOSED: for an evaluated command, whatever cannot be read (a syntax error, nesting deeper than MAX_DEPTH, a
timeout after TIMEOUT_SECONDS, an internal error) is a deny; so is an unreadable event whose text holds a delete word.
For a command that was never evaluated a crash is an allow, logged to `rmguard-error.log`. Not Bash, or no command:
allowed.

It is a tokenizer for the common shapes, not a shell parser. NOT covered: paths are compared as text, never resolved
through the file system (a symlink into a zone), `xargs` input the command does not show, a command word built from an
expansion whose own arguments name no zone, HOME changed by means the text scan does not see, and which agent is
running (the hook has no session identity).
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import json
import os
import posixpath
import re
import shlex
import signal
import stat
import sys
from collections.abc import Callable, Iterable, Sequence
from typing import Any, NamedTuple

from safo.leadwait import WRAPPERS, _ansi_c

# The shared scratch parent. Built, not written as a literal: this module only compares paths against it and never
# creates anything there, so the temp-file lint (S108) does not apply.
TMP = os.sep + "tmp"
MAX_DEPTH = 3
MAX_COMMAND_CHARS = 200_000
TIMEOUT_SECONDS = 3.0
LEAD_FOLDER = (".local", "share", "reach-around-lead")
MAX_LOGGED_CHARS = 500
# xargs and parallel run a command on input the line does not show, so they are handled apart, not skipped over.
WRAPS = {name: opts for name, opts in WRAPPERS.items() if name not in ("xargs", "parallel")}
WRAPS["builtin"] = frozenset()
POSITIONAL = frozenset({"flock", "taskset", "chrt"})  # one operand (lock file, CPU mask, priority) before the command
DELETERS = frozenset({"rm", "unlink", "shred", "rmdir"})
SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh"})
# `find -exec <tool>` is not a delete when the tool is one of these (after any wrapper such as env or nice).
READ_ONLY = frozenset(
    {"ls", "cat", "head", "tail", "wc", "grep", "egrep", "fgrep", "file", "stat", "du", "echo", "printf", "test", "["}
    | {"basename", "dirname", "md5sum", "sha1sum", "sha256sum", "readlink", "realpath", "true", "false", "diff", "cmp"}
)
_KEYWORDS = frozenset({"do", "then", "else", "elif", "if", "!", "{", "}", "while", "until"})
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_OPERATOR = re.compile(r"&>>?|<<<|<<-?|<>|<&|>&|>>|>\||<|>")
_NUMBERISH = re.compile(r"\d+(?:\.\d+)?[smhd]?")
_QUOTES = re.compile(r"[\\'\"]")
_DELETE_WORD = re.compile(r"(?<![A-Za-z0-9_])(?:rm|rmdir|unlink|shred)(?![A-Za-z0-9_])")
_FIND_WORD = re.compile(r"(?<![A-Za-z0-9_])find(?![A-Za-z0-9_])")
_DELETE_FLAG = re.compile(r"(?<![A-Za-z0-9_-])-delete(?![A-Za-z0-9_-])")
_EXEC_FLAG = re.compile(r"-(?:exec|execdir|ok|okdir)(?![A-Za-z])")
# Names that something other than a plain `NAME=value` can change: loop variables, read, `+=`, declare. Never tracked.
_TAINT_CLAUSE = re.compile(
    r"(?:^|[;&|\n({]|\bdo\b|\bthen\b)\s*(?:for|select|read|mapfile|readarray|getopts|local|declare|typeset|export|printf\s+-v|unset)\b[^;\n|&)]*"
)
_TAINT_APPEND = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\+=")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ZONE_WORDS = re.compile(r"-dev(?:/|\Z)|/tmp/claude")
# Text that makes a shared zone worth a look even when no delete word shows: a dev folder, the scratchpad parent, or a
# zone parent (`.local/share`, `.local`).
_ZONE_TEXT = re.compile(r"-dev(?![A-Za-z0-9_.])|/tmp/claude|\.local(?![A-Za-z0-9_.-])")
# Characters that can build a word the plain text does not show: `r?`, `r[m]`, `/bin/r*`, `r{m,}`, `$RM`, `$'..'`,
# a backtick substitution.
_SUSPECT = re.compile(r"[$`?*\[{]")
# Any mention of HOME that is not a plain `$HOME` or `${HOME}` read: an assignment, export, unset, read, `${HOME:=x}`...
_HOME_REDEFINED = re.compile(r"(?<![\w$])(?<!\$\{)HOME(?!\w)|\$\{HOME[^}]")
# Commands that can set a variable in ways the text scan does not follow: HOME is then unknown too (A3).
_HOME_COMMANDS = re.compile(
    r"(?<![\w-])(?:eval|declare|typeset|read|source|mapfile|readarray)(?![\w-])|printf\s+-v|(?:^|[;&|\n(])\s*\.\s+\S"
)
# Text that defeats variable tracking altogether: eval, source, `. file`, a function definition.
_NO_BIND = re.compile(r"(?<![\w-])(?:eval|source|function)(?![\w-])|(?:^|[;&|\n(])\s*\.\s+\S|[\w-]+\s*\(\)\s*\{?")


class Word(NamedTuple):
    text: str
    glob: int | None  # index of the first unquoted glob character, else None
    expands: bool  # holds a `$` expansion or substitution whose value is unknown
    quoted: bool
    redir: bool = False  # a redirection operator (its operand is the next word)


class Cmd(NamedTuple):
    words: list[Word]
    prev: str  # the separator that ended the command before this one ("" at the start)
    nxt: str  # the separator that ends this command ("" at the end)
    paren: str = ""  # "(" or ")" for a subshell boundary marker (words is empty then)


class Unparseable(Exception):
    """The command cannot be read with confidence."""


class UnknownCommand(Unparseable):
    """The command word is built from an expansion or a glob and an argument points into a shared zone: it may be a
    delete word in disguise."""


class Finding(NamedTuple):
    reason: str  # fixed wording per kind
    target: str  # the offending path as written (shortened), "" when none
    hint: str = ""  # "agent-root" when the target is an agents/<name> folder root


class Timeout(Exception):
    """The check ran past TIMEOUT_SECONDS."""


def plain_delete_word(text: str) -> bool:
    """A delete word as written (quotes and backslashes removed)."""
    text = text.replace("\\\n", "")
    # quotes removed (`r''m`) and quotes read as spaces (`-S'rm -rf x'`): either spelling can put the word in view
    for flat in (_QUOTES.sub("", text), _QUOTES.sub(" ", text)):
        if (
            _DELETE_WORD.search(flat)
            or _DELETE_FLAG.search(flat)
            or (_FIND_WORD.search(flat) and _EXEC_FLAG.search(flat))
        ):
            return True
    return False


def has_delete_word(text: str, cwd: str | None = None, home: str | None = None) -> bool:
    """Should this command be evaluated? True when the working directory is inside a shared zone (every command there
    is judged: `git clean`, a redirection and `mv` hold no delete word), when the text holds a delete word as written,
    when it holds a character that can build one (`$`, a backtick, `?`, `*`, `[`, `{`: `r?`, `r[m]`, `/bin/r*`, `$RM`,
    `r$'m'`), or when it mentions a shared zone. Backslash-newline pairs are removed first (`r\\<newline>m` is `rm`).
    Only a command that does none of these is allowed without being parsed."""
    if cwd and home and cwd.startswith("/") and Zones(home).roots(norm(cwd)) is not None:
        return True
    text = text.replace("\\\n", "")
    return plain_delete_word(text) or bool(_SUSPECT.search(text)) or bool(_ZONE_TEXT.search(text))


def norm(path: str) -> str:
    """normpath, with a leading run of slashes collapsed (`//x` and `/x` are the same file on Linux)."""
    out = posixpath.normpath(path)
    return "/" + out.lstrip("/") if out.startswith("/") else out


class Scanner:
    """Splits one command string into simple commands; substitutions and heredoc bodies that run code are collected in
    `nested` to be checked on their own. `home` is None when HOME may have been changed: `~` and `$HOME` are unknown."""

    def __init__(self, text: str, home: str | None) -> None:
        self.s = text
        self.home = home
        self.vars: dict[str, str] = {}  # NAME=literal assignments seen so far, so `$NAME` can be read
        self.staged: dict[str, str | None] = {}  # this command's assignments; kept only if it has no command word
        self.tainted: set[str] = {"HOME"}
        for clause in _TAINT_CLAUSE.finditer(text):
            self.tainted.update(_NAME.findall(clause.group()))
        self.tainted.update(_TAINT_APPEND.findall(text))
        self.no_bind = bool(_NO_BIND.search(text))  # eval, source or a function: nothing is bound
        self.depth = 0  # open parentheses: an assignment inside a subshell does not reach the caller
        self.i = 0
        self.nested: list[str] = []
        self.commands: list[Cmd] = []
        self.cur: list[Word] = []
        self.last = ""  # the separator that ended the previous command
        self.pending: list[tuple[str, bool, bool]] = []  # (delimiter, strip tabs, quoted)

    def home_text(self, st: dict[str, Any]) -> str:
        if self.home is None:
            st["expands"] = True
            return "\0"
        return self.home

    def end_word(self, buf: list[str], st: dict[str, Any]) -> None:
        if buf or st["quoted"]:
            word = Word("".join(buf), st["glob"], st["expands"], st["quoted"])
            m = _ASSIGN.match(word.text)
            if m and all(_ASSIGN.match(w.text) for w in self.cur):  # an assignment word at command position
                name = word.text[: m.end() - 1]
                clean = not word.expands and word.glob is None and not re.search(r"[\s*?\[{]", word.text[m.end() :])
                self.staged[name] = word.text[m.end() :] if clean and name not in self.tainted else None
            self.cur.append(word)
        buf.clear()
        st.update(glob=None, expands=False, quoted=False)

    def separator(self, sep: str) -> None:
        """A command boundary. A newline or `;` with nothing before it changes nothing."""
        if self.cur and all(_ASSIGN.match(w.text) for w in self.cur):  # assignments only: they bind for what follows
            # Bound only when it surely ran in this shell: not after `&&`, `||`, `|` or `&`, not before `|` or `&`
            # (a pipeline stage or a background job is a subshell), not inside parentheses, not near eval or a function.
            sure = (
                not self.no_bind
                and self.depth == 0
                and self.last in ("", ";", "\n", ")")
                and sep not in ("|", "|&", "&")
            )
            for name, value in self.staged.items():
                if value is None or not sure:
                    self.vars.pop(name, None)
                    self.tainted.add(name)
                else:
                    self.vars[name] = value
        if self.cur:
            self.staged = {}
        if self.cur:
            self.commands.append(Cmd(self.cur, self.last, sep))
            self.cur = []
            self.last = sep
        elif sep not in (";", "\n", ""):
            self.last = sep

    def matching(self, i: int, open_c: str, close_c: str) -> int:
        """Index of the close character matching an opener just before i, honoring quotes; Unparseable if none."""
        depth = 1
        s = self.s
        bodies: list[tuple[str, bool]] = []  # heredocs opened on this line: their bodies start after the newline
        while i < len(s):
            c = s[i]
            if c == "\\":
                i += 2
                continue
            if c == "\n" and bodies:
                i = self.skip_bodies(i + 1, bodies)
                bodies = []
                continue
            if c == "<" and s.startswith("<<", i) and not s.startswith("<<<", i):
                delim, strip, _, end = self.read_delimiter(i + 2)
                bodies.append((delim, strip))
                i = end
                continue
            if c in "'\"":
                j = s.find(c, i + 1) if c == "'" else self.dq_end(i + 1)
                if j < 0:
                    raise Unparseable
                i = j + 1
                continue
            if c == open_c:
                depth += 1
            elif c == close_c:
                depth -= 1
                if depth == 0:
                    return i
            i += 1
        raise Unparseable

    def dq_end(self, i: int) -> int:
        s = self.s
        while i < len(s):
            if s[i] == "\\":
                i += 2
                continue
            if s[i] == '"':
                return i
            if s.startswith("$(", i):
                i = self.matching(i + 2, "(", ")") + 1
                continue
            i += 1
        return -1

    def dollar(self, buf: list[str], st: dict[str, Any], in_dq: bool = False) -> None:
        """At a `$` (index self.i): ANSI-C or locale quoting, variable, `${...}`, `$(...)` or anything else."""
        s = self.s
        i = self.i
        if not in_dq and s.startswith("$'", i):
            text, j = _ansi_c(s, i + 2)
            if j < i + 3 or s[j - 1] != "'":
                raise Unparseable
            if "\0" in text:
                st["expands"] = True
            buf.append(text)
            st["quoted"] = True
            self.i = j
        elif not in_dq and s.startswith('$"', i):
            self.i = i + 1
            self.double(buf, st)
        elif s.startswith("$((", i):  # arithmetic: no commands, but a substitution inside it runs
            end = self.matching(i + 2, "(", ")")
            self.arithmetic_substitutions(i + 3, end)
            st["expands"] = True
            buf.append("\0")
            self.i = end + 1
        elif s.startswith("$(", i):
            end = self.matching(i + 2, "(", ")")
            self.nested.append(s[i + 2 : end])
            st["expands"] = True
            buf.append("\0")
            self.i = end + 1
        elif s.startswith("${", i):
            end = self.matching(i + 2, "{", "}")
            name = s[i + 2 : end]
            if name == "HOME":
                buf.append(self.home_text(st))
            else:
                self.variable(name, buf, st)
            self.i = end + 1
        else:
            m = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])").match(s, i)
            if m:
                if m.group(1) == "HOME":
                    buf.append(self.home_text(st))
                else:
                    self.variable(m.group(1), buf, st)
                self.i = m.end()
            else:
                nxt = s[i + 1 : i + 2]
                if nxt == "" or nxt in " \t\n;|&)<>\"'":
                    buf.append("$")  # a lone dollar sign is just that
                else:
                    st["expands"] = True  # an expansion form this scanner does not model: fail closed
                    buf.append("\0")
                self.i = i + 1

    def arithmetic_substitutions(self, j: int, end: int) -> None:
        """Queue every `$(...)`, backtick and `<(...)` inside an arithmetic body: they are commands."""
        s = self.s
        while j < end:
            if (s.startswith("$(", j) and not s.startswith("$((", j)) or s.startswith("<(", j) or s.startswith(">(", j):
                close = self.matching(j + 2, "(", ")")
                self.nested.append(s[j + 2 : close])
                j = close + 1
            elif s[j] == "`":
                close = s.find("`", j + 1)
                if close < 0:
                    raise Unparseable
                self.nested.append(s[j + 1 : close])
                j = close + 1
            else:
                j += 1

    def variable(self, name: str, buf: list[str], st: dict[str, Any]) -> None:
        """`$name`: its value when it was assigned a plain literal earlier in this command line, else unknown."""
        value = self.vars.get(name)
        if value is None or name in self.tainted:
            st["expands"] = True
            buf.append("\0")
        else:
            buf.append(value)

    def heredoc_bodies(self) -> None:
        """At the newline after a heredoc operator: read each pending body to its delimiter."""
        s = self.s
        for delim, strip, quoted in self.pending:
            start = self.i
            while True:
                if start > len(s):
                    raise Unparseable
                nl = s.find("\n", start)
                line = s[start : nl if nl >= 0 else len(s)]
                if (line.lstrip("\t") if strip else line) == delim:
                    body = s[self.i : start]
                    if not quoted and ("$(" in body or "`" in body):
                        self.nested.append(body)
                    self.i = nl + 1 if nl >= 0 else len(s)
                    break
                if nl < 0:
                    raise Unparseable
                start = nl + 1
        self.pending = []

    def skip_bodies(self, i: int, bodies: list[tuple[str, bool]]) -> int:
        """Index just past the closing delimiter lines of the heredocs opened on the line that ended at i."""
        s = self.s
        for delim, strip in bodies:
            while True:
                if i > len(s):
                    raise Unparseable
                nl = s.find("\n", i)
                line = s[i : nl if nl >= 0 else len(s)]
                i = nl + 1 if nl >= 0 else len(s) + 1
                if (line.lstrip("\t") if strip else line) == delim:
                    break
                if nl < 0:
                    raise Unparseable
        return min(i, len(s))

    def heredoc_start(self, op_end: int, strip: bool) -> None:
        """After `<<` or `<<-` (ending at op_end): note the delimiter word."""
        delim, strip2, quoted, _ = self.read_delimiter(op_end)
        self.pending.append((delim, strip or strip2, quoted))

    def read_delimiter(self, op_end: int) -> tuple[str, bool, bool, int]:
        """The heredoc delimiter word after `<<` (index op_end): (word, `<<-`, any part quoted, index past it)."""
        s = self.s
        j = op_end
        strip = j < len(s) and s[j] == "-"
        if strip:
            j += 1
        while j < len(s) and s[j] in " \t":
            j += 1
        out: list[str] = []
        quoted = False
        while j < len(s) and s[j] not in " \t\n;|&<>()":
            c = s[j]
            if c in "'\"":
                k = s.find(c, j + 1)
                if k < 0:
                    raise Unparseable
                out.append(s[j + 1 : k])
                quoted = True
                j = k + 1
                continue
            if c == "\\" and j + 1 < len(s):
                quoted = True
                j += 1
                c = s[j]
            out.append(c)
            j += 1
        if not out:
            raise Unparseable
        return "".join(out), strip, quoted, j

    def operator(self, buf: list[str], st: dict[str, Any]) -> None:
        """At an unquoted `<`, `>` or `&>`: a word boundary. A file-descriptor number glued in front is part of it."""
        s = self.s
        if buf and not st["quoted"] and "".join(buf).isdigit():
            buf.clear()
        self.end_word(buf, st)
        m = _OPERATOR.match(s, self.i)
        if not m:
            raise Unparseable
        op = m.group()
        end = m.end()
        if op in ("<", ">") and s.startswith("(", end):  # process substitution: code, and a word of its own
            close = self.matching(end + 1, "(", ")")
            self.nested.append(s[end + 1 : close])
            self.cur.append(Word("\0", None, True, False))
            self.i = close + 1
            return
        if op in ("<<", "<<-"):
            self.heredoc_start(end, op == "<<-")
        self.cur.append(Word(op, None, False, False, True))
        self.i = end

    def run(self) -> list[Cmd]:
        s = self.s
        buf: list[str] = []
        st: dict[str, Any] = {"glob": None, "expands": False, "quoted": False}
        while self.i < len(s):
            c = s[self.i]
            if c in " \t\r":
                self.end_word(buf, st)
                self.i += 1
            elif c == "\n":
                self.end_word(buf, st)
                self.separator("\n")
                self.i += 1
                if self.pending:
                    self.heredoc_bodies()
            elif c == "\\":
                if s.startswith("\\\n", self.i):
                    self.i += 2
                    continue
                if self.i + 1 >= len(s):
                    raise Unparseable
                buf.append(s[self.i + 1])
                st["quoted"] = True
                self.i += 2
            elif c == "'":
                end = s.find("'", self.i + 1)
                if end < 0:
                    raise Unparseable
                buf.append(s[self.i + 1 : end])
                st["quoted"] = True
                self.i = end + 1
            elif c == '"':
                self.double(buf, st)
            elif c == "`":
                end = s.find("`", self.i + 1)
                if end < 0:
                    raise Unparseable
                self.nested.append(s[self.i + 1 : end])
                st["expands"] = True
                buf.append("\0")
                self.i = end + 1
            elif c == "$":
                self.dollar(buf, st)
            elif c == "#" and not buf and not st["quoted"]:
                end = s.find("\n", self.i)
                self.i = len(s) if end < 0 else end
            elif c in "<>" or (c == "&" and s.startswith("&>", self.i)):
                self.operator(buf, st)
            elif c in "()":
                self.end_word(buf, st)
                self.depth += 1 if c == "(" else -1
                self.separator(c)  # closes any command before it
                self.commands.append(Cmd([], self.last, c, c))
                self.last = c
                self.i += 1
            elif c in ";|&":
                self.end_word(buf, st)
                two = s[self.i : self.i + 2]
                sep = two if two in ("&&", "||", "|&", ";;") else c
                self.separator(";" if sep == ";;" else sep)
                self.i += len(sep)
            else:
                if c == "~" and not st["quoted"] and self.tilde_position(buf):
                    j = self.i + 1
                    if j >= len(s) or s[j] in "/ \t\n;|&)<>":
                        buf.append(self.home_text(st))
                        self.i += 1
                        continue
                    st["expands"] = True  # ~user
                if st["glob"] is None and (c in "*?[" or (c == "{" and self.brace_list())):
                    st["glob"] = len("".join(buf))
                buf.append(c)
                self.i += 1
        if self.pending:
            raise Unparseable
        self.end_word(buf, st)
        self.separator("")
        return self.commands

    @staticmethod
    def tilde_position(buf: list[str]) -> bool:
        """A `~` expands at the start of a word and after the `=` (or a `:`) of an assignment word."""
        if not buf:
            return True
        before = "".join(buf)
        return before.endswith(("=", ":")) and bool(_ASSIGN.match(before))

    def brace_list(self) -> bool:
        end = self.s.find("}", self.i)
        if end < 0:
            return False
        inner = self.s[self.i + 1 : end]
        return "," in inner or ".." in inner

    def double(self, buf: list[str], st: dict[str, Any]) -> None:
        s = self.s
        self.i += 1
        st["quoted"] = True
        while True:
            if self.i >= len(s):
                raise Unparseable
            c = s[self.i]
            if c == '"':
                self.i += 1
                return
            if c == "\\" and self.i + 1 < len(s):
                nxt = s[self.i + 1]
                if nxt != "\n":
                    buf.append(nxt if nxt in '"\\$`' else "\\" + nxt)
                self.i += 2
            elif c == "$":
                self.dollar(buf, st, in_dq=True)
            elif c == "`":
                end = s.find("`", self.i + 1)
                if end < 0:
                    raise Unparseable
                self.nested.append(s[self.i + 1 : end])
                st["expands"] = True
                buf.append("\0")
                self.i = end + 1
            else:
                buf.append(c)
                self.i += 1


# -- zones ----------------------------------------------------------------------------------------------------------


class Zones:
    def __init__(self, home: str) -> None:
        self.home = norm(home)
        self.share = posixpath.join(self.home, ".local", "share")
        self.parents = {"/", TMP, self.home, posixpath.join(self.home, ".local"), self.share}

    def roots(self, path: str) -> str | None:
        """The shared root that `path` is at or below, else None."""
        if posixpath.dirname(path) == self.share and fnmatch.fnmatchcase(posixpath.basename(path), "*-dev"):
            return path
        if path.startswith(self.share + "/"):
            top = path[len(self.share) + 1 :].split("/", 1)[0]
            if fnmatch.fnmatchcase(top, "*-dev"):
                return posixpath.join(self.share, top)
        if path.startswith(TMP + "/"):
            top = path[len(TMP) + 1 :].split("/", 1)[0]
            if fnmatch.fnmatchcase(top, "claude-*"):
                return TMP + "/" + top
        return None

    def is_parent(self, path: str) -> bool:
        return path in self.parents or path == "/"

    def agent_exact(self, path: str, root: str) -> bool:
        parts = path[len(root) :].strip("/").split("/") if path != root else []
        if posixpath.dirname(root) == TMP:  # a harness scratchpad parent, not a dev folder of a home that is under /tmp
            return len(parts) >= 4 and parts[2] == "scratchpad"
        # Strictly below agents/<name>/: the <name> folder itself (the root) is removed by the owner, in a batch.
        return len(parts) >= 3 and parts[0] == "agents" and parts[1] not in ("", ".", "..")

    def is_agent_root(self, path: str, root: str) -> bool:
        parts = path[len(root) :].strip("/").split("/") if path != root else []
        return posixpath.dirname(root) != TMP and len(parts) == 2 and parts[0] == "agents" and parts[1] != ""

    def judge(self, path: str, glob: bool) -> str:
        """'ok' (exact, under a per-agent folder), 'shared' (blocked), 'outside' (not our business)."""
        path = norm(path)
        root = self.roots(path)
        if root is not None:
            return "ok" if (not glob and self.agent_exact(path, root)) else "shared"
        if self.is_parent(path):
            return "shared"
        return "outside"


def resolve(word: Word, cwd: str | None) -> tuple[str, bool] | None:
    """(absolute path of the literal part, whether a glob follows), or None when it cannot be resolved."""
    text = word.text
    glob = word.glob is not None
    if glob:
        text = text[: word.glob]
        text = text[: text.rfind("/") + 1] if "/" in text else ""
    if "\0" in text:
        return None
    if text.startswith("/"):
        return norm(text), glob
    if cwd is None:
        return None
    return norm(posixpath.join(cwd, text or ".")), glob


# -- the check ------------------------------------------------------------------------------------------------------


class Prefix(NamedTuple):
    at: int  # where the command word is
    chdir: tuple[str | None] | None  # a directory change by `env -C` or `sudo -D`: (resolved directory or None)
    split: str | None  # `env -S` text, to be scanned as a command line


class Checker:
    def __init__(self, home: str, cwd: str | None, scan_home: str | None) -> None:
        self.home = home
        self.scan_home = scan_home
        self.zones = Zones(home)
        self.cwd = norm(cwd) if cwd and cwd.startswith("/") else None
        self.mentions_zone = False
        self.moved = False  # the command being checked changed the shell's directory

    def blind(self) -> bool:
        """Is there a reason to doubt an expansion we cannot read: a zone in the command, or no safe directory?"""
        return self.mentions_zone or self.cwd is None or self.zones.roots(self.cwd) is not None

    def judge_word(self, word: Word, recursive: bool) -> Finding | None:
        shown = word.text.replace("\0", "?").replace(self.home, "~")[:120]
        resolved = resolve(word, self.cwd)
        if resolved is None:
            if recursive or not word.quoted or word.glob is not None or self.blind():
                return Finding(
                    "a target that cannot be resolved (an expansion, or a relative path after an unfollowed cd)",
                    shown,
                )
            return None
        path, glob = resolved
        if self.zones.judge(path, glob) != "shared":
            return None
        return self.shared_finding(word, path, shown)

    def shared_finding(self, word: Word, path: str, shown: str) -> Finding:
        if word.glob is not None:
            return Finding("a glob inside a shared dev directory", shown)
        root = self.zones.roots(path)
        if self.zones.is_parent(path) or path == root:
            return Finding("removal of a shared dev directory or one of its parents", shown)
        if root is not None and self.zones.is_agent_root(path, root):
            return Finding("removal of an agent folder root", shown, "agent-root")
        return Finding("a path in a shared dev directory outside a per-agent folder", shown)

    def judge_soft(self, word: Word) -> Finding | None:
        """For programs other than the deleters (a redirection, mv, truncate...): a target that cannot be resolved only
        counts when a zone is in sight or the working directory is inside one."""
        shown = word.text.replace("\0", "?").replace(self.home, "~")[:120]
        resolved = resolve(word, self.cwd)
        if resolved is None:
            inside = self.cwd is not None and self.zones.roots(self.cwd) is not None
            if self.mentions_zone or inside:
                return Finding("a target that cannot be resolved (an expansion, or a relative path)", shown)
            return None
        path, glob = resolved
        if self.zones.judge(path, glob) != "shared":
            return None
        return self.shared_finding(word, path, shown)

    @staticmethod
    def drop_redirects(words: list[Word]) -> list[Word]:
        out: list[Word] = []
        skip = False
        for w in words:
            if skip:
                skip = False
            elif w.redir:
                skip = True
            else:
                out.append(w)
        return out

    def prefix(self, words: list[Word]) -> Prefix:
        """Skip leading assignments, keywords and transparent wrappers; find the command word."""
        i = 0
        chdir: tuple[str | None] | None = None
        while i < len(words):
            w = words[i]
            if not w.quoted and (_ASSIGN.match(w.text) or w.text in _KEYWORDS):
                i += 1
            elif posixpath.basename(w.text) in WRAPS and not w.expands:
                name = posixpath.basename(w.text)
                i += 1
                takes = WRAPS[name]
                while i < len(words):
                    nxt = words[i]
                    t = nxt.text
                    flag = "-C" if name == "env" else "-D"
                    if (nxt.expands or nxt.glob is not None) and not (
                        _ASSIGN.match(t) or t in takes or t.startswith("-")
                    ):
                        break  # the command word itself is built from an expansion: simple() decides what that means
                    if name == "env" and self.is_split(t):
                        return Prefix(i, chdir, self.split_text(words, i))
                    if name in ("env", "sudo") and (t in (flag, "--chdir") or t.startswith("--chdir=")):
                        if t.startswith("--chdir="):
                            chdir = self.chdir_of(Word(t.split("=", 1)[1], None, False, False))
                            i += 1
                        else:
                            if i + 1 >= len(words):
                                raise Unparseable
                            chdir = self.chdir_of(words[i + 1])
                            i += 2
                    elif name == "env" and t.startswith("-C") and not t.startswith("--") and len(t) > 2:
                        chdir = self.chdir_of(Word(t[2:], None, False, False))
                        i += 1
                    elif t in takes:
                        i += 2
                    elif (
                        t.startswith("-")
                        or _ASSIGN.match(t)
                        or (_NUMBERISH.fullmatch(t) and name in ("timeout", "nice"))
                    ):
                        i += 1
                    else:
                        break
                if name in POSITIONAL and i < len(words):
                    i += 1
            else:
                break
        return Prefix(i, chdir, None)

    @staticmethod
    def is_split(t: str) -> bool:
        return t in ("-S", "--split-string") or t.startswith("--split-string=") or (t.startswith("-S") and len(t) > 2)

    @staticmethod
    def split_text(words: list[Word], i: int) -> str:
        """The command line `env -S` builds: its string, then the remaining words (quoted unless they hold a glob)."""
        t = words[i].text
        if t in ("-S", "--split-string"):
            if i + 1 >= len(words) or words[i + 1].expands:
                raise Unparseable
            value, rest = words[i + 1].text, words[i + 2 :]
        elif t.startswith("--split-string="):
            value, rest = t.split("=", 1)[1], words[i + 1 :]
        else:
            value, rest = t[2:], words[i + 1 :]
        parts = [value]
        for r in rest:
            parts.append(r.text if r.glob is not None else shlex.quote(r.text))
        return " ".join(parts)

    def chdir_of(self, word: Word) -> tuple[str | None]:
        if word.expands or word.glob is not None:
            return (None,)
        res = resolve(word, self.cwd)
        return (res[0] if res else None,)

    def existing_shared(self, word: Word) -> Finding | None:
        """For a redirection or `tee`: a target in a shared zone that already exists (a glob counts, it may match one).
        Creating a new file truncates nothing, and a target that cannot be resolved is not judged."""
        resolved = resolve(word, self.cwd)
        if resolved is None:
            return None
        path, glob = resolved
        if self.zones.judge(path, glob) != "shared" or (not glob and not os.path.lexists(path)):
            return None
        shown = word.text.replace("\0", "?").replace(self.home, "~")[:120]
        return self.shared_finding(word, path, shown)

    def redirections(self, words: list[Word]) -> Finding | None:
        """A `>`, `>|` or `&>` truncates an existing target (`: > file`, `echo x > file`); `>>` appends and is not
        judged, and a file that does not exist yet is only created."""
        for n, w in enumerate(words):
            if not w.redir or n + 1 >= len(words):
                continue
            target = words[n + 1]
            if w.text in (">", ">|", "&>") or (w.text == ">&" and not target.text.isdigit() and target.text != "-"):
                found = self.existing_shared(target)
                if found:
                    return Finding("a redirection that truncates " + found.reason, found.target, found.hint)
        return None

    def command(self, words: list[Word], depth: int) -> Finding | None:
        found = self.redirections(words)
        if found:
            return found
        words = self.drop_redirects(words)
        pre = self.prefix(words)
        if pre.split is not None:
            split = pre.split
            return self.in_cwd(pre.chdir, lambda: self.nested_text(split, depth))
        if pre.at >= len(words):
            return None
        rest = words[pre.at :]
        return self.in_cwd(pre.chdir, lambda: self.simple(rest, depth))

    def in_cwd(self, chdir: tuple[str | None] | None, fn: Callable[[], Finding | None]) -> Finding | None:
        """Run fn with the working directory a wrapper such as `env -C` sets for the command it runs."""
        if chdir is None:
            return fn()
        saved = self.cwd
        self.cwd = chdir[0]
        try:
            return fn()
        finally:
            self.cwd = saved

    def args_touch_zone(self, args: list[Word]) -> bool:
        """Does any argument name a shared zone, or a path in the working directory when that is inside one?"""
        for a in args:
            if a.text.startswith("-") and not a.quoted:
                continue
            resolved = resolve(a, self.cwd)
            if resolved is None:
                if _ZONE_WORDS.search(a.text) and "/scratchpad/" not in a.text and "/agents/" not in a.text:
                    return True
            elif self.zones.judge(*resolved) == "shared":
                return True
        return False

    def simple(self, words: list[Word], depth: int) -> Finding | None:
        head = words[0]
        if head.expands or (head.glob is not None and head.text not in ("[", "[[")):
            # A command built from an expansion cannot be shown not to delete. It is refused when one of ITS OWN
            # arguments points into (or cannot be told from) a shared zone; a zone named elsewhere in the line does
            # not make every unknown command word suspect.
            if self.args_touch_zone(self.drop_redirects(words[1:])):
                raise UnknownCommand
            return None
        name = posixpath.basename(head.text)
        args = words[1:]
        if name in ("cd", "pushd"):
            self.follow_cd(args)
            return None
        if name == "popd":
            self.cwd = None
            self.moved = True
            return None
        if name in SHELLS:
            return self.shell_c(args, depth)
        if name == "eval":
            return self.nested_text(" ".join(a.text for a in args), depth)
        if name in ("xargs", "parallel"):
            return self.xargs(args, depth)
        if name == "find":
            return self.find(args)
        if name in DELETERS:
            return self.delete(args, extra_dynamic=False)
        handler = {
            "git": self.git,
            "truncate": self.truncate,
            "rsync": self.rsync,
            "tar": self.tar,
            "mv": self.mv,
            "cp": self.cp,
            "dd": self.dd,
            "tee": self.tee,
        }.get(name)
        return handler(args) if handler else None

    @staticmethod
    def operands(args: list[Word], takes: frozenset[str]) -> tuple[list[Word], list[Word]]:
        """(operands, values of the options in `takes`): words that are not options, and what those options consumed."""
        out: list[Word] = []
        values: list[Word] = []
        after_dd = False
        skip = False
        for a in args:
            if skip:
                values.append(a)
                skip = False
            elif not after_dd and not a.quoted and a.text == "--":
                after_dd = True
            elif not after_dd and a.text.startswith("-") and len(a.text) > 1:
                if a.text in takes:
                    skip = True
                elif a.text.startswith("--") and "=" in a.text and a.text.split("=", 1)[0] in takes:
                    values.append(Word(a.text.split("=", 1)[1], None, a.expands, a.quoted))
            else:
                out.append(a)
        return out, values

    def judge_all(self, words: list[Word]) -> Finding | None:
        for w in words:
            found = self.judge_soft(w)
            if found:
                return found
        return None

    def git(self, args: list[Word]) -> Finding | None:
        """`git clean` removes untracked files from the working tree it runs in (or the pathspecs it is given)."""
        base = self.cwd
        i = 0
        while i < len(args):
            t = args[i].text
            if t == "-C" and i + 1 < len(args):
                base = self.chdir_of(args[i + 1])[0]
                i += 2
            elif t in ("-c", "--exec-path", "--namespace", "--super-prefix", "--config-env") and i + 1 < len(args):
                i += 2
            elif t.startswith(("--work-tree=", "--git-dir=")):
                if t.startswith("--work-tree="):
                    base = self.chdir_of(Word(t.split("=", 1)[1], None, False, False))[0]
                i += 1
            elif t in ("--work-tree", "--git-dir") and i + 1 < len(args):
                if t == "--work-tree":
                    base = self.chdir_of(args[i + 1])[0]
                i += 2
            elif t.startswith("-"):
                i += 1
            else:
                break
        if i >= len(args) or args[i].text != "clean":
            return None
        rest = args[i + 1 :]
        for a in rest:
            if a.text == "--dry-run" or (a.text.startswith("-") and not a.text.startswith("--") and "n" in a.text):
                return None  # a dry run removes nothing
        pathspecs, _ = self.operands(rest, frozenset({"-e", "--exclude"}))
        saved = self.cwd
        self.cwd = base
        try:
            if pathspecs:
                return self.judge_all(pathspecs)
            if base is None:
                return (
                    Finding("`git clean` in a working directory that could not be followed", "")
                    if self.mentions_zone
                    else None
                )
            found = self.judge_soft(Word(".", None, False, False))
            return Finding("`git clean` in " + found.reason, found.target, found.hint) if found else None
        finally:
            self.cwd = saved

    def truncate(self, args: list[Word]) -> Finding | None:
        targets, _ = self.operands(args, frozenset({"-s", "--size", "-r", "--reference"}))
        return self.judge_all(targets)

    def rsync(self, args: list[Word]) -> Finding | None:
        if not any(
            a.text.startswith(("--delete", "--del", "--remove-source-files", "--remove-sent-files")) for a in args
        ):
            return None
        takes = frozenset({"-e", "--rsh", "--exclude", "--include", "-f", "--filter", "--files-from", "--rsync-path"})
        targets, _ = self.operands(args, takes | {"--log-file", "--temp-dir", "-T", "--exclude-from", "--include-from"})
        return self.judge_all(targets)

    def tar(self, args: list[Word]) -> Finding | None:
        if not any(a.text == "--remove-files" for a in args):
            return None
        saved = self.cwd
        pending = ""  # what the previous word asked for: "" nothing, "file" an archive or list, "dir" a -C directory
        first = True
        try:
            for a in args:
                t = a.text
                if pending:
                    if pending == "dir":
                        self.cwd = self.chdir_of(a)[0]
                    pending = ""
                elif first and not t.startswith("-"):  # an old-style option cluster (`cf x.tar`)
                    pending = "dir" if "C" in t else ("file" if "f" in t else "")
                elif t in ("-C", "--directory"):
                    pending = "dir"
                elif t.startswith("--directory="):
                    self.cwd = self.chdir_of(Word(t.split("=", 1)[1], None, False, False))[0]
                elif t in ("-f", "--file", "-T", "--files-from", "-X", "--exclude-from"):
                    pending = "file"
                elif t.startswith("--"):
                    pass
                elif t.startswith("-"):
                    pending = "file" if "f" in t[1:] else ("dir" if "C" in t[1:] else "")
                else:
                    found = self.judge_soft(a)
                    if found:
                        return found
                first = False
            return None
        finally:
            self.cwd = saved

    @staticmethod
    def target_directories(args: list[Word]) -> list[Word]:
        """The directory given to `-t` / `--target-directory` of mv and cp."""
        out: list[Word] = []
        for n, a in enumerate(args):
            if a.text in ("-t", "--target-directory") and n + 1 < len(args):
                out.append(args[n + 1])
            elif a.text.startswith("--target-directory="):
                out.append(Word(a.text.split("=", 1)[1], None, a.expands, a.quoted))
            elif a.text.startswith("-t") and len(a.text) > 2 and not a.text.startswith("--"):
                out.append(Word(a.text[2:], None, a.expands, a.quoted))
        return out

    def mv(self, args: list[Word]) -> Finding | None:
        operands, _ = self.operands(args, frozenset({"-t", "--target-directory", "-S", "--suffix"}))
        return self.judge_all(operands + self.target_directories(args))

    def cp(self, args: list[Word]) -> Finding | None:
        operands, _ = self.operands(args, frozenset({"-t", "--target-directory", "-S", "--suffix"}))
        if not any(o.text in ("/dev/null", "/dev/zero") for o in operands):
            return None
        rest = [o for o in operands if o.text not in ("/dev/null", "/dev/zero")]
        return self.judge_all(rest + self.target_directories(args))

    def dd(self, args: list[Word]) -> Finding | None:
        for a in args:
            if a.text.startswith("of="):
                glob = a.glob - 3 if a.glob is not None and a.glob >= 3 else None
                found = self.judge_soft(Word(a.text[3:], glob, a.expands, a.quoted))
                if found:
                    return found
        return None

    def tee(self, args: list[Word]) -> Finding | None:
        if any(
            a.text in ("-a", "--append") or (a.text.startswith("-") and not a.text.startswith("--") and "a" in a.text)
            for a in args
        ):
            return None
        targets, _ = self.operands(args, frozenset())
        for t in targets:
            found = self.existing_shared(t)
            if found:
                return found
        return None

    def follow_cd(self, args: list[Word]) -> None:
        self.moved = True
        targets = [a for a in args if not a.text.startswith("-") or a.quoted]
        if len(targets) != 1 or targets[0].expands or targets[0].glob is not None or targets[0].text == "-":
            self.cwd = None
            return
        res = resolve(targets[0], self.cwd)
        self.cwd = res[0] if res else None

    def shell_c(self, args: list[Word], depth: int) -> Finding | None:
        for n, a in enumerate(args):
            if re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", a.text) and n + 1 < len(args):
                body = args[n + 1]
                if body.expands and not body.text.replace("\0", "").strip():
                    # the whole body is an expansion: nothing to read, so only a zone in sight or in the cwd matters
                    if self.mentions_zone or (self.cwd is not None and self.zones.roots(self.cwd) is not None):
                        raise UnknownCommand
                    return None
                return self.nested_text(body.text, depth)  # a body with unknown pieces is read with them unresolved
        return None

    def nested_text(self, text: str, depth: int, *, unknown_cwd: bool = False) -> Finding | None:
        """Scan text a command runs in its own shell: a directory change inside it never reaches the caller."""
        if depth >= MAX_DEPTH:
            raise Unparseable
        saved, moved = self.cwd, self.moved
        if unknown_cwd:
            self.cwd = None
        try:
            return self.scan(text, depth + 1)
        finally:
            self.cwd, self.moved = saved, moved

    def delete(self, args: list[Word], extra_dynamic: bool) -> Finding | None:
        targets: list[Word] = []
        recursive = False
        after_dd = False
        for a in args:
            if not after_dd and not a.quoted and a.text == "--":
                after_dd = True
            elif not after_dd and a.text.startswith("-") and len(a.text) > 1:
                if a.text.startswith("--"):
                    recursive |= a.text == "--recursive"
                else:
                    recursive |= any(ch in a.text for ch in "rRd")
            else:
                targets.append(a)
        for t in targets:
            found = self.judge_word(t, recursive)
            if found:
                return found
        if extra_dynamic:
            if self.cwd is None:
                return Finding("input from xargs with a working directory that could not be followed", "")
            if self.zones.judge(self.cwd, False) == "shared" or self.mentions_zone:
                return Finding("input from xargs in or near a shared dev directory", "")
        return None

    def xargs(self, args: list[Word], depth: int) -> Finding | None:
        for n, a in enumerate(args):
            if posixpath.basename(a.text) in DELETERS and not a.text.startswith("-"):
                return self.delete(args[n + 1 :], extra_dynamic=True)
            if posixpath.basename(a.text) in SHELLS | {"find", "eval"} | set(WRAPS):
                if depth >= MAX_DEPTH:
                    raise Unparseable
                return self.command(args[n:], depth + 1)
        return None

    def exec_deletes(self, words: list[Word]) -> bool:
        """Does the command of a `find -exec` delete, or might it? Wrappers are skipped; unknown tools count."""
        words = self.drop_redirects(words)
        pre = self.prefix(words)
        if pre.split is not None or pre.at >= len(words):
            return True
        head = words[pre.at]
        if head.expands or head.glob is not None:
            return True
        return posixpath.basename(head.text) not in READ_ONLY

    def find(self, args: list[Word]) -> Finding | None:
        n = 0
        while n < len(args) and not args[n].quoted:  # GNU global options come before the start paths
            t = args[n].text
            if t in ("-H", "-L", "-P") or (t.startswith("-O") and t[2:].isdigit()):
                n += 1
            elif t == "-D":
                if n + 1 >= len(args):
                    raise Unparseable
                n += 2
            elif t.startswith("-D") and len(t) > 2:
                n += 1
            else:
                break
        starts: list[Word] = []
        while n < len(args) and not (args[n].text.startswith(("-", "(", "!")) and not args[n].quoted):
            starts.append(args[n])
            n += 1
        deleting = False
        m = n
        while m < len(args):
            t = args[m].text
            if t == "-delete":
                deleting = True
            elif t in ("-exec", "-execdir", "-ok", "-okdir"):
                end = m + 1
                while end < len(args) and args[end].text not in (";", "+"):
                    end += 1
                if self.exec_deletes(args[m + 1 : end]):
                    deleting = True
                m = end
            m += 1
        if not deleting:
            return None
        if any(a.text.startswith("-files0-from") for a in args):
            raise Unparseable  # the start paths come from a file this hook cannot read
        if not starts:
            starts = [Word(".", None, False, False)]
        for s in starts:
            found = self.judge_word(s, True)
            if found:
                return Finding(
                    "`find` that deletes in or from a shared dev directory (" + found.reason + ")",
                    found.target,
                    found.hint,
                )
        return None

    def scan(self, text: str, depth: int = 0) -> Finding | None:
        if len(text) > MAX_COMMAND_CHARS:
            raise Unparseable
        sc = Scanner(text, self.scan_home)
        commands = sc.run()
        for cmd in commands:
            for w in cmd.words:
                resolved = resolve(w, self.cwd)
                if resolved is None:
                    self.mentions_zone |= (
                        bool(_ZONE_WORDS.search(w.text)) and "/scratchpad/" not in w.text and "/agents/" not in w.text
                    )
                elif self.zones.judge(*resolved) == "shared":
                    self.mentions_zone = True
        moved_any = False
        stack: list[str | None] = []
        for cmd in commands:
            if cmd.paren == "(":
                stack.append(self.cwd)
                continue
            if cmd.paren == ")":
                if stack:
                    self.cwd = stack.pop()
                continue
            self.moved = False
            found = self.command(cmd.words, depth)
            if found:
                return found
            if self.moved:
                moved_any = True
                stage = cmd.prev in ("|", "|&") or cmd.nxt in ("|", "|&", "&")
                if stage or cmd.nxt == "||" or cmd.prev == "||":
                    self.cwd = None  # it may or may not have happened in the shell that goes on: unknown
        for inner in sc.nested:
            if depth >= MAX_DEPTH:
                raise Unparseable
            found = self.nested_text(inner, depth, unknown_cwd=moved_any)
            if found:
                return found
        return None


def home_unknown(command: str) -> bool:
    """Could HOME have been changed by this command? Looked for in the text with quotes and backslashes removed (so
    `H""OME=x` counts) and, since nested bodies are part of that text, in every nested body too."""
    flat = _QUOTES.sub("", command.replace("\\\n", ""))
    return bool(_HOME_REDEFINED.search(flat) or _HOME_COMMANDS.search(flat))


def check(command: str, home: str, cwd: str | None) -> Finding | None:
    """The finding that makes `command` a deny, or None to allow. A command that holds no delete word, no character
    that can build one, no zone and whose cwd is outside every zone is allowed at once, unparsed. Anything else is
    evaluated, and what cannot be read (a syntax error, nesting, a timeout, an internal error) is a deny."""
    if not has_delete_word(command, cwd, home):
        return None
    checker = Checker(home, cwd, None if home_unknown(command) else home)
    try:
        return checker.scan(command)
    except UnknownCommand:
        return Finding("a command word built from an expansion or a pattern, aimed at a shared dev directory", "")
    except (Unparseable, RecursionError):
        return Finding("a command too tangled to check (unterminated quote, nesting or a built command word)", "")


# -- the hook -------------------------------------------------------------------------------------------------------


def message(found: Finding) -> str:
    target = f" (target: {found.target})" if found.target else ""
    if found.hint == "agent-root":
        return (
            f"safo rmguard: blocked, {found.reason}{target}. Agent folder roots are removed by the owner in a batch, "
            "not by an agent: leave it. Inside your per-agent folder you may delete exact files and subfolders below "
            "the root, but not the root itself. To hand the folder over, print its exact name for the owner with: "
            f"ls -d -- {shlex.quote(found.target)}"
        )
    return (
        f"safo rmguard: blocked, {found.reason}{target}. Shared dev directories (~/.local/share/*-dev and the "
        "scratchpad parent /tmp/claude-*) hold other sessions' work, so nothing there is deleted, truncated or moved "
        "by pattern, by parent or by a path outside an agent folder. Instead: work in a per-agent folder (for example "
        "~/.local/share/<project>-dev/agents/<issue>-<role>/) and delete only the EXACT path of a file or subfolder "
        "strictly below its root, with no wildcard and no parent. The folder root itself is removed by the owner in a "
        "batch; to clear a pattern, list the files first and remove each by exact name."
    )


def _assignment_repl(match: re.Match[str]) -> str:
    return match.group().split("=", 1)[0] + "=<redacted>"


# Applied in order. The assignment rule redacts everything after `=` in NAME=value words (and `--password=value`).
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str | Callable[[re.Match[str]], str]], ...] = (
    (re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{6,}"), r"\1 <redacted>"),
    (re.compile(r"://[^/\s:@]+:[^/\s@]+@"), "://<redacted>@"),
    (re.compile(r"\b(?:gh[pousr]_|github_pat_|sk-|xox[a-z]-|AKIA|AIza|glpat-)[A-Za-z0-9_-]{8,}"), "<redacted>"),
    (re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*=\S*"), _assignment_repl),
    (re.compile(r"(?i)(--?(?:password|passwd|secret|token|key|api-key) )\S+"), r"\1<redacted>"),
    (re.compile(r"\b[A-Za-z0-9+_-]{32,}={0,2}(?![A-Za-z0-9+_-])"), "<redacted>"),
)


def redact(command: str, home: str) -> str:
    """The command as a log may hold it: no secret-looking text, home paths shortened, one line, bounded."""
    text = command.replace(home, "~") if home else command
    for pattern, repl in _SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", " ")
    return text[:MAX_LOGGED_CHARS] + ("...<cut>" if len(text) > MAX_LOGGED_CHARS else "")


def _append_log(home: str, name: str, line: str) -> None:
    """Open the lead-only folder component by component through directory descriptors (no symlink is followed, every
    component must belong to this user), repair the folder to 0700, and append to a regular file this user owns."""
    uid = os.getuid()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)  # the home itself may sit behind a mount link
    try:
        for n, part in enumerate(LEAD_FOLDER):
            try:
                nxt = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part, 0o700, dir_fd=fd)
                nxt = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
            info = os.fstat(fd)
            if info.st_uid != uid:
                raise PermissionError(part)
            if n == len(LEAD_FOLDER) - 1 and stat.S_IMODE(info.st_mode) != 0o700:
                os.fchmod(fd, 0o700)
        log = os.open(name, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        try:
            info = os.fstat(log)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1:
                raise PermissionError(name)
            os.fchmod(log, 0o600)
            os.write(log, (line + "\n").encode("utf-8", "replace"))
        finally:
            os.close(log)
    finally:
        os.close(fd)


def append_log(home: str, name: str, line: str) -> None:
    """Append one line to a log in the lead-only folder. Never raises: a log must not block anything."""
    try:
        _append_log(home, name, line)
    except OSError:
        return


def log_line(mode: str, reason: str, command: str, home: str, now: dt.datetime) -> str:
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{stamp}\t{mode}\t{reason}\t{redact(command, home)}"


def parse_mode(argv: Sequence[str]) -> str:
    """`--mode warn|enforce` or `--mode=...`; anything else, or nothing, is enforce."""
    mode = "enforce"
    words = list(argv)
    for n, word in enumerate(words):
        if word == "--mode" and n + 1 < len(words):
            mode = words[n + 1]
        elif word.startswith("--mode="):
            mode = word.split("=", 1)[1]
    return mode if mode == "warn" else "enforce"


def deny_json(reason: str) -> str:
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    )


def _on_alarm(_signum: int, _frame: object) -> None:
    raise Timeout


def run_check(command: str, home: str, cwd: str | None) -> Finding | None:
    """check() under a wall-clock limit (a signal timer; where none can be set, no limit)."""
    try:
        old = signal.signal(signal.SIGALRM, _on_alarm)
    except (ValueError, AttributeError):  # not the main thread, or no SIGALRM
        return check(command, home, cwd)
    signal.setitimer(signal.ITIMER_REAL, TIMEOUT_SECONDS)
    try:
        return check(command, home, cwd)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


class Outcome(NamedTuple):
    reason: str  # "" to allow
    command: str  # the text to show in a log
    note: str  # a failure that was allowed (no delete word), for the error log


def gate(text: str, cwd: str | None = None, home: str | None = None) -> tuple[bool, bool, str]:
    """(evaluate it, it holds a delete word, note). If the gate itself crashes, a plain substring decides both and the
    note says so."""
    try:
        return has_delete_word(text, cwd, home), plain_delete_word(text), ""
    except Exception:
        held = any(word in text for word in ("rm", "unlink", "shred", "-delete", "-exec", "-ok"))
        return held, held, "internal error in the delete-word gate"


def evaluate(raw: str, home: str, default_cwd: str | None) -> Outcome:
    """Decide for one raw event."""
    try:
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError
    except ValueError:
        _, held, note = gate(raw)
        if held:
            return Outcome("safo rmguard: blocked, the hook event could not be read. Retry the command.", raw, "")
        return Outcome("", raw, note or "unreadable event allowed (no delete word)")
    if event.get("tool_name") != "Bash":
        return Outcome("", "", "")
    tool_input = event.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return Outcome("", "", "")
    cwd = event.get("cwd") if isinstance(event.get("cwd"), str) else default_cwd
    look, _, note = gate(command, cwd, home)
    if not look:
        return Outcome("", command, note)
    try:
        found = run_check(command, home, cwd)
    except Exception:  # fail closed: an evaluated command that crashes or times out is blocked
        reason = "safo rmguard: blocked, an internal error while checking the command (fail closed). Retry it."
        return Outcome(reason, command, "")
    return Outcome(message(found) if found else "", command, "")


def main(
    argv: Sequence[str] | None = None,
    stdin: Iterable[str] | None = None,
    home: str | None = None,
    now: dt.datetime | None = None,
) -> int:
    """Read one event, print a deny when the rule bites (enforce) or log one line (warn). Never raises."""
    mode = parse_mode(sys.argv[1:] if argv is None else argv)
    home = home or os.path.expanduser("~")
    when = now or dt.datetime.now(dt.UTC)
    try:
        raw = "".join(stdin) if stdin is not None else sys.stdin.read()
    except (OSError, UnicodeError):
        raw = ""
    try:
        outcome = evaluate(raw, home, os.getcwd())
    except Exception:  # a bug outside the checked region: the command was never shown to hold a delete word
        outcome = Outcome("", "", "internal error while reading the event; allowed")
    if outcome.note:
        append_log(home, "rmguard-error.log", log_line(mode, outcome.note, outcome.command, home, when))
    if not outcome.reason:
        return 0
    if mode == "warn":
        short = outcome.reason.removeprefix("safo rmguard: blocked, ").split(". Shared dev", 1)[0]
        append_log(home, "rmguard-warn.log", log_line(mode, short, outcome.command, home, when))
        return 0
    print(deny_json(outcome.reason))
    return 0


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
