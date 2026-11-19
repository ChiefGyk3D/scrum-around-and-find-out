# SPDX-License-Identifier: Apache-2.0
"""A positive proof that a Bash command only carries prose (#388).

This is not a shell model and it does not look for danger. It reads a command with a small, strict lexer and answers
two questions, and any form it does not model is a `Doubt`, which the caller treats as "not proven":

* `Parsed.without_comments()`: the command with real comments removed (a `#` that starts a word, outside every quote);
* `Parsed.pure()`: whether EVERY simple command is on a short allowlist of commands that only print, search, read or
  write text (echo, printf, cat, grep, rg, head, tail, wc, date, pwd, `git commit`, `gh issue|pr <verb>`), is spelled as
  a plain word, takes no assignment prefix, no wrapper, no expansion that could become a command, and is not redirected
  or piped into anything off that list. In such a command every argument, here-document body and redirect target is
  text: nothing in it is run.

The caller keeps the old denial and relaxes it only when this module proves the text harmless. A finite list of tools
is not a shell grammar, so nothing here tries to prove a command dangerous.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable

SAFE_COMMANDS = frozenset({"echo", "printf", "cat", "grep", "rg", "head", "tail", "wc", "date", "pwd"})
SUBST_COMMANDS = frozenset({"date", "pwd", "printf", "echo"})  # all a command substitution may run
GH_AREAS = frozenset({"issue", "pr"})
GH_VERBS = frozenset({"comment", "create", "edit", "close", "reopen", "review", "view", "list", "ready"})
DEV_OK = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin"})

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_BRACED = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")
_SPECIAL = "@*#?!$-0123456789"
_DELIM_END = " \t\n|&;()<>"
_DELIM_PLAIN = re.compile(r"[A-Za-z0-9_]+")
_DELIM_QUOTED = re.compile(r"'[A-Za-z0-9_.-]+'|\"[A-Za-z0-9_.-]+\"")


class Doubt(Exception):
    """The command uses a form this module does not model."""


@dataclasses.dataclass
class Word:
    value: str | None  # the text, or None when an expansion or an ANSI-C string is in it
    plain: bool  # made of plain characters only: no quote, escape or expansion
    starts_expanded: bool  # the first thing in the word is an expansion


@dataclasses.dataclass
class Cmd:
    words: list[Word] = dataclasses.field(default_factory=list)
    redirs: list[tuple[str, Word | None]] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Parsed:
    text: str
    cmds: list[Cmd]
    comments: list[tuple[int, int]]

    def without_comments(self) -> str:
        out: list[str] = []
        last = 0
        for start, end in self.comments:
            out.append(self.text[last:start])
            last = end
        out.append(self.text[last:])
        return "".join(out)

    def pure(self) -> bool:
        return all(_command_ok(cmd) for cmd in self.cmds)


def parse(command: str, tick: Callable[[], None]) -> Parsed | None:
    """The parse, or None when any part of the command is a form this lexer does not model."""
    if any((ord(c) < 32 and c not in "\t\n") or ord(c) == 127 for c in command) or "\\\n" in command:
        return None  # NUL and other control characters, and a line continuation (not honored inside a comment)
    try:
        return _Lexer(command, tick, nested=False).run()
    except Doubt:
        return None


class _Lexer:
    def __init__(self, text: str, tick: Callable[[], None], nested: bool) -> None:
        self.text = text
        self.tick = tick
        self.nested = nested
        self.cmds: list[Cmd] = []
        self.cmd = Cmd()
        self.comments: list[tuple[int, int]] = []
        self.buf: list[str] = []
        self.started = False
        self.plain = True
        self.valued = True
        self.starts_expanded = False
        self.pending_redir: str | None = None
        self.docs: list[tuple[str, bool, bool]] = []  # delimiter, tabs stripped, expansions apply
        self.i = 0

    # -- words ---------------------------------------------------------------------------------------------------
    def _char(self, c: str, plain: bool = True) -> None:
        self.buf.append(c)
        self.started = True
        self.plain = self.plain and plain

    def _expansion(self) -> None:
        if not self.buf:  # nothing but quotes before it
            self.starts_expanded = True
        self.started = True
        self.plain = False
        self.valued = False

    def _push_word(self) -> None:
        if not self.started:
            return
        word = Word("".join(self.buf) if self.valued else None, self.plain, self.starts_expanded)
        self.buf, self.started, self.plain, self.valued, self.starts_expanded = [], False, True, True, False
        if self.pending_redir is not None:
            self.cmd.redirs.append((self.pending_redir, word))
            self.pending_redir = None
        else:
            self.cmd.words.append(word)

    def _end_cmd(self) -> None:
        self._push_word()
        if self.pending_redir is not None:
            raise Doubt
        if self.cmd.words or self.cmd.redirs:
            self.cmds.append(self.cmd)
        self.cmd = Cmd()
        self.tick()

    # -- quoting and expansion -----------------------------------------------------------------------------------
    def _single(self) -> None:
        end = self.text.find("'", self.i + 1)
        if end < 0:
            raise Doubt
        for c in self.text[self.i + 1 : end]:
            self._char(c, plain=False)
        self.started, self.plain = True, False
        self.i = end + 1

    def _ansi(self) -> None:
        """`$'...'`: the text is data; its escapes are not evaluated (the value stays unknown)."""
        j = self.i + 2
        while j < len(self.text):
            c = self.text[j]
            if c == "\\":
                j += 2
            elif c == "'":
                self._expansion()
                self.i = j + 1
                return
            else:
                j += 1
        raise Doubt

    def _dollar(self, inside_quotes: bool) -> None:
        """`$` at self.i: a command substitution of harmless commands, `${NAME}`, `$NAME` or a special parameter."""
        nxt = self.text[self.i + 1 : self.i + 2]
        if nxt == "(":
            if self.nested or self.text[self.i + 2 : self.i + 3] == "(":
                raise Doubt  # a substitution inside one, or arithmetic
            end = self._subst_end()
            _check_substitution(self.text[self.i + 2 : end], self.tick)
            self._expansion()
            self.i = end + 1
        elif nxt == "{":
            m = _BRACED.match(self.text, self.i + 1)
            if not m:
                raise Doubt
            self._expansion()
            self.i = m.end()
        elif nxt == "'" and not inside_quotes:
            self._ansi()
        elif nxt == '"' and not inside_quotes:
            self.i += 1
            self._double()
        else:
            m = _NAME.match(self.text, self.i + 1)
            if m:
                self._expansion()
                self.i = m.end()
            elif nxt and nxt in _SPECIAL:
                self._expansion()
                self.i += 2
            else:
                self._char("$", plain=False)
                self.i += 1

    def _subst_end(self) -> int:
        """The index of the `)` that closes the `$(` at self.i; any form inside that this module does not model is a
        doubt (a nested substitution, a backtick, a subshell, a here-document, a comment)."""
        text, j = self.text, self.i + 2
        while j < len(text):
            c = text[j]
            if c == "'":
                k = text.find("'", j + 1)
                if k < 0:
                    raise Doubt
                j = k + 1
            elif c == '"':
                j += 1
                while j < len(text) and text[j] != '"':
                    if text[j] == "\\":
                        j += 1
                    j += 1
                if j >= len(text):
                    raise Doubt
                j += 1
            elif c == "\\":
                j += 2
            elif c in "`(#" or text.startswith("<<", j) or text.startswith("$(", j):
                raise Doubt
            elif c == ")":
                return j
            else:
                j += 1
        raise Doubt

    def _double(self) -> None:
        """A double-quoted string starting at self.i (the quote)."""
        text = self.text
        self.i += 1
        self.started, self.plain = True, False
        while self.i < len(text):
            c = text[self.i]
            if c == '"':
                self.i += 1
                return
            if c == "\\":
                if self.i + 1 >= len(text):
                    raise Doubt
                nxt = text[self.i + 1]
                if nxt not in '$`"\\':
                    self._char("\\", plain=False)
                self._char(nxt, plain=False)
                self.i += 2
            elif c == "`":
                raise Doubt
            elif c == "$":
                self._dollar(inside_quotes=True)
            else:
                self._char(c, plain=False)
                self.i += 1
        raise Doubt

    # -- here-documents ------------------------------------------------------------------------------------------
    def _heredoc_start(self, strip: bool) -> None:
        text = self.text
        while self.i < len(text) and text[self.i] in " \t":
            self.i += 1
        end = self.i
        while end < len(text) and text[end] not in _DELIM_END:
            end += 1
        raw = text[self.i : end]
        if _DELIM_PLAIN.fullmatch(raw):
            self.docs.append((raw, strip, True))
        elif _DELIM_QUOTED.fullmatch(raw):
            self.docs.append((raw[1:-1], strip, False))
        else:
            raise Doubt
        self.cmd.redirs.append(("<<", None))
        self.i = end

    def _read_bodies(self) -> None:
        """At a newline: the bodies of the pending here-documents follow, each up to a line equal to its delimiter."""
        text = self.text
        pos = self.i + 1
        for delim, strip, expands in self.docs:
            start = pos
            while True:
                if pos > len(text):
                    raise Doubt  # no terminator: bash would run to the end of the input
                end = text.find("\n", pos)
                stop = len(text) if end < 0 else end
                line = text[pos:stop]
                if (line.lstrip("\t") if strip else line) == delim:
                    body = text[start:pos]
                    pos = stop + 1
                    break
                if end < 0:
                    raise Doubt
                pos = end + 1
                self.tick()
            if expands:
                self._body_expansions(body)
        self.docs = []
        self.i = pos

    def _body_expansions(self, body: str) -> None:
        """An unquoted here-document body expands like a double-quoted string: only harmless forms may be in it."""
        probe = _Lexer(body, self.tick, self.nested)
        j = 0
        while j < len(body):
            c = body[j]
            if c == "\\":
                j += 2
            elif c == "`":
                raise Doubt
            elif c == "$":
                probe.text, probe.i = body, j
                probe._dollar(inside_quotes=True)
                j = probe.i
            else:
                j += 1

    # -- the main loop -------------------------------------------------------------------------------------------
    def _operator(self, c: str) -> None:
        text, i = self.text, self.i
        two = text[i : i + 2]
        if c in "<>":
            if self.started and self.plain and "".join(self.buf).isdigit():
                self.buf, self.started = [], False  # a file descriptor number in front of the operator
            else:
                self._push_word()
            if self.pending_redir is not None:
                raise Doubt
            if text.startswith("<<<", i):
                self.pending_redir, self.i = "<<<", i + 3
            elif two == "<<":
                if self.nested:
                    raise Doubt
                strip = text.startswith("<<-", i)
                self.i = i + (3 if strip else 2)
                self._heredoc_start(strip)
            elif two in ("<(", ">(", "<>", ">|"):
                raise Doubt
            elif two in ("<&", ">&"):
                m = re.compile(r"\d+").match(text, i + 2)
                if not m:
                    raise Doubt
                self.cmd.redirs.append(("dup", None))
                self.i = m.end()
            elif two == ">>":
                self.pending_redir, self.i = ">>", i + 2
            else:
                self.pending_redir, self.i = c, i + 1
        elif c == "|":
            if two == "|&":
                raise Doubt
            self._end_cmd()
            self.i = i + (2 if two == "||" else 1)
        elif c == "&":
            if two == "&&":
                self._end_cmd()
                self.i = i + 2
            elif two == "&>":
                self._push_word()
                if self.pending_redir is not None:
                    raise Doubt
                self.pending_redir = ">"
                self.i = i + (3 if text.startswith("&>>", i) else 2)
            else:
                raise Doubt  # background
        elif c == ";":
            if two in (";;", ";&"):
                raise Doubt
            self._end_cmd()
            self.i = i + 1
        else:  # ( or ): a subshell or a function
            raise Doubt

    def run(self) -> Parsed:
        text = self.text
        while self.i < len(text):
            c = text[self.i]
            if c in " \t":
                self._push_word()
                self.i += 1
            elif c == "\n":
                self._end_cmd()
                if self.docs:
                    self._read_bodies()
                else:
                    self.i += 1
            elif c == "#" and not self.started:
                if self.pending_redir is not None:
                    raise Doubt
                end = text.find("\n", self.i)
                end = len(text) if end < 0 else end
                self.comments.append((self.i, end))
                self.i = end
            elif c == "'":
                self._single()
            elif c == '"':
                self._double()
            elif c == "$":
                self._dollar(inside_quotes=False)
            elif c == "`":
                raise Doubt
            elif c == "\\":
                if self.i + 1 >= len(text):
                    raise Doubt
                self._char(text[self.i + 1], plain=False)
                self.i += 2
            elif c in "|&;()<>":
                self._operator(c)
            else:
                self._char(c)
                self.i += 1
        if self.docs:
            raise Doubt
        self._end_cmd()
        return Parsed(text, self.cmds, self.comments)


def _check_substitution(inner: str, tick: Callable[[], None]) -> None:
    """The inside of `$( )` may run only date, pwd, printf and echo, with no redirect and no `printf -v`."""
    parsed = _Lexer(inner, tick, nested=True).run()
    for cmd in parsed.cmds:
        first = cmd.words[0] if cmd.words else None
        if cmd.redirs or first is None or not first.plain or first.value not in SUBST_COMMANDS:
            raise Doubt
        if first.value is None or not _args_ok(first.value, cmd.words[1:]):
            raise Doubt


def _args_ok(name: str, args: list[Word]) -> bool:
    if name == "printf":
        # `printf -v` builds a variable; an unknown first argument could be that option
        return bool(args) and args[0].value is not None and not args[0].value.startswith("-v")
    if name == "rg":
        for word in args:
            if word.value is None:
                if word.starts_expanded:
                    return False  # could expand to an option that runs a program
                continue
            option = word.value.split("=", 1)[0]
            if option.startswith("--") and (
                option.startswith(("--pre", "--host")) or ("--pre".startswith(option) and len(option) >= 3)
            ):
                return False
            if option.startswith("--") and "--hostname-bin".startswith(option) and len(option) >= 4:
                return False
    return True


def _command_ok(cmd: Cmd) -> bool:
    if not cmd.words:
        return False  # a redirect with no command
    first = cmd.words[0]
    if not first.plain or first.value is None:
        return False  # a quoted, escaped or expanded command word is never on the list
    name, args = first.value, cmd.words[1:]
    if name in SAFE_COMMANDS:
        if not _args_ok(name, args):
            return False
    elif name == "git":
        i = 0
        if args and args[0].plain and args[0].value == "-C":
            i = 2
        if len(args) <= i or not args[i].plain or args[i].value != "commit":
            return False
    elif name == "gh":
        if len(args) < 2 or not (args[0].plain and args[1].plain):
            return False
        if args[0].value not in GH_AREAS or args[1].value not in GH_VERBS:
            return False
    else:
        return False
    for op, target in cmd.redirs:
        if op in (">", ">>", "<"):
            if target is None or not target.plain or target.value is None:
                return False  # the path of a redirect must be spelled out
            if "/dev/" in target.value and target.value not in DEV_OK:
                return False  # a device path can be a network connection
        elif op == "<<<":
            if target is None:
                return False
    return True
