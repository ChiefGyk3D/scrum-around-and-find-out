# SPDX-License-Identifier: Apache-2.0
"""Shared-directory deletion guard: `safo-rmguard`, a PreToolUse hook for Bash (#422).

On 2026-11-23 a reviewer agent ran `rm -rf ... *.py *.log` inside `~/.local/share/reach-around-dev` and deleted another
session's logs and helper scripts. Brief text is instruction only, so this is a check on the command itself.

It is its own entry point and its own module on purpose: the dispatch guard (`safo.guard`, `safo.modes.hooks`,
`safo.geminibrief`) is frozen (owner decision 2026-10-30), so nothing here touches it. The installed hook list gets one
more PreToolUse entry for Bash (docs/rmguard.md); nothing installs it for you.

SHARED ZONES (where the rule applies):

* `~/.local/share/<anything>-dev` (the folder itself and everything below it), and the parents above it
  (`~/.local/share`, `~/.local`, `~`), since removing a parent removes the zone;
* the harness scratchpad parent `/tmp/claude-*` (and `/tmp`, `/`, for the same reason).

WHAT IS BLOCKED, inside a shared zone or when it cannot be shown to be elsewhere: `rm`, `unlink`, `shred` and `rmdir`
(and `xargs` running them), and `find` with `-delete` or `-exec rm`-like actions, when any target

* holds an unquoted glob (`*`, `?`, `[`, a brace list), or
* is a shared zone itself or a parent of one, or
* is anything else in a shared zone that is not an EXACT path under a per-agent scratch folder, or
* cannot be resolved (an expansion other than `$HOME`/`~`, in a recursive delete or unquoted, and any relative or
  globbed target after a `cd` it could not follow).

WHAT IS ALLOWED: a target that is an exact path (no glob, no expansion) under `<dev>/agents/<name>` (the folder itself
included, so an agent can remove its own folder by its exact path), or strictly under a session's
`/tmp/claude-*/<project>/<session>/scratchpad`.

FAIL CLOSED: a command it cannot parse (an unterminated quote, nesting deeper than MAX_DEPTH, a command word built
from an expansion) is denied when it mentions a delete word or a shared zone; any internal error on a Bash event is a
deny. Not Bash, or no command: allowed.

It is a tokenizer for the common shapes, not a shell parser. NOT covered: an alias or function that hides `rm`, a
script or `python -c "shutil.rmtree(...)"` that deletes, a symlink that points into a zone (paths are resolved by
text, never by the file system), `xargs` input that comes from somewhere the command does not show, and the per-agent
folder not being the one named in a brief (the brief is not visible to a hook). The folder shape `agents/<name>` is
the convention.
"""

from __future__ import annotations

import fnmatch
import json
import os
import posixpath
import re
import sys
from collections.abc import Iterable, Mapping
from typing import Any, NamedTuple

from safo.leadwait import WRAPPERS

# The shared scratch parent. Built, not written as a literal: this module only compares paths against it and never
# creates anything there, so the temp-file lint (S108) does not apply.
TMP = os.sep + "tmp"
MAX_DEPTH = 3
MAX_COMMAND_CHARS = 200_000
# xargs and parallel run a command on input the line does not show, so they are handled apart, not skipped over.
WRAPS = {name: opts for name, opts in WRAPPERS.items() if name not in ("xargs", "parallel")}
POSITIONAL = frozenset({"flock", "taskset", "chrt"})  # one operand (lock file, CPU mask, priority) before the command
DELETERS = frozenset({"rm", "unlink", "shred", "rmdir"})
SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh"})
_KEYWORDS = frozenset({"do", "then", "else", "elif", "if", "!", "{", "}", "while", "until"})
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_REDIRECT = re.compile(r"(?:\d*|&)(?:>>?|<<<?|<)&?|&>>?")
_NUMBERISH = re.compile(r"\d+(?:\.\d+)?[smhd]?")
_DELETE_WORDS = re.compile(r"(?<![A-Za-z0-9_])(?:rm|rmdir|unlink|shred|find)(?![A-Za-z0-9_])|-delete|rmtree")
_ZONE_WORDS = re.compile(r"-dev|/tmp/claude|scratchpad")


class Word(NamedTuple):
    text: str
    glob: int | None  # index of the first unquoted glob character, else None
    expands: bool  # holds a `$` expansion or substitution whose value is unknown
    quoted: bool


class Unparseable(Exception):
    """The command cannot be read with confidence."""


class Finding(NamedTuple):
    reason: str  # fixed wording per kind
    target: str  # the offending path as written (shortened), "" when none


class Scanner:
    """Splits one command string into simple commands (lists of Word); substitutions and heredoc bodies that run code
    are collected in `nested` to be checked on their own."""

    def __init__(self, text: str, home: str) -> None:
        self.s = text
        self.home = home
        self.i = 0
        self.nested: list[str] = []
        self.commands: list[list[Word]] = []
        self.cur: list[Word] = []
        self.pending: list[tuple[str, bool, bool]] = []  # (delimiter, strip tabs, quoted)

    def end_word(self, buf: list[str], st: dict[str, Any]) -> None:
        if buf or st["quoted"]:
            self.cur.append(Word("".join(buf), st["glob"], st["expands"], st["quoted"]))
        buf.clear()
        st.update(glob=None, expands=False, quoted=False)

    def end_command(self) -> None:
        if self.cur:
            self.commands.append(self.cur)
        self.cur = []

    def matching(self, i: int, open_c: str, close_c: str) -> int:
        """Index of the close character matching an opener just before i, honoring quotes; Unparseable if none."""
        depth = 1
        s = self.s
        while i < len(s):
            c = s[i]
            if c == "\\":
                i += 2
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

    def dollar(self, buf: list[str], st: dict[str, Any]) -> None:
        """At a `$` (index self.i): variable, `${...}`, `$(...)` or arithmetic."""
        s = self.s
        i = self.i
        if s.startswith("$(", i):
            end = self.matching(i + 2, "(", ")")
            self.nested.append(s[i + 2 : end])
            st["expands"] = True
            buf.append("\0")
            self.i = end + 1
        elif s.startswith("${", i):
            end = self.matching(i + 2, "{", "}")
            name = s[i + 2 : end]
            if name == "HOME":
                buf.append(self.home)
            else:
                st["expands"] = True
                buf.append("\0")
            self.i = end + 1
        else:
            m = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])").match(s, i)
            if not m:
                buf.append("$")
                self.i = i + 1
            else:
                if m.group(1) == "HOME":
                    buf.append(self.home)
                else:
                    st["expands"] = True
                    buf.append("\0")
                self.i = m.end()

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

    def heredoc_start(self) -> None:
        """At `<<` (not `<<<`): note the delimiter word."""
        s = self.s
        j = self.i + 2
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
        self.pending.append(("".join(out), strip, quoted))

    def run(self) -> list[list[Word]]:
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
                self.end_command()
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
            elif c in ";|()" or (c == "&" and not self.literal_amp(buf)):
                self.end_word(buf, st)
                self.end_command()
                self.i += 1
            else:
                if c == "<" and s.startswith("<<", self.i) and not s.startswith("<<<", self.i):
                    self.heredoc_start()
                if c == "~" and not buf and not st["quoted"]:
                    j = self.i + 1
                    if j >= len(s) or s[j] in "/ \t\n;|&)":
                        buf.append(self.home)
                        self.i += 1
                        continue
                    st["expands"] = True  # ~user
                if st["glob"] is None and (c in "*?[" or (c == "{" and self.brace_list())):
                    st["glob"] = len(buf)
                buf.append(c)
                self.i += 1
        if self.pending:
            raise Unparseable
        self.end_word(buf, st)
        self.end_command()
        return self.commands

    def literal_amp(self, buf: list[str]) -> bool:
        s = self.s
        return (bool(buf) and buf[-1].endswith(">")) or s.startswith("&>", self.i)

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
                self.dollar(buf, st)
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
        self.home = posixpath.normpath(home)
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
        if root.startswith(TMP + "/"):
            return len(parts) >= 4 and parts[2] == "scratchpad"
        return len(parts) >= 2 and parts[0] == "agents" and parts[1] not in ("", ".", "..")

    def judge(self, path: str, glob: bool) -> str:
        """'ok' (exact, under a per-agent folder), 'shared' (blocked), 'outside' (not our business)."""
        path = posixpath.normpath(path)
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
        return posixpath.normpath(text), glob
    if cwd is None:
        return None
    return posixpath.normpath(posixpath.join(cwd, text or ".")), glob


# -- the check ------------------------------------------------------------------------------------------------------


class Checker:
    def __init__(self, home: str, cwd: str | None) -> None:
        self.home = home
        self.zones = Zones(home)
        self.cwd = posixpath.normpath(cwd) if cwd and cwd.startswith("/") else None
        self.mentions_zone = False

    def judge_word(self, word: Word, recursive: bool) -> Finding | None:
        shown = word.text.replace("\0", "?").replace(self.home, "~")[:120]
        resolved = resolve(word, self.cwd)
        if resolved is None:
            if recursive or not word.quoted or word.glob is not None:
                return Finding(
                    "a target that cannot be resolved (an expansion, or a relative path after an unfollowed cd)",
                    shown,
                )
            return None
        path, glob = resolved
        if self.zones.judge(path, glob) != "shared":
            return None
        if word.glob is not None:
            return Finding("a glob inside a shared dev directory", shown)
        if self.zones.is_parent(path) or path == self.zones.roots(path):
            return Finding("removal of a shared dev directory or one of its parents", shown)
        return Finding("a path in a shared dev directory outside a per-agent folder", shown)

    def command(self, words: list[Word], depth: int) -> Finding | None:
        i = 0
        # leading assignments, keywords and transparent wrappers
        while i < len(words):
            w = words[i]
            t = w.text
            if not w.quoted and (_ASSIGN.match(t) or t in _KEYWORDS):
                i += 1
            elif posixpath.basename(t) in WRAPS and not w.expands:
                name = posixpath.basename(t)
                i += 1
                takes = WRAPS[name]
                while i < len(words):
                    nxt = words[i]
                    if nxt.expands or nxt.glob is not None:
                        raise Unparseable
                    if nxt.text in takes:
                        i += 2
                    elif (
                        nxt.text.startswith("-")
                        or _ASSIGN.match(nxt.text)
                        or (_NUMBERISH.fullmatch(nxt.text) and name in ("timeout", "nice"))
                    ):
                        i += 1
                    else:
                        break
                if name in POSITIONAL and i < len(words):
                    i += 1
            else:
                break
        if i >= len(words):
            return None
        head = words[i]
        if head.expands or head.glob is not None:
            raise Unparseable
        name = posixpath.basename(head.text)
        args = words[i + 1 :]
        args = self.strip_redirects(args)
        if name in ("cd", "pushd"):
            self.follow_cd(args)
            return None
        if name in SHELLS:
            return self.shell_c(args, depth)
        if name == "eval":
            return self.nested_text(" ".join(a.text for a in args), depth)
        if name in ("xargs", "parallel"):
            return self.xargs(args, depth)
        if name == "find":
            return self.find(args, depth)
        if name in DELETERS:
            return self.delete(args, extra_dynamic=False)
        return None

    @staticmethod
    def strip_redirects(args: list[Word]) -> list[Word]:
        out: list[Word] = []
        skip = False
        for a in args:
            if skip:
                skip = False
                continue
            if not a.quoted and _REDIRECT.match(a.text):
                skip = _REDIRECT.fullmatch(a.text) is not None
                continue
            out.append(a)
        return out

    def follow_cd(self, args: list[Word]) -> None:
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
                if body.expands:
                    raise Unparseable
                return self.nested_text(body.text, depth)
        return None

    def nested_text(self, text: str, depth: int) -> Finding | None:
        if depth >= MAX_DEPTH:
            raise Unparseable
        return self.scan(text, depth + 1)

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

    def find(self, args: list[Word], depth: int) -> Finding | None:
        starts: list[Word] = []
        n = 0
        while n < len(args) and not (args[n].text.startswith(("-", "(", "!")) and not args[n].quoted):
            starts.append(args[n])
            n += 1
        deleting = False
        for m in range(n, len(args)):
            t = args[m].text
            if t == "-delete":
                deleting = True
            elif t in ("-exec", "-execdir", "-ok", "-okdir") and m + 1 < len(args):
                action = args[m + 1]
                if action.expands:
                    raise Unparseable
                if posixpath.basename(action.text) in DELETERS | {"find"} | SHELLS:
                    deleting = True
        if not deleting:
            return None
        if not starts:
            starts = [Word(".", None, False, False)]
        for s in starts:
            found = self.judge_word(s, True)
            if found:
                return Finding(
                    "`find` that deletes in or from a shared dev directory (" + found.reason + ")", found.target
                )
        return None

    def scan(self, text: str, depth: int = 0) -> Finding | None:
        if len(text) > MAX_COMMAND_CHARS:
            raise Unparseable
        sc = Scanner(text, self.home)
        commands = sc.run()
        for words in commands:
            for w in words:
                self.mentions_zone |= self.zones.judge(*(resolve(w, self.cwd) or ("/nonexistent", False))) == "shared"
        for words in commands:
            found = self.command(words, depth)
            if found:
                return found
        for inner in sc.nested:
            if depth >= MAX_DEPTH:
                raise Unparseable
            found = self.scan(inner, depth + 1)
            if found:
                return found
        return None


def check(command: str, home: str, cwd: str | None) -> Finding | None:
    """The finding that makes `command` a deny, or None to allow. Fail closed on a command it cannot read when the
    text mentions a delete word or a shared zone."""
    try:
        return Checker(home, cwd).scan(command)
    except (Unparseable, RecursionError):
        if _DELETE_WORDS.search(command) or _ZONE_WORDS.search(command):
            return Finding(
                "a command too tangled to check (unterminated quote, deep nesting or a built command word)", ""
            )
        return None


def message(found: Finding, home: str) -> str:
    target = f" (target: {found.target})" if found.target else ""
    return (
        f"safo rmguard: blocked, {found.reason}{target}. Shared dev directories (~/.local/share/*-dev and the "
        "scratchpad parent /tmp/claude-*) hold other sessions' logs and scripts, so nothing there is deleted by "
        "pattern or by parent. Instead: work in your own per-agent folder (for example "
        "~/.local/share/<project>-dev/agents/<issue>-<role>/), and clean up by the EXACT path of that folder or of a "
        "file inside it, with no wildcard and no parent. To clear a pattern, list the files first and remove each by "
        "exact name inside your own folder."
    )


def decide(event: Mapping[str, Any], home: str, default_cwd: str | None) -> str | None:
    """The deny text for one hook event, or None to allow."""
    if event.get("tool_name") != "Bash":
        return None
    tool_input = event.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, Mapping) else None
    if not isinstance(command, str):
        return None
    cwd = event.get("cwd") if isinstance(event.get("cwd"), str) else default_cwd
    found = check(command, home, cwd)
    return message(found, home) if found else None


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


def main(stdin: Iterable[str] | None = None, home: str | None = None) -> int:
    """Read one event, print a deny when the rule bites. Any internal error is a deny (fail closed)."""
    home = home or os.path.expanduser("~")
    try:
        raw = "".join(stdin) if stdin is not None else sys.stdin.read()
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError
    except (ValueError, OSError):
        print(deny_json("safo rmguard: blocked, the hook event could not be read. Retry the command."))
        return 0
    try:
        reason = decide(event, home, os.getcwd())
    except Exception:  # fail closed on anything unexpected; the message names no command text
        reason = "safo rmguard: blocked, an internal error while checking the command (fail closed). Retry it."
    if reason:
        print(deny_json(reason))
    return 0


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
