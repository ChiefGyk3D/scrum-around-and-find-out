# SPDX-License-Identifier: Apache-2.0
"""Shared-directory guard: `safo-rmguard`, a PreToolUse hook for Bash (#422).

On 2026-11-23 a reviewer agent ran `rm -rf ... *.py *.log` inside `~/.local/share/reach-around-dev` and deleted another
session's logs and helper scripts. Brief text is instruction only, so this is a check on the command itself.

It is its own entry point and its own module on purpose: the dispatch guard (`safo.guard`, `safo.modes.hooks`,
`safo.geminibrief`) is frozen (owner decision 2026-10-30), so nothing here touches it. The installed hook list gets one
more PreToolUse entry for Bash (docs/rmguard.md); nothing installs it for you.

PROGRAM FAMILIES JUDGED (and only these; docs/rmguard.md has the table): `rm`, `rmdir`, `unlink`, `shred`; `find` with
`-delete` or an `-exec` of anything not read-only (after the GNU global options); `git` (a short list of read-mostly
subcommands passes, every other subcommand is judged by its work tree); `truncate`; `rsync` and `tar` with delete or
remove options or an unknown long option (abbreviations included); `mv`; `cp` onto /dev/null sources or an existing
file; `dd of=`; `tee`; `sed -i`, `perl -i`, `awk -i inplace`, `ed`, `install`, `ln -f` on existing files; an inline
`python -c`, `perl -e`, `ruby -e`, `node -e`, `php -r`; and truncating redirections. Not covered: any other program, a
script, a container bind mount, an alias or a function, a symlink into a zone.

WHAT IS EVALUATED: when the working directory is inside a shared zone, every command. Elsewhere, a command whose text
(backslash-newline pairs removed) holds a delete word (`rm`, `rmdir`, `unlink`, `shred`, a whole-word `-delete`, `find`
with `-exec`/`-execdir`/`-ok`/`-okdir`; quotes and backslashes removed first, so `r''m` counts), a character that can
build one (`$`, a backtick, `?`, `*`, `[`, `{`), or a shared zone name (`-dev`, `/tmp/claude`, `.local`; also with its
quotes or backslashes removed, so `reach-around-d''ev` counts). Every other command returns allow at once, unparsed. A
command over MAX_SCAN_CHARS is decided by its first MAX_SCAN_CHARS characters (a delete word or zone name there is a
deny, otherwise an allow that is logged).

MODE: `safo-rmguard --mode enforce` (the default, and what any other value means) or `--mode warn`. The mode lives in
the hook command in the settings entry the owner controls, never in an environment variable an agent could set. In warn
mode nothing is ever blocked; each would-be block is appended, redacted, to
`~/.local/share/reach-around-lead/rmguard-warn.log` (folder 0700, file 0600, written through directory descriptors with
no symlink followed). `--record-integrity` records hashes of the launcher and the settings entry; warn mode logs once
when either differs (visibility only, not tamper-proof: a same-UID agent can change both).

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
import hashlib
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
MAX_SCAN_CHARS = 64 * 1024  # a command longer than this is decided by its first MAX_SCAN_CHARS characters
TIMEOUT_SECONDS = 3.0
LEAD_FOLDER = (".local", "share", "reach-around-lead")
MAX_LOGGED_CHARS = 500
# xargs and parallel run a command on input the line does not show, so they are handled apart, not skipped over.
WRAPS = {name: opts for name, opts in WRAPPERS.items() if name not in ("xargs", "parallel")}
WRAPS["builtin"] = frozenset()
POSITIONAL = frozenset({"flock", "taskset", "chrt"})  # one operand (lock file, CPU mask, priority) before the command


def _names(text: str) -> frozenset[str]:
    return frozenset(text.split())


# Git subcommands that cannot change a work tree: anything not here is judged by the tree it runs in (that covers
# `clean`, `reset`, `checkout`, `restore`, `rm`, `stash`, `switch`, `merge`, `rebase`, `pull`, `worktree`, an alias).
GIT_SAFE = _names(
    """
    add archive blame branch bundle cat-file check-attr check-ignore check-ref-format cherry clone commit
    config count-objects describe diff diff-files diff-index diff-tree fetch for-each-ref format-patch fsck
    get-tar-commit-id grep hash-object help init log ls-files ls-remote ls-tree merge-base merge-tree name-rev
    notes push range-diff reflog remote rev-list rev-parse shortlog show show-branch show-ref status symbolic-
    ref tag var verify-commit verify-tag version whatchanged
    """
)
GIT_GLOBAL_LONG = _names(
    """
    --bare --config-env --exec-path --git-dir --glob-pathspecs --help --html-path --icase-pathspecs --info-
    path --literal-pathspecs --man-path --namespace --no-advice --no-optional-locks --no-pager --no-replace-
    objects --noglob-pathspecs --paginate --super-prefix --version --work-tree
    """
)
TAR_LONG = _names(
    """
    absolute-names after-date anchored append auto-compress backup blocking-factor bzip2 catenate checkpoint
    checkpoint-action compare compress concatenate confirmation create delete dereference diff directory
    exclude exclude-backups exclude-caches exclude-from exclude-tag exclude-vcs extract file files-from format
    get gnu group gunzip gzip hard-dereference help hole-detection ignore-case ignore-failed-read ignore-zeros
    include incremental index-file info-script interactive keep-newer-files keep-old-files label level list
    listed-incremental lzip lzma lzop mode mtime multi-volume new-volume-script newer newer-mtime no-anchored
    no-ignore-case no-null no-overwrite-dir no-recursion no-same-owner no-same-permissions no-wildcards null
    numeric-owner older-mtime one-file-system overwrite overwrite-dir owner pax-option posix preserve-order
    preserve-permissions quiet read-full-records record-size recursion recursive-unlink remove-files same-
    order same-owner same-permissions show-defaults show-omitted-dirs silent skip-old-files sort sparse strip-
    components suffix tape-length test-label to-command to-stdout totals touch transform uncompress ungzip
    unlink-first update usage use-compress-program verbose verify version volno-file warning wildcards xform
    xz zstd
    """
)
RSYNC_LONG = _names(
    """
    append archive backup backup-dir bwlimit checksum chmod chown compare-dest compress contimeout copy-dest
    copy-links debug delete delete-after delete-before delete-delay delete-during delete-excluded delete-
    missing-args dirs dry-run exclude exclude-from existing files-from filter force from0 fuzzy group groupmap
    hard-links help human-readable ignore-errors ignore-existing include include-from info inplace itemize-
    changes link-dest links list-only log-file log-file-format max-size min-size mkpath modify-window munge-
    links no-dirs no-motd no-relative no-whole-file numeric-ids old-args one-file-system owner partial
    partial-dir perms port progress protect-args prune-empty-dirs quiet recursive relative remove-sent-files
    remove-source-files rsh rsync-path safe-links size-only sparse stats suffix temp-dir timeout times update
    usermap verbose version whole-file
    """
)
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
# A zone NAME (not a parent): a dev folder or the scratchpad parent. A parent needs a name or a building character
# to reach one.
_ZONE_NAME = re.compile(r"-dev(?![A-Za-z0-9_.])|/tmp/claude")
# Git environment that moves the work tree, the repository or the configuration (so an alias can appear from nowhere).
_GIT_ENV = re.compile(r"GIT_(?:WORK_TREE|DIR|COMMON_DIR|INDEX_FILE|NAMESPACE|CONFIG\w*|ALTERNATE\w*|OBJECT_DIRECTORY)")
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


def zone_text(text: str) -> bool:
    """Does the text name a zone, as written or with its quotes and backslashes removed (`reach-around-d''ev`)?"""
    text = text.replace("\\\n", "")
    return any(_ZONE_TEXT.search(v) for v in (text, _QUOTES.sub("", text), _QUOTES.sub(" ", text)))


def has_delete_word(text: str, cwd: str | None = None, home: str | None = None) -> bool:
    """Should this command be evaluated? True when the working directory is inside a shared zone (every command there
    is judged: `git clean`, a redirection and `mv` hold no delete word), when the text holds a delete word as written,
    when it holds a character that can build one (`$`, a backtick, `?`, `*`, `[`, `{`: `r?`, `r[m]`, `/bin/r*`, `$RM`,
    `r$'m'`), or when it mentions a shared zone, also with its name quoted or split by backslashes. Backslash-newline
    pairs are removed first. Only a command that does none of these is allowed without being parsed."""
    if cwd and home and cwd.startswith("/") and Zones(home).roots(norm(cwd)) is not None:
        return True
    text = text.replace("\\\n", "")
    return plain_delete_word(text) or bool(_SUSPECT.search(text)) or zone_text(text)


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
        self.only_assign = True  # every word of the current command so far is an assignment word
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
            if m and self.only_assign:  # an assignment word at command position
                name = word.text[: m.end() - 1]
                clean = not word.expands and word.glob is None and not re.search(r"[\s*?\[{]", word.text[m.end() :])
                self.staged[name] = word.text[m.end() :] if clean and name not in self.tainted else None
            if not m:
                self.only_assign = False
            self.cur.append(word)
        buf.clear()
        st.update(glob=None, expands=False, quoted=False)

    def separator(self, sep: str) -> None:
        """A command boundary. A newline or `;` with nothing before it changes nothing."""
        if self.cur and self.only_assign:  # assignments only: they bind for what follows
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
            self.only_assign = True
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
            self.only_assign = False
            self.i = close + 1
            return
        if op in ("<<", "<<-"):
            self.heredoc_start(end, op == "<<-")
        self.cur.append(Word(op, None, False, False, True))
        self.only_assign = False
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
        # Linear: only the last piece and the first few are looked at, never the whole buffer again.
        return buf[-1].endswith(("=", ":")) and bool(_ASSIGN.match("".join(buf[:64])))

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


# -- zones -----------------------------------------------------------------------------------------------------------


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
        """The path is a zone's parent: the home or an ancestor of the home, `~/.local`, `~/.local/share`, /tmp, `/`."""
        return path in self.parents or path == "/" or self.home.startswith(path.rstrip("/") + "/")

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


# -- the check -------------------------------------------------------------------------------------------------------


class Prefix(NamedTuple):
    at: int  # where the command word is
    chdir: tuple[str | None] | None  # a directory change by `env -C` or `sudo -D`: (resolved directory or None)
    split: str | None  # `env -S` text, to be scanned as a command line
    assigns: tuple[Word, ...] = ()  # the NAME=value words in front of the command (also those after `env`)


class Checker:
    def __init__(self, home: str, cwd: str | None, scan_home: str | None) -> None:
        self.home = home
        self.scan_home = scan_home
        self.zones = Zones(home)
        self.cwd = norm(cwd) if cwd and cwd.startswith("/") else None
        self.mentions_zone = False
        self.zone_named = False  # the text names a zone (as written, or with quotes and backslashes removed)
        self.plain = False  # the text holds a delete word as written
        self.git_env = False  # the text sets GIT_DIR, GIT_WORK_TREE or GIT_CONFIG*
        self.created: set[str] = set()  # targets an earlier command of this line wrote (so they exist by now)
        self.unknown_write = False  # an earlier command wrote somewhere that could not be resolved
        self.moved = False  # the command being checked changed the shell's directory
        self.assigns: tuple[Word, ...] = ()

    def near_zone(self) -> bool:
        """Is a zone in sight: named in the command, or the working directory in one or above one?"""
        if self.mentions_zone or self.zone_named:
            return True
        return self.cwd is not None and (self.zones.roots(self.cwd) is not None or self.zones.is_parent(self.cwd))

    def blind(self) -> bool:
        """Is there a reason to doubt an expansion we cannot read: a zone in the command, or no safe directory?"""
        return self.near_zone() or self.cwd is None

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
            if self.near_zone():
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
        assigns: list[Word] = []
        while i < len(words):
            w = words[i]
            if not w.quoted and (_ASSIGN.match(w.text) or w.text in _KEYWORDS):
                if _ASSIGN.match(w.text):
                    assigns.append(w)
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
                        return Prefix(i, chdir, self.split_text(words, i), tuple(assigns))
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
                        if _ASSIGN.match(t):
                            assigns.append(nxt)
                        i += 1
                    else:
                        break
                if name in POSITIONAL and i < len(words):
                    i += 1
            else:
                break
        return Prefix(i, chdir, None, tuple(assigns))

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

    def note_written(self, word: Word) -> None:
        """An earlier command of this line writes `word`: from now on that target exists (or may, if unplaced)."""
        resolved = resolve(word, self.cwd)
        if resolved is None:
            self.unknown_write = True
        elif not resolved[1]:
            self.created.add(resolved[0])

    def literal_agent_prefix(self, word: Word) -> bool:
        """The written part of the target, before its first unknown piece, already lies strictly below an agent folder
        or the scratchpad (`$HOME/.../agents/me/work/$name`). A known limit: the unknown piece could hold `..`."""
        head = word.text.split("\0", 1)[0]
        if not head.startswith("/") or ".." in head.split("/"):
            return False
        return self.zones.judge(posixpath.join(norm(head.rsplit("/", 1)[0] or "/"), "x"), False) == "ok"

    def existing_shared(self, word: Word) -> Finding | None:
        """For a redirection, `tee`, `cp` onto a file and the in-place editors: a target in a shared zone that exists,
        or that an earlier command of this same line created or may have created. Creating a brand-new file truncates
        nothing. A target that cannot be resolved follows the soft rule (judged when a zone is in sight)."""
        shown = word.text.replace("\0", "?").replace(self.home, "~")[:120]
        resolved = resolve(word, self.cwd)
        if resolved is None:
            if self.near_zone() and not self.literal_agent_prefix(word):
                return Finding("a target that cannot be resolved (an expansion, or a relative path)", shown)
            return None
        path, glob = resolved
        if self.zones.judge(path, glob) != "shared":
            return None
        if not glob and not (path in self.created or self.unknown_write or os.path.lexists(path)):
            return None
        return self.shared_finding(word, path, shown)

    def redirections(self, words: list[Word]) -> Finding | None:
        """A `>`, `>|` or `&>` truncates its target (`: > file`, `echo x > file`); `>>` appends and is not judged. A
        target that does not exist yet is only created, unless an earlier command of this line made it."""
        for n, w in enumerate(words):
            if not w.redir or n + 1 >= len(words):
                continue
            target = words[n + 1]
            writes = w.text in (">", ">|", "&>", ">>", "&>>", "<>") or (
                w.text == ">&" and not target.text.isdigit() and target.text != "-"
            )
            if not writes:
                continue
            if w.text != ">>" and w.text != "&>>":
                found = self.existing_shared(target)
                if found:
                    return Finding("a redirection that truncates " + found.reason, found.target, found.hint)
            self.note_written(target)
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
        self.assigns = pre.assigns
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
                if self.cwd is not None and (self.zones.roots(self.cwd) is not None or self.zones.is_parent(self.cwd)):
                    return True  # an argument it cannot place, from a directory in or above a zone
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
        base = name.rstrip("0123456789.")
        if base in ("python", "pypy", "python-config"):
            base = "python"
        handler = {
            "git": self.git,
            "truncate": self.truncate,
            "rsync": self.rsync,
            "tar": self.tar,
            "mv": self.mv,
            "cp": self.cp,
            "dd": self.dd,
            "tee": self.tee,
            "touch": self.touch,
            "sed": self.sed,
            "perl": self.perl,
            "ed": self.ed,
            "awk": self.awk,
            "gawk": self.awk,
            "mawk": self.awk,
            "nawk": self.awk,
            "install": self.install,
            "ln": self.ln,
            "python": self.interpreter,
            "ruby": self.interpreter,
            "node": self.interpreter,
            "nodejs": self.interpreter,
            "php": self.interpreter,
            "lua": self.interpreter,
        }.get(base if base in ("python", "ruby", "node", "nodejs", "php", "lua") else name)
        return handler(args) if handler else None

    @staticmethod
    def long_is(text: str, full: str, minimum: int = 3) -> bool:
        """Is `text` a GNU-style long option that is `--full` or an abbreviation of it (at least `minimum` letters)?"""
        if not text.startswith("--"):
            return False
        name = text[2:].split("=", 1)[0]
        return len(name) >= minimum and full.startswith(name)

    @classmethod
    def operands(cls, args: list[Word], takes: frozenset[str]) -> tuple[list[Word], list[Word]]:
        """(operands, values of the options in `takes`): words that are not options, and what those options consumed.
        A long option in `takes` also matches by abbreviation (`--target-dir` for `--target-directory`)."""
        out: list[Word] = []
        values: list[Word] = []
        longs = [t[2:] for t in takes if t.startswith("--")]
        after_dd = False
        skip = False
        for a in args:
            t = a.text
            if skip:
                values.append(a)
                skip = False
            elif not after_dd and not a.quoted and t == "--":
                after_dd = True
            elif not after_dd and t.startswith("-") and len(t) > 1:
                if t in takes or (t.startswith("--") and "=" not in t and any(cls.long_is(t, f) for f in longs)):
                    skip = True
                elif t.startswith("--") and "=" in t and any(cls.long_is(t, f) for f in longs):
                    values.append(Word(t.split("=", 1)[1], None, a.expands, a.quoted))
            else:
                out.append(a)
        return out, values

    def judge_all(self, words: list[Word]) -> Finding | None:
        for w in words:
            found = self.judge_soft(w)
            if found:
                return found
        return None

    def judge_existing_all(self, words: list[Word]) -> Finding | None:
        for w in words:
            found = self.existing_shared(w)
            if found:
                return found
        return None

    # git -----------------------------------------------------------------------------------------------------

    def git(self, args: list[Word]) -> Finding | None:
        """Only a short list of subcommands that cannot change a work tree is passed. Anything else (clean, reset,
        checkout, rm, stash, an alias, an unknown option) is judged by the tree it would run in."""
        base = self.cwd
        unknown = False
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
            elif t.startswith("--"):
                if t.split("=", 1)[0] not in GIT_GLOBAL_LONG:
                    unknown = True
                i += 1
            elif t.startswith("-") and t not in ("-p", "-P", "-h", "-v"):
                unknown = True
                i += 1
            elif t.startswith("-"):
                i += 1
            else:
                break
        sub = args[i].text if i < len(args) else ""
        if not unknown and sub in GIT_SAFE:
            return None
        rest = args[i + 1 :]
        dry = False
        pathspecs: list[Word] = []
        if sub == "clean" and not unknown:
            dry, pathspecs = self.clean_options(rest)
            if dry:
                return None  # a dry run removes nothing
        saved = self.cwd
        self.cwd = base
        try:
            env_set = self.git_env or any(_GIT_ENV.match(a.text) for a in self.assigns)
            # the work tree may come from GIT_WORK_TREE or GIT_DIR: it cannot be told, so a zone in sight decides
            if env_set and self.near_zone():
                return Finding("a git command whose work tree is set by the environment, aimed near a zone", "")
            if pathspecs:
                return self.judge_all(pathspecs)
            if base is None:
                if self.near_zone():
                    return Finding("`git " + (sub or "?") + "` in a working directory that could not be followed", "")
                return None
            found = self.judge_soft(Word(".", None, False, False))
            return Finding("`git " + (sub or "?") + "` in " + found.reason, found.target, found.hint) if found else None
        finally:
            self.cwd = saved

    def clean_options(self, rest: list[Word]) -> tuple[bool, list[Word]]:
        """Parse `git clean` options the way git does: short options cluster, `-e` takes a value (the rest of its
        cluster, or the next word), `--exclude` takes one, `-n` and `--dry-run` are the only dry-run flags (an
        abbreviation is not trusted). Returns (dry run, the pathspec operands)."""
        dry = False
        operands: list[Word] = []
        skip = False
        after_dd = False
        for a in rest:
            t = a.text
            if skip:
                skip = False
            elif after_dd:
                operands.append(a)
            elif t == "--":
                after_dd = True
            elif t.startswith("--"):
                if t == "--dry-run":
                    dry = True
                elif t == "--exclude":
                    skip = True
            elif t.startswith("-") and len(t) > 1:
                for k, ch in enumerate(t[1:]):
                    if ch == "n":
                        dry = True
                    elif ch == "e":
                        skip = k == len(t) - 2  # the value is the next word unless it is the rest of the cluster
                        break
            else:
                operands.append(a)
        return dry, operands

    # the plain destructive programs --------------------------------------------------------------------------

    def truncate(self, args: list[Word]) -> Finding | None:
        targets, _ = self.operands(args, frozenset({"-s", "--size", "-r", "--reference"}))
        found = self.judge_all(targets)
        for t in targets:
            self.note_written(t)
        return found

    def long_options(self, args: list[Word], known: frozenset[str]) -> tuple[list[str], list[str]]:
        """(known long options, unknown ones), by name; an abbreviation of a known option (3+ letters) is known."""
        good: list[str] = []
        bad: list[str] = []
        for a in args:
            if not a.text.startswith("--") or a.text == "--" or a.quoted:
                continue
            name = a.text[2:].split("=", 1)[0]
            match = [k for k in known if k == name or (len(name) >= 3 and k.startswith(name))]
            (good if match else bad).extend(match or [name])
        return good, bad

    def rsync(self, args: list[Word]) -> Finding | None:
        good, bad = self.long_options(args, RSYNC_LONG)
        destructive = bool(bad) or any(g.startswith(("delete", "remove")) for g in good)
        if not destructive:
            return None
        takes = frozenset({"-e", "--rsh", "--exclude", "--include", "-f", "--filter", "--files-from", "--rsync-path"})
        operands, _ = self.operands(
            args, takes | {"--log-file", "--temp-dir", "-T", "--exclude-from", "--include-from"}
        )
        found = self.judge_all(operands)
        if operands:
            self.note_written(operands[-1])
        return found

    def tar(self, args: list[Word]) -> Finding | None:
        good, bad = self.long_options(args, TAR_LONG)
        destructive = bool(bad) or any(g in ("remove-files", "recursive-unlink", "unlink-first") for g in good)
        if not destructive:
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
                elif t in ("-C", "--directory") or (self.long_is(t, "directory") and "=" not in t):
                    pending = "dir"
                elif t.startswith("--dir") and "=" in t and self.long_is(t, "directory"):
                    self.cwd = self.chdir_of(Word(t.split("=", 1)[1], None, False, False))[0]
                elif t in ("-f", "--file", "-T", "--files-from", "-X", "--exclude-from") or (
                    "=" not in t and any(self.long_is(t, f) for f in ("file", "files-from", "exclude-from"))
                ):
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

    def target_directories(self, args: list[Word]) -> list[Word]:
        """The directory given to `-t` / `--target-directory` (or an abbreviation) of mv, cp, install and ln."""
        out: list[Word] = []
        for n, a in enumerate(args):
            t = a.text
            if t in ("-t", "--target-directory") or (
                t.startswith("--") and "=" not in t and self.long_is(t, "target-directory")
            ):
                if n + 1 < len(args):
                    out.append(args[n + 1])
            elif t.startswith("--") and "=" in t and self.long_is(t, "target-directory"):
                out.append(Word(t.split("=", 1)[1], None, a.expands, a.quoted))
            elif t.startswith("-t") and len(t) > 2 and not t.startswith("--"):
                out.append(Word(t[2:], None, a.expands, a.quoted))
        return out

    MV_TAKES = frozenset({"-t", "--target-directory", "-S", "--suffix"})

    def mv(self, args: list[Word]) -> Finding | None:
        operands, _ = self.operands(args, self.MV_TAKES)
        dests = self.target_directories(args)
        found = self.judge_all(operands + dests)
        for w in dests or operands[-1:]:
            self.note_written(w)
        return found

    def cp(self, args: list[Word]) -> Finding | None:
        operands, _ = self.operands(args, self.MV_TAKES)
        dests = self.target_directories(args)
        sources = [o for o in operands if o.text not in ("/dev/null", "/dev/zero")]
        found: Finding | None = None
        if len(sources) < len(operands):  # `cp /dev/null file`: a truncation, judged whether or not the file exists
            found = self.judge_all(sources + dests)
        else:  # any other copy overwrites an existing target only
            found = self.judge_existing_all(dests or operands[-1:])
        for w in dests or operands[-1:]:
            self.note_written(w)
        return found

    def install(self, args: list[Word]) -> Finding | None:
        operands, _ = self.operands(args, self.MV_TAKES | {"-m", "--mode", "-o", "--owner", "-g", "--group"})
        dests = self.target_directories(args) or (operands[-1:] if len(operands) > 1 else [])
        found = self.judge_existing_all(dests)
        for w in dests:
            self.note_written(w)
        return found

    def ln(self, args: list[Word]) -> Finding | None:
        forced = any(
            (a.text.startswith("-") and not a.text.startswith("--") and "f" in a.text)
            or self.long_is(a.text, "force", 3)
            for a in args
        )
        operands, _ = self.operands(args, self.MV_TAKES)
        dests = self.target_directories(args) or operands[-1:]
        found = self.judge_existing_all(dests) if forced else None
        for w in dests:
            self.note_written(w)
        return found

    def touch(self, args: list[Word]) -> Finding | None:
        operands, _ = self.operands(args, frozenset({"-d", "--date", "-r", "--reference", "-t"}))
        for w in operands:
            self.note_written(w)
        return None

    def dd(self, args: list[Word]) -> Finding | None:
        for a in args:
            if a.text.startswith("of="):
                glob = a.glob - 3 if a.glob is not None and a.glob >= 3 else None
                word = Word(a.text[3:], glob, a.expands, a.quoted)
                found = self.judge_soft(word)
                self.note_written(word)
                if found:
                    return found
        return None

    def tee(self, args: list[Word]) -> Finding | None:
        targets, _ = self.operands(args, frozenset())
        append = any(
            a.text in ("-a", "--append") or (a.text.startswith("-") and not a.text.startswith("--") and "a" in a.text)
            for a in args
        )
        found = None if append else self.judge_existing_all(targets)
        for t in targets:
            self.note_written(t)
        return found

    # in-place editors ----------------------------------------------------------------------------------------

    def sed(self, args: list[Word]) -> Finding | None:
        inplace = any(
            (a.text.startswith("-") and not a.text.startswith("--") and "i" in a.text.split("e")[0].split("f")[0])
            or self.long_is(a.text, "in-place", 3)
            for a in args
        )
        if not inplace:
            return None
        operands, _ = self.operands(args, frozenset({"-e", "--expression", "-f", "--file", "-l", "--line-length"}))
        return self.judge_existing_all(operands)

    def perl(self, args: list[Word]) -> Finding | None:
        found = self.interpreter(args)
        if found:
            return found
        if not any(a.text.startswith("-") and not a.text.startswith("--") and "i" in a.text for a in args):
            return None
        operands, _ = self.operands(args, frozenset({"-e", "-E", "-I", "-M", "-m", "-x"}))
        return self.judge_existing_all(operands)

    def ed(self, args: list[Word]) -> Finding | None:
        operands, _ = self.operands(args, frozenset({"-p", "--prompt"}))
        return self.judge_existing_all(operands)

    def awk(self, args: list[Word]) -> Finding | None:
        inplace = any(
            (a.text == "-i" and n + 1 < len(args) and args[n + 1].text == "inplace")
            or a.text in ("-iinplace", "--include=inplace")
            for n, a in enumerate(args)
        )
        if not inplace:
            return None
        operands, _ = self.operands(args, frozenset({"-i", "-f", "-v", "-F", "--include", "--file", "--assign"}))
        return self.judge_existing_all(operands)

    def interpreter(self, args: list[Word]) -> Finding | None:
        """`python -c`, `perl -e`, `ruby -e`, `node -e`, `php -r`: code the hook cannot read. Fail closed when the cwd
        is in or above a zone, or the program text names one."""
        code: list[Word] = []
        for n, a in enumerate(args):
            t = a.text
            if t in ("-c", "-e", "-E", "-r", "--eval", "-p", "--print") and n + 1 < len(args):
                code.append(args[n + 1])
            elif t.startswith("-c") and len(t) > 2 and not t.startswith("--") and t[1] == "c":
                code.append(Word(t[2:], None, a.expands, a.quoted))
            elif re.fullmatch(r"-[a-zA-Z]*[ceEr]", t) and n + 1 < len(args):
                code.append(args[n + 1])
        if not code:
            return None
        if self.cwd is not None and self.zones.roots(self.cwd) is not None:
            return Finding("an inline program run from a shared dev directory", "")
        for c in code:
            if zone_text(c.text) or ("\0" in c.text and self.near_zone()):
                return Finding("an inline program that names a shared dev directory", "")
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
                    # the whole body is an expansion: nothing to read, so a zone in sight, the cwd in or above one,
                    # or a delete word elsewhere in the line decides
                    if self.near_zone() or self.plain:
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
        if any(a.text.startswith("--") and a.text not in ("--help", "--version") and not a.quoted for a in args):
            raise Unparseable  # a GNU-style long option find does not have: the layout is not understood
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


def too_large(command: str, home: str, cwd: str | None) -> Finding | None:
    """A command longer than MAX_SCAN_CHARS is decided by its first MAX_SCAN_CHARS characters, deterministically: a
    delete word or a zone name there (or a cwd inside a zone) is a deny, anything else an allow (the caller logs it)."""
    head = command[:MAX_SCAN_CHARS]
    inside = bool(cwd and cwd.startswith("/") and Zones(home).roots(norm(cwd)) is not None)
    if inside or plain_delete_word(head) or zone_text(head):
        return Finding("a command too large to check, with a delete word or a zone in its first 64 KB", "")
    return None


def check(command: str, home: str, cwd: str | None) -> Finding | None:
    """The finding that makes `command` a deny, or None to allow. A command that holds no delete word, no character
    that can build one, no zone and whose cwd is outside every zone is allowed at once, unparsed. Anything else is
    evaluated, and what cannot be read (a syntax error, nesting, a timeout, an internal error) is a deny. A command
    over MAX_SCAN_CHARS is decided by its head (see too_large)."""
    if not has_delete_word(command, cwd, home):
        return None
    if len(command) > MAX_SCAN_CHARS:
        return too_large(command, home, cwd)
    checker = Checker(home, cwd, None if home_unknown(command) else home)
    checker.zone_named = any(
        _ZONE_NAME.search(v) for v in (command, _QUOTES.sub("", command), _QUOTES.sub(" ", command))
    )
    checker.plain = plain_delete_word(command)
    checker.git_env = bool(_GIT_ENV.search(_QUOTES.sub("", command)))
    try:
        return checker.scan(command)
    except UnknownCommand:
        return Finding("a command word built from an expansion or a pattern, aimed at a shared dev directory", "")
    except (Unparseable, RecursionError):
        return Finding("a command too tangled to check (unterminated quote, nesting or a built command word)", "")


# -- the hook --------------------------------------------------------------------------------------------------------


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


def _lead_file(home: str, name: str, flags: int) -> int:
    """Open `name` in the lead-only folder through directory descriptors and return its descriptor. No symlink is
    followed, every component must belong to this user, the folder is repaired to 0700, and the file must be a regular
    file with one link, owned by this user, repaired to 0600."""
    uid = os.getuid()
    dflags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)  # the home itself may sit behind a mount link
    try:
        for n, part in enumerate(LEAD_FOLDER):
            try:
                nxt = os.open(part, dflags, dir_fd=fd)
            except FileNotFoundError:
                if flags & os.O_CREAT == 0:
                    raise
                os.mkdir(part, 0o700, dir_fd=fd)
                nxt = os.open(part, dflags, dir_fd=fd)
            os.close(fd)
            fd = nxt
            info = os.fstat(fd)
            if info.st_uid != uid:
                raise PermissionError(part)
            if n == len(LEAD_FOLDER) - 1 and stat.S_IMODE(info.st_mode) != 0o700:
                os.fchmod(fd, 0o700)
        opened = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        try:
            info = os.fstat(opened)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1:
                raise PermissionError(name)
            os.fchmod(opened, 0o600)
        except BaseException:
            os.close(opened)
            raise
        return opened
    finally:
        os.close(fd)


def _append_log(home: str, name: str, line: str) -> None:
    log = _lead_file(home, name, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
    try:
        os.write(log, (line + "\n").encode("utf-8", "replace"))
    finally:
        os.close(log)


def append_log(home: str, name: str, line: str) -> None:
    """Append one line to a log in the lead-only folder. Never raises: a log must not block anything."""
    try:
        _append_log(home, name, line)
    except OSError:
        return


def read_small(home: str, name: str) -> str | None:
    """A small file of the lead-only folder, or None when it is missing or cannot be read safely."""
    try:
        fd = _lead_file(home, name, os.O_RDONLY)
    except OSError:
        return None
    try:
        return os.read(fd, 65536).decode("utf-8", "replace")
    except OSError:
        return None
    finally:
        os.close(fd)


def write_small(home: str, name: str, text: str) -> bool:
    try:
        fd = _lead_file(home, name, os.O_WRONLY | os.O_CREAT)
    except OSError:
        return False
    try:
        os.ftruncate(fd, 0)
        os.write(fd, text.encode("utf-8", "replace"))
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


# -- integrity self-check (warn mode) --------------------------------------------------------------------------------
# A same-UID agent can edit the launcher or the settings entry; nothing here prevents that. This only makes a change
# visible: a hash of each is recorded on request, and warn mode logs once when either differs from the record.

LAUNCHER = (".config", "safo", "rmguard-hook")
SETTINGS = (".claude", "settings.json")
INTEGRITY_RECORD = "rmguard-integrity.json"
INTEGRITY_STATE = "rmguard-integrity.state"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def integrity_now(home: str) -> dict[str, str]:
    """{"launcher": hash or "missing", "settings": hash of the rmguard hook entries or "absent"}."""
    out = {"launcher": "missing", "settings": "absent"}
    try:
        with open(os.path.join(home, *LAUNCHER), "rb") as handle:
            out["launcher"] = _digest(handle.read(1_000_000))
    except OSError:
        pass
    try:
        with open(os.path.join(home, *SETTINGS), "rb") as handle:
            data = json.loads(handle.read(4_000_000))
        entries = [
            entry
            for entry in data.get("hooks", {}).get("PreToolUse", [])
            if "rmguard" in json.dumps(entry, sort_keys=True)
        ]
        out["settings"] = _digest(json.dumps(entries, sort_keys=True).encode()) if entries else "absent"
    except (OSError, ValueError, AttributeError):
        out["settings"] = "unreadable"
    return out


def record_integrity(home: str) -> bool:
    return write_small(home, INTEGRITY_RECORD, json.dumps(integrity_now(home), sort_keys=True))


def integrity_check(home: str, when: dt.datetime) -> None:
    """Warn mode: log one line when the launcher or the settings entry differ from the recorded hash. A line is written
    once per change (the last logged difference is kept), and again if it changes back and then differs anew."""
    recorded = read_small(home, INTEGRITY_RECORD)
    if recorded is None:
        return
    try:
        was = json.loads(recorded)
    except ValueError:
        return
    now = integrity_now(home)
    differs = sorted(k for k in now if was.get(k) != now[k])
    signature = ",".join(f"{k}={now[k][:12]}" for k in differs)
    last = read_small(home, INTEGRITY_STATE) or ""
    if signature and signature != last:
        what = " and ".join("the launcher" if k == "launcher" else "the settings entry" for k in differs)
        append_log(
            home,
            "rmguard-error.log",
            f"{when.strftime('%Y-%m-%dT%H:%M:%SZ')}\twarn\tintegrity: {what} differ from the record\t",
        )
    if signature != last:
        write_small(home, INTEGRITY_STATE, signature)


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
    if found is None and len(command) > MAX_SCAN_CHARS:
        return Outcome("", command, "command too large to check; allowed (no delete word or zone in its first 64 KB)")
    return Outcome(message(found) if found else "", command, "")


def main(
    argv: Sequence[str] | None = None,
    stdin: Iterable[str] | None = None,
    home: str | None = None,
    now: dt.datetime | None = None,
) -> int:
    """Read one event, print a deny when the rule bites (enforce) or log one line (warn). Never raises."""
    words = sys.argv[1:] if argv is None else list(argv)
    mode = parse_mode(words)
    home = home or os.path.expanduser("~")
    when = now or dt.datetime.now(dt.UTC)
    if "--record-integrity" in words:
        print("rmguard integrity record " + ("written" if record_integrity(home) else "NOT written"))
        return 0
    if mode == "warn":
        integrity_check(home, when)
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
