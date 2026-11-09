# SPDX-License-Identifier: Apache-2.0
"""Recognise an INVOCATION in a Bash command, not a trigger word in its text (#395).

The Bash check in `safo.geminibrief` has two heuristics that matched words anywhere in the command: "escapes beside a
network or secret tool" and "a secret tool run with a shell expansion". They fired on a grep pattern, a commit message,
a quoted argument, a heredoc body or a file name. This module lexes the command the way a shell does (quotes, escapes,
`$(...)` and backticks, heredocs, redirects, `; && || | &` and newlines), finds the COMMAND WORD of each segment (after
assignments and wrappers such as sudo, env, nohup, time, command, exec), and answers the two questions about real
invocations only.

It only ever NARROWS the old answer: the caller asks it after the old conditions already hold. Anything it cannot read
with certainty raises `Unreadable`, and the caller then keeps the old answer, so odd input is checked exactly as before.
Never resolved here: variable values, aliases, functions, files. A dynamic command word (`$X`, a glob, `$'..'`, a
substitution) is `Unreadable`.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass, field

MAX_DEPTH = 6
MAX_UNITS = 400
BUILT = "built"
TOOL = "tool"


class Unreadable(Exception):
    """The command cannot be read with certainty; the caller keeps the old, wider answer."""


@dataclass
class Word:
    raw: str
    value: str | None  # the unquoted text when it is fully static, else None
    expands: bool  # an expansion outside single quotes: $x ${..} $(..) `..`
    subs: list[str] = field(default_factory=list)  # command texts inside $(...) and backticks


@dataclass
class Heredoc:
    delim: str
    quoted: bool
    strip: bool = False
    body: str = ""


@dataclass
class Unit:
    words: list[Word]
    redirs: list[tuple[str, Word]]
    heredocs: list[Heredoc]
    herestrings: list[Word]
    pipe: int


_NAME = re.compile(r"[A-Za-z_]\w*")
_ASSIGN = re.compile(r"[A-Za-z_]\w*\+?=")
_REDIR_ALONE = re.compile(r"(?:\d*|&)(?:>>?\|?|<&|>&|<>|<)")
_REDIR_ATTACHED = re.compile(r"(?:\d*|&)(?P<op>>>?\|?|<&|>&|<>|<)(?P<rest>.+)", re.S)
_HERE_WORD = re.compile(r"<<(?!<)(?P<dash>-?)(?P<rest>.*)", re.S)


class _Counter:
    def __init__(self) -> None:
        self.n = 0
        self.units = 0


def _skip_single(t: str, i: int) -> int:
    j = t.find("'", i + 1)
    if j < 0:
        raise Unreadable("unterminated quote")
    return j + 1


def _balanced(t: str, i: int) -> int:
    """Index just after the `)` closing a `$(` whose body starts at i. Quotes, escapes and heredocs are skipped."""
    depth = 1
    n = len(t)
    while i < n:
        c = t[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            i = _skip_single(t, i)
            continue
        if c == '"':
            i += 1
            while i < n and t[i] != '"':
                i += 2 if t[i] == "\\" else 1
            i += 1
            continue
        if c == "<" and t.startswith("<<", i) and not t.startswith("<<<", i):
            m = re.compile(r"<<-?[ \t]*(?P<q>['\"]?)(?P<tag>\w+)(?P=q)").match(t, i)
            if m:
                eol = t.find("\n", m.end())
                if eol < 0:
                    raise Unreadable("heredoc without a body")
                tag = m.group("tag")
                pos = eol + 1
                while True:
                    nl = t.find("\n", pos)
                    line = t[pos:] if nl < 0 else t[pos:nl]
                    if line.strip() == tag:
                        i = pos + len(line)
                        break
                    if nl < 0:
                        raise Unreadable("unterminated heredoc")
                    pos = nl + 1
                continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise Unreadable("unterminated substitution")


def _backtick(t: str, i: int) -> int:
    j = i
    while j < len(t):
        if t[j] == "\\":
            j += 2
            continue
        if t[j] == "`":
            return j + 1
        j += 1
    raise Unreadable("unterminated backtick")


def _dollar(t: str, i: int, acc: dict) -> int:
    """Handle a `$` at t[i] (outside single quotes). Returns the new index; records expansions in acc."""
    nxt = t[i + 1 : i + 2]
    if nxt == "(":
        end = _balanced(t, i + 2)
        inner_start = i + 3 if t.startswith("$((", i) else i + 2
        acc["subs"].append(t[i + 2 : end - 1] if inner_start == i + 2 else t[i + 3 : end - 2])
        acc["expands"] = True
        acc["static"] = False
        return end
    if nxt == "{":
        j = t.find("}", i + 2)
        if j < 0 or "$(" in t[i:j] or "`" in t[i:j]:
            raise Unreadable("odd parameter expansion")
        acc["expands"] = True
        acc["static"] = False
        return j + 1
    if nxt and (nxt.isalnum() or nxt in "_@*#?!$-"):
        j = i + 1
        if nxt.isalnum() or nxt == "_":
            while j < len(t) and (t[j].isalnum() or t[j] == "_"):
                j += 1
        else:
            j += 1
        acc["expands"] = True
        acc["static"] = False
        return j
    acc["val"].append("$")
    return i + 1


def _read_word(t: str, i: int) -> tuple[Word, int]:
    start = i
    n = len(t)
    acc: dict = {"val": [], "static": True, "expands": False, "subs": []}
    while i < n:
        c = t[i]
        if c == "(" and i > start and t[i - 1] in "<>":
            end = _balanced(t, i + 1)
            acc["subs"].append(t[i + 1 : end - 1])
            acc["expands"] = True
            acc["static"] = False
            i = end
            continue
        if c in " \t\n;|()":
            break
        if c == "&":
            nxt = t[i + 1 : i + 2]
            if nxt == "&":
                break
            prev = t[i - 1] if i > start else ""
            if not (prev in "<>" and prev) and not (i == start and nxt == ">"):
                break
        if c == "\\":
            if i + 1 < n:
                acc["val"].append(t[i + 1])
            i += 2
            continue
        if c == "'":
            j = _skip_single(t, i)
            acc["val"].append(t[i + 1 : j - 1])
            i = j
            continue
        if c == '"':
            i += 1
            while True:
                if i >= n:
                    raise Unreadable("unterminated quote")
                ch = t[i]
                if ch == '"':
                    i += 1
                    break
                if ch == "\\":
                    if i + 1 < n and t[i + 1] in '$"\\`\n':
                        acc["val"].append(t[i + 1])
                    elif i + 1 < n:
                        acc["val"].append(ch + t[i + 1])
                    i += 2
                    continue
                if ch == "$":
                    i = _dollar(t, i, acc)
                    continue
                if ch == "`":
                    end = _backtick(t, i + 1)
                    acc["subs"].append(t[i + 1 : end - 1])
                    acc["expands"] = True
                    acc["static"] = False
                    i = end
                    continue
                acc["val"].append(ch)
                i += 1
            continue
        if c == "$":
            if t.startswith("$'", i):
                j = i + 2
                while j < n and t[j] != "'":
                    j += 2 if t[j] == "\\" else 1
                if j >= n:
                    raise Unreadable("unterminated ANSI-C quote")
                acc["static"] = False  # its value is not decoded here
                i = j + 1
                continue
            i = _dollar(t, i, acc)
            continue
        if c == "`":
            end = _backtick(t, i + 1)
            acc["subs"].append(t[i + 1 : end - 1])
            acc["expands"] = True
            acc["static"] = False
            i = end
            continue
        if c in "*?[{" or (c == "~" and i == start and t[i + 1 : i + 2] != "/"):
            acc["static"] = False
        acc["val"].append(c)
        i += 1
    raw = t[start:i]
    value = "".join(acc["val"]) if acc["static"] else None
    if t[start:i] in ("[", "[[", "{", "}"):
        value = t[start:i]
    return Word(raw, value, acc["expands"], acc["subs"]), i


def _heredoc_body(t: str, i: int, hd: Heredoc) -> int:
    """Read the body of hd starting at index i (the first body line); returns the index of the terminator's end."""
    pos = i
    n = len(t)
    body: list[str] = []
    while True:
        nl = t.find("\n", pos)
        line = t[pos:] if nl < 0 else t[pos:nl]
        cmp = line.lstrip("\t") if hd.strip else line
        if cmp.rstrip() == hd.delim:
            hd.body = "\n".join(body)
            if not hd.quoted and ("$(" in hd.body or "`" in hd.body):
                raise Unreadable("an unquoted heredoc holds a substitution")
            return n if nl < 0 else nl
        body.append(line)
        if nl < 0:
            raise Unreadable("unterminated heredoc")
        pos = nl + 1


def parse(text: str, counter: _Counter, tick: Callable[[], None], depth: int = 0) -> list[Unit]:
    if depth > MAX_DEPTH:
        raise Unreadable("too deeply nested")
    t = text.replace("\\\n", "")
    units: list[Unit] = []
    words: list[Word] = []
    pending: list[Heredoc] = []  # bodies still to be read at the next newline
    cur: list[Heredoc] = []  # heredocs of the segment being read
    pipe = counter.n
    n = len(t)
    i = 0

    def close(same_pipeline: bool) -> None:
        nonlocal words, cur, pipe
        if words or cur:
            counter.units += 1
            if counter.units > MAX_UNITS:
                raise Unreadable("too many commands")
            units.append(_make_unit(words, pipe, cur))
        words, cur = [], []
        if not same_pipeline:
            counter.n += 1
            pipe = counter.n

    while i < n:
        tick()
        c = t[i]
        if c in " \t":
            i += 1
            continue
        if c == "\n":
            close(False)
            for hd in pending:
                i = _heredoc_body(t, i + 1, hd)
            pending = []
            i += 1
            continue
        if c == "#" and (i == 0 or t[i - 1] in " \t\n;|&("):
            while i < n and t[i] != "\n":
                i += 1
            continue
        if c == ";":
            close(False)
            i += 2 if t.startswith(";;", i) else 1
            continue
        if c == "&" and not (i + 1 < n and t[i + 1] == ">"):
            close(False)
            i += 2 if t.startswith("&&", i) else 1
            continue
        if c == "|":
            if t.startswith("||", i):
                close(False)
                i += 2
            else:
                close(True)
                i += 2 if t.startswith("|&", i) else 1
            continue
        if c == "(" and not words and not cur:
            end = _balanced(t, i + 1)
            units.extend(parse(t[i + 1 : end - 1], counter, tick, depth + 1))
            i = end
            continue
        if c in "()":
            raise Unreadable("group or stray parenthesis")
        word, i = _read_word(t, i)
        if not word.raw:
            raise Unreadable("no progress")
        for sub in word.subs:
            units.extend(parse(sub, counter, tick, depth + 1))
        m = _HERE_WORD.fullmatch(word.raw)
        if m:
            rest = m.group("rest")
            if not rest:
                while i < n and t[i] in " \t":
                    i += 1
                dword, i = _read_word(t, i)
                if not dword.raw or dword.subs or dword.expands:
                    raise Unreadable("odd heredoc delimiter")
                rest = dword.raw
            delim = rest.replace("'", "").replace('"', "").replace("\\", "")
            hd = Heredoc(delim, bool(re.search(r"['\"\\]", rest)), bool(m.group("dash")))
            cur.append(hd)
            pending.append(hd)
            continue
        words.append(word)
    close(False)
    if pending:
        raise Unreadable("heredoc without a body")
    return units


_ALONE_OP = re.compile(r"(?:\d*|&)(?P<op>>>?\|?|<&|>&|<>|<)")
_ATTACHED = re.compile(r"(?:\d*|&)(?P<op>>>?\|?|<&|>&|<>|<)(?P<rest>.+)", re.S)


def _make_unit(words: list[Word], pipe: int, heredocs: list[Heredoc]) -> Unit:
    args: list[Word] = []
    redirs: list[tuple[str, Word]] = []
    herestrings: list[Word] = []
    k = 0
    while k < len(words):
        w = words[k]
        raw = w.raw
        if raw.startswith("<<<"):
            if raw == "<<<":
                if k + 1 >= len(words):
                    raise Unreadable("here-string without a string")
                herestrings.append(words[k + 1])
                k += 2
            else:
                v = w.value[3:] if w.value is not None and w.value.startswith("<<<") else None
                herestrings.append(Word(raw[3:], v, w.expands, w.subs))
                k += 1
            continue
        alone = _ALONE_OP.fullmatch(raw)
        if alone:
            if k + 1 >= len(words):
                raise Unreadable("redirect without a target")
            redirs.append((alone.group("op"), words[k + 1]))
            k += 2
            continue
        m = _ATTACHED.fullmatch(raw)
        if m:
            rest = m.group("rest")
            if rest[0] == "&" and m.group("op") in (">", ">>", "<&", ">&"):
                k += 1  # a descriptor copy such as 2>&1
                continue
            tv = None
            if w.value is not None:
                mv = _ATTACHED.fullmatch(w.value)
                tv = mv.group("rest") if mv else None
            redirs.append((m.group("op"), Word(rest, tv, w.expands, w.subs)))
            k += 1
            continue
        args.append(w)
        k += 1
    return Unit(args, redirs, heredocs, herestrings, pipe)


# --------------------------------------------------------------------------------------------------------------------
# What a unit runs

# "$DIR/bin/name" or "$DIR"/bin/name: one word (no splitting) whose last component is plain text
_QUOTED_PATH = re.compile(
    r"\"\$\{?\w+\}?(?:/[^\"$`\\]*)?/(?P<name>[\w.+-]+)\"|\"\$\{?\w+\}?\"(?:/[^\"$`\\ ]*)?/(?P<name2>[\w.+-]+)"
)
RESERVED = frozenset({"if", "then", "elif", "else", "do", "while", "until", "!", "time", "{", "}"})
WRAPPERS = frozenset(
    {
        "sudo", "doas", "env", "nohup", "command", "exec", "builtin", "nice", "ionice", "timeout", "stdbuf", "setsid",
        "xargs", "watch", "unbuffer", "chronic", "parallel",
    }
)  # fmt: skip
SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh", "ash", "fish", "csh", "tcsh"})
# the options that take a separate value, for the wrappers whose options matter
_WRAP_VALUE_OPTS = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U"},
    "nice": {"-n"},
    "ionice": {"-c", "-n", "-p"},
    "timeout": {"-s", "-k"},
    "xargs": {"-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a"},
    "watch": {"-n", "-d"},
    "env": {"-u", "-C", "-S"},
    "stdbuf": {"-i", "-o", "-e"},
}
# commands that cannot run code from their arguments (git, gh and find are checked further below)
DATA = frozenset(
    {
        "grep", "egrep", "fgrep", "rg", "ag", "cat", "head", "tail", "less", "more", "ls", "wc", "diff", "cmp", "jq",
        "sort", "uniq", "cut", "file", "stat", "test", "[", "echo", "printf", "true", "false", "cd", "pwd", "mkdir",
        "rm", "cp", "mv", "touch", "chmod", "date", "sleep", "basename", "dirname", "realpath", "readlink", "which",
        "type", "tr", "column", "nl", "tac", "rev", "fold", "seq", "id", "whoami", "uname", "df", "du", "ln",
    }
)  # fmt: skip
GIT_SAFE = frozenset(
    {
        "commit", "log", "show", "diff", "status", "add", "branch", "tag", "stash", "ls-files", "blame", "grep",
        "rev-parse", "describe", "worktree", "checkout", "switch", "reset", "restore", "mv", "rm", "merge", "shortlog",
        "show-ref", "cat-file", "rev-list", "apply", "format-patch", "cherry-pick", "revert", "remote",
    }
)  # fmt: skip
GH_SAFE = frozenset({"pr", "issue", "release", "repo", "run", "workflow", "label", "project", "search", "status"})
DOC_EXT = (".md", ".txt", ".json", ".yaml", ".yml", ".diff", ".patch", ".csv", ".toml", ".log", ".out", ".html")
EXEC_FLAGS = ("-exec", "-execdir", "-ok", "-okdir")
GIT_EXEC_FLAGS = frozenset({"--exec", "-x", "--extcmd", "--upload-pack", "--receive-pack", "-O"})
GIT_EXEC_PREFIXES = ("--open-files-in-pager", "--exec=", "--upload-pack=", "--receive-pack=")


@dataclass
class Eff:
    cmd: str  # basename of the command word, "" when the segment only assigns or redirects
    args: list[Word]
    unit: Unit
    text: str = ""  # the unit's own text: assignments, arguments, redirect targets, here-strings
    bodies: list[str] = field(default_factory=list)  # heredoc bodies fed to this command


def _skip_wrapper(name: str, rest: list[Word]) -> list[Word]:
    """Drop a wrapper's own options (and the values of the options that take one) from rest."""
    values = _WRAP_VALUE_OPTS.get(name, set())
    i = 0
    while i < len(rest):
        v = rest[i].value
        if v is None:
            return rest
        if name == "env" and _ASSIGN.match(v):
            i += 1
            continue
        if v == "--":
            return rest[i + 1 :]
        if v.startswith("-") and len(v) > 1:
            i += 2 if v in values else 1
            continue
        if name == "timeout" and i == 0 and re.fullmatch(r"[\d.]+[smhd]?", v):
            i += 1
            continue
        break
    return rest[i:]


def _static(words: list[Word]) -> str:
    out = []
    for w in words:
        if w.value is None:
            raise Unreadable("dynamic word")
        out.append(w.value)
    return " ".join(out)


def _recurse(script: str, counter: _Counter, tick: Callable[[], None], depth: int, out: list[Eff]) -> None:
    if depth + 1 > MAX_DEPTH:
        raise Unreadable("too deeply nested")
    for u in parse(script, counter, tick, depth + 1):
        effective(u, counter, tick, depth + 1, out)


def effective(unit: Unit, counter: _Counter, tick: Callable[[], None], depth: int, out: list[Eff]) -> None:
    tick()
    words = list(unit.words)
    prefix_text = []
    while words and _ASSIGN.match(words[0].raw):
        prefix_text.append(words[0].raw)
        words = words[1:]
    cmd = ""
    while words:
        first = words[0]
        if first.value is None:
            quoted_path = _QUOTED_PATH.fullmatch(first.raw)
            if quoted_path is None:
                raise Unreadable("dynamic command word")
            name = quoted_path.group("name") or quoted_path.group("name2")
        else:
            name = posixpath.basename(first.value)
        if name in RESERVED:
            words = words[1:]
            continue
        if name in WRAPPERS:
            words = _skip_wrapper(name, words[1:])
            continue
        if name == "function":
            raise Unreadable("function definition")
        cmd = name
        words = words[1:]
        break
    eff = Eff(cmd, words, unit)
    out.append(eff)
    pieces = list(prefix_text)
    pieces += [cmd] if cmd else []  # the command word is part of its text (`printf -v` is one of the patterns)
    pieces += [w.raw for w in words]
    pieces += [w.raw for _, w in unit.redirs]
    pieces += [w.raw for w in unit.herestrings]
    eff.text = " ".join(pieces)
    eff.bodies = [hd.body for hd in unit.heredocs]
    if cmd == "":
        return
    if cmd in SHELLS:
        script = None
        for k, w in enumerate(words):
            v = w.value
            if v is None:
                raise Unreadable("dynamic shell argument")
            if v.startswith("-") and not v.startswith("--") and "c" in v[1:]:
                if k + 1 >= len(words) or words[k + 1].value is None:
                    raise Unreadable("dynamic or missing script")
                script = words[k + 1].value
                break
        if script is not None:
            _recurse(script, counter, tick, depth, out)
        for hs in unit.herestrings:
            if hs.value is None:
                raise Unreadable("dynamic here-string")
            _recurse(hs.value, counter, tick, depth, out)
        for hd in unit.heredocs:
            _recurse(hd.body, counter, tick, depth, out)
    elif cmd == "eval":
        _recurse(_static(words), counter, tick, depth, out)
    elif cmd in (".", "source"):
        if unit.herestrings or unit.heredocs or any(w.value is None for w in words):
            raise Unreadable("sourced text")
    elif cmd == "find":
        for k, w in enumerate(words):
            if w.value in EXEC_FLAGS:
                sub = []
                for x in words[k + 1 :]:
                    if x.value in (";", "+"):
                        break
                    sub.append(x)
                effective(Unit(sub, [], [], [], unit.pipe), counter, tick, depth + 1, out)


# --------------------------------------------------------------------------------------------------------------------
# The two questions


def _git_data(words: list[Word]) -> bool:
    i = 0
    while i < len(words):
        v = words[i].value
        if v is None:
            return False
        if v == "-C" and i + 1 < len(words):
            i += 2
            continue
        if v.startswith("-") or v not in GIT_SAFE:
            return False  # -c k=v, --exec-path, an alias or an external subcommand can run programs
        rest = [w.value for w in words[i + 1 :]]
        return not any(x in GIT_EXEC_FLAGS or (x or "").startswith(GIT_EXEC_PREFIXES) for x in rest)
    return True


def _gh_data(words: list[Word]) -> bool:
    for w in words:
        if w.value is None:
            return False
        if w.value.startswith("-"):
            continue
        return w.value in GH_SAFE
    return True


def _doc_target(eff: Eff, all_effs: list[Eff]) -> bool:
    """Every output redirect goes to a document-type file that no other command in the input names."""
    for op, tw in eff.unit.redirs:
        if op in ("<", "<&", ">&"):
            continue
        tv = tw.value
        if tv is None:
            return False
        if tv in ("/dev/null", "/dev/stderr", "/dev/stdout"):
            continue
        if not tv.lower().endswith(DOC_EXT):
            return False
        if any(other is not eff and tv in other.text for other in all_effs):
            return False
        # another command with a glob or an expansion for an argument could name the file without spelling it
        if any(w.value is None for other in all_effs if other is not eff for w in other.args):
            return False
    return True


def _is_data(eff: Eff, all_effs: list[Eff]) -> bool:
    cmd = eff.cmd
    if cmd == "git":
        ok = _git_data(eff.args)
    elif cmd == "gh":
        ok = _gh_data(eff.args)
    elif cmd == "find":
        ok = not any(w.value in EXEC_FLAGS for w in eff.args)
    elif cmd == "printf":
        ok = not any(w.value is None or w.value == "-v" for w in eff.args[:1])  # printf -v NAME builds a variable
    else:
        ok = cmd in DATA
    return ok and _doc_target(eff, all_effs)


def classify(
    command: str,
    conceal: re.Pattern[str],
    network: re.Pattern[str],
    tick: Callable[[], None],
) -> str | None:
    """BUILT, TOOL or None for a command the old check would have refused. Raises Unreadable when unsure."""
    counter = _Counter()
    effs: list[Eff] = []
    for u in parse(command, counter, tick):
        effective(u, counter, tick, 0, effs)

    def is_tool(e: Eff) -> bool:
        return e.cmd == "doppler" or bool(e.cmd and network.fullmatch(e.cmd))

    def code_text(e: Eff) -> str:
        """The text of e that could be code or could build a command: nothing for a data command's arguments."""
        if e.cmd and _is_data(e, effs):
            return ""
        return " ".join([e.text, *e.bodies]).lower()

    def has_tool_word(text: str) -> bool:
        return bool(network.search(text) or "doppler" in text)

    texts = {id(e): code_text(e) for e in effs}
    full = {id(e): " ".join([e.text, *e.bodies]).lower() for e in effs}
    active_conceal = any(conceal.search(texts[id(e)]) for e in effs)
    tools = [e for e in effs if is_tool(e)]
    for e in tools:
        if e.cmd == "doppler" and any(w.expands for w in e.args):
            return TOOL
    for e in tools:
        if conceal.search(texts[id(e)]):
            return BUILT
        if any(conceal.search(full[id(m)]) for m in effs if m is not e and m.unit.pipe == e.unit.pipe):
            return BUILT
    if tools and active_conceal:
        # escapes in anything that is not plain data (an assignment, a redirected printf, a script being written, an
        # unknown command) beside a tool in the same input: the tool may take the built text through a variable, a
        # pipe or a file written a moment ago, none of which is followed here
        return BUILT
    # commands that are neither tools nor data keep the old pairing, per command: escapes beside a tool word
    for e in effs:
        text = texts[id(e)]
        if e not in tools and text and conceal.search(text) and has_tool_word(text):
            return BUILT
    return None
