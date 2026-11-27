# SPDX-License-Identifier: Apache-2.0
"""A best-effort reading of the shell `run:` steps of a gate workflow: which repository files do they execute or source?

`safo-ship` (issue #586) compares each such file between the base branch and the pinned head, because a pull request
that changes `ci/gate.sh` while leaving the workflow untouched changes what the gate does. This module only finds the
paths; it never reads the repository and never runs anything.

It is a derivation, not a proof, and it fails closed: any construct whose target it cannot name (command substitution,
`eval`, a heredoc, `xargs`, a path built from a variable, a pipe into an interpreter, `python -c`, a `cd` it cannot
follow, a path outside the repository) is reported as a problem, and the caller stops with NEEDS-HUMAN. Files that only
appear as arguments (a test directory handed to a test runner) are not "executed" and are not listed. What stays outside
it: Makefile targets (only the Makefile itself is listed), configuration files, installed dependencies, and what a
Python or Node program imports.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass

SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh"})
OTHER_INTERPRETERS = frozenset(
    {"node", "nodejs", "deno", "bun", "ruby", "perl", "pwsh", "php", "tsx", "ts-node", "source", "."}
)
PYTHON = re.compile(r"python[0-9.]*|pypy[0-9.]*")
WRAPPERS = frozenset({"env", "sudo", "time", "nohup", "exec", "command", "nice", "stdbuf", "builtin"})
KEYWORDS = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}"})
DYNAMIC = frozenset({"eval", "xargs", "parallel"})
SCRIPT_EXT = (".sh", ".bash", ".py", ".js", ".ts", ".mjs", ".cjs", ".rb", ".pl", ".ps1", ".php")
SAFE_MODULES = frozenset(
    {"pytest", "pip", "mypy", "ruff", "build", "venv", "twine", "coverage", "black", "isort", "flake8", "ensurepip"}
)
MAKES = frozenset({"make", "gmake"})
MAKEFILES = ("Makefile", "makefile", "GNUmakefile")
OPERATOR = re.compile(r"[();<>|&]+")
ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
WORKSPACE = re.compile(r"\$\{\{\s*github\.workspace\s*\}\}|\$\{GITHUB_WORKSPACE\}|\$GITHUB_WORKSPACE\b")
ACTION_PATH = re.compile(r"\$\{\{\s*github\.action_path\s*\}\}|\$\{GITHUB_ACTION_PATH\}|\$GITHUB_ACTION_PATH\b")
SAFE_PART = re.compile(r"[A-Za-z0-9._-]+")
MARK = "__EXPR__"


@dataclass(frozen=True)
class RunFacts:
    """What one `run:` text executes: repository paths (files or directories), the shell scripts among them (whose own
    text should be read too) and, when it could not be analyzed, why not."""

    files: tuple[str, ...] = ()
    scripts: tuple[str, ...] = ()
    problem: str = ""


class _Stop(Exception):
    pass


def _clean_path(raw: str, cwd: str) -> str | None:
    """The repository-relative path of `raw` resolved from `cwd`; None for a system path (absolute or `~`), and _Stop
    for anything that leaves the repository or has characters that are not plain path characters."""
    if MARK in raw or "$" in raw or "*" in raw or "?" in raw or "{" in raw or "[" in raw:
        raise _Stop(f"a path built at run time ({raw[:60]})")
    if raw.startswith(("/", "~")):
        return None
    joined = posixpath.normpath(posixpath.join(cwd or ".", raw))
    if joined == "." or joined == ".." or joined.startswith("../"):
        raise _Stop(f"a path outside the repository ({raw[:60]})")
    if not all(SAFE_PART.fullmatch(part) for part in joined.split("/")):
        raise _Stop(f"an unusual path ({raw[:60]})")
    return joined


def _path_like(token: str) -> bool:
    return "/" in token or token.endswith(SCRIPT_EXT)


def analyze(text: str, *, action_dir: str = "", workdir: str = "") -> RunFacts:
    """The files and scripts the shell text `text` executes, or the first problem. `action_dir` is what
    `github.action_path` stands for; `workdir` is the step's working directory (relative to the repository)."""
    try:
        files, scripts = _analyze(text, action_dir, workdir)
    except _Stop as why:
        return RunFacts(problem=str(why))
    return RunFacts(tuple(sorted(files)), tuple(sorted(scripts)))


def _analyze(text: str, action_dir: str, workdir: str) -> tuple[set[str], set[str]]:
    action = action_dir or "."
    text = WORKSPACE.sub(".", ACTION_PATH.sub(action, text))
    text = EXPRESSION.sub(MARK, text)
    text = re.sub(r"\\\n", " ", text)
    files: set[str] = set()
    scripts: set[str] = set()
    cwd = workdir
    for raw_line in text.split("\n"):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        for bad in ("<<", "`", "$(", "<(", ">("):
            if bad in line:
                raise _Stop(f"`{bad}` (a heredoc or a command built at run time)")
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            lexer.commenters = "#"
            tokens = list(lexer)
        except ValueError:
            raise _Stop("a quoted string spanning lines") from None
        cwd = _line(tokens, files, scripts, cwd, workdir)
    return files, scripts


def _line(tokens: list[str], files: set[str], scripts: set[str], cwd: str, workdir: str) -> str:
    command = True  # the next word is a command
    mode = ""  # what the words after this command mean
    pipe = False
    skip = False  # the word after a redirection is a file name, not a command
    after_wrapper = False
    prev = ""
    for token in tokens:
        if skip:
            skip = False
            continue
        if OPERATOR.fullmatch(token):
            if any(ch in token for ch in "<>"):
                skip = not token.endswith("&")
                continue
            pipe = "|" in token
            command, mode, after_wrapper = True, "", False
            continue
        if token in ("-exec", "-execdir", "-ok"):
            raise _Stop("`find -exec` (commands built at run time)")
        if command:
            if token in KEYWORDS or (ASSIGNMENT.match(token) and "/" not in token.split("=", 1)[0]):
                continue
            if posixpath.basename(token) in WRAPPERS:
                after_wrapper = True
                continue
            if after_wrapper and token.startswith("-"):
                continue
            after_wrapper = False
            base = posixpath.basename(token)
            if token in DYNAMIC or base in DYNAMIC:
                raise _Stop(f"`{base}` (commands built at run time)")
            if "$" in token or MARK in token:
                raise _Stop(f"a command built at run time ({token[:60]})")
            interpreter = base in SHELLS or base in OTHER_INTERPRETERS or PYTHON.fullmatch(base) is not None
            if pipe and interpreter:
                raise _Stop(f"a pipe into `{base}` (a script that is not in the repository)")
            command, pipe = False, False
            if base in ("cd", "pushd"):
                mode = "cd"
            elif base in MAKES:
                mode = "make"
                files.update(m if not cwd else posixpath.join(cwd, m) for m in MAKEFILES)
            elif interpreter:
                mode = "script:" + base
            elif _path_like(token):
                path = _clean_path(token, cwd)
                if path is not None:
                    files.add(path)
                    if path.endswith((".sh", ".bash")):
                        scripts.add(path)
            else:
                mode = ""
            prev = token
            continue
        # a word after a command
        if mode == "cd":
            target = _clean_path(token, cwd) if not token.startswith("-") else None
            if token.startswith("-"):
                continue
            if target is None:
                raise _Stop("a `cd` to a place it cannot follow")
            cwd, mode = target, ""
        elif mode == "make":
            if prev == "-f" or prev == "--file":
                path = _clean_path(token, cwd)
                if path is not None:
                    files.add(path)
        elif mode.startswith("script:"):
            mode = _script_word(mode[7:], token, prev, files, scripts, cwd)
        prev = token
    return cwd


def _script_word(interp: str, word: str, prev: str, files: set[str], scripts: set[str], cwd: str) -> str:
    """One word after an interpreter; returns the new mode ("" once the script, or module, was taken)."""
    mode = "script:" + interp
    if prev in ("-m",) and PYTHON.fullmatch(interp):
        _module(word, files, cwd)
        return ""
    if word.startswith("-"):
        code_flags: tuple[str, ...] = (
            ("-c",) if PYTHON.fullmatch(interp) else ("-e", "-E", "-p", "-r", "--eval", "--print")
        )
        if interp in SHELLS:
            code_flags = ()
        if (
            word == "-"
            or word in code_flags
            or (interp in SHELLS and re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", word) is not None)
        ):
            raise _Stop(f"`{interp} {word}` (code given on the command line)")
        return mode
    if prev in ("-W", "-X", "-o", "-O") and PYTHON.fullmatch(interp):
        return mode  # the value of an option, not the script
    if prev in ("-m",):
        return mode
    path = _clean_path(word, cwd)
    if path is not None:
        files.add(path)
        if interp in SHELLS or interp in ("source", ".") or path.endswith((".sh", ".bash")):
            scripts.add(path)
    return ""


def _module(name: str, files: set[str], cwd: str) -> None:
    """`python -m name`: a well-known tool is left alone; any other module may be repository code, so its file and
    package paths are listed (the caller compares them where they exist)."""
    if name.split(".")[0] in SAFE_MODULES:
        return
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", name):
        raise _Stop(f"a module name it cannot read ({name[:60]})")
    base = name.replace(".", "/")
    for candidate in (base + ".py", base):
        path = _clean_path(candidate, cwd)
        if path is not None:
            files.add(path)
