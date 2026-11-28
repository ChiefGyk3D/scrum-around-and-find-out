# SPDX-License-Identifier: Apache-2.0
"""A strict allowlist grammar for the `run:` steps of a gate workflow (issue #586).

`safo-ship` compares every repository file a gate's `run:` steps execute between the base branch and the pinned head,
because a pull request can change `ci/gate.sh` and leave the workflow untouched. Deriving "which files does this shell
text run?" from arbitrary shell is an open-ended class (every round finds one more construct), so this module does not
try. A `run:` text is accepted only when EVERY line is one of these forms; anything else is a problem that the
caller turns into NEEDS-HUMAN, naming the first offending line:

- blank, or a comment line (the first non-blank character is `#`);
- `cd DIR`: DIR a repo-relative literal path; it sets the directory of the lines after it (within this text only);
- `INTERPRETER [OPTION ...] SCRIPT [ARG ...]`: INTERPRETER is one of bash, sh, python, python3, node, ruby, perl, pwsh;
  each OPTION is a flag from that interpreter's short list of flags that take no value; SCRIPT is one repo-relative
  literal path; each ARG is a plain literal;
- `PATH [ARG ...]`: PATH a repo-relative executable path that contains a slash (`./ci/gate.sh`);
- `NAME [ARG ...]`: NAME one of the exact command names the operator listed (`--gate-command`); no file is derived from
  these, so the operator must also protect their inputs (`--protect-path`).

A line may use only the characters `A-Za-z0-9 . _ / = : @ , + -` and spaces: no quote, `$`, backtick, `;`, `&`, `|`,
`<`, `>`, parenthesis, brace, glob character, `~`, backslash, tab or `#` after the start. So there are no pipes, lists,
redirections, substitutions, expansions, heredocs or continuations to reason about. A PATH or SCRIPT has no empty, `.`
(except a leading `./`) or `..` part and does not start with `/`; an option with a value, a wrapper (`sudo`, `env`,
`timeout`, `uv run`...), `-c`/`-m`/`-e` and every unknown command are refused.

It is a gate by construction, at the price of more human stops. The caller applies the same grammar to the text of every
script found (from the directory it was run from) and to what those scripts run, down to a depth cap; `shebang_problem`
checks a script's first line. What it does not see: Makefile targets and the files a listed command uses,
configuration, installed dependencies, and what a Python or Node program imports.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass

SHELL_FLAGS = frozenset(
    {"-e", "-u", "-x", "-v", "-eu", "-ue", "-ex", "-xe", "-eux", "-uex", "-xeu", "-xue", "-uxe", "-exu"}
    | {"--noprofile", "--norc"}
)
PYTHON_FLAGS = frozenset({"-u", "-B", "-E", "-s", "-S", "-I", "-O", "-OO", "-q", "-b", "-bb", "-d", "-v"})
INTERPRETERS: dict[str, frozenset[str]] = {
    "bash": SHELL_FLAGS,
    "sh": SHELL_FLAGS,
    "python": PYTHON_FLAGS,
    "python3": PYTHON_FLAGS,
    "node": frozenset({"--no-warnings", "--trace-warnings", "--enable-source-maps"}),
    "ruby": frozenset({"-w"}),
    "perl": frozenset({"-w"}),
    "pwsh": frozenset({"-NoProfile", "-NonInteractive", "-NoLogo"}),
}
LINE_CHARS = re.compile(r"[A-Za-z0-9._/=:@, +-]*")
PLAIN_ARG = re.compile(r"[A-Za-z0-9._/=:@,+-]+")
PATH = re.compile(r"[A-Za-z0-9._/-]+")
OPTION = re.compile(r"-{1,2}[A-Za-z0-9][A-Za-z0-9_-]*")
COMMAND_NAME = re.compile(r"[A-Za-z0-9._+-]+")


@dataclass(frozen=True)
class RunFacts:
    """The repository files a `run:` text executes (sorted), the directory each one is run from, or the first line
    that is not in the grammar."""

    files: tuple[str, ...] = ()
    problem: str = ""
    runs: tuple[tuple[str, str], ...] = ()  # (file, directory it is run from), sorted


class _Stop(Exception):
    pass


def valid_command_name(name: str) -> bool:
    """A name that `--gate-command` may list: plain characters, no slash, not an option."""
    return COMMAND_NAME.fullmatch(name) is not None and not name.startswith("-") and name not in INTERPRETERS


def _literal_path(word: str, cwd: str) -> str:
    """The repository path of a literal path word resolved from `cwd`, or _Stop."""
    if not PATH.fullmatch(word) or word.startswith(("/", "-")):
        raise _Stop("not a repository-relative literal path")
    parts = word.split("/")
    if parts[0] == ".":
        parts = parts[1:]
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise _Stop("a path with an empty, `.` or `..` part")
    return posixpath.join(cwd, *parts) if cwd else "/".join(parts)


SHEBANG = re.compile(r"#!(?:/usr/bin/env |/usr/bin/|/bin/)([A-Za-z0-9._-]+)")


def shebang_problem(text: str) -> str:
    """ "" when the first line is not a shebang or names an allowed interpreter (as /bin/NAME, /usr/bin/NAME or
    /usr/bin/env NAME, with no arguments), else why not."""
    first = text.split("\n", 1)[0].rstrip("\r")
    if not first.startswith("#!"):
        return ""
    found = SHEBANG.fullmatch(first)
    if found is None or found.group(1) not in INTERPRETERS:
        return f"a shebang line that is not an allowed interpreter ({first[:60]})"
    return ""


def analyze(text: str, *, commands: Iterable[str] = (), cwd: str = "") -> RunFacts:
    """The files a `run:` text executes, if every line is in the grammar; else the first offending line as `problem`.
    `cwd` is the directory the text runs from (the repository root for a `run:` step)."""
    allowed = frozenset(commands)
    files: set[str] = set()
    runs: set[tuple[str, str]] = set()
    for number, raw in enumerate(text.split("\n"), 1):
        line = raw.rstrip("\r").strip(" ")
        if not line or line.startswith("#"):
            continue
        try:
            if LINE_CHARS.fullmatch(line) is None:
                raise _Stop("a character outside A-Za-z0-9 . _ / = : @ , + - and spaces")
            cwd = _simple_line([w for w in line.split(" ") if w], cwd, allowed, files, runs)
        except _Stop as why:
            return RunFacts(problem=f"line {number} ({line[:80]}): {why}")
    return RunFacts(files=tuple(sorted(files)), runs=tuple(sorted(runs)))


def _simple_line(
    words: list[str], cwd: str, allowed: frozenset[str], files: set[str], runs: set[tuple[str, str]]
) -> str:
    command, rest = words[0], words[1:]
    if command == "cd":
        if len(rest) != 1:
            raise _Stop("`cd` takes exactly one literal directory")
        return _literal_path(rest[0], cwd)
    if command in INTERPRETERS:
        flags = INTERPRETERS[command]
        index = 0
        while index < len(rest) and rest[index].startswith("-"):
            if OPTION.fullmatch(rest[index]) is None or rest[index] not in flags:
                raise _Stop(f"an option of `{command}` that is not on the list of flags without a value")
            index += 1
        if index >= len(rest):
            raise _Stop(f"`{command}` without a script path")
        script = _literal_path(rest[index], cwd)
        files.add(script)
        runs.add((script, cwd))
        _plain_args(rest[index + 1 :])
        return cwd
    if "/" in command:
        script = _literal_path(command, cwd)
        files.add(script)
        runs.add((script, cwd))
        _plain_args(rest)
        return cwd
    if command in allowed and valid_command_name(command):
        _plain_args(rest)
        return cwd
    raise _Stop(f"the command `{command[:40]}` is not an interpreter, a repository path or a listed command")


def _plain_args(args: list[str]) -> None:
    for arg in args:
        if PLAIN_ARG.fullmatch(arg) is None:
            raise _Stop("an argument that is not a plain literal")
