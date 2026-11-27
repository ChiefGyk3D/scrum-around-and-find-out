# SPDX-License-Identifier: Apache-2.0
"""safo-runner-check: flag a local full suite or mutation sweep and print the ra-remote command instead (#485).

    safo-runner-check [--strict] [--repo DIR] (--command LINE | --brief FILE|-)

Heavy work on a PUBLIC repo goes to the runner (`ra-remote`); targeted checks stay local. The check only prints advice:
it never runs ra-remote and never contacts the runner. It fails closed: anything it cannot prove public is kept local.

A repo is public only when EVERY remote (`git remote -v`) is a github.com owner/name URL (https, ssh, scp-like; the host
is parsed, userinfo is never echoed), no name on the denylist matches, and either the repo is on the repo allowlist
(`SAFO_PUBLIC_REPOS`, else the file `public-repos`) or, with no allowlist, its owner is on the owner list
(`SAFO_PUBLIC_OWNERS`, else the file `public-owners`). The denylist (built-in names plus the file `runner-never`) always
wins. A set-but-empty allowlist means no repo is public. Any git transport override means "cannot tell". Config files
live in the safo config dir; the whole path must be free of symlinks and owner-only. A content gate (untracked files,
nested git dirs, symlinks leaving the tree, secret-looking names) keeps a dirty public worktree local. Advice is given
only for a worktree under a folder
`ra-remote` allows. `--strict` exits 1 only when a public repo runs a full suite or sweep locally. Before it suggests a
command it proves that HEAD is published: one anonymous `git ls-remote` of the validated github.com URL (the
only network use).
One metrics line per check goes to `$XDG_STATE_HOME/safo/runner-check.jsonl` (class, decision, repo class; no command).
"""

from __future__ import annotations

import argparse
import contextlib
import fnmatch
import hashlib
import json
import os
import re
import select
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO
from urllib.parse import urlsplit

FULL = "full-suite"
MUTATION = "mutation"
INLINE = re.compile(r"`([^`\n]+)`")
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
SCP_LIKE = re.compile(r"^(?:[^@/:\s]+@)?([^@/:\s]+):([^/\s][^\s]*)$")
REMOTE_LINE = re.compile(r"^(\S+)\t(.+) \((?:fetch|push)\)$")
PUBLIC_HOST = "github.com"
SWEEPS = frozenset({"mutmut", "cosmic-ray", "stryker"})
NODE_MANAGERS = frozenset({"npm", "pnpm", "yarn"})
SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh"})
PYTEST_SELECT = ("--lf", "--last-failed", "--ff", "--failed-first")
PYTEST_INFO = frozenset(
    {"--version", "-V", "--help", "-h", "--collect-only", "--co", "--fixtures", "--markers", "--setup-plan"}
)
PYTEST_VALUE_OPTS = frozenset(
    {
        "--deselect",
        "--ignore",
        "--ignore-glob",
        "--junitxml",
        "--junit-xml",
        "-p",
        "--rootdir",
        "--confcutdir",
        "--cov",
        "--cov-report",
        "--cov-config",
        "-c",
        "-o",
        "-m",
        "-W",
        "-n",
        "--tb",
        "--maxfail",
        "--durations",
        "--log-level",
        "--color",
        "--import-mode",
        "--basetemp",
        "--override-ini",
        "--numprocesses",
        "-r",
    }
)
TOOL_INFO = frozenset({"--version", "--help", "-h", "-l", "--listenvs", "--list", "-V"})
UV_VALUE_OPTS = frozenset({"--with", "-p", "--python", "--extra", "--group", "--project", "--directory", "--env-file"})
XARGS_VALUE_OPTS = frozenset({"-I", "-n", "-P", "-L", "-d", "-s", "-E", "-a"})
GO_VALUE_OPTS = frozenset({"-count", "-timeout", "-tags", "-p", "-parallel", "-cpu", "-bench", "-coverprofile", "-o"})
CARGO_VALUE_OPTS = frozenset(
    {"-p", "--package", "--features", "-F", "--target", "-j", "--jobs", "--manifest-path", "--profile", "--exclude"}
    | {"--bin", "--example", "--bench", "--target-dir", "--color", "--test"}
)
MAKE_VALUE_OPTS = frozenset({"-C", "-f", "-j", "-I", "-o", "-W"})
WALK_LIMIT = 200_000
FILE_LIMIT = 100 * 1024 * 1024
TOTAL_LIMIT = 1024 * 1024 * 1024
READ_CHUNK = 1024 * 1024
SHELL_DEPTH_LIMIT = 4
WRAPPER_LIMIT = 10
TOO_DEEP = "nesting too deep to read: treat as a local full suite"
RISKY_NAME_PATTERNS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa*",
    "id_ed25519*",
    "*.p12",
    "*.pfx",
    "*.kdbx",
    ".netrc",
    "credentials*",
    "*secret*",
)
TRANSPORT_ENV = ("GIT_SSH", "GIT_SSH_COMMAND", "GIT_PROXY_COMMAND")
TRANSPORT_QUERY = (
    r"^(core\.sshcommand|core\.gitproxy|core\.askpass|protocol\..*|http\..*proxy|http\.proxy"
    r"|remote\..*\.(vcs|proxy|pushurl)|url\..*\.(insteadof|pushinsteadof)|include.*|credential\..*)$"
)
NON_RUNNER_HEADS = frozenset(
    {"pip", "pip3", "which", "echo", "printf", "grep", "rg", "cat", "less", "ls", "ssh", "scp", "git"}
    | {"apt", "apt-get", "brew", "man", "type"}
)
KNOWN_HEADS = frozenset(
    {"pytest", "py.test", "vitest", "jest", "make", "tox", "nox", "go", "cargo", "mvn", "mvnw", "gradle", "gradlew"}
    | {"unittest", "ra-remote"}
    | SWEEPS
    | NODE_MANAGERS
    | SHELLS
)
FALLBACK_FULL = frozenset({"pytest", "vitest", "jest", "tox", "nox", "unittest"})
FALLBACK_TEST_AFTER = frozenset({"make", "npm", "pnpm", "yarn", "cargo", "go", "mvn", "gradle"})
DEV_FOLDERS = (
    ".local/share/reach-around-dev",
    ".local/share/safo-dev/agents",
    ".local/share/chatty-kathy-dev",
)
# Names that never go to the runner, whatever the owner. The file `runner-never` extends this list.
BUILTIN_NEVER = (
    "*-instance",
    "reach-around-instance",
    "*brand*",
    "*dotfiles*",
    "*ai-shit*",
    "*lead*",
    "*notes*",
    "*private*",
    "*secret*",
    "*homelab-identity*",
)


@dataclass(frozen=True)
class Finding:
    klass: str
    command: str
    wrapped: bool
    simple: bool = False
    argv: tuple[str, ...] = ()
    note: str = ""


class _TooDeep(Exception):
    """A bound was reached while reading a command: ambiguous, so it counts as a full suite (fail closed)."""


def _tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _split(command: str) -> tuple[list[str], bool]:
    """Quote-aware split into segments; also report whether the line is more than one plain command."""
    segs: list[str] = []
    cur: list[str] = []
    quote = ""
    unsafe = False
    i, n = 0, len(command)

    def flush() -> None:
        text = "".join(cur).strip()
        cur.clear()
        if text:
            segs.append(text)

    while i < n:
        c = command[i]
        nxt = command[i + 1] if i + 1 < n else ""
        if quote == "'":
            cur.append(c)
            quote = "" if c == "'" else quote
        elif quote == '"':
            if c == "\\" and nxt:
                cur.append(c + nxt)
                i += 2
                continue
            unsafe = unsafe or c == "`" or c == "$"
            cur.append(c)
            quote = "" if c == '"' else quote
        elif c in "'\"":
            quote = c
            cur.append(c)
        elif c == "\\":
            unsafe = True
            cur.append(c + nxt)
            i += 2
            continue
        elif c == "$" and nxt == "(":
            unsafe = True
            flush()
            i += 2
            continue
        elif c == "$" or c in "<>":
            unsafe = True
            cur.append(c)
        elif c in "&;|\n()`":
            unsafe = unsafe or c != "\n"
            flush()
        else:
            cur.append(c)
        i += 1
    flush()
    return segs, unsafe or len(segs) > 1 or quote != ""


def _drop_options(ws: list[str], value_opts: frozenset[str]) -> list[str]:
    """What follows a wrapper's own options and an optional `--` end-of-options marker."""
    i = 0
    while i < len(ws) and ws[i].startswith("-") and ws[i] != "--":
        i += 2 if ws[i] in value_opts else 1
    return ws[i + 1 :] if i < len(ws) and ws[i] == "--" else ws[i:]


def _command_words(words: Sequence[str]) -> list[str]:
    """Strip env assignments and known wrappers (their options and a `--` marker); return the real command words."""
    ws = list(words)
    for _ in range(WRAPPER_LIMIT + 1):
        while ws and ASSIGN.match(ws[0]):
            ws.pop(0)
        if not ws:
            return ws
        base, rest = Path(ws[0]).name, ws[1:]
        if base == "command" and {"-v", "-V"} & set(rest[:2]):
            return []  # a lookup, nothing runs
        if base in {"nohup", "command", "builtin", "setsid", "unbuffer"}:
            ws = _drop_options(rest, frozenset())
        elif base == "time":
            ws = _drop_options(rest, frozenset({"-f", "-o", "--format", "--output"}))
        elif base == "exec":
            ws = _drop_options(rest, frozenset({"-a"}))
        elif base == "nice":
            ws = _drop_options(rest, frozenset({"-n", "--adjustment"}))
        elif base == "ionice":
            ws = _drop_options(rest, frozenset({"-c", "-n", "-p", "-P", "-u", "--class", "--classdata"}))
        elif base == "stdbuf":
            ws = _drop_options(rest, frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}))
        elif base == "timeout":
            rest = _drop_options(rest, frozenset({"-s", "-k", "--signal", "--kill-after"}))
            ws = _drop_options(rest[1:], frozenset())  # the duration, then an optional `--`
        elif base in {"taskset", "chrt", "flock"}:
            opts = {
                "taskset": frozenset(),
                "chrt": frozenset({"-T", "-P", "-D"}),
                "flock": frozenset({"-w", "-E", "--timeout", "--conflict-exit-code"}),
            }[base]
            rest = _drop_options(rest, opts)  # mask, priority or lock file
            ws = _drop_options(rest[1:], frozenset())
        elif base == "xvfb-run":
            ws = _drop_options(rest, frozenset({"-e", "-f", "-n", "-s", "-w", "--error-file", "--auth-file"}))
        elif base == "env":
            ws = _drop_options(rest, frozenset({"-u", "-C", "-S", "--unset", "--chdir", "--split-string"}))
        elif base in {"uv", "poetry", "pipenv", "pdm", "hatch"} and rest[:1] == ["run"]:
            ws = _drop_options(rest[1:], UV_VALUE_OPTS)
        elif base == "yarn" and rest[:1] == ["run"]:
            after = _drop_options(rest[1:], frozenset())
            if after and (after[0] in {"test", "t"} or after[0].startswith("test:")):
                return ws  # a package script named test, handled as a node script
            ws = after
        elif base in {"npx", "bunx"}:
            ws = _drop_options(rest, frozenset())
        elif base in {"pnpm", "npm"} and rest[:1] in (["exec"], ["dlx"]):
            ws = _drop_options(rest[1:], frozenset())
        elif base == "xargs":
            ws = _drop_options(rest, XARGS_VALUE_OPTS)
        elif re.fullmatch(r"python[0-9.]*", base):
            j = 0
            while j < len(rest) and rest[j].startswith("-") and rest[j] != "-m":
                j += 1
            if j + 1 < len(rest) and rest[j] == "-m":
                ws = rest[j + 1 :]
            else:
                return ws
        else:
            return ws
    raise _TooDeep  # still unwrapping after the bound: what runs is unknown


def _fail_closed(ws: Sequence[str]) -> tuple[str, bool] | None:
    """An unknown head that still carries a suite or sweep name is treated as a local run (false positives accepted)."""
    base = Path(ws[0]).name
    if base in NON_RUNNER_HEADS or (base == "uv" and ws[1:2] == ["pip"]):
        return None
    later = ws[1:]
    if SWEEPS & set(later):
        return MUTATION, False
    if FALLBACK_FULL & set(later):
        return FULL, False
    for i, word in enumerate(later):
        if word in FALLBACK_TEST_AFTER and "test" in later[i + 1 :]:
            return FULL, False
    return None


def _pytest_kind(args: Sequence[str]) -> str:
    skip = False
    targeted = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in PYTEST_INFO:
            return "info"
        if arg in PYTEST_SELECT or arg.startswith("-k"):
            targeted = True
            skip = arg == "-k"
            continue
        if arg.startswith("-"):
            skip = arg in PYTEST_VALUE_OPTS
            continue
        if "::" in arg or arg.endswith(".py"):
            targeted = True
    return "targeted" if targeted else "full"


def _positionals(args: Sequence[str], value_opts: frozenset[str]) -> list[str]:
    found: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg.startswith("-"):
            skip = arg in value_opts
        else:
            found.append(arg)
    return found


def _node_script(rest: list[str]) -> str:
    args = [a for a in rest if not a.startswith("-")]
    if args[:1] in (["run"], ["run-script"]) and len(args) > 1:
        return args[1]
    return args[0] if args else ""


def _tool_class(base: str, rest: list[str]) -> str | None:
    """Full-suite class for a non-pytest tool, or None."""
    if base in SWEEPS:
        return MUTATION
    if base in {"vitest", "jest"}:
        return None if _positionals(rest, frozenset()) not in ([], ["run"]) else FULL
    if base in NODE_MANAGERS:
        script = _node_script(rest)
        return FULL if script in {"test", "t"} or script.startswith("test:") else None
    if base == "make":
        return FULL if {"test", "check"} & set(_positionals(rest, MAKE_VALUE_OPTS)) else None
    if base in {"tox", "nox"}:
        return None if TOOL_INFO & set(rest) else FULL
    if base == "go" and rest[:1] == ["test"]:
        args = rest[1:]
        if any(a.split("=")[0] in {"-run", "-fuzz"} for a in args):
            return None
        pos = _positionals(args, GO_VALUE_OPTS)
        return FULL if not pos or any(p.endswith("...") for p in pos) else None
    if base == "cargo" and rest[:1] == ["test"]:
        args = rest[1:]
        return None if "--test" in args or _positionals(args, CARGO_VALUE_OPTS) else FULL
    if base in {"mvn", "mvnw"}:
        return FULL if "test" in rest and not any(a.startswith("-Dtest") for a in rest) else None
    if base in {"gradle", "gradlew"}:
        return FULL if "test" in rest and "--tests" not in rest else None
    if base == "unittest":
        pos = _positionals(rest, frozenset())
        return FULL if "-k" not in rest and (not pos or pos[0] == "discover") else None
    return None


def _classify_words(words: Sequence[str], depth: int) -> tuple[str, bool] | None:
    ws = _command_words(words)
    if not ws:
        return None
    if depth > SHELL_DEPTH_LIMIT:
        raise _TooDeep
    base, rest = Path(ws[0]).name, ws[1:]
    if base == "ra-remote":
        inner = rest[rest.index("--") + 1 :] if "--" in rest else []
        found = _classify_words(inner, depth + 1) if inner else None
        return (found[0], True) if found else None
    if base in SHELLS:
        for k, word in enumerate(rest[:-1]):
            if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", word):
                hits = classify(rest[k + 1], depth + 1)
                return (hits[0].klass, hits[0].wrapped) if hits else None
        return None
    if base in {"pytest", "py.test"}:
        return (FULL, False) if _pytest_kind(rest) == "full" else None
    klass = _tool_class(base, rest)
    if klass:
        return klass, False
    return None if base in KNOWN_HEADS else _fail_closed(ws)


def classify(command: str, depth: int = 0) -> list[Finding]:
    segs, unsafe = _split(command)
    simple = not unsafe
    out: list[Finding] = []
    for seg in segs:
        words = _tokens(seg)
        try:
            hit = _classify_words(words, depth)
        except _TooDeep:
            if depth:
                raise  # the outermost call reports it, once
            out.append(Finding(FULL, seg, False, simple, tuple(words), TOO_DEEP))
            continue
        if hit:
            out.append(Finding(hit[0], seg, hit[1], simple, tuple(words)))
    return out


def commands_from_brief(text: str) -> list[str]:
    commands: list[str] = []
    fenced = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            commands.append(stripped)
        elif stripped.startswith("$ "):
            commands.append(stripped[2:])
        else:
            commands.extend(INLINE.findall(line))
    return [c for c in commands if c]


def _normalize(segment: str) -> str:
    """NFKC, lowercase, trailing slashes, dots and spaces stripped, `.git` suffixes removed until stable."""
    text = unicodedata.normalize("NFKC", segment).lower()
    while True:
        short = text.rstrip("/. ").removesuffix(".git")
        if short == text:
            return text
        text = short


def _raw_pair(path: str) -> tuple[str, str] | None:
    parts = path.strip("/").split("/")
    if len(parts) != 2 or not all(p.isascii() and SEGMENT.fullmatch(p) for p in parts):
        return None  # non-ASCII names are never trusted
    return parts[0].lower(), parts[1].lower()


def _raw_remote(url: str) -> tuple[str, str] | None:
    url = url.strip()
    if "://" in url:
        try:
            parts = urlsplit(url)
            host = parts.hostname
        except ValueError:
            return None
        if parts.scheme not in {"https", "ssh", "git"} or host != PUBLIC_HOST or parts.query or parts.fragment:
            return None
        return _raw_pair(parts.path)
    match = SCP_LIKE.match(url)
    if match is None or match.group(1).lower() != PUBLIC_HOST:
        return None
    return _raw_pair(match.group(2))


def parse_remote(url: str) -> tuple[str, str] | None:
    """Normalized (owner, name) for a github.com https, ssh or scp-like URL; None for any other host or shape."""
    raw = _raw_remote(url)
    if raw is None:
        return None
    owner, name = _normalize(raw[0]), _normalize(raw[1])
    return (owner, name) if owner and name else None


def remote_owner(url: str) -> str | None:
    parsed = parse_remote(url)
    return parsed[0] if parsed else None


def _config_dir(env: Mapping[str, str]) -> Path | None:
    chosen = env.get("XDG_CONFIG_HOME", "")
    if chosen and Path(chosen).is_absolute():
        return Path(chosen) / "safo"
    home = env.get("HOME", "")
    return Path(home) / ".config" / "safo" if home else None


def _owner_only(info: os.stat_result, *, directory: bool) -> bool:
    kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    return kind and info.st_uid == os.geteuid() and not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def _same_file(first: os.stat_result, second: os.stat_result) -> bool:
    """True when two stat results describe the same file in the same state. The inode number alone is not enough:
    a filesystem may reuse a freed inode at once, so size, mtime and ctime are compared as well."""
    return (
        first.st_ino,
        first.st_dev,
        first.st_mode,
        first.st_size,
        first.st_mtime_ns,
        first.st_ctime_ns,
    ) == (
        second.st_ino,
        second.st_dev,
        second.st_mode,
        second.st_size,
        second.st_mtime_ns,
        second.st_ctime_ns,
    )


def _ancestry(path: Path, home: str) -> bool | None:
    """Walk every component from the root with lstat. False: a symlink, `..`, or a bad ancestor below home.
    None: a component is missing (nothing to read). True: clean."""
    if not path.is_absolute() or ".." in path.parts:
        return False
    here = Path(path.anchor)
    below_home = False
    for part in path.parts[1:]:
        here = here / part
        try:
            info = os.lstat(here)
        except FileNotFoundError:
            return None
        except OSError:
            return False
        if stat.S_ISLNK(info.st_mode) or (not stat.S_ISDIR(info.st_mode) and here != path):
            return False
        if below_home and (info.st_uid != os.geteuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            return False
        if home and str(here) == home:
            below_home = True
    return True


def _config_lines(env: Mapping[str, str], name: str) -> tuple[str, list[str]]:
    """(status, lowercased entries); status is ok, absent, or bad (symlink, wrong owner or mode, or a race)."""
    cfg = _config_dir(env)
    if cfg is None:
        return "absent", []
    path = cfg / name
    home = env.get("HOME", "")
    walk = _ancestry(path, home)
    if walk is None:
        return "absent", []
    if not walk:
        return "bad", []
    try:
        info = os.lstat(path)
        if not (_owner_only(os.lstat(cfg), directory=True) and _owner_only(info, directory=False)):
            return "bad", []
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, encoding="utf-8") as handle:
            now = os.fstat(handle.fileno())
            if not (_same_file(now, info) and _owner_only(now, directory=False)):
                return "bad", []
            text = handle.read()
    except FileNotFoundError:
        return "absent", []
    except (OSError, UnicodeDecodeError):
        return "bad", []
    lines = [ln.strip().lower() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    return "ok", lines


def _setting(env: Mapping[str, str], var: str, name: str) -> tuple[str, list[str]]:
    """The variable wins when it is SET (even empty); else the file. An empty list is still a list."""
    if var in env:
        return "ok", [o.strip().lower() for o in env[var].split(",") if o.strip()]
    return _config_lines(env, name)


def public_owners(env: Mapping[str, str]) -> set[str]:
    status, lines = _setting(env, "SAFO_PUBLIC_OWNERS", "public-owners")
    return set(lines) if status == "ok" else set()


def _git_env(env: Mapping[str, str]) -> dict[str, str]:
    genv = dict(env)
    genv.setdefault("PATH", os.environ.get("PATH", ""))
    genv["GIT_TERMINAL_PROMPT"] = "0"
    return genv


def _git_run(repo: Path, env: Mapping[str, str], *args: str) -> subprocess.CompletedProcess[bytes] | None:
    """Git with the caller's effective configuration: for questions about where a remote points."""
    return _spawn(repo, _git_env(env), args)


def _spawn(
    repo: Path, genv: dict[str, str], args: Sequence[str], data: bytes | None = None
) -> subprocess.CompletedProcess[bytes] | None:
    git = shutil.which("git")
    if git is None:
        return None
    try:
        return subprocess.run(  # noqa: S603 - fixed git argv, no shell
            [git, "-C", str(repo), *args],
            capture_output=True,
            timeout=30,
            check=False,
            env=genv,
            input=data,
            stdin=None if data is not None else subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _git(repo: Path, env: Mapping[str, str], *args: str) -> str:
    done = _git_run(repo, env, *args)
    if done is None or done.returncode != 0:
        return ""
    return done.stdout.decode("utf-8", errors="replace").strip()


# Mirrors `git_list` in ra-remote (the one function that selects the files it copies): the environment names
# GIT_CONFIG_GLOBAL=/dev/null and GIT_CONFIG_NOSYSTEM=1, ra-remote first unsets every other GIT_* variable, and the
# command carries these -c overrides. Nothing outside the worktree may decide which files are listed.
#
# The same calls also decide ancestry for the published-HEAD proof, so every local history-rewriting feature is off:
# replace refs (`--no-replace-objects`, core.useReplaceRefs, GIT_NO_REPLACE_OBJECTS), grafts (GIT_GRAFT_FILE points at
# an empty file), the commit-graph file, and alternate-ref commands.
SELECTION_CONFIG = (
    "core.fsmonitor=false",
    "core.untrackedCache=false",
    "core.excludesFile=/dev/null",
    "core.hooksPath=/dev/null",
    "core.useReplaceRefs=false",
    "core.commitGraph=false",
    "core.alternateRefsCommand=",
    "advice.graftFileDeprecated=false",
)


def _git_for_selection(
    repo: Path, env: Mapping[str, str], *args: str, data: bytes | None = None
) -> subprocess.CompletedProcess[bytes] | None:
    """Every git call that lists or inspects the files ra-remote would copy goes through here."""
    genv = {k: v for k, v in _git_env(env).items() if not k.startswith("GIT_")}
    genv["GIT_TERMINAL_PROMPT"] = "0"
    genv["GIT_CONFIG_GLOBAL"] = "/dev/null"
    genv["GIT_CONFIG_NOSYSTEM"] = "1"
    genv["GIT_NO_REPLACE_OBJECTS"] = "1"
    genv["GIT_GRAFT_FILE"] = "/dev/null"
    flags = [word for pair in SELECTION_CONFIG for word in ("-c", pair)]
    return _spawn(repo, genv, ["--no-replace-objects", *flags, *args], data)


def _git_z(repo: Path, env: Mapping[str, str], *args: str) -> list[str] | None:
    """NUL-separated output of a selection call as a list; None when git failed."""
    done = _git_for_selection(repo, env, *args, "-z")
    if done is None or done.returncode != 0:
        return None
    return [e.decode("utf-8", errors="surrogateescape") for e in done.stdout.split(b"\0") if e]


def _remote_urls(repo: Path, env: Mapping[str, str]) -> list[str] | None:
    """Every remote URL (fetch and push); None when a line cannot be read."""
    urls: list[str] = []
    for line in _git(repo, env, "remote", "-v").splitlines():
        match = REMOTE_LINE.match(line)
        if match is None:
            return None
        urls.append(match.group(2))
    return urls


def _override_name(key: str) -> str | None:
    k = key.lower()
    if k in {"core.sshcommand", "core.gitproxy"}:
        return k
    hit = re.fullmatch(r"remote\..+\.(vcs|proxy|pushurl)", k)
    if hit:
        return f"remote.*.{hit.group(1)}"
    hit = re.fullmatch(r"url\..+\.(insteadof|pushinsteadof)", k)
    if hit:
        return f"url.*.{hit.group(1)}"
    if k == "include.path":
        return k
    if k == "http.proxy" or re.fullmatch(r"http\..+\.proxy", k):
        return "http.proxy"  # the URL part of http.<url>.proxy is never shown; credential.* is left out on purpose
    if k.startswith("protocol."):
        return "protocol.*"
    if k.startswith("includeif."):
        return "includeIf gitdir" if k.startswith("includeif.gitdir") else "includeIf"
    return None


def env_override(env: Mapping[str, str]) -> str | None:
    for var in TRANSPORT_ENV:
        if var in env:
            return var
    return "GIT_CONFIG_*" if any(k.startswith("GIT_CONFIG_") for k in env) else None


def transport_override(repo: Path, env: Mapping[str, str]) -> str | None:
    """The key (never a value) of the first setting that can change where a remote really points."""
    done = _git_run(repo, env, "config", "--show-origin", "-z", "--get-regexp", TRANSPORT_QUERY)
    if done is None or done.returncode not in (0, 1):
        return "git config (unreadable)"
    entries = done.stdout.decode("utf-8", errors="replace").split("\0")
    for entry in entries[1::2]:
        name = _override_name(entry.split("\n", 1)[0])
        if name:
            return name
    return None


def _denied(owner: str, name: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) or fnmatch.fnmatchcase(f"{owner}/{name}", p) for p in patterns)


def repo_class(repo: Path, env: Mapping[str, str]) -> tuple[str, str]:
    """(public | private | unknown, the rule that decided)."""
    env_name = env_override(env)
    if env_name:
        return "unknown", f"git transport is overridden (setting {env_name})"
    urls = _remote_urls(repo, env)
    if not urls:
        return "unknown", "no git remote" if urls == [] else "a remote line could not be read"
    raws = [_raw_remote(u) for u in urls]
    pairs = [parse_remote(u) for u in urls]
    if any(r is None for r in raws) or any(p is None for p in pairs):
        return "unknown", f"a remote is not an ASCII {PUBLIC_HOST} owner/name URL"
    override = transport_override(repo, env)
    if override:
        return "unknown", f"git transport is overridden (setting {override})"
    extra_s, extra = _config_lines(env, "runner-never")
    allow_s, allow = _setting(env, "SAFO_PUBLIC_REPOS", "public-repos")
    owners_s, owners = _setting(env, "SAFO_PUBLIC_OWNERS", "public-owners")
    if "bad" in (extra_s, allow_s, owners_s):
        return "unknown", "a safo config file is not owner-only (or sits under a symlink)"
    patterns = [*BUILTIN_NEVER, *extra]
    checked = [p for p in pairs if p is not None] + [r for r in raws if r is not None]
    for owner, name in checked:
        if _denied(owner, name, patterns):
            return "private", f"denylist match: {owner}/{name}"
    clean = [p for p in pairs if p is not None]
    if allow_s == "ok":  # a present allowlist, even an empty one, switches owner trust off
        if all(f"{o}/{n}" in allow for o, n in clean):
            return "public", "public: listed in the repo allowlist, no denylist match"
        return "private", "not in the repo allowlist"
    if not owners:
        return "unknown", "no repo allowlist and no owner list"
    if all(o in owners for o, _ in clean):
        return "public", "public: owner listed, no denylist match"
    return "private", "owner is not on the public list"


@dataclass(frozen=True)
class ContentGate:
    untracked: int = 0
    nested: int = 0
    symlinks: int = 0
    risky_names: int = 0
    incomplete: bool = False
    modified: int = 0
    filtered: bool = False
    bounded: bool = False
    unpublished: str = ""  # the refusal text of the published-HEAD proof; empty when HEAD is proved public

    def refusal(self) -> str | None:
        parts = [t for t in (self.unpublished, self._differs(), self._unverifiable(), self._copies()) if t]
        return "\n  ".join(parts) or None

    def _differs(self) -> str:
        if not self.modified:
            return ""
        return (
            f"keep local: {self.modified} tracked files differ from the public commit (modified, staged, "
            "intent-to-add, assume-unchanged, skip-worktree, a changed mode or link, a missing or extra path, or a "
            "submodule); commit or discard them first"
        )

    def _unverifiable(self) -> str:
        texts = []
        if self.filtered:
            texts.append("cannot tell: content filters are configured (filter): the runner copies raw bytes")
        if self.bounded:
            texts.append(
                "cannot verify the copied bytes (size or entry bound): a file over 100 MB, a tree over 1 GB, "
                f"or more than {WALK_LIMIT} entries"
            )
        return "\n  ".join(f"keep local: {t}" for t in texts)

    def _copies(self) -> str:
        if not (self.untracked or self.nested or self.symlinks or self.risky_names or self.incomplete):
            return ""
        text = (
            "keep local: the worktree holds files the runner would copy that are not in the public repository "
            f"({self.untracked} untracked files; {self.nested} nested git directories; "
            f"{self.symlinks} symlinks leaving the tree)"
        )
        if self.risky_names:
            text += f"; secret-looking file names present ({self.risky_names})"
        if self.incomplete:
            text += f"; the tree could not be fully checked (more than {WALK_LIMIT} entries, or unreadable)"
        return text + f". Commit them, add them to .gitignore, or clone a clean copy under ~/{DEV_FOLDERS[0]} first"


LISTING_SECONDS = 20
LISTING_BYTES = 1024 * 1024
KILL_GRACE_SECONDS = 1
LISTING_REFS = 20000
LOCAL_TIP_LIMIT = 200  # existing local tips tried for the ancestry test; more is refused ("cannot tell")
LISTING_LINE = re.compile(r"([0-9a-f]{40}|[0-9a-f]{64})[ \t](refs/(?:heads|tags)/\S+)")


class ProofError(Exception):
    """The publication proof could not be made. `klass` is a fixed word; never the URL, output or error text."""

    def __init__(self, klass: str) -> None:
        super().__init__(klass)
        self.klass = klass


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    """SIGTERM the whole process group (git and its transport helpers), a short grace period, then SIGKILL; reap."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, sig)
        try:
            proc.wait(timeout=KILL_GRACE_SECONDS if sig == signal.SIGTERM else 5)
            break
        except subprocess.TimeoutExpired:
            continue
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)  # helpers that outlived the leader


def _listing_output(argv: list[str], genv: Mapping[str, str], home: str) -> bytes:
    """Run the listing in its own session; read at most LISTING_BYTES within LISTING_SECONDS.

    Any failure (timeout, size cap, error) kills the whole process group and is mapped to a fixed ProofError class."""
    try:
        proc = subprocess.Popen(  # noqa: S603 - fixed git argv built from validated names, no shell
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=dict(genv),
            cwd=home,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise ProofError("network") from None
    if proc.stdout is None:
        _kill_group(proc)
        raise ProofError("network")
    deadline = time.monotonic() + LISTING_SECONDS
    chunks: list[bytes] = []
    total = 0
    try:
        fd = proc.stdout.fileno()
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise ProofError("timeout")
            if not select.select([fd], [], [], left)[0]:
                continue
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > LISTING_BYTES:
                raise ProofError("unparseable")
            chunks.append(chunk)
        try:
            code = proc.wait(timeout=max(deadline - time.monotonic(), 0.01))
        except subprocess.TimeoutExpired:
            raise ProofError("timeout") from None
    except BaseException:
        _kill_group(proc)
        raise
    finally:
        proc.stdout.close()
    if code != 0:
        raise ProofError("network")
    return b"".join(chunks)


def _ls_remote(url: str) -> list[str]:
    """Tip object ids of the public remote's heads and tags (peeled tag lines included), anonymously over HTTPS.

    Nothing from the caller's environment, git configuration or repository reaches this process."""
    git = shutil.which("git")
    if git is None:
        raise ProofError("network")
    with tempfile.TemporaryDirectory(prefix="safo-ls-") as home:
        genv = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": home,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/false",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "0",
        }
        argv = [
            git,
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "credential.helper=",
            "-c",
            "http.proxy=",
            "-c",
            "core.askpass=",
            "-c",
            "http.followRedirects=false",
            "ls-remote",
            "--heads",
            "--tags",
            url,
        ]
        raw = _listing_output(argv, genv, home)
    lines = raw.decode("ascii", errors="replace").splitlines()
    if len(lines) > LISTING_REFS:
        raise ProofError("unparseable")
    tips: list[str] = []
    for line in lines:
        match = LISTING_LINE.fullmatch(line)
        if match is None:
            if re.fullmatch(r"([0-9a-f]{40}|[0-9a-f]{64})[ \t]refs/\S+", line):
                continue  # a well-formed line for some other ref namespace: not a branch or tag tip
            raise ProofError("unparseable")
        tips.append(match.group(1))
    return tips


def _proof_url(worktree: Path, env: Mapping[str, str]) -> str | None:
    """The one public URL built from the validated owner and name; None unless every remote names the same repo."""
    done = _git_for_selection(worktree, env, "remote", "-v")
    if done is None or done.returncode != 0:
        return None
    urls: list[str] = []
    for line in done.stdout.decode("utf-8", errors="replace").splitlines():
        match = REMOTE_LINE.match(line)
        if match is None:
            return None
        urls.append(match.group(2))
    if not urls:
        return None
    pairs = {parse_remote(u) for u in urls}
    if len(pairs) != 1 or None in pairs:
        return None
    pair = next(iter(pairs))
    if pair is None or not all(p.isascii() and SEGMENT.fullmatch(p) for p in pair):
        return None
    return f"https://{PUBLIC_HOST}/{pair[0]}/{pair[1]}.git"


def _unproven(klass: str) -> str:
    return f"keep local: cannot tell: could not verify that HEAD is published ({klass})"


def _local_tips(worktree: Path, env: Mapping[str, str], tips: Sequence[str]) -> list[str] | None:
    """The listed tips whose commit exists in this repository (`T^{commit}` resolves), checked in one git call."""
    if not tips:
        return []
    data = "".join(f"{oid}^{{commit}}\n" for oid in tips).encode("ascii")
    done = _git_for_selection(worktree, env, "cat-file", "--batch-check", data=data)
    if done is None or done.returncode != 0:
        return None
    rows = done.stdout.decode("ascii", errors="replace").splitlines()
    if len(rows) != len(tips):
        return None
    return [oid for oid, row in zip(tips, rows, strict=True) if row.endswith(" missing") is False and " commit " in row]


def _checked_tips(value: object) -> list[str]:
    """The listing as a list of object ids; a malformed value is refused ('unparseable')."""
    if not isinstance(value, (list, tuple)) or len(value) > LISTING_REFS:
        raise ProofError("unparseable")
    for item in value:
        if not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", item) is None:
            raise ProofError("unparseable")
    return list(value)


def _listed(ls_remote: Callable[[str], list[str]], url: str) -> list[str]:
    """Call the (possibly injected) listing; every ordinary exception becomes a ProofError with a fixed class."""
    try:
        return _checked_tips(ls_remote(url))
    except ProofError:
        raise
    except (MemoryError, RecursionError):
        raise
    except (OSError, subprocess.SubprocessError):
        raise ProofError("git") from None
    except (ValueError, TypeError):
        raise ProofError("unparseable") from None
    except Exception:
        raise ProofError("git") from None


def _published(worktree: Path, env: Mapping[str, str], ls_remote: Callable[[str], list[str]] | None = None) -> str:
    """Refusal text unless HEAD is proved to be part of the public repository's history.

    The proof asks the public remote (anonymous ls-remote of the URL rebuilt from the validated owner and name) for
    its branch and tag tips; HEAD must equal or be an ancestor of a tip that also exists locally. Local remote-tracking
    refs prove nothing (no provenance); replace refs and grafts are off. Fixed words only, never names."""
    head = _git_for_selection(worktree, env, "rev-parse", "--verify", "-q", "HEAD^{commit}")
    if head is None or head.returncode not in (0, 1):
        return _unproven("git")
    if head.returncode == 1:
        return "keep local: HEAD is not published on a public remote (there is no commit yet); push it first"
    url = _proof_url(worktree, env)
    if url is None:
        return _unproven("remote-identity")
    try:
        tips = _listed(ls_remote or _ls_remote, url)
    except ProofError as exc:
        return _unproven(exc.klass)
    unique = sorted(set(tips))
    present = _local_tips(worktree, env, unique)
    if present is None:
        return _unproven("git")
    if not present:
        return _unproven("no-local-tip")
    if len(present) > LOCAL_TIP_LIMIT:
        return _unproven("too-many-tips")
    for oid in present:
        done = _git_for_selection(worktree, env, "merge-base", "--is-ancestor", "HEAD", oid)
        if done is None or done.returncode not in (0, 1):
            return _unproven("git")
        if done.returncode == 0:
            return ""
    return _unproven("not-ancestor")


def _nested_git(root: Path) -> tuple[int, bool]:
    """(nested .git entries, incomplete): iterative scandir walk, symlinks not followed, bounded."""
    nested = seen = 0
    todo = [root]
    while todo:
        here = todo.pop()
        try:
            with os.scandir(here) as entries:
                for entry in entries:
                    seen += 1
                    if seen > WALK_LIMIT:
                        return nested, True
                    if entry.name == ".git":
                        nested += here != root  # the top-level .git is the worktree's own
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        todo.append(Path(entry.path))
        except OSError:
            return nested, True
    return nested, False


def _modified(worktree: Path, env: Mapping[str, str]) -> int | None:
    """Tracked entries whose current bytes may differ from the commit; None when git cannot say (fail closed)."""
    status = _git_z(worktree, env, "status", "--porcelain=v1", "--untracked-files=no")
    tags = _git_z(worktree, env, "ls-files", "-v")
    cached = _git_for_selection(worktree, env, "diff", "--cached", "--quiet")
    head = _git_for_selection(worktree, env, "rev-parse", "--verify", "-q", "HEAD")
    if status is None or tags is None or cached is None or head is None or cached.returncode not in (0, 1):
        return None
    # `ls-files -v` tags every entry; only `H` (cached, normal) is acceptable. Lowercase is assume-unchanged, `S` is
    # skip-worktree, `M` unmerged, `R` removed, `C` modified, `K` to be killed.
    odd = sum(1 for entry in tags if entry[:1] != "H")
    count = len(status) + odd + (cached.returncode == 1 and not (status or odd))
    if head.returncode != 0 and tags:
        return None  # tracked entries with no commit to compare against
    return count


@dataclass(frozen=True)
class Verdict:
    differ: int = 0
    bounded: bool = False
    filtered: bool = False


REGULAR_MODES = {"100644": False, "100755": True}


def _head_tree(worktree: Path, env: Mapping[str, str]) -> dict[str, tuple[str, str]] | None:
    """Every committed entry as path -> (mode, object id) from the HEAD tree; None when git cannot say."""
    unborn = _git_for_selection(worktree, env, "rev-parse", "--verify", "-q", "HEAD")
    if unborn is None or unborn.returncode not in (0, 1):
        return None
    if unborn.returncode == 1:
        return {}  # no commit: every tracked path then counts as not committed
    done = _git_for_selection(worktree, env, "ls-tree", "-r", "-z", "--full-tree", "HEAD")
    if done is None or done.returncode != 0:
        return None
    found: dict[str, tuple[str, str]] = {}
    for raw in done.stdout.split(b"\0"):
        if not raw:
            continue
        meta, tab, path = raw.partition(b"\t")
        fields = meta.decode("ascii", errors="replace").split(" ")
        if not tab or len(fields) != 3:
            return None
        found[os.fsdecode(path)] = (fields[0], fields[2])
    return found


def _blob_id(algo: str, content: Sequence[bytes], size: int) -> str:
    digest = hashlib.new(algo)
    digest.update(b"blob %d\0" % size)
    for chunk in content:
        digest.update(chunk)
    return digest.hexdigest()


class _Parents:
    """Directory descriptors opened component by component without following a symlink (one-entry cache)."""

    def __init__(self, root: Path) -> None:
        self.root = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.key: tuple[bytes, ...] | None = None
        self.fd = self.root

    def _drop(self) -> None:
        if self.fd != self.root:
            os.close(self.fd)
        self.key, self.fd = None, self.root

    def get(self, comps: tuple[bytes, ...]) -> int | None:
        if comps == self.key:
            return self.fd
        self._drop()
        fd = self.root
        try:
            for comp in comps:
                nxt = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                if fd != self.root:
                    os.close(fd)
                fd = nxt
        except OSError:
            if fd != self.root:
                os.close(fd)
            return None
        self.key, self.fd = comps, fd
        return fd

    def close(self) -> None:
        self._drop()
        os.close(self.root)


def _read_exact(name: bytes, fd: int, info: os.stat_result) -> list[bytes] | None:
    """The raw bytes of a regular file opened without following a link; None when it changed or is not regular."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        handle = os.open(name, flags, dir_fd=fd)
    except OSError:
        return None
    try:
        now = os.fstat(handle)
        if not stat.S_ISREG(now.st_mode) or not _same_file(now, info):
            return None
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(handle, READ_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > info.st_size:
                return None
            chunks.append(chunk)
        return chunks if total == info.st_size else None
    except OSError:
        return None
    finally:
        os.close(handle)


def _entry_matches(parents: _Parents, rel: bytes, mode: str, oid: str) -> tuple[bool, int]:
    """(the raw worktree entry equals the committed one, bytes read). A bound is signalled by size -1."""
    *dirs, name = rel.split(b"/")
    fd = parents.get(tuple(dirs))
    if fd is None:
        return False, 0
    try:
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except OSError:
        return False, 0
    algo = "sha256" if len(oid) == 64 else "sha1"
    if mode == "120000":
        if not stat.S_ISLNK(info.st_mode):
            return False, 0
        try:
            target = os.readlink(name, dir_fd=fd)
        except OSError:
            return False, 0
        return _blob_id(algo, [target], len(target)) == oid, len(target)
    if mode not in REGULAR_MODES or not stat.S_ISREG(info.st_mode):
        return False, 0
    if info.st_size > FILE_LIMIT:
        return False, -1
    if REGULAR_MODES[mode] != bool(info.st_mode & stat.S_IXUSR) or (
        not REGULAR_MODES[mode] and info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    ):
        return False, info.st_size
    content = _read_exact(name, fd, info)
    if content is None:
        return False, info.st_size
    return _blob_id(algo, content, info.st_size) == oid, info.st_size


def _mentions_filter(path: Path) -> bool:
    """True when the attributes file names a filter or cannot be read in full (a missing file is empty)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return True
        data = os.read(fd, READ_CHUNK + 1)
    except OSError:
        return True
    finally:
        os.close(fd)
    return len(data) > READ_CHUNK or b"filter" in data.lower()


def _filters_configured(worktree: Path, env: Mapping[str, str], copied: Sequence[str]) -> bool | None:
    """True when any content filter can apply to a copied path; None when git cannot say (fail closed)."""
    if copied:
        data = b"".join(os.fsencode(p) + b"\0" for p in copied)
        done = _git_for_selection(worktree, env, "check-attr", "-z", "--stdin", "filter", data=data)
        if done is None or done.returncode != 0:
            return None
        fields = done.stdout.split(b"\0")
        if any(value != b"unspecified" for value in fields[2::3] if value):
            return True
    files = [worktree / p for p in copied if os.path.basename(p) == ".gitattributes"]
    info = _git_for_selection(worktree, env, "rev-parse", "--git-path", "info/attributes")
    if info is None or info.returncode != 0:
        return None
    files.append(worktree / os.fsdecode(info.stdout.strip()))
    configured = _git_for_selection(worktree, env, "config", "--path", "--get", "core.attributesFile")
    if configured is None or configured.returncode not in (0, 1):
        return None
    if configured.returncode == 0:
        files.append(worktree / os.fsdecode(configured.stdout.strip()))
    return any(_mentions_filter(f) for f in files)


def _verify_content(
    worktree: Path, env: Mapping[str, str], copied: Sequence[str], untracked: Sequence[str]
) -> Verdict | None:
    """Compare the raw bytes the runner would copy with the HEAD tree; trusts neither status nor the index stat cache.

    Refuses (a count, never a name) every committed path that is missing, retyped, re-moded, retargeted or different,
    every tracked path that is not committed, and every gitlink; refuses outright (bounded) a file over 100 MB,
    a total over 1 GB or more than WALK_LIMIT entries; and flags any attribute filter."""
    head = _head_tree(worktree, env)
    if head is None:
        return None
    filtered = _filters_configured(worktree, env, copied)
    if filtered is None:
        return None
    if len(head) + len(copied) > WALK_LIMIT:
        return Verdict(bounded=True, filtered=filtered)
    in_index = set(copied) - set(untracked)
    bad = in_index ^ set(head)
    total = 0
    try:
        parents = _Parents(worktree)
    except OSError:
        return None
    try:
        for rel, (mode, oid) in head.items():
            if rel in bad:
                continue
            same, size = _entry_matches(parents, os.fsencode(rel), mode, oid)
            if size < 0 or total + size > TOTAL_LIMIT:
                return Verdict(len(bad), True, filtered)
            total += size
            if not same:
                bad.add(rel)
    finally:
        parents.close()
    return Verdict(len(bad), False, filtered)


def content_gate(
    worktree: Path, env: Mapping[str, str], ls_remote: Callable[[str], list[str]] | None = None
) -> ContentGate:
    """Inspect what ra-remote would copy (tracked plus untracked and not ignored; it skips ignored files)."""
    copied = _git_z(worktree, env, "ls-files", "-c", "-o", "--exclude-standard")
    untracked = _git_z(worktree, env, "ls-files", "-o", "--exclude-standard")
    modified = _modified(worktree, env)
    unpublished = _published(worktree, env, ls_remote)
    if copied is None or untracked is None or modified is None:
        return ContentGate(incomplete=True, modified=modified or 0, unpublished=unpublished)
    verdict = _verify_content(worktree, env, copied, untracked)
    if verdict is None:
        return ContentGate(incomplete=True, modified=modified, unpublished=unpublished)
    modified = max(modified, verdict.differ)
    nested, incomplete = _nested_git(worktree)
    root = os.path.realpath(worktree)
    symlinks = risky_names = 0
    for rel in copied:
        full = worktree / rel
        if full.is_symlink():
            target = os.path.realpath(full)
            symlinks += target != root and not target.startswith(root + os.sep)
        risky_names += any(
            fnmatch.fnmatchcase(part.lower(), pat) for part in rel.split("/") for pat in RISKY_NAME_PATTERNS
        )
    return ContentGate(
        len(untracked),
        nested,
        symlinks,
        risky_names,
        incomplete,
        modified,
        verdict.filtered,
        verdict.bounded,
        unpublished,
    )


def worktree_allowed(worktree: Path, env: Mapping[str, str]) -> bool:
    """Strictly below one of the folders ra-remote allows. `worktree` must already be resolved (main does it once)."""
    home = env.get("HOME", "")
    if not home:
        return False
    real = worktree
    for folder in DEV_FOLDERS:
        root = Path(os.path.realpath(Path(home) / folder))
        if real != root and real.is_relative_to(root):
            return True
    return False


def decide(finding: Finding, klass: str) -> str:
    if finding.wrapped:
        return "ok-remote"
    return {"public": "suggest-remote", "private": "keep-local-private"}.get(klass, "keep-local-unknown")


def _record(env: Mapping[str, str], rows: list[tuple[str, str, str]], err: TextIO) -> None:
    base = env.get("XDG_STATE_HOME", "")
    root = Path(base) if base and Path(base).is_absolute() else Path(env.get("HOME", "")) / ".local" / "state"
    try:
        root.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(FileExistsError):
            os.mkdir(root / "safo", stat.S_IRWXU)
        dfd = os.open(root / "safo", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchmod(dfd, stat.S_IRWXU)
            fd = os.open(
                "runner-check.jsonl",
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
                stat.S_IRUSR | stat.S_IWUSR,
                dir_fd=dfd,
            )
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                os.fchmod(handle.fileno(), stat.S_IRUSR | stat.S_IWUSR)
                for klass, decision, rclass in rows:
                    row = {"ts": int(time.time()), "class": klass, "decision": decision, "repo_class": rclass}
                    handle.write(json.dumps(row, sort_keys=True) + "\n")
        finally:
            os.close(dfd)
    except OSError as exc:
        err.write(f"safo-runner-check: metrics not written ({exc.__class__.__name__})\n")


def _advice(f: Finding, worktree: str, out: TextIO) -> None:
    if f.simple and f.argv:
        lead = 0
        while lead < len(f.argv) and ASSIGN.match(f.argv[lead]):
            lead += 1
        env_words = list(f.argv[:lead])
        body = list(f.argv[lead:])
        inner = shlex.join(["env", *env_words, *body] if env_words else body)
        out.write(f"  -> ra-remote --plan {worktree} -- {inner}\n")
        out.write(f"  -> ra-remote {worktree} -- {inner}\n")
    else:
        out.write(
            f"  -> run this through ra-remote: ra-remote --plan {worktree} -- <the suite command alone>\n"
            "     (this line has a cd, redirect, pipe, subshell, expansion or several commands, so no rewritten line)\n"
        )


def main(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    out: TextIO,
    err: TextIO,
    stdin: TextIO | None = None,
    ls_remote: Callable[[str], list[str]] | None = None,
) -> int:
    parser = argparse.ArgumentParser(prog="safo-runner-check", description=__doc__.split("\n\n")[0] if __doc__ else "")
    parser.add_argument(
        "--strict", action="store_true", help="exit 1 when a public repo runs a full suite or sweep locally"
    )
    parser.add_argument("--repo", default=".", help="repository directory (default: current)")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--command", help="one command line to check")
    source.add_argument("--brief", help="brief text file to scan, or - for stdin")
    args = parser.parse_args(list(argv))

    if args.command is not None:
        commands = [args.command]
    elif args.brief == "-":
        commands = commands_from_brief((stdin or sys.stdin).read())
    else:
        commands = commands_from_brief(Path(args.brief).read_text(encoding="utf-8"))

    repo = Path(args.repo)
    top = _git(repo, env, "rev-parse", "--show-toplevel")
    worktree = Path(os.path.realpath(top or repo))  # the one place the worktree path is resolved
    rclass, rule = repo_class(repo, env)
    label = {
        "public": f"repo: public ({rule})",
        "private": f"repo: looks private ({rule}): keep local",
        "unknown": f"repo: cannot tell: keep local ({rule})",
    }[rclass]
    out.write(label + "\n")

    findings = [f for c in commands for f in classify(c)]
    in_dev = worktree_allowed(worktree, env)
    rows: list[tuple[str, str, str]] = []
    violation = False
    refusal: str | None = None
    checked = False
    for f in findings:
        decision = decide(f, rclass)
        if decision == "suggest-remote" and not in_dev:
            decision = "keep-local-worktree"
        if decision == "suggest-remote":
            if not checked:
                refusal, checked = content_gate(worktree, env, ls_remote).refusal(), True
            if refusal:
                decision = "keep-local-content"
        rows.append((f.klass, decision, rclass))
        if decision == "ok-remote":
            out.write(f"ok: {f.klass} already runs through ra-remote: {f.command}\n")
        elif decision == "suggest-remote":
            violation = True
            out.write(f"local {f.klass}: {f.command}\n")
            out.write("  reason: heavy work on a public repo goes to the runner (2.1x to 2.7x faster)\n")
            if f.note:
                out.write(f"  note: {f.note}\n")
            _advice(f, shlex.quote(str(worktree)), out)
        elif decision == "keep-local-content":
            out.write(f"local {f.klass}: {f.command}\n  {refusal}\n")
        elif decision == "keep-local-worktree":
            out.write(
                f"local {f.klass}: {f.command}\n  keep local: the worktree is outside the runner's allowed folders "
                f"(move or clone it under ~/{DEV_FOLDERS[0]} first)\n"
            )
        else:
            out.write(f"local {f.klass}: {f.command}\n  keep local: runner is for public repos only\n")
    if not findings:
        rows.append(("none", "ok-targeted", rclass))
        out.write("ok: no local full suite or mutation sweep found\n")
    _record(env, rows, err)
    return 1 if args.strict and violation else 0


def run() -> None:
    raise SystemExit(main(sys.argv[1:], env=os.environ, out=sys.stdout, err=sys.stderr))


if __name__ == "__main__":
    run()
