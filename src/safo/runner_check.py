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
`ra-remote` allows. `--strict` exits 1 only when a public repo runs a full suite or sweep locally.
One metrics line per check goes to `$XDG_STATE_HOME/safo/runner-check.jsonl` (class, decision, repo class; no command).
"""

from __future__ import annotations

import argparse
import contextlib
import fnmatch
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import unicodedata
from collections.abc import Mapping, Sequence
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
SECRET_NAMES = (
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
    for _ in range(10):
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
    return ws


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
    if not ws or depth > 4:
        return None
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
        hit = _classify_words(words, depth)
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
    return kind and info.st_uid == os.geteuid() and not info.st_mode & 0o022


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
        if below_home and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
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
            same = (now.st_ino, now.st_dev, now.st_mode) == (info.st_ino, info.st_dev, info.st_mode)
            if not (same and _owner_only(now, directory=False)):
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
    git = shutil.which("git")
    if git is None:
        return None
    try:
        return subprocess.run(  # noqa: S603 - fixed git argv, no shell
            [git, "-C", str(repo), *args], capture_output=True, timeout=30, check=False, env=_git_env(env)
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _git(repo: Path, env: Mapping[str, str], *args: str) -> str:
    done = _git_run(repo, env, *args)
    if done is None or done.returncode != 0:
        return ""
    return done.stdout.decode("utf-8", errors="replace").strip()


def _git_z(repo: Path, env: Mapping[str, str], *args: str) -> list[str] | None:
    """NUL-separated git output as a list; None when git failed."""
    done = _git_run(repo, env, "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", *args, "-z")
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
    if k.startswith("includeif.gitdir"):
        return "includeIf gitdir"
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
    secrets: int = 0
    incomplete: bool = False

    def refusal(self) -> str | None:
        if not (self.untracked or self.nested or self.symlinks or self.secrets or self.incomplete):
            return None
        text = (
            "keep local: the worktree holds files the runner would copy that are not in the public repository "
            f"({self.untracked} untracked files; {self.nested} nested git directories; "
            f"{self.symlinks} symlinks leaving the tree)"
        )
        if self.secrets:
            text += f"; secret-looking file names present ({self.secrets})"
        if self.incomplete:
            text += f"; the tree could not be fully checked (more than {WALK_LIMIT} entries, or unreadable)"
        return text + f". Commit them, add them to .gitignore, or clone a clean copy under ~/{DEV_FOLDERS[0]} first"


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


def content_gate(worktree: Path, env: Mapping[str, str]) -> ContentGate:
    """Inspect what ra-remote would copy (tracked plus untracked and not ignored; it skips ignored files)."""
    copied = _git_z(worktree, env, "ls-files", "-c", "-o", "--exclude-standard")
    untracked = _git_z(worktree, env, "ls-files", "-o", "--exclude-standard")
    if copied is None or untracked is None:
        return ContentGate(incomplete=True)
    nested, incomplete = _nested_git(worktree)
    root = os.path.realpath(worktree)
    symlinks = secrets = 0
    for rel in copied:
        full = worktree / rel
        if full.is_symlink():
            target = os.path.realpath(full)
            symlinks += target != root and not target.startswith(root + os.sep)
        secrets += any(fnmatch.fnmatchcase(part.lower(), pat) for part in rel.split("/") for pat in SECRET_NAMES)
    return ContentGate(len(untracked), nested, symlinks, secrets, incomplete)


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
            os.mkdir(root / "safo", 0o700)
        dfd = os.open(root / "safo", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchmod(dfd, 0o700)
            fd = os.open(
                "runner-check.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=dfd
            )
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                os.fchmod(handle.fileno(), 0o600)
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


def main(argv: Sequence[str], *, env: Mapping[str, str], out: TextIO, err: TextIO, stdin: TextIO | None = None) -> int:
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
                refusal, checked = content_gate(worktree, env).refusal(), True
            if refusal:
                decision = "keep-local-content"
        rows.append((f.klass, decision, rclass))
        if decision == "ok-remote":
            out.write(f"ok: {f.klass} already runs through ra-remote: {f.command}\n")
        elif decision == "suggest-remote":
            violation = True
            out.write(f"local {f.klass}: {f.command}\n")
            out.write("  reason: heavy work on a public repo goes to the runner (2.1x to 2.7x faster)\n")
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
