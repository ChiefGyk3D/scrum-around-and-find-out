# SPDX-License-Identifier: Apache-2.0
"""safo-runner-check: flag a local full suite or mutation sweep and print the ra-remote command instead (#485).

    safo-runner-check [--strict] [--repo DIR] (--command LINE | --brief FILE|-)

Heavy work on a PUBLIC repo goes to the runner (`ra-remote`); targeted checks stay local. The check only prints advice:
it never runs ra-remote and never contacts the runner. It fails closed: anything it cannot prove public is kept local.

A repo is public only when EVERY remote (`git remote -v`) is a github.com owner/name URL (https, ssh, scp-like; the host
is parsed, userinfo is never echoed), no name on the denylist matches, and either the repo is on the repo allowlist
(`SAFO_PUBLIC_REPOS`, else the file `public-repos`) or, with no allowlist, its owner is on the owner list
(`SAFO_PUBLIC_OWNERS`, else the file `public-owners`). The denylist (built-in names plus the file `runner-never`) always
wins. Config files live in the safo config dir and must be owner-only. Advice is given only for a worktree under a
folder `ra-remote` allows. `--strict` exits 1 only when a public repo runs a full suite or sweep locally.
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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO
from urllib.parse import urlsplit

FULL = "full-suite"
MUTATION = "mutation"
INLINE = re.compile(r"`([^`\n]+)`")
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
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
    i = 0
    while i < len(ws) and ws[i].startswith("-") and ws[i] != "--":
        i += 2 if ws[i] in value_opts else 1
    return ws[i + 1 :] if i < len(ws) and ws[i] == "--" else ws[i:]


def _command_words(words: Sequence[str]) -> list[str]:
    """Strip env assignments and known wrappers; return the words starting at the real command."""
    ws = list(words)
    for _ in range(10):
        while ws and ASSIGN.match(ws[0]):
            ws.pop(0)
        if not ws:
            return ws
        base, rest = Path(ws[0]).name, ws[1:]
        if base in {"time", "nohup", "command", "exec", "builtin"}:
            ws = rest
        elif base == "nice":
            ws = _drop_options(rest, frozenset({"-n"}))
        elif base == "timeout":
            rest = _drop_options(rest, frozenset({"-s", "-k", "--signal", "--kill-after"}))
            ws = rest[1:]  # the duration
        elif base == "env":
            ws = _drop_options(rest, frozenset({"-u", "-C", "-S"}))
        elif base in {"uv", "poetry", "pipenv", "pdm", "hatch"} and rest[:1] == ["run"]:
            ws = _drop_options(rest[1:], UV_VALUE_OPTS)
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
    if base == "vitest":
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
    return (klass, False) if klass else None


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


def _owner_name(path: str) -> tuple[str, str] | None:
    parts = path.strip("/").removesuffix(".git").split("/")
    if len(parts) != 2 or not all(SEGMENT.match(p) for p in parts):
        return None
    return parts[0].lower(), parts[1].lower()


def parse_remote(url: str) -> tuple[str, str] | None:
    """(owner, name) for a github.com https, ssh or scp-like URL; None for any other host or shape."""
    url = url.strip()
    if "://" in url:
        try:
            parts = urlsplit(url)
            host = parts.hostname
        except ValueError:
            return None
        if parts.scheme not in {"https", "ssh", "git"} or host != PUBLIC_HOST or parts.query or parts.fragment:
            return None
        return _owner_name(parts.path)
    match = SCP_LIKE.match(url)
    if match is None or match.group(1).lower() != PUBLIC_HOST:
        return None
    return _owner_name(match.group(2))


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


def _config_lines(env: Mapping[str, str], name: str) -> list[str] | None:
    """Lowercased entries of a config file; [] when absent; None when the file or its folder is not owner-only."""
    cfg = _config_dir(env)
    if cfg is None:
        return []
    path = cfg / name
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return []
    except OSError:
        return None
    try:
        parent_ok = _owner_only(os.lstat(cfg), directory=True)
        if not (parent_ok and _owner_only(info, directory=False)):
            return None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, encoding="utf-8") as handle:
            text = handle.read()
    except (OSError, UnicodeDecodeError):
        return None
    return [ln.strip().lower() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def _setting(env: Mapping[str, str], var: str, name: str) -> list[str] | None:
    raw = env.get(var, "")
    if raw.strip():
        return [o.strip().lower() for o in raw.split(",") if o.strip()]
    return _config_lines(env, name)


def public_owners(env: Mapping[str, str]) -> set[str]:
    return set(_setting(env, "SAFO_PUBLIC_OWNERS", "public-owners") or [])


def _git(repo: Path, *args: str) -> str:
    git = shutil.which("git")
    if git is None:
        return ""
    try:
        done = subprocess.run(  # noqa: S603 - fixed git argv, no shell
            [git, "-C", str(repo), *args], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout.strip() if done.returncode == 0 else ""


def _remote_urls(repo: Path) -> list[str] | None:
    """Every remote URL (fetch and push); None when a line cannot be read."""
    urls: list[str] = []
    for line in _git(repo, "remote", "-v").splitlines():
        match = REMOTE_LINE.match(line)
        if match is None:
            return None
        urls.append(match.group(2))
    return urls


def _denied(owner: str, name: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) or fnmatch.fnmatchcase(f"{owner}/{name}", p) for p in patterns)


def repo_class(repo: Path, env: Mapping[str, str]) -> tuple[str, str]:
    """(public | private | unknown, the rule that decided)."""
    urls = _remote_urls(repo)
    if not urls:
        return "unknown", "no git remote" if urls == [] else "a remote line could not be read"
    parsed = [parse_remote(u) for u in urls]
    pairs = [p for p in parsed if p is not None]
    if len(pairs) != len(parsed):
        return "unknown", f"a remote is not a {PUBLIC_HOST} owner/name URL"
    extra = _config_lines(env, "runner-never")
    allow = _setting(env, "SAFO_PUBLIC_REPOS", "public-repos")
    owners = _setting(env, "SAFO_PUBLIC_OWNERS", "public-owners")
    if extra is None or allow is None or owners is None:
        return "unknown", "a safo config file is not owner-only"
    patterns = [*BUILTIN_NEVER, *extra]
    for owner, name in pairs:
        if _denied(owner, name, patterns):
            return "private", f"denylist match: {owner}/{name}"
    if allow:
        if all(f"{o}/{n}" in allow for o, n in pairs):
            return "public", "public: listed in the repo allowlist, no denylist match"
        return "private", "not in the repo allowlist"
    if not owners:
        return "unknown", "no repo allowlist and no owner list"
    if all(o in owners for o, _ in pairs):
        return "public", "public: owner listed, no denylist match"
    return "private", "owner is not on the public list"


def worktree_allowed(worktree: Path, env: Mapping[str, str]) -> bool:
    """Strictly below one of the folders ra-remote allows, after symlinks and .. are resolved."""
    home = env.get("HOME", "")
    if not home:
        return False
    real = Path(os.path.realpath(worktree))
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

    repo = Path(args.repo).resolve()
    top = _git(repo, "rev-parse", "--show-toplevel")
    worktree = Path(os.path.realpath(top)) if top else repo
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
    for f in findings:
        decision = decide(f, rclass)
        if decision == "suggest-remote" and not in_dev:
            decision = "keep-local-worktree"
        rows.append((f.klass, decision, rclass))
        if decision == "ok-remote":
            out.write(f"ok: {f.klass} already runs through ra-remote: {f.command}\n")
        elif decision == "suggest-remote":
            violation = True
            out.write(f"local {f.klass}: {f.command}\n")
            out.write("  reason: heavy work on a public repo goes to the runner (2.1x to 2.7x faster)\n")
            _advice(f, shlex.quote(str(worktree)), out)
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
