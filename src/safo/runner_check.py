# SPDX-License-Identifier: Apache-2.0
"""safo-runner-check: flag a local full suite or mutation sweep and print the ra-remote command instead (#485).

    safo-runner-check [--strict] [--repo DIR] (--command LINE | --brief FILE|-)

Heavy work on a PUBLIC repo goes to the runner (`ra-remote`); targeted checks stay local. The check only prints advice:
it never runs ra-remote and never contacts the runner. A repo is "public" only when its origin owner is in the owner
list (`SAFO_PUBLIC_OWNERS`, comma separated, else the file `public-owners` in the safo config dir, one owner per line).
Owner not listed: "looks private", keep local. No list or no remote: "cannot tell: keep local". Private repos are never
recommended for the runner. `--strict` exits 1 only when a public repo runs a full suite or sweep locally.
One metrics line per check goes to `$XDG_STATE_HOME/safo/runner-check.jsonl` (class, decision, repo class; no command).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

FULL = "full-suite"
MUTATION = "mutation"
SPLIT = re.compile(r"&&|\|\||;|\||\n")
OWNER = re.compile(r"github\.com[:/]+([^/\s]+)/[^/\s]+?(?:\.git)?/?$")
INLINE = re.compile(r"`([^`\n]+)`")
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SWEEPS = {"mutmut": "mutmut", "cosmic-ray": "cosmic-ray", "stryker": "stryker"}
NODE_MANAGERS = {"npm", "pnpm", "yarn"}
PYTEST_SELECT = ("-k", "--lf", "--last-failed", "--ff", "--failed-first")
WORKTREE_ROOT = "~/.local/share/reach-around-dev"


@dataclass(frozen=True)
class Finding:
    klass: str
    command: str
    wrapped: bool


def _tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _targeted_pytest(args: Sequence[str]) -> bool:
    for arg in args:
        if arg in PYTEST_SELECT or arg.startswith("-k"):
            return True
        if not arg.startswith("-") and (".py" in arg or "::" in arg):
            return True
    return False


def _classify_segment(segment: str) -> Finding | None:
    words = [w for w in _tokens(segment) if not ASSIGN.match(w)]
    if not words:
        return None
    if Path(words[0]).name == "ra-remote":
        inner = words[words.index("--") + 1 :] if "--" in words else []
        found = _classify_segment(" ".join(shlex.quote(w) for w in inner)) if inner else None
        return Finding(found.klass, segment.strip(), True) if found else None
    for i, word in enumerate(words):
        base = Path(word).name
        rest = words[i + 1 :]
        if base in SWEEPS:
            return Finding(MUTATION, segment.strip(), False)
        if base in {"pytest", "py.test"} or (base == "-m" and rest[:1] == ["pytest"]):
            args = rest[1:] if base == "-m" else rest
            return None if _targeted_pytest(args) else Finding(FULL, segment.strip(), False)
        if base == "vitest":
            files = [a for a in rest if not a.startswith("-") and a != "run"]
            return None if files else Finding(FULL, segment.strip(), False)
        if base in NODE_MANAGERS and (rest[:1] in (["test"], ["t"]) or rest[:2] == ["run", "test"]):
            return Finding(FULL, segment.strip(), False)
        if base == "make" and rest[:1] == ["check"]:
            return Finding(FULL, segment.strip(), False)
        if i == 0 and base in {"echo", "printf", "git", "ruff", "cat", "grep"}:
            return None
    return None


def classify(command: str) -> list[Finding]:
    found = (_classify_segment(seg) for seg in SPLIT.split(command))
    return [f for f in found if f is not None]


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


def remote_owner(url: str) -> str | None:
    match = OWNER.search(url.strip())
    return match.group(1).lower() if match else None


def _config_dir(env: Mapping[str, str]) -> Path | None:
    chosen = env.get("XDG_CONFIG_HOME", "")
    if chosen and Path(chosen).is_absolute():
        return Path(chosen) / "safo"
    home = env.get("HOME", "")
    return Path(home) / ".config" / "safo" if home else None


def public_owners(env: Mapping[str, str]) -> set[str]:
    raw = env.get("SAFO_PUBLIC_OWNERS", "")
    if raw.strip():
        return {o.strip().lower() for o in raw.split(",") if o.strip()}
    cfg = _config_dir(env)
    if cfg is None:
        return set()
    try:
        text = (cfg / "public-owners").read_text(encoding="utf-8")
    except OSError:
        return set()
    return {ln.strip().lower() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")}


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


def repo_class(repo: Path, env: Mapping[str, str]) -> str:
    """public, private (looks private) or unknown."""
    owners = public_owners(env)
    owner = remote_owner(_git(repo, "remote", "get-url", "origin"))
    if not owners or owner is None:
        return "unknown"
    return "public" if owner in owners else "private"


def decide(finding: Finding, klass: str) -> str:
    if finding.wrapped:
        return "ok-remote"
    return {"public": "suggest-remote", "private": "keep-local-private"}.get(klass, "keep-local-unknown")


def _record(env: Mapping[str, str], rows: list[tuple[str, str, str]], err: TextIO) -> None:
    base = env.get("XDG_STATE_HOME", "")
    root = Path(base) if base and Path(base).is_absolute() else Path(env.get("HOME", "")) / ".local" / "state"
    path = root / "safo" / "runner-check.jsonl"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            for klass, decision, rclass in rows:
                row = {"ts": int(time.time()), "class": klass, "decision": decision, "repo_class": rclass}
                handle.write(json.dumps(row, sort_keys=True) + "\n")
    except OSError as exc:
        err.write(f"safo-runner-check: metrics not written ({exc.__class__.__name__})\n")


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
    worktree = Path(top) if top else repo
    rclass = repo_class(repo, env)
    label = {
        "public": "repo: public (origin owner is on the public list)",
        "private": "repo: looks private (origin owner is not on the public list): keep local",
        "unknown": "repo: cannot tell: keep local (no owner list or no origin remote)",
    }[rclass]
    out.write(label + "\n")

    findings = [f for c in commands for f in classify(c)]
    rows: list[tuple[str, str, str]] = []
    violation = False
    for f in findings:
        decision = decide(f, rclass)
        rows.append((f.klass, decision, rclass))
        shown = f.command
        if decision == "ok-remote":
            out.write(f"ok: {f.klass} already runs through ra-remote: {shown}\n")
        elif decision == "suggest-remote":
            violation = True
            inner = shlex.join(_tokens(shown))
            out.write(f"local {f.klass}: {shown}\n")
            out.write("  reason: heavy work on a public repo goes to the runner (2.1x to 2.7x faster)\n")
            out.write(f"  -> ra-remote --plan {worktree} -- {inner}\n")
            out.write(f"  -> ra-remote {worktree} -- {inner}\n")
            if "reach-around-dev" not in str(worktree):
                out.write(
                    f"  note: ra-remote needs the worktree under {WORKTREE_ROOT} (or another allowed dev folder)\n"
                )
        else:
            out.write(f"local {f.klass}: {shown}\n  keep local: runner is for public repos only\n")
    if not findings:
        rows.append(("none", "ok-targeted", rclass))
        out.write("ok: no local full suite or mutation sweep found\n")
    _record(env, rows, err)
    return 1 if args.strict and violation else 0


def run() -> None:
    raise SystemExit(main(sys.argv[1:], env=os.environ, out=sys.stdout, err=sys.stderr))
