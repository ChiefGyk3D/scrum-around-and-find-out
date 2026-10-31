# SPDX-License-Identifier: Apache-2.0
"""Throwaway git repositories for the tests that read a file from a revision."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

IDENTITY = ("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false")


def git(repo: Path, *args: str) -> str:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    done = subprocess.run(  # noqa: S603 - fixed argv in a test helper, no shell
        ["git", *IDENTITY, "-C", str(repo), *args],  # noqa: S607 - git from PATH
        env=env,
        capture_output=True,
        text=True,
        check=True,
        stdin=subprocess.DEVNULL,
    )
    return done.stdout.strip()


def make_repo(path: Path, files: dict[str, str], links: dict[str, str] | None = None, *, message: str = "init") -> str:
    """Create (or extend) a repository at `path` with a commit holding `files` and symlinks `links`; return its sha."""
    path.mkdir(parents=True, exist_ok=True)
    if not (path / ".git").exists():
        git(path, "init", "-q", "-b", "main")
    for name, text in files.items():
        target = path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    for name, to in (links or {}).items():
        link = path / name
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(to)
    git(path, "add", "-A")
    git(path, "commit", "-q", "--allow-empty", "-m", message)
    return git(path, "rev-parse", "HEAD")
