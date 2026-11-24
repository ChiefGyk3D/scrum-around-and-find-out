# SPDX-License-Identifier: Apache-2.0
"""A fake `codex` on PATH and a throwaway account home for the safo-codex-run tests.

The fake records what it was given (argument vector, environment, working folder, its folder's listing, standard
input) one JSON object per call in `calls.jsonl` next to it, then behaves as its `mode` file says. The real codex is
never run. The prompt and output canaries are strings the ledger must never hold.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gitrepo import IDENTITY, git

PROMPT_CANARY = "PROMPTCANARY-7f3a"
OUTPUT_CANARY = "OUTCANARY-91cd"

FAKE = """#!{python}
import json, os, sys, time

base = {base!r}
mode = open(base + "/mode").read().strip()
argv = sys.argv[1:]
record = {{
    "argv": argv,
    "env": dict(os.environ),
    "cwd": os.getcwd(),
    "listing": sorted(os.listdir(".")),
    "stdin": sys.stdin.read(),
}}
with open(base + "/calls.jsonl", "a") as handle:
    handle.write(json.dumps(record) + "\\n")
out = argv[argv.index("-o") + 1]
if mode == "ok":
    open(out, "w").write("{output} done\\n")
elif mode == "filter":
    sys.stderr.write("This request was flagged for possible cybersecurity risk.\\n")
    sys.exit(1)
elif mode == "filter-short":
    open(out, "w").write("Flagged for possible\\ncybersecurity risk. Confirm the access program.\\n")
elif mode == "quote-long":
    open(out, "w").write("a review line\\n" * 2000 + "it quotes: flagged for possible cybersecurity risk\\n")
elif mode == "sleep":
    time.sleep(60)
elif mode == "fail":
    sys.exit(3)
elif mode == "stray":
    open("stray-file", "w").write("x")
    open(out, "w").write("ok\\n")
"""


@dataclass
class World:
    home: Path
    dev: Path
    bin: Path
    prompt: Path
    worktree: Path
    env: dict[str, str]

    def mode(self, name: str) -> None:
        (self.bin / "mode").write_text(name)

    def calls(self) -> list[dict[str, Any]]:
        path = self.bin / "calls.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def ledger(self) -> list[dict[str, Any]]:
        path = self.home / ".local" / "state" / "safo" / "codex-runs.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def write_prompt(self, text: str, name: str = "p.txt") -> Path:
        path = self.dev / "prompts" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o600)
        return path


def make_world(tmp: Path) -> World:
    home = tmp / "home"
    dev = home / ".local" / "share" / "t-dev"
    dev.mkdir(parents=True)
    bin_dir = tmp / "fakebin"
    bin_dir.mkdir()
    fake = bin_dir / "codex"
    fake.write_text(FAKE.format(python=sys.executable, base=str(bin_dir), output=OUTPUT_CANARY))
    fake.chmod(0o755)
    (bin_dir / "mode").write_text("ok")
    repo = dev / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("a\n")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-q", "-m", "init")
    worktree = dev / "agents" / "wt"
    worktree.parent.mkdir()
    subprocess.run(  # noqa: S603 - fixed argv in a test helper, no shell
        ["git", *IDENTITY, "-C", str(repo), "worktree", "add", "-q", "-b", "work", str(worktree)],  # noqa: S607
        check=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        },
    )
    world = World(home, dev, bin_dir, dev / "prompts" / "p.txt", worktree, {"PATH": f"{bin_dir}:/usr/bin:/bin"})
    world.write_prompt(f"Review the change. {PROMPT_CANARY}\n")
    assert stat.S_ISREG(world.prompt.stat().st_mode)
    return world
