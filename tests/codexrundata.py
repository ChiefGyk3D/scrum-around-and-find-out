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
base = base + "/state"  # the only folder of the fake's home that is bound read-write; the binary's folder is not
mode = open(base + "/mode").read().strip()
argv = sys.argv[1:]
probe = "none"
if os.path.exists(base + "/probe"):
    target = open(base + "/probe").read().strip()  # the path to try to read
    try:
        probe = "read:" + open(target).read()
    except OSError:
        probe = "blocked"
record = {{
    "probe": probe,
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
elif mode == "filter-event":
    print(json.dumps({{"type": "error", "message": "Flagged for possible cybersecurity risk."}}))
    sys.exit(1)
elif mode == "spoof-event":
    print(json.dumps({{"type": "item.completed", "text": "flagged for possible cybersecurity risk"}}))
    sys.exit(1)
elif mode == "filter-padded":
    sys.stderr.write("flagged for possible cybersecurity risk\\n")
    sys.stderr.write("x" * 3000000)
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
        (self.bin / "state" / "mode").write_text(name)

    def calls(self) -> list[dict[str, Any]]:
        path = self.bin / "state" / "calls.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def ledger_all(self) -> list[dict[str, Any]]:
        path = self.home / ".local" / "state" / "safo" / "codex-runs.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def ledger(self) -> list[dict[str, Any]]:
        """The closing rows only: one per finished run."""
        return [row for row in self.ledger_all() if row["status"] == "finished"]

    def configure(self, **extra: Any) -> None:
        """Rewrite the owner config: the fake codex, the test world's own paths, and any extra or changed key."""
        config = self.home / ".config" / "safo" / "codex-run.json"
        body: dict[str, Any] = {
            "codex": str(self.bin / "codex"),
            "confinement": "none",
            "ro_paths": sorted({sys.prefix, sys.base_prefix}),
            "rw_paths": [str(self.bin / "state")],
        }
        body.update(extra)
        config.write_text(json.dumps(body))
        config.chmod(0o600)

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
    fake.write_text(FAKE.format(python=os.path.abspath(sys.executable), base=str(bin_dir), output=OUTPUT_CANARY))
    fake.chmod(0o755)
    config = home / ".config" / "safo" / "codex-run.json"
    config.parent.mkdir(parents=True)
    (home / ".codex").mkdir(mode=0o700)
    (home / ".codex").chmod(0o700)
    (bin_dir / "state").mkdir()
    (bin_dir / "state" / "mode").write_text("ok")
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
    world.configure()
    world.write_prompt(f"Review the change. {PROMPT_CANARY}\n")
    assert stat.S_ISREG(world.prompt.stat().st_mode)
    return world
