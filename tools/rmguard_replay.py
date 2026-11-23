# SPDX-License-Identifier: Apache-2.0
"""Replay real Bash history through the rmguard rule, in dry run (#422). Not run in CI.

Reads every `~/.claude/projects/*/*.jsonl` session log, takes each Bash tool call, and asks `safo.rmguard.check` what
it would do (no hook, no log file, nothing executed). Prints the counts, and every command that would be blocked,
redacted the way the warn log redacts (home shortened, secret-looking text removed). The command itself is never
printed unredacted.

    python tools/rmguard_replay.py [--projects DIR] [--limit N]
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time
from collections import Counter
from collections.abc import Iterator

from safo import rmguard


def calls_in(path: str) -> Iterator[tuple[str, str | None]]:
    """(command, cwd) for every Bash tool call in one session log."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if '"Bash"' not in line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            message = entry.get("message") if isinstance(entry, dict) else None
            content = message.get("content") if isinstance(message, dict) else None
            if not isinstance(content, list):
                continue
            for item in content:
                if isinstance(item, dict) and item.get("type") == "tool_use" and item.get("name") == "Bash":
                    tool_input = item.get("input")
                    command = tool_input.get("command") if isinstance(tool_input, dict) else None
                    if isinstance(command, str):
                        cwd = entry.get("cwd")
                        yield command, cwd if isinstance(cwd, str) else None


def bash_calls(projects: str) -> Iterator[tuple[str, str | None]]:
    """(command, cwd) for every Bash tool call in every session log under `projects`."""
    for path in sorted(glob.glob(os.path.join(projects, "*", "*.jsonl"))):
        try:
            yield from calls_in(path)
        except OSError:
            continue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--projects", default=os.path.expanduser("~/.claude/projects"))
    parser.add_argument("--limit", type=int, default=0, help="stop after this many Bash commands (0 = all)")
    args = parser.parse_args(argv)
    home = os.path.expanduser("~")
    total = gated = plain_total = 0
    no_word: Counter[tuple[str, str]] = Counter()
    blocked: Counter[tuple[str, str]] = Counter()
    errors: Counter[str] = Counter()
    slowest = 0.0
    for command, cwd in bash_calls(args.projects):
        total += 1
        if args.limit and total > args.limit:
            total -= 1
            break
        if not rmguard.has_delete_word(command):
            continue
        gated += 1
        plain = rmguard.plain_delete_word(command)
        plain_total += plain
        begun = time.monotonic()
        try:
            found = rmguard.check(command, home, cwd)
        except Exception as exc:  # report, never stop the replay
            errors[type(exc).__name__] += 1
            continue
        slowest = max(slowest, time.monotonic() - begun)
        if found:
            blocked[(found.reason, rmguard.redact(command, home))] += 1
            if not plain:
                no_word[(found.reason, rmguard.redact(command, home))] += 1
    sys.stdout.write(f"total Bash commands: {total}\n")
    sys.stdout.write(f"evaluated (a delete word, a character that can build one, or a zone): {gated}\n")
    sys.stdout.write(f"  of which hold a plain delete word: {plain_total}\n")
    sys.stdout.write(f"blocked with NO plain delete word: {sum(no_word.values())} ({len(no_word)} distinct)\n")
    sys.stdout.write(f"blocked: {sum(blocked.values())} ({len(blocked)} distinct)\n")
    sys.stdout.write(f"internal errors: {sum(errors.values())} {dict(errors)}\n")
    sys.stdout.write(f"slowest check: {slowest * 1000:.1f} ms\n")
    for (reason, shown), count in sorted(blocked.items(), key=lambda kv: -kv[1]):
        sys.stdout.write(f"--- x{count}: {reason}\n{shown}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
