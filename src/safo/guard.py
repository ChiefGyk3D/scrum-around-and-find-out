# SPDX-License-Identifier: Apache-2.0
"""The guard's own entry point: `safo-guard` (console script) and `python -m safo.guard`.

The installed PreToolUse hook runs this, never `safo hooks guard`, so nothing has to guess from a command line whether
it is being called as the guard. It never parses subcommands, never builds argparse, never imports or enumerates the
modes, and never writes to standard error or prints help: the only words it reads are `--agents` and `--agents-local`
(`--opt V` or `--opt=V`); every other word is noise and is ignored, including `--help` and `--version`. The event on
standard input gets its verdict through the existing guard internals (safo.modes.hooks.guard_process), which end the
process exactly once through hard_exit within the deadline. A line this scan cannot make sense of changes nothing
about that: the event is still read and the verdict still computed (default configuration discovery, block
semantics); only an unreadable event takes the documented cannot-tell path (the visible degraded allow).

`safo hooks guard ...` lines that were installed earlier still work through the frozen legacy routing in safo.cli
(see guard_words in safo.modes.hooks); that routing is not extended. `safo hooks install` migrates them to this form.
"""

from __future__ import annotations

import datetime as dt
import os
import sys
from collections.abc import Sequence
from types import SimpleNamespace

from safo.context import LocalContext
from safo.modes import hooks

OPTIONS = ("--agents", "--agents-local")


def scan(words: Sequence[str]) -> SimpleNamespace:
    """The two paths in `words`, by a lenient scan. `--opt=V` and `--opt V` (last one wins); an empty value counts as
    absent; a value that starts with a single dash is kept (`-strict.yaml` is a path); the word after a bare `--opt` is
    its value unless it starts with `--` (then the option has no value and that word is read on its own). Everything
    else is ignored."""
    values = {name: "" for name in OPTIONS}
    index = 0
    while index < len(words):
        word = words[index]
        index += 1
        name, equals, value = word.partition("=")
        if name not in values:
            continue
        if not equals:
            if index >= len(words) or words[index].startswith("--"):
                continue
            value = words[index]
            index += 1
        if value:
            values[name] = value
    return SimpleNamespace(agents=values["--agents"], agents_local=values["--agents-local"])


def main(argv: Sequence[str] | None = None) -> int:
    """Run the guard for one event. The real entry never returns (hard_exit ends the process); a test gets the code."""
    hooks.arm_process_clock()  # the budget counts from the start of the process
    words = sys.argv[1:] if argv is None else list(argv)
    ctx = LocalContext(sys.stdout, os.environ, dt.datetime.now(dt.UTC))
    return hooks.guard_process(ctx, scan(words))


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
