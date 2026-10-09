# SPDX-License-Identifier: MIT
"""The real module entrypoint (`python -m safo`) of the hooks: argument errors must fail open, never exit 2.

A host reads exit 2 from a hook as "block this tool call", so a hook that cannot parse its own command line (a changed
install, an older safo) has to exit 0 with the degraded notice. In-process tests call `main([...])` with an explicit
list and so cannot see how `main()` finds its own command line; these run the interpreter the way a host does.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SRC = str(Path(__file__).resolve().parent.parent / "src")


def run_hook(home: Path, *args: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
    env = {"HOME": str(home), "PATH": os.environ.get("PATH", ""), "PYTHONPATH": SRC}
    # No -I: it would also drop PYTHONPATH, and the sources under test are found through it.
    return subprocess.run(
        [sys.executable, "-m", "safo", *args], input=stdin, capture_output=True, text=True, env=env, timeout=60
    )


def assert_degraded_fail_open(done: subprocess.CompletedProcess[str], event: str) -> None:
    assert done.returncode == 0, done.stderr
    data = json.loads(done.stdout)
    assert "degraded" in data["systemMessage"] and data["hookSpecificOutput"]["hookEventName"] == event
    assert done.stdout.count("\n") == 1


@pytest.mark.parametrize(
    "args,event",
    [
        (("hooks", "guard", "--no-such-flag"), "PreToolUse"),
        (("hooks", "probe", "--no-such-flag"), "SessionStart"),
        (("hooks", "guard", "bogus-positional"), "PreToolUse"),
        (("hooks", "probe", "bogus-positional"), "SessionStart"),
        (("hooks", "guard", "--agents"), "PreToolUse"),
    ],
)
def test_a_hook_that_cannot_parse_its_command_line_exits_zero_with_the_degraded_notice(
    tmp_path: Path, args: tuple[str, ...], event: str
) -> None:
    assert_degraded_fail_open(run_hook(tmp_path, *args), event)


@pytest.mark.parametrize("sub,event", [("guard", "PreToolUse"), ("probe", "SessionStart")])
def test_a_hook_with_an_empty_standard_input_exits_zero_with_the_degraded_notice(
    tmp_path: Path, sub: str, event: str
) -> None:
    assert_degraded_fail_open(run_hook(tmp_path, "hooks", sub, stdin=""), event)


def test_a_bad_flag_on_a_non_hook_command_still_exits_two(tmp_path: Path) -> None:
    """Negative case: only the two hook events fail open; a human's typo elsewhere is still a usage error."""
    done = run_hook(tmp_path, "hooks", "mode", "--no-such-flag")
    assert done.returncode == 2 and done.stdout == ""
    assert run_hook(tmp_path, "--no-such-flag").returncode == 2
