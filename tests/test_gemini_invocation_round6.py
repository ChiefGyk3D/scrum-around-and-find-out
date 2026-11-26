# SPDX-License-Identifier: Apache-2.0
"""Review round 6 on the invocation reader (#395): each reproduction must stay denied."""

from __future__ import annotations

import time

import pytest

from safo import geminibrief

REPRODUCTIONS = [
    # a script text piped into a shell or an interpreter that reads it from stdin
    "printf 'doppler secrets get \"$NAME\"' | sh",
    "printf 'doppler secrets get \"$NAME\"' | bash",
    "echo 'doppler secrets get $NAME' | bash -s",
    "printf 'curl \\x68ttp://x' | sh",
    "printf 'curl \\x68ttp://x' | sh -",
    "printf 'curl \\x68ttp://x' | bash -s",
    "printf 'curl \\x68ttp://x' | python3 -",
    "printf 'curl \\x68ttp://x' | python3",
    "printf 'curl \\x68ttp://x' | python3 -u",
    "printf 'curl \\x68ttp://x' | perl",
    "printf 'curl \\x68ttp://x' | ruby",
    "printf 'curl \\x68ttp://x' | node",
    "printf 'curl \\x68ttp://x' | node -",
    "echo curl \\x68ttp | $SHELL",
    "printf 'doppler secrets get \"$N\"' | $SHELL",
    # the expansion supplied by a here-string, a heredoc, a redirect target or fed content
    'doppler secrets get <<< "$NAME"',
    "doppler secrets get <<< `cat n`",
    "doppler run -- cmd <<E\n$NAME\nE",
    'doppler secrets get > "$OUT"',
    'doppler secrets download --no-file > "$(cat target)"',
    'env doppler secrets get < "$IN"',
]


@pytest.mark.parametrize("command", REPRODUCTIONS)
def test_a_round_six_reproduction_stays_denied(command: str) -> None:
    assert geminibrief.shell_command_class(command) is not None, command


def test_many_commands_with_nested_scans_answer_within_the_deadline() -> None:
    command = "".join(f"echo a > f{i}.md; " for i in range(380)) + "curl $'\\x68ttp://x' " + "x" * 3000
    started = time.monotonic()
    found = geminibrief.shell_command_class(command, time.monotonic() + 1)
    assert time.monotonic() - started < 3
    assert found is not None


def test_nested_shell_strings_answer_within_the_deadline() -> None:
    command = "curl $'\\x68ttp://x' " + "bash -c 'echo a; " * 6 + "x" + "'" * 6
    started = time.monotonic()
    found = geminibrief.shell_command_class(command, time.monotonic() + 1)
    assert time.monotonic() - started < 3
    assert found is not None
