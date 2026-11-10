# SPDX-License-Identifier: Apache-2.0
"""Daybreak review findings on the invocation reader (#395): each reproduction must stay denied."""

from __future__ import annotations

import time

import pytest

from safo import geminibrief

REPRODUCTIONS = [
    # env -S splits and expands its value into a command
    "env -S 'doppler secrets get ${NAME}'",
    'env -S "doppler secrets get $NAME"',
    "env --split-string='doppler secrets get ${NAME}'",
    # indirect executors
    'busybox env doppler secrets get "$NAME"',
    "busybox sh -c 'doppler secrets get \"$NAME\"'",
    'coproc doppler secrets get "$NAME"',
    'shopt -s expand_aliases; alias d=doppler; d secrets get "$NAME"',
    'alias d=doppler\nd secrets get "$NAME"',
    'ln -s /usr/bin/doppler ./d; ./d secrets get "$NAME"',
    'cp /usr/bin/doppler ./d; chmod +x ./d; ./d secrets get "$NAME"',
    'install -m 755 /usr/bin/doppler ./d && ./d secrets get "$NAME"',
    'mv /usr/bin/doppler ./d; ./d secrets get "$NAME"',
    # sourcing a file written a moment ago
    "printf 'doppler secrets get \"$NAME\"' > a.md; . a.md",
    "printf 'doppler secrets get \"$NAME\"' > a.md; source ./a.md",
    # an execution-capable command that is not proven inert, beside the secret tool name and an expansion
    'echo doppler > x.sh; sh x.sh "$NAME"',
    'printf doppler > d.txt2; ./runner "$NAME"',
    'make -C app run TOKEN="$(cat t)" TOOL=doppler',
    "python3 -c 'import os; os.sys" + "tem(\"doppler secrets get $NAME\")'",
]


@pytest.mark.parametrize("command", REPRODUCTIONS)
def test_a_daybreak_reproduction_stays_denied(command: str) -> None:
    assert geminibrief.shell_command_class(command) is not None, command


def test_a_large_nested_input_is_answered_quickly_and_denied() -> None:
    n = 5000
    command = "curl $'\\x68ttp://x' " + "$(echo " * n + ")" * n
    started = time.monotonic()
    found = geminibrief.shell_command_class(command, time.monotonic() + 5)
    assert time.monotonic() - started < 6
    assert found is not None


def test_a_passed_deadline_inside_the_reader_denies() -> None:
    command = "curl $'\\x68ttp://x' " + "'a' " * 15000
    assert geminibrief.shell_command_class(command, time.monotonic() - 1) is not None
