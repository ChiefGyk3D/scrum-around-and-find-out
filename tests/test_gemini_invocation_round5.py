# SPDX-License-Identifier: Apache-2.0
"""Review round 5 on the invocation reader (#395): each reproduction must stay denied, and a long word is bounded."""

from __future__ import annotations

import time

import pytest

from safo import geminibrief

HIDDEN = "$'\\x68ttp://x'"

REPRODUCTIONS = [
    # env -S beyond the eighth word, in clusters, after assignments
    "env A=1 B=2 C=3 D=4 E=5 F=6 G=7 H=8 I=9 J=10 -S 'doppler secrets get ${NAME}'",
    "env -i -i -i -i -i -i -i -i -i -S 'doppler secrets get ${NAME}'",
    "env -0iS 'doppler secrets get ${NAME}'",
    "env -u A -u B -u C -u D -iS 'doppler secrets get ${NAME}'",
    # printf -v in every attached or detached form builds a variable
    "printf -vX '\\x68ttp://x'; curl \"$X\"",
    "printf -v X '\\x68ttp://x'; curl \"$X\"",
    "printf -vURL %s '\\x68ttp://x'; curl \"$URL\"",
    f"printf -- -vX '\\x68ttp://x'; curl {HIDDEN}",
    "printf $FLAG X '\\x68ttp://x'; curl \"$X\"",
]


@pytest.mark.parametrize("command", REPRODUCTIONS)
def test_a_round_five_reproduction_stays_denied(command: str) -> None:
    assert geminibrief.shell_command_class(command) is not None, command


@pytest.mark.parametrize(
    "command",
    [
        "curl " + HIDDEN + " " + "a" * 60000,
        "echo " + "a" * 60000 + " | curl " + HIDDEN,
        "curl " + HIDDEN + " " + "a$(" * 15000,
        "curl " + HIDDEN + " " + "'" + "a" * 60000 + "'",
        "curl " + HIDDEN + " " + '"' + "a" * 60000 + '"',
    ],
)
def test_a_very_long_word_is_answered_within_the_deadline(command: str) -> None:
    started = time.monotonic()
    found = geminibrief.shell_command_class(command, time.monotonic() + 2)
    assert time.monotonic() - started < 4
    assert found is not None
