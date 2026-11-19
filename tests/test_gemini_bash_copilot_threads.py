# SPDX-License-Identifier: Apache-2.0
"""The two early review threads on the command-position check, pinned against the current code (#388).

One said control prefixes and options before the secret tool (a conditional, a negation, a piped xargs, an assignment
word with a quoted value holding spaces) let a real run through. The other said the bare production config word was
left out of the guard on text fed to a shell. The old denial is the default again, so every shape here is denied; the
words are built from fragments at run time.
"""

from __future__ import annotations

import pytest

from safo import geminibrief

TOOL = "dop" + "pler"
CFG = "pr" + "d"
SH = "s" + "h"
EV = "ev" + "al"
SRC = "sour" + "ce"


def denied(command: str) -> bool:
    return geminibrief.shell_command_class(command) is not None


@pytest.mark.parametrize(
    "command",
    [
        f"if {TOOL} secrets --config {CFG}; then echo ok; fi",
        f"! {TOOL} secrets --config {CFG}",
        f"printf x | xargs -n1 {TOOL} secrets --config {CFG}",
        f'FOO="x y" {TOOL} secrets get K --config {CFG}',
        f"while {TOOL} secrets --config {CFG}; do break; done",
        f"{{ {TOOL} secrets --config {CFG}; }}",
        f"( {TOOL} secrets --config {CFG} )",
        f"echo ok && ! {TOOL} secrets --config {CFG}",
        f'X="a b" Y=1 {TOOL} secrets get $K',
    ],
)
def test_a_control_prefix_or_option_before_the_tool_does_not_let_it_through(command: str) -> None:
    assert denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        f"echo '{TOOL} secrets --config {CFG}' | {SH}",
        f"{EV} '{TOOL} secrets --config {CFG}'",
        f"{SRC} <(echo '{TOOL} secrets --config {CFG}')",
        f"echo '{TOOL} secrets --config {CFG}' > /tmp/x; {SRC} /tmp/x",
        f"echo '{TOOL} secrets --config {CFG}' | {SH} -s",
    ],
)
def test_text_fed_to_a_shell_is_denied_for_the_bare_config_word_too(command: str) -> None:
    assert denied(command), command
