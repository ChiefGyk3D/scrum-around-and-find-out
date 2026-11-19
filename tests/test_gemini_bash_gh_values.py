# SPDX-License-Identifier: Apache-2.0
"""Every value of an allowed code host option must be a known literal, and body-like options are not repeated (#388).

An environment expansion, a braced expansion or a command substitution in a body, comment, title or label is text the
shell fills in at run time: it can carry local data to the network, so the command is not proven. A repeated body option
could hide a protected literal behind a final expanded one. Shapes are built from fragments at run time.
"""

from __future__ import annotations

import pytest

from safo import geminibrief

GH = "g" + "h"
TEXT = "dop" + "pler pr" + "d"
VAR = "SEC" + "RET"

VALUES = [
    f'"{TEXT} ${VAR}"',
    f'"{TEXT} ${{{VAR}}}"',
    f'"{TEXT} $(date)"',
    f'"{TEXT} $({VAR.lower()} x)"',
    f"${VAR}",
    f"${{{VAR}}}",
]


def denied(command: str) -> bool:
    return geminibrief.shell_command_class(command) is not None


def shapes() -> list[str]:
    out: list[str] = []
    for v in VALUES:
        out += [
            f"{GH} issue comment 5 --body {v}",
            f"{GH} issue comment 5 --body='{TEXT}' --body {v}",
            f"{GH} pr comment 3 --body {v} --body '{TEXT}'",
            f"{GH} issue create -t x --body {v}",
            f"{GH} pr create -t x -b '{TEXT}' --label {v}",
            f"{GH} pr create --title {v} --body '{TEXT}'",
            f"{GH} issue edit 5 --body {v}",
            f"{GH} pr edit 3 --title {v} --body '{TEXT}'",
            f"{GH} pr edit 3 --body '{TEXT}' --add-label {v}",
            f"{GH} pr edit 3 --body '{TEXT}' --remove-label {v}",
            f"{GH} pr review 3 --approve --body {v}",
            f"{GH} issue close 5 --comment {v}",
            f"{GH} issue close 5 -c '{TEXT}' -r {v}",
            f"{GH} issue reopen 5 -c {v}",
        ]
    return [f"{c} ; echo '{TEXT}'" for c in out]


@pytest.mark.parametrize("command", shapes())
def test_an_expanded_value_is_not_proven_literal(command: str) -> None:
    # a command with the comment form can be allowed by the comment path only when nothing expands; none of these is
    assert denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        f"{GH} issue comment 5 --body '{TEXT}' --body 'x'",
        f"{GH} issue comment 5 -b '{TEXT}' -b 'x'",
        f"{GH} issue comment 5 -b '{TEXT}' --body 'x'",
        f"{GH} issue create -t x -b '{TEXT}' --body y",
        f"{GH} issue create -t x -t y -b '{TEXT}'",
        f"{GH} pr edit 3 -b '{TEXT}' -b y",
        f"{GH} pr review 3 --approve -b '{TEXT}' -b y",
        f"{GH} issue close 5 -c '{TEXT}' --comment y",
        f"{GH} issue reopen 5 -c '{TEXT}' -c y",
    ],
)
def test_a_repeated_body_comment_or_title_option_is_not_proven(command: str) -> None:
    assert denied(command), command


def test_known_literals_including_an_ansi_c_string_are_still_allowed() -> None:
    assert geminibrief.shell_command_class(f"{GH} issue comment 5 --body '{TEXT}'") is None
    assert geminibrief.shell_command_class(f'{GH} issue comment 5 --body "{TEXT} plain"') is None
    assert geminibrief.shell_command_class(f"{GH} issue comment 5 --body $'caf\\u00e9 {TEXT}'") is None
    assert geminibrief.shell_command_class(f"{GH} pr create -t x -b '{TEXT}' -l a -l b") is None
