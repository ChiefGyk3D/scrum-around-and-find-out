# SPDX-License-Identifier: Apache-2.0
"""A word consumed as an option value is never itself read as a value-taking option (#388).

The code host verbs are checked word by word: the word after `--body` is its value. If that value word equals another
value-taking option name, it must not shift which later word counts as a value, or a later editor option is skipped.
"""

from __future__ import annotations

import pytest

from safo import geminibrief

TEXT = "dop" + "pler pr" + "d"
GH = "g" + "h"


@pytest.mark.parametrize(
    "command",
    [
        f"{GH} issue comment 5 -b -b --editor '{TEXT}'",
        f"{GH} issue comment 5 --body --body --editor '{TEXT}'",
        f"{GH} issue comment 5 --body --title --editor '{TEXT}'",
        f"{GH} pr create --title --title -e --body '{TEXT}'",
        f"{GH} pr comment 3 -F -F -e '{TEXT}'",
        f"{GH} pr comment 3 --body-file --body -we '{TEXT}'",
    ],
)
def test_a_value_word_that_names_an_option_does_not_hide_a_later_editor_option(command: str) -> None:
    assert geminibrief.shell_command_class(command) is not None, command


def test_the_same_options_with_real_values_are_allowed() -> None:
    assert geminibrief.shell_command_class(f"{GH} issue comment 5 --body '{TEXT}'") is None
    assert geminibrief.shell_command_class(f"{GH} pr create --title 't' --body '{TEXT}'") is None
