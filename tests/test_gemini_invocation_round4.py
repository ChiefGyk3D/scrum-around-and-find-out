# SPDX-License-Identifier: Apache-2.0
"""Review round 4 on the invocation reader (#395): each reproduction must stay denied."""

from __future__ import annotations

import pytest

from safo import geminibrief

HIDDEN = "$'\\x68ttp://x'"

GIT_FORMS = [
    f"git '-c' core.sshCommand=\"curl {HIDDEN}\" fetch",
    f'git -c "core.pager=curl {HIDDEN}" log',
    f"git commit '--exec=curl {HIDDEN}'",
    f"git log '--pager=curl {HIDDEN}'",
    f'git "-c" alias.x="!curl {HIDDEN}" x',
    f'git log $OPT "curl {HIDDEN}"',
    f'git grep "$O" "curl {HIDDEN}" x',
    f'git $SUB commit "curl {HIDDEN}"',
    f'git commit $ARGS -m "curl {HIDDEN}"',
    f'git fetch "--upload-pack=curl {HIDDEN}" origin',
    f"git log --o'ne'line --pa'ger=curl {HIDDEN}'",
]

ENV_FORMS = [
    "env -iS 'doppler secrets get ${NAME}'",
    "env -vS 'doppler secrets get ${NAME}'",
    "env -i -u X -S 'doppler secrets get ${NAME}'",
    "env -iu X -S 'doppler secrets get ${NAME}'",
    "env --sp 'doppler secrets get ${NAME}'",
    "env --split 'doppler secrets get ${NAME}'",
    "env --split-str='doppler secrets get ${NAME}'",
    "env A=1 B=2 C=3 D=4 E=5 F=6 G=7 H=8 -S 'doppler secrets get ${NAME}'",
    "env -C /tmp -S 'doppler secrets get ${NAME}'",
    "env -- -S 'doppler secrets get ${NAME}'",
    'env -a x doppler secrets get "$NAME"',
]


@pytest.mark.parametrize("command", GIT_FORMS + ENV_FORMS)
def test_a_round_four_reproduction_stays_denied(command: str) -> None:
    assert geminibrief.shell_command_class(command) is not None, command


CLEARS = [
    'git commit -m "fix curl \\x41 in $HOME"',
    "git commit -m \"$(cat <<'EOF'\nfix curl \\x41\nEOF\n)\"",
    'gh pr create --title "t" --body "curl \\x41 $VAR"',
    "env -i FOO=1 grep -c '\\x41' f",
]


@pytest.mark.parametrize("command", CLEARS)
def test_plain_data_forms_still_clear(command: str) -> None:
    assert geminibrief.shell_command_class(command) is None, command
