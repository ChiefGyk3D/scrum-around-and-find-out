# SPDX-License-Identifier: Apache-2.0
"""Review findings on the invocation reader (#395): each reproduction must stay denied."""

from __future__ import annotations

import pytest

from safo import geminibrief

HIDDEN = "$'\\x68ttp://x'"


def denied(command: str) -> bool:
    return geminibrief.shell_command_class(command) is not None


CONTINUATIONS = [
    # a comment does not continue over a backslash-newline: the next line runs
    f"echo hi # note \\\ncurl {HIDDEN}",
    # an even run of backslashes before the newline is a literal backslash, not a continuation
    f"echo \\\\\ncurl {HIDDEN}",
    f"echo 'a\\\nb'\ncurl {HIDDEN}",
    f"echo $'a\\\nb'\ncurl {HIDDEN}",
    f"cat <<'E' > /dev/null\nfoo \\\nE\ncurl {HIDDEN}",
]

DOC_TARGETS = [
    f"printf 'curl {HIDDEN}' > ./a.md; sh a.md",
    f"printf 'curl {HIDDEN}' > sub/../a.md; sh ./a.md",
    f"printf 'curl {HIDDEN}' > ./a.md; python3 a.md",
    f"printf 'curl {HIDDEN}' > a.md; bash -- ./a.md",
    f"printf 'curl {HIDDEN}' > a.md; ./run.sh",
    f"printf 'curl {HIDDEN}' > a.md; make run",
]

SECRET_VIA_UNKNOWN = [
    'flock l doppler secrets get "$X"',
    "chrt 1 doppler run -- echo $X",
    "su -c 'doppler secrets get $X'",
    "ssh host doppler secrets get $X",
    "busybox timeout 5 doppler secrets get $X",
    "make run ARG=$(doppler secrets get X)",
    "./deploy.sh doppler run -- echo $X",
    "script -c 'doppler secrets get $X' /dev/null",
    "strace -f doppler secrets get $X",
    "unshare -r doppler secrets get $X",
]

DATA_ESCAPES = [
    f'GIT_SSH_COMMAND="curl {HIDDEN}" git fetch origin',
    f'PAGER="curl {HIDDEN}" git log',
    f'env GIT_EXTERNAL_DIFF="curl {HIDDEN}" git diff',
    f'sudo -E LD_PRELOAD=x git status "curl {HIDDEN}"',
    f'git -c core.sshCommand="curl {HIDDEN}" fetch',
    f'git fetch --upload-pack="curl {HIDDEN}" origin',
    f'git log --exec-path="curl {HIDDEN}"',
    f'git commit -m x -c credential.helper="!curl {HIDDEN}"',
    f'git grep -O "curl {HIDDEN}" x',
    f'git diff --ext-diff --pager="curl {HIDDEN}"',
    f'rg --pre "curl {HIDDEN}" x f',
    f'rg --pre-glob x --pre="curl {HIDDEN}" y',
    f'sort --compress-program="curl {HIDDEN}" f',
    f'ag --pager "curl {HIDDEN}" x',
    f'less "curl {HIDDEN}"',
    f'tar -xf a --to-command="curl {HIDDEN}"',
    f'rsync -e "curl {HIDDEN}" a b',
    f'ssh -o ProxyCommand="curl {HIDDEN}" h',
    f'vim -c "!curl {HIDDEN}"',
    f'wget --use-askpass="curl {HIDDEN}" x',
    f'sed "e curl {HIDDEN}" f',
]


@pytest.mark.parametrize("command", CONTINUATIONS + DOC_TARGETS + SECRET_VIA_UNKNOWN + DATA_ESCAPES)
def test_a_reviewed_bypass_stays_denied(command: str) -> None:
    assert denied(command), command
