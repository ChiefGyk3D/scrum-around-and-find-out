# SPDX-License-Identifier: Apache-2.0
"""rmguard hardening (#424), round 3: regression cases. Names are generic on purpose."""

from __future__ import annotations

import pytest

from safo import rmguard

HOME = "/home/u"
DEV = f"{HOME}/.local/share/reach-around-dev"
AGENT = f"{DEV}/agents/424-impl"
SRC = f"{HOME}/src"


def denied(command: str, cwd: str = SRC) -> bool:
    return rmguard.check(command, HOME, cwd) is not None


def program(body: str) -> str:
    return f"python3 <<'EOF'\n{body}\nEOF"


BUILT = [
    pytest.param(f"import os\nos.remove(os.path.join('{AGENT}', '..', '..', 'a.log'))", id="p1"),
    pytest.param(f"import os\nos.chdir('{AGENT}')\nos.remove('../../a.log')", id="p2"),
    pytest.param(f"import os\nos.remove('{AGENT}/work/' + '../../../a.log')", id="p3"),
    pytest.param(f"from pathlib import Path\nPath('{AGENT}/work').joinpath('..', '..').unlink()", id="p4"),
    pytest.param(f"import os\nb = '{AGENT}'\nos.remove(f'{{b}}/../../x')", id="p5"),
    pytest.param(f"import os\nos.remove('{AGENT}/%s' % '../../x')", id="p6"),
    pytest.param(f"import os\nos.remove('{AGENT}/{{}}'.format('../../x'))", id="p7"),
    pytest.param(f"import os\nos.remove('{AGENT}/work/../../x')", id="p8"),
]


@pytest.mark.parametrize("body", BUILT)
def test_hardening_path_building_voids_the_agent_exemption(body: str) -> None:
    assert denied(program(body))


def test_hardening_literal_agent_path_stays_exempt() -> None:
    assert not denied(program(f"import os\nos.remove('{AGENT}/work/a.log')"))
    assert not denied(program(f"import os\nos.remove('{AGENT}/work/a.log')\nos.remove('{AGENT}/work/b.log')"))


FISH = [
    pytest.param(f"fish -C 'rm -rf {DEV}/*.py' -c true", id="f1"),
    pytest.param(f"fish --init-command 'rm -rf {DEV}/*.py' -c true", id="f2"),
    pytest.param(f"fish --init-command='rm -rf {DEV}/*.py' -c true", id="f3"),
    pytest.param(f"fish -C 'rm -rf {DEV}/*.py'", id="f4"),
    pytest.param(f"bash --unknown-option 'rm -rf {DEV}/*.py'", id="f5"),
    pytest.param(f"zsh -Z 'rm -rf {DEV}/*.py'", id="f6"),
]


@pytest.mark.parametrize("command", FISH)
def test_hardening_shell_command_strings_and_unknown_options(command: str) -> None:
    assert denied(command)


def test_hardening_ordinary_shell_invocations_stay_allowed() -> None:
    assert not denied("bash -eu script.sh")
    assert not denied("bash --norc --noprofile -c 'ls'")
    assert not denied("fish -C 'set -x A 1' -c ls")
    assert not denied("bash --version")
