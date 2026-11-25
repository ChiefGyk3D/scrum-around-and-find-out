# SPDX-License-Identifier: Apache-2.0
"""rmguard hardening (#424), round 3: regression cases. Names are generic on purpose; the specifics are tracked privately."""

from __future__ import annotations

import pytest

from safo import rmguard

HOME = "/home/u"
DEV = f"{HOME}/.local/share/reach-around-dev"
SRC = f"{HOME}/src"
RM = f"rm -rf {DEV}/x"


def denied(command: str, cwd: str = SRC) -> bool:
    return rmguard.check(command, HOME, cwd) is not None


CONFIG_DENIED = [
    pytest.param(f"GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.pager GIT_CONFIG_VALUE_0='{RM}' git log", id="c1"),
    pytest.param(f"GIT_CONFIG_PARAMETERS=\"'core.pager'='{RM}'\" git log", id="c2"),
    pytest.param(f"P='{RM}' git --config-env=core.pager=P log", id="c3"),
    pytest.param(f"P='{RM}' git --config-env core.pager=P log", id="c4"),
    pytest.param(f"GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.zz GIT_CONFIG_VALUE_0='!{RM}' git zz", id="c5"),
    pytest.param(f"git --config-env=core.pager=UNSET_NAME log {DEV}", id="c6"),
    pytest.param(f"GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=user.name GIT_CONFIG_VALUE_0=me git log {DEV}", id="c7"),
    pytest.param(f"env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.editor GIT_CONFIG_VALUE_0='{RM}' git log", id="c8"),
    pytest.param(f"GIT_CONFIG_PARAMETERS=\"'core.pager'='unterminated {DEV}\" git log", id="c9"),
]
CONFIG_ALLOWED = [
    pytest.param("A=me git --config-env=user.name=A log", id="c10"),
    pytest.param("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=user.name GIT_CONFIG_VALUE_0=me git log", id="c11"),
    pytest.param("GIT_CONFIG_PARAMETERS=\"'color.ui'='never'\" git log", id="c12"),
]


@pytest.mark.parametrize("command", CONFIG_DENIED)
def test_config_from_environment_is_judged(command: str) -> None:
    assert denied(command)


@pytest.mark.parametrize("command", CONFIG_ALLOWED)
def test_harmless_environment_config_passes(command: str) -> None:
    assert not denied(command)


STDIN_DENIED = [
    pytest.param(f"sudo -s <<'EOF'\n{RM}\nEOF", id="s1"),
    pytest.param(f"sudo -i <<< '{RM}'", id="s2"),
    pytest.param(f"echo '{RM}' | sudo -s", id="s3"),
    pytest.param(f"su <<'EOF'\n{RM}\nEOF", id="s4"),
    pytest.param(f"echo '{RM}' | su root", id="s5"),
    pytest.param(f"echo '{RM}' | script /dev/null", id="s6"),
    pytest.param(f"sudo -u root -s <<'EOF'\n{RM}\nEOF", id="s7"),
]
STDIN_ALLOWED = [
    pytest.param("sudo -s <<'EOF'\necho hi\nEOF", id="s8"),
    pytest.param("su -c 'echo hi'", id="s9"),
]


@pytest.mark.parametrize("command", STDIN_DENIED)
def test_wrapper_shell_reading_stdin_is_a_program(command: str) -> None:
    assert denied(command)


@pytest.mark.parametrize("command", STDIN_ALLOWED)
def test_wrapper_shell_with_harmless_input_passes(command: str) -> None:
    assert not denied(command)


def test_here_string_survives_recursion_through_a_multicall_binary() -> None:
    assert denied(f"busybox sh <<< '{RM}'")
    assert denied(f"toybox bash <<< '{RM}'")
    assert denied(f"busybox busybox sh <<< '{RM}'")
    assert not denied("busybox sh <<< 'echo hi'")
