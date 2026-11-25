# SPDX-License-Identifier: Apache-2.0
"""rmguard hardening (#424): inline-program exemption is judged on the normalized path. Names are generic."""

from __future__ import annotations

import pytest

from safo import rmguard

HOME = "/home/u"
DEV = f"{HOME}/.local/share/reach-around-dev"
SRC = f"{HOME}/src"


def program(path: str) -> str:
    return f"python3 <<'EOF'\nimport os\nos.remove('{path}')\nEOF"


def denied(path: str) -> bool:
    return rmguard.check(program(path), HOME, SRC) is not None


@pytest.mark.parametrize(
    "path",
    [
        pytest.param(f"{DEV}/shared/agents/a.log", id="prefix-agents"),
        pytest.param(f"{DEV}/shared/scratchpad/a.log", id="prefix-scratchpad"),
        pytest.param(f"{DEV}/agents/x/../../a.log", id="dotdot-agents"),
        pytest.param(f"{DEV}/agents/x/work/../../../a.log", id="dotdot-deep"),
        pytest.param(f"{DEV}/agents/a.log", id="agents-level"),
        pytest.param(f"{HOME}/agents/../.local/share/reach-around-dev/a.log", id="dotdot-leading"),
        pytest.param("/tmp/claude-1000/-p/s/../../a.log", id="dotdot-tmp"),
        pytest.param("/tmp/claude-1000/-p/scratchpad-x/a.log", id="tmp-near-miss"),
    ],
)
def test_lexical_substring_is_not_an_exemption(path: str) -> None:
    assert denied(path)


@pytest.mark.parametrize(
    "path",
    [
        pytest.param(f"{DEV}/agents/424-impl/work/a.log", id="agent-below"),
        pytest.param("~/.local/share/reach-around-dev/agents/424-impl/work/a.log", id="agent-tilde"),
        pytest.param("/tmp/claude-1000/-p/sess/scratchpad/a.txt", id="tmp-scratchpad"),
    ],
)
def test_real_agent_and_scratch_paths_stay_allowed(path: str) -> None:
    assert not denied(path)
