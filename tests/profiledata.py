# SPDX-License-Identifier: MIT
"""Fixtures for the profile tests: a document whose profiles are written here, so they do not depend on shipped text."""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any, TypeVar

import pytest
import yaml

from agentsdata import agents_dict
from safo.agentsfile import AgentsFile, load_agents, parse_agents
from safo.errors import ConfigError
from safo.profile import Profile

T = TypeVar("T")

LESSON = "lessons:codexs-sandbox-cannot-commit-inside-a-git-worktree"
OTHER_LESSON = "lessons:every-copilot-pull-request-needed-fixes"
OUTCOMES = "outcomes:v1:2026-10:copilot:runs>=4"
COHORT = ["claude-lead", "claude-sonnet", "claude-opus"]
MINIMAL_CLAUDE = {"status": "unmeasured", "persona": "adversarial-reviewer"}
MINIMAL_CODEX = {
    "status": "profiled",
    "brief": {"inline": "Work from this prompt alone and read state from files."},
    "dont": [{"text": "Expect it to commit inside a git worktree.", "evidence": LESSON}],
}


def prof(parsed: AgentsFile, agent: str) -> Profile:
    """The agent's profile, which the test knows is there."""
    found = parsed.agent(agent).profile
    assert found is not None
    return found


def need(value: T | None) -> T:
    assert value is not None
    return value


def claim(text: str = "Expect it to commit inside a git worktree.", evidence: str = LESSON) -> dict[str, str]:
    return {"text": text, "evidence": evidence}


def doc() -> dict[str, Any]:
    """The shipped document with every profile replaced by a small one defined in this file."""
    d = copy.deepcopy(agents_dict())
    for agent in d["agents"].values():
        agent.pop("profile", None)
    d.pop("profile_migration", None)
    d["profile_migration"] = {"agents": list(COHORT)}
    agents = d["agents"]
    agents["claude-haiku"]["profile"] = {
        "status": "profiled",
        "brief": {"inline": "Copy the plan exactly and report every concern."},
        "dont": [claim("Hand it security code nobody has reviewed.")],
    }
    agents["codex"]["profile"] = copy.deepcopy(MINIMAL_CODEX)
    agents["copilot"]["profile"] = {"status": "unmeasured"}
    agents["ollama"]["profile"] = {"status": "unmeasured", "brief": {"inline": "Answer in the format asked for."}}
    return d


def profile(d: dict[str, Any], agent: str) -> dict[str, Any]:
    p = d["agents"][agent]["profile"]
    assert isinstance(p, dict)
    return p


def rejects(d: object, pattern: str, **kwargs: Any) -> None:
    with pytest.raises(ConfigError, match=pattern):
        parse_agents(d, **kwargs)


def write(path: Path, d: dict[str, Any], mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(d, width=10_000))
    path.chmod(mode)
    return path


def loads(tmp_path: Path, d: dict[str, Any]) -> AgentsFile:
    return load_agents(write(tmp_path / "agents.yaml", d))


def put(tmp_path: Path, rel: str, data: bytes | str) -> Path:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    return path


def template_doc(rel: str = "templates/brief.md") -> dict[str, Any]:
    d = doc()
    profile(d, "codex")["brief"] = {"template": rel}
    return d


def fifo(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(path)
    return path
