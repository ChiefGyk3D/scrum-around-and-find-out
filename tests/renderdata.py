# SPDX-License-Identifier: MIT
"""A repository-shaped fixture whose profiles cover all four harnesses, for the renderer, digest and drift tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from evdata import LESSON_HEADINGS, repo
from profiledata import LESSON, OTHER_LESSON, claim, doc, profile, put
from safo.agentsfile import Agent, AgentsFile
from safo.evidence import VerifiedAgents, load_verified_agents
from safo.profile import Profile

PERSONA = (
    "---\n"
    "name: adversarial-reviewer\n"
    "description: Reviews a change adversarially.\n"
    "tools: Read, Grep, Glob\n"
    "disallowedTools: [Write, Edit]\n"
    "---\n"
    "# Adversarial reviewer\n"
    "\n"
    "Find what is wrong. Do not fix it.\n"
)
TEMPLATE = "Work from this prompt alone.\n\n{{task}}\n\nFiles you may edit:\n\n{{files_in_scope}}\n"
RENDER_PATHS = (
    "claude/claude-haiku.md",
    "claude/claude-sonnet.md",
    "codex/codex.prompt.md",
    "copilot/ISSUE_TEMPLATE/copilot-task.yml",
    "copilot/copilot-instructions.md",
    "local/ollama.wrapper.txt",
)


def render_doc() -> dict[str, object]:
    d = doc()
    d["profile_migration"] = {"agents": ["claude-lead", "claude-opus"]}
    d["agents"]["claude-sonnet"]["profile"] = {"status": "unmeasured", "persona": "adversarial-reviewer"}
    profile(d, "codex")["brief"] = {"template": "templates/codex-brief.md"}
    profile(d, "codex")["do"] = [claim("Give it a self-contained prompt.", OTHER_LESSON)]
    profile(d, "claude-haiku")["must_not_get"] = [{"shape": "security-sensitive-code", "evidence": LESSON}]
    d["agents"]["copilot"]["profile"] = {
        "status": "profiled",
        "brief": {"inline": "Keep the pull request small and say what you ran."},
        "review_gate": {
            "required": True,
            "reviewer_differs": True,
            "checks": [{"code": "test_vs_behaviour", "evidence": OTHER_LESSON}],
        },
        "do": [claim("Give it small single-repo pull requests.", OTHER_LESSON)],
        "models": {"gpt-5.1": {"status": "profiled", "dont": [claim("Trust its tests.", OTHER_LESSON)]}},
    }
    d["agents"]["ollama"]["profile"] = {
        "status": "profiled",
        "brief": {"inline": "Answer in the format asked for."},
        "thinking": {"value": "off", "evidence": LESSON},
        "context_ceiling": {"value": 2048, "evidence": LESSON},
        "output_cap": {"value": 512, "evidence": LESSON},
        "do": [claim("Treat its output as a draft.", LESSON)],
    }
    return d


def render_repo(tmp_path: Path, persona: str = PERSONA, template: str = TEMPLATE) -> Path:
    """tmp_path/agents.yaml with the lessons, a persona, a template and a CODEOWNERS beside it."""
    put(tmp_path, ".claude/agents/adversarial-reviewer.md", persona)
    put(tmp_path, "templates/codex-brief.md", template)
    return repo(tmp_path, render_doc(), lessons=LESSON_HEADINGS)


def verified(tmp_path: Path, persona: str = PERSONA, template: str = TEMPLATE) -> VerifiedAgents:
    v = load_verified_agents(render_repo(tmp_path, persona, template), trusted=False)
    v.require_clean()
    return v


def with_profile(v: VerifiedAgents, agent_id: str, **changes: Any) -> VerifiedAgents:
    """The same verified document with fields of one agent's profile replaced (a persona text, say)."""
    agents = []
    for a in v.agents.agents:
        if a.id == agent_id:
            assert a.profile is not None
            a = replace(a, profile=replace(a.profile, **changes))
        agents.append(a)
    return replace(v, agents=replace(v.agents, agents=tuple(agents)))


def with_agent(v: VerifiedAgents, agent_id: str, **changes: Any) -> VerifiedAgents:
    agents: list[Agent] = [replace(a, **changes) if a.id == agent_id else a for a in v.agents.agents]
    doc_: AgentsFile = replace(v.agents, agents=tuple(agents))
    return replace(v, agents=doc_)


def profile_of(v: VerifiedAgents, agent_id: str) -> Profile:
    found = v.agents.agent(agent_id).profile
    assert found is not None
    return found
