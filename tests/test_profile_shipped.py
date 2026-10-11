# SPDX-License-Identifier: MIT
"""The shipped agents.yaml: profiles only for what docs/lessons.md supports, in pointer form, and the slug function."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from profiledata import prof
from safo.agentsfile import MIGRATION_COHORT, AgentsFile, load_agents
from safo.profile import Evidence, slugify

ROOT = Path(__file__).parent.parent
LESSONS = (ROOT / "docs" / "lessons.md").read_text(encoding="utf-8")
HEADINGS = {slugify(m[1]) for m in re.finditer(r"^#{2,6} (.+)$", LESSONS, re.MULTILINE)}


def shipped() -> AgentsFile:
    return load_agents(ROOT / "agents.yaml")


@pytest.mark.parametrize(
    ("heading", "slug"),
    [
        ("Codex's sandbox cannot commit inside a git worktree", "codexs-sandbox-cannot-commit-inside-a-git-worktree"),
        ("Every Copilot pull request needed fixes", "every-copilot-pull-request-needed-fixes"),
        (
            "Any num_ctx other than the loaded one reloads the model (2026-10-07 evening)",
            "any-num_ctx-other-than-the-loaded-one-reloads-the-model-2026-10-07-evening",
        ),
        (
            "Editing a field's options through the API wipes the values",
            "editing-a-fields-options-through-the-api-wipes-the-values",
        ),
        ("`gh api --paginate` needs `$endCursor`", "gh-api---paginate-needs-endcursor"),
        ("  Leading and trailing  ", "leading-and-trailing"),
        ("A  B", "a--b"),
        ("Café au lait", "café-au-lait"),
    ],
)
def test_slugify_is_the_github_heading_slug(heading: str, slug: str) -> None:
    assert slugify(heading) == slug


def test_the_cohort_agents_have_no_profile_and_the_four_measured_agents_do() -> None:
    a = shipped()
    for agent_id in MIGRATION_COHORT:
        assert a.agent(agent_id).profile is None
    for agent_id in ("claude-haiku", "copilot", "codex", "ollama"):
        assert a.agent(agent_id).profile is not None, agent_id
    assert a.agent("maintainer").profile is None
    assert a.warnings == ()


def test_the_measured_status_per_agent() -> None:
    a = shipped()
    assert {x: prof(a, x).status for x in ("claude-haiku", "copilot", "codex", "ollama")} == {
        "claude-haiku": "profiled",
        "copilot": "profiled",
        "codex": "profiled",
        "ollama": "profiled",
    }


def test_every_shipped_claim_is_in_pointer_form_and_every_lessons_slug_is_a_real_heading() -> None:
    pointers: list[Evidence] = []
    for agent in shipped().agents:
        p = agent.profile
        if p is None:
            continue
        pointers += [e.evidence for e in (*p.do, *p.dont)]
        pointers += [e.evidence for e in p.must_not_get]
        pointers += [x.evidence for x in (p.context_ceiling, p.output_cap) if x is not None]
        pointers += [x.evidence for x in (p.thinking,) if x is not None]
        if p.review_gate:
            pointers += [c.evidence for c in p.review_gate.checks]
        assert not p.models, "no model layers until outcomes with a model exist"
    assert pointers
    for e in pointers:
        assert e.kind == "lessons", e.raw
        assert e.ref in HEADINGS, f"{e.raw}: no such heading in docs/lessons.md"


def test_the_codex_and_haiku_and_copilot_and_ollama_claims_are_the_ones_the_lessons_support() -> None:
    a = shipped()
    codex = a.agent("codex").profile
    assert codex is not None and codex.brief is not None and codex.brief.inline
    assert any("commit" in c.text and "worktree" in c.text for c in codex.dont)
    copilot = a.agent("copilot").profile
    assert copilot is not None and copilot.review_gate is not None
    assert [c.code for c in copilot.review_gate.checks] == ["test_vs_behaviour", "workflow_permissions"]
    ollama = a.agent("ollama").profile
    assert ollama is not None and ollama.thinking is not None and ollama.thinking.value == "off"
    haiku = a.agent("claude-haiku").profile
    assert haiku is not None and any("security" in c.text.lower() for c in (*haiku.do, *haiku.dont))
