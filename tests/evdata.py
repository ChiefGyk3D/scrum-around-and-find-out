# SPDX-License-Identifier: MIT
"""Fixtures for the evidence tests: a repository-shaped directory with agents.yaml, a lessons file and an outcomes log."""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from profiledata import doc, put, write
from safo.outcomes import Outcome

LESSON_HEADINGS = (
    "Codex's sandbox cannot commit inside a git worktree",
    "Every Copilot pull request needed fixes",
)
CARD = "https://github.com/acme/widgets/pull/{n}"
TODAY = dt.date(2026, 10, 11)


def lessons_text(headings: Iterable[str] = LESSON_HEADINGS, body: str = "The measured fact.") -> str:
    parts = ["# Lessons\n\n## 2026-10 (a week)\n\n"]
    for h in headings:
        parts.append(f"### {h}\n\n{body} ({h})\n\nA second paragraph.\n\n")
    return "".join(parts)


def rec(
    n: int = 1,
    *,
    agent: str = "copilot",
    date: str = "2026-10-05",
    model: str | None = None,
    rounds: int = 1,
    card: str | None = "",
    shape: str = "small-mechanical-pr",
    findings: dict[str, int] | None = None,
    credits: int | None = None,
) -> Outcome:
    return Outcome(
        date,
        CARD.format(n=n) if card == "" else card,
        agent,
        shape,
        rounds,
        dict(findings or {}),
        None,
        None,
        "",
        model,
        credits,
    )


def repo(
    tmp_path: Path,
    d: dict[str, Any] | None = None,
    *,
    lessons: Iterable[str] | None = LESSON_HEADINGS,
    outcomes: Iterable[Outcome] | None = None,
    sources: dict[str, str] | None = None,
    codeowners: str | None = "* @owner\n",
) -> Path:
    """tmp_path/agents.yaml with docs/lessons.md (when `lessons`) and docs/outcomes.jsonl (when `outcomes`) beside it."""
    d = d if d is not None else doc()
    if lessons is not None:
        put(tmp_path, "docs/lessons.md", lessons_text(lessons))
    if outcomes is not None:
        put(tmp_path, "docs/outcomes.jsonl", "".join(o.to_json() + "\n" for o in outcomes))
        d["evidence_sources"] = {"outcomes": "docs/outcomes.jsonl"}
    if sources is not None:
        d["evidence_sources"] = sources
    if codeowners is not None:
        put(tmp_path, ".github/CODEOWNERS", codeowners)
    return write(tmp_path / "agents.yaml", d)
