# SPDX-License-Identifier: MIT
"""docs/routing.md is generated from agents.yaml, and a test keeps the two from drifting."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from safo.agentsfile import load_agents
from safo.routing_doc import render_routing

ROOT = Path(__file__).parent.parent


def load_script() -> object:
    spec = importlib.util.spec_from_file_location("gen_routing", ROOT / "scripts" / "gen_routing.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_routing"] = module
    spec.loader.exec_module(module)
    return module


def test_the_page_in_the_repository_is_what_agents_yaml_renders() -> None:
    expected = render_routing(load_agents(ROOT / "agents.yaml"))
    assert (ROOT / "docs" / "routing.md").read_text() == expected, "run: python scripts/gen_routing.py --write"


def test_the_check_flag_passes_now_and_fails_on_a_hand_edit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script = load_script()
    assert script.main(["--check"]) == 0  # type: ignore[attr-defined]
    edited = tmp_path / "routing.md"
    edited.write_text("# Routing\n\nhand edited\n")
    monkeypatch.setattr(script, "PAGE", edited)
    assert script.main(["--check"]) == 1  # type: ignore[attr-defined]
    assert "stale" in capsys.readouterr().err


def test_the_rendering_names_shapes_agents_thresholds_and_says_it_is_generated() -> None:
    text = render_routing(load_agents(ROOT / "agents.yaml"))
    assert "Generated from `agents.yaml`" in text
    assert "| `research` |" in text and "Codex" in text
    assert "Codex above 80% of the 5-hour window: use Claude Sonnet instead." in text
    assert "Copilot coding agent above 70% of the month's AI credits: use Claude Haiku instead." in text
    assert "send exactly the loaded num_ctx (small-4b-agent=8192)" in text
    assert "resident-safety" not in text and "11435" not in text
    assert "Routing order 1:" in text and "Routing order 5:" in text
    assert "cannot commit inside a git worktree" in text
    assert "Needs the maintainer's OK before it is used." in text
    assert "—" not in text
