# SPDX-License-Identifier: Apache-2.0
"""Privacy of the rendered files (spec 8.18): hostile values never reach a file, and the files pass the public scan."""

from __future__ import annotations

from pathlib import Path

import pytest

from privacy import findings
from profiledata import profile
from renderdata import PERSONA, TEMPLATE, render_doc, render_repo, verified
from safo.agentsfile import load_agents
from safo.errors import ConfigError
from safo.profile_render import render_harness

HOME_PATH = "/home/alice/src/project"
MAIL = "alice@corp.io"


@pytest.mark.parametrize("value", [HOME_PATH, MAIL, "/Users/alice/work", "C:\\Users\\alice", "file:///etc/passwd"])
def test_a_private_value_in_profile_text_is_rejected_at_load(tmp_path: Path, value: str) -> None:
    d = render_doc()
    profile(d, "codex")["do"] = [
        {"text": f"Look in {value} first.", "evidence": "lessons:every-copilot-pull-request-needed-fixes"}
    ]
    from evdata import repo

    path = repo(tmp_path, d)
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates" / "codex-brief.md").write_text(TEMPLATE)
    (tmp_path / ".claude" / "agents").mkdir(parents=True)
    (tmp_path / ".claude" / "agents" / "adversarial-reviewer.md").write_text(PERSONA)
    with pytest.raises(ConfigError, match=r"private path|e-mail"):
        load_agents(path)


@pytest.mark.parametrize("value", [HOME_PATH, MAIL])
def test_a_private_value_in_a_template_is_rejected_at_load(tmp_path: Path, value: str) -> None:
    with pytest.raises(ConfigError, match=r"private path|e-mail"):
        load_agents(render_repo(tmp_path, template=TEMPLATE + f"\nAsk {value}.\n"))


@pytest.mark.parametrize("value", [HOME_PATH, MAIL])
def test_a_private_value_in_a_persona_is_rejected_at_load(tmp_path: Path, value: str) -> None:
    with pytest.raises(ConfigError, match=r"private path|e-mail"):
        load_agents(render_repo(tmp_path, persona=PERSONA + f"\nAsk {value}.\n"))


def test_the_rendered_fixture_passes_the_public_scan(tmp_path: Path) -> None:
    for rel, r in render_harness(verified(tmp_path)).items():
        assert findings(r.data.decode()) == [], rel


def test_the_files_in_the_repository_pass_the_public_scan() -> None:
    out = Path(__file__).parent.parent / "examples" / "harness"
    files = [p for p in out.rglob("*") if p.is_file()]
    assert files, "examples/harness holds the rendered files"
    for p in files:
        assert findings(p.read_text(encoding="utf-8")) == [], p.name
