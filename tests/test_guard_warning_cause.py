# SPDX-License-Identifier: Apache-2.0
"""#615 item 4: the visible warning names its cause, and a probe notice does not read like a denial."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from geminidata import write_config
from guardhealthdata import event, guard
from hooksdata import agents_file, hooks, read_log
from safo import geminibrief, guardlog
from safo.gemini import Locations
from safo.guardlog import warning_for


@pytest.fixture
def agents(tmp_path: Path, gemini_locations: Locations) -> Path:
    write_config(
        gemini_locations.config, "http://127.0.0.1:9", tmp_path / "data" / "ledger.jsonl", private_terms="none"
    )
    return agents_file(tmp_path / "agents.yaml")


def test_each_cause_has_its_own_visible_warning() -> None:
    texts = {code: warning_for(code, "PreToolUse") for code in ("input-parse", "input-oversize", "input-shell")}
    assert len(set(texts.values())) == 3
    assert "shell command" in texts["input-shell"] and "denied" in texts["input-shell"]
    assert "too large" in texts["input-oversize"]
    assert texts["input-parse"] == guardlog.WARNING  # the old generic text still means "could not be read"


def test_a_probe_notice_names_its_cause_and_says_nothing_was_denied() -> None:
    for code in ("input-parse", "config", "probe", "state-write", "timeout"):
        text = warning_for(code, "SessionStart")
        # other tools and tests key on the word degraded, so it stays; the cause and "nothing was denied" are added
        assert text.startswith("SAFO routing guard degraded:"), code
        assert "session probe could not finish" in text and "Nothing was denied" in text, code


def test_the_shell_warning_reaches_the_host_and_names_the_cause(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(geminibrief, "shell_command_class", lambda *_a, **_k: geminibrief.SHELL_UNVERIFIED)
    data = json.loads(guard(agents, _private_home, event("echo hello")))
    assert data["systemMessage"] == warning_for("input-shell", "PreToolUse")
    assert "input-shell" in data["hookSpecificOutput"]["additionalContext"]


def test_a_failing_probe_event_shows_the_probe_notice(_private_home: Path) -> None:
    out = hooks("probe", home=_private_home, stdin="{not json")[1]
    data = json.loads(out)
    assert data["systemMessage"] == warning_for("input-parse", "SessionStart")
    assert read_log(_private_home)[-1]["diagnostic"] == "input-parse"
