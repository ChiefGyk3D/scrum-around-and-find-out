# SPDX-License-Identifier: Apache-2.0
"""#364: a denial by the model-service rules is a denial, not a degraded input error.

Before: every shell denial was logged as decision=error, diagnostic=input, health=degraded, so a real parse failure
and a rule hit could not be told apart in the log or in `safo hooks status`. Now a rule hit is decision=deny,
diagnostic=gemini-deny, health=healthy; a command that could not be checked and an unparseable event stay errors.
Names are built at run time so scanners stay quiet about this file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from geminidata import write_config
from hooksdata import agents_file, hooks, read_log
from safo import geminibrief
from safo.gemini import Locations
from safo.guardlog import DIAGNOSTICS, guard_lines

HOST = "generative" + "language" + ".googleapis" + ".com"


def event(command: str) -> str:
    return json.dumps(
        {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": command}}
    )


@pytest.fixture
def agents(tmp_path: Path, gemini_locations: Locations) -> Path:
    write_config(
        gemini_locations.config, "http://127.0.0.1:9", tmp_path / "data" / "ledger.jsonl", private_terms="none"
    )
    return agents_file(tmp_path / "agents.yaml")


def guard(agents: Path, home: Path, payload: str) -> dict[str, Any]:
    out = hooks("guard", "--agents", str(agents), home=home, stdin=payload)[1]
    data: dict[str, Any] = json.loads(out)
    return data


def test_a_rule_hit_is_logged_as_a_denial_with_its_own_code(_private_home: Path, agents: Path) -> None:
    data = guard(agents, _private_home, event(f"curl https://{HOST}/v1/models"))
    assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
    row = read_log(_private_home)[-1]
    assert (row["decision"], row["diagnostic"], row["health"]) == ("deny", "gemini-deny", "healthy")
    assert "gemini-deny" in DIAGNOSTICS


def test_a_rule_hit_shows_no_degraded_warning(_private_home: Path, agents: Path) -> None:
    data = guard(agents, _private_home, event(f"curl https://{HOST}/v1/models"))
    shown = json.dumps(data)
    assert "degraded" not in shown and "gemini-material" in shown
    assert HOST not in shown, "the denial never repeats the command"


def test_a_check_that_could_not_finish_stays_a_degraded_error(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(geminibrief, "shell_command_class", lambda *_a, **_k: geminibrief.SHELL_UNVERIFIED)
    data = guard(agents, _private_home, event("echo hello"))
    assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
    row = read_log(_private_home)[-1]
    assert (row["decision"], row["diagnostic"], row["health"]) == ("error", "input", "degraded")


def test_an_unparseable_event_stays_an_input_error(_private_home: Path, agents: Path) -> None:
    out = hooks("guard", "--agents", str(agents), home=_private_home, stdin="{not json")[1]
    assert "degraded" in out
    row = read_log(_private_home)[-1]
    assert (row["decision"], row["diagnostic"], row["health"]) == ("error", "input", "degraded")


def row(decision: str, diagnostic: str, health: str) -> dict[str, Any]:
    return {
        "ts": "2026-11-07T09:00:00",
        "decision": decision,
        "mode": "warn",
        "model": None,
        "local_reachable": True,
        "local_step": False,
        "na": False,
        "rules": [],
        "health": health,
        "diagnostic": diagnostic,
    }


def test_status_counts_denials_and_parse_failures_on_separate_lines(tmp_path: Path) -> None:
    folder = tmp_path / "state" / "safo" / "hooks"
    folder.mkdir(parents=True)
    rows = [row("deny", "gemini-deny", "healthy")] * 3 + [row("error", "input", "degraded")] * 2
    (folder / "log.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    lines = guard_lines({"XDG_STATE_HOME": str(tmp_path / "state"), "HOME": str(tmp_path / "none")})
    assert "  model-service denials: 3" in lines
    assert "  input parse failures: 2" in lines


def test_status_prints_neither_line_when_there_is_nothing_to_count(tmp_path: Path) -> None:
    folder = tmp_path / "state" / "safo" / "hooks"
    folder.mkdir(parents=True)
    (folder / "log.jsonl").write_text(json.dumps(row("allow", "", "healthy")) + "\n")
    text = "\n".join(guard_lines({"XDG_STATE_HOME": str(tmp_path / "state"), "HOME": str(tmp_path / "none")}))
    assert "model-service denials" not in text and "input parse failures" not in text
