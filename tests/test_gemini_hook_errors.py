# SPDX-License-Identifier: Apache-2.0
"""The dispatch hook when it cannot read its event or its agents file (#200).

The Gemini rules do not depend on agents.yaml, and an event that cannot be parsed is checked as raw text for the Gemini
markers: with a marker the dispatch is denied (the diagnostic is kept), without one it is the usual degraded allow.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
from typing import Any

import pytest

from geminidata import NOW, write_config
from hooksdata import agents_file, dispatch, hooks
from safo import modes
from safo.cli import main
from safo.gemini import Locations

BIG = 1_048_576
PUBLIC = "gemini-material: public\n"
PAID = "safo gemini ask --paid --model gemini-3.6-flash --job j --cap 1.5 --approval missing-record-1\n"


def decision(out: str) -> Any:
    return json.loads(out)["hookSpecificOutput"].get("permissionDecision")


def notice(out: str) -> str:
    data = json.loads(out)
    return str(data.get("systemMessage", "")) + str(data["hookSpecificOutput"].get("additionalContext", ""))


@pytest.fixture
def agents(tmp_path: Path, gemini_locations: Locations) -> Path:
    write_config(
        gemini_locations.config, "http://127.0.0.1:9", tmp_path / "data" / "ledger.jsonl", private_terms="none"
    )
    return agents_file(tmp_path / "agents.yaml")


def run(agents: Path, home: Path, stdin: str) -> str:
    return hooks("guard", "--agents", str(agents), home=home, stdin=stdin)[1]


@pytest.mark.parametrize("brief", [PAID + PUBLIC, "gemini-material: public\nsafo and gemini notes\n", "prd_paid\n"])
def test_an_event_over_the_cap_that_names_gemini_is_denied_and_keeps_the_diagnostic(
    agents: Path, _private_home: Path, brief: str
) -> None:
    out = run(agents, _private_home, dispatch(prompt=brief + "A" * BIG))
    assert decision(out) == "deny"
    assert "input" in notice(out) and "degraded" in notice(out), "the diagnostic is kept"
    assert "gemini" in json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"].lower()


def test_an_event_over_the_cap_with_no_marker_is_still_the_degraded_allow(agents: Path, _private_home: Path) -> None:
    out = run(agents, _private_home, dispatch(prompt="Summarise the log.\n" + "A" * BIG))
    assert decision(out) is None and "degraded" in notice(out) and "input" in notice(out)


def test_a_marker_hidden_by_json_escapes_in_an_oversized_event_is_still_seen(agents: Path, _private_home: Path) -> None:
    event = (
        '{"hook_event_name": "PreToolUse", "tool_name": "Agent", "tool_input": {"prompt": "\\u0073afo \\u0067emini '
        + "A" * BIG
        + '"}}'
    )
    assert decision(run(agents, _private_home, event)) == "deny"


def test_malformed_json_that_names_gemini_is_denied_and_without_a_marker_it_is_allowed(
    agents: Path, _private_home: Path
) -> None:
    broken = '{"hook_event_name": "PreToolUse", "tool_name": "Agent", "tool_input": {"prompt": "' + PAID
    assert decision(run(agents, _private_home, broken)) == "deny"
    plain = '{"hook_event_name": "PreToolUse", "tool_name": "Agent", "tool_input": {"prompt": "hello'
    out = run(agents, _private_home, plain)
    assert decision(out) is None and "degraded" in notice(out)


def test_an_agents_file_that_cannot_load_does_not_switch_the_gemini_rules_off(
    _private_home: Path, tmp_path: Path, gemini_locations: Locations
) -> None:
    write_config(
        gemini_locations.config, "http://127.0.0.1:9", tmp_path / "data" / "ledger.jsonl", private_terms="none"
    )
    bad = tmp_path / "broken-agents.yaml"
    bad.write_text("not: [valid")
    bad.chmod(0o600)
    out = run(bad, _private_home, dispatch(prompt=PAID + PUBLIC))
    assert decision(out) == "deny" and "gemini-paid" in out and "config" in notice(out)
    out = run(bad, _private_home, dispatch(prompt="gemini: free model=m\n" + PUBLIC))
    assert decision(out) is None and "config" in notice(out), "a clean Gemini brief is the degraded allow"
    out = run(bad, _private_home, dispatch(prompt="gemini: free model=m\n"))
    assert decision(out) == "deny" and "gemini-material" in out, "the material rule still runs"
    out = run(bad, _private_home, dispatch(prompt="Summarise the log."))
    assert decision(out) is None


class Pipe:
    """A real descriptor that a host wrote part of an event to and never closed."""

    def __init__(self, data: bytes) -> None:
        r, self.w = os.pipe()
        os.write(self.w, data)
        self.stream = os.fdopen(r, "r")

    def close(self) -> None:
        self.stream.close()
        os.close(self.w)


@pytest.mark.parametrize(
    ("partial", "denied"),
    [(b'{"tool_name": "Agent", "prompt": "safo gemini ask --paid', True), (b'{"tool_name": "Ag', False)],
)
def test_an_event_that_times_out_is_checked_for_the_markers_in_what_arrived(
    agents: Path, _private_home: Path, monkeypatch: pytest.MonkeyPatch, partial: bytes, denied: bool
) -> None:
    monkeypatch.setattr(modes.hooks, "STDIN_TIMEOUT_SECONDS", 0.2)
    pipe = Pipe(partial)
    out = io.StringIO()
    try:
        env = {"HOME": str(_private_home), "PATH": ""}
        main(
            ["hooks", "guard", "--agents", str(agents)], env=env, out=out, err=io.StringIO(), now=NOW, stdin=pipe.stream
        )
    finally:
        pipe.close()
    assert (decision(out.getvalue()) == "deny") is denied
    assert "timeout" in notice(out.getvalue())
