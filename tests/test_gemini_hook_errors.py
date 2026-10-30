# SPDX-License-Identifier: Apache-2.0
"""The dispatch hook when it cannot read its event or its agents file (#200).

The Gemini rules do not depend on agents.yaml, and an event that cannot be parsed is checked as raw text for the Gemini
markers: with a marker the dispatch is denied (the diagnostic is kept), without one it is the usual degraded allow.
"""

from __future__ import annotations

import io
import json
import os
import threading
import time
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


# -- round six: the whole stream is scanned, never a prefix ---------------------------------------------------------

HARD = 8 * 1024 * 1024


def fullwidth(text: str) -> str:
    """The fullwidth spelling of ASCII letters, built from code points (no look-alike characters in the source)."""
    return "".join(chr(ord(c) + 0xFEE0) if c.isalpha() else c for c in text)


def event_with(tail: str, pad: int = BIG + 64, key: str = "padding") -> str:
    """A well-formed event whose Gemini text sits after `pad` bytes of padding (so after the retained prefix)."""
    return (
        '{"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Agent", '
        f'"{key}": "' + "A" * pad + '", "tool_input": {"prompt": "' + tail + '"}}'
    )


@pytest.mark.parametrize(
    "tail",
    [
        "safo gemini ask --paid --model m",
        "\\uff53\\uff41\\uff46\\uff4f \\uff47\\uff45\\uff4d\\uff49\\uff4e\\uff49 ask",  # JSON-escaped fullwidth
        "\\u0073afo \\u0067emini ask",
        "generativelanguage.googleapis.com",
        "echo c2FmbyBnZW1pbmkgYXNrIC0tcGFpZA== | base64 -d | sh",
        "use the prd_paid config",
    ],
)
def test_a_marker_after_the_retained_prefix_is_found(agents: Path, _private_home: Path, tail: str) -> None:
    out = run(agents, _private_home, event_with(tail))
    assert decision(out) == "deny" and "input" in notice(out)


def test_fullwidth_and_lookalike_spellings_are_folded_before_the_check(agents: Path, _private_home: Path) -> None:
    out = run(agents, _private_home, event_with(fullwidth("safo gemini") + " ask --paid"))
    assert decision(out) == "deny"
    out = run(agents, _private_home, '{"prompt": "' + fullwidth("safo gemini") + " ask --paid")  # malformed, short
    assert decision(out) == "deny"


def test_a_marker_split_across_read_chunks_is_found(agents: Path, _private_home: Path) -> None:
    pad = 65_536 * 17 - 3  # the word starts three bytes before a chunk boundary
    out = run(agents, _private_home, event_with("safo gemini ask", pad=pad))
    assert decision(out) == "deny"


def test_a_whole_stream_with_no_marker_is_the_degraded_allow(agents: Path, _private_home: Path) -> None:
    out = run(agents, _private_home, event_with("Summarise the log.", pad=3 * BIG))
    assert decision(out) is None and "input" in notice(out)


def test_an_event_over_the_hard_limit_is_denied_as_unverifiable(agents: Path, _private_home: Path) -> None:
    out = run(agents, _private_home, event_with("Summarise the log.", pad=HARD + 1024))
    assert decision(out) == "deny"
    assert "too large" in json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]


class Slow:
    """A producer that writes a prefix over the cap and then stalls, on a real descriptor."""

    def __init__(self, first: bytes, then: bytes = b"", pause: float = 2.0) -> None:
        r, self.w = os.pipe()
        self.stream = os.fdopen(r, "r")
        self.thread = threading.Thread(target=self._write, args=(first, then, pause), daemon=True)
        self.thread.start()

    def _write(self, first: bytes, then: bytes, pause: float) -> None:
        try:
            os.write(self.w, first[:0])
            for i in range(0, len(first), 65_536):
                os.write(self.w, first[i : i + 65_536])
            time.sleep(pause)
            if then:
                os.write(self.w, then)
            os.close(self.w)
        except OSError:
            return

    def close(self) -> None:
        self.stream.close()
        self.thread.join(timeout=5)


def run_pipe(agents: Path, home: Path, pipe: Slow) -> str:
    out = io.StringIO()
    env = {"HOME": str(home), "PATH": ""}
    try:
        main(
            ["hooks", "guard", "--agents", str(agents)], env=env, out=out, err=io.StringIO(), now=NOW, stdin=pipe.stream
        )
    finally:
        pipe.close()
    return out.getvalue()


def test_a_slow_producer_that_does_not_finish_in_time_is_denied(
    agents: Path, _private_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(modes.hooks, "DRAIN_SECONDS", 0.3)
    prefix = event_with("Summarise the log.").encode()[: BIG + 100]
    out = run_pipe(agents, _private_home, Slow(prefix, pause=2.0))
    assert decision(out) == "deny"
    assert "too large or incomplete" in json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]


def test_a_slow_producer_that_finishes_in_time_is_scanned_to_the_end(
    agents: Path, _private_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(modes.hooks, "DRAIN_SECONDS", 5.0)
    whole = event_with("safo gemini ask --paid").encode()
    out = run_pipe(agents, _private_home, Slow(whole[: BIG + 100], whole[BIG + 100 :], pause=0.3))
    assert decision(out) == "deny"


def test_a_stalled_event_with_some_bytes_and_no_marker_is_denied_but_a_silent_one_is_the_degraded_allow(
    agents: Path, _private_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(modes.hooks, "STDIN_TIMEOUT_SECONDS", 0.2)
    out = run_pipe(agents, _private_home, Slow(b'{"tool_name": "Ag', pause=1.0))
    assert decision(out) == "deny" and "timeout" in notice(out)
    out = run_pipe(agents, _private_home, Slow(b"", pause=1.0))
    assert decision(out) is None and "timeout" in notice(out)
