# SPDX-License-Identifier: MIT
"""usage: every meter from local files, read-only, exit 0."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsdata import A_MODELS, B_MODELS, write_agents
from fakeollama import FakeOllama
from localcli import cli
from meterdata import assistant, claude_transcript, codex_session, token_count


def test_usage_prints_every_meter_from_local_files(_private_home: Path, tmp_path: Path) -> None:
    codex_session(_private_home, "a", [token_count(56, 14, tokens=27_000_000)])
    claude_transcript(_private_home, "p/s.jsonl", [assistant("m1", "claude-sonnet-4", 50)])
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS[:1]).serve() as b:
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        code, out, _ = cli("usage", "--agents", str(agents), home=_private_home)
    assert code == 0
    assert "Codex (plus plan): 5-hour window 56%" in out and "weekly 14%" in out and "27,000,000 input tokens" in out
    assert "sonnet      1 messages" in out
    assert "Copilot: gh is not available" in out
    assert "Local LLM instance-a: reachable, loaded: resident-12b-thinking, small-4b-agent" in out
    assert "Local LLM instance-b: reachable, loaded: resident-safety" in out


def test_usage_json_is_one_document_with_every_meter(_private_home: Path, tmp_path: Path) -> None:
    codex_session(_private_home, "a", [token_count(56, 14)])
    code, out, _ = cli("usage", "--json", "--no-local", home=_private_home)
    data = json.loads(out)
    assert code == 0 and data["codex"]["five_hour_percent"] == 56.0 and data["copilot"]["available"] is False
    assert set(data) >= {"codex", "claude", "copilot", "ollama", "generated", "month"}


def test_usage_with_nothing_on_the_machine_is_still_exit_zero(
    _private_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)  # no ./agents.yaml here, so there is nothing to probe
    code, out, err = cli("usage", home=_private_home)
    assert (
        code == 0
        and "Codex: no session files found" in out
        and "Claude Code: no transcripts found" in out
        and err == ""
    )


def test_usage_reads_only_the_home_it_is_given(_private_home: Path, tmp_path: Path) -> None:
    other = tmp_path / "elsewhere"
    codex_session(other, "x", [token_count(99, 99)])
    _, out, _ = cli("usage", "--no-local", home=_private_home)
    assert "no session files found" in out


def test_local_context_repr_hides_environment_token(_private_home: Path) -> None:
    import io

    from meterdata import NOW
    from safo.context import LocalContext

    ctx = LocalContext(io.StringIO(), {"HOME": str(_private_home), "SAFO_TOKEN": "sentinel-credential"}, NOW)
    assert "sentinel-credential" not in repr(ctx)


def test_url_fields_are_redacted_in_usage_json() -> None:
    from safo.meters import as_json
    from safo.ollama import Probe

    p = Probe("test", "http://example.invalid?token=sentinel-credential", True)
    assert "sentinel-credential" not in json.dumps(as_json(p)) and "sentinel-credential" not in repr(p)


def test_usage_json_cannot_carry_a_workflow_command(_private_home: Path) -> None:
    codex_session(
        _private_home, "a", [{"type": "session_meta", "payload": {"cwd": "/w/::stop-commands::x"}}, token_count(1, 1)]
    )
    code, out, _ = cli("usage", "--json", "--no-local", home=_private_home)
    assert code == 0 and "::" not in out and out.count("\n") == 1
    assert json.loads(out)["codex"]["sessions"][0]["cwd"] == "::stop-commands::x"
