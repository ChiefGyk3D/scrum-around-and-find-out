# SPDX-License-Identifier: MIT
"""outcome add and usage --report."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsdata import write_agents
from localcli import cli


def test_outcome_add_appends_a_checked_line_and_usage_report_summarises_it(_private_home: Path, tmp_path: Path) -> None:
    agents = write_agents(tmp_path / "agents.yaml")
    log = tmp_path / "outcomes.jsonl"
    base = ["--agents", str(agents), "--log", str(log)]
    code, out, _ = cli(
        "outcome", "add", "--agent", "codex", "--shape", "research", "--review-rounds", "2",
        "--findings", "important=1", "--tokens", "1000", *base, home=_private_home,
    )  # fmt: skip
    assert code == 0 and "recorded codex / research" in out
    record = json.loads(log.read_text())
    assert record["date"] == "2026-10-07" and record["findings"] == {"important": 1} and record["tokens"] == 1000
    code, _, err = cli("outcome", "add", "--agent", "gpt-nine", "--shape", "research", *base, home=_private_home)
    assert code == 2 and "has no agent 'gpt-nine'" in err and len(log.read_text().splitlines()) == 1
    code, out, _ = cli("usage", "--report", *base, home=_private_home)
    assert code == 0 and "codex" in out and "1 tasks, 1 needed fixes" in out
    code, out, _ = cli("usage", "--report", "--json", *base, home=_private_home)
    assert json.loads(out)["agents"][0]["agent"] == "codex"


def test_outcome_dry_run_creates_neither_log_nor_parent(_private_home: Path, tmp_path: Path) -> None:
    log = tmp_path / "absent" / "outcomes.jsonl"
    code, out, _ = cli(
        "--dry-run", "outcome", "add", "--agent", "codex", "--shape", "research", "--log", str(log), home=_private_home
    )
    assert code == 0 and "nothing written" in out
    assert not log.exists() and not log.parent.exists()


def test_a_hostile_command_line_never_reaches_the_log(_private_home: Path, tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    base = ["outcome", "add", "--agent", "codex", "--shape", "research", "--log", str(log)]
    for extra in (
        ["--note", "my\nnewline"],
        ["--date", "2026-13-01"],
        ["--date", "2026-10-07 10:00:00"],
        ["--card", "https://google.com/search?q=safo"],
        ["--review-rounds", "-1"],
        ["--findings", "critical=1,invalid=2"],
        ["--findings", "critical=1,important=abc"],
        ["--tokens", "-500"],
        ["--requests", "-1"],
    ):
        code, _, _ = cli(*base, *extra, home=_private_home)
        assert code == 2, extra
    with pytest.raises(SystemExit) as stop:  # argparse refuses a non-integer before any mode runs
        cli(*base, "--review-rounds", "1.5", home=_private_home)
    assert stop.value.code == 2
    assert not log.exists()
    code, _, _ = cli(*base, "--note", "", home=_private_home)
    assert code == 0 and len(log.read_text().splitlines()) == 1


def test_the_default_log_is_in_the_state_directory_not_the_current_directory(
    _private_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    monkeypatch.chdir(checkout)
    code, _, _ = cli("outcome", "add", "--agent", "codex", "--shape", "research", home=_private_home)
    assert code == 0 and list(checkout.iterdir()) == []
    assert (_private_home / ".local" / "state" / "safo" / "outcomes.jsonl").is_file()


def test_the_log_inside_the_workspace_is_refused_under_actions(_private_home: Path, tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(ws)}
    code, _, err = cli(
        "outcome", "add", "--agent", "codex", "--shape", "research", "--log", str(ws / "o.jsonl"),
        home=_private_home, extra_env=env,
    )  # fmt: skip
    assert code == 2 and "GITHUB_WORKSPACE" in err and not (ws / "o.jsonl").exists()


def test_report_for_a_month_that_is_not_a_month_is_refused(_private_home: Path, tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    cli("outcome", "add", "--agent", "codex", "--shape", "research", "--log", str(log), home=_private_home)
    for month in ("2026-10-01", "2026-13", "x"):
        code, _, err = cli("usage", "--report", "--month", month, "--log", str(log), home=_private_home)
        assert code == 2 and "YYYY-MM" in err


def test_report_without_a_log_says_so(_private_home: Path, tmp_path: Path) -> None:
    code, _, err = cli("usage", "--report", "--log", str(tmp_path / "none.jsonl"), home=_private_home)
    assert code == 2 and "no outcomes log" in err


def test_report_json_is_one_line_and_a_note_never_appears_in_it(_private_home: Path, tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    cli(
        "outcome",
        "add",
        "--agent",
        "codex",
        "--shape",
        "research",
        "--note",
        "::stop-commands::x",
        "--log",
        str(log),
        home=_private_home,
    )
    code, out, _ = cli("usage", "--report", "--json", "--log", str(log), home=_private_home)
    assert code == 0 and out.count("\n") == 1 and "stop-commands" not in out
