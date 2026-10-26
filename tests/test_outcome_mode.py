# SPDX-License-Identifier: Apache-2.0
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


def test_the_default_log_in_a_group_writable_state_dir_is_refused_visibly(_private_home: Path) -> None:
    state = _private_home / ".local" / "state" / "safo"
    state.mkdir(parents=True)
    state.chmod(0o770)
    code, _, err = cli("outcome", "add", "--agent", "codex", "--shape", "research", home=_private_home)
    assert code != 0 and "cannot write outcomes log" in err
    assert not (state / "outcomes.jsonl").exists()


def test_an_explicit_log_in_a_group_writable_dir_is_the_users_choice_and_works(
    _private_home: Path, tmp_path: Path
) -> None:
    folder = tmp_path / "shared"
    folder.mkdir()
    folder.chmod(0o770)
    log = folder / "outcomes.jsonl"
    code, _, _ = cli("outcome", "add", "--agent", "codex", "--shape", "research", "--log", str(log), home=_private_home)
    assert code == 0 and log.is_file()


def test_outcome_add_takes_model_and_credits_and_the_report_shows_them(_private_home: Path, tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    base = ["--log", str(log)]
    code, _, _ = cli(
        "outcome", "add", "--agent", "codex", "--shape", "research", "--model", "gpt-5.4", "--credits-used", "12",
        *base, home=_private_home,
    )  # fmt: skip
    assert code == 0
    record = json.loads(log.read_text())
    assert record["model"] == "gpt-5.4" and record["credits_used"] == 12
    code, _, _ = cli("outcome", "add", "--agent", "codex", "--shape", "research", *base, home=_private_home)
    assert code == 0 and "model" not in json.loads(log.read_text().splitlines()[1])
    code, out, _ = cli("usage", "--report", *base, home=_private_home)
    assert code == 0 and "By agent and model" in out
    assert "codex" in out and "gpt-5.4" in out and "unknown" in out
    code, out, _ = cli("usage", "--report", "--json", *base, home=_private_home)
    models = json.loads(out)["models"]
    assert [(m["model"], m["credits_per_run"]) for m in models] == [("gpt-5.4", 12), ("unknown", None)]


def test_hostile_model_and_credits_flags_never_reach_the_log(_private_home: Path, tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    base = ["outcome", "add", "--agent", "codex", "--shape", "research", "--log", str(log)]
    for extra in (
        ["--model", "two words"], ["--model", "a\nb"], ["--model", "a\u2028b"], ["--model", "x" * 65], ["--model", ""],
        ["--credits-used", "-1"], ["--credits-used", str(10**13)],
    ):  # fmt: skip
        code, _, err = cli(*base, *extra, home=_private_home)
        assert code == 2 and ("model" in err or "credits_used" in err), extra
    with pytest.raises(SystemExit):
        cli(*base, "--credits-used", "1.5", home=_private_home)
    assert not log.exists()


def _add(log: Path, home: Path, *extra: str) -> tuple[int, str, str]:
    return cli("outcome", "add", "--agent", "codex", "--shape", "research", "--log", str(log), *extra, home=home)


def test_the_new_flags_are_written_when_given(_private_home: Path, tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    code, _, _ = _add(
        log, _private_home, "--outcome", "abandoned", "--attempts", "3", "--intervention-minutes", "25",
        "--defects-after-approval", "2",
    )  # fmt: skip
    row = json.loads(log.read_text())
    assert code == 0 and row["outcome"] == "abandoned" and row["attempts"] == 3
    assert row["intervention_minutes"] == 25 and row["defects_after_approval"] == 2


def test_without_the_new_flags_no_new_key_is_written(_private_home: Path, tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    assert _add(log, _private_home)[0] == 0
    new = {"outcome", "attempts", "intervention_minutes", "defects_after_approval"}
    assert not new & set(json.loads(log.read_text()))


def test_bad_new_flag_values_write_nothing_and_exit_nonzero(_private_home: Path, tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    assert _add(log, _private_home)[0] == 0
    before = log.read_bytes()
    for extra in (
        ["--outcome", "done"], ["--outcome", "Accepted"], ["--attempts", "0"], ["--attempts", "101"],
        ["--attempts", "-1"], ["--intervention-minutes", "-1"], ["--intervention-minutes", "10081"],
        ["--defects-after-approval", "-1"], ["--defects-after-approval", "1000000000001"],
    ):  # fmt: skip
        code, _, err = _add(log, _private_home, *extra)
        assert code != 0 and "expected" in err, extra
        assert log.read_bytes() == before, extra
    for extra in (["--attempts", "x"], ["--attempts", "1.5"], ["--intervention-minutes", ""]):
        with pytest.raises(SystemExit):
            _add(log, _private_home, *extra)
        assert log.read_bytes() == before, extra


def test_dry_run_with_the_new_flags_writes_nothing(_private_home: Path, tmp_path: Path) -> None:
    log = tmp_path / "o.jsonl"
    base = ["--dry-run", "outcome", "add", "--agent", "codex", "--shape", "research", "--log", str(log)]
    code, out, _ = cli(*base, "--attempts", "2", home=_private_home)
    assert code == 0 and "nothing written" in out and not log.exists()
    code, _, _ = cli(*base, "--attempts", "0", home=_private_home)
    assert code != 0 and not log.exists()
