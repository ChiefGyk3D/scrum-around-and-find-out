# SPDX-License-Identifier: Apache-2.0
"""safo local report: counts of local-model use from the guard and llm-local logs, read-only, no model called."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from localcli import cli
from safo.modes import local_report

ESC = chr(27)


def row(ts: str, model: str = "sonnet", *, reach: bool = True, step: bool = False, line: bool | None = None) -> dict:
    out: dict = {
        "ts": ts,
        "decision": "allow",
        "mode": "block",
        "model": model,
        "local_reachable": reach,
        "description": "x",
        "local_step": step,
        "problems": [],
    }
    if line is not None:
        out["local_line"] = line
    return out


def put(path: Path, rows: list[object], tail: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join((r if isinstance(r, str) else json.dumps(r)) + "\n" for r in rows) + tail)


def call(ts: str, model: str, task: str) -> dict:
    return {"ts": ts, "model": model, "task": task, "prompt_tokens": 10, "eval_tokens": 5, "seconds": 1.0}


@pytest.fixture
def fixture_home(_private_home: Path) -> Path:
    put(
        _private_home / ".local/state/agent-dispatch-guard/log.jsonl",
        [
            row("2026-10-05T09:00:00", step=True, line=True),  # Monday, ISO week 41
            row("2026-10-05T10:00:00", "haiku", step=False, line=False),
            row("2026-10-06T10:00:00", step=False, line=True),
            row("2026-10-06T11:00:00", reach=False),
            row("2026-10-12T11:00:00", "opus", step=True),  # next ISO week
            "{not json",
            '["a list"]',
        ],
        tail='{"ts": "2026-10-12T1',  # a torn last line
    )
    put(
        _private_home / ".local/share/llm-local/calls.jsonl",
        [
            call("2026-10-05T09:30:00", "gemma4:12b", "triage"),
            call("2026-10-06T09:30:00", "gemma4:12b", "triage"),
            call("2026-10-06T09:31:00", "qwen3.5:4b", "smoke"),
            "garbage",
        ],
    )
    state = _private_home / ".local/state/llm-local"
    state.mkdir(parents=True)
    (state / "state.json").write_text(json.dumps({"counters": {"admit": 55, "busy": 3}, "leases": []}))
    hooks = _private_home / ".local/state/safo/hooks"
    hooks.mkdir(parents=True)
    hooks.chmod(0o700)
    base = {
        "decision": "allow",
        "mode": "warn",
        "model": "sonnet",
        "local_reachable": True,
        "local_step": True,
        "na": False,
        "rules": [],
        "health": "healthy",
        "diagnostic": "",
    }
    put(hooks / "log.jsonl", [{**base, "ts": "2026-10-06T10:00:00"}, {**base, "ts": "2026-10-06T11:00:00", "na": True}])
    return _private_home


def test_text_report_counts_per_day_week_and_model(fixture_home: Path) -> None:
    code, out, err = cli("local", "report", "--days", "60", home=fixture_home)
    assert code == 0 and err == ""
    assert "2026-10-05  dispatches 2  reachable 2  local step 1  local-llm line 1  neither 1" in out
    assert "2026-10-06  dispatches 2  reachable 1  local step 0  local-llm line 1  neither 1" in out
    assert "2026-W41  dispatches 4" in out and "2026-W42  dispatches 1" in out
    assert "sonnet  dispatches 3" in out and "haiku  dispatches 1" in out and "opus  dispatches 1" in out
    assert "malformed lines skipped: 3" in out  # not json, not an object, torn last line
    assert "briefs with a local step 2, marked n/a 1" in out  # the hooks guard counts, from safo.guardlog
    assert "triage 2" in out and "smoke 1" in out and "malformed lines skipped: 1" in out
    assert "admit 55  busy 3" in out
    assert "MISSING DATA" in out and "na_reason" in out


def test_json_report_is_one_document_with_the_same_counts(fixture_home: Path) -> None:
    code, out, _ = cli("local", "report", "--json", "--days", "60", home=fixture_home)
    data = json.loads(out)
    assert code == 0
    assert data["dispatch"]["by_day"]["2026-10-05"] == {
        "dispatches": 2,
        "reachable": 2,
        "local_step": 1,
        "local_line": 1,
        "neither": 1,
    }
    assert data["dispatch"]["malformed"] == 3 and data["dispatch"]["rows"] == 5
    assert data["dispatch"]["by_model"]["opus"]["dispatches"] == 1
    assert data["llm_local"]["by_task"] == {"smoke": 1, "triage": 2}
    assert data["llm_local"]["counters"] == {"admit": 55, "busy": 3}
    assert data["hooks"]["local_steps"] == 2 and data["missing"]


def test_days_window_drops_older_rows(fixture_home: Path) -> None:
    code, out, _ = cli("local", "report", "--json", "--days", "1", home=fixture_home)  # NOW is 2026-10-07
    days = json.loads(out)["dispatch"]["by_day"]
    assert code == 0 and "2026-10-05" not in days and "2026-10-06" not in days


def test_empty_home_is_exit_zero_and_still_lists_missing_data(_private_home: Path) -> None:
    code, out, err = cli("local", "report", home=_private_home)
    assert code == 0 and err == ""
    assert "no dispatch log" in out and "no llm-local calls log" in out and "MISSING DATA" in out


def test_terminal_control_characters_in_a_task_label_are_escaped(_private_home: Path) -> None:
    put(
        _private_home / ".local/share/llm-local/calls.jsonl",
        [call("2026-10-06T09:30:00", "m", f"evil{ESC}[2J::stop-commands::x")],
    )
    code, out, _ = cli("local", "report", "--days", "60", home=_private_home)
    assert code == 0 and ESC not in out and "::stop" not in out and "evil\\x1b[2J" in out


def test_reads_are_capped_and_say_so(fixture_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local_report, "MAX_LINES", 2)
    code, out, _ = cli("local", "report", "--json", "--days", "60", home=fixture_home)
    data = json.loads(out)
    assert code == 0 and data["dispatch"]["rows"] == 0 and data["dispatch"]["malformed"] == 2
    assert data["dispatch"]["truncated"] is True
    monkeypatch.setattr(local_report, "MAX_LINES", 100_000)
    monkeypatch.setattr(local_report, "MAX_FILE_BYTES", 100)
    code, out, _ = cli("local", "report", "--json", "--days", "60", home=fixture_home)
    assert json.loads(out)["dispatch"]["truncated"] is True


def test_the_report_changes_nothing_it_reads(fixture_home: Path) -> None:
    files = [p for p in fixture_home.rglob("*") if p.is_file() and not p.name.endswith(".lock")]
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in files}
    code, _, _ = cli("local", "report", "--days", "60", home=fixture_home)
    assert code == 0
    assert {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in files} == before


def test_a_symlinked_log_is_not_followed(_private_home: Path, tmp_path: Path) -> None:
    real = tmp_path / "real.jsonl"
    put(real, [row("2026-10-06T10:00:00")])
    link = _private_home / ".local/state/agent-dispatch-guard/log.jsonl"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    code, out, _ = cli("local", "report", "--json", "--days", "60", home=_private_home)
    assert code == 0 and json.loads(out)["dispatch"]["rows"] == 0


def test_run_still_needs_its_shape_and_prompt(_private_home: Path) -> None:
    code, _, err = cli("local", "run", home=_private_home)
    assert code != 0 and "--shape" in err
