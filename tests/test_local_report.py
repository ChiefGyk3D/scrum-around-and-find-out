# SPDX-License-Identifier: Apache-2.0
"""safo local report: counts of local-model use from the guard and llm-local logs, read-only, no model called."""

from __future__ import annotations

import datetime as dt
import io
import json
import os
import signal
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from localcli import cli
from safo.cli import main
from safo.modes import local_report

ESC = chr(27)
OLD_ERROR = "safo local: error: the following arguments are required: --shape, --prompt-file"  # base commit 5dd0d87


@pytest.fixture(autouse=True)
def _utc(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """The guard writes local time without a zone; the tests pin the machine zone so dates do not move."""
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def at(home: Path, now: dt.datetime, *argv: str, extra: dict[str, str] | None = None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    env = {"HOME": str(home), "PATH": "", **(extra or {})}
    return main(list(argv), env=env, out=out, err=err, now=now), out.getvalue(), err.getvalue()


def row(
    ts: str, model: str = "sonnet", *, reach: bool = True, step: bool = False, line: bool | None = None
) -> dict[str, Any]:
    out: dict[str, Any] = {
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


def call(ts: str, model: str, task: str) -> dict[str, Any]:
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
            row("2026-09-29T11:00:00", "opus", step=True),  # the ISO week before
            "{not json",
            '["a list"]',
        ],
        tail='{"ts": "2026-10-06T1',  # a torn last line
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
    assert "2026-10-05  dispatches 2  reachable 2  names llm-local 1  local-llm line 1  neither 1" in out
    assert "2026-10-06  dispatches 2  reachable 1  names llm-local 0  local-llm line 1  neither 1" in out
    assert "2026-W41  dispatches 4" in out and "2026-W40  dispatches 1" in out
    assert "sonnet  dispatches 3" in out and "haiku  dispatches 1" in out and "opus  dispatches 1" in out
    assert "malformed lines skipped: 3" in out  # not json, not an object, torn last line
    assert "briefs with a local step 2, marked n/a 1" in out  # the hooks guard counts, from safo.guardlog
    assert "triage 2" in out and "smoke 1" in out and "malformed lines skipped: 1" in out
    assert "admit 55  busy 3" in out
    assert "MISSING DATA" in out and "replaces_tokens" in out


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


def test_terminal_control_characters_in_a_task_label_are_classed_not_printed(_private_home: Path) -> None:
    put(
        _private_home / ".local/share/llm-local/calls.jsonl",
        [call("2026-10-06T09:30:00", "m", f"evil{ESC}[2J::stop-commands::x")],
    )
    code, out, _ = cli("local", "report", "--days", "60", home=_private_home)
    assert code == 0 and ESC not in out and "::stop" not in out and "evil" not in out  # classed as other


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
    def snapshot() -> dict[Path, tuple[bytes, int]]:
        return {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in fixture_home.rglob("*") if p.is_file()}

    before = snapshot()
    code, out, _ = cli("local", "report", "--days", "60", home=fixture_home)
    assert code == 0 and "briefs with a local step 2" in out  # the hooks log was read
    assert snapshot() == before  # nothing changed and no file, such as a lock, was created


def test_a_symlinked_log_is_not_followed(_private_home: Path, tmp_path: Path) -> None:
    real = tmp_path / "real.jsonl"
    put(real, [row("2026-10-06T10:00:00")])
    link = _private_home / ".local/state/agent-dispatch-guard/log.jsonl"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    code, out, _ = cli("local", "report", "--json", "--days", "60", home=_private_home)
    assert code == 0 and json.loads(out)["dispatch"]["rows"] == 0


NOW = dt.datetime(2026, 10, 7, 12, 0, tzinfo=dt.UTC)


def test_run_without_flags_prints_the_old_required_argument_error(
    _private_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as stop:
        cli("local", "run", home=_private_home)
    err = capsys.readouterr().err
    flat = " ".join(err.split())
    assert stop.value.code == 2 and OLD_ERROR in err
    assert "--shape SHAPE --prompt-file PROMPT_FILE" in flat  # shown as required, not in brackets


def test_run_refuses_the_report_only_options(_private_home: Path, tmp_path: Path) -> None:
    for extra in (["--days", "3"], ["--json"]):
        code, _, err = cli(
            "local", "run", "--shape", "s", "--prompt-file", str(tmp_path / "p"), *extra, home=_private_home
        )
        assert code != 0 and "report" in err


def test_rows_dated_after_today_are_malformed_with_the_reason_future(_private_home: Path) -> None:
    put(
        _private_home / ".local/state/agent-dispatch-guard/log.jsonl",
        [row("2026-10-07T10:00:00"), row("2026-10-08T00:00:00"), row("2999-01-01T00:00:00")],
    )
    code, out, _ = cli("local", "report", "--json", "--days", "5", home=_private_home)
    d = json.loads(out)["dispatch"]
    assert code == 0 and d["rows"] == 1 and d["malformed"] == 2 and d["future"] == 2
    assert list(d["by_day"]) == ["2026-10-07"]
    code, text, _ = cli("local", "report", "--days", "5", home=_private_home)
    assert "malformed lines skipped: 2 (2 dated in the future)" in text


def test_future_rows_are_dropped_from_the_other_logs_too(fixture_home: Path) -> None:
    put(fixture_home / ".local/share/llm-local/calls.jsonl", [call("2999-01-01T00:00:00", "m", "t")])
    hooks = fixture_home / ".local/state/safo/hooks/log.jsonl"
    old = json.loads(hooks.read_text().splitlines()[0])
    put(hooks, [{**old, "ts": "2999-01-01T00:00:00"}])
    _code, out, _ = cli("local", "report", "--json", "--days", "5", home=fixture_home)
    data = json.loads(out)
    assert data["llm_local"]["calls"] == 0 and data["llm_local"]["future"] == 1
    assert data["hooks"]["total"] == 0 and data["hooks"]["future"] == 1


def test_the_window_uses_the_local_date_near_midnight(_private_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TZ", "EST5")  # UTC minus five hours, no daylight saving
    time.tzset()
    put(
        _private_home / ".local/state/agent-dispatch-guard/log.jsonl",
        [row("2026-10-06T23:59:59"), row("2026-10-07T20:00:00"), row("2026-10-08T01:00:00")],
    )
    now = dt.datetime(2026, 10, 8, 2, 0, tzinfo=dt.UTC)  # 21:00 on 2026-10-07 in the local zone
    code, out, _ = at(_private_home, now, "local", "report", "--json", "--days", "1")
    d = json.loads(out)["dispatch"]
    assert code == 0 and list(d["by_day"]) == ["2026-10-07"] and d["future"] == 1
    assert json.loads(out)["generated"] == "2026-10-07"


@pytest.mark.parametrize(
    "ts", ["2026-10-07 10:00:00", "2026-10-07T10:00", "2026-10-07T10:00:00Z", "2026-10-07T10:00:00x", "x" * 19]
)
def test_a_timestamp_that_is_not_exactly_the_logged_shape_is_malformed(_private_home: Path, ts: str) -> None:
    put(_private_home / ".local/state/agent-dispatch-guard/log.jsonl", [row(ts), row("2026-10-07T10:00:00")])
    _, out, _ = cli("local", "report", "--json", "--days", "5", home=_private_home)
    d = json.loads(out)["dispatch"]
    assert d["rows"] == 1 and d["malformed"] == 1


def test_a_fifo_or_a_directory_as_the_log_is_not_read_and_does_not_hang(_private_home: Path) -> None:
    folder = _private_home / ".local/state/agent-dispatch-guard"
    folder.mkdir(parents=True)
    os.mkfifo(folder / "log.jsonl")
    (_private_home / ".local/share/llm-local/calls.jsonl").mkdir(parents=True)  # a directory

    class Hung(BaseException):  # not an OSError: the reader must not be able to swallow it
        pass

    def stop(*_: object) -> None:
        raise Hung("the report waited on a FIFO")

    old = signal.signal(signal.SIGALRM, stop)
    signal.alarm(10)  # a read that waited on the FIFO fails the test here
    try:
        code, out, _ = cli("local", "report", "--json", home=_private_home)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)
    data = json.loads(out)
    assert code == 0 and data["dispatch"]["found"] is False and data["llm_local"]["found"] is False


def _three_rows(home: Path) -> list[bytes]:
    lines = [(json.dumps(row(f"2026-10-0{n}T10:00:00")) + "\n").encode() for n in (3, 4, 5)]
    path = home / ".local/state/agent-dispatch-guard/log.jsonl"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"".join(lines))
    return lines


def test_over_the_size_cap_a_cut_first_line_is_dropped_and_not_counted(
    _private_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lines = _three_rows(_private_home)
    monkeypatch.setattr(local_report, "MAX_FILE_BYTES", sum(map(len, lines)) - len(lines[0]) // 2)
    _, out, _ = cli("local", "report", "--json", "--days", "30", home=_private_home)
    d = json.loads(out)["dispatch"]
    assert d["rows"] == 2 and d["malformed"] == 0 and d["truncated"] is True and "2026-10-03" not in d["by_day"]


def test_over_the_size_cap_a_cut_on_a_line_boundary_keeps_the_whole_line(
    _private_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lines = _three_rows(_private_home)
    monkeypatch.setattr(local_report, "MAX_FILE_BYTES", len(lines[1]) + len(lines[2]))
    _, out, _ = cli("local", "report", "--json", "--days", "30", home=_private_home)
    d = json.loads(out)["dispatch"]
    assert d["rows"] == 2 and "2026-10-04" in d["by_day"] and d["truncated"] is True


def test_the_iso_year_boundary_belongs_to_week_53_of_2026(_private_home: Path) -> None:
    put(
        _private_home / ".local/state/agent-dispatch-guard/log.jsonl",
        [row("2026-12-31T10:00:00"), row("2027-01-01T10:00:00")],
    )
    now = dt.datetime(2027, 1, 2, 12, 0, tzinfo=dt.UTC)
    _, out, _ = at(_private_home, now, "local", "report", "--json", "--days", "5")
    assert json.loads(out)["dispatch"]["by_week"] == {
        "2026-W53": {"dispatches": 2, "reachable": 2, "local_step": 0, "local_line": 0, "neither": 2}
    }


def test_one_line_over_the_line_cap_is_malformed_and_the_rest_are_read(_private_home: Path) -> None:
    big = {**row("2026-10-07T10:00:00"), "description": "x" * (local_report.MAX_LINE_BYTES + 1)}
    put(
        _private_home / ".local/state/agent-dispatch-guard/log.jsonl",
        [row("2026-10-07T09:00:00"), big, row("2026-10-07T11:00:00")],
    )
    _, out, _ = cli("local", "report", "--json", "--days", "5", home=_private_home)
    d = json.loads(out)["dispatch"]
    assert d["rows"] == 2 and d["malformed"] == 1


def test_a_valid_last_line_with_no_newline_is_a_torn_line_and_not_counted(_private_home: Path) -> None:
    put(
        _private_home / ".local/state/agent-dispatch-guard/log.jsonl",
        [row("2026-10-07T09:00:00")],
        tail=json.dumps(row("2026-10-07T10:00:00")),
    )
    _, out, _ = cli("local", "report", "--json", "--days", "5", home=_private_home)
    d = json.loads(out)["dispatch"]
    assert d["rows"] == 1 and d["malformed"] == 1


def test_json_output_never_carries_a_double_colon(_private_home: Path) -> None:
    put(_private_home / ".local/share/llm-local/calls.jsonl", [call("2026-10-06T09:30:00", "m", "a::b")])
    code, out, _ = cli("local", "report", "--json", "--days", "60", home=_private_home)
    assert code == 0 and "::" not in out and json.loads(out)["llm_local"]["by_task"] == {"other": 1}


@pytest.mark.parametrize("days", ["0", "-1", "3661", "99999999999999999999"])
def test_days_out_of_range_is_a_clear_error(_private_home: Path, days: str) -> None:
    code, out, err = cli("local", "report", "--days", days, home=_private_home)
    assert code != 0 and out == "" and "--days" in err


def test_only_the_first_calls_log_is_read(_private_home: Path) -> None:
    put(_private_home / ".local/state/llm-local/calls.jsonl", [call("2026-10-06T09:30:00", "m", "triage")])
    put(_private_home / ".local/share/llm-local/calls.jsonl", [call("2026-10-06T09:30:00", "m", "summary")] * 2)
    _, out, _ = cli("local", "report", "--json", "--days", "60", home=_private_home)
    assert json.loads(out)["llm_local"]["by_task"] == {"triage": 1}


def test_llm_local_and_dispatch_files_are_found_under_home_ignoring_xdg(fixture_home: Path, tmp_path: Path) -> None:
    other = tmp_path / "xdg"
    other.mkdir()
    _code, out, _ = cli(
        "local",
        "report",
        "--json",
        "--days",
        "60",
        home=fixture_home,
        extra_env={"XDG_STATE_HOME": str(other), "XDG_DATA_HOME": str(other)},
    )
    data = json.loads(out)
    assert (
        data["llm_local"]["calls"] == 3
        and data["llm_local"]["counters"]["admit"] == 55
        and data["dispatch"]["rows"] == 5
    )
