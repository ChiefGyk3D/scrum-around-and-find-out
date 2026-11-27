# SPDX-License-Identifier: Apache-2.0
"""#615 item 1: the `input` diagnostic is split into input-parse, input-oversize and input-shell (the old value
stays readable); the shell row carries the check duration; `safo hooks status` counts each cause.
Names are built at run time so scanners stay quiet about this file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from geminidata import write_config
from guardhealthdata import event, guard, row
from hooksdata import agents_file, read_log
from safo import geminibrief
from safo.bounded import MAX_BYTES
from safo.gemini import Locations
from safo.guardlog import DIAGNOSTICS, guard_lines, valid_record


@pytest.fixture
def agents(tmp_path: Path, gemini_locations: Locations) -> Path:
    write_config(
        gemini_locations.config, "http://127.0.0.1:9", tmp_path / "data" / "ledger.jsonl", private_terms="none"
    )
    return agents_file(tmp_path / "agents.yaml")


def test_an_unparseable_event_is_input_parse(_private_home: Path, agents: Path) -> None:
    assert "degraded" in guard(agents, _private_home, "{not json")
    assert read_log(_private_home)[-1]["diagnostic"] == "input-parse"


def test_an_oversized_event_is_input_oversize(_private_home: Path, agents: Path) -> None:
    guard(agents, _private_home, '"' + "x" * (MAX_BYTES + 10) + '"')
    assert read_log(_private_home)[-1]["diagnostic"] == "input-oversize"


def test_a_shell_check_that_ran_out_is_input_shell_with_its_duration(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(geminibrief, "shell_command_class", lambda *_a, **_k: geminibrief.SHELL_UNVERIFIED)
    out = guard(agents, _private_home, event("echo hello"))
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    last = read_log(_private_home)[-1]
    assert (last["decision"], last["diagnostic"], last["health"]) == ("error", "input-shell", "degraded")
    assert type(last["check_ms"]) is int and last["check_ms"] >= 0
    assert valid_record(last)


def test_a_rows_without_a_duration_have_no_such_key(_private_home: Path, agents: Path) -> None:
    guard(agents, _private_home, "{not json")
    assert "check_ms" not in read_log(_private_home)[-1]


def test_the_old_input_value_and_the_new_ones_are_all_valid() -> None:
    for code in ("input", "input-parse", "input-oversize", "input-shell", "input-args"):
        assert code in DIAGNOSTICS and valid_record(row(code)), code
    assert not valid_record(row("input-other"))


@pytest.mark.parametrize("bad", [-1, True, 1.5, "12", None, 10**9])
def test_a_bad_duration_is_not_a_valid_row(bad: Any) -> None:
    assert valid_record(row("input-shell", check_ms=12))  # the guard: a good duration passes
    assert not valid_record(row("input-shell", check_ms=bad))


def test_an_unknown_extra_key_is_still_invalid() -> None:
    assert not valid_record(row("input-shell", check_ms=5, extra=1))


def test_status_counts_each_cause_on_its_own_line_and_reads_old_rows(tmp_path: Path) -> None:
    folder = tmp_path / "state" / "safo" / "hooks"
    folder.mkdir(parents=True)
    rows = (
        [row("input")] * 2  # written before the split
        + [row("input-parse")]
        + [row("input-oversize")] * 4
        + [row("input-shell", check_ms=1500), row("input-shell", check_ms=2750)]
    )
    (folder / "log.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    lines = guard_lines({"XDG_STATE_HOME": str(tmp_path / "state"), "HOME": str(tmp_path / "none")})
    assert "  input parse failures: 3" in lines
    assert "  oversized events: 4" in lines
    assert "  shell checks not finished: 2 (longest 2750 ms)" in lines


def test_status_prints_no_cause_line_when_there_is_nothing_to_count(tmp_path: Path) -> None:
    folder = tmp_path / "state" / "safo" / "hooks"
    folder.mkdir(parents=True)
    (folder / "log.jsonl").write_text(json.dumps(row("", decision="allow", health="healthy")) + "\n")
    text = "\n".join(guard_lines({"XDG_STATE_HOME": str(tmp_path / "state"), "HOME": str(tmp_path / "none")}))
    assert "oversized events" not in text and "shell checks not finished" not in text
