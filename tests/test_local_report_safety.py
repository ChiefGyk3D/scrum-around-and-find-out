# SPDX-License-Identifier: Apache-2.0
"""safo local report: labels are classed into a safe set, files are read only through safe directories, and a call
row that does not validate never becomes a join target (Daybreak round 1 of #372)."""

from __future__ import annotations

import json
import os
import stat
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from localcli import cli
from safo.modes import local_report
from test_local_report import call, put, row
from test_local_report_typed import good_call, outcome, typed

SECRET = "prompt: API_KEY=secret"
OTHER_WRITE = stat.S_IWOTH


@pytest.fixture(autouse=True)
def _utc(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def report(home: Path) -> tuple[str, Any]:
    _, text, _ = cli("local", "report", "--days", "60", home=home)
    _, out, _ = cli("local", "report", "--json", "--days", "60", home=home)
    return text, json.loads(out)


def test_labels_that_could_hold_prompt_text_are_classed_as_other(_private_home: Path) -> None:
    put(
        _private_home / ".local/share/llm-local/calls.jsonl",
        [
            typed("call", id="a" * 12, model=SECRET, task=SECRET, status="ok", prompt_tokens=1, eval_tokens=1),
            typed("call", id="b" * 12, model="Gemma4", task="triage", status="ok"),  # a capital is not in the set
            typed("call", id="c" * 12, model="m" * 41, task="x" * 41, status="ok"),  # one character too long
            typed("call", id="d" * 12, model="gemma4:12b", task="not-a-documented-task", status="ok"),
            typed("call", id="e" * 12, model="gemma4:12b", task="triage", status="ok"),
            typed("call", id="f" * 12, model="m", task="triage", status="failed", reason=SECRET),
        ],
    )
    (_private_home / ".local/state/llm-local").mkdir(parents=True)
    (_private_home / ".local/state/llm-local/state.json").write_text(json.dumps({"counters": {SECRET: 4, "admit": 2}}))
    put(
        _private_home / ".local/state/agent-dispatch-guard/log.jsonl",
        [{**row("2026-10-06T10:00:00"), "model": SECRET}],
    )
    text, data = report(_private_home)
    for shown in (text, json.dumps(data)):
        assert "API_KEY" not in shown and "secret" not in shown and "not-a-documented" not in shown
    ll = data["llm_local"]
    assert ll["by_task"] == {"other": 3, "triage": 2}
    assert ll["by_model"] == {"gemma4:12b": 2, "other": 3}
    assert ll["failed"]["by_reason"] == {"other": 1}
    assert ll["counters"] == {"admit": 2, "other": 4}
    assert ll["unknown_labels"] == {"task": 3, "model": 3, "reason": 1}
    assert data["dispatch"]["by_model"]["other"]["dispatches"] == 1
    assert "classed as other (text never shown), distinct labels: task 3, model 3, reason 1" in text


def seed(home: Path) -> Path:
    put(home / ".local/share/llm-local/calls.jsonl", [call("2026-10-06T09:30:00", "gemma4:12b", "triage")])
    return home / ".local/share/llm-local"


def test_a_symlinked_llm_local_directory_is_refused_with_a_clear_message(_private_home: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere-dir"
    put(elsewhere / "calls.jsonl", [call("2026-10-06T09:30:00", "gemma4:12b", "triage")])
    link = _private_home / ".local/share/llm-local"
    link.parent.mkdir(parents=True)
    link.symlink_to(elsewhere)
    text, data = report(_private_home)
    assert data["llm_local"]["calls"] == 0 and data["llm_local"]["found"] is False
    assert "not read: a directory on the path is a symlink" in text
    assert "elsewhere-dir" not in text and str(_private_home) not in text


def test_a_symlinked_directory_higher_up_is_refused_too(_private_home: Path, tmp_path: Path) -> None:
    real = tmp_path / "real-share"
    put(real / "llm-local/calls.jsonl", [call("2026-10-06T09:30:00", "gemma4:12b", "triage")])
    (_private_home / ".local").mkdir()
    (_private_home / ".local/share").symlink_to(real)
    _, data = report(_private_home)
    assert data["llm_local"]["calls"] == 0 and data["llm_local"]["refused"]


def test_a_world_writable_directory_or_file_is_refused(_private_home: Path) -> None:
    folder = seed(_private_home)
    folder.chmod(0o755 | OTHER_WRITE)
    text, data = report(_private_home)
    assert data["llm_local"]["calls"] == 0 and "not read:" in text
    folder.chmod(0o755)
    (folder / "calls.jsonl").chmod(0o644 | OTHER_WRITE)
    text, data = report(_private_home)
    assert data["llm_local"]["calls"] == 0 and "not a regular file, not yours or writable by others" in text


def test_a_file_that_another_user_owns_is_refused(_private_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seed(_private_home)
    _, before = report(_private_home)
    assert before["llm_local"]["calls"] == 1
    monkeypatch.setattr(local_report, "current_uid", lambda: os.geteuid() + 1)
    text, data = report(_private_home)
    assert data["llm_local"]["calls"] == 0 and "not read:" in text


def test_a_group_write_is_allowed_only_for_the_users_own_group(
    _private_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = seed(_private_home)
    folder.chmod(0o775)
    (folder / "calls.jsonl").chmod(0o664)
    _, own = report(_private_home)
    assert own["llm_local"]["calls"] == 1  # a private group, as on a default desktop
    monkeypatch.setattr(local_report, "current_gid", lambda: os.getegid() + 1)
    _, other = report(_private_home)
    assert other["llm_local"]["calls"] == 0 and other["llm_local"]["refused"]


def test_a_call_row_that_does_not_validate_never_becomes_a_join_target(_private_home: Path) -> None:
    put(
        _private_home / ".local/share/llm-local/calls.jsonl",
        [
            typed("call", "bad", id="x", status="sideways", task="forged", model="forged"),
            outcome("x", "accepted"),
            typed("call", id="y", status="sideways", task="forged", model="forged"),  # a bad status, a good time
            outcome("y", "accepted"),
            typed("call", "2999-01-01T00:00:00", id="z", status="ok", task="triage", model="m"),  # in the future
            outcome("z", "accepted"),
            good_call("g" * 12, "triage"),
            outcome("g" * 12, "accepted"),
        ],
    )
    _, data = report(_private_home)
    o = data["llm_local"]["outcomes"]
    assert o["joined"] == 1 and o["orphans"] == 3
    assert o["accept_rate"]["by_task"] == {"triage": 1.0} and "forged" not in json.dumps(o)
