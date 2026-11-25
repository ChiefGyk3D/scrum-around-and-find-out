# SPDX-License-Identifier: Apache-2.0
"""safo local report: the typed llm-local records (kind call or outcome) and the dispatch log's na_reason_class."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from localcli import cli
from test_local_report import ESC, call, put, row

BS = chr(92)
A, B, C, D = "a" * 12, "b" * 12, "c" * 12, "d" * 12


@pytest.fixture(autouse=True)
def _utc(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def typed(kind: str, ts: str = "2026-10-06T09:30:00", **fields: object) -> dict:
    return {"kind": kind, "ts": ts, **fields}


def good_call(cid: str, task: str, model: str = "gemma4:12b") -> dict:
    return typed(
        "call",
        id=cid,
        model=model,
        task=task,
        status="ok",
        prompt_tokens=10,
        eval_tokens=5,
        seconds=1.0,
        load_duration_s=0.1,
        load_fresh=False,
    )


def outcome(cid: str, what: str, ts: str = "2026-10-06T10:00:00") -> dict:
    return typed("outcome", ts, id=cid, outcome=what)


@pytest.fixture
def typed_home(_private_home: Path) -> Path:
    put(
        _private_home / ".local/share/llm-local/calls.jsonl",
        [
            call("2026-10-05T09:30:00", "gemma4:12b", "old"),  # an old-tool row: no kind, a successful call
            good_call(A, "triage"),
            good_call(B, "draft", "qwen3.5:4b"),
            typed("call", id=C, model="m", task="triage", status="failed", exit_code=2, reason="timeout"),
            typed("call", id=D, model="m", task="triage", status="failed", exit_code=2, reason="timeout"),
            typed("call", id="e" * 12, model="m", task="triage", status="busy", exit_code=75, reason="busy"),
            outcome(A, "accepted"),
            outcome(B, "rewritten"),
            outcome(B, "fact-error", "2026-10-06T11:00:00"),  # the latest outcome of a call is the one counted
            outcome("f" * 12, "accepted"),  # no such call
            typed("weird", id=A),  # an unknown kind
            typed("call", id="9" * 12, model="m", task="t", status="sideways"),  # an unknown status
            typed("outcome", id=A, outcome="loved-it"),  # an unknown outcome
        ],
    )
    return _private_home


def test_typed_rows_are_counted_by_kind_and_status(typed_home: Path) -> None:
    code, out, _ = cli("local", "report", "--json", "--days", "60", home=typed_home)
    ll = json.loads(out)["llm_local"]
    assert code == 0
    assert ll["calls"] == 3 and ll["tokens"] == 45  # the old row and two ok calls; failed and busy rows add none
    assert ll["by_task"] == {"draft": 1, "old": 1, "triage": 1}
    assert ll["failed"] == {"total": 2, "by_reason": {"timeout": 2}}
    assert ll["busy"] == {"total": 1, "by_reason": {"busy": 1}}
    assert ll["malformed"] == 3  # the unknown kind, the unknown status and the unknown outcome


def test_outcomes_are_joined_by_id_and_rates_are_computed_in_code(typed_home: Path) -> None:
    _, out, _ = cli("local", "report", "--json", "--days", "60", home=typed_home)
    o = json.loads(out)["llm_local"]["outcomes"]
    assert o["by_outcome"] == {"accepted": 1, "fact-error": 1}  # B's later outcome replaced its first
    assert o["orphans"] == 1 and o["joined"] == 2 and o["calls_without_outcome"] == 1  # the old row has no id
    assert o["accept_rate"]["by_task"] == {"draft": 0.0, "triage": 1.0}
    assert o["accept_rate"]["by_model"] == {"gemma4:12b": 1.0, "qwen3.5:4b": 0.0}


def test_the_text_report_shows_failures_busy_and_outcomes(typed_home: Path) -> None:
    _, out, _ = cli("local", "report", "--days", "60", home=typed_home)
    assert "failed 2: timeout 2" in out and "busy 1: busy 1" in out
    assert "outcomes: accepted 1, fact-error 1" in out and "1 outcome has no call (orphan)" in out
    assert "accept rate by task: draft 0%, triage 100%" in out


def test_hostile_labels_in_typed_rows_are_escaped_and_capped(_private_home: Path) -> None:
    hostile = f"x{ESC}[2J::stop-commands::y" + "z" * 200
    put(
        _private_home / ".local/share/llm-local/calls.jsonl",
        [
            typed("call", id=A, model=hostile, task=hostile, status="failed", reason=hostile),
            good_call(B, hostile, hostile),
            outcome(B, "accepted"),
            typed("outcome", id=hostile, outcome="accepted"),
        ],
    )
    _, out, _ = cli("local", "report", "--days", "60", home=_private_home)
    assert ESC not in out and "::stop" not in out and f"x{BS}x1b[2J" in out and "z" * 70 not in out
    _, out, _ = cli("local", "report", "--json", "--days", "60", home=_private_home)
    assert "::" not in out and json.loads(out)["llm_local"]["outcomes"]["joined"] == 1


def test_a_future_typed_row_is_dropped_like_any_other(_private_home: Path) -> None:
    put(
        _private_home / ".local/share/llm-local/calls.jsonl",
        [good_call(A, "t"), outcome(A, "accepted", "2999-01-01T00:00:00")],
    )
    _, out, _ = cli("local", "report", "--json", "--days", "60", home=_private_home)
    ll = json.loads(out)["llm_local"]
    assert ll["calls"] == 1 and ll["future"] == 1 and ll["outcomes"]["by_outcome"] == {}


def test_the_na_reason_class_is_counted_by_day_and_week(_private_home: Path) -> None:
    def classed(ts: str, value: object) -> dict:
        return {**row(ts), "na_reason_class": value}

    put(
        _private_home / ".local/state/agent-dispatch-guard/log.jsonl",
        [
            classed("2026-10-05T09:00:00", "code"),
            classed("2026-10-05T10:00:00", "code"),
            classed("2026-10-06T10:00:00", "security"),
            classed("2026-10-06T11:00:00", None),
            classed("2026-10-06T12:00:00", "made-up"),
            row("2026-10-06T13:00:00"),  # an old row without the field
        ],
    )
    _, out, _ = cli("local", "report", "--json", "--days", "60", home=_private_home)
    c = json.loads(out)["dispatch"]["na_reason_class"]
    assert c["by_day"] == {"2026-10-05": {"code": 2}, "2026-10-06": {"(invalid)": 1, "security": 1}}
    assert c["by_week"] == {"2026-W41": {"(invalid)": 1, "code": 2, "security": 1}}
    assert c["total"] == {"(invalid)": 1, "code": 2, "security": 1}
    _, text, _ = cli("local", "report", "--days", "60", home=_private_home)
    assert "n/a reason class" in text and "2026-10-05  code 2" in text


def test_no_na_reason_class_section_when_the_field_is_absent(_private_home: Path) -> None:
    put(_private_home / ".local/state/agent-dispatch-guard/log.jsonl", [row("2026-10-06T10:00:00")])
    _, out, _ = cli("local", "report", "--days", "60", home=_private_home)
    assert "n/a reason class" not in out


def test_missing_data_lists_only_what_the_typed_records_still_lack(_private_home: Path) -> None:
    _, out, _ = cli("local", "report", "--json", home=_private_home)
    text = " ".join(m["what"] + " " + m["change"] for m in json.loads(out)["missing"])
    for provided in ("accepted, rewritten", "na_reason", "reason text", "fresh"):
        assert provided not in text  # the outcome, failure, reason-class and load-fresh records now exist
    assert "brief" in text and "replaces_tokens" in text and "before the typed records" in text
