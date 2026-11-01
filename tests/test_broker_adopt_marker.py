# SPDX-License-Identifier: Apache-2.0
"""Reconcile: a used marker from an earlier month with no ledger row (#278).

The decision under test: spend is recorded before the vendor call, so a marker with no row is money that may have left.
The repair is an explicit, confirmed root step that can only RAISE totals: it adds the marker's reservation to the month
the marker belongs to, holds the call as ambiguous (the model stays stopped) and never rewrites or deletes the marker.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest
from brokerdata import Crash, CrashAt, new_ledger, state_dir
from test_broker_admin import WHO, ledger_bytes, last_rows, reserve, restore, run, snapshot

from safo.broker.errors import IllegalTransition, LedgerError
from safo.broker.ledger import AdminWho, CallLedger
from safo.broker.money import format_usd

LATER = dt.datetime(2026, 10, 30, 12, 0, 30, tzinfo=dt.UTC)
NOW = dt.datetime(2026, 10, 30, 12, 0, 0, tzinfo=dt.UTC)
STRAY = "e" * 16
SEPT_END = "2026-09-30T23:59:59Z"  # the last second of the month before the month of NOW


def make_stray(tmp: Path, ts: str = SEPT_END, **over: Any) -> Path:
    """A used marker for a call the ledger never recorded."""
    template = next((state_dir(tmp) / "used").iterdir())
    data = json.loads(template.read_text()) | {"nonce": STRAY, "call_id": "d" * 32, "ts": ts} | over
    stray = state_dir(tmp) / "used" / STRAY
    stray.write_text(json.dumps(data))
    stray.chmod(0o600)
    return stray


def totals(ledger: CallLedger) -> dict[str, int]:
    view = ledger.view()
    return {key: view.month_total(key) for key in ("2026-08", "2026-09", "2026-10", "2026-11")}


def seeded(tmp: Path, reserved: int = 5000) -> CallLedger:
    ledger = new_ledger(tmp)
    cid = reserve(ledger, reserved, now=NOW)
    ledger.mark_sent(cid, NOW)
    ledger.settle(cid, "ok", 1000, NOW)
    return ledger


def adopt(tmp: Path, nonce: str = STRAY, *, confirm: str | None = STRAY) -> tuple[int, str, str]:
    argv = ["reconcile", "--adopt-marker", nonce, "--reason", "lost row"]
    return run(tmp, *argv, *(["--confirm", confirm] if confirm is not None else []))


def test_an_earlier_month_marker_blocks_recovery_and_reconcile_points_at_the_repair(tmp_path: Path) -> None:
    seeded(tmp_path)
    make_stray(tmp_path)
    with pytest.raises(LedgerError, match="root must reconcile it"):
        CallLedger(state_dir(tmp_path)).recover(LATER)
    code, out, _ = run(tmp_path, "reconcile")
    assert code == 1
    assert f"marker {STRAY} has no ledger row" in out and f"--adopt-marker {STRAY}" in out and "2026-09" in out


def test_adopting_records_the_charge_in_its_own_month_and_lets_recovery_run(tmp_path: Path) -> None:
    ledger = seeded(tmp_path)
    make_stray(tmp_path, reserved_micro=7000)
    before = totals(ledger)
    code, out, _ = adopt(tmp_path)
    assert code == 0, out
    assert "adopted_month: 2026-09" in out and f"adopted_usd: {format_usd(7000)}" in out
    after = totals(ledger)
    assert after["2026-09"] == before["2026-09"] + 7000  # the charge is in the month it belongs to
    assert all(after[k] >= before[k] for k in before)  # and no month went down
    view = ledger.view()
    rec = next(c for c in view.calls.values() if c.nonce == STRAY)
    assert rec.ambiguous and rec.unresolved and rec.counted_micro == 7000  # held at the whole reservation
    assert view.suspended[rec.model] == (rec.call_id,)  # the model stays stopped until root clears it
    assert [r["action"] for r in last_rows(tmp_path, 5) if r["type"] == "admin_action"] == ["adjust"]
    assert CallLedger(state_dir(tmp_path)).recover(LATER) == []  # start-up recovery no longer refuses
    assert CallLedger(state_dir(tmp_path)).audit(LATER) == [
        f"ambiguous call {'d' * 32} has no real amount yet (unresolved)"
    ]


def test_adopting_changes_nothing_without_the_confirmation_or_with_a_wrong_one(tmp_path: Path) -> None:
    seeded(tmp_path)
    make_stray(tmp_path)
    before = ledger_bytes(tmp_path)
    code, out, err = adopt(tmp_path, confirm=None)
    assert code == 2 and "--confirm" in err and STRAY in out  # the record is shown
    assert adopt(tmp_path, confirm="f" * 16)[0] == 2
    assert run(tmp_path, "reconcile", "--adopt-marker", STRAY, "--confirm", STRAY)[0] == 2  # no reason given
    assert ledger_bytes(tmp_path) == before


def test_the_last_second_of_the_month_before_is_charged_to_that_month_not_to_the_month_of_the_repair(
    tmp_path: Path,
) -> None:
    ledger = seeded(tmp_path)
    make_stray(tmp_path, SEPT_END, reserved_micro=7000)
    before = totals(ledger)
    assert adopt(tmp_path)[0] == 0
    after = totals(ledger)
    assert after["2026-09"] - before["2026-09"] == 7000
    assert after["2026-10"] - before["2026-10"] == 7000  # held in the month of the repair too, until root settles it
    assert after["2026-08"] == before["2026-08"] and after["2026-11"] == before["2026-11"]


def test_a_marker_from_the_first_second_of_this_month_is_not_an_earlier_month_marker(tmp_path: Path) -> None:
    seeded(tmp_path)
    make_stray(tmp_path, "2026-10-01T00:00:00Z")
    before = ledger_bytes(tmp_path)
    code, _, err = adopt(tmp_path)
    assert code == 2 and "start-up recovery" in err  # recovery already handles this month's marker
    assert ledger_bytes(tmp_path) == before
    assert CallLedger(state_dir(tmp_path)).recover(LATER) == ["d" * 32]


def test_a_marker_dated_in_the_future_is_refused_and_not_charged_to_a_month_that_has_not_started(
    tmp_path: Path,
) -> None:
    seeded(tmp_path)
    make_stray(tmp_path, "2026-12-01T00:00:00Z")
    before = ledger_bytes(tmp_path)
    code, _, err = adopt(tmp_path)
    assert code == 2 and "not an earlier month" in err
    assert ledger_bytes(tmp_path) == before


@pytest.mark.parametrize(
    "over",
    [
        {"reserved_micro": 0},
        {"reserved_micro": -5},
        {"reserved_micro": 10**18},
        {"reserved_micro": True},
        {"reserved_micro": "5000"},
        {"model": "../../etc/passwd"},
        {"job": "x\ny"},
        {"ts": "2026-13-01T00:00:00Z"},
        {"ts": "not a time"},
        {"nonce": "a" * 16},  # the name and the content disagree
        {"extra": 1},
        {"v": 99},
    ],
)
def test_a_hostile_marker_is_refused_and_the_ledger_is_untouched(tmp_path: Path, over: dict[str, Any]) -> None:
    seeded(tmp_path)
    stray = make_stray(tmp_path, **over)
    before, marker = ledger_bytes(tmp_path), stray.read_bytes()
    code, _, err = adopt(tmp_path)
    assert code == 2 and "cannot be read" in err
    assert ledger_bytes(tmp_path) == before and stray.read_bytes() == marker


def test_a_cut_off_or_empty_or_linked_marker_is_refused(tmp_path: Path) -> None:
    seeded(tmp_path)
    stray = make_stray(tmp_path)
    before = ledger_bytes(tmp_path)
    for content in (b"", b'{"v": 3, "ts": "2026-09', b"[]", bytes([0xFF, 0xFE, 0x0A])):
        stray.write_bytes(content)
        assert adopt(tmp_path)[0] == 2
    stray.unlink()
    target = tmp_path / "elsewhere"
    target.write_text("{}")
    stray.symlink_to(target)
    assert adopt(tmp_path)[0] == 2
    assert ledger_bytes(tmp_path) == before


@pytest.mark.parametrize("nonce", ["../x", "E" * 16, "e" * 17, "ee ee", "e" * 16 + "\n", "0" * 16])
def test_a_nonce_that_is_not_a_plain_marker_name_or_names_no_marker_is_refused(tmp_path: Path, nonce: str) -> None:
    seeded(tmp_path)
    make_stray(tmp_path)
    before = ledger_bytes(tmp_path)
    assert adopt(tmp_path, nonce, confirm=nonce)[0] == 2
    assert ledger_bytes(tmp_path) == before


def test_a_marker_that_reuses_a_recorded_call_id_is_refused(tmp_path: Path) -> None:
    ledger = seeded(tmp_path)
    existing = next(iter(ledger.view().calls))
    make_stray(tmp_path, call_id=existing)
    before = ledger_bytes(tmp_path)
    code, _, err = adopt(tmp_path)
    assert code == 2 and "already recorded" in err
    assert ledger_bytes(tmp_path) == before


def test_a_marker_the_ledger_already_knows_is_not_adopted_twice(tmp_path: Path) -> None:
    ledger = seeded(tmp_path)
    make_stray(tmp_path)
    assert adopt(tmp_path)[0] == 0
    once = totals(ledger)
    code, _, err = adopt(tmp_path)
    assert code == 2 and "already has a ledger row" in err
    assert totals(ledger) == once


def test_a_kill_around_the_adoption_leaves_it_fully_in_or_fully_out_and_never_lowers_a_month(tmp_path: Path) -> None:
    ledger = seeded(tmp_path)
    make_stray(tmp_path, reserved_micro=7000)
    before = totals(ledger)
    saved = snapshot(tmp_path, "saved")
    for point, adopted in (("admin_before_append", False), ("admin_after_append", True)):
        restore(tmp_path, saved)
        with pytest.raises(Crash):
            CallLedger(state_dir(tmp_path), faults=CrashAt(point)).admin_adopt_marker(STRAY, "r", WHO, LATER)
        fresh = CallLedger(state_dir(tmp_path))
        now_totals = totals(fresh)
        assert all(now_totals[k] >= before[k] for k in before)
        assert (now_totals["2026-09"] == before["2026-09"] + 7000) is adopted
        if adopted:
            assert fresh.recover(LATER) == []
        else:
            with pytest.raises(LedgerError, match="root must reconcile it"):
                fresh.recover(LATER)
            fresh.admin_adopt_marker(STRAY, "r", WHO, LATER)  # the retry after a lost attempt works
            assert totals(fresh)["2026-09"] == before["2026-09"] + 7000


def test_adopting_validates_who_and_reason_in_the_ledger_itself(tmp_path: Path) -> None:
    ledger = seeded(tmp_path)
    make_stray(tmp_path)
    before = ledger_bytes(tmp_path)
    for who, reason in ((AdminWho(-1, 0), "r"), (WHO, ""), (WHO, "x" * 121), (WHO, "tab\t")):
        with pytest.raises(IllegalTransition):
            ledger.admin_adopt_marker(STRAY, reason, who, LATER)
    assert ledger_bytes(tmp_path) == before


def test_clearing_an_adopted_call_never_gives_back_the_earlier_month(tmp_path: Path) -> None:
    ledger = seeded(tmp_path)
    make_stray(tmp_path, reserved_micro=7000)
    assert adopt(tmp_path)[0] == 0
    model = next(iter(ledger.view().suspended))
    assert run(tmp_path, "clear", model)[0] == 2  # no confirmation: nothing is cleared
    assert ledger.view().suspended
    code, out, _ = run(tmp_path, "clear", model, "--confirm", "d" * 32)
    assert code == 0 and "settled" in out
    assert not ledger.view().suspended
    assert totals(ledger)["2026-09"] >= 7000  # the earlier month keeps its charge whatever is done to the call
