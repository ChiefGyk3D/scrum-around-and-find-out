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
from safo.broker.errors import IllegalTransition, LedgerError
from safo.broker.ledger import ADOPT_PREFIX, AdminWho, CallLedger, Confirmed, marker_digest
from safo.broker.money import format_usd
from test_broker_admin import WHO, last_rows, ledger_bytes, reserve, restore, run, snapshot

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


def confirmed_for(tmp: Path, nonce: str = STRAY) -> Confirmed:
    """What an operator who read the marker file would confirm."""
    data = json.loads((state_dir(tmp) / "used" / nonce).read_text())
    return Confirmed(marker_digest(data), data["model"], data["ts"][:7], data["reserved_micro"])


def adopt(tmp: Path, nonce: str = STRAY, *, confirm: bool = True) -> tuple[int, str, str]:
    argv = ["reconcile", "--adopt-marker", nonce, "--reason", "lost row"]
    if confirm:
        try:
            c = confirmed_for(tmp, nonce)
            argv += [
                "--confirm", c.digest, "--confirm-model", c.model, "--confirm-month", c.month,
                "--confirm-usd", format_usd(c.reserved_micro),
            ]  # fmt: skip
        except (OSError, ValueError, KeyError, TypeError):
            argv += ["--confirm", "0" * 64, "--confirm-model", "m", "--confirm-month", "2026-09", "--confirm-usd", "1"]
    return run(tmp, *argv)


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
    c = confirmed_for(tmp_path)
    base = ["reconcile", "--adopt-marker", STRAY, "--reason", "r"]
    full = ["--confirm", c.digest, "--confirm-model", c.model, "--confirm-month", c.month, "--confirm-usd", "0.007"]
    assert run(tmp_path, *base, "--confirm", c.digest)[0] == 2  # the digest alone is not enough
    assert run(tmp_path, *base, "--confirm", STRAY)[0] == 2  # the nonce is not the confirmation any more
    assert run(tmp_path, "reconcile", "--adopt-marker", STRAY, *full)[0] == 2  # no reason given
    assert run(tmp_path, *base, *full[:-1], "1e1")[0] == 2
    assert run(tmp_path, *base, *full[:5], "2026-9", *full[6:])[0] == 2
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
    assert adopt(tmp_path, nonce)[0] == 2
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
            CallLedger(state_dir(tmp_path), faults=CrashAt(point)).admin_adopt_marker(
                STRAY, "r", WHO, LATER, confirmed_for(tmp_path)
            )
        fresh = CallLedger(state_dir(tmp_path))
        now_totals = totals(fresh)
        assert all(now_totals[k] >= before[k] for k in before)
        assert (now_totals["2026-09"] == before["2026-09"] + 7000) is adopted
        if adopted:
            assert fresh.recover(LATER) == []
        else:
            with pytest.raises(LedgerError, match="root must reconcile it"):
                fresh.recover(LATER)
            fresh.admin_adopt_marker(
                STRAY, "r", WHO, LATER, confirmed_for(tmp_path)
            )  # the retry after a lost attempt works
            assert totals(fresh)["2026-09"] == before["2026-09"] + 7000


def test_adopting_validates_who_and_reason_in_the_ledger_itself(tmp_path: Path) -> None:
    ledger = seeded(tmp_path)
    make_stray(tmp_path)
    before = ledger_bytes(tmp_path)
    for who, reason in ((AdminWho(-1, 0), "r"), (WHO, ""), (WHO, "x" * 106), (WHO, "tab\t")):
        with pytest.raises(IllegalTransition):
            ledger.admin_adopt_marker(STRAY, reason, who, LATER, confirmed_for(tmp_path))
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


def other_marker(tmp: Path, **over: Any) -> bytes:
    """A different, strict, valid marker for the same nonce (what a swap would put in place)."""
    data = json.loads((state_dir(tmp) / "used" / STRAY).read_text()) | over
    return json.dumps(data).encode()


def test_a_marker_swapped_after_it_was_read_is_refused_and_nothing_is_charged(tmp_path: Path) -> None:
    ledger = seeded(tmp_path)
    stray = make_stray(tmp_path, reserved_micro=1000)
    confirmed = confirmed_for(tmp_path)  # what root read
    stray.write_bytes(other_marker(tmp_path, reserved_micro=900_000, call_id="c" * 32, job="other-job"))
    before, totals_before = ledger_bytes(tmp_path), totals(ledger)
    with pytest.raises(IllegalTransition, match="not what was confirmed"):
        ledger.admin_adopt_marker(STRAY, "r", WHO, LATER, confirmed)
    assert ledger_bytes(tmp_path) == before and totals(ledger) == totals_before


@pytest.mark.parametrize("what", ["digest", "model", "month", "amount"])
def test_every_part_of_the_confirmation_must_match_the_marker(tmp_path: Path, what: str) -> None:
    ledger = seeded(tmp_path)
    make_stray(tmp_path, reserved_micro=1000)
    good = confirmed_for(tmp_path)
    bad = {
        "digest": Confirmed("0" * 64, good.model, good.month, good.reserved_micro),
        "model": Confirmed(good.digest, "another-model", good.month, good.reserved_micro),
        "month": Confirmed(good.digest, good.model, "2026-08", good.reserved_micro),
        "amount": Confirmed(good.digest, good.model, good.month, good.reserved_micro + 1),
    }[what]
    before = ledger_bytes(tmp_path)
    with pytest.raises(IllegalTransition, match="not what was confirmed"):
        ledger.admin_adopt_marker(STRAY, "r", WHO, LATER, bad)
    assert ledger_bytes(tmp_path) == before
    assert adopt(tmp_path)[0] == 0  # and the right confirmation still works


def test_the_confirmed_contents_are_the_contents_charged(tmp_path: Path) -> None:
    ledger = seeded(tmp_path)
    make_stray(tmp_path, reserved_micro=1234, job="the-confirmed-job")
    c = confirmed_for(tmp_path)
    before = totals(ledger)
    done = ledger.admin_adopt_marker(STRAY, "r", WHO, LATER, c)
    assert (done.model, done.month, done.reserved_micro) == (c.model, c.month, 1234)
    rec = next(r for r in ledger.view().calls.values() if r.nonce == STRAY)
    assert (rec.model, rec.job, rec.reserved_micro) == (c.model, "the-confirmed-job", 1234)
    assert totals(ledger)["2026-09"] - before["2026-09"] == 1234


def test_a_confirmation_that_is_not_the_confirmed_type_is_refused(tmp_path: Path) -> None:
    ledger = seeded(tmp_path)
    make_stray(tmp_path)
    before = ledger_bytes(tmp_path)
    with pytest.raises(IllegalTransition):
        ledger.admin_adopt_marker(STRAY, "r", WHO, LATER, STRAY)  # type: ignore[arg-type]  # the point of the test
    assert ledger_bytes(tmp_path) == before


@pytest.mark.parametrize("mode", [0o644, 0o660, 0o606, 0o777])
def test_a_marker_open_to_other_users_is_refused(tmp_path: Path, mode: int) -> None:
    seeded(tmp_path)
    stray = make_stray(tmp_path)
    stray.chmod(mode)
    before = ledger_bytes(tmp_path)
    assert adopt(tmp_path)[0] == 2
    assert ledger_bytes(tmp_path) == before


def test_a_billing_reason_cannot_look_like_the_head_of_an_adoption(tmp_path: Path) -> None:
    ledger = seeded(tmp_path)
    before = ledger_bytes(tmp_path)
    with pytest.raises(IllegalTransition):
        ledger.admin_adjust("2026-10", 9_000_000, ADOPT_PREFIX + "x", WHO, LATER)
    assert ledger_bytes(tmp_path) == before


def test_a_write_cut_at_any_byte_of_the_adoption_batch_is_all_in_or_all_out_and_a_retry_charges_once(
    tmp_path: Path,
) -> None:
    ledger = seeded(tmp_path)
    make_stray(tmp_path, reserved_micro=7000)
    pre = snapshot(tmp_path, "pre")
    before = totals(ledger)
    ledger.admin_adopt_marker(STRAY, "r", WHO, LATER, confirmed_for(tmp_path))
    full = ledger_bytes(tmp_path)
    start = len((pre / "ledger.jsonl").read_bytes())
    batch = full[start:]
    assert batch.count(b"\n") == 5  # the adjustment and the four call rows are one write
    cuts = sorted({0, len(batch), *range(0, len(batch), 7), *(i + 1 for i, b in enumerate(batch) if b == 10)})
    seen: set[bool] = set()
    for cut in cuts:
        restore(tmp_path, pre)
        with (state_dir(tmp_path) / "ledger.jsonl").open("ab") as handle:
            handle.write(batch[:cut])  # the torn write; the height record is still the old one, as after a real kill
        fresh = CallLedger(state_dir(tmp_path))
        try:
            fresh.recover(LATER)
        except LedgerError as err:
            assert "root must reconcile it" in str(err)  # the repair of the tail ran, the marker is still unrecorded
        now_totals = totals(fresh)
        assert all(now_totals[k] >= before[k] for k in before), cut
        gained = now_totals["2026-09"] - before["2026-09"]
        assert gained in (0, 7000), cut
        seen.add(gained == 7000)
        retry = adopt(tmp_path)  # the operator reruns the same command
        assert (retry[0] == 0) is (gained == 0), (cut, retry)
        if gained == 7000:
            assert "already has a ledger row" in retry[2]
        after = totals(CallLedger(state_dir(tmp_path)))
        assert after["2026-09"] - before["2026-09"] == 7000, cut  # exactly once, whichever way it was cut
        assert CallLedger(state_dir(tmp_path)).recover(LATER) in ([], ["d" * 32])
    assert seen == {False, True}  # both outcomes were exercised
