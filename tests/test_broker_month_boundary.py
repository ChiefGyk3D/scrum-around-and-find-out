# SPDX-License-Identifier: Apache-2.0
"""A call that straddles the UTC month boundary (#289 A1). The rule: a call is counted in the month it was reserved
in, and also in the month it ended in when that is a later month, so the cap check of the new month always sees it.
Every clock here is injected; nothing sleeps."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from brokerdata import approval, flat_request, new_ledger, policy
from fakevendor import FakeClock
from geminidata import make_key
from pipedata import Rig, text_req
from safo.broker.errors import Refused
from safo.broker.ledger import CallLedger, Ticket
from safo.broker.policy import Caps
from safo.broker.states import CallState

EPOCH = "ab" * 16
SMALL = Caps(job_micro=10_000, month_micro=10_000)
LAST = dt.datetime(2026, 10, 31, 23, 59, 59, tzinfo=dt.UTC)
FIRST = dt.datetime(2026, 11, 1, 0, 0, 1, tzinfo=dt.UTC)
MIDNIGHT = dt.datetime(2026, 11, 1, 0, 0, 0, tzinfo=dt.UTC)


def reserve_at(ledger: CallLedger, when: dt.datetime, reserved: int = 4000) -> Ticket:
    req = flat_request(reserved)
    appr = approval(req, created=when - dt.timedelta(minutes=1), expires_at=when + dt.timedelta(minutes=5))
    return ledger.reserve(req, appr, policy(SMALL), epoch=EPOCH, now=when)


def spent(ledger: CallLedger, when: dt.datetime) -> int:
    return ledger.view().month_spent(when)


def test_a_call_reserved_in_october_and_settled_in_november_counts_in_both_months(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t = reserve_at(ledger, LAST)
    ledger.mark_sent(t.call_id, LAST)
    ledger.settle(t.call_id, "ok", 3000, FIRST)
    assert (spent(ledger, LAST), spent(ledger, FIRST)) == (3000, 3000)
    assert ledger.view().calls[t.call_id].month == "2026-10"


def test_the_november_cap_sees_the_straddling_call(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t = reserve_at(ledger, LAST)
    ledger.mark_sent(t.call_id, LAST)
    ledger.settle(t.call_id, "ok", 3000, FIRST)
    with pytest.raises(Refused) as err:
        reserve_at(ledger, FIRST, 7001)  # 3000 + 7001 is one micro over the 10000 month
    assert err.value.code == "needs_block_approval"
    reserve_at(ledger, FIRST, 7000)  # exactly the month
    assert spent(ledger, FIRST) == 10_000


def test_a_call_still_open_in_november_counts_at_its_reservation_in_the_new_month(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t = reserve_at(ledger, LAST, 4000)
    ledger.mark_sent(t.call_id, LAST)
    assert spent(ledger, LAST) == 4000
    assert spent(ledger, FIRST) == 4000  # in flight across midnight
    with pytest.raises(Refused):
        reserve_at(ledger, FIRST, 6001)
    assert ledger.view().calls[t.call_id].state is CallState.SENT


def test_an_ambiguous_straddling_call_keeps_the_whole_reservation_in_both_months(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t = reserve_at(ledger, LAST, 4000)
    ledger.mark_sent(t.call_id, LAST)
    ledger.mark_ambiguous(t.call_id, "timeout", FIRST)
    assert (spent(ledger, LAST), spent(ledger, FIRST)) == (4000, 4000)


def test_a_breach_that_straddles_is_counted_in_full_in_both_months(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t = reserve_at(ledger, LAST, 4000)
    ledger.mark_sent(t.call_id, LAST)
    ledger.settle(t.call_id, "ok", 4500, FIRST)
    assert (spent(ledger, LAST), spent(ledger, FIRST)) == (4500, 4500)


def test_a_call_that_never_left_costs_nothing_in_either_month(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t = reserve_at(ledger, LAST)
    ledger.settle(t.call_id, "not_sent", 0, FIRST)
    assert (spent(ledger, LAST), spent(ledger, FIRST)) == (0, 0)


def test_a_call_reserved_just_after_midnight_counts_only_in_november(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t = reserve_at(ledger, MIDNIGHT)
    ledger.mark_sent(t.call_id, MIDNIGHT)
    ledger.settle(t.call_id, "ok", 3000, FIRST)
    assert (spent(ledger, LAST), spent(ledger, FIRST)) == (0, 3000)
    assert ledger.view().calls[t.call_id].month == "2026-11"


def test_a_call_inside_one_month_is_not_counted_in_the_next(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t = reserve_at(ledger, LAST - dt.timedelta(seconds=30))
    ledger.mark_sent(t.call_id, LAST - dt.timedelta(seconds=30))
    ledger.settle(t.call_id, "ok", 3000, LAST)
    assert (spent(ledger, LAST), spent(ledger, FIRST)) == (3000, 0)


def test_a_clock_that_goes_backward_at_settle_cannot_move_a_novembers_call_into_october(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t = reserve_at(ledger, MIDNIGHT)
    ledger.mark_sent(t.call_id, MIDNIGHT)
    ledger.settle(t.call_id, "ok", 3000, LAST)  # the clock now says October 31
    assert (spent(ledger, LAST), spent(ledger, FIRST)) == (0, 3000)


def test_a_backward_clock_after_a_straddle_leaves_both_months_counted(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t = reserve_at(ledger, LAST, 4000)
    ledger.mark_sent(t.call_id, FIRST)
    ledger.settle(t.call_id, "ok", 2000, LAST)  # the clock went back to October; the row keeps the last row time
    assert (spent(ledger, LAST), spent(ledger, FIRST)) == (2000, 2000)


def test_recovery_in_november_of_a_call_left_open_in_october_counts_it_in_both(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t = reserve_at(ledger, LAST, 4000)
    ledger.mark_sent(t.call_id, LAST)
    ledger.recover(FIRST)
    assert (spent(ledger, LAST), spent(ledger, FIRST)) == (4000, 4000)
    assert ledger.view().calls[t.call_id].ambiguous


def test_the_month_of_a_third_month_is_not_touched(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t = reserve_at(ledger, LAST)
    ledger.mark_sent(t.call_id, LAST)
    ledger.settle(t.call_id, "ok", 3000, FIRST)
    assert spent(ledger, dt.datetime(2026, 12, 1, tzinfo=dt.UTC)) == 0
    assert spent(ledger, dt.datetime(2026, 9, 30, tzinfo=dt.UTC)) == 0


# -- through the pipeline, with the fake clocks ---------------------------------------------------------------------


@pytest.fixture(scope="module")
def key(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_key(tmp_path_factory.mktemp("keys") / "a")


def test_a_pipeline_call_whose_answer_arrives_after_midnight_counts_in_both_months(tmp_path: Path, key: Path) -> None:
    rig = Rig(tmp_path, key)
    clock: FakeClock = rig.clock
    clock.at = LAST

    def midnight_passes(_: object) -> None:
        clock.at = FIRST

    rig.vendor.on_send = midnight_passes
    result = rig.run(text_req())
    assert result.code == "ok"
    cost = result.receipt.actual_micro
    assert cost > 0
    assert rig.ledger.view().month_spent(LAST) == cost
    assert rig.ledger.view().month_spent(FIRST) == cost
    assert result.receipt.month_spent_micro == cost


def test_a_pipeline_call_with_a_backward_clock_does_not_leave_the_new_month(tmp_path: Path, key: Path) -> None:
    rig = Rig(tmp_path, key)
    rig.clock.at = FIRST

    def clock_steps_back(_: object) -> None:
        rig.clock.at = LAST

    rig.vendor.on_send = clock_steps_back
    result = rig.run(text_req())
    cost = result.receipt.actual_micro
    assert (rig.ledger.view().month_spent(LAST), rig.ledger.view().month_spent(FIRST)) == (0, cost)
