# SPDX-License-Identifier: Apache-2.0
"""The broker ledger: spend before the call, the state machine on disk, caps, replay, corruption, crashes, races."""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import os
import shutil
import stat
import threading
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from multiprocessing import get_context
from pathlib import Path
from typing import Any

import pytest

from brokerdata import (
    EPOCH,
    FLAT,
    NOW,
    Crash,
    CrashAt,
    approval,
    flat_request,
    new_ledger,
    policy,
    request,
    reserve_worker,
    state_dir,
)
from safo import gemini
from safo.bounded import MAX_FILE_BYTES
from safo.broker import records
from safo.broker.errors import IllegalTransition, LedgerError, Refused
from safo.broker.ledger import FAULT_POINTS, CallLedger, Ticket
from safo.broker.policy import JOB_CAP_MICRO, MONTH_CAP_MICRO, BrokerRequest, Caps
from safo.broker.records import ApprovalV3
from safo.broker.states import CallState

SMALL = Caps(job_micro=10_000, month_micro=10_000)  # a month that a few small reservations fill exactly
LATER = NOW + dt.timedelta(seconds=30)


def reserve(
    ledger: CallLedger,
    reserved: int = 5000,
    *,
    caps: Caps | None = None,
    now: dt.datetime = NOW,
    model: str = FLAT,
    **over: Any,
) -> tuple[Ticket, ApprovalV3, BrokerRequest]:
    req = flat_request(reserved, model=model)
    appr = approval(req, **over)
    ticket = ledger.reserve(req, appr, policy(caps), epoch=EPOCH, now=now)
    return ticket, appr, req


def rows(tmp: Path) -> list[dict[str, Any]]:
    text = (state_dir(tmp) / "ledger.jsonl").read_text()
    return [json.loads(line) for line in text.splitlines()]


def state_of(ledger: CallLedger, ticket: Ticket) -> CallState:
    return ledger.view().calls[ticket.call_id].state


def settled_ok(ledger: CallLedger, ticket: Ticket, actual: int) -> None:
    ledger.mark_sent(ticket.call_id, NOW)
    ledger.settle(ticket.call_id, "ok", actual, NOW)


# -- reserving -----------------------------------------------------------------------------------------------------


def test_reserve_spends_first_and_records_everything(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    ticket, appr, req = reserve(ledger, 5000)
    assert ticket.reserved_micro == 5000
    view = ledger.view()
    call = view.calls[ticket.call_id]
    assert (call.state, call.reserved_micro, call.model, call.job) == (CallState.RESERVED, 5000, FLAT, req.job)
    assert view.spent_nonces == {appr.nonce}
    assert view.month_spent(NOW) == 5000
    assert [r["type"] for r in rows(tmp_path)] == ["chain_start", "approval_used", "call_start"]
    assert (state_dir(tmp_path) / "used" / appr.nonce).exists()
    assert (state_dir(tmp_path) / "schema_version").read_text() == "3\n"


def test_files_and_folders_are_private(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    ticket, appr, _ = reserve(ledger)
    settled_ok(ledger, ticket, 10)
    folder = state_dir(tmp_path)
    for path in (folder, folder / "used"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
    files = [p for p in folder.rglob("*") if p.is_file()]
    assert {p.name for p in files} >= {"ledger.jsonl", "ledger.jsonl.head", "height", "schema_version", appr.nonce}
    for path in files:
        assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0, path.name
        assert path.stat().st_uid == os.geteuid()


def test_the_ledger_holds_integers_and_no_float(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    ticket, _, _ = reserve(ledger)
    settled_ok(ledger, ticket, 4999)

    def no_float(text: str) -> float:
        raise AssertionError(f"a float in the ledger: {text}")

    for line in (state_dir(tmp_path) / "ledger.jsonl").read_text().splitlines():
        json.loads(line, parse_float=no_float)


def test_the_call_id_is_random_and_the_ticket_matches_the_ledger(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    a, _, _ = reserve(ledger, 100)
    b, _, _ = reserve(ledger, 100)
    assert a.call_id != b.call_id
    assert set(ledger.view().calls) == {a.call_id, b.call_id}


# -- replay --------------------------------------------------------------------------------------------------------


def test_an_approval_spends_once(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    req = flat_request(5000)
    appr = approval(req)
    ledger.reserve(req, appr, policy(), epoch=EPOCH, now=NOW)
    for who in (ledger, CallLedger(state_dir(tmp_path))):
        with pytest.raises(Refused) as err:
            who.reserve(req, appr, policy(), epoch=EPOCH, now=NOW)
        assert err.value.code == "used"
    again = dataclasses.replace(approval(req), nonce=appr.nonce)  # a second signature over the same nonce
    with pytest.raises(Refused) as err:
        ledger.reserve(req, again, policy(), epoch=EPOCH, now=NOW)
    assert err.value.code == "used"
    assert ledger.view().month_spent(NOW) == 5000  # nothing was counted twice


def test_the_marker_alone_marks_a_nonce_spent(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    req = flat_request(5000)
    appr = approval(req)
    ledger.reserve(req, appr, policy(), epoch=EPOCH, now=NOW)
    folder = state_dir(tmp_path)
    for name in ("ledger.jsonl", "ledger.jsonl.head", "height"):  # a rolled-back ledger
        (folder / name).unlink()
    with pytest.raises(Refused) as err:
        CallLedger(folder).reserve(req, appr, policy(), epoch=EPOCH, now=NOW)
    assert err.value.code == "used"
    assert not (folder / "ledger.jsonl").exists()  # refused up front, not after a row was appended


def test_the_ledger_row_alone_marks_a_nonce_spent(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    req = flat_request(5000)
    appr = approval(req)
    ledger.reserve(req, appr, policy(), epoch=EPOCH, now=NOW)
    (state_dir(tmp_path) / "used" / appr.nonce).unlink()
    with pytest.raises(Refused) as err:
        ledger.reserve(req, appr, policy(), epoch=EPOCH, now=NOW)
    assert err.value.code == "used"


# -- refusals leave nothing behind ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("req_over", "appr_over", "code"),
    [
        ({}, {"prompt_sha256": "1" * 64}, "digest_mismatch"),
        ({}, {"job": "other"}, "job_mismatch"),
        ({}, {"model": "other-model"}, "model_mismatch"),
        ({}, {"epoch": "cd" * 16}, "bad_approval"),
        ({}, {"expires_at": NOW}, "expired"),
        ({}, {"max_micro": 4999}, "over_approved"),
        ({"model": "gemini-3.5-pro", "thinking_level": "none"}, {"model": "gemini-3.5-pro"}, "model_refused"),
        ({"model": "not-listed"}, {"model": "not-listed"}, "model_refused"),
    ],
)
def test_a_refused_reservation_writes_nothing(
    tmp_path: Path, req_over: dict[str, Any], appr_over: dict[str, Any], code: str
) -> None:
    ledger = new_ledger(tmp_path)
    req = flat_request(5000, **req_over)
    with pytest.raises(Refused) as err:
        ledger.reserve(req, approval(req, **appr_over), policy(), epoch=EPOCH, now=NOW)
    assert err.value.code == code
    assert not (state_dir(tmp_path) / "ledger.jsonl").exists()
    assert not list((state_dir(tmp_path) / "used").glob("*")) if (state_dir(tmp_path) / "used").exists() else True
    assert ledger.view().month_spent(NOW) == 0


def test_a_refusal_does_not_echo_the_prompt_or_the_nonce(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    req = request(prompt="SENTINEL-prompt-text", job="sentinel-job")
    appr = approval(req, prompt_sha256="1" * 64)
    with pytest.raises(Refused) as err:
        ledger.reserve(req, appr, policy(), epoch=EPOCH, now=NOW)
    text = str(err.value)
    assert not any(s in text for s in ("SENTINEL", "sentinel", appr.nonce, appr.quote))


# -- caps at the ledger ---------------------------------------------------------------------------------------------


def test_job_cap_at_the_limit_and_one_micro_over(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    ticket, _, _ = reserve(ledger, JOB_CAP_MICRO)
    assert ticket.reserved_micro == JOB_CAP_MICRO
    req = flat_request(JOB_CAP_MICRO + 1)
    before = (state_dir(tmp_path) / "ledger.jsonl").read_bytes()
    with pytest.raises(Refused) as err:
        ledger.reserve(req, approval(req, max_micro=10**9, beyond_ceiling=True), policy(), epoch=EPOCH, now=NOW)
    assert err.value.code == "over_job_cap"
    assert (state_dir(tmp_path) / "ledger.jsonl").read_bytes() == before


def test_signed_maximum_at_the_limit(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    reserve(ledger, 5000, max_micro=5000)
    with pytest.raises(Refused) as err:
        reserve(ledger, 5000, max_micro=4999)
    assert err.value.code == "over_approved"


def test_monthly_cap_filled_exactly_then_one_micro_over(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    reserve(ledger, 4000, caps=SMALL)
    reserve(ledger, 6000, caps=SMALL)  # 10000 of 10000: exactly at the limit
    assert ledger.view().month_spent(NOW) == 10_000
    with pytest.raises(Refused) as err:
        reserve(ledger, 74, caps=SMALL)  # the smallest reservation of this model
    assert err.value.code == "needs_block_approval"


def test_monthly_cap_one_micro_over_is_refused_and_the_flag_lifts_it(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    reserve(ledger, 4000, caps=SMALL)
    with pytest.raises(Refused) as err:
        reserve(ledger, 6001, caps=SMALL)
    assert err.value.code == "needs_block_approval"
    assert ledger.view().month_spent(NOW) == 4000
    reserve(ledger, 6001, caps=SMALL, beyond_ceiling=True)
    assert ledger.view().month_spent(NOW) == 10_001


def test_the_real_ten_dollar_month(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    for _ in range(4):
        reserve(ledger, JOB_CAP_MICRO)
    assert ledger.view().month_spent(NOW) == MONTH_CAP_MICRO
    with pytest.raises(Refused) as err:
        reserve(ledger, 74)
    assert err.value.code == "needs_block_approval"


def test_months_are_counted_apart_by_utc_calendar_month(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    last = dt.datetime(2026, 10, 31, 23, 59, 59, tzinfo=dt.UTC)
    first = dt.datetime(2026, 11, 1, 0, 0, 0, tzinfo=dt.UTC)
    old, _, _ = reserve(
        ledger,
        4000,
        caps=SMALL,
        now=last,
        expires_at=first + dt.timedelta(minutes=5),
        created=last - dt.timedelta(minutes=1),
    )
    ledger.mark_sent(old.call_id, last)  # settled inside its own month: it does not straddle
    ledger.settle(old.call_id, "ok", 4000, last)
    reserve(ledger, 7000, caps=SMALL, now=first, expires_at=first + dt.timedelta(minutes=5), created=last)
    view = ledger.view()
    assert (view.month_spent(last), view.month_spent(first)) == (4000, 7000)


# -- the clock ------------------------------------------------------------------------------------------------------


def test_a_clock_that_goes_backward_cannot_move_a_spend_to_an_earlier_month(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    reserve(ledger, 1000, now=LATER)
    with pytest.raises(Refused):
        reserve(ledger, 1000, now=NOW)
    reserve(ledger, 1000, now=LATER)  # the same second is fine
    earlier_month = dt.datetime(2026, 9, 30, tzinfo=dt.UTC)
    with pytest.raises(Refused):
        reserve(
            ledger, 1000, now=earlier_month, created=earlier_month, expires_at=earlier_month + dt.timedelta(minutes=5)
        )


@pytest.mark.parametrize("bad", [dt.datetime(2026, 10, 30, 12), NOW.timestamp(), "2026-10-30", None])
def test_now_must_be_a_plain_time_with_a_zone(tmp_path: Path, bad: Any) -> None:
    ledger = new_ledger(tmp_path)
    with pytest.raises(Refused) as err:
        reserve(ledger, now=bad)
    assert err.value.code == "bad_request"


# -- the state machine on disk -------------------------------------------------------------------------------------


def test_the_happy_path_reserved_sent_settled(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    ticket, _, _ = reserve(ledger, 5000)
    assert state_of(ledger, ticket) is CallState.RESERVED
    ledger.mark_sent(ticket.call_id, NOW)
    assert state_of(ledger, ticket) is CallState.SENT
    done = ledger.settle(ticket.call_id, "ok", 1234, NOW)
    assert (done.reserved_micro, done.actual_micro, done.released_micro, done.breach) == (5000, 1234, 3766, False)
    view = ledger.view()
    assert view.calls[ticket.call_id].state is CallState.SETTLED
    assert view.month_spent(NOW) == 1234  # the month counts the actual once it is known
    assert not view.suspended


def test_settling_exactly_at_the_reservation_is_not_a_breach_and_one_over_is(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    a, _, _ = reserve(ledger, 5000)
    settled_ok(ledger, a, 5000)
    assert not ledger.view().suspended
    b, _, _ = reserve(ledger, 5000)
    ledger.mark_sent(b.call_id, NOW)
    done = ledger.settle(b.call_id, "ok", 5001, NOW)
    assert (done.breach, done.released_micro) == (True, 0)
    view = ledger.view()
    assert view.calls[b.call_id].state is CallState.SUSPENDED
    assert view.suspended == {FLAT: (b.call_id,)}
    assert view.month_spent(NOW) == 5000 + 5001  # a breach is counted in full


def test_a_breached_model_is_stopped_until_root_clears_it(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t, _, _ = reserve(ledger, 5000)
    ledger.mark_sent(t.call_id, NOW)
    ledger.settle(t.call_id, "ok", 9000, NOW)
    with pytest.raises(Refused) as err:
        reserve(ledger, 100)
    assert err.value.code == "model_suspended"
    ledger.clear(FLAT, NOW)  # a breach has a real figure already: nothing to resolve
    assert ledger.view().calls[t.call_id].state is CallState.CLEARED
    reserve(ledger, 100)
    with pytest.raises(IllegalTransition):
        ledger.clear(FLAT, NOW)


def test_not_sent_is_a_definite_refusal_before_the_request_left(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t, _, _ = reserve(ledger, 5000)
    done = ledger.settle(t.call_id, "not_sent", 0, NOW)
    assert (done.actual_micro, done.released_micro) == (0, 5000)
    assert ledger.view().month_spent(NOW) == 0
    assert not ledger.view().suspended
    with pytest.raises(Refused) as err:  # the approval is still spent: the nonce does not come back
        ledger.reserve(flat_request(5000), approval(flat_request(5000), nonce=t.nonce), policy(), epoch=EPOCH, now=NOW)
    assert err.value.code == "used"


@pytest.mark.parametrize("status", ["rate_limited", "vendor_refused"])
def test_definite_non_billing_outcomes_do_not_suspend(tmp_path: Path, status: str) -> None:
    ledger = new_ledger(tmp_path)
    t, _, _ = reserve(ledger, 5000)
    ledger.mark_sent(t.call_id, NOW)
    ledger.settle(t.call_id, status, 0, NOW)
    view = ledger.view()
    assert not view.suspended and view.month_spent(NOW) == 0


def test_an_ambiguous_call_counts_the_whole_reservation_and_stops_the_model(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t, _, _ = reserve(ledger, 5000)
    ledger.mark_sent(t.call_id, NOW)
    ledger.mark_ambiguous(t.call_id, "timeout", NOW)
    view = ledger.view()
    assert view.calls[t.call_id].state is CallState.SUSPENDED and view.calls[t.call_id].ambiguous
    assert view.month_spent(NOW) == 5000
    with pytest.raises(Refused) as err:
        reserve(ledger, 100)
    assert err.value.code == "model_suspended"
    other = flat_request(100, model="gemini-3.6-flash", thinking_level="minimal")  # another model is not stopped
    ledger.reserve(other, approval(other), policy(), epoch=EPOCH, now=NOW)


def test_root_resolves_then_clears_an_ambiguous_call(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t, _, _ = reserve(ledger, 5000)
    ledger.mark_sent(t.call_id, NOW)
    ledger.mark_ambiguous(t.call_id, "connection", NOW)
    with pytest.raises(IllegalTransition):  # the real amount comes first
        ledger.clear(FLAT, NOW)
    ledger.resolve(t.call_id, 1200, NOW)
    assert ledger.view().month_spent(NOW) == 1200  # the real figure replaces the reservation
    with pytest.raises(IllegalTransition):
        ledger.resolve(t.call_id, 1300, NOW)  # once
    ledger.clear(FLAT, NOW)
    assert ledger.view().calls[t.call_id].state is CallState.CLEARED
    reserve(ledger, 100)


def test_resolving_may_raise_the_figure_above_the_reservation(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t, _, _ = reserve(ledger, 5000)
    ledger.mark_ambiguous(t.call_id, "status", NOW)
    ledger.resolve(t.call_id, 9000, NOW)
    assert ledger.view().month_spent(NOW) == 9000


@pytest.mark.parametrize("amount", [-1, 10**13, 1.5, True, "5", None])
def test_resolve_refuses_a_bad_amount(tmp_path: Path, amount: Any) -> None:
    ledger = new_ledger(tmp_path)
    t, _, _ = reserve(ledger, 5000)
    ledger.mark_ambiguous(t.call_id, "status", NOW)
    with pytest.raises(Refused):
        ledger.resolve(t.call_id, amount, NOW)


def test_illegal_steps_are_rejected_and_write_nothing(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t, _, _ = reserve(ledger, 5000)
    path = state_dir(tmp_path) / "ledger.jsonl"
    snapshots = [path.read_bytes()]

    def rejected(action: Callable[[], object]) -> None:
        with pytest.raises(IllegalTransition):
            action()
        assert path.read_bytes() == snapshots[-1]

    rejected(lambda: ledger.settle(t.call_id, "ok", 1, NOW))  # reserved -> settled needs a send first
    rejected(lambda: ledger.settle(t.call_id, "rate_limited", 0, NOW))
    ledger.mark_sent(t.call_id, NOW)
    snapshots.append(path.read_bytes())
    rejected(lambda: ledger.mark_sent(t.call_id, NOW))  # sent -> sent
    rejected(lambda: ledger.settle(t.call_id, "not_sent", 0, NOW))  # it did leave
    rejected(lambda: ledger.resolve(t.call_id, 1, NOW))  # not ambiguous
    rejected(lambda: ledger.clear(FLAT, NOW))  # not suspended
    ledger.settle(t.call_id, "ok", 10, NOW)
    snapshots.append(path.read_bytes())
    rejected(lambda: ledger.settle(t.call_id, "ok", 10, NOW))  # settled twice
    rejected(lambda: ledger.mark_sent(t.call_id, NOW))  # settled -> sent
    rejected(lambda: ledger.mark_ambiguous(t.call_id, "timeout", NOW))  # settled -> ambiguous
    rejected(lambda: ledger.resolve(t.call_id, 1, NOW))


@pytest.mark.parametrize(
    ("status", "amount"),
    [
        ("bogus", 0),
        ("ok", -1),
        ("ok", 1.5),
        ("ok", True),
        ("ok", 10**13),
        ("rate_limited", 5),
        ("vendor_refused", 1),
        ("not_sent", 1),
    ],
)
def test_settle_refuses_a_bad_status_or_amount(tmp_path: Path, status: str, amount: Any) -> None:
    ledger = new_ledger(tmp_path)
    t, _, _ = reserve(ledger, 5000)
    ledger.mark_sent(t.call_id, NOW)
    with pytest.raises(IllegalTransition):
        ledger.settle(t.call_id, status, amount, NOW)
    assert state_of(ledger, t) is CallState.SENT


@pytest.mark.parametrize("call_id", ["", "x", "0" * 32, None, 5, "../../etc/passwd"])
def test_an_unknown_call_id_is_rejected(tmp_path: Path, call_id: Any) -> None:
    ledger = new_ledger(tmp_path)
    reserve(ledger, 5000)
    for action in (
        lambda: ledger.mark_sent(call_id, NOW),
        lambda: ledger.settle(call_id, "ok", 1, NOW),
        lambda: ledger.mark_ambiguous(call_id, "timeout", NOW),
        lambda: ledger.resolve(call_id, 1, NOW),
    ):
        with pytest.raises(IllegalTransition):
            action()


def test_settle_uses_the_reservation_the_ledger_holds(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t, _, _ = reserve(ledger, 5000)
    ledger.mark_sent(t.call_id, NOW)
    forged = dataclasses.replace(t, reserved_micro=10**9)  # a caller's ticket cannot widen the breach threshold
    assert forged.reserved_micro != 5000
    done = ledger.settle(forged.call_id, "ok", 6000, NOW)
    assert done.reserved_micro == 5000 and done.breach


def test_a_settlement_after_a_restart_made_the_call_ambiguous_is_rejected(tmp_path: Path) -> None:
    # Time of check to time of use: the process that reserved is slow; a restart's recovery runs; its late settle must
    # not turn the ambiguous call into free budget.
    slow = new_ledger(tmp_path)
    t, _, _ = reserve(slow, 5000)
    slow.mark_sent(t.call_id, NOW)
    restarted = CallLedger(state_dir(tmp_path))
    assert restarted.recover(NOW) == [t.call_id]
    with pytest.raises(IllegalTransition):
        slow.settle(t.call_id, "ok", 0, NOW)
    view = restarted.view()
    assert view.month_spent(NOW) == 5000
    assert view.calls[t.call_id].ambiguous and FLAT in view.suspended


# -- corrupt and truncated files -----------------------------------------------------------------------------------


def seeded(tmp_path: Path) -> tuple[CallLedger, Path]:
    ledger = new_ledger(tmp_path)
    for n in (4000, 3000, 2000):
        t, _, _ = reserve(ledger, n)
        settled_ok(ledger, t, n - 1)
    return ledger, state_dir(tmp_path) / "ledger.jsonl"


def untouched(ledger: CallLedger, path: Path) -> None:
    before = path.read_bytes()
    with pytest.raises(LedgerError):
        ledger.view()
    with pytest.raises(LedgerError):
        reserve(ledger, 100)
    assert path.read_bytes() == before  # a damaged ledger takes no new rows


def test_a_truncated_last_line_stops_everything_until_recovery(tmp_path: Path) -> None:
    ledger, path = seeded(tmp_path)
    data = path.read_bytes()
    path.write_bytes(data[:-17])
    untouched(ledger, path)


def test_a_truncated_ledger_cut_anywhere_never_reads_as_free_budget(tmp_path: Path) -> None:
    ledger, path = seeded(tmp_path)
    data = path.read_bytes()
    spent = ledger.view().month_spent(NOW)
    for cut in range(0, len(data), 13):
        path.write_bytes(data[:cut])
        try:
            got = ledger.view().month_spent(NOW)
        except LedgerError:
            continue
        # a cut on a row boundary leaves a shorter chain, which the head file and height record refuse
        assert (cut == 0 and got == 0) or got == spent, cut


def test_a_cut_on_a_row_boundary_is_a_rewind_the_head_and_height_records_catch(tmp_path: Path) -> None:
    ledger, path = seeded(tmp_path)
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:-2]))
    untouched(ledger, path)


@pytest.mark.parametrize(
    "mutation",
    [
        "garbage_line",
        "binary",
        "not_a_dict",
        "duplicate_key",
        "deep",
        "bom",
        "edit_amount",
        "drop_middle",
        "swap_rows",
        "extra_field",
    ],
)
def test_a_damaged_ledger_is_refused_and_not_written_to(tmp_path: Path, mutation: str) -> None:
    ledger, path = seeded(tmp_path)
    lines = path.read_bytes().splitlines(keepends=True)
    if mutation == "garbage_line":
        lines.insert(3, b"this is not json\n")
    elif mutation == "binary":
        lines.insert(3, bytes(range(256)) + b"\n")
    elif mutation == "not_a_dict":
        lines.insert(3, b"[1,2,3]\n")
    elif mutation == "duplicate_key":
        lines[3] = lines[3].replace(b'{"', b'{"type":"x","type":"y",', 1)
    elif mutation == "deep":
        lines.insert(3, b'{"a":' * 200 + b"1" + b"}" * 200 + b"\n")
    elif mutation == "bom":
        lines[0] = b"\xef\xbb\xbf" + lines[0]
    elif mutation == "edit_amount":
        lines[2] = lines[2].replace(b'"reserved_micro": 4000', b'"reserved_micro": 1')
        assert lines[2] != path.read_bytes().splitlines(keepends=True)[2]
    elif mutation == "drop_middle":
        del lines[3]
    elif mutation == "swap_rows":
        lines[2], lines[3] = lines[3], lines[2]
    elif mutation == "extra_field":
        lines[2] = lines[2].replace(b'"job"', b'"zzz": 1, "job"', 1)
    path.write_bytes(b"".join(lines))
    untouched(ledger, path)


def test_a_rewritten_chain_with_matching_hashes_is_caught_by_the_height_record(tmp_path: Path) -> None:
    ledger, path = seeded(tmp_path)
    parsed = [json.loads(line) for line in path.read_text().splitlines()]
    previous = parsed[0]["hash"]
    for row in parsed[1:]:
        if row.get("reserved_micro") == 4000:
            row["reserved_micro"] = 1  # an attacker lowers a spend and re-chains every hash after it
        row["prev_hash"] = previous
        row["hash"] = gemini._chain_hash(row)
        previous = row["hash"]
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in parsed))
    # keep the head file in step as well: only the height record, kept apart, is left to notice
    (state_dir(tmp_path) / "ledger.jsonl.head").write_text(f"{len(parsed)} {previous}\n")
    untouched(ledger, path)


def test_a_huge_ledger_is_refused_not_read(tmp_path: Path) -> None:
    ledger, path = seeded(tmp_path)
    with path.open("ab") as handle:
        handle.truncate(MAX_FILE_BYTES + 10)
    with pytest.raises(LedgerError):
        ledger.view()


def test_a_symlinked_ledger_is_refused(tmp_path: Path) -> None:
    ledger, path = seeded(tmp_path)
    real = tmp_path / "elsewhere.jsonl"
    shutil.copy(path, real)
    path.unlink()
    path.symlink_to(real)
    with pytest.raises(LedgerError):
        ledger.view()
    with pytest.raises(LedgerError):
        reserve(ledger, 100)


def test_a_fifo_for_a_ledger_does_not_hang_and_is_refused(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    os.mkfifo(state_dir(tmp_path) / "ledger.jsonl", 0o600)
    with pytest.raises(LedgerError):
        ledger.view()


@pytest.mark.parametrize("name", ["ledger.jsonl", "ledger.jsonl.head", "height", "schema_version", "used"])
def test_state_files_open_to_other_users_are_refused(tmp_path: Path, name: str) -> None:
    ledger, _ = seeded(tmp_path)
    target = state_dir(tmp_path) / name
    mode = target.stat().st_mode
    for extra in (0o040, 0o004, 0o020, 0o002):
        os.chmod(target, stat.S_IMODE(mode) | extra)
        with pytest.raises(LedgerError):
            ledger.view()
        os.chmod(target, stat.S_IMODE(mode))
    assert ledger.view()


def test_a_state_directory_open_to_others_is_refused(tmp_path: Path) -> None:
    ledger, _ = seeded(tmp_path)
    private = stat.S_IMODE(state_dir(tmp_path).stat().st_mode)
    others = stat.S_IRGRP | stat.S_IXGRP  # read and search for the group
    os.chmod(state_dir(tmp_path), private | others)
    with pytest.raises(LedgerError):
        ledger.view()
    with pytest.raises(LedgerError):
        CallLedger(state_dir(tmp_path)).open()
    os.chmod(state_dir(tmp_path), 0o700)


def test_a_symlinked_state_directory_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(LedgerError):
        CallLedger(link).open()


def test_a_stray_file_or_link_in_the_used_folder_stops_recovery(tmp_path: Path) -> None:
    ledger, _ = seeded(tmp_path)
    stray = state_dir(tmp_path) / "used" / "not-a-nonce"
    stray.write_text("x")
    with pytest.raises(LedgerError):
        ledger.recover(NOW)
    stray.unlink()
    ledger.recover(NOW)


def test_a_marker_that_is_a_link_is_refused(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t, appr, _ = reserve(ledger)
    marker = state_dir(tmp_path) / "used" / appr.nonce
    marker.unlink()
    marker.symlink_to(tmp_path / "target")
    with pytest.raises(Refused):  # a link still marks the nonce spent
        reserve(ledger, 100, nonce=appr.nonce)
    with pytest.raises(LedgerError):
        ledger.recover(NOW)
    assert t


# -- schema version ------------------------------------------------------------------------------------------------


def hand_row(kind: str, ledger: CallLedger, **fields: Any) -> None:
    row = {"type": kind, "ts": gemini.stamp(NOW), "v": 3, **fields}
    ledger.ledger.append_many([row], ts=gemini.stamp(NOW))


def test_a_newer_schema_floor_stops_older_code(tmp_path: Path) -> None:
    ledger, _ = seeded(tmp_path)
    (state_dir(tmp_path) / "schema_version").write_text("4\n")
    with pytest.raises(LedgerError):
        ledger.view()
    with pytest.raises(LedgerError):
        reserve(ledger, 100)


@pytest.mark.parametrize("text", ["", "x\n", "0\n", "-1\n", "3.0\n", "99999999999999999999999999\n"])
def test_a_malformed_floor_is_refused(tmp_path: Path, text: str) -> None:
    ledger, _ = seeded(tmp_path)
    (state_dir(tmp_path) / "schema_version").write_text(text)
    with pytest.raises(LedgerError):
        ledger.view()


def test_a_missing_floor_is_recreated_not_trusted_as_lower(tmp_path: Path) -> None:
    ledger, _ = seeded(tmp_path)
    (state_dir(tmp_path) / "schema_version").unlink()
    ledger.recover(NOW)
    assert (state_dir(tmp_path) / "schema_version").read_text() == "3\n"


def test_rows_of_an_unread_version_are_refused(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    ledger.ledger.append_many(
        [{"type": "call_sent", "ts": gemini.stamp(NOW), "v": 4, "call_id": "a" * 32}], ts=gemini.stamp(NOW)
    )
    with pytest.raises(LedgerError):
        ledger.view()


def test_the_version_in_the_ledger_never_goes_backward(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(records, "SUPPORTED_VERSIONS", (3, 4))
    ledger = new_ledger(tmp_path)
    t, _, _ = reserve(ledger, 5000)
    ledger.ledger.append_many([{"type": "call_sent", "ts": gemini.stamp(NOW), "v": 4, "call_id": t.call_id}])
    assert ledger.view().calls[t.call_id].state is CallState.SENT  # a newer reader would accept a rising version
    ledger.ledger.append_many(
        [
            {
                "type": "call_end",
                "ts": gemini.stamp(NOW),
                "v": 3,
                "call_id": t.call_id,
                "status": "ok",
                "actual_micro": 1,
                "released_micro": 4999,
                "breach": False,
            }
        ]
    )
    with pytest.raises(LedgerError, match="goes backward"):
        ledger.view()


def test_row_times_never_go_backward(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t, _, _ = reserve(ledger, 5000, now=LATER)
    ledger.ledger.append_many([{"type": "call_sent", "ts": gemini.stamp(NOW), "v": 3, "call_id": t.call_id}])
    with pytest.raises(LedgerError):
        ledger.view()


# -- the ledger obeys the state machine when read ------------------------------------------------------------------

CID = "a" * 32
OTHER = "b" * 32


def start_rows(call_id: str = CID, nonce: str = "1" * 16, reserved: int = 100) -> list[dict[str, Any]]:
    ts = gemini.stamp(NOW)
    return [
        {
            "type": "approval_used",
            "ts": ts,
            "v": 3,
            "nonce": nonce,
            "call_id": call_id,
            "model": FLAT,
            "job": "j",
            "epoch": EPOCH,
        },
        {
            "type": "call_start",
            "ts": ts,
            "v": 3,
            "call_id": call_id,
            "nonce": nonce,
            "model": FLAT,
            "kind": "text",
            "job": "j",
            "reserved_micro": reserved,
            "prompt_sha256": "0" * 64,
            "prompt_bytes": 0,
            "image_size": "",
            "count": 0,
        },
    ]


def row_of(kind: str, **fields: Any) -> dict[str, Any]:
    return {"type": kind, "ts": gemini.stamp(NOW), "v": 3, **fields}


END = {"status": "ok", "actual_micro": 10, "released_micro": 90, "breach": False}
SCENARIOS: dict[str, list[dict[str, Any]]] = {
    "call_sent for a call that does not exist": [row_of("call_sent", call_id=OTHER)],
    "call_end without a send": [row_of("call_end", call_id=CID, **END)],
    "not_sent after a send": [
        row_of("call_sent", call_id=CID),
        row_of("call_end", call_id=CID, **{**END, "status": "not_sent", "actual_micro": 0, "released_micro": 100}),
    ],
    "call_sent twice": [row_of("call_sent", call_id=CID), row_of("call_sent", call_id=CID)],
    "end with the wrong release": [
        row_of("call_sent", call_id=CID),
        row_of("call_end", call_id=CID, **{**END, "released_micro": 91}),
    ],
    "end that hides a breach": [
        row_of("call_sent", call_id=CID),
        row_of("call_end", call_id=CID, **{**END, "actual_micro": 500, "released_micro": 0}),
    ],
    "a breach with no suspension after it": [
        row_of("call_sent", call_id=CID),
        row_of("call_end", call_id=CID, **{**END, "actual_micro": 500, "released_micro": 0, "breach": True}),
    ],
    "a breach followed by something else": [
        row_of("call_sent", call_id=CID),
        row_of("call_end", call_id=CID, **{**END, "actual_micro": 500, "released_micro": 0, "breach": True}),
        row_of("call_sent", call_id=CID),
    ],
    "a breach whose suspension comes after another call's row": [
        *start_rows(OTHER, "3" * 16),
        row_of("call_sent", call_id=CID),
        row_of("call_end", call_id=CID, **{**END, "actual_micro": 500, "released_micro": 0, "breach": True}),
        row_of("call_sent", call_id=OTHER),
        row_of("suspended", call_id=CID, model=FLAT, reason="breach"),
    ],
    "ambiguous with no suspension after it": [
        row_of("ambiguous_call", call_id=CID, model=FLAT, reserved_micro=100, reason="timeout")
    ],
    "ambiguous with the wrong reservation": [
        row_of("ambiguous_call", call_id=CID, model=FLAT, reserved_micro=99, reason="timeout"),
        row_of("suspended", call_id=CID, model=FLAT, reason="ambiguous"),
    ],
    "suspended with nothing before it": [row_of("suspended", call_id=CID, model=FLAT, reason="ambiguous")],
    "suspended for a settled call that did not breach": [
        row_of("call_sent", call_id=CID),
        row_of("call_end", call_id=CID, **END),
        row_of("suspended", call_id=CID, model=FLAT, reason="breach"),
    ],
    "resolved a call that is not ambiguous": [row_of("ambiguous_resolved", call_id=CID, actual_micro=1)],
    "cleared with nothing suspended": [row_of("suspension_cleared", model=FLAT)],
    "cleared with an unresolved ambiguous call": [
        row_of("ambiguous_call", call_id=CID, model=FLAT, reserved_micro=100, reason="timeout"),
        row_of("suspended", call_id=CID, model=FLAT, reason="ambiguous"),
        row_of("suspension_cleared", model=FLAT),
    ],
    "a send after clearing": [
        row_of("ambiguous_call", call_id=CID, model=FLAT, reserved_micro=100, reason="timeout"),
        row_of("suspended", call_id=CID, model=FLAT, reason="ambiguous"),
        row_of("ambiguous_resolved", call_id=CID, actual_micro=1),
        row_of("suspension_cleared", model=FLAT),
        row_of("call_sent", call_id=CID),
    ],
    "the same call id started twice": [*start_rows(CID, "2" * 16)],
    "the same nonce used twice": [*start_rows(OTHER, "1" * 16)],
    "an approval_used with no call_start": [start_rows(OTHER, "3" * 16)[0]],
    "an approval_used followed by another row": [start_rows(OTHER, "3" * 16)[0], row_of("call_sent", call_id=CID)],
    "a call_start with no approval_used": [start_rows(OTHER, "3" * 16)[1]],
    "a call_start that disagrees with its approval_used": [
        start_rows(OTHER, "3" * 16)[0],
        {**start_rows(OTHER, "3" * 16)[1], "job": "other"},
    ],
}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_a_ledger_that_breaks_the_state_machine_is_refused(tmp_path: Path, name: str) -> None:
    ledger = new_ledger(tmp_path)
    ledger.ledger.append_many(start_rows(), ts=gemini.stamp(NOW))
    ledger.ledger.append_many(SCENARIOS[name])
    with pytest.raises(LedgerError):
        ledger.view()


def test_the_scenarios_start_from_a_valid_ledger(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    ledger.ledger.append_many(start_rows(), ts=gemini.stamp(NOW))
    assert ledger.view().calls[CID].state is CallState.RESERVED


# -- recovery and crash points -------------------------------------------------------------------------------------


def clone(src: Path, dst: Path) -> CallLedger:
    shutil.copytree(state_dir(src), state_dir(dst))
    return CallLedger(state_dir(dst))


def after_restart(ledger: CallLedger) -> CallLedger:
    fresh = CallLedger(ledger.dir)
    fresh.recover(NOW)
    return fresh


def test_recover_on_a_healthy_ledger_changes_nothing_and_is_repeatable(tmp_path: Path) -> None:
    ledger, path = seeded(tmp_path)
    before = path.read_bytes()
    assert ledger.recover(NOW) == []
    assert ledger.recover(NOW) == []
    assert path.read_bytes() == before


@pytest.mark.parametrize("point", FAULT_POINTS)
def test_a_kill_at_any_step_reads_back_as_settled_or_ambiguous_never_as_free_budget(tmp_path: Path, point: str) -> None:
    ledger = new_ledger(tmp_path, faults=CrashAt(point))
    req = flat_request(5000)
    appr = approval(req)
    ticket: Ticket | None = None
    with pytest.raises(Crash):
        ticket = ledger.reserve(req, appr, policy(), epoch=EPOCH, now=NOW)
        assert ticket
        ledger.mark_sent(ticket.call_id, NOW)
        ledger.settle(ticket.call_id, "ok", 4000, NOW)
    restarted = after_restart(ledger)
    view = restarted.view()
    if point == "before_append":  # nothing was written and nothing could have left
        assert view.calls == {} and view.month_spent(NOW) == 0
        restarted.reserve(req, appr, policy(), epoch=EPOCH, now=NOW)  # the approval is still good
        return
    (call,) = view.calls.values()
    assert call.state is CallState.SUSPENDED and call.ambiguous  # never reserved, sent or settled-free
    assert view.month_spent(NOW) == 5000  # the whole reservation stays counted
    assert FLAT in view.suspended
    assert restarted.marker_exists(appr.nonce)
    with pytest.raises(Refused) as err:
        restarted.reserve(req, appr, policy(), epoch=EPOCH, now=NOW)
    assert err.value.code == "used"
    other = flat_request(100)
    with pytest.raises(Refused) as err:
        restarted.reserve(other, approval(other), policy(), epoch=EPOCH, now=NOW)
    assert err.value.code == "model_suspended"
    assert restarted.recover(NOW) == []  # and recovery does it only once


def test_a_kill_after_the_send_record_and_before_the_answer_is_ambiguous(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path, faults=CrashAt("after_sent"))
    t, _, _ = reserve(ledger, 5000)
    with pytest.raises(Crash):
        ledger.mark_sent(t.call_id, NOW)
    view = after_restart(ledger).view()
    assert view.calls[t.call_id].ambiguous and view.month_spent(NOW) == 5000


def test_a_kill_between_the_ledger_and_the_head_file_loses_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = new_ledger(tmp_path)
    req = flat_request(5000)
    appr = approval(req)

    def killed(*args: Any, **kwargs: Any) -> None:
        raise Crash("head file")

    monkeypatch.setattr(gemini, "write_text", killed)
    with pytest.raises(Crash):
        ledger.reserve(req, appr, policy(), epoch=EPOCH, now=NOW)
    monkeypatch.undo()
    restarted = after_restart(ledger)
    assert restarted.view().month_spent(NOW) == 5000
    assert restarted.marker_exists(appr.nonce)


def test_a_marker_cut_short_is_rewritten_from_the_ledger(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path, faults=CrashAt("after_append"))
    req = flat_request(5000)
    appr = approval(req)
    with pytest.raises(Crash):
        ledger.reserve(req, appr, policy(), epoch=EPOCH, now=NOW)
    marker = state_dir(tmp_path) / "used" / appr.nonce
    marker.parent.mkdir(mode=0o700, exist_ok=True)
    marker.write_bytes(b'{"v": 3, "ts"')  # the create happened, the write was cut
    os.chmod(marker, 0o600)
    restarted = after_restart(ledger)
    assert json.loads(marker.read_text())["nonce"] == appr.nonce
    assert restarted.view().month_spent(NOW) == 5000


def test_a_marker_with_no_ledger_row_and_no_readable_content_stops_recovery(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    folder = state_dir(tmp_path) / "used"
    folder.mkdir(mode=0o700, exist_ok=True)
    (folder / ("e" * 16)).write_bytes(b"{")
    os.chmod(folder / ("e" * 16), 0o600)
    with pytest.raises(LedgerError):
        ledger.recover(NOW)


def test_a_marker_with_no_ledger_row_is_charged_as_an_ambiguous_call(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t, appr, _ = reserve(ledger, 5000)
    folder = state_dir(tmp_path)
    for name in ("ledger.jsonl", "ledger.jsonl.head", "height"):  # the ledger was rolled back; the marker survived
        (folder / name).unlink()
    assert ledger.recover(NOW) == [t.call_id]
    view = ledger.view()
    assert view.month_spent(NOW) == 5000 and FLAT in view.suspended and appr.nonce in view.spent_nonces
    assert ledger.view().calls[t.call_id].ambiguous


def test_recovery_after_a_backward_clock_still_runs(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t, _, _ = reserve(ledger, 5000, now=LATER)
    ledger.mark_sent(t.call_id, LATER)
    assert CallLedger(ledger.dir).recover(NOW) == [t.call_id]


def build_for_cuts(tmp_path: Path, stage: str) -> tuple[Path, bytes, bytes, dict[str, bytes], CallLedger]:
    """The state directory just before one multi-row append, the ledger bytes before and after it, and the head and
    height records as they were before (a crash during the write has not reached them)."""
    base = tmp_path / "base"
    ledger = new_ledger(base)
    req = flat_request(5000)
    appr = approval(req)
    if stage == "reserve":
        pre_files = {n: (state_dir(base) / n).read_bytes() for n in ("ledger.jsonl",) if (state_dir(base) / n).exists()}
        pre = b""
        ledger.reserve(req, appr, policy(), epoch=EPOCH, now=NOW)
    else:
        t = ledger.reserve(req, appr, policy(), epoch=EPOCH, now=NOW)
        ledger.mark_sent(t.call_id, NOW)
        pre_files = {n: (state_dir(base) / n).read_bytes() for n in ("ledger.jsonl", "ledger.jsonl.head", "height")}
        pre = pre_files["ledger.jsonl"]
        if stage == "breach":
            ledger.settle(t.call_id, "ok", 9000, NOW)
        else:
            ledger.mark_ambiguous(t.call_id, "timeout", NOW)
    post = (state_dir(base) / "ledger.jsonl").read_bytes()
    return base, pre, post, pre_files, ledger


@pytest.mark.parametrize("stage", ["reserve", "breach", "ambiguous"])
def test_a_write_cut_at_every_byte_recovers_to_a_state_that_is_never_free_budget(tmp_path: Path, stage: str) -> None:
    base, pre, post, pre_files, _ = build_for_cuts(tmp_path, stage)
    complete_at = len(post) - 1  # the final newline alone may be missing: the row is whole and is kept
    edges = {i + d for i, byte in enumerate(post) if byte == 0x0A for d in (-2, -1, 0, 1, 2)}
    cuts = sorted(
        {c for c in range(len(pre), len(post) + 1, 7)} | {c for c in range(len(post) - 80, len(post) + 1)} | edges
    )
    cuts = [c for c in cuts if len(pre) <= c <= len(post)]
    checked = 0
    for cut in cuts:
        work = tmp_path / f"cut-{cut}"
        shutil.copytree(state_dir(base), state_dir(work))
        folder = state_dir(work)
        (folder / "ledger.jsonl").write_bytes(post[:cut])
        for name, content in pre_files.items():  # head and height are written after the ledger is on disk
            if name != "ledger.jsonl":
                (folder / name).write_bytes(content)
        if stage == "reserve":
            for leftover in (folder / "used").glob("*"):
                leftover.unlink()  # the marker comes after the append
            for name in ("ledger.jsonl.head", "height"):
                (folder / name).unlink(missing_ok=True)
        restarted = CallLedger(folder)
        restarted.recover(NOW)
        view = restarted.view()
        checked += 1
        if stage == "reserve":
            if cut >= complete_at:
                (call,) = view.calls.values()
                assert call.ambiguous and view.month_spent(NOW) == 5000
            else:  # the group never completed: nothing was recorded, nothing could have been sent
                assert view.calls == {} and view.month_spent(NOW) == 0
                assert not view.spent_nonces
        else:
            (call,) = view.calls.values()
            assert call.state is CallState.SUSPENDED
            assert view.month_spent(NOW) >= 5000  # the reservation never drops out
            end_row_at = len(post) - len(post.splitlines(keepends=True)[-1])
            if stage == "breach" and cut >= end_row_at - 1:  # the breach row is whole: its cost stays counted
                assert not call.ambiguous and view.month_spent(NOW) == 9000
            else:
                assert call.ambiguous and view.month_spent(NOW) == 5000
        shutil.rmtree(work)
    assert checked > 40  # the loop really ran over the appended region, including every row boundary


# -- two reservers on one ledger ------------------------------------------------------------------------------------


def test_two_threads_cannot_both_take_the_last_room(tmp_path: Path) -> None:
    new_ledger(tmp_path)
    start = threading.Barrier(8)
    outcomes: list[str] = []

    def worker(n: int) -> str:
        ledger = CallLedger(state_dir(tmp_path))
        req = flat_request(3000)
        appr = approval(req)
        start.wait()
        try:
            ledger.reserve(req, appr, policy(SMALL), epoch=EPOCH, now=NOW)
        except Refused as err:
            return err.code
        return "ok"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(worker, range(8)))
    assert sorted(outcomes) == ["needs_block_approval"] * 5 + ["ok"] * 3  # 3 x 3000 fit in 10000; a fourth does not
    view = CallLedger(state_dir(tmp_path)).view()
    assert view.month_spent(NOW) == 9000 and len(view.calls) == 3
    assert len(rows(tmp_path)) == 1 + 3 * 2  # chain_start, then two rows per accepted call, no torn or doubled row


def test_one_approval_raced_by_many_threads_spends_once(tmp_path: Path) -> None:
    new_ledger(tmp_path)
    req = flat_request(1000)
    appr = approval(req)
    start = threading.Barrier(8)

    def worker(n: int) -> str:
        start.wait()
        try:
            CallLedger(state_dir(tmp_path)).reserve(req, appr, policy(), epoch=EPOCH, now=NOW)
        except Refused as err:
            return err.code
        return "ok"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(worker, range(8)))
    assert sorted(outcomes) == ["ok"] + ["used"] * 7
    assert CallLedger(state_dir(tmp_path)).view().month_spent(NOW) == 1000


def test_two_processes_cannot_both_take_the_last_room(tmp_path: Path) -> None:
    new_ledger(tmp_path)
    jobs = [(str(state_dir(tmp_path)), "1" * 16, 6000, FLAT), (str(state_dir(tmp_path)), "2" * 16, 6000, FLAT)]
    with ProcessPoolExecutor(max_workers=2, mp_context=get_context("spawn")) as pool:
        outcomes = list(pool.map(reserve_worker, jobs))
    assert sorted(outcomes) == ["needs_block_approval", "ok"]
    assert CallLedger(state_dir(tmp_path)).view().month_spent(NOW) == 6000


def test_the_lock_is_released_after_a_refusal_and_after_a_crash(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path, faults=CrashAt("after_append"), lock_seconds=1.0)
    req = flat_request(1000)
    with pytest.raises(Crash):
        ledger.reserve(req, approval(req), policy(), epoch=EPOCH, now=NOW)
    assert after_restart(ledger).view()
    with pytest.raises(Refused):
        reserve(CallLedger(ledger.dir), 100)  # suspended, but the lock was free to find that out


# -- the signed ledger head, and a marker that disagrees with the ledger -------------------------------------------


def test_a_signed_ledger_head_must_be_one_the_ledger_had(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    req = flat_request(1000)
    ledger.reserve(req, approval(req), policy(), epoch=EPOCH, now=NOW)  # the genesis sentinel: the chain start
    head = ledger.view().head
    req2 = flat_request(1000)
    ledger.reserve(req2, approval(req2, ledger_head=head), policy(), epoch=EPOCH, now=NOW)  # a real, older head
    for bad in ("f" * 64, "1" * 64, "", head[:-1] + ("0" if head[-1] != "0" else "1")):
        req3 = flat_request(1000)
        before = (state_dir(tmp_path) / "ledger.jsonl").read_bytes()
        with pytest.raises(Refused) as err:
            ledger.reserve(req3, approval(req3, ledger_head=bad), policy(), epoch=EPOCH, now=NOW)
        assert err.value.code == "bad_approval"
        assert (state_dir(tmp_path) / "ledger.jsonl").read_bytes() == before


def test_a_marker_that_disagrees_with_the_ledger_stops_recovery(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    t, appr, _ = reserve(ledger, 5000)
    marker = state_dir(tmp_path) / "used" / appr.nonce
    data = json.loads(marker.read_text())
    for field, value in (("reserved_micro", 1), ("model", "gemini-3.6-flash"), ("job", "other"), ("call_id", "e" * 32)):
        marker.write_text(json.dumps({**data, field: value}))
        with pytest.raises(LedgerError):
            ledger.recover(NOW)
    marker.write_text(json.dumps(data))
    assert ledger.recover(NOW) == [t.call_id]  # the call was still reserved, so recovery makes it ambiguous


def test_a_marker_only_recovery_never_moves_a_charge_into_another_month(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    october = dt.datetime(2026, 10, 31, 23, 0, tzinfo=dt.UTC)
    reserve(
        ledger,
        5000,
        now=october,
        created=october - dt.timedelta(minutes=1),
        expires_at=october + dt.timedelta(minutes=9),
    )
    for name in ("ledger.jsonl", "ledger.jsonl.head", "height"):
        (state_dir(tmp_path) / name).unlink()
    november = dt.datetime(2026, 11, 1, 0, 5, tzinfo=dt.UTC)
    with pytest.raises(LedgerError):
        ledger.recover(november)
    assert not (state_dir(tmp_path) / "ledger.jsonl").exists()
    ledger.recover(october + dt.timedelta(minutes=30))  # the same month rebuilds it
    assert ledger.view().month_spent(october) == 5000
