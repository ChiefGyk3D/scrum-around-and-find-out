# SPDX-License-Identifier: Apache-2.0
"""`begin`: the nonce the broker hands out, the numbers it quotes, and the checks a call makes against it."""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from brokerdata import EPOCH, FLAT, NOW, approval, flat_request, policy
from geminidata import make_key
from pipedata import IMAGE_MODEL, Rig, image_req, text_req
from safo.broker.errors import LedgerError, Refused
from safo.broker.issue import DEFAULT_TTL, MAX_OUTSTANDING, Issuer
from safo.broker.policy import Caps


@pytest.fixture(scope="module")
def key(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_key(tmp_path_factory.mktemp("keys") / "a")


@pytest.fixture
def rig(tmp_path: Path, key: Path) -> Rig:
    return Rig(tmp_path, key)


def code_of(rig: Rig, req: Any, **kw: Any) -> str:
    kw.setdefault("max_micro", 2_500_000)
    kw.setdefault("prompt_bytes", 10)
    with pytest.raises(Refused) as err:
        rig.issuer.begin(req, now=rig.clock.wall(), **kw)
    return err.value.code


def test_begin_hands_out_a_nonce_and_the_numbers_an_approval_must_carry(rig: Rig) -> None:
    req = text_req()
    offer = rig.offer(req)
    assert len(offer.nonce) == 32 and offer.epoch == EPOCH
    assert offer.expires_at == NOW + DEFAULT_TTL and offer.ledger_head == "0" * 64
    assert offer.reserve_micro == (len(req.prompt) + 64) + 500 * 10  # input at 1 per token, output at 10 per token
    assert offer.thinking_level == "none" and offer.beyond_ceiling is False and offer.estimate_micro > 0


def test_nonces_are_unpredictable_and_distinct(rig: Rig) -> None:
    seen = {rig.offer(text_req()).nonce for _ in range(MAX_OUTSTANDING)}
    assert len(seen) == MAX_OUTSTANDING


def test_the_issued_file_is_private_and_holds_no_prompt(rig: Rig) -> None:
    req = text_req(prompt="SENTINEL-PROMPT-TEXT")
    offer = rig.offer(req)
    path = rig.ledger.dir / "issued" / offer.nonce
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600 and stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    data = json.loads(path.read_text())
    assert "SENTINEL" not in path.read_text() and data["prompt_bytes"] == len(req.prompt)
    assert data["expires_at"] == "2026-10-30T12:10:00Z" and data["model"] == FLAT


def test_begin_never_reads_the_prompt_text_it_is_given(rig: Rig) -> None:
    short = dataclasses.replace(text_req(), prompt="")
    long = text_req(prompt="x" * 5000)
    a = rig.issuer.begin(short, prompt_bytes=77, max_micro=2_500_000, now=rig.clock.wall())
    b = rig.issuer.begin(long, prompt_bytes=77, max_micro=2_500_000, now=rig.clock.wall())
    assert a.reserve_micro == b.reserve_micro


def test_only_four_nonces_are_outstanding_and_an_expired_one_frees_its_place(rig: Rig) -> None:
    for _ in range(MAX_OUTSTANDING):
        rig.offer(text_req())
    assert code_of(rig, text_req()) == "busy"
    rig.clock.at += DEFAULT_TTL  # exactly at expiry the old nonces are gone
    assert rig.offer(text_req()).nonce
    assert len(os.listdir(rig.ledger.dir / "issued")) == 1


@pytest.mark.parametrize(
    ("req", "kw", "code"),
    [
        (text_req(model="no-such-model"), {}, "model_refused"),
        (text_req(model="gemini-3.5-pro"), {}, "model_refused"),
        (text_req(model="stale-test", thinking_level="none"), {}, "prices_expired"),
        (text_req(thinking_level="high"), {}, "bad_request"),
        (text_req(kind="video"), {}, "bad_request"),
        (text_req(count=1), {}, "bad_request"),
        (text_req(max_output_tokens=0), {}, "bad_request"),
        (text_req(), {"prompt_bytes": 200_001}, "bad_request"),
        (text_req(), {"prompt_bytes": -1}, "bad_request"),
        (text_req(), {"max_micro": 1}, "over_approved"),
        (text_req(), {"max_micro": 0}, "bad_request"),
        (text_req(), {"max_micro": True}, "bad_request"),
        (text_req(max_output_tokens=400_000), {"prompt_bytes": 10}, "over_job_cap"),
        (image_req(count=2), {}, "bad_request"),
        (image_req(image_size="8K"), {}, "bad_request"),
        (image_req(max_output_tokens=100), {}, "bad_request"),
        (image_req(thinking_level="high"), {}, "bad_request"),
        (text_req(job="has space"), {}, "bad_request"),
    ],
)
def test_a_request_the_broker_would_refuse_is_refused_at_begin(
    rig: Rig, req: Any, kw: dict[str, Any], code: str
) -> None:
    assert code_of(rig, req, **kw) == code
    assert not os.path.exists(rig.ledger.dir / "issued") or os.listdir(rig.ledger.dir / "issued") == []


def test_an_image_offer_quotes_the_worst_case_with_the_interim_images(rig: Rig) -> None:
    offer = rig.offer(image_req())
    assert offer.thinking_level == "minimal" and 1_000_000 < offer.reserve_micro < 1_100_000
    assert 30_000 < offer.estimate_micro < 100_000


def test_a_suspended_model_gets_no_nonce(rig: Rig) -> None:
    req = flat_request(1000)
    ticket = rig.ledger.reserve(req, approval(req), rig.policy, epoch=EPOCH, now=NOW)
    rig.ledger.mark_ambiguous(ticket.call_id, "timeout", NOW)
    assert code_of(rig, text_req()) == "model_suspended"
    assert rig.offer(image_req()).nonce  # another model is not affected


def test_begin_says_when_a_call_would_pass_the_monthly_ceiling(rig: Rig) -> None:
    small = policy(Caps(job_micro=10_000, month_micro=10_000))
    rig.issuer = Issuer(rig.ledger, small, EPOCH)
    first = flat_request(6000)
    rig.ledger.reserve(first, approval(first), small, epoch=EPOCH, now=NOW)
    offer = rig.issuer.begin(text_req(max_output_tokens=500), prompt_bytes=10, max_micro=2_500_000, now=NOW)
    assert offer.beyond_ceiling is True and offer.reserve_micro == 74 + 5000
    tiny = rig.issuer.begin(text_req(max_output_tokens=10), prompt_bytes=10, max_micro=2_500_000, now=NOW)
    assert tiny.beyond_ceiling is False


def test_the_offer_carries_the_ledger_head_once_there_is_one(rig: Rig) -> None:
    req = flat_request(1000)
    rig.ledger.reserve(req, approval(req), rig.policy, epoch=EPOCH, now=NOW)
    assert rig.offer(text_req()).ledger_head == rig.ledger.view().head != "0" * 64


# -- the check a call makes ----------------------------------------------------------------------------------------


def parsed(rig: Rig, req: Any, offer: Any, **over: Any) -> Any:
    from safo.broker.records import parse_approval

    return parse_approval(rig.text(req, offer, **over))


def test_an_issued_unexpired_matching_nonce_passes(rig: Rig) -> None:
    req = text_req()
    offer = rig.offer(req)
    rig.issuer.check(parsed(rig, req, offer), now=rig.clock.wall())


def test_a_nonce_the_broker_never_issued_is_refused(rig: Rig) -> None:
    req = text_req()
    offer = rig.offer(req)
    forged = dataclasses.replace(offer, nonce="ab" * 16)
    with pytest.raises(Refused) as err:
        rig.issuer.check(parsed(rig, req, forged), now=rig.clock.wall())
    assert err.value.code == "bad_approval"


def test_an_expired_nonce_is_refused_at_the_instant_of_expiry(rig: Rig) -> None:
    req = text_req()
    offer = rig.offer(req)
    appr = parsed(rig, req, offer)
    rig.issuer.check(appr, now=offer.expires_at - dt.timedelta(seconds=1))
    with pytest.raises(Refused) as err:
        rig.issuer.check(appr, now=offer.expires_at)
    assert err.value.code == "expired"


@pytest.mark.parametrize(
    "over",
    [
        {"model": "stale-test"},
        {"job": "other-job"},
        {"max_output_tokens": 501},
        {"prompt_bytes": 9999},
        {"epoch": "cd" * 16},
        {"kind": "image", "count": 1, "image_size": "1K", "aspect_ratio": "1:1"},
    ],
)
def test_an_approval_that_differs_from_what_was_asked_for_at_begin_is_refused(rig: Rig, over: dict[str, Any]) -> None:
    req = text_req()
    offer = rig.offer(req)
    with pytest.raises(Refused) as err:
        rig.issuer.check(parsed(rig, req, offer, **over), now=rig.clock.wall())
    assert err.value.code == "bad_approval"


def test_every_image_field_is_compared(rig: Rig) -> None:
    req = image_req()
    offer = rig.offer(req)
    for over in ({"image_size": "2K"}, {"aspect_ratio": "16:9"}, {"count": 2}):
        with pytest.raises(Refused):
            rig.issuer.check(parsed(rig, req, offer, **over), now=rig.clock.wall())
    rig.issuer.check(parsed(rig, req, offer), now=rig.clock.wall())


def test_state_reports_live_used_expired_and_unknown(rig: Rig) -> None:
    offer = rig.offer(text_req())
    now = rig.clock.wall()
    assert rig.issuer.state(offer.nonce, now) == "live"
    assert rig.issuer.state(offer.nonce, offer.expires_at) == "expired"
    assert rig.issuer.state("ff" * 16, now) == "unknown" and rig.issuer.state("not hex", now) == "unknown"
    rig.issuer.consume(offer.nonce)
    assert rig.issuer.state(offer.nonce, now) == "unknown"


def test_a_spent_nonce_is_used_even_after_its_issued_file_is_gone(rig: Rig) -> None:
    req = flat_request(1000)
    appr = approval(req)
    rig.ledger.reserve(req, appr, rig.policy, epoch=EPOCH, now=NOW)
    assert rig.issuer.state(appr.nonce, NOW) == "used"


def test_a_restart_empties_the_table(rig: Rig) -> None:
    offers = [rig.offer(text_req()) for _ in range(3)]
    assert rig.issuer.flush() == 3
    assert rig.issuer.flush() == 0
    assert all(rig.issuer.state(o.nonce, rig.clock.wall()) == "unknown" for o in offers)


def test_consume_is_idempotent_and_removes_only_that_nonce(rig: Rig) -> None:
    a, b = rig.offer(text_req()), rig.offer(text_req())
    rig.issuer.consume(a.nonce)
    rig.issuer.consume(a.nonce)
    assert os.listdir(rig.ledger.dir / "issued") == [b.nonce]


def test_a_stray_or_damaged_file_in_the_issued_folder_stops_the_table(rig: Rig) -> None:
    offer = rig.offer(text_req())
    folder = rig.ledger.dir / "issued"
    (folder / "README").write_text("x")
    with pytest.raises(LedgerError):
        rig.offer(text_req())
    (folder / "README").unlink()
    path = folder / offer.nonce
    good = path.read_text()
    path.write_text(good.replace("expires_at", "expires_xx"))
    with pytest.raises(LedgerError):
        rig.issuer.state(offer.nonce, NOW)
    path.write_text("{")
    with pytest.raises(LedgerError):
        rig.issuer.state(offer.nonce, NOW)
    path.write_text(good.replace("2026-10-30T12:10:00Z", "tomorrow"))
    with pytest.raises(LedgerError):
        rig.issuer.state(offer.nonce, NOW)


def test_a_naive_time_is_refused(rig: Rig) -> None:
    with pytest.raises(Refused) as err:
        rig.issuer.begin(text_req(), prompt_bytes=5, max_micro=2_500_000, now=dt.datetime(2026, 10, 30, 12))
    assert err.value.code == "bad_request"
    assert IMAGE_MODEL in policy().prices.models
