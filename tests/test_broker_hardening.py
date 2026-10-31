# SPDX-License-Identifier: Apache-2.0
"""Findings from a whole-build review of the broker, each with a test that fails without its fix: the approval must come
from a touched hardware key; the issued record binds every cost-relevant field the signer states; a model whose output
cap is unverified is refused when its worst case is over 2 USD, whatever the job cap is; a temporary file left by a kill
in the issued folder cannot stop `begin` or the start-up flush."""

from __future__ import annotations

import dataclasses
import inspect
import os
from pathlib import Path
from typing import Any

import pytest

from brokerdata import EPOCH, NOW, Crash, CrashAt, approval, flat_request, policy, prices_data
from geminidata import make_key
from pipedata import IMAGE_MODEL, Rig, image_req, text_req
from safo import geminisign
from safo.broker import policy as policy_module
from safo.broker.approval import verify_approval
from safo.broker.errors import LedgerError, Refused
from safo.broker.issue import MAX_OUTSTANDING, Issuer
from safo.broker.pipeline import Pipeline
from safo.broker.policy import UNVERIFIED_LIMIT_MICRO, Caps, Policy
from safo.broker.prices import parse_prices
from safo.geminisign import Trust

NB2 = "gemini-3.1-flash-image"


@pytest.fixture(scope="module")
def key(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_key(tmp_path_factory.mktemp("keys") / "a")


@pytest.fixture
def rig(tmp_path: Path, key: Path) -> Rig:
    return Rig(tmp_path, key)


def code_of(call: Any) -> str:
    with pytest.raises(Refused) as err:
        call()
    return err.value.code


# -- M1: hardware only ---------------------------------------------------------------------------------------------


def opted_in_software(rig: Rig) -> Trust:
    """Root enrolled the key with the written software opt-in, and the broker uses the strict production trust."""
    rig.signers.write_text(rig.signers.read_text() + "# safo: yubikey-a allow-software\n")
    rig.signers.chmod(0o644)
    return Trust(rig.signers, rig.revoked, os.geteuid(), True, True)


def test_a_software_key_with_the_written_opt_in_cannot_approve_a_paid_call(rig: Rig) -> None:
    req = text_req()
    text = rig.text(req, rig.offer(req))
    trust = opted_in_software(rig)
    assert geminisign.verify(trust, text.encode(), rig.sign(text), now=NOW).hardware is False  # the opt-in works here
    assert code_of(lambda: verify_approval(text, rig.sign(text), trust, now=NOW)) == "bad_approval"


def test_the_pipeline_refuses_a_software_key_before_anything_is_spent(rig: Rig) -> None:
    rig.trust = opted_in_software(rig)
    rig.verifier = geminisign.verify  # the production verifier, no stand-in
    rig.build()
    with pytest.raises(Refused) as err:
        rig.run(text_req())
    assert err.value.code == "bad_approval" and rig.ledger.view().calls == {} and rig.vendor.requests == []


@pytest.mark.parametrize(("hardware", "present"), [(False, True), (True, False), (True, None), (False, None)])
def test_a_key_must_be_hardware_and_show_a_touch(rig: Rig, hardware: bool, present: bool | None) -> None:
    req = text_req()
    text = rig.text(req, rig.offer(req))

    def fake(trust: Trust, payload: bytes, armor: str, *, namespace: str, now: Any) -> geminisign.Verified:
        who = geminisign.verify(trust, payload, armor, namespace=namespace, now=now)
        return dataclasses.replace(who, hardware=hardware, user_present=present)

    assert code_of(lambda: verify_approval(text, rig.sign(text), rig.trust, now=NOW, verifier=fake)) == "bad_approval"


def test_a_hardware_key_with_a_touch_passes(rig: Rig) -> None:
    req = text_req()
    text = rig.text(req, rig.offer(req))
    assert verify_approval(text, rig.sign(text), rig.trust, now=NOW, verifier=rig.verifier).principal == "yubikey-a"


def test_there_is_no_software_opt_in_in_the_broker_path() -> None:
    for fn in (verify_approval, Pipeline.__init__):
        names = set(inspect.signature(fn).parameters)
        assert not names & {"allow_software", "require_hardware", "software"}
    assert inspect.signature(verify_approval).parameters["verifier"].default is geminisign.verify


# -- M2: the issued record binds what the signer states ------------------------------------------------------------


def check_code(rig: Rig, req: Any, **over: Any) -> str:
    offer = rig.offer(req)
    text = rig.text(req, offer, **over)
    return code_of(lambda: rig.pipeline.call(req, text, rig.sign(text)))


def test_the_offer_states_the_maximum_that_was_agreed(rig: Rig) -> None:
    assert rig.offer(text_req(), max_micro=300_000).max_micro == 300_000


@pytest.mark.parametrize("signed", ["2.5", "0.300001", "0.299999", "1"])
def test_a_signed_maximum_that_differs_from_the_one_agreed_at_begin_is_refused(rig: Rig, signed: str) -> None:
    req = text_req()
    offer = rig.issuer.begin(req, prompt_bytes=len(req.prompt), max_micro=300_000, now=NOW)
    text = rig.text(req, offer, max_usd=signed)
    assert code_of(lambda: rig.pipeline.call(req, text, rig.sign(text))) == "bad_approval"
    assert rig.ledger.view().calls == {}


def test_the_agreed_maximum_passes(rig: Rig) -> None:
    req = text_req()
    offer = rig.issuer.begin(req, prompt_bytes=len(req.prompt), max_micro=300_000, now=NOW)
    text = rig.text(req, offer)
    assert rig.pipeline.call(req, text, rig.sign(text)).code == "ok"


def test_a_client_cannot_sign_beyond_ceiling_to_skip_the_monthly_ceiling(rig: Rig) -> None:
    rig.policy = policy(Caps(job_micro=2_500_000, month_micro=3_000_000))
    rig.build()
    first = flat_request(2_000_000)
    rig.ledger.reserve(first, approval(first), rig.policy, epoch=EPOCH, now=NOW)  # the month is nearly spent
    small = text_req(max_output_tokens=10)  # fits in the room that is left, so begin says beyond_ceiling false
    assert rig.offer(small).beyond_ceiling is False
    assert check_code(rig, small, beyond_ceiling=True) == "bad_approval"


def test_beyond_ceiling_must_be_signed_when_begin_said_so_and_only_then(rig: Rig) -> None:
    rig.policy = policy(Caps(job_micro=2_500_000, month_micro=3_000_000))
    rig.build()
    first = flat_request(2_000_000)
    rig.ledger.reserve(first, approval(first), rig.policy, epoch=EPOCH, now=NOW)
    big = text_req(max_output_tokens=200_000)  # 2.000087 USD more: over the ceiling
    assert rig.offer(big).beyond_ceiling is True
    # the signer cannot leave out what begin said: the ceiling check or the issue check stops it, nothing is spent
    assert check_code(rig, big, beyond_ceiling=False) in ("bad_approval", "needs_block_approval")
    offer = rig.offer(big)
    text = rig.text(big, offer)
    assert rig.pipeline.call(big, text, rig.sign(text)).code == "ok"  # signed as begin said: allowed (the extra block)


def test_the_ledger_head_must_be_the_one_begin_gave(rig: Rig) -> None:
    req = flat_request(1000)
    rig.ledger.reserve(req, approval(req), rig.policy, epoch=EPOCH, now=NOW)
    head = rig.ledger.view().head
    other = text_req(prompt="another prompt")
    offer = rig.offer(other)
    assert offer.ledger_head == head
    text = rig.text(other, offer, ledger_head="0" * 64)  # the chain start is accepted by the ledger, not by the issue
    assert code_of(lambda: rig.pipeline.call(other, text, rig.sign(text))) == "bad_approval"


def test_an_approval_made_before_the_nonce_was_issued_is_refused(rig: Rig) -> None:
    req = text_req()
    offer = rig.offer(req)
    from safo import gemini

    old = gemini.stamp(NOW.replace(hour=11, minute=30))
    text = rig.text(req, offer, created=old, quoted_at=old)
    assert code_of(lambda: rig.pipeline.call(req, text, rig.sign(text))) == "bad_approval"


def test_the_issued_record_holds_the_fields_it_is_compared_with(rig: Rig) -> None:
    import json

    offer = rig.offer(text_req(), max_micro=400_000)
    data = json.loads((rig.ledger.dir / "issued" / offer.nonce).read_text())
    assert data["max_micro"] == 400_000 and data["beyond_ceiling"] is False and data["ledger_head"] == "0" * 64


# -- M3: decision 13 does not depend on the job cap ----------------------------------------------------------------


def with_job_cap(monkeypatch: pytest.MonkeyPatch, job_micro: int) -> Policy:
    monkeypatch.setattr(policy_module, "JOB_CAP_MICRO", max(job_micro, 2_500_000))
    return Policy(parse_prices(prices_data()), Caps(job_micro=job_micro))


@pytest.mark.parametrize("job_micro", [2_000_000, 2_500_000, 5_000_000])
def test_nano_banana_2_stays_refused_until_its_cap_is_verified_at_any_job_cap(
    monkeypatch: pytest.MonkeyPatch, job_micro: int
) -> None:
    pol = with_job_cap(monkeypatch, job_micro)
    req = policy_module.canonical_broker_request(
        policy_module.BrokerRequest(NB2, "image", "job-one", "a prompt", 4096, "minimal", 1, "1K", "1:1")
    )
    with pytest.raises(Refused) as err:
        pol.price(req, NOW)
    assert err.value.code == "model_refused"


@pytest.mark.parametrize("job_micro", [2_000_000, 2_500_000, 5_000_000])
def test_nano_banana_2_is_allowed_once_its_cap_is_verified(monkeypatch: pytest.MonkeyPatch, job_micro: int) -> None:
    data = prices_data()
    data["models"][NB2]["cap_verified"] = True
    monkeypatch.setattr(policy_module, "JOB_CAP_MICRO", max(job_micro, 2_500_000))
    pol = Policy(parse_prices(data), Caps(job_micro=job_micro))
    req = policy_module.canonical_broker_request(
        policy_module.BrokerRequest(NB2, "image", "job-one", "a prompt", 4096, "minimal", 1, "1K", "1:1")
    )
    assert pol.price(req, NOW).reservation.total_micro < UNVERIFIED_LIMIT_MICRO


def test_the_limit_is_two_dollars_exactly_and_a_micro_dollar_over_is_refused() -> None:
    assert UNVERIFIED_LIMIT_MICRO == 2_000_000
    data = prices_data()
    data["models"]["unverified-edge"] = {
        "kind": "text",
        "valid_through": "2026-12-31",
        "input_per_mtok": "1",
        "text_output_per_mtok": "1",
        "output_token_limit": 1_999_936,
        "cap_verified": False,
    }
    pol = Policy(parse_prices(data), Caps())
    edge = policy_module.canonical_broker_request(
        policy_module.BrokerRequest("unverified-edge", "text", "job-one", "", 1, "none")
    )
    assert pol.price(edge, NOW).reservation.total_micro == 2_000_000  # 64 input tokens plus 1,999,936 output tokens
    data["models"]["unverified-edge"]["output_token_limit"] = 1_999_937
    over = Policy(parse_prices(data), Caps())
    with pytest.raises(Refused) as err:
        over.price(edge, NOW)
    assert err.value.code == "model_refused"


def test_begin_refuses_such_a_model_too_and_the_other_listed_models_are_unaffected(rig: Rig) -> None:
    nb2 = image_req(model=NB2)
    assert code_of(lambda: rig.offer(nb2)) == "model_refused"
    assert rig.offer(image_req()).nonce and rig.offer(text_req()).nonce
    assert IMAGE_MODEL != NB2


# -- M7: a leftover temporary file in issued/ ------------------------------------------------------------------------

TEMP = "." + "ab" * 16 + ".k3j2h1x9"


def plant(rig: Rig, name: str = TEMP) -> Path:
    folder = rig.ledger.dir / "issued"
    folder.mkdir(mode=0o700, exist_ok=True)
    path = folder / name
    path.write_text('{"half":')
    return path


def test_begin_works_and_clears_a_temporary_file_left_by_a_kill(rig: Rig) -> None:
    leftover = plant(rig)
    assert rig.offer(text_req()).nonce
    assert not leftover.exists()


def test_the_start_up_flush_works_and_clears_a_temporary_file_left_by_a_kill(rig: Rig) -> None:
    offers = [rig.offer(text_req()) for _ in range(2)]
    leftover = plant(rig)
    assert rig.issuer.flush() == 2
    assert not leftover.exists() and os.listdir(rig.ledger.dir / "issued") == []
    assert all(rig.issuer.state(o.nonce, NOW) == "unknown" for o in offers)


def test_restart_recovery_runs_with_a_temporary_file_present(rig: Rig) -> None:
    plant(rig)
    rig.restart()
    rig.issuer.flush()
    assert rig.offer(text_req()).nonce


def test_a_temporary_file_does_not_count_against_the_four_outstanding(rig: Rig) -> None:
    for i in range(MAX_OUTSTANDING):
        plant(rig, "." + f"{i:02x}" * 16 + ".abcd1234")
    for _ in range(MAX_OUTSTANDING):
        rig.offer(text_req())
    assert code_of(lambda: rig.offer(text_req())) == "busy"


@pytest.mark.parametrize(
    "name",
    [
        "README",
        ".hidden",
        "." + "ab" * 16,
        "." + "ab" * 16 + ".",
        "ab" * 16 + ".tmp",
        ".ab.cd",
    ],
)
def test_a_file_that_is_not_a_nonce_or_one_of_our_temporary_names_still_stops_the_table(rig: Rig, name: str) -> None:
    plant(rig, name)
    with pytest.raises(LedgerError):
        rig.issuer.flush()
    with pytest.raises(LedgerError):
        rig.offer(text_req())


def test_a_symlink_with_a_temporary_name_is_not_followed(rig: Rig, tmp_path: Path) -> None:
    target = tmp_path / "precious"
    target.write_text("keep")
    folder = rig.ledger.dir / "issued"
    folder.mkdir(mode=0o700, exist_ok=True)
    os.symlink(target, folder / TEMP)
    rig.issuer.flush()
    assert target.read_text() == "keep" and not (folder / TEMP).exists()


@pytest.mark.parametrize("point", ["issued_before_replace", "issued_after_write"])
def test_a_kill_while_an_issued_record_is_written_leaves_a_table_that_still_works(
    tmp_path: Path, key: Path, point: str
) -> None:
    rig = Rig(tmp_path, key)
    rig.issuer.faults = CrashAt(point)
    with pytest.raises(Crash):
        rig.offer(text_req())
    # a SIGKILL leaves the temporary file (the in-process kill above runs the cleanup): put it back
    plant(rig)
    rig.issuer.faults = lambda point: None
    assert rig.offer(text_req()).nonce
    assert rig.issuer.flush() >= 1
    assert os.listdir(rig.ledger.dir / "issued") == []
    assert isinstance(rig.issuer, Issuer)
