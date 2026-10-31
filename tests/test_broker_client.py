# SPDX-License-Identifier: Apache-2.0
"""The broker client against a scripted fake broker: the approval screen, the signed text, every reply code, a lost or
spoofed reply, images, and what is never done (no retry, no free-tier fallback, no prompt in a diagnostic). No socket,
no thread, no clock that moves by itself, no network."""

from __future__ import annotations

import ast
import datetime as dt
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import pytest

import clientdata as d
from fakevendor import FakeClock
from geminidata import make_key
from safo import gemini, geminisign
from safo.broker import client, protocol
from safo.broker.records import parse_approval

CHARGED = "THE CALL MAY HAVE BEEN CHARGED"
CHARGE_CODES = ("rate_limited", "vendor_refused", "outcome_unknown", "internal")
TEXT_FLOW = ["terms", "connect", "confirm", "sign", "terms", "connect"]


@pytest.fixture(scope="module")
def key(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_key(tmp_path_factory.mktemp("clientkey") / "k")


@pytest.fixture
def rig(key: Path) -> d.Rig:
    return d.make_rig(key)


def call_request(rig: d.Rig) -> dict[str, Any]:
    return next(r for r in rig.broker.requests if r["op"] == "call")


# -- the happy path and what was signed --------------------------------------------------------------------------------


def test_a_text_call_runs_begin_then_one_call_and_prints_the_answer(rig: d.Rig) -> None:
    assert rig.run() == 0
    assert rig.broker.ops == ["begin", "call"]
    assert d.ANSWER in rig.out.getvalue()
    assert rig.err.getvalue() == ""
    assert "receipt: call " + d.CALL_ID in rig.out.getvalue()
    assert "tokens: 12 in, 7 out" in rig.out.getvalue()
    assert "month: 0.5 USD used after this call" in rig.out.getvalue()
    assert [c.closed for c in rig.broker.channels] == [True, True]


def test_the_steps_happen_in_the_designed_order(rig: d.Rig) -> None:
    rig.run()
    assert rig.events == TEXT_FLOW


def test_the_begin_request_asks_for_the_numbers_the_user_named(rig: d.Rig) -> None:
    rig.run()
    _, size = gemini.prompt_binding(d.PROMPT)
    assert rig.broker.requests[0] == {
        "v": 1,
        "op": "begin",
        "model": "flat-test",
        "job": "job-one",
        "kind": "text",
        "max_output_tokens": 500,
        "prompt_bytes": size,
        "max_usd": "0.5",
    }


def test_the_signed_text_is_the_text_sent_and_binds_the_broker_numbers(rig: d.Rig) -> None:
    rig.run()
    (payload,) = rig.signer.payloads
    sent = call_request(rig)["approval"]
    assert sent["payload"].encode("ascii") == payload
    assert sent["signature"].startswith("-----BEGIN SSH SIGNATURE-----")
    ap = parse_approval(payload.decode("ascii"))  # the broker's own strict parser accepts it
    digest, size = gemini.prompt_binding(d.PROMPT)
    assert (ap.nonce, ap.epoch, ap.ledger_head) == (d.NONCE, d.EPOCH, d.HEAD)
    assert (ap.prompt_sha256, ap.prompt_bytes) == (digest, size)
    assert (ap.model, ap.job, ap.kind) == ("flat-test", "job-one", "text")
    assert (ap.max_output_tokens, ap.thinking_level) == (500, "none")
    assert ap.max_micro == 500_000 and ap.beyond_ceiling is False
    assert ap.principal == d.PRINCIPAL and ap.quote == d.QUOTE
    assert ap.issue == "ChiefGyk3D/scrum-around-and-find-out#260"
    assert ap.created == FakeClock().wall()
    assert ap.created < ap.expires_at <= ap.created + dt.timedelta(minutes=10)
    assert call_request(rig)["prompt"] == d.PROMPT


def test_the_signature_is_made_in_the_approval_namespace(rig: d.Rig) -> None:
    rig.run()
    armor = call_request(rig)["approval"]["signature"]
    assert geminisign.parse_signature(armor).namespace == geminisign.NAMESPACE


def test_a_signature_in_another_namespace_is_never_sent(rig: d.Rig, key: Path) -> None:
    rig.signer.armor_override = geminisign.sign(str(key), b"x", geminisign.DRYRUN_NAMESPACE, {})
    assert rig.run() == 2
    assert rig.broker.ops == ["begin"]


def test_the_expiry_is_never_later_than_the_offers(rig: d.Rig) -> None:
    rig.broker.answer("begin", d.offer_reply(expires_at="2026-10-30T12:03:00Z"))
    rig.run()
    ap = parse_approval(rig.signer.payloads[0].decode())
    assert gemini.stamp(ap.expires_at) == "2026-10-30T12:03:00Z"


def test_an_offer_that_has_already_expired_is_not_signed(rig: d.Rig) -> None:
    rig.broker.answer("begin", d.offer_reply(expires_at="2026-10-30T12:00:00Z"))
    assert rig.run() == 2
    assert rig.signer.payloads == [] and rig.broker.ops == ["begin"]


def test_an_approval_that_ran_out_while_the_person_read_is_not_sent(rig: d.Rig) -> None:
    def slow(prompt: str) -> str:
        rig.clock.at += dt.timedelta(minutes=30)
        return "approve job-one"

    rig.deps.confirm = slow
    assert rig.run() == 2
    assert rig.broker.ops == ["begin"] and "expired" in rig.err.getvalue()


def test_an_image_call_signs_the_image_fields(rig: d.Rig) -> None:
    rig.broker.answer("begin", d.offer_reply(thinking_level="minimal"))
    rig.broker.answer("call", d.ok_call(text="", rcpt=d.image_receipt(), images=(d.PNG,)))
    assert rig.run(d.image_params()) == 0
    ap = parse_approval(rig.signer.payloads[0].decode())
    assert (ap.kind, ap.count, ap.image_size, ap.aspect_ratio) == ("image", 1, "1K", "1:1")
    assert ap.thinking_level == "minimal"
    begin = rig.broker.requests[0]
    assert (begin["count"], begin["image_size"], begin["aspect_ratio"]) == (1, "1K", "1:1")
    assert call_request(rig)["aspect_ratio"] == "1:1"


def test_a_beyond_the_ceiling_offer_is_signed_as_such_and_shown(rig: d.Rig) -> None:
    rig.broker.answer("begin", d.offer_reply(beyond_ceiling=True))
    rig.run()
    assert parse_approval(rig.signer.payloads[0].decode()).beyond_ceiling is True
    assert "PASSES the monthly ceiling" in rig.out.getvalue()
    quiet = d.make_rig(rig.signer.key)
    quiet.run()
    assert "PASSES the monthly ceiling" not in quiet.out.getvalue()


# -- the approval screen: what the person sees is what is signed -------------------------------------------------------


def test_every_signed_field_is_on_the_screen_before_the_confirmation(rig: d.Rig) -> None:
    rig.run()
    signed = json.loads(rig.signer.payloads[0])
    screen = rig.shown[0]
    assert set(signed) >= {
        "nonce",
        "epoch",
        "model",
        "kind",
        "max_usd",
        "job",
        "prompt_sha256",
        "ledger_head",
        "principal",
    }
    for name, value in signed.items():
        shown = value if isinstance(value, str) else json.dumps(value)
        assert f"  {name}: {shown}\n" in screen, name


def test_the_image_fields_are_on_the_screen_too(rig: d.Rig) -> None:
    rig.broker.answer("begin", d.offer_reply(thinking_level="minimal"))
    rig.broker.answer("call", d.ok_call(text="", rcpt=d.image_receipt(), images=(d.PNG,)))
    rig.run(d.image_params())
    screen = rig.shown[0]
    for line in ("  count: 1\n", "  image_size: 1K\n", "  aspect_ratio: 1:1\n", "  thinking_level: minimal\n"):
        assert line in screen


def test_the_screen_shows_the_cost_the_cap_and_the_digest(rig: d.Rig) -> None:
    rig.run()
    screen = rig.shown[0]
    digest, size = gemini.prompt_binding(d.PROMPT)
    assert (
        "cost: typical estimate 0.004 USD, worst case 0.012 USD (what the caps check), you approve up to 0.5 USD"
        in screen
    )
    assert "reserves 0.012 USD; 0.5 of 10 USD used this month" in screen
    assert f"prompt: {len(d.PROMPT)} characters, {size} bytes, SHA-256 {digest}" in screen
    assert f"quote of his message (2026-10-30T11:59:00Z): {d.QUOTE}" in screen
    assert "you are approving up to 0.5 USD on flat-test for job job-one" in screen


def test_the_whole_prompt_is_shown_line_by_line_and_escaped(rig: d.Rig) -> None:
    prompt = "first line\nsecond ünïcode\n\x1b[31mred\x1b[0m and a tab\there\nlast-line-marker"
    rig.broker.answer("call", d.ok_call(rcpt=d.receipt(prompt)))
    assert rig.run(d.text_params(prompt=prompt)) == 0
    screen = rig.shown[0]
    for number, row in enumerate(prompt.split("\n"), 1):
        assert f"{number:4d}| {row!a}" in screen
    assert "\x1b" not in screen and "\t" not in screen
    assert "the WHOLE prompt starts" in screen and "the prompt ends" in screen


def test_a_prompt_of_exactly_the_limit_is_shown_to_its_last_character(rig: d.Rig) -> None:
    prompt = ("x" * (gemini.MAX_APPROVED_PROMPT_CHARS - 9)) + "ENDMARK-1"
    assert len(prompt) == gemini.MAX_APPROVED_PROMPT_CHARS
    rig.broker.answer("call", d.ok_call(rcpt=d.receipt(prompt)))
    assert rig.run(d.text_params(prompt=prompt)) == 0
    assert "ENDMARK-1" in rig.shown[0]
    assert call_request(rig)["prompt"] == prompt


def test_a_prompt_over_the_limit_is_refused_before_the_broker_is_contacted(rig: d.Rig) -> None:
    assert rig.run(d.text_params(prompt="y" * (gemini.MAX_APPROVED_PROMPT_CHARS + 1))) == 2
    assert rig.broker.opened == 0 and rig.signer.payloads == []
    assert str(gemini.MAX_APPROVED_PROMPT_CHARS) in rig.err.getvalue()
    assert "y" * 50 not in rig.everything


@pytest.mark.parametrize("prompt", ["", "token: AIzaSyA1234567890abcdefghijklmnopqrstuv_12345", "bad \ud800 text"])
def test_an_empty_prompt_a_secret_shape_and_a_lone_surrogate_are_refused_unseen(rig: d.Rig, prompt: str) -> None:
    assert rig.run(d.text_params(prompt=prompt)) == 2
    assert rig.broker.opened == 0 and rig.signer.payloads == []


def test_a_private_term_hit_stops_everything(rig: d.Rig) -> None:
    def hit(text: str) -> None:
        raise gemini.RefusedError("the prompt matches a private term; nothing was sent")

    rig.deps.terms = hit
    assert rig.run() == 2
    assert rig.broker.opened == 0 and rig.signer.payloads == []


def test_a_private_term_that_appears_only_at_the_second_check_stops_the_send(rig: d.Rig) -> None:
    seen: list[str] = []

    def second(text: str) -> None:
        seen.append(text)
        if len(seen) == 2:
            raise gemini.RefusedError("the prompt matches a private term; nothing was sent")

    rig.deps.terms = second
    assert rig.run() == 2
    assert seen == [d.PROMPT, d.PROMPT] and rig.broker.ops == ["begin"]


@pytest.mark.parametrize("answer", ["", "yes", "approve other", "approve job-one now", "Approve job-one"])
def test_a_wrong_confirmation_signs_nothing_and_sends_nothing(key: Path, answer: str) -> None:
    r = d.make_rig(key, [answer])
    assert r.run() == 2
    assert r.signer.payloads == [] and r.broker.ops == ["begin"]


def test_the_confirmation_phrase_may_carry_surrounding_blanks(key: Path) -> None:
    r = d.make_rig(key, ["  approve job-one \n"])
    assert r.run() == 0


def test_the_confirmation_must_be_typed_by_a_person_at_a_terminal(rig: d.Rig) -> None:
    rig.deps.interactive = False
    assert rig.run() == 2
    assert rig.signer.payloads == [] and rig.broker.ops == []


# -- the signer --------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "failure", [gemini.RefusedError("SIGNER-DETAIL-1"), OSError("SIGNER-DETAIL-2"), ValueError("SIGNER-DETAIL-3")]
)
def test_a_signer_failure_or_cancelled_touch_sends_no_call(rig: d.Rig, failure: BaseException) -> None:
    rig.signer.fail = failure
    assert rig.run() == 2
    assert rig.broker.ops == ["begin"] and rig.broker.opened == 1
    assert "nothing was sent" in rig.err.getvalue()
    assert "SIGNER-DETAIL" not in rig.err.getvalue()


@pytest.mark.parametrize("armor", ["", "not a signature", "-----BEGIN SSH SIGNATURE-----\n" + "A" * 5000])
def test_a_signature_that_is_not_ascii_armor_is_never_sent(key: Path, armor: str) -> None:
    r = d.make_rig(key)
    r.signer.armor_override = armor
    assert r.run() == 2
    assert r.broker.ops == ["begin"]


# -- the offer is checked before anything is signed --------------------------------------------------------------------


@pytest.mark.parametrize(
    "over",
    [
        {"nonce": "XYZ"},
        {"nonce": 5},
        {"epoch": "no"},
        {"ledger_head": "ab"},
        {"expires_at": "tomorrow"},
        {"estimate_usd": "-1"},
        {"reserve_usd": "0.6"},  # over the 0.5 the person named
        {"reserve_usd": "x"},
        {"thinking_level": ""},
        {"thinking_level": "\x1b[0m"},
        {"beyond_ceiling": "false"},
        {"beyond_ceiling": 1},
    ],
)
def test_a_bad_offer_is_never_signed(rig: d.Rig, over: dict[str, Any]) -> None:
    rig.broker.answer("begin", d.offer_reply(**over))
    assert rig.run() == 2
    assert rig.signer.payloads == [] and rig.broker.ops == ["begin"]


def test_an_offer_missing_a_field_is_never_signed(rig: d.Rig) -> None:
    body = protocol.ok_body({"nonce": d.NONCE, "epoch": d.EPOCH})
    rig.broker.answer("begin", [d.reply_frame(body)])
    assert rig.run() == 2 and rig.signer.payloads == []


def test_an_unsafe_offer_line_is_not_shown(rig: d.Rig) -> None:
    rig.broker.answer("begin", d.offer_reply(line="\x1b]0;owned\x07 reserves"))
    rig.run()
    assert "\x1b" not in rig.out.getvalue() and "owned" not in rig.out.getvalue()


def test_a_begin_refusal_is_reported_and_nothing_is_signed(rig: d.Rig) -> None:
    rig.broker.answer("begin", d.err("disabled"))
    assert rig.run() == 2
    assert "disabled: " + protocol.REPLY_CODES["disabled"][1] in rig.err.getvalue()
    assert rig.signer.payloads == [] and rig.broker.ops == ["begin"]
    assert "free tier" in rig.err.getvalue()


@pytest.mark.parametrize("code", sorted(protocol.REPLY_CODES))
def test_every_reply_code_to_begin_maps_to_its_exit_and_signs_nothing(rig: d.Rig, code: str) -> None:
    rig.broker.answer("begin", d.err(code))
    assert rig.run() == protocol.REPLY_CODES[code][0]
    assert rig.signer.payloads == [] and rig.broker.ops == ["begin"]


def test_a_broker_that_is_not_there_is_reported_with_nothing_sent(rig: d.Rig) -> None:
    rig.broker.connect_error[0] = FileNotFoundError()
    assert rig.run() == 2
    assert "not reachable" in rig.err.getvalue() and rig.signer.payloads == []
    assert "free tier" in rig.err.getvalue()


def test_a_begin_reply_that_never_comes_spends_nothing_and_says_so(rig: d.Rig) -> None:
    rig.broker.answer("begin", [TimeoutError()])
    assert rig.run() == 2
    assert rig.signer.payloads == [] and "nothing was spent" in rig.err.getvalue()


# -- every reply code to a call ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("code", sorted(protocol.REPLY_CODES))
def test_every_reply_code_to_a_call_maps_to_its_exit_and_one_safe_message(rig: d.Rig, code: str) -> None:
    extra: dict[str, Any] = {"receipt": d.receipt()} if code in CHARGE_CODES else {}
    rig.broker.answer("call", d.err(code, **extra))
    assert rig.run() == protocol.REPLY_CODES[code][0]
    text = rig.err.getvalue()
    assert f"{code}: {protocol.REPLY_CODES[code][1]}" in text
    assert rig.broker.ops == ["begin", "call"], "a call is never repeated"
    assert (CHARGED in text) == (code in CHARGE_CODES)
    assert ("receipt: call " + d.CALL_ID in text) == (code in CHARGE_CODES)
    assert ("no receipt was issued" in text) == (code not in CHARGE_CODES)
    assert "free tier" in text and "not retried" in text
    assert d.PROMPT not in rig.everything and d.QUOTE not in rig.err.getvalue()
    assert d.ANSWER not in rig.out.getvalue()


def test_an_internal_failure_without_a_receipt_may_still_have_charged(rig: d.Rig) -> None:
    rig.broker.answer("call", d.err("internal"))
    assert rig.run() == 4
    assert CHARGED in rig.err.getvalue() and "no receipt arrived" in rig.err.getvalue()


def test_rate_limited_shows_the_retry_hint_and_asks_for_nothing_more(rig: d.Rig) -> None:
    rig.broker.answer("call", d.err("rate_limited", receipt=d.receipt(actual_usd="0"), retry_after=30))
    assert rig.run() == 3
    assert "retry hint from the vendor: 30 seconds" in rig.err.getvalue()
    assert rig.broker.opened == 2 and rig.events.count("sign") == 1 and rig.events.count("confirm") == 1


@pytest.mark.parametrize("hint", [-1, 86_401, "30", 1.5, True, None])
def test_a_bad_retry_hint_is_not_shown(rig: d.Rig, hint: Any) -> None:
    rig.broker.answer("call", d.err("rate_limited", receipt=d.receipt(), retry_after=hint))
    assert rig.run() == 3
    assert "retry hint" not in rig.err.getvalue()


def test_outcome_unknown_says_it_was_counted_and_not_repeated(rig: d.Rig) -> None:
    rig.broker.answer("call", d.err("outcome_unknown", receipt=d.receipt()))
    assert rig.run() == 4
    assert "reservation" in rig.err.getvalue() and "model is stopped" in rig.err.getvalue()


@pytest.mark.parametrize("code", ["busy", "disabled", "needs_block_approval"])
def test_a_refusal_before_any_spend_says_no_receipt_was_issued(key: Path, code: str) -> None:
    r = d.make_rig(key)
    r.broker.answer("call", d.err(code))
    assert r.run() == 2
    assert "no receipt was issued" in r.err.getvalue() and CHARGED not in r.err.getvalue()


def test_needs_block_approval_does_not_ask_again_by_itself(rig: d.Rig) -> None:
    rig.broker.answer("call", d.err("needs_block_approval"))
    assert rig.run() == 2
    assert rig.events.count("confirm") == 1 and rig.events.count("sign") == 1 and rig.broker.opened == 2


# -- a lost, truncated, oversize, malformed or foreign reply -----------------------------------------------------------


def lost(rig: d.Rig, items: list[d.Item]) -> str:
    rig.broker.answer("call", items)
    assert rig.run() == 4
    assert rig.broker.ops == ["begin", "call"] and rig.broker.opened == 2, (
        "a call that may have been sent is never retried"
    )
    text = rig.err.getvalue()
    assert CHARGED in text and "not retried" in text and "free tier" in text
    assert f"prompt SHA-256 {gemini.prompt_binding(d.PROMPT)[0]}" in text and f"nonce {d.NONCE[:8]}" in text
    assert d.ANSWER not in rig.everything and d.PROMPT not in rig.everything
    return text


def test_a_truncated_reply_is_outcome_unknown(rig: d.Rig) -> None:
    whole = d.raw(d.ok_call()[0])
    assert "short reply" in lost(rig, [whole[: len(whole) // 2]])


def test_a_reply_cut_inside_its_length_header_is_outcome_unknown(rig: d.Rig) -> None:
    assert "short reply" in lost(rig, [b"\x00\x00"])


def test_a_silent_close_after_the_request_is_outcome_unknown(rig: d.Rig) -> None:
    assert "short reply" in lost(rig, [])


def test_an_oversize_declared_reply_is_refused_without_reading_it(rig: d.Rig) -> None:
    huge = protocol.HEADER.pack(protocol.MAX_REPLY_FRAME + 1) + b"x" * 64
    assert "oversize reply" in lost(rig, [huge])
    assert max(rig.broker.channels[1].asked) <= protocol.READ_CHUNK
    assert len(rig.broker.channels[1].asked) == 1, "the body of an oversize frame is not read"


def test_a_reset_after_the_send_is_outcome_unknown_and_not_retried(rig: d.Rig) -> None:
    assert "connection lost" in lost(rig, [ConnectionResetError()])


def test_a_timeout_after_the_send_is_outcome_unknown_and_not_retried(rig: d.Rig) -> None:
    assert "timeout" in lost(rig, [TimeoutError()])


def test_a_deadline_that_has_passed_is_a_timeout(rig: d.Rig) -> None:
    def slow(fields: dict[str, Any]) -> list[d.Item]:
        rig.clock.advance(100_000)
        return d.ok_call()

    rig.broker.handlers["call"] = slow
    assert rig.run() == 4
    assert "timeout" in rig.err.getvalue() and rig.broker.opened == 2


def test_the_wait_is_bounded_by_the_configured_seconds(rig: d.Rig) -> None:
    rig.run()
    waits = rig.broker.channels[1].timeouts
    assert len(waits) >= 2, "one bound for the send and one for each read"
    assert waits[0] == client.SEND_SECONDS
    assert waits and all(w is not None and 0 < w <= client.DEFAULT_REPLY_SECONDS for w in waits)


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[]",
        b'{"v":1,"ok":true,"v":1}',
        b'{"v":2,"ok":true}',
        b'{"v":1,"ok":"yes"}',
        b'{"v":1,"ok":false}',
    ],
)
def test_a_malformed_reply_is_outcome_unknown(key: Path, body: bytes) -> None:
    assert "malformed reply" in lost(d.make_rig(key), [d.reply_frame(body)])


@pytest.mark.parametrize("tweak", [{"message": "all fine"}, {"exit": 0}, {"code": "made_up"}])
def test_an_error_reply_with_the_wrong_sentence_exit_or_code_is_malformed(key: Path, tweak: dict[str, Any]) -> None:
    body = json.loads(protocol.error_body("busy"))
    body.update(tweak)
    assert "malformed reply" in lost(d.make_rig(key), [d.reply_frame(json.dumps(body).encode())])


def test_a_send_failure_on_the_call_is_treated_as_unknown(rig: d.Rig) -> None:
    rig.broker.send_error[1] = BrokenPipeError()
    assert rig.run() == 4
    assert CHARGED in rig.err.getvalue() and rig.broker.ops == ["begin"] and rig.broker.opened == 2


def test_a_connect_failure_for_the_call_is_nothing_sent(rig: d.Rig) -> None:
    rig.broker.connect_error[1] = ConnectionRefusedError()
    assert rig.run() == 2
    assert CHARGED not in rig.err.getvalue() and "nothing was sent" in rig.err.getvalue()
    assert "approval" in rig.err.getvalue()


def test_a_keyboard_interrupt_while_waiting_is_outcome_unknown(rig: d.Rig) -> None:
    rig.broker.answer("call", [KeyboardInterrupt()])
    assert rig.run() == 4
    assert CHARGED in rig.err.getvalue()


def test_a_reply_for_another_prompt_is_discarded(rig: d.Rig) -> None:
    rig.broker.answer("call", d.ok_call(rcpt=d.receipt("a completely different prompt")))
    assert rig.run() == 4
    assert d.ANSWER not in rig.everything
    assert "does not belong to this request" in rig.err.getvalue() and CHARGED in rig.err.getvalue()
    assert "receipt: call " not in rig.everything, "a foreign receipt is not shown"


@pytest.mark.parametrize(
    "over",
    [
        {"nonce": "9" * 32},
        {"epoch": "9" * 32},
        {"model": "other-model"},
        {"kind": "image"},
        {"count": 1},
        {"image_size": "2K"},
    ],
)
def test_a_receipt_for_another_nonce_epoch_model_or_shape_is_discarded(rig: d.Rig, over: dict[str, Any]) -> None:
    rig.broker.answer("call", d.ok_call(rcpt=d.receipt(**over)))
    assert rig.run() == 4
    assert d.ANSWER not in rig.everything and CHARGED in rig.err.getvalue()


def test_an_error_reply_with_another_digest_is_not_trusted(rig: d.Rig) -> None:
    rig.broker.answer("call", d.err("vendor_refused", receipt=d.receipt("a different prompt")))
    assert rig.run() == 4
    assert "vendor_refused" not in rig.err.getvalue() and "does not belong to this request" in rig.err.getvalue()


def test_a_digest_that_differs_in_one_character_is_discarded(rig: d.Rig) -> None:
    digest = gemini.prompt_binding(d.PROMPT)[0]
    flipped = digest[:-1] + ("0" if digest[-1] != "0" else "1")
    rig.broker.answer("call", d.ok_call(rcpt=d.receipt(prompt_sha256=flipped)))
    assert rig.run() == 4 and d.ANSWER not in rig.everything


def test_a_success_without_a_receipt_is_discarded(rig: d.Rig) -> None:
    rig.broker.answer("call", [d.reply_frame(protocol.ok_body({"text": d.ANSWER, "attachments": []}))])
    assert rig.run() == 4 and d.ANSWER not in rig.everything


@pytest.mark.parametrize(
    "over",
    [
        {"call_id": "zz"},
        {"reserved_usd": "1e3"},
        {"actual_usd": "-1"},
        {"tokens_in": -1},
        {"tokens_out": True},
        {"tokens_in": "12"},
        {"breach": "no"},
        {"broker_version": "\x1b[31m"},
        {"ts": "yesterday"},
        {"month_spent_after": 5},
        {"images": "none"},
        {"ledger_head_after": "short"},
    ],
)
def test_a_receipt_with_a_field_of_the_wrong_shape_is_discarded(rig: d.Rig, over: dict[str, Any]) -> None:
    rig.broker.answer("call", d.ok_call(rcpt=d.receipt(**over)))
    assert rig.run() == 4 and d.ANSWER not in rig.everything


def test_a_receipt_with_no_token_figures_is_accepted_and_says_unknown(rig: d.Rig) -> None:
    rig.broker.answer("call", d.ok_call(rcpt=d.receipt(tokens_in=None, tokens_out=None)))
    assert rig.run() == 0
    assert "tokens: unknown in, unknown out" in rig.out.getvalue()


def test_a_text_reply_that_carries_an_attachment_is_discarded(rig: d.Rig) -> None:
    rig.broker.answer("call", d.ok_call(images=(d.PNG,)))
    assert rig.run() == 4 and d.ANSWER not in rig.everything and rig.writer.calls == []


# -- the answer is untrusted output ------------------------------------------------------------------------------------


def test_an_answer_cannot_write_escapes_to_the_terminal(rig: d.Rig) -> None:
    nasty = "plain\x1b[2J\x1b]0;title\x07 bidi \u202e text \u2028 next ::set-output name=x::y\x00 nul"
    rig.broker.answer("call", d.ok_call(text=nasty))
    assert rig.run() == 0
    out = rig.out.getvalue()
    assert "\x1b" not in out and "\x07" not in out and "\x00" not in out and "\u202e" not in out and "\u2028" not in out
    assert "\\x1b[2J" in out and "\\u202e" in out


def test_an_answer_that_is_not_text_is_discarded(rig: d.Rig) -> None:
    rig.broker.answer("call", [d.reply_frame(protocol.ok_body({"receipt": d.receipt(), "text": 5, "attachments": []}))])
    assert rig.run() == 4


# -- images ------------------------------------------------------------------------------------------------------------


def image_rig(rig: d.Rig, data: bytes = d.PNG, mime: str = "image/png", **over: Any) -> None:
    rig.broker.answer("begin", d.offer_reply(thinking_level="minimal"))
    receipt = d.image_receipt(data, mime, **over)
    rig.broker.answer("call", d.ok_call(text="", rcpt=receipt, images=(data,), desc=[d.described(data, mime)]))


def test_an_image_is_written_through_the_writer_and_only_its_summary_is_printed(rig: d.Rig) -> None:
    image_rig(rig)
    assert rig.run(d.image_params()) == 0
    ((data, directory, stem, limit),) = rig.writer.calls
    assert data == d.PNG and directory == d.IMAGE_DIR and limit == protocol.MAX_ATTACHMENT_FRAME
    assert stem == "20261030T120000Z-job-img-01234567-0"
    out = rig.out.getvalue()
    assert f"image: {d.IMAGE_DIR}/{stem}.png ({len(d.PNG)} bytes, type png)" in out
    assert "PNG" not in out.replace("type png", "").replace("type PNG", "")
    assert rig.events[0] == "dir", "the folder is checked before the call is even asked for"
    assert rig.events.index("dir") < rig.events.index("connect")


@pytest.mark.parametrize(
    ("data", "mime", "kind"),
    [(d.PNG, "image/png", "png"), (d.JPEG, "image/jpeg", "jpeg"), (d.WEBP, "image/webp", "webp")],
)
def test_the_sniffed_type_is_printed_for_each_allowed_format(rig: d.Rig, data: bytes, mime: str, kind: str) -> None:
    image_rig(rig, data, mime)
    assert rig.run(d.image_params()) == 0
    assert f"type {kind})" in rig.out.getvalue()


def test_the_sidecar_holds_the_receipt_and_says_unreviewed(rig: d.Rig) -> None:
    image_rig(rig)
    rig.run(d.image_params())
    ((path, raw),) = rig.sidecar.calls
    assert path.startswith(d.IMAGE_DIR + "/20261030T120000Z-job-img-01234567-0")
    sidecar = json.loads(raw)
    assert sidecar["reviewed"] is False and sidecar["receipt"]["call_id"] == d.CALL_ID
    assert sidecar["image"] == d.described(d.PNG) and "prompt" not in sidecar and d.PROMPT not in raw.decode()
    assert "receipt file:" in rig.out.getvalue()


def test_a_sidecar_failure_is_a_warning_and_the_image_stays_saved(rig: d.Rig) -> None:
    image_rig(rig)
    rig.sidecar.fail = OSError("disk full")
    assert rig.run(d.image_params()) == 0
    assert "the receipt file was not written" in rig.err.getvalue() and "disk full" not in rig.everything


def test_a_tampered_attachment_is_not_written(rig: d.Rig) -> None:
    rig.broker.answer("begin", d.offer_reply(thinking_level="minimal"))
    tampered = d.PNG[:-1] + b"\x01"
    head = d.ok_call(text="", rcpt=d.image_receipt(d.PNG), images=(), desc=[d.described(d.PNG)])
    rig.broker.answer("call", [*head, d.attach_frame(tampered)])
    assert rig.run(d.image_params()) == 4
    assert rig.writer.calls == [] and CHARGED in rig.err.getvalue()
    assert "receipt: call " + d.CALL_ID in rig.err.getvalue() and "image was NOT saved" in rig.err.getvalue()
    assert "did not match its description" in rig.err.getvalue()


def test_a_truncated_attachment_is_not_written(rig: d.Rig) -> None:
    rig.broker.answer("begin", d.offer_reply(thinking_level="minimal"))
    whole = d.ok_call(text="", rcpt=d.image_receipt(), images=(d.PNG,), desc=[d.described(d.PNG)])
    rig.broker.answer("call", [whole[0], d.raw(whole[1])[:-5]])
    assert rig.run(d.image_params()) == 4
    assert rig.writer.calls == [] and "image was NOT saved" in rig.err.getvalue()
    assert "did not arrive whole" in rig.err.getvalue()


def test_an_attachment_longer_than_described_is_not_written(rig: d.Rig) -> None:
    rig.broker.answer("begin", d.offer_reply(thinking_level="minimal"))
    head = d.ok_call(text="", rcpt=d.image_receipt(d.PNG), images=(), desc=[d.described(d.PNG)])
    rig.broker.answer("call", [*head, d.attach_frame(d.PNG + b"extra")])
    assert rig.run(d.image_params()) == 4 and rig.writer.calls == []


def test_a_missing_attachment_for_an_image_call_is_reported(rig: d.Rig) -> None:
    rig.broker.answer("begin", d.offer_reply(thinking_level="minimal"))
    rig.broker.answer("call", d.ok_call(text="", rcpt=d.image_receipt(d.PNG, images=[]), images=()))
    assert rig.run(d.image_params()) == 4 and rig.writer.calls == []
    assert CHARGED in rig.err.getvalue()


def test_a_receipt_that_disagrees_with_the_attachment_description_is_discarded(rig: d.Rig) -> None:
    rig.broker.answer("begin", d.offer_reply(thinking_level="minimal"))
    other = d.described(d.JPEG, "image/jpeg")
    rig.broker.answer("call", d.ok_call(text="", rcpt=d.image_receipt(d.PNG, images=[other]), images=(d.PNG,)))
    assert rig.run(d.image_params()) == 4 and rig.writer.calls == []


def test_bytes_whose_type_disagrees_with_the_named_mime_are_not_written(rig: d.Rig) -> None:
    image_rig(rig, d.JPEG, "image/png")
    assert rig.run(d.image_params()) == 4 and rig.writer.calls == []
    assert "image was NOT saved" in rig.err.getvalue()


def test_bytes_that_are_not_an_image_are_not_written(rig: d.Rig) -> None:
    image_rig(rig, b"<html>not an image at all, long enough</html>", "image/png")
    assert rig.run(d.image_params()) == 4 and rig.writer.calls == []


def test_a_writer_failure_says_money_was_spent_and_gives_the_digest(rig: d.Rig) -> None:
    image_rig(rig)
    rig.writer.fail = OSError("no space")
    assert rig.run(d.image_params()) == 4
    text = rig.err.getvalue()
    assert CHARGED in text and hashlib.sha256(d.PNG).hexdigest() in text and "no space" not in text
    assert rig.sidecar.calls == []


def test_the_name_never_comes_from_the_reply(rig: d.Rig) -> None:
    image_rig(rig)
    rig.broker.answer(
        "call",
        d.ok_call(
            text="../../etc/passwd",
            rcpt=d.image_receipt(d.PNG, call_id="12" * 16),
            images=(d.PNG,),
            desc=[d.described(d.PNG)],
        ),
    )
    rig.run(d.image_params())
    stem = rig.writer.calls[0][2]
    assert "passwd" not in stem and "12121212" not in stem and ".." not in stem and "/" not in stem


def test_an_image_call_without_a_folder_is_refused_before_the_broker_is_asked(rig: d.Rig) -> None:
    rig.cfg = client.ClientConfig(
        socket=rig.cfg.socket, signing_key=rig.cfg.signing_key, principal=rig.cfg.principal, image_dir=""
    )
    assert rig.run(d.image_params()) == 2
    assert rig.broker.opened == 0


def test_an_unusable_folder_is_refused_before_the_broker_is_asked(rig: d.Rig) -> None:
    def bad(directory: str) -> None:
        raise gemini.RefusedError("the image folder is not private")

    rig.deps.check_dir = bad
    assert rig.run(d.image_params()) == 2
    assert rig.broker.opened == 0 and rig.signer.payloads == []


def test_a_text_call_never_needs_a_folder_or_a_writer(rig: d.Rig) -> None:
    rig.run()
    assert "dir" not in rig.events and rig.writer.calls == [] and rig.sidecar.calls == []


# -- the parameters ----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "over",
    [
        {"model": "Bad Model"},
        {"model": ""},
        {"job": "bad job"},
        {"job": "x" * 65},
        {"kind": "video"},
        {"max_output_tokens": 0},
        {"max_output_tokens": -3},
        {"max_output_tokens": 10_000_001},
        {"max_usd": "0"},
        {"max_usd": "2.5000001"},
        {"max_usd": "-1"},
        {"max_usd": "1e2"},
        {"quote": ""},
        {"quote": "line\nbreak"},
        {"quote": "x" * 501},
        {"quoted_at": "2026-10-30 11:59:00"},
        {"issue": "x" * 81},
    ],
)
def test_a_bad_parameter_is_refused_before_the_broker_is_contacted(rig: d.Rig, over: dict[str, Any]) -> None:
    assert rig.run(d.text_params(**over)) == 2
    assert rig.broker.opened == 0 and rig.signer.payloads == []


@pytest.mark.parametrize(
    "over", [{"count": 0}, {"count": 17}, {"image_size": ""}, {"image_size": "1 K"}, {"aspect_ratio": "wide"}]
)
def test_a_bad_image_parameter_is_refused_before_the_broker_is_contacted(rig: d.Rig, over: dict[str, Any]) -> None:
    assert rig.run(d.image_params(**over)) == 2
    assert rig.broker.opened == 0


def test_a_text_call_with_image_fields_is_refused(rig: d.Rig) -> None:
    assert rig.run(d.text_params(image_size="1K")) == 2 and rig.broker.opened == 0


def test_a_missing_signing_setup_is_refused_before_anything_happens(rig: d.Rig) -> None:
    rig.cfg = client.ClientConfig(socket=rig.cfg.socket, signing_key="", principal="", image_dir=d.IMAGE_DIR)
    assert rig.run() == 2 and rig.broker.opened == 0
    assert "signing" in rig.err.getvalue()


# -- what is never done ------------------------------------------------------------------------------------------------


def test_no_failure_path_puts_the_prompt_the_quote_or_the_answer_in_a_diagnostic(
    key: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    scenarios: list[tuple[str, list[d.Item]]] = []
    for code in sorted(protocol.REPLY_CODES):
        scenarios.append(("call", d.err(code, receipt=d.receipt())))
    scenarios += [
        ("call", [TimeoutError()]),
        ("call", [ConnectionResetError()]),
        ("call", [d.raw(d.ok_call()[0])[:30]]),
        ("call", d.ok_call(rcpt=d.receipt("another prompt"))),
        ("call", [d.reply_frame(b"garbage " + d.PROMPT.encode() + d.ANSWER.encode())]),
        ("begin", d.err("busy")),
        ("begin", [d.reply_frame(b"garbage " + d.PROMPT.encode())]),
    ]
    for op, items in scenarios:
        r = d.make_rig(key)
        r.broker.answer(op, items)
        r.run()
        assert "ZEBRA" not in r.err.getvalue(), (op, items)
        assert "ANSWER-SENTINEL" not in r.err.getvalue() and "QUOTE-SENTINEL" not in r.err.getvalue()
    assert caplog.records == []


def test_the_signer_failure_text_never_reaches_the_user(key: Path) -> None:
    r = d.make_rig(key)
    r.signer.fail = gemini.RefusedError("ZEBRA-PROMPT-7731 leaked into a signer message")
    assert r.run() == 2 and "ZEBRA" not in r.err.getvalue()


def test_no_failure_falls_back_to_the_free_tier(key: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kw: object) -> None:
        raise AssertionError("the free tier was called")

    monkeypatch.setattr(gemini, "ask", forbidden)
    monkeypatch.setattr(gemini, "doppler_key_provider", forbidden)
    for code in ("rate_limited", "disabled", "busy", "internal", "outcome_unknown"):
        r = d.make_rig(key)
        r.broker.answer("call", d.err(code))
        r.run()
        assert r.broker.ops == ["begin", "call"]


def test_the_client_source_never_names_the_free_path_a_logger_or_print() -> None:
    assert forbidden_names(Path(client.__file__).read_text()) == []


def forbidden_names(source: str) -> list[str]:
    """What the client must never reach: the free-tier call, its key reader, an HTTP client, logging, print."""
    bad = {"ask", "doppler_key_provider"}
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and node.module == "safo.gemini":
            found += [a.name for a in node.names if a.name in bad]
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.split(".")[0] in {"http", "urllib", "logging"}
        ):
            found.append(node.module)
        elif isinstance(node, ast.Import):
            found += [a.name for a in node.names if a.name.split(".")[0] in {"http", "urllib", "requests", "logging"}]
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
            found.append("print")
    return found


def test_the_forbidden_name_guard_bites() -> None:
    assert forbidden_names("from safo.gemini import ask\n") == ["ask"]
    assert forbidden_names("import logging\nprint('x')\n") == ["logging", "print"]
    assert forbidden_names("import urllib.request\n") == ["urllib.request"]
    assert forbidden_names("from safo.gemini import prompt_binding\n") == []


def test_the_client_uses_the_protocol_module_unchanged() -> None:
    assert vars(client)["protocol"] is protocol
    text = Path(client.__file__).read_text()
    assert "protocol.read_frame" in text and "protocol.parse_reply" in text and "protocol.request_body" in text


def test_an_image_count_the_broker_would_refuse_is_never_signed(rig: d.Rig) -> None:
    rig.broker.answer("begin", d.offer_reply(thinking_level="minimal"))
    assert rig.run(d.image_params(count=5)) == 2
    assert rig.signer.payloads == [] and rig.broker.ops == ["begin"]


def test_an_offer_that_brings_an_attachment_is_never_signed(rig: d.Rig) -> None:
    fields = {
        "nonce": d.NONCE,
        "epoch": d.EPOCH,
        "expires_at": "2026-10-30T12:10:00Z",
        "ledger_head": d.HEAD,
        "estimate_usd": "0.004",
        "reserve_usd": "0.012",
        "thinking_level": "none",
        "beyond_ceiling": False,
        "attachments": [d.described(d.PNG)],
    }
    rig.broker.answer("begin", [d.reply_frame(protocol.ok_body(fields)), d.attach_frame(d.PNG)])
    assert rig.run() == 2 and rig.signer.payloads == []


def test_only_the_first_bytes_name_an_image_type() -> None:
    assert client.sniff_image_type(d.PNG) == "png" and client.sniff_image_type(d.JPEG) == "jpeg"
    assert client.sniff_image_type(d.WEBP) == "webp"
    assert client.sniff_image_type(b"RIFF\x00\x00\x00\x00AVI LIST" + b"\x00" * 8) is None
    assert client.sniff_image_type(b"\xff\xd8\x00\x00") is None
    assert client.sniff_image_type(b"GIF89a") is None and client.sniff_image_type(b"") is None


def test_a_signature_with_a_non_ascii_tail_is_never_sent(rig: d.Rig, key: Path) -> None:
    good = geminisign.sign(str(key), b"x", geminisign.NAMESPACE, {})
    rig.signer.armor_override = good + "\u3000"
    assert rig.run() == 2
    assert rig.broker.ops == ["begin"] and rig.broker.opened == 1
