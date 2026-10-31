# SPDX-License-Identifier: Apache-2.0
"""The call pipeline against a fake vendor: spend first, the template, every outcome, ambiguity, the output cap, images,
crash points between every step, and properties of what is recorded. No socket, no key, no timing."""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

import pytest

from brokerdata import EPOCH, FLAT, NOW, Crash, CrashAt, Rng, approval, flat_request, policy
from fakevendor import jpeg, png, webp
from geminidata import make_key
from pipedata import IMAGE_MODEL, IMAGE_PROMPT, Rig, image_req, text_req
from safo import gemini
from safo.broker import pipeline as pipeline_module
from safo.broker import vendor as vendor_module
from safo.broker.errors import IllegalTransition, Refused
from safo.broker.ledger import FAULT_POINTS, CallLedger
from safo.broker.pipeline import PIPELINE_FAULTS, CallResult
from safo.broker.states import CallState


@pytest.fixture(scope="module")
def key(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_key(tmp_path_factory.mktemp("keys") / "a")


@pytest.fixture
def rig(tmp_path: Path, key: Path) -> Rig:
    return Rig(tmp_path, key)


def only_call(rig: Rig) -> Any:
    (rec,) = rig.ledger.view().calls.values()
    return rec


def row_types(rig: Rig) -> list[str]:
    text = (rig.ledger.dir / "ledger.jsonl").read_text()
    return [json.loads(line)["type"] for line in text.splitlines()]


def refusal(rig: Rig, req: Any, **over: Any) -> str:
    with pytest.raises(Refused) as err:
        rig.run(req, **over)
    return err.value.code


def assert_ambiguous(rig: Rig, result: CallResult, reason: str) -> None:
    assert result.code == "outcome_unknown" and result.text == "" and result.images == ()
    rec = only_call(rig)
    assert rec.state is CallState.SUSPENDED and rec.ambiguous and rec.unresolved
    assert rig.ledger.view().month_spent(NOW) == rec.reserved_micro == result.receipt.reserved_micro
    assert result.receipt.estimated and result.receipt.actual_micro == rec.reserved_micro
    rows = [json.loads(x) for x in (rig.ledger.dir / "ledger.jsonl").read_text().splitlines()]
    assert [r["reason"] for r in rows if r["type"] == "ambiguous_call"] == [reason]
    assert len(rig.vendor.requests) == 1  # the request was sent once and is never repeated


# -- the good path -------------------------------------------------------------------------------------------------


def test_a_good_text_call_is_verified_spent_first_sent_once_and_settled(rig: Rig) -> None:
    req = text_req()
    seen: dict[str, Any] = {}

    def look(_: Any) -> None:  # what the ledger says at the moment the request leaves
        seen["types"] = row_types(rig)
        seen["state"] = only_call(rig).state

    rig.vendor.on_send = look
    result = rig.run(req)
    assert seen["types"] == ["chain_start", "approval_used", "call_start", "call_sent"]
    assert seen["state"] is CallState.SENT
    assert result.code == "ok" and result.text == "a short answer" and result.images == ()
    assert len(rig.vendor.requests) == 1
    rec = only_call(rig)
    cost = result.receipt.actual_micro
    assert rec.state is CallState.SETTLED and rec.counted_micro == cost and 0 < cost < rec.reserved_micro
    assert row_types(rig)[-1] == "call_end"
    assert result.receipt.released_micro == rec.reserved_micro - cost and not result.receipt.breach
    assert result.receipt.month_spent_micro == cost and result.receipt.tokens_in and not result.receipt.estimated


def test_the_request_that_leaves_is_the_fixed_template_with_the_approved_prompt_and_limit(rig: Rig) -> None:
    req = text_req(prompt='quote " and \\ and \n newline and café')
    rig.run(req)
    (sent,) = rig.vendor.requests
    body = json.loads(sent.body)
    assert body["contents"][0]["parts"][0]["text"] == req.prompt
    assert body["generationConfig"] == {"maxOutputTokens": 500}
    assert set(body) == {"contents", "generationConfig"} and sent.path.endswith("flat-test:generateContent")
    assert sent.timeout_seconds == 180.0


def test_the_receipt_holds_no_prompt_no_quote_and_no_key(rig: Rig) -> None:
    req = text_req(prompt="SENTINEL-PROMPT go")
    result = rig.run(req)
    shown = repr(result.receipt)
    assert "SENTINEL" not in shown and "go ahead" not in shown and result.receipt.prompt_sha256 in shown


def test_a_replayed_approval_is_refused_and_never_reaches_the_vendor(rig: Rig) -> None:
    req = text_req()
    payload, signature = rig.approved(req)
    assert rig.pipeline.call(req, payload, signature).code == "ok"
    with pytest.raises(Refused) as err:
        rig.pipeline.call(req, payload, signature)
    assert err.value.code == "used" and len(rig.vendor.requests) == 1
    assert row_types(rig).count("call_start") == 1


def test_an_approval_for_other_bytes_is_refused_before_anything_is_spent(rig: Rig) -> None:
    req = text_req()
    payload, signature = rig.approved(req)
    for changed in (
        text_req(prompt=req.prompt + " "),
        text_req(job="other"),
        text_req(max_output_tokens=501),
        text_req(model="gemini-3.6-flash", thinking_level="minimal"),
    ):
        with pytest.raises(Refused):
            rig.pipeline.call(changed, payload, signature)
    assert rig.ledger.view().calls == {} and rig.vendor.requests == []


def test_a_nonce_the_broker_did_not_issue_is_refused_before_anything_is_spent(rig: Rig) -> None:
    req = text_req()
    offer = rig.offer(req)
    rig.issuer.flush()  # a restart between begin and call
    text = rig.text(req, offer)
    with pytest.raises(Refused) as err:
        rig.pipeline.call(req, text, rig.sign(text))
    assert err.value.code == "bad_approval" and rig.ledger.view().calls == {}


def test_the_issued_nonce_is_consumed_by_the_spend(rig: Rig) -> None:
    rig.run(text_req())
    assert os.listdir(rig.ledger.dir / "issued") == []


def test_a_key_revoked_after_verification_and_before_the_spend_is_caught(rig: Rig, key: Path) -> None:
    pub = key.with_suffix(".pub").read_text().split()

    def revoke(point: str) -> None:
        if point == "after_verify":
            rig.revoked.write_text(f"{pub[0]} {pub[1]}\n")

    rig.pipeline_faults = revoke
    rig.build()
    assert refusal(rig, text_req()) == "revoked"
    assert rig.ledger.view().calls == {} and rig.vendor.requests == []


def test_an_issued_nonce_that_expires_between_the_checks_is_caught_under_the_lock(rig: Rig) -> None:
    req = text_req()
    offer = rig.offer(req)
    late = gemini.stamp(NOW + dt.timedelta(minutes=30))  # the approval outlives the nonce; the nonce is what ends
    text = rig.text(req, offer, expires_at=late)
    signature = rig.sign(text)

    def pass_time(point: str) -> None:
        if point == "after_verify":
            rig.clock.at = offer.expires_at

    rig.pipeline_faults = pass_time
    rig.build()
    with pytest.raises(Refused) as err:
        rig.pipeline.call(req, text, signature)
    assert err.value.code == "expired" and rig.ledger.view().calls == {} and rig.vendor.requests == []


# -- failures that leave nothing billed ----------------------------------------------------------------------------


def test_a_failure_after_the_spend_and_before_the_send_ends_as_not_sent_and_frees_the_money(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: Any) -> Any:
        raise RuntimeError("template bug")

    monkeypatch.setattr("safo.broker.pipeline.build_request", boom)
    with pytest.raises(RuntimeError):
        rig.run(text_req())
    rec = only_call(rig)
    assert rec.state is CallState.SETTLED and rec.actual_micro == 0 and not rec.ambiguous
    assert rig.ledger.view().month_spent(NOW) == 0 and rig.vendor.requests == []
    assert row_types(rig)[-1] == "call_end" and "call_sent" not in row_types(rig)


def test_a_request_body_that_is_not_the_approved_prompt_is_never_sent(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = vendor_module.build_request

    def tampered(req: Any, price: Any, deadline: float) -> Any:
        return real(text_req(prompt=req.prompt + "!"), price, deadline)

    monkeypatch.setattr("safo.broker.pipeline.build_request", tampered)
    assert refusal(rig, text_req()) == "internal"
    assert rig.vendor.requests == [] and only_call(rig).actual_micro == 0


def test_a_failure_while_writing_call_sent_makes_the_call_ambiguous(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*_: Any, **__: Any) -> None:
        raise OSError("disk")

    monkeypatch.setattr(CallLedger, "mark_sent", broken)
    with pytest.raises(OSError):
        rig.run(text_req())
    rec = only_call(rig)
    assert rec.ambiguous and rec.state is CallState.SUSPENDED and rig.vendor.requests == []
    assert rig.ledger.view().month_spent(NOW) == rec.reserved_micro


# -- definite vendor answers ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "want"),
    [("30", 30), ("0.5", 1), ("nan", None), ("inf", None), ("-5", None), ("99999999", None), ("x", None)],
)
def test_a_429_is_final_costs_nothing_keeps_the_nonce_spent_and_does_not_suspend(
    rig: Rig, header: str, want: int | None
) -> None:
    rig.vendor.mode, rig.vendor.status = "status", 429
    rig.vendor.headers = {"Retry-After": header}
    result = rig.run(text_req())
    assert result.code == "rate_limited" and result.retry_after == want and result.text == ""
    rec = only_call(rig)
    assert rec.state is CallState.SETTLED and rec.actual_micro == 0 and not rec.ambiguous and not rec.breach
    assert rig.ledger.view().month_spent(NOW) == 0 and rig.ledger.view().suspended == {}
    assert len(rig.vendor.requests) == 1 and result.receipt.released_micro == rec.reserved_micro


def test_a_429_without_a_retry_after_header_gives_none(rig: Rig) -> None:
    rig.vendor.mode, rig.vendor.status = "status", 429
    assert rig.run(text_req()).retry_after is None


@pytest.mark.parametrize("status", [400, 401, 403, 404, 413, 422, 499])
def test_a_definite_4xx_is_vendor_refused_costs_nothing_and_does_not_suspend(rig: Rig, status: int) -> None:
    rig.vendor.mode, rig.vendor.status = "status", status
    rig.vendor.error_body = b'{"error":{"message":"SENTINEL-VENDOR-BODY"}}'
    result = rig.run(text_req())
    assert result.code == "vendor_refused" and "SENTINEL" not in repr(result)
    rec = only_call(rig)
    assert rec.state is CallState.SETTLED and rec.actual_micro == 0 and rig.ledger.view().suspended == {}


def test_a_spent_approval_stays_spent_after_a_429_or_a_refusal(rig: Rig) -> None:
    req = text_req()
    payload, signature = rig.approved(req)
    rig.vendor.mode, rig.vendor.status = "status", 429
    rig.pipeline.call(req, payload, signature)
    rig.vendor.mode = "normal"
    with pytest.raises(Refused) as err:
        rig.pipeline.call(req, payload, signature)
    assert err.value.code == "used" and len(rig.vendor.requests) == 1


# -- ambiguous outcomes --------------------------------------------------------------------------------------------


def test_a_timeout_is_ambiguous(rig: Rig) -> None:
    rig.vendor.mode = "timeout"
    assert_ambiguous(rig, rig.run(text_req()), "timeout")


def test_a_reset_connection_is_ambiguous(rig: Rig) -> None:
    rig.vendor.mode = "reset"
    assert_ambiguous(rig, rig.run(text_req()), "connection")


def test_a_slow_answer_that_arrives_after_the_deadline_is_ambiguous_and_its_content_is_dropped(rig: Rig) -> None:
    rig.vendor.mode = "slow"
    assert_ambiguous(rig, rig.run(text_req()), "timeout")


def test_an_answer_exactly_at_the_deadline_still_counts(rig: Rig) -> None:
    rig.vendor.on_send = lambda request: rig.clock.advance(request.timeout_seconds)
    assert rig.run(text_req()).code == "ok"


@pytest.mark.parametrize("status", [100, 201, 204, 206, 301, 302, 307, 308, 408, 500, 502, 503, 504, 599, 600, 700])
def test_a_status_that_does_not_tell_what_was_billed_is_ambiguous(rig: Rig, status: int) -> None:
    rig.vendor.mode, rig.vendor.status = "status", status
    assert_ambiguous(rig, rig.run(text_req()), "status")


@pytest.mark.parametrize("mode", ["malformed", "truncated", "oversized", "wrong_model", "duplicated_part"])
def test_a_reply_that_cannot_be_trusted_is_ambiguous(rig: Rig, mode: str) -> None:
    rig.vendor.mode = mode
    if mode == "malformed":
        rig.vendor.body = b"{not json"
    assert_ambiguous(rig, rig.run(text_req()), "unreadable")


@pytest.mark.parametrize(
    "body",
    [b"", b"null", b'{"a":1,"a":2}', b'{"usageMetadata":NaN}', b"[" * 50_000 + b"]" * 50_000, b"\xff\xff"],
)
def test_hostile_json_is_ambiguous_and_never_escapes_as_an_error(rig: Rig, body: bytes) -> None:
    rig.vendor.body = body
    assert_ambiguous(rig, rig.run(text_req()), "unreadable")


def test_a_content_length_that_does_not_match_the_body_is_ambiguous(rig: Rig) -> None:
    rig.vendor.headers = {"content-length": "99999"}
    assert_ambiguous(rig, rig.run(text_req()), "unreadable")


@pytest.mark.parametrize("length", ["-1", "1e3", "٣", " 5", "0x10", ""])
def test_a_content_length_that_is_not_a_plain_number_is_ambiguous(rig: Rig, length: str) -> None:
    rig.vendor.headers = {"Content-Length": length}
    assert_ambiguous(rig, rig.run(text_req()), "unreadable")


@pytest.mark.parametrize(
    "usage",
    [
        None,
        {},
        "x",
        {"promptTokenCount": True, "candidatesTokenCount": 3},
        {"promptTokenCount": -1, "candidatesTokenCount": 1},
        {"promptTokenCount": 0, "candidatesTokenCount": 3},
        {"promptTokenCount": 10**9, "candidatesTokenCount": 3},
    ],
)
def test_usage_that_cannot_be_trusted_is_ambiguous_with_the_whole_reservation_counted(rig: Rig, usage: Any) -> None:
    rig.vendor.usage = usage
    rig.vendor.text = "twenty-four bytes of text"
    assert_ambiguous(rig, rig.run(text_req()), "usage")


def test_an_ambiguous_call_stops_the_model_until_root_resolves_and_clears_it(rig: Rig) -> None:
    rig.vendor.mode = "timeout"
    rig.run(text_req())
    rig.vendor.mode = "normal"
    with pytest.raises(Refused) as err:
        rig.offer(text_req())
    assert err.value.code == "model_suspended"
    rec = only_call(rig)
    with pytest.raises(IllegalTransition, match="real amount"):
        rig.ledger.clear(FLAT, NOW)
    rig.ledger.resolve(rec.call_id, 77, NOW)
    rig.ledger.clear(FLAT, NOW)
    assert rig.ledger.view().month_spent(NOW) == 77
    assert rig.run(text_req()).code == "ok"
    assert len(rig.vendor.requests) == 2


def test_a_suspension_for_one_model_does_not_stop_another(rig: Rig) -> None:
    rig.vendor.mode = "timeout"
    rig.run(text_req())
    rig.vendor.mode = "normal"
    assert rig.run(image_req()).code == "ok"


def test_a_suspended_model_refuses_a_call_even_with_an_approval_issued_before(rig: Rig) -> None:
    req = text_req()
    payload, signature = rig.approved(req)
    rig.vendor.mode = "timeout"
    rig.run(text_req())
    rig.vendor.mode = "normal"
    with pytest.raises(Refused) as err:
        rig.pipeline.call(req, payload, signature)
    assert err.value.code == "model_suspended" and len(rig.vendor.requests) == 1


def test_a_transport_that_raises_something_unexpected_is_ambiguous_not_a_crash(rig: Rig) -> None:
    def explode(_: Any) -> Any:
        raise ValueError("anything at all")

    rig.vendor.on_send = explode
    assert_ambiguous(rig, rig.run(text_req()), "connection")


def test_a_settle_that_fails_after_a_good_answer_leaves_the_call_ambiguous(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: Any, **__: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(CallLedger, "settle", broken)
    with pytest.raises(OSError):
        rig.run(text_req())
    rec = only_call(rig)
    assert rec.ambiguous and rig.ledger.view().month_spent(NOW) == rec.reserved_micro


# -- the output cap (decision 13) ----------------------------------------------------------------------------------


def test_a_reply_over_the_signed_cap_is_a_breach_settled_at_the_higher_figure_and_stops_the_model(rig: Rig) -> None:
    rig.vendor.mode = "over_cap"  # 501 output tokens against a cap of 500
    result = rig.run(text_req())
    rec = only_call(rig)
    assert result.code == "ok" and result.receipt.cap_breach and result.receipt.breach
    assert rec.state is CallState.SUSPENDED and rec.breach and not rec.ambiguous
    assert rig.ledger.view().suspended == {FLAT: (rec.call_id,)}
    tokens_in = result.receipt.tokens_in
    assert tokens_in is not None
    at_cap = (len(text_req().prompt) + 64) + 500 * 10  # the reservation: input margin plus the cap at the output rate
    reported = tokens_in + 501 * 10
    assert rec.actual_micro == max(reported, at_cap)
    assert rig.ledger.view().month_spent(NOW) == rec.actual_micro


def test_a_reply_that_reports_less_than_the_cap_costs_is_recorded_at_the_cap(rig: Rig) -> None:
    """Over the cap by one token with a small input: the reported usage costs less than the cap allowed, and the
    cap's figure (the higher of the two) is what is recorded."""
    rig.vendor.tokens_in = 10
    rig.vendor.tokens_out = 501
    result = rig.run(text_req(prompt="p" * 40))
    at_cap = (40 + 64) + 500 * 10
    reported = 10 + 501 * 10
    assert reported < at_cap
    assert only_call(rig).actual_micro == at_cap and result.receipt.actual_micro == at_cap


def test_a_reply_far_over_the_cap_is_settled_at_what_it_reports(rig: Rig) -> None:
    rig.vendor.tokens_out = 90_000
    result = rig.run(text_req())
    rec = only_call(rig)
    tokens_in = result.receipt.tokens_in
    assert tokens_in is not None and rec.breach
    assert rec.actual_micro == tokens_in + 90_000 * 10
    assert rec.actual_micro > rec.reserved_micro and result.receipt.released_micro == 0


def test_a_reply_exactly_at_the_cap_is_not_a_breach(rig: Rig) -> None:
    rig.vendor.tokens_out = 500
    result = rig.run(text_req())
    assert not result.receipt.cap_breach and not result.receipt.breach and rig.ledger.view().suspended == {}


def test_a_model_whose_cap_is_not_verified_still_breaches_inside_its_larger_reservation(rig: Rig) -> None:
    """With `cap_verified` false the reservation covers the documented limit, so money stays inside it; the cap the
    broker sent was still ignored, and that alone suspends the model."""
    req = text_req(model="gemini-3.6-flash", thinking_level="minimal", max_output_tokens=500)
    rig.vendor.tokens_out = 800
    result = rig.run(req)
    rec = only_call(rig)
    assert rec.actual_micro < rec.reserved_micro and rec.breach and result.receipt.cap_breach
    assert rec.state is CallState.SUSPENDED and rig.ledger.view().suspended == {"gemini-3.6-flash": (rec.call_id,)}
    input_part = (len(req.prompt) + 64) * 300_000 // 1_000_000 + 1  # 0.30 per million, rounded up
    assert rec.actual_micro >= input_part + 500 * 2_500_000 // 1_000_000  # at least the cap's worth of output


def test_the_thinking_tokens_count_against_the_cap(rig: Rig) -> None:
    rig.vendor.usage = {"promptTokenCount": 10, "candidatesTokenCount": 300, "thoughtsTokenCount": 201}
    rig.vendor.text = "x" * 30
    assert rig.run(text_req()).receipt.cap_breach


def test_a_breach_is_counted_in_the_month_and_the_next_call_for_that_model_is_refused(rig: Rig) -> None:
    rig.vendor.mode = "over_cap"
    rig.run(text_req())
    rig.vendor.mode = "normal"
    with pytest.raises(Refused) as err:
        rig.offer(text_req())
    assert err.value.code == "model_suspended"


# -- images --------------------------------------------------------------------------------------------------------


def test_a_good_image_call_returns_one_checked_image_with_a_receipt(rig: Rig) -> None:
    rig.vendor.image = png(1024, 1024)
    result = rig.run(image_req())
    assert result.code == "ok" and len(result.images) == 1
    image = result.images[0]
    assert image.data == png(1024, 1024) and image.mime == "image/png"
    assert result.receipt.images == ((0, "image/png", len(image.data), image.sha256),)
    (sent,) = rig.vendor.requests
    body = json.loads(sent.body)
    assert sent.path == "/v1beta/interactions" and body["generation_config"]["max_output_tokens"] == 4000
    assert body["input"][0]["text"] == IMAGE_PROMPT and sent.max_reply_bytes == 32 * 1024 * 1024
    rec = only_call(rig)
    assert rec.state is CallState.SETTLED and 0 < rec.actual_micro < rec.reserved_micro


@pytest.mark.parametrize(("mime", "data"), [("image/jpeg", jpeg()), ("image/webp", webp())])
def test_the_other_allowed_formats_pass(rig: Rig, mime: str, data: bytes) -> None:
    rig.vendor.image, rig.vendor.mime = data, mime
    assert rig.run(image_req()).images[0].mime == mime


def refused_image(rig: Rig, result: CallResult) -> None:
    assert result.code == "vendor_refused" and result.images == () and result.text == ""
    rec = only_call(rig)
    assert rec.state is CallState.SETTLED and not rec.ambiguous and rig.ledger.view().suspended == {}
    assert rec.actual_micro > 0 and rig.ledger.view().month_spent(NOW) == rec.actual_micro  # billed, so counted
    assert result.receipt.images == ()


@pytest.mark.parametrize(
    "image",
    [
        b"not an image, just words",
        b"GIF89a" + b"\x00" * 30,
        png() + b"PK\x03\x04",
        jpeg() + b"<?php",
        png(9000, 9000),
        png(8193, 1),
        b"\x89PNG\r\n\x1a\n",
    ],
)
def test_an_image_that_fails_the_checks_is_not_handed_on_and_its_cost_is_counted(rig: Rig, image: bytes) -> None:
    rig.vendor.image = image
    refused_image(rig, rig.run(image_req()))


@pytest.mark.parametrize(
    ("mime", "data"),
    [("image/gif", png()), ("image/jpeg", png()), ("text/html", png()), ("image/png", jpeg())],
)
def test_a_type_off_the_list_or_a_type_that_lies_is_not_handed_on(
    tmp_path: Path, key: Path, mime: str, data: bytes
) -> None:
    rig = Rig(tmp_path, key)
    rig.vendor.image, rig.vendor.mime = data, mime
    refused_image(rig, rig.run(image_req()))


def test_a_reply_with_no_image_is_refused_with_its_cost_counted(rig: Rig) -> None:
    rig.vendor.part = {"type": "text", "text": "I cannot draw that"}
    result = rig.run(image_req())
    assert result.code == "vendor_refused" and result.images == ()
    assert only_call(rig).actual_micro > 0


def test_a_second_identical_part_is_dropped_the_first_kept_and_both_are_billed(rig: Rig) -> None:
    rig.vendor.mode = "duplicated_part"
    result = rig.run(image_req())
    assert result.code == "ok" and len(result.images) == 1 and result.receipt.extra_images == 1
    assert only_call(rig).actual_micro >= 2 * 33_600  # the floor counts every image item that came back


def test_more_images_than_were_approved_are_never_decoded(rig: Rig) -> None:
    rig.vendor.extra_parts = [{"type": "image", "data": "!!not base64!!", "mime_type": "image/png"}] * 3
    result = rig.run(image_req())
    assert result.code == "ok" and len(result.images) == 1 and result.receipt.extra_images == 3


@pytest.mark.parametrize(
    "part",
    [
        {"type": "image", "data": "AAAA", "mime_type": "image/png", "file_name": "../../home/x.png"},
        {"type": "image", "data": "AAAA", "mime_type": "image/png", "uri": "file:///etc/passwd"},
        {"type": "file", "path": "/etc/passwd"},
        {"type": "image", "data": "AAAA"},
    ],
)
def test_a_name_a_path_or_a_link_in_the_answer_makes_the_call_ambiguous_and_nothing_is_passed_on(
    rig: Rig, part: dict[str, Any]
) -> None:
    rig.vendor.part = part
    assert_ambiguous(rig, rig.run(image_req()), "unreadable")


def test_an_image_reply_that_goes_over_the_cap_is_a_breach_and_the_image_is_still_returned(rig: Rig) -> None:
    rig.vendor.mode = "over_cap"
    result = rig.run(image_req())
    assert result.code == "ok" and len(result.images) == 1 and result.receipt.cap_breach
    assert only_call(rig).state is CallState.SUSPENDED


def test_an_oversized_image_body_is_ambiguous_because_the_request_left(rig: Rig) -> None:
    rig.vendor.mode = "oversized"
    assert_ambiguous(rig, rig.run(image_req()), "unreadable")


def test_an_image_approval_for_one_size_cannot_be_used_for_another(rig: Rig) -> None:
    req = image_req()
    payload, signature = rig.approved(req)
    for changed in (image_req(image_size="2K"), image_req(aspect_ratio="16:9"), image_req(count=2)):
        with pytest.raises(Refused):
            rig.pipeline.call(changed, payload, signature)
    assert rig.vendor.requests == [] and rig.ledger.view().calls == {}


def test_the_dearest_listed_model_is_refused_before_anything_is_spent(rig: Rig) -> None:
    pro = image_req(model="gemini-3-pro-image", thinking_level="none")
    with pytest.raises(Refused) as err:
        rig.offer(pro)
    assert err.value.code == "model_refused" and rig.ledger.view().calls == {}
    assert pro.model != IMAGE_MODEL


# -- crash points between every step -------------------------------------------------------------------------------

BEFORE_SPEND = {"after_verify", "before_append"}
ALL_POINTS = [*PIPELINE_FAULTS, *FAULT_POINTS]
SENT_BY = {"after_send": 1, "before_settle": 1, "after_settle": 1}  # the points after which the request had left


def crash_run(tmp: Path, key: Path, point: str) -> tuple[Rig, str, str]:
    crash = CrashAt(point)
    rig = Rig(tmp, key, faults=crash if point in FAULT_POINTS else None, pipeline_faults=crash)
    req = text_req()
    payload, signature = rig.approved(req)
    with pytest.raises(Crash):
        rig.pipeline.call(req, payload, signature)
    return rig, payload, signature


@pytest.mark.parametrize("point", ALL_POINTS)
def test_a_kill_at_any_step_leaves_the_call_unspent_settled_or_ambiguous_never_free_budget(
    tmp_path: Path, key: Path, point: str
) -> None:
    rig, payload, signature = crash_run(tmp_path, key, point)
    sent_before = len(rig.vendor.requests)
    assert sent_before == SENT_BY.get(point, 0)
    rig.restart()  # a new process: recovery runs before anything is served
    view = rig.ledger.view()
    if point in BEFORE_SPEND:
        assert view.calls == {} and view.spent_nonces == frozenset() and view.month_spent(NOW) == 0
        return
    (rec,) = view.calls.values()
    if point == "after_settle":
        assert rec.state is CallState.SETTLED and not rec.ambiguous
        assert rec.actual_micro is not None and view.month_spent(NOW) == rec.actual_micro > 0
    else:
        assert rec.ambiguous and rec.state is CallState.SUSPENDED
        assert view.month_spent(NOW) == rec.reserved_micro > 0  # the whole reservation stays counted
        assert view.suspended == {FLAT: (rec.call_id,)}
    # the approval can never be used again, and no second request leaves
    with pytest.raises(Refused) as err:
        rig.pipeline.call(text_req(), payload, signature)
    assert err.value.code in ("used", "model_suspended", "bad_approval")
    assert len(rig.vendor.requests) == sent_before


@pytest.mark.parametrize(
    "point",
    ["after_append", "after_marker", "after_reserve", "after_build", "after_sent", "after_send", "before_settle"],
)
def test_recovery_after_a_kill_is_stable_when_run_twice(tmp_path: Path, key: Path, point: str) -> None:
    rig, _, _ = crash_run(tmp_path, key, point)
    rig.restart()
    first = (rig.ledger.dir / "ledger.jsonl").read_bytes()
    rig.restart()
    assert (rig.ledger.dir / "ledger.jsonl").read_bytes() == first


def test_a_kill_after_the_request_left_is_counted_at_the_reservation_even_if_the_reply_was_good(
    tmp_path: Path, key: Path
) -> None:
    rig, _, _ = crash_run(tmp_path, key, "after_send")
    assert len(rig.vendor.requests) == 1
    rig.restart()
    (rec,) = rig.ledger.view().calls.values()
    assert rig.ledger.view().month_spent(NOW) == rec.reserved_micro and rec.unresolved


def test_a_kill_before_the_spend_leaves_the_budget_untouched_and_a_fresh_approval_works(
    tmp_path: Path, key: Path
) -> None:
    rig, _, _ = crash_run(tmp_path, key, "before_append")
    rig.restart()
    assert rig.run(text_req()).code == "ok"


# -- properties ----------------------------------------------------------------------------------------------------


def test_what_is_recorded_is_never_less_than_the_reported_usage_costs(tmp_path: Path, key: Path) -> None:
    """For random reported usage, whatever the broker settles is at least the exact cost of the tokens reported (FLAT
    prices one micro-dollar per input token and ten per output token), and the month never counts less than that."""
    rig = Rig(tmp_path, key)
    rng = Rng(20261031)
    total_exact = 0
    done = 0
    for _ in range(40):
        tokens_in = rng.randrange(10, 4000)
        tokens_out = rng.choice([rng.randrange(1, 500), rng.randrange(450, 600), rng.randrange(1, 90_000)])
        rig.vendor.tokens_in, rig.vendor.tokens_out = tokens_in, tokens_out
        rig.vendor.text = "y" * rng.randrange(0, 40)
        req = text_req(prompt="p" * rng.randrange(1, 3000), max_output_tokens=rng.randrange(1, 40_000))
        try:
            result = rig.run(req)
        except Refused:
            rig.issuer.flush()
            continue
        done += 1
        exact = tokens_in + 10 * tokens_out
        if result.code == "outcome_unknown":
            assert result.receipt.actual_micro == result.receipt.reserved_micro
            exact = result.receipt.reserved_micro
        else:
            assert result.receipt.actual_micro >= exact
        total_exact += exact
        for rec in rig.ledger.view().calls.values():
            if rec.state is CallState.SUSPENDED and rec.unresolved:
                rig.ledger.resolve(rec.call_id, rec.reserved_micro, rig.clock.wall())
        if FLAT in rig.ledger.view().suspended:
            rig.ledger.clear(FLAT, rig.clock.wall())
        assert rig.ledger.view().month_spent(rig.clock.wall()) >= total_exact
        rig.issuer.flush()
    assert total_exact > 0 and done > 20


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_settle_never_records_less_than_the_actual_for_any_amount(tmp_path: Path, seed: int) -> None:
    ledger = CallLedger(tmp_path / f"s{seed}")
    ledger.open()
    rng = Rng(seed)
    for _ in range(25):
        reserved = rng.randrange(100, 9000)
        req = flat_request(reserved)
        ticket = ledger.reserve(req, approval(req), policy(), epoch=EPOCH, now=NOW)
        ledger.mark_sent(ticket.call_id, NOW)
        actual = rng.choice([0, reserved - 1, reserved, reserved + 1, rng.randrange(0, 3 * reserved)])
        before = ledger.view().month_spent(NOW)
        done = ledger.settle(ticket.call_id, "ok", actual, NOW, cap_breach=rng.choice([False, True]))
        view = ledger.view()
        rec = view.calls[ticket.call_id]
        assert rec.counted_micro == actual and view.month_spent(NOW) == before - reserved + actual
        assert done.breach == (actual > reserved or rec.breach)
        if rec.breach:
            ledger.clear(FLAT, NOW)


def test_an_ambiguous_call_always_counts_the_whole_reservation(tmp_path: Path, key: Path) -> None:
    for i, mode in enumerate(["timeout", "reset", "malformed", "slow", "oversized", "wrong_model"]):
        (tmp_path / str(i)).mkdir()
        rig = Rig(tmp_path / str(i), key)
        rig.vendor.mode = mode
        rig.vendor.body = b"{not json" if mode == "malformed" else None
        result = rig.run(text_req())
        assert result.code == "outcome_unknown"
        assert rig.ledger.view().month_spent(NOW) == only_call(rig).reserved_micro


def test_a_failure_path_never_puts_a_vendor_body_or_prompt_in_a_result_or_the_ledger(rig: Rig) -> None:
    req = text_req(prompt="SENTINEL-PROMPT")
    rig.vendor.mode = "status"
    rig.vendor.status = 500
    rig.vendor.error_body = b"SENTINEL-VENDOR-BODY SENTINEL-KEY"
    shown = repr(rig.run(req))
    assert "SENTINEL" not in shown
    ledger_text = (rig.ledger.dir / "ledger.jsonl").read_text()
    assert "SENTINEL" not in ledger_text and "go ahead" not in ledger_text


def test_only_a_call_that_returned_an_answer_can_breach_the_output_cap(tmp_path: Path) -> None:
    ledger = CallLedger(tmp_path / "state")
    ledger.open()
    req = flat_request(1000)
    ticket = ledger.reserve(req, approval(req), policy(), epoch=EPOCH, now=NOW)
    ledger.mark_sent(ticket.call_id, NOW)
    with pytest.raises(IllegalTransition, match="breach"):
        ledger.settle(ticket.call_id, "rate_limited", 0, NOW, cap_breach=True)
    assert ledger.view().calls[ticket.call_id].state is CallState.SENT
    assert ledger.settle(ticket.call_id, "ok", 10, NOW, cap_breach=True).breach


@pytest.mark.parametrize("tokens_out", [0, 1, 100, 1119])
def test_an_image_whose_reported_output_is_below_the_size_it_must_have_is_ambiguous(rig: Rig, tokens_out: int) -> None:
    """A 1K image is 1120 output tokens. A figure below that cannot be true, so the cost is not taken from it."""
    rig.vendor.tokens_out = tokens_out
    assert_ambiguous(rig, rig.run(image_req()), "usage")


def test_an_image_at_exactly_the_size_it_must_have_is_priced_from_its_usage(rig: Rig) -> None:
    rig.vendor.tokens_out = 1120
    assert rig.run(image_req()).code == "ok"


def test_a_large_image_is_not_accepted_on_the_figure_of_a_small_one(rig: Rig) -> None:
    """4K is 3780 output tokens on this model: a reply that reports the 1K figure would be recorded far too low."""
    req = image_req(image_size="4K", max_output_tokens=5000)
    rig.vendor.tokens_out = 1200
    assert_ambiguous(rig, rig.run(req), "usage")


def test_a_large_image_at_its_own_size_is_recorded_at_more_than_the_smallest_figure(tmp_path: Path, key: Path) -> None:
    rig = Rig(tmp_path, key)
    rig.vendor.tokens_out = 3780
    result = rig.run(image_req(image_size="4K", max_output_tokens=5000))
    assert result.code == "ok" and result.receipt.actual_micro >= 3780 * 30  # at the image output rate
    assert result.receipt.actual_micro > 33_600


def test_a_reply_with_no_image_is_not_held_to_an_image_size(rig: Rig) -> None:
    rig.vendor.part = {"type": "text", "text": "I cannot draw that"}
    rig.vendor.tokens_out = 5
    assert rig.run(image_req()).code == "vendor_refused"


def test_a_lone_surrogate_in_the_answer_text_makes_the_call_ambiguous(rig: Rig) -> None:
    rig.vendor.body = (
        b'{"modelVersion":"flat-test","candidates":[{"content":{"parts":[{"text":"\\ud800 abc"}]}}],'
        b'"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5}}'
    )
    assert_ambiguous(rig, rig.run(text_req()), "unreadable")


@pytest.mark.parametrize(
    "length",
    [
        pytest.param("9" * 5000, id="5000-digits"),
        pytest.param("9" * 13, id="13-digits"),
        pytest.param("1" + "0" * 40, id="41-digits"),
    ],
)
def test_a_content_length_with_an_absurd_number_of_digits_makes_the_call_ambiguous(rig: Rig, length: str) -> None:
    rig.vendor.headers = {"Content-Length": length}
    assert_ambiguous(rig, rig.run(text_req()), "unreadable")


def test_anything_that_goes_wrong_while_reading_the_answer_makes_the_call_ambiguous_not_open(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: Any) -> Any:
        raise RuntimeError("a parser bug")

    monkeypatch.setattr("safo.broker.pipeline.parse_reply", broken)
    assert_ambiguous(rig, rig.run(text_req()), "unreadable")
    assert rig.ledger.view().suspended != {}


def test_an_error_after_the_call_is_settled_does_not_turn_it_into_an_ambiguous_one(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: Any, **__: Any) -> Any:
        raise RuntimeError("receipt bug")

    monkeypatch.setattr(pipeline_module.Pipeline, "_receipt", broken)
    with pytest.raises(RuntimeError, match="receipt bug"):
        rig.run(text_req())
    rec = only_call(rig)
    assert rec.state is CallState.SETTLED and not rec.ambiguous and rec.actual_micro is not None
