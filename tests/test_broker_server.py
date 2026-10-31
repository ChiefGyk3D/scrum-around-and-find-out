# SPDX-License-Identifier: Apache-2.0
"""The broker socket server against the fake vendor: operations, refusals that change nothing, deadlines, peers,
bounds, shutdown. Sockets are socketpairs and a temporary unix socket; the clock is injected; nothing is timed."""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import logging
import os
import signal
import socket
import threading
from pathlib import Path
from typing import Any

import pytest

from brokerdata import Crash, CrashAt
from fakevendor import jpeg, png
from geminidata import make_key
from pipedata import Rig, image_req, text_req
from safo import geminisign
from safo.broker import protocol
from safo.broker.issue import Offer
from safo.broker.server import (
    DeadlineExceeded,
    PeerCred,
    RateLimiter,
    ServerConfig,
    install_signal_handlers,
    peer_credentials,
)
from safo.broker.states import CallState
from serverdata import CRED, UID, Env, FakeConn, call_fields, exchange, split_frames, state_snapshot


@pytest.fixture(scope="module")
def key(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_key(tmp_path_factory.mktemp("keys") / "a")


@pytest.fixture
def rig(tmp_path: Path, key: Path) -> Rig:
    return Rig(tmp_path, key)


@pytest.fixture
def env(rig: Rig) -> Env:
    return Env(rig)


def later(rig: Rig, seconds: float) -> None:
    """Move both fake clocks (the wall clock stamps the ledger; the monotonic one drives deadlines and limits)."""
    rig.clock.at += dt.timedelta(seconds=seconds)
    rig.clock.advance(seconds)


def rows(rig: Rig) -> list[dict[str, Any]]:
    text = (rig.ledger.dir / "ledger.jsonl").read_text()
    return [json.loads(x) for x in text.splitlines()]


def only_call(rig: Rig) -> Any:
    (rec,) = rig.ledger.view().calls.values()
    return rec


# -- the operations ------------------------------------------------------------------------------------------------


def test_status_reports_the_state_and_spends_nothing(env: Env) -> None:
    before = state_snapshot(env.rig)
    res = env.ask("status")
    assert res.code == "ok" and len(res.frames) == 1
    data = res.json
    assert data["enabled"] is True and data["key_loaded"] is True
    assert data["epoch"] == env.rig.pipeline.epoch and data["suspended"] == []
    assert data["month_spent"] == "0" and data["month_cap"] == "10" and data["block"] == "2"
    assert data["prices_valid_through"] == "2026-10-29"  # the earliest in the table (the stale test model)
    assert data["ledger_head"] == env.rig.ledger.view().head and "0 of 10 USD" in data["line"]
    assert state_snapshot(env.rig) == before


def test_status_answers_while_disabled_and_says_so(env: Env) -> None:
    env.enabled = False
    env.key_loaded = False
    data = env.ask("status").json
    assert data["ok"] is True and data["enabled"] is False and data["key_loaded"] is False


def test_a_key_check_that_raises_is_not_loaded(env: Env) -> None:
    def boom() -> bool:
        raise RuntimeError("SENTINEL-KEY")

    env.server.key_loaded = boom
    res = env.ask("status")
    assert res.json["key_loaded"] is False and b"SENTINEL" not in res.raw


def test_status_lists_suspended_models(env: Env) -> None:
    env.rig.vendor.mode = "timeout"
    env.call(text_req())
    assert env.ask("status").json["suspended"] == [text_req().model]
    assert "0 of 10" not in env.ask("status").json["line"]


@pytest.mark.parametrize(
    ("op", "fields"),
    [
        (
            "begin",
            {
                "model": "flat-test",
                "job": "j",
                "kind": "text",
                "max_output_tokens": 5,
                "prompt_bytes": 5,
                "max_usd": "2",
            },
        ),
        ("check", {"nonce": "0123456789abcdef"}),
    ],
)
def test_every_operation_but_status_and_dryrun_answers_disabled_and_changes_nothing(
    env: Env, op: str, fields: dict[str, Any]
) -> None:
    env.enabled = False
    before = state_snapshot(env.rig)
    res = env.ask(op, **fields)
    assert res.code == "disabled" and res.json["exit"] == 2
    assert state_snapshot(env.rig) == before


def test_a_call_while_disabled_is_refused_before_anything_is_checked(env: Env) -> None:
    payload, signature = env.rig.approved(text_req())
    env.enabled = False
    before = state_snapshot(env.rig)
    res = env.ask("call", **call_fields(text_req(), payload, signature))
    assert res.code == "disabled" and env.rig.vendor.requests == [] and state_snapshot(env.rig) == before
    env.enabled = True  # the switch is read on every request: the same approval now works
    assert env.ask("call", **call_fields(text_req(), payload, signature)).code == "ok"


def test_the_switch_is_read_on_every_request(env: Env) -> None:
    seen: list[int] = []

    def switch() -> bool:
        seen.append(1)
        return True

    env.server.switch = switch
    env.ask("check", nonce="0123456789abcdef")
    env.ask("check", nonce="0123456789abcdef")
    assert len(seen) == 2


def test_begin_issues_a_nonce_and_the_numbers_the_approval_must_carry(env: Env) -> None:
    res = env.ask(
        "begin", model="flat-test", job="job-one", kind="text", max_output_tokens=500, prompt_bytes=10, max_usd="2.5"
    )
    data = res.json
    assert res.code == "ok" and len(data["nonce"]) == 32 and data["epoch"] == env.rig.pipeline.epoch
    assert data["thinking_level"] == "none" and data["beyond_ceiling"] is False
    assert data["reserve_usd"] == "0.005074" and data["estimate_usd"]
    assert data["expires_at"] == "2026-10-30T12:10:00Z" and data["ledger_head"]
    assert (env.rig.ledger.dir / "issued" / data["nonce"]).exists()


def test_begin_refusals_come_back_as_their_codes_and_issue_nothing(env: Env) -> None:
    base = {"job": "j", "kind": "text", "max_output_tokens": 5, "prompt_bytes": 5, "max_usd": "2"}
    before = state_snapshot(env.rig)
    assert env.ask("begin", model="no-such-model", **base).code == "model_refused"
    assert env.ask("begin", **{**base, "model": "flat-test", "max_usd": "0.000001"}).code == "over_approved"
    assert env.ask("begin", **{**base, "model": "flat-test", "max_usd": "0"}).code == "bad_request"
    assert state_snapshot(env.rig) == before


def test_begin_for_an_image_model_works(env: Env) -> None:
    req = image_req()
    res = env.ask(
        "begin",
        model=req.model,
        job=req.job,
        kind="image",
        max_output_tokens=req.max_output_tokens,
        prompt_bytes=10,
        max_usd="2.5",
        count=1,
        image_size="1K",
        aspect_ratio="1:1",
    )
    assert res.code == "ok" and res.json["thinking_level"] == "minimal"


def test_a_whole_call_through_the_socket_from_begin_to_receipt(env: Env) -> None:
    req = text_req()
    begin = env.ask(
        "begin",
        model=req.model,
        job=req.job,
        kind="text",
        max_output_tokens=500,
        prompt_bytes=len(req.prompt),
        max_usd="2.5",
    ).json
    offer = Offer(
        begin["nonce"],
        begin["epoch"],
        env.rig.clock.wall(),
        begin["ledger_head"],
        0,
        0,
        begin["thinking_level"],
        begin["beyond_ceiling"],
    )
    text = env.rig.text(req, offer)
    res = env.ask("call", **call_fields(req, text, env.rig.sign(text)))
    assert res.code == "ok" and res.json["text"] == "a short answer" and res.json["attachments"] == []
    receipt = res.json["receipt"]
    assert receipt["nonce"] == begin["nonce"] and receipt["model"] == req.model and receipt["kind"] == "text"
    assert receipt["reserved_usd"] == begin["reserve_usd"] and receipt["breach"] is False
    assert receipt["estimated"] is False and receipt["broker_version"] and receipt["ts"] == "2026-10-30T12:00:00Z"
    assert receipt["month_spent_after"] == receipt["actual_usd"] and receipt["images"] == []
    assert receipt["ledger_head_after"] == env.rig.ledger.view().head
    assert only_call(env.rig).state is CallState.SETTLED and len(env.rig.vendor.requests) == 1
    assert env.ask("check", nonce=begin["nonce"]).json["state"] == "used"


def test_an_image_call_sends_the_json_then_the_image_frame(env: Env) -> None:
    env.rig.vendor.image = jpeg()
    env.rig.vendor.mime = "image/jpeg"
    res = env.call(image_req())
    assert res.code == "ok" and len(res.frames) == 2
    (described,) = res.json["attachments"]
    assert res.attachments[0] == jpeg() and described["bytes"] == len(jpeg()) and described["mime"] == "image/jpeg"
    assert described["index"] == 0 and len(described["sha256"]) == 64
    assert res.json["receipt"]["images"] == [described]
    assert protocol.attachment_count(protocol.parse_reply(res.frames[0])) == 1


def test_the_reply_is_the_json_frame_and_the_attachments_and_nothing_else(env: Env) -> None:
    res = env.call(image_req())
    assert res.raw == b"".join(protocol.HEADER.pack(len(f)) + f for f in res.frames)


def test_refusals_after_verification_come_back_as_their_codes_with_no_vendor_call(env: Env) -> None:
    req = text_req()
    payload, signature = env.rig.approved(req)
    assert env.ask("call", **call_fields(req, payload, signature)).code == "ok"
    sent = len(env.rig.vendor.requests)
    assert env.ask("call", **call_fields(req, payload, signature)).code == "used"  # replay
    other = text_req(prompt="another prompt entirely")
    p2, s2 = env.rig.approved(req)
    assert env.ask("call", **call_fields(other, p2, s2)).code in ("digest_mismatch", "bad_approval")
    assert (
        env.ask(
            "call", **call_fields(req, payload, "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n")
        ).code
        == "bad_approval"
    )
    assert len(env.rig.vendor.requests) == sent


@pytest.mark.parametrize(
    ("mode", "code", "exit_status"),
    [("timeout", "outcome_unknown", 4), ("reset", "outcome_unknown", 4), ("status", "vendor_refused", 2)],
)
def test_the_codes_a_finished_call_returns_carry_the_receipt(env: Env, mode: str, code: str, exit_status: int) -> None:
    env.rig.vendor.mode = mode
    env.rig.vendor.status = 400
    res = env.call(text_req())
    assert res.code == code and res.json["exit"] == exit_status and res.json["receipt"]["call_id"]
    assert len(env.rig.vendor.requests) == 1
    protocol.parse_reply(res.frames[0])


def test_a_vendor_429_is_final_and_carries_retry_after(env: Env) -> None:
    env.rig.vendor.mode = "status"
    env.rig.vendor.status = 429
    env.rig.vendor.headers = {"Retry-After": "30"}
    res = env.call(text_req())
    assert res.code == "rate_limited" and res.json["exit"] == 3 and res.json["retry_after"] == 30
    assert only_call(env.rig).state is CallState.SETTLED and len(env.rig.vendor.requests) == 1
    env.rig.vendor.headers = {}
    assert "retry_after" not in env.call(text_req()).json


def test_an_ambiguous_call_is_recorded_at_the_reservation_and_reported(env: Env) -> None:
    env.rig.vendor.mode = "timeout"
    res = env.call(text_req())
    rec = only_call(env.rig)
    assert rec.ambiguous and rec.reserved_micro > 0
    assert (
        res.json["receipt"]["estimated"] is True
        and res.json["receipt"]["actual_usd"] == res.json["receipt"]["reserved_usd"]
    )
    base = {"job": "j", "kind": "text", "max_output_tokens": 5, "prompt_bytes": 5, "max_usd": "2"}
    assert env.ask("begin", model=text_req().model, **base).code == "model_suspended"
    assert len(env.rig.vendor.requests) == 1


def test_check_reports_the_states(env: Env) -> None:
    offer = env.rig.offer(text_req())
    assert env.ask("check", nonce=offer.nonce).json["state"] == "live"
    assert env.ask("check", nonce="f" * 32).json["state"] == "unknown"
    later(env.rig, 3600)
    assert env.ask("check", nonce=offer.nonce).json["state"] == "expired"


# -- dryrun --------------------------------------------------------------------------------------------------------


def dry(env: Env, namespace: str = geminisign.DRYRUN_NAMESPACE, text: str = '{"dry_run":true}') -> dict[str, Any]:
    return {"payload": text, "signature": env.rig.sign(text, namespace)}


def test_dryrun_verifies_a_throwaway_signature_and_changes_nothing(env: Env) -> None:
    before = state_snapshot(env.rig)
    res = env.ask("dryrun", approval=dry(env))
    assert res.code == "ok"
    assert res.json["principal"] == "yubikey-a" and res.json["fingerprint"].startswith("SHA256:")
    assert res.json["hardware"] is False and res.json["touch"] is None and res.json["pin"] is None
    assert res.json["enabled"] is True and env.rig.vendor.requests == []
    assert state_snapshot(env.rig) == before


def test_dryrun_works_while_disabled_and_says_so(env: Env) -> None:
    env.enabled = False
    assert env.ask("dryrun", approval=dry(env)).json["enabled"] is False


def test_dryrun_refuses_a_signature_for_another_namespace(env: Env) -> None:
    assert env.ask("dryrun", approval=dry(env, geminisign.NAMESPACE)).code == "bad_approval"
    text = env.rig.text(text_req(), env.rig.offer(text_req()))
    real = {"payload": text, "signature": env.rig.sign(text)}
    assert env.ask("dryrun", approval=real).code == "bad_approval"


def test_dryrun_refuses_a_revoked_key(env: Env) -> None:
    approval = dry(env)
    (enrolled,) = geminisign.load_roster(env.rig.trust).keys
    env.rig.revoked.write_text(enrolled.fingerprint + "\n")
    assert env.ask("dryrun", approval=approval).code == "revoked"


# -- malformed requests change nothing -----------------------------------------------------------------------------


def good_begin() -> bytes:
    return protocol.request_body(
        "begin", model="flat-test", job="j", kind="text", max_output_tokens=5, prompt_bytes=5, max_usd="2"
    )


def frame_of(body: bytes) -> bytes:
    return protocol.HEADER.pack(len(body)) + body


@pytest.mark.parametrize(
    ("name", "raw", "code"),
    [
        ("not json", frame_of(b"nope"), "bad_request"),
        ("an array", frame_of(b"[1]"), "bad_request"),
        ("a duplicate key", frame_of(b'{"v":1,"op":"status","op":"status"}'), "bad_request"),
        ("wrong version", frame_of(b'{"v":2,"op":"status"}'), "unsupported_version"),
        ("unknown action", frame_of(b'{"v":1,"op":"clear"}'), "bad_request"),
        ("an unknown key", frame_of(b'{"v":1,"op":"status","x":1}'), "bad_request"),
        ("a zero length", b"\x00\x00\x00\x00", "bad_request"),
        ("an oversize declaration", protocol.HEADER.pack(protocol.MAX_REQUEST_FRAME + 1) + b"x" * 64, "too_large"),
        ("four gigabytes", b"\xff\xff\xff\xff", "too_large"),
        ("a short header", b"\x00\x00", "bad_request"),
        ("a short body", protocol.HEADER.pack(50) + b'{"v":1', "bad_request"),
        ("nothing", b"", "bad_request"),
    ],
)
def test_a_malformed_request_gets_a_fixed_reply_and_changes_nothing(env: Env, name: str, raw: bytes, code: str) -> None:
    before = state_snapshot(env.rig)
    res = env.exchange(raw=raw)
    assert res.code == code, name
    assert res.json["message"] == protocol.REPLY_CODES[code][1]
    assert env.rig.vendor.requests == [] and state_snapshot(env.rig) == before


def test_an_unsupported_version_reply_lists_the_supported_ones(env: Env) -> None:
    assert env.exchange(raw=frame_of(b'{"v":2,"op":"status"}')).json["supported"] == [1]


def test_a_second_frame_after_the_request_is_not_served(env: Env) -> None:
    res = env.exchange(raw=frame_of(b'{"v":1,"op":"status"}') + frame_of(good_begin()))
    assert res.code == "ok" and len(res.frames) == 1
    assert state_snapshot(env.rig)[1] == []  # the begin that followed was never read


def test_the_server_leaves_the_body_of_an_oversize_declaration_unread(env: Env) -> None:
    conn = FakeConn(env.rig.clock, [protocol.HEADER.pack(protocol.MAX_REQUEST_FRAME + 1), b"x" * 100])
    unread: list[int] = []
    conn.on_send = lambda: unread.append(len(conn.script))
    env.server.handle_connection(conn, CRED)  # type: ignore[arg-type]  # a scripted stand-in for a socket
    assert conn.closed and unread == [1]  # when the answer went out, the 100 bytes had not been taken
    assert json.loads(split_frames(bytes(conn.sent))[0])["code"] == "too_large"


# -- deadlines -----------------------------------------------------------------------------------------------------


def serve_fake(env: Env, conn: FakeConn) -> None:
    env.server.handle_connection(conn, CRED)  # type: ignore[arg-type]  # a scripted stand-in for a socket


def test_a_slow_loris_is_dropped_at_the_whole_frame_deadline(env: Env) -> None:
    frame = protocol.frame(b'{"v":1,"op":"status"}', protocol.MAX_REQUEST_FRAME)
    conn = FakeConn(env.rig.clock, [frame[i : i + 1] for i in range(len(frame))], tick=2.0)
    before = state_snapshot(env.rig)
    serve_fake(env, conn)
    assert conn.closed and bytes(conn.sent) == b"" and conn.script  # dropped with the rest of the bytes unread
    assert len(conn.script) > len(frame) - 6  # only a few one-byte reads got through
    assert state_snapshot(env.rig) == before


def test_each_read_is_given_only_the_time_left(env: Env) -> None:
    frame = protocol.frame(b'{"v":1,"op":"status"}', protocol.MAX_REQUEST_FRAME)
    conn = FakeConn(env.rig.clock, [frame[:3], frame[3:]], tick=1.0)
    serve_fake(env, conn)
    assert conn.timeouts[:2] == [5.0, 4.0]
    assert json.loads(split_frames(bytes(conn.sent))[0])["ok"] is True


def test_a_peer_that_sends_nothing_is_dropped_by_its_read_timeout(env: Env) -> None:
    conn = FakeConn(env.rig.clock, [TimeoutError()])
    serve_fake(env, conn)
    assert conn.closed and bytes(conn.sent) == b""


def test_a_peer_that_connects_and_resets_is_dropped(env: Env) -> None:
    conn = FakeConn(env.rig.clock, [ConnectionResetError()])
    serve_fake(env, conn)
    assert conn.closed and bytes(conn.sent) == b""


def test_a_deadline_already_gone_means_no_read_at_all(env: Env) -> None:
    conn = FakeConn(env.rig.clock, [b"\x00\x00\x00\x05"])
    env.rig.clock.advance(0)
    env.server.cfg = ServerConfig(allowed_uids=frozenset({UID}), read_deadline=0.001)
    env.rig.clock.advance(1000)  # the clock the server reads is the rig's; it jumps before the first read
    start = env.rig.clock.mono

    class Jump:
        def __call__(self) -> float:
            return start() + (0 if not conn.timeouts else 1000)

    env.server.mono = Jump()
    serve_fake(env, conn)
    assert conn.closed and bytes(conn.sent) == b""


def test_a_reply_write_that_makes_no_progress_is_dropped(env: Env) -> None:
    frame = protocol.frame(b'{"v":1,"op":"status"}', protocol.MAX_REQUEST_FRAME)
    conn = FakeConn(env.rig.clock, [frame])
    conn.send_error = TimeoutError()
    serve_fake(env, conn)
    assert conn.closed and bytes(conn.sent) == b""


def test_a_reader_that_takes_one_byte_at_a_time_is_dropped_at_the_whole_frame_deadline(env: Env) -> None:
    frame = protocol.frame(b'{"v":1,"op":"status"}', protocol.MAX_REQUEST_FRAME)
    conn = FakeConn(env.rig.clock, [frame])
    conn.send_limit = 1
    conn.tick = 1.0  # each send moves the clock a second: 5 seconds for the whole JSON frame
    env.server.cfg = ServerConfig(allowed_uids=frozenset({UID}))
    serve_fake(env, conn)
    assert 0 < len(conn.sent) < 5 + 2 and conn.closed  # a handful of bytes, then the frame deadline


def test_an_attachment_is_written_in_pieces_each_under_the_progress_deadline(env: Env) -> None:
    env.rig.vendor.image = png()
    req = image_req()
    payload, signature = env.rig.approved(req)
    body = protocol.request_body("call", **call_fields(req, payload, signature))
    conn = FakeConn(env.rig.clock, [protocol.frame(body, protocol.MAX_REQUEST_FRAME)])
    serve_fake(env, conn)
    frames = split_frames(bytes(conn.sent))
    assert len(frames) == 2 and frames[1] == png()
    assert 10.0 in conn.timeouts  # an attachment write may take 10 seconds to make progress; the JSON frame 5


def test_an_attachment_that_stalls_is_dropped_and_the_call_is_already_settled(env: Env) -> None:
    req = image_req()
    payload, signature = env.rig.approved(req)
    body = protocol.request_body("call", **call_fields(req, payload, signature))
    conn = FakeConn(env.rig.clock, [protocol.frame(body, protocol.MAX_REQUEST_FRAME)])
    sends: list[int] = []

    def stall() -> None:
        sends.append(1)
        if len(sends) == 2:  # the first send is the JSON frame; the second the attachment header
            raise TimeoutError

    conn.on_send = stall
    serve_fake(env, conn)
    assert len(split_frames(bytes(conn.sent))) == 1 and conn.closed
    assert only_call(env.rig).state is CallState.SETTLED and env.server.calls_in_flight == 0


# -- the paid-call slot --------------------------------------------------------------------------------------------


def test_a_second_call_while_one_is_in_flight_is_busy_not_queued(env: Env) -> None:
    second: list[Any] = []

    def during(_: Any) -> None:
        second.append(env.call(text_req(job="job-two")))

    env.rig.vendor.on_send = during
    first = env.call(text_req())
    assert first.code == "ok" and second[0].code == "busy" and second[0].json["exit"] == 2
    assert len(env.rig.vendor.requests) == 1 and len(env.rig.ledger.view().calls) == 1


def test_two_calls_run_together_when_the_config_allows_two(rig: Rig) -> None:
    env = Env(rig, max_concurrent_calls=2)
    second: list[Any] = []
    started: list[int] = []

    def during(_: Any) -> None:
        if not started:  # only the first request starts the second call
            started.append(1)
            second.append(env.call(text_req(job="job-two")))

    rig.vendor.on_send = during
    first = env.call(text_req())
    assert first.code == "ok" and second[0].code == "ok" and len(rig.vendor.requests) == 2


def test_the_slot_is_free_before_the_reply_is_written(env: Env) -> None:
    req = text_req()
    payload, signature = env.rig.approved(req)
    body = protocol.request_body("call", **call_fields(req, payload, signature))
    conn = FakeConn(env.rig.clock, [protocol.frame(body, protocol.MAX_REQUEST_FRAME)])
    seen: list[int] = []
    conn.on_send = lambda: seen.append(env.server.calls_in_flight)
    serve_fake(env, conn)
    assert seen == [0]
    assert json.loads(split_frames(bytes(conn.sent))[0])["ok"] is True


def test_the_slot_is_released_after_a_refusal_and_after_a_crash(rig: Rig) -> None:
    env = Env(rig)
    payload, signature = rig.approved(text_req())
    bad = call_fields(text_req(), payload, signature)
    bad["approval"]["signature"] = "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"
    assert env.ask("call", **bad).code == "bad_approval" and env.server.calls_in_flight == 0
    assert env.call(text_req()).code == "ok"  # the slot was free again
    rig.pipeline.faults = CrashAt("after_reserve")
    with pytest.raises(Crash):
        raise_from_thread(env, rig)
    assert env.server.calls_in_flight == 0
    rig.pipeline.faults = lambda point: None


def raise_from_thread(env: Env, rig: Rig) -> None:
    """Run one call whose pipeline is killed with a BaseException; re-raise it here."""
    req = text_req(job="job-crash")
    payload, signature = rig.approved(req)
    body = protocol.request_body("call", **call_fields(req, payload, signature))
    conn = FakeConn(rig.clock, [protocol.frame(body, protocol.MAX_REQUEST_FRAME)])
    env.server.handle_connection(conn, CRED)  # type: ignore[arg-type]  # a scripted stand-in for a socket


def test_a_call_killed_after_the_spend_ends_ambiguous_at_the_next_start(rig: Rig) -> None:
    env = Env(rig)
    rig.pipeline.faults = CrashAt("after_build")
    with pytest.raises(Crash):
        raise_from_thread(env, rig)
    assert only_call(rig).state is CallState.RESERVED
    rig.restart()
    rec = only_call(rig)
    assert rec.ambiguous and rec.unresolved and rig.ledger.view().month_spent(rig.clock.wall()) == rec.reserved_micro
    assert rig.ledger.view().suspended


def test_the_call_budget_per_minute_and_per_day_comes_from_the_ledger(rig: Rig) -> None:
    env = Env(rig, max_calls_per_minute=1, max_calls_per_day=2)
    assert env.call(text_req()).code == "ok"
    assert env.call(text_req(job="job-b")).code == "busy"  # one a minute
    later(rig, 61)
    assert env.call(text_req(job="job-c")).code == "ok"
    later(rig, 61)
    assert env.call(text_req(job="job-d")).code == "busy"  # two a day
    later(rig, 86_400)
    assert env.call(text_req(job="job-e")).code == "ok"
    assert len(rig.vendor.requests) == 3


# -- rate limits ---------------------------------------------------------------------------------------------------


def test_the_rate_limiter_counts_per_peer_and_per_bucket_in_a_sliding_window() -> None:
    now = [0.0]
    limiter = RateLimiter(lambda: now[0], 60.0)
    assert [limiter.allow(1, "a", 2) for _ in range(3)] == [True, True, False]
    assert limiter.allow(2, "a", 2) and limiter.allow(1, "b", 2)
    now[0] = 59.9
    assert limiter.allow(1, "a", 2) is False
    now[0] = 60.0
    assert limiter.allow(1, "a", 2) is True


def test_begin_is_limited_per_minute_and_a_refusal_changes_nothing(env: Env) -> None:
    fields = {
        "model": "flat-test",
        "job": "j",
        "kind": "text",
        "max_output_tokens": 5,
        "prompt_bytes": 5,
        "max_usd": "2",
    }
    codes = [env.ask("begin", **fields).code for _ in range(7)]
    assert codes == ["ok"] * 4 + ["busy"] * 3  # the 4 outstanding nonces stop it first, then the 6 a minute
    assert len(list((env.rig.ledger.dir / "issued").iterdir())) == 4


def test_the_begin_limit_alone_is_six_a_minute(rig: Rig) -> None:
    env = Env(rig, begin_per_minute=2)
    fields = {
        "model": "flat-test",
        "job": "j",
        "kind": "text",
        "max_output_tokens": 5,
        "prompt_bytes": 5,
        "max_usd": "2",
    }
    assert [env.ask("begin", **fields).code for _ in range(3)] == ["ok", "ok", "busy"]
    rig.clock.advance(61)
    assert env.ask("begin", **fields).code == "ok"


def test_call_attempts_are_limited_even_when_they_fail(rig: Rig) -> None:
    env = Env(rig, call_per_minute=2)
    req = text_req()
    payload, _ = rig.approved(req)
    bad = call_fields(req, payload, "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n")
    assert [env.ask("call", **bad).code for _ in range(3)] == ["bad_approval", "bad_approval", "busy"]


def test_status_and_check_and_dryrun_are_limited_too(rig: Rig) -> None:
    env = Env(rig, other_per_minute=2)
    assert [env.ask("status").code for _ in range(3)] == ["ok", "ok", "busy"]
    assert env.ask("check", nonce="0123456789abcdef").code == "ok"  # its own bucket
    assert env.ask("dryrun", approval=dry(env)).code == "ok"


# -- peers and bounds ----------------------------------------------------------------------------------------------


def unix_server(tmp_path: Path, env: Env, **kw: Any) -> tuple[socket.socket, threading.Thread, list[int]]:
    path = str(tmp_path / "s.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(16)
    result: list[int] = []
    thread = threading.Thread(target=lambda: result.append(env.server.serve(listener)))
    thread.start()
    return listener, thread, result


def connect(tmp_path: Path) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(str(tmp_path / "s.sock"))
    return sock


def read_all(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        try:
            chunk = sock.recv(1 << 20)
        except ConnectionResetError:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def test_real_peer_credentials_are_this_process_on_a_unix_socket() -> None:
    a, b = socket.socketpair()
    cred = peer_credentials(a)
    assert (cred.uid, cred.gid, cred.pid) == (os.getuid(), os.getgid(), os.getpid())
    a.close()
    b.close()


def test_peer_credentials_need_a_unix_socket() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock, pytest.raises(OSError):
        peer_credentials(sock)


def test_a_peer_with_the_wrong_uid_is_refused_and_nothing_is_read(tmp_path: Path, env: Env) -> None:
    env.server.peer_cred = lambda sock: PeerCred(1, UID + 1, 1)
    listener, thread, _ = unix_server(tmp_path, env)
    before = state_snapshot(env.rig)
    client = connect(tmp_path)
    reply = read_all(client)  # the server answers and closes before we send a byte
    client.close()
    env.server.stop()
    thread.join()
    listener.close()
    frames = split_frames(reply)
    assert json.loads(frames[0])["code"] == "unauthorized_peer" and len(frames) == 1
    assert state_snapshot(env.rig) == before and env.rig.vendor.requests == []


def test_a_peer_whose_credentials_cannot_be_read_is_closed_without_a_reply(tmp_path: Path, env: Env) -> None:
    def broken(sock: socket.socket) -> PeerCred:
        raise OSError("no credentials SENTINEL")

    env.server.peer_cred = broken
    listener, thread, _ = unix_server(tmp_path, env)
    client = connect(tmp_path)
    assert read_all(client) == b""
    client.close()
    env.server.stop()
    thread.join()
    listener.close()


def test_the_wrong_uid_gets_no_work_done_even_with_a_valid_call(tmp_path: Path, env: Env) -> None:
    payload, signature = env.rig.approved(text_req())
    env.server.peer_cred = lambda sock: PeerCred(1, 0, 0)
    listener, thread, _ = unix_server(tmp_path, env)
    client = connect(tmp_path)
    assert json.loads(split_frames(read_all(client))[0])["code"] == "unauthorized_peer"
    body = protocol.request_body("call", **call_fields(text_req(), payload, signature))
    with contextlib.suppress(OSError):
        client.sendall(protocol.frame(body, protocol.MAX_REQUEST_FRAME))  # too late: nobody is reading
    client.close()
    env.server.stop()
    thread.join()
    listener.close()
    assert env.rig.vendor.requests == [] and env.rig.ledger.view().calls == {}


def test_a_ninth_connection_and_a_third_from_one_uid_are_closed_unread(tmp_path: Path, rig: Rig) -> None:
    env = Env(rig, allowed_uids=frozenset(range(100, 120)))
    uids = iter(range(100, 120))
    env.server.peer_cred = lambda sock: PeerCred(1, next(uids), 1)
    listener, thread, _ = unix_server(tmp_path, env)
    held = [connect(tmp_path) for _ in range(8)]  # eight distinct uids, all silent
    ninth = connect(tmp_path)
    assert read_all(ninth) == b""  # closed at once, unread
    ninth.close()
    assert env.server.peak_open == 8 and env.server.open_connections == 8
    for sock in held:
        sock.close()
    env.server.stop()
    thread.join()
    listener.close()


def test_a_third_connection_from_one_uid_is_closed_unread(tmp_path: Path, env: Env) -> None:
    listener, thread, _ = unix_server(tmp_path, env)
    held = [connect(tmp_path) for _ in range(2)]
    third = connect(tmp_path)
    assert read_all(third) == b""
    third.close()
    assert env.server.peak_open == 2
    for sock in held:
        sock.close()
    env.server.stop()
    thread.join()
    listener.close()


def test_counts_return_to_zero_and_a_new_connection_is_served_after_the_old_ones_close(
    tmp_path: Path, env: Env
) -> None:
    listener, thread, _ = unix_server(tmp_path, env)
    for _ in range(6):  # more than the per-uid cap, one after another
        client = connect(tmp_path)
        client.sendall(protocol.frame(protocol.request_body("status"), protocol.MAX_REQUEST_FRAME))
        client.shutdown(socket.SHUT_WR)
        assert json.loads(split_frames(read_all(client))[0])["ok"] is True
        client.close()
    env.server.stop()
    thread.join()
    listener.close()
    assert env.server.open_connections == 0


def test_many_clients_at_once_each_get_a_reply_or_a_clean_close(tmp_path: Path, rig: Rig) -> None:
    env = Env(rig, allowed_uids=frozenset(range(1000, 1100)), max_per_uid=64, max_connections=8)
    counter = iter(range(1000, 1100))
    lock = threading.Lock()

    def cred(sock: socket.socket) -> PeerCred:
        with lock:
            return PeerCred(1, next(counter), 1)

    env.server.peer_cred = cred
    listener, thread, _ = unix_server(tmp_path, env)
    outcomes: list[str] = []

    def client() -> None:
        sock = connect(tmp_path)
        try:
            sock.sendall(protocol.frame(protocol.request_body("status"), protocol.MAX_REQUEST_FRAME))
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        data = read_all(sock)
        sock.close()
        outcomes.append("ok" if data and json.loads(split_frames(data)[0])["ok"] else "closed")

    workers = [threading.Thread(target=client) for _ in range(40)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    env.server.stop()
    thread.join()
    listener.close()
    assert len(outcomes) == 40 and "ok" in outcomes and env.server.peak_open <= 8
    assert env.server.open_connections == 0 and state_snapshot(rig)[1] == []


# -- replies never exceed the frame --------------------------------------------------------------------------------


def test_an_answer_too_big_for_the_reply_frame_is_reported_internal_with_the_receipt(rig: Rig) -> None:
    env = Env(rig)
    rig.vendor.text = "é" * 60_000  # 120,000 bytes of UTF-8, 360,000 once escaped
    res = env.call(text_req(max_output_tokens=200_000))
    assert res.code == "internal" and res.json["exit"] == 4 and res.json["receipt"]["reserved_usd"]
    assert len(res.frames[0]) <= protocol.MAX_REPLY_FRAME and len(res.frames) == 1
    assert only_call(rig).state is CallState.SETTLED  # it was paid for and recorded
    rig.vendor.text = "e" * 100_000
    ok = env.call(text_req(max_output_tokens=200_000, job="job-two"))
    assert ok.code == "ok" and len(ok.json["text"]) == 100_000 and len(ok.frames[0]) <= protocol.MAX_REPLY_FRAME


def test_no_reply_frame_ever_exceeds_the_limit(env: Env) -> None:
    replies = [
        env.exchange(raw=b"\xff\xff\xff\xff"),
        env.ask("status"),
        env.exchange(raw=frame_of(b"x" * 1000)),
        env.call(text_req()),
        env.call(image_req()),
    ]
    for res in replies:
        assert res.frames and len(res.frames[0]) <= protocol.MAX_REPLY_FRAME
        protocol.parse_reply(res.frames[0])


# -- a connection reset mid-call -----------------------------------------------------------------------------------


def test_a_client_that_leaves_during_the_vendor_call_still_has_the_call_recorded(env: Env) -> None:
    req = text_req()
    payload, signature = env.rig.approved(req)
    body = protocol.request_body("call", **call_fields(req, payload, signature))

    def leave(client: socket.socket) -> None:
        env.rig.vendor.on_send = lambda _: client.shutdown(socket.SHUT_RDWR)

    res = exchange(env.server, body, before=leave, half_close=False)
    assert res.frames == []  # nobody was listening
    rec = only_call(env.rig)
    assert rec.state is CallState.SETTLED and env.server.calls_in_flight == 0 and len(env.rig.vendor.requests) == 1


def test_a_vendor_connection_reset_mid_call_is_recorded_ambiguous_and_reported(env: Env) -> None:
    env.rig.vendor.mode = "reset"
    res = env.call(text_req())
    rec = only_call(env.rig)
    assert res.code == "outcome_unknown" and rec.ambiguous and rec.state is CallState.SUSPENDED
    assert env.rig.ledger.view().suspended == {text_req().model: (rec.call_id,)}


def test_a_ledger_that_cannot_record_the_answer_is_reported_internal_and_keeps_the_reservation(env: Env) -> None:
    def refuse(*args: Any, **kwargs: Any) -> None:
        raise OSError("SENTINEL disk gone")

    env.rig.ledger.settle = refuse  # type: ignore[method-assign,assignment]  # the failure to inject
    res = env.call(text_req())
    assert res.code == "internal" and b"SENTINEL" not in res.raw
    rec = only_call(env.rig)
    assert rec.ambiguous and env.rig.ledger.view().month_spent(env.rig.clock.wall()) == rec.reserved_micro


# -- shutdown ------------------------------------------------------------------------------------------------------


def test_stop_before_serve_returns_at_once_with_nothing_abandoned(env: Env, tmp_path: Path) -> None:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(tmp_path / "s.sock"))
    listener.listen(1)
    env.server.stop()
    assert env.server.serve(listener) == 0
    assert listener.fileno() != -1  # the listener belongs to systemd: not closed here
    listener.close()


def test_a_stop_mid_call_lets_the_call_finish_and_answer(tmp_path: Path, env: Env) -> None:
    env.rig.vendor.on_send = lambda _: env.server.stop()
    listener, thread, result = unix_server(tmp_path, env)
    req = text_req()
    payload, signature = env.rig.approved(req)
    client = connect(tmp_path)
    client.sendall(
        protocol.frame(
            protocol.request_body("call", **call_fields(req, payload, signature)), protocol.MAX_REQUEST_FRAME
        )
    )
    reply = read_all(client)
    client.close()
    thread.join()
    listener.close()
    assert json.loads(split_frames(reply)[0])["ok"] is True and result == [0]
    assert only_call(env.rig).state is CallState.SETTLED


def test_a_stopped_server_accepts_no_new_connection(tmp_path: Path, env: Env) -> None:
    listener, thread, _ = unix_server(tmp_path, env)
    env.server.stop()
    thread.join()
    late = connect(tmp_path)  # the kernel queues it; nobody serves it
    late.settimeout(0.2)
    with pytest.raises(TimeoutError):
        late.recv(1)
    late.close()
    listener.close()


def test_a_call_still_open_when_the_grace_runs_out_ends_ambiguous_never_free(tmp_path: Path, rig: Rig) -> None:
    env = Env(rig, grace_seconds=0.0)
    release = threading.Event()
    entered = threading.Event()

    def hang(_: Any) -> None:
        entered.set()
        release.wait(30)

    rig.vendor.on_send = hang
    listener, thread, result = unix_server(tmp_path, env)
    req = text_req()
    payload, signature = rig.approved(req)
    client = connect(tmp_path)
    client.sendall(
        protocol.frame(
            protocol.request_body("call", **call_fields(req, payload, signature)), protocol.MAX_REQUEST_FRAME
        )
    )
    assert entered.wait(30)
    env.server.stop()
    thread.join()  # serve returns although the call is still in flight
    assert result == [1]
    rec = only_call(rig)
    assert rec.ambiguous and rec.unresolved and rec.state is CallState.SUSPENDED
    assert rig.ledger.view().month_spent(rig.clock.wall()) == rec.reserved_micro
    release.set()  # the vendor answers late: the settle is refused, the reservation stays counted
    reply = read_all(client)
    client.close()
    listener.close()
    assert json.loads(split_frames(reply)[0])["code"] == "internal"
    rec = only_call(rig)
    assert rec.ambiguous and rec.unresolved and rig.ledger.view().month_spent(rig.clock.wall()) == rec.reserved_micro
    assert [r["type"] for r in rows(rig)].count("call_end") == 0


def test_a_real_sigterm_during_a_call_stops_the_server_after_the_call_settles(tmp_path: Path, env: Env) -> None:
    restore = install_signal_handlers(env.server, (signal.SIGTERM,))
    try:
        env.rig.vendor.on_send = lambda _: os.kill(os.getpid(), signal.SIGTERM)
        listener, thread, result = unix_server(tmp_path, env)
        req = text_req()
        payload, signature = env.rig.approved(req)
        client = connect(tmp_path)
        client.sendall(
            protocol.frame(
                protocol.request_body("call", **call_fields(req, payload, signature)), protocol.MAX_REQUEST_FRAME
            )
        )
        reply = read_all(client)
        client.close()
        thread.join()
        listener.close()
    finally:
        restore()
    assert json.loads(split_frames(reply)[0])["ok"] is True and result == [0]
    assert only_call(env.rig).state is CallState.SETTLED
    assert signal.getsignal(signal.SIGTERM) in (signal.SIG_DFL, signal.default_int_handler) or callable(
        signal.getsignal(signal.SIGTERM)
    )


def test_signal_handlers_are_put_back(env: Env) -> None:
    before = signal.getsignal(signal.SIGUSR1)
    restore = install_signal_handlers(env.server, (signal.SIGUSR1,))
    assert signal.getsignal(signal.SIGUSR1) is not before
    restore()
    assert signal.getsignal(signal.SIGUSR1) is before


# -- the log -------------------------------------------------------------------------------------------------------


def test_no_failure_path_logs_client_text_or_secrets(env: Env, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    sentinel = "SENTINELPROMPTTEXT"
    req = text_req(prompt=sentinel + " quote", job="SENTINELJOB")
    payload, signature = env.rig.approved(req)
    bad_sig = "-----BEGIN SSH SIGNATURE-----\nSENTINELSIG\n-----END SSH SIGNATURE-----\n"
    env.rig.vendor.mode = "status"
    env.rig.vendor.status = 400
    env.rig.vendor.error_body = b"SENTINELVENDORBODY"
    env.exchange(raw=frame_of(b'{"v":1,"op":"SENTINELOP"}'))
    env.exchange(raw=frame_of(b'{"v":1,"op":"status","SENTINELKEY":"SENTINELVALUE"}'))
    env.ask("call", **call_fields(req, payload, bad_sig))
    env.ask("check", nonce="abcdef0123456789")
    env.enabled = False
    env.ask("call", **call_fields(req, payload, signature))
    env.enabled = True
    env.call(req)
    env.rig.pipeline.faults = lambda point: (_ for _ in ()).throw(RuntimeError("SENTINELEXC"))
    env.call(text_req(prompt=sentinel, job="SENTINELJOB2"))
    text = "\n".join(r.getMessage() for r in caplog.records if r.name == "safo.broker")
    assert text and "SENTINEL" not in text and "quote" not in text
    assert "op=call" in text and "code=" in text and "uid=1000" in text and "RuntimeError" in text


def test_the_log_takes_only_allowlisted_fields_and_plain_values(caplog: pytest.LogCaptureFixture) -> None:
    from safo.broker.server import AuditLog

    caplog.set_level(logging.INFO)
    AuditLog().event(
        "done", op="call", code="bad text", uid=5, model="a b", prompt="SECRET", nonce8="deadbeef", ok=True
    )
    (line,) = [r.getMessage() for r in caplog.records]
    assert line == "done op=call code=? uid=5 model=?  nonce8=deadbeef".replace("  ", " ")
    assert "SECRET" not in line


def test_a_deadline_is_its_own_exception() -> None:
    assert issubclass(DeadlineExceeded, Exception) and not issubclass(DeadlineExceeded, OSError)


def test_serverconfig_defaults_are_the_design_numbers() -> None:
    cfg = ServerConfig(allowed_uids=frozenset({1}))
    assert (cfg.max_connections, cfg.max_per_uid, cfg.read_deadline, cfg.write_json_deadline) == (8, 2, 5.0, 5.0)
    assert (cfg.write_progress, cfg.write_frame_total, cfg.max_concurrent_calls) == (10.0, 60.0, 1)
    assert (cfg.begin_per_minute, cfg.call_per_minute) == (6, 10)
    assert (cfg.max_calls_per_minute, cfg.max_calls_per_day) == (5, 20)
    assert dt.timedelta(seconds=cfg.grace_seconds) > dt.timedelta(seconds=120)  # more than a slow image call
