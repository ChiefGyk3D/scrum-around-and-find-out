# SPDX-License-Identifier: Apache-2.0
"""The wire format: frames, the field tables, the reply codes. No socket, no clock: `recv` is a function."""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

import pytest

from safo import gemini, geminisign
from safo.broker import protocol as p
from safo.broker.errors import CODES, Refused
from safo.broker.protocol import ProtocolError, Truncated
from safo.broker.records import MAX_APPROVAL_BYTES

APPROVAL = {"payload": "{}", "signature": "-----BEGIN SSH SIGNATURE-----"}
NONCE = "0123456789abcdef"


class Feeder:
    """A `recv` over fixed bytes that hands out at most `step` at a time and records what was asked."""

    def __init__(self, data: bytes, step: int = 1 << 20) -> None:
        self.data = data
        self.step = step
        self.pos = 0
        self.asked: list[int] = []

    def __call__(self, n: int) -> bytes:
        self.asked.append(n)
        chunk = self.data[self.pos : self.pos + min(n, self.step)]
        self.pos += len(chunk)
        return chunk


def req(op: str, **over: Any) -> bytes:
    base: dict[str, Any] = {"v": 1, "op": op}
    base.update(over)
    return json.dumps({k: v for k, v in base.items() if v is not None}).encode()


def code_of(body: Any) -> str:
    with pytest.raises(ProtocolError) as err:
        p.parse_request(body)
    return err.value.code


TEXT_CALL = {
    "model": "flat-test",
    "job": "job-one",
    "kind": "text",
    "max_output_tokens": 500,
    "prompt": "hello",
    "approval": APPROVAL,
}
IMAGE_CALL = {**TEXT_CALL, "kind": "image", "count": 1, "image_size": "1K", "aspect_ratio": "1:1"}
TEXT_BEGIN = {
    "model": "flat-test",
    "job": "job-one",
    "kind": "text",
    "max_output_tokens": 500,
    "prompt_bytes": 5,
    "max_usd": "2.5",
}
IMAGE_BEGIN = {**TEXT_BEGIN, "kind": "image", "count": 1, "image_size": "1K", "aspect_ratio": "1:1"}


# -- frames --------------------------------------------------------------------------------------------------------


def test_a_frame_is_a_big_endian_length_and_the_bytes() -> None:
    assert p.frame(b"abc", 10) == b"\x00\x00\x00\x03abc"
    assert p.read_frame(Feeder(p.frame(b"abc", 10)), 10) == b"abc"


def test_a_frame_may_be_exactly_the_limit_and_not_one_over() -> None:
    assert p.read_frame(Feeder(p.HEADER.pack(10) + b"x" * 10), 10) == b"x" * 10
    with pytest.raises(ProtocolError) as err:
        p.frame(b"x" * 11, 10)
    assert err.value.code == "too_large"
    assert p.frame(b"x" * 10, 10)


def test_an_empty_frame_is_never_made_or_read() -> None:
    with pytest.raises(ProtocolError) as err:
        p.frame(b"", 10)
    assert err.value.code == "bad_request"
    with pytest.raises(ProtocolError) as err2:
        p.read_frame(Feeder(b"\x00\x00\x00\x00"), 10)
    assert err2.value.code == "bad_request" and not isinstance(err2.value, Truncated)


def test_only_bytes_are_framed() -> None:
    with pytest.raises(ProtocolError):
        p.frame("text", 10)  # type: ignore[arg-type]  # the point of the test: a str is refused at run time too


def test_a_declared_length_over_the_limit_is_refused_without_reading_the_body() -> None:
    recv = Feeder(p.HEADER.pack(p.MAX_REQUEST_FRAME + 1) + b"x" * 100)
    with pytest.raises(ProtocolError) as err:
        p.read_frame(recv, p.MAX_REQUEST_FRAME)
    assert err.value.code == "too_large"
    assert recv.pos == 4  # only the header was taken from the stream


def test_a_declared_length_of_four_gigabytes_is_too_large() -> None:
    with pytest.raises(ProtocolError) as err:
        p.read_frame(Feeder(b"\xff\xff\xff\xff"), p.MAX_REQUEST_FRAME)
    assert err.value.code == "too_large"


@pytest.mark.parametrize("data", [b"", b"\x00", b"\x00\x00\x00", b"\x00\x00\x00\x05ab", b"\x00\x00\x00\x05"])
def test_a_stream_that_ends_inside_a_frame_is_truncated(data: bytes) -> None:
    with pytest.raises(Truncated) as err:
        p.read_frame(Feeder(data), 100)
    assert err.value.code == "bad_request"


def test_a_frame_is_assembled_from_one_byte_reads() -> None:
    assert p.read_frame(Feeder(p.frame(b"hello", 100), step=1), 100) == b"hello"


def test_the_body_is_read_in_bounded_chunks_never_more_than_is_left() -> None:
    body = b"x" * (p.READ_CHUNK * 2 + 5)
    recv = Feeder(p.frame(body, p.MAX_REQUEST_FRAME))
    assert p.read_frame(recv, p.MAX_REQUEST_FRAME) == body
    assert recv.asked == [4, p.READ_CHUNK, p.READ_CHUNK, 5]


@pytest.mark.parametrize("bad", [b"abcdefgh", "text", None, bytearray(b"ab")])
def test_a_reader_that_returns_more_than_asked_or_not_bytes_is_refused(bad: Any) -> None:
    with pytest.raises(ProtocolError):
        p.read_frame(lambda n: bad, 100)


def test_the_reader_does_not_read_past_the_frame() -> None:
    recv = Feeder(p.frame(b"one", 10) + p.frame(b"two", 10))
    assert p.read_frame(recv, 10) == b"one"
    assert recv.pos == 7


# -- requests: the good ones ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("op", "fields"),
    [
        ("status", {}),
        ("begin", TEXT_BEGIN),
        ("begin", IMAGE_BEGIN),
        ("call", TEXT_CALL),
        ("call", IMAGE_CALL),
        ("check", {"nonce": NONCE}),
        ("dryrun", {"approval": APPROVAL}),
    ],
)
def test_every_operation_parses_and_round_trips(op: str, fields: dict[str, Any]) -> None:
    parsed = p.parse_request(req(op, **fields))
    assert parsed == p.Request(op, fields)
    assert p.parse_request(p.request_body(op, **fields)) == parsed


def test_request_body_refuses_what_the_server_would_refuse() -> None:
    with pytest.raises(ProtocolError):
        p.request_body("begin", **{**TEXT_BEGIN, "model": "Bad Model"})
    with pytest.raises(ProtocolError):
        p.request_body("status", extra=1)


def test_the_boundary_values_are_accepted() -> None:
    p.parse_request(req("check", nonce="a" * 64))
    p.parse_request(req("check", nonce="a" * 16))
    p.parse_request(req("begin", **{**TEXT_BEGIN, "model": "a" * 64, "job": "J" * 64, "prompt_bytes": 200_000}))
    p.parse_request(req("call", **{**TEXT_CALL, "prompt": "a" * 200_000}))
    p.parse_request(req("call", **{**TEXT_CALL, "prompt": "é" * 100_000}))
    p.parse_request(req("begin", **{**TEXT_BEGIN, "max_output_tokens": 1, "max_usd": "0.000001"}))
    p.parse_request(req("begin", **{**TEXT_BEGIN, "max_output_tokens": p.MAX_TOKENS, "prompt_bytes": 0}))
    p.parse_request(req("begin", **{**IMAGE_BEGIN, "count": 16, "image_size": "512px", "aspect_ratio": "16:9"}))


# -- requests: the bad ones ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not json",
        b"[]",
        b'"status"',
        b"null",
        b"1",
        b'{"v":1,"op":"status"} trailing',
        b'{"v":1,"op":"status"}{"v":1,"op":"status"}',
        b'{"v":1,"v":1,"op":"status"}',
        b'{"v":1,"op":"status","op":"status"}',
        b'{"v":NaN,"op":"status"}',
        b'{"v":1,"op":"status","x":Infinity}',
        b'{"v":1,"op":"status","x":-Infinity}',
        b"\xef\xbb\xbf" + b'{"v":1,"op":"status"}',
        b'{"v":1,"op":"stat\xffus"}',
        b'{"v":1,"op":"status"',
        b"{'v':1,'op':'status'}",
        b'{"v":1,"op":"status",}',
        b'{"v":1.0,"op":"status"}',
        b'{"v":true,"op":"status"}',
        b'{"v":"1","op":"status"}',
        b'{"op":"status"}',
        b'{"v":null,"op":"status"}',
        b'{"v":1}',
        b'{"v":1,"op":null}',
        b'{"v":1,"op":["status"]}',
        b'{"v":1,"op":"Status"}',
        b'{"v":1,"op":"clear"}',
        b'{"v":1,"op":""}',
    ],
)
def test_a_malformed_message_is_a_bad_request(body: bytes) -> None:
    assert code_of(body) == "bad_request"


@pytest.mark.parametrize("version", [0, 2, -1, 10**30])
def test_any_other_version_is_unsupported(version: int) -> None:
    assert code_of(json.dumps({"v": version, "op": "status"}).encode()) == "unsupported_version"
    assert code_of(json.dumps({"v": version, "junk": 1}).encode()) == "unsupported_version"  # before anything else


def test_a_duplicate_key_inside_the_approval_is_refused() -> None:
    body = b'{"v":1,"op":"dryrun","approval":{"payload":"a","payload":"b","signature":"c"}}'
    assert code_of(body) == "bad_request"


def test_nesting_over_the_depth_limit_is_refused() -> None:
    deep = b'{"v":1,"op":"status","x":' + b"[" * 100 + b"]" * 100 + b"}"
    assert code_of(deep) == "bad_request"


def test_a_body_over_the_request_limit_is_too_large_before_parsing() -> None:
    assert code_of(b" " * (p.MAX_REQUEST_FRAME + 1)) == "too_large"
    assert code_of(b"x" * (p.MAX_REQUEST_FRAME + 1)) == "too_large"


@pytest.mark.parametrize("body", ["status", None, bytearray(b"{}")])
def test_a_body_that_is_not_bytes_is_a_bad_request(body: Any) -> None:
    assert code_of(body) == "bad_request"


def test_an_unknown_key_is_refused_not_ignored() -> None:
    assert code_of(req("status", extra=1)) == "bad_request"
    assert code_of(req("check", nonce=NONCE, extra=1)) == "bad_request"
    assert code_of(req("begin", **{**TEXT_BEGIN, "thinking_level": "none"})) == "bad_request"


@pytest.mark.parametrize("missing", sorted(TEXT_BEGIN))
def test_a_missing_begin_field_is_refused(missing: str) -> None:
    assert code_of(req("begin", **{k: v for k, v in TEXT_BEGIN.items() if k != missing})) == "bad_request"


@pytest.mark.parametrize("missing", sorted(TEXT_CALL))
def test_a_missing_call_field_is_refused(missing: str) -> None:
    assert code_of(req("call", **{k: v for k, v in TEXT_CALL.items() if k != missing})) == "bad_request"


@pytest.mark.parametrize("missing", ["count", "image_size", "aspect_ratio"])
def test_an_image_request_needs_its_image_fields(missing: str) -> None:
    assert code_of(req("begin", **{k: v for k, v in IMAGE_BEGIN.items() if k != missing})) == "bad_request"
    assert code_of(req("call", **{k: v for k, v in IMAGE_CALL.items() if k != missing})) == "bad_request"


@pytest.mark.parametrize("extra", [{"count": 1}, {"image_size": "1K"}, {"aspect_ratio": "1:1"}])
def test_a_text_request_has_no_image_fields(extra: dict[str, Any]) -> None:
    assert code_of(req("begin", **{**TEXT_BEGIN, **extra})) == "bad_request"
    assert code_of(req("call", **{**TEXT_CALL, **extra})) == "bad_request"


@pytest.mark.parametrize("kind", ["Text", "audio", "", None, 1, ["text"], True])
def test_the_kind_is_text_or_image(kind: Any) -> None:
    assert code_of(req("begin", **{**TEXT_BEGIN, "kind": kind})) == "bad_request"


BAD_VALUES = [
    ("model", "Bad"),
    ("model", "-lead"),
    ("model", "a" * 65),
    ("model", ""),
    ("model", "a b"),
    ("model", "a\n"),
    ("model", "aé"),
    ("model", 5),
    ("model", None),
    ("job", "a b"),
    ("job", "a" * 65),
    ("job", ""),
    ("job", "a/b"),
    ("job", "a\n"),
    ("job", 7),
    ("max_output_tokens", 0),
    ("max_output_tokens", -1),
    ("max_output_tokens", p.MAX_TOKENS + 1),
    ("max_output_tokens", True),
    ("max_output_tokens", 5.0),
    ("max_output_tokens", "5"),
    ("max_output_tokens", None),
]


@pytest.mark.parametrize(("name", "value"), BAD_VALUES)
def test_shared_fields_are_checked_in_begin_and_call(name: str, value: Any) -> None:
    assert code_of(req("begin", **{**TEXT_BEGIN, name: value})) == "bad_request"
    assert code_of(req("call", **{**TEXT_CALL, name: value})) == "bad_request"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("prompt_bytes", -1),
        ("prompt_bytes", 200_001),
        ("prompt_bytes", True),
        ("prompt_bytes", 1.5),
        ("prompt_bytes", "5"),
        ("max_usd", "-1"),
        ("max_usd", "2.5 "),
        ("max_usd", " 2.5"),
        ("max_usd", "2.5\n"),
        ("max_usd", "1e3"),
        ("max_usd", "0.0000001"),
        ("max_usd", "01"),
        ("max_usd", ".5"),
        ("max_usd", "1000000000"),
        ("max_usd", 2.5),
        ("max_usd", 2),
    ],
)
def test_begin_only_fields_are_checked(name: str, value: Any) -> None:
    assert code_of(req("begin", **{**TEXT_BEGIN, name: value})) == "bad_request"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("count", 0),
        ("count", 17),
        ("count", True),
        ("count", 1.0),
        ("image_size", ""),
        ("image_size", "1K "),
        ("image_size", "123456789"),
        ("image_size", "1K\n"),
        ("aspect_ratio", "1x1"),
        ("aspect_ratio", "100:1"),
        ("aspect_ratio", "1:1\n"),
        ("aspect_ratio", ""),
    ],
)
def test_image_fields_are_checked(name: str, value: Any) -> None:
    assert code_of(req("begin", **{**IMAGE_BEGIN, name: value})) == "bad_request"
    assert code_of(req("call", **{**IMAGE_CALL, name: value})) == "bad_request"


@pytest.mark.parametrize(
    "prompt",
    ["", "a" * 200_001, "é" * 100_001, "\ud800", "ok\udfff", 5, None, ["a"], True],
)
def test_the_prompt_is_a_plain_string_that_encodes_and_fits(prompt: Any) -> None:
    body = json.dumps({"v": 1, "op": "call", **{**TEXT_CALL, "prompt": prompt}}).encode()
    assert code_of(body) == "bad_request"


def test_a_lone_surrogate_written_as_an_escape_is_refused() -> None:
    body = (
        b'{"v":1,"op":"call","model":"m","job":"j","kind":"text","max_output_tokens":5,'
        b'"prompt":"\\ud800","approval":{"payload":"{}","signature":"s"}}'
    )
    assert code_of(body) == "bad_request"


@pytest.mark.parametrize(
    "approval",
    [
        {},
        {"payload": "{}"},
        {"signature": "s"},
        {"payload": "{}", "signature": "s", "extra": "x"},
        {"payload": "", "signature": "s"},
        {"payload": "{}", "signature": ""},
        {"payload": "{}", "signature": "x" * (p.MAX_SIGNATURE_TEXT + 1)},
        {"payload": "x" * (p.MAX_APPROVAL_TEXT + 1), "signature": "s"},
        {"payload": "café", "signature": "s"},
        {"payload": "{}", "signature": "café"},
        {"payload": 5, "signature": "s"},
        {"payload": "{}", "signature": None},
        [],
        "text",
        None,
    ],
)
def test_the_approval_is_two_plain_ascii_strings_of_bounded_size(approval: Any) -> None:
    assert code_of(req("call", **{**TEXT_CALL, "approval": approval})) == "bad_request"
    assert code_of(req("dryrun", approval=approval)) == "bad_request"


def test_the_approval_may_be_exactly_the_size_limits() -> None:
    ok = {"payload": "x" * p.MAX_APPROVAL_TEXT, "signature": "s" * p.MAX_SIGNATURE_TEXT}
    p.parse_request(req("dryrun", approval=ok))


@pytest.mark.parametrize("nonce", ["", "a" * 15, "a" * 65, "A" * 16, "g" * 16, "a" * 16 + "\n", 5, None, ["a" * 16]])
def test_a_nonce_is_lowercase_hex_of_a_known_length(nonce: Any) -> None:
    body = json.dumps({"v": 1, "op": "check", "nonce": nonce}).encode()
    assert code_of(body) == "bad_request"


# -- replies -------------------------------------------------------------------------------------------------------


def test_every_broker_code_has_a_status_and_a_sentence() -> None:
    assert set(p.REPLY_CODES) >= CODES
    for code, (status, message) in p.REPLY_CODES.items():
        assert status in (2, 3, 4) and message
        assert "{" not in message and "%" not in message  # a fixed sentence, never a template
        assert json.loads(p.error_body(code))["message"] == message


def test_the_design_table_of_codes_and_exit_statuses() -> None:
    two = [
        *("bad_request", "too_large", "unsupported_version", "unauthorized_peer", "disabled", "bad_approval"),
        *("revoked", "expired", "used", "digest_mismatch", "model_mismatch", "job_mismatch", "over_job_cap"),
        *("over_approved", "needs_block_approval", "month_cap", "model_suspended", "busy", "vendor_refused"),
        *("model_refused", "prices_expired"),
    ]
    for code in two:
        assert p.REPLY_CODES[code][0] == 2, code
    assert p.REPLY_CODES["rate_limited"][0] == 3
    assert p.REPLY_CODES["outcome_unknown"][0] == 4 and p.REPLY_CODES["internal"][0] == 4
    assert len(p.REPLY_CODES) == len(two) + 3


def test_the_sentences_are_all_different() -> None:
    sentences = [message for _, message in p.REPLY_CODES.values()]
    assert len(set(sentences)) == len(sentences)


@pytest.mark.parametrize("code", ["rate_limited", "vendor_refused", "outcome_unknown"])
def test_the_codes_a_finished_call_returns_are_known_to_the_core(code: str) -> None:
    assert code in CODES and code in p.REPLY_CODES and code in p.CALL_CODES
    assert Refused(code, "x").code == code  # phase 1's code list used to lack them
    assert p.CALL_CODES == ("rate_limited", "vendor_refused", "outcome_unknown")


def test_a_code_the_core_does_not_know_is_still_refused() -> None:
    with pytest.raises(ValueError):
        Refused("not_a_code", "x")
    with pytest.raises(ValueError):
        p.error_body("not_a_code")
    with pytest.raises(ValueError):
        ProtocolError("not_a_code")


def test_an_error_reply_has_the_envelope_and_round_trips() -> None:
    body = p.error_body("busy")
    assert json.loads(body) == {
        "v": 1,
        "ok": False,
        "code": "busy",
        "message": p.REPLY_CODES["busy"][1],
        "exit": 2,
    }
    assert p.parse_reply(body)["code"] == "busy"
    assert json.loads(p.error_body("rate_limited"))["exit"] == 3


def test_an_unsupported_version_reply_lists_what_is_supported() -> None:
    assert json.loads(p.error_body("unsupported_version"))["supported"] == [1]
    assert "supported" not in json.loads(p.error_body("bad_request"))


def test_error_extras_ride_along_but_cannot_overwrite_the_envelope() -> None:
    body = p.error_body("outcome_unknown", {"receipt": {"call_id": "c1"}})
    assert json.loads(body)["receipt"] == {"call_id": "c1"}
    for key in ("v", "ok", "code", "message", "exit"):
        with pytest.raises(ValueError):
            p.error_body("busy", {key: 1})
        with pytest.raises(ValueError):
            p.ok_body({key: 1})


def test_a_success_reply_round_trips_and_is_ascii() -> None:
    body = p.ok_body({"text": "café \U0001f600", "attachments": []})
    assert body.isascii() and json.loads(body)["text"] == "café \U0001f600"
    assert p.parse_reply(body)["ok"] is True


def test_a_reply_never_exceeds_the_reply_frame() -> None:
    assert len(p.ok_body({"text": "a" * (p.MAX_REPLY_FRAME - 200)})) <= p.MAX_REPLY_FRAME
    with pytest.raises(ProtocolError) as err:
        p.ok_body({"text": "a" * p.MAX_REPLY_FRAME})
    assert err.value.code == "too_large"
    with pytest.raises(ProtocolError):  # escaping makes a short text long
        p.ok_body({"text": "é" * (p.MAX_REPLY_FRAME // 6 + 1)})
    with pytest.raises(ProtocolError):
        p.error_body("busy", {"receipt": "x" * p.MAX_REPLY_FRAME})


def test_non_finite_numbers_are_never_written() -> None:
    with pytest.raises(ValueError):
        p.ok_body({"x": float("nan")})


def good_error() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(p.error_body("busy"))
    return data


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(v=2),
        lambda d: d.update(v=True),
        lambda d: d.pop("v"),
        lambda d: d.update(ok="false"),
        lambda d: d.pop("ok"),
        lambda d: d.update(code="nope"),
        lambda d: d.update(code=5),
        lambda d: d.pop("code"),
        lambda d: d.update(exit=3),
        lambda d: d.update(exit=2.0),
        lambda d: d.update(exit=True),
        lambda d: d.pop("exit"),
        lambda d: d.update(message="another sentence"),
        lambda d: d.pop("message"),
    ],
)
def test_a_client_refuses_a_failure_reply_that_does_not_match_the_table(mutate: Any) -> None:
    data = good_error()
    mutate(data)
    with pytest.raises(ProtocolError):
        p.parse_reply(json.dumps(data).encode())


@pytest.mark.parametrize("body", [b"", b"[]", b"nope", b'{"v":1,"v":1,"ok":true}', b'{"v":1}', b'{"v":1,"ok":null}'])
def test_a_client_refuses_a_reply_that_is_not_an_object_with_an_outcome(body: bytes) -> None:
    with pytest.raises(ProtocolError):
        p.parse_reply(body)


def test_a_success_reply_carrying_failure_keys_is_refused() -> None:
    for key in ("code", "message", "exit"):
        with pytest.raises(ProtocolError):
            p.parse_reply(json.dumps({"v": 1, "ok": True, key: 1}).encode())


def test_a_reply_over_the_frame_limit_is_refused_by_the_client() -> None:
    with pytest.raises(ProtocolError):
        p.parse_reply(b" " * (p.MAX_REPLY_FRAME + 1))


GOOD_ATTACHMENT = {"index": 0, "mime": "image/png", "bytes": 12, "sha256": "ab" * 32}


def test_attachments_are_described_and_counted() -> None:
    reply = p.parse_reply(p.ok_body({"attachments": [GOOD_ATTACHMENT]}))
    assert p.attachment_count(reply) == 1
    assert p.attachment_count(p.parse_reply(p.ok_body({}))) == 0
    assert p.attachment_count(p.parse_reply(p.ok_body({"attachments": []}))) == 0


@pytest.mark.parametrize(
    "attachments",
    [
        "x",
        {},
        [GOOD_ATTACHMENT, GOOD_ATTACHMENT],
        [{**GOOD_ATTACHMENT, "bytes": 0}],
        [{**GOOD_ATTACHMENT, "bytes": p.MAX_ATTACHMENT_FRAME + 1}],
        [{**GOOD_ATTACHMENT, "bytes": True}],
        [{**GOOD_ATTACHMENT, "index": 1}],
        [{**GOOD_ATTACHMENT, "index": -1}],
        [{**GOOD_ATTACHMENT, "sha256": "AB" * 32}],
        [{**GOOD_ATTACHMENT, "sha256": "ab" * 31}],
        [{**GOOD_ATTACHMENT, "mime": "../x"}],
        [{**GOOD_ATTACHMENT, "mime": "image/png\n"}],
        [{**GOOD_ATTACHMENT, "extra": 1}],
        [{k: v for k, v in GOOD_ATTACHMENT.items() if k != "mime"}],
        [5],
    ],
)
def test_a_client_refuses_a_malformed_attachment_list(attachments: Any) -> None:
    with pytest.raises(ProtocolError):
        p.parse_reply(json.dumps({"v": 1, "ok": True, "attachments": attachments}).encode())


def test_the_largest_attachment_description_is_accepted() -> None:
    big = {**GOOD_ATTACHMENT, "bytes": p.MAX_ATTACHMENT_FRAME}
    assert p.attachment_count(p.parse_reply(p.ok_body({"attachments": [big]}))) == 1


# -- the module itself ---------------------------------------------------------------------------------------------


def test_the_limits_are_the_design_numbers() -> None:
    assert (p.MAX_REQUEST_FRAME, p.MAX_REPLY_FRAME, p.MAX_ATTACHMENT_FRAME) == (1_048_576, 262_144, 25_165_824)
    assert p.VERSION == 1 and p.SUPPORTED == (1,) and p.MAX_ATTACHMENTS == 1


def test_the_shared_constants_equal_the_ones_they_copy() -> None:
    assert p.MODEL_NAME.pattern == gemini.MODEL_NAME.pattern
    assert p.JOB_NAME.pattern == gemini.JOB_NAME.pattern
    assert p.MAX_PROMPT_BYTES == gemini.MAX_PROMPT_BYTES
    assert p.MAX_APPROVAL_TEXT == MAX_APPROVAL_BYTES
    assert p.MAX_SIGNATURE_TEXT == geminisign.SIGNATURE_BYTES


def test_the_operation_table_is_the_design_table() -> None:
    assert sorted(p.OPERATIONS) == ["begin", "call", "check", "dryrun", "status"]  # no root `clear` on the socket
    assert p.OPERATIONS["status"].required == ()


def test_a_thin_client_can_import_it_with_nothing_else_of_ours() -> None:
    code = (
        "import sys, safo.broker.protocol\n"
        "print(','.join(sorted(m for m in sys.modules if m == 'safo' or m.startswith('safo.'))))"
    )
    done = subprocess.run(  # noqa: S603 - this interpreter with a fixed program, no shell
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True
    )
    assert done.stdout.strip() == "safo,safo.bounded,safo.broker,safo.broker.protocol"
