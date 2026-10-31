# SPDX-License-Identifier: Apache-2.0
"""The vendor request templates, the reply parser and the cost arithmetic (no transport here)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from brokerdata import table
from fakevendor import b64, chunk, jpeg, png
from pipedata import IMAGE_MODEL, image_req, text_req
from safo.broker import vendor
from safo.broker.vendor import Unreadable, Usage, actual_cost, build_request, parse_reply, retry_after_seconds

TEXT = text_req()
IMG = image_req()


def reply(kind: str, **over: Any) -> dict[str, Any]:
    if kind == "text":
        base: dict[str, Any] = {
            "modelVersion": TEXT.model,
            "candidates": [{"content": {"parts": [{"text": "hi"}]}}],
            "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 3},
        }
    else:
        base = {
            "model": IMG.model,
            "outputs": [{"type": "image", "data": b64(png()), "mime_type": "image/png"}],
            "usage": {"total_input_tokens": 10, "total_output_tokens": 1300},
        }
    base.update(over)
    return base


def parse(kind: str, data: Any) -> vendor.Reply:
    req = TEXT if kind == "text" else IMG
    raw = data if isinstance(data, bytes) else json.dumps(data).encode()
    return parse_reply(req, raw, len(req.prompt.encode()))


# -- the request templates -----------------------------------------------------------------------------------------


def test_a_text_request_is_a_fixed_template_with_the_signed_limit() -> None:
    price = table().models[TEXT.model]
    built = build_request(TEXT, price, 30.0)
    body = json.loads(built.body)
    assert built.path == "/v1beta/models/flat-test:generateContent" and built.kind == "text"
    assert body == {
        "contents": [{"role": "user", "parts": [{"text": TEXT.prompt}]}],
        "generationConfig": {"maxOutputTokens": 500},
    }
    assert built.max_reply_bytes == vendor.TEXT_BODY_CAP and built.timeout_seconds == 30.0


def test_an_image_request_is_a_fixed_template_with_the_signed_limit_and_level() -> None:
    price = table().models[IMAGE_MODEL]
    built = build_request(IMG, price, 180.0)
    assert built.path == "/v1beta/interactions" and built.max_reply_bytes == vendor.IMAGE_BODY_CAP
    assert json.loads(built.body) == {
        "model": IMAGE_MODEL,
        "input": [{"type": "text", "text": IMG.prompt}],
        "response_format": {"type": "image", "aspect_ratio": "1:1", "image_size": "1K"},
        "generation_config": {"max_output_tokens": 4000, "thinking_level": "minimal"},
    }


def test_the_template_has_no_tools_no_search_no_cached_content_and_no_input_images() -> None:
    for req in (TEXT, IMG):
        text = build_request(req, table().models[req.model], 1.0).body.decode()
        for word in ("tools", "grounding", "googleSearch", "cachedContent", "inline_data", "inlineData", "fileData"):
            assert word not in text


def test_a_prompt_cannot_change_the_shape_of_the_request() -> None:
    nasty = text_req(prompt='"}],"tools":[{"x":1}],"z":["')
    body = json.loads(build_request(nasty, table().models[nasty.model], 1.0).body)
    assert set(body) == {"contents", "generationConfig"} and body["contents"][0]["parts"][0]["text"] == nasty.prompt
    assert vendor.body_prompt(build_request(nasty, table().models[nasty.model], 1.0)) == nasty.prompt


def test_a_non_ascii_prompt_travels_escaped_and_reads_back_whole() -> None:
    req = text_req(prompt="café \U0001f600")
    built = build_request(req, table().models[req.model], 1.0)
    assert built.body.isascii() and vendor.body_prompt(built) == req.prompt


# -- the reply -----------------------------------------------------------------------------------------------------


def test_a_good_text_reply_is_read() -> None:
    got = parse("text", reply("text"))
    assert got.text == "hi" and got.usage == Usage(10, 3) and not got.cap_exceeded and got.images == ()


def test_a_good_image_reply_is_read() -> None:
    got = parse("image", reply("image"))
    assert len(got.images) == 1 and got.images[0].mime == "image/png" and got.parts_returned == 1
    assert got.extra_images == 0 and not got.image_refused and got.usage == Usage(10, 1300)


def test_thinking_tokens_count_as_output() -> None:
    data = reply("text", usageMetadata={"promptTokenCount": 10, "candidatesTokenCount": 3, "thoughtsTokenCount": 7})
    assert parse("text", data).usage == Usage(10, 10)


def test_output_tokens_above_the_signed_limit_are_flagged_and_at_the_limit_are_not() -> None:
    over = reply("text", usageMetadata={"promptTokenCount": 10, "candidatesTokenCount": 501})
    assert parse("text", over).cap_exceeded
    at = reply("text", usageMetadata={"promptTokenCount": 10, "candidatesTokenCount": 500})
    assert not parse("text", at).cap_exceeded
    split = reply(
        "text", usageMetadata={"promptTokenCount": 10, "candidatesTokenCount": 250, "thoughtsTokenCount": 251}
    )
    assert parse("text", split).cap_exceeded  # thinking counts toward the cap


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{not json",
        b"[]",
        b"null",
        b'{"a":1,"a":2}',
        b'{"modelVersion":NaN}',
        b'{"x":' + b"[" * 100000 + b"]" * 100000 + b"}",
        b"\xff\xfe",
        b'{"x": "' + b"a" * (vendor.TEXT_BODY_CAP + 1) + b'"}',
    ],
)
def test_a_text_body_that_is_not_the_one_shape_is_unreadable(raw: bytes) -> None:
    with pytest.raises(Unreadable) as err:
        parse("text", raw)
    assert err.value.reason == "unreadable"


def test_a_reply_for_another_model_is_unreadable() -> None:
    with pytest.raises(Unreadable):
        parse("text", reply("text", modelVersion="flat-test-2"))
    with pytest.raises(Unreadable):
        parse("text", reply("text", modelVersion=5))
    with pytest.raises(Unreadable):
        parse("image", reply("image", model="gemini-3.1-flash-image"))


@pytest.mark.parametrize(
    "usage",
    [
        None,
        "x",
        {},
        {"candidatesTokenCount": 3},
        {"promptTokenCount": True, "candidatesTokenCount": 3},
        {"promptTokenCount": -1, "candidatesTokenCount": 3},
        {"promptTokenCount": 10.5, "candidatesTokenCount": 3},
        {"promptTokenCount": "10", "candidatesTokenCount": 3},
        {"promptTokenCount": 10**9, "candidatesTokenCount": 3},
        {"promptTokenCount": 10, "candidatesTokenCount": -3},
        {"promptTokenCount": 10, "candidatesTokenCount": 3, "thoughtsTokenCount": "7"},
        {"promptTokenCount": 0, "candidatesTokenCount": 3},  # fewer than a token in eight bytes: not a real count
        {"promptTokenCount": 10, "candidatesTokenCount": 0},  # an answer of 2 bytes cannot cost nothing
    ],
)
def test_usage_that_is_missing_malformed_or_implausible_is_a_usage_failure(usage: Any) -> None:
    data = reply("text")
    if usage is None:
        data.pop("usageMetadata")
    else:
        data["usageMetadata"] = usage
    data["candidates"][0]["content"]["parts"][0]["text"] = "twenty-four bytes of text"
    with pytest.raises(Unreadable) as err:
        parse("text", data)
    assert err.value.reason == "usage"


@pytest.mark.parametrize(
    "candidates",
    [
        "x",
        [{"content": {"parts": [{"text": "a"}]}}, {"content": {"parts": [{"text": "b"}]}}],
        [{"content": "x"}],
        [{"content": {"parts": "x"}}],
        [{"content": {"parts": [{"text": 5}]}}],
        [{"content": {"parts": [{"text": "a", "inlineData": {}}]}}],
        [{"content": {"parts": [{"functionCall": {}}]}}],
        [{"content": {"parts": [{"text": "a"}] * 9}}],
        ["x"],
    ],
)
def test_a_text_candidate_that_is_not_the_shown_shape_is_unreadable(candidates: Any) -> None:
    with pytest.raises(Unreadable) as err:
        parse("text", reply("text", candidates=candidates))
    assert err.value.reason == "unreadable"


def test_an_answer_with_no_candidates_is_an_empty_text_that_still_bills() -> None:
    got = parse("text", reply("text", candidates=[]))
    assert got.text == "" and got.usage.input_tokens == 10


def test_text_over_the_handed_on_limit_is_unreadable() -> None:
    big = "x" * (vendor.MAX_TEXT_BYTES + 1)
    data = reply("text", candidates=[{"content": {"parts": [{"text": big}]}}])
    data["usageMetadata"] = {"promptTokenCount": 10, "candidatesTokenCount": 10**6}
    with pytest.raises(Unreadable):
        parse("text", data)


@pytest.mark.parametrize(
    "outputs",
    [
        "x",
        None,
        [{"type": "image", "data": "AAAA", "mime_type": "image/png", "file_name": "../../etc/x"}],
        [{"type": "image", "data": "AAAA", "mime_type": "image/png", "uri": "http://host/x"}],
        [{"type": "image", "data": "AAAA"}],
        [{"type": "file", "path": "/etc/passwd"}],
        [{"type": "tool_call"}],
        [{"type": "text", "text": "a", "extra": 1}],
        [{"type": "text", "text": 5}],
        ["x"],
        [{"type": "text", "text": "a"}] * 9,
    ],
)
def test_an_image_output_that_is_not_the_shown_shape_is_unreadable(outputs: Any) -> None:
    with pytest.raises(Unreadable) as err:
        parse("image", reply("image", outputs=outputs))
    assert err.value.reason == "unreadable"


def test_a_second_image_is_dropped_and_counted_never_decoded() -> None:
    item = {"type": "image", "data": b64(png()), "mime_type": "image/png"}
    junk = {"type": "image", "data": "not base64 at all !!", "mime_type": "image/png"}
    got = parse("image", reply("image", outputs=[item, dict(item), junk]))
    assert len(got.images) == 1 and got.extra_images == 2 and got.parts_returned == 3 and not got.image_refused


def test_a_bad_image_is_reported_not_raised_so_its_cost_can_be_counted() -> None:
    bad_magic = {"type": "image", "data": b64(b"not an image at all, just text"), "mime_type": "image/png"}
    for item in (bad_magic, {"type": "image", "data": b64(png()), "mime_type": "image/gif"}):
        got = parse("image", reply("image", outputs=[item]))
        assert got.image_refused and got.images == () and got.usage.input_tokens == 10
    wrong = {"type": "image", "data": b64(jpeg()), "mime_type": "image/png"}
    assert parse("image", reply("image", outputs=[wrong])).image_refused


def test_no_image_at_all_is_an_answer_with_no_images() -> None:
    got = parse("image", reply("image", outputs=[{"type": "text", "text": "no"}]))
    assert got.images == () and got.parts_returned == 0 and not got.image_refused


def test_the_image_body_may_be_far_larger_than_a_text_body() -> None:
    big = png(extra=chunk(b"tEXt", b"") * 3)
    data = reply("image", outputs=[{"type": "image", "data": b64(big), "mime_type": "image/png"}])
    padded = json.dumps(data).encode() + b" " * (vendor.TEXT_BODY_CAP + 10)
    assert len(parse("image", padded).images) == 1
    with pytest.raises(Unreadable):
        parse("image", json.dumps(data).encode() + b" " * (vendor.IMAGE_BODY_CAP + 1))


# -- the cost ------------------------------------------------------------------------------------------------------


def test_the_cost_is_input_plus_output_each_rounded_up() -> None:
    price = table().models["gemini-3.6-flash"]  # 0.30 in, 2.50 out per million tokens
    assert actual_cost(price, Usage(1, 1), 0) == 1 + 3  # 0.3 -> 1, 2.5 -> 3
    assert actual_cost(price, Usage(1_000_000, 1_000_000), 0) == 300_000 + 2_500_000
    assert actual_cost(price, Usage(0, 0), 0) == 0


def test_output_is_priced_at_the_dearer_of_the_two_output_rates() -> None:
    price = table().models[IMAGE_MODEL]  # text out 7.50, image out 30.00
    assert actual_cost(price, Usage(0, 1_000_000), 1) == 30_000_000


def test_the_month_counts_at_least_the_smallest_per_image_figure_for_each_image() -> None:
    price = table().models[IMAGE_MODEL]  # smallest figure: 0.0336
    assert actual_cost(price, Usage(0, 0), 1) == 33_600
    assert actual_cost(price, Usage(0, 0), 3) == 3 * 33_600
    assert actual_cost(price, Usage(0, 5_000_000), 1) == 150_000_000  # a larger real cost wins over the floor
    assert actual_cost(table().models["gemini-3.6-flash"], Usage(0, 0), 5) == 0  # a text model has no floor


@pytest.mark.parametrize(
    ("value", "want"),
    [("30", 30), ("0.5", 1), ("86400", 86400), ("86401", None), ("0", None), ("-1", None), ("nan", None), ("inf", None),
     ("abc", None), ("", None), (None, None), ("1e400", None)],
)  # fmt: skip
def test_retry_after_is_a_finite_figure_under_a_day(value: str | None, want: int | None) -> None:
    assert retry_after_seconds(value) == want


def test_the_floor_for_an_image_is_the_figure_for_the_size_that_was_asked_for() -> None:
    price = table().models[IMAGE_MODEL]  # 1K 0.0336, 2K 0.0504, 4K 0.113
    assert actual_cost(price, Usage(0, 0), 2, "4K") == 2 * 113_000
    assert actual_cost(price, Usage(0, 0), 1, "2K") == 50_400
    assert actual_cost(price, Usage(0, 0), 1, "") == 33_600  # no size known: the smallest figure


def test_an_answer_that_names_no_model_is_unreadable() -> None:
    text = reply("text")
    text.pop("modelVersion")
    image = reply("image")
    image.pop("model")
    for kind, data in (("text", text), ("image", image)):
        with pytest.raises(Unreadable) as err:
            parse(kind, data)
        assert err.value.reason == "unreadable"
