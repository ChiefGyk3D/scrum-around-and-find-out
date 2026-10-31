# SPDX-License-Identifier: Apache-2.0
"""The vendor side of a call: the fixed request templates, the transport interface, the reply parser and the cost.

Nothing here opens a socket. A `Transport` is injected (a fake in the tests; the pinned HTTPS connection in a later
phase). The request body is built from a fixed template per kind out of the canonical request and the price table, plus
nothing a client supplied except the prompt text, the size, the aspect ratio and the signed limits.

The reply parser targets one shape per kind and refuses any other (docs/gemini-broker.md, "Images"). The text shape is
the one `safo.gemini` already reads. The image shape (an `outputs` list of `text` and `image` items with inline base64
data, and a `usage` object) is **inferred** from the vendor's SDK examples, not read from a recorded response: phase 7
records the real one and replaces the fixture. A parse failure is never a guess: it is `Unreadable`, and the pipeline
makes the call ambiguous.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from safo.broker.errors import BrokerError
from safo.broker.images import Image, ImageRefused, decode_part
from safo.broker.money import MICRO, ceil_div
from safo.broker.policy import BrokerRequest
from safo.broker.prices import MAX_TOKENS, ModelPrice

TEXT_BODY_CAP = 1_048_576  # the whole HTTP body of a text answer
IMAGE_BODY_CAP = 32 * 1024 * 1024  # the whole HTTP body of an image answer
MAX_TEXT_BYTES = 200_000  # the answer text handed on; more is unreadable (the reply frame is 256 KiB)
MAX_PARTS = 8  # items in an answer; more is unreadable
MAX_RETRY_AFTER = 86_400.0
TEXT_PATH = "/v1beta/models/{model}:generateContent"
IMAGE_PATH = "/v1beta/interactions"


# -- the transport interface ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class VendorRequest:
    model: str
    kind: str
    path: str
    body: bytes
    max_reply_bytes: int
    timeout_seconds: float


@dataclass(frozen=True)
class RawReply:
    status: int
    headers: Mapping[str, str]
    body: bytes


class TransportError(Exception):
    """The request may have left and no whole answer came back (a reset, a short body, a failed read)."""


class TransportTimeout(TransportError):
    """A deadline passed after the request was sent."""


class Transport(Protocol):
    """One request, one reply, no retry, no redirect. The transport adds the key; the broker never holds it here."""

    def send(self, request: VendorRequest) -> RawReply: ...


class Unreadable(Exception):
    """The answer cannot be trusted. `reason` is a ledger ambiguity reason: `unreadable` or `usage`."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# -- the request ---------------------------------------------------------------------------------------------------


def build_request(req: BrokerRequest, price: ModelPrice, timeout_seconds: float) -> VendorRequest:
    """The one request for a canonical broker request. The output limit is always sent (decision 13) and so is the
    thinking level the table names; tools, search, cached content and input images are never in a template."""
    if req.kind == "image":
        generation: dict[str, Any] = {"max_output_tokens": req.max_output_tokens}
        if req.thinking_level != "none":
            generation["thinking_level"] = req.thinking_level
        body: dict[str, Any] = {
            "model": req.model,
            "input": [{"type": "text", "text": req.prompt}],
            "response_format": {"type": "image", "aspect_ratio": req.aspect_ratio, "image_size": req.image_size},
            "generation_config": generation,
        }
        path, cap = IMAGE_PATH, IMAGE_BODY_CAP
    else:
        config: dict[str, Any] = {"maxOutputTokens": req.max_output_tokens}
        if req.thinking_level != "none":
            config["thinkingConfig"] = {"thinkingLevel": req.thinking_level}
        body = {"contents": [{"role": "user", "parts": [{"text": req.prompt}]}], "generationConfig": config}
        path, cap = TEXT_PATH.format(model=req.model), TEXT_BODY_CAP
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return VendorRequest(req.model, req.kind, path, raw, cap, timeout_seconds)


def body_prompt(request: VendorRequest) -> str:
    """The prompt found in a finished request body (read back so it can be compared with what was approved)."""
    data = json.loads(request.body)
    block = data["input"][0] if request.kind == "image" else data["contents"][0]["parts"][0]
    text = block["text"]
    if type(text) is not str:
        raise BrokerError("the request body holds no prompt")
    return text


# -- the reply -----------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Usage:
    input_tokens: int
    output_tokens: int  # text, thinking and image output together


@dataclass(frozen=True)
class Reply:
    text: str
    images: tuple[Image, ...]
    usage: Usage
    parts_returned: int  # image items in the answer, including any dropped
    extra_images: int  # image items beyond the approved count (dropped, never decoded)
    image_refused: bool  # an image failed the checks: no bytes go on, the cost is still counted
    cap_exceeded: bool  # more output tokens than the signed limit


def _strict_loads(raw: bytes, limit: int) -> Any:
    """JSON from the vendor: size cap, no duplicate key, no NaN, and a deep nest is Unreadable, not an escaped error."""
    if len(raw) > limit:
        raise Unreadable("unreadable")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate key")
            out[key] = value
        return out

    def bad_constant(_: str) -> None:
        raise ValueError("non-finite number")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=bad_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Unreadable("unreadable") from None


def _token(value: object, low: int = 0) -> int:
    if type(value) is not int or not low <= value <= MAX_TOKENS:
        raise Unreadable("usage")
    return value


def _usage(block: object, names: tuple[str, str, str], prompt_bytes: int) -> Usage:
    if not isinstance(block, dict):
        raise Unreadable("usage")
    for name in block:
        if type(name) is not str:
            raise Unreadable("usage")
    if names[0] not in block:
        raise Unreadable("usage")
    tokens_in = _token(block[names[0]])
    tokens_out = _token(block.get(names[1], 0)) + _token(block.get(names[2], 0))
    if tokens_in < prompt_bytes // 8:  # fewer than one token per eight bytes cannot be a real count
        raise Unreadable("usage")
    return Usage(tokens_in, tokens_out)


def _same_model(value: object, model: str) -> None:
    if value is not None and (type(value) is not str or value != model):
        raise Unreadable("unreadable")


def _text_reply(data: Any, req: BrokerRequest, prompt_bytes: int) -> Reply:
    if not isinstance(data, dict):
        raise Unreadable("unreadable")
    _same_model(data.get("modelVersion"), req.model)
    usage = _usage(
        data.get("usageMetadata"), ("promptTokenCount", "candidatesTokenCount", "thoughtsTokenCount"), prompt_bytes
    )
    candidates = data.get("candidates", [])
    if not isinstance(candidates, list) or len(candidates) > 1:
        raise Unreadable("unreadable")
    pieces: list[str] = []
    if candidates:
        content = candidates[0].get("content") if isinstance(candidates[0], dict) else None
        parts = content.get("parts", []) if isinstance(content, dict) else None
        if not isinstance(parts, list) or len(parts) > MAX_PARTS:
            raise Unreadable("unreadable")
        for part in parts:
            if not isinstance(part, dict) or set(part) != {"text"} or type(part["text"]) is not str:
                raise Unreadable("unreadable")
            pieces.append(part["text"])
    return _finish(req, usage, pieces, 0, [])


def _image_reply(data: Any, req: BrokerRequest, prompt_bytes: int) -> Reply:
    if not isinstance(data, dict):
        raise Unreadable("unreadable")
    _same_model(data.get("model"), req.model)
    usage = _usage(
        data.get("usage"), ("total_input_tokens", "total_output_tokens", "total_thought_tokens"), prompt_bytes
    )
    outputs = data.get("outputs")
    if not isinstance(outputs, list) or len(outputs) > MAX_PARTS:
        raise Unreadable("unreadable")
    pieces: list[str] = []
    found: list[dict[str, Any]] = []
    for item in outputs:
        if not isinstance(item, dict):
            raise Unreadable("unreadable")
        if item.get("type") == "text" and set(item) == {"type", "text"} and type(item["text"]) is str:
            pieces.append(item["text"])
        elif item.get("type") == "image" and set(item) == {"type", "data", "mime_type"}:
            found.append(item)
        else:  # any shape not shown: a path, a name, a link, a tool call, an unknown type
            raise Unreadable("unreadable")
    return _finish(req, usage, pieces, len(found), found)


def _finish(req: BrokerRequest, usage: Usage, pieces: list[str], returned: int, found: list[dict[str, Any]]) -> Reply:
    text = "".join(pieces)
    try:
        size = len(text.encode("utf-8"))
    except UnicodeEncodeError:  # a JSON escape can spell a lone surrogate, which is not text
        raise Unreadable("unreadable") from None
    if size > MAX_TEXT_BYTES:
        raise Unreadable("unreadable")
    if req.kind == "text" and usage.output_tokens < size // 8:
        raise Unreadable("usage")
    approved = max(req.count, 0)
    images: list[Image] = []
    refused = False
    for index, item in enumerate(found[:approved]):
        try:
            images.append(decode_part(index, item["mime_type"], item["data"]))
        except ImageRefused:
            refused = True
            break
    if refused:
        images = []
    return Reply(
        text,
        tuple(images),
        usage,
        returned,
        max(returned - approved, 0),
        refused,
        usage.output_tokens > req.max_output_tokens,
    )


def parse_reply(req: BrokerRequest, body: bytes, prompt_bytes: int) -> Reply:
    """The answer to a canonical request, or Unreadable. Every image problem is reported on the Reply, not raised: the
    usage was read, so the cost can be counted."""
    limit = IMAGE_BODY_CAP if req.kind == "image" else TEXT_BODY_CAP
    data = _strict_loads(body, limit)
    if req.kind == "image":
        return _image_reply(data, req, prompt_bytes)
    return _text_reply(data, req, prompt_bytes)


# -- the cost ------------------------------------------------------------------------------------------------------


def actual_cost(price: ModelPrice, usage: Usage, parts_returned: int) -> int:
    """What the reported usage bills, in micro-dollars, rounded up. Output tokens of every kind are priced at the dearer
    output rate, the same rate the reservation uses, so this is never below the true figure for a mixed answer. The
    month counts at least the smallest per-image figure for each image item returned."""
    rate = max(price.text_output_per_mtok, price.image_output_per_mtok)
    cost = ceil_div(usage.input_tokens * price.input_per_mtok, MICRO) + ceil_div(usage.output_tokens * rate, MICRO)
    floor = parts_returned * min(price.image_usd.values()) if price.image_usd else 0
    return max(cost, floor)


def retry_after_seconds(value: str | None) -> int | None:
    """A Retry-After figure the client may be told: a finite number of seconds above 0 and at most a day, else None."""
    try:
        seconds = float(value or "")
    except ValueError:
        return None
    return math.ceil(seconds) if math.isfinite(seconds) and 0 < seconds <= MAX_RETRY_AFTER else None
