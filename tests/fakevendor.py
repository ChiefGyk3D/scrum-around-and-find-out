# SPDX-License-Identifier: Apache-2.0
"""A fake vendor for the broker pipeline tests: no socket, no key, no clock. It is a `Transport` that answers from a
script, plus tiny valid PNG, JPEG and WebP files built here and a fake clock.

Modes: normal, over_cap, malformed, truncated, slow, duplicated_part, wrong_model, timeout, reset, status, oversized.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import struct
import zlib
from collections.abc import Callable
from typing import Any

from safo.broker.vendor import RawReply, TransportError, TransportTimeout, VendorRequest

START = dt.datetime(2026, 10, 30, 12, 0, 0, tzinfo=dt.UTC)


class FakeClock:
    """Injected wall and monotonic clocks. Nothing sleeps: a slow vendor advances this clock."""

    def __init__(self, start: dt.datetime = START) -> None:
        self.at = start
        self.ticks = 0.0

    def wall(self) -> dt.datetime:
        return self.at

    def mono(self) -> float:
        return self.ticks

    def advance(self, seconds: float) -> None:
        self.ticks += seconds


# -- tiny valid files ----------------------------------------------------------------------------------------------


def png(width: int = 1, height: int = 1, extra: bytes = b"") -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    body = chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"\x00\x00")) + extra
    return b"\x89PNG\r\n\x1a\n" + body + chunk(b"IEND", b"")


def jpeg(width: int = 1, height: int = 1) -> bytes:
    sof = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, height, width, 1) + b"\x01\x11\x00"
    sos = b"\xff\xda" + struct.pack(">H", 8) + b"\x01\x01\x00\x00\x3f\x00" + b"\x00"
    return b"\xff\xd8\xff\xe0" + struct.pack(">H", 4) + b"\x00\x00" + sof + sos + b"\xff\xd9"


def webp(width: int = 1, height: int = 1) -> bytes:
    chunk = b"VP8X" + struct.pack("<I", 10) + b"\x00\x00\x00\x00" + (width - 1).to_bytes(3, "little")
    chunk += (height - 1).to_bytes(3, "little")
    return b"RIFF" + struct.pack("<I", 4 + len(chunk)) + b"WEBP" + chunk


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# -- the vendor ----------------------------------------------------------------------------------------------------


class FakeVendor:
    def __init__(self, clock: FakeClock | None = None) -> None:
        self.clock = clock or FakeClock()
        self.mode = "normal"
        self.requests: list[VendorRequest] = []
        self.on_send: Callable[[VendorRequest], None] | None = None
        self.text = "a short answer"
        self.image: bytes = png()
        self.mime = "image/png"
        self.status = 200
        self.headers: dict[str, str] = {}
        self.body: bytes | None = None  # replaces the whole body when set
        self.error_body = b'{"error":{"status":"RESOURCE_EXHAUSTED"}}'
        self.tokens_in: int | None = None
        self.tokens_out: int | None = None
        self.usage: object = "default"  # replaces the usage block when not "default"
        self.reply_model: str | None = None
        self.part: dict[str, Any] | None = None  # replaces the image item when set
        self.extra_parts: list[dict[str, Any]] = []

    # the transport interface
    def send(self, request: VendorRequest) -> RawReply:
        self.requests.append(request)
        if self.on_send is not None:
            self.on_send(request)
        mode = self.mode
        if mode == "timeout":
            raise TransportTimeout("deadline")
        if mode == "reset":
            raise TransportError("reset")
        if mode == "status":
            return RawReply(self.status, dict(self.headers), self.error_body if self.body is None else self.body)
        if mode == "slow":
            self.clock.advance(request.timeout_seconds + 1)
        if mode == "oversized":
            return RawReply(200, {}, b" " * (request.max_reply_bytes + 1))
        body = self.body if self.body is not None else self._normal(request)
        headers = dict(self.headers)
        if mode == "truncated":
            headers["Content-Length"] = str(len(body))
            body = body[: len(body) // 2]
        return RawReply(self.status, headers, body)

    # building an answer
    def _numbers(self, data: dict[str, Any], request: VendorRequest) -> tuple[int, int]:
        prompt = data["input"][0]["text"] if request.kind == "image" else data["contents"][0]["parts"][0]["text"]
        cap = (data["generation_config"] if request.kind == "image" else data["generationConfig"])[
            "max_output_tokens" if request.kind == "image" else "maxOutputTokens"
        ]
        tokens_in = self.tokens_in if self.tokens_in is not None else len(prompt.encode()) // 3 + 1
        if self.tokens_out is not None:
            tokens_out = self.tokens_out
        elif self.mode == "over_cap":
            tokens_out = cap + 1
        else:
            tokens_out = len(self.text.encode()) // 3 + (1200 if request.kind == "image" else 1)
        return tokens_in, tokens_out

    def _normal(self, request: VendorRequest) -> bytes:
        data = json.loads(request.body)
        tokens_in, tokens_out = self._numbers(data, request)
        model = self.reply_model if self.reply_model is not None else request.model
        if self.mode == "wrong_model":
            model = request.model + "-other"
        if request.kind == "image":
            item = self.part or {"type": "image", "data": b64(self.image), "mime_type": self.mime}
            outputs: list[dict[str, Any]] = [{"type": "text", "text": self.text}, item]
            if self.mode == "duplicated_part":
                outputs.append(dict(item))
            outputs += self.extra_parts
            usage: object = {"total_input_tokens": tokens_in, "total_output_tokens": tokens_out}
            reply: dict[str, Any] = {"model": model, "outputs": outputs, "usage": usage}
            if self.usage != "default":
                reply["usage"] = self.usage
        else:
            candidate = {"content": {"parts": [{"text": self.text}]}}
            reply = {
                "modelVersion": model,
                "candidates": [candidate, candidate] if self.mode == "duplicated_part" else [candidate],
                "usageMetadata": {"promptTokenCount": tokens_in, "candidatesTokenCount": tokens_out},
            }
            if self.usage != "default":
                reply["usageMetadata"] = self.usage
        if self.usage is None:
            reply.pop("usage", None)
            reply.pop("usageMetadata", None)
        return json.dumps(reply).encode()
