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


def chunk(kind: bytes, data: bytes, crc: int | None = None) -> bytes:
    """One PNG chunk; the CRC is right unless a wrong one is given."""
    check = zlib.crc32(kind + data) if crc is None else crc
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", check)


def ihdr(
    width: int = 1, height: int = 1, *, depth: int = 8, color: int = 0, comp: int = 0, filt: int = 0, inter: int = 0
) -> bytes:
    return chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, depth, color, comp, filt, inter))


IDAT = chunk(b"IDAT", zlib.compress(b"\x00\x00"))
IEND = chunk(b"IEND", b"")


def png_of(*chunks: bytes) -> bytes:
    return b"\x89PNG\r\n\x1a\n" + b"".join(chunks)


def png(width: int = 1, height: int = 1, extra: bytes = b"") -> bytes:
    """A valid PNG; `extra` is raw bytes placed between the image data and the end chunk."""
    return png_of(ihdr(width, height), IDAT, extra, IEND)


def jseg(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


def sof(width: int = 1, height: int = 1, marker: int = 0xC0) -> bytes:
    return jseg(marker, struct.pack(">BHHB", 8, height, width, 1) + b"\x01\x11\x00")


SOS = jseg(0xDA, b"\x01\x01\x00\x00\x3f\x00")
JPEG_APP0 = jseg(0xE0, b"JFIF\x00")


def jpeg_of(*segments: bytes, scan: bytes = b"\x00", end: bytes = b"\xff\xd9") -> bytes:
    """SOI, the given segments in order, entropy data, then `end` (the EOI unless a test says otherwise)."""
    return b"\xff\xd8" + b"".join(segments) + scan + end


def jpeg(width: int = 1, height: int = 1) -> bytes:
    return jpeg_of(JPEG_APP0, sof(width, height), SOS)


def vp8l_payload(width: int, height: int) -> bytes:
    return b"\x2f" + ((width - 1) | ((height - 1) << 14)).to_bytes(4, "little")


def riff(*chunks: bytes) -> bytes:
    body = b"WEBP" + b"".join(chunks)
    return b"RIFF" + struct.pack("<I", len(body)) + body


def wchunk(kind: bytes, payload: bytes) -> bytes:
    pad = b"\x00" if len(payload) % 2 else b""
    return kind + struct.pack("<I", len(payload)) + payload + pad


def vp8x(width: int, height: int, flags: int = 0) -> bytes:
    body = bytes([flags]) + b"\x00\x00\x00" + (width - 1).to_bytes(3, "little") + (height - 1).to_bytes(3, "little")
    return wchunk(b"VP8X", body)


def webp(width: int = 1, height: int = 1) -> bytes:
    return riff(vp8x(width, height), wchunk(b"VP8L", vp8l_payload(width, height)))


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
