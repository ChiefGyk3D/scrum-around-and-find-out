# SPDX-License-Identifier: Apache-2.0
"""Support for the broker client tests: a scripted fake broker (no socket, no thread, no timing), a recording signer,
reply builders and the dependency set the client is given. Nothing here touches the network or a real key."""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fakevendor import FakeClock
from safo import gemini, geminisign
from safo.broker import client, protocol

NONCE = "0123456789abcdef0123456789abcdef"
EPOCH = "ab" * 16
HEAD = "cd" * 32
CALL_ID = "ef" * 16
PRINCIPAL = "yubikey-a"
PROMPT = "ZEBRA-PROMPT-7731 draw a small blue square\nsecond line"
ANSWER = "ANSWER-SENTINEL-4410 hello"
QUOTE = "QUOTE-SENTINEL-2208 go ahead"
IMAGE_DIR = "/tmp/images-for-the-test"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 24
WEBP = b"RIFF\x00\x00\x00\x00WEBPVP8 " + b"\x00" * 8

Item = bytes | BaseException
Handler = Callable[[dict[str, Any]], list[Item]]


def reply_frame(body: bytes) -> bytes:
    return protocol.frame(body, protocol.MAX_REPLY_FRAME)


def attach_frame(data: bytes) -> bytes:
    return protocol.frame(data, protocol.MAX_ATTACHMENT_FRAME)


def receipt(prompt: str = PROMPT, **over: Any) -> dict[str, Any]:
    digest, _ = gemini.prompt_binding(prompt)
    base: dict[str, Any] = {
        "call_id": CALL_ID,
        "nonce": NONCE,
        "epoch": EPOCH,
        "model": "flat-test",
        "kind": "text",
        "count": 0,
        "image_size": "",
        "prompt_sha256": digest,
        "tokens_in": 12,
        "tokens_out": 7,
        "reserved_usd": "0.012",
        "actual_usd": "0.0001",
        "released_usd": "0.0119",
        "breach": False,
        "cap_breach": False,
        "estimated": False,
        "extra_images": 0,
        "images": [],
        "month_spent_after": "0.5",
        "ledger_head_after": HEAD,
        "broker_version": "0.0.0",
        "ts": "2026-10-30T12:00:05Z",
    }
    base.update(over)
    return base


def described(data: bytes, mime: str = "image/png", index: int = 0) -> dict[str, Any]:
    return {"index": index, "mime": mime, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def image_receipt(data: bytes = PNG, mime: str = "image/png", **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "kind": "image",
        "count": 1,
        "image_size": "1K",
        "model": "gemini-nano-banana-2.1",
        "images": [described(data, mime)],
    }
    base.update(over)
    return receipt(**base)


def ok_call(
    text: str = ANSWER,
    rcpt: dict[str, Any] | None = None,
    images: tuple[bytes, ...] = (),
    desc: list[dict[str, Any]] | None = None,
) -> list[Item]:
    rcpt = rcpt or receipt()
    shown = desc if desc is not None else [described(d, index=i) for i, d in enumerate(images)]
    body = protocol.ok_body({"receipt": rcpt, "text": text, "attachments": shown})
    return [reply_frame(body), *[attach_frame(d) for d in images]]


def raw(item: Item) -> bytes:
    assert isinstance(item, bytes)
    return item


def err(code: str, **extra: Any) -> list[Item]:
    return [reply_frame(protocol.error_body(code, extra))]


def offer_reply(**over: Any) -> list[Item]:
    fields: dict[str, Any] = {
        "nonce": NONCE,
        "epoch": EPOCH,
        "expires_at": "2026-10-30T12:10:00Z",
        "ledger_head": HEAD,
        "estimate_usd": "0.004",
        "reserve_usd": "0.012",
        "thinking_level": "none",
        "beyond_ceiling": False,
        "line": "reserves 0.012 USD; 0.5 of 10 USD used this month",
    }
    fields.update(over)
    return [reply_frame(protocol.ok_body(fields))]


class ScriptChannel:
    """One connection. When the whole request frame has been sent, `handler` is given the parsed request and returns the
    items `recv` will hand out next: bytes, or an exception to raise. After them, `recv` answers b"" (closed)."""

    def __init__(self, handler: Handler, *, send_error: BaseException | None = None) -> None:
        self.handler = handler
        self.send_error = send_error
        self.sent = bytearray()
        self.script: list[Item] = []
        self.closed = False
        self.timeouts: list[float | None] = []
        self.asked: list[int] = []
        self.fed = False

    def sendall(self, data: bytes, /) -> None:
        if self.send_error is not None:
            raise self.send_error
        self.sent += data
        if len(self.sent) >= 4 and not self.fed:
            (size,) = protocol.HEADER.unpack(bytes(self.sent[:4]))
            if len(self.sent) >= 4 + size:
                self.fed = True
                self.script.extend(self.handler(json.loads(bytes(self.sent[4 : 4 + size]))))

    def recv(self, count: int, /) -> bytes:
        self.asked.append(count)
        if not self.script:
            return b""
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        if len(item) > count:
            self.script.insert(0, item[count:])
            item = item[:count]
        return item

    def settimeout(self, value: float | None, /) -> None:
        self.timeouts.append(value)

    def close(self) -> None:
        self.closed = True


class FakeBroker:
    """The set of connections a client opens. `handlers` maps an operation to what the broker answers."""

    def __init__(self) -> None:
        self.handlers: dict[str, Handler] = {
            "begin": lambda f: offer_reply(),
            "call": lambda f: ok_call(),
        }
        self.requests: list[dict[str, Any]] = []
        self.channels: list[ScriptChannel] = []
        self.connect_error: dict[int, BaseException] = {}  # the nth connection (from 0) fails to open
        self.send_error: dict[int, BaseException] = {}
        self.opened = 0

    def answer(self, op: str, items: list[Item]) -> None:
        self.handlers[op] = lambda fields: list(items)

    def _handle(self, fields: dict[str, Any]) -> list[Item]:
        self.requests.append(fields)
        return self.handlers[fields["op"]](fields)

    def connect(self) -> ScriptChannel:
        n = self.opened
        self.opened += 1
        if n in self.connect_error:
            raise self.connect_error[n]
        chan = ScriptChannel(self._handle, send_error=self.send_error.get(n))
        self.channels.append(chan)
        return chan

    @property
    def ops(self) -> list[str]:
        return [r["op"] for r in self.requests]


class Signer:
    def __init__(self, key: Path, events: list[str]) -> None:
        self.key = key
        self.payloads: list[bytes] = []
        self.events = events
        self.fail: BaseException | None = None
        self.armor_override: str | None = None

    def __call__(self, payload: bytes) -> str:
        self.payloads.append(payload)
        self.events.append("sign")
        if self.fail is not None:
            raise self.fail
        if self.armor_override is not None:
            return self.armor_override
        return geminisign.sign(str(self.key), payload, geminisign.NAMESPACE, {})


class Writer:
    """A recording image writer with the 4a signature; it returns a fixed path and writes nothing."""

    def __init__(self) -> None:
        self.calls: list[tuple[bytes, str, str, int]] = []
        self.fail: BaseException | None = None

    def __call__(self, data: bytes, directory: str, stem: str, max_bytes: int) -> str:
        self.calls.append((data, directory, stem, max_bytes))
        if self.fail is not None:
            raise self.fail
        return f"{directory}/{stem}.png"


class Sidecar:
    def __init__(self) -> None:
        self.calls: list[tuple[str, bytes]] = []
        self.fail: BaseException | None = None

    def __call__(self, image_path: str, data: bytes) -> str:
        self.calls.append((image_path, data))
        if self.fail is not None:
            raise self.fail
        return image_path + ".receipt.json"


@dataclasses.dataclass
class Rig:
    broker: FakeBroker
    signer: Signer
    writer: Writer
    sidecar: Sidecar
    clock: FakeClock
    events: list[str]
    out: io.StringIO
    err: io.StringIO
    deps: client.Deps
    cfg: client.ClientConfig
    shown: list[str]

    def run(self, params: client.PaidParams | None = None) -> int:
        return client.run_paid(params or text_params(), self.cfg, self.deps, self.out, self.err)

    @property
    def everything(self) -> str:
        return self.out.getvalue() + self.err.getvalue()


def text_params(**over: Any) -> client.PaidParams:
    base: dict[str, Any] = {
        "model": "flat-test",
        "job": "job-one",
        "kind": "text",
        "prompt": PROMPT,
        "max_output_tokens": 500,
        "max_usd": "0.5",
        "quote": QUOTE,
        "quoted_at": "2026-10-30T11:59:00Z",
        "issue": "ChiefGyk3D/scrum-around-and-find-out#260",
    }
    base.update(over)
    return client.PaidParams(**base)


def image_params(**over: Any) -> client.PaidParams:
    base: dict[str, Any] = {
        "model": "gemini-nano-banana-2.1",
        "job": "job-img",
        "kind": "image",
        "count": 1,
        "image_size": "1K",
        "aspect_ratio": "1:1",
        "max_output_tokens": 4000,
    }
    base.update(over)
    return text_params(**base)


def make_rig(key: Path, answers: list[str] | None = None) -> Rig:
    broker = FakeBroker()
    events: list[str] = []
    out, err_stream = io.StringIO(), io.StringIO()
    replies = None if answers is None else list(answers)
    clock = FakeClock()
    writer, sidecar = Writer(), Sidecar()
    signer = Signer(key, events)

    shown: list[str] = []

    def confirm(prompt: str) -> str:
        events.append("confirm")
        shown.append(out.getvalue())
        if replies is None:  # a person who types exactly what the prompt asks for
            found = re.search(r"`(approve [^`]+)`", prompt)
            return found.group(1) if found else ""
        return replies.pop(0) if replies else ""

    cfg = client.ClientConfig(
        socket="/run/test-broker.sock", signing_key="/home/x/.ssh/id_sk", principal=PRINCIPAL, image_dir=IMAGE_DIR
    )

    def terms(text: str) -> None:
        events.append("terms")

    def connect() -> ScriptChannel:
        events.append("connect")
        return broker.connect()

    deps = client.Deps(
        connect=connect,
        sign=signer,
        now=clock.wall,
        mono=clock.mono,
        writer=writer,
        sidecar=sidecar,
        check_dir=lambda d: events.append("dir"),
        terms=terms,
        confirm=confirm,
        interactive=True,
    )
    return Rig(broker, signer, writer, sidecar, clock, events, out, err_stream, deps, cfg, shown)
