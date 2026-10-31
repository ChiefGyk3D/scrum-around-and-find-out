# SPDX-License-Identifier: Apache-2.0
"""Support for the broker server tests: a server over a rig, a client over a socketpair, a scripted fake connection."""

from __future__ import annotations

import dataclasses
import json
import socket
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fakevendor import FakeClock
from pipedata import Rig, image_req, text_req
from safo.broker import protocol
from safo.broker.policy import BrokerRequest
from safo.broker.server import PeerCred, Server, ServerConfig

UID = 1000
CRED = PeerCred(4242, UID, UID)


@dataclasses.dataclass
class Res:
    raw: bytes
    frames: list[bytes]

    @property
    def json(self) -> dict[str, Any]:
        data: dict[str, Any] = json.loads(self.frames[0])
        return data

    @property
    def code(self) -> str:
        return "ok" if self.json["ok"] else str(self.json["code"])

    @property
    def attachments(self) -> list[bytes]:
        return self.frames[1:]


def split_frames(raw: bytes) -> list[bytes]:
    frames: list[bytes] = []
    pos = 0
    while pos < len(raw):
        (size,) = protocol.HEADER.unpack(raw[pos : pos + 4])
        frames.append(raw[pos + 4 : pos + 4 + size])
        assert len(frames[-1]) == size, "a frame was cut short"
        pos += 4 + size
    return frames


class Env:
    """A server wired to a rig. `enabled` and `key_loaded` are what the root-owned switch and the key reader answer."""

    def __init__(self, rig: Rig, slots: int = 1, **config: Any) -> None:
        self.rig = rig
        self.enabled = True
        self.key_loaded = True
        config.setdefault("allowed_uids", frozenset({UID}))
        self.server = Server(
            rig.pipeline,
            ServerConfig(**config),
            switch=lambda: self.enabled,
            key_loaded=lambda: self.key_loaded,
            mono=rig.clock.mono,
        )
        if slots != 1:  # test only: the config refuses more than one call in flight; this exercises the budget lock
            self.server._slots = threading.BoundedSemaphore(slots)

    def exchange(self, body: bytes | None = None, *, raw: bytes | None = None, uid: int = UID, **kw: Any) -> Res:
        """One connection over a socketpair: send, read until the server closes."""
        return exchange(self.server, body, raw=raw, cred=PeerCred(1, uid, uid), **kw)

    def ask(self, op: str, **fields: Any) -> Res:
        return self.exchange(protocol.request_body(op, **fields))

    def call(self, req: BrokerRequest, **over: Any) -> Res:
        payload, signature = self.rig.approved(req, **over)
        return self.ask("call", **call_fields(req, payload, signature))


def exchange(
    server: Server,
    body: bytes | None = None,
    *,
    raw: bytes | None = None,
    cred: PeerCred = CRED,
    half_close: bool = True,
    before: Callable[[socket.socket], None] | None = None,
) -> Res:
    client, peer = socket.socketpair()
    worker = threading.Thread(target=server.handle_connection, args=(peer, cred))
    worker.start()
    try:
        if before is not None:
            before(client)
        data = raw if raw is not None else protocol.frame(body or b"", protocol.MAX_REQUEST_FRAME)
        try:
            client.sendall(data)
            if half_close:
                client.shutdown(socket.SHUT_WR)
        except OSError:
            pass  # the server answered and closed before the whole request was sent (an oversize declaration)
        chunks: list[bytes] = []
        while True:
            try:
                chunk = client.recv(1 << 20)
            except OSError:  # a reset, or this end was closed by the test
                break
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        worker.join(timeout=30)
        client.close()
    assert not worker.is_alive()
    joined = b"".join(chunks)
    return Res(joined, split_frames(joined) if joined else [])


def call_fields(req: BrokerRequest, payload: str, signature: str) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "model": req.model,
        "job": req.job,
        "kind": req.kind,
        "max_output_tokens": req.max_output_tokens,
        "prompt": req.prompt,
        "approval": {"payload": payload, "signature": signature},
    }
    if req.kind == "image":
        fields |= {"count": req.count, "image_size": req.image_size, "aspect_ratio": req.aspect_ratio}
    return fields


class FakeConn:
    """A connection with a script: what `recv` returns (bytes, or an exception to raise), and what `send` does."""

    def __init__(self, clock: FakeClock, script: list[Any] | None = None, *, tick: float = 0.0) -> None:
        self.clock = clock
        self.script = list(script or [])
        self.tick = tick  # seconds the fake clock moves on every recv or send
        self.sent = bytearray()
        self.closed = False
        self.timeouts: list[float | None] = []
        self.send_limit: int | None = None  # bytes accepted per send (None: all)
        self.send_error: BaseException | None = None
        self.on_send: Callable[[], None] | None = None

    def settimeout(self, value: float | None) -> None:
        self.timeouts.append(value)

    def setblocking(self, flag: bool) -> None:
        pass

    def recv(self, count: int) -> bytes:
        self.clock.advance(self.tick)
        if not self.script:
            raise BlockingIOError
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        assert isinstance(item, bytes)
        if len(item) > count:
            self.script.insert(0, item[count:])
            item = item[:count]
        return item

    def send(self, data: bytes | memoryview) -> int:
        self.clock.advance(self.tick)
        if self.on_send is not None:
            self.on_send()
        if self.send_error is not None:
            raise self.send_error
        n = len(data) if self.send_limit is None else min(len(data), self.send_limit)
        self.sent += bytes(data[:n])
        return n

    def shutdown(self, how: int) -> None:
        pass

    def close(self) -> None:
        self.closed = True


def state_snapshot(rig: Rig) -> tuple[bytes, list[str], list[str]]:
    """Everything a refused request must leave alone: the ledger bytes, the issued table and the used markers."""
    ledger = rig.ledger.dir / "ledger.jsonl"
    issued = rig.ledger.dir / "issued"
    used = rig.ledger.dir / "used"
    return (
        ledger.read_bytes() if ledger.exists() else b"",
        sorted(p.name for p in issued.iterdir()) if issued.exists() else [],
        sorted(p.name for p in used.iterdir()) if used.exists() else [],
    )


__all__ = ["CRED", "UID", "Env", "FakeConn", "Path", "Res", "call_fields", "exchange", "image_req", "text_req"]
