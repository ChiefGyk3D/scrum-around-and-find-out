# SPDX-License-Identifier: Apache-2.0
"""A seeded, bounded fuzz of the broker framing (#298; the design promised it in docs/gemini-broker.md, "Tests").

The seed and the iteration counts are fixed, so a run is deterministic and a failure repeats. The properties:

* `read_frame` on any byte stream, cut at any point and handed out in any chunk size, returns a non-empty body that is
  within the limit or raises `ProtocolError` (`Truncated` included); it never raises anything else and never asks for
  more than a bounded number of reads (no hang, no endless loop);
* `parse_request` and `parse_reply` on any bytes return a parsed value or raise `ProtocolError`;
* the server's connection handler, fed any bytes on a real socket pair, answers with one well-formed refusal or closes
  without a word; it never answers `ok` to bytes that are not a valid request, and it leaves the ledger, the issued
  table and the used markers exactly as they were.

The harness has a negative case: a reader that breaks a property makes it fail.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

from geminidata import make_key
from pipedata import Rig
from safo.broker import protocol
from safo.broker.protocol import ProtocolError, Truncated
from serverdata import Env, state_snapshot

SEED = 298
STREAM_ITERATIONS = 400
PARSE_ITERATIONS = 400
SERVER_ITERATIONS = 80
LIMIT = 256
APPROVAL = {"payload": "{}", "signature": "armor"}
SHAPE = {"model": "flat-test", "job": "job-one", "kind": "text", "max_output_tokens": 500}
MAX_READS = 4_000  # a read loop that needs more than this for a stream of at most a few KiB is a hang


class Rng:
    """A small deterministic generator (splitmix64) so a run is the same on every machine and Python version. It is a
    test input source, not a secret source, and it avoids the standard `random` module on purpose."""

    def __init__(self, seed: int) -> None:
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def next64(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
        return z ^ (z >> 31)

    def randrange(self, low: int, high: int | None = None) -> int:
        if high is None:
            low, high = 0, low
        return low + self.next64() % (high - low)

    def randbytes(self, count: int) -> bytes:
        return bytes(self.next64() & 0xFF for _ in range(count))

    def choice(self, items: list[Any]) -> Any:
        return items[self.randrange(len(items))]


def valid_status() -> bytes:
    return protocol.request_body("status")


def junk(rng: Rng, high: int = 600) -> bytes:
    return rng.randbytes(rng.randrange(0, high))


def mutate(rng: Rng, data: bytes) -> bytes:
    """Flip, drop, insert, repeat, cut or splice bytes: the shapes a broken or hostile peer sends."""
    out = bytearray(data)
    for _ in range(rng.randrange(1, 5)):
        choice = rng.randrange(6)
        at = rng.randrange(0, len(out) + 1)
        if choice == 0 and out:
            out[min(at, len(out) - 1)] ^= 1 << rng.randrange(8)
        elif choice == 1 and out:
            del out[min(at, len(out) - 1)]
        elif choice == 2:
            out[at:at] = rng.randbytes(rng.randrange(1, 9))
        elif choice == 3:
            out[at:at] = bytes(out[at : at + rng.randrange(1, 20)]) * rng.randrange(2, 6)
        elif choice == 4:
            del out[at:]
        else:
            out[at:at] = rng.choice([b"\x00", b"\xff", b'"', b"{", b"}", b"\xc3\x28", b"\\u0000", b"NaN", b"1e999"])
    return bytes(out)


def framed(rng: Rng, body: bytes) -> bytes:
    """A frame whose header is sometimes honest and sometimes a lie (short, long, zero, huge)."""
    size = len(body)
    size = rng.choice([size, size, size + rng.randrange(1, 50), max(0, size - rng.randrange(1, 50)), 0, 2**32 - 1])
    return protocol.HEADER.pack(size) + body


class Source:
    """A `recv` over fixed bytes. It hands out at most `step` bytes, then b"" at the end, and counts the reads."""

    def __init__(self, data: bytes, step: int) -> None:
        self.data, self.step, self.pos, self.reads = data, step, 0, 0

    def __call__(self, count: int) -> bytes:
        self.reads += 1
        if self.reads > MAX_READS:
            raise AssertionError("the reader did not finish: it keeps asking for bytes")
        chunk = self.data[self.pos : self.pos + min(count, self.step)]
        self.pos += len(chunk)
        return chunk


def check_stream(read: Callable[[Callable[[int], bytes], int], bytes], data: bytes, step: int) -> str:
    """Run `read` over the stream and return how it ended: `frame`, `refused` or `truncated`. Anything else fails."""
    source = Source(data, step)
    try:
        body = read(source, LIMIT)
    except Truncated:
        return "truncated"
    except ProtocolError as err:
        assert err.code in protocol.REPLY_CODES
        return "refused"
    assert type(body) is bytes and 0 < len(body) <= LIMIT, "a frame is non-empty and within the limit"
    assert source.pos >= protocol.HEADER.size + len(body)
    return "frame"


def stream_cases(rng: Rng) -> list[tuple[bytes, int]]:
    cases: list[tuple[bytes, int]] = []
    for _ in range(STREAM_ITERATIONS):
        kind = rng.randrange(4)
        if kind == 0:
            data = junk(rng)
        elif kind == 1:
            data = framed(rng, junk(rng, 400))
        elif kind == 2:
            data = mutate(rng, framed(rng, valid_status()))
        else:
            data = framed(rng, valid_status())[: rng.randrange(0, 40)]
        cases.append((data, rng.choice([1, 2, 3, 7, 64, 1 << 20])))
    return cases


def test_read_frame_returns_a_frame_or_a_protocol_error_and_always_finishes() -> None:
    rng = Rng(SEED)
    seen = {"frame": 0, "refused": 0, "truncated": 0}
    for data, step in stream_cases(rng):
        seen[check_stream(protocol.read_frame, data, step)] += 1
    assert all(seen.values()), seen  # the fuzz reached every way a read can end, so it is not testing nothing


def test_a_frame_cut_at_every_point_is_truncated_or_whole() -> None:
    body = valid_status()
    wire = protocol.frame(body, protocol.MAX_REQUEST_FRAME)
    for cut in range(len(wire)):
        assert check_stream(protocol.read_frame, wire[:cut], 3) == "truncated"
    assert check_stream(lambda r, _limit: protocol.read_frame(r, protocol.MAX_REQUEST_FRAME), wire, 3) == "frame"


def test_a_reader_that_answers_wrongly_is_a_protocol_error() -> None:
    """More bytes than asked, or not bytes at all, are refused instead of trusted."""

    def too_many(count: int) -> bytes:
        return b"x" * (count + 1)

    def not_bytes(count: int) -> bytes:
        return cast("bytes", "text")  # the point of the case: a recv that breaks its contract

    for recv in (too_many, not_bytes):
        with pytest.raises(ProtocolError):
            protocol.read_frame(recv, LIMIT)


def parse_cases(rng: Rng) -> list[bytes]:
    seeds = [
        valid_status(),
        protocol.request_body("check", nonce="0123456789abcdef0123456789abcdef"),
        protocol.request_body("dryrun", approval=APPROVAL),
        protocol.request_body("call", **{**SHAPE, "prompt": "hello", "approval": APPROVAL}),
        protocol.request_body("begin", **{**SHAPE, "prompt_bytes": 5, "max_usd": "0.50"}),
        json.dumps({"v": 1, "op": "status"}).encode(),
        json.dumps({"v": 1, "ok": True, "attachments": []}).encode(),
        json.dumps({"v": 1, "ok": False, "code": "busy", "message": "x", "exit": 3}).encode(),
    ]
    cases = [mutate(rng, rng.choice(seeds)) for _ in range(PARSE_ITERATIONS)]
    cases += [junk(rng) for _ in range(PARSE_ITERATIONS // 4)]
    cases += [b"[" * rng.randrange(1, 5000) + b"]" * rng.randrange(0, 5000) for _ in range(10)]  # nesting depth
    return cases


def test_the_parsers_return_a_value_or_a_protocol_error_for_any_bytes() -> None:
    rng = Rng(SEED + 1)
    parsed = refused = 0
    for body in parse_cases(rng):
        for parse in (protocol.parse_request, protocol.parse_reply):
            try:
                parse(body)
            except ProtocolError as err:
                assert err.code in protocol.REPLY_CODES
                refused += 1
            else:
                parsed += 1
    assert refused > 0 and parsed > 0, (refused, parsed)


@pytest.fixture(scope="module")
def key(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_key(tmp_path_factory.mktemp("keys") / "a")


def test_the_server_answers_any_bytes_with_a_refusal_or_closes_and_changes_nothing(tmp_path: Path, key: Path) -> None:
    rig = Rig(tmp_path, key)
    env = Env(rig)
    before = state_snapshot(rig)
    rng = Rng(SEED + 2)
    answered = silent = 0
    for _ in range(SERVER_ITERATIONS):
        kind = rng.randrange(4)
        if kind == 0:
            raw = junk(rng)
        elif kind == 1:
            raw = framed(rng, junk(rng, 400))
        elif kind == 2:
            raw = mutate(rng, framed(rng, valid_status()))
        else:
            raw = framed(rng, mutate(rng, valid_status()))
        try:
            request = protocol.parse_request(raw[4:])  # would these bytes be a valid request?
            body_ok = len(raw) - 4 == protocol.HEADER.unpack(raw[:4])[0]
        except ProtocolError:
            request, body_ok = None, False
        result = env.exchange(raw=raw)
        if not result.frames:
            silent += 1  # closed without a word: allowed
            continue
        answered += 1
        reply = protocol.parse_reply(result.frames[0])
        if reply["ok"]:
            assert request is not None and request.op == "status" and body_ok, "ok only for a valid status request"
        else:
            assert reply["code"] in protocol.REPLY_CODES
        assert len(result.frames) == 1, "a refusal carries no attachment"
    assert answered > 0 and silent >= 0 and answered + silent == SERVER_ITERATIONS
    assert state_snapshot(rig) == before, "no input changed the ledger, the issued table or the used markers"
    bad = env.exchange(raw=protocol.HEADER.pack(protocol.MAX_REQUEST_FRAME + 1) + b"x")
    assert bad.frames and protocol.parse_reply(bad.frames[0])["code"] == "too_large"


def test_the_harness_catches_a_reader_that_breaks_the_properties() -> None:
    """The negative case: a reader that crashes, hangs or returns an empty frame is reported, not swallowed."""

    def crashes(recv: Callable[[int], bytes], limit: int) -> bytes:
        return bytes([protocol.read_frame(recv, limit)[999]])  # IndexError on a short body

    def returns_empty(recv: Callable[[int], bytes], limit: int) -> bytes:
        return b""

    def never_finishes(recv: Callable[[int], bytes], limit: int) -> bytes:
        while True:
            recv(1)

    good = protocol.frame(valid_status(), LIMIT)
    with pytest.raises(IndexError):
        check_stream(crashes, good, 5)
    with pytest.raises(AssertionError):
        check_stream(returns_empty, good, 5)
    with pytest.raises(AssertionError, match="did not finish"):
        check_stream(never_finishes, good, 5)
