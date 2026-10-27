# SPDX-License-Identifier: Apache-2.0
"""The response-size cap is enforced where the body is read, so a query and a mutation are both covered.

A raw loopback server answers with exactly the bytes and headers each case needs; MAX_BODY is lowered through its
module attribute so the cases stay small.
"""

from __future__ import annotations

import gzip
import json
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from safo import graphql
from safo.errors import ApiError, UnknownOutcomeError

CAP = 2000
QUERY = "query Q { viewer { login } }"
MUTATION = "mutation AddItem($x: ID!) { addItem(input: {x: $x}) { id } }"
QUERY_ANSWER = b'{"data": {"viewer": {"login": "x"}}}'
MUTATION_ANSWER = b'{"data": {"addItem": {"id": "x"}}}'

Respond = Callable[[BaseHTTPRequestHandler], None]


@pytest.fixture(autouse=True)
def _small_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(graphql, "MAX_BODY", CAP)


@contextmanager
def raw_server(respond: Respond) -> Iterator[tuple[str, list[dict[str, str]]]]:
    seen: list[dict[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append({key.lower(): value for key, value in self.headers.items()})
            respond(self)

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/graphql", seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def sends(
    body: bytes, *, status: int = 200, length: int | None = None, headers: dict[str, str] | None = None
) -> Respond:
    def respond(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body) if length is None else length))
        for key, value in (headers or {}).items():
            handler.send_header(key, value)
        handler.end_headers()
        handler.wfile.write(body)

    return respond


def padded(answer: bytes, size: int) -> bytes:
    assert len(answer) <= size
    return answer + b" " * (size - len(answer))


def client(url: str) -> graphql.Client:
    return graphql.Client("test-token", url, sleep=lambda _s: None, max_attempts=2)


def refused(respond: Respond, document: str, error: type[Exception], match: str | None = None) -> Exception:
    """Serve `respond`, ask `document`, and return the exception the client raised (the test fails if none)."""
    with raw_server(respond) as (url, _), pytest.raises(error, match=match) as caught:
        ask(url, document)
    return caught.value


def ask(url: str, document: str) -> Any:
    return client(url).execute(document, {"x": "1"} if document == MUTATION else {})


# -- the cap, on both paths ------------------------------------------------------------------------------------------


def test_a_query_answer_of_exactly_the_cap_is_accepted() -> None:
    with raw_server(sends(padded(QUERY_ANSWER, CAP))) as (url, _):
        assert ask(url, QUERY) == {"viewer": {"login": "x"}}


def test_a_query_answer_one_byte_over_the_cap_is_refused() -> None:
    with raw_server(sends(padded(QUERY_ANSWER, CAP + 1))) as (url, _), pytest.raises(ApiError, match="too large"):
        ask(url, QUERY)


def test_a_mutation_answer_of_exactly_the_cap_is_accepted() -> None:
    with raw_server(sends(padded(MUTATION_ANSWER, CAP))) as (url, _):
        assert ask(url, MUTATION) == {"addItem": {"id": "x"}}


def test_a_mutation_answer_one_byte_over_the_cap_is_an_unknown_outcome() -> None:
    error = refused(sends(padded(MUTATION_ANSWER, CAP + 1)), MUTATION, UnknownOutcomeError, "too large")
    assert isinstance(error, ApiError)  # callers that guard against ApiError still catch it


def test_a_mutation_answer_far_over_the_cap_with_a_valid_json_prefix_is_not_a_success() -> None:
    """The prefix alone is a clean success; the bytes after it were never read. It must not count as one."""
    with raw_server(sends(padded(MUTATION_ANSWER, CAP * 10))) as (url, _), pytest.raises(UnknownOutcomeError):
        ask(url, MUTATION)


def test_a_query_answer_far_over_the_cap_with_a_valid_json_prefix_is_refused() -> None:
    with raw_server(sends(padded(QUERY_ANSWER, CAP * 10))) as (url, _), pytest.raises(ApiError, match="too large"):
        ask(url, QUERY)


@pytest.mark.parametrize("status", [403, 500, 502, 404])
def test_an_oversized_error_body_is_refused_too(status: int) -> None:
    with raw_server(sends(b"x" * (CAP + 1), status=status)) as (url, _), pytest.raises(ApiError, match="too large"):
        ask(url, QUERY)


def test_the_cap_does_not_stop_a_normal_answer() -> None:
    with raw_server(sends(QUERY_ANSWER)) as (url, _):
        assert ask(url, QUERY) == {"viewer": {"login": "x"}}


# -- bodies that are not what the headers say ------------------------------------------------------------------------


def chunked_and_cut(handler: BaseHTTPRequestHandler) -> None:
    handler.send_response(200)
    handler.send_header("Transfer-Encoding", "chunked")
    handler.end_headers()
    handler.wfile.write(b"5\r\nhello\r\n")  # no terminating chunk: the connection just ends


def test_a_chunked_answer_that_ends_early_is_never_a_success() -> None:
    with raw_server(chunked_and_cut) as (url, _), pytest.raises(ApiError):
        ask(url, QUERY)
    with raw_server(chunked_and_cut) as (url, _), pytest.raises(UnknownOutcomeError):
        ask(url, MUTATION)


def test_a_content_length_larger_than_the_body_is_an_incomplete_read() -> None:
    with raw_server(sends(QUERY_ANSWER, length=len(QUERY_ANSWER) + 50)) as (url, _), pytest.raises(ApiError):
        ask(url, QUERY)
    refused(sends(MUTATION_ANSWER, length=len(MUTATION_ANSWER) + 50), MUTATION, UnknownOutcomeError)


def test_a_content_length_smaller_than_the_body_cuts_the_body_and_is_never_a_success() -> None:
    cut = sends(MUTATION_ANSWER + b" " * 100, length=len(MUTATION_ANSWER) - 5)
    with raw_server(cut) as (url, _), pytest.raises(UnknownOutcomeError):
        ask(url, MUTATION)
    refused(sends(QUERY_ANSWER + b" " * 100, length=len(QUERY_ANSWER) - 5), QUERY, ApiError)


def test_a_content_length_that_is_not_a_number_is_refused_whatever_the_size() -> None:
    def respond_with(answer: bytes) -> Respond:
        def respond(handler: BaseHTTPRequestHandler) -> None:
            handler.send_response(200)
            handler.send_header("Content-Length", "lots")
            handler.end_headers()
            handler.wfile.write(answer)

        return respond

    refused(respond_with(padded(QUERY_ANSWER, CAP + 1)), QUERY, ApiError, "framing")
    refused(respond_with(padded(MUTATION_ANSWER, CAP + 1)), MUTATION, UnknownOutcomeError, "framing")


# -- encodings -------------------------------------------------------------------------------------------------------


def test_the_client_never_asks_for_a_compressed_answer() -> None:
    with raw_server(sends(QUERY_ANSWER)) as (url, seen):
        ask(url, QUERY)
    assert seen[0].get("accept-encoding", "identity") == "identity"  # urllib says `identity` by itself


@pytest.mark.parametrize("encoding", ["gzip", "deflate", "br"])
def test_a_compressed_answer_is_not_decoded_and_is_never_a_success(encoding: str) -> None:
    body = gzip.compress(json.dumps({"data": {"viewer": {"login": "x"}}}).encode())
    with raw_server(sends(body, headers={"Content-Encoding": encoding})) as (url, _), pytest.raises(ApiError):
        ask(url, QUERY)
    body = gzip.compress(MUTATION_ANSWER)
    refused(sends(body, headers={"Content-Encoding": encoding}), MUTATION, UnknownOutcomeError)


def test_a_compression_bomb_is_never_expanded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(graphql, "MAX_BODY", 1_000_000)  # above the compressed size, far below the expanded one
    bomb = gzip.compress(b"0" * (200 * 1024 * 1024))
    assert len(bomb) < 1_000_000
    with raw_server(sends(bomb, headers={"Content-Encoding": "gzip"})) as (url, _), pytest.raises(ApiError):
        ask(url, QUERY)
