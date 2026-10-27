# SPDX-License-Identifier: Apache-2.0
"""A response may be framed by Content-Length or by plain `Transfer-Encoding: chunked`, never both and never anything
else. http.client decodes a chunked body and ignores what Content-Length says about it, so a response that carries both
would be accepted as complete when the two happen to agree: an ambiguously framed answer is not a definite one."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler

import pytest

from safo.errors import ApiError, UnknownOutcomeError
from test_graphql_body_cap import (
    MUTATION,
    MUTATION_ANSWER,
    QUERY,
    QUERY_ANSWER,
    Respond,
    ask,
    raw_server,
    refused,
)


def chunked(body: bytes) -> bytes:
    return f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"


def framed(*header_lines: bytes, body: bytes) -> Respond:
    """A response with exactly these framing header lines, then the given (already framed) body bytes."""

    def respond(handler: BaseHTTPRequestHandler) -> None:
        head = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
        handler.wfile.write(head + b"".join(line + b"\r\n" for line in header_lines) + b"\r\n" + body)

    return respond


def with_length(answer: bytes, extra: int = 0) -> bytes:
    return b"Content-Length: " + str(len(answer) + extra).encode()


TE = b"Transfer-Encoding: "


def cases(answer: bytes) -> list[tuple[str, tuple[bytes, ...]]]:
    return [
        ("chunked and an agreeing length", (TE + b"chunked", with_length(answer))),
        ("chunked and a disagreeing length", (TE + b"chunked", with_length(answer, 7))),
        ("length first, then chunked", (with_length(answer), TE + b"chunked")),
        ("gzip", (TE + b"gzip",)),
        ("deflate", (TE + b"deflate",)),
        ("compress", (TE + b"compress",)),
        ("identity", (TE + b"identity",)),
        ("chunked, identity", (TE + b"chunked, identity",)),
        ("identity, chunked", (TE + b"identity, chunked",)),
        ("gzip, chunked", (TE + b"gzip, chunked",)),
        ("chunked, chunked", (TE + b"chunked, chunked",)),
        ("capitalized", (TE + b"Chunked",)),
        ("upper case", (TE + b"CHUNKED",)),
        ("a stray token", (TE + b"chunked ;",)),
        ("trailing spaces", (TE + b"chunked  ",)),
        ("duplicate headers", (TE + b"chunked", TE + b"chunked")),
        ("empty", (TE + b"",)),
    ]


@pytest.mark.parametrize("index", range(17))
def test_each_ambiguous_or_unsupported_framing_is_refused(index: int) -> None:
    """A query gets an ApiError; a sent mutation gets the more specific UnknownOutcomeError."""
    _, lines = cases(QUERY_ANSWER)[index]
    refused(framed(*lines, body=chunked(QUERY_ANSWER)), QUERY, ApiError, "framing")
    _, mutation_lines = cases(MUTATION_ANSWER)[index]
    refused(framed(*mutation_lines, body=chunked(MUTATION_ANSWER)), MUTATION, UnknownOutcomeError, "framing")


def test_the_repro_chunked_with_an_agreeing_length_is_not_a_definite_mutation_success() -> None:
    lines = (TE + b"chunked", with_length(MUTATION_ANSWER))
    refused(framed(*lines, body=chunked(MUTATION_ANSWER)), MUTATION, UnknownOutcomeError, "framing")


def test_plain_chunked_without_a_length_still_works() -> None:
    with raw_server(framed(TE + b"chunked", body=chunked(QUERY_ANSWER))) as (url, _):
        assert ask(url, QUERY) == {"viewer": {"login": "x"}}
    with raw_server(framed(TE + b"chunked", body=chunked(MUTATION_ANSWER))) as (url, _):
        assert ask(url, MUTATION) == {"addItem": {"id": "x"}}


def test_a_plain_content_length_response_still_works() -> None:
    with raw_server(framed(with_length(QUERY_ANSWER), body=QUERY_ANSWER)) as (url, _):
        assert ask(url, QUERY) == {"viewer": {"login": "x"}}
