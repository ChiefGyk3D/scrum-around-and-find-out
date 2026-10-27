# SPDX-License-Identifier: Apache-2.0
"""Content-Length is ASCII digits or the response is not trusted, and `data` is an object.

http.client reads Content-Length with int(), which accepts a sign, spaces, underscores and non-ASCII digits. A stricter
check in the client has to refuse every value int() is lenient about, or a connection closed after a valid JSON prefix
reads as a complete answer, and an applied mutation as a definite success.
"""

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
    sends,
)


def raw_framing(*length_lines: bytes, body: bytes) -> Respond:
    """A response with exactly these header lines (bytes, so non-ASCII digits can be sent), then the body, then the
    connection closes: a body shorter than the length it announces."""

    def respond(handler: BaseHTTPRequestHandler) -> None:
        head = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
        head += b"".join(line + b"\r\n" for line in length_lines)
        handler.wfile.write(head + b"\r\n" + body)

    return respond


MALFORMED = [
    pytest.param((b"Content-Length: +100",), id="plus sign"),
    pytest.param((b"Content-Length: 1_00",), id="underscore"),
    pytest.param((b"Content-Length: \xef\xbc\x91\xef\xbc\x90\xef\xbc\x90",), id="fullwidth digits"),
    pytest.param((b"Content-Length: 100, 100",), id="comma list"),
    pytest.param((b"Content-Length: ",), id="empty"),
    pytest.param((b"Content-Length: 35", b"Content-Length: 100"), id="conflicting headers"),
    pytest.param((b"Content-Length: 100", b"Content-Length: 100"), id="repeated header"),
    pytest.param((b"Content-Length: 1234567890123456",), id="sixteen digits"),
    pytest.param((b"Content-Length: -1",), id="negative"),
]


@pytest.mark.parametrize("lines", MALFORMED)
def test_a_malformed_content_length_is_never_a_complete_answer(lines: tuple[bytes, ...]) -> None:
    refused(raw_framing(*lines, body=QUERY_ANSWER), QUERY, ApiError, "framing")
    refused(raw_framing(*lines, body=MUTATION_ANSWER), MUTATION, UnknownOutcomeError, "framing")


def test_a_content_length_with_extra_spaces_is_normalized_by_the_parser_and_a_short_body_still_fails() -> None:
    """The header parser strips the spaces, so the value reads `100`: well formed, and the body is shorter."""
    refused(raw_framing(b"Content-Length:   100  ", body=QUERY_ANSWER), QUERY, ApiError)
    refused(raw_framing(b"Content-Length:   100  ", body=MUTATION_ANSWER), MUTATION, UnknownOutcomeError)


def test_a_well_formed_content_length_still_works() -> None:
    length = str(len(QUERY_ANSWER)).encode()
    with raw_server(raw_framing(b"Content-Length: " + length, body=QUERY_ANSWER)) as (url, _):
        assert ask(url, QUERY) == {"viewer": {"login": "x"}}
    length = str(len(MUTATION_ANSWER)).encode()
    with raw_server(raw_framing(b"Content-Length: " + length, body=MUTATION_ANSWER)) as (url, _):
        assert ask(url, MUTATION) == {"addItem": {"id": "x"}}


def test_fifteen_digits_are_well_formed_and_a_short_body_is_then_incomplete() -> None:
    refused(raw_framing(b"Content-Length: 123456789012345", body=QUERY_ANSWER), QUERY, ApiError)
    refused(raw_framing(b"Content-Length: 123456789012345", body=MUTATION_ANSWER), MUTATION, UnknownOutcomeError)


DATA_NOT_AN_OBJECT = [b'{"data": []}', b'{"data": 42}', b'{"data": "x"}', b'{"data": true}', b'{"data": null}']


@pytest.mark.parametrize("answer", DATA_NOT_AN_OBJECT)
def test_data_that_is_not_an_object_is_an_error_for_a_query(answer: bytes) -> None:
    refused(sends(answer), QUERY, ApiError)


@pytest.mark.parametrize("answer", DATA_NOT_AN_OBJECT)
def test_data_that_is_not_an_object_is_an_unknown_outcome_for_a_mutation(answer: bytes) -> None:
    refused(sends(answer), MUTATION, UnknownOutcomeError)


def test_a_query_whose_data_is_an_empty_object_is_still_an_answer() -> None:
    with raw_server(sends(b'{"data": {}}')) as (url, _):
        assert ask(url, QUERY) == {}


# -- a response with no framing at all, and a declared Content-Encoding on a body that parses ---------------------------


def test_a_response_with_no_framing_headers_is_never_a_complete_answer() -> None:
    """Close-delimited: a clean end cannot be told from a cut right after a valid JSON prefix."""
    refused(raw_framing(b"Connection: close", body=QUERY_ANSWER), QUERY, ApiError, "framing")
    refused(raw_framing(b"Connection: close", body=MUTATION_ANSWER), MUTATION, UnknownOutcomeError, "framing")
    refused(raw_framing(body=MUTATION_ANSWER), MUTATION, UnknownOutcomeError, "framing")


@pytest.mark.parametrize("encoding", ["gzip", "GZIP", "deflate", "br", "identity, gzip", "compress"])
def test_a_declared_content_encoding_on_a_valid_json_body_is_never_a_success(encoding: str) -> None:
    """The body is plain JSON that would parse: only the header says it cannot be trusted as sent."""
    headers = {"Content-Encoding": encoding}
    with raw_server(sends(QUERY_ANSWER, headers=headers)) as (url, _), pytest.raises(ApiError, match="Content-Encoding"):
        ask(url, QUERY)
    refused(sends(MUTATION_ANSWER, headers=headers), MUTATION, UnknownOutcomeError, "Content-Encoding")


@pytest.mark.parametrize("encoding", ["identity", "Identity"])
def test_an_identity_content_encoding_is_accepted(encoding: str) -> None:
    with raw_server(sends(MUTATION_ANSWER, headers={"Content-Encoding": encoding})) as (url, _):
        assert ask(url, MUTATION) == {"addItem": {"id": "x"}}
