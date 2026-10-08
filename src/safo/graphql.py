# SPDX-License-Identifier: MIT
"""GraphQL over urllib: retries, backoff, pagination through `$endCursor`.

The token stays inside this object. It is never put in a message, a log line or
an exception, and a dry run sends no mutation at all.
"""

from __future__ import annotations

import http.client
import json
import math
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any, TextIO

from safo import __version__
from safo.errors import (
    ApiError,
    AuthError,
    ConfigError,
    MalformedDataError,
    NotFoundError,
    RateLimitedError,
    SafoError,
    UnknownOutcomeError,
)

JSON = dict[str, Any]
GRAPHQL_URL = "https://api.github.com/graphql"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
_OPERATION = re.compile(r"^\s*(query|mutation)\s+(\w+)")
MAX_PAGES = 1000


def operation_name(document: str) -> str:
    """The one named operation a document defines. Every document must have a name."""
    match = _OPERATION.match(document)
    if not match:
        raise SafoError("a GraphQL document must start with `query Name` or `mutation Name`")
    return match.group(2)


def is_mutation(document: str) -> bool:
    match = _OPERATION.match(document)
    return bool(match and match.group(1) == "mutation")


def _is_mutation_robust(document: str) -> bool:
    """Detect mutation robustly by stripping comments and leading whitespace."""
    # Remove GraphQL comments (# to end of line)
    cleaned = re.sub(r"#[^\n]*", "", document)
    # Match the first operation keyword (query or mutation) ignoring whitespace
    match = re.search(r"\b(query|mutation)\b", cleaned)
    return match is not None and match.group(1) == "mutation"


def _check_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in LOOPBACK):
        return
    raise ConfigError(f"GraphQL URL {url!r} must be https (plain http is accepted for loopback only)")


class _Transport(Exception):
    """The request did not complete. `before_send` is true when no byte of it left this machine."""

    def __init__(self, error: Exception, *, before_send: bool) -> None:
        super().__init__(error.__class__.__name__)
        self.error = error
        self.before_send = before_send


class _Connected:
    """Set once the TCP (and TLS) connection is up; before that nothing has been sent."""

    done = False


def _tracking(base: type[http.client.HTTPConnection], state: _Connected) -> type[http.client.HTTPConnection]:
    class Tracking(base):  # type: ignore[valid-type, misc]
        def connect(self) -> None:
            super().connect()
            state.done = True

    return Tracking


def _http_handler(state: _Connected) -> urllib.request.HTTPHandler:
    class Handler(urllib.request.HTTPHandler):
        def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
            return self.do_open(_tracking(http.client.HTTPConnection, state), req)

    return Handler()


def _https_handler(state: _Connected) -> urllib.request.HTTPSHandler:
    class Handler(urllib.request.HTTPSHandler):
        def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
            return self.do_open(
                _tracking(http.client.HTTPSConnection, state), req, context=getattr(self, "_context", None)
            )

    return Handler()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse all redirects: any 3xx becomes an error, so the token never follows one."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, hdrs: Any, newurl: str) -> Any:
        return None


class Client:
    """`execute(document, variables)`: one named operation, retried on transient failures."""

    def __init__(
        self,
        token: str,
        url: str = GRAPHQL_URL,
        *,
        dry_run: bool = False,
        sleep: Callable[[float], None] = time.sleep,
        max_attempts: int = 5,
        max_wait: float = 120.0,
        timeout: float = 60.0,
        out: TextIO | None = None,
    ) -> None:
        _check_url(url)
        self._token = token
        self._url = url
        self.dry_run = dry_run
        self._sleep = sleep
        self._max_attempts = max_attempts
        self._max_wait = max_wait
        self._timeout = timeout
        self._out = out or sys.stdout
        self.skipped = 0
        self.requests = 0

    def __repr__(self) -> str:
        return f"Client(url={self._url!r}, dry_run={self.dry_run})"

    # -- one request ---------------------------------------------------------

    def execute(
        self, document: str, variables: Mapping[str, Any] | None = None, *, dry_result: JSON | None = None
    ) -> JSON:
        op = operation_name(document)
        if "updateProjectV2Field" in document:
            # It regenerates every option id and wipes every item's value for the field.
            raise SafoError(f"{op}: updateProjectV2Field is never sent; see docs/lessons.md")
        variables = dict(variables or {})
        if _is_mutation_robust(document):
            if self.dry_run:
                self.skipped += 1
                print(f"dry run: would {op} {json.dumps(variables, sort_keys=True, default=str)}", file=self._out)
                return dry_result or {}
            return self._mutate(op, self._payload(document, variables, op))
        return self._query(op, self._payload(document, variables, op))

    @staticmethod
    def _payload(document: str, variables: Mapping[str, Any], op: str) -> bytes:
        return json.dumps({"query": document, "variables": variables, "operationName": op}).encode()

    # -- mutations: one rule ---------------------------------------------------
    #
    # A mutation is never replayed unless the server provably refused it before running it. The
    # refusals that prove it are a connection that failed before any byte was sent, HTTP 401, and an
    # HTTP-level 403/429 that carries a rate-limit signal. Once the request has gone out, the only
    # success is HTTP 200 with a JSON object holding `data` as an object and no errors. Anything
    # else (a timeout, a 5xx, a dropped connection, a body that is not what it should be, any
    # error entry at all, even next to data) says nothing about whether it was applied.

    def _mutate(self, op: str, payload: bytes) -> JSON:
        for attempt in range(1, self._max_attempts + 1):
            try:
                status, headers, raw = self._post(payload)
            except _Transport as err:
                if err.before_send:
                    raise ApiError(f"could not reach GitHub for {op}: {err.error.__class__.__name__}") from None
                raise self._unknown(op, "the connection failed after the request was sent", cause=err.error) from None
            self.requests += 1
            if status == 401:
                raise AuthError(f"GitHub refused the token (401) on {op}")
            if status in (403, 429):
                wait = self._rate_limit_wait(headers, raw, attempt)
                if wait is not None:
                    if attempt == self._max_attempts or wait > self._max_wait:
                        raise RateLimitedError(f"{op}: still rate limited after {attempt} attempts")
                    self._sleep(wait)
                    continue
            return self._mutation_data(op, status, raw)
        raise ApiError(f"GitHub kept failing {op}")  # pragma: no cover - the loop always returns or raises

    def _mutation_data(self, op: str, status: int, raw: bytes) -> JSON:
        """The data of a clean success, or UnknownOutcomeError carrying everything the server said."""
        try:
            body: Any = json.loads(raw)
        except (ValueError, RecursionError):
            body = None
            parsed = False
        else:
            parsed = True
        data: JSON | None = None
        errors: list[dict[str, Any]] | None = None
        if isinstance(body, dict):
            if isinstance(body.get("data"), dict):
                data = body["data"]
            if isinstance(body.get("errors"), list):
                errors = body["errors"]

        def unknown(reason: str) -> UnknownOutcomeError:
            return self._unknown(op, reason, data=data, errors=errors, status=status)

        if status != 200:
            raise unknown(f"GitHub answered {status}")
        if not parsed:
            raise unknown("the response was not valid JSON")
        if not isinstance(body, dict):
            raise unknown(f"the response was {type(body).__name__}, not an object")
        if "errors" in body and body["errors"] != []:
            raise unknown("the response carried errors: " + _describe(body["errors"]))
        if data is None:
            raise unknown("the response had no data object")
        if any(payload is None for payload in data.values()):
            # `{"data": {"createX": null}}` with no errors is not a success: nothing says the write landed.
            raise unknown("the mutation's payload was null")
        return data

    def _unknown(
        self,
        op: str,
        reason: str,
        *,
        cause: Exception | None = None,
        data: JSON | None = None,
        errors: list[dict[str, Any]] | None = None,
        status: int | None = None,
    ) -> UnknownOutcomeError:
        message = (
            f"{op}: the mutation may or may not have been applied ({reason}); "
            "re-read state before retrying, do not simply resend it"
        )
        return UnknownOutcomeError(
            message.replace(self._token, "***") if self._token else message,
            cause,
            data=data,
            errors=errors,
            status=status,
        )

    # -- queries: read-only, so safe to retry -----------------------------------

    def _query(self, op: str, payload: bytes) -> JSON:
        for attempt in range(1, self._max_attempts + 1):
            last = attempt == self._max_attempts
            try:
                status, headers, raw = self._post(payload)
            except _Transport as err:
                if last:
                    raise ApiError(f"could not reach GitHub for {op}: {err.error.__class__.__name__}") from None
                self._sleep(min(self._max_wait, 2.0**attempt))
                continue
            self.requests += 1
            if status == 401:
                raise AuthError(f"GitHub refused the token (401) on {op}")
            if status in (403, 429):
                wait = self._rate_limit_wait(headers, raw, attempt)
                if wait is None:
                    raise AuthError(
                        f"GitHub refused the token ({status}) on {op}; it needs Projects read/write and "
                        "Issues and Pull requests read on the installation that owns the repositories"
                    )
                if last or wait > self._max_wait:
                    raise RateLimitedError(f"{op}: still rate limited after {attempt} attempts")
                self._sleep(wait)
                continue
            if status in (500, 502, 503, 504):
                if last:
                    raise ApiError(f"GitHub answered {status} to {op} {attempt} times")
                self._sleep(min(self._max_wait, 2.0**attempt))
                continue
            if status != 200:
                raise ApiError(f"GitHub answered {status} to {op}")
            try:
                body: JSON = json.loads(raw)
            except json.JSONDecodeError as err:
                raise ApiError(f"GitHub answered {op} with invalid JSON: {err}") from None
            if not isinstance(body, dict):
                raise ApiError(f"GitHub answered {op} with non-object JSON: {type(body).__name__}")
            errors: list[dict[str, Any]] = body.get("errors") or []
            if not errors:
                if "data" not in body:
                    raise ApiError(f"GitHub answered {op} with neither errors nor data")
                data: JSON = body["data"]
                if data is None:
                    raise ApiError(f"GitHub answered {op} with null data and no errors")
                return data
            types = {str(e.get("type", "")) for e in errors}
            message = "; ".join(str(e.get("message", e)) for e in errors)
            if "INSUFFICIENT_SCOPES" in types:
                raise AuthError(
                    f"{op}: the token lacks a scope the query needs ({message}); for `gh` run "
                    "`gh auth refresh -s project`, for an App grant the Projects permission"
                )
            if "RATE_LIMITED" in types and not last:
                self._sleep(min(self._max_wait, 30.0 * attempt))
                continue
            if types == {"NOT_FOUND"}:
                raise NotFoundError(f"{op}: {message}", errors, body.get("data"))
            raise ApiError(f"GitHub rejected {op}: {message}", errors, body.get("data"))
        raise ApiError(f"GitHub kept failing {op}")  # pragma: no cover - the loop always returns or raises

    def _post(self, payload: bytes) -> tuple[int, Mapping[str, str], bytes]:
        """One POST. A transport failure is raised as _Transport, saying whether any byte was sent."""
        request = urllib.request.Request(  # noqa: S310 - _check_url allows https or loopback only
            self._url,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "User-Agent": f"safo/{__version__}",
            },
        )
        connected = _Connected()
        opener = urllib.request.build_opener(_NoRedirect, _http_handler(connected), _https_handler(connected))
        try:
            try:
                response = opener.open(request, timeout=self._timeout)
                with response as resp:
                    return resp.status, _lower(resp.headers.items()), resp.read()
            except urllib.error.HTTPError as err:
                return err.code, _lower(err.headers.items()), err.read()
        except (OSError, http.client.HTTPException) as err:
            raise _Transport(err, before_send=not connected.done) from None

    def _rate_limit_wait(self, headers: Mapping[str, str], raw: bytes, attempt: int) -> float | None:
        """Seconds to wait, or None when a 403 is a refusal rather than a rate limit."""
        if "retry-after" in headers:
            try:
                wait = float(headers["retry-after"])
                if math.isfinite(wait) and wait >= 0:
                    return wait
            except ValueError:
                pass
            return 60.0
        text = raw.decode("utf-8", "replace").lower()
        if "secondary rate limit" in text or "abuse detection" in text:
            return min(self._max_wait, 60.0 * attempt)
        if headers.get("x-ratelimit-remaining") == "0" and "x-ratelimit-reset" in headers:
            try:
                reset = float(headers["x-ratelimit-reset"])
                if math.isfinite(reset) and reset >= 0:
                    return max(0.0, reset - time.time())
            except ValueError:
                # Invalid reset header: fall back to computed backoff
                return min(self._max_wait, 60.0 * attempt)
        return None

    # -- pagination ------------------------------------------------------------

    def pages(
        self, document: str, variables: Mapping[str, Any], path: Sequence[str], require: Sequence[str] = ()
    ) -> Iterator[JSON]:
        """Yield each page's connection object. The document declares `$endCursor: String`.

        Every node must be an object holding each key in `require` (non-null); anything else is
        MalformedDataError, because a node that is skipped or half-read makes a partial read look complete.
        """
        cursor: str | None = None
        seen: set[str] = set()
        page_count = 0
        while True:
            data = self.execute(document, {**variables, "endCursor": cursor})
            node: Any = data
            for key in path:
                node = node.get(key) if isinstance(node, dict) else None
                if node is None:
                    raise NotFoundError(f"{operation_name(document)}: nothing at {'.'.join(path)}")
            connection = _connection(operation_name(document), node, require)
            yield connection
            info = connection["pageInfo"]
            if not info["hasNextPage"]:
                return
            page_count += 1
            if page_count >= MAX_PAGES:
                raise ApiError(f"{operation_name(document)}: exceeded {MAX_PAGES} pages")
            next_cursor = info.get("endCursor")
            if next_cursor is None or next_cursor == "":
                raise ApiError(f"{operation_name(document)}: hasNextPage is true but endCursor is null or empty")
            cursor = str(next_cursor)
            if cursor in seen:
                raise ApiError(f"{operation_name(document)}: GitHub repeated the cursor {cursor}")
            seen.add(cursor)

    def nodes(
        self, document: str, variables: Mapping[str, Any], path: Sequence[str], require: Sequence[str] = ()
    ) -> Iterator[JSON]:
        for page in self.pages(document, variables, path, require):
            for node in page["nodes"]:
                if node is not None:
                    yield node


def _connection(op: str, node: Any, require: Sequence[str] = ()) -> JSON:
    """A connection with a boolean hasNextPage and a list of non-null nodes, or MalformedDataError.

    A page that cannot be read in full must never look like the last page, and a null node must never
    be skipped: either would make a partial read look complete.
    """
    if not isinstance(node, dict):
        raise MalformedDataError(f"{op}: the connection is {type(node).__name__}, not an object")
    info = node.get("pageInfo")
    if not isinstance(info, dict) or not isinstance(info.get("hasNextPage"), bool):
        raise MalformedDataError(f"{op}: pageInfo.hasNextPage is missing or not a boolean")
    rows = node.get("nodes")
    if not isinstance(rows, list):
        raise MalformedDataError(f"{op}: the connection has no list of nodes")
    for row in rows:
        if row is None:
            raise MalformedDataError(f"{op}: the connection contains a null node")
        if not isinstance(row, dict):
            raise MalformedDataError(
                f"{op}: the connection contains a node that is {type(row).__name__}, not an object"
            )
        missing = [key for key in require if row.get(key) is None]
        if missing:
            raise MalformedDataError(f"{op}: a node lacks {', '.join(missing)}")
    return node


def _describe(errors: Any) -> str:
    """The error messages in a response, short enough for one line."""
    entries = errors if isinstance(errors, list) else [errors]
    text = "; ".join(str(e.get("message", e)) if isinstance(e, dict) else str(e) for e in entries)
    return text if len(text) <= 300 else text[:300] + "..."


def _lower(items: Any) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in items}
