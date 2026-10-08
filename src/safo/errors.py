# SPDX-License-Identifier: MIT
"""Errors, each carrying the exit code the command line returns for it."""

from __future__ import annotations

from typing import Any

EXIT_OK = 0
EXIT_DRIFT = 1  # drift found, or something could not be fixed
EXIT_UNKNOWN = 2  # the question could not be asked: bad config, bad token, unreachable


class SafoError(Exception):
    """A problem the operator can fix; printed as one sentence, never a traceback."""

    exit_code = EXIT_UNKNOWN


class ConfigError(SafoError):
    """board.yaml or an Action input is wrong. The message names the key."""


class AuthError(SafoError):
    """GitHub refused the token (401, or 403 that is not a rate limit)."""


class ApiError(SafoError):
    """GitHub answered with an error the caller cannot work around."""

    def __init__(self, message: str, errors: list[dict[str, Any]] | None = None, data: dict[str, Any] | None = None):
        super().__init__(message)
        self.errors = errors or []
        self.data = data


class MalformedDataError(ApiError):
    """GitHub answered with a value of the wrong kind (a date that is not a date, a count that is not a number).

    An ApiError, so a caller that guards against any bad answer catches it; a distinct class, so audit can
    report "cannot tell" for it. The message names the field and never echoes the value.
    """


class NotFoundError(ApiError):
    """Every GraphQL error was NOT_FOUND: a deleted node, or one the token cannot see."""


class RateLimitedError(ApiError):
    """Still rate limited after every retry, or the reset is further away than we will wait."""


class UnknownOutcomeError(ApiError):
    """A mutation's outcome is unknown: the server may or may not have processed it.

    The caller must re-read state to decide whether to retry. Can wrap a transport failure
    (cause), or carry whatever the server answered: the HTTP status, and the data and errors
    that arrived with it, which may show a partial success.
    """

    def __init__(
        self,
        message: str,
        cause: Exception | None = None,
        data: dict[str, Any] | None = None,
        errors: list[dict[str, Any]] | None = None,
        status: int | None = None,
    ):
        super().__init__(message, errors, data)
        self.cause = cause
        self.status = status
