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


class NotFoundError(ApiError):
    """Every GraphQL error was NOT_FOUND: a deleted node, or one the token cannot see."""


class RateLimitedError(ApiError):
    """Still rate limited after every retry, or the reset is further away than we will wait."""
