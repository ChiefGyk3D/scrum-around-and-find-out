# SPDX-License-Identifier: MIT
"""Parsing what GitHub sent: a bad value is a MalformedDataError naming the field, never a bare ValueError."""

from __future__ import annotations

import datetime as dt
import re

from safo.errors import MalformedDataError

MAX_INT = 2**31 - 1  # GitHub GraphQL Int is 32-bit signed; a count or number is never negative
_DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_STAMP = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.[0-9]+)?(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)


def _kind(value: object) -> str:
    return type(value).__name__  # the type, never the value: it may be anything a payload carried


def whole_number(value: object, what: str) -> int:
    """An int in 0..2**31-1, or a short string of ASCII digits in that range. Booleans, floats, exponents refused."""
    if type(value) is int and 0 <= value <= MAX_INT:
        return value
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 18 and int(value) <= MAX_INT:
        return int(value)
    raise MalformedDataError(
        f"{what}: expected a whole number, got {_kind(value)} (the value on the project is not an integer)"
    )


def iso_day(value: object, what: str) -> dt.date:
    """A date written YYYY-MM-DD."""
    if isinstance(value, str) and _DAY.fullmatch(value):  # fromisoformat alone also takes 20261008 and 2026-W41-4
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            pass
    raise MalformedDataError(
        f"{what}: expected a date as YYYY-MM-DD, got {_kind(value)} (the value on the project is not a date)"
    )


def utc_timestamp(value: object, what: str) -> dt.datetime:
    """An RFC 3339 timestamp with an explicit offset (`Z` or `+hh:mm`), converted to UTC.

    A bare date, a missing offset, trailing text and out-of-range parts are refused: a day computed from a
    timestamp is only the right day once it is in UTC.
    """
    if isinstance(value, str):
        match = _STAMP.fullmatch(value)
        if match:
            offset = "+00:00" if match.group(2) == "Z" else match.group(2)
            try:
                return dt.datetime.fromisoformat(match.group(1) + offset).astimezone(dt.UTC)
            except (ValueError, OverflowError):
                pass
    raise MalformedDataError(
        f"{what}: expected a timestamp such as 2000-01-02T03:04:05Z, got {_kind(value)} "
        "(the value from GitHub is not a valid RFC 3339 timestamp)"
    )
