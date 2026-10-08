# SPDX-License-Identifier: MIT
"""Parsing what GitHub sent: a bad value is a MalformedDataError naming the field, never a bare ValueError."""

from __future__ import annotations

import datetime as dt
import re

from safo.errors import MalformedDataError

MAX_INT = 2**31 - 1  # GitHub GraphQL Int is 32-bit signed; a count or number is never negative
_DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


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
