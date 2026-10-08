# SPDX-License-Identifier: MIT
"""Parsing what GitHub sent: a bad value is a MalformedDataError naming the field, never a bare ValueError."""

from __future__ import annotations

import datetime as dt
import re

from safo.errors import MalformedDataError

_DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _kind(value: object) -> str:
    return type(value).__name__  # the type, never the value: it may be anything a payload carried


def whole_number(value: object, what: str) -> int:
    """An int, or a short string of ASCII digits. Booleans, floats, signs and exponents are refused."""
    if type(value) is int:
        return value
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 18:
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
