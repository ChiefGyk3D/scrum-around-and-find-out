# SPDX-License-Identifier: MIT
"""values: a malformed live value is an error that names the field, never a bare ValueError."""

from __future__ import annotations

import datetime as dt

import pytest

from safo.errors import ApiError, MalformedDataError, SafoError
from safo.values import iso_day, whole_number


def test_a_whole_number_is_read_from_an_int_or_from_digits() -> None:
    assert whole_number(7, "x") == 7 and whole_number("12", "x") == 12


@pytest.mark.parametrize("value", [None, True, 1.5, "1e3", "-1", "", [1], "\u0661\u0662", "9" * 40])
def test_a_bad_number_is_an_error_that_names_the_field(value: object) -> None:
    with pytest.raises(ApiError, match=r"items\.content\.number: expected a whole number"):
        whole_number(value, "items.content.number")
    assert issubclass(ApiError, SafoError)


def test_a_date_is_read_from_an_iso_day() -> None:
    assert iso_day("2026-10-08", "x") == dt.date(2026, 10, 8)


@pytest.mark.parametrize("value", [None, "", "2026-13-01", "yesterday", 20261008, "2026-10-08T00:00:00Z"])
def test_a_bad_date_is_an_error_that_names_the_field(value: object) -> None:
    with pytest.raises(ApiError, match=r"iterations\.startDate: expected a date as YYYY-MM-DD"):
        iso_day(value, "iterations.startDate")


def test_the_bad_value_is_never_echoed() -> None:
    with pytest.raises(ApiError) as caught:
        whole_number("sentinel-secret", "x")
    assert "sentinel-secret" not in str(caught.value)


@pytest.mark.parametrize("value", ["20261008", "2026-W41-4", "2026-10-08\n", "٢٠٢٦-10-08"])
def test_a_date_in_another_iso_shape_is_refused(value: str) -> None:
    """date.fromisoformat takes more than YYYY-MM-DD; the live field is exactly that and nothing else."""
    with pytest.raises(MalformedDataError, match="expected a date as YYYY-MM-DD"):
        iso_day(value, "x")


def test_a_malformed_value_is_an_api_error_that_audit_can_tell_apart() -> None:
    with pytest.raises(MalformedDataError) as number:
        whole_number("many", "x")
    with pytest.raises(MalformedDataError) as day:
        iso_day("soon", "x")
    assert issubclass(MalformedDataError, ApiError)
    assert "not an integer" in str(number.value) and "not a date" in str(day.value)


@pytest.mark.parametrize("value", [-1, 2**31, 10**100, "2147483648", True])
def test_a_negative_or_oversized_integer_is_refused_and_never_echoed(value: object) -> None:
    """GitHub's GraphQL Int is 32-bit signed; a count or a project number is never negative."""
    with pytest.raises(MalformedDataError, match="expected a whole number") as caught:
        whole_number(value, "x")
    assert str(value) not in str(caught.value).replace("2**31", "")


def test_the_largest_graphql_int_is_accepted() -> None:
    assert whole_number(2**31 - 1, "x") == 2**31 - 1 and whole_number("0", "x") == 0
