# SPDX-License-Identifier: Apache-2.0
"""Integer micro-dollars: exact parsing, one canonical text, round-up division."""

from __future__ import annotations

from typing import Any

import pytest

from brokerdata import Rng
from safo.broker.money import MAX_MICRO, MICRO, MoneyError, ceil_div, format_usd, parse_usd


@pytest.mark.parametrize(
    ("text", "micro"),
    [
        ("0", 0),
        ("1", MICRO),
        ("2.5", 2_500_000),
        ("0.000001", 1),
        ("10", 10_000_000),
        ("0.0336", 33_600),
        ("999999999.999999", 999_999_999_999_999),
    ],
)
def test_parse_exact(text: str, micro: int) -> None:
    if micro > MAX_MICRO:
        with pytest.raises(MoneyError):
            parse_usd(text)
    else:
        assert parse_usd(text) == micro


@pytest.mark.parametrize(
    "text",
    [
        "",
        " 1",
        "1 ",
        "-1",
        "+1",
        "1e3",
        "1E3",
        "0x10",
        "1.",
        ".5",
        "1.0000001",
        "01",
        "1,5",
        "NaN",
        "inf",
        "\uff11",
        "1\n",
        "1000001",
        "1" * 20,
    ],
)
def test_parse_refuses(text: str) -> None:
    with pytest.raises(MoneyError):
        parse_usd(text)


@pytest.mark.parametrize("value", [1, 1.5, True, None, b"1", ["1"], object()])
def test_parse_refuses_non_text(value: object) -> None:
    with pytest.raises(MoneyError):
        parse_usd(value)


def test_parse_refuses_a_str_subclass() -> None:
    class Lying(str):
        pass

    with pytest.raises(MoneyError):
        parse_usd(Lying("1"))


def test_a_seventh_decimal_is_refused_not_rounded() -> None:
    with pytest.raises(MoneyError):
        parse_usd("0.0000004")
    with pytest.raises(MoneyError):
        parse_usd("0.0000005")


def test_format_is_canonical_and_round_trips() -> None:
    assert [format_usd(n) for n in (0, 1, 33_600, 2_500_000, 10_000_000, MAX_MICRO)] == [
        "0",
        "0.000001",
        "0.0336",
        "2.5",
        "10",
        "1000000",
    ]
    rng = Rng(205)
    for _ in range(5000):
        n = rng.choice([rng.randrange(0, 20_000_000), rng.randrange(0, MAX_MICRO + 1)])
        assert parse_usd(format_usd(n)) == n
        assert format_usd(parse_usd(format_usd(n))) == format_usd(n)


@pytest.mark.parametrize("value", [-1, MAX_MICRO + 1, 1.0, True, "1", None])
def test_format_refuses_out_of_range_and_wrong_types(value: Any) -> None:
    with pytest.raises(MoneyError):
        format_usd(value)


def test_ceil_div_rounds_up_and_never_down() -> None:
    rng = Rng(7)
    for _ in range(5000):
        n, d = rng.randrange(0, 10**15), rng.randrange(1, 10**7)
        q = ceil_div(n, d)
        assert q * d >= n
        assert (q - 1) * d < n or q == 0
    assert ceil_div(0, 5) == 0
    assert ceil_div(1, 1_000_000) == 1
    assert ceil_div(1_000_000, 1_000_000) == 1
    assert ceil_div(1_000_001, 1_000_000) == 2


@pytest.mark.parametrize(("n", "d"), [(-1, 1), (1, 0), (1, -1)])
def test_ceil_div_refuses_nonsense(n: int, d: int) -> None:
    with pytest.raises(MoneyError):
        ceil_div(n, d)
