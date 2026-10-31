# SPDX-License-Identifier: Apache-2.0
"""Money is an integer count of micro-dollars (millionths of a US dollar). There is no float and no Decimal here."""

from __future__ import annotations

import re

MICRO = 1_000_000
MAX_MICRO = 10**12  # 1,000,000 USD: far under 2**63, so no sum of bounded amounts can overflow a 64-bit field
_USD = re.compile(r"(0|[1-9][0-9]{0,8})(?:\.([0-9]{1,6}))?")


class MoneyError(ValueError):
    """An amount that is not a plain, bounded US dollar figure."""


def parse_usd(text: object) -> int:
    """Exact micro-dollars from text such as "2.5" or "0.000001": at most six decimals (a seventh is refused, never
    rounded), no sign, no exponent, no spaces, a plain `str` only."""
    if type(text) is not str:
        raise MoneyError("an amount is plain text such as 2.5")
    match = _USD.fullmatch(text)
    if match is None:
        raise MoneyError("an amount is whole dollars with up to six decimals, such as 2.5")
    whole, frac = match.group(1), match.group(2) or ""
    value = int(whole) * MICRO + int(frac.ljust(6, "0"))
    if value > MAX_MICRO:
        raise MoneyError("an amount is at most 1000000 USD")
    return value


def format_usd(micro: int) -> str:
    """The one canonical text of an amount: no trailing zeros, no decimal point for whole dollars."""
    if type(micro) is not int or not 0 <= micro <= MAX_MICRO:
        raise MoneyError("an amount is a whole number of micro-dollars from 0 to the maximum")
    whole, frac = divmod(micro, MICRO)
    return f"{whole}.{frac:06d}".rstrip("0").rstrip(".")


def ceil_div(numerator: int, denominator: int) -> int:
    """Division that rounds up, for non-negative whole numbers."""
    if numerator < 0 or denominator <= 0:
        raise MoneyError("rounding up needs a non-negative numerator and a positive denominator")
    return -(-numerator // denominator)
