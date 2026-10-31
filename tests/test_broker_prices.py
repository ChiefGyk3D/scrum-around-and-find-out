# SPDX-License-Identifier: Apache-2.0
"""The price table loader and the worst-case reservation: never under, never negative, never overflowing, rounded up."""

from __future__ import annotations

import copy
import datetime as dt
from fractions import Fraction
from typing import Any

import pytest

from brokerdata import FLAT, Rng, prices_data, table
from safo.broker.errors import Refused
from safo.broker.money import MAX_MICRO, MICRO
from safo.broker.prices import (
    INPUT_MARGIN_TOKENS,
    ModelPrice,
    load_prices_text,
    parse_prices,
    reserve_amount,
    typical_estimate,
)
from safo.errors import ConfigError

TODAY = dt.date(2026, 10, 30)
NB21, LITE, NB2, PRO_IMG = (
    "gemini-nano-banana-2.1",
    "gemini-3.1-flash-lite-image",
    "gemini-3.1-flash-image",
    "gemini-3-pro-image",
)


def total(model: str, **over: Any) -> int:
    price = table().models[model]
    args: dict[str, Any] = {
        "kind": price.kind,
        "prompt_bytes": 0,
        "max_output_tokens": price.output_token_limit,
        "image_size": "1K" if price.kind == "image" else "",
        "count": 1 if price.kind == "image" else 0,
        "today": TODAY,
    }
    args.update(over)
    return reserve_amount(price, **args).total_micro


def exact(price: ModelPrice, *, prompt_bytes: int, tokens: int, size: str, verified_interim: bool) -> Fraction:
    """The worst case as an exact fraction of a micro-dollar, written independently of the code under test."""
    rate = max(price.text_output_per_mtok, price.image_output_per_mtok)
    value = Fraction((prompt_bytes + 64) * price.input_per_mtok + tokens * rate, MICRO)
    if verified_interim:
        value += Fraction(price.interim_images * price.image_tokens[size] * price.image_output_per_mtok, MICRO)
    return value


# -- the design's worked numbers -----------------------------------------------------------------------------------


def test_design_worked_examples_for_a_1k_image() -> None:
    assert 1_050_000 <= total(NB21) < 1_051_000  # B 0.983 + C 0.067
    assert 190_000 <= total(LITE) < 192_000  # B 0.123 + C 0.067
    assert 2_100_000 <= total(NB2) < 2_102_000  # B 1.966 + C 0.134: over 2.00, under the 2.50 testing cap
    assert total(PRO_IMG) > 3_900_000  # B 3.93: over every cap


def test_the_documented_limit_is_reserved_until_the_cap_is_verified() -> None:
    assert total(NB21, max_output_tokens=2000) == total(NB21)  # M does not matter while cap_verified is false
    data = prices_data()
    data["models"][NB21]["cap_verified"] = True
    verified = parse_prices(data).models[NB21]
    low = reserve_amount(
        verified, kind="image", prompt_bytes=0, max_output_tokens=2000, image_size="1K", count=1, today=TODAY
    )
    assert low.interim_micro == 0
    assert low.total_micro < total(NB21) // 10


# -- properties ----------------------------------------------------------------------------------------------------


def test_never_under_reserves_and_rounds_up_by_less_than_three_micro() -> None:
    rng = Rng(205)
    models = [m for m, p in table().models.items() if p.valid_through >= TODAY]
    for _ in range(4000):
        name = rng.choice(models)
        price = table().models[name]
        size = rng.choice(sorted(price.image_tokens)) if price.kind == "image" else ""
        floor = price.image_tokens[size] + price.min_text_tokens if size else 1
        tokens = rng.randrange(floor, price.output_token_limit + 1)
        prompt_bytes = rng.choice([0, 1, rng.randrange(0, 200_001), 200_000])
        got = reserve_amount(
            price,
            kind=price.kind,
            prompt_bytes=prompt_bytes,
            max_output_tokens=tokens,
            image_size=size,
            count=1 if size else 0,
            today=TODAY,
        )
        billed = tokens if price.cap_verified else price.output_token_limit
        want = exact(
            price,
            prompt_bytes=prompt_bytes,
            tokens=billed,
            size=size,
            verified_interim=bool(size) and not price.cap_verified,
        )
        assert got.total_micro >= want  # never under
        assert got.total_micro - want < 3  # one round up per part, no more
        assert min(got.input_micro, got.output_micro, got.interim_micro) >= 0
        assert 0 < got.total_micro <= MAX_MICRO


def test_reservation_grows_with_the_prompt_and_with_the_limit() -> None:
    price = table().models[FLAT]
    last = 0
    for size in (0, 1, 10, 1000, 200_000):
        now = reserve_amount(
            price, kind="text", prompt_bytes=size, max_output_tokens=1000, image_size="", count=0, today=TODAY
        ).total_micro
        assert now > last
        last = now
    last = 0
    for tokens in (1, 2, 1000, 400_000):
        now = reserve_amount(
            price, kind="text", prompt_bytes=5, max_output_tokens=tokens, image_size="", count=0, today=TODAY
        ).total_micro
        assert now > last
        last = now


def test_one_input_token_per_byte_plus_the_margin() -> None:
    price = table().models[FLAT]  # one micro-dollar per input token
    got = reserve_amount(price, kind="text", prompt_bytes=500, max_output_tokens=1, image_size="", count=0, today=TODAY)
    assert got.input_micro == 500 + INPUT_MARGIN_TOKENS
    assert got.output_micro == 10


def test_the_largest_allowed_inputs_do_not_overflow() -> None:
    data = prices_data()
    for body in data["models"].values():
        body["input_per_mtok"] = "1000"
        body["text_output_per_mtok"] = "1000"
        body["output_token_limit"] = 10_000_000
        if body["kind"] == "image":
            body["image_output_per_mtok"] = "1000"
            body["image_tokens"] = {k: 10_000_000 for k in body["image_tokens"]}
    biggest = 0
    for price in parse_prices(data).models.values():
        if price.valid_through < TODAY:
            continue  # the deliberately stale model
        size = sorted(price.image_tokens)[0] if price.kind == "image" else ""
        floor = price.image_tokens[size] + price.min_text_tokens if size else 1
        if floor > price.output_token_limit:
            continue
        got = reserve_amount(
            price,
            kind=price.kind,
            prompt_bytes=200_000,
            max_output_tokens=price.output_token_limit,
            image_size=size,
            count=1 if size else 0,
            today=TODAY,
        )
        biggest = max(biggest, got.total_micro)
    assert 0 < biggest <= MAX_MICRO < 2**63


# -- refusals ------------------------------------------------------------------------------------------------------


def test_a_stale_table_refuses_every_call() -> None:
    price = table().models["stale-test"]
    ok: dict[str, Any] = dict(kind="text", prompt_bytes=1, max_output_tokens=1, image_size="", count=0)
    assert reserve_amount(price, today=dt.date(2026, 10, 29), **ok).total_micro > 0  # the last valid day
    with pytest.raises(Refused) as err:
        reserve_amount(price, today=dt.date(2026, 10, 30), **ok)
    assert err.value.code == "prices_expired"


@pytest.mark.parametrize(
    "over",
    [
        {"kind": "text"},  # kind does not match an image model
        {"image_size": "8K"},
        {"image_size": "2K"},  # not offered by the Lite model (tested below by name)
        {"count": 0},
        {"count": 2},
        {"max_output_tokens": 0},
        {"max_output_tokens": 1631},  # below 1120 image tokens + 512 text tokens
        {"max_output_tokens": 4097},  # above the Lite limit
        {"prompt_bytes": -1},
        {"prompt_bytes": 200_001},
        {"prompt_bytes": True},
    ],
)
def test_a_request_the_table_does_not_cover_is_refused(over: dict[str, Any]) -> None:
    with pytest.raises(Refused) as err:
        total(LITE, **over)
    assert err.value.code == "bad_request"


def test_a_text_request_has_no_image_fields() -> None:
    for over in ({"image_size": "1K"}, {"count": 1}, {"kind": "image"}):
        with pytest.raises(Refused):
            total(FLAT, max_output_tokens=10, **over)


def test_typical_estimate_is_the_per_image_figure_plus_prompt_and_text() -> None:
    price = table().models[NB21]
    got = typical_estimate(price, prompt_bytes=300, image_size="1K", count=1)
    assert got == 33_600 + 150 + 3_840  # 100 tokens at 1.50, and 512 text tokens at 7.50, rounded up
    with pytest.raises(Refused):
        typical_estimate(price, prompt_bytes=1, image_size="8K", count=1)


# -- the loader ----------------------------------------------------------------------------------------------------


def test_the_shipped_shape_loads() -> None:
    loaded = table()
    assert loaded.checked == dt.date(2026, 10, 30)
    assert loaded.models[NB21].image_usd["1K"] == 33_600
    assert loaded.models[NB21].image_output_per_mtok == 30 * MICRO


def mutate(path: tuple[str, ...], value: Any) -> dict[str, Any]:
    data = copy.deepcopy(prices_data())
    node: Any = data
    for key in path[:-1]:
        node = node[key]
    if value is KeyError:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return data


@pytest.mark.parametrize(
    "bad",
    [
        mutate(("models", NB21, "input_per_mtok"), 1.5),  # a float, not a quoted string
        mutate(("models", NB21, "input_per_mtok"), "1.5000001"),  # seven decimals
        mutate(("models", NB21, "input_per_mtok"), "-1"),
        mutate(("models", NB21, "input_per_mtok"), "1001"),  # above 1000 USD per million tokens
        mutate(("models", NB21, "input_per_mtok"), "1e3"),
        mutate(("models", NB21, "input_per_mtok"), True),
        mutate(("models", NB21, "output_token_limit"), 0),
        mutate(("models", NB21, "output_token_limit"), 10_000_001),
        mutate(("models", NB21, "output_token_limit"), "32768"),
        mutate(("models", NB21, "output_token_limit"), True),
        mutate(("models", NB21, "cap_verified"), "false"),
        mutate(("models", NB21, "cap_verified"), KeyError),
        mutate(("models", NB21, "kind"), "video"),
        mutate(("models", NB21, "valid_through"), "soon"),
        mutate(("models", NB21, "valid_through"), 20261231),
        mutate(("models", NB21, "unknown_key"), 1),
        mutate(("models", NB21, "image_usd"), {"1K": "0.0336"}),  # sizes differ from image_tokens
        mutate(("models", NB21, "image_usd"), {"9K": "1", "1K": "1", "2K": "1", "4K": "1"}),
        mutate(("models", NB21, "image_tokens"), {}),
        mutate(("models", NB21, "image_output_per_mtok"), KeyError),
        mutate(("models", NB21, "thinking_level_sent"), "high-plus"),
        mutate(("models", NB21, "interim_images"), 5),
        mutate(("models", NB21, "max_images"), 5),
        mutate(("models", NB21, "max_images"), 0),
        mutate(("models", FLAT, "image_usd"), {"1K": "1"}),  # a text model with image prices
        mutate(("models",), {}),
        mutate(("models",), []),
        mutate(("models", "Bad Name"), {}),
        mutate(("price_checked",), "yesterday"),
        mutate(("extra",), 1),
        [],
        "models",
        None,
    ],
)
def test_the_loader_refuses_bad_tables(bad: Any) -> None:
    with pytest.raises(ConfigError):
        parse_prices(bad)


def test_a_level_that_is_not_listed_is_refused() -> None:
    with pytest.raises(ConfigError):
        parse_prices(mutate(("models", NB2, "thinking_level_sent"), "medium"))


def test_the_yaml_loader_applies_the_hostile_input_rules() -> None:
    good = (
        "price_checked: '2026-10-30'\n"
        "models:\n"
        "  m:\n"
        "    kind: text\n"
        "    valid_through: '2026-12-31'\n"
        "    input_per_mtok: '1'\n"
        "    text_output_per_mtok: '1'\n"
        "    output_token_limit: 10\n"
        "    cap_verified: false\n"
    )
    assert load_prices_text(good).models["m"].output_token_limit == 10
    bad = {
        "duplicate key": good + "  m:\n    kind: text\n",
        "alias": good.replace("kind: text\n", "kind: &a text\n", 1) + "    other: *a\n",
        "merge key": good + "    <<: {x: 1}\n",
        "not yaml": "models: [unclosed",
        "deep": "a: " + "[" * 5000 + "]" * 5000,
        "huge": "# " + "x" * 3_000_000,
        "tag": "!!python/object/apply:os.system ['true']",
    }
    for name, text in bad.items():
        with pytest.raises(ConfigError):
            load_prices_text(text)
        assert name
