# SPDX-License-Identifier: Apache-2.0
"""The price table and the worst-case reservation (docs/gemini-broker.md, "Cost").

reservation = A + B + C, every part rounded UP to a whole micro-dollar, all in integers:

* A, input: (prompt bytes + 64) tokens at the input rate. One token per byte is a true upper bound.
* B, output: the output-token limit at the dearer of the text and image output rates. The limit is the signed
  `max_output_tokens` only for a model whose cap is verified; otherwise it is the model's documented output limit.
* C, interim images: two interim images at the image output rate, added unless the cap is verified (text has none).

A rate is micro-dollars per million tokens, so a token count times a rate divided by 1,000,000 is micro-dollars.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from safo.broker.errors import Refused
from safo.broker.money import MAX_MICRO, MICRO, MoneyError, ceil_div, parse_usd
from safo.gemini import MAX_PROMPT_BYTES, MODEL_NAME
from safo.schema import Reader, _safe_load

INPUT_MARGIN_TOKENS = 64  # tokens the vendor may add around a request (inferred, not shown by a page)
KINDS = ("text", "image")
IMAGE_SIZES = ("512px", "1K", "2K", "4K")
MAX_RATE_MICRO = 1_000 * MICRO  # a rate above 1000 USD per million tokens is a typo, not a price
MAX_TOKENS = 10_000_000
MAX_IMAGES = 4
MAX_INTERIM = 4
IMAGE_FIGURE_TOLERANCE_PERCENT = 5  # how far below tokens x rate a stated per-image figure may sit
THINKING_LEVELS = ("none", "minimal", "low", "medium", "high")


@dataclass(frozen=True)
class ModelPrice:
    name: str
    kind: str
    valid_through: dt.date
    input_per_mtok: int  # micro-dollars per million tokens
    text_output_per_mtok: int
    image_output_per_mtok: int  # 0 for a text model
    image_usd: Mapping[str, int] = field(default_factory=dict)  # per-image figure by size, micro-dollars
    image_tokens: Mapping[str, int] = field(default_factory=dict)  # tokens an image of that size takes
    output_token_limit: int = 1
    thinking_levels: tuple[str, ...] = ()
    thinking_level_sent: str = "none"
    min_text_tokens: int = 0
    interim_images: int = 0
    cap_verified: bool = False
    max_images: int = 1


@dataclass(frozen=True)
class PriceTable:
    checked: dt.date
    models: Mapping[str, ModelPrice]


@dataclass(frozen=True)
class Reservation:
    input_micro: int
    output_micro: int
    interim_micro: int

    @property
    def total_micro(self) -> int:
        return self.input_micro + self.output_micro + self.interim_micro


# -- the table -----------------------------------------------------------------------------------------------------


def _rate(r: Reader, value: object, path: str) -> int:
    try:
        rate = parse_usd(value)
    except MoneyError as err:
        raise r.fail(path, f"{err} (write it as a quoted string)") from None
    if rate > MAX_RATE_MICRO:
        raise r.fail(path, "a rate is at most 1000 USD per million tokens")
    return rate


def _bounded(r: Reader, value: object, path: str, low: int, high: int) -> int:
    number = r.integer(value, path, minimum=low)
    if number > high:
        raise r.fail(path, f"expected an integer from {low} to {high}")
    return number


def _date(r: Reader, value: object, path: str) -> dt.date:
    if not isinstance(value, str):
        raise r.fail(path, "expected a date written as a quoted YYYY-MM-DD string")
    return r.date(value, path)


def _check_image_figure(r: Reader, path: str, usd: int, tokens: int, rate: int) -> None:
    """The stated per-image figure must agree with what the reservation charges for the same image: the token count
    times the image rate, rounded up. Above it, a call could bill (and be counted) beyond its reservation; far below
    it, one of the three numbers is wrong. Both are refused."""
    by_tokens = ceil_div(tokens * rate, MICRO)
    if usd > by_tokens:
        raise r.fail(path, f"the per-image figure is above its token price ({tokens} tokens x the image rate)")
    if usd * 100 < by_tokens * (100 - IMAGE_FIGURE_TOLERANCE_PERCENT):
        raise r.fail(
            path,
            f"the per-image figure is more than {IMAGE_FIGURE_TOLERANCE_PERCENT} percent below its token price "
            f"({tokens} tokens x the image rate)",
        )


def _model(r: Reader, name: str, data: object) -> ModelPrice:
    path = f"models.{name}"
    allowed = {
        "kind",
        "valid_through",
        "input_per_mtok",
        "text_output_per_mtok",
        "image_output_per_mtok",
        "image_usd",
        "image_tokens",
        "output_token_limit",
        "thinking_levels",
        "thinking_level_sent",
        "min_text_tokens",
        "interim_images",
        "cap_verified",
        "max_images",
    }
    required = {"kind", "valid_through", "input_per_mtok", "text_output_per_mtok", "output_token_limit", "cap_verified"}
    m = r.mapping(data, path, allowed, required, bounded=True)
    kind = r.choice(m["kind"], f"{path}.kind", KINDS)
    if type(m["cap_verified"]) is not bool:
        raise r.fail(f"{path}.cap_verified", "expected true or false")
    sizes_usd: dict[str, int] = {}
    sizes_tokens: dict[str, int] = {}
    for key, store, high in (("image_usd", sizes_usd, MAX_MICRO), ("image_tokens", sizes_tokens, MAX_TOKENS)):
        raw = m.get(key, {})
        table = r.mapping(raw, f"{path}.{key}", set(IMAGE_SIZES), bounded=True)
        for size, value in table.items():
            if key == "image_usd":
                store[size] = _rate(r, value, f"{path}.{key}.{size}")
            else:
                store[size] = _bounded(r, value, f"{path}.{key}.{size}", 1, high)
    levels_raw = r.seq(m.get("thinking_levels", []), f"{path}.thinking_levels")
    levels = tuple(r.choice(v, f"{path}.thinking_levels", THINKING_LEVELS) for v in levels_raw)
    sent = r.choice(m.get("thinking_level_sent", "none"), f"{path}.thinking_level_sent", THINKING_LEVELS)
    if levels and sent not in levels:
        raise r.fail(f"{path}.thinking_level_sent", "must be one of the model's thinking_levels")
    if not levels and sent != "none":
        raise r.fail(f"{path}.thinking_level_sent", "a model with no listed levels sends none")
    image_rate = (
        _rate(r, m["image_output_per_mtok"], f"{path}.image_output_per_mtok") if "image_output_per_mtok" in m else 0
    )
    if kind == "image":
        if "image_output_per_mtok" not in m or not sizes_usd or set(sizes_usd) != set(sizes_tokens):
            raise r.fail(
                path, "an image model lists image_output_per_mtok and the same sizes in image_usd and image_tokens"
            )
        for size, usd in sizes_usd.items():
            _check_image_figure(r, f"{path}.image_usd.{size}", usd, sizes_tokens[size], image_rate)
    elif sizes_usd or sizes_tokens or image_rate:
        raise r.fail(path, "a text model has no image prices")
    return ModelPrice(
        name=name,
        kind=kind,
        valid_through=_date(r, m["valid_through"], f"{path}.valid_through"),
        input_per_mtok=_rate(r, m["input_per_mtok"], f"{path}.input_per_mtok"),
        text_output_per_mtok=_rate(r, m["text_output_per_mtok"], f"{path}.text_output_per_mtok"),
        image_output_per_mtok=image_rate,
        image_usd=sizes_usd,
        image_tokens=sizes_tokens,
        output_token_limit=_bounded(r, m["output_token_limit"], f"{path}.output_token_limit", 1, MAX_TOKENS),
        thinking_levels=levels,
        thinking_level_sent=sent,
        min_text_tokens=_bounded(r, m.get("min_text_tokens", 0), f"{path}.min_text_tokens", 0, MAX_TOKENS),
        interim_images=_bounded(r, m.get("interim_images", 0), f"{path}.interim_images", 0, MAX_INTERIM),
        cap_verified=m["cap_verified"],
        max_images=_bounded(r, m.get("max_images", 1), f"{path}.max_images", 1, MAX_IMAGES),
    )


def parse_prices(data: object, source: str = "broker prices") -> PriceTable:
    """The `prices:` block of broker.yaml, strictly: unknown keys, floats where a quoted string belongs, a rate with
    more than six decimals, an image model without a size table, or a wrong type is a ConfigError naming the key."""
    r = Reader(source)
    top = r.mapping(data, "", {"price_checked", "models"}, {"price_checked", "models"}, bounded=True)
    models = top["models"]
    if not isinstance(models, Mapping) or not models:
        raise r.fail("models", "list at least one model")
    out: dict[str, ModelPrice] = {}
    for name, body in models.items():
        if not isinstance(name, str) or not MODEL_NAME.fullmatch(name):
            raise r.fail("models", "a model name is a plain name (a-z, 0-9, . _ -)")
        out[name] = _model(r, name, body)
    return PriceTable(_date(r, top["price_checked"], "price_checked"), out)


def load_prices_text(text: str, source: str = "broker prices") -> PriceTable:
    """YAML text through the repository's hostile-input loader (size cap, duplicate keys, anchors, aliases, depth)."""
    data: Any = _safe_load(text, source)
    return parse_prices(data, source)


# -- the arithmetic ------------------------------------------------------------------------------------------------


def _check_size(price: ModelPrice, kind: str, image_size: str, count: int) -> None:
    if kind != price.kind:
        raise Refused("bad_request", "the request kind does not match the model")
    if kind == "image":
        if image_size not in price.image_tokens:
            raise Refused("bad_request", "the image size is not offered for this model")
        if not 1 <= count <= price.max_images:
            raise Refused("bad_request", "the image count is not allowed for this model")
    elif image_size or count:
        raise Refused("bad_request", "a text request has no image size or count")


def reserve_amount(
    price: ModelPrice,
    *,
    kind: str,
    prompt_bytes: int,
    max_output_tokens: int,
    image_size: str,
    count: int,
    today: dt.date,
) -> Reservation:
    """The most this request can bill, computed only from the price table and the request, never from a figure the
    client sent. Refuses a stale table, a size the table lacks, and an output limit outside the allowed range."""
    if price.valid_through < today:
        raise Refused("prices_expired", "the price table is out of date; every paid call is refused")
    _check_size(price, kind, image_size, count)
    if type(prompt_bytes) is not int or not 0 <= prompt_bytes <= MAX_PROMPT_BYTES:
        raise Refused("bad_request", "the prompt size is out of range")
    floor = 1
    if kind == "image":
        floor = price.image_tokens[image_size] + price.min_text_tokens
    if type(max_output_tokens) is not int or not floor <= max_output_tokens <= price.output_token_limit:
        raise Refused("bad_request", "the output limit is outside the range this model allows")
    out_rate = max(price.text_output_per_mtok, price.image_output_per_mtok)
    billed_output = max_output_tokens if price.cap_verified else price.output_token_limit
    interim_tokens = 0
    if kind == "image" and not price.cap_verified:
        interim_tokens = price.interim_images * price.image_tokens[image_size]
    copies = count if kind == "image" else 1  # a text request has no count; it is one answer
    parts = Reservation(
        input_micro=ceil_div((prompt_bytes + INPUT_MARGIN_TOKENS) * price.input_per_mtok, MICRO),
        output_micro=ceil_div(billed_output * out_rate * copies, MICRO),
        interim_micro=ceil_div(interim_tokens * price.image_output_per_mtok * copies, MICRO),
    )
    if parts.total_micro > MAX_MICRO:  # unreachable with the bounds above; a guard against a future bound change
        raise Refused("bad_request", "the reservation is out of range")
    return parts


def typical_estimate(price: ModelPrice, *, prompt_bytes: int, image_size: str, count: int) -> int:
    """What a call normally costs, shown to the maintainer (never used to enforce a cap): the per-image figure, the
    prompt at three bytes a token and the minimum text allowance at the text rate, rounded up."""
    _check_size(price, price.kind, image_size, count)
    images = price.image_usd[image_size] * count if price.kind == "image" else 0
    prompt = ceil_div(ceil_div(prompt_bytes, 3) * price.input_per_mtok, MICRO)
    text = ceil_div(price.min_text_tokens * price.text_output_per_mtok, MICRO)
    return images + prompt + text
