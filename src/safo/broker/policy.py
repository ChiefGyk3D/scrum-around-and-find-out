# SPDX-License-Identifier: Apache-2.0
"""Caps, the model allow-list and the refusals (docs/gemini-broker.md, "Cost" and decision 13).

The broker prices a request itself from its own table. A model that is not in the table is refused; a Pro-class model
(Pro, Nano Banana Pro) is refused until its table entry says the output cap is verified; a reservation above the signed
`max_usd`, the per-job cap or the month's room is refused before anything is spent.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass

from safo import gemini
from safo.broker.errors import Refused
from safo.broker.money import MICRO, MoneyError, parse_usd
from safo.broker.prices import IMAGE_SIZES, KINDS, THINKING_LEVELS, ModelPrice, PriceTable, Reservation, reserve_amount
from safo.errors import ConfigError

JOB_CAP_MICRO = (
    2_500_000  # per job, testing phase (maintainer decision 2026-10-30): a config may lower it, never raise it
)
MONTH_CAP_MICRO = 10 * MICRO  # per month; past it every call needs an approval that says so
BLOCK_MICRO = 2 * MICRO
# Decision 13: a model whose output cap is not yet shown to hold is refused when its worst case passes this figure.
# It is its own constant and does not move with the job cap, which was raised for the testing phase.
UNVERIFIED_LIMIT_MICRO = 2 * MICRO
MAX_COUNT_PER_APPROVAL = 1  # decision 7: one image and one approval per call
PRO_CLASS = re.compile(r"(?:^|[-._])pro(?:$|[-._])")
ASPECT = re.compile(r"[0-9]{1,2}:[0-9]{1,2}")


@dataclass(frozen=True)
class Caps:
    job_micro: int = JOB_CAP_MICRO
    month_micro: int = MONTH_CAP_MICRO

    def __post_init__(self) -> None:
        if type(self.job_micro) is not int or type(self.month_micro) is not int:
            raise ConfigError("caps: amounts are whole micro-dollars")
        if not 0 < self.job_micro <= JOB_CAP_MICRO:
            raise ConfigError(
                "caps: the per-job cap is above 0 and at most the built-in cap (a config lowers it, never raises it)"
            )
        if not 0 < self.month_micro <= MONTH_CAP_MICRO:
            raise ConfigError("caps: the monthly cap is above 0 and at most the built-in monthly cap")

    @classmethod
    def from_usd(cls, job_usd: str | None = None, month_usd: str | None = None) -> Caps:
        try:
            job = parse_usd(job_usd) if job_usd is not None else JOB_CAP_MICRO
            month = parse_usd(month_usd) if month_usd is not None else MONTH_CAP_MICRO
        except MoneyError as err:
            raise ConfigError(f"caps: {err}") from None
        return cls(job, month)


def is_pro_class(model: str) -> bool:
    return PRO_CLASS.search(model) is not None


@dataclass(frozen=True)
class BrokerRequest:
    model: str
    kind: str
    job: str
    prompt: str
    max_output_tokens: int
    thinking_level: str
    count: int = 0  # images wanted; 0 for text
    image_size: str = ""
    aspect_ratio: str = ""


def canonical_broker_request(req: BrokerRequest) -> BrokerRequest:
    """The one entry copy: built from base types only, through the same entry copy the free and approval paths use
    (`gemini.canonical_request`), so a `str` or `int` subclass cannot lie later. Then the shape is checked."""
    if type(req) is not BrokerRequest:
        raise Refused("bad_request", "the request is not a plain request")
    names = (
        "model",
        "kind",
        "job",
        "prompt",
        "max_output_tokens",
        "thinking_level",
        "count",
        "image_size",
        "aspect_ratio",
    )
    raw = {name: object.__getattribute__(req, name) for name in names}
    try:
        base = gemini.canonical_request(
            gemini.Request(
                model=raw["model"],
                prompt=raw["prompt"],
                tier="paid",
                job=raw["job"],
                max_output_tokens=raw["max_output_tokens"],
            )
        )
        kind = gemini.plain_str(raw["kind"], "kind")
        level = gemini.plain_str(raw["thinking_level"], "thinking_level")
        size = gemini.plain_str(raw["image_size"], "image_size")
        aspect = gemini.plain_str(raw["aspect_ratio"], "aspect_ratio")
        count = gemini.plain_int(raw["count"], "count")
    except gemini.RefusedError:
        raise Refused("bad_request", "the request has a field of the wrong type") from None
    if not gemini.MODEL_NAME.fullmatch(base.model):
        raise Refused("bad_request", "the model name is not a plain model name")
    if not gemini.JOB_NAME.fullmatch(base.job):
        raise Refused("bad_request", "the job is a plain name (letters, digits, . _ -)")
    if kind not in KINDS or level not in THINKING_LEVELS:
        raise Refused("bad_request", "the kind or the thinking level is not one the broker knows")
    if len(base.prompt.encode("utf-8")) > gemini.MAX_PROMPT_BYTES:
        raise Refused("bad_request", "the prompt is too large")
    if gemini.has_secret_shape(base.prompt):
        raise Refused("bad_request", "the prompt holds something shaped like a secret")
    if kind == "image":
        if size not in IMAGE_SIZES or not ASPECT.fullmatch(aspect) or not 1 <= count <= MAX_COUNT_PER_APPROVAL:
            raise Refused("bad_request", "an image request names one image, a known size and an aspect ratio")
    elif size or aspect or count:
        raise Refused("bad_request", "a text request has no image size, aspect ratio or count")
    return BrokerRequest(base.model, kind, base.job, base.prompt, base.max_output_tokens, level, count, size, aspect)


@dataclass(frozen=True)
class Priced:
    price: ModelPrice
    reservation: Reservation
    prompt_sha256: str
    prompt_bytes: int


@dataclass(frozen=True)
class Policy:
    prices: PriceTable
    caps: Caps = Caps()

    def allowed(self, model: str) -> ModelPrice:
        """The table entry for a model the broker will call, or a refusal. The table is the allow-list."""
        price = self.prices.models.get(model)
        if price is None:
            raise Refused("model_refused", "this model is not in the broker's allow-list")
        if is_pro_class(model) and not price.cap_verified:
            raise Refused("model_refused", "this model is refused until its output cap is shown to hold")
        return price

    def price(self, req: BrokerRequest, now: dt.datetime) -> Priced:
        """Allow-list, refusal list, shape and the worst-case reservation for a request already made canonical."""
        price = self.allowed(req.model)
        if req.thinking_level != price.thinking_level_sent:
            raise Refused("bad_request", "the thinking level is not the one the broker sends for this model")
        digest, size = gemini.prompt_binding(req.prompt)
        reservation = reserve_amount(
            price,
            kind=req.kind,
            prompt_bytes=size,
            max_output_tokens=req.max_output_tokens,
            image_size=req.image_size,
            count=req.count,
            today=now.astimezone(dt.UTC).date(),
        )
        self.check_unverified(price, reservation.total_micro)
        return Priced(price, reservation, digest, size)

    @staticmethod
    def check_unverified(price: ModelPrice, reserved_micro: int) -> None:
        """Decision 13: an unverified output cap and a worst case over 2 USD is refused, whatever the job cap is."""
        if not price.cap_verified and reserved_micro > UNVERIFIED_LIMIT_MICRO:
            raise Refused("model_refused", "this model is refused until its output cap is shown to hold")

    def check_caps(self, reserved_micro: int, *, max_micro: int, beyond_ceiling: bool, month_spent_micro: int) -> None:
        """Refuse a reservation above the job cap, the signed maximum, or the month's room. A reservation exactly at a
        limit passes; one micro-dollar over does not."""
        if reserved_micro > self.caps.job_micro:
            raise Refused("over_job_cap", "the worst case is over the per-job cap")
        if reserved_micro > max_micro:
            raise Refused("over_approved", "the worst case is over the approved maximum")
        # Over the monthly ceiling: refused unless the signed approval says beyond_ceiling (the extra-block rule).
        if month_spent_micro + reserved_micro > self.caps.month_micro and not beyond_ceiling:
            raise Refused(
                "needs_block_approval", "this call would pass the monthly ceiling and the approval does not say so"
            )
