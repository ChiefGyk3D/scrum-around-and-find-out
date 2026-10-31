# SPDX-License-Identifier: Apache-2.0
"""Caps, the allow-list, the refusals and the canonical request."""

from __future__ import annotations

from typing import Any

import pytest

from brokerdata import NOW, flat_request, policy, prices_data, request
from safo.broker.errors import Refused
from safo.broker.policy import (
    BLOCK_MICRO,
    JOB_CAP_MICRO,
    MONTH_CAP_MICRO,
    BrokerRequest,
    Caps,
    Policy,
    canonical_broker_request,
    is_pro_class,
)
from safo.broker.prices import parse_prices, reserve_amount
from safo.errors import ConfigError

NB21, LITE, NB2, PRO_IMG, PRO_TEXT = (
    "gemini-nano-banana-2.1",
    "gemini-3.1-flash-lite-image",
    "gemini-3.1-flash-image",
    "gemini-3-pro-image",
    "gemini-3.5-pro",
)


def image(model: str, **over: Any) -> BrokerRequest:
    base: dict[str, Any] = {
        "model": model,
        "kind": "image",
        "count": 1,
        "image_size": "1K",
        "aspect_ratio": "1:1",
        "thinking_level": "minimal",
        "max_output_tokens": 4096,
    }
    base.update(over)
    return request(**base)


def test_constants_are_the_decided_values() -> None:
    assert (JOB_CAP_MICRO, MONTH_CAP_MICRO, BLOCK_MICRO) == (2_500_000, 10_000_000, 2_000_000)


# -- caps may be lowered, never raised -----------------------------------------------------------------------------


def test_caps_lower_but_never_raise() -> None:
    assert Caps.from_usd("1", "5") == Caps(1_000_000, 5_000_000)
    assert Caps.from_usd() == Caps(JOB_CAP_MICRO, MONTH_CAP_MICRO)
    assert Caps.from_usd("2.5", "10") == Caps()
    for job, month in (
        ("2.500001", "10"),
        ("2.5", "10.000001"),
        ("0", "10"),
        ("2.5", "0"),
        ("-1", "10"),
        ("x", "10"),
        ("1e1", "10"),
    ):
        with pytest.raises(ConfigError):
            Caps.from_usd(job, month)


@pytest.mark.parametrize(
    ("job", "month"),
    [(JOB_CAP_MICRO + 1, MONTH_CAP_MICRO), (JOB_CAP_MICRO, MONTH_CAP_MICRO + 1), (1.5, 1), (True, 1), (0, 1), (1, 0)],
)
def test_building_caps_directly_applies_the_same_bounds(job: Any, month: Any) -> None:
    with pytest.raises(ConfigError):
        Caps(job, month)


# -- the allow-list and the refusals -------------------------------------------------------------------------------


def test_a_model_that_is_not_in_the_table_is_refused() -> None:
    with pytest.raises(Refused) as err:
        policy().price(request(model="gemini-9-unlisted"), NOW)
    assert err.value.code == "model_refused"


@pytest.mark.parametrize(
    ("name", "pro"),
    [
        (PRO_IMG, True),
        (PRO_TEXT, True),
        ("gemini-nano-banana-pro", True),
        ("pro", True),
        ("gemini-2.5-pro-preview", True),
        ("gemini-3.1-pro", True),
        ("gemini_pro_x", True),
        (NB21, False),
        (NB2, False),
        (LITE, False),
        ("gemini-3.6-flash", False),
        ("approx-pro1", False),
        ("improve", False),
    ],
)
def test_pro_class_names(name: str, pro: bool) -> None:
    assert is_pro_class(name) is pro


def test_pro_and_nano_banana_pro_are_refused_while_the_cap_is_unverified() -> None:
    cases = (
        image(PRO_IMG, thinking_level="none", max_output_tokens=2000),
        request(model=PRO_TEXT, thinking_level="none"),
    )
    for req in cases:
        with pytest.raises(Refused) as err:
            policy().price(req, NOW)
        assert err.value.code == "model_refused"


def test_a_verified_pro_model_is_allowed_by_name_and_then_priced_at_its_cap() -> None:
    data = prices_data()
    data["models"][PRO_IMG]["cap_verified"] = True
    pol = Policy(parse_prices(data), Caps())
    priced = pol.price(image(PRO_IMG, thinking_level="none", max_output_tokens=2000), NOW)
    assert priced.reservation.interim_micro == 0
    assert priced.reservation.total_micro < JOB_CAP_MICRO  # 2000 tokens at the image rate


def test_nano_banana_2_is_under_the_testing_cap_but_refused_until_its_cap_is_verified_and_pro_is_over_it() -> None:
    pol = policy()
    with pytest.raises(Refused) as refused:  # decision 13: over 2 USD with the cap unverified
        pol.price(image(NB2), NOW)
    assert refused.value.code == "model_refused"
    nb2 = reserve_amount(
        pol.prices.models[NB2],
        kind="image",
        prompt_bytes=0,
        max_output_tokens=4096,
        image_size="1K",
        count=1,
        today=NOW.date(),
    ).total_micro
    assert 2_100_000 <= nb2 <= JOB_CAP_MICRO
    pol.check_caps(nb2, max_micro=JOB_CAP_MICRO, beyond_ceiling=False, month_spent_micro=0)
    pro = reserve_amount(
        pol.prices.models[PRO_IMG],
        kind="image",
        prompt_bytes=0,
        max_output_tokens=2000,
        image_size="1K",
        count=1,
        today=NOW.date(),
    ).total_micro
    assert pro > JOB_CAP_MICRO  # 3.93 USD: the documented limit is reserved while the cap is unverified
    with pytest.raises(Refused) as err:
        pol.check_caps(pro, max_micro=10**9, beyond_ceiling=False, month_spent_micro=0)
    assert err.value.code == "over_job_cap"


def test_the_thinking_level_must_be_the_one_the_broker_sends() -> None:
    assert policy().price(image(NB21), NOW)
    for level in ("high", "medium", "none", "low"):
        with pytest.raises(Refused) as err:
            policy().price(image(NB21, thinking_level=level), NOW)
        assert err.value.code == "bad_request"


def test_prices_past_valid_through_refuse() -> None:
    req = request(model="stale-test", thinking_level="none", max_output_tokens=1)
    with pytest.raises(Refused) as err:
        policy().price(req, NOW)
    assert err.value.code == "prices_expired"


# -- cap boundaries: exactly at the limit, and one micro-dollar over -----------------------------------------------


def test_job_cap_exact_and_one_micro_over() -> None:
    pol = policy()
    at = pol.price(flat_request(JOB_CAP_MICRO), NOW)
    assert at.reservation.total_micro == JOB_CAP_MICRO
    pol.check_caps(at.reservation.total_micro, max_micro=JOB_CAP_MICRO, beyond_ceiling=False, month_spent_micro=0)
    over = pol.price(flat_request(JOB_CAP_MICRO + 1), NOW)
    assert over.reservation.total_micro == JOB_CAP_MICRO + 1
    with pytest.raises(Refused) as err:
        pol.check_caps(over.reservation.total_micro, max_micro=10**9, beyond_ceiling=True, month_spent_micro=0)
    assert err.value.code == "over_job_cap"  # no flag lifts the per-job cap


def test_signed_maximum_exact_and_one_micro_over() -> None:
    pol = policy()
    pol.check_caps(1_000_000, max_micro=1_000_000, beyond_ceiling=False, month_spent_micro=0)
    with pytest.raises(Refused) as err:
        pol.check_caps(1_000_001, max_micro=1_000_000, beyond_ceiling=False, month_spent_micro=0)
    assert err.value.code == "over_approved"


def test_month_cap_exact_and_one_micro_over() -> None:
    pol = policy()
    room = MONTH_CAP_MICRO - 2_000_000
    pol.check_caps(2_000_000, max_micro=JOB_CAP_MICRO, beyond_ceiling=False, month_spent_micro=room)
    with pytest.raises(Refused) as err:
        pol.check_caps(2_000_001, max_micro=JOB_CAP_MICRO, beyond_ceiling=False, month_spent_micro=room)
    assert err.value.code == "needs_block_approval"
    pol.check_caps(2_000_001, max_micro=JOB_CAP_MICRO, beyond_ceiling=True, month_spent_micro=room)
    with pytest.raises(Refused):  # already at the ceiling: any further call needs the flag
        pol.check_caps(1, max_micro=JOB_CAP_MICRO, beyond_ceiling=False, month_spent_micro=MONTH_CAP_MICRO)


def test_a_lowered_cap_is_the_cap() -> None:
    pol = policy(Caps(job_micro=1000, month_micro=5000))
    pol.check_caps(1000, max_micro=10**6, beyond_ceiling=False, month_spent_micro=4000)
    with pytest.raises(Refused):
        pol.check_caps(1001, max_micro=10**6, beyond_ceiling=False, month_spent_micro=0)
    with pytest.raises(Refused):
        pol.check_caps(1000, max_micro=10**6, beyond_ceiling=False, month_spent_micro=4001)


# -- the canonical request -----------------------------------------------------------------------------------------


def test_a_good_request_is_copied_to_base_types() -> None:
    got = canonical_broker_request(request())
    assert type(got) is BrokerRequest
    assert all(type(v) in (str, int) for v in vars(got).values())


class LyingStr(str):
    pass


class LyingInt(int):
    pass


@pytest.mark.parametrize(
    "over",
    [
        {"model": LyingStr("flat-test")},
        {"job": LyingStr("job-one")},
        {"prompt": LyingStr("hi")},
        {"kind": LyingStr("text")},
        {"max_output_tokens": LyingInt(5)},
        {"max_output_tokens": True},
        {"max_output_tokens": "5"},
        {"max_output_tokens": 2.0},
        {"model": None},
        {"prompt": b"bytes"},
        {"count": True},
    ],
)
def test_subclasses_and_wrong_types_are_refused(over: dict[str, Any]) -> None:
    with pytest.raises(Refused) as err:
        canonical_broker_request(request(**over))
    assert err.value.code == "bad_request"


def test_something_that_is_not_a_request_is_refused() -> None:
    bad: Any = object()
    with pytest.raises(Refused):
        canonical_broker_request(bad)


@pytest.mark.parametrize(
    "over",
    [
        {"prompt": "bad \ud800 surrogate"},
        {"prompt": "\udc80"},
        {"prompt": "x" * 200_001},
        {"prompt": "key AIzaSyA1234567890123456789012345678901234"},
        {"model": "Gemini"},
        {"model": ""},
        {"model": "../x"},
        {"job": ""},
        {"job": "a b"},
        {"kind": "video"},
        {"thinking_level": "extreme"},
        {"image_size": "1K"},  # a text request with image fields
        {"count": 1},
        {"aspect_ratio": "1:1"},
    ],
)
def test_malformed_requests_are_refused_without_echo(over: dict[str, Any]) -> None:
    with pytest.raises(Refused) as err:
        canonical_broker_request(request(**over))
    assert err.value.code == "bad_request"
    assert "AIza" not in str(err.value)


@pytest.mark.parametrize(
    "over",
    [
        {"count": 0},
        {"count": 2},
        {"image_size": ""},
        {"image_size": "9K"},
        {"aspect_ratio": ""},
        {"aspect_ratio": "wide"},
    ],
)
def test_an_image_request_names_one_image_a_size_and_a_ratio(over: dict[str, Any]) -> None:
    with pytest.raises(Refused):
        canonical_broker_request(image(NB21, **over))
    assert canonical_broker_request(image(NB21)).count == 1
