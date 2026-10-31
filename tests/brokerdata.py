# SPDX-License-Identifier: Apache-2.0
"""Support for the broker core tests: a price table, requests and approvals. No key, no vendor, no network, no clock."""

from __future__ import annotations

import dataclasses
import datetime as dt
import secrets
from pathlib import Path
from typing import Any

from safo import gemini, geminisign
from safo.broker.ledger import CallLedger
from safo.broker.policy import BrokerRequest, Caps, Policy
from safo.broker.prices import PriceTable, parse_prices
from safo.broker.records import ApprovalV3

NOW = dt.datetime(2026, 10, 30, 12, 0, 0, tzinfo=dt.UTC)
EPOCH = "ab" * 16
PROMPT = "a plain prompt for a test"
FLAT = "flat-test"  # one micro-dollar per input token, ten per output token: a reservation is easy to land on a limit
FLAT_MAX = 400_000


def prices_data() -> dict[str, Any]:
    return {
        "price_checked": "2026-10-30",
        "models": {
            "gemini-nano-banana-2.1": {
                "kind": "image",
                "valid_through": "2026-12-31",
                "input_per_mtok": "1.50",
                "text_output_per_mtok": "7.50",
                "image_output_per_mtok": "30.00",
                "image_usd": {"1K": "0.0336", "2K": "0.0504", "4K": "0.113"},
                "image_tokens": {"1K": 1120, "2K": 1680, "4K": 3780},
                "output_token_limit": 32768,
                "thinking_levels": ["minimal", "medium", "high"],
                "thinking_level_sent": "minimal",
                "min_text_tokens": 512,
                "interim_images": 2,
                "cap_verified": False,
                "max_images": 1,
            },
            "gemini-3.1-flash-lite-image": {
                "kind": "image",
                "valid_through": "2026-12-31",
                "input_per_mtok": "0.25",
                "text_output_per_mtok": "1.50",
                "image_output_per_mtok": "30.00",
                "image_usd": {"1K": "0.0336"},
                "image_tokens": {"1K": 1120},
                "output_token_limit": 4096,
                "thinking_levels": ["minimal", "high"],
                "thinking_level_sent": "minimal",
                "min_text_tokens": 512,
                "interim_images": 2,
                "cap_verified": False,
            },
            "gemini-3.1-flash-image": {  # Nano Banana 2: worst case about 2.10 USD, under the 2.50 testing cap
                "kind": "image",
                "valid_through": "2026-12-31",
                "input_per_mtok": "0.50",
                "text_output_per_mtok": "3.00",
                "image_output_per_mtok": "30.00",
                "image_usd": {"1K": "0.067"},
                "image_tokens": {"1K": 2240},
                "output_token_limit": 65536,
                "thinking_levels": ["minimal", "high"],
                "thinking_level_sent": "minimal",
                "min_text_tokens": 512,
                "interim_images": 2,
                "cap_verified": False,
            },
            "gemini-3-pro-image": {  # Nano Banana Pro: worst case about 3.93 USD
                "kind": "image",
                "valid_through": "2026-12-31",
                "input_per_mtok": "2.00",
                "text_output_per_mtok": "12.00",
                "image_output_per_mtok": "30.00",
                "image_usd": {"1K": "0.134"},
                "image_tokens": {"1K": 1120},
                "output_token_limit": 131072,
                "min_text_tokens": 512,
                "interim_images": 2,
                "cap_verified": False,
            },
            "gemini-3.6-flash": {
                "kind": "text",
                "valid_through": "2026-12-31",
                "input_per_mtok": "0.30",
                "text_output_per_mtok": "2.50",
                "output_token_limit": 65536,
                "thinking_levels": ["minimal", "high"],
                "thinking_level_sent": "minimal",
                "cap_verified": False,
            },
            "gemini-3.5-pro": {
                "kind": "text",
                "valid_through": "2026-12-31",
                "input_per_mtok": "1.25",
                "text_output_per_mtok": "10.00",
                "output_token_limit": 65536,
                "cap_verified": False,
            },
            FLAT: {
                "kind": "text",
                "valid_through": "2026-12-31",
                "input_per_mtok": "1",
                "text_output_per_mtok": "10",
                "output_token_limit": FLAT_MAX,
                "cap_verified": True,
            },
            "stale-test": {
                "kind": "text",
                "valid_through": "2026-10-29",
                "input_per_mtok": "1",
                "text_output_per_mtok": "1",
                "output_token_limit": 100,
                "cap_verified": False,
            },
        },
    }


def table() -> PriceTable:
    return parse_prices(prices_data())


def policy(caps: Caps | None = None) -> Policy:
    return Policy(table(), caps or Caps())


def request(**over: Any) -> BrokerRequest:
    base: dict[str, Any] = {
        "model": FLAT,
        "kind": "text",
        "job": "job-one",
        "prompt": PROMPT,
        "max_output_tokens": 1000,
        "thinking_level": "none",
    }
    base.update(over)
    return BrokerRequest(**base)


def flat_request(reserved_micro: int, **over: Any) -> BrokerRequest:
    """A FLAT request whose reservation is exactly `reserved_micro` (a prompt of the right size, then a limit)."""
    prompt_len = (reserved_micro - 64) % 10  # leaves a multiple of ten for the output tokens
    limit = (reserved_micro - 64 - prompt_len) // 10
    assert 1 <= limit <= FLAT_MAX
    return request(prompt="x" * prompt_len, max_output_tokens=limit, **over)


def approval(req: BrokerRequest, **over: Any) -> ApprovalV3:
    digest, size = gemini.prompt_binding(req.prompt)
    base: dict[str, Any] = {
        "nonce": secrets.token_hex(8),
        "epoch": EPOCH,
        "model": req.model,
        "kind": req.kind,
        "count": req.count,
        "image_size": req.image_size,
        "aspect_ratio": req.aspect_ratio,
        "max_output_tokens": req.max_output_tokens,
        "thinking_level": req.thinking_level,
        "max_micro": 2_500_000,
        "job": req.job,
        "prompt_sha256": digest,
        "prompt_bytes": size,
        "quote": "go ahead",
        "quoted_at": NOW - dt.timedelta(minutes=1),
        "created": NOW - dt.timedelta(minutes=1),
        "expires_at": NOW + dt.timedelta(minutes=9),
        "beyond_ceiling": False,
        "ledger_head": "0" * 64,
        "issue": "ChiefGyk3D/scrum-around-and-find-out#205",
        "principal": "maintainer",
    }
    base.update(over)
    return ApprovalV3(**base)


def signed_text(**over: Any) -> str:
    """The canonical JSON of a version 3 text approval, with fields replaced (None removes one)."""
    data: dict[str, Any] = {
        "version": 3,
        "nonce": "0123456789abcdef",
        "epoch": EPOCH,
        "model": FLAT,
        "kind": "text",
        "max_output_tokens": 1000,
        "thinking_level": "none",
        "max_usd": "2.5",
        "job": "job-one",
        "prompt_sha256": gemini.prompt_binding(PROMPT)[0],
        "prompt_bytes": len(PROMPT),
        "quote": "go ahead",
        "quoted_at": "2026-10-30T11:59:00Z",
        "created": "2026-10-30T11:59:00Z",
        "expires_at": "2026-10-30T12:09:00Z",
        "beyond_ceiling": False,
        "ledger_head": "0" * 64,
        "issue": "ChiefGyk3D/scrum-around-and-find-out#205",
        "principal": "maintainer",
    }
    for key, value in over.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    return geminisign.canonical(data)


def image_text(**over: Any) -> str:
    base: dict[str, Any] = {"kind": "image", "count": 1, "image_size": "1K", "aspect_ratio": "1:1"}
    base.update(over)
    return signed_text(**base)


def state_dir(tmp: Path) -> Path:
    return tmp / "state"


def new_ledger(tmp: Path, **kw: Any) -> CallLedger:
    ledger = CallLedger(state_dir(tmp), **kw)
    ledger.open()
    return ledger


class Rng:
    """A small deterministic generator (a 64-bit linear congruential one) so property tests repeat exactly; it makes
    nothing secret."""

    def __init__(self, seed: int) -> None:
        self.state = seed & 0xFFFFFFFFFFFFFFFF

    def _next(self) -> int:
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        return self.state >> 11

    def randrange(self, start: int, stop: int | None = None) -> int:
        if stop is None:
            start, stop = 0, start
        return start + self._next() % (stop - start)

    def choice(self, items: list[Any]) -> Any:
        return items[self.randrange(len(items))]


class Crash(BaseException):
    """A simulated kill: not an Exception, so no handler in the code under test can swallow it."""


class CrashAt:
    def __init__(self, point: str) -> None:
        self.point = point

    def __call__(self, point: str) -> None:
        if point == self.point:
            raise Crash(point)


def reserve_worker(args: tuple[str, str, int, str]) -> str:
    """Run in a separate process: reserve once on a shared state directory and report the outcome."""
    folder, nonce, reserved, model = args
    from safo.broker.errors import Refused

    ledger = CallLedger(Path(folder))
    req = flat_request(reserved, model=model)
    try:
        ledger.reserve(
            req, dataclasses.replace(approval(req), nonce=nonce), policy(Caps(10_000, 10_000)), epoch=EPOCH, now=NOW
        )
    except Refused as err:
        return err.code
    return "ok"
