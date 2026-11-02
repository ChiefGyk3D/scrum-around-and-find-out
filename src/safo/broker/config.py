# SPDX-License-Identifier: Apache-2.0
"""The root-owned broker config, loaded once, the same way by the service and by the preflight (#298).

`/etc/safo/broker.yaml` has the sections `server` (allowed uids and limits), `prices` (the price table), and optionally
`caps` (`job_usd`, `month_usd`: they may lower the built-in caps, never raise them) and `deadline_seconds`. An example
that loads through this function ships as examples/broker.example.yaml; the runbook writes the same text.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from safo.broker.pipeline import DEFAULT_DEADLINE_SECONDS
from safo.broker.policy import Caps, Policy
from safo.broker.prices import parse_prices
from safo.broker.server import ServerConfig, read_config
from safo.errors import SafoError

__all__ = ["BrokerConfig", "load_broker_config", "parse_broker_config", "read_config"]

SECTIONS = {"server", "prices", "caps", "deadline_seconds"}


@dataclass(frozen=True)
class BrokerConfig:
    server: ServerConfig
    policy: Policy
    deadline_seconds: float


def parse_broker_config(data: dict[str, Any]) -> BrokerConfig:
    """The sections of an already-read mapping, each validated strictly. Raises `SafoError` (a `ConfigError`)."""
    if set(data) - SECTIONS or not {"server", "prices"} <= set(data):
        raise SafoError("the broker config has an unknown or a missing section")
    server = ServerConfig.from_mapping(data["server"])
    caps_data = data.get("caps", {})
    if type(caps_data) is not dict or set(caps_data) - {"job_usd", "month_usd"}:
        raise SafoError("the broker config caps section is job_usd and month_usd")
    policy = Policy(parse_prices(data["prices"]), Caps.from_usd(caps_data.get("job_usd"), caps_data.get("month_usd")))
    deadline = data.get("deadline_seconds", DEFAULT_DEADLINE_SECONDS)
    if type(deadline) not in (int, float) or not 1 <= deadline <= 600:
        raise SafoError("the broker config deadline_seconds is from 1 to 600")
    return BrokerConfig(server, policy, float(deadline))


def load_broker_config(path: Path, trust_uid: int = 0) -> BrokerConfig:
    """Read the root-owned file (the ownership walk of the trust files, safe YAML) and validate it."""
    return parse_broker_config(read_config(path, trust_uid))
