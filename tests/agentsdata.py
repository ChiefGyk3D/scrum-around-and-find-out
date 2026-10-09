# SPDX-License-Identifier: MIT
"""The optional two-GPU deployment example pointed at fake loopback servers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from safo.agentsfile import AgentsFile, parse_agents

ROOT = Path(__file__).parent.parent
A_MODELS = ["resident-12b-thinking", "small-4b-agent"]
B_MODELS = ["resident-safety", "embed-small"]


def agents_dict(a_url: str = "http://127.0.0.1:9", b_url: str = "http://127.0.0.1:9") -> dict[str, Any]:
    data = yaml.safe_load((ROOT / "agents.yaml").read_text())
    local = yaml.safe_load((ROOT / "examples/agents.local.example.yaml").read_text())
    data["agents"]["ollama"]["endpoints"] = local["agents"]["ollama"]["endpoints"]
    for name, override in local["shapes"].items():
        data["shapes"][name].update(override)
    endpoints = {e["id"]: e for e in data["agents"]["ollama"]["endpoints"]}
    endpoints["instance-a"]["url"] = a_url
    endpoints["instance-b"]["url"] = b_url
    assert isinstance(data, dict)
    return data


def agents_with(a_url: str = "http://127.0.0.1:9", b_url: str = "http://127.0.0.1:9") -> AgentsFile:
    return parse_agents(agents_dict(a_url, b_url))


def write_agents(path: Path, a_url: str = "http://127.0.0.1:9", b_url: str = "http://127.0.0.1:9") -> Path:
    path.write_text(yaml.safe_dump(agents_dict(a_url, b_url)))
    return path
