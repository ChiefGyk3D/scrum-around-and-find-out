# SPDX-License-Identifier: MIT
"""Support for the hooks tests: run `safo hooks` in-process against a private HOME, and build the files it reads."""

from __future__ import annotations

import datetime as dt
import io
import json
from pathlib import Path
from typing import Any

import yaml

from agentsdata import agents_dict
from meterdata import NOW
from safo.agentsfile import load_agents, parse_agents
from safo.cli import main
from safo.hooks import attempt_path, state_path


def hooks(
    *argv: str,
    home: Path,
    stdin: str = "",
    now: dt.datetime = NOW,
    env: dict[str, str] | None = None,
    dry_run: bool = False,
) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    environment = {"HOME": str(home), "PATH": "", **(env or {})}
    if argv and argv[0] == "probe" and not stdin:
        stdin = json.dumps({"hook_event_name": "SessionStart", "session_id": "session-a"})
    code = main(
        [*(["--dry-run"] if dry_run else []), "hooks", *argv],
        env=environment,
        out=out,
        err=err,
        now=now,
        stdin=io.StringIO(stdin),
    )
    return code, out.getvalue(), err.getvalue()


def agents_file(
    path: Path, a_url: str = "http://127.0.0.1:9", b_url: str = "http://127.0.0.1:9", **hooks_over: Any
) -> Path:
    data = agents_dict(a_url, b_url)
    data["hooks"] = {**data.get("hooks", {}), **hooks_over}
    path.write_text(yaml.safe_dump(data))
    return path


def dispatch(
    model: str | None = "sonnet", prompt: str = "Summarise it. safo local run --shape ci-log-summary", **extra: Any
) -> str:
    """The PreToolUse event Claude Code sends for an Agent tool call."""
    tool_input: dict[str, Any] = {
        "description": "sentinel-description",
        "prompt": prompt,
        "subagent_type": "general-purpose",
    }
    if model is not None:
        tool_input["model"] = model
    tool_input.update(extra)
    return json.dumps(
        {"hook_event_name": "PreToolUse", "session_id": "session-a", "tool_name": "Agent", "tool_input": tool_input}
    )


def state_folder(home: Path) -> Path:
    return home / ".local" / "state" / "safo" / "hooks"


def probe_file(home: Path, agents: Path | None = None, session: str = "session-a") -> Path:
    doc = load_agents(agents) if agents else parse_agents(agents_dict())
    return state_path(state_folder(home), session, doc)


def set_probe(
    home: Path, *, reachable: bool = True, age: float = 60.0, agents: Path | None = None, session: str = "session-a"
) -> None:
    folder = state_folder(home)
    folder.mkdir(parents=True, exist_ok=True)
    state = {"ts": NOW.timestamp() - age, "reachable": reachable, "endpoints": []}
    probe_file(home, agents, session).write_text(json.dumps(state))


def block_reprobe(home: Path, agents: Path | None = None, age: float = 1.0) -> None:
    """Record a re-probe attempt a moment ago, so a stale state is not refreshed by the next dispatch."""
    attempt_path(probe_file(home, agents)).write_text(json.dumps({"ts": NOW.timestamp() - age}))


def set_mode(home: Path, mode: str) -> None:
    folder = home / ".config" / "safo"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "mode").write_text(mode + "\n")


def read_log(home: Path) -> list[dict[str, Any]]:
    path = state_folder(home) / "log.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
