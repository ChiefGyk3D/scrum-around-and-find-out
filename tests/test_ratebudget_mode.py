# SPDX-License-Identifier: Apache-2.0
"""`safo ratebudget`: the status line and the by-caller report, from a ledger in a private HOME."""

from __future__ import annotations

import json
from pathlib import Path

from localcli import cli
from meterdata import NOW
from safo import ratebudget as rb


def ledger(home: Path) -> rb.Budget:
    return rb.Budget(home / ".local" / "state" / "safo" / "ratebudget", lambda: NOW.timestamp())


def seed(home: Path, remaining: int) -> None:
    b = ledger(home)
    counter = rb.Counter("core/header", "core", 5000, remaining, NOW.timestamp() + 600)
    b.record(caller="agent-a", bucket="core", klass="repos/*/*/issues/#", write=True, status=200, counters=[counter])


def test_empty_ledger(tmp_path: Path) -> None:
    code, out, _ = cli("ratebudget", home=tmp_path)
    assert (code, out.strip()) == (0, "ratebudget: no calls recorded")


def test_status_line_ok_exits_zero(tmp_path: Path) -> None:
    seed(tmp_path, 4000)
    code, out, _ = cli("ratebudget", home=tmp_path)
    assert code == 0
    assert "core 20%" in out


def test_warn_exits_one(tmp_path: Path) -> None:
    seed(tmp_path, 1000)
    code, out, _ = cli("ratebudget", home=tmp_path)
    assert code == 1
    assert "WARN" in out


def test_by_caller(tmp_path: Path) -> None:
    seed(tmp_path, 4000)
    _, out, _ = cli("ratebudget", "--by-caller", home=tmp_path)
    assert "agent-a" in out
    assert "core 1 calls (1 writes)" in out


def test_json(tmp_path: Path) -> None:
    seed(tmp_path, 4000)
    _, out, _ = cli("ratebudget", "--by-caller", "--json", home=tmp_path)
    data = json.loads(out)
    assert data["by_caller"] == {"agent-a": {"core": {"calls": 1, "writes": 1}}}
    assert data["line"].startswith("ratebudget:")
