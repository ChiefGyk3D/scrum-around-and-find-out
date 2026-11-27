# SPDX-License-Identifier: Apache-2.0
"""#615 item 2: the shell check's time budget has a higher floor, grows with the load per core up to a cap well
under the hook timeout, and the denial when it is still exceeded is unchanged.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from geminidata import write_config
from guardhealthdata import event, guard
from hooksdata import agents_file
from safo import geminibrief
from safo.gemini import Locations
from safo.hooks import GUARD_TIMEOUT_SECONDS
from safo.modes import hooks as hooks_mode


@pytest.fixture
def agents(tmp_path: Path, gemini_locations: Locations) -> Path:
    write_config(
        gemini_locations.config, "http://127.0.0.1:9", tmp_path / "data" / "ledger.jsonl", private_terms="none"
    )
    return agents_file(tmp_path / "agents.yaml")


def budget(monkeypatch: pytest.MonkeyPatch, load: float | None, cpus: int | None = 4) -> float:
    def fake_load() -> tuple[float, float, float]:
        if load is None:
            raise OSError("no load average")
        return (load, 0.0, 0.0)

    monkeypatch.setattr(os, "getloadavg", fake_load)
    monkeypatch.setattr(os, "cpu_count", lambda: cpus)
    return hooks_mode.shell_check_seconds()


def test_the_floor_is_higher_than_the_old_fixed_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    assert hooks_mode.SHELL_CHECK_FLOOR_SECONDS > hooks_mode.ISOLATED_CHECK_SECONDS
    assert budget(monkeypatch, 0.0) == hooks_mode.SHELL_CHECK_FLOOR_SECONDS
    assert budget(monkeypatch, 2.0, cpus=4) == hooks_mode.SHELL_CHECK_FLOOR_SECONDS  # under one per core: no scaling


def test_the_budget_grows_with_load_per_core(monkeypatch: pytest.MonkeyPatch) -> None:
    floor = hooks_mode.SHELL_CHECK_FLOOR_SECONDS
    assert budget(monkeypatch, 6.0, cpus=4) == pytest.approx(floor * 1.5)
    assert budget(monkeypatch, 6.0, cpus=4) > budget(monkeypatch, 4.0, cpus=4)


def test_the_budget_stops_at_a_cap_well_under_the_hook_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    assert budget(monkeypatch, 10_000.0) == hooks_mode.SHELL_CHECK_CAP_SECONDS
    assert hooks_mode.SHELL_CHECK_CAP_SECONDS <= GUARD_TIMEOUT_SECONDS / 2


@pytest.mark.parametrize("load", [None, float("nan"), float("inf"), -3.0])
def test_an_unreadable_or_absurd_load_gives_the_floor_or_cap_never_an_error(
    monkeypatch: pytest.MonkeyPatch, load: float | None
) -> None:
    got = budget(monkeypatch, load)
    assert hooks_mode.SHELL_CHECK_FLOOR_SECONDS <= got <= hooks_mode.SHELL_CHECK_CAP_SECONDS


def test_an_unknown_cpu_count_counts_as_one_core(monkeypatch: pytest.MonkeyPatch) -> None:
    assert budget(monkeypatch, 1.5, cpus=None) == pytest.approx(hooks_mode.SHELL_CHECK_FLOOR_SECONDS * 1.5)


def test_the_shell_check_is_given_the_computed_budget_and_still_fails_closed(
    _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hooks_mode, "shell_check_seconds", lambda: 4.25)
    seen: list[float] = []

    def check(_command: str, deadline: float | None = None) -> str:
        assert deadline is not None
        seen.append(deadline - time.monotonic())
        return geminibrief.SHELL_UNVERIFIED  # still over budget: the denial is unchanged

    monkeypatch.setattr(geminibrief, "shell_command_class", check)
    out = guard(agents, _private_home, event("echo hello"))
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert seen and 3.5 < seen[0] <= 4.25
