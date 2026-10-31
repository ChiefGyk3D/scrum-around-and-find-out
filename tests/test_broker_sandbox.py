# SPDX-License-Identifier: Apache-2.0
"""The broker under the sandbox properties of its unit (scripts/broker_sandbox_check.py), driven from pytest.

These tests need a user systemd manager (`systemd-run --user`). Where there is none (CI runners, containers) each of
them SKIPS with the reason the script gives, so the skip is explicit and the suite stays green. Run the script itself
for a local check: `python scripts/broker_sandbox_check.py [--kill] [--extra-filter '~socketpair'] [--mutate recvmsg]`.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "broker_sandbox_check.py"


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("broker_sandbox_check", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # a dataclass in the script looks its module up here
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def check() -> ModuleType:
    module = load()
    reason = module.unavailable_reason()
    if reason:
        pytest.skip(f"the sandbox acceptance check needs a user systemd manager: {reason}")
    return module


def shown(outcome: Any) -> str:
    return str("\n".join(outcome.steps) + "\n--- service log ---\n" + outcome.log[-2000:])


# -- the script itself, without systemd ----------------------------------------------------------------------------


def test_the_script_reports_why_it_cannot_run_when_systemd_run_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load()
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert module.unavailable_reason() == "systemd-run is not installed"


def test_the_property_list_mirrors_the_hardening_of_the_unit() -> None:
    props = load().PROPERTIES
    for wanted in (
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "SystemCallFilter=@system-service",
        "SystemCallFilter=~@privileged @resources",
        "MemoryDenyWriteExecute=yes",
        "RestrictAddressFamilies=AF_INET",
        "ProtectSystem=strict",
        "LimitNOFILE=64",
        "TasksMax=32",
    ):
        assert wanted in props
    assert not any(p.startswith("SystemCallErrorNumber") for p in props)  # added only in the error-number mode


def test_the_harness_names_no_machine_path() -> None:
    for path in (SCRIPT, SCRIPT.parent.parent / "tests" / "sandbox_serve.py"):
        text = path.read_text()
        assert "/home/" not in text and "/Users/" not in text, path.name


# -- under the sandbox ---------------------------------------------------------------------------------------------


def test_the_server_runs_under_the_unit_properties_with_an_error_number(check: ModuleType) -> None:
    outcome = check.run_check()
    assert outcome.ok, shown(outcome)
    assert any(s.endswith("image call") for s in outcome.steps) and any("SIGTERM" in s for s in outcome.steps)


def test_the_server_runs_in_kill_mode_where_a_filtered_call_ends_the_process(check: ModuleType) -> None:
    outcome = check.run_check(kill=True)
    assert outcome.ok, shown(outcome)


def test_the_server_does_not_need_socketpair(check: ModuleType) -> None:
    outcome = check.run_check(kill=True, extra_filter="~socketpair")
    assert outcome.ok, shown(outcome)


@pytest.mark.parametrize(
    ("mutate", "kill", "extra"),
    [
        ("socket", False, ""),
        ("socket", True, ""),
        ("recvmsg", False, ""),
        ("recvmsg", True, ""),
        ("socketpair", False, "~socketpair"),
        ("socketpair", True, "~socketpair"),
    ],
)
def test_a_server_that_asks_for_a_call_the_unit_refuses_fails_the_check(
    check: ModuleType, mutate: str, kill: bool, extra: str
) -> None:
    outcome = check.run_check(kill=kill, extra_filter=extra, mutate=mutate)
    assert not outcome.ok, "the check passed a server with an injected " + mutate + " call\n" + shown(outcome)
