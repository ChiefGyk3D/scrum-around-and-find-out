# SPDX-License-Identifier: Apache-2.0
"""The broker under the sandbox properties of its unit (scripts/broker_sandbox_check.py), driven from pytest.

These tests need a user systemd manager (`systemd-run --user`). Where there is none (CI runners, containers) each of
them SKIPS with the reason the script gives, so the skip is explicit and the suite stays green. Run the script itself
for a local check: `python scripts/broker_sandbox_check.py [--kill] [--extra-filter '~socketpair'] [--mutate recvmsg]`.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import sys
from collections.abc import Mapping
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


OPT_IN = "SAFO_SANDBOX_CHECK"


def sandbox_skip_reason(module: ModuleType, environ: Mapping[str, str]) -> str | None:
    """Why the systemd tests do not run, or None. They are opt-in (hosted runners differ from a desktop), and then they
    still need a user manager that really works."""
    if environ.get(OPT_IN) != "1":
        return f"the sandbox acceptance check is opt-in: set {OPT_IN}=1 to run it (it needs a user systemd manager)"
    reason = module.unavailable_reason()
    if reason:
        return f"the sandbox acceptance check needs a user systemd manager: {reason}"
    return None


@pytest.fixture(scope="module")
def check() -> ModuleType:
    module = load()
    reason = sandbox_skip_reason(module, os.environ)
    if reason:
        pytest.skip(reason)
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


# -- the skip and timeout logic, against fake tools ----------------------------------------------------------------


def fake_tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, systemd_run: str, systemctl: str = "exit 0") -> None:
    """Put a fake systemd-run and systemctl first on PATH. A body that waits uses `exec sleep` or a background job."""
    for name, body in (("systemd-run", systemd_run), ("systemctl", systemctl)):
        path = tmp_path / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")


def test_the_systemd_tests_are_opt_in() -> None:
    module = load()
    for environ in ({}, {OPT_IN: "0"}, {OPT_IN: ""}, {OPT_IN: "yes"}, {OPT_IN: "1 "}):
        reason = sandbox_skip_reason(module, environ)
        assert reason is not None and OPT_IN in reason and "opt-in" in reason, environ


def test_when_opted_in_the_skip_reason_is_the_probe_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load()
    monkeypatch.setattr(module, "unavailable_reason", lambda: "no manager here")
    reason = sandbox_skip_reason(module, {OPT_IN: "1"})
    assert reason is not None and "no manager here" in reason
    monkeypatch.setattr(module, "unavailable_reason", lambda: None)
    assert sandbox_skip_reason(module, {OPT_IN: "1"}) is None


def test_a_probe_that_hangs_is_a_skip_reason_not_a_hang(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load()
    fake_tools(tmp_path, monkeypatch, "exec sleep 120")
    monkeypatch.setattr(module, "PROBE_TIMEOUT", 0.5)
    reason = module.unavailable_reason()
    assert reason is not None and "did not answer" in reason


def test_a_probe_that_leaves_a_background_job_holding_the_pipe_is_still_cut_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load()
    fake_tools(tmp_path, monkeypatch, "sleep 120 &\nwait")
    monkeypatch.setattr(module, "PROBE_TIMEOUT", 0.5)
    assert "did not answer" in (module.unavailable_reason() or "")


def test_a_failing_probe_is_a_skip_reason(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_tools(tmp_path, monkeypatch, "exit 1")
    assert "unavailable" in (load().unavailable_reason() or "")


@pytest.mark.parametrize("answer", ["offline", "starting", "stopping", "maintenance", "initializing", ""])
def test_a_user_manager_that_is_not_running_is_a_skip_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: str
) -> None:
    fake_tools(tmp_path, monkeypatch, "exit 0", f"echo '{answer}'")
    assert "not running" in (load().unavailable_reason() or "")


@pytest.mark.parametrize("answer", ["running", "degraded"])
def test_a_running_or_degraded_user_manager_passes_the_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: str
) -> None:
    fake_tools(tmp_path, monkeypatch, "exit 0", f"echo '{answer}'")
    assert load().unavailable_reason() is None


def test_a_state_query_that_hangs_is_a_skip_reason(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load()
    fake_tools(tmp_path, monkeypatch, "exit 0", "exec sleep 120")
    monkeypatch.setattr(module, "PROBE_TIMEOUT", 0.5)
    assert "did not answer" in (module.unavailable_reason() or "")


def test_a_check_whose_unit_never_starts_ends_in_a_failure_naming_the_step_not_a_hang(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load()
    fake_tools(tmp_path, monkeypatch, "exec sleep 120")
    monkeypatch.setattr(module, "STEP_TIMEOUT", 1.0)
    outcome = module.run_check()
    assert not outcome.ok
    assert any("FAIL start the socket unit: timed out" in line for line in outcome.steps), outcome.steps


def test_the_total_deadline_ends_the_check_with_the_step_it_was_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load()
    fake_tools(tmp_path, monkeypatch, "exit 0")
    monkeypatch.setattr(module, "TOTAL_TIMEOUT", 0.0)
    outcome = module.run_check()
    assert not outcome.ok and any("timed out" in line for line in outcome.steps), outcome.steps


def test_a_unit_that_starts_but_answers_nothing_fails_each_step_without_hanging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load()
    fake_tools(tmp_path, monkeypatch, "exit 0")  # "starts" fine; nothing ever listens on the socket
    monkeypatch.setattr(module, "STEP_TIMEOUT", 2.0)
    outcome = module.run_check()
    assert not outcome.ok
    assert any(line.startswith("FAIL status") for line in outcome.steps), outcome.steps


def test_the_main_function_exits_3_with_the_reason_when_the_check_cannot_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = load()
    fake_tools(tmp_path, monkeypatch, "exit 1")
    assert module.main([]) == 3
    assert "not available" in capsys.readouterr().err


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
