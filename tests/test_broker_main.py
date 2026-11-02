# SPDX-License-Identifier: Apache-2.0
"""The broker entry point: with no arguments it starts the service (and fails closed with status 4 when systemd did not
hand it a socket), and its self-test imports every module."""

from __future__ import annotations

import importlib
import os
import pkgutil
import subprocess
import sys

import pytest

from safo.broker import __main__ as entry
from safo.broker import runtime


def test_without_a_socket_from_systemd_it_fails_closed_with_status_4(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(runtime, "harden_process", lambda: None)
    monkeypatch.setattr(os, "environ", {})
    assert entry.main([]) == entry.EXIT_FAILED == 4
    err = capsys.readouterr().err
    assert "cannot start (ListenError)" in err and err.count("\n") == 1


def test_unknown_arguments_are_refused(capsys: pytest.CaptureFixture[str]) -> None:
    assert entry.main(["--serve"]) == 2
    assert capsys.readouterr().err != ""


def test_the_self_test_imports_every_broker_module() -> None:
    assert entry.main(["--self-test"]) == 0
    seen = {
        m.name for m in pkgutil.iter_modules(importlib.import_module("safo.broker").__path__) if m.name != "__main__"
    }
    assert {"ledger", "policy", "floor", "money"} <= seen


def test_the_self_test_fails_when_a_module_does_not_import(monkeypatch: pytest.MonkeyPatch) -> None:
    class Info:
        name = "no_such_module_here"

    monkeypatch.setattr(pkgutil, "iter_modules", lambda path: [Info()])
    assert entry.main(["--self-test"]) == 1


def test_running_it_as_the_service_does_exits_with_the_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LISTEN_PID", raising=False)
    monkeypatch.delenv("LISTEN_FDS", raising=False)
    done = subprocess.run(
        [sys.executable, "-I", "-m", "safo.broker"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    assert done.returncode == entry.EXIT_FAILED, done.stderr  # no socket was passed: refused, not hung
    assert "ListenError" in done.stderr
    done = subprocess.run(
        [sys.executable, "-I", "-m", "safo.broker", "--self-test"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
