# SPDX-License-Identifier: Apache-2.0
"""The broker entry point: until the socket server exists it refuses to run, and its self-test imports every module."""

from __future__ import annotations

import importlib
import pkgutil
import subprocess
import sys

import pytest

from safo.broker import __main__ as entry


def test_without_arguments_it_refuses_with_a_clear_status(capsys: pytest.CaptureFixture[str]) -> None:
    assert entry.main([]) == entry.NOT_IMPLEMENTED
    assert "not implemented" in capsys.readouterr().err


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


def test_running_it_as_the_service_does_exits_with_the_status() -> None:
    done = subprocess.run(
        [sys.executable, "-I", "-m", "safo.broker"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    assert done.returncode == entry.NOT_IMPLEMENTED
    done = subprocess.run(
        [sys.executable, "-I", "-m", "safo.broker", "--self-test"],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
