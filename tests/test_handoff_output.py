# SPDX-License-Identifier: Apache-2.0
"""The exit code is the contract. Once the verdict is computed, a failure to print it changes nothing; a failure to
compute it is exit 2, whatever was raised (but never a Ctrl-C swallowed)."""

from __future__ import annotations

import io
from typing import Any

import pytest

from fakegh import FakeGitHub
from fakegh.core import FPull
from safo.cli import main
from safo.modes import handoff
from test_handoff_check import REPO, A, B, comment, env_for, report


class BrokenPipe(io.StringIO):
    def write(self, text: str) -> int:
        raise BrokenPipeError(32, "Broken pipe")


class Closed(io.StringIO):
    def write(self, text: str) -> int:
        raise ValueError("I/O operation on closed file")


class Weird(io.StringIO):
    def write(self, text: str) -> int:
        raise SystemExit(1)  # a stream wrapper that exits


def call(fake: FakeGitHub, out: io.StringIO, head: str = A, comments: list[Any] | None = None) -> int:
    fake.pulls[(REPO, 7)] = FPull(head=head, comments=comments if comments is not None else [comment(report(A))])
    env = {"HOME": "/nonexistent-home", "PATH": "", **env_for(fake)}
    return main(["handoff", "check", REPO, "7"], env=env, out=out, err=io.StringIO())


@pytest.mark.parametrize("stream", [BrokenPipe, Closed, Weird])
def test_a_print_failure_leaves_the_exit_code_alone(fake: FakeGitHub, stream: type[io.StringIO]) -> None:
    assert call(fake, stream()) == 0  # FRESH
    assert call(fake, stream(), head=B) == 1  # STALE
    assert call(fake, stream(), comments=[]) == 2  # UNKNOWN: no report


def test_a_print_failure_while_reporting_a_crash_is_still_exit_2(
    fake: FakeGitHub, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*args: Any) -> Any:
        raise ValueError("secret")

    monkeypatch.setattr(handoff, "verdict", boom)
    assert call(fake, BrokenPipe()) == 2
    assert call(fake, Closed()) == 2


@pytest.mark.parametrize("code", [0, 1, 2, None, "text"])
def test_a_system_exit_from_the_check_is_exit_2_with_the_class_name_only(
    fake: FakeGitHub, monkeypatch: pytest.MonkeyPatch, code: Any
) -> None:
    def leave(*args: Any) -> Any:
        raise SystemExit(code)

    monkeypatch.setattr(handoff, "verdict", leave)
    out = io.StringIO()
    assert call(fake, out) == 2
    assert out.getvalue() == "UNKNOWN internal error (SystemExit)\n"


def test_a_system_exit_from_a_dependency_deep_in_the_check_is_exit_2(
    fake: FakeGitHub, monkeypatch: pytest.MonkeyPatch
) -> None:
    def leave(*args: Any) -> Any:
        raise SystemExit(0)

    monkeypatch.setattr(handoff, "read_pull", leave)
    assert call(fake, io.StringIO()) == 2


def test_other_base_exceptions_are_exit_2(fake: FakeGitHub, monkeypatch: pytest.MonkeyPatch) -> None:
    def leave(*args: Any) -> Any:
        raise GeneratorExit()

    monkeypatch.setattr(handoff, "verdict", leave)
    out = io.StringIO()
    assert call(fake, out) == 2 and "GeneratorExit" in out.getvalue()


def test_a_keyboard_interrupt_is_not_swallowed(fake: FakeGitHub, monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupt(*args: Any) -> Any:
        raise KeyboardInterrupt()

    monkeypatch.setattr(handoff, "verdict", interrupt)
    with pytest.raises(KeyboardInterrupt):
        call(fake, io.StringIO())


def test_a_keyboard_interrupt_while_printing_is_not_swallowed(fake: FakeGitHub) -> None:
    class Interrupted(io.StringIO):
        def write(self, text: str) -> int:
            raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        call(fake, Interrupted())


def test_the_line_is_printed_once_when_printing_works(fake: FakeGitHub) -> None:
    out = io.StringIO()
    assert call(fake, out, head=B) == 1 and out.getvalue().count("\n") == 1 and out.getvalue().startswith("STALE")
