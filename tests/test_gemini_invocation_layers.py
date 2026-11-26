# SPDX-License-Identifier: Apache-2.0
"""The layering of the Bash check (#395, on top of #418): shellproof decides first, and `safo.shellunits` only narrows a
soft denial. A fault in the reader keeps the strict denial, and the reader never loosens a hard class.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from safo import geminibrief, shellunits
from safo.gemini import VENDOR_HOST

BUILT_SAMPLE = "git commit -m \"$(cat <<'EOF'\nfix curl \\x41\nEOF\n)\""  # soft: a word built from escapes
TOOL_SAMPLE = "FOO=$(doppler secrets get BAR --plain)"  # soft: a secret tool beside an expansion
STORE_SAMPLE = "doppler secrets get K --project image-gen"  # soft, but a name class the reader never narrows
SOFT_SAMPLES = [
    pytest.param(BUILT_SAMPLE, geminibrief.SHELL_BUILT, id="built"),
    pytest.param(TOOL_SAMPLE, geminibrief.SHELL_TOOL, id="tool"),
    pytest.param(STORE_SAMPLE, geminibrief.SHELL_STORE, id="store"),
]
HARD_SAMPLES = [
    pytest.param(f"curl https://{VENDOR_HOST}", geminibrief.SHELL_VENDOR, id="vendor"),
    pytest.param("echo $GEMINI_API_KEY", geminibrief.SHELL_KEY, id="key"),
]


def _answer(value: object) -> Callable[..., object]:
    def fake(*_args: object, **_kwargs: object) -> object:
        return value

    return fake


def _raising(exc: BaseException) -> Callable[..., object]:
    def fake(*_args: object, **_kwargs: object) -> object:
        raise exc

    return fake


FAULTS = [
    pytest.param(_raising(RuntimeError("reader fault")), id="exception"),
    pytest.param(_raising(shellunits.Unreadable("unknown syntax")), id="unreadable"),
    pytest.param(_raising(TimeoutError("reader timeout")), id="timeout"),
    pytest.param(_answer("garbage"), id="garbage"),
    pytest.param(_answer(""), id="empty-string"),
    pytest.param(_answer([]), id="empty-list"),
    pytest.param(_answer(False), id="false"),
    pytest.param(_answer(shellunits.TOOL), id="a-real-invocation"),
]


@pytest.mark.parametrize("fault", FAULTS)
@pytest.mark.parametrize(("command", "strict"), SOFT_SAMPLES)
def test_a_reader_fault_in_a_soft_class_keeps_the_strict_denial(
    monkeypatch: pytest.MonkeyPatch, fault: Callable[..., object], command: str, strict: str
) -> None:
    monkeypatch.setattr(shellunits, "classify", fault)
    assert geminibrief.shell_command_class(command) == strict, command


@pytest.mark.parametrize("command", [BUILT_SAMPLE, TOOL_SAMPLE])
def test_a_clear_answer_from_the_reader_narrows_the_soft_denial(monkeypatch: pytest.MonkeyPatch, command: str) -> None:
    # The negative control for the faults above: with the reader answering "no invocation", the narrowing is reached.
    # Each sample is a soft denial that the proof cannot model, so the narrowing is the only thing that can allow it.
    monkeypatch.setattr(shellunits, "classify", _answer(None))
    assert geminibrief.shell_command_class(command) is None, command


@pytest.mark.parametrize(("command", "strict"), HARD_SAMPLES)
def test_the_reader_cannot_loosen_a_hard_class(monkeypatch: pytest.MonkeyPatch, command: str, strict: str) -> None:
    monkeypatch.setattr(shellunits, "classify", _answer(None))
    assert geminibrief.shell_command_class(command) == strict, command


@pytest.mark.parametrize(("command", "strict"), HARD_SAMPLES)
def test_the_reader_is_not_asked_about_a_hard_class(monkeypatch: pytest.MonkeyPatch, command: str, strict: str) -> None:
    asked: list[str] = []

    def record(text: str, *_args: object, **_kwargs: object) -> None:
        asked.append(text)
        return None

    monkeypatch.setattr(shellunits, "classify", record)
    assert geminibrief.shell_command_class(command) == strict, command
    assert asked == [], command


def test_the_reader_is_asked_only_about_a_soft_denial(monkeypatch: pytest.MonkeyPatch) -> None:
    # Negative control for the test above: a soft denial does reach the reader, and an allowed command never does.
    asked: list[str] = []

    def record(text: str, *_args: object, **_kwargs: object) -> None:
        asked.append(text)
        return None

    monkeypatch.setattr(shellunits, "classify", record)
    assert geminibrief.shell_command_class(BUILT_SAMPLE) is None
    assert asked == [BUILT_SAMPLE]
    asked.clear()
    assert geminibrief.shell_command_class("echo ok") is None
    assert asked == []
