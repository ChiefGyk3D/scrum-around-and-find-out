# SPDX-License-Identifier: Apache-2.0
"""The startup-variable refusal runs as early as this program can (#287, finding D3, tracked launcher follow-up #267):
the first statement of `safo.cli.run`, before the hook clock, the guard entry or any parsing."""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

import pytest

from safo import cli, wrapper
from safo.errors import EXIT_UNKNOWN
from safo.modes import hooks

SECRET_VALUE = "value-that-must-not-be-printed"


def test_a_startup_variable_beside_the_gemini_word_is_refused_naming_the_variable_only(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = wrapper.early_refusal(["gemini", "quota", "--model", "m"], {"PYTHONPATH": SECRET_VALUE, "PATH": "/usr/bin"})
    assert code == EXIT_UNKNOWN
    err = capsys.readouterr().err
    assert "PYTHONPATH" in err and SECRET_VALUE not in err and "nothing was run" in err


@pytest.mark.parametrize("name", ["PYTHONSTARTUP", "BASH_ENV", "ENV", "LD_PRELOAD", "GCONV_PATH"])
def test_each_class_of_startup_variable_is_refused(name: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert wrapper.early_refusal(["gemini", "ask"], {name: "x"}) == EXIT_UNKNOWN
    assert name in capsys.readouterr().err


def test_a_clean_environment_or_another_mode_is_left_to_the_normal_path() -> None:
    assert wrapper.early_refusal(["gemini", "quota"], {"PATH": "/usr/bin", "HOME": "/h"}) is None
    assert wrapper.early_refusal(["status"], {"PYTHONPATH": "x"}) is None  # not the research wrapper: not its business


def test_run_refuses_before_the_hook_clock_or_any_parsing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def must_not_run(*args: object, **kwargs: object) -> None:
        raise AssertionError("the refusal must come first")

    monkeypatch.setattr(hooks, "arm_process_clock", must_not_run)
    monkeypatch.setattr(hooks, "guard_words", must_not_run)
    monkeypatch.setattr(wrapper, "enter", must_not_run)
    monkeypatch.setattr(sys, "argv", ["safo", "gemini", "quota", "--model", "m"])
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    with pytest.raises(SystemExit) as stopped:
        cli.run()
    assert stopped.value.code == EXIT_UNKNOWN


def test_the_guard_bites_run_without_a_startup_variable_does_reach_the_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Negative case: with a clean environment `run` does get past the refusal (the hook clock is armed)."""
    reached = []

    def stop(*args: object, **kwargs: object) -> None:
        reached.append(True)
        raise KeyboardInterrupt

    monkeypatch.setattr(hooks, "arm_process_clock", stop)
    monkeypatch.setattr(sys, "argv", ["safo", "gemini", "quota", "--model", "m"])
    for name in [k for k in os.environ if k.startswith(wrapper.STARTUP_PREFIXES) or k in wrapper.STARTUP_NAMES]:
        monkeypatch.delenv(name)
    with pytest.raises(KeyboardInterrupt):
        cli.run()
    assert reached == [True]
