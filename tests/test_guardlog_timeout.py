# SPDX-License-Identifier: Apache-2.0
"""SAFO_APPEND_LOCK_TIMEOUT is parsed defensively: guardlog sits on the guard path, so import must never fail."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

from safo import guardlog
from safo.hooks import GUARD_TIMEOUT_SECONDS

DEFAULT = 3.0
BAD = ["", "abc", "nan", "inf", "-inf", "-1", "0", "-0.0", "1e999", "  ", "1,5", "0x10"]
GOOD = [("2", 2.0), (" 2 ", 2.0), ("0.25", 0.25), ("3.0", 3.0), ("1e0", 1.0)]


@pytest.mark.parametrize("raw", BAD)
def test_a_bad_value_falls_back_to_the_default_with_a_warning(raw: str) -> None:
    value, warning = guardlog.parse_append_lock_timeout(raw)
    assert value == DEFAULT
    assert warning
    assert "SAFO_APPEND_LOCK_TIMEOUT" in warning


@pytest.mark.parametrize(("raw", "expected"), GOOD)
def test_a_good_value_is_used_without_a_warning(raw: str, expected: float) -> None:
    assert guardlog.parse_append_lock_timeout(raw) == (expected, None)


@pytest.mark.parametrize("raw", ["1000", "6", "1e300"])
def test_a_very_large_value_is_clamped_with_a_warning(raw: str) -> None:
    value, warning = guardlog.parse_append_lock_timeout(raw)
    assert value == guardlog.MAX_APPEND_LOCK_TIMEOUT
    assert warning


def test_an_unset_variable_gives_the_default_silently() -> None:
    assert guardlog.parse_append_lock_timeout(None) == (DEFAULT, None)


def test_the_clamp_leaves_room_inside_the_guard_budget() -> None:
    assert DEFAULT <= guardlog.MAX_APPEND_LOCK_TIMEOUT < GUARD_TIMEOUT_SECONDS


@pytest.mark.parametrize("raw", [*BAD, "1000", "2"])
def test_importing_guardlog_never_raises(
    raw: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SAFO_APPEND_LOCK_TIMEOUT", raw)
    try:
        importlib.reload(guardlog)  # the module body is the import-time parse
        assert 0 < guardlog.APPEND_LOCK_TIMEOUT <= guardlog.MAX_APPEND_LOCK_TIMEOUT
        captured = capsys.readouterr()
        assert captured.out == "" and captured.err == "", (
            "importing writes nothing: a full pipe would block it for ever"
        )
        warning = guardlog.LOCK_TIMEOUT_WARNING  # kept, and printed by main() for commands that are not hooks
        assert (warning is not None) == (raw in BAD or raw == "1000")
        assert warning is None or "SAFO_APPEND_LOCK_TIMEOUT" in warning
    finally:
        monkeypatch.delenv("SAFO_APPEND_LOCK_TIMEOUT")
        importlib.reload(guardlog)


def test_reload_picks_up_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SAFO_APPEND_LOCK_TIMEOUT", "abc")
    try:
        importlib.reload(guardlog)
        assert guardlog.APPEND_LOCK_TIMEOUT == DEFAULT
    finally:
        monkeypatch.delenv("SAFO_APPEND_LOCK_TIMEOUT")
        importlib.reload(guardlog)


@pytest.mark.parametrize(("raw", "expected"), [("1_0", 5.0), ("٣", 3.0), ("1e-5", 1e-5)])
def test_python_float_syntax_is_accepted_as_documented(raw: str, expected: float) -> None:
    assert guardlog.parse_append_lock_timeout(raw)[0] == expected


def test_the_warning_is_printed_by_main_for_other_commands_and_never_for_the_hooks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import io

    from safo.cli import main

    monkeypatch.setattr(guardlog, "LOCK_TIMEOUT_WARNING", "SAFO_APPEND_LOCK_TIMEOUT is not a number; using 3 s")
    env = {"HOME": str(tmp_path), "PATH": ""}
    other = io.StringIO()
    main(["hooks", "status"], env=env, out=io.StringIO(), err=other)
    assert "safo: SAFO_APPEND_LOCK_TIMEOUT is not a number" in other.getvalue(), (
        "printed AFTER the command, for a person"
    )
    for hook in (["hooks", "guard"], ["hooks", "probe"]):
        quiet = io.StringIO()
        main(hook, env=env, out=io.StringIO(), err=quiet, stdin=io.StringIO("{}"))
        assert quiet.getvalue() == "", f"{hook}: a hook never prints it"


def test_a_closed_stderr_leaves_stdout_empty(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SAFO_APPEND_LOCK_TIMEOUT", "abc")
    monkeypatch.setattr(sys, "stderr", None)
    try:
        importlib.reload(guardlog)
        assert guardlog.APPEND_LOCK_TIMEOUT == DEFAULT
        assert capsys.readouterr().out == ""
    finally:
        monkeypatch.undo()
        importlib.reload(guardlog)


class _BrokenStream:
    def write(self, _text: str) -> int:
        raise OSError("broken pipe")

    def flush(self) -> None:
        raise OSError("broken pipe")


def test_a_failing_stderr_write_does_not_stop_the_import(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SAFO_APPEND_LOCK_TIMEOUT", "abc")
    monkeypatch.setattr(sys, "stderr", _BrokenStream())
    try:
        importlib.reload(guardlog)
        assert guardlog.APPEND_LOCK_TIMEOUT == DEFAULT
    finally:
        monkeypatch.undo()
        importlib.reload(guardlog)
