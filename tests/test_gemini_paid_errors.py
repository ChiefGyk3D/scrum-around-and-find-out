# SPDX-License-Identifier: Apache-2.0
"""Any error while reading the paid-use switch means disabled, in the wrapper and in the dispatch hook (#200)."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest

from safo import gemini, geminisign
from safo.errors import ConfigError
from safo.gemini import DisabledCheck, Locations, paid_enabled

PUBLIC = "gemini-material: public\n"
ERRORS: list[Exception] = [
    ConfigError("a directory above the file is not owned by this user or root"),
    OSError("input/output error"),
    PermissionError("permission denied"),
    UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
]


def raising(error: Exception) -> Any:
    def read(*args: object, **kwargs: object) -> bytes:
        raise error

    return read


@pytest.mark.parametrize("error", ERRORS, ids=lambda e: type(e).__name__)
def test_any_error_reading_the_switch_means_disabled(
    gemini_locations: Locations, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    assert paid_enabled() is True, "the fixture switch is on until the read fails"
    monkeypatch.setattr(geminisign, "read_trust_file", raising(error))
    assert paid_enabled() is False


@pytest.mark.parametrize("error", ERRORS, ids=lambda e: type(e).__name__)
def test_an_error_finding_the_fixed_locations_means_disabled(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    def boom() -> Locations:
        raise error

    monkeypatch.setattr(gemini, "fixed_locations", boom)
    assert paid_enabled() is False


@pytest.mark.parametrize("error", ERRORS, ids=lambda e: type(e).__name__)
def test_the_hook_gets_the_disabled_check_when_the_switch_check_itself_fails(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    from safo.context import LocalContext
    from safo.modes.hooks import approval_checker

    def boom() -> bool:
        raise error

    monkeypatch.setattr(gemini, "paid_enabled", boom)
    import io

    check = approval_checker(LocalContext(io.StringIO(), {}, dt.datetime.now(dt.UTC)))
    assert isinstance(check, DisabledCheck)


@pytest.mark.parametrize("error", ERRORS, ids=lambda e: type(e).__name__)
def test_the_guard_denies_paid_steps_and_allows_free_ones_when_the_switch_read_fails(
    _private_home: Path, tmp_path: Path, gemini_locations: Locations, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    from geminidata import write_config
    from hooksdata import agents_file, dispatch, hooks

    agents = agents_file(tmp_path / "agents.yaml")
    write_config(
        gemini_locations.config, "http://127.0.0.1:9", tmp_path / "data" / "ledger.jsonl", private_terms="none"
    )
    monkeypatch.setattr(geminisign, "read_trust_file", raising(error))
    paid = f"gemini: paid model=gemini-3.6-flash cap=1.50 approval=abcdefgh12\n{PUBLIC}"
    _, out, _ = hooks("guard", "--agents", str(agents), home=_private_home, stdin=dispatch(prompt=paid))
    data = json.loads(out)
    assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "paid use is disabled" in data["hookSpecificOutput"]["permissionDecisionReason"]
    _, out, _ = hooks(
        "guard", "--agents", str(agents), home=_private_home, stdin=dispatch(prompt=f"gemini: free\n{PUBLIC}")
    )
    assert "deny" not in out
