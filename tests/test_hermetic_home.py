"""Canary: every test runs with HOME private and no XDG base directory set, so no test reads real-home state."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from conftest import XDG_NAMES
from safo.guardlog import config_dir, state_dir


def test_home_is_private_and_no_xdg_override_survives(_private_home: Path) -> None:
    assert os.environ["HOME"] == str(_private_home)
    assert Path.home() == _private_home
    assert not any(name in os.environ for name in XDG_NAMES)
    assert not any(_private_home.iterdir())


def test_config_and_state_resolve_under_the_private_home(_private_home: Path) -> None:
    assert config_dir(os.environ) == _private_home / ".config" / "safo"
    assert (state_dir(os.environ) or Path("/nonexistent")).is_relative_to(_private_home)


def test_the_canary_bites_when_an_xdg_override_is_present(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Negative case: re-introduce the leak and the resolution escapes the private home."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "elsewhere"))
    assert config_dir(os.environ) == tmp_path / "elsewhere" / "safo"
    assert any(name in os.environ for name in XDG_NAMES)
