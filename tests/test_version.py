# SPDX-License-Identifier: MIT
"""The smallest thing CI's smoke step relies on: `safo --version`."""

from __future__ import annotations

import pytest

from safo import __version__
from safo.cli import main


def test_version_prints_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        main(["--version"])
    assert stop.value.code == 0
    assert capsys.readouterr().out.strip() == f"safo {__version__}"
