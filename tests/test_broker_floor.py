# SPDX-License-Identifier: Apache-2.0
"""The broker refuses to start below the root-owned floor: the second layer behind the installer's own check."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from safo.broker import floor
from unitdata import parse_unit, read


def make_floor(tmp_path: Path, text: str = "1.2.3\n") -> tuple[Path, Path]:
    base = tmp_path / "etc"
    (base / "safo").mkdir(parents=True)
    for d in (base, base / "safo"):
        d.chmod(0o755)
    path = base / "safo" / "broker-min-version"
    path.write_text(text)
    path.chmod(0o644)
    return path, tmp_path


def check(tmp_path: Path, version: str, text: str = "1.2.3\n") -> str | None:
    path, anchor = make_floor(tmp_path, text)
    return floor.check(path, version, uid=os.getuid(), anchor=anchor)


def test_a_version_at_or_above_the_floor_may_start(tmp_path: Path) -> None:
    assert check(tmp_path, "1.2.3") is None
    assert check(tmp_path / "b", "1.2.4") is None
    assert check(tmp_path / "c", "2.0.0") is None


def test_a_version_below_the_floor_must_not_start(tmp_path: Path) -> None:
    assert "below the floor 1.2.3" in (check(tmp_path, "1.2.2") or "")
    assert "below the floor" in (check(tmp_path / "b", "0.9.9") or "")


@pytest.mark.parametrize("text", ["", "banana\n", "1.2\n", "v1.2.3\n", "1.2.3 \n1.2.4\n"])
def test_a_floor_file_without_a_clean_version_refuses(tmp_path: Path, text: str) -> None:
    assert "does not hold a version" in (check(tmp_path, "9.9.9", text) or "")


def test_a_version_the_release_cannot_state_refuses(tmp_path: Path) -> None:
    assert "no usable version" in (check(tmp_path, "dev") or "")


def test_a_missing_symlinked_or_writable_floor_refuses(tmp_path: Path) -> None:
    uid = os.getuid()
    path, anchor = make_floor(tmp_path / "a")
    path.unlink()
    assert "missing" in (floor.check(path, "9.9.9", uid=uid, anchor=anchor) or "")
    path, anchor = make_floor(tmp_path / "b")
    real = tmp_path / "real"
    real.write_text("0.0.1\n")
    path.unlink()
    path.symlink_to(real)
    assert "symlink" in (floor.check(path, "9.9.9", uid=uid, anchor=anchor) or "")
    path, anchor = make_floor(tmp_path / "c")
    path.chmod(0o664)
    assert "writable" in (floor.check(path, "9.9.9", uid=uid, anchor=anchor) or "")
    path, anchor = make_floor(tmp_path / "d")
    path.parent.chmod(0o775)
    assert "writable" in (floor.check(path, "9.9.9", uid=uid, anchor=anchor) or "")
    path, anchor = make_floor(tmp_path / "e")
    assert "not owned" in (floor.check(path, "9.9.9", uid=uid + 1, anchor=anchor) or "")


def test_main_exit_codes_and_messages(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    path, _ = make_floor(tmp_path, "999.0.0\n")
    monkeypatch.setattr(floor, "FLOOR_PATH", path)
    real_check = floor.check
    monkeypatch.setattr(floor, "check", lambda p, v: real_check(p, v, uid=os.getuid(), anchor=tmp_path))
    assert floor.main([]) == 1
    assert "refusing to start" in capsys.readouterr().err
    path.write_text("0.0.1\n")
    assert floor.main([]) == 0
    assert capsys.readouterr().err == ""
    assert floor.main(["--ignore-floor"]) == 2


def test_the_service_runs_the_floor_check_before_the_broker() -> None:
    triples = parse_unit(read("safo-broker.service"))
    order = [v for s, k, v in triples if k in ("ExecStartPre", "ExecStart")]
    assert order == [
        "/opt/safo-broker/current/venv/bin/python -I -m safo.broker.floor",
        "/opt/safo-broker/current/venv/bin/python -I -m safo.broker",
    ]
