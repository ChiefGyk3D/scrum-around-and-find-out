# SPDX-License-Identifier: Apache-2.0
"""The broker's unit files carry every hardening line the design requires, and systemd accepts them."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from unitdata import (
    FORBIDDEN_SERVICE_KEYS,
    REQUIRED_SERVICE,
    REQUIRED_SOCKET,
    UNIT_DIR,
    missing,
    parse_unit,
    read,
)

ANALYZE = shutil.which("systemd-analyze")
ALL_REQUIRED = [("safo-broker.service", r) for r in REQUIRED_SERVICE] + [
    ("safo-broker.socket", r) for r in REQUIRED_SOCKET
]


def test_the_unit_files_exist_and_are_collected() -> None:
    assert sorted(p.name for p in UNIT_DIR.iterdir()) == ["safo-broker.service", "safo-broker.socket"]
    assert len(ALL_REQUIRED) > 50  # the guard looks at something


def test_service_has_every_required_line() -> None:
    assert missing(read("safo-broker.service"), REQUIRED_SERVICE) == []


def test_socket_has_every_required_line() -> None:
    assert missing(read("safo-broker.socket"), REQUIRED_SOCKET) == []


@pytest.mark.parametrize(("unit", "line"), ALL_REQUIRED, ids=[f"{u}:{r[1]}={r[2]}"[:70] for u, r in ALL_REQUIRED])
def test_removing_any_required_line_is_caught(unit: str, line: tuple[str, str, str]) -> None:
    """The negative case: delete exactly one required line from a copy of the shipped file, and the check names it."""
    section, key, value = line
    required = REQUIRED_SERVICE if unit.endswith(".service") else REQUIRED_SOCKET
    kept: list[str] = []
    removed = 0
    current = ""
    for raw in read(unit).splitlines():
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1]
        if current == section and stripped == f"{key}={value}":
            removed += 1
            continue
        kept.append(raw)
    assert removed == 1
    assert missing("\n".join(kept), required) == [f"{section}: {key}={value}"]


def test_a_weakened_value_is_caught() -> None:
    weak = read("safo-broker.service").replace("ProtectSystem=strict", "ProtectSystem=full")
    assert missing(weak, REQUIRED_SERVICE) == ["Service: ProtectSystem=strict"]


def test_service_has_no_forbidden_key() -> None:
    triples = parse_unit(read("safo-broker.service"))
    keys = {k for _, k, _ in triples}
    for bad in FORBIDDEN_SERVICE_KEYS:
        assert bad not in keys, bad
    assert [v for s, k, v in triples if k == "Environment"] == ["PYTHONDONTWRITEBYTECODE=1"]
    # the only writable path is the state directory
    assert [v for s, k, v in triples if k == "ReadWritePaths"] == ["/var/lib/safo-broker"]
    # no address allow or deny list (the vendor addresses are not fixed; the design says so)
    assert not {"IPAddressAllow", "IPAddressDeny"} & keys


def test_the_key_never_appears_in_a_unit() -> None:
    for name in ("safo-broker.service", "safo-broker.socket"):
        text = read(name)
        assert "AIza" not in text
        assert "Environment=" not in text.replace("Environment=PYTHONDONTWRITEBYTECODE=1", "")


def test_service_exec_runs_isolated_from_the_release_link() -> None:
    exec_lines = [v for s, k, v in parse_unit(read("safo-broker.service")) if k == "ExecStart"]
    assert exec_lines == ["/opt/safo-broker/current/venv/bin/python -I -m safo.broker"]


def _stage(tmp_path: Path) -> Path:
    """Copy the units next to a stub interpreter so systemd-analyze can resolve ExecStart."""
    stub = tmp_path / "bin" / "python"
    stub.parent.mkdir()
    stub.write_text("#!/bin/sh\n")
    stub.chmod(0o755)
    out = tmp_path / "units"
    out.mkdir()
    for name in ("safo-broker.service", "safo-broker.socket"):
        text = read(name).replace("/opt/safo-broker/current/venv/bin/python", str(stub))
        (out / name).write_text(text)
    return out


@pytest.mark.skipif(
    ANALYZE is None, reason="systemd-analyze is not installed on this machine; unit syntax is not checked here"
)
def test_systemd_analyze_verify_accepts_the_units(tmp_path: Path) -> None:
    out = _stage(tmp_path)
    done = subprocess.run(  # noqa: S603 - absolute-or-PATH systemd-analyze, fixed argv, no shell, files in tmp_path
        [str(ANALYZE), "verify", "--man=no", str(out / "safo-broker.service"), str(out / "safo-broker.socket")],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert "Unknown key" not in done.stderr
    assert "Unknown section" not in done.stderr


@pytest.mark.skipif(
    ANALYZE is None, reason="systemd-analyze is not installed on this machine; the exposure score is not checked here"
)
def test_systemd_analyze_security_score_is_ok(tmp_path: Path) -> None:
    out = _stage(tmp_path)
    done = subprocess.run(  # noqa: S603 - same as above, offline mode reads only the file
        [str(ANALYZE), "security", "--offline=true", "--no-pager", str(out / "safo-broker.service")],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    last = done.stdout.strip().splitlines()[-1]
    assert "Overall exposure level" in last
    score = float(last.split(":")[1].split()[0])
    assert score <= 2.0, last  # the design recorded 1.2; a rise past 2.0 means a hardening line was lost
