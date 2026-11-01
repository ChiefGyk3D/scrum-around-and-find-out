# SPDX-License-Identifier: Apache-2.0
"""`check-install` reads the egress config by the rules of the egress helper (#299).

The helper (`packaging/safo_broker_egress.py`) is a root-run file with no import of this package, and the admin tool
must not import a root helper, so the rules live twice. This file keeps them one: ONE table of config texts is run
through both readers, and they must agree on every row (the same host and mode, or both refuse). A row the helper
refuses and the admin tool accepts is the false "ok" the review found."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import safo_broker_egress as egress
from safo.broker import admin

HOST = "api.vendor.example.invalid"
BAD_MODE = "ob" + "serve"  # a near miss of a real mode, built so the table reads as data
# text -> (host, mode) when the helper accepts it, None when it refuses
TABLE: list[tuple[str, str, tuple[str, str] | None]] = [
    ("host and drop", f"VENDOR_HOST={HOST}\nMODE=drop\n", (HOST, "drop")),
    ("host and observe", f"VENDOR_HOST={HOST}\nMODE=observe\n", (HOST, "observe")),
    ("a missing mode means drop", f"VENDOR_HOST={HOST}\n", (HOST, "drop")),
    ("comments, blanks and padding", f"# c\n\n  VENDOR_HOST={HOST}  \n\tMODE=drop\n", (HOST, "drop")),
    ("the order does not matter", f"MODE=observe\nVENDOR_HOST={HOST}\n", (HOST, "observe")),
    ("a duplicate host", f"VENDOR_HOST={HOST}\nVENDOR_HOST={HOST}\nMODE=drop\n", None),
    ("a duplicate host with another name", f"VENDOR_HOST={HOST}\nVENDOR_HOST=other.example\n", None),
    ("a duplicate mode", f"VENDOR_HOST={HOST}\nMODE=observe\nMODE=drop\n", None),
    ("no host", "MODE=drop\n", None),
    ("an empty file", "", None),
    ("only comments", "# nothing\n", None),
    ("an empty host", "VENDOR_HOST=\nMODE=drop\n", None),
    ("a numeric host", "VENDOR_HOST=203.0.113.9\nMODE=drop\n", None),
    ("an upper-case host", "VENDOR_HOST=API.Vendor.Example\nMODE=drop\n", None),
    ("a host with a slash", "VENDOR_HOST=api.vendor.example/path\nMODE=drop\n", None),
    ("a host with a space", "VENDOR_HOST=api vendor.example\nMODE=drop\n", None),
    ("a host with no dot", "VENDOR_HOST=localhost\nMODE=drop\n", None),
    ("a bad mode", f"VENDOR_HOST={HOST}\nMODE=allow\n", None),
    ("a near-miss mode", f"VENDOR_HOST={HOST}\nMODE={BAD_MODE}d\n", None),
    ("an empty mode", f"VENDOR_HOST={HOST}\nMODE=\n", None),
    ("a mode in the wrong case", f"VENDOR_HOST={HOST}\nMODE=Drop\n", None),
    ("an unknown key", f"VENDOR_HOST={HOST}\nMODE=drop\nEXTRA=1\n", None),
    ("a line that is not a setting", f"VENDOR_HOST={HOST}\nnonsense\n", None),
    ("spaces around the equals sign", f"VENDOR_HOST = {HOST}\n", None),
    ("a lower-case key", f"vendor_host={HOST}\nMODE=drop\n", None),
]


def helper_reads(tmp_path: Path, text: str) -> tuple[str, str] | None:
    conf = tmp_path / "broker-egress.conf"
    conf.write_text(text)
    conf.chmod(0o644)
    try:
        cfg = egress.read_config(conf, uid=os.getuid(), anchor=tmp_path)
    except egress.EgressError:
        return None
    return cfg.host, cfg.mode


def admin_reads(text: str) -> tuple[str, str] | None:
    try:
        return admin.parse_egress_config(text)
    except ValueError:
        return None


def test_the_table_is_not_trimmed() -> None:
    names = [row[0] for row in TABLE]
    assert len(TABLE) == 25 and len(set(names)) == len(names)
    assert sum(row[2] is None for row in TABLE) == 20  # the rows the helper refuses
    assert sum(row[2] is not None for row in TABLE) == 5  # the rows it accepts


@pytest.mark.parametrize(("name", "text", "expected"), TABLE, ids=[row[0] for row in TABLE])
def test_the_helper_reads_each_row_as_the_table_says(tmp_path: Path, name: str, text: str, expected: object) -> None:
    assert helper_reads(tmp_path, text) == expected, name


@pytest.mark.parametrize(("name", "text", "expected"), TABLE, ids=[row[0] for row in TABLE])
def test_the_admin_tool_reads_each_row_as_the_helper_does(name: str, text: str, expected: object) -> None:
    assert admin_reads(text) == expected, name
