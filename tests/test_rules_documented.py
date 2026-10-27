# SPDX-License-Identifier: Apache-2.0
"""Every key the schema accepts under `rules` is documented in docs/board-yaml.md and shown in examples/safo.yaml."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from safo.schema import RULES_KEYS

ROOT = Path(__file__).parent.parent
DOC = (ROOT / "docs" / "board-yaml.md").read_text(encoding="utf-8")
EXAMPLE = yaml.safe_load((ROOT / "examples" / "safo.yaml").read_text(encoding="utf-8"))


def undocumented(keys: frozenset[str], doc: str) -> list[str]:
    """Keys with no table row: a row names the key in code ticks, alone or as the head of a dotted key."""
    return sorted(k for k in keys if not re.search(rf"`{re.escape(k)}[`.]", doc))


def test_the_schema_names_its_rules_keys() -> None:
    assert len(RULES_KEYS) >= 10  # something was collected
    assert {
        "gate_check",
        "gate_forbid_force_push",
        "gate_exempt_repos",
        "gate_require_admin_enforced",
        "gate_admin_exempt_repos",
        "gate_check_app_id",
    } <= RULES_KEYS


def test_every_rules_key_has_a_row_in_board_yaml_md() -> None:
    assert undocumented(RULES_KEYS, DOC) == []


def test_every_rules_key_is_shown_in_the_example_board() -> None:
    shown = set(EXAMPLE["rules"])
    assert sorted(RULES_KEYS - shown) == []
    assert sorted(shown - RULES_KEYS) == []  # and the example uses no key the schema does not know


def test_the_guard_bites() -> None:
    """A table with a row removed is reported, so a new key cannot go undocumented."""
    without = "\n".join(line for line in DOC.splitlines() if "`gate_exempt_repos`" not in line)
    assert "gate_exempt_repos" in undocumented(RULES_KEYS, without)
    assert undocumented(frozenset({"brand_new_key"}), DOC) == ["brand_new_key"]
