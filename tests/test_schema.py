# SPDX-License-Identifier: MIT
"""board.yaml: what loads, and the sentence that names the key when it does not."""

from __future__ import annotations

import copy
import datetime as dt
from pathlib import Path
from typing import Any

import pytest
import yaml

from safo.errors import ConfigError
from safo.schema import load_board, parse_board

DATA = Path(__file__).parent / "data"
EXAMPLES = Path(__file__).parent.parent / "examples"


def doc() -> dict[str, Any]:
    loaded = yaml.safe_load((DATA / "board.yaml").read_text())
    assert isinstance(loaded, dict)
    return copy.deepcopy(loaded)


def test_the_test_board_loads_with_everything_in_it() -> None:
    board = load_board(DATA / "board.yaml")
    assert board.project.owner == "acme" and board.project.number == 1
    assert [f.name for f in board.fields][:2] == ["Status", "Area"]
    sprint = board.field_named("Sprint")
    assert sprint and sprint.start == dt.date(2026, 10, 6) and sprint.count == 3
    assert board.repositories[0].area_rules[0].area == "Docs"
    assert board.rules.status.opened_pr == "In progress"
    assert board.rules.new_item_defaults == (("Priority", "P2 later"),)


@pytest.mark.parametrize(
    "example", sorted(p for p in EXAMPLES.glob("*.yaml") if not p.name.startswith("agents")), ids=lambda p: p.name
)
def test_every_shipped_example_validates(example: Path) -> None:
    load_board(example)


def test_an_unknown_key_is_named_with_its_path() -> None:
    d = doc()
    d["fields"][0]["options"][1]["colour"] = "BLUE"
    with pytest.raises(ConfigError, match=r"fields\[0\]\.options\[1\]\.colour: unknown key"):
        parse_board(d)


def test_a_bad_colour_names_the_key_and_the_choices() -> None:
    d = doc()
    d["fields"][0]["options"][0]["color"] = "TEAL"
    with pytest.raises(ConfigError, match=r"fields\[0\]\.options\[0\]\.color: 'TEAL' is not one of GRAY, BLUE"):
        parse_board(d)


def test_a_missing_required_key_is_named() -> None:
    d = doc()
    del d["project"]["owner_type"]
    with pytest.raises(ConfigError, match=r"project\.owner_type: required"):
        parse_board(d)


def test_the_error_starts_with_the_file_name() -> None:
    d = doc()
    d["version"] = 2
    with pytest.raises(ConfigError, match=r"^my-board\.yaml: version: only version 1"):
        parse_board(d, "my-board.yaml")


def test_yaml_turns_an_unquoted_no_into_a_boolean_and_the_key_is_still_named() -> None:
    """YAML 1.1 reads `No`, `yes`, `on` as booleans; an option called No must be quoted."""
    d = yaml.safe_load(
        """
version: 1
project: {owner: acme, owner_type: organization, title: T}
repositories: []
fields:
  - name: Gate
    type: single_select
    options:
      - {name: No}
"""
    )
    with pytest.raises(ConfigError, match=r"fields\[0\]\.options\[0\]\.name: expected a non-empty string"):
        parse_board(d)


def test_a_date_that_is_a_timestamp_is_refused() -> None:
    d = doc()
    d["fields"][4]["start"] = dt.datetime(2026, 10, 6, 9, 0)
    with pytest.raises(ConfigError, match=r"fields\[4\]\.start: expected a date"):
        parse_board(d)


def test_duplicates_are_refused() -> None:
    d = doc()
    d["fields"][1]["name"] = "Status"
    with pytest.raises(ConfigError, match=r"fields\[1\]\.name: field 'Status' is defined twice"):
        parse_board(d)
    d = doc()
    d["repositories"].append({"owner": "ACME", "name": "Widgets"})
    with pytest.raises(ConfigError, match=r"repositories\[2\].*listed twice"):
        parse_board(d)


def test_a_status_rule_must_name_an_existing_option() -> None:
    d = doc()
    d["rules"]["status"]["closed"] = "Finished"
    with pytest.raises(ConfigError, match=r"rules\.status\.closed: 'Finished' is not an option of 'Status'"):
        parse_board(d)


def test_a_default_area_must_name_an_existing_option() -> None:
    d = doc()
    d["repositories"][1]["default_area"] = "Nowhere"
    with pytest.raises(ConfigError, match=r"repositories\[1\]\.default_area: 'Nowhere'"):
        parse_board(d)


def test_the_done_date_field_must_be_a_date_field() -> None:
    d = doc()
    d["rules"]["done_date_field"] = "Status"
    with pytest.raises(ConfigError, match=r"rules\.done_date_field: 'Status' must be a date field"):
        parse_board(d)


def test_an_iteration_needs_its_three_keys_and_no_other_type_may_have_them() -> None:
    d = doc()
    del d["fields"][4]["count"]
    with pytest.raises(ConfigError, match=r"fields\[4\]\.count: required for an iteration"):
        parse_board(d)
    d = doc()
    d["fields"][5]["start"] = "2026-10-06"
    with pytest.raises(ConfigError, match=r"fields\[5\]\.start: only an iteration field"):
        parse_board(d)


def test_a_single_select_needs_options_and_other_types_may_not_have_them() -> None:
    d = doc()
    d["fields"][0]["options"] = []
    with pytest.raises(ConfigError, match=r"fields\[0\]\.options: a single_select field needs"):
        parse_board(d)
    d = doc()
    d["fields"][5]["options"] = [{"name": "x"}]
    with pytest.raises(ConfigError, match=r"fields\[5\]\.options: only a single_select"):
        parse_board(d)


def test_the_project_number_may_be_absent_for_bootstrap() -> None:
    d = doc()
    del d["project"]["number"]
    assert parse_board(d).project.number is None


def test_an_unreadable_or_invalid_file_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read the board file"):
        load_board(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("a: [unclosed\n")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_board(bad)


def test_yaml_is_only_ever_loaded_with_safe_load() -> None:
    """Verify that only our custom _SafeLoader is used for YAML loading."""
    import re

    src = Path(__file__).parent.parent / "src" / "safo"
    for path in src.rglob("*.py"):
        text = path.read_text()
        # Forbid unsafe loaders: full_load, load_all, Loader=yaml.Loader, FullLoader, UnsafeLoader
        bad_calls = re.findall(
            r"yaml\.(full_load|load_all|Loader|FullLoader|UnsafeLoader|unsafe_load)\b",
            text,
        )
        # Also forbid Loader= with anything other than _SafeLoader
        bad_loader_arg = re.findall(r"Loader\s*=\s*(?!_SafeLoader)[\w.]+", text)
        assert not bad_calls, f"{path} contains unsafe YAML loaders: {bad_calls}"
        assert not bad_loader_arg, f"{path} uses unsafe Loader=: {bad_loader_arg}"


# ===== Tests for all validation branches (item 6) =====


def test_duplicate_option_names_are_refused() -> None:
    """Verify duplicate option validation survives (schema.py line 254)."""
    d = doc()
    d["fields"][0]["options"][0]["name"] = "Next"
    d["fields"][0]["options"][1]["name"] = "Next"
    with pytest.raises(ConfigError, match=r"option 'Next' is defined twice"):
        parse_board(d)


def test_owner_login_check_is_required() -> None:
    """Verify _LOGIN check survives (schema.py line 195)."""
    d = doc()
    d["project"]["owner"] = "-invalid"  # Invalid: starts with dash
    with pytest.raises(ConfigError, match=r"is not a GitHub login"):
        parse_board(d)


def test_repository_owner_name_check_is_required() -> None:
    """Verify _LOGIN/_REPO check survives (schema.py line 225)."""
    d = doc()
    d["repositories"][0]["owner"] = "-invalid"  # Invalid: starts with dash
    with pytest.raises(ConfigError, match=r"is not an owner/name pair"):
        parse_board(d)


def test_owner_type_choice_is_required() -> None:
    """Verify owner_type choice validation survives."""
    d = doc()
    d["project"]["owner_type"] = "alien"
    with pytest.raises(ConfigError, match=r"is not one of organization, user"):
        parse_board(d)


def test_field_type_choice_is_required() -> None:
    """Verify field type choice validation survives (schema.py line 238)."""
    d = doc()
    d["fields"][0]["type"] = "unknown"
    with pytest.raises(ConfigError, match=r"is not one of single_select, iteration"):
        parse_board(d)


def test_view_layout_choice_is_required() -> None:
    """Verify view layout choice validation survives."""
    d = doc()
    d["views"][0]["layout"] = "calendar"
    with pytest.raises(ConfigError, match=r"is not one of board, table, roadmap"):
        parse_board(d)


def test_duplicate_view_names_are_refused() -> None:
    """Verify duplicate view name validation survives."""
    d = doc()
    d["views"].append({"name": "Board", "layout": "table"})
    with pytest.raises(ConfigError, match=r"view 'Board' is defined twice"):
        parse_board(d)


def test_area_rules_area_cross_check() -> None:
    """Verify area_rules[].area cross-check survives."""
    d = doc()
    d["repositories"][0]["area_rules"][0]["area"] = "Unknown"
    with pytest.raises(ConfigError, match=r"repositories\[0\]\.area_rules\[0\]\.area"):
        parse_board(d)


def test_new_item_defaults_cross_check() -> None:
    """Verify new_item_defaults cross-check survives."""
    d = doc()
    d["rules"]["new_item_defaults"]["Priority"] = "Unknown"
    with pytest.raises(ConfigError, match=r"rules\.new_item_defaults\.Priority"):
        parse_board(d)


def test_bool_guard_in_integer() -> None:
    """Verify bool guard in integer survives (schema.py)."""
    d = doc()
    d["fields"][4]["count"] = True
    with pytest.raises(ConfigError, match=r"fields\[4\]\.count: expected an integer"):
        parse_board(d)


def test_add_closed_days_check() -> None:
    """Verify add_closed_days integer check survives."""
    d = doc()
    d["rules"]["add_closed_days"] = "five"
    with pytest.raises(ConfigError, match=r"rules\.add_closed_days: expected an integer"):
        parse_board(d)


def test_agents_field_check() -> None:
    """Verify agents.field string check survives."""
    d = doc()
    d["agents"] = {"field": 123}
    with pytest.raises(ConfigError, match=r"agents\.field: expected a non-empty string"):
        parse_board(d)


def test_duration_days_minimum() -> None:
    """Verify duration_days minimum check survives."""
    d = doc()
    d["fields"][4]["duration_days"] = 0
    with pytest.raises(ConfigError, match=r"fields\[4\]\.duration_days: expected an integer >= 1"):
        parse_board(d)


# ===== Tests for hostile YAML (items 1-4) =====


def test_duplicate_yaml_keys_are_refused(tmp_path: Path) -> None:
    """Verify duplicate YAML keys are caught and named."""
    bad = tmp_path / "dup.yaml"
    bad.write_text(
        """version: 1
project:
  owner: acme
  owner: acme
  owner_type: organization
  title: T
repositories: []
"""
    )
    with pytest.raises(ConfigError, match=r"duplicate key"):
        load_board(bad)


def test_yaml_aliases_are_refused(tmp_path: Path) -> None:
    """Verify YAML aliases are refused."""
    bad = tmp_path / "alias.yaml"
    bad.write_text(
        """version: 1
project: &p
  owner: acme
  owner_type: organization
  title: T
repositories: []
"""
    )
    with pytest.raises(ConfigError, match=r"aliases are not allowed|anchors are not allowed"):
        load_board(bad)


def test_yaml_merge_keys_are_refused(tmp_path: Path) -> None:
    """Verify YAML merge keys are refused."""
    bad = tmp_path / "merge.yaml"
    bad.write_text(
        """version: 1
defaults: &defaults
  owner: acme
  owner_type: organization
project:
  <<: *defaults
  title: T
repositories: []
"""
    )
    with pytest.raises(ConfigError, match=r"merge keys|aliases|anchors"):
        load_board(bad)


def test_yaml_size_cap(tmp_path: Path) -> None:
    """Verify files over 1 MiB are refused."""
    big = tmp_path / "big.yaml"
    # Create a file slightly over 1 MiB
    big.write_text("x: " + "y" * (1024 * 1024 + 1))
    with pytest.raises(ConfigError, match=r"exceeds maximum size"):
        load_board(big)


def test_yaml_depth_limit(tmp_path: Path) -> None:
    """Verify deeply nested YAML is refused without RecursionError."""
    deep = tmp_path / "deep.yaml"
    # Create YAML with very deep nesting in a nested mapping structure
    # Build a mapping nested 100 levels deep
    yaml_text = "version: 1\nproject: {owner: a, owner_type: organization, title: T}\nrepositories: []\nfields:\n"
    # Add 100 levels of nested mappings through the options structure
    yaml_text += "  - name: F\n    type: single_select\n    options:\n"
    yaml_text += "      - " + "{x: " * 100 + "1" + "}" * 100 + "\n"
    deep.write_text(yaml_text)
    # The loader should refuse this without crashing
    try:
        load_board(deep)
        pytest.fail("Expected ConfigError for deeply nested YAML")
    except ConfigError:
        # Expected - depth or validation error
        pass
    except RecursionError:
        pytest.fail("Should not raise RecursionError, should be ConfigError")


def test_version_true_is_refused() -> None:
    """Verify version: true is refused (not treated as 1)."""
    d = {"version": True, "project": {"owner": "a", "owner_type": "organization", "title": "T"}, "repositories": []}
    with pytest.raises(ConfigError, match=r"version: only version 1"):
        parse_board(d)


def test_non_string_mapping_key_is_reported_as_key_error() -> None:
    """Verify non-string keys in mappings are reported as key errors, not field names."""
    d = {
        "version": 1,
        "project": {"owner": "a", "owner_type": "organization", "title": "T"},
        "repositories": [],
        "rules": {"new_item_defaults": {True: "P2 later"}},
    }
    with pytest.raises(ConfigError, match=r"key must be a string"):
        parse_board(d)


def test_agents_working_cross_check() -> None:
    """Verify agents.working options are checked against Status options."""
    d = doc()
    d["agents"] = {"field": "Agent", "working": ["Unknown"], "waiting": ["Blocked"]}
    with pytest.raises(ConfigError, match=r"agents\.working\[0\].*is not an option"):
        parse_board(d)


def test_agents_waiting_cross_check() -> None:
    """Verify agents.waiting options are checked against Status options."""
    d = doc()
    d["agents"] = {"field": "Agent", "working": ["In progress"], "waiting": ["Unknown"]}
    with pytest.raises(ConfigError, match=r"agents\.waiting\[0\].*is not an option"):
        parse_board(d)


def test_agents_field_exists_check() -> None:
    """Verify agents.field references an existing field."""
    d = doc()
    d["agents"] = {"field": "Unknown"}
    with pytest.raises(ConfigError, match=r"agents\.field.*is not in fields"):
        parse_board(d)
