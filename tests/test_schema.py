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
    bad = DATA.parent.parent / "src" / "safo"
    for path in bad.rglob("*.py"):
        text = path.read_text()
        assert "yaml.load(" not in text and "yaml.unsafe_load" not in text and "FullLoader" not in text, path
