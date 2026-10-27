# SPDX-License-Identifier: Apache-2.0
"""Every place the loader echoes file text in an error is bounded (round 6 of #134).

Three kinds of echo, each cut so a sub-1-MiB file cannot flood a log, and none of them changes the text of a
normal-sized message:

* `rep()` sites (the legacy repr echoes): 200 characters of repr, then "...";
* keys placed in an error path (unknown keys, `rules.new_item_defaults.<key>`): 200 characters, then "...";
* each option name in the legacy option listing: 200 characters, then "..." (at most 64 names).
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import safo.schema as schema
from safo.errors import ConfigError
from safo.schema import parse_board
from test_process_schema import base

LONG = 100_000
HUGE = 900_000
CEILING = 350  # one long value: the fixed words around it plus 200 characters of repr and "..."


def run(d: dict[str, Any]) -> str:
    with pytest.raises(ConfigError) as err:
        parse_board(d)
    return str(err.value)


def cut(value: str) -> str:
    return repr(value)[:200] + "..."


def big(prefix: str = "F") -> str:
    return prefix * LONG


# -- one case per rep() call site ------------------------------------------------------------------------------


def c_choice(d: dict[str, Any]) -> str:
    d["project"]["owner_type"] = big("u")
    return big("u")


def c_owner(d: dict[str, Any]) -> str:
    value = "x y" + "z" * LONG
    d["project"]["owner"] = value
    return value


def c_pair(d: dict[str, Any]) -> str:
    name = "bad name" + "z" * LONG
    d["repositories"][0]["name"] = name
    return "acme/" + name


def c_field_twice(d: dict[str, Any]) -> str:
    d["fields"] += [{"name": big(), "type": "text"}, {"name": big(), "type": "text"}]
    return big()


def c_option_twice(d: dict[str, Any]) -> str:
    d["fields"].append({"name": "Big", "type": "single_select", "options": [{"name": big("O")}, {"name": big("O")}]})
    return big("O")


def c_option_twice_field(d: dict[str, Any]) -> str:
    d["fields"].append({"name": big(), "type": "single_select", "options": [{"name": "a"}, {"name": "a"}]})
    return big()


def c_view_twice(d: dict[str, Any]) -> str:
    d["views"] += [{"name": big("V"), "layout": "table"}, {"name": big("V"), "layout": "table"}]
    return big("V")


def c_names_field(d: dict[str, Any]) -> str:
    d["rules"]["status_field"] = big("S")
    return big("S")


def c_field_type(d: dict[str, Any]) -> str:
    d["fields"].append({"name": big("S"), "type": "text"})
    d["rules"]["status_field"] = big("S")
    return big("S")


def c_not_an_option(d: dict[str, Any]) -> str:
    d["rules"]["status"] = {"opened": big("N")}
    return big("N")


def c_not_an_option_field(d: dict[str, Any]) -> str:
    d["fields"].append({"name": big("S"), "type": "single_select", "options": [{"name": "Done"}]})
    d["rules"]["status_field"] = big("S")
    return big("S")


def c_done_date(d: dict[str, Any]) -> str:
    d["fields"].append({"name": big("D"), "type": "text"})
    d["rules"]["done_date_field"] = big("D")
    return big("D")


def c_agents_field(d: dict[str, Any]) -> str:
    d["agents"] = {"field": big("A")}
    return big("A")


def c_agents_field_type(d: dict[str, Any]) -> str:
    d["fields"].append({"name": big("A"), "type": "text"})
    d["agents"] = {"field": big("A")}
    return big("A")


def c_agents_status(key: str, long_status_field: bool) -> Callable[[dict[str, Any]], str]:
    def go(d: dict[str, Any]) -> str:
        if long_status_field:
            d["fields"].append(
                {
                    "name": big("S"),
                    "type": "single_select",
                    "options": [{"name": "Backlog"}, {"name": "In progress"}, {"name": "Done"}],
                }
            )
            d["rules"]["status_field"] = big("S")
            d["agents"] = {"working": [], "waiting": [], key: ["Nope"]}
            return big("S")
        d["agents"] = {key: [big("W")]}
        return big("W")

    return go


# (label, case). Two sites of one message get one case each: only that site holds the long value.
SITES: list[tuple[str, Callable[[dict[str, Any]], str]]] = [
    ("choice value", c_choice),
    ("owner", c_owner),
    ("owner/name pair", c_pair),
    ("field defined twice", c_field_twice),
    ("option defined twice: option", c_option_twice),
    ("option defined twice: field", c_option_twice_field),
    ("view defined twice", c_view_twice),
    ("names field", c_names_field),
    ("field is not single_select", c_field_type),
    ("not an option: option", c_not_an_option),
    ("not an option: field", c_not_an_option_field),
    ("done date field", c_done_date),
    ("agents.field missing", c_agents_field),
    ("agents.field type", c_agents_field_type),
    ("agents.working: status", c_agents_status("working", False)),
    ("agents.working: status field", c_agents_status("working", True)),
    ("agents.waiting: status", c_agents_status("waiting", False)),
    ("agents.waiting: status field", c_agents_status("waiting", True)),
]
# The duplicate YAML key is driven through the loader (next section); two sites hold an owner/name entry that the
# grammar already limits to 139 characters, so their repr never reaches the 200-character cut.
GRAMMAR_BOUNDED = ["rules.gate_exempt_repos listed twice", "rules.gate_exempt_repos not in repositories"]
LOADER_SITES = ["duplicate key"]


def rep_call_sites() -> int:
    tree = ast.parse(Path(schema.__file__).read_text())
    return sum(1 for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "rep")


def test_every_rep_call_site_has_a_case() -> None:
    assert rep_call_sites() == len(SITES) + len(GRAMMAR_BOUNDED) + len(LOADER_SITES)


@pytest.mark.parametrize(("label", "case"), SITES, ids=[s[0] for s in SITES])
def test_a_hundred_kilobyte_value_is_cut_at_every_rep_site(label: str, case: Callable[[dict[str, Any]], str]) -> None:
    d = base()
    value = case(d)
    message = run(d)
    assert cut(value) in message
    assert len(message) <= CEILING


def test_the_grammar_keeps_an_exemption_entry_under_the_cut() -> None:
    longest = "o" * 39 + "/" + "r" * 100  # the longest owner/name the grammar accepts
    assert len(repr(longest)) <= 200


def test_a_huge_duplicate_yaml_key_is_cut_at_the_loader() -> None:
    key = "k" * 400_000  # explicit-key form: PyYAML refuses a simple key over 1024 characters before this point
    text = f"? {key}\n: 1\n? {key}\n: 2\n"
    with pytest.raises(ConfigError) as err:
        schema._safe_load(text)
    message = str(err.value)
    assert message.endswith(f"duplicate key {cut(key)}")
    assert len(message) <= CEILING


# -- keys placed in an error path ----------------------------------------------------------------------------------


def key_cut(key: str) -> str:
    return key[:200] + "..."


def top_unknown(d: dict[str, Any], key: str) -> str:
    d[key] = 1
    return key


def rules_unknown(d: dict[str, Any], key: str) -> str:
    d["rules"][key] = 1
    return f"rules.{key}"


def repo_unknown(d: dict[str, Any], key: str) -> str:
    d["repositories"][0][key] = 1
    return f"repositories[0].{key}"


@pytest.mark.parametrize("where", [top_unknown, rules_unknown, repo_unknown])
def test_an_unknown_key_is_cut_in_the_path(where: Callable[[dict[str, Any], str], str]) -> None:
    key = "K" * HUGE
    d = base()
    where(d, key)
    message = run(d)
    assert key_cut(key) in message and len(message) <= CEILING + 250
    # a key of exactly 200 characters is echoed whole, as before
    d = base()
    where(d, "K" * 200)
    assert "K" * 200 + ":" in run(d) and "..." not in run(d)


def test_a_new_item_default_key_is_cut_in_the_path_when_it_is_not_a_field() -> None:
    key = "N" * HUGE
    d = base()
    d["rules"]["new_item_defaults"] = {key: "x"}
    message = run(d)
    assert key_cut(key) in message and len(message) <= 2 * CEILING + 100


def test_a_new_item_default_key_is_cut_in_the_path_when_its_value_is_empty() -> None:
    key = "N" * HUGE
    d = base()
    d["rules"]["new_item_defaults"] = {key: ""}
    message = run(d)
    assert message == f"board.yaml: rules.new_item_defaults.{key_cut(key)}: expected a non-empty string"


def test_a_new_item_default_key_naming_a_field_with_no_such_option_is_cut() -> None:
    key = "P" * HUGE
    d = base()
    d["fields"].append({"name": key, "type": "single_select", "options": [{"name": "a"}]})
    d["rules"]["new_item_defaults"] = {key: "zzz"}
    message = run(d)
    assert key_cut(key) in message and len(message) <= 4 * CEILING


# -- the legacy option listing --------------------------------------------------------------------------------------


def listing_error(names: list[str]) -> str:
    d = base()
    d["fields"][0]["options"] = [{"name": "Backlog"}, {"name": "Done"}, *({"name": n} for n in names)]
    d["rules"]["status"] = {"opened": "Nope"}
    return run(d)


def test_one_huge_option_name_is_cut_in_the_listing() -> None:
    name = "L" * HUGE
    message = listing_error([name])
    assert message.endswith(f"(options: Backlog, Done, {key_cut(name)})")


def test_sixty_four_options_of_13_kib_have_a_documented_ceiling() -> None:
    names = [f"{i:02d}" + "x" * 13_000 for i in range(62)]
    message = listing_error(names)
    assert len(message) <= 64 * 205 + 300  # 64 names of at most 200 characters, "..." and a separator each


def test_a_name_of_exactly_200_characters_is_listed_whole() -> None:
    name = "N" * 200
    assert listing_error([name]).endswith(f"(options: Backlog, Done, {name})")


def test_an_oversized_exemption_entry_is_refused_by_the_grammar_before_any_echo() -> None:
    d = base()
    d["rules"]["gate_exempt_repos"] = ["acme/" + "r" * LONG]
    assert run(d) == "board.yaml: rules.gate_exempt_repos[0]: expected owner/name"
