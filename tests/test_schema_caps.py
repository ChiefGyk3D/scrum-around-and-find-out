# SPDX-License-Identifier: Apache-2.0
"""Cardinality caps on every list the board loader reads, and a bound on the legacy repr echoes (round 5 of #134).

A cap is checked on the raw list length before any entry is read or built, so a hostile file costs one comparison,
not a quadratic scan. Boards under the caps load and print exactly as before.
"""

from __future__ import annotations

import copy
import glob
import hashlib
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

import legacy_echo_cases as echo
import safo.schema as schema
from safo.errors import ConfigError
from safo.schema import parse_board
from test_process_schema import base, refuses

ROOT = Path(__file__).parent.parent


def repos(n: int) -> list[dict[str, str]]:
    return [{"owner": "acme", "name": f"r{i}"} for i in range(n)]


def set_repositories(d: dict[str, Any], n: int) -> None:
    d["repositories"] = repos(n)


def set_fields(d: dict[str, Any], n: int) -> None:
    d["fields"] = [{"name": f"F{i}", "type": "text"} for i in range(n)]


def set_views(d: dict[str, Any], n: int) -> None:
    d["views"] = [{"name": f"V{i}", "layout": "table"} for i in range(n)]


def set_options(d: dict[str, Any], n: int) -> None:
    d["fields"].append({"name": "Big", "type": "single_select", "options": [{"name": f"O{i}"} for i in range(n)]})


def set_area_rules(d: dict[str, Any], n: int) -> None:
    d["repositories"][0]["area_rules"] = [{"match": f"m{i}", "area": "Core"} for i in range(n)]


def set_ui_only(d: dict[str, Any], n: int) -> None:
    d["ui_only"] = [f"s{i}" for i in range(n)]


def set_new_item_defaults(d: dict[str, Any], n: int) -> None:
    d["rules"]["new_item_defaults"] = {f"F{i}": "x" for i in range(n)}


def set_agents(key: str) -> Callable[[dict[str, Any], int], None]:
    def go(d: dict[str, Any], n: int) -> None:
        d["agents"] = {key: [f"S{i}" for i in range(n)]}

    return go


def set_exempt(*keys: str) -> Callable[[dict[str, Any], int], None]:
    def go(d: dict[str, Any], n: int) -> None:
        set_repositories(d, 200)
        node = d["rules"]
        for key in keys[:-1]:
            node = node.setdefault(key, {})
        node[keys[-1]] = [f"acme/r{i}" for i in range(n)]

    return go


# (name, builder, path, limit)
CAPS: list[tuple[str, Callable[[dict[str, Any], int], None], str, int]] = [
    ("repositories", set_repositories, "repositories", 200),
    ("fields", set_fields, "fields", 100),
    ("views", set_views, "views", 50),
    ("options", set_options, "fields[6].options", 64),
    ("area_rules", set_area_rules, "repositories[0].area_rules", 100),
    ("ui_only", set_ui_only, "ui_only", 100),
    ("new_item_defaults", set_new_item_defaults, "rules.new_item_defaults", 100),
    ("agents.working", set_agents("working"), "agents.working", 64),
    ("agents.waiting", set_agents("waiting"), "agents.waiting", 64),
    ("tracking.exempt_repos", set_exempt("tracking", "exempt_repos"), "rules.tracking.exempt_repos", 200),
    ("threat_model.exempt_repos", set_exempt("threat_model", "exempt_repos"), "rules.threat_model.exempt_repos", 200),
    ("gate_exempt_repos", set_exempt("gate_exempt_repos"), "rules.gate_exempt_repos", 200),
    ("gate_admin_exempt_repos", set_exempt("gate_admin_exempt_repos"), "rules.gate_admin_exempt_repos", 200),
]


@pytest.mark.parametrize(("name", "build", "path", "limit"), CAPS, ids=[c[0] for c in CAPS])
def test_each_cap_accepts_the_limit_and_refuses_one_more(
    name: str, build: Callable[[dict[str, Any], int], None], path: str, limit: int
) -> None:
    d = base()
    build(d, limit)
    parse_board(d, check_fields=False)
    d = base()
    build(d, limit + 1)
    refuses(d, f"{path}: at most {limit} entries", check_fields=False)


# -- hostile sizes are refused before any entry is built ------------------------------------------------------


class Spy:
    def __init__(self, real: Any) -> None:
        self.real, self.count = real, 0

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.count += 1
        return self.real(*args, **kwargs)


@pytest.mark.parametrize(
    ("symbol", "build", "path", "limit"),
    [
        ("Repository", set_repositories, "repositories", 200),
        ("Field", set_fields, "fields", 100),
        ("View", set_views, "views", 50),
    ],
)
def test_twenty_thousand_entries_are_refused_fast_and_unbuilt(
    monkeypatch: pytest.MonkeyPatch, symbol: str, build: Callable[[dict[str, Any], int], None], path: str, limit: int
) -> None:
    spy = Spy(getattr(schema, symbol))
    monkeypatch.setattr(schema, symbol, spy)
    d = base()
    build(d, 20_000)
    started = time.monotonic()
    refuses(d, f"{path}: at most {limit} entries")
    assert spy.count == 0 and time.monotonic() - started < 2


def test_twenty_thousand_options_are_refused_fast_and_unbuilt(monkeypatch: pytest.MonkeyPatch) -> None:
    spy = Spy(schema.Option)
    monkeypatch.setattr(schema, "Option", spy)
    d = base()
    spy.count = 0
    set_options(d, 20_000)
    started = time.monotonic()
    refuses(d, "fields[6].options: at most 64 entries")
    assert spy.count == sum(len(f.get("options", [])) for f in base()["fields"][:6])  # only the six real fields
    assert time.monotonic() - started < 2


def test_duplicates_are_found_without_a_quadratic_scan() -> None:
    d = base()
    set_fields(d, 100)
    d["fields"][99] = {"name": "F0", "type": "text"}
    started = time.monotonic()
    with pytest.raises(ConfigError, match=r"fields\[99\]\.name: field 'F0' is defined twice"):
        parse_board(d, check_fields=False)
    assert time.monotonic() - started < 2


# -- shipped boards still load, under the caps ----------------------------------------------------------------

# Measured on 2026-10-27 over boards/*.yaml, examples/*.yaml and tests/data/board.yaml (the file that has the maximum).
MEASURED = {"repositories": 25, "fields": 12, "views": 5, "options": 15, "area_rules": 27, "ui_only": 4}


def test_the_shipped_boards_are_far_under_every_cap() -> None:
    files = sorted(glob.glob(str(ROOT / "boards/*.yaml")) + glob.glob(str(ROOT / "examples/*.yaml")))
    seen = {k: 0 for k in MEASURED}
    for name in files:
        d = yaml.safe_load(Path(name).read_text())
        if not isinstance(d, dict) or "repositories" not in d:
            continue
        seen["repositories"] = max(seen["repositories"], len(d["repositories"]))
        seen["fields"] = max(seen["fields"], len(d.get("fields", [])))
        seen["views"] = max(seen["views"], len(d.get("views", [])))
        seen["ui_only"] = max(seen["ui_only"], len(d.get("ui_only", [])))
        seen["area_rules"] = max([seen["area_rules"], *(len(r.get("area_rules", [])) for r in d["repositories"])])
        seen["options"] = max([seen["options"], *(len(f.get("options", [])) for f in d.get("fields", []))])
    assert seen == MEASURED
    limits = {"repositories": 200, "fields": 100, "views": 50, "options": 64, "area_rules": 100, "ui_only": 100}
    assert all(seen[k] * 2 <= limits[k] for k in seen)


# -- the legacy repr echoes -------------------------------------------------------------------------------------

# Generated by running origin/main's schema.py in a throwaway copy: (sha256 of the message, its length).
ECHO_PINS = {
    "owner": ("735aaa17c53e2c2e36a8f384c328020176d06850bb2fdffba7b99e98182c7a98", 60),
    "pair": ("0f0eaab6f578ae8954d20f4bb7728c0320d15626df4f0fa6045b9aaed6459bac", 70),
    "field_twice": ("7c3d52508108f34c1d22b0294b77982ab16bba614a6c1ccd3916c06436998fe5", 57),
    "option_twice": ("aa815326171689f4c28dbb440c74873e411912758e1c2517c17d6823f449452c", 81),
    "view_twice": ("41ef88830754785720efe519f2d2d2e9735090b7197baa7b2ee1a53857aff238", 56),
    "not_an_option": ("487fa44cc10d8c4c50496b3d2e8f515f7efb27fc28bebd03ef5d72eaf7e38d37", 121),
    "no_such_field": ("e9bcb0f542e140bf439d1e62652023244dd8944abb403f057b4a5121cf33b158", 84),
    "not_single_select": ("5b7f3f37e5dbd2b1ce951d7348472da459ddd78084d6583260faa3d725019ac4", 87),
    "done_date": ("55e47a60e1852efad70d65575bb999f852b664693a3857c6656838913871b1c1", 74),
    "agents_field": ("0f5a2f7bb99bc9a43efe5f21bbb2118954e429f4522041c4a0489c5d7e658a02", 55),
    "agents_working": ("5e6bd775f76ddff1fdaf4e0589ae840466a68893549c186bdd91604cf8316913", 66),
    "duplicate_key": ("c23b3ffb2530162f174a26e88a1a5d2f14d13eae5e080a9f3d4634f27063c856", 48),
}


@pytest.mark.parametrize("name", sorted(echo.CASES))
def test_a_normal_sized_legacy_echo_keeps_main_s_bytes(name: str) -> None:
    d = base()
    echo.CASES[name](d)
    with pytest.raises(ConfigError) as err:
        parse_board(d)
    message = str(err.value)
    assert (hashlib.sha256(message.encode()).hexdigest(), len(message)) == ECHO_PINS[name]


def test_a_duplicate_yaml_key_keeps_main_s_bytes() -> None:
    with pytest.raises(ConfigError) as err:
        schema._safe_load(echo.DUPLICATE_KEY_TEXT)
    message = str(err.value)
    assert (hashlib.sha256(message.encode()).hexdigest(), len(message)) == ECHO_PINS["duplicate_key"]


def owner_error(owner: str) -> str:
    d = base()
    d["project"]["owner"] = owner
    with pytest.raises(ConfigError) as err:
        parse_board(d)
    return str(err.value)


def test_a_one_mebibyte_legacy_echo_is_bounded() -> None:
    value = "x y" + "z" * (1 << 20)
    message = owner_error(value)
    assert message == "board.yaml: project.owner: " + repr(value)[:200] + "... is not a GitHub login"
    assert len(message) < 300


def test_the_echo_bound_is_200_characters_of_repr() -> None:
    inside = "a b" + "c" * 195  # repr is exactly 200 characters: unchanged
    assert len(repr(inside)) == 200
    assert owner_error(inside) == f"board.yaml: project.owner: {inside!r} is not a GitHub login"
    over = inside + "c"  # repr is 201: cut to 200, then "..."
    assert owner_error(over) == f"board.yaml: project.owner: {repr(over)[:200]}... is not a GitHub login"


def test_a_huge_duplicate_yaml_key_is_bounded() -> None:
    key = "k" * 400_000
    text = f"{key}: 1\n{key}: 2\n"
    with pytest.raises(ConfigError) as err:
        schema._safe_load(text)
    assert len(str(err.value)) < 300


def test_a_huge_legacy_choice_value_is_bounded() -> None:
    d = copy.deepcopy(base())
    d["project"]["owner_type"] = "u" * (1 << 20)
    with pytest.raises(ConfigError) as err:
        parse_board(d)
    assert len(str(err.value)) < 300


# -- the stated ceilings are true totals ------------------------------------------------------------------------


def test_show_never_exceeds_120_characters_in_total() -> None:
    emoji = "\U0001f600" * 40
    for value in (emoji, "a" * 500, "ü" * 40, "\x00" * 40, "ab"):
        assert len(schema.show(value)) <= 120
    assert len(schema.show(emoji)) == 120
    assert schema.show("ab") == "'ab'"


def test_a_listing_never_exceeds_400_characters_in_total() -> None:
    names = ["\U00010400" * 30 + str(i) for i in range(12)]
    text = schema.options_text(names)
    assert len(text) == 400 and text.endswith("...")
    assert len(schema.options_text(["a", "b"])) == 4
