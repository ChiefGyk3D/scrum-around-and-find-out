# SPDX-License-Identifier: Apache-2.0
"""Board edits that make a legacy (pre-process) error echo a value with repr().

Shared by the test and the pin generator.

The expected bytes are pinned in test_schema_caps.py from origin/main's schema.py, run in a throwaway copy.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

Edit = Callable[[dict[str, Any]], None]


def _owner(d: dict[str, Any]) -> None:
    d["project"]["owner"] = "two words"


def _pair(d: dict[str, Any]) -> None:
    d["repositories"][0]["name"] = "bad name"


def _field_twice(d: dict[str, Any]) -> None:
    d["fields"].append({"name": "Area", "type": "text"})


def _option_twice(d: dict[str, Any]) -> None:
    d["fields"][0]["options"].append({"name": "Done"})


def _view_twice(d: dict[str, Any]) -> None:
    d["views"].append({"name": "Board", "layout": "table"})


def _not_an_option(d: dict[str, Any]) -> None:
    d["rules"]["status"] = {"opened": "Nope"}


def _no_such_field(d: dict[str, Any]) -> None:
    d["rules"]["new_item_defaults"] = {"Nope": "x"}


def _not_single_select(d: dict[str, Any]) -> None:
    d["rules"]["new_item_defaults"] = {"Done on": "x"}


def _done_date(d: dict[str, Any]) -> None:
    d["rules"]["done_date_field"] = "Status"


def _agents_field(d: dict[str, Any]) -> None:
    d["agents"] = {"field": "Nope"}


def _agents_working(d: dict[str, Any]) -> None:
    d["agents"] = {"working": ["Nope"]}


CASES: dict[str, Edit] = {
    "owner": _owner,
    "pair": _pair,
    "field_twice": _field_twice,
    "option_twice": _option_twice,
    "view_twice": _view_twice,
    "not_an_option": _not_an_option,
    "no_such_field": _no_such_field,
    "not_single_select": _not_single_select,
    "done_date": _done_date,
    "agents_field": _agents_field,
    "agents_working": _agents_working,
}
DUPLICATE_KEY_TEXT = "version: 1\nproject: {owner: a, owner_type: user, title: t}\nrepositories: []\nrepositories: []\n"
