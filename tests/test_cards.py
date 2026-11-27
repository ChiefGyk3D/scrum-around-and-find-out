# SPDX-License-Identifier: Apache-2.0
"""safo-cards (#591): Kind, Epic and Effort from a table, REST only. A stateful fake API stands behind every call.

Nothing here reaches GitHub or the real board: HOME is a temporary directory and the transport is a fake.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest

from safo import boardmap as bm
from safo import cards

PROJECT = "users/ChiefGyk3D/projectsV2/3"
BOARD = """\
version: 1
project: {owner: ChiefGyk3D, owner_type: user, number: 3, title: T}
repositories:
  - {owner: ChiefGyk3D, name: widgets, default_area: Core}
  - {owner: ChiefGyk3D, name: gadgets}
fields:
  - {name: Kind, type: single_select, options: [{name: Story}, {name: Bug}]}
  - {name: Effort, type: single_select, options: [{name: S}, {name: M}]}
  - {name: Area, type: single_select, options: [{name: Core}, {name: Docs}]}
  - {name: Priority, type: single_select, options: [{name: P1 soon}, {name: P2 later}]}
  - {name: Epic, type: text}
rules:
  new_item_defaults: {Priority: P2 later}
"""
FIELDS: list[dict[str, Any]] = [
    {"id": 11, "name": "Kind", "options": [{"id": "aaaaaaa1", "name": "Story"}, {"id": "aaaaaaa2", "name": "Bug"}]},
    {"id": 12, "name": "Effort", "options": [{"id": "bbbbbbb1", "name": "S"}, {"id": "bbbbbbb2", "name": "M"}]},
    {"id": 13, "name": "Area", "options": [{"id": "ccccccc1", "name": "Core"}, {"id": "ccccccc2", "name": "Docs"}]},
    {
        "id": 14,
        "name": "Priority",
        "options": [{"id": "ddddddd1", "name": "P1 soon"}, {"id": "ddddddd2", "name": "P2 later"}],
    },
    {"id": 15, "name": "Epic"},
]
BY_ID: dict[int, dict[str, Any]] = {f["id"]: f for f in FIELDS}


class FakeApi:
    """The REST layer: field list, issue read, item lookup, item read, item PATCH and item POST."""

    def __init__(
        self, on_board: dict[int, int] | None = None, lose_patch: bool = False, drop_patch: bool = False
    ) -> None:
        self.calls: list[tuple[str, str, str | None]] = []
        self.items: dict[int, dict[int, Any]] = {}  # item id -> {field id: stored value}
        self.numbers: dict[int, int] = {}  # issue number -> item id
        for number, item_id in (on_board or {}).items():
            self.items[item_id] = {}
            self.numbers[number] = item_id
        self.lose_patch, self.drop_patch = lose_patch, drop_patch
        self.next_id = 900

    def __call__(self, method: str, path: str, body: str | None) -> bm.Reply:
        self.calls.append((method, path, body))
        url = urlparse(path)
        query = parse_qs(url.query)
        if method == "GET" and path.startswith(f"{PROJECT}/fields"):
            return self.ok(FIELDS)
        if method == "GET" and "/issues/" in path:
            return self.ok({"title": f"issue {path.rsplit('/', 1)[1]}"})
        if method == "GET" and url.path == f"{PROJECT}/items" and "q" in query:
            number = int(query["q"][0].split()[-1])
            found = self.numbers.get(number)
            repo = "https://api.github.com/repos/ChiefGyk3D/widgets"
            return self.ok([{"id": found, "content": {"number": number, "repository_url": repo}}] if found else [])
        if method == "GET":
            item_id = int(url.path.rsplit("/", 1)[1])
            wanted = [int(x) for x in query["fields"][0].split(",")]
            stored = self.items[item_id]
            return self.ok({"id": item_id, "fields": [self.show(i, stored.get(i)) for i in wanted]})
        if method == "PATCH":
            if self.lose_patch:
                raise TimeoutError("lost")
            item_id = int(url.path.rsplit("/", 1)[1])
            for entry in json.loads(body or "{}")["fields"]:
                if not self.drop_patch:
                    self.items[item_id][entry["id"]] = entry["value"]
            return self.ok({})
        if method == "POST":
            payload = json.loads(body or "{}")
            self.next_id += 1
            self.items[self.next_id] = {}
            self.numbers[payload["number"]] = self.next_id
            return self.ok({"id": self.next_id})
        raise AssertionError(path)

    @staticmethod
    def ok(data: Any) -> bm.Reply:
        return bm.Reply(True, json.dumps(data).encode())

    @staticmethod
    def show(field_id: int, value: Any) -> dict[str, Any]:
        spec = BY_ID[field_id]
        if value is None:
            return {"id": field_id, "name": spec["name"], "value": None}
        if "options" in spec:
            name = next(o["name"] for o in spec["options"] if o["id"] == value)
            return {"id": field_id, "name": spec["name"], "value": {"id": value, "name": {"raw": name}}}
        return {"id": field_id, "name": spec["name"], "value": {"raw": value}}

    def writes(self) -> list[tuple[str, str, str | None]]:
        return [c for c in self.calls if c[0] != "GET"]

    def stored(self, item_id: int, name: str) -> Any:
        field = next(f for f in FIELDS if f["name"] == name)
        return self.show(int(field["id"]), self.items[item_id].get(int(field["id"])))["value"]


def row(issue: int, **over: Any) -> dict[str, Any]:
    return {"repo": "ChiefGyk3D/widgets", "issue": issue, "kind": "Story", "epic": "Epic 518", "effort": "M", **over}


def run(
    tmp_path: Path, api: FakeApi, cards_: list[dict[str, Any]], *extra: str, mode: str = "apply"
) -> tuple[int, str, str]:
    (tmp_path / "board.yaml").write_text(BOARD)
    (tmp_path / "table.json").write_text(json.dumps({"cards": cards_}))
    out, err = io.StringIO(), io.StringIO()
    argv = [mode, str(tmp_path / "table.json"), "--board", str(tmp_path / "board.yaml"), *extra]
    code = cards.main(argv, env={"HOME": str(tmp_path), "PATH": ""}, out=out, err=err, transport=api)
    return code, out.getvalue(), err.getvalue()


def test_apply_sets_all_five_fields_in_one_patch_and_reads_back(tmp_path: Path) -> None:
    api = FakeApi({7: 101})
    code, out, err = run(tmp_path, api, [row(7)])
    assert code == 0, err
    patches = [c for c in api.writes() if c[0] == "PATCH"]
    assert len(patches) == 1 and patches[0][1] == f"{PROJECT}/items/101"
    assert api.stored(101, "Kind") == {"id": "aaaaaaa1", "name": {"raw": "Story"}}
    assert api.stored(101, "Epic") == {"raw": "Epic 518"}
    assert api.stored(101, "Area")["name"]["raw"] == "Core"  # the repository's default
    assert api.stored(101, "Priority")["name"]["raw"] == "P2 later"  # the board's new item default
    assert "(read back)" in out
    # the read-back is a GET with a comma-separated fields= list, after the PATCH
    last = api.calls[-1]
    assert last[0] == "GET" and "fields=" in last[1] and "," in last[1] and "[]" not in last[1]


def test_a_card_not_on_the_board_is_added_with_one_post_then_set(tmp_path: Path) -> None:
    api = FakeApi()
    code, out, err = run(tmp_path, api, [row(8)])
    assert code == 0, err
    posts = [c for c in api.writes() if c[0] == "POST"]
    assert len(posts) == 1 and posts[0][1] == f"{PROJECT}/items"
    assert json.loads(posts[0][2] or "")["number"] == 8
    assert "ADDED" in out and api.stored(api.numbers[8], "Effort")["name"]["raw"] == "M"


def test_plan_reads_but_never_writes(tmp_path: Path) -> None:
    api = FakeApi({7: 101})
    code, out, _ = run(tmp_path, api, [row(7), row(8)], mode="plan")
    assert code == 0 and api.writes() == []
    assert "WOULD SET" in out and "WOULD ADD" in out


def test_a_second_run_changes_nothing(tmp_path: Path) -> None:
    api = FakeApi({7: 101})
    assert run(tmp_path, api, [row(7)])[0] == 0
    before = len(api.writes())
    code, out, _ = run(tmp_path, api, [row(7)])
    assert code == 0 and len(api.writes()) == before and "nothing to change" in out


def test_defaults_never_overwrite_a_value_already_on_the_card(tmp_path: Path) -> None:
    api = FakeApi({7: 101})
    api.items[101] = {13: "ccccccc2", 14: "ddddddd1"}  # Area Docs, Priority P1 soon
    assert run(tmp_path, api, [row(7)])[0] == 0
    assert api.stored(101, "Area")["name"]["raw"] == "Docs" and api.stored(101, "Priority")["name"]["raw"] == "P1 soon"


def test_a_table_value_beats_what_is_on_the_card(tmp_path: Path) -> None:
    api = FakeApi({7: 101})
    api.items[101] = {11: "aaaaaaa2", 14: "ddddddd1"}  # Kind Bug, Priority P1 soon
    assert run(tmp_path, api, [row(7, priority="P2 later")])[0] == 0
    assert (
        api.stored(101, "Kind")["name"]["raw"] == "Story" and api.stored(101, "Priority")["name"]["raw"] == "P2 later"
    )


@pytest.mark.parametrize(
    "bad",
    [
        {"kind": "Epic"},  # not a Kind of this board
        {"effort": "XL"},
        {"area": "Nowhere"},
        {"priority": "P9"},
        {"repo": "ChiefGyk3D/elsewhere"},
        {"epic": "line\nbreak"},
        {"issue": 0},
        {"issue": True},
        {"extra": 1},
    ],
)
def test_an_unknown_value_refuses_the_whole_table_before_any_call(tmp_path: Path, bad: dict[str, Any]) -> None:
    api = FakeApi({7: 101})
    code, _, err = run(tmp_path, api, [row(7), {**row(9), **bad}])
    assert code != 0 and "card 2" in err and api.calls == []


def test_a_duplicate_card_and_a_missing_key_are_refused(tmp_path: Path) -> None:
    assert run(tmp_path, FakeApi(), [row(7), row(7)])[0] != 0
    short = row(7)
    del short["effort"]
    assert run(tmp_path, FakeApi(), [short])[0] != 0


def test_a_duplicate_json_key_and_a_symlinked_table_are_refused(tmp_path: Path) -> None:
    (tmp_path / "board.yaml").write_text(BOARD)
    real = tmp_path / "real.json"
    real.write_text('{"cards": [], "cards": []}')
    link = tmp_path / "link.json"
    link.symlink_to(real)
    for name in ("real.json", "link.json"):
        err = io.StringIO()
        argv = ["plan", str(tmp_path / name), "--board", str(tmp_path / "board.yaml")]
        assert (
            cards.main(argv, env={"HOME": str(tmp_path), "PATH": ""}, out=io.StringIO(), err=err, transport=FakeApi())
            != 0
        )


def test_a_write_that_does_not_read_back_stops_the_run(tmp_path: Path) -> None:
    api = FakeApi({7: 101, 8: 102}, drop_patch=True)
    code, _, err = run(tmp_path, api, [row(7), row(8)])
    assert code != 0 and "read-back" in err
    assert len([c for c in api.writes() if c[0] == "PATCH"]) == 1  # the second card was never touched


def test_a_lost_patch_reply_is_not_replayed(tmp_path: Path) -> None:
    api = FakeApi({7: 101}, lose_patch=True)
    code, _, err = run(tmp_path, api, [row(7)])
    assert code != 0 and "may or may not" in err
    assert len([c for c in api.writes() if c[0] == "PATCH"]) == 1


def test_the_write_cap_stops_cleanly_and_a_rerun_finishes(tmp_path: Path) -> None:
    api = FakeApi({7: 101, 8: 102})
    code, out, _ = run(tmp_path, api, [row(7), row(8)], "--max-writes", "1")
    assert code == 0 and "write cap" in out and api.items[102] == {}
    assert run(tmp_path, api, [row(7), row(8)])[0] == 0 and api.items[102]


def test_nothing_ever_lists_the_board_or_uses_graphql(tmp_path: Path) -> None:
    api = FakeApi({7: 101})
    run(tmp_path, api, [row(7), row(8)])
    for method, path, _ in api.calls:
        assert "graphql" not in path
        assert method != "GET" or path.startswith(
            ("repos/", f"{PROJECT}/fields", f"{PROJECT}/items/", f"{PROJECT}/items?q=")
        )
        assert path != f"{PROJECT}/items" or method == "POST"


def test_the_item_id_is_remembered_so_a_rerun_does_not_look_it_up(tmp_path: Path) -> None:
    api = FakeApi({7: 101})
    run(tmp_path, api, [row(7)])
    api.calls.clear()
    run(tmp_path, api, [row(7)])
    assert not any("/issues/" in c[1] or "items?q=" in c[1] for c in api.calls)


def test_a_map_for_another_project_is_refused(tmp_path: Path) -> None:
    other = bm.default_map()
    other.project = "users/ChiefGyk3D/projectsV2/9"
    bm.save(other, bm.map_path({"HOME": str(tmp_path)}))
    code, _, err = run(tmp_path, FakeApi({7: 101}), [row(7)])
    assert code != 0 and "another project" in err


def test_output_holds_no_token_or_response_body(tmp_path: Path) -> None:
    api = FakeApi({7: 101})
    _, out, err = run(tmp_path, api, [row(7)])
    assert "ghp_" not in out + err and "{" not in out
