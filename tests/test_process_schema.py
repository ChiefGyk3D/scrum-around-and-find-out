# SPDX-License-Identifier: Apache-2.0
"""process.method, the phase field, gates and approvers in board.yaml (spec 2026-10-26-process-profiles.md, 2.2-2.5).

Every refusal is a ConfigError naming the key path, raised before any request; a valid agile board is unchanged.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

import test_golden_process_agile as golden
from cliutil import run_cli
from fakegh import FakeGitHub
from safo.errors import ConfigError
from safo.schema import Process, load_board, parse_board
from world import DATA

PHASES = ["Requirements", "Design", "Build", "Verify", "Release"]


def base() -> dict[str, Any]:
    loaded = yaml.safe_load((DATA / "board.yaml").read_text())
    assert isinstance(loaded, dict)
    return copy.deepcopy(loaded)


def waterfall() -> dict[str, Any]:
    d = base()
    d["fields"].append({"name": "Phase", "type": "single_select", "options": [{"name": p} for p in PHASES]})
    d["rules"]["add_closed_days"] = 30
    d["process"] = {
        "method": "waterfall",
        "active_statuses": ["In progress"],
        "phase_field": "Phase",
        "approvers": [{"login": "maintainer-login", "id": 1234567}],
        "gates": [
            {"phase": "Requirements", "issue": "acme/widgets#1"},
            {"phase": "Design", "issue": "acme/widgets#2"},
        ],
    }
    return d


def gates(*pairs: tuple[str, str]) -> list[dict[str, str]]:
    return [{"phase": p, "issue": i} for p, i in pairs]


def refuses(d: dict[str, Any], message: str, **kw: Any) -> None:
    with pytest.raises(ConfigError) as err:
        parse_board(d, **kw)
    assert str(err.value) == f"board.yaml: {message}"


# -- compatibility -----------------------------------------------------------


def test_absent_process_and_explicit_agile_parse_to_the_default() -> None:
    assert parse_board(base()).process == Process()
    d = base()
    d["process"] = {"method": "agile"}
    assert parse_board(d).process == Process()
    d["process"] = {}
    assert parse_board(d).process == Process()
    assert Process().method == "agile" and Process().dependencies == "none"


@pytest.mark.parametrize(("board", "mode"), golden.CASES, ids=[golden.golden_name(b, m) for b, m in golden.CASES])
def test_explicit_agile_prints_the_golden_bytes(
    board: str, mode: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = golden.board_copy

    def with_process(name: str, folder: Path) -> Path:
        path = original(name, folder)
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        data["process"] = {"method": "agile"}
        path.write_text(yaml.safe_dump(data), encoding="utf-8")
        return path

    monkeypatch.setattr(golden, "board_copy", with_process)
    golden.compare(golden.GOLDEN / golden.golden_name(board, mode), golden.fresh(board, mode, golden.FROZEN, tmp_path))


def test_unknown_key_text_lists_process_and_method() -> None:
    d = base()
    d["bogus"] = 1
    with pytest.raises(ConfigError, match=r"bogus: unknown key \(allowed: .*\bprocess\b"):
        parse_board(d)
    d = base()
    d["repositories"][0]["bogus"] = 1
    with pytest.raises(ConfigError, match=r"repositories\[0\]\.bogus: unknown key \(allowed: .*\bmethod\b"):
        parse_board(d)
    d = base()
    d["process"] = {"baseline": {}}
    with pytest.raises(ConfigError, match=r"process\.baseline: unknown key \(allowed: "):
        parse_board(d)


def test_a_complete_waterfall_board_loads() -> None:
    p = parse_board(waterfall()).process
    assert p.method == "waterfall" and p.phase_field == "Phase" and p.active_statuses == ("In progress",)
    assert [(a.login, a.id) for a in p.approvers] == [("maintainer-login", 1234567)]
    assert [(g.phase, g.issue) for g in p.gates] == [("Requirements", "acme/widgets#1"), ("Design", "acme/widgets#2")]


def test_a_waterfall_repository_alone_turns_the_waterfall_keys_on() -> None:
    d = waterfall()
    d["process"]["method"] = "agile"
    d["repositories"][1]["method"] = "waterfall"
    b = parse_board(d)
    assert b.process.method == "agile" and b.repositories[1].method == "waterfall" and b.repositories[0].method is None


# -- method and dependencies ---------------------------------------------------


def test_method_choice_messages() -> None:
    d = base()
    d["process"] = {"method": "kanban"}
    refuses(d, "process.method: 'kanban' is not one of agile, waterfall")
    d["process"] = {"method": "./mine.yaml"}
    refuses(d, "process.method: './mine.yaml' is not one of agile, waterfall")
    d["process"] = {"method": None}
    refuses(d, "process.method: None is not one of agile, waterfall")
    d = base()
    d["repositories"][1]["method"] = "hybrid"
    refuses(d, "repositories[1].method: 'hybrid' is not one of agile, waterfall")
    d["repositories"][1]["method"] = None
    refuses(d, "repositories[1].method: None is not one of agile, waterfall")


def test_dependencies() -> None:
    d = base()
    d["process"] = {"dependencies": "blocked_by"}
    assert parse_board(d).process.dependencies == "blocked_by"
    d["process"] = {"dependencies": False}  # YAML reads off as false
    refuses(d, "process.dependencies: False is not one of none, blocked_by")
    d["process"] = {"dependencies": None}
    refuses(d, "process.dependencies: None is not one of none, blocked_by")


def test_a_foreign_value_is_named_by_type_and_a_long_string_is_cut() -> None:
    d = base()
    d["process"] = {"method": {"x": "y" * 500}}
    refuses(d, "process.method: a dict is not one of agile, waterfall")
    d["process"] = {"method": "a" * 500 + "\x1b[31m"}
    with pytest.raises(ConfigError) as err:
        parse_board(d)
    assert len(str(err.value)) < 200 and "\x1b" not in str(err.value)


def test_process_must_be_a_mapping() -> None:
    for bad, name in (([], "list"), (None, "NoneType"), ("agile", "str")):
        d = base()
        d["process"] = bad
        refuses(d, f"process: expected a mapping, got {name}")


def test_an_unknown_key_with_control_characters_is_escaped() -> None:
    d = base()
    d["process"] = {"x\x1b[31m": 1}
    with pytest.raises(ConfigError) as err:
        parse_board(d)
    assert "\x1b" not in str(err.value) and "unknown key" in str(err.value)


# -- waterfall requirements -----------------------------------------------------


def test_waterfall_keys_on_an_all_agile_board_are_refused() -> None:
    for key, value in (
        ("gates", []),
        ("active_statuses", ["In progress"]),
        ("phase_field", "Phase"),
        ("approvers", []),
    ):
        d = waterfall()
        d["process"] = {"method": "agile", key: value}
        refuses(d, f"process.{key}: only used when the method or a repository is waterfall")
    d = waterfall()
    del d["process"]["method"]  # the default is agile
    refuses(d, "process.active_statuses: only used when the method or a repository is waterfall")


@pytest.mark.parametrize(
    ("key", "message"),
    [
        ("phase_field", "process.phase_field: required when a repository is waterfall"),
        ("active_statuses", "process.active_statuses: required when a repository is waterfall"),
        ("approvers", "process.approvers: required (at least one) when the method or a repository is waterfall"),
    ],
)
def test_waterfall_requires_each_key(key: str, message: str) -> None:
    d = waterfall()
    del d["process"][key]
    refuses(d, message)
    if key != "phase_field":
        d["process"][key] = []
        refuses(d, message)


def test_a_waterfall_repository_requires_them_too() -> None:
    d = waterfall()
    d["process"] = {"method": "agile"}
    d["repositories"][0]["method"] = "waterfall"
    refuses(d, "process.phase_field: required when a repository is waterfall")


def test_phase_field_must_be_a_single_select_in_fields() -> None:
    d = waterfall()
    d["process"]["phase_field"] = "Missing"
    refuses(d, "process.phase_field: names field 'Missing', which is not in fields")
    d["process"]["phase_field"] = "Done on"
    refuses(d, "process.phase_field: field 'Done on' is date, not single_select")
    d["process"]["phase_field"] = "Status"
    refuses(d, "process.phase_field: 'Status' is the status field, not a phase field")
    d["process"]["phase_field"] = "Area"
    refuses(d, "process.phase_field: 'Area' is the area field, not a phase field")
    for bad in (None, 7):
        d["process"]["phase_field"] = bad
        refuses(d, "process.phase_field: expected a non-empty string")


def test_active_statuses() -> None:
    d = waterfall()
    d["process"]["active_statuses"] = ["In progress", "Doing"]
    refuses(d, "process.active_statuses[1]: 'Doing' is not an option of 'Status'")
    d["process"]["active_statuses"] = ["In progress", "Done"]
    refuses(d, "process.active_statuses[1]: 'Done' is a done status (rules.status.closed or merged)")
    d["process"]["active_statuses"] = ["In progress", "In progress"]
    refuses(d, "process.active_statuses[1]: 'In progress' is listed twice")
    d["process"]["active_statuses"] = ["In progress", 3]
    refuses(d, "process.active_statuses[1]: expected a non-empty string")
    d["process"]["active_statuses"] = "In progress"
    refuses(d, "process.active_statuses: expected a list, got str")
    d["process"]["active_statuses"] = None
    refuses(d, "process.active_statuses: expected a list, got NoneType")
    d = waterfall()
    d["rules"]["status"] = {"merged": "Blocked"}
    d["process"]["active_statuses"] = ["Blocked"]
    refuses(d, "process.active_statuses[0]: 'Blocked' is a done status (rules.status.closed or merged)")


def test_add_closed_days_must_be_at_least_one() -> None:
    d = waterfall()
    d["rules"]["add_closed_days"] = 0
    message = (
        "rules.add_closed_days: must be at least 1 when a repository is waterfall"
        " (the gate rule reads recently closed cards)"
    )
    refuses(d, message)
    del d["rules"]["add_closed_days"]
    refuses(d, message)
    d["rules"]["add_closed_days"] = 1
    parse_board(d)


# -- approvers ----------------------------------------------------------------------


def test_approver_messages() -> None:
    d = waterfall()
    for bad in ("someone", {"login": "a"}, {"login": "a", "id": 1, "extra": 1}, {"id": 1}, None, ["a", 1]):
        d["process"]["approvers"] = [bad]
        refuses(d, "process.approvers[0]: expected {login, id}")
    d["process"]["approvers"] = [{"login": "two words", "id": 1}]
    refuses(d, "process.approvers[0].login: 'two words' is not a GitHub login")
    d["process"]["approvers"] = [{"login": 5, "id": 1}]
    refuses(d, "process.approvers[0].login: expected a non-empty string")
    for bad_id in (0, -1, True, "7", 1.5, None, 2**63):
        d["process"]["approvers"] = [{"login": "ok", "id": bad_id}]
        refuses(d, "process.approvers[0].id: expected a positive integer (the user's databaseId)")
    d["process"]["approvers"] = [{"login": "ok", "id": 1}, {"login": "OK", "id": 2}]
    refuses(d, "process.approvers[1].login: 'OK' is listed twice")
    d["process"]["approvers"] = [{"login": "ok", "id": 1}, {"login": "other", "id": 1}]
    refuses(d, "process.approvers[1].id: 1 is listed twice")
    d["process"]["approvers"] = {"login": "ok", "id": 1}
    refuses(d, "process.approvers: expected a list, got dict")


# -- gates ---------------------------------------------------------------------------


def test_gate_messages() -> None:
    d = waterfall()
    d["process"]["gates"] = gates(("Requirements", "acme/widgets#1"), ("Buld", "acme/widgets#2"))
    refuses(
        d,
        "process.gates[1].phase: 'Buld' is not an option of 'Phase'"
        " (options: Requirements, Design, Build, Verify, Release)",
    )
    d["process"]["gates"] = gates(
        ("Requirements", "acme/widgets#1"), ("Design", "acme/widgets#2"), ("Design", "acme/widgets#3")
    )
    refuses(d, "process.gates[2].phase: phase 'Design' has a gate already (gates[1])")
    d["process"]["gates"] = gates(("Requirements", "acme/widgets#1"), ("Release", "acme/widgets#2"))
    refuses(d, "process.gates[1].phase: 'Release' is the last phase, so its gate would gate nothing")
    d["process"]["gates"] = gates(("Requirements", "acme/widgets#1"), ("Design", "acme/widgets#1"))
    refuses(d, "process.gates[1].issue: acme/widgets#1 is a gate already (gates[0])")


@pytest.mark.parametrize(
    "ref", ["acme/widgets", "acme/widgets#0", "acme/widgets#01", "acme/widgets#1 ", "x#1", "acme/widgets#1\n", "#1"]
)
def test_a_bad_gate_reference(ref: str) -> None:
    d = waterfall()
    d["process"]["gates"] = gates(("Requirements", ref))
    refuses(d, "process.gates[0].issue: expected owner/repo#N")


def test_a_gate_reference_outside_repositories_is_refused_offline() -> None:
    d = waterfall()
    d["process"]["gates"] = gates(("Requirements", "acme/widgets#1"), ("Design", "acme/elsewhere#2"))
    refuses(d, "process.gates[1].issue: acme/elsewhere is not in repositories")
    refuses(d, "process.gates[1].issue: acme/elsewhere is not in repositories", check_fields=False)
    d["process"]["gates"] = gates(("Requirements", "ACME/Widgets#1"))  # repositories compare case-insensitively
    parse_board(d)


def test_gate_entry_shapes() -> None:
    d = waterfall()
    d["process"]["gates"] = ["x"]
    refuses(d, "process.gates[0]: expected a mapping, got str")
    d["process"]["gates"] = [{"phase": "Design"}]
    refuses(d, "process.gates[0].issue: required")
    d["process"]["gates"] = [{"issue": "acme/widgets#1"}]
    refuses(d, "process.gates[0].phase: required")
    d["process"]["gates"] = [{"phase": "Design", "issue": "acme/widgets#1", "x": 1}]
    refuses(d, "process.gates[0].x: unknown key (allowed: issue, phase)")
    d["process"]["gates"] = [{"phase": None, "issue": "acme/widgets#1"}]
    refuses(d, "process.gates[0].phase: expected a non-empty string")
    d["process"]["gates"] = [{"phase": "Design", "issue": 5}]
    refuses(d, "process.gates[0].issue: expected a non-empty string")
    d["process"]["gates"] = None
    refuses(d, "process.gates: expected a list, got NoneType")


def test_gates_may_be_left_out_or_empty() -> None:
    d = waterfall()
    d["process"]["gates"] = []
    assert parse_board(d).process.gates == ()
    del d["process"]["gates"]
    assert parse_board(d).process.gates == ()


def test_field_checks_are_skipped_without_check_fields_but_structure_is_not() -> None:
    d = waterfall()
    d["fields"] = [f for f in d["fields"] if f["name"] != "Phase"]
    refuses(d, "process.phase_field: names field 'Phase', which is not in fields")
    parse_board(d, check_fields=False)
    d["process"]["gates"] = gates(("A", "acme/widgets#1"), ("A", "acme/widgets#2"))
    refuses(d, "process.gates[1].phase: phase 'A' has a gate already (gates[0])", check_fields=False)


# -- caps ------------------------------------------------------------------------------


def with_phases(n: int) -> dict[str, Any]:
    d = waterfall()
    for f in d["fields"]:
        if f["name"] == "Phase":
            f["options"] = [{"name": f"P{i}"} for i in range(n)]
    d["process"]["gates"] = gates(("P0", "acme/widgets#1"))
    return d


def test_phase_cap() -> None:
    parse_board(with_phases(16))
    refuses(with_phases(17), "process.phase_field: field 'Phase' has 17 options, at most 16 phases")


def test_approver_cap() -> None:
    d = waterfall()
    d["process"]["approvers"] = [{"login": f"user{i}", "id": i + 1} for i in range(32)]
    parse_board(d)
    d["process"]["approvers"].append({"login": "user32", "id": 33})
    refuses(d, "process.approvers: at most 32 entries")


def test_active_status_cap() -> None:
    d = waterfall()
    for f in d["fields"]:
        if f["name"] == "Status":
            f["options"] += [{"name": f"S{i}"} for i in range(17)]
    d["process"]["active_statuses"] = [f"S{i}" for i in range(16)]
    parse_board(d)
    d["process"]["active_statuses"].append("S16")
    refuses(d, "process.active_statuses: at most 16 entries")


def test_gate_cap() -> None:
    # distinct phases give at most 15 usable gates (16 minus the last), so 32 exist only without the field checks
    d = waterfall()
    d["process"]["gates"] = gates(*[(f"P{i}", f"acme/widgets#{i + 1}") for i in range(32)])
    parse_board(d, check_fields=False)
    d["process"]["gates"] += gates(("P32", "acme/widgets#33"))
    refuses(d, "process.gates: at most 32 entries", check_fields=False)
    refuses(d, "process.gates: at most 32 entries")  # the cap is read before the entries


# -- hostile YAML and the fake GitHub sees nothing -------------------------------------------

BOARD_TEXT = (DATA / "board.yaml").read_text(encoding="utf-8")


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "board.yaml"
    p.write_text(text, encoding="utf-8")
    return p


@pytest.mark.parametrize(
    ("block", "message"),
    [
        ("process: &p\n  method: agile\n", r"anchors are not allowed"),
        ("process:\n  method: *p\n", r"(aliases are not allowed|not valid YAML)"),
        ("process:\n  <<: {method: agile}\n", r"(merge keys \(<<\) are not allowed|not valid YAML)"),
        ("process:\n  method: agile\n  method: waterfall\n", r"duplicate key 'method'"),
        ("process:\n  gates: " + "[" * 100 + "]" * 100 + "\n", r"nesting exceeds"),
        ("process:\n  method: ./mine.yaml\n", r"process.method: './mine.yaml' is not one of agile, waterfall"),
    ],
)
def test_hostile_yaml_in_process_is_refused(tmp_path: Path, block: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        load_board(write(tmp_path, BOARD_TEXT + block))


def test_oversize_process_is_refused(tmp_path: Path) -> None:
    text = BOARD_TEXT + "process:\n  approvers:\n" + "    - {login: a, id: 1}\n" * 60000
    with pytest.raises(ConfigError, match="exceeds maximum size"):
        load_board(write(tmp_path, text))


@pytest.mark.parametrize("mode", ["audit", "reconcile", "status"])
def test_a_bad_process_block_exits_2_and_sends_no_request(fake: FakeGitHub, tmp_path: Path, mode: str) -> None:
    d = waterfall()
    d["process"]["gates"] = gates(("Requirements", "acme/elsewhere#1"))
    path = write(tmp_path, yaml.safe_dump(d))
    code, _, err = run_cli("--board", str(path), mode, env={"GITHUB_GRAPHQL_URL": fake.url, "SAFO_TOKEN": fake.token})
    assert code == 2 and "process.gates[0].issue: acme/elsewhere is not in repositories" in err
    assert fake.requests == []


def _unknown_phase(p: dict[str, Any]) -> None:
    p["gates"] = gates(("Buld", "acme/widgets#1"))


def _two_gates(p: dict[str, Any]) -> None:
    p["gates"] = gates(("Design", "acme/widgets#1"), ("Design", "acme/widgets#2"))


def _last_phase(p: dict[str, Any]) -> None:
    p["gates"] = gates(("Release", "acme/widgets#1"))


def _bad_ref(p: dict[str, Any]) -> None:
    p["gates"] = gates(("Design", "not a ref"))


@pytest.mark.parametrize("mutate", [_unknown_phase, _two_gates, _last_phase, _bad_ref])
def test_each_gate_error_exits_2_and_sends_no_request(
    fake: FakeGitHub, tmp_path: Path, mutate: Callable[[dict[str, Any]], None]
) -> None:
    d = waterfall()
    mutate(d["process"])
    path = write(tmp_path, yaml.safe_dump(d))
    env = {"GITHUB_GRAPHQL_URL": fake.url, "SAFO_TOKEN": fake.token}
    code, _, err = run_cli("--board", str(path), "audit", env=env)
    assert code == 2 and "process.gates[" in err
    assert fake.requests == []


def test_a_huge_gate_reference_is_refused_without_echoing_it() -> None:
    d = waterfall()
    d["process"]["gates"] = gates(("Requirements", "a" * 200_000 + "/b#1"))
    refuses(d, "process.gates[0].issue: expected owner/repo#N")
