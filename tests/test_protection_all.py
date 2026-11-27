# SPDX-License-Identifier: Apache-2.0
"""safo protection --all: the tracked repositories' default-branch protection against the standard (#541).

A loopback server stands in for the REST API (no network). Each rule has a fixture that must name it, and a clean
repository must stay silent about it, so a rule that is removed from the check turns a test red.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pytest

from cliutil import run_cli
from test_protection import ENV, NOT_PROTECTED, REPO, Route, check, classic, good_routes, j, repo_doc, ruleset, server
from world import DATA

SECURITY_WF = (
    "name: sec\non: [pull_request]\njobs:\n  security:\n    runs-on: x\n    steps: []\n  build:\n    runs-on: x\n"
)
PUSH_ONLY_WF = "name: sec\non: [push]\njobs:\n  security:\n    runs-on: x\n    steps: []\n"


def board(tmp_path: Path, *repos: str, exempt: str = "") -> str:
    """The shared test board with its repositories replaced, and one gate exemption when asked."""
    lines = (DATA / "board.yaml").read_text().splitlines()
    start = lines.index("repositories:")
    end = lines.index("fields:")
    lines[start:end] = ["repositories:", *(f"  - {{owner: o, name: {name}}}" for name in repos)]
    text = "\n".join(lines) + "\n"
    if exempt:
        text = text.replace("rules:\n", f"rules:\n  gate_exempt_repos: [{exempt}]\n", 1)
    path = tmp_path / "board.yaml"
    path.write_text(text)
    return str(path)


def workflow(text: str, name: str = "sec.yml", repo: str = "r") -> dict[str, Route]:
    base = f"/repos/o/{repo}/contents/.github/workflows"
    body = {
        "type": "file",
        "path": f".github/workflows/{name}",
        "encoding": "base64",
        "content": base64.b64encode(text.encode()).decode(),
    }
    return {base: j([{"name": name, "path": f".github/workflows/{name}", "type": "file"}]), f"{base}/{name}": j(body)}


def renamed(routes: dict[str, Route], repo: str) -> dict[str, Route]:
    moved = {path.replace(REPO, f"/repos/o/{repo}", 1): value for path, value in routes.items()}
    moved[f"/repos/o/{repo}"] = j(repo_doc(full_name=f"o/{repo}"))
    return moved


def clean(**edit: Any) -> dict[str, Route]:
    body = classic()
    body["required_status_checks"]["checks"].append({"context": "sec / security", "app_id": 15368})
    body["required_conversation_resolution"] = {"enabled": True}
    body.update(edit)
    return {**good_routes(), **workflow(SECURITY_WF), f"{REPO}/branches/main/protection": j(body)}


def run_all(tmp_path: Path, routes: dict[str, Route], *repos: str, exempt: str = "") -> tuple[int, str, str, Any]:
    with server(routes) as (url, seen):
        code, out, err = run_cli(
            "--board",
            board(tmp_path, *(repos or ("r",)), exempt=exempt),
            "protection",
            "--all",
            "--api-url",
            url,
            env=ENV,
        )
    return code, out, err, seen


def test_a_clean_repository_exits_zero_with_a_count_and_only_gets(tmp_path: Path) -> None:
    code, out, err, seen = run_all(tmp_path, clean())
    assert (code, err) == (0, "")
    assert "OK o/r" in out and "MISSING" not in out and "DRIFT" not in out
    assert out.strip().splitlines()[-1] == "protection: 1 repositories read, 0 with drift"
    assert seen and {method for method, _ in seen} == {"GET"}
    assert "t0ken" not in out


def with_classic(edit: Any) -> dict[str, Route]:
    routes = clean()
    body = classic()
    body["required_status_checks"]["checks"].append({"context": "sec / security", "app_id": 15368})
    edit(body)
    return {**routes, f"{REPO}/branches/main/protection": j(body)}


def without_ci(body: dict[str, Any]) -> None:
    body["required_status_checks"]["checks"] = [{"context": "sec / security", "app_id": 15368}]


def without_security(body: dict[str, Any]) -> None:
    body["required_status_checks"]["checks"] = [{"context": "ci / CI green", "app_id": 15368}]


def without_pr(body: dict[str, Any]) -> None:
    del body["required_pull_request_reviews"]


def force_on(body: dict[str, Any]) -> None:
    body["allow_force_pushes"] = {"enabled": True}


def deletion_on(body: dict[str, Any]) -> None:
    body["allow_deletions"] = {"enabled": True}


RULES = [
    ("MISSING ci-green", with_classic(without_ci)),
    ("MISSING security-check security", with_classic(without_security)),
    ("MISSING pull-request", with_classic(without_pr)),
    ("DRIFT force-push", with_classic(force_on)),
    ("DRIFT deletion", with_classic(deletion_on)),
    ("MISSING protection", {**clean(), f"{REPO}/branches/main/protection": j(NOT_PROTECTED, 404)}),
]


@pytest.mark.parametrize(("item", "routes"), RULES)
def test_each_rule_names_itself_and_exits_one(tmp_path: Path, item: str, routes: dict[str, Route]) -> None:
    code, out, _, seen = run_all(tmp_path, routes)
    assert code == 1, out
    line = next(x for x in out.splitlines() if x.startswith("o/r"))
    assert item in line
    others = [i for i, _ in RULES if i != item and not i.startswith("MISSING protection")]
    if item != "MISSING protection":
        assert not any(o in line for o in others)
    assert out.strip().splitlines()[-1] == "protection: 1 repositories read, 1 with drift"
    assert {method for method, _ in seen} == {"GET"}


def test_a_security_job_that_never_runs_on_pull_requests_is_not_demanded(tmp_path: Path) -> None:
    routes = {**with_classic(without_security), **workflow(PUSH_ONLY_WF)}
    code, out, _, _ = run_all(tmp_path, routes)
    assert code == 0, out


def test_an_absent_workflow_directory_is_proved_by_a_readable_contents_root(tmp_path: Path) -> None:
    root = f"{REPO}/contents"
    routes = {**with_classic(without_security), f"{root}/.github/workflows": j(NOT_PROTECTED, 404), root: j([])}
    code, out, _, _ = run_all(tmp_path, routes)
    assert code == 0, out


def test_a_workflow_directory_404_with_an_unreadable_contents_root_is_unknown(tmp_path: Path) -> None:
    root = f"{REPO}/contents"
    routes = {**clean(), f"{root}/.github/workflows": j(NOT_PROTECTED, 404), root: j(NOT_PROTECTED, 404)}
    code, out, _, _ = run_all(tmp_path, routes)
    assert code == 2, out
    assert "OK o/r" not in out


def test_a_malformed_thread_resolution_value_in_a_ruleset_is_unknown(tmp_path: Path) -> None:
    rule = ruleset()
    rule["rules"][2]["parameters"]["required_review_thread_resolution"] = "true"
    rule["rules"][3]["parameters"]["required_status_checks"].append({"context": "sec / security"})
    routes = {
        **clean(),
        f"{REPO}/branches/main/protection": j(NOT_PROTECTED, 404),
        f"{REPO}/rulesets": j([{"id": 7, "target": "branch", "enforcement": "active"}]),
        f"{REPO}/rulesets/7": j(rule),
    }
    code, out, _, _ = run_all(tmp_path, routes)
    assert code == 2, out


def test_admin_bypass_and_conversation_state_are_reported_without_failing(tmp_path: Path) -> None:
    body = classic()
    body["required_status_checks"]["checks"].append({"context": "sec / security", "app_id": 15368})
    body["enforce_admins"] = {"enabled": False}
    routes = {**clean(), f"{REPO}/branches/main/protection": j(body)}
    code, out, _, _ = run_all(tmp_path, routes)
    assert code == 0, out
    assert "admins: can bypass" in out and "conversation resolution: off" in out
    code, out, _, _ = run_all(tmp_path, clean())
    assert "admins: enforced" in out and "conversation resolution: required" in out


def test_a_ruleset_can_satisfy_the_standard(tmp_path: Path) -> None:
    rule = ruleset()
    rule["rules"][2]["parameters"]["required_review_thread_resolution"] = True
    rule["rules"][3]["parameters"]["required_status_checks"].append({"context": "sec / security"})
    routes = {
        **clean(),
        f"{REPO}/branches/main/protection": j(NOT_PROTECTED, 404),
        f"{REPO}/rulesets": j([{"id": 7, "target": "branch", "enforcement": "active"}]),
        f"{REPO}/rulesets/7": j(rule),
    }
    code, out, _, _ = run_all(tmp_path, routes)
    assert code == 0, out
    assert "conversation resolution: required" in out


def test_one_repository_that_cannot_be_read_is_unknown_and_the_rest_are_still_read(tmp_path: Path) -> None:
    routes = {**clean(), **renamed(clean(), "s"), "/repos/o/s": j({"message": "boom"}, 500)}
    code, out, _, _ = run_all(tmp_path, routes, "r", "s")
    assert code == 2
    assert "UNKNOWN o/s" in out and "OK o/r" in out
    assert out.strip().splitlines()[-1] == "protection: 2 repositories read, 0 with drift, 1 unknown"


def test_drift_in_one_repository_among_several_exits_one(tmp_path: Path) -> None:
    bad = renamed(with_classic(force_on), "s")
    code, out, _, _ = run_all(tmp_path, {**clean(), **bad}, "r", "s")
    assert code == 1 and "OK o/r" in out
    assert out.strip().splitlines()[-1] == "protection: 2 repositories read, 1 with drift"


def test_an_exempt_repository_is_not_read(tmp_path: Path) -> None:
    code, out, _, seen = run_all(tmp_path, clean(), "r", "s", exempt="o/s")
    assert code == 0, out
    assert "o/s" in out and "exempt" in out
    assert not any(path.startswith("/repos/o/s") for _, path in seen)


def test_all_and_repo_are_mutually_exclusive_and_one_is_required(tmp_path: Path) -> None:
    both = run_cli("--board", board(tmp_path, "r"), "protection", "--all", "--repo", "o/r", env=ENV)
    neither = run_cli("--board", board(tmp_path, "r"), "protection", env=ENV)
    assert both[0] == 2 and neither[0] == 2
    assert "--all" in both[2] and "--repo" in neither[2]


def test_the_single_repository_mode_is_unchanged() -> None:
    code, out, _, _ = check(good_routes())
    assert code == 0 and out.count("PASS") == 10
