# SPDX-License-Identifier: MIT
"""The repository's own workflows follow GYST's rules: pinned by commit, read-only by default, one pin."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
GYST_USE = re.compile(
    r"ChiefGyk3D/git-your-ship-together/\.github/workflows/([a-z-]+\.yml)@([0-9a-f]{40}) # (v\d+\.\d+\.\d+)$"
)
ANY_USE = re.compile(r"^\s*(?:- )?uses:\s+\S+")


def load(path: Path) -> dict[Any, Any]:
    loaded = yaml.safe_load(path.read_text())
    assert isinstance(loaded, dict)
    return loaded


def uses_lines(path: Path) -> list[str]:
    return [line.strip().removeprefix("- ") for line in path.read_text().splitlines() if ANY_USE.match(line)]


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_reference_is_pinned_by_commit_with_a_version_comment(path: Path) -> None:
    for line in uses_lines(path):
        target = line.removeprefix("uses:").strip()
        if target.startswith("./"):
            continue
        assert re.search(r"@[0-9a-f]{40} # v\d+\.\d+\.\d+$", target), f"{path.name}: {line}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_permissions_start_read_only_and_secrets_are_never_inherited(path: Path) -> None:
    doc = load(path)
    assert doc["permissions"] == {"contents": "read"}, path.name
    assert "secrets: inherit" not in path.read_text()
    assert "pull_request_target" not in path.read_text()


def test_one_gyst_pin_in_every_caller() -> None:
    pins = {m[2] for path in WORKFLOWS for line in uses_lines(path) if (m := GYST_USE.search(line))}
    versions = {m[3] for path in WORKFLOWS for line in uses_lines(path) if (m := GYST_USE.search(line))}
    assert len(pins) == 1 and len(versions) == 1, "a GYST bump moves every caller together"


def test_the_ci_gates_are_named_ci_green_through_python_ci_and_bash_ci() -> None:
    jobs = load(ROOT / ".github" / "workflows" / "ci.yml")["jobs"]
    assert set(jobs) == {"ci", "shell"}
    assert "python-ci.yml@" in jobs["ci"]["uses"] and "bash-ci.yml@" in jobs["shell"]["uses"]


def test_the_live_audit_never_runs_on_a_pull_request() -> None:
    path = ROOT / ".github" / "workflows" / "live-audit.yml"
    if not path.exists():
        pytest.skip("live-audit.yml arrives with the dogfood task")
    triggers = load(path).get("on") or load(path).get(True) or {}
    assert set(triggers) == {"workflow_dispatch"}
