# SPDX-License-Identifier: MIT
"""The project's own board and its scheduled reconcile: user-owned, no token in CI, run from the maintainer's login."""

from __future__ import annotations

from pathlib import Path

import yaml

from safo.schema import load_board

EXAMPLES = Path(__file__).parent.parent / "examples"
WORKFLOWS = EXAMPLES.parent / ".github" / "workflows"


def test_the_projects_own_board_is_user_owned_and_has_no_number_until_bootstrap_creates_it() -> None:
    board = load_board(EXAMPLES / "safo.yaml")
    assert board.project.owner_type == "user" and board.project.number is None
    assert [r.full_name for r in board.repositories] == ["ChiefGyk3D/scrum-around-and-find-out"]


def test_the_timer_runs_reconcile_from_the_users_own_login_with_no_token_stored() -> None:
    service = (EXAMPLES / "systemd" / "safo-reconcile.service").read_text()
    exec_line = next(line for line in service.splitlines() if line.startswith("ExecStart="))
    assert exec_line.endswith(".config/safo/board.yaml reconcile")
    assert not any(line.startswith(("Environment", "EnvironmentFile")) for line in service.splitlines())
    assert "SAFO_TOKEN" not in service
    assert "OnCalendar=daily" in (EXAMPLES / "systemd" / "safo-reconcile.timer").read_text()


def test_no_workflow_gives_the_own_board_a_personal_access_token() -> None:
    paths = list(WORKFLOWS.glob("*.yml"))
    assert paths
    for path in paths:
        text = path.read_text()
        assert "allow-token-for-org" not in text and "inputs.token" not in text
        assert "secrets.GH_PAT" not in text and "PERSONAL_ACCESS_TOKEN" not in text


def test_own_board_number_belongs_in_local_copy_and_service_reads_that_copy(tmp_path: Path) -> None:
    source = EXAMPLES / "safo.yaml"
    before = source.read_text()
    local = tmp_path / "board.yaml"
    data = yaml.safe_load(before)
    data["project"]["number"] = 1
    local.write_text(yaml.safe_dump(data))
    assert load_board(local).project.number == 1 and source.read_text() == before
    service = (EXAMPLES / "systemd" / "safo-reconcile.service").read_text()
    assert "%h/.config/safo/board.yaml reconcile" in service


def test_the_live_audit_is_manual_only_read_only_and_least_privilege() -> None:
    path = WORKFLOWS / "live-audit.yml"
    text = path.read_text()
    doc = yaml.safe_load(text)
    assert set(doc[True]) == {"workflow_dispatch"}
    assert doc["permissions"] == {"contents": "read"}
    job = doc["jobs"]["audit"]
    assert job["permissions"] == {"contents": "read", "id-token": "write"}
    assert "pull_request" not in text
    steps = job["steps"]
    assert steps[0]["uses"].startswith("step-security/harden-runner@")
    assert steps[0]["with"]["egress-policy"] == "block"
    action = next(s for s in steps if s.get("uses", "").startswith("./"))
    assert action["with"]["mode"] == "audit"
    assert "token" not in action["with"] and "private-key" not in action["with"]
    assert "dry-run" not in action["with"] or action["with"]["dry-run"] != "false"
    checkout = next(s for s in steps if s.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False
