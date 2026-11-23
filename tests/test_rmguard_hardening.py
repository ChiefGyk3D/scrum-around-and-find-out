# SPDX-License-Identifier: Apache-2.0
"""rmguard hardening (#422, Daybreak round 1): the cwd gate, the log files, and the install documentation."""

from __future__ import annotations

import io
import json
import os
import re
from pathlib import Path

import pytest

from safo import rmguard

DOC = Path(__file__).resolve().parent.parent / "docs" / "rmguard.md"
LEAD = (".local", "share", "reach-around-lead")


def event(command: str, cwd: str = "/") -> str:
    return json.dumps({"tool_name": "Bash", "cwd": cwd, "tool_input": {"command": command}})


def warn(raw: str, home: Path) -> int:
    return rmguard.main(["--mode", "warn"], io.StringIO(raw), str(home))


def would_block(home: Path) -> str:
    return event(f"rm -rf {home}/.local/share/x-dev/*.py")


# -- D1: the cwd decides whether the narrow gate applies --------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "cwd", "expected"),
    [
        ("git clean -fdx", "/home/u/.local/share/reach-around-dev", True),
        ("git clean -fdx", "/home/u/.local/share/reach-around-dev/agents/a/work", True),
        ("git clean -fdx", "/tmp/claude-1000/p/s/scratchpad", True),
        ("git clean -fdx", "/home/u/src/repo", False),
        ("git clean -fdx", "/home/u", False),
        ("git clean -fdx", None, False),
    ],
)
def test_the_gate_widens_when_the_cwd_is_inside_a_zone(command: str, cwd: str | None, expected: bool) -> None:
    assert rmguard.has_delete_word(command, cwd, "/home/u") is expected


# -- D1: a truncating redirection judges an EXISTING target in a zone; a new file is only created --


@pytest.mark.parametrize(
    "redirect",
    ["> {t}", ": > {t}", "echo x > {t}", "true >| {t}", "echo hi &> {t}", "{{ :; }} > {t}", "echo x | tee {t}"],
)
def test_a_redirection_that_truncates_an_existing_shared_file_is_denied(redirect: str, tmp_path: Path) -> None:
    dev = tmp_path / ".local/share/reach-around-dev"
    dev.mkdir(parents=True)
    (dev / "a.log").write_text("keep")
    command = redirect.format(t=dev / "a.log")
    assert rmguard.check(command, str(tmp_path), "/") is not None, command
    # the same text aimed at a file that does not exist yet only creates it
    assert rmguard.check(redirect.format(t=dev / "new.log"), str(tmp_path), "/") is None


def test_the_relative_redirection_in_a_zone_cwd_is_judged_the_same_way(tmp_path: Path) -> None:
    dev = tmp_path / ".local/share/reach-around-dev"
    dev.mkdir(parents=True)
    (dev / "a.log").write_text("keep")
    assert rmguard.check(": > a.log", str(tmp_path), str(dev)) is not None
    assert rmguard.check(": > b.log", str(tmp_path), str(dev)) is None


def test_append_and_agent_folder_redirections_are_allowed(tmp_path: Path) -> None:
    dev = tmp_path / ".local/share/reach-around-dev"
    agent = dev / "agents/me/work"
    agent.mkdir(parents=True)
    (dev / "a.log").write_text("keep")
    (agent / "o.log").write_text("mine")
    home = str(tmp_path)
    assert rmguard.check(f"echo x >> {dev}/a.log", home, "/") is None
    assert rmguard.check(f"echo x > {agent}/o.log", home, "/") is None
    assert rmguard.check(f"echo x | tee -a {dev}/a.log", home, "/") is None


# -- D4: the logs are written through a trusted directory descriptor --------------------------------------------------


def lead_dir(home: Path) -> Path:
    return home.joinpath(*LEAD)


def test_a_symlink_planted_at_the_log_path_is_not_followed(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")
    lead_dir(tmp_path).mkdir(parents=True)
    (lead_dir(tmp_path) / "rmguard-warn.log").symlink_to(victim)
    assert warn(would_block(tmp_path), tmp_path) == 0
    assert victim.read_text() == "keep"


def test_a_symlinked_log_directory_is_not_followed(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    parent = lead_dir(tmp_path).parent
    parent.mkdir(parents=True)
    lead_dir(tmp_path).symlink_to(elsewhere)
    assert warn(would_block(tmp_path), tmp_path) == 0
    assert list(elsewhere.iterdir()) == []


def test_a_symlinked_parent_component_is_not_followed(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "share").mkdir(parents=True)
    (tmp_path / ".local").symlink_to(elsewhere)
    assert warn(would_block(tmp_path), tmp_path) == 0
    assert list((elsewhere / "share").iterdir()) == []


def test_existing_modes_are_repaired(tmp_path: Path) -> None:
    folder = lead_dir(tmp_path)
    folder.mkdir(parents=True)
    folder.chmod(0o755)
    log = folder / "rmguard-warn.log"
    log.write_text("old\n")
    log.chmod(0o644)
    assert warn(would_block(tmp_path), tmp_path) == 0
    assert folder.stat().st_mode & 0o777 == 0o700
    assert log.stat().st_mode & 0o777 == 0o600
    assert log.read_text().startswith("old\n") and len(log.read_text().splitlines()) == 2


def test_a_hard_linked_log_is_refused(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")
    lead_dir(tmp_path).mkdir(parents=True)
    os.link(victim, lead_dir(tmp_path) / "rmguard-warn.log")
    assert warn(would_block(tmp_path), tmp_path) == 0
    assert victim.read_text() == "keep"


def test_a_directory_owned_by_someone_else_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lead_dir(tmp_path).mkdir(parents=True)
    monkeypatch.setattr(os, "getuid", lambda: os.stat(tmp_path).st_uid + 1)
    assert warn(would_block(tmp_path), tmp_path) == 0
    assert not (lead_dir(tmp_path) / "rmguard-warn.log").exists()


def test_a_log_that_is_not_a_regular_file_is_refused(tmp_path: Path) -> None:
    lead_dir(tmp_path).mkdir(parents=True)
    (lead_dir(tmp_path) / "rmguard-warn.log").mkdir()
    assert warn(would_block(tmp_path), tmp_path) == 0


def test_a_fresh_log_is_created_0600_in_a_0700_folder(tmp_path: Path) -> None:
    assert warn(would_block(tmp_path), tmp_path) == 0
    log = lead_dir(tmp_path) / "rmguard-warn.log"
    assert log.stat().st_mode & 0o777 == 0o600
    assert lead_dir(tmp_path).stat().st_mode & 0o777 == 0o700
    assert len(log.read_text().splitlines()) == 1


# -- D5: the install documentation ------------------------------------------------------------------------------------


def doc_entries() -> dict[str, dict[str, object]]:
    """The JSON code blocks of docs/rmguard.md that hold a hook entry, by the mode they name."""
    found: dict[str, dict[str, object]] = {}
    for block in re.findall(r"```json\n(.*?)```", DOC.read_text(), flags=re.S):
        entry = json.loads(block)
        hook = entry["hooks"][0]
        mode = "warn" if "--mode warn" in hook["command"] else "enforce"
        found[mode] = hook
    return found


def test_the_warn_entry_never_blocks_on_failure() -> None:
    hook = doc_entries()["warn"]
    assert "onFailure" not in hook
    assert "safo-rmguard --mode warn" in str(hook["command"])


def test_the_enforce_entry_blocks_on_failure_and_uses_a_launcher_outside_the_environment() -> None:
    hook = doc_entries()["enforce"]
    assert hook["onFailure"] == "block"
    assert "pipx" not in str(hook["command"])
    text = DOC.read_text()
    assert "exit 2" in text
    assert "warn-mode period" in text
    assert "cp -p" in text
    assert "Edit and Write" in text


def test_the_docs_name_the_covered_families_and_not_a_blanket_claim() -> None:
    text = DOC.read_text()
    for family in ("git clean", "truncate", "rsync", "tar --remove-files", "mv", "cp /dev/null", "dd", "find"):
        assert family in text
    assert "not covered" in text.lower()
    assert "own folder" not in text.lower()


def test_the_docs_state_the_residual_risk_the_integrity_check_and_the_promotion_threshold() -> None:
    text = DOC.read_text()
    assert "--record-integrity" in text
    assert "not tamper-proof" in text.lower() or "tamper-proof" in text.lower()
    assert "same user" in text.lower() or "same uid" in text.lower()
    assert "promotion threshold" in text.lower()
    assert "Edit and Write" in text
