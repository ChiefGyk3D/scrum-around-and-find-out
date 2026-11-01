# SPDX-License-Identifier: Apache-2.0
"""The rootless rehearsal of the phase 7 root setup (#263): scripts/rehearse_broker_setup.py.

It walks docs/gemini-enrollment.md and the runbook (src/safo/broker/runbook.py) against a throwaway prefix directory
with a test-only software key, runs the preflight and a dry run through the real broker code against a fake vendor, and
prints one PASS, FAIL or SKIPPED line per step. These tests run the whole rehearsal and require it to find nothing wrong
with the shipped docs and runbook; the negative tests show it does find a doctored runbook and a doctored page."""

from __future__ import annotations

import importlib.util
import io
import re
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from safo.broker import runbook

ROOT = Path(__file__).resolve().parent.parent


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "rehearse_broker_setup", ROOT / "scripts" / "rehearse_broker_setup.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["rehearse_broker_setup"] = module  # dataclasses look the module up by name
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def prefix() -> Iterator[Path]:
    # short on purpose: a Unix socket path is limited to about 100 bytes
    folder = Path(tempfile.mkdtemp(prefix="rh"))
    try:
        yield folder / "p"
    finally:
        shutil.rmtree(folder, ignore_errors=True)


@pytest.fixture(scope="module")
def shipped() -> Iterator[list[Any]]:
    folder = Path(tempfile.mkdtemp(prefix="rh"))
    try:
        yield load().rehearse(folder / "p")
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def by_step(rows: list[Any]) -> dict[str, Any]:
    return {r.step: r for r in rows}


STEP_COUNT = len(runbook.steps("maintainer"))
# these need root, systemd, nftables or a hardware-signed tag for their real effect
ROOT_ONLY = ("R1", "R4", "R6", "R8", "R10", "R11")


def test_every_runbook_step_has_a_row_named_by_its_number(shipped: list[Any]) -> None:
    rows = by_step(shipped)
    assert STEP_COUNT == 13, "the runbook changed: update the rehearsal and this count together"
    for n in range(1, STEP_COUNT + 1):
        assert f"R{n}" in rows, f"no row for runbook step {n}"


def test_the_shipped_docs_and_runbook_pass_the_rehearsal(shipped: list[Any]) -> None:
    assert len(shipped) > STEP_COUNT, "collected too little: the rehearsal must also walk the enrollment steps"
    failed = [(r.step, r.detail) for r in shipped if r.status == "FAIL"]
    assert failed == []


def test_steps_that_need_root_or_systemd_say_skipped_with_a_reason(shipped: list[Any]) -> None:
    rows = by_step(shipped)
    for step in ROOT_ONLY:
        assert rows[step].status == "SKIPPED", step
        assert re.search(r"root|systemd|nft|hardware", rows[step].detail), (step, rows[step].detail)


def test_the_steps_that_can_run_rootless_really_ran(shipped: list[Any]) -> None:
    rows = by_step(shipped)
    for step in ("R2", "R3", "R5", "R7", "R9", "R12", "R13", "E0", "Ea4", "Ec", "Ed", "Ee2", "DRYRUN"):
        assert rows[step].status == "PASS", (step, rows[step].detail)


def test_the_dry_run_made_no_vendor_call_and_recorded_no_approval(shipped: list[Any]) -> None:
    detail = by_step(shipped)["DRYRUN"].detail
    assert "0 vendor requests" in detail and "no approval recorded" in detail


def test_the_table_names_each_step_and_ends_with_a_total(shipped: list[Any]) -> None:
    text = load().render(shipped)
    assert re.search(r"^R2\s+PASS", text, re.MULTILINE)
    assert re.search(r"^R1\s+SKIPPED", text, re.MULTILINE)
    assert re.search(r"^total: \d+ pass, 0 fail, \d+ skipped$", text, re.MULTILINE)


def test_the_script_runs_from_the_command_line_and_exits_zero(prefix: Path) -> None:
    out = io.StringIO()
    assert load().main(["--prefix", str(prefix)], out=out) == 0
    assert not re.search(r"^\S+\s+FAIL\s", out.getvalue(), re.MULTILINE)
    assert "SKIPPED" in out.getvalue()


# -- the guard bites ---------------------------------------------------------------------------------------------


def test_a_broker_config_the_loader_refuses_is_reported_as_a_failed_step_9(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runbook, "BROKER_CONFIG", runbook.BROKER_CONFIG.replace("[ACCOUNT_UID_HERE]", "[]"))
    assert by_step(load().rehearse(prefix))["R9"].status == "FAIL"


def test_a_runbook_line_with_a_shell_syntax_error_is_reported(prefix: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = runbook.steps

    def broken(login: str) -> tuple[runbook.Step, ...]:
        out = list(real(login))
        step = out[1]  # the root-owned directories
        bad = "ssh -t host 'sudo install -d \"/etc/safo'"
        out[1] = runbook.Step(step.title, step.why, (bad, *step.commands[1:]), step.blast, step.rollback, step.note)
        return tuple(out)

    monkeypatch.setattr(runbook, "steps", broken)
    assert by_step(load().rehearse(prefix))["R2"].status == "FAIL"


def test_a_doctored_page_whose_failure_count_is_wrong_is_reported(prefix: Path) -> None:
    doc = (ROOT / "docs" / "gemini-enrollment.md").read_text()
    sample = "summary: 3 pass, 4 warn, 4 fail; exit 1"
    assert sample in doc
    wrong = doc.replace(sample, "summary: 3 pass, 4 warn, 2 fail; exit 1")
    assert by_step(load().rehearse(prefix, doc=wrong))["E0"].status == "FAIL"


def test_a_hard_coded_release_key_type_is_reported_as_a_failed_step_5(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mistake the rehearsal found (#263): the old step baked in the ed25519-sk type word."""
    monkeypatch.setattr(runbook, "PASTE_KEY_TYPE", "sk-ssh-ed25519@openssh.com")
    row = by_step(load().rehearse(prefix))["R5"]
    assert row.status == "FAIL" and "ecdsa-sk" in row.detail


def test_a_page_that_calls_the_merged_commands_unmerged_is_reported(prefix: Path) -> None:
    doc = (ROOT / "docs" / "gemini-enrollment.md").read_text() + "\nThis needs the unmerged broker code.\n"
    assert by_step(load().rehearse(prefix, doc=doc))["Ed"].status == "FAIL"


def test_it_refuses_a_prefix_that_is_not_a_new_empty_folder() -> None:
    with pytest.raises(SystemExit) as stop:
        load().main(["--prefix", "/etc"], out=io.StringIO())
    assert stop.value.code == 2


def test_it_refuses_to_run_as_root(prefix: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = load()
    monkeypatch.setattr(mod.os, "geteuid", lambda: 0)
    with pytest.raises(SystemExit) as stop:
        mod.main(["--prefix", str(prefix)], out=io.StringIO())
    assert stop.value.code == 2
