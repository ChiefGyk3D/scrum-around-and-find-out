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
import socket
import subprocess
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
ROOT_ONLY = ("R1", "R3", "R4", "R6", "R8", "R10", "R11")


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
    for step in ("R2", "R5", "R7", "R9", "R12", "R13", "E0", "Ea4", "Ec", "Ed", "Ee2", "DRYRUN"):
        assert rows[step].status == "PASS", (step, rows[step].detail)


def test_the_dry_run_made_no_vendor_call_and_recorded_no_approval(shipped: list[Any]) -> None:
    detail = by_step(shipped)["DRYRUN"].detail
    assert "0 vendor requests" in detail and "no approval recorded" in detail


def test_the_table_names_each_step_and_ends_with_a_total(shipped: list[Any]) -> None:
    text = load().render(shipped)
    assert re.search(r"^R2\s+PASS", text, re.MULTILINE)
    assert re.search(r"^R1\s+SKIPPED", text, re.MULTILINE)
    assert re.search(r"^total: \d+ pass, 0 fail, \d+ skipped$", text, re.MULTILINE)


def test_r3_is_skipped_not_passed_because_the_root_review_is_not_done(shipped: list[Any]) -> None:
    row = by_step(shipped)["R3"]
    assert row.status == "SKIPPED" and "mandatory root review" in row.detail


def test_the_uncontained_run_exits_zero_and_every_line_says_so(prefix: Path) -> None:
    out = io.StringIO()
    assert load().main(["--prefix", str(prefix), "--no-containment"], out=out) == 0
    lines = out.getvalue().splitlines()
    assert len(lines) > STEP_COUNT and all(x.endswith("[NO CONTAINMENT]") for x in lines)
    assert not re.search(r"^\S+\s+FAIL\s", out.getvalue(), re.MULTILINE)


NO_BWRAP = load().containment_problem()
needs_bwrap = pytest.mark.skipif(NO_BWRAP is not None, reason=f"cannot contain here: {NO_BWRAP}")


@needs_bwrap
def test_the_contained_run_exits_zero_and_carries_no_warning_marker(prefix: Path) -> None:
    out = io.StringIO()
    assert load().main(["--prefix", str(prefix)], out=out) == 0
    assert "NO CONTAINMENT" not in out.getvalue() and "SKIPPED" in out.getvalue()
    assert not re.search(r"^\S+\s+FAIL\s", out.getvalue(), re.MULTILINE)


def test_it_refuses_to_run_when_it_cannot_be_contained_unless_told_to(
    prefix: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    mod = load()
    monkeypatch.setattr(mod, "containment_problem", lambda: "bubblewrap (bwrap) is not installed")
    with pytest.raises(SystemExit) as stop:
        mod.main(["--prefix", str(prefix)], out=io.StringIO())
    assert stop.value.code == 2
    assert "--no-containment" in capsys.readouterr().err
    assert not prefix.exists()  # nothing was made


def run_contained(prefix: Path, code: str) -> subprocess.CompletedProcess[str]:
    prefix.mkdir(parents=True, exist_ok=True)
    (prefix / "tmp").mkdir(exist_ok=True)
    argv = load().contained_argv(prefix, [sys.executable, "-I", "-c", code])
    return subprocess.run(  # noqa: S603 - argv built by the code under test, no shell, bounded time
        argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60, check=False
    )


@needs_bwrap
def test_the_sandbox_blocks_writes_outside_the_prefix_and_the_checkout(prefix: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    code = (
        "import pathlib,sys\n"
        f"ok = []\n"
        f"for t in ({str(ROOT / '.probe')!r}, {str(outside)!r}, '/usr/probe', '/etc/probe'):\n"
        "    try:\n        pathlib.Path(t).write_text('x'); ok.append(t)\n    except OSError: pass\n"
        f"pathlib.Path({str(prefix / 'inside')!r}).write_text('x')\n"
        "sys.exit(len(ok))"
    )
    done = run_contained(prefix, code)
    assert done.returncode == 0, done.stderr
    assert (prefix / "inside").exists()  # the prefix is writable
    assert not outside.exists() and not (ROOT / ".probe").exists()


@needs_bwrap
def test_the_sandbox_has_no_network_and_cannot_see_the_home_folder_or_the_callers_files(
    prefix: Path, tmp_path: Path
) -> None:
    secret = tmp_path / "secret"
    secret.write_text("not for the rehearsal")
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    home = str(Path.home())
    code = (
        "import os,socket,sys\n"
        "bad = []\n"
        f"try:\n    socket.create_connection(('127.0.0.1', {port}), timeout=3); bad.append('network')\n"
        "except OSError: pass\n"
        f"if os.path.exists({str(secret)!r}): bad.append('secret')\n"
        f"if os.path.exists({home!r}): bad.append('home')\n"
        f"if os.environ.get('SSH_AUTH_SOCK') or os.environ.get('HOME', '').startswith({home!r}): bad.append('env')\n"
        "print(bad); sys.exit(len(bad))"
    )
    try:
        done = run_contained(prefix, code)
    finally:
        server.close()
    assert done.returncode == 0, done.stdout + done.stderr


def test_a_service_user_that_never_exists_makes_r13_fail_like_the_real_command(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R13 used to pass because the tool ignored the service-user check (#263 review); the real enabling preflight
    exits nonzero without that user, so the row must fail."""
    mod = load()
    monkeypatch.setattr(mod.Rehearsal, "fake_lookup", lambda _self, _name: None)
    assert by_step(mod.rehearse(prefix))["R13"].status == "FAIL"


def test_the_preflight_host_checks_never_touch_the_real_machine(prefix: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from safo import gemini_preflight

    def forbidden(*_a: object, **_k: object) -> object:
        raise AssertionError("the rehearsal asked the real machine")

    monkeypatch.setattr(gemini_preflight, "default_runner", forbidden)
    monkeypatch.setattr(gemini_preflight, "default_lookup", forbidden)
    mod = load()
    rows = by_step(mod.rehearse(prefix))
    assert rows["E0"].status == "PASS" and rows["R13"].status == "PASS"
    where = mod.Rehearsal(prefix, "").locations()
    assert all(str(prefix) in str(d) for d in (*where.udev_dirs, *where.sk_helper_dirs))


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
