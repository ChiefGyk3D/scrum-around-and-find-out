# SPDX-License-Identifier: Apache-2.0
"""The root-only broker administration command: privilege drop, status, usage, check-install, clear, reconcile.

Every test uses a temporary state directory and an injected set of process-identity operations, so nothing here needs
root, touches /etc, /opt or /var, or reads the clock. The ledger's own owner rule (a file must belong to the effective
uid) is left exactly as it is; one test pins that.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from brokerdata import (
    EPOCH,
    FLAT,
    NOW,
    Crash,
    CrashAt,
    Rng,
    approval,
    flat_request,
    new_ledger,
    prices_data,
    state_dir,
)
from safo import output
from safo.broker import admin
from safo.broker.doors import DoorPaths
from safo.broker.errors import IllegalTransition, LedgerError
from safo.broker.ledger import AdminWho, CallLedger
from safo.broker.money import MICRO, format_usd
from safo.broker.policy import Caps, Policy
from safo.broker.prices import parse_prices
from safo.broker.states import CallState
from test_broker_doors import World

LATER = NOW + dt.timedelta(seconds=30)
SUDO_USER = (
    4001  # the uid "sudo" reports; not a uid a test runner has, so files the tests create are not the maintainer's
)
WHO = AdminWho(uid=0, sudo_uid=SUDO_USER)
BIG = Caps(job_micro=2_500_000, month_micro=10_000_000)
SERVICE_UID = 4242
SERVICE_GID = 4343


# -- helpers -------------------------------------------------------------------------------------------------------


@dataclasses.dataclass
class Pw:
    pw_uid: int
    pw_gid: int


SERVICE_USER_ENTRY = Pw(SERVICE_UID, SERVICE_GID)


class FakeOps:
    """The process-identity operations, recorded. `regain` makes a setuid(0) after the drop succeed (a broken drop)."""

    def __init__(self, euid: int = 0, *, regain: bool = False, user: Pw | None = SERVICE_USER_ENTRY) -> None:
        self.log: list[str] = []
        self.uids = (euid, euid, euid)
        self.gids = (0, 0, 0)
        self.groups = [0, 4]
        self.real_uid = euid
        self.regain = regain
        self.user = user
        self.fail_on: str | None = None

    def _step(self, name: str) -> None:
        self.log.append(name)
        if self.fail_on == name.split("(")[0]:
            raise PermissionError(name)

    def geteuid(self) -> int:
        return self.uids[1]

    def getuid(self) -> int:
        return self.real_uid

    def getpwnam(self, name: str) -> Pw:
        self.log.append(f"getpwnam({name})")
        if self.user is None:
            raise KeyError(name)
        return self.user

    def setgroups(self, groups: list[int]) -> None:
        self._step(f"setgroups({groups})")
        self.groups = list(groups)

    def setgid(self, gid: int) -> None:
        self._step(f"setgid({gid})")
        self.gids = (gid, gid, gid)

    def setuid(self, uid: int) -> None:
        self._step(f"setuid({uid})")
        if uid == 0 and self.uids[1] != 0 and not self.regain:
            raise PermissionError("not permitted")
        self.uids = (uid, uid, uid)

    def getresuid(self) -> tuple[int, int, int]:
        return self.uids

    def getresgid(self) -> tuple[int, int, int]:
        return self.gids

    def getgroups(self) -> list[int]:
        return list(self.groups)

    def umask(self, mask: int) -> int:
        self.log.append(f"umask({mask:o})")
        return 0o022

    def chdir(self, path: str) -> None:
        self.log.append(f"chdir({path})")

    def as_ops(self) -> admin.PrivOps:
        return admin.PrivOps(
            geteuid=self.geteuid,
            getuid=self.getuid,
            getpwnam=self.getpwnam,
            setgroups=self.setgroups,
            setgid=self.setgid,
            setuid=self.setuid,
            getresuid=self.getresuid,
            getresgid=self.getresgid,
            getgroups=self.getgroups,
            umask=self.umask,
            chdir=self.chdir,
        )


OTHER = "other-model"


def two_models(caps: Caps | None = None) -> Policy:
    """The test price table with a second model that prices exactly like FLAT."""
    data = prices_data()
    data["models"][OTHER] = dict(data["models"][FLAT])
    return Policy(parse_prices(data), caps or Caps())


DOOR_WORLDS: dict[Path, World] = {}


def door_paths(tmp: Path, **over: Any) -> DoorPaths:
    """A clean fake machine for the root-door checks, with the scans that walk many files switched off (the door
    checks have their own tests in test_broker_doors.py). The maintainer is the uid `run` passes as SUDO_UID."""
    quiet: dict[str, Any] = {
        "writable_roots": (),
        "unit_dirs": (),
        "cron_files": (),
        "cron_dirs": (),
        "setuid_roots": (),
    }
    if tmp not in DOOR_WORLDS:  # built once per test: building it again would rewrite files and move their times
        DOOR_WORLDS[tmp] = World(tmp / "doors", maint=SUDO_USER)
    return DOOR_WORLDS[tmp].door(**(quiet | over))


def paths(tmp: Path) -> admin.Paths:
    return admin.Paths(
        door=door_paths(tmp),
        state_dir=state_dir(tmp),
        switch=tmp / "etc" / "gemini-paid-enabled",
        min_version=tmp / "etc" / "broker-min-version",
        install_version=tmp / "var" / "version",
        release_link=tmp / "opt" / "current",
        unit_dir=tmp / "units",
        egress_helper=tmp / "sbin" / "safo-broker-egress",
        egress_conf=tmp / "etc" / "broker-egress.conf",
        trust_uid=os.getuid(),
    )


def run(
    tmp: Path,
    *argv: str,
    ops: FakeOps | None = None,
    env: dict[str, str] | None = None,
    now: dt.datetime = LATER,
) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = admin.run(
        list(argv),
        ops=(ops or FakeOps()).as_ops(),
        paths=paths(tmp),
        env={"SUDO_UID": str(SUDO_USER)} if env is None else env,
        now=now,
        out=out,
        err=err,
    )
    return code, out.getvalue(), err.getvalue()


def reserve(ledger: CallLedger, reserved: int = 5000, *, model: str = FLAT, now: dt.datetime = NOW) -> str:
    req = flat_request(reserved, model=model)
    return ledger.reserve(req, approval(req), two_models(BIG), epoch=EPOCH, now=now).call_id


def ambiguous(ledger: CallLedger, reserved: int = 5000, *, now: dt.datetime = NOW) -> str:
    cid = reserve(ledger, reserved, now=now)
    ledger.mark_sent(cid, now)
    ledger.mark_ambiguous(cid, "timeout", now)
    return cid


def breached(ledger: CallLedger, reserved: int = 5000, actual: int = 9000) -> str:
    cid = reserve(ledger, reserved)
    ledger.mark_sent(cid, NOW)
    assert ledger.settle(cid, "ok", actual, NOW).breach
    return cid


def month(ledger: CallLedger, now: dt.datetime = LATER) -> int:
    return ledger.view().month_spent(now)


def last_rows(tmp: Path, count: int) -> list[dict[str, Any]]:
    text = (state_dir(tmp) / "ledger.jsonl").read_text()
    return [json.loads(line) for line in text.splitlines()][-count:]


def ledger_bytes(tmp: Path) -> bytes:
    return (state_dir(tmp) / "ledger.jsonl").read_bytes()


# -- privilege -----------------------------------------------------------------------------------------------------


def test_a_command_run_without_root_is_refused_before_anything_is_read(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    ambiguous(ledger)
    ops = FakeOps(euid=1000)
    code, out, err = run(tmp_path, "status", ops=ops)
    assert code == 2
    assert out == ""
    assert "root" in err
    assert ops.log == []  # no lookup, no drop, no ledger read


def test_the_drop_clears_groups_then_group_then_user_and_proves_it_cannot_be_undone() -> None:
    ops = FakeOps()
    admin.drop_privilege("safo-broker", ops.as_ops())
    assert ops.log == [
        "getpwnam(safo-broker)",
        "chdir(/)",
        "umask(77)",
        "setgroups([])",
        f"setgid({SERVICE_GID})",
        f"setuid({SERVICE_UID})",
        "setuid(0)",  # the probe: it must be refused
    ]
    assert ops.uids == (SERVICE_UID,) * 3
    assert ops.gids == (SERVICE_GID,) * 3
    assert ops.groups == []


def test_a_drop_that_can_be_undone_is_refused() -> None:
    ops = FakeOps(regain=True)
    with pytest.raises(admin.AdminError, match="privilege"):
        admin.drop_privilege("safo-broker", ops.as_ops())


@pytest.mark.parametrize("step", ["setgroups", "setgid", "setuid"])
def test_a_failed_step_of_the_drop_stops_the_command_with_the_ledger_untouched(tmp_path: Path, step: str) -> None:
    ledger = new_ledger(tmp_path)
    ambiguous(ledger)
    before = ledger_bytes(tmp_path)
    ops = FakeOps()
    ops.fail_on = step
    code, out, err = run(tmp_path, "status", ops=ops)
    assert code == 2
    assert out == ""
    assert "privilege" in err
    assert ledger_bytes(tmp_path) == before


@pytest.mark.parametrize("fault", ["uid", "gid", "groups"])
def test_a_drop_whose_result_is_not_what_was_asked_is_refused(fault: str) -> None:
    pops = FakeOps().as_ops()
    if fault == "uid":
        pops = dataclasses.replace(pops, getresuid=lambda: (SERVICE_UID, SERVICE_UID, 0))
    elif fault == "gid":
        pops = dataclasses.replace(pops, getresgid=lambda: (SERVICE_GID, 0, SERVICE_GID))
    else:
        pops = dataclasses.replace(pops, getgroups=lambda: [4])
    with pytest.raises(admin.AdminError, match="privilege"):
        admin.drop_privilege("safo-broker", pops)


def test_the_service_user_must_exist_and_must_not_be_root() -> None:
    with pytest.raises(admin.AdminError, match="service user"):
        admin.drop_privilege("safo-broker", FakeOps(user=None).as_ops())
    with pytest.raises(admin.AdminError, match="service user"):
        admin.drop_privilege("safo-broker", FakeOps(user=Pw(0, SERVICE_GID)).as_ops())
    with pytest.raises(admin.AdminError, match="service user"):
        admin.drop_privilege("safo-broker", FakeOps(user=Pw(SERVICE_UID, 0)).as_ops())


def test_the_ledger_is_opened_only_after_the_drop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = new_ledger(tmp_path)
    ambiguous(ledger)
    ops = FakeOps()
    original = CallLedger.view

    def spy(self: CallLedger) -> Any:
        ops.log.append("ledger-read")
        return original(self)

    monkeypatch.setattr(CallLedger, "view", spy)
    code, _, _ = run(tmp_path, "status", ops=ops)
    assert code == 0
    assert ops.log.index("ledger-read") > ops.log.index(f"setuid({SERVICE_UID})")


def test_check_install_never_opens_the_ledger_and_never_drops(tmp_path: Path) -> None:
    ops = FakeOps()
    code, _, _ = run(tmp_path, "check-install", ops=ops)
    assert code in (0, 1)
    assert not any(step.startswith("setuid") for step in ops.log)


def test_the_ledger_still_refuses_a_different_effective_uid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The service's owner rule is unchanged: root does not get in by being root, it drops to the owner.
    ledger = new_ledger(tmp_path)
    ambiguous(ledger)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(LedgerError, match=r"not private|not ours"):
        CallLedger(state_dir(tmp_path)).view()


def test_nothing_is_read_from_standard_input(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Trap:
        def read(self, *a: Any) -> str:
            raise AssertionError("stdin was read")

        readline = read

    monkeypatch.setattr(sys, "stdin", Trap())
    ledger = new_ledger(tmp_path)
    cid = ambiguous(ledger)
    assert run(tmp_path, "status")[0] == 0
    assert run(tmp_path, "clear", FLAT)[0] == 2  # shows the record and waits for the typed confirmation argument
    assert run(tmp_path, "clear", FLAT, "--confirm", cid)[0] == 0


def test_the_module_runs_with_python_dash_m_and_standard_input_closed() -> None:
    if os.geteuid() == 0:
        pytest.skip("this check expects a non-root test run")
    done = subprocess.run(
        [sys.executable, "-I", "-m", "safo.broker.admin", "status"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 2
    assert "root" in done.stderr
    assert done.stdout == ""


def test_all_output_goes_through_the_output_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = new_ledger(tmp_path)
    ambiguous(ledger)
    seen: list[str] = []

    def record(stream: Any, text: str) -> None:
        seen.append(text)

    monkeypatch.setattr(output, "write", record)
    out, err = io.StringIO(), io.StringIO()
    for argv in (["status"], ["usage"], ["check-install"], ["reconcile"], ["clear", FLAT], ["bogus"]):
        admin.run(argv, ops=FakeOps().as_ops(), paths=paths(tmp_path), env={}, now=LATER, out=out, err=err)
    assert out.getvalue() == "" and err.getvalue() == ""
    assert any("schema_version" in text for text in seen)


def test_text_that_looks_like_a_workflow_command_is_written_out_escaped(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    ambiguous(ledger)
    paths(tmp_path).switch.parent.mkdir(parents=True)
    paths(tmp_path).min_version.write_text("::set-output name=x::y\n")
    code, out, _ = run(tmp_path, "status")
    assert code == 0
    assert "::set-output" not in out


# -- status and usage ----------------------------------------------------------------------------------------------


def test_status_summarizes_the_ledger_without_prompt_text_or_secrets(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = ambiguous(ledger, 5000)
    open_id = reserve(ledger, 4000, model=OTHER)
    p = paths(tmp_path)
    p.switch.parent.mkdir(parents=True)
    p.switch.write_text("enabled\n")
    p.min_version.write_text("1.2.0\n")
    code, out, err = run(tmp_path, "status")
    assert code == 0 and err == ""
    assert "month: 2026-10" in out
    assert f"spent_usd: {format_usd(9000)}" in out
    assert "schema_version: 3" in out
    assert "schema_floor: 3" in out
    assert "switch: enabled" in out
    assert "min_version: 1.2.0" in out
    assert f"open_calls: 1 ({open_id})" in out
    assert f"suspended: {FLAT} ({cid})" in out
    assert "xxxxx" not in out  # no prompt text
    assert "key" not in out.lower()


def test_status_says_when_the_switch_is_absent_or_not_enabled(tmp_path: Path) -> None:
    new_ledger(tmp_path)
    assert "switch: disabled" in run(tmp_path, "status")[1]
    p = paths(tmp_path)
    p.switch.parent.mkdir(parents=True)
    p.switch.write_text("yes please\n")
    assert "switch: disabled" in run(tmp_path, "status")[1]
    p.switch.write_text("enabled\n")
    assert "switch: enabled" in run(tmp_path, "status")[1]
    p.switch.chmod(0o666)  # writable by others: not trusted
    assert "switch: disabled" in run(tmp_path, "status")[1]


def test_status_of_a_state_directory_that_cannot_be_trusted_is_an_error_not_a_summary(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    ambiguous(ledger)
    (state_dir(tmp_path) / "ledger.jsonl").chmod(0o666)
    code, out, err = run(tmp_path, "status")
    assert code == 2 and out == ""
    assert "open to other users" in err


def test_a_missing_state_directory_is_not_created(tmp_path: Path) -> None:
    code, _, err = run(tmp_path, "status")
    assert code == 2
    assert "state" in err
    assert not state_dir(tmp_path).exists()


def test_usage_lists_the_month_per_job_with_the_total(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    for job, reserved in (("job-a", 3000), ("job-b", 7000), ("job-a", 2000)):
        req = flat_request(reserved, job=job)
        t = ledger.reserve(req, approval(req), two_models(BIG), epoch=EPOCH, now=NOW)
        ledger.mark_sent(t.call_id, NOW)
        ledger.settle(t.call_id, "ok", reserved - 1000, NOW)
    code, out, _ = run(tmp_path, "usage")
    assert code == 0
    rows = {line.split()[0]: line.split() for line in out.splitlines() if line.startswith("job-")}
    assert rows["job-a"][1:] == ["2", format_usd(3000)]
    assert rows["job-b"][1:] == ["1", format_usd(6000)]
    assert f"total_usd: {format_usd(9000)}" in out
    assert "adjustments_usd: 0" in out


def test_usage_takes_another_month_and_refuses_a_malformed_one(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    reserve(ledger)
    other = run(tmp_path, "usage", "--month", "2026-09")[1]
    assert "total_usd: 0" in other and "job-one" not in other
    assert run(tmp_path, "usage", "--month", "2026-13")[0] == 2
    assert run(tmp_path, "usage", "--month", "last")[0] == 2


# -- check-install -------------------------------------------------------------------------------------------------


UNIT_NAMES = (
    "safo-broker.service",
    "safo-broker.socket",
    "safo-broker-egress.service",
    "safo-broker-egress-refresh.service",
    "safo-broker-egress-refresh.timer",
)


def unit_text(name: str) -> bytes:
    return f"[Unit]\nDescription={name}\n".encode()


def manifest_line(release: Path, rel: str) -> str:
    return f"file\t{hashlib.sha256((release / rel).read_bytes()).hexdigest()}\t{rel}"


def install(tmp: Path, *, current: str = "1.2.3", recorded: str = "1.2.3", floor: str = "1.0.0") -> None:
    """A complete, consistent install: link, release (units, VERSION, manifest), installed units, helper, records."""
    p = paths(tmp)
    release = tmp / "opt" / "releases" / current
    (release / "units").mkdir(parents=True, exist_ok=True)
    for name in UNIT_NAMES:
        (release / "units" / name).write_bytes(unit_text(name))
    (release / "VERSION").write_text(current + "\n")
    (release / "COMMIT").write_text("0" * 40 + "\n")
    lines = [manifest_line(release, f"units/{n}") for n in UNIT_NAMES] + [manifest_line(release, "VERSION")]
    (release / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")
    if p.release_link.is_symlink():
        p.release_link.unlink()
    p.release_link.symlink_to(release)
    p.install_version.parent.mkdir(parents=True, exist_ok=True)
    p.install_version.write_text(recorded + "\n")
    p.min_version.parent.mkdir(parents=True, exist_ok=True)
    p.min_version.write_text(floor + "\n")
    p.unit_dir.mkdir(exist_ok=True)
    for name in UNIT_NAMES:
        (p.unit_dir / name).write_bytes(unit_text(name))
        (p.unit_dir / name).chmod(0o644)
    p.egress_helper.parent.mkdir(exist_ok=True)
    p.egress_helper.write_text("#!/bin/sh\n")
    p.egress_helper.chmod(0o755)
    p.egress_conf.write_text("VENDOR_HOST=api.vendor.example\nMODE=drop\n")
    p.egress_conf.chmod(0o644)


def test_check_install_passes_when_link_record_and_floor_agree(tmp_path: Path) -> None:
    install(tmp_path, floor="1.2.3")  # all three equal: the boundary is allowed
    code, out, _ = run(tmp_path, "check-install")
    assert code == 0
    assert "release: 1.2.3" in out and "recorded: 1.2.3" in out and "floor: 1.2.3" in out
    assert "ok: " in out


def test_check_install_fails_below_the_floor(tmp_path: Path) -> None:
    install(tmp_path, current="1.2.3", recorded="1.2.3", floor="1.2.4")
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "below the floor" in out


def test_check_install_fails_when_the_release_is_newer_than_the_record(tmp_path: Path) -> None:
    install(tmp_path, current="1.2.4", recorded="1.2.3")
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "newer than the record" in out


def test_check_install_notes_but_accepts_a_release_below_the_highest_recorded(tmp_path: Path) -> None:
    install(tmp_path, current="1.2.2", recorded="1.2.3")
    code, out, _ = run(tmp_path, "check-install")
    assert code == 0 and "below the highest" in out


def test_check_install_fails_when_the_floor_is_above_the_record(tmp_path: Path) -> None:
    install(tmp_path, current="1.2.3", recorded="1.2.3", floor="1.2.5")
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "above the record" in out


def test_check_install_fails_for_a_link_that_is_not_a_link_or_leaves_releases(tmp_path: Path) -> None:
    install(tmp_path)
    p = paths(tmp_path)
    p.release_link.unlink()
    p.release_link.mkdir()
    assert "not a symbolic link" in run(tmp_path, "check-install")[1]
    p.release_link.rmdir()
    elsewhere = tmp_path / "elsewhere" / "1.2.3"
    elsewhere.mkdir(parents=True)
    p.release_link.symlink_to(elsewhere)
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "outside the releases folder" in out


def test_check_install_fails_for_a_link_to_a_missing_or_oddly_named_release(tmp_path: Path) -> None:
    install(tmp_path)
    p = paths(tmp_path)
    p.release_link.unlink()
    p.release_link.symlink_to(tmp_path / "opt" / "releases" / "9.9.9")
    assert "does not exist" in run(tmp_path, "check-install")[1]
    odd = tmp_path / "opt" / "releases" / "latest"
    odd.mkdir()
    p.release_link.unlink()
    p.release_link.symlink_to(odd)
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "not a version" in out


def test_check_install_fails_for_missing_or_malformed_version_files(tmp_path: Path) -> None:
    install(tmp_path)
    p = paths(tmp_path)
    p.install_version.write_text("1.2\n")
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "recorded version is not a version" in out
    p.install_version.write_text("1.2.3\n")
    p.min_version.unlink()
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "floor cannot be read" in out
    p.min_version.write_text("1.0.0\n")
    p.install_version.unlink()
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "recorded version cannot be read" in out


@pytest.mark.parametrize("mode", [0o775, 0o757, 0o777])
def test_check_install_fails_for_a_release_folder_others_can_write(tmp_path: Path, mode: int) -> None:
    install(tmp_path)
    (tmp_path / "opt" / "releases" / "1.2.3").chmod(mode)
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "closed to group and others" in out


def test_check_install_changes_nothing(tmp_path: Path) -> None:
    install(tmp_path)

    def tree() -> dict[str, tuple[bool, int]]:
        return {
            str(p.relative_to(tmp_path)): (p.is_symlink(), p.lstat().st_mtime_ns) for p in sorted(tmp_path.rglob("*"))
        }

    before = tree()
    run(tmp_path, "check-install")
    assert tree() == before


# -- clear ---------------------------------------------------------------------------------------------------------


def test_clear_without_the_confirmation_shows_the_record_and_changes_nothing(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = ambiguous(ledger, 5000)
    before = ledger_bytes(tmp_path)
    code, out, err = run(tmp_path, "clear", FLAT)
    assert code == 2
    for part in (
        f"call: {cid}",
        f"model: {FLAT}",
        "kind: ambiguous",
        "started: 2026-10-30T12:00:00Z",
        f"reserved_usd: {format_usd(5000)}",
        "state: suspended",
        f"counted_usd: {format_usd(5000)}",
    ):
        assert part in out
    assert "--confirm" in err
    assert ledger_bytes(tmp_path) == before
    assert FLAT in ledger.view().suspended


def test_clear_with_a_wrong_or_partial_confirmation_changes_nothing(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = ambiguous(ledger)
    before = ledger_bytes(tmp_path)
    for wrong in (cid[:-1] + ("0" if cid[-1] != "0" else "1"), cid.upper(), cid[:8], "", FLAT, cid + " "):
        assert run(tmp_path, "clear", FLAT, "--confirm", wrong)[0] == 2
    assert run(tmp_path, "clear", FLAT, "--confirm", cid, "--confirm", "f" * 32)[0] == 2
    assert ledger_bytes(tmp_path) == before


def test_clear_of_an_ambiguous_call_settles_it_at_the_whole_reservation(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = ambiguous(ledger, 5000)
    before = month(ledger)
    code, out, _ = run(tmp_path, "clear", FLAT, "--confirm", cid)
    assert code == 0
    assert "cleared" in out
    view = ledger.view()
    assert FLAT not in view.suspended
    assert view.calls[cid].state is CallState.CLEARED
    assert view.calls[cid].counted_micro == 5000
    assert view.month_spent(LATER) == before == 5000
    action, resolved, cleared = last_rows(tmp_path, 3)
    assert action["type"] == "admin_action" and resolved["type"] == "ambiguous_resolved"
    assert cleared["type"] == "suspension_cleared"
    assert resolved["actual_micro"] == 5000
    assert (action["action"], action["uid"], action["sudo_uid"], action["model"]) == ("clear", 0, SUDO_USER, FLAT)
    assert action["ts"] == "2026-10-30T12:00:30Z"


def test_clear_records_no_sudo_uid_when_there_is_none_or_it_is_not_a_number(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = ambiguous(ledger)
    run(tmp_path, "clear", FLAT, "--confirm", cid, env={})
    assert last_rows(tmp_path, 3)[0]["sudo_uid"] == -1
    cid2 = ambiguous(ledger, now=LATER)
    run(tmp_path, "clear", FLAT, "--confirm", cid2, env={"SUDO_UID": "12; rm"})
    assert last_rows(tmp_path, 3)[0]["sudo_uid"] == -1
    cid3 = ambiguous(ledger, now=LATER)
    run(tmp_path, "clear", FLAT, "--confirm", cid3, env={"SUDO_UID": str(2**32)})
    assert last_rows(tmp_path, 3)[0]["sudo_uid"] == -1


def test_clear_of_a_breach_keeps_the_recorded_actual(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = breached(ledger, 5000, 9000)
    assert month(ledger) == 9000
    code, _, _ = run(tmp_path, "clear", FLAT, "--confirm", cid)
    assert code == 0
    assert ledger.view().month_spent(LATER) == 9000
    rows = last_rows(tmp_path, 2)
    assert [r["type"] for r in rows] == ["admin_action", "suspension_cleared"]  # nothing to resolve for a breach


def test_the_breach_record_is_shown_before_clearing(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = breached(ledger, 5000, 9000)
    _, out, _ = run(tmp_path, "clear", FLAT)
    assert "kind: breach" in out and f"recorded_actual_usd: {format_usd(9000)}" in out and cid in out


def test_clear_with_a_verified_actual_needs_a_reason_and_counts_that_amount(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = ambiguous(ledger, 5000)
    assert run(tmp_path, "clear", FLAT, "--confirm", cid, "--actual", f"{cid}=0.002")[0] == 2  # no reason
    assert FLAT in ledger.view().suspended
    code, _, _ = run(
        tmp_path, "clear", FLAT, "--confirm", cid, "--actual", f"{cid}=0.002", "--reason", "billing page 2026-10-30"
    )
    assert code == 0
    assert ledger.view().calls[cid].counted_micro == 2000
    action, resolved, _ = last_rows(tmp_path, 3)
    assert resolved["actual_micro"] == 2000
    assert action["reason"] == "billing page 2026-10-30"


def test_an_actual_above_the_reservation_is_counted_in_full(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = ambiguous(ledger, 5000)
    run(tmp_path, "clear", FLAT, "--confirm", cid, "--actual", f"{cid}=0.007", "--reason", "billed more")
    assert ledger.view().month_spent(LATER) == 7000


@pytest.mark.parametrize("bad", ["0.0000001", "-1", "1e3", "abc", "1000001", " 1", ""])
def test_an_actual_that_is_not_a_plain_bounded_amount_is_refused(tmp_path: Path, bad: str) -> None:
    ledger = new_ledger(tmp_path)
    cid = ambiguous(ledger)
    code, _, _ = run(tmp_path, "clear", FLAT, "--confirm", cid, "--actual", f"{cid}={bad}", "--reason", "r")
    assert code == 2
    assert FLAT in ledger.view().suspended


def test_an_actual_for_a_call_that_is_not_among_the_cause_or_is_a_breach_is_refused(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = breached(ledger)
    args = ("clear", FLAT, "--confirm", cid, "--reason", "r")
    assert run(tmp_path, *args, "--actual", f"{cid}=0.001")[0] == 2  # a breach is already counted at its actual
    assert run(tmp_path, *args, "--actual", f"{cid}=0.02")[0] == 2  # not even a higher figure: nothing to resolve
    assert run(tmp_path, *args, "--actual", f"{'a' * 32}=0.001")[0] == 2
    assert run(tmp_path, *args, "--actual", "nonsense")[0] == 2
    assert FLAT in ledger.view().suspended


def test_an_actual_below_the_usage_already_recorded_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = new_ledger(tmp_path)
    cid = ambiguous(ledger, 5000)
    original = CallLedger._view

    def with_usage(self: CallLedger) -> Any:
        view = original(self)
        view.calls[cid].actual_micro = 700
        return view

    monkeypatch.setattr(CallLedger, "_view", with_usage)
    with pytest.raises(IllegalTransition, match="recorded"):
        ledger.admin_clear(FLAT, [cid], {cid: 699}, "r", WHO, LATER)
    ledger.admin_clear(FLAT, [cid], {cid: 700}, "r", WHO, LATER)


def test_clear_of_a_model_that_is_not_suspended_is_refused(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    reserve(ledger)
    code, _, err = run(tmp_path, "clear", FLAT)
    assert code == 2 and "not suspended" in err
    assert run(tmp_path, "clear", "Bad Model!")[0] == 2


def test_clear_of_two_causes_needs_both_ids(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    one, two = reserve(ledger, 3000), reserve(ledger, 4000)
    assert sorted(ledger.recover(LATER)) == sorted([one, two])
    assert run(tmp_path, "clear", FLAT, "--confirm", one)[0] == 2
    assert FLAT in ledger.view().suspended
    code, out, _ = run(tmp_path, "clear", FLAT, "--confirm", one, "--confirm", two)
    assert code == 0 and one in out and two in out
    assert ledger.view().month_spent(LATER) == 7000


def test_the_confirmation_is_checked_against_the_ledger_as_it_is_when_the_lock_is_held(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    one, two = reserve(ledger, 3000), reserve(ledger, 4000)
    ledger.recover(LATER)
    with pytest.raises(IllegalTransition, match="confirm"):
        ledger.admin_clear(FLAT, [one], {}, "", WHO, LATER)  # a stale view that knew only one cause
    ledger.admin_clear(FLAT, [two, one], {}, "", WHO, LATER)


def test_clear_frees_no_room_under_the_month_cap(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = ambiguous(ledger, 9_000)
    small = Caps(job_micro=2_500_000, month_micro=10_000)
    req = flat_request(2_000)
    with pytest.raises(Exception, match="stopped"):
        ledger.reserve(req, approval(req), two_models(small), epoch=EPOCH, now=LATER)
    run(tmp_path, "clear", FLAT, "--confirm", cid)
    with pytest.raises(Exception, match="month"):
        ledger.reserve(req, approval(req), two_models(small), epoch=EPOCH, now=LATER)  # 9000 + 2000 > 10_000 still


def test_clear_validates_who_and_reason_in_the_ledger_itself(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = ambiguous(ledger)
    for who in (AdminWho(-1, 0), AdminWho(0, -2), AdminWho(2**32, 0), AdminWho(0, 2**32)):
        with pytest.raises(IllegalTransition):
            ledger.admin_clear(FLAT, [cid], {}, "", who, LATER)
    for reason in ("x" * 121, "tab\there", "line\nbreak", "café"):
        with pytest.raises(IllegalTransition):
            ledger.admin_clear(FLAT, [cid], {}, reason, WHO, LATER)
    with pytest.raises(IllegalTransition):
        ledger.admin_clear(FLAT, [cid], {cid: 1}, "", WHO, LATER)  # an actual with no reason
    assert FLAT in ledger.view().suspended


# -- crash points and torn writes ----------------------------------------------------------------------------------


def snapshot(tmp: Path, name: str) -> Path:
    target = tmp / name
    shutil.copytree(state_dir(tmp), target)
    return target


def restore(tmp: Path, copy: Path) -> None:
    shutil.rmtree(state_dir(tmp))
    shutil.copytree(copy, state_dir(tmp))


def test_a_kill_before_the_append_leaves_the_model_stopped_and_after_it_leaves_it_cleared(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = ambiguous(ledger)
    saved = snapshot(tmp_path, "saved")
    before = month(ledger)
    with pytest.raises(Crash):
        CallLedger(state_dir(tmp_path), faults=CrashAt("admin_before_append")).admin_clear(
            FLAT, [cid], {}, "", WHO, LATER
        )
    fresh = CallLedger(state_dir(tmp_path))
    assert FLAT in fresh.view().suspended and month(fresh) == before
    restore(tmp_path, saved)
    with pytest.raises(Crash):
        CallLedger(state_dir(tmp_path), faults=CrashAt("admin_after_append")).admin_clear(
            FLAT, [cid], {}, "", WHO, LATER
        )
    fresh = CallLedger(state_dir(tmp_path))
    assert FLAT not in fresh.view().suspended and month(fresh) == before
    assert fresh.recover(LATER) == []


def test_a_write_cut_anywhere_reads_back_as_suspended_or_cleared_and_never_costs_less(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = ambiguous(ledger, 5000)
    saved = snapshot(tmp_path, "saved")
    old = ledger_bytes(tmp_path)
    before = month(ledger)
    ledger.admin_clear(FLAT, [cid], {}, "", WHO, LATER)
    new = ledger_bytes(tmp_path)[len(old) :]
    boundaries = [i + 1 for i, byte in enumerate(new) if byte == 0x0A]
    assert len(boundaries) == 3
    cuts = sorted({*boundaries, *(b - 1 for b in boundaries), *range(0, len(new), 13)})
    seen = set()
    for cut in cuts:
        restore(tmp_path, saved)
        with open(state_dir(tmp_path) / "ledger.jsonl", "ab") as handle:
            handle.write(new[:cut])
        again = CallLedger(state_dir(tmp_path))
        again.recover(LATER)
        view = again.view()
        assert view.month_spent(LATER) >= before
        cleared = FLAT not in view.suspended
        seen.add(cleared)
        assert cleared == (cut >= len(new) - 1)  # only the whole group (a lost final newline aside) clears
        if not cleared:
            assert view.calls[cid].state in (CallState.SUSPENDED, CallState.AMBIGUOUS)
            again.admin_clear(FLAT, [cid], {}, "", WHO, LATER)  # and a second try finishes it
        assert FLAT not in again.view().suspended
        assert again.view().month_spent(LATER) == before
    assert seen == {True, False}


# -- reconcile -----------------------------------------------------------------------------------------------------


def test_reconcile_of_a_healthy_state_reports_nothing_and_changes_nothing(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = reserve(ledger)
    ledger.mark_sent(cid, NOW)
    ledger.settle(cid, "ok", 3000, NOW)
    before = ledger_bytes(tmp_path)
    code, out, _ = run(tmp_path, "reconcile")
    assert code == 0
    assert "mismatches: 0" in out
    assert f"spent_usd: {format_usd(3000)}" in out
    assert ledger_bytes(tmp_path) == before


def test_reconcile_reports_a_marker_with_no_ledger_row(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = reserve(ledger)
    ledger.mark_sent(cid, NOW)
    ledger.settle(cid, "ok", 1000, NOW)
    marker = next((state_dir(tmp_path) / "used").iterdir())
    data = json.loads(marker.read_text())
    stray = state_dir(tmp_path) / "used" / ("e" * 16)
    stray.write_text(json.dumps(data | {"nonce": "e" * 16, "call_id": "d" * 32}))
    stray.chmod(0o600)
    code, out, _ = run(tmp_path, "reconcile")
    assert code == 1
    assert f"marker {'e' * 16} has no ledger row" in out
    assert "mismatches: 1" in out


def test_reconcile_reports_a_call_with_no_marker_and_a_marker_that_disagrees(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    for reserved in (3000, 4000):
        cid = reserve(ledger, reserved)
        ledger.mark_sent(cid, NOW)
        ledger.settle(cid, "ok", 1000, NOW)
    markers = sorted((state_dir(tmp_path) / "used").iterdir())
    data = json.loads(markers[0].read_text())
    markers[1].unlink()
    markers[0].write_text(json.dumps(data | {"reserved_micro": data["reserved_micro"] - 1}))
    code, out, _ = run(tmp_path, "reconcile")
    assert code == 1
    assert "has no marker" in out
    assert f"marker {data['nonce']} disagrees with the ledger" in out
    assert "mismatches: 2" in out


def test_reconcile_reports_open_calls_and_unresolved_suspensions(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    reserve(ledger, 2000, model=OTHER)
    ambiguous(ledger)
    code, out, _ = run(tmp_path, "reconcile")
    assert code == 1
    assert "open call" in out
    assert "unresolved" in out
    assert "mismatches: 2" in out


def test_reconcile_reports_a_ledger_newer_than_the_clock(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    reserve(ledger, 2000, now=LATER)
    code, out, _ = run(tmp_path, "reconcile", now=NOW)
    assert code == 1 and "newer than the clock" in out


def test_reconcile_reports_a_broken_ledger_instead_of_a_traceback(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    reserve(ledger)
    path = state_dir(tmp_path) / "ledger.jsonl"
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:-1]))
    code, out, err = run(tmp_path, "reconcile")
    assert code == 1
    assert "ledger" in out + err
    assert "Traceback" not in out + err


def test_a_restore_is_caught_by_a_higher_billing_figure_which_is_added_never_replaced(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = reserve(ledger, 5000)
    ledger.mark_sent(cid, NOW)
    ledger.settle(cid, "ok", 4000, NOW)
    code, out, _ = run(
        tmp_path, "reconcile", "--billing-usd", "0.009", "--reason", "billing page", "--month", "2026-10"
    )
    assert code == 0
    assert f"adjusted_usd: {format_usd(5000)}" in out
    assert month(ledger) == 9000
    row = last_rows(tmp_path, 1)[0]
    assert (row["type"], row["action"], row["add_micro"], row["month"], row["uid"]) == (
        "admin_action",
        "adjust",
        5000,
        "2026-10",
        0,
    )
    again = run(tmp_path, "reconcile", "--billing-usd", "0.009", "--reason", "billing page")
    assert again[0] == 0 and "adjusted_usd: 0" in again[1]
    assert month(ledger) == 9000


def test_a_billing_figure_at_or_below_the_ledger_changes_nothing(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = reserve(ledger, 5000)
    ledger.mark_sent(cid, NOW)
    ledger.settle(cid, "ok", 5000, NOW)
    before = ledger_bytes(tmp_path)
    for figure in ("0.005", "0.004", "0"):
        code, out, _ = run(tmp_path, "reconcile", "--billing-usd", figure, "--reason", "r")
        assert code == 0 and "adjusted_usd: 0" in out
    assert ledger_bytes(tmp_path) == before
    assert month(ledger) == 5000


def test_a_billing_figure_needs_a_reason_a_sane_month_and_a_plain_amount(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    cid = reserve(ledger, 5000)
    ledger.mark_sent(cid, NOW)
    ledger.settle(cid, "ok", 5000, NOW)
    before = ledger_bytes(tmp_path)
    base = ("reconcile", "--billing-usd", "1")
    assert run(tmp_path, *base)[0] == 2  # no reason
    assert run(tmp_path, *base, "--reason", "r", "--month", "2026-11")[0] == 2  # next month: not yet
    assert run(tmp_path, *base, "--reason", "r", "--month", "x")[0] == 2
    assert run(tmp_path, "reconcile", "--billing-usd", "1e1", "--reason", "r")[0] == 2
    assert run(tmp_path, "reconcile", "--month", "2026-10")[0] == 0  # a month alone only reports
    assert ledger_bytes(tmp_path) == before


def test_the_adjustment_of_an_earlier_month_counts_in_that_month_only(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    reserve(ledger, 5000)
    run(tmp_path, "reconcile", "--billing-usd", "3", "--reason", "r", "--month", "2026-09")
    view = ledger.view()
    assert view.month_total("2026-09") == 3 * MICRO
    assert view.month_spent(LATER) == 5000
    assert "adjustments_usd: 3" in run(tmp_path, "usage", "--month", "2026-09")[1]


def test_a_kill_around_the_adjustment_leaves_it_fully_in_or_fully_out(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    reserve(ledger, 5000)
    saved = snapshot(tmp_path, "saved")
    for point, expected in (("admin_before_append", 5000), ("admin_after_append", 9000)):
        restore(tmp_path, saved)
        with pytest.raises(Crash):
            CallLedger(state_dir(tmp_path), faults=CrashAt(point)).admin_adjust("2026-10", 9000, "r", WHO, LATER)
        assert month(CallLedger(state_dir(tmp_path))) == expected


def test_adjust_validates_its_inputs_in_the_ledger_itself(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    reserve(ledger, 5000)
    bad: list[tuple[Any, ...]] = [
        ("2026-13", 9000, "r", WHO, LATER),
        ("2026-11", 9000, "r", WHO, LATER),
        ("2026-10", -1, "r", WHO, LATER),
        ("2026-10", 10**12 + 1, "r", WHO, LATER),
        ("2026-10", 9000, "", WHO, LATER),
        ("2026-10", 9000.5, "r", WHO, LATER),
        ("2026-10", True, "r", WHO, LATER),
        ("2026-10", 9000, "r", AdminWho(-1, 0), LATER),
    ]
    for args in bad:
        with pytest.raises(IllegalTransition):
            ledger.admin_adjust(*args)
    assert month(ledger) == 5000


# -- the property: no admin action lowers the spend or frees budget -------------------------------------------------


@pytest.mark.parametrize("seed", range(8))
def test_no_admin_action_lowers_the_month_or_frees_budget(tmp_path: Path, seed: int) -> None:
    rng = Rng(seed)
    ledger = new_ledger(tmp_path)
    models = [FLAT, OTHER]
    for _ in range(14):
        action = rng.choice(["ambiguous", "breach", "ok", "clear", "clear-actual", "reconcile", "reconcile-low"])
        model = rng.choice(models)
        view = ledger.view()
        before = view.month_spent(LATER)
        if action in ("ambiguous", "breach", "ok"):
            if model in view.suspended:
                continue
            reserved = 1000 * rng.randrange(1, 9) + 1
            reserved = reserved - ((reserved - 64) % 10)
            cid = reserve(ledger, reserved, model=model, now=LATER)
            ledger.mark_sent(cid, LATER)
            if action == "ambiguous":
                ledger.mark_ambiguous(cid, "timeout", LATER)
            elif action == "breach":
                ledger.settle(cid, "ok", reserved + 500, LATER)
            else:
                ledger.settle(cid, "ok", reserved // 2, LATER)
        elif action.startswith("clear"):
            ids = view.suspended.get(model)
            if not ids:
                continue
            args = ["clear", model] + [x for i in ids for x in ("--confirm", i)]
            unresolved = [i for i in ids if view.calls[i].unresolved]
            if action == "clear-actual" and unresolved:
                target = unresolved[0]
                amount = rng.randrange(0, view.calls[target].reserved_micro * 2)
                args += ["--actual", f"{target}={format_usd(amount)}", "--reason", "billing page"]
                assert run(tmp_path, *args)[0] == 0
                after = ledger.view()
                assert after.calls[target].counted_micro == amount  # exactly the verified figure, nothing else moves
                assert after.month_spent(LATER) == before - view.calls[target].counted_micro + amount
                continue
            assert run(tmp_path, *args)[0] == 0
            assert month(ledger) == before  # a plain clear never changes what is counted
        else:
            figure = format_usd(rng.randrange(0, before + 20_000)) if action == "reconcile" else "0"
            run(tmp_path, "reconcile", "--billing-usd", figure, "--reason", "r")
            assert month(ledger) >= before
    ledger.recover(LATER)  # whatever happened, a fresh recovery and a fresh read still agree with the rows
    ledger.view()


def test_usage_status_and_the_caps_use_the_same_month_figure(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    ambiguous(ledger, 5000)
    run(tmp_path, "reconcile", "--billing-usd", "0.007", "--reason", "r")
    assert ledger.view().month_spent(LATER) == 7000
    assert f"total_usd: {format_usd(7000)}" in run(tmp_path, "usage")[1]
    assert f"spent_usd: {format_usd(7000)}" in run(tmp_path, "status")[1]


def test_the_first_row_ever_written_by_an_adjustment_carries_the_given_time_not_the_clock(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    code, _, _ = run(tmp_path, "reconcile", "--billing-usd", "0.003", "--reason", "r")
    assert code == 0
    assert {row["ts"] for row in rows_of(tmp_path)} == {"2026-10-30T12:00:30Z"}
    assert month(ledger) == 3000


def rows_of(tmp: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (state_dir(tmp) / "ledger.jsonl").read_text().splitlines()]


@pytest.mark.parametrize(
    "fields",
    [
        {"action": "clear", "model": FLAT, "month": "", "add_micro": 5},  # a clear adds nothing
        {"action": "clear", "model": "", "month": "", "add_micro": 0},  # a clear names a model
        {"action": "clear", "model": FLAT, "month": "2026-10", "add_micro": 0},
        {"action": "adjust", "model": FLAT, "month": "2026-10", "add_micro": 5},  # an adjustment names no model
        {"action": "adjust", "model": "", "month": "", "add_micro": 5},
        {"action": "adjust", "model": "", "month": "2026-10", "add_micro": 0},  # and adds something
        {"action": "adjust", "model": "", "month": "2026-11", "add_micro": 5},  # and never for a future month
    ],
)
def test_a_forged_admin_row_with_a_pairing_the_command_never_writes_makes_the_ledger_unreadable(
    tmp_path: Path, fields: dict[str, Any]
) -> None:
    ledger = new_ledger(tmp_path)
    reserve(ledger)
    row = {
        "type": "admin_action",
        "ts": "2026-10-30T12:00:30Z",
        "v": 3,
        "uid": 0,
        "sudo_uid": -1,
        "reason": "",
    } | fields
    ledger.ledger.append_many([row], ts="2026-10-30T12:00:30Z")
    with pytest.raises(LedgerError):
        ledger.view()
    assert run(tmp_path, "status")[0] == 2


def test_an_admin_row_goes_through_the_strict_row_shape(tmp_path: Path) -> None:
    ledger = new_ledger(tmp_path)
    reserve(ledger)
    good = {
        "type": "admin_action",
        "ts": "2026-10-30T12:00:30Z",
        "v": 3,
        "action": "adjust",
        "uid": 0,
        "sudo_uid": -1,
        "model": "",
        "month": "2026-10",
        "add_micro": 5,
        "reason": "r",
    }
    for bad in ({"uid": -1}, {"sudo_uid": -2}, {"uid": True}, {"reason": "tab\t"}, {"extra": 1}, {"action": "other"}):
        shutil.copytree(state_dir(tmp_path), tmp_path / "copy", dirs_exist_ok=True)
        copy = CallLedger(tmp_path / "copy")
        copy.ledger.append_many([good | bad], ts="2026-10-30T12:00:30Z")
        with pytest.raises(LedgerError):
            copy.view()
        shutil.rmtree(tmp_path / "copy")
    copy2 = CallLedger(state_dir(tmp_path))
    copy2.ledger.append_many([good], ts="2026-10-30T12:00:30Z")
    assert copy2.view().month_total("2026-10") == 5005


def plant(tmp: Path) -> tuple[Path, Path]:
    """Modules an operator's directory or environment could hold, named like what the command imports first."""
    folder, marker = tmp / "planted", tmp / "ran"
    folder.mkdir()
    for name in ("pwd", "argparse", "dataclasses"):
        (folder / f"{name}.py").write_text(f"open({str(marker)!r}, 'w').write('x')\n")
    return folder, marker


def start(folder: Path, *, isolated: bool) -> subprocess.CompletedProcess[str]:
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(folder)}
    if isolated:
        return subprocess.run(
            [sys.executable, "-I", "-m", "safo.broker.admin", "status"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=folder,
            env=env,
        )
    return subprocess.run(
        [sys.executable, "-B", "-m", "safo.broker.admin", "status"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        cwd=folder,
        env=env,
    )


def test_an_isolated_start_imports_nothing_from_the_working_directory_or_the_python_path(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("this check expects a non-root test run")
    folder, marker = plant(tmp_path)
    done = start(folder, isolated=True)
    assert not marker.exists()
    assert done.returncode == 2 and "root" in done.stderr


def test_a_start_that_is_not_isolated_is_refused_before_anything_is_imported(tmp_path: Path) -> None:
    folder, marker = plant(tmp_path)
    done = start(folder, isolated=False)  # no -I: the planted modules are on the path
    assert not marker.exists()
    assert done.returncode == 2
    assert "python -I -m safo.broker.admin" in done.stderr
    assert done.stdout == ""


def test_the_entry_function_refuses_when_python_was_not_started_isolated(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert not sys.flags.isolated  # the test runner itself is not isolated
    monkeypatch.setattr(sys, "argv", ["admin", "status"])
    assert admin.main() == 2
    assert "refusing to run" in capsys.readouterr().err


def test_the_usage_lines_name_the_isolated_command() -> None:
    assert all(
        "python -I -m safo.broker.admin" in line
        for line in admin.USAGE.splitlines()
        if "usage" in line or "   " in line
    )
    assert "python -m" not in admin.USAGE and "python -m" not in (admin.__doc__ or "").replace("python -I -m", "")


# -- check-install: what the docs claim beyond the link, the record and the floor (issue 288) -----------------------


def test_a_complete_install_reports_units_helper_and_switch(tmp_path: Path) -> None:
    install(tmp_path)
    code, out, _ = run(tmp_path, "check-install")
    assert code == 0, out
    assert "units: 5 match the signed release" in out
    assert "release version file: 1.2.3" in out
    assert "egress helper: root-owned and executable" in out
    assert "switch: absent (paid use is off)" in out
    assert "egress mode: drop" in out


def test_a_unit_that_differs_from_the_release_fails(tmp_path: Path) -> None:
    install(tmp_path)
    unit = paths(tmp_path).unit_dir / "safo-broker.service"
    unit.write_bytes(unit.read_bytes() + b"ExecStartPre=/bin/true\n")
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "fail: unit safo-broker.service differs from the signed release" in out


@pytest.mark.parametrize("name", UNIT_NAMES)
def test_every_unit_is_checked_and_a_missing_one_fails(tmp_path: Path, name: str) -> None:
    install(tmp_path)
    (paths(tmp_path).unit_dir / name).unlink()
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and f"fail: unit {name} is missing" in out


def test_a_symlinked_or_writable_unit_fails(tmp_path: Path) -> None:
    install(tmp_path)
    unit = paths(tmp_path).unit_dir / "safo-broker.socket"
    unit.chmod(0o664)
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "unit safo-broker.socket" in out and "writable" in out
    unit.unlink()
    real = tmp_path / "real.socket"
    real.write_bytes(unit_text("safo-broker.socket"))
    real.chmod(0o644)
    unit.symlink_to(real)
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "fail: unit safo-broker.socket is a symbolic link" in out


def test_a_release_unit_that_differs_from_the_manifest_fails(tmp_path: Path) -> None:
    install(tmp_path)
    release = tmp_path / "opt" / "releases" / "1.2.3"
    changed = unit_text("safo-broker.service") + b"# changed\n"
    (release / "units" / "safo-broker.service").write_bytes(changed)
    (paths(tmp_path).unit_dir / "safo-broker.service").write_bytes(
        changed
    )  # installed == release, but not the manifest
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "does not match the release manifest" in out


def test_a_missing_manifest_or_manifest_line_fails(tmp_path: Path) -> None:
    install(tmp_path)
    manifest = tmp_path / "opt" / "releases" / "1.2.3" / "MANIFEST.sha256"
    kept = [x for x in manifest.read_text().splitlines() if "safo-broker.timer" not in x and "refresh.timer" not in x]
    manifest.write_text("\n".join(kept) + "\n")
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "no line for units/safo-broker-egress-refresh.timer" in out
    manifest.unlink()
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "release manifest cannot be read" in out


def test_the_release_version_file_must_match_the_folder(tmp_path: Path) -> None:
    install(tmp_path)
    version = tmp_path / "opt" / "releases" / "1.2.3" / "VERSION"
    version.write_text("1.2.4\n")
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "release version file says 1.2.4, the folder is 1.2.3" in out
    version.unlink()
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "release version file cannot be read" in out


def test_the_egress_helper_must_exist_be_root_owned_executable_and_closed(tmp_path: Path) -> None:
    install(tmp_path)
    helper = paths(tmp_path).egress_helper
    helper.chmod(0o644)
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "egress helper is not executable" in out
    helper.chmod(0o775)
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "egress helper" in out and "writable" in out
    helper.unlink()
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "egress helper" in out and "missing" in out


def test_a_symlinked_egress_helper_fails(tmp_path: Path) -> None:
    install(tmp_path)
    helper = paths(tmp_path).egress_helper
    real = tmp_path / "real-helper"
    real.write_text("#!/bin/sh\n")
    real.chmod(0o755)
    helper.unlink()
    helper.symlink_to(real)
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "egress helper" in out and "symbolic link" in out


def test_the_helper_owner_check_names_a_wrong_owner(tmp_path: Path) -> None:
    helper = tmp_path / "h"
    helper.write_text("x")
    helper.chmod(0o755)
    assert admin._helper_problem(helper, os.getuid()) == ""
    assert "owned by" in admin._helper_problem(helper, os.getuid() + 1)


def test_the_switch_state_is_reported_and_an_invalid_file_fails(tmp_path: Path) -> None:
    install(tmp_path)
    switch = paths(tmp_path).switch
    switch.write_text("enabled\n")
    switch.chmod(0o644)
    code, out, _ = run(tmp_path, "check-install")
    assert code == 0 and "switch: enabled" in out
    switch.write_text("yes\n")
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "fail: the switch file exists but the broker would treat it as off" in out
    switch.write_text("enabled\n")
    switch.chmod(0o666)
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "broker would treat it as off" in out


def test_an_enabled_switch_with_the_egress_control_in_observe_mode_is_noted(tmp_path: Path) -> None:
    install(tmp_path)
    p = paths(tmp_path)
    p.switch.write_text("enabled\n")
    p.switch.chmod(0o644)
    p.egress_conf.write_text("VENDOR_HOST=api.vendor.example\nMODE=observe\n")
    code, out, _ = run(tmp_path, "check-install")
    assert code == 0
    assert "note: paid use is enabled while the egress control is in observe mode" in out
    p.egress_conf.unlink()
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "fail: paid use is enabled but the egress config cannot be read" in out


def test_the_unit_list_here_equals_the_installers() -> None:
    import safo_broker_install as installer

    assert admin.UNIT_NAMES == installer.UNIT_NAMES == UNIT_NAMES


# -- check-install runs the root-door checks (#293) ------------------------------------------------------------------

DOOR_NAMES = ("sudo", "groups", "polkit", "writable", "jobs", "preload", "setuid", "credential")


def run_with_door(tmp: Path, door: DoorPaths, *, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = admin.run(
        ["check-install"],
        ops=FakeOps().as_ops(),
        paths=dataclasses.replace(paths(tmp), door=door),
        env={"SUDO_UID": str(SUDO_USER)} if env is None else env,
        now=LATER,
        out=out,
        err=err,
    )
    return code, out.getvalue(), err.getvalue()


def test_check_install_reports_every_root_door_check_and_passes_on_a_clean_machine(tmp_path: Path) -> None:
    install(tmp_path)
    code, out, _ = run(tmp_path, "check-install")
    assert code == 0
    for name in DOOR_NAMES:
        assert f"pass: {name}: " in out
    assert "not checked here" not in out
    assert out.rstrip().splitlines()[-1].startswith("limits: ")


def test_a_root_door_failure_makes_check_install_exit_1(tmp_path: Path) -> None:
    install(tmp_path)
    (tmp_path / "doors" / "w" / "sudoers.d" / "10-me").write_text("ALL ALL=(ALL) NOPASSWD: ALL\n")
    (tmp_path / "doors" / "w" / "sudoers.d" / "10-me").chmod(0o440)
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "fail: sudo: " in out


def test_a_root_door_warning_alone_keeps_exit_0_but_is_not_called_ok(tmp_path: Path) -> None:
    install(tmp_path)
    (tmp_path / "doors" / "w" / "home" / "maint" / ".doppler").mkdir()
    code, out, _ = run(tmp_path, "check-install")
    assert code == 0 and "warn: credential: " in out


def test_check_install_without_sudo_uid_warns_for_the_account_checks_and_fails_nothing(tmp_path: Path) -> None:
    install(tmp_path)
    out_code, out, _ = run(tmp_path, "check-install", env={})
    assert out_code == 0
    for name in ("sudo", "groups", "polkit", "writable", "jobs", "setuid", "credential"):
        assert f"warn: {name}: " in out
    assert "pass: preload: " in out


def test_check_install_scans_the_brokers_own_folders_for_writable_paths(tmp_path: Path) -> None:
    install(tmp_path)
    release = tmp_path / "opt" / "releases" / "1.2.3"
    release.chmod(0o755)
    (release / "units" / "safo-broker.service").chmod(0o666)
    code, out, _ = run_with_door(tmp_path, door_paths(tmp_path))
    assert code == 1 and "fail: writable: " in out and "safo-broker.service" in out
    state = state_dir(tmp_path)
    assert str(state) not in out  # an unrelated folder is not named


def test_check_install_door_checks_leave_the_ledger_and_the_tree_alone(tmp_path: Path) -> None:
    install(tmp_path)
    ops = FakeOps()
    before = sorted(str(p) for p in tmp_path.rglob("*"))
    code, _, _ = run(tmp_path, "check-install", ops=ops)
    assert code == 0 and ops.log == []
    assert sorted(str(p) for p in tmp_path.rglob("*")) == before


# -- check-install reads the egress config by the helper's rules (#299) ------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "VENDOR_HOST=api.vendor.example\nVENDOR_HOST=api.vendor.example\nMODE=drop\n",
        "VENDOR_HOST=api.vendor.example\nMODE=observe\nMODE=drop\n",
        "MODE=drop\n",
        "VENDOR_HOST=\nMODE=drop\n",
        "VENDOR_HOST=api.vendor.example\nMODE=allow\n",
        "VENDOR_HOST=api.vendor.example\nEXTRA=1\n",
    ],
    ids=["duplicate host", "duplicate mode", "missing host", "empty host", "bad mode", "unknown key"],
)
@pytest.mark.parametrize("switch_on", [False, True])
def test_check_install_fails_on_an_egress_config_the_helper_refuses(tmp_path: Path, text: str, switch_on: bool) -> None:
    install(tmp_path)
    p = paths(tmp_path)
    if switch_on:
        p.switch.write_text("enabled\n")
        p.switch.chmod(0o644)
    p.egress_conf.write_text(text)
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1, out
    assert "fail: the egress config is refused by the egress helper's rules" in out
    assert "egress mode:" not in out


def test_check_install_fails_on_an_egress_config_that_is_not_text(tmp_path: Path) -> None:
    install(tmp_path)
    junk = bytes([0xFF, 0xFE, 0x0A])  # not UTF-8; the helper's strict read refuses it
    paths(tmp_path).egress_conf.write_bytes(b"VENDOR_HOST=api.vendor.example\nMODE=drop\n" + junk)
    code, out, _ = run(tmp_path, "check-install")
    assert code == 1 and "fail: the egress config is refused by the egress helper's rules" in out
