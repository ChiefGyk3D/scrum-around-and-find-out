# SPDX-License-Identifier: Apache-2.0
"""The read-only enrollment preflight (#263): every check takes its paths and its command runner as parameters.

The tests use temporary directories and a fake runner. They prove the checker reports each state, changes nothing (it
runs on a tree it cannot write to, and the tree is compared before and after), runs only the commands on its read-only
list, and never prints a secret or a key line.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import io
import os
import pwd
import shutil
import stat
import struct
from collections.abc import Sequence
from pathlib import Path

import pytest

from safo import gemini_preflight as pf

NS = "safo-gemini-approval"
EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


# built at run time so no key-shaped literal sits in the tree (the secret scan reads every commit); each is a public key
# blob of exactly the shape its type has, which is what the broker's own parser demands
def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _blob(*parts: bytes) -> str:
    return base64.b64encode(b"".join(_string(p) for p in parts)).decode()


SK = "sk-ssh-ed25519@openssh.com"
KEY_B64 = _blob(SK.encode(), bytes(range(32)), b"ssh:")  # an sk key
KEY_B2_B64 = _blob(SK.encode(), bytes(range(64, 96)), b"ssh:")  # another sk key
KEY_SOFT_B64 = _blob(b"ssh-ed25519", bytes(range(100, 132)))  # a software key
VENDOR = "api" + ".vendor.example"  # a stand-in host name; the report must never print it
SECRET = "BEGIN OPENSSH PRIVATE KEY topsecretmaterial"
ALLOWED_COMMANDS = {
    ("ssh", "-Q", "key"),
    ("ldconfig", "-p"),
    ("fido2-token", "-L"),
    ("ssh-add", "-L"),
}


class FakeRunner:
    """Answers only the read-only commands; records every argv so a test can prove nothing else was asked."""

    def __init__(self, answers: dict[tuple[str, ...], pf.RunResult | None] | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        base: dict[tuple[str, ...], pf.RunResult | None] = {
            ("ssh", "-Q", "key"): pf.RunResult(
                0, "ssh-ed25519\nsk-ssh-ed25519@openssh.com\nsk-ecdsa-sha2-nistp256@openssh.com\n"
            ),
            ("ldconfig", "-p"): pf.RunResult(
                0, "\tlibfido2.so.1 (libc6,x86-64) => /lib/x86_64-linux-gnu/libfido2.so.1\n"
            ),
            ("fido2-token", "-L"): pf.RunResult(0, "/dev/hidraw3: vendor=0x1050, product=0x0407 (Yubico YubiKey)\n"),
            ("ssh-add", "-L"): pf.RunResult(0, f"sk-ssh-ed25519@openssh.com {KEY_B64} comment\n"),
        }
        base.update(answers or {})
        self.answers = base

    def __call__(self, argv: Sequence[str]) -> pf.RunResult:
        key = tuple(argv)
        self.calls.append(key)
        answer = self.answers.get(key)
        if answer is None:
            raise FileNotFoundError(argv[0])
        return answer


def make_tree(tmp_path: Path, *, signers_lines: list[str] | None = None) -> pf.Locations:
    root = tmp_path / "root"
    etc = root / "etc" / "safo"
    etc.mkdir(parents=True)
    signers = etc / "gemini-allowed-signers"
    lines = (
        signers_lines
        if signers_lines is not None
        else [f'yubikey-a namespaces="{NS}" sk-ssh-ed25519@openssh.com {KEY_B64}']
    )
    signers.write_text("# a comment\n\n" + "\n".join(lines) + "\n")
    signers.chmod(0o644)
    etc.chmod(0o755)
    udev = root / "udev"
    udev.mkdir()
    (udev / "70-u2f.rules").write_text(
        'KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", '
        'TAG+="uaccess", GROUP="plugdev", MODE="0660"\n'
    )
    helper = root / "openssh"
    helper.mkdir()
    (helper / "ssh-sk-helper").write_text("")
    conf = etc / "broker-egress.conf"
    conf.write_text(f"VENDOR_HOST={VENDOR}\nMODE=drop\n")
    conf.chmod(0o644)
    state = root / "state"
    state.mkdir()
    state.chmod(0o700)
    (state / "epoch").write_text("x")
    (state / "epoch").chmod(0o600)
    broker = etc / "broker.yaml"
    broker.write_text(
        (EXAMPLES / "broker.example.yaml").read_text().replace("allowed_uids: []", "allowed_uids: [1000]")
    )
    broker.chmod(0o644)
    client = root / "home" / ".config" / "safo" / "broker-client.yaml"
    client.parent.mkdir(parents=True)
    shutil.copyfile(EXAMPLES / "broker-client.example.yaml", client)
    client.chmod(0o600)
    return pf.Locations(
        broker_config=broker,
        client_config=client,
        client_root_config=root / "etc-client" / "broker-client.yaml",  # absent unless a test writes it
        allowed_signers=signers,
        switch=etc / "gemini-paid-enabled",
        egress_conf=conf,
        state_dir=state,
        udev_dirs=(udev,),
        sk_helper_dirs=(helper,),
        service_user="safo-broker",
        trust_uid=os.getuid(),
    )


def lookup_ok(name: str) -> int | None:
    return os.getuid() if name == "safo-broker" else None


def lookup_none(name: str) -> int | None:
    return None


def by_name(checks: list[pf.Check]) -> dict[str, pf.Check]:
    return {c.name: c for c in checks}


def test_a_complete_setup_passes_every_check_and_exits_zero(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    checks = pf.run_preflight(loc, FakeRunner(), lookup_ok)
    got = by_name(checks)
    assert {c.status for c in checks} == {"pass"}, [(c.name, c.status, c.detail) for c in checks]
    assert got["switch"].detail.startswith("absent")
    assert pf.exit_code(checks) == 0


def test_the_output_has_one_status_line_per_check(tmp_path: Path) -> None:
    checks = pf.run_preflight(make_tree(tmp_path), FakeRunner(), lookup_ok)
    lines = pf.render(checks).splitlines()
    assert len(lines) == len(checks) >= 8
    assert all(line.split(" ", 1)[0] in {"PASS", "WARN", "FAIL"} for line in lines)


def test_ssh_without_sk_key_types_fails(tmp_path: Path) -> None:
    runner = FakeRunner({("ssh", "-Q", "key"): pf.RunResult(0, "ssh-ed25519\nssh-rsa\n")})
    got = by_name(pf.run_preflight(make_tree(tmp_path), runner, lookup_ok))
    assert got["ssh-sk-support"].status == "fail"


def test_a_missing_sk_helper_fails_even_when_the_types_are_listed(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    (loc.sk_helper_dirs[0] / "ssh-sk-helper").unlink()
    got = by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))
    assert got["ssh-sk-support"].status == "fail"


def test_libfido2_missing_fails(tmp_path: Path) -> None:
    runner = FakeRunner({("ldconfig", "-p"): pf.RunResult(0, "\tlibc.so.6 => /lib/libc.so.6\n")})
    got = by_name(pf.run_preflight(make_tree(tmp_path), runner, lookup_ok))
    assert got["libfido2"].status == "fail"


def test_a_missing_ldconfig_is_a_warning_not_a_crash(tmp_path: Path) -> None:
    runner = FakeRunner({("ldconfig", "-p"): None})
    got = by_name(pf.run_preflight(make_tree(tmp_path), runner, lookup_ok))
    assert got["libfido2"].status == "warn"


def test_no_udev_rule_for_the_key_class_warns(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    (loc.udev_dirs[0] / "70-u2f.rules").write_text('KERNEL=="hidraw*", ATTRS{idVendor}=="dead"\n')
    got = by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))
    assert got["udev-rule"].status == "warn"
    assert pf.exit_code(pf.run_preflight(loc, FakeRunner(), lookup_ok)) == 0
    assert pf.exit_code(pf.run_preflight(loc, FakeRunner(), lookup_ok), strict=True) == 1


def test_a_key_in_the_agent_that_matches_an_enrolled_signer_passes(tmp_path: Path) -> None:
    got = by_name(pf.run_preflight(make_tree(tmp_path), FakeRunner(), lookup_ok))
    assert got["hardware-key"].status == "pass"
    assert "yubikey-a" in got["hardware-key"].detail and "enrolled" in got["hardware-key"].detail


def test_an_authenticator_alone_cannot_be_tied_to_an_enrolled_signer(tmp_path: Path) -> None:
    """The finding D4 case: a visible device passed before; now it warns, because nothing links it to the enrollment."""
    runner = FakeRunner({("ssh-add", "-L"): pf.RunResult(1, "The agent has no identities.\n")})
    got = by_name(pf.run_preflight(make_tree(tmp_path), runner, lookup_ok))
    assert got["hardware-key"].status == "warn"
    assert "cannot be tied to an enrolled signer" in got["hardware-key"].detail


def test_a_visible_key_that_no_allowed_signers_line_matches_warns_clearly(tmp_path: Path) -> None:
    other = base64.b64encode(b"\x00\x00\x00\x1bsk-ssh-ed25519@openssh.com" + b"\x01" * 40).decode()
    runner = FakeRunner({("ssh-add", "-L"): pf.RunResult(0, f"sk-ssh-ed25519@openssh.com {other} c\n")})
    got = by_name(pf.run_preflight(make_tree(tmp_path), runner, lookup_ok))
    assert got["hardware-key"].status == "warn"
    assert "no allowed-signers entry matches the visible key" in got["hardware-key"].detail
    assert other not in pf.render(pf.run_preflight(make_tree(tmp_path / "again"), runner, lookup_ok))


def test_the_configured_key_file_is_matched_against_the_enrollment(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    runner = FakeRunner({("ssh-add", "-L"): pf.RunResult(1, "The agent has no identities.\n")})
    pub = tmp_path / "approval_key.pub"
    pub.write_text(f"sk-ssh-ed25519@openssh.com {KEY_B64} comment\n")
    got = by_name(pf.run_preflight(dataclasses.replace(loc, key_file=tmp_path / "approval_key"), runner, lookup_ok))
    assert got["hardware-key"].status == "pass"
    assert "key file" in got["hardware-key"].detail and "yubikey-a" in got["hardware-key"].detail


def test_a_configured_key_file_that_is_not_enrolled_warns(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    runner = FakeRunner({("ssh-add", "-L"): pf.RunResult(1, "The agent has no identities.\n")})
    other = base64.b64encode(b"\x00\x00\x00\x1bsk-ssh-ed25519@openssh.com" + b"\x02" * 40).decode()
    pub = tmp_path / "approval_key.pub"
    pub.write_text(f"sk-ssh-ed25519@openssh.com {other} comment\n")
    got = by_name(pf.run_preflight(dataclasses.replace(loc, key_file=pub), runner, lookup_ok))
    assert got["hardware-key"].status == "warn"
    assert "no allowed-signers entry matches the visible key" in got["hardware-key"].detail


def test_a_configured_key_file_with_a_software_key_type_warns(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    pub = tmp_path / "soft.pub"
    pub.write_text(f"ssh-ed25519 {KEY_B64} comment\n")
    got = by_name(pf.run_preflight(dataclasses.replace(loc, key_file=pub), FakeRunner(), lookup_ok))
    assert "not a hardware key type" in got["hardware-key"].detail


def test_an_enrolled_software_key_never_makes_the_check_pass(tmp_path: Path) -> None:
    loc = make_tree(tmp_path, signers_lines=[f'soft namespaces="{NS}" ssh-ed25519 {KEY_SOFT_B64}'])
    runner = FakeRunner({("ssh-add", "-L"): pf.RunResult(0, f"ssh-ed25519 {KEY_SOFT_B64} comment\n")})
    got = by_name(pf.run_preflight(loc, runner, lookup_ok))
    assert got["hardware-key"].status == "warn"


def test_the_fingerprint_is_the_sha256_of_the_decoded_blob() -> None:
    blob = b"\x00\x00\x00\x0bsk-ssh-test" + bytes(range(20))
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    assert pf.fingerprint(base64.b64encode(blob).decode()) == expected
    assert pf.fingerprint("not base64 !!") is None


def test_no_key_visible_warns(tmp_path: Path) -> None:
    runner = FakeRunner(
        {("fido2-token", "-L"): pf.RunResult(0, ""), ("ssh-add", "-L"): pf.RunResult(1, "no identities\n")}
    )
    got = by_name(pf.run_preflight(make_tree(tmp_path), runner, lookup_ok))
    assert got["hardware-key"].status == "warn"


def test_a_software_agent_key_is_not_a_hardware_key(tmp_path: Path) -> None:
    runner = FakeRunner(
        {
            ("fido2-token", "-L"): pf.RunResult(0, ""),
            ("ssh-add", "-L"): pf.RunResult(0, f"ssh-ed25519 {KEY_B64} comment\n"),
        }
    )
    got = by_name(pf.run_preflight(make_tree(tmp_path), runner, lookup_ok))
    assert got["hardware-key"].status == "warn"


def test_missing_allowed_signers_fails(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    loc.allowed_signers.unlink()
    got = by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))
    assert got["allowed-signers"].status == "fail"


def broker_reads(path: Path) -> bool:
    """Whether the broker's own trusted-file reader takes the file (owner and mode rules of `read_trust_file`)."""
    from safo import geminisign
    from safo.gemini import RefusedError

    try:
        geminisign.read_trust_file(path, os.getuid(), "file")
    except RefusedError:
        return False
    return True


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644, 0o444, 0o755, 0o700])
def test_a_mode_the_broker_accepts_passes_for_the_signers_the_switch_and_the_egress_config(
    tmp_path: Path, mode: int
) -> None:
    """The broker takes any root-owned file that group and others cannot write; the preflight uses its rule (#299)."""
    loc = make_tree(tmp_path)
    loc.allowed_signers.chmod(mode)
    loc.switch.write_text("enabled\n")
    loc.switch.chmod(mode)
    loc.egress_conf.chmod(mode)
    for path in (loc.allowed_signers, loc.switch, loc.egress_conf):
        assert broker_reads(path), (path.name, mode)
    got = by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))
    assert got["allowed-signers"].status == "pass", got["allowed-signers"].detail
    assert got["switch"].status == "warn"  # present: not a failure
    assert got["egress-mode"].status != "fail", got["egress-mode"].detail


@pytest.mark.parametrize("mode", [0o664, 0o666, 0o620, 0o602, 0o646])
def test_a_mode_the_broker_refuses_fails_for_the_signers_the_switch_and_the_egress_config(
    tmp_path: Path, mode: int
) -> None:
    loc = make_tree(tmp_path)
    loc.allowed_signers.chmod(mode)
    loc.switch.write_text("enabled\n")
    loc.switch.chmod(mode)
    loc.egress_conf.chmod(mode)
    for path in (loc.allowed_signers, loc.switch, loc.egress_conf):
        assert not broker_reads(path), (path.name, mode)
    got = by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))
    assert got["allowed-signers"].status == "fail" and "writable" in got["allowed-signers"].detail
    assert got["switch"].status == "fail"
    assert got["egress-mode"].status == "fail"


def test_the_preflight_uses_the_brokers_mode_rule_not_its_own_number() -> None:
    from safo import geminisign

    source = Path(pf.__file__).read_text()
    assert "0o644" not in source and "geminisign.writable_by_others(" in source
    assert geminisign.writable_by_others(0o664) and not geminisign.writable_by_others(0o600)


def test_allowed_signers_owned_by_someone_else_fails(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    other = pf.Locations(**{**loc.__dict__, "trust_uid": os.getuid() + 1})
    got = by_name(pf.run_preflight(other, FakeRunner(), lookup_ok))
    assert got["allowed-signers"].status == "fail"
    assert "owner" in got["allowed-signers"].detail


def test_a_symlinked_allowed_signers_file_fails(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    real = loc.allowed_signers.with_name("real")
    loc.allowed_signers.rename(real)
    loc.allowed_signers.symlink_to(real)
    got = by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))
    assert got["allowed-signers"].status == "fail"


def test_a_group_writable_parent_directory_fails(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    loc.allowed_signers.parent.chmod(0o775)
    got = by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))
    assert got["allowed-signers"].status == "fail"


def test_a_line_without_the_namespace_fails_and_names_only_its_number(tmp_path: Path) -> None:
    loc = make_tree(
        tmp_path,
        signers_lines=[
            f'a namespaces="{NS}" sk-ssh-ed25519@openssh.com {KEY_B64}',
            f"b sk-ssh-ed25519@openssh.com {KEY_B64}",
        ],
    )
    got = by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))
    check = got["allowed-signers"]
    assert check.status == "fail"
    assert "line 4" in check.detail and "line 3" not in check.detail
    assert KEY_B64 not in check.detail


def test_a_wrong_or_wide_namespace_fails(tmp_path: Path) -> None:
    for bad in ('namespaces="file"', 'namespaces="*"', f'namespaces="{NS},file"', f'namespaces="{NS}-dryrun"'):
        loc = make_tree(
            tmp_path / bad.replace('"', "").replace("*", "star").replace(",", "_").replace("=", "_"),
            signers_lines=[f"a {bad} ssh-ed25519 {KEY_B64}"],
        )
        got = by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))
        assert got["allowed-signers"].status == "fail", bad


def test_an_empty_allowed_signers_file_fails_because_nothing_can_approve(tmp_path: Path) -> None:
    loc = make_tree(tmp_path, signers_lines=[])
    got = by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))
    assert got["allowed-signers"].status == "fail"


def test_private_key_text_in_the_signers_file_fails_without_echoing_it(tmp_path: Path) -> None:
    loc = make_tree(tmp_path, signers_lines=[SECRET])
    out = pf.render(pf.run_preflight(loc, FakeRunner(), lookup_ok))
    assert "FAIL allowed-signers" in out
    assert "topsecretmaterial" not in out


def test_switch_absent_passes_and_present_warns(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    assert by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))["switch"].status == "pass"
    loc.switch.write_text("enabled\n")
    loc.switch.chmod(0o644)
    got = by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))["switch"]
    assert got.status == "warn"
    assert "present" in got.detail


def test_a_switch_with_the_wrong_mode_fails(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    loc.switch.write_text("enabled\n")
    loc.switch.chmod(0o666)
    assert by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))["switch"].status == "fail"


def test_a_symlinked_switch_fails(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    target = loc.switch.with_name("elsewhere")
    target.write_text("enabled\n")
    loc.switch.symlink_to(target)
    assert by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))["switch"].status == "fail"


def test_a_missing_service_user_fails(tmp_path: Path) -> None:
    got = by_name(pf.run_preflight(make_tree(tmp_path), FakeRunner(), lookup_none))
    assert got["service-user"].status == "fail"


def test_a_missing_state_directory_warns_because_systemd_makes_it_at_first_start(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    (loc.state_dir / "epoch").unlink()
    loc.state_dir.rmdir()
    assert by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))["state-dir"].status == "warn"


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o770])
def test_a_state_directory_that_is_not_0700_fails(tmp_path: Path, mode: int) -> None:
    loc = make_tree(tmp_path)
    loc.state_dir.chmod(mode)
    assert by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))["state-dir"].status == "fail"


def test_a_state_file_that_is_not_0600_fails(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    (loc.state_dir / "epoch").chmod(0o644)
    got = by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))["state-dir"]
    assert got.status == "fail"
    assert "epoch" in got.detail


def test_a_state_directory_owned_by_another_user_fails(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    got = by_name(pf.run_preflight(loc, FakeRunner(), lambda name: os.getuid() + 1))["state-dir"]
    assert got.status == "fail"


def snapshot(root: Path) -> dict[str, tuple[int, int, int]]:
    out: dict[str, tuple[int, int, int]] = {}
    for p in [root, *root.rglob("*")]:
        st = p.lstat()
        out[str(p)] = (stat.S_IMODE(st.st_mode), st.st_mtime_ns, st.st_size)
    return out


def test_the_checker_changes_nothing_and_runs_on_a_read_only_tree(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    root = tmp_path / "root"
    paths = sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True)
    for p in paths:
        if p.is_dir():
            p.chmod(0o555)
    # the files keep their modes (0644 and 0600 are what is being checked); only the directories are read-only, so the
    # state directory (0500 here, read-only for its owner) is the one check that reports a problem
    root.chmod(0o555)
    try:
        before = snapshot(root)
        probe = root / "etc" / "probe"
        with pytest.raises(PermissionError):
            probe.write_text("x")  # proves the tree really is read-only for this process
        out = io.StringIO()
        code = pf.main_with(loc, FakeRunner(), lookup_ok, out=out)
        assert snapshot(root) == before
        assert not list(root.rglob("probe"))
    finally:
        for p in [root, *root.rglob("*")]:
            if p.is_dir():
                p.chmod(0o755)
    report = out.getvalue()
    assert code == 1  # the 0500 state directory is flagged; nothing else is
    assert [ln for ln in report.splitlines() if ln.startswith("FAIL")] == [
        ln for ln in report.splitlines() if "FAIL state-dir" in ln
    ]
    assert sum(1 for ln in report.splitlines() if ln.startswith("PASS")) == 10, report


def test_only_the_read_only_commands_are_run(tmp_path: Path) -> None:
    runner = FakeRunner()
    pf.run_preflight(make_tree(tmp_path), runner, lookup_ok)
    assert runner.calls
    assert set(runner.calls) <= ALLOWED_COMMANDS


def test_the_default_runner_uses_no_shell_and_only_the_given_argv() -> None:
    result = pf.default_runner(["python3", "-c", "print('hi')"])
    assert result == pf.RunResult(0, "hi\n")
    with pytest.raises(FileNotFoundError):
        pf.default_runner(["definitely-not-a-command-safo"])


def test_nothing_secret_or_key_shaped_is_printed(tmp_path: Path) -> None:
    runner = FakeRunner(
        {
            ("ssh-add", "-L"): pf.RunResult(0, f"sk-ssh-ed25519@openssh.com {KEY_B64} {SECRET}\n"),
            ("fido2-token", "-L"): pf.RunResult(0, f"/dev/hidraw3: vendor=0x1050, product=0x0407 ({SECRET})\n"),
        }
    )
    loc = make_tree(tmp_path)
    loc.switch.write_text(f"enabled\n{SECRET}\n")
    loc.switch.chmod(0o644)
    out = pf.render(pf.run_preflight(loc, runner, lookup_ok))
    for forbidden in ("topsecretmaterial", "PRIVATE KEY", KEY_B64, "AAAA"):
        assert forbidden not in out


def test_the_module_never_imports_the_network_or_vendor_code() -> None:
    # The one allowed import of the free-tier module is the refusal class the broker's parser raises (#299): the parser
    # itself is the broker's, imported from `safo.geminisign`. Nothing else of `safo.gemini` may be named here.
    allowed = "from safo.gemini import RefusedError\n"
    source = (Path(pf.__file__)).read_text()
    assert source.count(allowed) == 1
    source = source.replace(allowed, "")
    for banned in ("socket", "urllib", "http.client", "requests", "safo.gemini ", "import safo.broker"):
        assert banned not in source, banned


def test_the_guard_bites_a_checker_that_would_write(tmp_path: Path) -> None:
    """Negative case for the read-only proof: the same snapshot comparison does catch a write."""
    loc = make_tree(tmp_path)
    root = tmp_path / "root"
    before = snapshot(root)
    (root / "etc" / "safo" / "stray").write_text("x")
    assert snapshot(root) != before
    assert loc.allowed_signers.exists()


def test_a_state_entry_name_with_a_control_character_is_escaped_in_the_report(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    (loc.state_dir / "bad\x1bname").write_text("x")  # mode 0644: reported, and the name must not reach the output raw
    out = pf.render(pf.run_preflight(loc, FakeRunner(), lookup_ok))
    assert "\x1b" not in out
    assert "bad\\x1bname" in out


# ---- the egress mode: paid use may not be enabled while the egress control only logs (issue 288) ------------------


def set_mode(loc: pf.Locations, text: str, mode: int = 0o644) -> None:
    loc.egress_conf.write_text(text)
    loc.egress_conf.chmod(mode)


def egress(loc: pf.Locations, **kw: bool) -> pf.Check:
    return by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok, **kw))["egress-mode"]


def test_drop_mode_passes_whether_or_not_paid_use_is_being_enabled(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    assert egress(loc).status == egress(loc, enabling=True).status == "pass"
    loc.switch.write_text("enabled\n")
    loc.switch.chmod(0o644)
    assert egress(loc).status == "pass"


def test_a_missing_mode_line_means_drop_like_the_helper(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    set_mode(loc, f"VENDOR_HOST={VENDOR}\n")
    assert egress(loc, enabling=True).status == "pass"


def test_observe_mode_only_warns_while_paid_use_is_off(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    set_mode(loc, f"VENDOR_HOST={VENDOR}\nMODE=observe\n")
    got = egress(loc)
    assert got.status == "warn" and "observe" in got.detail
    checks = pf.run_preflight(loc, FakeRunner(), lookup_ok)
    assert pf.exit_code(checks) == 0
    assert pf.exit_code(checks, strict=True) == 1


def test_enabling_paid_use_in_observe_mode_fails(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    set_mode(loc, f"VENDOR_HOST={VENDOR}\nMODE=observe\n")
    got = egress(loc, enabling=True)
    assert got.status == "fail" and "--ack-observe-mode" in got.detail
    checks = pf.run_preflight(loc, FakeRunner(), lookup_ok, enabling=True)
    assert pf.exit_code(checks) == 1


def test_a_switch_that_is_already_present_counts_as_enabled(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    set_mode(loc, f"VENDOR_HOST={VENDOR}\nMODE=observe\n")
    loc.switch.write_text("enabled\n")
    loc.switch.chmod(0o644)
    assert egress(loc).status == "fail"


def test_the_acknowledgement_turns_the_failure_into_a_warning_that_names_the_minimum_evidence(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    set_mode(loc, f"VENDOR_HOST={VENDOR}\nMODE=observe\n")
    got = egress(loc, enabling=True, ack_observe=True)
    assert got.status == "warn"
    assert "empty" in got.detail and "dry run" in got.detail and "drop" in got.detail
    named = dataclasses.replace(loc, maintainer_uid=1000)
    assert pf.exit_code(pf.run_preflight(named, FakeRunner(), lookup_ok, enabling=True, ack_observe=True)) == 0


def test_the_acknowledgement_does_not_excuse_a_missing_or_unusable_config(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    loc.egress_conf.unlink()
    assert egress(loc).status == "warn"  # nothing to enable yet
    assert egress(loc, enabling=True, ack_observe=True).status == "fail"
    set_mode(loc, f"VENDOR_HOST={VENDOR}\nMODE=drop\n", mode=0o666)
    assert egress(loc, enabling=True, ack_observe=True).status == "fail"
    set_mode(loc, f"VENDOR_HOST={VENDOR}\nMODE=maybe\n")
    assert egress(loc, enabling=True, ack_observe=True).status == "fail"
    set_mode(loc, f"VENDOR_HOST={VENDOR}\nMODE=drop\nMODE=observe\n")
    assert egress(loc, enabling=True, ack_observe=True).status == "fail"
    set_mode(loc, f"VENDOR_HOST={VENDOR}\nSURPRISE=1\n")
    assert egress(loc, enabling=True, ack_observe=True).status == "fail"


def test_a_symlinked_config_is_unusable(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    real = loc.egress_conf.with_name("real.conf")
    real.write_text("MODE=drop\n")
    real.chmod(0o644)
    loc.egress_conf.unlink()
    loc.egress_conf.symlink_to(real)
    assert egress(loc, enabling=True).status == "fail"


def test_the_egress_report_never_prints_the_vendor_host_or_the_file(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    for text in (f"VENDOR_HOST={VENDOR}\nMODE=observe\n", f"VENDOR_HOST={VENDOR}\nMODE=drop\n", "garbage " + VENDOR):
        set_mode(loc, text)
        out = pf.render(pf.run_preflight(loc, FakeRunner(), lookup_ok, enabling=True))
        assert VENDOR not in out and "garbage" not in out


def test_the_command_line_takes_the_two_flags_and_nothing_else(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    loc = make_tree(tmp_path)
    set_mode(loc, f"VENDOR_HOST={VENDOR}\nMODE=observe\n")
    monkeypatch.setattr(pf, "Locations", lambda **kw: dataclasses.replace(loc, maintainer_uid=kw.get("maintainer_uid")))
    monkeypatch.setattr(pf, "default_runner", FakeRunner())
    monkeypatch.setattr(pf, "default_lookup", lookup_ok)
    uid = str(os.getuid())
    assert pf.main(["--enabling", "--maintainer-uid", uid]) == 1
    assert pf.main(["--enabling", "--ack-observe-mode"]) == 1  # no maintainer named: the run fails
    assert pf.main(["--enabling", "--ack-observe-mode", "--maintainer-uid", uid]) == 0
    assert pf.main(["--ack-observe-mode"]) == 0
    assert pf.main(["--bogus"]) == 2


# -- the broker config and the client config (#298, item 2) ------------------------------------------------------------


def broker_check(loc: pf.Locations) -> pf.Check:
    return by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))["broker-config"]


def client_check(loc: pf.Locations) -> pf.Check:
    return by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))["client-config"]


def test_a_complete_setup_passes_the_broker_config_and_the_client_config(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    got = broker_check(loc)
    assert got.status == "pass" and "1 allowed uid" in got.detail and "2 model" in got.detail, got
    assert client_check(loc).status == "pass"


def test_a_missing_broker_config_fails_and_points_at_the_runbook_step(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    loc.broker_config.unlink()
    got = broker_check(loc)
    assert got.status == "fail" and "does not exist" in got.detail and "runbook" in got.detail


def test_a_broker_config_with_the_wrong_owner_or_open_to_group_or_others_fails(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    other = dataclasses.replace(loc, trust_uid=os.getuid() + 1)
    assert broker_check(other).status == "fail" and "owner" in broker_check(other).detail
    for mode in (0o664, 0o646, 0o666, 0o620):
        loc.broker_config.chmod(mode)
        got = broker_check(loc)
        assert got.status == "fail" and "writable" in got.detail, (oct(mode), got)
    loc.broker_config.chmod(0o600)  # stricter than 0644 is not a problem the service has
    assert broker_check(loc).status == "pass"


def test_a_broker_config_that_is_a_link_or_not_a_file_fails(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    real = loc.broker_config.with_name("real.yaml")
    loc.broker_config.rename(real)
    loc.broker_config.symlink_to(real)
    assert broker_check(loc).status == "fail" and "link" in broker_check(loc).detail
    loc.broker_config.unlink()
    loc.broker_config.mkdir()
    assert broker_check(loc).status == "fail"


def test_a_broker_config_the_real_loader_refuses_fails_without_printing_its_text(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    good = loc.broker_config.read_text()
    for label, text in {
        "not yaml": "server: [unclosed\n" + SECRET,
        "no uids": good.replace("allowed_uids: [1000]", "allowed_uids: []"),
        "no server": good.replace("\nserver:", "\nsrv:"),
        "bad price": good.replace('input_per_mtok: "1.50"', "input_per_mtok: 1.5"),
        "unknown key": good.replace("max_per_uid: 2", "max_per_uid: 2\n  surprise: 1"),
    }.items():
        loc.broker_config.write_text(text)
        got = broker_check(loc)
        assert got.status == "fail", label
        assert "topsecretmaterial" not in got.detail and "PRIVATE KEY" not in got.detail, label
    loc.broker_config.write_text(good)
    assert broker_check(loc).status == "pass"


def test_a_broker_config_must_list_at_least_one_allowed_uid(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    loc.broker_config.write_text(loc.broker_config.read_text().replace("allowed_uids: [1000]", "allowed_uids: []"))
    got = broker_check(loc)
    assert got.status == "fail" and "allowed" in got.detail


def test_a_missing_or_broken_client_config_fails(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    assert loc.client_config is not None
    good = loc.client_config.read_text()
    loc.client_config.write_text("version: 2\n")
    assert client_check(loc).status == "fail"
    loc.client_config.write_text(good.replace("reply_seconds: 240", "reply_seconds: 5"))
    assert client_check(loc).status == "fail"
    loc.client_config.write_text(good)
    loc.client_config.chmod(0o666)
    assert client_check(loc).status == "fail" and "writable" in client_check(loc).detail
    loc.client_config.chmod(0o600)
    loc.client_config.unlink()
    got = client_check(loc)
    assert got.status == "fail" and "does not exist" in got.detail and "broker-client.example.yaml" in got.detail


def test_a_client_config_without_a_signing_key_warns(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    assert loc.client_config is not None
    loc.client_config.write_text("version: 1\n")
    got = client_check(loc)
    assert got.status == "warn" and "signing" in got.detail


def test_the_client_config_defaults_to_the_calling_accounts_own_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loc = dataclasses.replace(make_tree(tmp_path), client_config=None)
    home = tmp_path / "home"
    (home / ".config" / "safo").mkdir(parents=True)
    shutil.copyfile(EXAMPLES / "broker-client.example.yaml", home / ".config" / "safo" / "broker-client.yaml")
    (home / ".config" / "safo" / "broker-client.yaml").chmod(0o600)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    assert client_check(loc).status == "pass"


def test_the_flag_names_the_client_config_and_a_relative_path_is_refused(tmp_path: Path) -> None:
    seen: list[Path | None] = []

    def fake(loc: pf.Locations, runner: object, lookup: object, **kw: object) -> int:
        seen.append(loc.client_config)
        return 0

    import unittest.mock as mock

    with mock.patch.object(pf, "main_with", fake):
        assert pf.main(["--client-config", "/home/x/.config/safo/broker-client.yaml"]) == 0
        assert pf.main(["--enabling", "--client-config", "/abs/c.yaml", "--strict"]) == 0
        assert pf.main(["--client-config", "relative.yaml"]) == 2
        assert pf.main(["--client-config"]) == 2
    assert seen == [Path("/home/x/.config/safo/broker-client.yaml"), Path("/abs/c.yaml")]


def test_loading_the_configs_opens_no_connection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The loaders come from the broker package, which imports its network modules; the preflight must still make no
    connection (nothing here may reach the broker or the vendor)."""
    import socket

    def refuse(*args: object, **kw: object) -> None:
        raise AssertionError("the preflight opened a connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    checks = pf.run_preflight(make_tree(tmp_path), FakeRunner(), lookup_ok)
    assert {c.status for c in checks} == {"pass"}


# -- hardening of the client-config read (#298 review) -----------------------------------------------------------

WEIRD = ["a b", 'q"uote', "d$ollar", "back`tick", "new\nline", "semi;colon", "tab\there", "glob*", "(paren)"]


def client_tree(tmp_path: Path, home_parts: list[str]) -> pf.Locations:
    loc = make_tree(tmp_path)
    home = tmp_path.joinpath("weird-home", *home_parts)
    target = home / ".config" / "safo" / "broker-client.yaml"
    target.parent.mkdir(parents=True)
    shutil.copyfile(EXAMPLES / "broker-client.example.yaml", target)
    target.chmod(0o600)
    return dataclasses.replace(loc, client_config=target, maintainer_uid=os.getuid())


def test_a_home_with_spaces_quotes_dollars_backticks_newlines_or_a_semicolon_is_read_as_data(tmp_path: Path) -> None:
    """The home is a path in Python, never text in a shell: every awkward name loads and nothing is expanded."""
    for number, name in enumerate(WEIRD):
        loc = client_tree(tmp_path / str(number), [name])
        got = client_check(loc)
        assert got.status == "pass", (name, got)
        assert name not in got.detail  # and the path is not echoed into the report


def test_the_maintainer_uid_flag_finds_the_home_in_python_and_a_bad_value_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import types
    import unittest.mock as mock

    seen: list[tuple[Path | None, int | None]] = []

    def fake(loc: pf.Locations, runner: object, lookup: object, **kw: object) -> int:
        seen.append((loc.client_config, loc.maintainer_uid))
        return 0

    for name in WEIRD:
        home = f"/h/{name}"
        monkeypatch.setattr(pwd, "getpwuid", lambda uid, home=home: types.SimpleNamespace(pw_dir=home))
        with mock.patch.object(pf, "main_with", fake):
            assert pf.main(["--maintainer-uid", "1234"]) == 0
        assert seen[-1] == (Path(home) / ".config" / "safo" / "broker-client.yaml", 1234)
    with mock.patch.object(pf, "main_with", fake):
        for bad in ("", "-1", "12a", "$(id -u)", "1;2", "99999999999", "1 2"):
            assert pf.main(["--maintainer-uid", bad]) == 2, bad
        assert pf.main(["--maintainer-uid"]) == 2
        monkeypatch.setattr(pwd, "getpwuid", lambda uid: types.SimpleNamespace(pw_dir="relative/home"))
        assert pf.main(["--maintainer-uid", "5"]) == 2  # a home that is not absolute is refused
        monkeypatch.setattr(pwd, "getpwuid", mock.Mock(side_effect=KeyError("no such uid")))
        assert pf.main(["--maintainer-uid", "5"]) == 2


def test_the_client_config_is_judged_on_the_opened_descriptor_not_on_a_path_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loc = client_tree(tmp_path, ["h"])

    real_lstat = os.lstat

    def no_lookup(path: object, *args: object, **kw: object) -> os.stat_result:
        # the root-owned override is a different file, which the client's own loader looks up by name (#303)
        if Path(str(path)) == loc.client_root_config:
            return real_lstat(str(path))
        raise AssertionError("a path was inspected by name instead of by the opened descriptor")

    monkeypatch.setattr(os, "lstat", no_lookup)
    monkeypatch.setattr(Path, "lstat", no_lookup)
    assert pf.check_client_config(loc).status == "pass"  # this check alone: the other checks do look files up


def test_a_client_config_under_a_directory_others_can_write_is_not_trusted(tmp_path: Path) -> None:
    loc = client_tree(tmp_path, ["h"])
    assert loc.client_config is not None
    home = loc.client_config.parents[2]
    for mode in (0o777, 0o775, 0o757, 0o1777):  # a sticky bit does not help a directory this account owns
        home.chmod(mode)
        got = client_check(loc)
        assert got.status == "fail" and "directory" in got.detail and "writable" in got.detail, (oct(mode), got)
    home.chmod(0o700)
    loc.client_config.parent.chmod(0o770)  # the directory that holds the file
    assert client_check(loc).status == "fail"
    loc.client_config.parent.chmod(0o700)
    assert client_check(loc).status == "pass"


def test_a_symbolic_link_in_the_file_or_in_a_parent_is_refused(tmp_path: Path) -> None:
    loc = client_tree(tmp_path, ["h"])
    assert loc.client_config is not None
    real = loc.client_config.with_name("real.yaml")
    loc.client_config.rename(real)
    loc.client_config.symlink_to(real)
    assert client_check(loc).status == "fail" and "link" in client_check(loc).detail
    loc.client_config.unlink()
    real.rename(loc.client_config)
    home = loc.client_config.parents[2]
    moved = home.with_name("moved")
    home.rename(moved)
    home.symlink_to(moved)
    assert client_check(loc).status == "fail"


def test_a_root_run_accepts_only_root_or_the_named_maintainer_as_the_file_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Run as root the preflight must not accept a file owned by just any account."""
    loc = client_tree(tmp_path, ["h"])
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    mine = os.getuid()
    assert client_check(dataclasses.replace(loc, maintainer_uid=mine)).status == "pass"
    for other in (None, mine + 1):
        got = client_check(dataclasses.replace(loc, maintainer_uid=other))
        assert got.status == "fail" and "owner" in got.detail, (other, got)
    monkeypatch.setattr(os, "geteuid", lambda: mine)  # not root: only the caller's own file passes
    assert client_check(dataclasses.replace(loc, maintainer_uid=mine + 1)).status == "pass"


# -- the allowed-signers check is the broker's own parser (#299) ------------------------------------------------------
# The shapes the broker refuses at run time (`geminisign.parse_signers`) must fail the readiness check too. Each row is
# a whole file; the first test proves the broker refuses it (so the table is not a guess), the second that preflight
# refuses it and does not use it to say the key is enrolled.

GOOD = f'yubikey-a namespaces="{NS}" {SK} {KEY_B64}'
REFUSED_BY_THE_BROKER: dict[str, list[str]] = {
    "no-touch-required": [f'a namespaces="{NS}",no-touch-required {SK} {KEY_B64}'],
    "cert-authority": [f'a cert-authority,namespaces="{NS}" {SK} {KEY_B64}'],
    "an unknown option": [f'a namespaces="{NS}",principals="x" {SK} {KEY_B64}'],
    "a window that ends before it starts": [
        f'a namespaces="{NS}",valid-after="20300101Z",valid-before="20200101Z" {SK} {KEY_B64}'
    ],
    "a window in local time": [f'a namespaces="{NS}",valid-after="20300101" {SK} {KEY_B64}'],
    "an upper-case label": [f'Yubi namespaces="{NS}" {SK} {KEY_B64}'],
    "a label with a comma": [f'a,b namespaces="{NS}" {SK} {KEY_B64}'],
    "a key type the broker does not accept": [f'a namespaces="{NS}" ssh-rsa {KEY_B64}'],
    "a key that does not match its type": [f'a namespaces="{NS}" ssh-ed25519 {KEY_B64}'],
    "a key that is not base64": [f'a namespaces="{NS}" {SK} not*base64*at*all'],
    "a truncated key": [f'a namespaces="{NS}" {SK} {KEY_B64[:-8]}'],
    "a label used twice": [
        f'a namespaces="{NS}" {SK} {KEY_B64}',
        f'a namespaces="{NS}" {SK} {KEY_B2_B64}',
    ],
    "a key enrolled twice": [
        f'a namespaces="{NS}" {SK} {KEY_B64}',
        f'b namespaces="{NS}" {SK} {KEY_B64}',
    ],
    "an unknown safo directive": [GOOD, "# safo: yubikey-a frobnicate"],
    "a directive for a label that is not enrolled": [GOOD, "# safo: nobody require-pin"],
    "a line with too few fields": [f'a namespaces="{NS}"'],
    "one good line and one refused line": [GOOD, f'b namespaces="{NS}",no-touch-required {SK} {KEY_B2_B64}'],
}
ACCEPTED_BY_THE_BROKER: dict[str, list[str]] = {
    "one sk key": [GOOD],
    "two sk keys": [GOOD, f'yubikey-b namespaces="{NS}" {SK} {KEY_B2_B64}'],
    "a valid window": [f'a namespaces="{NS}",valid-after="20200101Z",valid-before="20300101Z" {SK} {KEY_B64}'],
    "a directive for an enrolled label": [GOOD, "# safo: yubikey-a require-pin"],
    "a software key": [f'soft namespaces="{NS}" ssh-ed25519 {KEY_SOFT_B64}'],
}


def broker_accepts(lines: list[str]) -> bool:
    from safo import geminisign
    from safo.gemini import RefusedError

    try:
        geminisign.parse_signers("\n".join(lines) + "\n")
    except RefusedError:
        return False
    return True


def test_the_parity_tables_are_not_trimmed() -> None:
    assert len(REFUSED_BY_THE_BROKER) == 17
    assert len(ACCEPTED_BY_THE_BROKER) == 5


@pytest.mark.parametrize("name", list(REFUSED_BY_THE_BROKER))
def test_the_broker_refuses_each_shape_in_the_table(name: str) -> None:
    assert not broker_accepts(REFUSED_BY_THE_BROKER[name]), name


@pytest.mark.parametrize("name", list(ACCEPTED_BY_THE_BROKER))
def test_the_broker_accepts_each_good_shape_in_the_table(name: str) -> None:
    assert broker_accepts(ACCEPTED_BY_THE_BROKER[name]), name


@pytest.mark.parametrize("name", list(REFUSED_BY_THE_BROKER))
def test_a_file_the_broker_refuses_fails_the_readiness_check(tmp_path: Path, name: str) -> None:
    loc = make_tree(tmp_path, signers_lines=REFUSED_BY_THE_BROKER[name])
    got = by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))
    assert got["allowed-signers"].status == "fail", name
    assert got["hardware-key"].status != "pass", name  # the agent holds the key, but the broker would not use the file
    out = pf.render(pf.run_preflight(loc, FakeRunner(), lookup_ok))
    assert KEY_B64 not in out and KEY_B2_B64 not in out and "not*base64" not in out


@pytest.mark.parametrize("name", list(ACCEPTED_BY_THE_BROKER))
def test_a_file_the_broker_accepts_passes_the_readiness_check(tmp_path: Path, name: str) -> None:
    loc = make_tree(tmp_path, signers_lines=ACCEPTED_BY_THE_BROKER[name])
    got = by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))
    assert got["allowed-signers"].status == "pass", (name, got["allowed-signers"].detail)


def test_preflight_calls_the_brokers_parser_and_has_no_parser_of_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One implementation: replace the broker's parser and the readiness check follows it; the module also holds no
    option, key-type or label table of its own."""
    from safo import geminisign
    from safo.gemini import RefusedError

    calls: list[int] = []

    def refuse(text: str) -> list[geminisign.Enrolled]:
        calls.append(len(text))
        raise RefusedError("allowed-signers line 1: a stand-in refusal")

    monkeypatch.setattr(geminisign, "parse_signers", refuse)
    got = by_name(pf.run_preflight(make_tree(tmp_path), FakeRunner(), lookup_ok))  # a file the real parser accepts
    assert calls, "preflight did not call the broker's parser"
    assert got["allowed-signers"].status == "fail" and "stand-in refusal" in got["allowed-signers"].detail
    assert got["hardware-key"].status != "pass"
    source = Path(pf.__file__).read_text()
    assert source.count("geminisign.parse_signers(") == 2  # the readiness check and the key-to-name link
    for own_parser in ("no-touch-required", "cert-authority", "valid-before", "KEY_TYPES", "_line_namespace_problem"):
        assert own_parser not in source, own_parser


# -- setup-command hardening (#303) ------------------------------------------------------------------------------------


def test_the_enabling_preflight_requires_the_named_maintainer_in_allowed_uids(tmp_path: Path) -> None:
    loc = dataclasses.replace(make_tree(tmp_path), maintainer_uid=1000)
    assert broker_check(loc).status == "pass"  # the tree lists 1000
    wrong = dataclasses.replace(loc, maintainer_uid=1001)
    got = broker_check(wrong)
    assert got.status == "fail" and "1001" in got.detail, got
    loc.broker_config.write_text(loc.broker_config.read_text().replace("allowed_uids: [1000]", "allowed_uids: [1001]"))
    got = broker_check(loc)  # the list is not empty but names someone else
    assert got.status == "fail", got


def test_an_extra_allowed_uid_fails_when_a_maintainer_is_named(tmp_path: Path) -> None:
    loc = dataclasses.replace(make_tree(tmp_path), maintainer_uid=1000)
    loc.broker_config.write_text(
        loc.broker_config.read_text().replace("allowed_uids: [1000]", "allowed_uids: [1000, 1001]")
    )
    got = broker_check(loc)
    assert got.status == "fail" and "1001" in got.detail, got
    without = dataclasses.replace(loc, maintainer_uid=None)
    assert broker_check(without).status == "pass"  # no maintainer named: the old rule (nonempty) alone


def test_the_enable_line_creates_no_switch_when_the_config_admits_another_account(tmp_path: Path) -> None:
    import io

    loc = dataclasses.replace(make_tree(tmp_path), maintainer_uid=1000)
    loc.broker_config.write_text(
        loc.broker_config.read_text().replace("allowed_uids: [1000]", "allowed_uids: [1000, 1001]")
    )
    # no strict flag, like the runbook line: the exit code alone must stop the switch
    code = pf.main_with(loc, FakeRunner(), lookup_ok, out=io.StringIO(), enabling=True, ack_observe=True)
    assert code == 1
    switch = tmp_path / "out" / "gemini-paid-enabled"
    switch.parent.mkdir()
    # the shape of the runbook line: the switch is written only when the preflight exits 0
    if code == 0:
        switch.write_text("enabled\n")
    assert not switch.exists()


def test_an_enabling_run_without_a_named_maintainer_fails_and_creates_no_switch(tmp_path: Path) -> None:
    import io

    loc = make_tree(tmp_path)
    assert loc.maintainer_uid is None
    loc.broker_config.write_text(
        loc.broker_config.read_text().replace("allowed_uids: [1000]", "allowed_uids: [1000, 1001]")
    )
    checks = pf.run_preflight(loc, FakeRunner(), lookup_ok, enabling=True, ack_observe=True)
    assert [c for c in checks if c.name == "maintainer-uid" and c.status == "fail"], pf.render(checks)
    code = pf.main_with(loc, FakeRunner(), lookup_ok, out=io.StringIO(), enabling=True, ack_observe=True)
    assert code == 1
    switch = tmp_path / "out" / "gemini-paid-enabled"
    switch.parent.mkdir()
    if code == 0:  # the shape of the runbook line: the switch is written only when the preflight exits 0
        switch.write_text("enabled\n")
    assert not switch.exists()
    plain = pf.run_preflight(loc, FakeRunner(), lookup_ok)  # outside the enabling run no maintainer is required
    assert not [c for c in plain if c.name == "maintainer-uid"]


def test_the_client_config_check_applies_the_root_owned_override_like_the_client(tmp_path: Path) -> None:
    loc = make_tree(tmp_path)
    assert client_check(loc).status == "pass"  # no override file
    root = loc.client_root_config
    root.parent.mkdir(parents=True)
    root.write_text("version: 1\nsocket: /run/safo-broker/broker.sock\n")
    root.chmod(0o644)
    loc = dataclasses.replace(loc, trust_uid=os.getuid())
    assert client_check(loc).status == "pass"  # a valid override
    root.write_text("version: 1\nunknown_setting: 1\n")
    got = client_check(loc)
    assert got.status == "fail" and "load" in got.detail, got
    root.write_text("version: 1\nsocket: relative/path\n")
    assert client_check(loc).status == "fail"
    root.write_text("version: 1\nsocket: /run/safo-broker/broker.sock\n")
    root.chmod(0o666)  # an override others can write is refused by the client's own reader
    assert client_check(loc).status == "fail"
    root.chmod(0o644)
    assert client_check(loc).status == "pass"
