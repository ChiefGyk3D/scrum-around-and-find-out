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
import shutil
import stat
from collections.abc import Sequence
from pathlib import Path

import pytest

from safo import gemini_preflight as pf

NS = "safo-gemini-approval"
EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
# built from pieces at run time so no key-shaped literal sits in the tree (the secret scan reads every commit)
KEY_B64 = "".join(
    ["AAAA", "GnNrLXNzaC1lZDI1NTE5QG9w", "ZW5zc2guY29tAAAA", "I" + "Placeholder" * 4 + "AAA"]
)  # 92 characters: a whole number of base64 quanta
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
    shutil.copyfile(EXAMPLES / "broker.example.yaml", broker)
    broker.chmod(0o644)
    client = root / "home" / ".config" / "safo" / "broker-client.yaml"
    client.parent.mkdir(parents=True)
    shutil.copyfile(EXAMPLES / "broker-client.example.yaml", client)
    client.chmod(0o600)
    return pf.Locations(
        broker_config=broker,
        client_config=client,
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
    loc = make_tree(tmp_path, signers_lines=[f'soft namespaces="{NS}" ssh-ed25519 {KEY_B64}'])
    runner = FakeRunner({("ssh-add", "-L"): pf.RunResult(0, f"ssh-ed25519 {KEY_B64} comment\n")})
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


@pytest.mark.parametrize("mode", [0o600, 0o664, 0o666, 0o755])
def test_allowed_signers_must_be_exactly_0644(tmp_path: Path, mode: int) -> None:
    loc = make_tree(tmp_path)
    loc.allowed_signers.chmod(mode)
    got = by_name(pf.run_preflight(loc, FakeRunner(), lookup_ok))
    assert got["allowed-signers"].status == "fail"
    assert "0644" in got["allowed-signers"].detail


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
    source = (Path(pf.__file__)).read_text()
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
    assert pf.exit_code(pf.run_preflight(loc, FakeRunner(), lookup_ok, enabling=True, ack_observe=True)) == 0


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
    monkeypatch.setattr(pf, "Locations", lambda: loc)
    monkeypatch.setattr(pf, "default_runner", FakeRunner())
    monkeypatch.setattr(pf, "default_lookup", lookup_ok)
    assert pf.main(["--enabling"]) == 1
    assert pf.main(["--enabling", "--ack-observe-mode"]) == 0
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
    loc.client_config.write_text(good.replace("socket: /run/safo-broker.sock", "socket: relative/path"))
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
