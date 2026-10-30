# SPDX-License-Identifier: Apache-2.0
"""Signed approvals (#200): the verifier, the trust files and the `keys` subcommands.

Hermetic: software ed25519 keys made by ssh-keygen in a temporary directory. A real approval key is a hardware sk key;
the flag rules for a hardware key (touch, PIN) are tested on well-formed envelopes with the cryptographic check
replaced, because only a real authenticator can make a real sk signature. Every check that decides who may approve
spend has a test that goes red when the check is removed.
"""

from __future__ import annotations

import datetime as dt
import os
import subprocess
from pathlib import Path

import pytest

from geminidata import NAMESPACE, SSH_KEYGEN, fake_sk_armor, fake_sk_key, fingerprint, make_key, pub_parts, signers_line
from safo import geminisign
from safo.gemini import RefusedError
from safo.geminisign import Trust

PAYLOAD = b'{"job":"j","max_usd":"1"}'


class Rig:
    def __init__(self, tmp_path: Path) -> None:
        self.dir = tmp_path
        self.a = make_key(tmp_path / "a")
        self.b = make_key(tmp_path / "b")
        self.signers = tmp_path / "signers"
        self.revoked = tmp_path / "revoked"
        self.set_signers(signers_line("yubikey-a", self.a.with_suffix(".pub")))

    def set_signers(self, *lines: str) -> None:
        self.signers.write_text("\n".join(lines) + "\n")
        self.signers.chmod(0o644)

    def trust(self, *, hardware: bool = False, uid: int | None = None) -> Trust:
        return Trust(self.signers, self.revoked, os.geteuid() if uid is None else uid, hardware)

    def sign(self, key: Path | None = None, payload: bytes = PAYLOAD, namespace: str = NAMESPACE) -> str:
        return geminisign.sign(str(key or self.a), payload, namespace, {})


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    return Rig(tmp_path)


def refused(match: str) -> pytest.RaisesExc[RefusedError]:
    return pytest.raises(RefusedError, match=match)


# -- the signature ---------------------------------------------------------------------------------------------------


def test_a_good_signature_names_the_enrolled_key(rig: Rig) -> None:
    who = geminisign.verify(rig.trust(), PAYLOAD, rig.sign())
    expected = subprocess.run(  # noqa: S603 - the system ssh-keygen, a path made by the test, no shell
        [SSH_KEYGEN, "-lf", str(rig.a) + ".pub"], capture_output=True, text=True, check=True
    )
    assert who.label == "yubikey-a" and who.fingerprint in expected.stdout and not who.hardware


def test_a_changed_payload_does_not_verify(rig: Rig) -> None:
    armor = rig.sign()
    with refused("does not verify"):
        geminisign.verify(rig.trust(), PAYLOAD + b" ", armor)


def test_a_signature_for_another_namespace_is_refused(rig: Rig) -> None:
    armor = rig.sign(namespace="file")
    with refused("namespace"):
        geminisign.verify(rig.trust(), PAYLOAD, armor)


def test_the_namespace_is_also_bound_by_openssh_itself(rig: Rig) -> None:
    """Even if our own namespace comparison were skipped, OpenSSH checks the namespace it is asked for."""
    armor = rig.sign(namespace="file")
    ok = geminisign._ssh_keygen_verify(
        geminisign.ssh_keygen(),
        signers_line("yubikey-a", rig.a.with_suffix(".pub")),
        PAYLOAD,
        armor,
        NAMESPACE,
        "yubikey-a",
        dt.datetime.now(dt.UTC),
    )
    assert ok is False


def test_a_key_that_is_not_enrolled_is_refused(rig: Rig) -> None:
    with refused("not signed by an enrolled key"):
        geminisign.verify(rig.trust(), PAYLOAD, rig.sign(rig.b))


@pytest.mark.parametrize("how", ["public key", "fingerprint"])
def test_a_revoked_key_is_refused_even_while_it_is_still_enrolled(rig: Rig, how: str) -> None:
    armor = rig.sign()
    assert geminisign.verify(rig.trust(), PAYLOAD, armor).label == "yubikey-a"
    key_type, b64 = pub_parts(rig.a.with_suffix(".pub"))
    import base64

    line = f"{key_type} {b64} lost" if how == "public key" else fingerprint(base64.b64decode(b64))
    rig.revoked.write_text(f"# lost on purpose\n{line}\n")
    rig.revoked.chmod(0o644)
    with refused("revoked"):
        geminisign.verify(rig.trust(), PAYLOAD, armor)


def test_a_revocation_list_that_cannot_be_read_blocks_everything(rig: Rig) -> None:
    rig.revoked.write_text("this is not a key\n")
    rig.revoked.chmod(0o644)
    with refused("revocation list line 1"):
        geminisign.verify(rig.trust(), PAYLOAD, rig.sign())


def test_garbage_is_not_a_signature(rig: Rig) -> None:
    for armor in ("", "nonsense", "-----BEGIN SSH SIGNATURE-----\n!!!\n-----END SSH SIGNATURE-----", "x" * 5000):
        with refused("signature"):
            geminisign.verify(rig.trust(), PAYLOAD, armor)


# -- hardware by default ---------------------------------------------------------------------------------------------


def test_the_default_refuses_a_plain_software_key(rig: Rig) -> None:
    with refused("not a hardware key"):
        geminisign.verify(rig.trust(hardware=True), PAYLOAD, rig.sign())


def test_a_software_key_works_only_with_the_written_opt_in(rig: Rig) -> None:
    rig.set_signers(signers_line("yubikey-a", rig.a.with_suffix(".pub")), "# safo: yubikey-a allow-software")
    assert geminisign.verify(rig.trust(hardware=True), PAYLOAD, rig.sign()).label == "yubikey-a"


def test_an_opt_in_for_a_label_that_is_not_enrolled_is_refused(rig: Rig) -> None:
    rig.set_signers(signers_line("yubikey-a", rig.a.with_suffix(".pub")), "# safo: typo-a allow-software")
    with refused("not enrolled"):
        geminisign.verify(rig.trust(), PAYLOAD, rig.sign())


def test_an_unknown_directive_flag_is_refused(rig: Rig) -> None:
    rig.set_signers(signers_line("yubikey-a", rig.a.with_suffix(".pub")), "# safo: yubikey-a allow-everything")
    with refused("unknown safo directive"):
        geminisign.load_roster(rig.trust())


class SkRig(Rig):
    """A hardware key we cannot sign with: the cryptographic check is replaced, the flag rules are real."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra: str = "") -> None:
        super().__init__(tmp_path)
        self.blob, b64 = fake_sk_key()
        self.set_signers(
            f'yubikey-a namespaces="{NAMESPACE}" sk-ssh-ed25519@openssh.com {b64}', *([extra] if extra else [])
        )
        self.verified_called = 0
        monkeypatch.setattr(geminisign, "_ssh_keygen_verify", self._ok)

    def _ok(self, *args: object) -> bool:
        self.verified_called += 1
        return True

    def verify(self, flags: int) -> geminisign.Verified:
        return geminisign.verify(self.trust(hardware=True), PAYLOAD, fake_sk_armor(self.blob, flags))


def test_a_hardware_signature_needs_the_touch_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rig = SkRig(tmp_path, monkeypatch)
    who = rig.verify(0x01)
    assert who.hardware and who.user_present and not who.user_verified and who.label == "yubikey-a"
    with refused("touch"):
        rig.verify(0x00)
    with refused("touch"):
        rig.verify(0x04)  # a PIN check alone is not a touch


def test_a_pin_is_required_where_the_maintainer_wrote_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rig = SkRig(tmp_path, monkeypatch, "# safo: yubikey-a require-pin")
    with refused("PIN"):
        rig.verify(0x01)
    assert rig.verify(0x05).user_verified


def test_a_hardware_envelope_for_another_key_or_type_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = SkRig(tmp_path, monkeypatch)
    other, _ = fake_sk_key(seed=2)
    with refused("not signed by an enrolled key"):
        geminisign.verify(rig.trust(hardware=True), PAYLOAD, fake_sk_armor(other, 0x01))
    with refused("not a readable"):  # a plain ed25519 type name on a hardware blob
        geminisign.verify(rig.trust(hardware=True), PAYLOAD, fake_sk_armor(rig.blob, 0x01, key_type="ssh-ed25519"))


# -- the allowed-signers file ----------------------------------------------------------------------------------------


def test_a_key_that_carries_no_touch_required_is_refused_at_load(rig: Rig) -> None:
    pub = rig.a.with_suffix(".pub")
    for options in (
        f'no-touch-required,namespaces="{NAMESPACE}"',
        f'namespaces="{NAMESPACE}",NO-TOUCH-REQUIRED',
    ):
        rig.set_signers(signers_line("yubikey-a", pub, options=options))
        with refused("carries no-touch-required"):
            geminisign.load_roster(rig.trust())


@pytest.mark.parametrize(
    ("options", "match"),
    [
        ("", "must be bound"),
        ('namespaces="file"', "namespaces must be exactly"),
        (f'namespaces="{NAMESPACE},file"', "namespaces must be exactly"),
        (f'cert-authority,namespaces="{NAMESPACE}"', "not allowed"),
        (f'namespaces="{NAMESPACE}",verify-required', "not allowed"),
        (f'namespaces="{NAMESPACE}",valid-before="soon"', "UTC time"),
        (f'namespaces="{NAMESPACE}",valid-after="20261029Z",valid-before="20261029Z"', "later than valid-after"),
    ],
)
def test_the_options_on_a_key_are_strict(rig: Rig, options: str, match: str) -> None:
    rig.set_signers(signers_line("yubikey-a", rig.a.with_suffix(".pub"), options=options))
    with refused(match):
        geminisign.load_roster(rig.trust())


def test_labels_keys_and_types_are_checked(rig: Rig) -> None:
    pub_a, pub_b = rig.a.with_suffix(".pub"), rig.b.with_suffix(".pub")
    cases = {
        "twice": [signers_line("k", pub_a), signers_line("k", pub_b)],
        "enrolled twice": [signers_line("k1", pub_a), signers_line("k2", pub_a)],
        "one plain lowercase": [signers_line("a@example.com", pub_a)],
        "one plain lowercase ": [signers_line("a,b", pub_a)],
        "not accepted": [f'k namespaces="{NAMESPACE}" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQ'],
        "does not match its type": [f'k namespaces="{NAMESPACE}" ssh-ed25519 {pub_parts(pub_a)[1][:20]}AAAA'],
    }
    for match, lines in cases.items():
        rig.set_signers(*lines)
        with refused(match.strip()):
            geminisign.load_roster(rig.trust())


def test_an_empty_allowed_signers_file_approves_nothing(rig: Rig) -> None:
    rig.set_signers("# nobody")
    with refused("not signed by an enrolled key"):
        geminisign.verify(rig.trust(), PAYLOAD, rig.sign())


# -- the trust files must not be writable by the agent's account -----------------------------------------------------


def test_the_trust_file_must_be_owned_by_the_required_account(rig: Rig) -> None:
    with refused("not owned"):
        geminisign.verify(rig.trust(uid=os.geteuid() + 1), PAYLOAD, rig.sign())


def test_the_file_itself_must_be_owned_by_the_required_account(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolated from the directory rule: every directory is fine and only the file's owner differs."""
    real = os.fstat

    def other_owner(fd: int) -> os.stat_result:
        r = real(fd)
        fields = (r.st_mode, r.st_ino, r.st_dev, r.st_nlink, r.st_uid + 1, r.st_gid, r.st_size, 0, 0, 0)
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", other_owner)
    with refused("file is not owned|not owned by the account"):
        geminisign.read_trust_file(rig.signers, os.geteuid(), "allowed-signers file")


def test_the_production_trust_account_is_root(tmp_path: Path) -> None:
    from safo import gemini

    real = gemini.Locations(tmp_path, tmp_path / "c", tmp_path / "a", tmp_path / "t")
    assert real.trust_uid == 0 and real.require_hardware is True
    assert str(real.signers) == "/etc/safo/gemini-allowed-signers"
    assert str(real.revoked) == "/etc/safo/gemini-revoked-signers"


def test_a_group_or_world_writable_trust_file_is_refused(rig: Rig) -> None:
    rig.signers.chmod(0o664)
    with refused("writable"):
        geminisign.load_roster(rig.trust())
    rig.signers.chmod(0o646)
    with refused("writable"):
        geminisign.load_roster(rig.trust())


def test_a_writable_directory_above_the_trust_file_is_refused(rig: Rig) -> None:
    rig.dir.chmod(0o777)
    try:
        with refused("directory"):
            geminisign.load_roster(rig.trust())
    finally:
        rig.dir.chmod(0o700)


def test_a_symlinked_or_missing_trust_file_is_refused(rig: Rig, tmp_path: Path) -> None:
    link = tmp_path / "link"
    link.symlink_to(rig.signers)
    # the path is resolved first, so a link to a trusted file is the file itself; a dangling one is missing
    assert geminisign.read_trust_file(link, os.geteuid(), "x")
    with refused("does not exist"):
        geminisign.read_trust_file(tmp_path / "nowhere", os.geteuid(), "x")
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with refused("not a regular"):
        geminisign.read_trust_file(fifo, os.geteuid(), "x")


# -- the keys subcommands: read-only ---------------------------------------------------------------------------------


def test_propose_prints_the_line_and_the_fingerprint_and_writes_nothing(rig: Rig) -> None:
    before = rig.signers.read_bytes()
    lines = geminisign.propose_line(rig.trust(), rig.b.with_suffix(".pub"), "backup-1")
    text = "\n".join(lines)
    assert f'backup-1 namespaces="{NAMESPACE}" ssh-ed25519 {pub_parts(rig.b.with_suffix(".pub"))[1]}' in text
    assert "SHA256:" in text and "WARNING" in text and "allow-software" in text
    assert rig.signers.read_bytes() == before and not rig.revoked.exists()


@pytest.mark.parametrize("label", ["", "Bad Label", "a@b", "x" * 80])
def test_propose_refuses_a_bad_label(rig: Rig, label: str) -> None:
    with pytest.raises(Exception, match="label"):
        geminisign.propose_line(rig.trust(), rig.b.with_suffix(".pub"), label)


def test_propose_refuses_a_private_key_and_duplicates(rig: Rig) -> None:
    with pytest.raises(Exception, match="public key"):
        geminisign.propose_line(rig.trust(), rig.b, "backup-1")
    with pytest.raises(Exception, match="already enrolled"):
        geminisign.propose_line(rig.trust(), rig.a.with_suffix(".pub"), "backup-1")
    with pytest.raises(Exception, match="already enrolled"):
        geminisign.propose_line(rig.trust(), rig.b.with_suffix(".pub"), "yubikey-a")


def test_list_shows_label_type_fingerprint_flags_and_revocation(rig: Rig) -> None:
    rig.set_signers(
        signers_line("yubikey-a", rig.a.with_suffix(".pub")),
        signers_line("backup-1", rig.b.with_suffix(".pub")),
        "# safo: backup-1 allow-software",
    )
    rows = geminisign.key_rows(rig.trust(hardware=True))
    assert len(rows) == 2 and "yubikey-a" in rows[0] and "SHA256:" in rows[0]
    assert "SOFTWARE" in rows[0] and "NOT usable: not a hardware key" in rows[0] and "not revoked" in rows[0]
    assert "software opt-in written" in rows[1] and "  usable" in rows[1]
    rig.revoked.write_text(fingerprint(__import__("base64").b64decode(pub_parts(rig.b.with_suffix(".pub"))[1])) + "\n")
    rig.revoked.chmod(0o644)
    assert "REVOKED" in geminisign.key_rows(rig.trust(hardware=True))[1]


def test_check_warns_about_one_key_software_keys_and_a_missing_revocation_file(rig: Rig) -> None:
    problems, warnings = geminisign.check_report(rig.trust(hardware=True))
    text = " ".join(warnings)
    assert problems and "no usable key" in problems[0]
    assert "software key" in text and "NOT usable" in text and "no revocation list" in text
    rig.set_signers(signers_line("yubikey-a", rig.a.with_suffix(".pub")), "# safo: yubikey-a allow-software")
    problems, warnings = geminisign.check_report(rig.trust(hardware=True))
    assert problems == [] and any("only one usable key" in w for w in warnings)


def test_check_with_two_hardware_keys_and_a_revocation_file_is_quiet_but_for_the_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = SkRig(tmp_path, monkeypatch)
    _, b64 = fake_sk_key(seed=2)
    rig.set_signers(
        signers_line("yubikey-a", rig.a.with_suffix(".pub")).split(" ssh-ed25519")[0]
        + " sk-ssh-ed25519@openssh.com "
        + fake_sk_key()[1],
        f'backup-1 namespaces="{NAMESPACE}" sk-ssh-ed25519@openssh.com {b64}',
        "# safo: yubikey-a require-pin",
    )
    rig.revoked.write_text("# nothing revoked yet\n")
    rig.revoked.chmod(0o644)
    problems, warnings = geminisign.check_report(rig.trust(hardware=True))
    assert problems == [] and len(warnings) == 1 and "backup-1 needs a touch but no PIN" in warnings[0]


def test_check_fails_on_no_touch_required_and_when_nothing_is_enrolled(rig: Rig) -> None:
    rig.set_signers(
        signers_line("yubikey-a", rig.a.with_suffix(".pub"), options=f'no-touch-required,namespaces="{NAMESPACE}"')
    )
    with refused("no-touch-required"):
        geminisign.check_report(rig.trust())
    rig.set_signers("# nothing")
    assert geminisign.check_report(rig.trust())[0]


def test_canonical_json_has_no_variance() -> None:
    assert geminisign.canonical({"b": 1, "a": "é"}) == '{"a":"\\u00e9","b":1}'


def test_check_warns_about_a_tier_two_passkey_in_the_same_file(rig: Rig) -> None:
    rig.set_signers(
        signers_line("yubikey-a", rig.a.with_suffix(".pub")),
        "# safo: yubikey-a allow-software",
        "# safo-passkey: label=laptop-1 rp=localhost origin=http://localhost:1 alg=ES256 id=AAAA key=AAAA",
    )
    _, warnings = geminisign.check_report(rig.trust())
    text = " ".join(warnings)
    assert "laptop-1 is a passkey (assurance tier 2)" in text and "passkey approvals are OFF" in text
    # and the SSH verifier is untouched by the extra line
    assert geminisign.verify(rig.trust(), PAYLOAD, rig.sign()).label == "yubikey-a"


# -- validity window: valid-after / valid-before are enforced, not just parsed ---------------------------------------

AT = dt.datetime(2026, 10, 29, 20, 0, tzinfo=dt.UTC)


def windowed(rig: Rig, after: str = "", before: str = "") -> None:
    options = f'namespaces="{NAMESPACE}"'
    if after:
        options += f',valid-after="{after}"'
    if before:
        options += f',valid-before="{before}"'
    rig.set_signers(signers_line("yubikey-a", rig.a.with_suffix(".pub"), options=options))


def test_a_key_inside_its_window_signs(rig: Rig) -> None:
    windowed(rig, "20260101Z", "20261231235959Z")
    assert geminisign.verify(rig.trust(), PAYLOAD, rig.sign(), now=AT).label == "yubikey-a"


@pytest.mark.parametrize(
    ("after", "before", "word"),
    [("", "20260101Z", "expired"), ("", "202610291959Z", "expired"), ("20270101Z", "", "not yet valid")],
)
def test_an_expired_or_not_yet_valid_key_is_refused_at_verify_and_shown_as_unusable(
    rig: Rig, after: str, before: str, word: str
) -> None:
    windowed(rig, after, before)
    with refused(word):
        geminisign.verify(rig.trust(), PAYLOAD, rig.sign(), now=AT)
    assert word in geminisign.key_rows(rig.trust(), AT)[0] and "NOT usable" in geminisign.key_rows(rig.trust(), AT)[0]
    problems, _ = geminisign.check_report(rig.trust(), AT)
    assert problems and "no usable key" in problems[0]


def test_the_window_edges_are_inclusive_and_use_the_clock_it_is_given(rig: Rig) -> None:
    windowed(rig, "20261029195900Z", "20261029200000Z")
    assert geminisign.verify(rig.trust(), PAYLOAD, rig.sign(), now=AT).label == "yubikey-a"
    with refused("expired"):
        geminisign.verify(rig.trust(), PAYLOAD, rig.sign(), now=AT + dt.timedelta(seconds=1))
    with refused("not yet valid"):
        geminisign.verify(rig.trust(), PAYLOAD, rig.sign(), now=AT - dt.timedelta(minutes=1, seconds=1))


def test_openssh_enforces_the_window_too_even_if_our_own_check_is_bypassed(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    windowed(rig, "", "20260101Z")
    monkeypatch.setattr(geminisign, "_window_problem", lambda key, now: None)
    with refused("does not verify"):
        geminisign.verify(rig.trust(), PAYLOAD, rig.sign(), now=AT)


@pytest.mark.parametrize("value", ["20261029", "soon", "2026-10-29Z", "20261029T1200Z", "202610291200"])
def test_a_window_time_must_be_utc_and_well_formed(rig: Rig, value: str) -> None:
    windowed(rig, "", value)
    with refused("valid-before"):
        geminisign.load_roster(rig.trust())
