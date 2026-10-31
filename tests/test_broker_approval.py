# SPDX-License-Identifier: Apache-2.0
"""Verifying a signed approval: the signature, the namespace, the canonical text, the signer and revocation. Software
ed25519 keys made by ssh-keygen stand in for the hardware key; a temporary allowed-signers file stands in for root's."""

from __future__ import annotations

import datetime as dt
import inspect
import json
from functools import partial
from pathlib import Path
from typing import Any

import pytest

from geminidata import make_key, signers_line
from pipedata import LABEL, Rig, as_hardware, text_req
from safo import geminisign
from safo.broker.approval import verify_approval
from safo.broker.errors import Refused
from safo.broker.records import ApprovalV3


@pytest.fixture(scope="module")
def key(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_key(tmp_path_factory.mktemp("keys") / "a")


@pytest.fixture(scope="module")
def other_key(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return make_key(tmp_path_factory.mktemp("keys") / "b")


@pytest.fixture
def rig(tmp_path: Path, key: Path) -> Rig:
    return Rig(tmp_path, key)


def code_of(call: Any) -> str:
    with pytest.raises(Refused) as err:
        call()
    return err.value.code


def check(rig: Rig, text: object, sig: object) -> ApprovalV3:
    return verify_approval(text, sig, rig.trust, now=rig.clock.wall(), verifier=as_hardware)


def good(rig: Rig, **over: Any) -> tuple[str, str]:
    req = text_req()
    text = rig.text(req, rig.offer(req), **over)
    return text, rig.sign(text)


def signed_code(rig: Rig, text: str) -> str:
    """The refusal code for a text that carries a VALID signature of its own bytes."""
    return code_of(partial(check, rig, text, rig.sign(text)))


def test_a_good_approval_is_verified_and_parsed(rig: Rig) -> None:
    text, sig = good(rig)
    got = check(rig, text, sig)
    assert got.model == "flat-test" and got.principal == LABEL and got.max_micro == 2_500_000


def test_a_changed_byte_in_the_signed_text_does_not_verify(rig: Rig) -> None:
    text, sig = good(rig)
    other = text.replace('"job-one"', '"job-two"')
    assert other != text and code_of(partial(check, rig, other, sig)) == "bad_approval"


def test_a_signature_over_a_different_spelling_of_the_same_approval_is_refused(rig: Rig) -> None:
    """Signer and verifier must agree on the bytes: spaces, key order or an escaped letter make a different text, and
    even a valid signature over it is not an approval, because only the canonical form is accepted."""
    text, _ = good(rig)
    data = json.loads(text)
    spellings = [
        json.dumps(data, sort_keys=True),  # spaces after the separators
        json.dumps(dict(reversed(list(data.items()))), separators=(",", ":")),  # another key order
        text.replace('"flat-test"', '"flat\\u002dtest"'),  # an escaped character
        text + "\n",  # a trailing newline
        " " + text,
    ]
    for spelling in spellings:
        assert spelling != text
        assert signed_code(rig, spelling) == "bad_approval"


def test_non_ascii_text_is_refused_before_it_is_verified(rig: Rig) -> None:
    text, sig = good(rig)
    assert code_of(partial(check, rig, text.replace("go ahead", "go ahead é"), sig)) == "bad_approval"
    assert code_of(partial(check, rig, text + "\ud800", sig)) == "bad_approval"


def test_a_signature_from_the_dry_run_namespace_is_refused(rig: Rig) -> None:
    text, _ = good(rig)
    sig = rig.sign(text, namespace=geminisign.DRYRUN_NAMESPACE)
    assert code_of(partial(check, rig, text, sig)) == "bad_approval"


@pytest.mark.parametrize("namespace", ["file", "git", "safo-gemini-approval-x", "safo-gemini", "SAFO-GEMINI-APPROVAL"])
def test_a_signature_from_any_other_namespace_is_refused(rig: Rig, namespace: str) -> None:
    text, _ = good(rig)
    assert code_of(partial(check, rig, text, rig.sign(text, namespace=namespace))) == "bad_approval"


def test_the_namespace_is_not_a_choice_of_the_caller() -> None:
    assert "namespace" not in inspect.signature(verify_approval).parameters


def test_a_key_that_is_not_enrolled_is_refused(rig: Rig, other_key: Path) -> None:
    text, _ = good(rig)
    assert code_of(partial(check, rig, text, rig.sign(text, key=other_key))) == "bad_approval"


def test_a_revoked_key_is_refused_with_the_revoked_code(rig: Rig, key: Path) -> None:
    text, sig = good(rig)
    pub = key.with_suffix(".pub").read_text().split()
    rig.revoked.write_text(f"{pub[0]} {pub[1]}\n")
    assert code_of(partial(check, rig, text, sig)) == "revoked"


def test_a_missing_or_group_writable_trust_file_fails_closed(rig: Rig) -> None:
    text, sig = good(rig)
    rig.signers.chmod(0o666)
    assert code_of(partial(check, rig, text, sig)) == "bad_approval"
    rig.signers.chmod(0o644)
    rig.signers.unlink()
    assert code_of(partial(check, rig, text, sig)) == "bad_approval"


def test_trust_files_owned_by_someone_else_fail_closed(rig: Rig) -> None:
    text, sig = good(rig)
    other = geminisign.Trust(rig.signers, rig.revoked, 4242, False, False)
    assert (
        code_of(partial(verify_approval, text, sig, other, now=rig.clock.wall(), verifier=as_hardware))
        == "bad_approval"
    )


def test_a_software_key_without_the_written_opt_in_is_refused_when_hardware_is_required(rig: Rig) -> None:
    text, sig = good(rig)
    strict = geminisign.Trust(rig.signers, rig.revoked, rig.trust.uid, True, False)
    assert (
        code_of(partial(verify_approval, text, sig, strict, now=rig.clock.wall(), verifier=as_hardware))
        == "bad_approval"
    )


def test_a_key_outside_its_validity_window_is_refused(rig: Rig, key: Path) -> None:
    text, sig = good(rig)
    options = f'namespaces="{geminisign.NAMESPACE}",valid-before="20260101000000Z"'
    rig.signers.write_text(signers_line(LABEL, key.with_suffix(".pub"), options=options) + "\n")
    assert code_of(partial(check, rig, text, sig)) == "bad_approval"


def test_the_signing_key_must_be_the_principal_named_in_the_text(rig: Rig, key: Path, other_key: Path) -> None:
    text = rig.text(text_req(), rig.offer(text_req()), principal="yubikey-b")
    rig.signers.write_text(
        signers_line(LABEL, key.with_suffix(".pub"))
        + "\n"
        + signers_line("yubikey-b", other_key.with_suffix(".pub"))
        + "\n"
    )
    assert code_of(partial(check, rig, text, rig.sign(text))) == "bad_approval"  # signed by a, claims b
    assert check(rig, text, rig.sign(text, key=other_key)).principal == "yubikey-b"


@pytest.mark.parametrize("bad", [None, 5, b"x", ["x"], "", "x" * 20_000])
def test_a_payload_or_signature_of_the_wrong_kind_or_size_is_refused(rig: Rig, bad: object) -> None:
    text, sig = good(rig)
    assert code_of(partial(check, rig, bad, sig)) == "bad_approval"
    assert code_of(partial(check, rig, text, bad)) == "bad_approval"


def test_a_str_subclass_cannot_stand_in_for_the_text(rig: Rig) -> None:
    class Sneaky(str):
        pass

    text, sig = good(rig)
    assert code_of(partial(check, rig, Sneaky(text), sig)) == "bad_approval"
    assert code_of(partial(check, rig, text, Sneaky(sig))) == "bad_approval"


def test_a_signed_text_in_an_older_or_unknown_version_is_refused_even_when_signed(rig: Rig) -> None:
    offer = rig.offer(text_req())
    for version in (1, 2, 4):
        text = rig.text(text_req(), offer, version=version)
        assert signed_code(rig, text) == "bad_approval"


def test_a_signed_text_with_an_extra_or_missing_field_is_refused(rig: Rig) -> None:
    offer = rig.offer(text_req())
    for over in ({"surprise": 1}, {"issue": None}, {"nonce": "XYZ"}, {"max_usd": "2.50"}, {"beyond_ceiling": 1}):
        text = rig.text(text_req(), offer, **over)
        assert signed_code(rig, text) == "bad_approval"


def test_a_plain_time_is_required(rig: Rig) -> None:
    text, sig = good(rig)
    naive = dt.datetime(2026, 10, 30, 12, 0, 0)
    assert code_of(partial(verify_approval, text, sig, rig.trust, now=naive, verifier=as_hardware)) == "bad_request"


def test_no_message_echoes_the_text_or_the_signature(rig: Rig) -> None:
    text, sig = good(rig)
    with pytest.raises(Refused) as err:
        check(rig, text.replace("job-one", "SENTINEL-JOB"), sig)
    assert "SENTINEL" not in str(err.value) and sig[40:60] not in str(err.value)
