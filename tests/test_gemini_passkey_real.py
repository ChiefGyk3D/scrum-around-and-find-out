# SPDX-License-Identifier: Apache-2.0
"""Assurance Tier 2 (#211): real WebAuthn assertion verification with the `cryptography` package.

The test file holds a software authenticator: it makes keys at test time, builds authenticator data and client data the
way a browser and an authenticator do, and signs with the private half. Nothing here is a stored key or a stored
signature, so there is no secret-shaped literal in the tree. Pathological inputs are built at run time as well.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from collections.abc import Callable

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from safo import geminipasskey as pk
from safo.geminipasskey import Passkey, Tier2Refused, Tier2Unavailable

ORIGIN = "http://localhost:41234"
RP = "localhost"
NOW = dt.datetime(2026, 10, 30, 12, 0, 0, tzinfo=dt.UTC)
NONCE = "0123456789abcdef"
PROMPT_DIGEST = hashlib.sha256(b"the prompt text").hexdigest()


def payload(**over: object) -> str:
    data: dict[str, object] = {
        "version": 1,
        "nonce": NONCE,
        "model": "gemini-3.6-flash",
        "prompt_sha256": PROMPT_DIGEST,
        "max_usd": "1.50",
        "job": "job-1",
        "created": "2026-10-30T11:55:00Z",
        "expires_at": "2026-10-30T12:25:00Z",
        "principal": "laptop-1",
    }
    data.update(over)
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


EXPECT = {"nonce": NONCE, "model": "gemini-3.6-flash", "prompt_sha256": PROMPT_DIGEST}


class Authenticator:
    """A software authenticator. Holds a private key; reports what a real one would."""

    def __init__(self, algorithm: str) -> None:
        self.algorithm = algorithm
        self.private: ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey
        if algorithm == "ES256":
            self.private = ec.generate_private_key(ec.SECP256R1())
        else:
            self.private = ed25519.Ed25519PrivateKey.generate()
        self.spki = self.private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.key = Passkey("laptop-1", RP, ORIGIN, algorithm, b"cred-id-1", self.spki)

    def sign(self, message: bytes) -> bytes:
        if isinstance(self.private, ec.EllipticCurvePrivateKey):
            return self.private.sign(message, ec.ECDSA(hashes.SHA256()))
        return self.private.sign(message)

    def assertion(
        self,
        text: str,
        *,
        flags: int = 0x05,
        counter: int = 7,
        rp: str = RP,
        client: dict[str, object] | None = None,
    ) -> tuple[bytes, bytes, bytes]:
        data: dict[str, object] = {
            "type": "webauthn.get",
            "challenge": pk.b64url(pk.challenge_for(text)),
            "origin": ORIGIN,
            "crossOrigin": False,
        }
        data.update(client or {})
        client_json = json.dumps(data).encode()
        auth = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + counter.to_bytes(4, "big")
        return client_json, auth, self.sign(auth + hashlib.sha256(client_json).digest())


@pytest.fixture(params=["ES256", "EdDSA"])
def device(request: pytest.FixtureRequest) -> Authenticator:
    return Authenticator(request.param)


def verify(
    device: Authenticator,
    assertion: tuple[bytes, bytes, bytes],
    *,
    text: str | None = None,
    key: Passkey | None = None,
    **over: object,
) -> pk.PasskeyResult:
    args: dict[str, object] = {
        "verifier": pk.CryptographyVerifier(),
        "allowed": True,
        "now": NOW,
        "expect": EXPECT,
    }
    args.update(over)
    client, auth, sig = assertion
    return pk.verify_assertion(key or device.key, text or payload(), client, auth, sig, **args)  # type: ignore[arg-type]


def test_a_good_assertion_verifies_for_both_algorithms(device: Authenticator) -> None:
    result = verify(device, device.assertion(payload()))
    assert (result.label, result.counter, result.user_verified, result.synced) == ("laptop-1", 7, True, False)


def test_the_counter_must_increase_against_stored_state(device: Authenticator) -> None:
    assertion = device.assertion(payload(), counter=7)
    assert verify(device, assertion, previous_counter=6).counter == 7
    for stored in (7, 8):
        with pytest.raises(Tier2Refused, match="counter"):
            verify(device, assertion, previous_counter=stored)


def test_a_wrong_key_does_not_verify(device: Authenticator) -> None:
    other = Authenticator(device.algorithm)
    wrong = Passkey("laptop-1", RP, ORIGIN, device.algorithm, b"cred-id-1", other.spki)
    with pytest.raises(Tier2Refused, match="signature does not verify"):
        verify(device, device.assertion(payload()), key=wrong)


def test_a_key_of_the_other_algorithm_does_not_verify() -> None:
    es, ed = Authenticator("ES256"), Authenticator("EdDSA")
    mixed = Passkey("laptop-1", RP, ORIGIN, "ES256", b"cred-id-1", ed.spki)
    with pytest.raises(Tier2Refused, match="public key"):
        verify(es, es.assertion(payload()), key=mixed)
    mixed = Passkey("laptop-1", RP, ORIGIN, "EdDSA", b"cred-id-1", es.spki)
    with pytest.raises(Tier2Refused, match="public key"):
        verify(ed, ed.assertion(payload()), key=mixed)


def test_a_p384_or_rsa_key_is_refused_for_es256() -> None:
    es = Authenticator("ES256")
    for private in (ec.generate_private_key(ec.SECP384R1()), rsa.generate_private_key(65537, 2048)):
        spki = private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key = Passkey("laptop-1", RP, ORIGIN, "ES256", b"cred-id-1", spki)
        with pytest.raises(Tier2Refused, match="public key"):
            verify(es, es.assertion(payload()), key=key)


def test_a_wrong_relying_party_id_is_refused(device: Authenticator) -> None:
    with pytest.raises(Tier2Refused, match="relying party"):
        verify(device, device.assertion(payload(), rp="evil.example"))


@pytest.mark.parametrize(
    ("flags", "match"),
    [(0x04, "presence"), (0x01, "verification"), (0x00, "presence"), (0x45, "carries parts"), (0x85, "carries parts")],
)
def test_a_flipped_flag_is_refused(device: Authenticator, flags: int, match: str) -> None:
    with pytest.raises(Tier2Refused, match=match):
        verify(device, device.assertion(payload(), flags=flags))


def test_a_signed_flag_flip_after_the_fact_breaks_the_signature(device: Authenticator) -> None:
    client, auth, sig = device.assertion(payload(), flags=0x01 | 0x04)
    flipped = auth[:32] + bytes([auth[32] | 0x08]) + auth[33:]  # backup-eligible bit turned on after signing
    with pytest.raises(Tier2Refused, match="signature does not verify"):
        verify(device, (client, flipped, sig))


def test_a_replayed_assertion_for_another_approval_is_refused(device: Authenticator) -> None:
    old = device.assertion(payload())
    with pytest.raises(Tier2Refused, match="challenge"):
        verify(device, old, text=payload(nonce="ffffffffffffffff"), expect={**EXPECT, "nonce": "ffffffffffffffff"})


@pytest.mark.parametrize("field", ["nonce", "model", "prompt_sha256"])
def test_the_approval_must_be_for_the_expected_nonce_model_and_prompt(device: Authenticator, field: str) -> None:
    # the passkey signs the changed approval text correctly; the caller's expectation is what stops it
    changed = payload(**{field: "x" * 16 if field != "prompt_sha256" else hashlib.sha256(b"other").hexdigest()})
    with pytest.raises(Tier2Refused, match=field):
        verify(device, device.assertion(changed), text=changed)


def test_a_missing_expected_field_in_the_approval_is_refused(device: Authenticator) -> None:
    data = json.loads(payload())
    del data["prompt_sha256"]
    text = json.dumps(data, sort_keys=True, separators=(",", ":"))
    with pytest.raises(Tier2Refused, match="prompt_sha256"):
        verify(device, device.assertion(text), text=text)


def test_a_wrong_challenge_and_a_wrong_origin_are_refused(device: Authenticator) -> None:
    other_challenge = pk.b64url(pk.challenge_for(payload(max_usd="9.00")))
    with pytest.raises(Tier2Refused, match="challenge"):
        verify(device, device.assertion(payload(), client={"challenge": other_challenge}))
    with pytest.raises(Tier2Refused, match="origin"):
        verify(device, device.assertion(payload(), client={"origin": "http://localhost:1"}))


def test_the_approval_expiry_is_the_hardware_path_rule(device: Authenticator) -> None:
    assertion = device.assertion(payload())
    expires = dt.datetime(2026, 10, 30, 12, 25, 0, tzinfo=dt.UTC)
    assert verify(device, assertion, now=expires - dt.timedelta(seconds=1)).counter == 7
    with pytest.raises(Tier2Refused, match="expired"):
        verify(device, assertion, now=expires)  # now >= expires_at is expired, as in gemini.py
    for broken in (payload(expires_at="tomorrow"), payload(expires_at=5)):
        with pytest.raises(Tier2Refused, match="expir"):
            verify(device, device.assertion(broken), text=broken)


def test_an_approval_that_is_not_a_json_object_is_refused(device: Authenticator) -> None:
    for text in ("not json", "[]", "5"):
        with pytest.raises(Tier2Refused, match="approval"):
            verify(device, device.assertion(text), text=text)


def test_truncated_data_is_refused_everywhere(device: Authenticator) -> None:
    client, auth, sig = device.assertion(payload())
    with pytest.raises(Tier2Refused, match="37 bytes"):
        verify(device, (client, auth[:36], sig))
    with pytest.raises(Tier2Refused):
        verify(device, (client[:-5], auth, sig))
    with pytest.raises(Tier2Refused, match="signature"):
        verify(device, (client, auth, sig[:-1]))
    with pytest.raises(Tier2Refused, match="signature"):
        verify(device, (client, auth, b""))


def test_oversized_input_is_refused_before_any_cryptography(device: Authenticator) -> None:
    client, auth, sig = device.assertion(payload())
    with pytest.raises(Tier2Refused, match="too large"):
        verify(device, (b"A" * (pk.MAX_CLIENT_DATA + 1), auth, sig))
    with pytest.raises(Tier2Refused, match="signature is too large"):
        verify(device, (client, auth, b"\x30" + b"A" * 5000))
    with pytest.raises(Tier2Refused, match="37 bytes"):
        verify(device, (client, auth + b"B" * 5000, sig))
    with pytest.raises(Tier2Refused, match="too large"):
        verify(device, device.assertion(payload()), text="{" + '"a":1,' * 40000 + '"b":2}')
    huge = Passkey("laptop-1", RP, ORIGIN, device.algorithm, b"c", b"\x30" + b"A" * 5000)
    with pytest.raises(Tier2Refused, match="public key"):
        verify(device, (client, auth, sig), key=huge)


def test_a_garbage_public_key_is_refused(device: Authenticator) -> None:
    junk = Passkey("laptop-1", RP, ORIGIN, device.algorithm, b"c", b"\x00" * 91)
    with pytest.raises(Tier2Refused, match="public key"):
        verify(device, device.assertion(payload()), key=junk)


def test_a_non_canonical_or_corrupt_es256_signature_is_refused() -> None:
    es = Authenticator("ES256")
    client, auth, sig = es.assertion(payload())
    r, s = decode_dss_signature(sig)
    padded = bytearray(encode_dss_signature(r, s))
    # BER-style long-form length on the outer sequence: same numbers, not canonical DER
    long_form = bytes([0x30, 0x81, padded[1]]) + bytes(padded[2:])
    for bad in (long_form, sig + b"\x00", bytes(len(sig))):
        with pytest.raises(Tier2Refused, match="signature"):
            verify(es, (client, auth, bad))


def test_an_ed25519_signature_must_be_exactly_64_bytes() -> None:
    ed = Authenticator("EdDSA")
    client, auth, sig = ed.assertion(payload())
    for bad in (sig + b"\x00", sig[:63]):
        with pytest.raises(Tier2Refused, match="signature"):
            verify(ed, (client, auth, bad))


def test_an_unknown_algorithm_is_refused(device: Authenticator) -> None:
    with pytest.raises(Tier2Refused, match="algorithm"):
        pk.CryptographyVerifier().verify("RS256", device.spki, b"m", b"s")


def test_both_algorithms_parse_from_the_trust_file(device: Authenticator) -> None:
    line = (
        f"# safo-passkey: label=laptop-1 rp=localhost origin={ORIGIN} alg={device.algorithm} "
        f"id={pk.b64url(b'cred-id-1')} key={pk.b64url(device.spki)}"
    )
    assert pk.parse_passkeys(line) == [device.key]


def test_without_the_library_the_verifier_says_how_to_get_it(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import: Callable[..., object] = builtins.__import__

    def refuse(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("cryptography"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse)
    with pytest.raises(Tier2Unavailable, match=r"safo\[passkeys\]"):
        pk.CryptographyVerifier().verify("ES256", b"k", b"m", b"s")


def test_the_module_import_does_not_need_the_library() -> None:
    import subprocess
    import sys

    code = (
        "import sys; sys.modules['cryptography']=None; import safo.geminipasskey as p; assert p.NoVerifier is not None"
    )
    done = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=False)  # noqa: S603
    assert done.returncode == 0, done.stderr


# -- packaging: the library is an optional, hash-locked extra ------------------------------------------------------

ROOT = __import__("pathlib").Path(__file__).resolve().parent.parent


def test_the_library_is_an_optional_extra_pinned_and_hash_locked() -> None:
    import re
    import tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["dependencies"] == ["PyYAML==6.0.3"]  # a plain install and the Action never carry it
    pinned = [r for r in project["optional-dependencies"]["passkeys"] if r.startswith("cryptography==")]
    assert len(pinned) == 1
    assert pinned[0] in (ROOT / "requirements-passkey.in").read_text().splitlines()
    for name in ("requirements-passkey.txt", "requirements-dev.txt"):
        lock = (ROOT / name).read_text()
        found = dict(re.findall(r"^([A-Za-z0-9_.-]+)==(\S+) \\$", lock, re.MULTILINE))
        assert found["cryptography"] == pinned[0].split("==")[1]
        assert lock.count("--hash=sha256:") >= 10
    assert "cryptography" not in (ROOT / "requirements.txt").read_text()


# -- the caller must say which approval it expects (round 2) --------------------------------------------------------


def test_expect_is_required_and_must_name_nonce_model_and_prompt_digest(device: Authenticator) -> None:
    assertion = device.assertion(payload())
    client, auth, sig = assertion
    with pytest.raises(TypeError):  # no `expect` at all: not a call that can be made
        pk.verify_assertion(  # type: ignore[call-arg]
            device.key, payload(), client, auth, sig, verifier=pk.CryptographyVerifier(), allowed=True, now=NOW
        )
    for bad in (
        {},
        None,
        {"nonce": NONCE, "model": EXPECT["model"]},  # prompt digest missing
        {"nonce": NONCE, "prompt_sha256": PROMPT_DIGEST},  # model missing
        {"model": EXPECT["model"], "prompt_sha256": PROMPT_DIGEST},  # nonce missing
        {**EXPECT, "nonce": ""},  # empty value
        {**EXPECT, "model": ""},
        {**EXPECT, "prompt_sha256": ""},
        {**EXPECT, "nonce": 5},  # not text
        {**EXPECT, "model": "gemini-other"},  # mismatch
    ):
        with pytest.raises(Tier2Refused, match="expect"):
            verify(device, assertion, expect=bad)
    assert verify(device, assertion, expect={**EXPECT, "job": "job-1"}).counter == 7


def test_an_empty_signed_field_never_matches_an_empty_expectation(device: Authenticator) -> None:
    text = payload(nonce="")
    with pytest.raises(Tier2Refused, match="expect"):
        verify(device, device.assertion(text), text=text, expect={**EXPECT, "nonce": ""})
