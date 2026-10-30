# SPDX-License-Identifier: Apache-2.0
"""Assurance Tier 2 (#200): the rules around a passkey assertion, against a FAKE signature verifier.

No cryptography is exercised here on purpose: the project ships no library for it, and the choice is the maintainer's
(docs/gemini-passkeys.md). The fake records what it was asked to verify, so the tests prove the message and the key
are the right ones, and that every other rule bites. Tier 2 is not shippable until a real verifier is chosen.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json

import pytest

from safo import geminipasskey as pk
from safo.geminipasskey import Passkey, Tier2Refused, Tier2Unavailable

PAYLOAD = (
    '{"expires_at":"2026-10-30T12:25:00Z","job":"job-1","max_usd":"1.50",'
    '"model":"m-1","nonce":"n-1","prompt_sha256":"p-1"}'
)
EXPECT = {"nonce": "n-1", "model": "m-1", "prompt_sha256": "p-1"}
NOW = dt.datetime(2026, 10, 30, 12, 0, 0, tzinfo=dt.UTC)
ORIGIN = "http://localhost:41234"
RP = "localhost"
KEY = Passkey("laptop-1", RP, ORIGIN, "ES256", b"cred-id-1", b"spki-der-bytes")


class FakeVerifier:
    def __init__(self, result: bool = True) -> None:
        self.result = result
        self.calls: list[tuple[str, bytes, bytes, bytes]] = []

    def verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        self.calls.append((algorithm, public_key, message, signature))
        return self.result


def auth_data(*, flags: int = 0x05, counter: int = 5, rp: str = RP) -> bytes:
    return hashlib.sha256(rp.encode()).digest() + bytes([flags]) + counter.to_bytes(4, "big")


def client_data(**over: object) -> bytes:
    data: dict[str, object] = {
        "type": "webauthn.get",
        "challenge": pk.b64url(pk.challenge_for(PAYLOAD)),
        "origin": ORIGIN,
        "crossOrigin": False,
    }
    data.update(over)
    return json.dumps(data).encode()


def check(fake: pk.SignatureVerifier | None = None, **over: object) -> pk.PasskeyResult:
    args: dict[str, object] = {
        "key": KEY,
        "canonical_payload": PAYLOAD,
        "client_data_json": client_data(),
        "authenticator_data": auth_data(),
        "signature": b"sig",
        "verifier": fake or FakeVerifier(),
        "allowed": True,
        "now": NOW,
        "expect": EXPECT,
    }
    args.update(over)
    return pk.verify_assertion(**args)  # type: ignore[arg-type]


def test_a_good_assertion_counts_and_the_verifier_gets_the_right_message_and_key() -> None:
    fake = FakeVerifier()
    result = check(fake)
    assert result.label == "laptop-1" and result.user_verified and not result.synced and result.counter == 5
    algorithm, key, message, signature = fake.calls[0]
    assert (algorithm, key, signature) == ("ES256", b"spki-der-bytes", b"sig")
    assert message == auth_data() + hashlib.sha256(client_data()).digest()


def test_the_challenge_is_the_hash_of_the_same_canonical_text_tier_one_signs() -> None:
    assert pk.challenge_for(PAYLOAD) == hashlib.sha256(PAYLOAD.encode()).digest()
    with pytest.raises(Tier2Refused, match="challenge"):
        check(canonical_payload=PAYLOAD.replace("1.50", "2.00"))


def test_it_is_off_unless_the_trust_file_says_so() -> None:
    with pytest.raises(Tier2Refused, match="off"):
        check(allowed=False)
    assert pk.passkeys_allowed("# safo-policy: allow-passkeys\n") is True
    for text in ("", "# safo-policy: allow-everything\n", "allow-passkeys\n", "# safo: allow-passkeys\n"):
        assert pk.passkeys_allowed(text) is False


@pytest.mark.parametrize(
    ("over", "match"),
    [
        ({"client_data_json": client_data(type="webauthn.create")}, "type"),
        ({"client_data_json": client_data(origin="http://localhost:9")}, "origin"),
        ({"client_data_json": client_data(origin="http://localhost:41234.evil.example")}, "origin"),
        ({"client_data_json": client_data(crossOrigin=True)}, "cross-origin"),
        ({"client_data_json": client_data(challenge="AAAA")}, "challenge"),
        ({"client_data_json": client_data(challenge=5)}, "challenge"),
        ({"client_data_json": b"not json"}, "JSON"),
        ({"client_data_json": b"[]"}, "type"),
        ({"client_data_json": b"x" * 5000}, "too large"),
        ({"authenticator_data": auth_data(rp="evil.example")}, "relying party"),
        ({"authenticator_data": auth_data(flags=0x04)}, "presence"),
        ({"authenticator_data": auth_data(flags=0x01)}, "verification"),
        ({"authenticator_data": auth_data() + b"\x00"}, "37 bytes"),
        ({"authenticator_data": auth_data(flags=0x45)}, "carries parts"),
        ({"authenticator_data": auth_data(flags=0x85)}, "carries parts"),
    ],
)
def test_every_rule_around_the_signature_bites(over: dict[str, object], match: str) -> None:
    fake = FakeVerifier()
    with pytest.raises(Tier2Refused, match=match):
        check(fake, **over)
    assert fake.calls == [] or match == "signature"


def test_a_signature_that_does_not_verify_is_refused() -> None:
    with pytest.raises(Tier2Refused, match="signature does not verify"):
        check(FakeVerifier(False))


def test_the_counter_must_increase_but_a_zero_counter_authenticator_is_allowed() -> None:
    assert check(previous_counter=4).counter == 5
    with pytest.raises(Tier2Refused, match="counter"):
        check(previous_counter=5)
    with pytest.raises(Tier2Refused, match="counter"):
        check(authenticator_data=auth_data(counter=3), previous_counter=5)
    assert check(authenticator_data=auth_data(counter=0), previous_counter=None).counter == 0
    assert check(authenticator_data=auth_data(counter=0), previous_counter=0).counter == 0


def test_a_synced_credential_is_reported_as_synced() -> None:
    assert check(authenticator_data=auth_data(flags=0x1D)).synced is True


def test_a_revoked_credential_is_refused_by_fingerprint() -> None:
    with pytest.raises(Tier2Refused, match="revoked"):
        check(revoked=frozenset({pk.credential_fingerprint(KEY)}))


def test_the_default_verifier_refuses_everything_until_a_library_is_chosen() -> None:
    with pytest.raises(Tier2Unavailable, match="no signature-verification library"):
        check(pk.NoVerifier())


def test_passkey_lines_in_the_trust_file_parse_and_are_strict() -> None:
    cred, spki = pk.b64url(b"cred-id-1"), pk.b64url(b"spki-der-bytes")
    line = f"# safo-passkey: label=laptop-1 rp=localhost origin=http://localhost:41234 alg=ES256 id={cred} key={spki}"
    text = f"# comment\n{line}\nbackup-1 ssh-ed25519 AAAA\n"
    assert pk.parse_passkeys(text) == [KEY]
    for broken in (
        line.replace("alg=ES256", "alg=RS256"),
        line.replace("label=laptop-1", "label=Bad_Label"),
        line.replace(" rp=localhost", ""),
        line.replace("origin=http://localhost:41234", "origin=ftp://x"),
    ):
        with pytest.raises(Tier2Refused):
            pk.parse_passkeys(broken)
    with pytest.raises(Tier2Refused, match="unique"):
        pk.parse_passkeys(line + "\n" + line)


def test_a_passkey_line_is_only_a_comment_to_the_ssh_side() -> None:
    from safo import geminisign

    line = "# safo-passkey: label=laptop-1 rp=localhost origin=http://localhost:1 alg=ES256 id=AAAA key=AAAA"
    assert geminisign.parse_signers(line + "\n# safo-policy: allow-passkeys\n") == []


def test_keys_check_warns_about_passkeys() -> None:
    notes = pk.check_warnings([KEY], allowed=False)
    assert any("OFF" in n for n in notes) and any("synced passkey is only as strong" in n for n in notes)
    assert pk.check_warnings([KEY], allowed=True)[0].startswith("laptop-1 is a passkey (assurance tier 2)")
    assert pk.check_warnings([], allowed=False) == []
