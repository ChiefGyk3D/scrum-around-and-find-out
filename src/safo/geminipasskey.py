# SPDX-License-Identifier: Apache-2.0
"""Assurance Tier 2 for Gemini approvals: a WebAuthn passkey assertion (#200). NOT SHIPPABLE until the maintainer
decides the dependency question in docs/gemini-passkeys.md.

Tier 1 (a hardware sk key signed through OpenSSH, `safo.geminisign`) is the recommended default. This module is the
verifier side of Tier 2 and nothing else: the rules that decide whether an assertion counts, written against a small
interface so that the one piece that needs real cryptography (checking a signature) is injected, not hand-rolled here.

Nothing here is wired into `ApprovalStore`, and `Tier2Unavailable` is what the default verifier raises, so no passkey
assertion can authorize anything today. What is real and tested: the challenge (the hash of the same canonical approval
JSON that Tier 1 signs), the parsing of the authenticator data, and every rule around the signature (relying party
hash, origin, challenge, user presence, user verification REQUIRED, counter, revocation, per-credential labels).

An assertion carries only what the authenticator reports. User verification is a flag the authenticator sets; a synced
passkey is as strong as the cloud account and device unlock behind it; software that drives a browser can ask for an
assertion. See docs/gemini-passkeys.md for why Tier 1 is the recommendation.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import re
from typing import Protocol

from safo.bounded import loads
from safo.errors import SafoError
from safo.geminisign import LABEL

PASSKEY_LINE = re.compile(r"#\s*safo-passkey:\s*(?P<fields>.+)$")
POLICY_LINE = re.compile(r"#\s*safo-policy:\s*(?P<flag>\S+)\s*$")
ALGORITHMS = ("ES256",)  # ECDSA P-256 with SHA-256: the one algorithm every platform and hardware authenticator offers
FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08  # backup eligible: the credential can be synced, so it is a passkey in the cloud
FLAG_BS = 0x10  # backed up now
FLAG_AT = 0x40
FLAG_ED = 0x80
MAX_CLIENT_DATA = 4096


class Tier2Unavailable(SafoError):
    """The signature check for a passkey needs a cryptography dependency that has not been chosen."""


class Tier2Refused(SafoError):
    """An assertion that does not count; the message says which rule stopped it. Nothing is authorized."""


class SignatureVerifier(Protocol):
    """The one injected piece. A real implementation checks `signature` over `message` with `public_key` (a
    SubjectPublicKeyInfo DER, what `AuthenticatorAttestationResponse.getPublicKey()` returns) using a reviewed library,
    never hand-rolled code."""

    def verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool: ...


class NoVerifier:
    """The default until a dependency is chosen: refuses, so a passkey can never authorize anything."""

    def verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        raise Tier2Unavailable("passkey approvals are not available: no signature-verification library has been chosen")


@dataclasses.dataclass(frozen=True)
class Passkey:
    """An enrolled public credential. Everything here is public; the private half stays in the authenticator."""

    label: str
    rp_id: str  # the relying party id; for the loopback page this is `localhost`
    origin: str  # the exact origin the page is served from, scheme, host and port
    algorithm: str
    credential_id: bytes
    public_key: bytes  # SPKI DER


@dataclasses.dataclass(frozen=True)
class AuthData:
    rp_id_hash: bytes
    flags: int
    counter: int

    @property
    def user_present(self) -> bool:
        return bool(self.flags & FLAG_UP)

    @property
    def user_verified(self) -> bool:
        return bool(self.flags & FLAG_UV)

    @property
    def synced(self) -> bool:
        """The authenticator says the credential is backup-eligible: it can live in a cloud account."""
        return bool(self.flags & FLAG_BE)


@dataclasses.dataclass(frozen=True)
class PasskeyResult:
    label: str
    counter: int
    user_verified: bool
    synced: bool


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise Tier2Refused("not base64url") from None


def challenge_for(canonical_payload: str) -> bytes:
    """What the browser is asked to sign: the SHA-256 of the same canonical approval JSON that Tier 1 signs, so the two
    tiers bind the same text (job, model, amount, expiry, nonce, ledger head, quote, principal)."""
    return hashlib.sha256(canonical_payload.encode()).digest()


def parse_authenticator_data(data: bytes) -> AuthData:
    """An assertion's authenticator data is 32 bytes of relying-party hash, one flags byte and a 4-byte counter, then
    optional parts. A flag that announces attested credential data or extensions in an assertion is refused, so the
    parser never has to read CBOR."""
    if len(data) != 37:
        raise Tier2Refused("the authenticator data is not the 37 bytes of a plain assertion")
    flags = data[32]
    if flags & (FLAG_AT | FLAG_ED):
        raise Tier2Refused("the authenticator data carries parts an assertion does not need")
    return AuthData(data[:32], flags, int.from_bytes(data[33:37], "big"))


def parse_passkeys(text: str) -> list[Passkey]:
    """`# safo-passkey: label=NAME rp=ID origin=ORIGIN alg=ES256 id=CREDENTIAL_ID_B64URL key=SPKI_B64URL` lines of the
    maintainer-edited trust file. They are comments to ssh-keygen, so Tier 1 never sees them."""
    found: list[Passkey] = []
    for number, raw in enumerate(text.splitlines(), 1):
        match = PASSKEY_LINE.fullmatch(raw.strip())
        if not match:
            continue
        fields = dict(part.split("=", 1) for part in match.group("fields").split() if "=" in part)
        if set(fields) != {"label", "rp", "origin", "alg", "id", "key"}:
            raise Tier2Refused(f"trust file line {number}: a safo-passkey line needs label, rp, origin, alg, id, key")
        if not LABEL.fullmatch(fields["label"]) or any(p.label == fields["label"] for p in found):
            raise Tier2Refused(f"trust file line {number}: the label is not a plain unique name")
        if fields["alg"] not in ALGORITHMS:
            raise Tier2Refused(f"trust file line {number}: only ES256 is accepted")
        if not re.fullmatch(r"https?://[A-Za-z0-9.\[\]:-]{1,80}", fields["origin"]) or not re.fullmatch(
            r"[A-Za-z0-9.-]{1,80}", fields["rp"]
        ):
            raise Tier2Refused(f"trust file line {number}: the origin or relying party id is malformed")
        found.append(
            Passkey(
                fields["label"],
                fields["rp"],
                fields["origin"],
                fields["alg"],
                b64url_decode(fields["id"]),
                b64url_decode(fields["key"]),
            )
        )
    return found


def passkeys_allowed(text: str) -> bool:
    """Tier 2 is off unless the root-owned trust file says `# safo-policy: allow-passkeys`. It is not a setting in the
    account's own gemini.yaml, which the agent's account can edit."""
    found = (POLICY_LINE.fullmatch(line.strip()) for line in text.splitlines())
    return any(m is not None and m.group("flag") == "allow-passkeys" for m in found)


def credential_fingerprint(key: Passkey) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.public_key).digest()).decode().rstrip("=")


def verify_assertion(
    key: Passkey,
    canonical_payload: str,
    client_data_json: bytes,
    authenticator_data: bytes,
    signature: bytes,
    *,
    verifier: SignatureVerifier,
    previous_counter: int | None = None,
    revoked: frozenset[str] = frozenset(),
    allowed: bool = False,
) -> PasskeyResult:
    """Every rule for a passkey approval, in the order a failure is cheapest to explain. The signature check is last and
    goes through `verifier`."""
    if not allowed:
        raise Tier2Refused("passkey approvals are off: the trust file has no `# safo-policy: allow-passkeys` line")
    if credential_fingerprint(key) in revoked:
        raise Tier2Refused(f"the passkey {key.label} is revoked")
    if len(client_data_json) > MAX_CLIENT_DATA:
        raise Tier2Refused("the client data is too large")
    try:
        client = loads(client_data_json)
    except (ValueError, UnicodeError):
        raise Tier2Refused("the client data is not JSON") from None
    if not isinstance(client, dict) or client.get("type") != "webauthn.get":
        raise Tier2Refused("the client data is not a sign-in assertion (type)")
    if client.get("crossOrigin") is True:
        raise Tier2Refused("the assertion was made from a cross-origin frame")
    if client.get("origin") != key.origin:
        raise Tier2Refused("the assertion is for another origin")
    challenge = client.get("challenge")
    if not isinstance(challenge, str) or b64url_decode(challenge) != challenge_for(canonical_payload):
        raise Tier2Refused("the assertion's challenge is not the hash of this approval")
    auth = parse_authenticator_data(authenticator_data)
    if auth.rp_id_hash != hashlib.sha256(key.rp_id.encode()).digest():
        raise Tier2Refused("the assertion is for another relying party")
    if not auth.user_present:
        raise Tier2Refused("the authenticator did not report user presence")
    if not auth.user_verified:
        raise Tier2Refused("the authenticator did not report user verification (required for approvals)")
    if previous_counter is not None and (auth.counter or previous_counter) and auth.counter <= previous_counter:
        raise Tier2Refused("the signature counter did not increase (a cloned or replayed credential)")
    message = authenticator_data + hashlib.sha256(client_data_json).digest()
    if not verifier.verify(key.algorithm, key.public_key, message, signature):
        raise Tier2Refused("the assertion's signature does not verify")
    return PasskeyResult(key.label, auth.counter, auth.user_verified, auth.synced)


def check_warnings(keys: list[Passkey], allowed: bool) -> list[str]:
    """What `keys check` says about Tier 2 credentials."""
    notes: list[str] = []
    if keys and not allowed:
        notes.append("passkeys are enrolled but passkey approvals are OFF (no `# safo-policy: allow-passkeys` line)")
    for key in keys:
        notes.append(
            f"{key.label} is a passkey (assurance tier 2): a synced passkey is only as strong as the cloud account and "
            "device unlock behind it, and software that drives a browser can ask it to sign; "
            "prefer a hardware security key (tier 1)"
        )
    return notes
