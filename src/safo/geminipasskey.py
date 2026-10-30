# SPDX-License-Identifier: Apache-2.0
"""Assurance Tier 2 for Gemini approvals: a WebAuthn passkey assertion (#200, #211). Opt-in, off by default.

Tier 1 (a hardware sk key signed through OpenSSH, `safo.geminisign`) is the recommended default. This module is the
verifier side of Tier 2 and nothing else: the rules that decide whether an assertion counts, and a real signature
check (`CryptographyVerifier`, ES256 and EdDSA) through the reviewed `cryptography` package, which is the optional
extra `safo[passkeys]` (hash-locked in requirements-passkey.txt). The module imports without it; only the verifier
needs it. No network, no CBOR: the public key is the SubjectPublicKeyInfo the browser reports at enrollment.

Nothing here is wired into `ApprovalStore`, and paid use stays disabled by its own root-owned switch (#205), so no
passkey assertion can authorize spend today. Every parse or length problem is a refusal.

An assertion carries only what the authenticator reports. User verification is a flag the authenticator sets; a synced
passkey is as strong as the cloud account and device unlock behind it; software that drives a browser can ask for an
assertion. See docs/gemini-passkeys.md for why Tier 1 is the recommendation.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import datetime as dt
import hashlib
import hmac
import re
from collections.abc import Mapping
from typing import Protocol

from safo.bounded import loads
from safo.errors import SafoError
from safo.geminisign import LABEL

PASSKEY_LINE = re.compile(r"#\s*safo-passkey:\s*(?P<fields>.+)$")
POLICY_LINE = re.compile(r"#\s*safo-policy:\s*(?P<flag>\S+)\s*$")
ALGORITHMS = ("ES256", "EdDSA")  # ECDSA P-256 with SHA-256 (COSE -7) and Ed25519 (COSE -8)
FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08  # backup eligible: the credential can be synced, so it is a passkey in the cloud
FLAG_BS = 0x10  # backed up now
FLAG_AT = 0x40
FLAG_ED = 0x80
MAX_CLIENT_DATA = 4096
REQUIRED_EXPECT = ("nonce", "model", "prompt_sha256")  # the caller must name all three, non-empty
MAX_PAYLOAD = 8192  # the canonical approval JSON is a few hundred bytes
MAX_SIGNATURE = 128  # a DER ES256 signature is at most 72 bytes, an Ed25519 signature is 64
MAX_PUBLIC_KEY = 256  # a P-256 or Ed25519 SubjectPublicKeyInfo is 91 or 44 bytes


class Tier2Unavailable(SafoError):
    """The signature check for a passkey needs the optional `cryptography` package, which is not installed."""


class Tier2Refused(SafoError):
    """An assertion that does not count; the message says which rule stopped it. Nothing is authorized."""


class SignatureVerifier(Protocol):
    """The one injected piece. A real implementation checks `signature` over `message` with `public_key` (a
    SubjectPublicKeyInfo DER, what `AuthenticatorAttestationResponse.getPublicKey()` returns) using a reviewed library,
    never hand-rolled code."""

    def verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool: ...


class NoVerifier:
    """Refuses everything. For callers that must pass a verifier but must never authorize."""

    def verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        raise Tier2Unavailable("passkey approvals are not available: no signature-verification library has been chosen")


class CryptographyVerifier:
    """Checks an ES256 or EdDSA WebAuthn signature with the `cryptography` package (imported when used, so people who
    never use passkeys do not need it). A key of the wrong type or curve, a signature that is not canonical or the wrong
    length, or an unknown algorithm is refused, never guessed at. A signature that is well formed but wrong is False."""

    def verify(self, algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec, ed25519
            from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        except ImportError:
            raise Tier2Unavailable(
                "passkey approvals need the cryptography package: pip install 'safo[passkeys]' "
                "(hash-locked in requirements-passkey.txt)"
            ) from None
        if algorithm not in ALGORITHMS:
            raise Tier2Refused("the passkey algorithm is not one safo accepts")
        if not 0 < len(public_key) <= MAX_PUBLIC_KEY or not 0 < len(signature) <= MAX_SIGNATURE:
            raise Tier2Refused("the public key or the signature has an impossible length")
        try:
            key = serialization.load_der_public_key(public_key)
            canonical_key = key.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except (ValueError, TypeError):
            raise Tier2Refused("the public key is not a SubjectPublicKeyInfo") from None
        if canonical_key != public_key:
            raise Tier2Refused("the public key has trailing or non-canonical bytes")
        try:
            if algorithm == "ES256":
                if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
                    raise Tier2Refused("the public key is not a P-256 key (ES256)")
                try:
                    decode_dss_signature(signature)  # strict DER: the library refuses BER forms and bad padding
                except ValueError:
                    raise Tier2Refused("the signature is not a DER ECDSA signature") from None
                key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            else:
                if not isinstance(key, ed25519.Ed25519PublicKey):
                    raise Tier2Refused("the public key is not an Ed25519 key (EdDSA)")
                if len(signature) != 64:
                    raise Tier2Refused("an Ed25519 signature is exactly 64 bytes")
                key.verify(signature, message)
        except InvalidSignature:
            return False
        return True


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
            raise Tier2Refused(f"trust file line {number}: only ES256 and EdDSA are accepted")
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
    now: dt.datetime,
    expect: Mapping[str, str],
) -> PasskeyResult:
    """Every rule for a passkey approval, in the order a failure is cheapest to explain. The signature check is last and
    goes through `verifier`. `expect` is REQUIRED and must hold a non-empty nonce, model and prompt_sha256 (it may
    hold more); the approval text must carry exactly these values. `now` is the clock for the same expiry rule the
    hardware-key path applies (`now >= expires_at` is expired). The caller spends the nonce and stores the counter."""
    if not allowed:
        raise Tier2Refused("passkey approvals are off: the trust file has no `# safo-policy: allow-passkeys` line")
    if credential_fingerprint(key) in revoked:
        raise Tier2Refused(f"the passkey {key.label} is revoked")
    _check_approval(canonical_payload, expect, now)
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
    if not isinstance(challenge, str) or not hmac.compare_digest(
        b64url_decode(challenge), challenge_for(canonical_payload)
    ):
        raise Tier2Refused("the assertion's challenge is not the hash of this approval")
    auth = parse_authenticator_data(authenticator_data)
    if not hmac.compare_digest(auth.rp_id_hash, hashlib.sha256(key.rp_id.encode()).digest()):
        raise Tier2Refused("the assertion is for another relying party")
    if not auth.user_present:
        raise Tier2Refused("the authenticator did not report user presence")
    if not auth.user_verified:
        raise Tier2Refused("the authenticator did not report user verification (required for approvals)")
    if previous_counter is not None and (auth.counter or previous_counter) and auth.counter <= previous_counter:
        raise Tier2Refused("the signature counter did not increase (a cloned or replayed credential)")
    if not 0 < len(signature) <= MAX_SIGNATURE:
        raise Tier2Refused("the signature is too large" if signature else "the signature is empty")
    message = authenticator_data + hashlib.sha256(client_data_json).digest()
    if not verifier.verify(key.algorithm, key.public_key, message, signature):
        raise Tier2Refused("the assertion's signature does not verify")
    return PasskeyResult(key.label, auth.counter, auth.user_verified, auth.synced)


def _check_approval(canonical_payload: str, expect: Mapping[str, str], now: dt.datetime) -> None:
    """The approval text the passkey signs over: bounded, a JSON object, carrying the expected nonce, model and prompt
    digest, and not expired by the rule the hardware-key path uses."""
    if len(canonical_payload) > MAX_PAYLOAD:
        raise Tier2Refused("the approval text is too large")
    try:
        data = loads(canonical_payload)
    except (ValueError, UnicodeError):
        raise Tier2Refused("the approval text is not JSON") from None
    if not isinstance(data, dict):
        raise Tier2Refused("the approval text is not a JSON object")
    for field in REQUIRED_EXPECT:
        wanted = expect.get(field) if isinstance(expect, Mapping) else None
        if not isinstance(wanted, str) or not wanted:
            raise Tier2Refused(f"the caller did not say which {field} to expect; nothing is verified without it")
    for field, wanted in expect.items():
        if data.get(field) != wanted:
            raise Tier2Refused(f"the approval's {field} is not the one expected")
    from safo.gemini import _parse_stamp  # the same stamp parser as the hardware-key path

    expires = _parse_stamp(data.get("expires_at"))
    if expires is None:
        raise Tier2Refused("the approval has no valid expiry (expires_at)")
    if now >= expires:
        raise Tier2Refused("the approval has expired")


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
