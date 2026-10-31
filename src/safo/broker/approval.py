# SPDX-License-Identifier: Apache-2.0
"""Verify a hardware-key signed approval (docs/gemini-broker.md, "What a signed approval binds", checks 3 and 4).

The cryptographic check is OpenSSH's own: `geminisign.verify` runs `ssh-keygen -Y verify` (an absolute path, a fixed
argument vector, no shell, a two-entry environment, the signers line and the signature sealed in memory) against the
root-owned allowed-signers file and revocation list, and reads the touch and PIN flags from the signature. This module
adds what a socket-facing caller needs around it:

* the namespace is a constant here, never a parameter: a signature made for any other purpose (the dry-run namespace
  included) is refused by our own comparison and by `ssh-keygen -n`;
* the bytes that are verified are the text that is parsed: it must be an exact `str` that encodes to ASCII (the
  canonical form is ASCII only, so anything else cannot be a canonical approval), and the same value is parsed;
* the strict version 3 loader then requires the text to BE the canonical form, so a different spelling of the same
  approval cannot carry a valid signature;
* the key that verified must be the principal named inside the signed text;
* the signing key must be a hardware key and the signature must show a touch: a software key is refused even
  when root wrote the opt-in for it in the shared signers file (decision 9, hardware keys only). There is no opt-in
  in this path;
* every failure is one `Refused`. Nothing a client sent is echoed.
"""

from __future__ import annotations

import datetime as dt
from typing import Protocol

from safo import geminisign
from safo.broker.errors import Refused
from safo.broker.records import MAX_APPROVAL_BYTES, ApprovalV3, parse_approval
from safo.errors import ConfigError
from safo.gemini import RefusedError, plain_time


class Verifier(Protocol):
    """`geminisign.verify`. A test supplies a stand-in for the authenticator; production never does."""

    def __call__(
        self, trust: geminisign.Trust, payload: bytes, armor: str, *, namespace: str, now: dt.datetime
    ) -> geminisign.Verified: ...


def _bad(message: str = "the approval is not signed by a key that may approve; ask for a fresh one") -> Refused:
    return Refused("bad_approval", message)


def _revoked(trust: geminisign.Trust, signature: str) -> bool:
    """After a refusal only: was the signing key one root has revoked? Used to pick the reply code, never to allow."""
    try:
        blob = geminisign.parse_signature(signature).blob
        roster = geminisign.load_roster(trust)
        key = next((k for k in roster.keys if k.blob == blob), None)
        return key is not None and roster.is_revoked(key)
    except (RefusedError, ConfigError, OSError, ValueError):
        return False


def verify_approval(
    payload: object,
    signature: object,
    trust: geminisign.Trust,
    *,
    now: dt.datetime,
    verifier: Verifier = geminisign.verify,
) -> ApprovalV3:
    """The approval a hardware key signed, or `Refused`. `payload` is the canonical signed text and `signature` the
    SSH signature armor. Fails closed: any problem with the files, the key, the signature or the text is a refusal."""
    try:
        when = plain_time(now, "now")
    except RefusedError:
        raise Refused("bad_request", "the time is not a plain time with a time zone") from None
    if type(payload) is not str or type(signature) is not str:
        raise _bad("the approval is not plain text")
    if not 0 < len(payload) <= MAX_APPROVAL_BYTES or not 0 < len(signature) <= geminisign.SIGNATURE_BYTES:
        raise _bad("the approval or its signature has a size the broker does not accept")
    try:
        raw = str.encode(payload, "ascii")
    except UnicodeEncodeError:
        raise _bad("the signed text is not the canonical form") from None
    try:
        who = verifier(trust, raw, signature, namespace=geminisign.NAMESPACE, now=when)
    except (RefusedError, ConfigError, OSError, ValueError, UnicodeError):
        if _revoked(trust, signature):
            raise Refused("revoked", "the key that signed this approval has been revoked") from None
        raise _bad() from None
    if not who.hardware or who.user_present is not True:
        raise _bad("a paid approval needs a hardware key and a touch")
    approval = parse_approval(payload)  # an exact str, so these are the characters whose bytes were verified
    if approval.principal != who.label:
        raise _bad("the key that signed is not the principal named in the approval")
    return approval


def verify_dryrun(
    payload: object, signature: object, trust: geminisign.Trust, *, now: dt.datetime
) -> geminisign.Verified:
    """The key that signed a throw-away text in the dry-run namespace, or `Refused`. The same file checks, key window,
    touch and PIN rules as a real approval, and the same sealed `ssh-keygen`; but the text is not parsed (it is only a
    proof that the key works), and nothing is recorded or spent. A signature made for a real approval is refused here
    by the namespace, and a dry-run signature is refused there."""
    try:
        when = plain_time(now, "now")
    except RefusedError:
        raise Refused("bad_request", "the time is not a plain time with a time zone") from None
    if type(payload) is not str or type(signature) is not str:
        raise _bad("the approval is not plain text")
    if not 0 < len(payload) <= MAX_APPROVAL_BYTES or not 0 < len(signature) <= geminisign.SIGNATURE_BYTES:
        raise _bad("the approval or its signature has a size the broker does not accept")
    try:
        raw = str.encode(payload, "ascii")
    except UnicodeEncodeError:
        raise _bad("the signed text is not plain ASCII") from None
    try:
        return geminisign.verify(trust, raw, signature, namespace=geminisign.DRYRUN_NAMESPACE, now=when)
    except (RefusedError, ConfigError, OSError, ValueError, UnicodeError):
        if _revoked(trust, signature):
            raise Refused("revoked", "the key that signed this approval has been revoked") from None
        raise _bad() from None
