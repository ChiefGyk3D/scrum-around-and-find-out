# Gemini passkeys (assurance Tier 2): design, not shippable

**Status: not shippable until the maintainer decides the dependency question below.** The rules for a passkey assertion and
their tests are in the tree (`src/safo/geminipasskey.py`, `tests/test_gemini_passkey.py`), against an injected fake
signature verifier. The default verifier refuses everything, nothing in the approval path calls this code, and passkeys are
off unless a root-owned trust file says otherwise. No passkey can authorize spend today.

The maintainer's requirement (2026-10-29): build in passkey support but recommend hardware keys; he will use hardware keys
only, others may not have one. So: Tier 1 (a hardware security key through OpenSSH) is the recommended default; Tier 2 is
an opt-in for people without one, off by default.

## Why Tier 1 is the recommendation

- **A synced passkey is only as strong as the cloud account and the device unlock behind it.** The authenticator data
  has a "backup eligible" flag; when it is set, the credential can live in a cloud account, and whoever gets into that
  account or unlocks that device holds the approval.
- **An agent running as you can drive a browser** (a Playwright-style script) and ask for an assertion. User
  verification must be required (this design requires it) and a platform biometric or a hardware authenticator must stand
  behind it, or the "approval" is a click a script can make.
- **The verifier can only check flags the authenticator reports.** User presence and user verification are bits in the
  authenticator data; software authenticators can set them. Tier 1 has the same limit for the flags, but the key is a
  separate device whose touch is a physical act.
- A hardware key's signature needs no browser, no loopback web page and no cloud, and uses `ssh-keygen`, which is
  already here.

## The design

1. **Enrollment** (maintainer, once per credential). A one-shot loopback page registers a credential for the relying
   party id `localhost` at the page's exact origin, with user verification required, and prints a trust-file line. The
   browser gives the public key as a SubjectPublicKeyInfo through `getPublicKey()` and its algorithm through
   `getPublicKeyAlgorithm()` (both are in the W3C WebAuthn Level 2 recommendation, checked in the spec text fetched
   2026-10-29). Using them means **no CBOR attestation object has to be parsed**. The maintainer adds the line by hand to
   the root-owned trust file, the same file as the SSH keys:

   ```text
   # safo-passkey: label=laptop-1 rp=localhost origin=http://localhost:PORT alg=ES256 id=CREDENTIAL_ID_B64URL key=SPKI_B64URL
   # safo-policy: allow-passkeys
   ```

   The first line is a comment to `ssh-keygen`, so Tier 1 is untouched. Only `ES256` (ECDSA P-256 with SHA-256) is
   accepted. The policy line is the switch that turns Tier 2 on: it is in the root-owned file, not in the account's own
   `gemini.yaml` that an agent can edit.
2. **Approval.** `safo gemini approve` (same terminal and typed `approve <job>` confirmation as Tier 1) starts a one-shot
   loopback page: a random port, a one-time token in the URL, bound to `127.0.0.1`, closed after one assertion or a short
   life. The page shows the quota line and the approval summary. Its challenge is the **SHA-256 of the same canonical
   approval JSON** that Tier 1 signs (`challenge_for`), so both tiers bind the same text: job, model, amount, expiry,
   nonce, ledger head, quote, principal.
3. **Verification** (`verify_assertion`), in this order: Tier 2 enabled by the trust file; credential not on the
   revocation list (the same file; a passkey is revoked by the SHA-256 fingerprint of its public key); client data is
   `webauthn.get`, not cross-origin, the **exact origin** enrolled, and the challenge equals the hash of this approval;
   authenticator data is the plain 37-byte form (relying-party hash, flags, counter), the relying-party hash is the hash of
   the enrolled id, **user presence set, user verification set (required)**, the counter increased where both are non-zero;
   then the signature over `authenticatorData || SHA-256(clientDataJSON)` through the injected verifier.
4. **Record.** The same record as Tier 1 with an assertion in place of the SSH signature: the same nonce, expiry, ledger
   head and single use, a ledger row that records `tier: 2` and the credential label, and `keys list` and `keys check`
   showing it with the Tier 2 warnings (`keys check` already warns about any enrolled passkey and when the policy line is
   missing).

Nothing in steps 1, 2 and 4 is built: they need the page, a small HTTP server and the record plumbing, and the signature
check in step 3 needs the dependency. Steps 3's rules are built and tested.

## What is built and tested, and what is not

- Built and tested with a fake verifier: the challenge, the authenticator-data parser, the origin, relying-party,
  challenge, presence, verification, counter and revocation rules, the trust-file lines, the policy switch, and that the
  SSH side ignores the passkey lines.
- Not built: the enrollment page, the approval page and server, wiring into the record and the ledger, the real signature
  verifier.
- Not tested with a real browser or authenticator.

## The decision for the maintainer: how to verify a signature

SAFO ships one runtime dependency (PyYAML, hash-pinned in `requirements.txt` and `requirements-dev.txt`), so verifying an
ES256 signature needs a new one. The design deliberately avoids CBOR (see enrollment), so the only thing needed is "check
an ECDSA P-256 signature over these bytes with this SPKI key", behind the `SignatureVerifier` interface. Options, read
from PyPI on 2026-10-29 (sizes, licenses, dates are from the package metadata):

| Option | What it is | Version, last release | License | Size | Pulls in | Hash-pin cost |
|---|---|---|---|---|---|---|
| `cryptography` alone | The reviewed ECDSA/SPKI primitives; our rules stay as written | 50.0.2, 2026-09-30 | Apache-2.0 OR BSD-3-Clause | about 3.7 MB per binary wheel (59 files) | `cffi` (and its `pycparser`) | Highest: a lock needs a hash for every platform wheel, and wheels change with each release; the lock grows by dozens of lines |
| `fido2` (Yubico python-fido2) | A FIDO library with a WebAuthn server and CTAP; would replace some of our parsing | 2.2.1, 2026-06-29 | Yubico's BSD-style terms (BSD-2-Clause by the text in the metadata; confirm before use) | about 0.3 MB (2 files) | `cryptography` (pinned below 52) | `cryptography`'s cost plus 2 files; but a large API we would use a sliver of |
| `webauthn` (py_webauthn) | A relying-party library: registration and authentication verification | 3.0.1, 2026-09-25 | BSD-3-Clause | about 0.2 MB (2 files) | `cryptography`, `cbor2`, `pyasn1`, `pyasn1-modules`, `pyOpenSSL` | Five more packages to pin; most surface; replaces our rules with theirs |
| `cbor2` | A CBOR reader (MIT, 6.1.5, 2026-10-01, about 0.3 MB, 65 files, no dependencies) | | MIT | | none | Needed only if we parse attestation objects or COSE keys instead of using `getPublicKey()`; not needed by this design |

My recommendation, for you to overrule: **`cryptography` alone**, behind the existing interface, because the design needs
one primitive and the library is the most widely reviewed and maintained of the four. The cost is the wheel hashes and a
compiled dependency in a project that today has one pure-Python dependency. If you would rather not take that cost at all,
the honest alternative is to leave Tier 2 out: Tier 1 needs no new dependency, since it uses `ssh-keygen`.

Do not hand-roll the ECDSA check or a CBOR reader, and do not add a dependency without the hash lock being regenerated.
