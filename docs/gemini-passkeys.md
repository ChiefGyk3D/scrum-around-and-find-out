# Gemini passkeys (assurance Tier 2): opt-in, hardware keys recommended

**Status.** The signature and rule checks for a passkey assertion are built and tested against real signatures
(`src/safo/geminipasskey.py`, `tests/test_gemini_passkey_real.py`): ES256 and EdDSA, through the `cryptography` package.
The maintainer decided on 2026-10-30 to ship the opt-in tier (#211). What is still **not built**: the loopback
enrollment page, the approval page and server, and the wiring into the approval record and the ledger. Nothing in the
approval path calls this code, passkeys are off unless a root-owned trust file says otherwise, and paid use stays disabled
by its own switch (#205). **No passkey can authorize spend today.**

The maintainer's requirement (2026-10-29): build in passkey support but recommend hardware keys; he uses hardware keys
only, others may not have one. So Tier 1 (a hardware security key through OpenSSH) is the recommended default; Tier 2 is
an opt-in for people without one, off by default.

## Installing the dependency (only if you use passkeys)

`cryptography` is the optional extra `passkeys`: `pip install 'safo[passkeys]'`. A plain install and the GitHub Action do
not carry it, and importing the module (`src/safo/geminipasskey.py`) works without it; only the verifier needs it, and says how to get it. It
is hash-locked: one input file in the repository root names the pin, and `requirements-passkey.txt` is its `pip-compile
--generate-hashes` lock (with `cffi` and `pycparser`), and `requirements-dev.txt` includes it so the tests run real
cryptography. To install from the lock: `pip install --require-hashes -r requirements-passkey.txt`.

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

1. **Enrollment** (maintainer, once per credential; the page is not built yet, the trust-file format is final). A one-shot loopback page registers a credential for the relying
   party id `localhost` at the page's exact origin, with user verification required, and prints a trust-file line. The
   browser gives the public key as a SubjectPublicKeyInfo through `getPublicKey()` and its algorithm through
   `getPublicKeyAlgorithm()` (both are in the W3C WebAuthn Level 2 recommendation, checked in the spec text fetched
   2026-10-29). Using them means **no CBOR attestation object has to be parsed**. The maintainer adds the line by hand to
   the root-owned trust file, the same file as the SSH keys:

   ```text
   # safo-passkey: label=laptop-1 rp=localhost origin=http://localhost:PORT alg=ES256 id=CREDENTIAL_ID_B64URL key=SPKI_B64URL
   # safo-policy: allow-passkeys
   ```

   The first line is a comment to `ssh-keygen`, so Tier 1 is untouched.    `ES256` and `EdDSA` (Ed25519) are accepted (`alg=ES256` or `alg=EdDSA`). The policy line is the switch that turns Tier 2 on: it is in the root-owned file, not in the account's own
   `gemini.yaml` that an agent can edit.
2. **Approval.** `safo gemini approve` (same terminal and typed `approve <job>` confirmation as Tier 1) starts a one-shot
   loopback page: a random port, a one-time token in the URL, bound to `127.0.0.1`, closed after one assertion or a short
   life. The page shows the quota line and the approval summary. Its challenge is the **SHA-256 of the same canonical
   approval JSON** that Tier 1 signs (`challenge_for`), so both tiers bind the same text: job, model, amount, expiry,
   nonce, ledger head, quote, principal.
3. **Verification** (`verify_assertion`), in this order: Tier 2 enabled by the trust file; credential not on the
   revocation list (the same file; a passkey is revoked by the SHA-256 fingerprint of its public key); the approval text is
   bounded, JSON, carries the nonce, model and prompt digest the caller expects, and is not expired (`now >= expires_at`,
   the hardware-key rule); client data is bounded, `webauthn.get`, not cross-origin, the **exact origin** enrolled, and the
   challenge equals the hash of this approval; authenticator data is the plain 37-byte form (relying-party hash, flags,
   counter), the relying-party hash is the hash of the enrolled id, **user presence set, user verification set
   (required)**, the counter increased against the stored value where either is non-zero; then the signature over
   `authenticatorData || SHA-256(clientDataJSON)` through `CryptographyVerifier`. The verifier takes the key as a
   SubjectPublicKeyInfo only (a P-256 key for ES256, an Ed25519 key for EdDSA), refuses any other key type, curve,
   trailing bytes, an oversized or non-DER signature, and an unknown algorithm. Every parse or length problem is a refusal;
   nothing touches the network.
4. **Record.** The same record as Tier 1 with an assertion in place of the SSH signature: the same nonce, expiry, ledger
   head and single use, a ledger row that records `tier: 2` and the credential label, and `keys list` and `keys check`
   showing it with the Tier 2 warnings (`keys check` already warns about any enrolled passkey and when the policy line is
   missing).

Nothing in steps 1, 2 and 4 is built: they need the page, a small HTTP server and the record plumbing. When they are, the
nonce is spent and the expiry enforced by the same store as Tier 1, and the caller stores the counter that
`verify_assertion` returns.

## What is built and tested, and what is not

- Built and tested with real signatures (a software authenticator in the test file makes keys, authenticator data and
  client data at test time): ES256 and EdDSA, wrong relying-party id, flipped and missing flags, replayed and stale
  counter, wrong challenge, wrong nonce, model or prompt digest, expired approval, wrong key, wrong key type or curve,
  truncated and oversized input, and a corrupt signature. Also the trust-file lines, the policy switch, and that the SSH
  side ignores the passkey lines.
- Not built: the enrollment page, the approval page and server, and the wiring into the record and the ledger.
- Not tested with a real browser or authenticator. A real authenticator can behave differently from the test one (for
  example, a platform authenticator that reports no backup flags).

## Dependency choice (decided 2026-10-30)

`cryptography` alone, behind the `SignatureVerifier` interface, as the 2026-10-29 analysis recommended: the design needs
one primitive, and the library is the most widely reviewed of the options. The cost is a compiled dependency and wheel
hashes, kept out of the default install by the extra. `fido2`, `webauthn` and `cbor2` were not taken: the design avoids
CBOR and the relying-party libraries replace our rules with theirs. Do not hand-roll the ECDSA check or a CBOR reader.
