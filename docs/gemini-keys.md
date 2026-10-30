# Gemini keys

> **Status.** These steps are **needed only when paid use is enabled**. The free research path needs no key and no root
> file, and paid use is disabled by a root-owned switch until a state authority outside the maintainer's account
> exists (see [Gemini](gemini.md)). The setup is kept so it is ready, and `keys check` and a dry run of `safo gemini approve` can
> test a key while the switch is off.

Who may approve paid Gemini spend, and how to add, rotate, back up and revoke the keys that do. Read
[Gemini](gemini.md) first for what a signed approval is and what it cannot do.

**Marks used here.** *Verified* means read from the real source named, on the date given, or run on this machine.
*Inferred* means reasoned from verified facts and not run. *Unverified* means neither. Commands come from `man
ssh-keygen` and `man ssh-add` on this machine (OpenSSH 10.3p1, read 2026-10-29) or from the vendor pages named below.
Nothing here uses a serial number, a hostname or a machine name: keys are named by a **label** you choose
(`yubikey-a`, `yubikey-b`, `backup-1`).

## The assurance tiers

| Tier | What signs | Status |
|---|---|---|
| 1 (recommended, the default) | A hardware security key (`ed25519-sk` or `ecdsa-sk`) through OpenSSH, a touch for every approval, a PIN if you require one | Built and tested (with software keys; see "What the tests could not prove") |
| 2 (opt-in, off) | A WebAuthn passkey assertion (ES256 or EdDSA), checked with the optional `safo[passkeys]` extra | Verification built and tested with real signatures; enrollment page and approval wiring **not built**, and paid use is disabled, so it authorizes nothing today. See [Gemini passkeys](gemini-passkeys.md) |
| Other | A software key (a file) or an agent-held key | Refused unless a written per-key opt-in; `keys check` warns loudly |

## The trust files

Both are public, maintainer-edited, root-owned, and **never written by safo**.

- `/etc/safo/gemini-allowed-signers`: one line per key: `LABEL namespaces="safo-gemini-approval" KEYTYPE BASE64`. This
  is OpenSSH's allowed-signers format (verified in `man ssh-keygen`, section ALLOWED SIGNERS: principals, options, key
  type, base64 key; the `namespaces=` option binds a key to a signature namespace). The label is the principal. The code
  accepts only the `namespaces`, `valid-after` and `valid-before` options (the last two must be quoted UTC times ending in `Z`: `valid-before="20261231Z"`, `YYYYMMDDHHMMZ` or `YYYYMMDDHHMMSSZ`, and `valid-before` must be later than `valid-after`; both ends are inclusive), refuses `no-touch-required`, certificates and
  a duplicate label or key, and accepts only `sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com` and
  `ssh-ed25519` keys.
- `/etc/safo/gemini-revoked-signers`: **required, but it may be empty**; a missing file refuses every approval (so a
  maintenance step that removes it cannot let a revoked key through; replace it atomically). A public key (`TYPE BASE64
  comment`) or a `SHA256:` fingerprint per line. A
  signature from a revoked key is refused even if the key is still enrolled, so revoking does not delete history.

A key outside its window is **refused** at verify (OpenSSH is given the same window and the current time through
`-Overify-time=`, both verified in `man ssh-keygen` and run on this machine), and `keys list` and `keys check` show it as
`NOT usable: expired` or `not yet valid`. Use `valid-before` to give a key an end date you do not want to forget.

Per-key switches are comment lines in the allowed-signers file (OpenSSH ignores them):

- `# safo: LABEL require-pin`: the signature must show the PIN check (user verification), not just the touch. Use it for
  a key made with `-O verify-required`.
- `# safo: LABEL allow-software`: the written opt-in for a key that is not a hardware key. See "Software and agent-held
  keys".
- `# safo-policy: allow-passkeys` and `# safo-passkey: ...` belong to Tier 2 (see "Passkeys (Tier 2)" below). They are comments to OpenSSH.

The files must be owned by root, not writable by group or others, in directories that are root-owned and not writable
by others. That is what stops an agent running as you from enrolling its own key. A file that fails is refused with
the rule it broke.

## Passkeys (Tier 2, opt-in)

**Use a hardware security key if you have one.** A passkey is the fallback for people who do not. A synced passkey is only
as strong as the cloud account and the device unlock behind it, and software that drives a browser can ask it to sign;
a hardware key is a separate device whose touch is a physical act. `keys check` warns about every enrolled passkey.

Enrolling one (the loopback enrollment page is **not built yet**; the trust-file format below is final):

1. Install the extra: `pip install 'safo[passkeys]'` (hash-locked; people who never use passkeys do not need it).
2. Register a credential for relying party id `localhost` at the loopback page's exact origin, with user verification
   required. Algorithm ES256 or EdDSA. Keep the credential id and the SubjectPublicKeyInfo public key, both base64url.
3. Add the lines to `/etc/safo/gemini-allowed-signers` as root, with a backup and a diff, exactly as for an SSH key
   (see "Setup" above):

   ```text
   # safo-passkey: label=laptop-1 rp=localhost origin=http://localhost:PORT alg=ES256 id=CREDENTIAL_ID_B64URL key=SPKI_B64URL
   # safo-policy: allow-passkeys
   ```

   Without the policy line the passkey is ignored and `keys check` says so. A passkey is revoked by the SHA-256
   fingerprint of its public key in the revocation file.
4. Run `safo gemini keys check`. Paid use stays disabled by its own switch whatever you enroll.

**Warning for agent-held keys that are not FIDO keys** (for example a fingerprint reader that holds an SSH key in an agent
with a cooldown): they are not Tier 1 and not Tier 2. A process that can reach the agent can sign again inside the
cooldown without a new touch, so "one touch per approval" does not hold. They are refused unless you write the per-key
`allow-software` opt-in, and `keys check` warns. Prefer a hardware security key.

## Read-only commands

```bash
safo gemini keys list                                   # label, type, fingerprint, hardware or software, PIN, revoked, usable
safo gemini keys check                                  # every key parses; none has no-touch-required; warnings below
safo gemini keys propose ~/.ssh/KEYFILE.pub --label yubikey-a   # prints the exact line and fingerprint; writes nothing
```

`check` warns when fewer than two usable keys are enrolled, when a key is a software key, when a hardware key has no PIN
requirement, and when a Tier 2 credential is enrolled. It fails when no usable key is enrolled, when a key carries
`no-touch-required`, or when the revocation file is missing.

## Setup: the first key (only when paid use is enabled; needs your touch; the agent does not do this)

1. **Check OpenSSH.** `ssh -V` must be 8.2 or newer for FIDO keys, and 8.4 or newer for `verify-required` (verified,
   Yubico page, 2026-10-29). The build must have FIDO support (`ssh-keygen -t ed25519-sk` says so if not).
2. **Make the key.** Plug in the security key and run, with your own file name and label in the comment:

   ```bash
   ssh-keygen -t ed25519-sk -O verify-required -O application=ssh:safo-gemini-a -C "safo gemini approvals, yubikey-a" -f ~/.ssh/safo_gemini_yubikey_a
   ```

   The options are verified in `man ssh-keygen` (FIDO AUTHENTICATOR): `-t ed25519-sk`; `-O verify-required` (require
   user verification, a PIN, for each signature; not every authenticator supports it); `-O application=ssh:NAME` (the
   name must begin with `ssh:`); `-O resident` (store the credential on the key itself; typically needs a PIN set first);
   `-O no-touch-required` (**never use it**). The command asks you to touch the key. It writes a small *key handle* file
   (`safo_gemini_yubikey_a`, not a secret: it only names the credential on the device) and the public key
   `safo_gemini_yubikey_a.pub`.
   If the device does not support `ed25519-sk` (older Yubico firmware, below 5.2.3), use `-t ecdsa-sk` instead (verified,
   Yubico page, 2026-10-29).
3. **Print the line to enroll.**

   ```bash
   safo gemini keys propose ~/.ssh/safo_gemini_yubikey_a.pub --label yubikey-a
   ```

4. **Add it as root, with a backup and a diff.** First time only, make the folder and **both** files, the revocation
   file included (it may be empty, but a missing one refuses every approval):

   ```bash
   sudo install -d -m 755 -o root -g root /etc/safo
   sudo install -m 644 -o root -g root /dev/null /etc/safo/gemini-allowed-signers
   sudo install -m 644 -o root -g root /dev/null /etc/safo/gemini-revoked-signers
   ```

   Every time: back up, edit, diff, and check ownership.

   ```bash
   sudo cp -a /etc/safo/gemini-allowed-signers /etc/safo/gemini-allowed-signers-backup
   sudoedit /etc/safo/gemini-allowed-signers
   diff /etc/safo/gemini-allowed-signers-backup /etc/safo/gemini-allowed-signers
   ls -l /etc/safo
   ```

   Paste the line `propose` printed. If the key was made with `verify-required`, add the line
   `# safo: yubikey-a require-pin` beneath it. (`install`, `sudoedit`, `cp -a` and `diff` are standard tools; they were
   not run for this page. Inferred.)
5. **Tell safo which key signs.** In `~/.config/safo/gemini.yaml`:

   ```yaml
   signing:
     key: /path/to/safo_gemini_yubikey_a
     principal: yubikey-a
   ```

6. **Test without spending.**

   ```bash
   safo gemini keys check
   # a dry run of safo gemini approve: it signs a throw-away text, spends nothing and writes nothing
   safo --dry-run gemini approve --model gemini-3.6-flash --prompt-file prompt.txt --max-output-tokens 1000 --max-usd 1.50 --job key-test --quote "key test" --quoted-at 2026-10-29T15:00:00Z
   ```

   At a terminal, type `approve key-test`, touch the key (and give the PIN if you set one). The dry run signs a throw-away
   text in another namespace (`safo-gemini-approval-dryrun`), verifies it against the enrolled key, prints the label,
   fingerprint and whether it saw the touch and the PIN, and writes no record and no ledger row. Use a current
   `--quoted-at` (within the last 24 hours, UTC).

## Several keys: add, rotate, back up

- **Enroll at least two.** `keys check` warns about one. Keep **one key offline** in a safe place; it is the way back in
  if the other is lost. Enroll the second the same way (own label, own `application=` name, own `.pub`).
- **Record the fingerprints** from `safo gemini keys list` somewhere other than this machine, next to where each key
  lives. You need a fingerprint to revoke a key whose `.pub` you no longer have.
- **Which key signs** is `signing.principal` in `gemini.yaml`. To use the second key, change `key:` and `principal:`.
- **Rotate** a key: enroll the new one (steps 2-6), switch `gemini.yaml`, confirm a dry run, then revoke the old one
  (below) and keep its line in the allowed-signers file so the history still reads.
- **A key per desktop** is fine (a Yubikey on one machine, a second on another); each is a separate label.
- **Resident or not.** A non-resident key (no `-O resident`) keeps its credential reference only in the handle file, so
  back that file up with the key: without it that credential cannot sign (Yubico page, below). A resident key stores the
  credential on the device, and `ssh-keygen -K` downloads the handle and public key files from it (`-K` is in `man
  ssh-keygen`; `ssh-add -K` loads resident keys into an agent, `man ssh-add`; both verified locally). Resident keys need
  a PIN set on the key first (Yubico). Either works for safo.

## Revoking a key (lost, stolen, retired)

A key is lost or stolen: **revoke first, investigate second.**

1. Get the fingerprint: `safo gemini keys list`, your offline record, or `ssh-keygen -lf KEY.pub` (`-l` prints a
   fingerprint, verified in `man ssh-keygen`).
2. Add one line to the revocation list, with a backup and a diff:

   ```bash
   sudo cp -a /etc/safo/gemini-revoked-signers /etc/safo/gemini-revoked-signers-backup
   sudoedit /etc/safo/gemini-revoked-signers
   diff /etc/safo/gemini-revoked-signers-backup /etc/safo/gemini-revoked-signers
   ```

   The line is `SHA256:...` (the fingerprint) or the whole public key line. A line that is neither stops every approval
   until you fix it.
3. Run `safo gemini keys list`: the key shows `REVOKED`. Any unspent approval it signed is now refused.
4. Look for what it did: the ledger's `approval_issued` and `approval_used` rows name the principal; compare with the
   vendor billing page, and add any spend the ledger missed with `safo gemini usage`.
5. If the stolen key could have been used with its PIN, change the PIN (the vendor's manager tool). If you suspect the
   paid API key was exposed, rotate it in the secret store.
6. Enroll a replacement (steps 2-6 above).

## Checklist

- [ ] Two or more keys enrolled; one stored offline; `keys check` has no problems.
- [ ] Keys were made with `-O verify-required`, and the allowed-signers file carries `# safo: LABEL require-pin` for each.
- [ ] Files in `/etc/safo` are owned by root, mode 644, and `ls -l` shows it.
- [ ] Fingerprints written down off this machine.
- [ ] The revocation file exists (it may be empty; without it every approval is refused).
- [ ] A `--dry-run` approval worked with each key.
- [ ] You know the rule: **touch the key only after reading the quota line and the quote, and never for a prompt you did
      not start.**
- [ ] The vendor-side monthly limit is still set (it is the backstop for everything this gate cannot see).

## What the tests could not prove (software key versus a real sk key)

The tests use a **software ed25519 key** made by `ssh-keygen` in a temporary directory, with the hardware-only default
switched off through a test-only argument. The code path is the same: `ssh-keygen -Y sign` signs, `ssh-keygen -Y verify`
checks. What differs with a real `ed25519-sk` key:

- The signature carries two extra fields from the authenticator, a **flags byte** (touch, PIN) and a **counter**. The
  verifier reads the flags itself and refuses a signature without the touch flag, and without the PIN flag where
  `require-pin` is written. The tests build well-formed hardware envelopes and replace only the cryptographic check, so
  the flag rules and the key-shape rules are tested; **the cryptographic check of a real hardware signature is not**.
- Whether `ssh-keygen -Y verify` itself refuses a signature that lacks the touch flag is **unverified** (the man page does
  not say it checks, and it documents `no-touch-required` only for certificates and key generation). The code does not
  rely on it: it checks the flag.
- Key generation, the touch, the PIN prompt and a device with FIDO support were never run here, and no hardware key was
  attached. Run the dry run (step 6) with each key as the real test.

## Yubico security keys (OpenSSH sk keys)

Read from Yubico's page "Securing SSH Authentication with FIDO2 Security Keys",
`https://developers.yubico.com/SSH/Securing_SSH_with_FIDO2.html`, on 2026-10-29. **Verified** against that page:

- OpenSSH 8.2+ is needed for FIDO keys; 8.3+ to download resident keys with `ssh-keygen -K`; 8.4+ for `verify-required`.
  The OpenSSH build must include FIDO support (libfido2).
- `ed25519-sk` needs YubiKey firmware 5.2.3 or newer; older firmware uses `ecdsa-sk`, which all FIDO2 YubiKeys support.
- A touch (user presence) is always required unless the key was made with `no-touch-required`. `verify-required` adds user
  verification: a FIDO2 PIN on most YubiKeys, a fingerprint on the YubiKey Bio Series.
- Resident keys (`-O resident`) are stored on the key and need firmware 5.2.3+ and a FIDO2 PIN; a non-resident key keeps
  its credential reference only in the handle file. The handle file is not the private key.
- `ssh-agent` never caches the PIN; the touch is still required. Avoid agent forwarding.
- If the PIN is forgotten the FIDO2 application must be reset, which deletes every FIDO2 credential on the key (you would
  re-enroll).

Not verified: anything about a specific model beyond the page; the PIN-retry limits.

## Immurok

Researched from the vendor's own pages on 2026-10-29 (`https://immurok.com/` and
`https://immurok.com/blog/fingerprint-gate-for-ai-agents/`, the blog "Published May 8, 2026; updated September 4, 2026"),
and by the lead from the same pages. **Verified on the pages:**

- It is **not a FIDO device**: it does not register with websites as a passkey or security key. It is a Bluetooth LE
  fingerprint reader (USB-C is charge only); the fingerprint is matched on the device. The feature list names an "SSH
  Agent" with on-device ECDSA private keys. Linux is supported. The page said pre-orders ship in December 2026, so whether
  you hold a unit is your statement, not something the page shows.
- The agent integration is a wrapper: `imk run --agent -- COMMAND`. One touch opens an **AUTH cooldown** (about five
  minutes for `sudo`) that also satisfies SSH key signing for the wrapped subprocess. The author does not say what stops an
  agent from simply not using the wrapper.

**Not stated, so unverified:** whether it works with `ssh-keygen -Y sign` or `ssh-agent`, which curve it uses, and the
signature format.

**What that means for approvals.** The Immurok is **not an sk key**, so it cannot be a Tier 1 key, and an agent-held key
with a cooldown can sign again inside the window without a new touch, which breaks "one touch per approval". It is
therefore a *non-hardware-approval* key to this code: refused unless you add the per-key opt-in
`# safo: LABEL allow-software` for it, and `keys check` will warn loudly. It is a good fit for what the vendor built it
for (a human gate on `sudo`, `git push` and secret reads in a wrapped command), not for paid-spend approval.

**What to test before opting it in** (nothing was connected or installed to write this):

1. Does `ssh-keygen -Y sign -f <its public key file> -n safo-gemini-approval FILE` work through its agent at all? (`man
   ssh-keygen`, `-Y sign`: the `-f` key "may refer to either a private key, or a public key with the private half
   available via ssh-agent". The `-U` flag the vendor-side notes suggested is documented there only for a CA key, so it is
   not used here.)
2. Does *each* signature need its own touch, or does one touch cover several inside the cooldown? Sign twice in a row and
   see whether the second asks.
3. Can a process that does not use `imk run` get a signature? If so, an agent can.

If 2 or 3 fail, do not opt it in for approvals.

## Passkeys

See [Gemini passkeys](gemini-passkeys.md). Short version: a hardware key is recommended because a synced passkey is only as
strong as the cloud account and the device unlock behind it, and a process running as you can drive a browser. Passkeys
stay off.
