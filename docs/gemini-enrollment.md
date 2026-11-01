# Gemini enrollment runbook (maintainer side, #263)

This is the copy-paste runbook for the maintainer-side setup of the paid Gemini broker: enroll hardware keys for
approvals, test a second device, make a separate release-signing key, build the root-owned allowed-signers lines, and
rotate or revoke. It is the preparation for phase 7 and does not depend on the broker code: every command here
uses OpenSSH, git and libfido2 tools, not the broker. The design is in [Gemini broker](gemini-broker.md),
[Gemini keys](gemini-keys.md) and [Gemini passkeys](gemini-passkeys.md); this page does not change it.

**Who runs what.** Every command is for the maintainer to run, by hand, in a terminal on a machine where no agent is
running. The agent that wrote this page ran none of the key, root, device or `/etc` commands. Lines starting with `sudo`
need root and change the machine. Nothing here contains a secret: a PIN is typed at a prompt, a public key is public,
and a key handle file is a reference, not the private key.

**Every step carries three things:** its blast radius (what it can change), its rollback, and the output to compare. If
the output differs, stop and do not go on.

## Rehearse first (no root, no vendor call)

`python scripts/rehearse_broker_setup.py` walks this page and the root runbook against a throwaway folder with a test-only
software key, a fake vendor and the real broker code, then prints one `PASS`, `FAIL` or `SKIPPED` row per step (`R1` to
`R13` are the root runbook's step numbers; `E` rows are this page's). It finds runbook mistakes before the real run. It
does not replace the real run: the steps that need root, systemd, nftables or a hardware key (`R1`, `R4`, `R6`, `R8`,
`R10`, `R11`, the restart and probe lines of `R12`, the hardware key steps `Ea2` and `Eb`) are reported `SKIPPED` with the
reason, and a software key cannot show the touch and PIN flags. It writes only under its own folder, makes no network
call and refuses to run as root.

## What was verified, and when

Read on **2026-10-31**. A line marked **unverified** was not found on a vendor page and not run here; do not trust it
until you have seen it work.

| Source (what was read) | Date of the page | Used for |
|---|---|---|
| OpenBSD manual page `ssh-keygen(1)` | October 1, 2026 | `-t ed25519-sk`, `-O resident`, `-O verify-required`, `-O application=`, `-K`, `-w`, `-Y sign`, `-Y verify`, `-Y find-principals`, `-Y check-novalidate`, `-r`, `-O print-pubkey`, `-O verify-time=`, the ALLOWED SIGNERS format and `namespaces=`, `valid-after`, `valid-before` |
| OpenBSD manual page `ssh-add(1)` | read 2026-10-31 | `-L` lists agent keys, `-K` loads resident keys, `SSH_SK_PROVIDER` |
| OpenBSD manual page `ssh(1)` | read 2026-10-31 | `ssh -Q key` queries supported key types |
| OpenBSD manual page `sshd(8)` | read 2026-10-31 | `no-touch-required` and `verify-required` are `authorized_keys` options (not used for approvals; read for context) |
| Yubico page "Securing SSH with FIDO2" on `developers.yubico.com` | read 2026-10-31 | OpenSSH 8.2+, 8.3+ for `-K`, 8.4+ for `verify-required`; `ed25519-sk` needs firmware 5.2.3+, `ecdsa-sk` works on all FIDO2 YubiKeys; resident needs a PIN; PIN reset deletes all FIDO2 credentials |
| Yubico libfido2 project page on `developers.yubico.com`, its README and `udev/70-u2f.rules` in the `Yubico/libfido2` repository on `github.com`, and the `fido2-token(1)` manual on `developers.yubico.com` | libfido2 1.17.0 | package names `libfido2-1`, `fido2-tools` (Ubuntu list), the udev rule text, `fido2-token -L`, `-S`, `-C`, `-I`, `-D` |
| Debian package pages (`fido2-tools`, `libu2f-udev`, trixie) | read 2026-10-31 | `fido2-tools` ships `fido2-token`, `fido2-cred`, `fido2-assert` (file list read). The page for `libu2f-udev` exists; what rules file it installs was **not** read: **unverified**. `libfido2-1` was seen installed on this machine with `dpkg -l`, not on a Debian page |
| systemd manual page `systemd-creds(1)` | systemd 262 | `--name=`, `--with-key=` (only mentioned in "Related root step" below) |
| systemd manual page `udevadm(8)` | read 2026-10-31 | `udevadm control --reload` and `udevadm trigger` exist |
| git manual pages `git-config` (`gpg.format`, `gpg.ssh.allowedSignersFile`, `user.signingKey`) and `git-tag` (`-s`, `-v`) | read 2026-10-31 | signed annotated tags with an SSH key |
| Immurok vendor blog page "fingerprint-gate-for-ai-agents" on `immurok.com` | read 2026-10-31 | `imk run --agent -- COMMAND`, the AUTH cooldown. It says nothing about `ssh-keygen -Y sign`: **unverified** (see step b) |

Also run on this machine on 2026-10-31 with a throw-away **software** key in a scratch directory (no hardware key, no
root): `-Y sign`, `-Y verify`, `-Y find-principals`, `-Y check-novalidate`, `-r`, the namespace refusals, and a git SSH
signed tag, with OpenSSH 10.3 and git 2.47. The output lines quoted below marked "(run)" are real output of those runs.
Lines marked "(shape)" show what to expect from a hardware key, which was not available to the author: the words
`ED25519-SK` and the touch prompts are **unverified** until you see them.

## Step 0. Prerequisites and the read-only preflight

Needs: OpenSSH 8.4 or newer built with FIDO support (Yubico page: 8.2 for FIDO keys, 8.3 for `-K`, 8.4 for
`verify-required`), libfido2, and the udev access rule for your key class. A recent OpenSSH is necessary but not always
sufficient: it must be built with libfido2 (Yubico page). The Debian and Parrot builds link it (checked by the
preflight below).

1. **Install the packages** (Debian and Parrot family). `libfido2-1` and `fido2-tools` are the names on the Yubico
   list for Ubuntu and on the Debian package pages; the same names apply to Debian.

   ```bash
   sudo apt install openssh-client libfido2-1 fido2-tools
   ```

   Blast radius: installs three packages system-wide; `libfido2-1` is usually present already. Rollback:
   `sudo apt remove fido2-tools` (leave `libfido2-1`: OpenSSH depends on it). Expected: apt ends without an error.
   (`apt install` itself was not run for this page; Inferred.)

2. **Check the key is visible and readable without root.** Plug in one key.

   ```bash
   fido2-token -L
   ```

   Expected (shape, from the `fido2-token(1)` description "produces a list of authenticators found by the operating
   system"; the exact line format is **unverified**): one line per device naming a `/dev/hidrawN` path. Note the path:
   later commands call it DEVICE. Empty output, or a permission error, means the udev rule is missing.

3. **Add the udev rule if step 2 showed nothing.** This is the rule text from the libfido2 README (verified), for
   Yubico devices (USB vendor id 1050):

   ```bash
   printf '%s\n' 'KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0664", GROUP="plugdev", ATTRS{idVendor}=="1050"' | sudo tee /etc/udev/rules.d/70-safo-fido.rules
   sudo usermod -aG plugdev "$USER"
   sudo udevadm control --reload
   sudo udevadm trigger
   ```

   Then log out and back in (the group change applies at the next login) and unplug and replug the key. Another vendor
   needs its own vendor id; the libfido2 repository lists every supported one in `udev/70-u2f.rules`, which also uses
   `TAG+="uaccess"` instead of a group for the logged-in seat user. The Debian package `libu2f-udev` may ship such a
   rules file; what it contains was not read (**unverified**).
   Blast radius: lets every process of your account (and of the `plugdev` group) open the key's HID node. A signature
   still needs a physical touch, so this does not let a process approve anything by itself. Rollback:
   `sudo rm /etc/udev/rules.d/70-safo-fido.rules`, `sudo gpasswd -d "$USER" plugdev`, then the same two `udevadm`
   commands. Expected: `fido2-token -L` now prints the device. (`tee`, `usermod`, `gpasswd` and the `udevadm` flags other
   than `--reload` and `trigger` were not checked against a vendor page; Inferred.)

4. **Run the read-only preflight** from a checkout with safo installed (it only reads, runs `ssh -Q key`, `ldconfig -p`,
   `fido2-token -L` and `ssh-add -L`, and makes no network call):

   ```bash
   python -m safo.gemini_preflight
   echo "exit=$?"
   ```

   One line per check, `PASS`, `WARN` or `FAIL`, then a summary and the exit code (1 when anything failed; add `--strict`
   to also fail on a warning). On a machine before any setup, expect (run, 2026-10-31, no key attached):

   ```text
   PASS ssh-sk-support: ssh lists ed25519-sk and ecdsa-sk and ssh-sk-helper is installed
   PASS libfido2: libfido2 is in the linker cache
   WARN udev-rule: no hidraw rule with uaccess or plugdev for vendor 1050 was found; ...
   WARN hardware-key: no hardware key is visible: plug it in (and load it with ssh-add if you use the agent)
   FAIL allowed-signers: the file does not exist (step d of docs/gemini-enrollment.md)
   PASS switch: absent: paid use is off (the safe state until the dry run has passed)
   WARN egress-mode: the egress config does not exist (the egress steps of the runbook are not done)
   FAIL broker-config: the file does not exist (the 'Create the broker configuration' step of the runbook)
   FAIL client-config: the file does not exist (copy examples/broker-client.example.yaml to ~/.config/safo/broker-client.yaml)
   FAIL service-user: user safo-broker does not exist (step 2 of the root setup in docs/gemini-broker.md)
   WARN state-dir: absent: systemd creates it at the first start of the service (StateDirectory=)
   summary: 3 pass, 4 warn, 4 fail; exit 1
   ```

   The four `FAIL` lines are expected until step d (`allowed-signers`), the root setup (`broker-config` and
   `service-user`) and your own client config (`client-config`) are done. Run it again at the end. Blast radius:
   none (read only; the tests run it on a read-only tree). Rollback: none needed.

## Step a. Enroll one or two FIDO2 keys for approvals

Approvals are OpenSSH signatures in the namespace `safo-gemini-approval` (a dry run uses `safo-gemini-approval-dryrun`).
**Plan: enroll two physical keys, A and B.** Keep B offline in a safe place; it is the way back in if A is lost.

**Choices, with the reason:**

- **Type.** `ed25519-sk` needs YubiKey firmware 5.2.3 or newer; on older firmware use `ecdsa-sk`, which works on all FIDO2
  YubiKeys (Yubico page). The broker accepts both (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`).
- **`-O verify-required`.** Every signature needs the PIN as well as the touch. Needs OpenSSH 8.4 or newer (Yubico page)
  and a PIN set first. Use it: a stolen key alone then cannot approve.
- **Resident or not.** The manual says a resident key stores the key handle on the device, "increases the likelihood of an
  attacker being able to use a stolen authenticator device" if both parts are on it, and typically needs a PIN. **Default
  here: not resident.** The credential reference then lives only in the handle file on disk, so back that file up with
  the key (Yubico page); without it that credential cannot sign. A resident variant is given after the command.
- **`-O application=ssh:NAME`.** A distinct credential label (it must start with `ssh:`), so the approval key, the
  release key and any other key on the same device never overwrite each other.

### a1. Set a PIN on the key (once per key)

```bash
fido2-token -L
fido2-token -S DEVICE
```

Replace `DEVICE` with the `/dev/hidrawN` path from the first command. `-S` "sets the PIN of device"; to change an
existing PIN use `fido2-token -C DEVICE` (both from the `fido2-token(1)` manual). Blast radius: the PIN on that one key.
Rollback: change it with `-C`; a forgotten PIN needs a FIDO2 reset in the vendor manager, which **deletes every FIDO2
credential on the key** (Yubico page) and means re-enrolling. Expected: a prompt for the new PIN twice; exit 0 (shape,
**unverified** wording).

### a2. Create approval key A

```bash
mkdir -p ~/.ssh/safo && chmod 700 ~/.ssh/safo
ssh-keygen -t ed25519-sk -O verify-required -O application=ssh:safo-gemini-a -C "safo gemini approval key A" -f ~/.ssh/safo/safo_gemini_a
```

Touch the key when it blinks and type the PIN when asked. ssh-keygen then asks for a passphrase for the handle file;
setting one is allowed and is an extra layer. Blast radius: creates one credential on the key and two files,
`~/.ssh/safo/safo_gemini_a` (the handle: a reference, not the private key) and `~/.ssh/safo/safo_gemini_a.pub`. Nothing
is enrolled anywhere yet, so this authorizes nothing. Rollback: `rm ~/.ssh/safo/safo_gemini_a ~/.ssh/safo/safo_gemini_a.pub`;
the credential stays on the key unused (for a non-resident key it cannot be listed or removed individually; a FIDO2
reset clears it). Expected (shape, **unverified** wording): a line `Generating public/private ed25519-sk key pair.`, a
touch prompt, then the saved paths and a `SHA256:` fingerprint.

On firmware older than 5.2.3 replace `ed25519-sk` with `ecdsa-sk`.

**Resident variant** (stores the credential on the key so it can be re-downloaded; needs a PIN set and, per Yubico,
firmware 5.2.3 or newer): add `-O resident` to the command. To recover on another machine: `ssh-keygen -K` writes the
handle and public key files into the current directory (OpenSSH 8.3 or newer; "keys will be downloaded from the first
touched authenticator").

Record the fingerprint, and keep a copy off this machine next to where the key is stored:

```bash
ssh-keygen -lf ~/.ssh/safo/safo_gemini_a.pub
```

Expected (shape; the run with a software key printed `256 SHA256:... comment (ED25519)`; a hardware key should end in
`(ED25519-SK)`, **unverified**). Blast radius and rollback: none (read only).

### a3. Create key B on the second physical key

Unplug A, plug in B, and set its PIN as in a1. Then:

```bash
ssh-keygen -t ed25519-sk -O verify-required -O application=ssh:safo-gemini-b -C "safo gemini approval key B" -f ~/.ssh/safo/safo_gemini_b
ssh-keygen -lf ~/.ssh/safo/safo_gemini_b.pub
```

Same blast radius, rollback and expected output as a2. Copy `safo_gemini_b` and `safo_gemini_b.pub` to the offline store
with key B. If only one key is available now, enroll it and put B on your list: `safo gemini keys check` warns about a
single key.

### a4. Test a signature, in the dry-run namespace, with a throw-away allowed-signers file

This proves the key signs and that the namespace and the tamper checks bite. It uses the **dry-run** namespace and a
file in a scratch directory that you own; it touches no `/etc` file and no real approval. Replace `a` with `b` to test B.

```bash
T="$(mktemp -d)" && cd "$T" && printf 'safo enrollment test\n' > msg
ssh-keygen -Y sign -f ~/.ssh/safo/safo_gemini_a -n safo-gemini-approval-dryrun < msg > sig.txt
printf 'key-a namespaces="safo-gemini-approval-dryrun" %s\n' "$(cut -d' ' -f1,2 ~/.ssh/safo/safo_gemini_a.pub)" > allowed
ssh-keygen -Y verify -f allowed -I key-a -n safo-gemini-approval-dryrun -s sig.txt < msg; echo "rc=$?"
```

Touch the key and give the PIN at the sign step. With no file argument `-Y sign` signs standard input and writes
the signature to standard output (manual), which the redirect saves as `sig.txt`. Blast radius: files under the new temporary directory
only. Rollback: `rm -r "$T"`. Expected:

```text
Good "safo-gemini-approval-dryrun" signature for key-a with ED25519-SK key SHA256:...
rc=0
```

(run with a software key, which printed `with ED25519 key`; the `-SK` form is **unverified**). Now the three refusals,
each of which must print a failure and a nonzero rc:

```bash
ssh-keygen -Y verify -f allowed -I key-a -n safo-gemini-approval -s sig.txt < msg; echo "rc=$?"
printf 'other\n' | ssh-keygen -Y verify -f allowed -I key-a -n safo-gemini-approval-dryrun -s sig.txt; echo "rc=$?"
ssh-keygen -Y verify -f allowed -I key-a -n safo-gemini-approval-dryrun -s sig.txt -r ~/.ssh/safo/safo_gemini_a.pub < msg; echo "rc=$?"
```

Expected (run): `Couldn't verify signature: namespace does not match` with `rc=255`; `Signature verification failed:
incorrect signature` with `rc=255`; and for the revocation test `Could not verify signature.` with `rc=255` (the `-r` file
may be a list of public keys; manual). If any of these three ends in `rc=0`, stop: the check is not biting.

Two more checks, by hand. Sign again and confirm it asks for a touch and the PIN every time (the manual says
`verify-required` requires verification for each signature). Then unplug the key and confirm the sign command fails.

The manual does not say that `-Y verify` reports the PIN check, so a green verify does not prove the PIN was asked. The
safo dry run reads the authenticator flags and prints touch and PIN, and that is the proof (`safo gemini paid-dryrun`, built and merged).

For the structure-only check, `ssh-keygen -Y check-novalidate -n NAMESPACE -s SIGFILE < msg` does not validate that a
signature comes from an authorized signer (manual). Run with a software key it printed a Good line and exited 0.

## Step b. Test a second device (the Immurok): decision table

**Prior art and what is known.** [Gemini keys](gemini-keys.md) records what the vendor pages say. Re-read on 2026-10-31:
the blog page shows `imk run --agent -- COMMAND` and says the device AUTH cooldown also satisfies SSH key signing; it
does not say whether `ssh-keygen -Y sign` works, which curve is used, or what the signature format is. The device is not
a FIDO security key. **Unverified**: everything about how it appears to `ssh-agent`.

**Rule that the table applies.** The broker accepts `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`
as hardware keys and plain `ssh-ed25519` only with a written per-key opt-in (`allow-software`), which the key check warns
about. A key held by an agent that can sign more than once per gesture breaks "one touch per approval".

Run these tests with the device connected, in a scratch directory. They sign only a throw-away text in the dry-run
namespace.

```bash
ssh-add -L
```

B1: the device's key is listed (type and comment visible). Save its public key line into a file, `IMK.pub`:

```bash
T="$(mktemp -d)" && cd "$T" && printf 'safo enrollment test\n' > msg
ssh-add -L > agent_keys.txt && cut -d' ' -f1 agent_keys.txt
```

Edit `agent_keys.txt` down to the single line for the device and rename it `IMK.pub` (the first column shows the key
type; an `sk-` prefix means a FIDO-style hardware key). Then:

```bash
ssh-keygen -Y sign -f IMK.pub -n safo-gemini-approval-dryrun < msg > sig.txt ; echo "rc=$?"
printf 'imk namespaces="safo-gemini-approval-dryrun" %s\n' "$(cut -d' ' -f1,2 IMK.pub)" > allowed
ssh-keygen -Y verify -f allowed -I imk -n safo-gemini-approval-dryrun -s sig.txt < msg; echo "rc=$?"
```

B2: the sign works (rc 0, `sig.txt` exists). B3: the verify prints `Good ... signature for imk` with rc 0. The manual says the
`-f` of `-Y sign` may be "a public key with the private half available via ssh-agent". `-U` is documented there only for
a CA key, so it is not used; if the sign fails with a message about reading the private key, that is itself a result,
not a reason to add flags. If the vendor ships a signing library, `-w PROVIDER` (for key creation) and the
`SSH_SK_PROVIDER` variable are the documented ways to point OpenSSH at it; running a vendor library inside `ssh-keygen`
is trusting that code, so read what it is first.

Then three more tests, each with a fresh sign command:

```bash
for i in 1 2 3; do rm -f sig.txt; ssh-keygen -Y sign -f IMK.pub -n safo-gemini-approval-dryrun < msg > sig.txt; echo "sign $i rc=$?"; done
```

B4: count the gestures. Each of the three signatures must have asked for its own fingerprint gesture. If the second or
third went through silently, one gesture covers several signatures (the cooldown).

B5: open a second terminal that does **not** go through the vendor wrapper (no `imk run`, a fresh shell) and run the same
sign command with the same `IMK.pub`. It must fail or demand a gesture. If a plain process gets a signature without a
gesture, an agent can too.

B6: `cut -d' ' -f1 IMK.pub` shows the key type. `sk-ssh-ed25519@openssh.com` or `sk-ecdsa-sha2-nistp256@openssh.com`
means an sk key; `ssh-ed25519` or `ecdsa-sha2-nistp256` means a software or agent-held key. Note: the broker also refuses
a plain `ecdsa-sha2-nistp256` key (it accepts only the two sk types and `ssh-ed25519`).

| B1 listed | B2 sign rc 0 | B3 verify rc 0 | B4 gesture every time | B5 no signature without wrapper | B6 key type | Decision |
|---|---|---|---|---|---|---|
| no | n/a | n/a | n/a | n/a | n/a | **FAIL.** Not usable through OpenSSH here. Do not enroll. |
| yes | no | n/a | n/a | n/a | any | **FAIL.** `ssh-keygen -Y sign` cannot use it. Do not enroll. |
| yes | yes | no | n/a | n/a | any | **FAIL.** The signature does not verify. Do not enroll. |
| yes | yes | yes | no | any | any | **FAIL for approvals.** One gesture covers several signatures. Do not enroll. |
| yes | yes | yes | yes | no | any | **FAIL for approvals.** A process without the wrapper can sign, so an agent can. Do not enroll. |
| yes | yes | yes | yes | yes | `ssh-ed25519` | **WARN, not recommended.** Passes the gesture tests but is a software or agent-held key: enrolling needs `# safo: LABEL allow-software` and the key check warns loudly. A hardware key (step a) stays the approval key. Use the device for what the vendor built it for (a human gate on `sudo` and `git push`), not for spend. |
| yes | yes | yes | yes | yes | `sk-` type | **PASS.** A hardware key to OpenSSH. Enroll it as a third key with its own label, then confirm its touch and PIN flags with the safo dry run before relying on it. |

Blast radius: the tests sign only throw-away text, in the dry-run namespace, in a scratch directory; they enroll nothing.
Rollback: `rm -r "$T"`; if you loaded a key into the agent, `ssh-add -d IMK.pub` removes it (`-d` was not read for this
page; Inferred). Record the table row you reached and the date in your notes; the result stays private to you.

## Step c. A separate release-signing key for the installer tags

The installer verifies a signed annotated tag against `/etc/safo/broker-release-signers` (see "Install and update
chain" in [Gemini broker](gemini-broker.md)). A key that approves spend and a key that releases code are different
powers: **never put one key in both files**, and prefer a different physical key for each.

- **Best:** a third physical key, used only for releases, stored apart from A and B.
- **Acceptable:** a second credential on key B with `-O application=ssh:safo-release`, a different handle file, and a
  different label. One stolen device then holds both powers; the PIN is the only barrier between them. Say so in your notes.

```bash
mkdir -p ~/.ssh/safo-release && chmod 700 ~/.ssh/safo-release
ssh-keygen -t ed25519-sk -O verify-required -O application=ssh:safo-release -C "safo broker release signer" -f ~/.ssh/safo-release/safo_release
ssh-keygen -lf ~/.ssh/safo-release/safo_release.pub
```

Set the PIN first as in a1 (on ecdsa-only firmware use `ecdsa-sk`). Blast radius: one new credential and two files in a
folder separate from the approval keys. Nothing is enrolled yet. Rollback: delete the folder; the credential stays on the
key unused. Expected: the same shape as a2.

**Test with a signed tag in a throw-away repository.** Git signs tags with an SSH key when `gpg.format` is `ssh` and
`user.signingKey` is the key path (git-config manual). Git uses the namespace `git`; that is not stated on the git pages
read, but a run on 2026-10-31 (git 2.47.3, a software key) showed `Good "git" signature for release-signer` with
`namespaces="git"` and the refusal `key is not permitted for use in signature namespace "git"` when the file said
`safo-gemini-approval`.

```bash
T="$(mktemp -d)" && cd "$T" && git init -q repo && cd repo
git config user.name "release test" && git config user.email "test@example.com"
git commit -q --allow-empty -m "test"
git config gpg.format ssh && git config user.signingkey ~/.ssh/safo-release/safo_release
git tag -s -m "release test" v0.0.0-test
printf 'release-key namespaces="git" %s\n' "$(cut -d' ' -f1,2 ~/.ssh/safo-release/safo_release.pub)" > ../release-signers
git -c gpg.ssh.allowedSignersFile=../release-signers tag -v v0.0.0-test; echo "rc=$?"
git cat-file -t v0.0.0-test
```

Touch and PIN at the `tag -s` step. Expected: `Good "git" signature for release-key with ED25519-SK key SHA256:...`
(shape; run with a software key: `... with ED25519 key ...`), `rc=0`, and `tag` from the last command (an annotated tag
object; the installer refuses a lightweight tag). Then prove the key is not an approval key:

```bash
printf 'release-key namespaces="safo-gemini-approval" %s\n' "$(cut -d' ' -f1,2 ~/.ssh/safo-release/safo_release.pub)" > ../wrong-signers
git -c gpg.ssh.allowedSignersFile=../wrong-signers tag -v v0.0.0-test; echo "rc=$?"
```

Expected (run): `Could not verify signature.` and `key is not permitted for use in signature namespace "git"`, rc 1.
Blast radius: a scratch repository only. Rollback: `rm -r "$T"`. The exact `git` flags the installer will use are
**inferred** in the broker design and are re-checked when the installer is built; this step proves the key and the
namespace, not the installer.

Keep the two groups of files apart: approval keys in `~/.ssh/safo/`, the release key in `~/.ssh/safo-release/`, public
keys of the first group go in `gemini-allowed-signers`, the second in `broker-release-signers`, and the fingerprints of
both are recorded off this machine under different headings.

## Step d. The root-owned allowed-signers lines

The approval file is `/etc/safo/gemini-allowed-signers`: root-owned, mode 0644, in a root-owned directory, one line per
key: `LABEL namespaces="safo-gemini-approval" KEYTYPE BASE64`. The label is the principal. Never write a line without the
`namespaces=` option: a key without it is accepted by OpenSSH for any namespace, and the broker refuses the line.

1. **Print the line.** Preferred (`safo gemini keys propose` is built and merged; it works before the files of step 2 exist):

   ```bash
   safo gemini keys propose ~/.ssh/safo/safo_gemini_a.pub --label yubikey-a
   ```

   Cross-check (the two lines must be the same):

   ```bash
   printf '%s namespaces="safo-gemini-approval" %s\n' yubikey-a "$(cut -d' ' -f1,2 ~/.ssh/safo/safo_gemini_a.pub)"
   ```

   Expected: one line, `yubikey-a namespaces="safo-gemini-approval" sk-ssh-ed25519@openssh.com AAAA...` (the key
   type word of a hardware key is `sk-ssh-ed25519@openssh.com`; shape). Labels are lowercase letters, digits, dot,
   underscore and dash. Blast radius and rollback: none (prints only).

2. **Create the folder and both files, once, as root.** The revocation file may be empty but a missing one refuses every
   approval.

   ```bash
   sudo install -d -m 755 -o root -g root /etc/safo
   sudo install -m 644 -o root -g root /dev/null /etc/safo/gemini-allowed-signers
   sudo install -m 644 -o root -g root /dev/null /etc/safo/gemini-revoked-signers
   ls -ld /etc/safo && ls -l /etc/safo
   ```

   Blast radius: creates `/etc/safo` and two empty root-owned files; with no keys enrolled, nothing can be approved.
   Rollback: `sudo rm /etc/safo/gemini-allowed-signers /etc/safo/gemini-revoked-signers` (and `sudo rmdir /etc/safo` if
   empty). Expected: `drwxr-xr-x ... root root ... /etc/safo` and two `-rw-r--r-- 1 root root 0` files.

3. **Add the lines, with a backup and a diff, every time.**

   ```bash
   sudo cp -a /etc/safo/gemini-allowed-signers /etc/safo/gemini-allowed-signers-backup
   sudoedit /etc/safo/gemini-allowed-signers
   diff /etc/safo/gemini-allowed-signers-backup /etc/safo/gemini-allowed-signers
   ls -l /etc/safo
   ```

   Paste the line from step 1. For a key made with `verify-required`, add under it the comment line
   `# safo: yubikey-a require-pin` (OpenSSH ignores comments). Add key B the same way with its own label. Blast radius:
   this file decides who can authorize spend; a wrong line can enroll a key you do not hold. Rollback:
   `sudo cp -a /etc/safo/gemini-allowed-signers-backup /etc/safo/gemini-allowed-signers`. Expected: the diff shows only
   the lines you added (`>` lines); `ls -l` shows `root root` and `-rw-r--r--` on both files. (`sudoedit`, `cp -a`,
   `diff` are standard tools; not checked against a vendor page here; Inferred.)

4. **Check it with OpenSSH, and with the preflight.**

   ```bash
   ssh-keygen -Y find-principals -f /etc/safo/gemini-allowed-signers -s "$T/sig.txt"
   python -m safo.gemini_preflight
   ```

   For `$T/sig.txt` use the signature from step a4 (re-run a4 first if the folder is gone). Expected: the first command
   prints `key-a`'s label as it appears in the file (run with a software key: it printed the principal), and `find-principals`
   does not check the namespace, so it only proves the key is listed. To prove the **namespace restriction** bites, the
   dry-run signature must now be refused by the real file (run, with the restriction `safo-gemini-approval`):

   ```bash
   ssh-keygen -Y verify -f /etc/safo/gemini-allowed-signers -I yubikey-a -n safo-gemini-approval-dryrun -s "$T/sig.txt" < "$T/msg"; echo "rc=$?"
   ```

   Expected: a line ending in `is not permitted for use in signature namespace` followed by the dry-run name, then
   `Could not verify signature.`, then `rc=255`.

   The preflight line `allowed-signers` must read `PASS`, with every key line bound to the approval namespace, root-owned,
   mode 0644. Do not sign any other text in the real approval namespace: a signature there is what the broker is built to
   accept once the payload is right. The `--dry-run` approve in the keys page (section "Test without spending") is the
   proof that matters, now that the broker is merged.

5. **The release signers file** is the same shape with the other namespace, and its own file, installed by root the same
   way: `/etc/safo/broker-release-signers`, lines `release-key namespaces="git" KEYTYPE BASE64`, root-owned, mode 0644.
   The installer accepts only that exact shape: one plain principal name (no list, wildcard or `!`), exactly the option
   `namespaces="git"` and no other option (so no `cert-authority`, no `valid-before`), a hardware key type
   (`sk-ssh-ed25519@openssh.com` or `sk-ecdsa-sha2-nistp256@openssh.com`) and a base64 key. A certificate-authority line
   would let any software key holding a certificate from that authority sign a release without a touch, so it is refused,
   and after `git verify-tag` the installer also refuses a signature whose reported key type is a certificate. To retire a
   key, delete its line.

The enable switch /etc/safo/gemini-paid-enabled is created by the **last step** of the root runbook, after the dry run,
and by no other line. That line runs the preflight first (python -I -m safo.gemini_preflight --enabling, as root, from the
installed release) and writes the file only if it exits 0. The preflight reports the switch as absent (pass) and as
present (warn: the content is not read, because the broker, not the preflight, decides). Its egress-mode line reads the
root-owned egress config and prints the mode word only: drop passes; observe warns while paid use is off and **fails**
when the switch is being created (--enabling) or already exists; a missing or unusable config fails in that case too.

Two more lines read the configuration the broker needs, and both must pass before the switch is created. `broker-config`
checks `/etc/safo/broker.yaml` (written by the "Create the broker configuration" step of the root runbook): it exists, root
owns it, group and others cannot write it, it loads through the same loader the service uses, and it lists at least one
allowed uid. `client-config` checks your own `~/.config/safo/broker-client.yaml` (copy `examples/broker-client.example.yaml`,
mode 0600, in a 0700 directory, and set the key file and the principal): it exists and loads. Root runs the last step, so that
line passes `--maintainer-uid $(id -u LOGIN)` (a number); the preflight looks up that account's home itself, opens the file
without following links, judges the opened descriptor and every directory above it (none writable by group or others),
and accepts only a file owned by root or that account. Run the preflight yourself without the flag and it looks in your own home.
The interpreter in that line is the one the installer builds, `/opt/safo-broker/current/venv/bin/python`.

The one way past the observe-mode failure is the flag `--ack-observe-mode`, which you add to that line yourself. Observe
mode logs and accepts, so a code execution bug in the broker could send the paid key to any IPv4 address until you switch
to drop; the vendor-side spend limit is the only backstop. Use the flag only after an empty observe log (see the runbook's
egress step) through a full dry run, which is the minimum evidence, and switch to drop after the first clean real call at
the latest. Blast radius: the window between enabling and the switch to drop. Rollback: remove the switch, set `MODE=drop`,
restart the egress service.

## Step e. Rotate and revoke

### e1. Rotate an approval key (planned)

1. Make the new key (step a2 with a new `application=` name and file name) and test it (a4).
2. Add its line to `/etc/safo/gemini-allowed-signers` (step d3). Keep the old line: history still reads. To give the old
   key an end date you will not forget, add `valid-before="YYYYMMDDZ"` to its options (accepted forms are in
   [Gemini keys](gemini-keys.md); the options are `valid-after` and `valid-before` in the manual).
3. Switch `signing.principal` and `signing.key` in `~/.config/safo/gemini.yaml` to the new key and run a dry run.
4. Revoke the old key (e2) once the dry run passes, then record the new fingerprint off this machine.

Blast radius: two keys valid together for a short time. Rollback: switch `gemini.yaml` back; remove the new line using
the backup. Expected: `safo gemini keys list` shows both until the old one is revoked.

### e2. Revoke a key (lost, stolen or retired). Revoke first, investigate second.

1. Get the fingerprint: your off-machine record, or

   ```bash
   ssh-keygen -lf ~/.ssh/safo/safo_gemini_a.pub
   ```

2. Add one line to the revocation list: the `SHA256:` fingerprint or the whole public key line (the broker reads both;
   a plain `ssh-keygen -Y verify -r FILE` takes public keys or a KRL, per the manual, so keep the public-key form
   if you want to cross-check with OpenSSH).

   ```bash
   sudo cp -a /etc/safo/gemini-revoked-signers /etc/safo/gemini-revoked-signers-backup
   sudoedit /etc/safo/gemini-revoked-signers
   diff /etc/safo/gemini-revoked-signers-backup /etc/safo/gemini-revoked-signers
   ls -l /etc/safo
   ```

   Blast radius: that key can no longer approve, even if it is still enrolled; a malformed line stops every approval
   until fixed. Rollback: restore the backup file, only if the key was revoked by mistake and is not lost. Expected: the
   diff shows one added line; the files stay `root root` and `-rw-r--r--`.

3. Cross-check with OpenSSH (public-key form of the revocation file, in a scratch directory):

   ```bash
   ssh-keygen -Y verify -f allowed -I key-a -n safo-gemini-approval-dryrun -s sig.txt -r ~/.ssh/safo/safo_gemini_a.pub < msg; echo "rc=$?"
   ```

   Expected (run): `Could not verify signature.`, `rc=255`.
4. Look for what it did: the ledger rows `approval_issued` and `approval_used` name the principal; compare them with the
   vendor billing page ([Gemini keys](gemini-keys.md), "Revoking a key"). If the PIN could have been seen, change it with
   `fido2-token -C DEVICE`. If the paid API key might have been exposed, rotate it (the root setup in
   [Gemini broker](gemini-broker.md)).
5. If the key is a resident key and you keep the device, you can list and delete its credentials: `fido2-token -L -r
   DEVICE` lists relying parties with resident credentials, `fido2-token -L -k RP_ID DEVICE` lists those for one, and
   `fido2-token -D -i ID DEVICE` deletes one (all from the `fido2-token(1)` manual; ask for the PIN). A non-resident
   credential cannot be removed one by one; resetting the FIDO2 application deletes all (Yubico page). A retired key you
   keep: revoke it anyway; the line costs nothing.
6. Enroll a replacement (steps a to d).

### e3. Rotate or revoke the release key

Same shape. A new release key is added to `/etc/safo/broker-release-signers` before the old one is removed (so a
release can still be signed), then the old line is deleted by root with a backup and a diff. Tags signed by the old key
stay valid only as long as its line stays in the file; to retire its signed history on purpose, remove the line. A
stolen release key means: remove the line first, then raise `/etc/safo/broker-min-version` as the broker design
describes, then review what was released. Blast radius: which code root will install. Rollback: restore the backup.

## Related root step (not part of enrollment)

The API key of the broker goes in with `systemd-creds encrypt --name=paid-key --with-key=host`, as in [Gemini broker](gemini-broker.md).
Both flags were found in the `systemd-creds(1)` manual (systemd 262) on 2026-10-31: `--name=` sets the credential name
embedded in the file (and checked at decrypt), and `--with-key=` selects the key (host, and a TPM2 option). That
procedure is not repeated here, and the preflight does not read the credential.

## Ordering, and what comes after

1. Step 0 (packages, udev, preflight). 2. Step a (keys A and B), test a4. 3. Step b (optional, any time). 4. Step c.
5. The root setup in [Gemini broker](gemini-broker.md) (user, folders, the paid key). 6. Step d (the files). 7. Install
the broker and run the preflight again. 8. The dry run. 9. Only then the switch, and the first real call, which
is phase 7 itself and needs the maintainer's real key and a vendor call.

## Not verified

- Output words for hardware keys: `ED25519-SK`, the touch prompts and the exact `fido2-token -L` line format.
- What the Debian package `libu2f-udev` installs.
- Whether the Immurok works with `ssh-keygen -Y sign` at all.
- That the installer uses exactly the `git` namespace and these flags.
- `ssh-add -d`, `tee`, `usermod`, `gpasswd`, `apt`, `sudoedit`, `diff`: standard tools, not read from a vendor page here.
- Nothing in this runbook was run against a hardware key or as root by the author.
