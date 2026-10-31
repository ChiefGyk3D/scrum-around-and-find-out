# Gemini broker: design for the paid path

> **Status: phases 1 to 3 and the client module of phase 4 are in the tree; the rest is design.** The core library, the
> call pipeline, the socket server and the thin client under `src/safo/broker/` exist (see "Phase 1 status" to
> "Phase 4b status" below). There is no unit, no installer and no `safo gemini` wiring, and no vendor call has ever been made, so
> paid use stays disabled by the root-owned switch (see [Gemini](gemini.md)) until the broker is built, reviewed and
> enabled by the maintainer. This page is the design for issue #205 (steps 1 and 2); the risks are in
> [the broker threat model](gemini-broker-threat-model.md). Nothing here is a promise about code that does not exist yet; the
> claims about what code does today are checked against the tree, and the claims about the vendor were read from the
> vendor pages on 2026-10-30 (marked **verified** with the page, or **unverified**).

### Phase 1 status

Built and tested (pure functions and a file ledger, no network): integer micro-dollar money; the price table loader
and the worst-case reservation `A + B + C`, each part rounded up; the per-job cap (2.50 USD in the testing phase) and
the monthly ceiling (10 USD) with the extra-block flag, which a configuration may lower and never raise; the model
allow-list and the refusal of Pro-class models until their output cap is verified; the call state machine (reserved,
sent, settled, ambiguous, suspended, cleared) with every other pair rejected; the schema version 3 approval text and
ledger rows, parsed strictly; and a ledger that records the spend before a call is sent, reads back as ambiguous or
settled after any interruption, and refuses a rolled-back, edited, truncated or world-readable state directory.

Known limit, as the design already says under "Backup key": restoring the whole state directory from an earlier copy
rewinds the ledger, the height record and the used markers together, and the ledger cannot see that. The defense is the
rule that the state directory is never restored into a running broker, and root's reconciliation against the vendor
billing page. A high-water record kept outside the broker user's reach is a design question for a later phase.

Not built yet: the socket server, the real transport, the client, the units, the installer and the administration command. Where the phase-1 code adds something the design did
not name, it is listed in the pull request: a `call_sent` row written before the connection opens, suspensions kept as
chained ledger rows instead of a separate state file, and two reply codes (`model_refused`, `prices_expired`).

### Phase 2 status

Built and tested against a fake vendor (no socket, no key, no network): approval verification, `begin`, the call
pipeline, the vendor request templates and reply parser, the image checks, and the output-cap rule.

- **Approval verification** (`approval.py`). The signed text is encoded to ASCII once, verified by `ssh-keygen -Y verify`
  through the existing verifier (absolute path, fixed argument vector, no shell, a two-entry environment, signers line
  and signature sealed in memory), and only then parsed again. The namespace is a constant in code. The text must be the
  canonical form and the key that verified must be the principal named in it. Revocation is checked again under the
  ledger lock, just before the spend.
- **`begin`** (`issue.py`) writes `issued/NONCE` (private, at most four outstanding, ten minute life); a call needs its
  nonce there, unexpired, and an approval that agrees with what was asked for. A restart flushes the table.
- **The pipeline** (`pipeline.py`): verify, reserve (the spend and the markers are written first), build the request
  from a fixed template, write `call_sent`, send through an injected transport, classify, settle or make ambiguous. A
  429 and a definite 4xx settle at zero. Everything after the request may have left that does not tell what was billed
  is ambiguous: the full reservation stays counted and the model is suspended. A failure after the spend and before the
  send settles as `not_sent`. Tests kill the process at every step and check that the result is unspent, settled or
  ambiguous, never free budget.
- **The output cap** (decision 13): the signed `max_output_tokens` is always sent and checked against the reply (text,
  thinking and image tokens together). A reply over it is a breach: recorded at the cap or the reported usage, whichever
  is higher, the model suspended, even when the money stays inside the reservation (`cap_verified` false).
- **Images** (`images.py`, `vendor.py`): one image per call, PNG, JPEG or WebP only, found by the first bytes and matching
  the named type. The broker decodes no pixels and is not a decoder, but it walks each container to its real end by
  lengths and markers as an allow-list: every segment or chunk is a known type whose body has exactly its shape (JPEG
  tables and headers, a plain JFIF header, PNG chunks with checksums, rows that inflate to exactly the declared size
  with a real filter type, a plain WebP or the extended header and the one image). Exif, XMP, ICC and compressed
  metadata, animations, thumbnails and anything appended are refused, and the declared size is capped (8192 per side,
  2^25 pixels, 24 MiB). The compressed bitstream itself (JPEG entropy data, WebP codec data) is not validated, so a
  well-framed file can still fail to decode in a viewer: images stay untrusted output. An image that fails is not
  passed on, and its cost is still counted from usage.

Where phase 2 read the design and had to choose, it is listed in the pull request. Still unverified: the real response
shapes. The text shape is the one the existing wrapper already reads; the image shape is inferred from the vendor SDK examples
and the parser refuses any other, so a real reply that differs makes the call ambiguous until phase 7 records it.

The maintainer decided on 2026-10-30 that the paid path must be finished, because other projects are blocked on it.
The first thing those projects need is **quality image generation**, which is paid-only (the free tier gives none). So
this design treats an image call as the first-class case and text as the simpler case that rides the same path.

### Phase 3 status

Built and tested over socketpairs and a temporary unix socket, with the fake vendor and injected clocks (no network, no
key, no timing assertions): the wire format, the server, the entry point and the readers around it.

- **`protocol.py`** is the wire format and nothing else, importable by a thin client unchanged (standard library and
  the repository's bounded JSON loader only). Frames, limits, the field table per operation, `parse_request`, `request_body` (what a client
  builds, validated by the same parser), the reply codes with their exit status and one sentence each, `parse_reply`
  (what a client reads). `rate_limited`, `vendor_refused` and `outcome_unknown` are now in the core code list.
- **`server.py`.** The listening descriptor comes from systemd: `LISTEN_PID` must be this process, `LISTEN_FDS` exactly
  `1`, the descriptor a listening unix stream socket; the variables are removed and the descriptor made non-inheritable.
  The peer's uid (`SO_PEERCRED`) must be in `server.allowed_uids` of the root-owned `broker.yaml`; another uid gets one
  `unauthorized_peer` frame and nothing is read. At most 8 connections and 2 per uid, a ninth or third is closed unread.
  One request frame is read under a 5 second whole-frame deadline; a reply is one JSON frame (5 seconds) and then one
  frame per attachment (each write must progress within 10 seconds, the frame within 60). A missed deadline or a broken
  connection drops the connection. Operations: `status`, `begin`, `call`, `check`, `dryrun`. Root's `clear` is **not** on
  the socket (phase 5). While the switch is off, every operation but `status` and `dryrun` answers `disabled`; the switch
  is read on every request. Per peer and per minute: 6 `begin`, 10 `call` attempts, 30 of each other operation; a refusal
  is `busy`. One paid call is in flight at once (`max_concurrent_calls`; a second `call` is `busy` after `slot_wait`
  seconds, default 0), the slot is released before the reply is written, and vendor calls started are counted from the
  ledger (5 a minute, 20 a day). The server logs numbers and enumerated words from an allowlist of field names.
- **Stopping.** SIGTERM stops accepting, lets calls in flight finish and answer, and waits `grace_seconds` (default 150).
  A call still open after that is made ambiguous (the reservation stays counted, the model is suspended) and the exit
  status is 4. A call killed some other way is made ambiguous by `recover` at the next start, before the first accept.
- **`python -I -m safo.broker`** reads `/etc/safo/broker.yaml` (sections `server`, `prices`, `caps`, `deadline_seconds`),
  the state directory and credential directory systemd passes, creates the epoch once in the state directory, sets
  no-core and not-dumpable, scrubs the environment, recovers, flushes the issued table and serves. `transport.py` is the
  HTTPS transport to the vendor: constant host, the checked pinned connection, no redirect followed, the answer capped, the
  key in the `x-goog-api-key` header only and read for every request.

Where phase 3 read the design and had to choose, it is listed in the pull request. Not built: the idle exit, the audit copy
`approvals/NONCE.json` of the design, the installer and units, the admin command (so nothing can yet clear a suspension),
and the client (phase 4b, below). The transport has only been run against loopback; TLS to the real host is unverified until phase 7.

### Phase 4b status

The thin client, `src/safo/broker/client.py`, built and tested with a scripted fake broker, the real server over
socketpairs (a software key, the fake vendor) and a temporary unix socket, with injected clocks and no network. It is
described in "The client" below. What is **not** done: wiring it into `safo gemini` (see "Where the client is not wired
yet"), the dispatch guard's `check`, removal of the in-process paid path, and the free-path independence tests; those
are the rest of phase 4. The safe image writer is phase 4a, a separate branch; until it is in the tree the client uses a
small marked adapter with the same signature.

## The requirement

Approval consumption, spend accounting and the paid API key must live under an authority outside the maintainer's
day-to-day account, so that account cannot rewind them or call the vendor directly. Today all three live under that
account, which is why paid use is disabled. A hardware-key signature proves the maintainer touched a key; it cannot
stop a process running as the maintainer from reusing a signed approval, resetting the ledger, or calling the vendor
with a key it can read.

## The choice, and what was compared

Three ways to get an authority the maintainer's account cannot write:

| Option | Holds the key from the account? | Stops replay and rewind? | Costs |
|---|---|---|---|
| **A small privileged broker** (chosen) | Yes: the key is readable only by the broker's user | Yes: the broker owns the consumption records and the ledger | A service to install and review; one local socket |
| A TPM-backed monotonic counter | No: the paid key would still be readable by the account, so the vendor can be called directly | Only the rewind half: a counter proves "not rolled back", it does not hold the key or make the call | Needs a TPM and its tooling on every machine; a counter can be incremented by anyone allowed to use the TPM; hardware-specific, so poor for a public tool |
| A vendor-side one-time authorization | Would, if it existed | Would, if it existed | Not available for this call (below) |

- **Vendor-side one-time authorization, checked 2026-10-30.** The vendor page on ephemeral tokens
  (`ai.google.dev/gemini-api/docs/ephemeral-tokens`, "Last updated" shown on the page, read 2026-10-30) says they are
  "only compatible with Live API". They carry a use count, but not for text or image generation calls, so they cannot
  be the one-time authorization for this path. **Verified** against that page; whether the vendor has another such
  mechanism is **unverified** (no page found that says so). The vendor-side monthly limit stays as the backstop.
- **A broker on another machine** (the lab) would be stronger against a compromised laptop. It needs a network
  authentication story that does not exist yet. The socket protocol below is written so it could later be carried to
  another host; it is not chosen now. The laptop's root is already the trust assumption of the signed-approval design.

The broker moves the trust anchor from "the maintainer's account" to "root on this machine plus the hardware key". It
does not remove the need to trust either (see [the threat model](gemini-broker-threat-model.md)).

## The broker in one page

- **A system service** run as a dedicated unprivileged system user, `safo-broker` (no login shell, no home), not the
  maintainer's account and **not root**. Root is not needed: the broker reads root-owned public files, writes its own
  state directory, holds one credential that systemd hands it, and makes one outbound HTTPS call. Running as a
  non-root user means a bug in the broker does not give root.
- **Started by a systemd socket unit** on a local Unix socket. The service starts on the first connection and exits
  after an idle period; the socket stays.
- **It holds the paid key.** The key reaches it only as a systemd credential (below). The maintainer's account never
  reads it.
- **It owns the state:** the approval consumption records and the spend ledger, in a directory writable only by
  `safo-broker`.
- **It verifies the hardware-key signed approval itself**, against the allowed signers and the revocation list, which
  are root-owned files, with the same `ssh-keygen` sealed-input approach as today ([Gemini](gemini.md), "Inputs to
  ssh-keygen are sealed").
- **It enforces** the single-use nonce, the expiry, the model and job, the prompt digest, and the per-job and monthly
  caps and the extra-block rule, by **reserving the worst-case cost** of each call before it is sent (see "Cost").
- **It makes the vendor call itself**, to a destination fixed in code, writes the ledger, and returns only the
  response (text or image bytes) and a receipt.
- **The maintainer's wrapper becomes a thin client.** It builds the approval (the touch), sends one request, receives
  one reply, and writes image files to a fixed folder. It holds no paid key and no authoritative state.
- **The free path never touches the broker.** See "The free path stays independent".

```text
 maintainer account (agents also run here)            safo-broker (unprivileged system user)
 +-----------------------------------+  unix socket  +----------------------------------------+
 | safo gemini approve  (hardware    |<------------->| verify signature (root-owned signers)  |
 |   key touch, builds signed text)  |  framed JSON  | single-use nonce, expiry, caps, digest |
 | safo gemini ask --paid (client)   |  + binary     | ledger + consumption records (own dir) |
 | writes images to a fixed folder   |               | paid key (systemd credential, in RAM)  |
 +-----------------------------------+               | one HTTPS call to the pinned vendor    |
                                                     +----------------------------------------+
        root owns: /etc/safo/* (signers, revocations, switch, broker.yaml), /opt/safo-broker (code), the units
```

## How the key reaches the broker

Goal: the paid key is never readable by the maintainer's account or by agents, at rest or at run time.

**At run time.** The service unit uses `LoadCredentialEncrypted=paid-key:/etc/safo/broker/paid-key`. systemd
(PID 1, root) decrypts the credential and places it in the service's private credentials directory
(`$CREDENTIALS_DIRECTORY`, under `/run/credentials/`), which only the service's user can read. systemd 257 is on this
machine, `systemd-creds` and the `LoadCredentialEncrypted=` setting are in its manuals (read 2026-10-30); the exact
directory mode and the memory-backed filesystem claim are from the manual text and **unverified** by a run on this
machine. The broker reads the file when it needs the key for a call, holds it in a mutable buffer, and overwrites the
buffer after the request. That is best effort in Python (copies can survive in the interpreter); the real protection is
the process boundary, `LimitCORE=0`, `PR_SET_DUMPABLE` off, and a different user id.

**At rest.** The encrypted credential file is `root:root`, mode 0600, in a `root:root` 0700 directory. Encryption is
`systemd-creds encrypt` with `--with-key=host` (a key kept under `/var/lib/systemd`, root only), or `host+tpm2` when the
machine has a TPM (the credential then also needs the TPM to decrypt). The encryption defends the file against a disk
image, a backup, or a stray `cat` by root. It is not the access control: the file's owner, mode and directory are.

**What the maintainer does once as root** (commands are inferred from the manuals and not yet run end to end; the
installer phase turns them into a script with checks):

1. **Create a new key for the broker; do not reuse the old one.** A key the maintainer's account has ever read is
   exposed to that account. In the vendor console, create a new API key in the paid project, restrict it to the
   Generative Language API, and keep the vendor-side monthly limit. Do this on a device that is not this laptop (a
   phone is fine), or at least not in a desktop session where an agent runs.
2. **Create the user, group and folders:**

   ```bash
   sudo groupadd --system safo-broker-clients
   sudo useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin safo-broker
   sudo usermod -aG safo-broker-clients MAINTAINER_LOGIN      # takes effect at the next login
   sudo install -d -m 0755 -o root -g root /etc/safo
   sudo install -d -m 0700 -o root -g root /etc/safo/broker
   ```

3. **Put the key in, from a virtual console or a shell on another machine, not a desktop terminal.** The key is typed
   into a root shell's `read` (never on a command line, so never in `ps` or in history), and goes straight into the
   encrypter:

   ```bash
   sudo -i
   read -rs -p 'paid key: ' K; echo
   printf %s "$K" | systemd-creds encrypt --name=paid-key --with-key=host - /etc/safo/broker/paid-key
   unset K; chmod 0600 /etc/safo/broker/paid-key; exit
   ```

   (`--name=paid-key` is needed because the file name is otherwise embedded as the credential name; the manual says so.
   Use `--with-key=host+tpm2` on a machine with a TPM.)
4. **Delete the old key.** Revoke the old paid key at the vendor and delete the `prd_paid` config from the secret
   store. Until that is done, "the account cannot call the vendor directly" is false.
5. **Install the broker code, config and units** with `safo-broker-install` (see "Install and update chain"), then
   `systemctl enable --now safo-broker.socket`.
6. **Enroll the signing keys and create the switch** as in [Gemini keys](gemini-keys.md). The switch is the last step.

**A precondition the design cannot prove.** The maintainer's account must not have root through another door. The
installer checks for many such doors and cannot prove there are none; see "The root-door precondition" below for the
list of checks, what they cannot see, and what it means for the guarantees if a door exists.

## What lives where

```text
/etc/safo/                         root:root 0755
  broker-release-signers           root:root 0644   keys that may sign a broker release tag (not the approval keys)
  broker-min-version               root:root 0644   the lowest broker version that may run
  gemini-allowed-signers           root:root 0644   public keys that may approve (existing file)
  gemini-revoked-signers           root:root 0644   revoked keys (existing; may be empty; missing refuses all)
  gemini-paid-enabled              root:root 0644   the enable switch (existing; says "enabled")
  broker.yaml                      root:root 0644   caps, model allowlist, prices, allowed uids, limits, timeouts
  broker/                          root:root 0700
    paid-key                       root:root 0600   the encrypted credential
/opt/safo-broker/                  root:root 0755   releases/VERSION (a venv of locked wheels plus the broker source, read-only) and the symlink current
/var/lib/safo-broker-install/version  root:root 0644   the highest broker version ever installed (monotonic)
/etc/systemd/system/
  safo-broker.socket               root:root 0644
  safo-broker.service              root:root 0644
/var/lib/safo-broker/              safo-broker:safo-broker 0700   (StateDirectory=)
  epoch                            0600   a random id made once, in every receipt
  ledger.jsonl and its head file   0600   the hash-chained ledger (today's row format, plus the new rows below)
  height                           0600   the highest chain height seen
  issued/NONCE                     0600   a nonce the broker handed out and has not seen spent
  used/NONCE                       0600   created with O_EXCL when a nonce is spent
  approvals/NONCE.json             0600   the signed text and signature as presented, for audit
/run/safo-broker.sock              root:safo-broker-clients 0660   made by the socket unit; /run is root 0755, so no parent can block it
/run/credentials/safo-broker.service/paid-key   readable by safo-broker only; made by systemd at start
```

- `broker.yaml` is root-owned because **prices and caps decide how much a call may cost**. If the maintainer's
  account could edit the price table, a price of zero would make every reservation zero. The per-job cap (2 USD) and the
  monthly ceiling (10 USD) stay constants in the code that a config may lower and never raise, as today. The broker
  loads `broker.yaml` through the same ownership walk as the trust files, on every request.
- The broker runs code from `/opt/safo-broker`, not from the maintainer's checkout or virtualenv, because code the
  maintainer's account can write is code an agent can change. Updating it is a root-run install from a hardware-key
  signed tag, never from a folder the account can write (see "Install and update chain").
- The ledger keeps today's hash-chained row format so the existing reader code is shared, not copied. It adds row
  types for the broker (`nonce_issued`, `ambiguous_call`, `ambiguous_resolved`) and fields for images and reservations (below). A model
  suspension (see "Cost") is a file in the state directory that a restart does not remove.
- The maintainer reads spend through the socket (`status`), not by reading the directory.

## Install and update chain

The broker holds the key, so the code that runs as `safo-broker` is the most valuable thing to protect. A tag name, or a
digest compared against a file in a folder the maintainer's account can write, proves nothing: the same account that
could swap the artifact could swap the digest. The chain below uses only things that account cannot forge, and says what
it still leaves to a human.

**What root trusts, installed once by root and never writable by the maintainer's account:**

- `/etc/safo/broker-release-signers` (root:root 0644): the public keys, in the allowed-signers format, that may sign a
  release tag. These are hardware security keys with a touch, kept **separate from the approval keys** in
  `gemini-allowed-signers` (a key that approves spend and a key that releases code are different powers). Enrolled by
  root the same way as the approval keys ([Gemini keys](gemini-keys.md)).
- `/usr/local/sbin/safo-broker-install` (root:root 0755): the installer. The first copy is reviewed by the maintainer and
  copied by root; later versions of it arrive inside the signed releases and are covered by the review below.
- `git` and `ssh-keygen` from the operating system, which the installer uses to verify signatures.

**What `safo-broker-install VERSION` does, as root, and refuses to skip:**

1. **Fetches the source itself**, as root, into a root-owned temporary directory (a shallow clone of the repository at the
   tag). It never reads a maintainer-writable staging folder, a download folder or a copy handed to it.
2. **Verifies the signed annotated tag object, not just a commit.** The tag must be an annotated tag (`git cat-file -t`
   says `tag`; a lightweight tag is refused) and its own signature must verify against
   `/etc/safo/broker-release-signers` (git's SSH signature verification with that file as the allowed signers; exact flags
   are **inferred** from the git and `ssh-keygen` manuals and re-checked when the installer is built). The commit that
   tag points to is the only tree used afterward. A compromised maintainer account cannot sign without the touch.
3. **Takes the version from the signed tag and nowhere else.** The version is parsed with a strict pattern from the
   signed tag's name (a leading `v` and three dotted numbers) and cross-checked against the package's own `__version__`, read from the source
   without importing it. A mismatch is refused. The `VERSION` argument on the command line is only an expected value that
   must equal the tag's; there is no separately supplied VERSION file.
4. **Refuses a rollback.** `/var/lib/safo-broker-install/version` (root:root 0644) holds the highest version ever
   installed. A version below it is refused, and the same version is refused unless root passes `--reinstall`. Going
   down needs root to pass `--allow-downgrade VERSION` explicitly; the installer logs it to the journal and to a
   root-owned log. A second root-owned file, `/etc/safo/broker-min-version`, is a floor: after a fix for a flaw, root
   raises it, and **the broker itself refuses to start below it**.
5. **Shows the review and waits.** It prints the old and new versions, the tag's signer label and fingerprint, the commit
   hash, and: the diff of **every packaging and build-control file** changed since the installed release (`pyproject.toml`,
   any setup script or setup configuration, the packaging manifest, the requirements inputs and the lock, the installer, the units and
   any build or release script), the diff of the broker source, and **every dependency that is added, removed or changed,
   with its exact wheel filename, its hash and the index it comes from** (the lock records the index). Root types the new
   version to continue. That is the **review gate before every install**. The release notes state whether the cyber-tier
   review covers the diff.
6. **Installs from wheels only, so no build code runs as root.** The environment is made with `pip install
   --only-binary=:all: --require-hashes --no-deps --isolated`, from a clean environment, against the index named in the
   signed lock. `--only-binary=:all:` makes pip refuse any source distribution, so **no build backend ever runs as root**;
   `--require-hashes` and `--no-deps` mean exactly the wheel files in the lock are installed and nothing is resolved at
   install time. The lock lists exact wheel files and their hashes; **a dependency that has no wheel is a release
   blocker**. The broker's own package is a plain copy of its source directory from the verified tree (a pure-Python
   package, no build step), and the copied file list is checked against the tree. Installing a wheel runs no project code as
   root; code inside a wheel runs only as `safo-broker`, which is why step 5 shows every dependency change.
7. **Stages, verifies, then activates atomically.** The release is built in a new, root-owned directory
   `/opt/safo-broker/releases/VERSION` (made read-only when built); the live path is the symlink
   `/opt/safo-broker/current`, and the unit's `ExecStart` runs through it. Before activation the installer, offline:
   checks the ownership walk of the whole staged tree; re-hashes every installed file against a manifest generated from
   the verified commit; runs `systemd-analyze verify` on the staged units; and runs a self-test of the staged tree as the
   `safo-broker` user with a fake key, a fake vendor and no network. Only then does it swap the symlink with an atomic
   rename, install the units (written under a temporary name and renamed), reload systemd and restart the service, and
   check that `status` answers.
8. **Rolls back automatically.** A failure in the build, the verification, the unit install, the restart or the
   post-start `status` check swaps the symlink back to the previous release, restores the previous release's units,
   restarts, and reports what failed. The previous two releases are kept. The monotonic version file is written only
   after the new release has started and answered, so a failed install does not raise the floor.

**A second layer, for any prebuilt artifact.** If a release ever ships a prebuilt wheel or archive, root verifies a
build attestation (a sigstore attestation made by the release workflow) against the pinned identity of that workflow
(repository, workflow file and tag pattern in `/etc/safo/broker-release-policy.yaml`, root-owned), using a verifier and
trust root installed by root once from the operating system or from a source root verified out of band. The release
workflow is a caller of the shared release workflow in git-your-ship-together; if that workflow does not yet make
attestations, it gains them there first. The signed tag stays the primary control: an attestation says the workflow built
this artifact from that tag, not that anyone reviewed the tag, and a compromised maintainer account can push a tag and
run the workflow.

**What the chain does not do.** It does not tell root that the signed code is good: the maintainer's reading of the diff
and the cyber-tier review are the controls for that. It does not protect against root, against a stolen release-signing
key whose PIN is known, or against a maintainer who types the version without reading the diff. The first install is
trust on first use of a tag the maintainer has reviewed.

**Verification (planned, phase 5).** Installer tests against a temporary tree and a throwaway git repository with test
keys: an unsigned tag, a tag signed by a key not in the signers file, a tag signed by an approval key (wrong file), a
lower version, an equal version, a downgrade with and without the flag, a tampered requirements hash, a lightweight tag, a
tag whose name disagrees with the code's version, a dependency with only a source distribution (pip must refuse it and no
build backend may run), a source path supplied by the caller (ignored), and a broker started below the floor each refuse;
a correct signed tag installs. Failure injection at each of build, verification, unit install, restart and the post-start
check must leave the previous release active and the version file unchanged.

## The root-door precondition (a documented residual risk)

The whole design assumes the maintainer's account, and every agent running as it, has **no way to become root**. The
installer's checks reduce the chance that this is false; they cannot prove it, and this page does not claim they do.

**What `safo-broker-admin check-install` checks (phase 5), reporting each hit for the maintainer to fix or explain in
writing, and failing while any hit is unexplained:**

- `sudo -l -U LOGIN`: any rule at all for the account, `NOPASSWD` or not, including command-specific rules (a rule for
  one command can be an editor, a service manager or an installer with a shell escape); and `sudo -n true`.
- Group membership: `root`, `sudo`, `wheel`, `admin`, `docker`, `lxd`, `lxc`, `libvirt`, `disk`, `shadow`, and any group
  that owns a root-run socket or device.
- polkit: rule files that grant the account or one of its groups an action without authentication.
- Root-owned files and directories the account can write, under `/etc`, `/usr/local`, `/opt`, the systemd unit and
  drop-in directories, cron and `at` spools, `/etc/sudoers.d` and `/etc/polkit-1`.
- Units, timers, cron jobs and `at` jobs that run as root and execute a file (or load one from a directory) that the
  account can write, and root-run jobs that read files under the account's home.
- Setuid and setgid binaries not owned by an installed package, and files with capabilities that the account can write.
- Anything the account can write in the dynamic linker's preload file and configuration directory, and in the broker's own
  paths.

**What it cannot see.** A kernel or privileged-service vulnerability (including a package-owned setuid program or a
system service with a local flaw); a privileged D-Bus or container socket the account can reach through a path the
checks do not list; access control lists and attributes it does not read; a root process started later; physical
access; and any change after the check runs, since the check is a snapshot. A clean report is "no door found by
these checks", never "no door".

**The stated consequence.** If any root-equivalent door exists, the broker raises the bar only for accidents and for
prompt-injected agents that do not look for one. Against a deliberate local attacker running as the maintainer, the
spend caps, the single-use rule and the key's confinement are **advisory**: that attacker can become root and read the
key, rewind the state, or replace the broker. The vendor-side monthly limit is then the only hard backstop. The
maintainer accepts this residual risk by enabling paid use, and the installer prints it when it passes.

## The socket protocol

One request, one reply, then the broker closes the connection. Version 1.

**Framing.** A frame is a 4-byte unsigned big-endian length `N` followed by `N` bytes.

- A **request** is exactly one frame holding a UTF-8 JSON object, `1 <= N <= 1,048,576` (1 MiB). A longer declared
  length is refused without reading the body.
- A **reply** is one JSON frame, `N <= 262,144` (256 KiB), optionally followed by binary **attachment frames**, one
  per image, announced in the JSON (`attachments`). An attachment frame is the same 4-byte length plus the raw bytes,
  `N <= 25,165,824` (24 MiB). Images travel as raw bytes, not base64, so the 4/3 inflation stays off the socket.
- **Deadlines on every frame, both directions.** The broker reads the request frame under a **5 second** deadline for the
  whole frame, and drops a connection that sends nothing. It writes the reply under a **write deadline**: the JSON frame
  within 5 seconds, and each attachment frame as a series of writes where each write must make progress within 10
  seconds and the whole frame must finish within 60 seconds (a 24 MiB frame needs about 0.4 MiB a second). Any missed
  deadline closes the connection and drops the rest of the reply. The client waits up to the broker's call deadline for
  the reply (see "A call, step by step"). Sockets are non-blocking in the broker, so one stalled peer holds no thread
  and no lock.
- **The paid-call slot is not held while writing.** The slot covers steps 4 to 6 of a call, through the ledger's
  `call_end`; it is released **before** the reply is written. A client that stops reading therefore cannot hold the slot,
  only its own connection until the write deadline.
- **The real connection bound is in the broker.** `MaxConnections=` has no effect on a socket with `Accept=no` (the
  systemd manual says so), so it is not used. The broker caps itself: at most 8 open connections (a ninth is closed at
  once, unread), at most 2 open per peer uid, and the listen queue is bounded in the socket unit (`Backlog=`). The
  numbers are in `broker.yaml`.

**JSON rules.** The request is parsed with the repository's bounded loader (a size limit and a depth limit), plus a
duplicate-key check, no `NaN` or `Infinity`, and no key outside the table for its operation. An unknown key is
`bad_request`, not ignored. Strings that name things (model, job, ids) are checked against the same patterns the
signed approval uses (`[a-z0-9._-]` names, at most 64 characters). The prompt is a string of at most 200,000 bytes
UTF-8 after decoding (the limit the wrapper has today).

**Versioning.** Every request carries `"v": 1`. A broker that does not speak the version replies
`{"v": 1, "ok": false, "code": "unsupported_version", "supported": [1]}`. Within a version, fields are never added
silently: a new field is a new version, and the broker may serve two versions during an upgrade. Because unknown keys
are refused, a newer client cannot be quietly misunderstood by an older broker.

**Peer credentials.** After `accept` the broker reads `SO_PEERCRED` (the kernel's record of the peer's pid, uid and
gid). The uid must be in `allowed_uids` in `broker.yaml`; otherwise the connection is closed with `unauthorized_peer`
and nothing is read. The socket's file mode and group (`safo-broker-clients`, 0660) are a first filter and the uid
check is a second. **A peer check cannot tell an agent from the maintainer's own wrapper, because both run as the same
uid.** The broker therefore does not authorize by who is calling. Authorization is the hardware-key signature over the
exact request. The pid is logged as a number and never trusted.

**Operations.**

| `op` | Request fields | Reply fields (when `ok` is true) | What it does |
|---|---|---|---|
| `status` | none | `enabled`, `key_loaded`, `epoch`, `ledger_head`, `month_spent`, `month_cap`, `block`, `prices_valid_through`, `suspended` (the models stopped by a breach or an ambiguous call), `line` | Reads state; spends nothing. Works when disabled, and says so. |
| `begin` | `model`, `job`, `kind`, `count`, `image_size`, `aspect_ratio`, `prompt_bytes`, `max_output_tokens`, `max_usd` (not less than the reservation) | `nonce`, `epoch`, `expires_at`, `ledger_head`, `estimate_usd`, `reserve_usd`, `thinking_level`, `beyond_ceiling`, `line` | Hands out a broker-chosen nonce and the numbers the approval must carry, after checking the request against the caps. Writes `issued/NONCE`. |
| `call` | the same fields, plus `prompt`, `approval` (`payload`, `signature`) | `receipt`, `text`, `attachments` | Verifies, spends, calls the vendor, records, returns. |
| `check` | `nonce` | `state` (`live`, `used`, `expired`, `unknown`) | For the dispatch guard: is this approval still live? Spends nothing. |
| `dryrun` | `approval` signed in the dry-run namespace | `principal`, `fingerprint`, `hardware`, `touch`, `pin`, `enabled` | Verifies a throw-away signature; no state, no vendor call. |

`kind` is `text` or `image`. For `text`, `count`, `image_size` and `aspect_ratio` are absent.

**A reply** is `{"v": 1, "ok": true, ...}` or `{"v": 1, "ok": false, "code": CODE, "message": TEXT, "exit": N}`.
`message` is one of a fixed set of sentences; it never echoes client strings, the prompt, the vendor's error body or
the key. `code` and `exit`:

| `code` | `exit` | Meaning |
|---|---|---|
| `bad_request`, `too_large`, `unsupported_version`, `unauthorized_peer` | 2 | The request was refused before any state changed |
| `disabled` | 2 | The root-owned switch is not `enabled` |
| `bad_approval`, `revoked`, `expired`, `used`, `digest_mismatch`, `model_mismatch`, `job_mismatch` | 2 | The approval does not cover this request |
| `over_job_cap`, `over_approved`, `needs_block_approval`, `month_cap`, `model_suspended` | 2 | A cap, or a suspension after a breach, stops it |
| `busy` | 2 | A paid call is already in flight, or a rate limit applies |
| `rate_limited` | 3 | The vendor answered 429; **final**, never retried, never falls through to another tier |
| `vendor_refused` | 2 | A definite vendor 4xx other than 429; not repeated |
| `outcome_unknown` | 4 | The request left and its result cannot be told; recorded as spent at the reservation, the model suspended until root clears it; not repeated |
| `internal` | 4 | The broker failed; state is described in "Crash and power loss" |

**Receipt** (in the `call` reply, and written by the client beside each image): `call_id`, `nonce`, `epoch`, `model`,
`kind`, `count`, `image_size`, `prompt_sha256`, `tokens_in`, `tokens_out`, `reserved_usd`, `actual_usd`, `released_usd`,
`breach` (true when the actual passed the reservation), `estimated` (true when the reservation stood in for a missing or
implausible usage figure), `month_spent_after`, `ledger_head_after`,
`images` (for each: `index`, `mime`, `bytes`, `sha256`), `broker_version`, `ts`. It holds no prompt text, no quote and
no key.

## What a signed approval binds

The approval keeps the shape `safo gemini approve` makes today (canonical JSON, signed with `ssh-keygen -Y sign` in the `safo-gemini-approval`
namespace) and the broker verifies the same properties. #217 has shipped the prompt binding: payload `version: 2` carries
`prompt_sha256` (lowercase hex SHA-256 of the exact UTF-8 prompt bytes) and `prompt_bytes` (their count) on both tiers,
and the client refuses to approve a prompt of more than 4000 characters (the signer reads the whole prompt). The broker
adds a schema `version: 3` with the fields a priced image call needs, so that nothing which changes the cost is
outside the signature:

`version`, `nonce`, `epoch`, `model`, `kind`, `count`, `image_size`, `aspect_ratio`, `max_output_tokens`,
`thinking_level`, `max_usd`, `job`, `prompt_sha256`, `prompt_bytes`, `quote`, `quoted_at`, `created`, `expires_at`,
`beyond_ceiling`, `ledger_head`, `issue`, `principal`.

`prompt_sha256` and `prompt_bytes` keep the names and meaning #217 shipped. Version 2 records (text only, from today's
code) are refused by a broker that speaks version 3, with a message to ask for a fresh approval.

The broker checks, in this order, and stops at the first failure (each refusal before the key is read):

1. The switch file passes the root-owned walk and says `enabled`; `broker.yaml` loads; prices are not past their
   `valid_through`.
2. The peer uid is allowed; the frame and fields are well formed.
3. The signature verifies against the allowed signers (key by key, window, namespace, hardware flags, `require-pin`)
   and the key is not in the revocation list. Both files are re-read on every request.
4. The signed text is canonical, `version` is 3, `epoch` equals the broker's, and the `nonce` is in `issued/`,
   unexpired, not in `used/` and not in the ledger as used.
5. `model`, `job`, `kind`, `count`, `image_size`, `aspect_ratio`, `max_output_tokens` and `thinking_level` of the
   request equal the signed ones; the broker's own SHA-256 of the received prompt equals `prompt_sha256`.
6. The broker **computes the reservation itself** (worst-case cost, see "Cost") from its own price table and the
   request, never from a number the client sent. The reservation must be at most the signed `max_usd` and at most the
   job cap; the month total plus the reservation must fit the ceiling, or `beyond_ceiling` must be true in the signed text (the extra-block rule: past 10 USD
   a month, each further 2 USD block needs its own approval that says so).
7. The prompt passes the shape check for secrets (the same patterns as today, run by the broker on the received
   text), as defense in depth. The maintainer's private-terms check runs in the client, before `approve` and before
   the send (see "Images").

## A call, step by step

1. Client: `begin` (the broker answers with a nonce, its ledger head, the typical estimate, the reservation and the quota
   line).
2. Client: `approve` shows the quota line, the quote, the digest, the size, the whole prompt (at most 4000 characters, escaped) and (for images) the model, size and count; the maintainer types `approve JOB` and
   touches the key; the client keeps the signed approval in the existing approvals folder as a convenience (it is a
   transport copy and carries no authority).
3. Client: `call` with the prompt and the approval.
4. Broker, under the state lock: verify (above); **write the spend first**: append `approval_used` and `call_start`
   (with the reservation) to the ledger, create `used/NONCE` with `O_EXCL`, `fsync` the files and the directory.
5. Broker, outside the state lock but inside the one-call slot: read the key, send **one** request, with the deadline
   from `broker.yaml` (images are slow; the default is 180 seconds), no retry.
6. Broker: classify the answer, append `call_end` with the actual cost and the amount released from the reservation
   (see "Cost"; a breach or an ambiguous outcome also suspends the model), `fsync`, **release the call slot**, then write the reply under the
   write deadline.

**Crash and power loss, the stated choice: spend is recorded BEFORE the vendor call.** The cost is that a crash between
step 4 and the vendor request charges the month for a call that may never have left: at most one reservation (2 USD at
most) is counted that was not spent. The benefit is that no crash can allow a replay or an undercount. The rules:

- A crash before step 4 completes: nothing was recorded and nothing left, so the approval is still usable.
- A crash after step 4: the nonce is spent, and because nothing can say whether the request left or what it was billed,
  the call is **ambiguous** (see "Cost", rule 7). On the next start, before the socket serves anything, recovery finds
  every `call_start` with no `call_end`, appends `ambiguous_call`, keeps the **full reservation counted as spent**, and
  **suspends that model**. A restart never clears the suspension; only root does. A `used/` marker with no ledger row (or
  the reverse) is made to agree the same way. **Either record alone marks the nonce spent.**
- The reply is lost with the connection. The broker keeps no copy of text or images, so the maintainer asks again with
  a new approval, after root has cleared the suspension if the call was ambiguous. The amount counted is the
  reservation; what the vendor actually billed is learned from its billing page.
- The maintainer reads the vendor billing page and root enters the real amount with the root-only `usage` command, which
  resolves the ambiguous call; the client has no way to write a `usage` row.
- Power loss is the same case, so the `fsync` of the file and its directory completes before the connection to the
  vendor is opened.

## The client

`src/safo/broker/client.py` is the only code on the maintainer's side that talks to the broker. It holds no paid key
(it never reads one), no ledger and no state. It imports the wire format, `protocol.py`, unchanged, and uses nothing from
the free path: no secret-store reader, no vendor call, no HTTP client, no logging, no direct printing (a test fails on any
of them).

**Where it finds the socket and the key.** In this order: a root-owned `/etc/safo/broker-client.yaml` (read through the
same ownership walk as the trust files; it may set `socket` and nothing else), then the maintainer's own
`~/.config/safo/broker-client.yaml` (private to the account), then the constant `/run/safo-broker.sock`. No environment
variable names the socket, because the wrapper strips the environment and a variable is the caller's to set. The user
file holds `version: 1`, `socket`, `signing.key` and `signing.principal` (the same two settings as `gemini.yaml`),
`image_output_dir` (an absolute path to a mode 0700 folder), `private_terms` and `reply_seconds` (10 to 900, default 240).
The client opens the socket path without following a link, checks on the descriptor that it is a socket owned by root and
not writable by everyone, and connects through `/proc/self/fd`, so the object it checked is the object it connected to;
an account that is not root cannot put a socket there for the client to talk to.

**A paid call, in order.**

1. Everything that can be checked alone, before a socket is opened: names, the amounts, the quote and its time, the image
   fields, that the prompt is plain text of at most 4000 characters (more is refused, as the design says, because the
   person signing must be able to read all of it), has no secret shape and no private term, and, for an image, that the
   output folder is usable (so a full disk cannot discard an image that was paid for). The private-terms check runs
   again on the same bytes just before the send.
2. `begin` on its own connection. The offer (nonce, epoch, ledger head, estimate, reservation, thinking level, whether it
   passes the monthly ceiling, expiry) is checked field by field; an offer whose worst case is over the amount named, or
   that is already expired, is not signed.
3. The signed text is built from the offer and the parameters and checked by the broker's own approval parser. The
   screen is then rendered **from that text**: every signed field as `name: value`, the cost line (typical estimate, worst
   case, the amount approved), the quote, the digest and size, the **whole** prompt line by line with non-ASCII and control
   characters escaped, and a warning when the call passes the monthly ceiling. A field cannot be signed without being on
   the screen because the list is made from the signed text.
4. The person types `approve JOB`. A terminal is required (standard input and output).
5. `ssh-keygen -Y sign` through the existing signer: an absolute system binary, the argument vector `-Y sign -f KEY -n
   safo-gemini-approval`, no shell, the text on standard input, a small environment (`PATH`, `HOME`, and the signing
   variables), and standard error left on the terminal so the key's touch prompt is seen. A signer failure, a cancelled
   touch, or a signature in another namespace sends nothing.
6. `call` on a new connection, once. Exactly one reply is read: the JSON frame, then the one attachment frame it names.

**What a reply is believed for.** A success or a charge-related failure is used only if its receipt names this request:
the nonce, epoch, model, kind, count, size and the SHA-256 of the exact prompt bytes. Anything else is discarded and
reported as a possible charge with the nonce and digest to look up. Every receipt field is checked for shape and the
extra fields are dropped. An answer is printed through the repository's output module, which writes out every control and format
character, so a reply cannot move the cursor or rewrite the terminal.

**Never retried.** A timeout, a reset, a short, oversize or malformed reply, or an interrupt after the call request was
started is an unknown outcome: exit 4, "THE CALL MAY HAVE BEEN CHARGED", the nonce and digest, no retry, and no fallback
to the free tier (a paid 429 is final, as above). A failure to connect, before anything is sent, is exit 2 and leaves the
signed approval unused.

| Exit | Meaning |
|---|---|
| 0 | The call succeeded and the receipt matched |
| 2 | Refused before anything was spent or sent: a bad parameter, no terminal, a wrong confirmation, a failed signer, the broker's refusal codes (`disabled`, `bad_approval`, `expired`, `over_job_cap`, `needs_block_approval`, `busy`, and the rest of exit 2 in the table above), or `vendor_refused` |
| 3 | `rate_limited`: the vendor refused the call; the retry hint is shown, nothing was repeated |
| 4 | `outcome_unknown`, `internal`, or any reply the client could not use after the request was sent |

`rate_limited`, `vendor_refused`, `outcome_unknown` and `internal` print the sentence for the code, say the call may have
been charged and show the receipt (or say none arrived). The other codes are refused before any vendor call: they print
the sentence and say that no receipt was issued.

**Images.** The attachment is checked against its description (length and SHA-256) and against the receipt, its first
bytes must name the type the broker named, and it goes through the writer with the signature `(data, directory, stem,
max_bytes)`. The stem is built from the UTC time, the job, the first 8 characters of the nonce and the index; nothing in
a name comes from the reply. The client never opens, previews or parses the image: it prints the path, the byte count and
the type the first bytes name. A receipt file, `NAME.receipt.json`, is written beside the image (exclusive, mode 0600,
`reviewed: false`). If the image cannot be saved, the message says money was spent and gives the size and digest.

**Running it.** `python3 -I -m safo.broker.client --model M --job J --kind text|image --max-output-tokens N --max-usd X
--quote Q --quoted-at T --prompt-file F [--issue I] [--image-size S --aspect-ratio R --count N]`. The prompt comes from a
file, never from the command line.

**Where the client is not wired yet.** `safo gemini ask --paid` and `safo gemini approve` still use the in-process path,
which stays disabled by the switch. Wiring the client in needs the wrapper to hand `ask` the signing variables and a
standard input (today only `approve` gets them) and the dispatch guard to learn the new step, and both were being changed
by other work, so the client ships as a module with the entry above.

## Cost

The broker does not enforce a cost bound by estimating. It **reserves the worst case** the vendor is allowed to bill,
before the call, and reconciles afterwards. Two numbers are kept apart:

- the **typical estimate**, shown to the maintainer so he knows what a call normally costs;
- the **reservation**, the most the request as the broker will send it can bill. The signed `max_usd`, the job cap (2
  USD) and the monthly ceiling (10 USD, with the extra-block rule) are all checked against the **reservation**, never
  the estimate. A call whose reservation does not fit is refused before the key is read.

`reservation = A + B + C`

- **A, input:** `(prompt_bytes + 64) * input_per_mtok`. **One input token per byte of the UTF-8 prompt is a true upper
  bound**, because a token stands for at least one byte, so no tokenizer can produce more tokens than bytes; the fixed 64
  is a margin for tokens the vendor adds around a request (inferred, not shown by any page; the margin is small against
  any realistic price). The earlier "three bytes a token" rule is an estimate and is **not** used for the reservation
  (it stays in the typical estimate shown to the maintainer). The alternative, calling the vendor's token-counting
  endpoint first, was rejected: it is a second vendor call with its own failure and ambiguity cases, its answer can
  differ from the billed count, and the byte bound needs neither. The cost of the byte bound is a larger reservation for
  long prompts (at most 0.40 USD for a 200,000 byte prompt on the dearest input rate listed), which `approve` shows.
- **B, output:** `M * max(text_output_per_mtok, image_output_per_mtok)`, where `M` is the output-token limit the broker
  puts in the vendor request (below) or, for a model whose cap is not yet verified, the vendor's documented output limit
  for the model.
- **C, interim images:** for an image call, `2 * image_tokens[size] * image_output_per_mtok`, added **on top of B**
  unless the cap has been observed to cover them (below). The vendor's image guide says the model may generate up to two
  interim images before the final one (verified); whether they are billed as image output, and whether they count
  inside `M`, is inferred. Text calls have no C.

Every other billed category is excluded by construction, not estimated: the request carries no tools, no grounding or
search, no cached content and no input images, and asks for no thought summaries (`thinking_summaries: none`); the vendor's
pricing page says tool and grounding tokens are billed only when those features are used (verified, 2026-10-30).

### What the vendor lets a request cap (read 2026-10-30)

Verified on the vendor pages named, with the date each page shows:

- The Interactions API reference (`ai.google.dev/api/interactions`, "Last updated 2026-10-28 UTC") documents, in a
  request's generation configuration, an optional `max_output_tokens` ("the maximum number of tokens to include in the
  response") and an optional `thinking_level` (`minimal`, `low`, `medium`, `high`).
- The image-generation guide (`ai.google.dev/gemini-api/docs/image-generation`, "Last updated 2026-10-26 UTC") says the
  Gemini 3 image models think by default, that thinking **cannot be disabled** in the API, that thinking tokens are
  billed whether or not they are viewed, and that the model may generate up to two interim images. It lists the
  supported thinking levels: Nano Banana 2.1 `minimal`, `medium`, `high` (default `medium`); Nano Banana 2 and Nano
  Banana 2 Lite `minimal`, `high` (default `minimal`); no level control is listed for Nano Banana Pro.
- The model pages (`ai.google.dev/gemini-api/docs/models/MODEL`, "Last updated 2026-10-29 UTC") give output token
  limits: 32,768 for `gemini-nano-banana-2.1`, `gemini-3.1-flash-image` and `gemini-3-pro-image`; 4,096 for
  `gemini-3.1-flash-lite-image`.

**Inferred, not shown by any page read:** that `max_output_tokens` bounds thinking tokens and image tokens together on
the image models; what the vendor returns, and bills, when the cap is lower than the work needs; and whether the
interim images are billed as image output. The design therefore does not trust the cap until it has been observed.

### The rules

1. **The broker sends the caps itself.** The request builder for an image call always sends
   `max_output_tokens = M` and, for a model that lists levels, the lowest listed `thinking_level` (`minimal`). The client
   cannot change either. `M` and the level are in the signed text. For Nano Banana Pro no level can be sent, so only `M`
   limits it.
2. **`M` has a floor and a ceiling.** The floor is the image's token count for the signed size plus a minimum text
   allowance (default 512 tokens), so a cap that would truncate the image before it exists is refused rather than
   billed for nothing; the ceiling is the model's documented output limit.
3. **Reserve before the call.** The broker computes the reservation, refuses if it exceeds the signed `max_usd`, the job
   cap, or the month room (or the signed `beyond_ceiling` does not cover it), writes it into the ledger as the
   call's reserved amount with `call_start`, and only then sends.
4. **Until a cap is verified for a model, reserve the vendor's documented maximum.** Each model in `broker.yaml` has
   `cap_verified`, false by default, set by root only after phase 7 has observed real responses with the cap in force:
   total billed output tokens, **interim images included**, at or below `M` for the sizes and model. While it is false B
   uses the model's documented output limit instead of `M`, and C is added. The arithmetic for a 1K image, from the
   vendor's per-token prices of 2026-10-30 (input negligible): Nano Banana 2.1, B 0.983 plus C 0.067 is **1.05 USD**; Nano
   Banana 2 Lite, B 0.123 plus C 0.067 is **0.19 USD**; Nano Banana 2, B 1.966 plus C 0.134 is **2.10 USD, over the 2 USD
   job cap, so refused** until its cap is verified; Nano Banana Pro, B 3.93 alone is **over the cap, refused**. That is
   deliberate: the design does not admit a model whose worst case it cannot fit under the approval.
5. **Reconcile after.** From the usage the vendor returns (input, text and thinking, image output tokens) at the
   table's prices the broker computes the actual cost and records `reserved_usd`, `actual_usd` and
   `released_usd = reserved - actual`. The month then counts the actual, never less than a floor from the number of
   images returned times the smallest per-image figure for the model. A response whose usage is missing, malformed or
   implausible is not reconciled at all: it is an ambiguous call (rule 7).
6. **A breach stops the model.** If the actual cost is above the reservation, the actual is recorded and counted, the
   receipt says `breach: true`, and the broker **suspends that model**: further calls for it are refused, across restarts,
   until root clears the suspension (`safo-broker-admin clear-suspend MODEL`) after reading the vendor billing page.
7. **An ambiguous call is a loss of knowledge, so it also stops the model.** A call is ambiguous when the request left (or
   may have left) and the broker cannot establish what was billed: the broker crashes or loses power after the spend is
   written, the request times out, the connection drops, the answer is unreadable or oversized, a 5xx or 408 or redirect
   comes back, or the usage figures are missing, malformed or implausible. The broker then: keeps the **full reservation
   counted as spent**; appends an `ambiguous_call` row; and **suspends that model** with a state file written before
   anything else is allowed to proceed. After a crash the same happens at the next start: recovery finds every
   `call_start` with no `call_end`, appends `ambiguous_call`, and suspends the model before the socket serves anything.
   A restart never clears a suspension; only root does, with `clear-suspend`, after the maintainer has read the vendor
   billing page and entered the real amount (`safo-broker-admin usage`), which appends an `ambiguous_resolved` row that
   replaces the reservation with the real figure. Definite non-billing outcomes (a 429, a definite 4xx, a refusal before
   the request left) are not ambiguous and do not suspend. The price of this rule is availability: a vendor 5xx or a
   crash takes that model off until root acts.
8. **What this does and does not guarantee.** Guaranteed: no call is sent whose worst case, as the broker computes it,
   exceeds the signed maximum, the job cap or the month room; and after a breach or an ambiguous outcome no further call
   on that model runs without root. Not guaranteed: that the vendor honors the cap or bills only what it reports. If it
   does not, **one call per model** can bill more than reserved before the broker finds out (up to the documented limit
   at the image rate, plus whatever is billed after a lost connection), and a billing completed after the broker lost the
   response is not seen until the billing page is read. **The vendor-side monthly spend limit is the only hard
   backstop for that amount, and decision 14 keeps it set.**

Text calls follow the same rules: the generation request already carries `maxOutputTokens`, which the broker always
sends, the reservation is that limit times the output rate (thinking tokens are billed as output), and a text model
has `cap_verified` too.

### The price table

`broker.yaml` carries one entry per model, with the date the figures were read. The shape for an image model adds the
vendor-stated per-image figure by size, the token count for each size, the output limit and the cap flags:

```yaml
prices:
  price_checked: "2026-10-30"
  models:
    gemini-nano-banana-2.1:
      kind: image
      valid_through: "2026-12-31"
      input_per_mtok: "1.50"           # text and image input
      text_output_per_mtok: "7.50"     # text and thinking output
      image_output_per_mtok: "30.00"   # image output tokens
      image_usd: { "1K": "0.0336", "2K": "0.0504", "4K": "0.113" }   # as the vendor page states them
      image_tokens: { "1K": 1120, "2K": 1680, "4K": 3780 }           # as the vendor page states them
      output_token_limit: 32768        # the model page's documented limit
      thinking_levels: ["minimal", "medium", "high"]
      thinking_level_sent: "minimal"
      min_text_tokens: 512
      interim_images: 2                # the vendor guide's stated maximum before the final image (reserved in C)
      cap_verified: false              # root sets true after phase 7 observes total billed output within M
      max_images: 1
    gemini-3.1-flash-lite-image:
      kind: image
      valid_through: "2026-12-31"
      input_per_mtok: "0.25"
      text_output_per_mtok: "1.50"
      image_output_per_mtok: "30.00"
      image_usd: { "1K": "0.0336" }
      image_tokens: { "1K": 1120 }
      output_token_limit: 4096
      thinking_levels: ["minimal", "high"]
      thinking_level_sent: "minimal"
      min_text_tokens: 512
      interim_images: 2
      cap_verified: false
      max_images: 1
```

These numbers show the shape and what the pages said on 2026-10-30; the shipped example is filled in by re-reading them.
A size missing from `image_usd` and `image_tokens` for a model is refused. A model whose token count for a size the
page does not state (Nano Banana Pro states per-image prices, not token counts) cannot be listed until the count is
read from the vendor. Prices change; a table past its `valid_through` refuses every paid call.

The **typical estimate** shown at `approve` is `count * image_usd[size]`, plus the prompt at the input rate, plus
`min_text_tokens` at the text rate.

**The vendor ceilings are not prices.** The maintainer's own AI Studio screenshots of 2026-10-30 show per-minute and
per-day request ceilings for the paid project (for example Nano Banana Pro at 20 requests per minute and 250 per day,
Nano Banana 2 at 100 per minute and 1K per day). They are vendor limits far above the broker's money caps, and a request
count is not a money bound. The broker also keeps its own `max_calls_per_minute` and `max_calls_per_day` below them.

## Images

### The request

For an image model the broker sends the request shape on the vendor's image-generation page
(`ai.google.dev/gemini-api/docs/image-generation`, "Last updated 2026-10-26 UTC", read 2026-10-30): a POST to the
vendor's `/v1beta/interactions` endpoint with `model`, `input` (one text block) and `response_format`
(`type: image`, `aspect_ratio`, and `image_size` as `512px`, `1K`, `2K` or `4K` with an uppercase K; the page says
lowercase is rejected). This differs from the text path (`generateContent`), so the broker has one fixed request
builder per `kind`. **The request shape is verified against the page; the response shape is not.** The page shows
generated images as base64 data blocks, but the exact JSON field names for the REST response were not in the text read.
The parser is therefore written in phase 2 against the shape in the vendor's SDK examples and **rejects any shape it has
not been shown**; the real response is recorded in phase 7 by the first calls, which use Nano Banana 2 Lite (its
worst-case reservation is 0.12 USD), and turned into a fixture before any other model is used.

Phase 1 of the image path is **text-to-image only: no input images**. Editing and reference images (the page allows many)
are refused. That also keeps images the maintainer holds out of the prompt.

### The response is binary

- **Vendor answer cap for images:** 32 MiB for the whole HTTP body (the text cap of 1 MiB is far too small), read in a
  bounded loop; more is `outcome_unknown` as for text, because the request left.
- **Maximum images per call:** `max_images` in the price table, at most 4, and 1 in the first release. More images than
  the approved `count` in a reply is an error: the extra bytes are dropped and the receipt says so; the cost is counted
  from usage.
- **Format allowlist and magic bytes.** The vendor names a MIME type for each image. The broker accepts only
  `image/png`, `image/jpeg` and `image/webp`, and checks that the decoded bytes start with the matching signature
  (`89 50 4E 47 0D 0A 1A 0A` for PNG, `FF D8 FF` for JPEG, `RIFF` plus `WEBP` at offset 8 for WebP). A mismatch, another
  type, or an empty or oversized image (over 24 MiB decoded) is refused as `vendor_refused` with the cost counted
  from usage, and no bytes go to the client.
- **The broker never parses an image.** It does not decode pixels, read metadata, resize or re-encode. It base64-decodes,
  checks the first bytes and the size, hashes the bytes, and hands them on. Parsing is where image-library bugs live, and
  the broker holds the key. The client does not parse them either.
- **Receipt per image:** `index`, `mime` (the one the magic check confirmed), `bytes`, `sha256`.

### Safe writing by the client

The broker never sends a path or a file name. The client:

- writes only into **one output directory the maintainer sets** (`image_output_dir` in `gemini.yaml`: an absolute path,
  owned by the maintainer, mode 0700, not a symlink, checked when the config loads and again at write time);
- builds each file name itself from a fixed pattern: UTC time, the job name (already restricted to `[A-Za-z0-9._-]`), the
  first 8 characters of the nonce, the image index, and an extension chosen from the broker's confirmed MIME type through
  a fixed map (`png`, `jpg`, `webp`); nothing from the reply is used in a name;
- opens the directory once and creates the file relative to that descriptor with `O_CREAT|O_EXCL|O_NOFOLLOW|O_WRONLY`
  and mode 0600, so it **never overwrites** and never follows a link; an existing name is an error, not a retry with a
  new name that hides the clash;
- re-hashes the bytes it received and compares with the receipt's `sha256` before writing, and writes a sidecar
  `NAME.receipt.json` (mode 0600, same exclusive create) holding the receipt, the digest, the cost and `reviewed: false`;
- checks that the output directory is writable **before** it asks for the call, so a full disk does not discard an image
  that has already been paid for; if the write still fails, the message says money was spent and gives the digest.

### The safety side

- **Nothing private goes in the prompt.** The private-terms check and the secret-shape check run on the prompt in the
  client before `approve` and again before the send, exactly as for the free path, and the broker repeats the
  secret-shape check. The terms file is the maintainer's and cannot be trusted by the broker (it is in his home), so the
  terms check is a client-side step by design; because the approval binds the prompt digest, a prompt the maintainer
  signed is the prompt that was checked at `approve` time. The paid tier's terms differ from the free tier's (the vendor
  pricing page marks "Used to improve our products" as No for the paid tier); that is not a reason to relax the rule.
- **Generated images are untrusted output.** They are never executed, never auto-opened, previewed or parsed by safo,
  and **an agent must not open them**; the maintainer reviews each one himself before it goes anywhere. The files land in
  the output directory with mode 0600 for that reason. The dispatch guard cannot enforce "an agent does not open a file";
  this is a rule in the briefs ([Hooks](hooks.md)) and in the consuming projects.
- **Brand rule: the mascot without the Star of David.** Public brand art must use the mascot version without the star,
  checked **per file**. **The broker does not enforce this and cannot; the consuming project's own review does.** The
  receipt's `reviewed: false` sidecar is a reminder, not a check.
- Every generated image carries a vendor SynthID watermark (stated on the image-generation page). Whether and how to
  disclose AI-generated art is the consuming project's decision.

### Approvals and batches

An approval names the model, the kind, the count, the size and the maximum cost, and **covers exactly one call**.
Recommendation: **one image per call and one approval per call** in the first release (`count` fixed at 1), because it
makes the signed text a precise statement of what is bought. Several images are several approvals, which is several
touches. If touch fatigue becomes the real cost, the next step is an approval that names a count up to 4 and one call
that must return at most that many images, with `max_usd` covering `count` times the per-image figure; it is still one
call. Whether the vendor returns several images from one call is **unverified**, so that step waits for a recorded real
response. An approval that covers "up to N calls" is not offered: it is the shape that turns one touch into unbounded
spend.

## Revocation and key rotation

- **Revoke a signing key:** add its fingerprint to `/etc/safo/gemini-revoked-signers` as root (the procedure in
  [Gemini keys](gemini-keys.md)). The broker re-reads the file on every request, so it takes effect on the next request
  with no restart, including for approvals already signed but not spent. Revocation is checked again under the state
  lock, immediately before the nonce is spent, so a revocation during a call's verification is not missed.
- **Flush outstanding approvals:** `systemctl restart safo-broker.service` empties the `issued/` table (every nonce the
  broker has handed out must be asked for again). Spent nonces stay spent.
- **Rotate the paid key:** create a new key in the vendor console, replace `/etc/safo/broker/paid-key` (steps 3 above),
  `systemctl restart safo-broker.service`, check `status` shows `key_loaded`, then revoke the old key at the vendor.
  The socket unit stays up through the restart. Rotate on a schedule the maintainer picks and at once on any doubt;
  the vendor-side revocation is the step that ends exposure.
- **Emergency stop, two layers:** set the switch file to anything but `enabled` (the broker, the client and the guard all
  refuse, and the key is not read), and `systemctl disable --now safo-broker.socket safo-broker.service` (nothing
  listens). Neither needs the broker's cooperation.
- **Rotate the signing keys:** enroll the new key, test with a dry run, revoke the old one, as in [Gemini keys](gemini-keys.md).

## Backup key

- **Signing:** two or more hardware keys enrolled, one offline, as [Gemini keys](gemini-keys.md) already requires. The
  broker adds no new signing material.
- **The paid API key has no backup copy, on purpose.** The vendor console is the source of truth: if the encrypted file
  or the TPM is lost (for example a replaced board), create a new key and repeat step 3. A second stored copy of a key is
  a second thing to protect.
- **Root recovery** is the way back in if both hardware keys are lost: root can edit the root-owned trust files. Keep
  root's recovery separate from the hardware keys, or losing the keys also loses the recovery.
- **State backups:** `/var/lib/safo-broker` is not restored from backup into a running broker. A restore rewinds the
  consumption records and the month's spend; the longest a signed approval lives is 60 minutes, so after any restore the
  maintainer reconciles spend against the vendor billing page and enters the difference with `usage` before turning the
  switch back on. The root-only `safo-broker-admin` command (phase 5) documents it.

## The root-owned enable switch

`/etc/safo/gemini-paid-enabled` is read by the broker **on every request, never cached**, through the same ownership
walk as the trust files. Anything but the single line `enabled` (absent, wrong owner, writable, a link, other text) is
disabled: the broker answers `disabled` to every operation except `status` and `dryrun`, before it opens `broker.yaml`
beyond what it needs and **before it reads the key**. The client reads the same file for a friendlier message and the
dispatch guard keeps blocking paid steps, but neither is the control; the broker is. The broker does not create or
change the file, and no socket request, flag, environment variable or `gemini.yaml` setting can turn it on. Stopping the
units is the second, harder off switch (see "Revocation and key rotation").

## The unit files and their hardening

These are the files the build will ship, in full. The option names were checked against the systemd 257 manuals on this
machine on 2026-10-30; whether each one is accepted and has the intended effect is checked by `systemd-analyze` in CI
and by a run on a throwaway machine in phase 5 (below), and until then is **unverified**.

`/etc/systemd/system/safo-broker.socket`. The socket sits directly in `/run` (root, mode 0755), so there is no
parent directory that could be too closed for the group to reach it (an automatically created parent is owned by root
with its own mode, and `SocketGroup=` applies only to the socket file). `MaxConnections=` is left out because it has no
effect with `Accept=no`; the connection bound is in the broker (see "The socket protocol"):

```ini
[Unit]
Description=SAFO Gemini broker socket

[Socket]
ListenStream=/run/safo-broker.sock
SocketUser=root
SocketGroup=safo-broker-clients
SocketMode=0660
Accept=no
Backlog=16

[Install]
WantedBy=sockets.target
```

`/etc/systemd/system/safo-broker.service`:

```ini
[Unit]
Description=SAFO Gemini broker
Requires=safo-broker.socket
After=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=safo-broker
Group=safo-broker
ExecStart=/opt/safo-broker/current/venv/bin/python -I -m safo.broker
LoadCredentialEncrypted=paid-key:/etc/safo/broker/paid-key
StateDirectory=safo-broker
StateDirectoryMode=0700
UMask=0077
Environment=PYTHONDONTWRITEBYTECODE=1
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=yes
PrivateDevices=yes
PrivateMounts=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=/etc/safo /opt/safo-broker
ProtectProc=invisible
ProcSubset=pid
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM
DevicePolicy=closed
KeyringMode=private
RemoveIPC=yes
LimitCORE=0
LimitNOFILE=64
TasksMax=32
MemoryMax=512M
Restart=on-failure
RestartSec=2s
```

| Option | Why |
|---|---|
| `User=`, `Group=`, no `DynamicUser` | A fixed, unprivileged, non-root user owns the state directory across restarts; a dynamic user would lose the ownership the state relies on. |
| `LoadCredentialEncrypted=` | The only route for the key: PID 1 decrypts into a directory only the service user reads. The key is never in the environment (`/proc/PID/environ`) or in an argument. |
| `StateDirectory=`, `StateDirectoryMode=0700`, `UMask=0077` | The one writable place; nothing outside the broker user can read or write it. |
| `NoNewPrivileges`, empty `CapabilityBoundingSet`, empty `AmbientCapabilities` | The broker needs no capability; a bug cannot gain one through a setuid program. |
| `PrivateTmp`, `PrivateDevices`, `PrivateMounts`, `DevicePolicy=closed` | No shared `/tmp` with the maintainer's processes, no device nodes, a private mount namespace. |
| `ProtectSystem=strict`, `ProtectHome=yes`, `ReadOnlyPaths=` | The whole file system is read-only except the state directory; the maintainer's home is not visible, so the broker cannot be talked into reading or writing there. The code and the config are read-only to it. |
| `ProtectProc=invisible`, `ProcSubset=pid` | Other users' processes are hidden from the broker. |
| `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname` | None of these is needed; each closes a class of damage after a compromise. |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` | The socket and the outbound HTTPS only; no raw, packet or netlink sockets. |
| `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality` | Cuts off namespace, scheduling and setuid tricks. |
| `MemoryDenyWriteExecute=yes` | No writable-and-executable memory. It applies to child processes too, so `ssh-keygen` (run for verification) must work under it; this is checked in phase 5 and is the first thing to relax with a stated reason if `ssh-keygen` needs it, never silently. |
| `SystemCallArchitectures=native`, `SystemCallFilter=@system-service`, `~@privileged @resources`, `SystemCallErrorNumber=EPERM` | An allowlist of ordinary service calls with the privileged and resource-control groups removed; a denied call returns an error instead of killing the process. The sealed memory files used for `ssh-keygen` need `memfd_create`; whether `@system-service` includes it is **unverified** and checked in phase 5. |
| `RemoveIPC=yes`, `KeyringMode=private` | No leftover shared memory, a private kernel keyring. |
| `LimitCORE=0` | No core dump that could hold the key. |
| `LimitNOFILE=64`, `TasksMax=32`, `MemoryMax=512M` | Bounds on a runaway or a flood; 512 MiB covers a few 24 MiB images and one 32 MiB vendor body at a time. |
| `Restart=on-failure` with `StartLimitBurst=` and `StartLimitIntervalSec=` in `[Unit]` | A crash restarts at most five times a minute, then stays down and loud. |
| `Requires=safo-broker.socket` | The service is only ever started by the socket. |

A unit check does not prove the group can connect, so the first-run test is part of the runbook: after the next login,
`namei -l /run/safo-broker.sock` must show every parent traversable and the socket as `srw-rw---- root
safo-broker-clients`, and `safo gemini status` as the maintainer must print `key_loaded` and the switch state through
the socket (inferred commands; the installer in phase 5 runs the same connection as the account and the group).

`systemd-analyze verify` on these two files accepted every option (after `StartLimit*` was moved to `[Unit]`, where it
belongs) and `systemd-analyze security --offline=true` scored the service 1.2 ("OK") on this machine on 2026-10-30. The
checks it still marks are the ones the broker needs (local and Internet sockets, the host network, no `IPAddressDeny`, the host
root directory, other users visible). The score is a lint, not a proof.

Not used, with the reason: `IPAddressAllow` (the vendor's addresses are not fixed, so an allowlist would break calls or
be wrong); an optional host firewall rule that lets only the broker's uid reach port 443 is a good extra and is left to
the maintainer's network setup. `PrivateUsers` is not used because the unit starts as root-assigned `User=` and the
socket's `SocketGroup` check relies on the real group ids. `DynamicUser` is not used (above).

The service also drops `PR_SET_DUMPABLE` in code, runs with a scrubbed environment, never reads a proxy variable, and
runs `ssh-keygen` from a fixed absolute path with a minimal environment, as the verifier does today. The ptrace
protection of one user's process from another is the kernel's ordinary uid separation; the maintainer's account has no
privilege to attach to the broker, and root is outside this design.

## Logging

The broker logs to the journal (standard error). Every field is from an **allowlist of numbers and enumerated
values**: time, request id (the broker's own), operation, the `code` of the result, peer uid and pid (numbers), model
(only a value that passed the allowlist in `broker.yaml`), `kind`, `count`, reserved and actual cost, HTTP status of the
vendor, byte counts, latency, the first 8 characters of the nonce. **No client-supplied free text is ever logged:** not
the prompt, the response, the quote, the job name, the approval text, a vendor error body, or any exception message that
could quote one. Exceptions are logged by class and a fixed tag. The key is never formatted into any string. A test
greps the captured log of every failure-path test for sentinel strings in each of those fields. The ledger (which
only the broker can read) holds job names and the nonce, never the prompt or the quote.

## The transport to the vendor

Destination fixed in code: `https://generativelanguage.googleapis.com`, a constant, not a setting (a test builds the
broker with a loopback endpoint through its constructor, never through the config file). TLS verification stays on with
the system store; no proxy from the environment; the connection goes to a checked address (the existing `netguard`
pinned connection); a **redirect is refused** and never followed, so the key cannot be carried to another host; every
answer is size-capped; connect and read timeouts apply. The key goes in the `x-goog-api-key` header only.

## Rate limits and the vendor 429

- **One paid vendor call in flight.** A second `call` gets `busy` at once; it does not queue.
- Broker limits, in `broker.yaml` (defaults): `begin` 6 per minute, `call` attempts (including ones that fail
  verification, which each cost a process start) 10 per minute, at most 4 nonces outstanding, `max_calls_per_minute` and
  `max_calls_per_day` for vendor calls (default 5 and 20), 8 open connections and 2 per uid (enforced by the broker, see
  "The socket protocol"), 5 seconds to send a request, the write deadlines above.
- **Same-uid denial of service is accepted residual risk.** The one uid allowed to connect can fill the four outstanding
  nonces, spend the `begin` budget or keep connections open until their deadlines. It costs no money and cannot
  authorize a call; the per-minute limits and deadlines bound how long it lasts, and `systemctl restart
  safo-broker.service` clears it. The free path is unaffected.
- **A vendor 429 is final.** The ledger gets `call_end` with status `rate_limited` and zero cost, the nonce stays spent,
  the reply is `rate_limited` with exit 3 and the vendor's `Retry-After` when it is a finite number of seconds under a day.
  Nothing is retried. There is no other tier for the broker to fall through to, and the client never answers a paid 429
  by calling the free path or asking for a second approval. After the request leaves, a timeout, a 5xx, a 408, a redirect
  or an unreadable answer is `outcome_unknown`, counted at the reservation, the model suspended, not repeated.

## The free path stays independent

`safo gemini ask` without `--paid`, `quota` and `keys` never open the broker's socket, never import the client module,
and need neither the unit nor the switch. The free key is read from the secret store as today and the free ledger stays
in the maintainer's own folder. If the broker is stopped, absent or broken, free calls are unchanged. The free key must
belong to a project with **billing disabled**, so that it cannot spend money even if misused; the maintainer confirms this
once in the vendor console (**unverified** today). Tests: a free run with the socket path absent, and a free run against
a fake peer that fails the test if anything connects.

## The maintainer dry run, with a real key and no spend

The dry run tests the **hardware key** and the broker's verification, not the vendor:

1. The dry run of `safo gemini approve` (the global `--dry-run` flag) signs a throw-away text in the `safo-gemini-approval-dryrun` namespace (the
   key blinks; the maintainer touches it).
2. The client sends it in a `dryrun` request. The broker verifies it against the root-owned signers and revocations
   exactly as for a real approval and replies with the label, the fingerprint, whether the touch and PIN flags were
   present, and whether the switch is enabled.
3. The broker writes no ledger row, no `issued/` or `used/` file, makes no vendor call and does not read the key. A
   second operation, `status`, shows `key_loaded` (the credential file exists and has a plain printable shape), which tests
   the setup without sending the key anywhere.

A check that the paid key is accepted by the vendor without spending (a metadata request) is **not in the design**: whether
such a request is free is unverified, and the first real image call (the smallest size, with its own approval) is the
honest end-to-end test. Issue #205's "done" condition, "the maintainer has run the dry-run approval with a real key", is
the steps above.

## Test plan (hermetic)

No test uses the real key, the real vendor, the real `/etc/safo`, a real hardware key or the maintainer's state. Fakes:

- **A fake vendor server** on loopback, scripted per test: a good text answer, a good image answer (with a PNG, JPEG and
  WebP of a few bytes with correct signatures), a 429 with and without `Retry-After`, a 4xx, a 5xx, a 408, a redirect, a
  slow answer past the deadline, a connection closed mid-body, an oversized body, an image with a wrong signature, an
  unlisted MIME type, more images than approved, a malformed body, and a reply with the key echoed back (to prove the key
  never reaches a log).
- **Fake socket peers** over a temporary Unix socket (the broker takes the peer-credential reader as a parameter):
  a wrong uid, a length prefix of zero, one over the limit, a short body, a body that never arrives, duplicate keys, deep
  nesting, an unknown key, an unknown version, an unknown op, a flood of connections, a peer that connects and closes, a
  peer that stops reading the reply.
- **Root-owned file fakes:** the existing `fixed_locations` seam points the trust files and `broker.yaml` into a temporary
  tree with test ownership; software `ssh-keygen` keys stand in for a hardware key, as in the existing tests.
- **A fake key provider** and a fake clock.
- **Crash tests:** the ledger and marker writers take a fault-injection point; a test kills the in-process broker between
  each pair of steps in "A call, step by step" and restarts it, and asserts the nonce state, the month total and that no
  second call is possible.
- **Properties:** a replayed nonce, a rewound ledger copy placed in the state directory by a test (it must be refused by
  the height record and the chain), two simultaneous `call`s on one nonce (exactly one proceeds), a changed prompt byte,
  model, size or count against the signed text, a reservation above `max_usd`, the cost arithmetic per model and size (including the worst case with `cap_verified` false and the refusal of Nano Banana Pro), actual usage above the reservation (a breach: counted, model suspended, the next call refused until cleared), usage below it (released), no usage (reservation stands), the month ceiling and the extra block, a
  revoked key between `begin` and `call`, an expired approval, a missing switch, a switch that flips off mid-flight, and
  a price past `valid_through`.
- **The client:** writes with `O_EXCL`; refuses an existing file, a symlinked directory and a symlink at the target; never
  uses a name from the reply; mode 0600; the sidecar matches the digest; a tampered attachment is rejected by the digest.
- **The free path:** the independence tests above.
- **Socket abuse:** a ninth connection and a third from one uid are closed unread; a peer that stops reading a 24 MiB
  attachment is dropped at the write deadline and the paid-call slot is already free (a second call proceeds); a peer
  that reads one byte at a time is dropped by the whole-frame deadline.
- **The installer:** the cases listed in "Install and update chain".
- **A log test** for each failure path (sentinels for prompt, key, quote, job, vendor body).
- **systemd checks (phase 5):** `systemd-analyze verify` and `systemd-analyze security --offline` on the shipped units
  in CI, with the score recorded; and a run on a throwaway VM or container with a fake key and a fake vendor, which is
  the only place the unit's real effect (credential delivery, `MemoryDenyWriteExecute` with `ssh-keygen`, the system-call
  filter with `memfd_create`) is observed.

## Build plan: small pull requests, a review gate between each

Prerequisite: #217 (the prompt digest in the signed approval, payload version 2), merged with PR #226. The image vertical slice (phases 1 to 5)
comes first, because the blocked projects need generated images; the text path is added after. Each phase is its own
pull request with tests first, and **no phase starts until the previous one has passed review**; phases 1 to 3 add no
service and spend nothing.

| Phase | What lands | Gate before the next |
|---|---|---|
| 0 | This design and the threat model (documents only) | The maintainer answers the decisions below; a cyber-tier review of the design |
| 1 | The broker core as a library, no socket, no systemd: state directory checks, the ledger shared with today's code, issue and consume of nonces, recovery, spend-before-call, the signed approval schema version 3 (extending the version 2 of #217) and its verification, the reservation and typical-estimate arithmetic for `image` and `text`, with the hermetic fakes | Review of the state machine and the crash tests |
| 2 | The call pipeline against the fake vendor: request builders per kind, the image response handling (magic bytes, limits, receipts), 429 and ambiguous outcomes. Reservation, reconciliation, breach and suspension. The response parser targets the vendor's documented shape and refuses any shape it has not been shown | Review |
| 3 | The socket server: framing, protocol version 1 with attachments, peer credentials, limits, deadlines, idle exit, the operations, logging allowlist; fake socket peers and a fuzz test of the framing | Review of the parser and the limits |
| 4 | The thin client: `approve` and `ask --paid` go through the socket, safe image writing and sidecars, the guard's `check`, **removal of the in-process paid path**, the free-path independence tests, docs | Review; the old local paid code must be gone, not just unused |
| 5 | The units, `safo-broker-install` with its signed-tag, rollback and review-gate checks, `safo-broker-admin` (`check-install` with the root-door checks, `status`, `usage`, `reconcile`, `clear-suspend`), `systemd-analyze` in CI, the throwaway-VM run including the first-run connection test, and the setup runbook | Review of the units, the installer and the checks |
| 6 | **Cyber-tier security review** of the broker and the signed-approval verification (issue step 3) | Clean review |
| 7 | The maintainer does the root setup and the dry run, then creates the switch (issue step 5). The first calls use Nano Banana 2 Lite to record the real response shape and to observe the output cap; root then sets `cap_verified` for each model observed; a fixture PR follows | The maintainer's own run; the observation reviewed |
| 8 | Text paid calls through the same path, the `usage` workflow, then the optional count-per-approval and passkey wiring if the maintainer wants them | Review per item |

The smallest thing useful to the blocked projects is the result of phases 1 to 7: one text-to-image call per approval,
one image per call, written to a fixed folder with a receipt. Nothing in it needs the text path.

## Decisions for the maintainer

The maintainer approved decisions 1 to 11 as recommended on 2026-10-30 (decision 10 is restated below after the design
review). Decisions 12 to 14 came out of that review and are **open**.

| # | Decision | Recommendation |
|---|---|---|
| 1 | Accept the broker as the design (against a TPM counter or a vendor-side authorization, neither of which fits) | Yes |
| 2 | The broker runs as a dedicated unprivileged system user, started by a socket unit, not as root | Yes |
| 3 | The paid key is created fresh for the broker, held as a systemd encrypted credential (`host`, or `host+tpm2` where a TPM exists), and the old Doppler paid key and config are revoked and deleted | Yes; this step is the one only the maintainer can do, once, as root |
| 4 | Who may talk to the socket: the maintainer's uid, by a uid list in `broker.yaml` plus the socket group | Yes; accept that this cannot tell an agent from the wrapper, and rely on the signature |
| 5 | The broker hands out the nonce (`begin`), so an approval can only be made for a request the broker has seen | Yes |
| 6 | Crash rule: spend is recorded before the vendor call and an interrupted call counts at its reservation | Yes |
| 7 | Images first, text-to-image only, one image and one approval per call; a count per approval only later, and "up to N calls" never | Yes |
| 8 | Image output: a fixed folder of the maintainer's choosing, files 0600, never overwritten, a sidecar receipt, never auto-opened by an agent | Yes; name the folder when phase 4 is built |
| 9 | Broker v1 accepts hardware-key (Tier 1) approvals only; passkeys wait until their approval wiring exists | Yes |
| 10 | Broker code is installed by root from a hardware-key signed annotated tag verified against a root-owned signers file, from hash-locked wheels only (no build backend as root), staged and activated atomically with automatic rollback, never from a folder the maintainer's account can write; no rollback of version without an explicit root flag; the diff and every dependency change are read before every install ("Install and update chain") | Yes |
| 11 | Remote broker on the lab machine, as a later option | Not now |
| 12 | Whether to enroll a separate hardware key (or keys) for signing broker releases, kept apart from the approval keys | Yes: a release key and an approval key are different powers; a second touch per release is the price |
| 13 | Nano Banana Pro and Nano Banana 2 are refused until the output cap is shown to hold (their unverified worst cases are over the 2 USD job cap). Start with Nano Banana 2.1 and Lite and revisit the others with evidence | Yes; the others only if the quality of 2.1 is not enough |
| 14 | Accept the root-door precondition as a documented residual risk: with any root door open the caps are advisory against a deliberate local attacker, and the vendor-side monthly limit is the only hard backstop | Yes, and keep the vendor-side limit set |

## What this page does not claim

- That any of it is built or run. Everything in "Build plan" is future.
- That the root account, the kernel, systemd or `ssh-keygen` are trustworthy. The design needs them to be.
- That a human who touches the key for a prompt he did not read is protected. See the threat model's residual risk.
- The response shape of the vendor's image call, whether the vendor honors `max_output_tokens` on image models, the cost of a metadata request, whether `@system-service` allows
  `memfd_create`, whether `MemoryDenyWriteExecute` is compatible with `ssh-keygen` here, and whether the free key's
  project has billing disabled: **unverified**, each with the phase that checks it.
