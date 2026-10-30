# Gemini broker: design for the paid path

> **Status: design only.** No broker code exists. Paid use stays disabled by the root-owned switch
> (see [Gemini](gemini.md)) until the broker is built, reviewed and enabled by the maintainer. This page is the design
> for issue #205 (steps 1 and 2); the risks are in [the broker threat model](gemini-broker-threat-model.md). Nothing
> here is a promise about code that does not exist yet; the claims about what code does today are checked against the
> tree, and the claims about the vendor were read from the vendor pages on 2026-10-30 (marked **verified** with the
> page, or **unverified**).

The maintainer decided on 2026-10-30 that the paid path must be finished, because other projects are blocked on it.
The first thing those projects need is **quality image generation**, which is paid-only (the free tier gives none). So
this design treats an image call as the first-class case and text as the simpler case that rides the same path.

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
- **It enforces** the single-use nonce, the expiry, the model, job, count and cost bound, the prompt digest, the
  per-job and monthly caps and the extra-block rule.
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
5. **Install the broker code, config and units** (phase 5 below), then `systemctl enable --now safo-broker.socket`.
6. **Enroll the signing keys and create the switch** as in [Gemini keys](gemini-keys.md). The switch is the last step.

**Preconditions the design cannot check from inside.** The maintainer's account must not have root through another
door: no passwordless `sudo`, no `docker` group, no other root-equivalent group. The installer's check (phase 5) runs
`sudo -n true` and looks at group membership and fails if either is a door. A compromised root defeats every control
in this design; that is stated, not hidden.

## What lives where

```text
/etc/safo/                         root:root 0755
  gemini-allowed-signers           root:root 0644   public keys that may approve (existing file)
  gemini-revoked-signers           root:root 0644   revoked keys (existing; may be empty; missing refuses all)
  gemini-paid-enabled              root:root 0644   the enable switch (existing; says "enabled")
  broker.yaml                      root:root 0644   caps, model allowlist, prices, allowed uids, limits, timeouts
  broker/                          root:root 0700
    paid-key                  root:root 0600   the encrypted credential
/opt/safo-broker/                  root:root 0755   a venv built from the hash-locked requirements; the broker code
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
/run/safo-broker/broker.sock       root:safo-broker-clients 0660   made by the socket unit
/run/credentials/safo-broker.service/paid-key   readable by safo-broker only; made by systemd at start
```

- `broker.yaml` is root-owned because **prices and caps decide how much a call may cost**. If the maintainer's
  account could edit the price table, a price of zero would make every estimate zero. The per-job cap (2 USD) and the
  monthly ceiling (10 USD) stay constants in the code that a config may lower and never raise, as today. The broker
  loads `broker.yaml` through the same ownership walk as the trust files, on every request.
- The broker runs code from `/opt/safo-broker`, not from the maintainer's checkout or virtualenv, because code the
  maintainer's account can write is code an agent can change. Updating it is a root-run install from a tagged
  release, and the maintainer reads the diff.
- The ledger keeps today's hash-chained row format so the existing reader code is shared, not copied. It adds row
  types for the broker (`nonce_issued`, `call_recovered`) and fields for images (below).
- The maintainer reads spend through the socket (`status`), not by reading the directory.

## The socket protocol

One request, one reply, then the broker closes the connection. Version 1.

**Framing.** A frame is a 4-byte unsigned big-endian length `N` followed by `N` bytes.

- A **request** is exactly one frame holding a UTF-8 JSON object, `1 <= N <= 1,048,576` (1 MiB). A longer declared
  length is refused without reading the body.
- A **reply** is one JSON frame, `N <= 262,144` (256 KiB), optionally followed by binary **attachment frames**, one
  per image, announced in the JSON (`attachments`). An attachment frame is the same 4-byte length plus the raw bytes,
  `N <= 25,165,824` (24 MiB). Images travel as raw bytes, not base64, so the 4/3 inflation stays off the socket.
- The broker reads the request frame under a **5 second** deadline for the whole frame, and refuses a connection that
  sends nothing. The client waits up to the broker's call deadline for the reply (see "A call, step by step").

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
| `status` | none | `enabled`, `key_loaded`, `epoch`, `ledger_head`, `month_spent`, `month_cap`, `block`, `prices_valid_through`, `line` | Reads state; spends nothing. Works when disabled, and says so. |
| `begin` | `model`, `job`, `kind`, `count`, `image_size`, `aspect_ratio`, `prompt_bytes`, `max_output_tokens`, `max_usd` | `nonce`, `epoch`, `expires_at`, `ledger_head`, `estimate_usd`, `beyond_ceiling`, `line` | Hands out a broker-chosen nonce and the numbers the approval must carry, after checking the request against the caps. Writes `issued/NONCE`. |
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
| `over_job_cap`, `over_approved`, `needs_block_approval`, `month_cap` | 2 | A cap stops it |
| `busy` | 2 | A paid call is already in flight, or a rate limit applies |
| `rate_limited` | 3 | The vendor answered 429; **final**, never retried, never falls through to another tier |
| `vendor_refused` | 2 | A definite vendor 4xx other than 429; not repeated |
| `outcome_unknown` | 4 | The request left and its result cannot be told; recorded as spent at the estimate; not repeated |
| `internal` | 4 | The broker failed; state is described in "Crash and power loss" |

**Receipt** (in the `call` reply, and written by the client beside each image): `call_id`, `nonce`, `epoch`, `model`,
`kind`, `count`, `image_size`, `prompt_sha256`, `tokens_in`, `tokens_out`, `cost_usd`, `estimated` (true when the
estimate stood in for a missing or implausible usage figure), `month_spent_after`, `ledger_head_after`,
`images` (for each: `index`, `mime`, `bytes`, `sha256`), `broker_version`, `ts`. It holds no prompt text, no quote and
no key.

## What a signed approval binds

The approval keeps the shape `safo gemini approve` makes today (canonical JSON, signed with `ssh-keygen -Y sign` in the `safo-gemini-approval`
namespace) and the broker verifies the same properties. The design assumes #217 lands first and adds the prompt
digest (`prompt_sha256`, the SHA-256 of the exact prompt bytes, UTF-8) on both tiers. The broker adds a schema
`version: 2` with the fields a priced image call needs, so that nothing which changes the cost is outside the
signature:

`version`, `nonce`, `epoch`, `model`, `kind`, `count`, `image_size`, `aspect_ratio`, `max_output_tokens`,
`max_usd`, `job`, `prompt_sha256`, `quote`, `quoted_at`, `created`, `expires_at`, `beyond_ceiling`, `ledger_head`,
`issue`, `principal`.

If #217 names the digest field differently, this page follows #217; the broker build starts only after #217 merges.

The broker checks, in this order, and stops at the first failure (each refusal before the key is read):

1. The switch file passes the root-owned walk and says `enabled`; `broker.yaml` loads; prices are not past their
   `valid_through`.
2. The peer uid is allowed; the frame and fields are well formed.
3. The signature verifies against the allowed signers (key by key, window, namespace, hardware flags, `require-pin`)
   and the key is not in the revocation list. Both files are re-read on every request.
4. The signed text is canonical, `version` is 2, `epoch` equals the broker's, and the `nonce` is in `issued/`,
   unexpired, not in `used/` and not in the ledger as used.
5. `model`, `job`, `kind`, `count`, `image_size`, `aspect_ratio` and `max_output_tokens` of the request equal the
   signed ones; the broker's own SHA-256 of the received prompt equals `prompt_sha256`.
6. The broker **recomputes the estimate itself** from its own price table and the request, never from a number the
   client sent. The estimate must be at most the signed `max_usd` and at most the job cap; the month total plus the
   estimate must fit the ceiling, or `beyond_ceiling` must be true in the signed text (the extra-block rule: past 10 USD
   a month, each further 2 USD block needs its own approval that says so).
7. The prompt passes the shape check for secrets (the same patterns as today, run by the broker on the received
   text), as defense in depth. The maintainer's private-terms check runs in the client, before `approve` and before
   the send (see "Images").

## A call, step by step

1. Client: `begin` (the broker answers with a nonce, its ledger head, the estimate and the quota line).
2. Client: `approve` shows the quota line, the quote, the digest, the size, the beginning of the prompt and (for images) the model, size and count; the maintainer types `approve JOB` and
   touches the key; the client keeps the signed approval in the existing approvals folder as a convenience (it is a
   transport copy and carries no authority).
3. Client: `call` with the prompt and the approval.
4. Broker, under the state lock: verify (above); **write the spend first**: append `approval_used` and `call_start`
   (with the estimate) to the ledger, create `used/NONCE` with `O_EXCL`, `fsync` the files and the directory.
5. Broker, outside the state lock but inside the one-call slot: read the key, send **one** request, with the deadline
   from `broker.yaml` (images are slow; the default is 180 seconds), no retry.
6. Broker: classify the answer, append `call_end` with the actual cost (never below the floor from the sizes of what was
   sent and received; see "Cost"), `fsync`, and reply.

**Crash and power loss, the stated choice: spend is recorded BEFORE the vendor call.** The cost is that a crash between
step 4 and the vendor request charges the month for a call that may never have left: at most one estimate (2 USD at most)
is counted that was not spent. The benefit is that no crash can allow a replay or an undercount. The rules:

- A crash before step 4 completes: nothing was recorded and nothing left, so the approval is still usable.
- A crash after step 4: the nonce is spent. On the next start, recovery finds every `call_start` with no `call_end` and
  appends `call_end` with status `ambiguous` and `call_recovered`; the estimate stays counted. A `used/` marker with no
  ledger row (or the reverse) is made to agree the same way. **Either record alone marks the nonce spent.**
- The reply is lost with the connection. The broker keeps no copy of text or images, so the maintainer asks again with
  a new approval. The lost cost is bounded by the approved maximum.
- The maintainer can read the vendor billing page and add a correction with the root-only `usage` command; the client
  has no way to write a `usage` row.
- Power loss is the same case, so the `fsync` of the file and its directory completes before the connection to the
  vendor is opened.

## Cost

The estimate is an upper bound computed by the broker before the call, and the approval's `max_usd` must cover it.

**Text.** As today: the prompt counted at three bytes a token, plus every output token the request allows, at the table's
prices.

**Images.** Image models are billed per output token, with the vendor stating the per-image equivalent by size. The
vendor's pricing page (`ai.google.dev/gemini-api/docs/pricing`, the page says "Last updated 2026-10-28 UTC", read
2026-10-30) lists, for example: Nano Banana 2.1 (`gemini-nano-banana-2.1`) at 30 USD per million image output tokens, which it states as 0.0336 USD
for a 1K image, 0.0504 for 2K and 0.113 for 4K; Nano Banana 2 (`gemini-3.1-flash-image`) at 60 USD per million, stated as 0.045
(0.5K), 0.067 (1K), 0.101 (2K) and 0.151 (4K); Nano Banana 2 Lite (`gemini-3.1-flash-lite-image`) at 30 USD per
million, 0.0336 for 1K, 1K only; Nano Banana Pro (`gemini-3-pro-image`) at 120 USD per million, stated as 0.134 for a 1K or 2K
image and 0.24 for 4K. Text and thinking output on these models is billed at the model's text rate, and input at the
input rate. **Verified** against that page on that date; prices change, so the table carries a date and a
`valid_through`, and the build re-reads the page before it ships.

The price table in `broker.yaml` gets a second shape, `kind: image`, with the per-image figure by size taken from the
vendor's own statement (not derived by the broker):

```yaml
prices:
  price_checked: "2026-10-30"
  models:
    gemini-3-pro-image:
      kind: image
      valid_through: "2026-12-31"
      input_per_mtok: "2.00"            # text and image input
      text_output_per_mtok: "12.00"     # text and thinking output
      image_usd:                        # per output image, by size, as the vendor page states it
        "1K": "0.134"
        "2K": "0.134"
        "4K": "0.24"
      max_images: 1                     # per call
      text_allowance_tokens: 2000       # thinking and text the estimate always includes
    gemini-3.1-flash-lite-image:
      kind: image
      valid_through: "2026-12-31"
      input_per_mtok: "0.25"
      text_output_per_mtok: "1.50"
      image_usd: { "1K": "0.0336" }
      max_images: 1
      text_allowance_tokens: 2000
```

These numbers are an example of the shape and of what the page said on that date; the shipped example file is filled
in by re-reading the page. The estimate for an image call is

`count * image_usd[image_size] + prompt_tokens * input_per_mtok + text_allowance_tokens * text_output_per_mtok`

with `prompt_tokens` counted at three bytes a token, as for text. A size not in `image_usd` for that model (for
example 4K on the Lite model) is refused. After the call the actual cost is computed from the usage the vendor returns
(input tokens, text and thinking tokens, image output tokens) at the table's prices. A reported figure below a floor
(the number of images actually returned times the smallest per-image figure for that model) is raised to the floor, and
a response with no usage uses the estimate. If the actual cost is above the approved `max_usd` (for example the model
thinks for longer than the allowance), the **actual cost is recorded and counts toward the month**, the receipt says
`overrun: true`, and the maintainer sees it; the broker cannot recall a spent call. Whether the image request can cap
text and thinking tokens the way `maxOutputTokens` does for text is **unverified**; until it is shown, the allowance
and the monthly ceiling are the bound, and the vendor-side limit is the backstop. No grounding or search tools are ever
put in the request, since they bill separately; the broker builds the request body itself from a fixed template and
the client cannot add fields.

**The vendor ceilings are not prices.** The maintainer's own AI Studio screenshots of 2026-10-30 show per-minute and
per-day request ceilings for the paid project (for example Nano Banana Pro at 20 requests per minute and 250 per day,
Nano Banana 2 at 100 per minute and 1K per day). They are vendor limits far above the broker's money caps, so the caps
bound spend. The broker also keeps its own `max_calls_per_minute` and `max_calls_per_day` below them.

## Images

### The request

For an image model the broker sends the request shape on the vendor's image-generation page
(`ai.google.dev/gemini-api/docs/image-generation`, "Last updated 2026-10-26 UTC", read 2026-10-30): a POST to the
vendor's `/v1beta/interactions` endpoint with `model`, `input` (one text block) and `response_format`
(`type: image`, `aspect_ratio`, and `image_size` as `512px`, `1K`, `2K` or `4K` with an uppercase K; the page says
lowercase is rejected). This differs from the text path (`generateContent`), so the broker has one fixed request
builder per `kind`. **The request shape is verified against the page; the response shape is not.** The page shows
generated images as base64 data blocks, but the exact JSON field names for the REST response were not in the text read.
The first build phase therefore records one real response (the smallest allowed call, with its own approval, under the
maintainer's eye) and turns it into a test fixture, and the parser rejects any shape it has not been shown.

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

`/etc/systemd/system/safo-broker.socket`:

```ini
[Unit]
Description=SAFO Gemini broker socket

[Socket]
ListenStream=/run/safo-broker/broker.sock
SocketUser=root
SocketGroup=safo-broker-clients
SocketMode=0660
DirectoryMode=0750
Accept=no
MaxConnections=8

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
ExecStart=/opt/safo-broker/venv/bin/python -I -m safo.broker
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
(only a value that passed the allowlist in `broker.yaml`), `kind`, `count`, estimate and actual cost, HTTP status of the
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
  `max_calls_per_day` for vendor calls (default 5 and 20), 8 connections (the socket unit), 5 seconds to send a request.
- **A vendor 429 is final.** The ledger gets `call_end` with status `rate_limited` and zero cost, the nonce stays spent,
  the reply is `rate_limited` with exit 3 and the vendor's `Retry-After` when it is a finite number of seconds under a day.
  Nothing is retried. There is no other tier for the broker to fall through to, and the client never answers a paid 429
  by calling the free path or asking for a second approval. After the request leaves, a timeout, a 5xx, a 408, a redirect
  or an unreadable answer is `outcome_unknown`, counted at the estimate, not repeated.

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
  model, size or count against the signed text, an estimate above `max_usd`, the month ceiling and the extra block, a
  revoked key between `begin` and `call`, an expired approval, a missing switch, a switch that flips off mid-flight, and
  a price past `valid_through`.
- **The client:** writes with `O_EXCL`; refuses an existing file, a symlinked directory and a symlink at the target; never
  uses a name from the reply; mode 0600; the sidecar matches the digest; a tampered attachment is rejected by the digest.
- **The free path:** the independence tests above.
- **A log test** for each failure path (sentinels for prompt, key, quote, job, vendor body).
- **systemd checks (phase 5):** `systemd-analyze verify` and `systemd-analyze security --offline` on the shipped units
  in CI, with the score recorded; and a run on a throwaway VM or container with a fake key and a fake vendor, which is
  the only place the unit's real effect (credential delivery, `MemoryDenyWriteExecute` with `ssh-keygen`, the system-call
  filter with `memfd_create`) is observed.

## Build plan: small pull requests, a review gate between each

Prerequisite: **#217 has merged** (the prompt digest in the signed approval). The image vertical slice (phases 1 to 5)
comes first, because the blocked projects need generated images; the text path is added after. Each phase is its own
pull request with tests first, and **no phase starts until the previous one has passed review**; phases 1 to 3 add no
service and spend nothing.

| Phase | What lands | Gate before the next |
|---|---|---|
| 0 | This design and the threat model (documents only) | The maintainer answers the decisions below; a cyber-tier review of the design |
| 1 | The broker core as a library, no socket, no systemd: state directory checks, the ledger shared with today's code, issue and consume of nonces, recovery, spend-before-call, the signed approval schema version 2 and its verification, the cost estimate for `image` and `text`, with the hermetic fakes | Review of the state machine and the crash tests |
| 2 | The call pipeline against the fake vendor: request builders per kind, the image response handling (magic bytes, limits, receipts), 429 and ambiguous outcomes. Includes recording one real image response as a fixture, with the maintainer's approval of that one call, once phase 4 exists | Review; the fixture reviewed by hand |
| 3 | The socket server: framing, protocol version 1 with attachments, peer credentials, limits, deadlines, idle exit, the operations, logging allowlist; fake socket peers and a fuzz test of the framing | Review of the parser and the limits |
| 4 | The thin client: `approve` and `ask --paid` go through the socket, safe image writing and sidecars, the guard's `check`, **removal of the in-process paid path**, the free-path independence tests, docs | Review; the old local paid code must be gone, not just unused |
| 5 | The units, the installer and `safo-broker-admin` (`check-install`, `status`, `usage`, `reconcile`), `systemd-analyze` in CI, the throwaway-VM run, and the setup runbook | Review of the units and the install checks |
| 6 | **Cyber-tier security review** of the broker and the signed-approval verification (issue step 3) | Clean review |
| 7 | The maintainer does the root setup, the dry run, then one smallest-size image call; then creates the switch (issue step 5) | The maintainer's own run |
| 8 | Text paid calls through the same path, the `usage` workflow, then the optional count-per-approval and passkey wiring if the maintainer wants them | Review per item |

The smallest thing useful to the blocked projects is the result of phases 1 to 7: one text-to-image call per approval,
one image per call, written to a fixed folder with a receipt. Nothing in it needs the text path.

## Decisions for the maintainer

| # | Decision | Recommendation |
|---|---|---|
| 1 | Accept the broker as the design (against a TPM counter or a vendor-side authorization, neither of which fits) | Yes |
| 2 | The broker runs as a dedicated unprivileged system user, started by a socket unit, not as root | Yes |
| 3 | The paid key is created fresh for the broker, held as a systemd encrypted credential (`host`, or `host+tpm2` where a TPM exists), and the old Doppler paid key and config are revoked and deleted | Yes; this step is the one only the maintainer can do, once, as root |
| 4 | Who may talk to the socket: the maintainer's uid, by a uid list in `broker.yaml` plus the socket group | Yes; accept that this cannot tell an agent from the wrapper, and rely on the signature |
| 5 | The broker hands out the nonce (`begin`), so an approval can only be made for a request the broker has seen | Yes |
| 6 | Crash rule: spend is recorded before the vendor call and an interrupted call counts at its estimate | Yes |
| 7 | Images first, text-to-image only, one image and one approval per call; a count per approval only later, and "up to N calls" never | Yes |
| 8 | Image output: a fixed folder of the maintainer's choosing, files 0600, never overwritten, a sidecar receipt, never auto-opened by an agent | Yes; name the folder when phase 4 is built |
| 9 | Broker v1 accepts hardware-key (Tier 1) approvals only; passkeys wait until their approval wiring exists | Yes |
| 10 | Broker code is installed by root from a tagged release into `/opt/safo-broker` and updated the same way, each update reviewed | Yes |
| 11 | Remote broker on the lab machine, as a later option | Not now |

## What this page does not claim

- That any of it is built or run. Everything in "Build plan" is future.
- That the root account, the kernel, systemd or `ssh-keygen` are trustworthy. The design needs them to be.
- That a human who touches the key for a prompt he did not read is protected. See the threat model's residual risk.
- The response shape of the vendor's image call, the cost of a metadata request, whether `@system-service` allows
  `memfd_create`, whether `MemoryDenyWriteExecute` is compatible with `ssh-keygen` here, and whether the free key's
  project has billing disabled: **unverified**, each with the phase that checks it.
