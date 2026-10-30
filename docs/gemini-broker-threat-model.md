# Gemini broker: threat model

> **Status: a model of a design that is not built.** It covers [the broker design](gemini-broker.md) for issue #205 and
> is a draft for the maintainer and the cyber-tier review, not a verdict and not an audit. Every "verification" below
> names a test or command that does **not exist yet** (the planned test files are listed in the design's build plan) or
> a command that reads the installed system; nothing here has been run against a built broker. It states what the
> design guarantees and what it explicitly does not.

Method: assets, actors, trust boundaries, abuse cases, risks ranked by impact and by what the actor needs first, a
mitigation and a verification for each, residual risk. Page-level limits: no active testing was done, and the
review that led to the broker is summarized in the public docs only ([Gemini](gemini.md), "Residual risk").

## Scope

In scope: the broker, its socket, its state, its key, the signed approval it checks, the vendor call it makes, the
binary image reply, and the thin client's handling of that reply. Out of scope: the vendor's own security, the hardware
key's firmware, the kernel and systemd, a malicious root, the free path's own rate limits ([Gemini](gemini.md)), and the
consuming projects' review of generated art.

## Assets

| Asset | Why it matters | Data class |
|---|---|---|
| The paid API key | Anyone holding it can spend the vendor account directly | Secret |
| The spend ledger and the consumption records | They decide how much is spent and whether an approval can be used again | Integrity-critical, not secret |
| The trust files (`gemini-allowed-signers`, `gemini-revoked-signers`) and the enable switch | They decide who may approve and whether paid use is on | Integrity-critical, public content |
| `broker.yaml` (caps, models, prices, uid list) | A wrong price or cap breaks every cost bound | Integrity-critical |
| The broker's code and units | Code the broker runs holds the key | Integrity-critical |
| Prompts | May carry what the maintainer should not send; sent to a third party | Sensitive, must not reach logs |
| Generated images and text | Untrusted output that may be published | Untrusted content |
| The maintainer's hardware keys and their touch | The only thing that authorizes spend | Secret and human |
| Availability of the paid path | Blocked projects depend on it; the free path does not | Availability |

## Actors

| Actor | Can do |
|---|---|
| The maintainer | Holds the hardware keys; has root through a password; reads what he approves |
| An agent or any process running as the maintainer's account (may be prompt-injected) | Run commands as that uid, write that account's files, read its environment, connect to the broker's socket, run `approve` and so make a key blink |
| Another local user | Is not in the socket group; may still try the socket path |
| A local process as the broker's own user after a bug | Is the broker; limited by the unit |
| The vendor, and a network attacker between | Answer the broker's request; a network attacker cannot present the vendor's certificate |
| A holder of a stolen hardware key | Can sign if the PIN is not required or is known |
| Someone who persuades the maintainer to touch | Gets a signature for what is shown |
| Root (the maintainer acting as root, or an attacker who has root) | Everything; outside the design |
| A compromised dependency or release artifact | Runs as the broker if it is in the installed code |
| A model reading attacker-controlled text and writing prompts or briefs | May ask for spend or for an image of anything |

## Trust boundaries

1. **Maintainer account to broker** (the Unix socket). Everything arriving is untrusted bytes; the peer uid proves a
   local account, not intent.
2. **Maintainer account to root-owned files** (`/etc/safo`, `/opt/safo-broker`, the units). Written only by root.
3. **Broker to its state directory.** Written only by the broker's user; the broker trusts its own state, with a chain
   and a height record to notice damage.
4. **Broker to the hardware key** (through the signature). The touch is the human boundary; the broker trusts only a
   verified signature over exact bytes.
5. **Broker to the vendor** (outbound TLS). The vendor's reply is untrusted: sizes, types, counts, usage figures.
6. **Broker to client** (the reply). Text and image bytes are untrusted content to the client and to anything that opens them.
7. **Client to the output folder** (files written under the maintainer's account).
8. **Free path to paid path.** Two separate keys, projects and ledgers.

## Risk register

Ranked by impact and by the prerequisite the actor needs first; a heavy prerequisite ranks below a moderate one anyone
local can reach. Impact: Critical (spend outside any cap), High (spend above a cap or a bypass of the approval),
Medium (loss within the caps, or loss of privacy), Low (availability or annoyance).

| Id | Abuse case | Impact | Prerequisite | Rank |
|---|---|---|---|---|
| R1 | The account reads the paid key and calls the vendor directly | Critical | Key readable by the account (the case today); with the broker: root | 1 |
| R2 | A local process feeds the broker malformed, huge or slow input to take control of it or its key | Critical | Local access to the socket (every agent has it) | 2 |
| R3 | Replay of an approval, or a rewound ledger, to spend past the caps | High | Same account (today); with the broker: root or a state restore | 3 |
| R4 | An approval is reused for something else: another prompt, size, count or model | High | A valid signed approval in hand | 4 |
| R5 | The broker's code, config, prices or units are changed | High | Root, or a poisoned release | 5 |
| R6 | The maintainer touches for a request he did not read | High | A prompt-injected agent that can run `approve` | 6 |
| R7 | Binary output abuse: oversized, mislabeled or polyglot bytes; a client path or link trick; an agent opens the file | Medium to High | A hostile or confused vendor reply, or a confused client | 7 |
| R8 | The estimate undercounts (thinking tokens, a stale price, a size outside the table) | Medium | A normal call | 8 |
| R9 | An enrolled key is stolen or lost | High | Physical theft, plus the PIN if required | 9 |
| R10 | The key or a prompt leaks through a log, an error, a core dump, a process listing | High | Read access to logs or the process | 10 |
| R11 | Request goes to the wrong host, or the key is carried by a redirect | Critical | DNS or network position, plus a missing check | 11 |
| R12 | A crash or power loss mid-call leaves spend unrecorded or an approval reusable | Medium | A crash at the wrong moment | 12 |
| R13 | A vendor 429 or error falls through to another tier or is retried into more spend | Medium | A rate-limited moment | 13 |
| R14 | Private material is sent to the vendor in a prompt | Medium | A careless or injected prompt | 14 |
| R15 | Generated art is published unreviewed: wrong mascot, a rights or disclosure problem | Medium | A consuming project skipping review | 15 |
| R16 | The root-equivalent doors: passwordless sudo, the docker group | Critical | Present on the machine | 16 |
| R17 | A flood or slow clients keep the paid path unavailable | Low | Local access | 17 |
| R18 | The clock is moved to extend an approval's life | Medium | Root or a time-source attack | 18 |
| R19 | The free key spends money, or the free path calls the broker | Medium | A project with billing on the free key | 19 |
| R20 | A state backup is restored over live state | Medium | Root | 20 |

The ranking puts R1 first because it is the case today and the one the broker exists to close, and R2 second because
the socket is reachable by every agent and the broker holds the key. R16 is a precondition more than a risk the broker
can reduce: its impact is Critical if the installer's check is ignored.

## Findings, mitigations and verifications

Each entry: the abuse case, the control, the check that shows it bites (a planned test that goes red without the
control, or a command that reads the installed system), then the residual risk.

### R1. Direct use of the paid key

- **Mitigation.** The key exists only as `/etc/safo/broker/paid-key` (root, 0600, in a 0700 directory) and as the
  service's credential (readable only by the broker's user). A new key replaces the old one, and the old key and the
  secret-store config are revoked and deleted. The broker is the only holder; the client and the guard hold none. The dispatch guard
  keeps denying shell commands that name the vendor host, as defense in depth ([Hooks](hooks.md)); it is a speed bump, not the control.
- **Verification.** Commands run as the maintainer account on the installed system, each expected to fail: `cat
  /etc/safo/broker/paid-key`, `ls /etc/safo/broker`, `ls /run/credentials/safo-broker.service`, `cat
  /proc/$(systemctl show -p MainPID --value safo-broker.service)/environ`, and a secret-store read of the old paid
  config (expected: gone). `safo-broker-admin check-install` runs these and prints pass or fail. Planned test:
  `tests/test_broker_install_check.py` builds a temporary tree with each wrong owner and mode and expects a failure.
- **Residual.** The key passes through the vendor console and the maintainer's hands once (created on another device,
  typed on a virtual console). Root can read it. The vendor-side monthly limit stays the backstop.

### R2. Attack on the socket parser and the process

- **Mitigation.** Strict framing with a length cap checked before any read (1 MiB request, 256 KiB reply header,
  24 MiB attachment); a 5 second deadline to deliver a request; the bounded JSON loader plus duplicate-key, depth and
  unknown-key rejection; no `pickle`, `eval` or shell anywhere in the path; patterns for names checked with
  `fullmatch`; peer uid allowlist; at most 8 connections; one vendor call in flight; the unit's confinement (no
  capabilities, no home, a system-call allowlist, no writable-executable memory, bounded memory and tasks) so that a
  parser bug yields a confined, unprivileged process whose only secret is the key it was already handed.
- **Verification.** Planned `tests/test_broker_protocol.py`: a table of malformed frames (zero length, over the cap,
  short body, stalled body, invalid UTF-8, duplicate keys, deep nesting, wrong types, unknown keys, unknown version)
  each expecting a coded refusal and no state change; a randomized framing fuzz with a fixed seed; a connection-flood
  test. `systemd-analyze security --offline` on the shipped unit in CI.
- **Residual.** A memory-safety bug in the interpreter or a library could still reach the key. The unit limits what
  follows; it does not remove the key from the process. The cyber-tier review (phase 6) is the check on the parser.

### R3. Replay and rewind

- **Mitigation.** The consumption records and the chained ledger live in a directory only the broker's user can write.
  The nonce is handed out by the broker (`begin`), is spent with an exclusive create plus a ledger row before the
  vendor request, and either record alone marks it spent. The chain, the head file and the height record are kept, and
  an approval older than 60 minutes is dead anyway. An approval also carries the broker's `epoch`.
- **Verification.** Planned: a replayed nonce is refused; two simultaneous `call`s on one nonce let exactly one through; a
  ledger copy from an earlier moment placed in the state directory by the test is refused by the height record and the
  chain; kill-and-restart tests at each step leave the nonce spent. Command: as the maintainer account, `touch
  /var/lib/safo-broker/x` and `ls /var/lib/safo-broker` must both fail.
- **Residual.** Root can rewind. A restored backup rewinds (R20). The ledger is tamper-evident, not tamper-proof, against
  the broker's own user.

### R4. An approval used for something else

- **Mitigation.** The signed text binds the model, kind, count, size, aspect ratio, output limit, maximum cost, job,
  nonce, epoch, expiry and the SHA-256 of the exact prompt; the broker recomputes the digest from the bytes it received
  and recomputes the estimate from its own prices. The client cannot add request fields: the broker builds the vendor
  body from a fixed template. This depends on #217 landing the digest.
- **Verification.** Planned: for each bound field, a request that differs in only that field is refused with its own
  code and the vendor fake sees no request; a unit test that lists the signed fields and fails if a field that affects
  cost is not in the list (so adding a billable field without binding it goes red).
- **Residual.** An approval binds what the client sent, not what the maintainer understood (R6).

### R5. Tampering with code, config, prices or units

- **Mitigation.** All are root-owned and read-only to the broker (`ReadOnlyPaths=`); the code is installed from a
  hash-locked requirements file into `/opt/safo-broker`, not run from the maintainer's checkout; `broker.yaml` is read
  through the ownership walk on every request; prices carry `valid_through`; caps in config can only lower the constants.
  The broker has no dependency on the passkey extra in v1, which keeps the installed set small.
- **Verification.** Planned: `check-install` walks every path and fails on a wrong owner, a group or world write, a
  symlink, or a parent directory the maintainer account can write; a config that raises a cap is refused; a price past
  its date refuses a paid estimate. Release artifacts are hashed and the maintainer compares the digest on install.
- **Residual.** A poisoned release that the maintainer installs. The update is his decision and he reads the diff.

### R6. The touch for a request he did not read

- **Mitigation.** The same controls as today: the quota line printed first by the broker's own numbers, a typed
  `approve JOB`, an expiry of minutes, a signed maximum cost, one call per approval. New: the signed text carries the
  digest and size of the prompt and (for images) the model, size and count, which the screen shows. The client
  also shows the beginning of the prompt it will send. The rule stays: touch only after reading, never for a prompt you did
  not start.
- **Verification.** Planned: the `approve` screen test checks that it prints the quota line, the digest, the size, and
  the image fields before it asks for the typed confirmation. The human step cannot be tested.
- **Residual (accepted by the maintainer, reopened by any report of a surprise touch).** A tired or deceived maintainer
  approves what is shown. A compromised `approve` binary or terminal can show one prompt and sign another; the
  broker verifies the signed bytes, not what was displayed. A key with a display would close this and is not assumed.

### R7. Binary output

- **Mitigation.** The broker accepts `image/png`, `image/jpeg`, `image/webp` only, and only when the first bytes match
  the type; at most the approved count of images; at most 24 MiB each; 32 MiB for the whole vendor body; it never
  decodes an image. It sends no path or name. The client chooses the name from a fixed pattern, opens the output
  directory once and creates files relative to it with `O_EXCL|O_NOFOLLOW`, mode 0600, checks the digest, and writes a
  sidecar. Safo never opens, previews or parses an image. The briefs tell agents not to open them.
- **Verification.** Planned tests with the fake vendor: wrong signature for the claimed type, an unlisted type, an empty
  image, an oversized image, more images than approved, a truncated body, and a malformed body each give a coded
  refusal and send no bytes to the client. Client tests: an existing target, a symlink at the target, a symlinked
  directory, a name from the reply, and a tampered attachment are all refused; modes are checked with `stat`. A static
  check (grep in the test suite) that the broker and client modules import no image library.
- **Residual.** A valid PNG, JPEG or WebP can still carry content that harms whatever opens it, or an image that is
  wrong for its purpose. The maintainer's review is the control for what is in the picture; the brand rule is below (R15).

### R8. Cost undercount

- **Mitigation.** The broker computes the estimate from a price table the maintainer's account cannot edit, includes a
  fixed text and thinking allowance for image calls, refuses sizes not in the table, refuses stale prices, raises a
  reported cost to a floor from the number of images returned, and records an overrun as spent. The request carries no
  grounding or tools. The monthly ceiling and the vendor-side limit bound the rest.
- **Verification.** Planned: estimate tests per model and size against the table values; a fake vendor reply with
  implausibly low usage is floored; a reply with high thinking usage records `overrun` and counts it; a request for 4K on
  the 1K-only model is refused.
- **Residual.** If the image request cannot cap thinking tokens (unverified), one call can exceed its approved maximum
  by the thinking cost; it is recorded and counts. The vendor-side limit is the backstop.

### R9. A stolen or lost enrolled key

- **Mitigation.** Revocation by fingerprint in a root-owned file, re-read on every request and again under the state
  lock; `require-pin` per key; two or more keys with one offline; validity windows. Revocation takes effect for approvals
  already signed. See [Gemini keys](gemini-keys.md).
- **Verification.** Planned: a revoked key's unspent approval is refused; a revocation written between `begin` and `call`
  is honored; a revoked-signers file that is missing refuses every approval.
- **Residual.** A thief with the key and its PIN can approve until the maintainer revokes; the 2 USD job and 10 USD
  month caps and the expiry bound that.

### R10. Leaks through logs, errors, dumps, listings

- **Mitigation.** The log allowlist (numbers and enumerated values only; no client text); fixed reply sentences that
  echo nothing; the key never in argv, environment or an exception message; `LimitCORE=0`, `PR_SET_DUMPABLE` off;
  `ProtectProc=invisible`; the prompt held only for the call; the ledger never holds the prompt or the quote.
- **Verification.** Planned: every failure-path test captures the log and asserts that sentinel strings placed in the
  prompt, job, quote, key, approval text and a fake vendor error body are absent from it and from the reply. Command:
  `systemctl show -p LimitCORE safo-broker.service` shows 0; `grep -R` over the repository's broker modules finds no
  logging call with a client string argument (a static test).
- **Residual.** Python cannot guarantee that a copy of the key is gone from memory after use. Root can read it.

### R11. Wrong host, or a redirect carrying the key

- **Mitigation.** The host is a constant in code, not a setting; TLS verification on; no proxy variable; the checked
  address connection; redirects are refused and never followed.
- **Verification.** Planned: the fake vendor returns a 302 to another address and the test asserts the second server
  receives nothing and the call is `outcome_unknown`; a test that the production constructor takes no endpoint from
  `broker.yaml`; a test that a proxy variable in the environment has no effect.
- **Residual.** A compromised certificate authority in the system store.

### R12. Crash or power loss mid-call

- **Mitigation.** Spend is recorded and synced **before** the vendor request; recovery marks every unfinished call
  `ambiguous` at its estimate; either consumption record alone marks the nonce spent; nothing replays.
- **Verification.** Planned: fault injection between each pair of steps, then restart; assert the nonce is unusable, the
  month counts the estimate and the vendor fake saw at most one request. Documented cost: a crash before the request
  charges one estimate for nothing.
- **Residual.** The lost reply is not recoverable (the broker keeps no copy), so one approval can be spent for no
  usable output; bounded by the approved maximum.

### R13. A 429 or an error falls through, or is retried

- **Mitigation.** A 429 is `rate_limited` and final; no retry loop exists; no second tier exists for the broker; the
  client never answers a paid 429 with a free call or a second approval; the broker's own per-minute and per-day limits sit
  below the vendor's.
- **Verification.** Planned: the fake vendor returns 429 and the test asserts exactly one request, exit 3, the nonce
  spent, zero cost recorded, and that a free call was not made; a test that the client module has no import path to the
  free `ask` function in its paid branch.
- **Residual.** None known beyond the cost of an approval spent on a 429.

### R14. Private material in a prompt

- **Mitigation.** The private-terms and secret-shape checks run in the client before `approve` and before the send; the
  broker repeats the secret-shape check; the approval binds the digest of the checked prompt; images are
  text-to-image only, so no private picture is uploaded. `--material public` stays a statement by the caller.
- **Verification.** Planned: a prompt matching a term or a secret shape is refused before `begin`; a prompt changed
  after `approve` is refused by the digest; a request with an input image is refused.
- **Residual.** No code knows what is public. The terms check is client-side and the broker cannot read the maintainer's
  terms file; a compromised client skips it, and the maintainer's reading at `approve` is the remaining control.

### R15. Unreviewed generated art

- **Mitigation.** Files land mode 0600 in one folder with a sidecar saying `reviewed: false`; the briefs say an agent
  never opens or publishes an image; the maintainer reviews each file. **The broker does not enforce the brand rule
  (the mascot without the Star of David, checked per file) and cannot; the consuming project's review does.**
  Disclosure of AI-generated art is also the consuming project's decision; the vendor adds a SynthID watermark.
- **Verification.** Not testable in the broker. The consuming project carries its own per-file check; the review that
  matters is a person looking at each image.
- **Residual.** Entirely the consuming project's.

### R16. Root-equivalent doors on the maintainer's account

- **Mitigation.** `safo-broker-admin check-install` fails if `sudo -n true` succeeds for the account, if the account is
  in the `docker` group or another root-equivalent group, or if any path in the table above has the wrong owner or mode.
  The runbook states the precondition.
- **Verification.** Command: `sudo -n true` must fail; `id -nG` must not list `docker`. Planned test of the check
  against a fake group database and a fake sudo.
- **Residual.** A new door added later; the check is a snapshot, so it runs again on every start of the admin tool and
  is repeated by `status`.

### R17. Availability

- **Mitigation.** Connection, rate, size and time limits; one call in flight; restart limits; the free path unaffected.
- **Verification.** Planned flood and slow-peer tests; the free-path independence tests.
- **Residual.** A local process can keep the paid path busy. Loss of paid use is accepted; loss of money is not.

### R18. Clock

- **Mitigation.** The broker reads its own clock; expiries are short; the nonce is single-use whatever the time; pending
  nonces also expire by uptime. Changing the clock needs root.
- **Verification.** Planned: a fake clock moved backward does not revive a spent nonce.
- **Residual.** A network time attack within the 60 minute maximum life of an approval.

### R19. Free and paid mixing

- **Mitigation.** Separate keys, projects and ledgers; the free key's project has billing disabled (the maintainer
  confirms once; unverified today); the free path never opens the socket; the broker never calls the free path.
- **Verification.** Planned independence tests (a free run with no socket, and with a fake peer that fails on connect).
  Command: the vendor console shows billing off for the free project (a manual step).
- **Residual.** Depends on the vendor-side setting.

### R20. State restore

- **Mitigation.** The runbook forbids restoring the state directory into a running broker; after any restore the
  maintainer reconciles with the billing page and enters the difference through the root-only `usage` command before the
  switch is on again. The longest signed life is 60 minutes.
- **Verification.** Planned: `reconcile` refuses to enable when the chain height is below the height record.
- **Residual.** A restore by root is a root decision.

## Trust assumptions the design cannot prove

- Root, the kernel, systemd, `ssh-keygen` and the TLS store behave.
- The hardware key reports its touch and PIN flags honestly.
- The vendor bills what its page says and returns honest usage figures.
- The maintainer's account has no door to root (checked as a snapshot).

## What was covered and what was not

Covered: the design in [the broker design](gemini-broker.md) read against the current code in `src/safo/gemini.py`,
`geminisign.py`, `geminipasskey.py` and `modes/gemini.py`, and the public docs. Not covered: any built broker (there is
none); the systemd unit's behavior on a running system (only an offline lint was run); a real hardware key; the vendor's
real image response; the interaction of `MemoryDenyWriteExecute` and the system-call filter with `ssh-keygen`; the
installer. This model is the input to the cyber-tier review in phase 6, which is a separate step and not replaced by it.

## Reopen this model when

A phase changes the protocol, the unit, the state layout or the signed text; the vendor changes image billing, adds a
tool the request could carry, or documents a one-time authorization for generation calls; a report of a surprise touch;
any change in who can reach root on the maintainer's machine.
