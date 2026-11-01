# Gemini broker: threat model

> **Status: a model of a built but never-run broker, aligned with the code on 2026-10-31 (issue #273).** It covers
> [the broker design](gemini-broker.md) for issue #205, is an input for the maintainer and was the input to the cyber-tier
> review (phase 6, done), and is not a verdict and not an audit. Each "verification" below names the test files in
> `tests/` that exercise the control against fakes, or a command that reads the installed system, or says **not built yet**.
> Nothing here has been run against an installed broker or the real vendor: the controls are tested with a fake vendor, fake
> socket peers and temporary trees. It states what the design guarantees and what it explicitly does not.

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
| A compromised dependency or release artifact | Its code runs as the broker user; the installer never runs a build backend as root |
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
| R3 | Replay of an approval, or a rewound ledger, to spend past the caps | High | Same account (today); with the broker: root or a state restore | 4 |
| R4 | An approval is reused for something else: another prompt, size, count or model | High | A valid signed approval in hand | 5 |
| R5 | The broker's code, config, prices or units are changed | High | Root, a stolen release-signing key, or a reviewed-but-malicious tag | 6 |
| R6 | The maintainer touches for a request he did not read | High | A prompt-injected agent that can run `approve` | 7 |
| R7 | Binary output abuse: oversized, mislabeled or polyglot bytes; a client path or link trick; an agent opens the file | Medium to High | A hostile or confused vendor reply, or a confused client | 8 |
| R8 | One accepted image or text call bills more than its approval: thinking and text output that the vendor does not cap, a stale price, a size outside the table | High | A normal call; no attacker needed | 3 |
| R9 | An enrolled key is stolen or lost | High | Physical theft, plus the PIN if required | 9 |
| R10 | The key or a prompt leaks through a log, an error, a core dump, a process listing | High | Read access to logs or the process | 10 |
| R11 | Request goes to the wrong host, or the key is carried by a redirect | Critical | DNS or network position, plus a missing check | 11 |
| R12 | A crash or power loss mid-call leaves spend unrecorded or an approval reusable | Medium | A crash at the wrong moment | 12 |
| R13 | A vendor 429 or error falls through to another tier or is retried into more spend | Medium | A rate-limited moment | 13 |
| R14 | Private material is sent to the vendor in a prompt | Medium | A careless or injected prompt | 14 |
| R15 | Generated art is published unreviewed: wrong mascot, a rights or disclosure problem | Medium | A consuming project skipping review | 15 |
| R16 | A root-equivalent door on the maintainer's account (a command-specific sudo or polkit grant, a root-run job on a writable file, a group, a setuid helper, a vulnerable privileged service) | Critical | Present on the machine | 16 |
| R17 | A flood, slow clients or a client that stops reading keep the paid path unavailable | Low | Local access as the allowed uid | 17 |
| R18 | The clock is moved to extend an approval's life | Medium | Root or a time-source attack | 18 |
| R19 | The free key spends money, or the free path calls the broker | Medium | A project with billing on the free key | 19 |
| R20 | A state backup is restored over live state | Medium | Root | 20 |

The ranking puts R1 first because it is the case today and the one the broker exists to close, and R2 second because
the socket is reachable by every agent and the broker holds the key. R8 is third because it needs no attacker at all:
an ordinary call can bill past its approval if the vendor does not honor a cap. R16 is a precondition more than a risk
the broker can reduce: its impact is Critical, and the checks for it are partial (see its entry).

## Findings, mitigations and verifications

Each entry: the abuse case, the control, the check that shows it bites (a test that goes red without the control, or a
command that reads the installed system), then the residual risk. Test files are named, not individual tests; the files
are `tests/test_broker_*.py` and `tests/test_gemini_*.py`.

### R1. Direct use of the paid key

- **Mitigation.** The key exists only as `/etc/safo/broker/paid-key` (root, 0600, in a 0700 directory) and as the
  service's credential (readable only by the broker's user). A new key replaces the old one, and the old key and the
  secret-store config are revoked and deleted. The broker is the only holder; the client and the guard hold none. The dispatch guard
  keeps denying shell commands that name the vendor host, as defense in depth ([Hooks](hooks.md)); it is a speed bump, not the control.
- **Verification.** Commands run as the maintainer account on the installed system, each expected to fail: `cat
  /etc/safo/broker/paid-key`, `ls /etc/safo/broker`, `ls /run/credentials/safo-broker.service`, `cat
  /proc/$(systemctl show -p MainPID --value safo-broker.service)/environ`, and a secret-store read of the old paid
  config (expected: gone). These are run by hand today; the administration command `check-install` does not run them (it
  checks the release, units, egress helper and switch; a read-only check for the rest is **not built yet**, issue #293).
  `tests/test_broker_admin.py` builds temporary trees with wrong owners and modes for what `check-install` does cover.
- **Residual.** The key passes through the vendor console and the maintainer's hands once (created on another device,
  typed on a virtual console). Root can read it. The vendor-side monthly limit stays the backstop.

### R2. Attack on the socket parser and the process

- **Mitigation.** Strict framing with a length cap checked before any read (1 MiB request, 256 KiB reply frame,
  24 MiB attachment); a 5 second deadline to deliver a request; the bounded JSON loader plus duplicate-key, depth and
  unknown-key rejection; no `pickle`, `eval` or shell anywhere in the path; patterns for names checked with
  `fullmatch`; peer uid allowlist; a connection cap and a per-uid cap enforced in the broker (the socket unit's
  `MaxConnections=` does nothing with `Accept=no`, so it is not relied on); a deadline on every frame read and every frame
  written, with the paid-call slot released before the reply is written; one vendor call in flight; the unit's confinement (no
  capabilities, no home, a system-call allowlist, no writable-executable memory, bounded memory and tasks) so that a
  parser bug yields a confined, unprivileged process whose only secret is the key it was already handed.
- **Verification.** `tests/test_broker_protocol.py`: a table of malformed frames (zero length, over the cap, short body,
  invalid UTF-8, duplicate keys, deep nesting, wrong types, unknown keys, unknown version) each expecting a coded refusal;
  `tests/test_broker_server.py` and `tests/test_broker_deadline.py`: the connection caps (the ninth and the
  third-per-uid are closed unread), stalled readers and writers dropped at the deadline with the slot already free;
  `tests/test_broker_units.py` and `tests/test_broker_unit_policy.py`: `systemd-analyze security --offline` on the shipped
  units where the tool exists. A seeded, bounded framing fuzz (`tests/test_broker_framing_fuzz.py`) feeds the frame reader, both parsers and the server handler arbitrary bytes.
- **Residual.** A memory-safety bug in the interpreter or a library could still reach the key. The unit limits what
  follows; it does not remove the key from the process. The cyber-tier review (phase 6) is the check on the parser.

### R3. Replay and rewind

- **Mitigation.** The consumption records and the chained ledger live in a directory only the broker's user can write.
  The nonce is handed out by the broker (`begin`), is spent with an exclusive create plus a ledger row before the
  vendor request, and either record alone marks it spent. The chain, the head file and the height record are kept, and
  an approval older than 60 minutes is dead anyway. An approval also carries the broker's `epoch`.
- **Verification.** `tests/test_broker_ledger.py` and `tests/test_broker_pipeline.py`: a replayed nonce is refused; two
  simultaneous `call`s on one nonce let exactly one through; a ledger copy from an earlier moment is refused by the height
  record and the chain; fault injection at each step leaves the nonce spent. Command: as the maintainer account, `touch
  /var/lib/safo-broker/x` and `ls /var/lib/safo-broker` must both fail.
- **Residual.** Root can rewind. A restored backup rewinds (R20). The ledger is tamper-evident, not tamper-proof, against
  the broker's own user.

### R4. An approval used for something else

- **Mitigation.** The signed text binds the model, kind, count, size, aspect ratio, output limit, maximum cost, job,
  nonce, epoch, expiry and the SHA-256 of the exact prompt; the broker recomputes the digest from the bytes it received
  and recomputes the estimate from its own prices. The client cannot add request fields: the broker builds the vendor
  body from a fixed template. The digest binding of #217 has shipped.
- **Verification.** `tests/test_broker_records.py`, `tests/test_broker_issue.py` and `tests/test_broker_ledger.py`: a
  request that differs from the approval in the prompt, model, job or a cost field is refused with its own code
  (`digest_mismatch`, `model_mismatch`, `job_mismatch`, `bad_approval`) and the vendor fake sees no request. A test that
  lists the signed fields and fails if a billable field is left out is **not built yet**.
- **Residual.** An approval binds what the client sent, not what the maintainer understood (R6).

### R5. Tampering with code, config, prices or units

- **Mitigation.** All are root-owned and read-only to the broker (`ReadOnlyPaths=`). The code is installed by root from a
  **signed annotated tag object** (a hardware key, verified against a root-owned signers file kept apart from the approval
  keys); the version is parsed from the signed tag name and cross-checked against the code, never read from a separately
  supplied file. The installer fetches the source itself, refuses any version below the root-owned monotonic version file
  (and the broker refuses to start below the root-owned floor), and shows root every packaging and build-control change and
  every added or changed dependency with its wheel file, hash and index before a typed confirmation. It installs **only
  from hash-locked wheels** (`--only-binary=:all:`, `--require-hashes`, `--no-deps`), so no build backend runs as root;
  the broker's own source is copied, not built. The release is staged read-only, verified offline (ownership, file hashes,
  units, a self-test as the broker user), activated by an atomic symlink swap, and rolled back automatically on any
  failure. `broker.yaml` is read through the ownership walk once, when the service starts (a change needs `systemctl restart
  safo-broker.service`; the switch, the allowed signers and the revocation list are the files read on every request);
  prices carry `valid_through`; caps in config can only lower the constants.
- **Verification.** `tests/test_broker_install.py`, `tests/test_broker_install_gates.py`, `tests/test_broker_floor.py` and `tests/test_broker_unit_policy.py` run installer tests against a throwaway git repository with test keys: an unsigned tag, a
  lightweight tag, a tag signed by a key that is not a release key (including an approval key), a tag name that
  disagrees with the code's version, a lower and an equal version, a downgrade with and without the explicit flag, a
  tampered hash, a dependency with only a source distribution (pip must refuse it and no build backend may run), a
  caller-supplied source path, and a broker started below the floor all refuse; failure injected at each install stage
  leaves the previous release active and the version file unchanged. `check-install` (`tests/test_broker_admin.py`) checks the
  release link and folder, the version record, the floor, the installed units against the signed release and its manifest,
  the egress helper and the switch; it does not walk every path of the system (see R16).
- **Residual.** The signed code and the wheels can still be bad: wheel code runs as the broker user, so the maintainer's
  reading of the diff and the dependency list, and the cyber-tier review, are the controls. A stolen release key whose
  PIN is known, or a maintainer who confirms without reading, defeats the gate. The first install is trust on first use of
  a reviewed tag. A build attestation, when a prebuilt artifact ships, shows which workflow built it, not that the tag was
  reviewed.

### R6. The touch for a request he did not read

- **Mitigation.** The same controls as today: the quota line printed first by the broker's own numbers, a typed
  `approve JOB`, an expiry of minutes, a signed maximum cost, one call per approval. New: the signed text carries the
  digest and size of the prompt and (for images) the model, size and count, which the screen shows. The client
  shows every signed field and the whole prompt (at most 4000 characters, escaped) before it asks for the typed confirmation. The rule stays: touch only after reading, never for a prompt you did
  not start.
- **Verification.** `tests/test_broker_client.py`: the screen test checks that every signed field, the cost, the cap, the
  digest and the image fields are on the screen before the typed confirmation. The human step cannot be tested.
- **Residual (accepted by the maintainer, reopened by any report of a surprise touch).** A tired or deceived maintainer
  approves what is shown. A compromised `approve` binary or terminal can show one prompt and sign another; the
  broker verifies the signed bytes, not what was displayed. A key with a display would close this and is not assumed.

### R7. Binary output

- **Mitigation.** The broker accepts `image/png`, `image/jpeg`, `image/webp` only, and only when the first bytes match
  the type; at most the approved count of images; at most 24 MiB each; 32 MiB for the whole vendor body. It decodes no
  pixels and uses no image library, but it walks each container from its first byte to its real end as an allow-list (see
  the design page, "Phase 2 status"), and refuses Exif, XMP, ICC profiles, C2PA, compressed text, animations, a WebP with a
  separate alpha chunk and anything appended. It sends no path or name. The client chooses the name from a fixed pattern, opens the output
  directory once and creates files relative to it with `O_EXCL|O_NOFOLLOW`, mode 0600, checks the digest, and writes a
  sidecar. Safo never opens, previews or parses an image. The briefs tell agents not to open them.
- **Verification.** `tests/test_broker_images.py`, `tests/test_broker_images_strict.py`, `tests/test_broker_images_structure.py`
  and `tests/test_broker_vendor.py`, with the fake vendor: a wrong signature for the claimed type, an unlisted type, an empty
  image, an oversized image, more images than approved and a malformed body each give a coded refusal or a dropped item and
  send no bytes to the client. Client tests: an existing target, a symlink at the target, a symlinked
  directory, a name from the reply, and a tampered attachment are all refused; modes are checked with `stat` (`tests/test_broker_imagewrite.py`, `tests/test_broker_client.py`). A static check over the import graph that no module the broker loads imports an image library is `tests/test_broker_no_image_library.py`.
- **Residual.** A valid PNG, JPEG or WebP can still carry content that harms whatever opens it, or an image that is
  wrong for its purpose. The maintainer's review is the control for what is in the picture; the brand rule is below (R15).

### R8. A call bills more than its approval

- **Mitigation.** The broker does not rely on an estimate. It **reserves the worst case** before the call and refuses
  when the reservation exceeds the signed `max_usd`, the job cap or the month room. The reservation is the input at one
  token per byte of the prompt (a true upper bound) plus a margin, plus the output cap `M` at the highest output rate,
  plus, for image calls, the vendor's documented maximum of two interim images at the image rate. The vendor documents
  `max_output_tokens` and `thinking_level` for the request (verified on the vendor's API reference, read 2026-10-30);
  the broker always sends them (the thinking level the table names for the model, or none for a model that lists no levels,
  and `M` in the signed text), and sends no
  tools, grounding, cached content, input images or thought summaries, so no other category can be billed. That the
  vendor honors `M` on image models, interim images included, is **inferred, not shown**, so until a model's cap has
  been observed (`cap_verified`) the reservation uses the model's documented output limit: 1.05 USD for Nano Banana
  2.1, 0.19 for Lite, and refused for Nano Banana 2 (2.10 USD, over the 2 USD limit of decision 13) and for Pro (a Pro-class
  model), all for a 1K image. The per-job cap is 2.50 USD in the testing phase; decision 13 does not move with it. After the
  call it reconciles the actual usage and records reserved, actual and released amounts. Any outcome the broker cannot
  establish (a crash, a timeout, a lost response, a 5xx, a redirect, missing or unusable usage) is **ambiguous**: the
  full reservation stays counted, an `ambiguous_call` row is written, and the model is suspended across restarts until
  root clears it after reading the vendor billing page. An actual above the reservation (a breach) is counted and
  suspends the model the same way.
- **Verification.** `tests/test_broker_prices.py`, `tests/test_broker_policy.py`, `tests/test_broker_pipeline.py` and `tests/test_broker_money.py`: reservation arithmetic per model and size, with `cap_verified` true and false, including the
  input bound on a prompt of single-byte-per-token worst case and the interim-image term; the refusals above;
  usage below the reservation releases the difference; usage above it records `breach` and suspends; each ambiguous case
  (crash after the spend is written, timeout, dropped connection, unreadable answer, 5xx, missing, malformed or implausible
  usage) writes `ambiguous_call`, keeps the reservation and suspends, and a restart does not clear it; the next call on
  the model is refused until root runs `clear`; a 429 and a definite 4xx do not suspend; an `M` below the image's token count is
  refused. Phase 7 observes the real cap on Nano Banana 2 Lite first (0.19 USD worst case) before any other model is
  enabled.
- **Residual.** The cap is a request to the vendor and the broker cannot force it, and a call whose result is lost may
  have been billed in full after the connection dropped. In either case **one call per model** can bill more than reserved
  before the broker, or root reading the billing page, learns of it; the suspension stops the second. **The vendor-side
  monthly spend limit is the only hard backstop for that amount, and decision 14 keeps it set.** The monthly ceiling bounds
  only what the broker can see before sending.

### R9. A stolen or lost enrolled key

- **Mitigation.** Revocation by fingerprint in a root-owned file, re-read on every request and again under the state
  lock; `require-pin` per key; two or more keys with one offline; validity windows. Revocation takes effect for approvals
  already signed. See [Gemini keys](gemini-keys.md).
- **Verification.** `tests/test_broker_approval.py` and `tests/test_broker_pipeline.py`: a revoked key's unspent approval is refused; a revocation written between `begin` and `call`
  is honored; a revoked-signers file that is missing refuses every approval.
- **Residual.** A thief with the key and its PIN can approve until the maintainer revokes; the 2.50 USD job (testing phase) and 10 USD
  month caps and the expiry bound that.

### R10. Leaks through logs, errors, dumps, listings

- **Mitigation.** The log allowlist (numbers and enumerated values only; no client text); fixed reply sentences that
  echo nothing; the key never in argv, environment or an exception message; `LimitCORE=0`, `PR_SET_DUMPABLE` off;
  `ProtectProc=invisible`; the prompt held only for the call; the ledger never holds the prompt or the quote.
- **Verification.** `tests/test_broker_server.py` (the log test) and `tests/test_broker_pipeline.py`: every failure-path test captures the log and asserts that sentinel strings placed in the
  prompt, job, quote, key, approval text and a fake vendor error body are absent from it and from the reply. Command:
  `systemctl show -p LimitCORE safo-broker.service` shows 0; a static test that no logging call takes a client string is **not built yet**; the log takes only allowlisted field names with plain values (tested).
- **Residual.** Python cannot guarantee that a copy of the key is gone from memory after use. Root can read it.

### R11. Wrong host, or a redirect carrying the key

- **Mitigation.** The host is a constant in code, not a setting; TLS verification on; no proxy variable; the checked
  address connection; redirects are refused and never followed.
- **Verification.** `tests/test_broker_runtime.py` and `tests/test_broker_pipeline.py`: a redirect is returned and never
  followed, and the call is `outcome_unknown`; the host is a constructor argument and not a config setting; a proxy variable
  has no effect.
- **Residual.** A compromised certificate authority in the system store.

### R12. Crash or power loss mid-call

- **Mitigation.** Spend is recorded and synced **before** the vendor request, so nothing replays and nothing is
  undercounted. Because a crash after that point leaves it unknown whether the request left and what it cost, recovery
  treats every unfinished call as **ambiguous**: it keeps the full reservation counted, appends `ambiguous_call`, and
  suspends the model before serving anything; only root clears the suspension, after reconciling with the vendor billing
  page. Either consumption record alone marks the nonce spent.
- **Verification.** `tests/test_broker_ledger.py`, `tests/test_broker_pipeline.py` and `tests/test_broker_admin.py`: fault
  injection between each pair of steps, then restart; the nonce is unusable, the month counts the reservation, the model
  is suspended and stays suspended after another restart, a call on it is refused, `clear` is root-only (the administration
  command), and the vendor fake saw at most one request. Documented costs: a crash before the request
  charges one reservation for nothing, and takes the model off until root acts.
- **Residual.** The lost reply is not recoverable (the broker keeps no copy), so one approval can be spent for no usable
  output. The amount actually billed after a lost connection is unknown until the billing page is read; the vendor-side
  monthly limit is the backstop.

### R13. A 429 or an error falls through, or is retried

- **Mitigation.** A 429 is `rate_limited` and final; no retry loop exists; no second tier exists for the broker; the
  client never answers a paid 429 with a free call or a second approval; the broker's own per-minute and per-day limits sit
  below the vendor's.
- **Verification.** `tests/test_broker_pipeline.py`, `tests/test_broker_server.py` and `tests/test_broker_client_system.py`:
  the fake vendor returns 429 and the test asserts exactly one request, exit 3, the nonce spent and zero cost recorded;
  `tests/test_broker_client.py` asserts that no failure falls back to the free tier and that the client source names no
  free path.
- **Residual.** None known beyond the cost of an approval spent on a 429.

### R14. Private material in a prompt

- **Mitigation.** The private-terms and secret-shape checks run in the client before `approve` and before the send; the
  broker repeats the secret-shape check; the approval binds the digest of the checked prompt; images are
  text-to-image only, so no private picture is uploaded. `--material public` stays a statement by the caller.
- **Verification.** `tests/test_broker_client.py`, `tests/test_broker_ledger.py` and `tests/test_broker_vendor.py`: a prompt
  matching a term or a secret shape is refused before `begin`; a prompt changed after `approve` is refused by the digest;
  the vendor request template carries no input image.
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

### R16. A root-equivalent door on the maintainer's account

- **Mitigation.** The maintainer reviews by hand today (the administration command `check-install` does not do this yet; its output says so, and a read-only check is **not built yet**, issue #293) and fixes or explains in writing any hit: any `sudo` rule for the
  account (`sudo -l -U`, not only `sudo -n true`), root-equivalent group membership (including `docker`, `lxd`, `disk`),
  polkit rules that grant the account actions, root-owned paths under `/etc`, `/usr/local`, `/opt` and the unit,
  cron and sudoers directories that the account can write, root-run units, timers and jobs that execute a file the
  account can write or read files from its home, and setuid, setgid or file-capability files not owned by a package.
  The design lists the review in full ("The root-door precondition").
- **Verification.** Tests of a check against a fake sudoers output, a fake group database, a temporary tree with writable
  root-run scripts and units, and a fake polkit directory are **not built yet** (issue #293). Commands on the installed
  system: `sudo -l -U LOGIN`, `id -nG`.
- **Residual (a documented, accepted risk).** The checks are partial and a snapshot. They cannot see a kernel or privileged
  service flaw, a package-owned setuid program with a local bug, a privileged socket the checks do not list, access control
  lists they do not read, a root process started later, or physical access. A clean report means "no door found by these
  checks". **If any root door exists, the broker raises the bar only for accidents and prompt-injected agents; against a
  deliberate local attacker running as the maintainer, the spend caps, single use and key confinement are advisory,** and
  the vendor-side monthly limit is the only hard backstop. The maintainer accepts this by enabling paid use.

### R17. Availability

- **Mitigation.** Connection and per-uid caps in the broker; read deadlines on every request frame and write deadlines on
  every reply frame (the 24 MiB attachment included); the paid-call slot released before the reply is written, so a client
  that stops reading cannot hold it; rate, size and time limits; one call in flight; restart limits; the free path
  unaffected.
- **Verification.** `tests/test_broker_server.py` and `tests/test_broker_deadline.py`: flood, slow-reader and slow-writer
  tests (a stalled reader is dropped and a second call proceeds).
- **Residual (accepted).** The one uid that is allowed to connect can always occupy the outstanding-nonce and `begin`
  budgets and its own connections until their deadlines. It costs no money and cannot authorize a call. The limits bound
  how long it lasts and a service restart clears it. Loss of paid use is accepted; loss of money is not.

### R18. Clock

- **Mitigation.** The broker reads its own clock; expiries are short; the nonce is single-use whatever the time; an
  issued nonce expires after 10 minutes by the wall clock, and a reservation is refused (`internal`) when the clock is
  earlier than the last ledger row. Changing the clock needs root.
- **Verification.** `tests/test_broker_ledger.py`, `tests/test_broker_month_boundary.py` and `tests/test_broker_deadline.py`: a
  clock moved backward cannot move a spend into an earlier month and a reservation is refused.
- **Residual.** A network time attack within the 60 minute maximum life of an approval.

### R19. Free and paid mixing

- **Mitigation.** Separate keys, projects and ledgers; the free key's project has billing disabled (the maintainer
  confirms once; unverified today); the free path never opens the socket; the broker never calls the free path.
- **Verification.** `tests/test_broker_client.py` (the client names no free path) and the guard test of #287 (no module
  outside the broker names the vendor host, a paid model or the key header). A free run with the broker socket absent, and with one that refuses, is `tests/test_gemini_cli.py` (the free path makes no broker connection). Command: the vendor console shows billing off for the free project (a manual step).
- **Residual.** Depends on the vendor-side setting.

### R20. State restore

- **Mitigation.** The runbook forbids restoring the state directory into a running broker; after any restore the
  maintainer reconciles with the billing page and enters the difference through the root-only `reconcile --billing-usd` before the
  switch is on again. The longest signed life is 60 minutes.
- **Verification.** `tests/test_broker_ledger.py` and `tests/test_broker_admin.py`: a chain shorter than the height record is
  refused, and `reconcile` reports it. `reconcile` does not itself enable anything.
- **Residual.** A restore by root is a root decision.

## Trust assumptions the design cannot prove

- Root, the kernel, systemd, `ssh-keygen` and the TLS store behave.
- The hardware key reports its touch and PIN flags honestly.
- The vendor bills what its page says and returns honest usage figures.
- The maintainer's account has no door to root. The installer checks for many doors and reports a clean result as "none
found"; the statement itself is accepted, not proven (R16).
- The vendor honors the output cap and thinking level the broker sends. Not shown by any page read; observed in phase 7
  before a model is trusted (R8).

## What was covered and what was not

Covered: the design in [the broker design](gemini-broker.md) read against the code in `src/safo/broker/`, `src/safo/gemini.py`,
`geminisign.py`, `modes/gemini.py`, `packaging/` and the public docs, on 2026-10-31. Not covered: an installed broker (nothing
has run on a real machine); the systemd units' behavior on a running system (only an offline lint and a transient user-unit
check were run); a real hardware key; the vendor's real text and image responses; the interaction of `MemoryDenyWriteExecute`
and the system-call filter with `ssh-keygen`; the installer against a real system; the vendor behavior under `max_output_tokens`
on image models. This model was the input to the cyber-tier review in phase 6, which is a separate step and is not replaced by it.

## Reopen this model when

A phase changes the protocol, the unit, the state layout or the signed text; the vendor changes image billing, adds a
tool the request could carry, or documents a one-time authorization for generation calls; a report of a surprise touch;
any change in who can reach root on the maintainer's machine.
