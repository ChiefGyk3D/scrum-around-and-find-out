# Changelog

## Unreleased

- Paid Gemini broker setup gaps (#298). The runbook last step ran the preflight as `/opt/safo-broker/current/bin/python`,
  which the installer never builds (it builds `current/venv/bin/python`): the runbook, the admin docs and a new test that
  compares every interpreter path in the runbook with the installer's own constant now agree. Nothing created the broker
  config, so the service could not start: the runbook has a new step, before the socket is enabled, that writes
  `/etc/safo/broker.yaml` (root-owned, mode 0644, atomically, refusing to replace a file) from a here-document with the
  maintainer's numeric uid inserted by `id -u` at run time; `examples/broker.example.yaml` (prices from the vendor pricing
  page read 2026-10-31, "Last updated 2026-10-30 UTC") and `examples/broker-client.example.yaml` load through the real
  loaders in tests, and a test requires the runbook text and the example to be the same. The service and the preflight now
  share one loader, `safo.broker.config`. The preflight has two new checks, `broker-config` (exists, root-owned, not group
  or other writable, loads, lists an allowed uid) and `client-config` (exists, loads; new `--client-config PATH` and `--maintainer-uid N`; the enable step passes the numeric id and the
  preflight finds the home itself, reads the file by descriptor under checked parent directories, and accepts only a
  root or maintainer owner; the example `broker.yaml` ships with an empty `allowed_uids` the loader refuses); the enable step is still last and still refuses unless the preflight passes. `docs/gemini.md`
  and its pinned phrase now say 2.50 USD per job in the testing phase. A lock timeout while the issuer takes
  `issued.lock` is now answered `busy` (it was `internal`). New tests the design promised: a seeded, bounded framing fuzz
  for the protocol and the server frame reader, a static check that nothing the broker loads imports an image library
  (allow-list over the import graph), and a free-path test with a broker socket that is absent or refuses.
- Docs: the paid Gemini broker design page and its threat model now say what the code does (#273, with #256 and #270).
  Documentation only, no code change. The 2.50 USD testing-phase job cap replaces the older 2.00 USD wording; the page lists
  the reply codes and when each is returned (`month_cap` is in the list and nothing returns it; `needs_block_approval` is the
  monthly-ceiling code), the further-block flag with no per-block limit, the monotonic version and ledger head rules as
  built, the `call_sent` row, the text and image approval field sets, `none` as the thinking level of a model without levels,
  `count` fixed at 1, the typical estimate (three bytes a token) versus the reservation (one token per byte plus 64), the
  clock-backward refusal, the pre-spend hook, the 10 minute nonce versus the approval lifetime, the slot wait, the per-peer
  limits, the 256 KiB reply frame versus the 200,000 byte answer (paid but not delivered, `internal` with the receipt), the
  image metadata refusals, the month-boundary rule, the 5 percent price-table rule, the single connect deadline, the egress
  observe mode and the order rule for the enable switch, the 300 second grace cap and 360 second stop timeout, the strict
  signers file, what `check-install` covers (the rest is issue #293), and what stays unverified. The shipped units are
  quoted in full, the unit start condition on the switch is gone from the text (decided 2026-10-31), and text for things not
  built is marked "not built yet". Threat model: each planned verification now names the test files, or says not built yet.
- Review items of the phase 6 fixes (#299), all tested red first. Second round: the broker-module route detector is bounded work (whitespace squeezed before any pattern runs, no adjacent whitespace repeats, spans capped, an over-long or over-numerous line set refused unread) and checks the guard deadline per line in the Bash check, the brief scan and the oversized-event scan; the preflight judges the mode of the signers file, the switch and the egress config by the broker's rule (any root-owned file that group and others cannot write) instead of exactly 0644; and the docs now say plainly that the terminal-only start and the text patterns are defense in depth, and list what the socket allows without a signed approval. The broker client's own module entry is now a paid
  command word like `paid`: the dispatch guard denies it in a brief (also built at run time, wrapped in `eval`,
  `bash -c` or `xargs`, imported, or started by file) and the Bash check refuses it for an agent; naming the module or its
  file in prose, or checking or reading the file, stays allowed, and `safo gemini paid` is unchanged. The module also refuses to start
  directly unless a person is at a terminal (a controlling terminal, a terminal on standard input and output, no
  startup variable), so a spelling the text patterns miss still does not run for an agent; script paths are read after
  collapsing repeated slashes and dot and parent segments, and a `-m` value ending in `client` counts while the broker
  is named. The oversized-event
  scan treats it the same way, and the guard's test shape list now has an exact count with no skip. The preflight's
  allowed-signers check and its key-to-name link call the broker's own parser, so a file the broker refuses cannot pass
  the readiness check. `check-install` reads the egress config by the helper's rules (a duplicate key, a missing or bad
  host, an unknown line or a bad mode fail), with one shared table of cases run through both readers.
- Paid Gemini: the in-process paid path is deleted and the broker is the only way to a paid call (#287). Removed from
  `safo.gemini` and `safo gemini`: the paid branch of `ask`, the approval store and its records, the local `approve` and
  its dry run, the paid spend counter and quota line, the paid key read, the root-owned in-process paid switch, the
  `usage` action, and the `paid_config`, `signing`, caps, `price_source`, `price_checked` and `paid` settings of
  `gemini.yaml` (a file that still has one is refused; the new optional `image_models` list names paid-only models the free
  tier must refuse). `ask --paid`, `--approval`, `--cap` and `approve` are still parsed, only so the dispatch guard keeps
  reading them as paid steps, and the command refuses them. New: `safo gemini paid` (one paid call through the broker
  client) and `safo gemini paid-dryrun` (sign a throw-away text in the dry-run namespace and ask the broker to verify it:
  no call, no charge); the wrapper hands only these two actions the signing variables and a standard input. The dispatch
  guard now denies every paid step (it no longer looks up an approval record) and recognizes `paid` and `paid-dryrun`
  as paid actions. A test fails if any module outside `safo.broker` (other than the free-tier module and the guard's own
  deny patterns) names the vendor host, a paid model or the key header. Broker client: `run_dryrun`.
  Also in this change: the image writer takes the stricter reading of its contract (output directory mode 0700 exactly,
  an optional `expected_sha256` checked before anything is written, and `write_receipt_file` for the exclusive 0600
  `reviewed: false` sidecar, which the client now uses); the wrapper's startup-variable refusal also runs as the first
  statement of `safo.cli.run`, and the docs say precisely what it covers and what it cannot (the installed script starts
  a plain interpreter; the launcher follow-up is #267); the preflight's hardware-key check passes only when the visible
  key matches an enrolled signer (new `--key-file`), and a visible device alone is a warning; and the docs now say
  that `broker.yaml` is read once when the broker starts (a change needs a restart), while the switch, the allowed signers
  and the revocation list are read on every request. The paid API key exists only in the broker's credential.
  Migrating an existing config: the schema change means a `gemini.yaml` that still has the dropped keys
  (`price_source`, `price_checked`, `secrets.paid_config`, `caps`, `paid`, and `signing`) is refused when it loads, so
  remove them first (the signing key and principal move to `broker-client.yaml`). A helper for this exists outside the
  repository on the maintainer machine.
- Paid Gemini broker, phase 6 review items for install and units (#288): the broker unit now waits 360 seconds to stop
  (above the longest drain, which the config now caps at 300 seconds, so a stop no longer kills a call before it is
  recorded); the release signers file accepts only exact hardware key lines with `namespaces="git"` (no
  `cert-authority`, no other option, no principal list or pattern) and a signature made through a certificate is refused;
  the egress helper treats a missing `MODE` as drop, the preflight reports the egress mode and fails when the enable
  switch is being created (`--enabling`) or exists while the mode is observe, unless `--ack-observe-mode` is passed after
  an empty observe log through a full dry run, and the runbook gains a last step that creates the switch only if that
  preflight passes and says to switch to drop after the first clean real call at the latest; `check-install` now also
  checks the installed unit files against the signed release and its manifest, the release version file, the egress
  helper and the switch, and says which root-door checks it does not do (the docs are corrected to match). Paid use stays
  disabled.
- Paid Gemini broker, accounting and transport hardening (#289): a call that straddles the UTC month boundary now counts
  in the month it was reserved in and also in the later month it ended in (and, while open, at its reservation), so the
  new month's cap sees it; a price table whose per-image figure disagrees with its token price (above it, or more than
  5 percent below it) is refused at load; and the call deadline now covers the name lookup and every connect attempt
  (each attempt gets the time left, no address is tried after the deadline, a late connection is closed before any byte
  is sent). The pinned HTTP(S) connections take an optional deadline; without one they behave as before. Paid use
  stays disabled.

- Paid Gemini broker, administration command (#262): `python -I -m safo.broker.admin` with `status`, `usage`,
  `check-install`, `clear` and `reconcile`, run by root. It reads the root-owned files, then drops to the service user
  (groups emptied, group, user, read back, regain probe) before opening the ledger, so the ledger's owner rule is
  unchanged; it refuses to start unless Python is isolated. `clear` prints the call records, needs the typed call ids,
  settles an ambiguous call at its whole reservation unless root names a verified amount with a reason, and records the
  uid and time in a new `admin_action` ledger row. `reconcile` reports mismatches and can only raise a month. Paid use
  stays disabled.
- Paid Gemini broker, phase 5 (#261): the systemd units and the installer, none of it run on a real machine yet. New
  `packaging/systemd/` socket and service units for a dedicated unprivileged user (strong sandboxing, an encrypted
  credential for the paid key, the root-owned switch as a start condition), `packaging/broker-requirements.txt` (hash-locked
  wheels), `packaging/safo_broker_install.py` (`safo-broker-install`: dry run by default; verifies a signed annotated tag against a
  root-owned signers file; wheels only, with hashes required; floor and monotonic version checks; a staged, read-only,
  manifest-checked release activated by an atomic symlink swap; automatic and manual rollback; never touches the state
  directory), `safo.broker.floor` (the broker refuses to start below the root-owned version floor) and `safo.broker.runbook` (the one-time root setup as copy-paste lines with blast radius and rollback, printed
  and never run). Also an egress control for the service user (an nftables table, a refresh timer, a hosts view and a files-only name
  service configuration; observe mode first), a fixed unit policy the installer enforces, a real self-test of the staged
  release, a hardware-key requirement for release signers and a trusted-interpreter check. Paid use stays disabled.
- Gemini enrollment preparation (#263): `docs/gemini-enrollment.md`, a copy-paste maintainer runbook (enroll one or two
  FIDO2 keys for approvals, a pass or fail table for testing a second device, a separate release-signing key, the
  root-owned allowed-signers lines with the namespace restriction, rotate and revoke), each step with its blast radius,
  rollback and expected output, and every command and flag checked against the vendor pages on 2026-10-31 (unverified
  items are marked). `src/safo/gemini_preflight.py` is a read-only preflight (`python -m safo.gemini_preflight`): ssh sk
  support, libfido2, the udev rule, a visible hardware key, the allowed-signers file (root, 0644, namespace on every
  line), the enable switch, the service user and the state directory modes. It writes nothing, makes no network or
  vendor call, and prints no key or file content. It is not wired into `safo gemini` yet. Paid use stays disabled.

- Tests: the random-output tests in `tests/test_protection.py` no longer depend on chance (#247). `_random_token` draws only from `secrets.randbelow`, and the tests inject a scripted or seeded source (and spy on the default one) instead of hoping two real draws differ or that a statistic stays under a bound.
- Gemini wrapper hardening (#221): `safo gemini` refuses to run when an interpreter startup variable (`PYTHON*`) or a shell startup variable (`BASH_ENV`, `ENV`) is set, then re-runs itself as `python -I -m safo` by the absolute interpreter path, with an allow-list environment (fixed PATH, locale and temporary directory; the secret-store token for `ask` only, the signing variables for `approve` only), no shell, no inherited descriptor above 2 (standard input only for `approve`), the `safo` package that launched it pinned first on the import path, and a fresh private working directory; the child verifies its own environment and directory instead of trusting the interpreter flag, and the mode is read by the real parser. No signing provider library or askpass program is passed on. Proxies, `LD_*`, `XDG_*` and the other secret-store variables no longer reach the wrapper. See `docs/gemini.md`.
- CI: the security workflow's pip-audit now audits `requirements-passkey.txt` as well as `requirements.txt`, and `tests/test_workflows.py` fails when a hash-locked runtime requirements file at the root is left out of the audit (#216).
- Paid Gemini broker, phase 4a (#260): `src/safo/broker/imagewrite.py`, the client's safe image writer, with no socket
  or protocol dependency. `write_image` takes the type from the first bytes (png, jpeg, webp; 24 MiB by default), makes
  the file name itself from a restricted stem, a random suffix and a fixed extension, opens the output directory
  component by component with `O_NOFOLLOW | O_DIRECTORY`, writes through a 0600 temporary file relative to the
  directory descriptor, `fsync`s, links it into place without replacing anything and leaves no file behind on any
  failure. `default_output_dir` makes a private 0700 directory under the user state directory, and `print_summary`
  prints one line without opening the image. Paid use stays disabled.
- Paid Gemini broker, phase 1 (#205): the core library under `src/safo/broker/`. Integer micro-dollar arithmetic and the
  worst-case reservation (prompt bytes plus 64 tokens at one token per byte, the output cap, two interim images), the
  per-job cap (2.50 USD in the testing phase) and monthly ceiling (10 USD), the model allow-list with Pro and Nano Banana
  Pro refused, the call state machine, schema version 3 approval and ledger records parsed strictly, and a ledger that
  records the spend before a call is sent and recovers any interruption as ambiguous or settled. No socket, service or
  vendor call: paid use stays disabled. `Ledger` in `gemini.py` gains `append_many` and an overridable empty-ledger
  hook, and `valid_quote` is shared; the existing behavior is unchanged.

- Paid Gemini broker, phase 2 (#258): the call pipeline in `src/safo/broker/`, tested against a fake vendor with no
  socket and no key. Approval verification runs `ssh-keygen -Y verify` through the existing fixed-argument verifier with
  the namespace fixed in code, requires the canonical signed text and the signer named inside it, and checks revocation
  again under the ledger lock just before the spend. `begin` issues broker-chosen nonces (at most four outstanding). A
  call reserves the worst case before anything is sent, builds the request from a fixed template, sends through an
  injected transport, and settles from the reported usage; a timeout, transport error, redirect, 5xx, short, oversized
  or malformed answer, a reply for another model or unusable usage leaves the call ambiguous and the model suspended
  until root clears it. A reply over the signed output cap is a breach, recorded at the cap or the reported usage
  (whichever is higher), and suspends the model. Image replies accept only PNG, JPEG or WebP: the container is walked to
  its real end (an allow-list of segments and chunks, each with a body of exactly its shape; one image, no trailing data, no
  animation, checksums and exact decoded size where the format has them, no Exif, XMP or compressed metadata), the declared size is capped, and nothing but the checked bytes is passed on. Review fixes: the approval must come from a hardware key with a
  touch (no software opt-in in the broker path); the issued record binds the maximum, the ceiling flag, the ledger head
  and the creation time; a model with an unverified output cap is refused above 2 USD whatever the job cap is; a
  temporary file left in `issued/` by a kill no longer stops `begin` or the start-up flush. `CallLedger.settle` gains `cap_breach` and `reserve` gains a
  `pre_spend` hook. Paid use stays disabled.

- Paid Gemini broker, phase 4b (#260): the thin client, `src/safo/broker/client.py`, run as `python3 -I -m
  safo.broker.client`. It checks everything it can alone, asks the broker for `begin`, builds the signed approval text,
  shows the person that text (every signed field, the cost, and the whole prompt, escaped), signs through the existing
  `ssh-keygen -Y sign` signer, sends one `call` and reads one reply, maps every reply code to an exit status and one safe
  message, refuses a reply whose receipt does not name the request, never retries a call that may have been sent and never
  falls back to the free tier. The socket path comes from a root-owned or user file, never from the environment, and must
  be a root-owned socket. Images go through a writer with the phase 4a signature (the phase 4a writer when it is in the tree, else a
  small marked adapter) and are never opened or parsed. Not yet wired into `safo gemini`; paid use stays disabled.
- Paid Gemini broker, phase 3 (#259): the socket server in `src/safo/broker/`, tested over socketpairs and a temporary
  unix socket against the fake vendor, with injected clocks and no network. `protocol.py` is the wire format on its own
  (length-prefixed frames, the 1 MiB request and 256 KiB reply limits, a versioned envelope, strict field tables, one
  fixed sentence per reply code; a thin client imports it unchanged). The core code list gains `rate_limited`,
  `vendor_refused` and `outcome_unknown`. `server.py` takes the descriptor systemd passes (exactly one listening unix
  stream socket for this pid, else it refuses), checks the peer uid with `SO_PEERCRED` against the root-owned list,
  reads one request under a whole-frame deadline, runs the operations (`status`, `begin`, `call`, `check`, `dryrun`),
  writes one reply and closes. It fails closed: a malformed request changes no state and makes no vendor call. It
  enforces the connection caps, per-peer rate limits, one paid call in flight (released before the reply is written)
  and per-minute and per-day call budgets, checks the root-owned switch on every request, logs numbers and enumerated
  words only, and on SIGTERM lets calls in flight finish and records any still open after the grace period as
  ambiguous. `python -I -m safo.broker` wires it: the epoch, switch, key and `broker.yaml` readers, no-core and
  not-dumpable hardening, a scrubbed environment, the checked HTTPS transport to the vendor, and recovery before the
  first accept. The stop wakeup is a pipe, not a socket pair, so the unit's address-family or system-call filters never touch it; `scripts/broker_sandbox_check.py` (with an opt-in pytest wrapper, `SAFO_SANDBOX_CHECK=1`, that skips with its reason otherwise; every step has a timeout and the check a total deadline) runs the real start-up flow as a socket-activated user unit under the unit's hardening properties, in error-number and kill modes and with `~socketpair` filtered, and fails for an injected socket, socketpair or recvmsg call. Paid use stays disabled.

- Tests: the guard emit-first tests no longer depend on machine load (#251). The real-process children run with a
  generous scaled budget (15 s) and an event-driven wait of 90 s on the test side, and no assertion compares an elapsed
  time with the budget any more; what they prove is the behavior (the one complete JSON line, the exit status 0 or 2,
  the process ending by itself with the blocked call still blocked, no post-delivery step started after an overrun, the
  budget counted from the process start). The in-process tests use the injected clock, or a call that blocks until the
  test releases it, instead of a stopwatch, and the order of the budget points is checked as arithmetic for any host
  timeout. Nothing was skipped, and the guard is unchanged.
- Tests: the linear-time guard in `tests/test_gemini_constructs.py` counts executed lines instead of reading a clock, so machine speed, load and Python version cannot flip it; its negative case runs a quadratic brace scan (#248).
- Gemini approvals: hardened what a signed paid approval binds (#217). Approval payload version 2 carries a prompt digest
  (`prompt_sha256`, `prompt_bytes`) on both approval tiers; `approve` shows the digest and the whole prompt (approvals are refused above 4000 characters), the paid gate
  recomputes it from the prompt it is about to send and refuses on any mismatch, missing digest or older payload version,
  and the passkey verifier takes it through its `expect` mapping. Approvals from before this change are refused with a
  clear message. The approval display and binding are hardened further: the prompt is snapshotted once and checked again at the send boundary. Every request field and approval argument is copied once through base types at the entry (exact types only).
  Paid use stays disabled.
- Threat model for SAFO as a whole (#228): `docs/safo-threat-model.md` (assets, actors, trust boundaries, 25 ranked risks,
  each with a mitigation marked verified or inferred, a verification and a residual risk) and the OWASP Threat Dragon file
  `docs/threat-model/safo.threat-dragon.json`. The paid Gemini broker keeps its own model. Linked from the README, the wiki
  home and `docs/threat-model.md`; the wiki page is `Safo-threat-model`. `tests/test_safo_threat_model.py` keeps the page,
  the file, the links and the named tests in step.
- Action: the trust the Action places in its caller is hardened. A credential (the secret-manager fetch, a literal
  `private-key` and the `token` input) is now used only on an event the preflight positively classifies as trusted:
  `push` to the default branch or a tag, `schedule`, `workflow_dispatch`, `issues` and `workflow_run` on the default
  branch, `pull_request` from this repository, and `pull_request_target`. Any other event, and any value the preflight
  cannot read, is refused with a message naming the event. The board file and the status-body file are read from the
  revision the caller binds (new input `trusted-ref`, default the commit the run is on), from git and not from the
  working tree, and a path that leaves the tree or goes through a link is refused. The preflight prints the event, the
  ref and the trusted revision it used. The `dry-run` description now says the read-only token applies to the App path.
  What a caller must change: check the repository out before the Action in any job that passes `board-file` or
  `status-body-file` (the files must be committed, regular files, and the checked-out commit must be the trusted one);
  add `trusted-ref: ${{ github.sha }}` to say so explicitly (optional); keep credentials off events other than the
  listed ones; for a pull request from a fork under `pull_request_target`, set the new input
  `allow-fork-pull-request-target: "true"` on that job; and for a repository that is itself a fork, set
  `allow-fork-repository: "true"`. The preflight now runs before the credential-masking step, which waits for its
  verdict. Details: `docs/action.md`.
- Docs: the design and threat model for the Gemini paid-path broker (#205): a small unprivileged system service behind a
  socket unit that holds the paid key, the approval consumption records and the spend ledger, verifies the signed
  approval and makes the vendor call, with image generation as the first case. Documents only; no broker code, and
  paid use stays disabled.
- Gemini Tier 2: real WebAuthn assertion verification (ES256 and EdDSA) with the `cryptography` package, an optional
  hash-locked extra (`safo[passkeys]`). Opt-in; nothing in the approval path calls it and paid use stays disabled (#211).
- Guard: a dedicated entry point, `safo-guard` (and `python -m safo.guard`), so the hook never parses subcommands
  (#189). It reads only `--agents` and `--agents-local`, ignores every other word, and always computes the verdict.
- `safo hooks install` writes the new hook command and migrates an existing `safo hooks guard` line on a rerun.
  `safo hooks status` reports the installed form (new, legacy, mixed, absent) and takes `--settings`.
- Lines `safo hooks guard ...` already installed keep the frozen legacy routing. Re-installing the live hook is a
  separate, explicit step after the release.
