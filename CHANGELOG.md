# Changelog

## Unreleased

- Gemini wrapper hardening (#221): `safo gemini` refuses to run when an interpreter startup variable (`PYTHON*`) or a shell startup variable (`BASH_ENV`, `ENV`) is set, then re-runs itself as `python -I -m safo` by the absolute interpreter path, with an allow-list environment (fixed PATH, locale and temporary directory; the secret-store token for `ask` only, the signing variables for `approve` only), no shell, no inherited descriptor above 2 (standard input only for `approve`), the `safo` package that launched it pinned first on the import path, and a fresh private working directory; the child verifies its own environment and directory instead of trusting the interpreter flag, and the mode is read by the real parser. No signing provider library or askpass program is passed on. Proxies, `LD_*`, `XDG_*` and the other secret-store variables no longer reach the wrapper. See `docs/gemini.md`.
- CI: the security workflow's pip-audit now audits `requirements-passkey.txt` as well as `requirements.txt`, and `tests/test_workflows.py` fails when a hash-locked runtime requirements file at the root is left out of the audit (#216).
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
