# Changelog

## Unreleased

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
