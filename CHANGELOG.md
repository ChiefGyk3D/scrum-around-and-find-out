# Changelog

## Unreleased

- Gemini approvals: hardened what a signed paid approval binds (#217). Approval payload version 2 carries a prompt digest
  (`prompt_sha256`, `prompt_bytes`) on both approval tiers; `approve` shows the digest and the whole prompt (approvals are refused above 4000 characters), the paid gate
  recomputes it from the prompt it is about to send and refuses on any mismatch, missing digest or older payload version,
  and the passkey verifier takes it through its `expect` mapping. Approvals from before this change are refused with a
  clear message. The approval display and binding are hardened further: the prompt is snapshotted once and checked again at the send boundary. Paid use stays disabled.
- Gemini Tier 2: real WebAuthn assertion verification (ES256 and EdDSA) with the `cryptography` package, an optional
  hash-locked extra (`safo[passkeys]`). Opt-in; nothing in the approval path calls it and paid use stays disabled (#211).
- Guard: a dedicated entry point, `safo-guard` (and `python -m safo.guard`), so the hook never parses subcommands
  (#189). It reads only `--agents` and `--agents-local`, ignores every other word, and always computes the verdict.
- `safo hooks install` writes the new hook command and migrates an existing `safo hooks guard` line on a rerun.
  `safo hooks status` reports the installed form (new, legacy, mixed, absent) and takes `--settings`.
- Lines `safo hooks guard ...` already installed keep the frozen legacy routing. Re-installing the live hook is a
  separate, explicit step after the release.
