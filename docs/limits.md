# Limits

Each tool meters differently, and the only honest way to plan a batch is to read the number the tool itself reports.

## Codex

Codex writes one JSONL file per session under `~/.codex/sessions/YYYY/MM/DD/`. Rows of type `token_count` carry
`rate_limits`: `plan_type`, and `primary` (the 5-hour window) and `secondary` (the weekly window), each with `used_percent`
and `resets_at`. `safo agents-status` reads the newest of these. Codex's own companion plugin records only jobs started with
`--background`, so it under-reports; the session files are the source of truth.

One measured data point (2026-10-07, Plus plan): six research and plan jobs used 29% of the 5-hour window and 10% of the
weekly one. Treat it as an order of magnitude and replace it with your own after a week of use. A later burst the same
evening took the 5-hour window to 78%: that window is the binding constraint, so space Codex's jobs.

## Copilot coding agent

`gh agent-task list` shows recent tasks (it needs a recent `gh` and a Copilot plan). Usage is metered by GitHub; read it in
the account's billing page, not from a script. One measured data point (2026-10-07): a monthly quota of 7000 AI credits and a
burn of about 400 a day early in the month, so spend it on small single-repo pull requests.

## Claude

Claude subagents live inside the lead's session and cannot be listed from a shell. Usage is read in the client. `safo` does
not guess at it; the board's cards tagged Agent = Claude are the visible record of what the subagents were given.

`safo usage` prints all of these in one place, from local files only; see [Usage](usage.md).

## Deciding to switch

- Read the limits before a batch, not during it. Multiply the number of jobs by the cost per job you measured.
- If the 5-hour window cannot hold the batch, split it across agents by routing (see [Routing](routing.md)) rather than
  waiting for the reset, unless the work is research that can sleep.
- If a weekly window is nearly spent, route to the agent with room and keep the expensive tier for what only it can do.
- Write the measured numbers into [Lessons](lessons.md) with the date. A limit nobody recorded is a limit rediscovered.

## The trust boundary of the Action

Never run untrusted code (a PR checkout, a build, a script) in the same job before the SAFO Action. With
`pull_request_target`, run SAFO in its own job with no checkout of PR code. The job/runner boundary is the trust boundary:
a same-user process from an earlier step can mutate the Action's venv or read credential-step environments.

This is a limit of composite actions, not something SAFO can close from inside one job. The Action builds its venv in a
new private directory, checks it, and runs isolated Python, which stops a hostile checkout from shadowing an import and
stops a planted venv. It does not stop a process an earlier step left running as the same user. Put the Action in a job of
its own, give that job only the permissions it needs, and let nothing untrusted run in it first. See
[Adopting](adoption.md) for the caller workflow.

## Accepted residuals

These are known, measured and left in place on purpose. Each one is written down so that nobody discovers it later and
takes it for a bug that was hidden.

- **The approval token is a speed bump, not proof.** It travels in text a model writes, so a prompt-injected model can
  forge it. `safo hooks` in `block` mode makes forgetting visible; it does not prove a person said yes. See
  [safo hooks](hooks.md), rule 2 and Known limits.
- **`safo handoff check` proves staleness, not authorship.** Every agent comments through the maintainer's account, so a
  forged report header posted from that account reads as fresh. The check reads only comments from an owner, member or
  collaborator, so a fork contributor cannot fake one, and it catches the ordinary failure (a push after the review). It
  does not prove who wrote the report, or that the review approved: FRESH means the report names the current head, and a
  `FINDINGS` verdict at that head is still FRESH. Only reports by a reviewing role count (`reviewer`,
  `adversarial-reviewer`; `--roles` changes it), and the role is read from the header the same account wrote. It is a
  speed bump like the approval token. A report must also be no older than the moment its commit became the head; with
  no force-push that moment is the commit's own `committedDate`, which its author sets, so it is a floor, not proof.
  See [Handoff](handoff.md).
- **An explicit `--agents`, `--log` or `$SAFO_AGENTS` path in the current directory is the user's own choice.** Outside
  Actions it is allowed, because the person typed it. SAFO never searches the current directory for these files on its own.
  Under Actions an explicit path inside the workspace is refused.
- **User-supplied directories are not trust-checked.** An outcomes log given with `--log` or `$SAFO_OUTCOMES`, and the
  settings directory `safo hooks install` is pointed at, are the user's choice; only SAFO's own default directories
  are checked for being private to the user.
- **The installer race is narrowed, not closed.** `safo hooks install` checks the identity of `settings.json` again just
  before it replaces the file, but pathname operations cannot make that atomic: a writer can still land between the last
  check and the rename.
- **The `gh` fallback is off under Actions.** On a laptop SAFO may use `gh auth token`; under GitHub Actions it never runs
  `gh`, and the only credentials are the App or the token you pass in.
- **Local modes are not allowed in the Action.** `usage`, `route`, `outcome`, `local`, `hooks`, `profiles` and `handoff` read files and logins on
  a person's machine; the Action refuses them before it mints anything.
- **The trust policy covers every private agents file.** A file read from a private path (the `agents.yaml` and its local
  override) must be a regular file you own, not writable by its group or by others, with no symbolic link on the way and
  only directories that are yours or root's above it. That is strict on a system where your group is private and
  directories are created group-writable; fix the modes. See [Agent profiles](profiles.md).
- **Look-alike letters and deep encodings are not caught in profile text.** The private-path and e-mail checks run on the
  text as written, with character references decoded, NFKC-normalised and after two rounds of percent-decoding. A
  confusable letter from another script in an e-mail host (a Cyrillic letter that looks Latin), or a path encoded three
  times, passes. This is a tripwire for accidents, and a person reads the generated diff.
- **The migration deadline turns CI red on 2027-01-01.** The shipped `agents.yaml` lists three agents in
  `profile_migration`, and a non-empty list is a load error after 2026-12-31. Prune the list (give the agents a profile)
  before then.
- **A repository checkout is trusted by review, not by ownership.** Its files belong to the runner, so no ownership check
  means anything there. The control is that `agents.yaml`, the persona files and the templates change only by a pull request
  with a visible diff, and that the maintainer is the code owner. A repository without that gets no protection from
  profiles against a hostile pull request.
- **The phrase list in profile text is a tripwire, not a filter.** It catches accidents and the lazy attack. A well-formed,
  plausibly cited, harmful instruction passes it, and whether a citation is relevant to its claim is a person's judgement.
- **Promotion counts are a speed bump, not proof.** Outcomes are self-reported by the lead into a file you own. The
  `promotion` settings make a thin sample visible and slow an honest mistake. They do not stop anyone who can append to
  the log from adding ten plausible records, and `safo` does not fetch the card URLs. Status stays declared in
  `agents.yaml`, a reviewed file, and the maintainer reads the evidence before accepting a change of status.
- **A resolved pointer proves the evidence exists, not that it fits the claim.** `safo profiles verify` prints each claim
  beside the lesson or the computed metric it cites so a person can judge. `safo profiles verify` checks that CODEOWNERS
  names an owner for the profile paths; it cannot see whether branch protection requires that owner's review.
- **The render digests are tamper-evidence, not a signature.** The header of each generated file carries a manifest digest
  and a body digest. They are not secret: anyone who can rewrite `agents.yaml`, the persona, the template and the generated
  files together produces a consistent set. They show a reader holding the sources that a file was edited or is stale; the
  controls are the generated diff and CODEOWNERS. See [Agent profiles](profiles.md).
- **The generator never deletes, so a stale file stays until its owner removes it.** `--write` reports a stale or
  unexpected file or directory with the `git rm` command and exits 1; `--check` reports it as drift. A header or a digest
  in a generated file is tamper evidence for a reader, not authorization to remove anything.
- **The generated files mix two audiences.** The header, the `think=false` comment and some `do`/`dont` lines address the
  caller, but the Codex and local-model files are sent whole to the model (see [Agent profiles](profiles.md)).
- **The generator narrows the output-tree race, it does not close it.** Files are opened without following links and written
  through directory descriptors with an exclusive temporary file and a rename, but another process with write access to
  `examples/harness/` can still swap an entry between the inventory and the write. The run re-resolves the output path
  from the repository root before each write and at the end and fails with "the output directory moved during the run",
  but this is best-effort detection of a rename completed before a check, it cannot prevent one and a rename racing the
  very last instructions of a run can still go unreported: a concurrent process with write access to the parent of the output
  directory (or of the repository tree itself) can move it while the generator runs, and a write in that window lands in
  the moved directory. That is an explicitly unsupported threat boundary; no lock is built. After the writes a fresh
  inventory is taken, the path is checked once more, and the inventory is compared with the render before success is reported. Run the generator on a checkout you control. CI runs it on
  a fresh checkout.
- **The privacy scan proves only the generic patterns.** CI checks home paths, e-mail addresses, private addresses and
  callsign-shaped tokens in `examples/harness/`. A private handle, an employer term or an internal hostname is caught only
  where `SAFO_PRIVACY_EXTRA_FILE` is applied, which a release that publishes the files must do ([Privacy check](privacy.md)).
- **The migration cohort and deadline are code.** The three agents allowed to have no profile, and the date that ends the
  allowance, are constants in `src/safo/agentsfile.py`. Changing them is a pull request to that file.
