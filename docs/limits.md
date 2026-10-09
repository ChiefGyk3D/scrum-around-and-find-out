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
- **An explicit `--agents`, `--log` or `$SAFO_AGENTS` path in the current directory is the user's own choice.** Outside
  Actions it is allowed, because the person typed it. SAFO never searches the current directory for these files on its own.
  Under Actions an explicit path inside the workspace is refused.
- **The installer race is narrowed, not closed.** `safo hooks install` checks the identity of `settings.json` again just
  before it replaces the file, but pathname operations cannot make that atomic: a writer can still land between the last
  check and the rename.
- **The `gh` fallback is off under Actions.** On a laptop SAFO may use `gh auth token`; under GitHub Actions it never runs
  `gh`, and the only credentials are the App or the token you pass in.
- **Local modes are not allowed in the Action.** `usage`, `route`, `outcome`, `local` and `hooks` read files and logins on
  a person's machine; the Action refuses them before it mints anything.
