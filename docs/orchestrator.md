# The orchestrator: the lead never waits

The lead session is a project manager. It decides, briefs, dispatches, reads results and answers the maintainer. It does
not stand and watch. Every wait (a CI run, a runner, a deploy, a review loop) is delegated, so the maintainer's next
message gets an answer in the turn it arrives.

## The rules

1. **The lead never waits.** CI, runner, deploy and review waits, `gh run watch`, `gh pr checks --watch`, sleeps and polling
   loops go to `run_in_background` or to a Sonnet agent whose brief has an `issue:` line.
2. **Independent steps go in one response.** Two reads, two lookups or two dispatches that do not depend on each other are
   issued together, not one after the other.
3. **The maintainer's message gets an answer in the turn it arrives.** A message that lands while an agent or a background
   command runs is answered now, from what is known, not after the wait.
4. **A hung step is reported after 5 minutes, not 20.** A step that has shown no progress for 5 minutes is a finding, not
   something to keep watching. Say so, with the evidence, and let the maintainer decide.

Sub-agents are not covered. A monitor agent is allowed to watch, because watching is its whole job; the rules are about the
lead's main thread.

## Worked example: 2026-10-25

A lead session was waiting on CI, and the runner was hung.

- The lead blocked its main thread on the hung runner for about **10 minutes**, with the maintainer waiting for answers.
- It then ran a polling loop (a `sleep` in a loop) in the foreground: **2 more minutes**, same blocking, same silence.

What was wrong was not the tools. `gh run watch` is the right tool for a monitor agent. It was the wrong thing for the
lead's thread, and a stuck step should have been reported at the 5 minute mark with the run's state, not at 12.

What the rules say to do instead:

- Start the check with `run_in_background` (one command, read the result when it exits), or dispatch a Sonnet monitor agent
  with the brief below.
- Keep working on, or answer, whatever else is open while it runs.
- If the run shows no progress after 5 minutes, report that and the evidence, then ask for a decision (re-run, cancel,
  look at the runner). Do not keep watching.

## What flags it

The `lead-waits` rule of `safo hooks guard` looks at the lead's Bash calls. It flags `gh run watch`, `gh pr checks` with
`--watch` or `-w`, a `sleep` loop, and a single sleep of 10 seconds or more, unless the call is run in the background. It
ignores sub-agents. It is a reminder and an audit trail, not a security boundary. See [safo hooks](hooks.md) for the modes,
the exemption (which always needs a stated reason), the sleep threshold and what it cannot see.

## The monitor-agent brief

A monitor agent is read-only. It watches one exact thing and reports what it saw, quoting the lines that decide the
answer. Copy the template, fill in the angle-bracket parts, and send it with `model: "sonnet"`.

```
issue: <owner/repo#N>
local-llm: n/a - waiting on and reading a run; code and shell, no text drafting

Task: watch <exact run URL or id, or exact PR number in owner/repo> and report when it finishes. Read only.

Do not push, merge, re-run, cancel, comment, approve or edit anything. Do not change any file. If the run needs one of
those, say so in the report and stop.

How: poll with `gh run view <id> --repo <owner/repo> --json status,conclusion,jobs` (or `gh pr checks <number> --repo
<owner/repo>`). Poll every 30 to 60 seconds. You may use `gh run watch`; you are not the lead.

Report when the run concludes, or when a step has shown no progress for 5 minutes. Do not wait past 5 minutes on a hung
step and do not keep polling "to see if it clears". Report it as hung.

The report has:
1. Run or PR, and the final status and conclusion.
2. For every failed or hung job: the job name, the step name, and how long the step ran.
3. The decisive log lines, quoted verbatim in a code block, with the job and step each came from. Do not paraphrase them.
   For a hung step, quote the last log line and its timestamp.
4. What you did not check. "None" only if you checked.

Return the report as your final message. No other output is read.
```

Why each part is there:

- **The exact run or PR** because "watch the CI" resolves to whichever run the agent finds first, which may be an older
  one.
- **Verbatim quotes** because a paraphrase of a failure hides the line that explains it, and the lead has to trust the
  report without re-reading the log.
- **Hung after 5 minutes** because the failure on 2026-10-25 was watching a stuck step instead of reporting it.
- **Read only** because a watcher that can re-run or cancel will eventually do it unasked.

## Measured: does the guard fire?

Not yet measured. The rule is new, and no real session has run with it installed. The line to fill in, from
`safo hooks status` once there is a week of use: how many `lead-waits` warnings, how many were a real foreground wait, and
how many were exemptions. Until then this page makes no claim about its hit rate. See
[Measurements](measurements.md) for how that page records dated results.
