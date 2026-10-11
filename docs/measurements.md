# What the first month measured

Dated 2026-10-11. Every figure here is aggregated, and the date and window sit beside it. Nothing names a project,
a repository other than this one, a machine or a path.

## How to read this

These are one maintainer's numbers from a single machine, read at one moment: 2026-10-11 around 15:18 UTC, from the
output of `safo usage --no-local --json` (and one local probe for the model section). They show what the meters
report, not what any agent costs. Usage meters move while you read them: a window that has just reset reads low, one
that is mid-job reads high. [Usage, routing and outcomes](usage.md) says how to collect your own figures; replace these
with them.

## Claude Code, last 7 days (read 2026-10-11)

Window: the 7 days to 2026-10-11, 796 transcript files, de-duplicated by message id.

| Family | Messages | Output tokens | Cache-read tokens | Output tokens per message |
|---|---|---|---|---|
| Haiku | 667 | 22,208 | 61,120,550 | 33 |
| Opus | 2,215 | 2,330,747 | 118,245,982 | 1,052 |
| Sonnet | 12,805 | 3,656,428 | 3,082,321,739 | 286 |
| Other | 4 | 2,093 | 324,715 | 523 |

Opus is small by message count (2,215 of 15,691, about 14%) and large per message: about 1,052 output tokens a message,
roughly 3.7 times Sonnet's 286 and 32 times Haiku's 33. Its share of output tokens is about 39% (2,330,747 of
6,011,476). Sonnet carries almost all of the cache reads (3.08 billion of 3.26 billion), which is the long, repeated
context of a lead session; that is volume, not output.

The Claude meter read nothing at first. It did not read the usage fields that Claude Code nests inside its transcript rows (issue #24). PR #26 fixed that, and v0.1.2 shipped the fix. So the Claude figures in
[Lessons](lessons.md) that predate it were counted from transcripts by hand, not by the meter; the table above is the
first set the tool produced itself.

## Codex Plus (read 2026-10-11)

In the 7-day window the local session files held 227 sessions and about 95.2M input tokens, of which about 89.5M were
cached input. At the time of reading the plan showed 11% of the weekly window and 67% of the 5-hour window. The two
percentages are the account's, not a sum of the sessions, and `safo` reports a window whose reset time has passed as unknown.

One earlier datapoint is in `examples/outcomes-2026-10.jsonl`: on 2026-10-07, Codex stood at 14% of its weekly window and
56% of its 5-hour window after about 27M input tokens, across research, a 3,400-line plan, a review and one
implementation task. The 5-hour window was the binding limit that day, which is why its jobs are spaced.

## Copilot (October 2026, read 2026-10-11)

43 sessions in October. Premium requests are unknown: the token `safo` uses cannot read billing, which is by design (it
never asks for a broader scope than it was given, and `--billing` is opt in). A session count is exact; a credit count
needs the billing endpoint.

## The routing guard, warn mode (since 2026-10-09, read 2026-10-11)

The `safo hooks` guard on the Agent tool, in warn mode: 53 dispatches since 2026-10-09, 50 allowed and 3 flagged, one
each for approval, no local step and no model. Models named: Sonnet 50, Opus 2, none 1. Seven briefs named a local step
and 45 were marked not applicable.

This is a soak, not a finding. Two days of one maintainer's dispatches show that the guard runs, fails open and flags
what it is meant to flag. They do not show that it changes behaviour, that the flagged cases were mistakes, or that
the not-applicable marks were honest. The approval token is also a speed bump, not proof of approval (see
[hooks](hooks.md)). The counts cover retained history only.

## The local model (read 2026-10-11)

The local Ollama endpoint was reachable. Twelve models were installed, from about 4B to 14B parameters, and two were
loaded at the time: one in the 12B class and one in the 4B class. The endpoint and model names are left out on purpose.
The probe is `GET /api/tags` and `GET /api/ps` only, so reading it never loads anything. What the local model is good
and bad at is in [Local LLM](local-llm.md).

## What is not measured yet

- **Cost against rework, per agent and model.** The outcomes log is where it would come from, and the real log is
  empty. PR #27 added the `model` and `credits_used` fields to it, so the data can now be recorded, but none has been.
  Until it has entries, "which agent is cheapest for a shape" is a routing opinion, not a measurement.
- **Whether the guard changes anything.** See the soak caveat above.
- **Copilot premium requests.** Unknown without a token that can read billing.
- **The items still to come from issue #23:** profiles, promotion of a rule from a lesson into the routing file, and
  metrics computed from the outcomes log. They are specified and in review (PR #29), not built.

## Where the review evidence is

The rounds, findings and fixes from the build are in [The review loop](review-loop.md) and [Lessons](lessons.md). They are
not restated here.
