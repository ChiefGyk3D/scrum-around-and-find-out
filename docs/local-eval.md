# Local LLM evaluation

`safo-eval` measures how well the local models do on the work SAFO routes to them, so routing is set by evidence and not
by feel. It scores with code only (no model grades a model), calls `llm-local` one request at a time, and ends in a
routing table with stated thresholds. Background on the local server is in [Local LLM](local-llm.md) and the routing
rules in [Routing](routing.md).

## Run it

```sh
safo-eval run --models qwen3.5:4b,gemma4:12b --tasks all --repeats 3 --out ./eval-out --calibrate 12
safo-eval report --runs ./eval-out/runs.jsonl --out ./eval-out     # rebuild report.md from a JSONL
safo-eval report --runs ./eval-out/runs.jsonl --out ./eval-out --rescore   # re-score stored outputs, no model call
safo-eval calibrate --runs ./eval-out/runs.jsonl --n 30 --out ./eval-out/cal            # sample to judge by hand
safo-eval calibrate --ingest ./eval-out/cal/calibration.json --out ./eval-out/cal         # store the verdicts
safo-eval report --runs ./eval-out/runs.jsonl --out ./eval-out --calibration ./eval-out/cal/calibration-agreement.json
```

`--out` is a directory. It gets `runs.jsonl` (one record per call, with the output and the score), `report.md` (the
per-task, per-model table and the ROUTING TABLE) and, with `--calibrate N`, `calibration.md`.

How a call is made: `llm-local --task eval-<task> --model <m> --wait 120 --envelope "<prompt>"`, stdin always
`/dev/null`, one call at a time. Exit 75 (queue busy) is retried four times with a doubling backoff, then recorded as
`busy`: not an error, and left out of the pass rate. Any other failure is recorded as `failed`, counted as not passed
and never hidden. Tokens per second come from the `llm-local` call log (`eval_tokens / seconds`) when it is there.

## What is scored

Per run, by code: fact recall (share of the fixture's `facts` found in the output), forbidden hits (each is a failure),
the format check and the length bound. A run passes when recall is 0.8 or more, there are no forbidden hits, the format
is valid and the output is within `max_chars`. The table shows pass rate, mean recall, median latency, tokens per second,
the number of runs with a forbidden hit, and the busy and failed counts.

Code fences: for `json` and `json-object` formats the scorer strips exactly one outer markdown code fence (an opening
line of three backticks with an optional language tag, a closing line of three backticks, only whitespace outside)
before the strict JSON check. Text before or after the fence, an unclosed fence, or a second fence still fails the
format check. Each run records `fenced: true` when a fence was stripped, and the report shows the fenced share per task
and model next to the pass rate. A model with a fenced share above 0 passes only because of the strip, so a downstream
consumer of its output must strip one outer fence too. `report --rescore` recomputes every stored output with the
current scorer, without calling a model, and writes `report-rescored.md` and `runs-rescored.jsonl`.

## Hardened scoring (what stops copying and loose matches)

A run passes only when every check below holds; the record keeps `reasons` (which checks failed), `copy_ratio`,
`structure_ok` and `facts_only`. Without these, echoing the input passed 17 of 42 fixtures, the facts joined by spaces
24 and the facts as headings 30; with them the three shims pass 0 (a test keeps each at most 1 of 6 per task). The template shim
`The change fixes <fact1>, <fact2>, and <fact3>.` passed 6 of 6 ci-log-digest and 6 of 6 first-pass-review-comment
fixtures before the round-5 tightening and passes none now.

- **Word boundaries.** A fact must match as a whole word: 60 is not in 600, 137 not in 1370, Install not in Uninstall.
  A fact of two characters or fewer (Z, Id) is also case-sensitive. Variants are regexes: write `\b` into them.
- **Per-task structure.** issue-draft: a title line of at most 80 characters, then at least two bullets or sentences.
  pr-summary: one summary paragraph, then at least two bullets. ci-log-digest: at most six lines, no log line copied, at least 8 distinct content words that are
  neither fact words nor words of the input (`CI_MIN_NOVEL`; a short stopword list is ignored), and a causal or locator
  word or phrase (`CAUSAL`: because, caused, cause, due to, failed at, failed in, in step, at line, after, when, since,
  root cause, during, while) within 80 characters of a fact.
  first-pass-review-comment: at most three lines, at least 8 words that are not words of a fact, and the function and
  the defect class in one sentence or two neighboring sentences, the sentence that states the defect carrying a verb or
  auxiliary (`DEFECT_VERB`: is, are, will, can, may, does, never, should, must, leaks, skips, returns, ...). doc-skeleton: a title heading, then each named section as a heading followed by a placeholder
  line. commit-message and issue-triage keep their `required_format`.
- **Copy cap.** The share of the output that is copied from the input, as the larger of the share of lines of four or
  more words found verbatim in the input and the share of 8-word shingles found in the input, may not exceed 0.5
  (`COPY_CAP_DEFAULT`; issue-triage is exempt because a JSON answer restates labels by design). Failure reason `copy`.
- **Facts only.** An output where fewer than 30 percent of the tokens are words that are not fact tokens is the facts
  strung together, not an answer (`FACTS_ONLY_MIN`; issue-triage exempt). Failure reason `facts-only`. This differs
  from counting words outside the input too, which would reject honest short answers made of input words.
- **Must-copy values are facts.** A value an input says must be copied exactly (the version in doc-skeleton/05-exact) is
  a required fact. For doc-skeleton a fixture may list `sections`: the facts that must be headings (default: every
  fact), so a fact such as a version does not have to be a section name.
- **Valid alternatives.** A fixture may list `correct_alts`, valid answers worded differently; a test asserts every one
  passes, and the `wrong` lists must still fail. Add the reviewer's valid wording whenever a correct answer fails.
- **Known-wrong outputs.** Every fixture lists at least two `wrong` outputs; a test asserts none passes. Add the wrong
  answer a model gave whenever the scorer let one through.

Result files are owner-only: the output directory is created with mode 0700 and every file (`runs.jsonl`,
`report.md`, `calibration.md`, the rescored files) is written with mode 0600, an existing file is chmodded, and a
symlink as the target is refused.

Every run record carries `ts` (UTC) and `hour_utc`, and `busy_retries` (exit-75 answers seen). The report ends with a
TIME OF DAY table: pass rate and median latency per 4-hour UTC bucket per model, with n; a bucket under 10 scored runs
says `too few` and no rate. Older records without `ts` show under `unknown`.

## Known limitation: what a pass means

A pass means the facts are present and the shape is right, not that the answer is meaningful. The scorer cannot read:
a shim that writes the required shape with generic filler words and then the facts (shim (e) in the tests) still passes
these tasks, because the shape is the whole content of the check. After round 5 the template sentence and the
facts-only shims pass none; shim (e) passes 6 of 6 fixtures of each task below (a test keeps the count exact, so the
list cannot drift):

- `issue-draft` (6 of 6)
- `ci-log-digest` (6 of 6)
- `pr-summary` (6 of 6)
- `commit-message` (6 of 6)
- `first-pass-review-comment` (6 of 6)
- `doc-skeleton` (6 of 6; the correct answer here is the shape, so this one is expected)

`issue-triage` passes none (the JSON labels are the answer). Every one of the six tasks above needs calibration before
it can go local-only; in fact the routing rule now requires it for every cell (next section).

## Calibration gate (before local-only)

A cell is one (task, model). The scorer pass rate alone can no longer route a cell to local-only:

1. `safo-eval calibrate --runs runs.jsonl --out DIR --n 30` writes `DIR/calibration.json`: up to 30 PASSING outputs
   per cell (all of them when fewer pass), each with an `id` and an empty `verdict`.
2. A person or a reviewer sets each `verdict` to exactly `ok` or `wrong` (an empty one means not judged yet).
3. `safo-eval calibrate --ingest DIR/calibration.json --out DIR` reads the verdicts and stores the agreement per cell in
   `DIR/calibration-agreement.json` (ok and wrong counts, ok share, Wilson interval). Any other verdict string, a
   duplicate id or an unknown task is an error. Verdict and agreement files are read only when they are regular files
   you own with mode 0600 or 0400, never through a symlink; results are written 0600 in a 0700 directory.
4. `safo-eval report ... --calibration DIR/calibration-agreement.json` applies the rule and shows a CALIBRATION table
   with the status per cell: `none` (no verdict), `partial` (under 20), `done` (20 or more).

A cell reaches local-only only when both hold: (a) the 95 percent Wilson lower bound of the scorer pass rate is at
least 0.9, and (b) there are at least 20 verdicts and the lower bound of the ok share is at least 0.9. Otherwise the
best it can be is `local-then-claude-check`. Constants: `CAL_SAMPLE_DEFAULT` 30, `CAL_MIN_VERDICTS` 20,
`CAL_MIN_LOWER` 0.9. The ok-share bound is one-sided (z = 1.645, `CAL_Z`), because only the low side matters for a
"good enough" claim; with the two-sided 1.96 used for the pass rate, 30 of 30 ok gives 0.886 and would never clear 0.9
(35 of 35 would). With the one-sided bound, 30 of 30 ok clears it and 29 of 30 does not; 20 ok and 5 wrong does not.

## Add a fixture

Add one JSON file under `eval/fixtures/<task>/`. The task type is the directory and the `task` field. Tasks:
`issue-draft`, `issue-triage`, `ci-log-digest`, `pr-summary`, `commit-message`, `first-pass-review-comment`,
`doc-skeleton`.

```json
{
  "task": "ci-log-digest",
  "input": "the text the model is given",
  "facts": ["exact string", {"text": "off-by-one", "variants": ["off[- ]by[- ]one"]}],
  "forbidden": ["\\b4357\\b"],
  "max_chars": 700,
  "wrong": ["a plausible answer with a wrong number"],
  "required_format": "any"
}
```

- `facts`: short strings a correct answer must contain, as whole words (case-insensitive). A fact may list `variants`,
  regexes that also count.
- `wrong`: at least two outputs that are plausible but wrong; none may pass.
- `forbidden`: regexes that must not appear. Use them as hallucination traps: a number or name that is not in the input,
  or a near miss of a number the model must copy exactly.
- `required_format`: `any`, `json`, `json-object`, or `regex:<pattern>` (searched over the whole output, DOTALL).
- Everything is synthetic. Use example domains and placeholder names. No real hostnames, addresses, serials,
  callsigns or grids, employer names or session links; a test scans the shipped fixtures for these.
- Keep at least six fixtures per task, and keep a few hard ones: input over 4,000 characters, a noisy log, two plausible
  labels settled by a rule in the input, and a number to copy exactly.
- Run `pytest tests/test_localeval.py` after adding one: it loads every fixture and checks the hygiene rules.

## Read the routing table

For each task the report takes the best model by the lower bound of the 95 percent Wilson interval of its pass rate
(the `95% CI` column shows the whole interval) and applies one rule to that lower bound, so a cell with few runs cannot
qualify on luck: two passes out of two has a rate of 1.00 but a lower bound of about 0.34.

| best lower bound | tier |
|---|---|
| 0.9 or more, and calibrated | local only: `local-qwen` or `local-gemma`, whichever scored higher (a tie goes to qwen) |
| 0.9 or more, not calibrated | `local-then-claude-check` |
| 0.6 up to 0.9 | `local-then-claude-check`: the local model drafts, a Claude model checks against the source |
| below 0.6, or no scored runs | `claude` |

The thresholds are unchanged (0.9 and 0.6); only what they are applied to changed. Reaching a 0.9 lower bound takes
about 40 clean runs in a cell, and local-only also needs the calibration above, so most cells land in the check tier
until the sample and the verdicts grow.

The thresholds are constants in `src/safo/localeval.py` (`LOCAL_MIN`, `CHECK_MIN`, `PASS_RECALL`). A small sample is a
lead, not a verdict: with two repeats over six fixtures a task has twelve scored runs per model, so one miss moves the
rate by about eight points, and the interval is wide. Spot-check with `--calibrate` before trusting a table, and re-run after a model or prompt
change.

## How the table drives enforcement

The table is meant to be read by the things that already route work, not by a person each time:

- **Brief templates.** A brief for a task type names the tier the latest table gives it: `local-qwen` or `local-gemma`
  means the brief names the exact local step (see the guard in [safo hooks](hooks.md)); `local-then-claude-check` means
  the brief names the local draft and the Claude check; `claude` means no local step is required.
- **The local-first wrapper.** The wrapper that logs local calls can read the same table and refuse or warn when a task
  type rated `claude` is sent to a local model, and when a task rated `local-*` is sent to Claude without a reason.
- **Evidence trail.** Each table is built from a `runs.jsonl` that is kept, so a routing decision can be traced to the
  runs that justify it.

This page does not change any guard or config file; wiring the table into enforcement is a separate change.
