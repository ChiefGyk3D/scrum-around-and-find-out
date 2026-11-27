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
safo-eval calibrate --runs ./eval-out/runs.jsonl --n 35 --out ./eval-out/cal            # sample to judge by hand
safo-eval calibrate --ingest ./eval-out/cal/calibration.json --out ./eval-out/cal         # store the verdicts
safo-eval report --runs ./eval-out/runs.jsonl --out ./eval-out --calibration ./eval-out/cal/calibration-agreement.json
```

`--out` is a directory. It gets `runs.jsonl` (one record per call, with the output and the score), `report.md` (the
per-task, per-model table and the ROUTING TABLE) and, with `--calibrate N`, `calibration.md`.

How a call is made: `llm-local --task eval-<task> --model <m> --wait 120 --envelope "<prompt>"`, stdin always
`/dev/null`, one call at a time. Exit 75 (queue busy) is retried four times with a doubling backoff, then recorded as
`busy`: not an error, and left out of the pass rate. Any other failure is recorded as `failed`, counted as not passed
and never hidden. That includes `llm-local` exit 3 (the server truncated the prompt) and exit 4 (the prompt is over the
model's input cap; see [Local LLM](local-llm.md)): the record's `error` starts with `exit 3` or `exit 4`, and there is no
output to score. `--force-size` is never passed. Tokens per second come from the `llm-local` call log (`eval_tokens / seconds`) when it is there.

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
`structure_ok` and `facts_only`. Without these, echoing the input passed 17 of the first 42 fixtures, the facts joined by spaces
24 and the facts as headings 30; with them the three shims pass 0 of the 140 (a test pins 0 per task). The template shim
`The change fixes <fact1>, <fact2>, and <fact3>` passed 6 of 6 ci-log-digest and 6 of 6 first-pass-review-comment
fixtures of that first set before the round-5 tightening and passes none now.

- **Word boundaries.** A fact must match as a whole word: 60 is not in 600, 137 not in 1370, Install not in Uninstall.
  A fact of two characters or fewer (Z, Id) is also case-sensitive. Variants are regexes: write `\b` into them.
- **Per-task structure.** issue-draft: a title line of at most 80 characters, then at least two bullets or sentences.
  pr-summary: one summary paragraph, then at least two bullets. ci-log-digest: at most six lines, no log line copied, at least 8 distinct content words that are
  neither fact words nor words of the input (`CI_MIN_NOVEL`; a short stopword list is ignored), and a causal or locator
  word or phrase (`CAUSAL`: because, caused, cause, due to, failed at, failed in, in step, at line, after, when, since,
  root cause, during, while) within 80 characters of a fact.
  first-pass-review-comment: at most three lines, at least 8 words that are not words of a fact, and the function and
  the defect class in one sentence or two neighboring sentences, the sentence that states the defect carrying a verb or
  auxiliary (`DEFECT_VERB`: is, are, will, can, may, does, never, should, must, leaks, skips, returns, ...) and no negation marker next to the defect fact (see Known limitation). doc-skeleton: a title heading, then each named section as a heading followed by a placeholder
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

A pass means the facts are present and the shape is right, not that the answer is meaningful. Code cannot read. The
tightening in the scorer raises the cost of lazy output; it does not defeat generic templates, and this page does not
claim it does. Plainly:

- (a) A trivial causal template with all the facts passes every fixture (20 of 20) of `ci-log-digest` and of
  `first-pass-review-comment` (and the same filler passes the other shape-only tasks below). The two example templates are the `shim (e)` templates in `tests/test_localeval.py`
  (`SHAPE["ci-log-digest"]`: "A generic summary of the job output goes here. It names what stopped and why, because of
  <facts>." and the review-comment template "The function <fact one> is wrong here: <the defect facts> is the defect,
  and it is a generic remark of filler."). A test keeps the count exact, so the list cannot drift.
- (b) A wrong statement that contradicts the defect can pass because code cannot judge negation or meaning: "the
  slice is fine, so there is no off-by-one" is caught only where the negation guard below sees a marker next to the
  fact, and "so there is no SQL injection risk" depends on that list. Any wording outside it passes if the facts and
  shape are there.
- (c) Therefore calibration with real verdicts is the only mitigation, and the gate is only as strong as the binding
  of those verdicts to the sampled runs (next section).

After round 5 the template sentence (`The change fixes <fact1>, <fact2>, and <fact3>.`) and the facts-only shims pass
none; shim (e) passes the number of fixtures shown for each task below (three `commit-message` fixtures carry a wrong-type
trap in `forbidden` that its `chore:` subject trips):

- `issue-draft` (20 of 20)
- `ci-log-digest` (20 of 20)
- `pr-summary` (20 of 20)
- `commit-message` (17 of 20)
- `first-pass-review-comment` (20 of 20)
- `doc-skeleton` (20 of 20; the correct answer here is the shape, so this one is expected)

`issue-triage` passes none (the JSON labels are the answer). Every one of the six tasks above needs calibration before
it can go local-only; in fact the routing rule now requires it for every cell (next section).

**Negation guard (first-pass-review-comment only).** In a sentence that holds a defect fact, an output fails
`structure` when (1) the sentence has a denial phrase (`not possible`, `cannot happen`, `can not happen`,
`impossible`, `no risk`, `no issue`, `no problem`, `not an issue`), or (2) one of the markers `no`, `correct`,
`correctly`, `safe`, `fine`, `ok`, `harmless` sits within three words of the fact (`NEGATION_MARKERS`, `NEG_WINDOW`,
`DENIAL_PHRASES`): "so there is no SQL injection risk", "SQL injection is not possible here" and "the boundary is
correct" fail. A marker is dropped when it is itself negated ("This is not safe: it leaks") or when the sentence says the
defect is present (`DEFECT_CUES`: `possible`, `remain(s)`, `still`, `leak(s)`, `vulnerable`, `exploitable`, `no escaping`,
`no guarantee`): "The query has no escaping, so SQL injection is possible" and "The fix is correct but SQL injection
remains" pass. `not`, `never` and `without` are not markers because they state defects ("never closes the file", "does
not close the file"), and `no longer` is skipped for the same reason. The guard is a word list, not understanding: it
also fails an honest "there is no parameterization" next to the fact, it misses every denial worded some other way, and a
defect cue can hide a denial that happens to use one ("there is still no risk" is caught by the phrase, "still fine" is
not).

## Calibration gate (before local-only)

A cell is one (task, model). The scorer pass rate alone can no longer route a cell to local-only:

1. `safo-eval calibrate --runs runs.jsonl --out DIR --n 35` writes `DIR/calibration.json`: up to 35 PASSING outputs
   per cell (all of them when fewer pass). The file names the sha256 of the runs file it sampled from (`runs_sha256`),
   `n` and `seed`; each entry has an `id` derived from the run (a hash of its position in the runs file, `ts`, task,
   model and the output hash, not a counter), the `output_sha256` and an empty `verdict`.
2. A person or a reviewer sets each `verdict` to exactly `ok` or `wrong` (an empty one means not judged yet). Every
   sampled entry of a cell must be judged: the sample is drawn by the tool, not chosen by the judge.
3. `safo-eval calibrate --ingest DIR/calibration.json --runs runs.jsonl --out DIR` draws the same sample again from
   the runs file (same seed) and accepts a verdict ONLY for ids in that sample whose task, model and output hash match.
   One foreign entry, a changed output or hash, a runs file whose sha256 differs, a missing `--runs`, any other verdict
   string, a duplicate id or an unknown task rejects the whole file (exit 2; the error names a count, never output
   text). A file may omit sampled entries (or leave verdicts empty); the verdicts it holds are stored, merged with the
   ones of an earlier ingest into the same `DIR` (same runs file, `n` and seed), in `DIR/calibration-agreement.json`
   together with the runs sha256, the judged entries, the sampled count per cell, the `--replace` log and an `integrity`
   field: the sha256 over the counts, the runs hash, the sample, the judged entries and the log. A verdict that differs
   from one already stored for the same id is refused (exit 2) unless `--replace` is passed; each replacement is logged
   in the file (`replaced`: id, old, new). A cell is calibrated only when EVERY entry the sample holds for it has a
   verdict: judging 35 of a 100-entry sample and dropping the other 65 reads `partial (35 of 100 judged)` and the gate
   stays closed until all 100 are judged. A cell with fewer than 35 sampled entries (fewer passing outputs) can never
   calibrate.
   Verdict and agreement files are read only when they are regular files you own with mode 0600 or 0400, never
   through a symlink; results are written 0600 in a 0700 directory.
4. `safo-eval report --runs runs.jsonl ... --calibration DIR/calibration-agreement.json` recomputes the integrity
   field and compares the runs hash with the file given to `--runs`. A mismatch (an edited agreement file, or another
   runs file) means no cell is calibrated: a loud WARNING on stderr and a CALIBRATION IGNORED line in the report, and
   the routing stays at `local-then-claude-check`. The CALIBRATION table shows the status per cell: `none` (no
   verdict), `partial (k of n judged)` (under 35 verdicts, or not every sampled entry judged), `failed` (all judged, 35 or more, but
   the ok lower bound under 0.9; the routing reason reads `calibration failed: ok lower bound 0.71 < 0.9`), `done`
   (all judged, 35 or more and the bound clears 0.9).

**Editing the runs file voids the verdicts.** The ids are positions in `runs.jsonl` plus the run's own fields, and the
agreement file names the sha256 of the file. Appending or editing any row changes that hash and the position-based ids,
so existing verdicts are void (the report ignores them loudly): draw the sample again and judge it again. An ingest into
a `DIR` holding verdicts of another runs file starts over and says so on stderr.

**What this defends against.** Mistakes (a stale file, verdicts from another run) and an agent that writes verdicts or
counts without having the sample: it cannot unlock local-only without ids that exist in the runs file. It does NOT
defend against the owner editing files: the integrity field has no key, so a solo owner who rewrites the agreement
file, recomputes the hash, or edits the runs file and re-samples can always get a pass. That is accepted for one
person. The gate is also only as good as the verdicts themselves.

A cell reaches local-only only when both hold: (a) the 95 percent Wilson lower bound of the scorer pass rate is at
least 0.9, and (b) every sampled entry of the cell is judged, there are at least 35 verdicts and the lower bound of the ok share is at least 0.9. Otherwise the
best it can be is `local-then-claude-check`. Constants: `CAL_SAMPLE_DEFAULT` 35, `CAL_MIN_VERDICTS` 35,
`CAL_MIN_LOWER` 0.9. The ok-share bound is the same two-sided 95 percent Wilson bound as the pass rate (z = 1.96,
`CAL_Z`), so 35 of 35 ok gives about 0.901 and clears 0.9. 34 of 35 ok does not, 30 of 30 ok does not (0.886), and 20 ok
with 5 wrong does not.

## Canary: catch a silent quality drop

`safo-eval-canary` (#540) runs the fixtures on the two configured local models and compares each pass rate with a stored
baseline. The models are not named on the command line: they are the two `safo-draft` models (`DRAFT_MODEL` and
`DIGEST_MODEL` in the safo-draft module), so a model change there is followed here. No host or port appears either; the calls
go through `llm-local` as in a normal run.

```sh
safo-eval-canary --update-baseline            # first run, or after a change you accept: writes the baseline
safo-eval-canary                               # every later run: compare, alert, never write
safo-eval-canary --threshold 0.05 --tasks commit-message,pr-summary --repeats 2
```

The score of a model is passed runs over scored runs. The default threshold is `0.10`: an absolute drop of more than ten
points of pass rate against the baseline is an alert. `--baseline PATH` defaults to
`~/.local/share/safo/eval-canary-baseline.json`.

| exit | meaning |
| --- | --- |
| 0 | every score is within the threshold (or the baseline was written) |
| 1 | a drop over the threshold: one `ALERT eval-canary: ...` line on stderr |
| 2 | usage, a bad threshold, or a missing, wrong-shaped, symlinked, oversized or malformed baseline |
| 3 | a server was unreachable: said so on stderr, no score is invented, nothing is written |
| 75 | the queue stayed busy after the retries: not a drop |

A busy queue (`llm-local` exit 75) is retried by the runner and then, if a model has no scored run at all, the whole
model is retried `--busy-retries` times (default 3) with a doubling wait; busy runs never count as failures. Any other
`llm-local` failure except exit 3 or 4 (the model's own truncated or over-cap runs, which count as not passed) makes
that model unreachable for the run. The baseline is read with a size cap (64 KiB), no symlink, regular file only,
duplicate keys and non-finite numbers refused, and scores must be numbers from 0 to 1. The baseline also stores a digest of the exact fixtures it was measured on; a run on a different `--tasks` selection or an edited fixture set is refused (exit 2) until the baseline is updated. `--update-baseline` writes a
new file at mode 0600 by replace, never through a symlink, and only when every model produced a score.

It is a separate entry point (`safo-eval-canary`), not `safo eval-canary`: a new `safo` subcommand needs a line in the
guard's `TOP_LEVEL_COMMANDS` tuple, which is guard code and waits for the owner's OK (same as `safo-wait-ci`).

No scheduler is installed. A systemd user timer example, as text only:

```ini
# a user service unit named safo-eval-canary
[Service]
Type=oneshot
ExecStart=%h/.local/bin/safo-eval-canary

# a user timer unit named safo-eval-canary
[Timer]
OnCalendar=weekly
Persistent=true
```

The timer also needs the usual install section of any user timer, so `systemctl --user enable --now` works.

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
  or a near miss of a number the model must copy exactly. When the input names an item as out of scope (deferred,
  untouched, not part of the change), a summary that repeats that is correct: write the pattern so it matches
  ADOPTING the item (a verb such as add, implement, include or fix near the item, with no negation or scope word in
  between), not merely naming it, keep a `correct_alts` entry that mentions it as out of scope, and a `wrong` entry
  that adopts it. Patterns stay linear (bounded windows, no nested unbounded quantifier; a test checks this).
- `required_format`: `any`, `json`, `json-object`, or `regex:<pattern>` (searched over the whole output, DOTALL).
- Everything is synthetic. Use example domains and placeholder names. No real hostnames, addresses, serials,
  callsigns or grids, employer names or session links; a test scans the shipped fixtures for these.
- Keep at least six fixtures per task (every task ships 20, so a cell can reach the local-only tier on independent
  fixtures and not on repeats of a few), and keep a few hard ones: input over 4,000 characters, a noisy log, two plausible
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
lead, not a verdict: with two repeats over twenty fixtures a task has forty scored runs per model, so one miss moves the
rate by about two and a half points, and the interval is wide. Spot-check with `--calibrate` before trusting a table, and re-run after a model or prompt
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
