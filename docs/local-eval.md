# Local LLM evaluation

`safo-eval` measures how well the local models do on the work SAFO routes to them, so routing is set by evidence and not
by feel. It scores with code only (no model grades a model), calls `llm-local` one request at a time, and ends in a
routing table with stated thresholds. Background on the local server is in [Local LLM](local-llm.md) and the routing
rules in [Routing](routing.md).

## Run it

```sh
safo-eval run --models qwen3.5:4b,gemma4:12b --tasks all --repeats 3 --out ./eval-out --calibrate 12
safo-eval report --runs ./eval-out/runs.jsonl --out ./eval-out     # rebuild report.md from a JSONL
safo-eval calibrate --runs ./eval-out/runs.jsonl --n 12 --out ./eval-out/spot-check.md
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

## Add a fixture

Add one JSON file under `eval/fixtures/<task>/`. The task type is the directory and the `task` field. Tasks:
`issue-draft`, `issue-triage`, `ci-log-digest`, `pr-summary`, `commit-message`, `first-pass-review-comment`,
`doc-skeleton`.

```json
{
  "task": "ci-log-digest",
  "input": "the text the model is given",
  "facts": ["exact string", {"text": "off-by-one", "variants": ["off.by.one", "\\+ ?1"]}],
  "forbidden": ["\\b4357\\b"],
  "max_chars": 700,
  "required_format": "any"
}
```

- `facts`: short strings a correct answer must contain (case-insensitive). A fact may list `variants`, regexes that also
  count.
- `forbidden`: regexes that must not appear. Use them as hallucination traps: a number or name that is not in the input,
  or a near miss of a number the model must copy exactly.
- `required_format`: `any`, `json`, `json-object`, or `regex:<pattern>` (searched over the whole output, DOTALL).
- Everything is synthetic. Use example domains and placeholder names. No real hostnames, addresses, serials,
  callsigns or grids, employer names or session links; a test scans the shipped fixtures for these.
- Keep at least six fixtures per task, and keep a few hard ones: input over 4,000 characters, a noisy log, two plausible
  labels settled by a rule in the input, and a number to copy exactly.
- Run `pytest tests/test_localeval.py` after adding one: it loads every fixture and checks the hygiene rules.

## Read the routing table

For each task the report takes the best pass rate of any model and applies one rule:

| best pass rate | tier |
|---|---|
| 0.9 or more | local only: `local-qwen` or `local-gemma`, whichever scored higher (a tie goes to qwen) |
| 0.6 up to 0.9 | `local-then-claude-check`: the local model drafts, a Claude model checks against the source |
| below 0.6, or no scored runs | `claude` |

The thresholds are constants in `src/safo/localeval.py` (`LOCAL_MIN`, `CHECK_MIN`, `PASS_RECALL`). A small sample is a
lead, not a verdict: with two repeats over six fixtures a task has twelve scored runs per model, so one miss moves the
rate by about eight points. Spot-check with `--calibrate` before trusting a table, and re-run after a model or prompt
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
