# Usage, routing and outcomes

These commands turn "which agent should do this?" from a feeling into a measurement, and `safo hooks` makes Claude Code
hold the lead to the answer. None of them dispatches anything: the lead reads the answer and decides.

```sh
safo usage                          # what each agent has used and has left
safo route research                 # which agent should take a task of this shape, and why
safo outcome add --agent codex --shape research --review-rounds 1 --note "..."
safo usage --report                 # the month, from the outcomes log
safo local run --shape ci-log-summary --prompt-file log-summary.txt
safo hooks install                  # make Claude Code enforce the routing rules (warn mode first)
safo hooks status                   # the guard mode and what it has logged
```

## What stays on your machine

`safo usage` reads files and runs commands on this machine, read-only, and sends nothing about your sessions anywhere.
Its only network requests are the two it cannot avoid, both made with your own logins:

- `gh agent-task list` (and, only with `--billing`, one billing read) asks GitHub for your Copilot tasks. `safo` never asks for
  a broader token scope on your behalf; if the token cannot read the billing endpoint the answer is `unknown`.
- A read-only probe of each Ollama endpoint you configured: `GET /api/tags` and `GET /api/ps` with a 3-second timeout. It never
  calls `/api/generate`, so a probe can never load a model.

## Where the numbers come from

| Agent | Source | Gives |
|---|---|---|
| Codex | `~/.codex/sessions/**/*.jsonl`, the `token_count` rows | `plan_type`, the 5-hour window (`primary`) and the weekly one (`secondary`) as percent used with `resets_at`, and per-session token totals |
| Claude Code | `~/.claude/projects/**/*.jsonl`, subagent transcripts included | Messages and tokens per model family (Opus, Sonnet, Haiku), de-duplicated by message id |
| Copilot | `gh agent-task list`; optionally the billing endpoint | Sessions this month; exact premium requests only if the token may read billing |
| Ollama | `GET /api/tags`, `GET /api/ps` | Reachable or not, installed models, loaded models |

A half-written last line (an agent is still writing) is skipped. A Codex window whose reset time has passed is reported as
unknown rather than as stale usage. `--json` prints the same data for a script; the exit code is always 0.

## Routing

`safo route <shape>` applies the rules in `agents.yaml` (see [Routing](routing.md), generated from it) to the live headroom:

- An agent over a threshold is skipped and the reason printed (Codex above 80% of its 5-hour window goes to Claude Sonnet;
  Copilot above 70% of its month goes to Claude Haiku).
- A reviewer is chosen who is not the author and is not short of headroom.
- Unknown headroom never blocks; it is printed.
- The output ends with the value to put on the card's Agent field.

The routing order the shapes in `agents.yaml` encode, as measured on 2026-10-07 evening (first match wins; replace it with
your own measurements):

1. Text-in/text-out work (summaries, triage, classification, first drafts, log and CI digests) goes to the local LLM first,
   and a Claude model checks anything that will be applied.
2. Mechanical code from a complete spec goes to Haiku, or to Copilot when it is a small single-repo PR and credits allow.
3. Code from prose, every task review, and ops runbooks go to Sonnet.
4. Security-sensitive or risky code: Sonnet builds it, and Codex attacks it before merge.
5. Decisions go to the lead and the maintainer; Opus only with the maintainer's OK.

## The local LLM

An Ollama endpoint is the cheapest agent and the least safe to use carelessly: a GPU keeps models resident for other services,
and asking for any other model, or for the same model with any other `num_ctx`, makes Ollama load something and can evict a
resident. So an endpoint lists the models `safo` may ask for, the `num_ctx` each resident model is loaded with
(`loaded_num_ctx`), a default `think` setting and its `protected_models`; `safo route` and `safo local run` never send a
request that would load a different model or use a different `num_ctx` (a cap applies only on an endpoint with no protected
models), use an endpoint only when the probe finds it reachable, never route to a guard model (the safety model of a production bot), and prefer an endpoint that
is not shared with production. If nothing fits, or the endpoint goes away mid-request, nothing is sent elsewhere: the command
names the fallback and exits 1.

Real endpoints never go in the repository. `agents.yaml` carries placeholders (`ollama.lan`); put the real ones in
`~/.config/safo/agents.local.yaml` (git-ignored), which is merged over it key by key.

Measured on 2026-10-07 evening, on two GPUs with an endpoint pinned to each card: a 16 GB card keeps a resident 12B general
model (`num_ctx` 131072) and a resident small 4B agent model (`num_ctx` 8192), and an 8 GB card keeps a resident safety model
(`num_ctx` 8192) that a moderation bot uses in production. All three are protected. The small model gives 58 to 116 tokens a
second; the 12B model generates about 50 tokens a second, and one sentence cost about 436 evaluated tokens because it thinks by
default. Cheap tasks send `think: false`, which is the endpoint default here. On a multi-GPU NVIDIA machine, Ollama's Vulkan
backend ignores `CUDA_VISIBLE_DEVICES` and spilled models onto the wrong card until `OLLAMA_VULKAN=0`.

An on-demand embedding model (`embed-small` here) loads on the 8 GB card beside the resident safety model without evicting it.
Measured: the safety model stays fully on the GPU, and the embedding model sits partly on the GPU and partly on the CPU, with
about 1.1 GB of VRAM left. It is loaded with a short `keep_alive` and its own `num_ctx`, never the safety model's.

Short-text shapes (commit-message drafts, CI-log and test-output summaries, changelog fragments) are pinned to the small 4B
model at its own `num_ctx`; long ones (issue triage, docs proofreading) use the 12B model. If your local file replaces the
endpoint list and a pinned model is missing, the shape falls back to the endpoint's first allowed model and `safo route` and
`safo local run` print a warning instead of failing.

A rule, 2026-10-07: code does the grouping and the counting, and the local model only writes prose over a structure that is
already correct. A model that miscounts or regroups puts a wrong number or the wrong card under the maintainer's name, and
a draft is cheap to check only when the structure is not the model's. `safo status --post` follows it: the groups and the
counts come from the board's fields and code renders the count sentence. The model sees four counts and no titles; it may
append only one exact approved prose clause, or nothing.

A local answer is a draft. It is logged with zero review rounds and a Claude model reviews it before anything lands. It is
never used for a security decision or for code that ships without review. The 12B model drafted a triage (kind, priority,
effort) of 114 issues in minutes, at zero cost, and also misspelled repository names in ids, gave the same CVE different
priorities in two repos, and asserted "false positive" verdicts it could not verify: apply only the field values a reviewer
checked, never its verdicts.

## The outcomes log

One JSON line per finished task: `date`, `card` (a GitHub URL or null), `agent`, `shape`, `review_rounds` (review passes, the
passing one included), `findings` by severity (`critical`, `important`, `minor`, `unrated`), `tokens` and `requests` when
known, and a one-line `note`. `safo outcome add` appends one after checking it. `safo usage --report` summarises a month per
agent: tasks, how many needed fixes, review rounds, findings, tokens. [Lessons](lessons.md) cite it.

The seed, [examples/outcomes-2026-10.jsonl](../examples/outcomes-2026-10.jsonl), is one measured day.

## Enforcing routing with hooks

A rule that the lead has to remember is a rule that gets forgotten when the day is busy, so `safo hooks` makes Claude Code
enforce the routing rules in `agents.yaml` instead. `safo hooks install` adds two hooks to a Claude Code `settings.json`,
keeps the ones already there and is safe to run again. A session-start probe asks each local LLM endpoint what is loaded and
tells the session whether it is reachable. A guard runs before every Agent dispatch and checks the brief:

- An explicit `model` is set.
- A model that `agents.yaml` marks `approval_required` (Opus, in the shipped file), or a model the guard cannot identify
  (`inherit`, an unrecognised name), comes with the approval token from the
  `hooks` section of `agents.yaml` in the brief, which the maintainer adds only after saying yes.
- While the local LLM was reachable at session start, the brief names a local step (`safo local run` or `llm-local`) or
  says `local-llm: n/a - <reason>`.

Start in warn mode, the default: the guard reports a broken rule and lets the dispatch go. After a few days of reading
`safo hooks status` and `safo agents-status`, switch with `safo hooks mode block`, and the guard denies a dispatch that breaks
a rule. The guard is a speed bump and an audit trail, not a security boundary: whoever writes the brief can type the token, so
the token is not proof of approval (see [safo hooks](hooks.md) for the details and the known limits).
It logs the decision, the model and the rules broken, never the brief, and a hook that hits an error of its own lets the
dispatch through, because a broken guard that blocks work is worse than none.
