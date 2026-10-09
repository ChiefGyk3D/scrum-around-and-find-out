# Routing

> Generated from `agents.yaml` by `scripts/gen_routing.py`. Do not edit this page: edit `agents.yaml` and run
> `python scripts/gen_routing.py --write`. `safo route <shape>` applies these rules to the live headroom
> that `safo usage` measures; see [Usage](usage.md).

## Task shapes

Find the shape of the task, then take the first agent that has headroom. The reviewer is never the author.

| Shape | What it is | Prefer | Fallback | Reviewer |
|---|---|---|---|---|
| `research` | Find out how something works or what exists; no code to merge. | Codex | Claude Sonnet | Claude Sonnet, Codex |
| `plan-writing` | Turn a spec into a plan another agent can build from. | Codex, Claude Sonnet | Claude lead | Claude Sonnet, Codex |
| `integration-code` | Code that touches several files of an existing codebase. | Claude Sonnet | Codex | Codex, Claude Sonnet |
| `well-specified-code` | Code from a complete plan with the files, the change and the test all named. Haiku transcribes the plan's code exactly, its bugs included, so the review reads the plan's code as well. | Claude Haiku | Claude Sonnet | Claude Sonnet, Codex |
| `small-mechanical-pr` | A small pull request with an exact change. | Copilot coding agent | Claude Haiku | Claude Sonnet |
| `security-sensitive-design` | A design whose mistakes expose a secret or widen access. Opus only with the maintainer's OK and the reason stated. | Claude lead | none | Codex |
| `security-sensitive-code` | Code whose mistakes expose a secret, widen access or replay a mutation, including security code transcribed from a plan. Both reviews are required before merge, a Sonnet review of the diff and a Codex adversarial review; space Codex's jobs, because its five-hour window is the binding limit. | Claude Sonnet | none | Codex, Claude Sonnet |
| `ops-runbook` | A runbook or operational procedure someone will follow on a live system. | Claude Sonnet | none | Claude lead |
| `adversarial-review` | Try to break a finished change and its claims. | Codex | Claude Sonnet | Claude lead |
| `ci-log-summary` | Summarise a CI log or test output so a person or a Claude model reads ten lines, not ten thousand. | Local LLM (Ollama) | Claude Haiku | Claude Sonnet |
| `issue-triage` | Draft a triage (kind, priority, effort) for issues. Only field values a reviewer checked are applied, never the draft's verdicts. | Local LLM (Ollama) | Claude Haiku | Claude Sonnet |
| `changelog-draft` | A first draft of a changelog fragment or a commit message. | Local LLM (Ollama) | Claude Haiku | Claude Sonnet |
| `docs-proofread` | A proofreading pass over documentation: typos, broken sentences, inconsistent terms. | Local LLM (Ollama) | Claude Haiku | Claude Sonnet |
| `duplicate-issue-search` | Recommend an embedding-search route; local run does not execute embedding or similarity search. | Local LLM (Ollama) | Claude Haiku | Claude Sonnet |
| `status-headline` | An optional fixed prose clause for a status update; code renders the groups and the entire count sentence. Used only if it is one plain line whose numbers are the computed counts; otherwise the template line is posted. | Local LLM (Ollama) | none | The maintainer |
| `decision` | A trade-off, or anything that touches hardware. The lead frames the options and recommends; the maintainer decides. Opus only with the maintainer's OK and the reason stated. | The maintainer | none | none |

## When an agent is short of headroom

- Codex above 80% of the 5-hour window: use Claude Sonnet instead.
- Codex above 90% of the weekly window: use Claude Sonnet instead.
- Copilot coding agent above 70% of the month's AI credits: use Claude Haiku instead.

## The agents

### Claude lead

Plans, splits work into cards, hands out briefs, reviews results and keeps the board current.

Limits:

- plan: the Claude plan allowance, read in the client

Strengths:

- Holds the whole picture and the maintainer's standing rules.

Constraints:

- Does not merge. Opus is used only with the maintainer's OK and the reason stated.

### Claude Sonnet

The default implementer and reviewer.

Limits:

- plan: counts against the Claude plan; cheap enough to run in parallel

Strengths:

- Integration code that touches several files and an existing codebase.
- Code from prose, every task review (a review with no memory of the work), and ops runbooks.
- Builds security-sensitive code; a Codex adversarial review attacks it before merge.

Constraints:

- Needs a complete brief; does not pick its own scope.

### Claude Haiku

Mechanical code from a complete spec, and single-file edits with an exact before and after.

Limits:

- plan: negligible against the Claude plan

Strengths:

- Cheap and fast for work with no judgment in it.
- Transcribes a plan's code exactly, including the plan's own bugs: a redirect that carried the auth token to another host shipped in the plan's code and was caught in review.

Constraints:

- Anything that needs the word "decide" is not a Haiku task.
- Transcribed security code still gets a Sonnet review plus a Codex adversarial review.

### Claude Opus

A judgment problem a Sonnet agent failed twice on, or a whole-branch review of something risky.

Needs the maintainer's OK before it is used.

Limits:

- plan: burns the plan several times faster than Sonnet

Strengths:

- The hardest design judgment.

Constraints:

- Only with the maintainer's OK and the reason stated; never upgraded silently.

### Codex

Research, plans, and adversarial review of risky changes; implementation only when its window allows.

Limits:

- five hour window: percent used, read from the session files
- weekly window: percent used, read from the session files

Strengths:

- Adversarial review is a strong second reviewer: it found three real issues in one pull request.
- Adversarial review found a high-severity issue the Sonnet reviews missed on two security-sensitive changes the same day: mutation replay after an ambiguous failure, and an authenticated-scan claim with no proof of sign-in.
- Writes long plans; a plan it wrote still needs a preflight scan before anyone builds from it.

Constraints:

- Its binding constraint is the five-hour window, which reached 78% after one burst: space its jobs.
- Its sandbox cannot commit inside a git worktree or open sockets, so the lead runs the full suite and commits.
- Cannot resume a thread across git worktrees: hand it a self-contained prompt that reads state from files.

### Copilot coding agent

Small, fully specified issues and deferred minor items.

Limits:

- monthly ai credits: 7000

Strengths:

- Runs on its own and returns a pull request.

Constraints:

- Measured burn about 400 a day early in the month: spend it on small single-repo PRs.
- Every pull request needs a review gate: in the measured month every one needed fixes, one of them a functional bug its own test hid, and a reviewer caught a missing `id-token: write` that would have failed every run at startup.

### Local LLM (Ollama)

The cheapest agent: models on machines you own, and the first stop for text-in/text-out work. Cost is zero; a Claude model checks anything that will be applied.

Limits:

- cost: zero, but a shared GPU is never free: see the protected models

Strengths:

- Summaries of CI logs and test output, issue triage, first drafts of changelog fragments and commit messages, docs proofreading, and embedding-based duplicate search.
- Measured: the small 4B model gives 58 to 116 tokens a second.
- Measured: the resident 12B model generates about 50 tokens a second, and a one-sentence answer cost about 436 evaluated tokens because it thinks by default, so cheap tasks send think=false.
- Measured: the 12B model drafted a triage (kind, priority, effort) of 114 issues in minutes, at zero cost.

Constraints:

- Never a security decision, and never code that ships without review.
- Its output is a draft. Error modes seen: it misspelled repository names in ids, gave the same CVE different priorities in two repos, and asserted 'false positive' verdicts it could not verify. Only field values a reviewer checked are applied, never its verdicts.
- Send exactly the num_ctx a model is loaded with. Any other value makes Ollama reload the model and can evict another resident: a client sending 65536 to a model loaded at 131072 reloaded it.
- On a multi-GPU NVIDIA machine, Ollama's Vulkan backend ignores CUDA_VISIBLE_DEVICES and spilled models onto the wrong card until OLLAMA_VULKAN=0.
- An on-demand embedding model loads beside the resident safety model without evicting it, but only partly fits on the card: the safety model stays fully on the GPU and the embedding model sits partly on the GPU and partly on the CPU, with about 1.1 GB of VRAM left. Give it a short keep_alive and its own num_ctx, never the safety model's.
- Reachability comes and goes (the LAN at home, a zero-trust remote-access client when away): `safo route` uses it only when `safo usage` finds it reachable, and falls back otherwise.
- Real endpoints never go in this repository: put them in ~/.config/safo/agents.local.yaml, which is merged over this file and git-ignored.

Endpoints (placeholders here; real ones go in the git-ignored local file):

- `local` at `http://ollama.lan:11434`: roles general; allowed models small-4b-agent; send exactly the loaded num_ctx (small-4b-agent=8192); think off by default

### The maintainer

Decisions, bench and hardware work, and every merge.

Limits:

- time: evenings and weekends: batch the questions

Strengths:

- The only one who can decide or touch the hardware.

Constraints:

- Merges are the one gate that never moves.

## Rules of thumb

- Routing order 1: text-in/text-out work (summaries, triage, classification, first drafts, log and CI digests) goes to the local LLM first, and a Claude model checks anything that will be applied.
- Routing order 2: mechanical code from a complete spec goes to Haiku, or to Copilot when it is a small single-repo PR and credits allow.
- Routing order 3: code from prose, every task review, and ops runbooks go to Sonnet.
- Routing order 4: security-sensitive or risky code is built by Sonnet, and Codex attacks it before merge.
- Routing order 5: decisions go to the lead and the maintainer; Opus only with the maintainer's OK.
- Write the brief before choosing the agent. If you cannot write a complete one, the task is a decision or research.
- The reviewer is a different agent or model from the author, and starts with no memory of the work.
- Run agents in parallel only when their work is independent.
- Read the limits before a batch, not during it.
