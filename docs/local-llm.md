# Local LLM

A local model costs nothing per call, so it is the cheapest agent in the mix. `safo local run`, the reachability probe and
the dispatch guard are built; this page is the reasoning behind them and the failure modes that shaped them. The
measurements were taken on one home Ollama server with two GPUs on 2026-10-07 and are the maintainer's, not general
results. The commands are in [Usage](usage.md) and the rules in [Routing](routing.md).

The Claude Code plugin for Ollama is covered on [Claude Code plugins](plugins.md).

## Why have one

On 2026-10-07 the maintainer noticed the local server had sat idle all day while paid quotas were burning. The rule that
came out of it: text in, text out work goes to the local model first, and a paid model only checks the result. Code,
security review and anything that changes state or carries risk stays on Claude or Codex.

## What it is good at

- **Classification and triage drafts.** A 12B model drafted kind, priority and effort for 114 issues in minutes, at no cost.
- **One-line headlines over data that is already grouped correctly.**
- **Skeletons that a paid model then checks against the source.** Summaries and digests of logs or CI output, first drafts
  of commit messages and pull request text, changelog fragments, docs proofreading.
- **Speed on short text.** The small 4B model gave 58 to 116 tokens a second; the 12B model about 50.

## What it is bad at (measured failure modes)

All from 2026-10-07, on the 12B model unless noted.

- **It misfiled facts when summarising structured data.** Given a board list in which two items were Done, it put them
  under "In progress" and "Waiting on the maintainer".
- **It ignored a word limit on long input**, missed the headline feature in a set of release notes and misnamed workflow
  files.
- **Triage verdicts it could not support.** It misspelled repository names inside ids, gave the same CVE different
  priorities in two repositories, and asserted "false positive" verdicts it had no way to verify.
- **Precise technical prose.** An implementer who tried a local draft of a technical report found it too loose and partly
  wrong. (The record does not say which model wrote that draft.)
- **Thinking costs tokens.** A one-sentence answer from the 12B model cost about 436 evaluated tokens because it thinks by
  default. Cheap tasks send `think: false`; on the 4B model the maintainer's own wrapper measured about 15 times fewer
  tokens with thinking off.

## The rule: code groups and counts, the model writes prose

Do the grouping, counting and status in code, and give the model only prose to write over a structure that is already
correct. A model asked to both sort items into statuses and describe them will do the first badly. Concretely: a script
produces the lists ("Done: these two; In progress: these three"), and the model is asked for a sentence about each list,
nothing more. Apply only what a reviewer checked, never the model's verdicts. `safo status --post` follows it (see
[Usage](usage.md)).

A related lesson about briefs: "use the local model for drafts" was skipped as optional. A brief has to name the exact step
that goes through it, such as "draft the pull request body locally and keep the draft". The guard in [safo hooks](hooks.md)
checks for exactly that.

## Reachability

A home server is not always reachable: it is there on the home network and may not be elsewhere. SAFO handles this without
guessing:

- `safo usage` probes each configured endpoint **read-only**: `GET /api/tags` and `GET /api/ps` with a 3-second timeout. It
  never calls the generate endpoint, so a probe can never load a model.
- `safo route` uses the local agent only when the probe finds it reachable, and falls back to a named Claude model
  otherwise.
- If the endpoint disappears mid-request, `safo local run` names the fallback and exits 1.
- Endpoints come from configuration, never from the repository. The shipped example uses a placeholder host; real endpoints
  live in a local, git-ignored override file. The privacy check fails on carrier-grade (VPN) addresses and on remote-access
  product names; see [Privacy check](privacy.md).

## The dispatch guard

The dangerous failure is not a wrong answer but eviction. A GPU shared with other services keeps its models resident, and
Ollama loads a new model when a request names a different model **or the same model with a different context size**, which
can push a resident out of memory. The guard exists so a convenience call can never take down a production service.

- **Allow-list.** An endpoint lists the only models SAFO may ask for.
- **Exact context.** SAFO sends exactly the `num_ctx` a resident model is loaded with. Measured: a client that sent 65536 to
  a model loaded at 131072 made Ollama reload it, and any other value, smaller included, does the same. An earlier rule of
  "8192 or less" was wrong for that reason.
- **Protected models** must never be evicted, and a safety (guard) model used by a production bot is protected and is never
  routed to. The loader refuses a configuration where an allowed model is neither protected nor declared on demand, and
  refuses a URL with credentials in it.
- **On-demand models** such as an embedding model load with a short `keep_alive` and their own context. Measured: an
  embedding model loaded beside the resident safety model without evicting it, sitting partly on the GPU and partly on the
  CPU.
- **Prefer an endpoint that is not shared with production.**
- **Multi-GPU NVIDIA hosts:** Ollama's Vulkan backend ignored `CUDA_VISIBLE_DEVICES` and spilled models onto the wrong card
  until `OLLAMA_VULKAN=0` was set. Check `/api/ps` on each instance to see where models actually live.

## Retrieval (RAG) on the free endpoint

Retrieval-augmented generation fits the endpoint that is not shared with production: embed a body of text once, find the
passages nearest a question, and have a chat model write from only those passages. It earns its place when an answer has
to trace to a source: documentation, runbooks, a decisions log, a study book, long issue and pull request history.

Measured on one 700-page book (about 1,000 chunks) with a Qwen3 embedding model on the free card and a 12B chat model on
the other:

- Embedding the whole book took minutes. A cited answer took about 5 seconds and a five-question quiz about 20.
- Keyword search (BM-25) fused with the vector ranking finds acronyms that vectors alone miss. Run both.
- **Size the embedder to coexist.** On the 8 GB card that holds the safety model, a 4B embedding model evicted it; the 0.6B
  model loaded beside it and both stayed fully on the GPU (about 1.4 GB plus 5.8 GB). Check `/api/ps` before and after the
  first run, and send the embedder its own small `num_ctx`.
- Code checks, the model writes prose. Citations must point at a passage that was retrieved, quoted evidence must appear
  word for word in the passage, and a second, independent call must pick the same quiz answer before anyone sees the
  question. The first version trusted the model's own answer index and marked two of three questions wrong, with real
  evidence quoted. Ask for the correct answer and the distractors as separate fields and let code build and shuffle the
  choices.
- A copyrighted source is indexed locally and never committed. Index the project's own documents as a separate, labeled
  source so every answer says which one it came from.

A local answer is always a draft. It is logged with zero review rounds and a Claude model reviews it before anything lands.
See also [Lessons](lessons.md).
