# Claude Code plugins

The lead session is Claude Code. Two plugins let it hand work to the other agents without leaving the session: the Codex
plugin from OpenAI, and a community Ollama plugin for a local model. They are optional. SAFO works without them, and
nothing in the Action depends on them. This page is the setup, and why each one earns its place.

## Why plugins at all

[Routing](routing.md) sends a task to the agent measured best at it. Without a plugin, "send this to Codex" means leaving the
session, pasting a prompt and copying the answer back. With one it is a slash command, the job shows up in the session, and
the result lands where the lead can check it. The plugins move the work. [safo hooks](hooks.md) still decides whether a
dispatch follows the rules, and [the review loop](review-loop.md) still decides what gets merged.

## Codex

The plugin is OpenAI's `codex-plugin-cc`. It needs Node 18.18 or later and either a ChatGPT plan or an OpenAI API key.
Its usage counts against your Codex limits, so [`safo usage`](usage.md) is how to see what is left.

```
/plugin marketplace add openai/codex-plugin-cc
/plugin install codex@openai-codex
/reload-plugins
/codex:setup
```

`/codex:setup` says whether Codex is ready, and offers to install the CLI if npm is available. To do it yourself:

```sh
npm install -g @openai/codex
```

If Codex is installed but not signed in, run `codex login` from the prompt with a leading `!`.

What you get: `/codex:review`, `/codex:adversarial-review`, `/codex:rescue`, `/codex:status`, `/codex:result` and
`/codex:cancel`, and a `codex:codex-rescue` subagent.

Where it fits here:

- **Adversarial review of security-relevant code before merge.** This is the plugin's job in the measured workload: it found
  what green CI and a Sonnet review had missed ([lesson](lessons.md)). Use `/codex:adversarial-review` with focus text naming
  the risk, such as trust boundaries or credential handling. The plugin's `task` cannot pass `-c`, so it cannot select an
  access tier a security review may need; if your plan has one and the default model's filter cuts a review off, run
  `codex exec` directly with the model and `-c` setting that tier asks for ([lesson](lessons.md)).
- **Research and plan writing**, per [routing](routing.md).
- **Not for work that must commit inside a git worktree.** Codex's sandbox could not, and `--resume-last` finds threads per
  repository path. Hand it self-contained prompts, and let the lead commit ([lesson](lessons.md)).

Two measured gotchas: the companion records only jobs started with `--background`, so [`safo usage`](limits.md) reads
Codex's own session files for the rate-limit windows instead. And leave the stop-time review gate off until you have a
reason to turn it on, because it is a hook that runs a review whenever a turn stops, which is a cost nobody here has measured.

## Ollama

There is no first-party Ollama plugin, so this one is community maintained: `darrylmorley/ollama-plugin-cc`, an Ollama port
of the Codex plugin, Apache-2.0. Read it before you install it, as you would any plugin that adds hooks and runs commands.
The points that matter for a quick read:

- It adds `SessionStart`, `SessionEnd` and `Stop` hooks. The `Stop` hook is the optional review gate.
- Its network calls go to `OLLAMA_HOST` and nowhere else.
- Its agentic `rescue` runs allowlisted commands and applies patches with `git apply`.
- Models with a `:cloud` suffix run on Ollama's hosted service and send your diff context there. Pass one only on purpose.

### Setup

1. Point it at your server **before** setup. The plugin reads `OLLAMA_HOST` and otherwise assumes `127.0.0.1`, so setup on a
   machine with no local server reports "not reachable". Put the export in a shell startup file that is **not** synced to a
   repository (a synced settings file would carry your address into every commit):

   ```sh
   echo 'export OLLAMA_HOST=http://ollama.lan:11434' >> ~/.bashrc
   ```

   Replace the placeholder host with your own, open a new terminal and start Claude Code from it. A session that was already
   running will not see the change.

2. Check the server answers, with the same read-only call SAFO's own probe uses:

   ```sh
   curl -s http://ollama.lan:11434/api/tags | head -c 300
   ```

   If this hangs or is refused, the fault is the server's bind address or a firewall, not the plugin. Ollama listens on
   loopback unless `OLLAMA_HOST` on the server says otherwise.

3. Install, reload and run setup:

   ```
   /plugin marketplace add darrylmorley/ollama-plugin-cc
   /plugin install ollama@darrylmorley-ollama
   /reload-plugins
   /ollama:setup
   ```

   The marketplace registers as `darrylmorley-ollama`, which is the name `/plugin install` takes. `/ollama:setup` checks the
   server, pulls a model if there is none and sets a default. Leave the review gate off at first, for the reason above, and
   see the next section before turning it on.

### The review gate needs a fix in v0.11.0

With a default model set but no `--model`, the plugin's `task` command sends a request with no model, Ollama answers `400
model is required`, and the `Stop` hook blocks every stop with an empty `status: 1`. `/ollama:setup` reports the default
correctly, so nothing looks wrong until the first stop. It is reported upstream
([issue 1](https://github.com/darrylmorley/ollama-plugin-cc/issues/1)). Until a release fixes it, `handleTask` in the
companion script needs to resolve the model through `resolveRoleModel`, the way the planner commands do, instead of using
only the `--model` flag. A plugin update overwrites a local patch, so check the gate again after one.

What you get: `/ollama:review`, `/ollama:adversarial-review`, `/ollama:rescue`, `/ollama:status`, `/ollama:result`,
`/ollama:cancel`, a plan, execute and review pipeline (`/ollama:plan`, `/ollama:execute-plan`) and an `ollama:ollama-rescue`
subagent.

### How it sits beside `safo local run`

They overlap, and they should not be mixed up. `safo local run` is for text in, text out work (summaries, triage, drafts)
and is built around the [local model guard](local-llm.md): it sends exactly the `num_ctx` a model is loaded with and never
picks one that would evict a protected model. The plugin is for review and code tasks, and SAFO has no measurement of it yet.
Until there is one, treat its output the way [routing](routing.md) treats any local model's: a first draft that a paid model
or a person checks, and never the only reviewer of security-relevant code. Before pointing it at a server that keeps another
model resident, check which context size it requests, because any other value makes Ollama reload the model.

## Keeping the hooks honest

Both plugins add Claude Code hooks next to the ones `safo hooks install` writes, and they do not interfere. After adding a
plugin, run `safo hooks status` to confirm the guard is still healthy, and note the plugin in your outcomes log
([usage](usage.md)) the first time you route real work through it, so the next month's report has data on it.
