# Port ledger: SAFO and the portable edition

One row per SAFO item with a stated port decision for the sister project, the portable edition (the sister-project
rule is in `CLAUDE.md` and `AGENTS.md`, issue #565; this ledger is #571, under epic #518). The two are at parity on base
features and differ in application: SAFO is the maintainer's own setup, the portable edition is for an enterprise
setting where everything is configurable.

## How to read it

Decisions, and nothing else:

- **Ported**: the work exists in the portable edition's `main`. Each such row was checked against that repository on
  2026-11-27 (a file or a merged pull request is named).
- **Port as configurable**: it belongs there, an issue is filed, nothing is built yet. Thresholds, weights, models,
  paths and vendors are config values, never the maintainer's numbers.
- **Not ported**: stays SAFO-only, with the reason.
- **Proposed**: no issue there yet and no owner decision recorded; the row says what is proposed. A proposal is not a
  filing. Turn it into one of the three above when decided.

Numbers in the SAFO column are issues or pull requests in this repository. "PE #n" is an issue or pull request in the
portable edition's repository (a link is added once the rule in #573 lets this public repository name it). Rows are
added as ports land; verify a row against both repositories before changing its status.

## Ported (verified in the portable edition's `main`)

| SAFO item | Decision | Portable edition | Check |
| --- | --- | --- | --- |
| Roles and packs from the Department of Internal Arguments (`docs/personas.md`, `docs/roles.md`) | Ported | PE #5: starter set of four roles and six packs (`.claude/agents`, `.codex/agents`, `prompts/`, packs under `.agents/skills`) | merged; files present |
| Brief, report-header, handoff and decision contracts (`docs/handoff.md`, `docs/personas.md`) | Ported | PE #28, #34, #38: contracts, validators, config template | merged |
| Public-docs privacy scan, `tests/test_privacy.py` (`docs/privacy.md`) | Ported, as configurable | PE #32 (`shit/privacy.py`): generic patterns plus an optional deny list, off by default, path from config only; PE #30 closed | merged; `shit/privacy.py` present |
| Hostile-input fixtures and revert proofs as a gate (`docs/review-loop.md`, `docs/lessons.md`) | Ported | PE #40 (`tests/test_hostile.py`, `docs/hostile-revert-proofs.md`) | merged |
| Several assistants, one wrapper (Claude, Codex, Copilot; `docs/plugins.md`, `docs/routing.md`) | Ported, as configurable | PE #35: adapters for Claude, Codex, Copilot and paste-in; flags still unverified, PE #36 open | merged |
| Threat model before build (`docs/threat-model.md`) | Ported | PE #26 (`docs/threat-model.md`) | merged |
| Sister-project rule, #565, #566 | Ported | PE #41 closed by PE #42 and #47 | merged |

## Port as configurable (issue filed, not built)

| SAFO item | Decision | Portable edition | Config the port must expose |
| --- | --- | --- | --- |
| #531 pre-digest tool output: capped digest, full output saved | Port as configurable | PE #43, open | `digest_threshold_bytes`, `digest_max_output_bytes`, `digest_mode` (deterministic or local) |
| #512 `safo spend`, #538 weekly post, #558 lead curve (`docs/spend-report.md`) | Port as configurable | PE #44, open; it reports only its own numbers | weights; token counts only if an adapter supplies them |
| #489, #519 slim the fixed context, one-file instruction layout | Port as configurable | PE #45, open | `instruction_max_bytes`, `listed_roles_max`, warn or fail in `shit check` |
| #484, #488, #491, #492, #493, #507, #515 local model tier: eval harness, local-first drafts, outcome rows, model default | Port as configurable | PE #25, open; design merged as PE #27 and #33 (`docs/design/local-model-tier.md`, 32K default window) | server, model, context size and routing table all config; the draft says routes are from the maintainer's measurements and are re-measured on the install's data |
| #490 llm-local: silent truncation guard, input caps | Port as configurable | PE #25, section 5 of the design | window size from config |
| Dependency graph, queue and leases for dispatching ready work (SAFO's lead-discipline epic #445) | Port as configurable | PE #17 to #21, #7; PE #46 open; per-worker leases PE #48 | parallelism cap, routing, retry |

## Proposed (no issue in the portable edition yet)

| SAFO item | Proposed decision | Reason |
| --- | --- | --- |
| #540 weekly eval canary, #569 truncation regression probe | Port as configurable, after PE #25 lands | Needs the local tier first; interval and models from config |
| #533 keep_alive measurement | Port as a documented setting inside PE #25 | The value depends on the install's server; no number is carried over |
| #528 cap on agent hand-back report size, #529 reuse finished agents | Port as configurable | Generic to any multi-agent use; cap in bytes from config |
| #530 stable prompt prefix, #521 trim skill listing | Port as guidance in `docs/` | A practice, not code |
| #537 secret scan on briefs and reports | Port as configurable, merge with PE #32 | Same scanner, applied to brief text |
| #556 session-length nudge, #567 handoff threshold | Port as configurable, after measurement here | Not measured yet in SAFO (#567) |
| #504 track local-model share per project | Port as configurable | Counts only, read from the task log |
| #542 generated-file check before push | Port as configurable | Generic to any repo that generates files |
| #541 branch-protection drift audit | Port as configurable | Required check name and standard come from config |
| #536 Dependabot auto-merge after the 7-day hold | Port as configurable | Hold days from config; merge stays a human or lead decision |

## Not ported (SAFO-only)

| SAFO item | Reason |
| --- | --- |
| #423, #458 `safo-rmguard`, `docs/rmguard.md` | A guard for the maintainer's shared dev directories and his hooks; the portable edition ships confined storage instead (PE #9) |
| #427 to #439 pace routing by Claude weekly plan | Tied to one person's vendor plan and overage windows; the portable edition routes by configured roles |
| #438 `safo-codex-run`, #545, #553 | A wrapper around the maintainer's Codex setup; the adapters (PE #35) cover the generic case |
| Gemini broker, keys, passkeys, #467 to #477, `docs/gemini*.md` | Hardware keys, paid-vendor spend and a root-owned broker on his machines |
| #366, #375, #381, #549 shared GitHub API budget, `ghw` | His GitHub account's rate buckets |
| #479, #440, #508, #503 All Projects board reconcile, Kind writer | His boards; the portable edition keeps task state in project storage, not a GitHub Project |
| #485, #494, #534 runner-first, runner checker | His runner machines |
| #463, #398, #384 GYST re-pins | His CI standard; each repo calls GYST on its own |
| #421, #481 `exempt_authors` for Dependabot | Board rule of this repository |
| #403 SAFO activity pane | Claude Code status surface for one maintainer |
| #351 `safo-ship` merge watcher | Merge stays a human decision in the portable edition (PE #22); revisit if a team asks |
