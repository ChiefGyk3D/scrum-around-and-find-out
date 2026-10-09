# Lessons

Each entry: what happened, the evidence, and the rule the code or the playbook holds now. Dates are when it was learned.
Add one whenever something costs more than ten minutes to find out. An entry marked **test** has a test that fails if
the rule is broken.

## 2026-10-05..07 (the first week of running a board with agents)

### Editing a field's options through the API wipes the values

- **What happened.** `updateProjectV2Field` with `singleSelectOptions` on an existing single-select field replaced every
  option with a new id.
- **Evidence.** Every item's value for that field was gone afterwards, because the stored value is the old option id.
- **Rule now.** `safo` never sends `updateProjectV2Field`. `bootstrap` creates a field that is missing, with its options,
  and for an existing field that lacks an option it prints the UI step that adds one safely. **test**

### `gh api --paginate` needs `$endCursor`

- **What happened.** A paginated GraphQL query returned the first page again, or only the first page.
- **Evidence.** `gh api --paginate` finds the next page only if the query declares a variable named `$endCursor` and uses it
  in `after:`.
- **Rule now.** Every connection of 50 or more declares `$endCursor: String`, uses `after: $endCursor` and selects
  `pageInfo { hasNextPage endCursor }`; the client follows the cursor and stops if GitHub repeats one. **test**

### Roadmap date fields and view grouping are UI-only

- **What happened.** A view's Roadmap date fields, its zoom, and its Group by could not be set through any mutation.
- **Evidence.** No field of `ProjectV2View` accepts them.
- **Rule now.** `board.yaml` has a `ui_only` list; `bootstrap` prints it as a checklist and `audit` repeats it.

### `createProjectV2View` takes no filter

- **What happened.** A view created with a filter in the input was rejected.
- **Evidence.** The input type has no `filter`.
- **Rule now.** A view is created with its layout, then `updateProjectV2View(viewId, filter)` sets the filter. **test**

### An organization project cannot be linked to a personal repository

- **What happened.** A personal-account repository could not be linked to an organization project.
- **Evidence.** The link is refused across owners; adding the repository's issues by node id still works.
- **Rule now.** `repositories` may list a repository of any owner; `reconcile` covers it without linking. **test**

### Fresh items lag in listings, so discover and verify identities before writing

- **What happened.** An item just added was missing from the project's item listing for a while.
- **Evidence.** `addProjectV2ItemById` returns the item's node id at once; the listing catches up later; the project's
  `items.totalCount` is current.
- **Rule now.** Discover the content's project item before adding, preserve its nonblank fields, and verify the returned item id through the content connection. `items.totalCount` is supporting evidence, never proof of an individual add. Do not rely on a
  listing. A run that follows another before the listing catches up still verifies. **test**

### Pull-request events cannot reach a secret store whose identity does not cover them

- **What happened.** Board sync failed on pull-request events while issue events worked (GYST issue 93).
- **Evidence.** The OIDC identity's allowed subjects covered the default branch but not the `pull_request` subject, so the
  secret fetch was refused for that event.
- **Rule now.** Either cover the `pull_request` subject for that one narrow key, or let pull requests reach the board
  through the scheduled `reconcile`, which needs no event.

### Codex's plugin records only background jobs

- **What happened.** `agents-status` through the Codex companion showed nothing for jobs that were running.
- **Evidence.** The companion records only jobs started with `--background`; Codex's own session files record every one.
- **Rule now.** Read `~/.codex/sessions/**/*.jsonl`, whose `token_count` rows carry `rate_limits`. **test**

### The first measured Codex Plus usage

- **What happened.** Six research and plan jobs ran in one sitting.
- **Evidence.** They used 29% of the 5-hour window and 10% of the weekly one (Plus plan, 2026-10-07).
- **Rule now.** Plan a batch from a measured cost, and replace this number with your own. See [Limits](limits.md).

### Codex cannot resume a thread across git worktrees

- **What happened.** `task --resume-last` answered "No previous Codex task thread was found for this repository" and ran
  nothing.
- **Evidence.** Threads are found per repository path, and a git worktree is a different path.
- **Rule now.** Hand Codex a self-contained prompt that reads its state from files; never rely on resume across worktrees.

### A pull request with a merge conflict gets no checks at all

- **What happened.** "No checks reported" on a pull request, and closing and reopening did nothing (GYST issue 114).
- **Evidence.** A conflicting pull request has no merge ref, so no `pull_request` run starts.
- **Rule now.** When no checks are reported, read `mergeable` first. See [Handoff](handoff.md).

### REST cannot clear a bypass-force-push list

- **What happened.** A repository was flagged "force pushes allowed", and a REST `PUT` of `allow_force_pushes: false`
  returned 200 and still reported it enabled.
- **Evidence.** The rule had `allowsForcePushes: false` but a `bypassForcePushAllowances` entry; the REST field folds the
  bypass list in, so REST cannot clear it.
- **Rule now.** Clear it over GraphQL: `updateBranchProtectionRule(allowsForcePushes: false, bypassForcePushActorIds: [])`.
  `scripts/apply-baseline.sh` reads the rule back over GraphQL and fails if force pushes are still possible. **test**

### Read a file at another ref with `git show`, not `git checkout`

- **What happened.** Checking out another ref in a shared checkout to read one file left it on a detached HEAD.
- **Evidence.** The checkout was restored by hand.
- **Rule now.** `git show origin/main:path/to/file`. Never move a shared checkout to read from it.

## 2026-10-07 (routing, measured; the data is `examples/outcomes-2026-10.jsonl`)

### Every Copilot pull request needed fixes

- **What happened.** Four pull requests from the Copilot coding agent, all small and specified.
- **Evidence.** All four needed fixes; one was a functional bug that the pull request's own test hid. By that day 40 Copilot
  sessions had run in the month.
- **Rule now.** A Copilot pull request always goes through a Claude review before it merges; `agents.yaml` lists that as the
  reviewer for the small-mechanical-pr shape.

### A plan Codex wrote needed a preflight scan

- **What happened.** Codex wrote a 3,400-line plan.
- **Evidence.** A preflight scan found 21 conflicts and 19 defects before anyone built from it.
- **Rule now.** Scan a plan against the code and the spec before the first task starts; review it as you would code.

### Codex's adversarial review is a strong second reviewer

- **What happened.** Codex was asked to try to break a shared-workflow change.
- **Evidence.** It found three real issues in one pull request.
- **Rule now.** The adversarial-review shape goes to Codex first, and security-sensitive design is reviewed by it.

### Codex's sandbox cannot commit inside a git worktree

- **What happened.** An implementation task from a complete plan finished in Codex's sandbox but could not be committed there.
- **Evidence.** It passed review after one fix round once the lead ran the full suite and committed.
- **Rule now.** The lead runs the full suite and commits Codex's work. Related: it cannot open sockets either, so a test that
  needs a loopback server runs outside the sandbox.

### A local thinking model spends hundreds of tokens on one sentence

- **What happened.** A one-sentence answer from the resident 12B model on a 16 GB card.
- **Evidence.** About 50 tokens a second, and about 436 evaluated tokens because the model thinks by default.
- **Rule now.** Cheap local tasks send `think: false`, which is the endpoint default in `agents.yaml`.

### Asking a shared Ollama server for another model evicts a resident one

- **What happened.** A GPU shared with other services keeps its models resident.
- **Evidence.** Requesting any other model loads it and evicts one of them.
- **Rule now.** An endpoint lists the only models `safo` may ask for and its protected models; `agents.yaml` refuses to load if
  an allowed model is not protected, and `route` and `local run` never send a request that would load another. **test**

### Any num_ctx other than the loaded one reloads the model (2026-10-07 evening)

- **What happened.** The endpoints were reorganised onto two GPUs, each pinned to its own card: a 16 GB card with a resident
  12B general model at `num_ctx` 131072 and a resident small 4B agent model at `num_ctx` 8192, and an 8 GB card with a resident
  safety model at `num_ctx` 8192 that a moderation bot uses in production. All three are protected.
- **Evidence.** A client that sent 65536 to the model loaded at 131072 made Ollama reload it. The old rule, "8192 or less",
  allowed any smaller value, and every value other than the loaded one does this.
- **Rule now.** Send exactly the `num_ctx` a resident model is loaded with (`loaded_num_ctx` in `agents.yaml`). Any other
  value, smaller included, is refused before a request is sent. **test**

### Ollama's Vulkan backend ignores CUDA_VISIBLE_DEVICES (2026-10-07 evening)

- **What happened.** On a machine with two NVIDIA cards, each Ollama instance was pinned to one card with
  `CUDA_VISIBLE_DEVICES`.
- **Evidence.** Models spilled onto the wrong card until `OLLAMA_VULKAN=0` was set.
- **Rule now.** On a multi-GPU NVIDIA machine set `OLLAMA_VULKAN=0`, then check `/api/ps` on each instance to see which
  models are resident where.

### An embedding model can load beside the guard (2026-10-07 evening)

- **What happened.** An embedding model (`embed-small` here) was loaded on demand on the 8 GB card that keeps the resident
  safety model for a moderation bot.
- **Evidence.** The safety model stayed fully on the GPU and was not evicted. The embedding model sat partly on the GPU and
  partly on the CPU, with about 1.1 GB of VRAM left.
- **Rule now.** The embedding model is listed as on demand, with a short `keep_alive` and its own `num_ctx`. An embedding
  request never carries the safety model's `num_ctx`, and the safety model stays protected and is never routed to. **test**

### A local model's triage is a draft (2026-10-07 evening)

- **What happened.** The resident 12B model drafted a triage (kind, priority, effort) of 114 issues.
- **Evidence.** It took minutes and cost nothing; the small 4B model gives 58 to 116 tokens a second. The 12B model also
  misspelled repository names in ids, gave the same CVE different priorities in two repos, and asserted "false positive"
  verdicts it could not verify.
- **Rule now.** Text-in/text-out work goes to the local model first, and its output is a draft: only field values a reviewer
  checked are applied, never its verdicts. The `issue-triage` shape names a Claude reviewer.

### Codex's adversarial review found what the Sonnet reviews missed (2026-10-07 evening)

- **What happened.** Two security-sensitive changes were each reviewed by Sonnet and then attacked by Codex the same day.
- **Evidence.** Codex found a high-severity issue the Sonnet reviews missed on each: mutation replay after an ambiguous
  failure, and an authenticated-scan claim with no proof of sign-in. One burst of Codex jobs took its 5-hour window to 78%.
- **Rule now.** Security-sensitive or risky code is built by Sonnet and attacked by Codex before merge (the
  `security-sensitive-code` shape). Codex's five-hour window is its binding constraint, so space its jobs.

### Haiku transcribes a plan's bugs along with its code (2026-10-07 evening)

- **What happened.** Haiku transcribed a plan's code exactly, as asked.
- **Evidence.** A redirect that carried the auth token to another host shipped in the plan's code and was caught in review.
- **Rule now.** Mechanical code from a complete spec goes to Haiku, and transcribed security code still gets a Sonnet review
  plus a Codex adversarial review. The plan is part of what is reviewed.

### Copilot's quota is credits, and a reviewer still caught a startup failure (2026-10-07 evening)

- **What happened.** The Copilot quota was measured as 7000 AI credits a month, not the 300 premium requests first assumed.
- **Evidence.** The burn was about 400 a day early in the month. A reviewer caught a missing `id-token: write` that would have
  failed every run at startup.
- **Rule now.** Spend the credits on small single-repo pull requests, and keep the review gate on every Copilot pull request.

### Code does the grouping and the counting; the model writes prose (2026-10-07)

- **What happened.** `safo status --post` had to decide who builds a status update that is posted under the maintainer's name:
  the code or the local model.
- **Evidence.** The same day's triage by the 12B model misspelled repository names in ids, gave one CVE two priorities in two
  repositories and asserted verdicts it could not verify. A model that does that to ids and priorities will do it to groups
  and counts.
- **Rule now.** Code groups and counts the cards from the board's own fields. The model sees only four counts, never a card
  title, and may append only one exact approved prose clause. Code renders the count sentence from the computed mapping.
  **test**

### The routing order is local first, Opus last (2026-10-07 evening)

- **What happened.** The measured results above were put in one order.
- **Evidence.** Text work was cheap and good enough as a draft locally, mechanical code was safe to transcribe, and the
  expensive review (Codex) found what the cheaper one missed on risky code only.
- **Rule now.** Local LLM for text-in/text-out work, Haiku or Copilot for mechanical code from a complete spec, Sonnet for code
  from prose, every task review and ops runbooks, Sonnet plus Codex for security-sensitive code, and the lead and the
  maintainer for decisions, with Opus only with the maintainer's OK. It is in `agents.yaml` and [Routing](routing.md).
