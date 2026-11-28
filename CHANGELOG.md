# Changelog

## Unreleased

- The shell guard now unconditionally denies a command containing both a decoder and a shell or interpreter (#645),
  independent of order, wrappers, connections or protected words. The conservative rule does not prove byte flow:
  it recognizes concrete decoder command names regardless of option spelling; split the operations into separate
  commands or use a file. Decoder look-alikes remain allowed only when the command has no sink word; the former
  `base64 ...; python report.py` allowance is now denied. Tests cover input-redirection, separate-statement,
  reversed-order, wrapper and option-spelling bypasses, plus harmless decoding with no interpreter anywhere.
- `docs/port-ledger.md` (#622): the `safo-threads` row (#587) is Ported (SAFO `b499b33`, portable edition PR #70, merged), #489 and #519 are Ported (PE PR #49), #512, #538 and #558 name what PE PR #50 still lacks, 13 rows are Deferred with their blocking issue, and #537 stays Proposed because the portable edition has no issue for it; adds a Deferred section.
- `safo-codex-run` (#577): a clean codex exit with an empty result, or a short result that says the run did not start, is now exit 60 (`INCOMPLETE`, ledger `exit` 60) instead of 0, so a review that never ran is never reported as done; docs say a wrapper's `exit=N status=ok` marker line is never proof of a review. Docs: `docs/codex-run.md`. Tests: `tests/test_codexrun.py`.
- `safo-ship` (#586, Daybreak round 8, scope shrunk): a gate that uses ANY local action or local workflow (a `./` path, or a reference into this repository) is always NEEDS-HUMAN (exit 10) naming the reference, and nothing about such an action is read; the code that derived action manifests, composite steps, entry points, local reusable workflows and action directories, and its tests, are deleted. Every whole-tree entry is validated before use (strings, known mode that agrees with the type, 40 or 64 hex sha, plain path, no duplicates, no file that is also a directory) and a malformed tree is exit 7; the fake gh refuses to produce an impossible tree unless a test asks.
- `safo-ship` (#586, Daybreak round 7): a symlink or submodule under a local action, as an executed or local-workflow file, as the gate workflow or as a directory above one of them is NEEDS-HUMAN (exit 10) even when unchanged, because its target is not compared; the protection answer must carry a string `url` that matches exactly (missing or non-string is unreadable, so PROTECTED); the fake gh adds the exact url and link entries.
- `safo-ship` (#586, Daybreak round 6): refuses (PROTECTED, exit 9) unless branch protection has strict required status checks, because no client-side read can bind `gh pr merge` to the base tip; `--accept-base-race` opts out with a NOTICE and a mark in the MERGED line, and the docs now say the restart only narrows the window; a local action is compared by everything under it from the whole Git tree (a truncated tree is exit 7), files are identified by path, type and blob sha (a directory or symlink is exit 7); the protection answer's url must match exactly.
- `safo-ship` (#586, Daybreak round 5): the contents reads that compare a gate's files are status aware (only a structurally valid 404 is absence; any other failure or odd answer is exit 7); a path the gate runs that is absent at either ref is NEEDS-HUMAN (no generated-file support); `--gate-command` needs at least one `--protect-path`; every branch name is percent-encoded in API paths and the ref and protection answers must name the asked-for branch.
- `safo-ship` (#586, Daybreak round 4): the `run:` steps of the gate workflow and of the local composite actions it uses are accepted only in a strict allowlist grammar (`safo.shipscan`: one simple command per line, an interpreter with value-less flags and one repository script path, a repository executable path, `cd` to a literal directory, or a command named with the repeatable `--gate-command`; no pipes, lists, redirections, expansions, quotes, wrappers or heredocs); every script it names must be identical on base and head and is itself read and held to the same grammar (shebang checked, down to three levels, at most 20 files), and any other line is NEEDS-HUMAN (exit 10) naming the file and line; steps must run from the root in bash or sh (job and workflow `defaults.run` merged, an unset shell counts as bash only on an ubuntu or macos label); only a clear HTTP 404 means a missing file. The base tip is pinned, and when it moves or the merge says "Base branch was modified" the whole chain runs again (once) before any second merge call; protection is read per pull request, the gate once more right before the merge, the per-PR deadline is kept through every merge call (a 30 s recovery read settles the outcome). Limits and the grammar are in `docs/ship.md`.
- `safo-ship` (#586, Daybreak round 3): it now refuses to merge (PROTECTED, exit 9) unless branch protection requires conversation resolution, in plain and queue mode, and `--best-effort-threads` opts out with a NOTICE (a known race); the gate workflow is read with a YAML parser and every `uses:` must be a sha-pinned remote reference or a local workflow or action identical on base and head, else NEEDS-HUMAN (exit 10), including too many references, too deep nesting, an unparsed `uses` or an unparsable file; plain mode shares the per-PR deadline for every gh call; a gh call that times out is TIMEOUT (exit 5) naming the call; the fake GitHub in the tests no longer makes up evidence when `derive_evidence` is off. A local `uses: ./path` may hold only `[A-Za-z0-9._/-]` with no empty, `.` or `..` part (else NEEDS-HUMAN), contents calls quote each path part and send the ref as `-f ref=`, and an answer about another path is exit 7.
- `safo-ship` (#586, review of round 2): the gate run must belong to this PR (a `pull_request` run listing its number and base, or a `push` run on its head branch) and a failed gate run on the pin is a failure; any change under `.github/` or a repeatable `--protect-path` needs a human (exit 10), as does a gate file that differs between base and head; the PR is re-read before the workflow check and again before the merge and a changed base stops it.
- `safo-ship` hardening round 2 (#586): the `CI green` check run must belong to a successful run of the gate workflow file (`--gate-workflow`, default the base branch's `ci.yml`) on the pinned sha, so a same-name job of another workflow no longer counts; a pull request that changes a workflow file stops with NEEDS-HUMAN (exit 10); every `gh` call is capped by the per-PR and total deadline and none starts after it; required-check apps are per PR; with a clean merge state a hostile error text no longer names CONFLICT or PROTECTED. Residuals in `docs/ship.md`.
- `safo-ship` hardening (#586, Daybreak round 1): a required check counts only as a check run of the app branch protection names (`CI green` defaults to GitHub Actions, `--gate-app-id`), never a same-name commit status, read with every page; protection is told missing only by an HTTP 404 status line (also the single-PR path); queue update-branch re-pins only to the verified GitHub web-flow merge of the pin and the base tip; `--total-timeout` and per-PR deadlines now cap every sleep and call; merge refusals are classified from the merge state first; malformed thread output is exit 7; PR numbers must be positive; a NOTICE when conversation resolution is not required; docs `docs/ship.md` cover queue mode and exit codes 8 and 9.
- `safo-ship --queue` (#586, epic #518): PRs one at a time, stopping at the first that does not merge (later ones print SKIPPED); `--pin N=SHA` re-reads a lagging head for a bounded time before HEAD-MOVED; a BEHIND branch gets update-branch once (guarded by expected_head_sha), is re-pinned and CI is waited for again; new stops CONFLICT (exit 8) and PROTECTED (exit 9) beside the existing CI-FAILED, THREADS (count) and MERGE-REFUSED. Single-PR behavior and exit codes unchanged. Tests: `tests/test_ship_queue.py`.
- `safo hooks install` (#615 review): a guarded wrapper around another form (the legacy `safo hooks guard`) is kept exactly as found instead of having only its `exec` payload replaced (which left a probe of one program and a run of another); arguments are rewritten only for a wrapper of the same program. Docs: `docs/hooks.md`. Tests: `tests/test_guard_wrapped_form.py`.
- `safo hooks` guarded wrapper form (#615, #397): one implementation. `guard_form` reads the wrapper through `unwrap_guarded` (the stricter rule: plain command text, the program probed is the program run); the duplicate looser recognizer added with #617 is removed, and the signature helpers take a command as written. Docs: `docs/hooks.md`. Tests: `tests/test_guard_wrapped_form.py`, `tests/test_hooks.py`.
- `safo hooks` guard shell check (#615 review): its deadline is bounded by what is left of the hook's budget (the lesser of the load-aware value and the guard's pre-decision deadline); with no time left the command is denied at once as `input-shell`. Docs: `docs/hooks.md`. Tests: `tests/test_guard_check_budget.py`.
- `safo hooks` visible warning (#615): names the cause per diagnostic (a shell command not checked in time, an event too large to check); a SessionStart probe failure is `SAFO routing guard degraded: the session probe could not finish (cause) ... Nothing was denied` instead of the guard's degraded line. Docs: `docs/hooks.md`. Tests: `tests/test_guard_warning_cause.py`.
- `safo hooks status` (#615): the wrapped guard command `command -v safo-guard >/dev/null 2>&1 && exec safo-guard || exit 0` is read as the `new` form instead of `absent`; only that exact shape, matcher and type rules unchanged, and `install` writes the same lines as before. Docs: `docs/hooks.md`. Tests: `tests/test_guard_wrapped_form.py`.
- `safo hooks` guard shell check (#615): its time budget is load-aware: a 3 s floor (was 1.5 s), scaled by the one-minute load average per core up to a 5 s cap, an unreadable load gives the floor; a check that still runs out is denied as before. Docs: `docs/hooks.md`. Tests: `tests/test_guard_check_budget.py`.
- `safo hooks` guard log (#615): the `input` diagnostic is split into `input-parse`, `input-oversize`, `input-shell` (and `input-args` for the hook's own command line); old `input` rows stay readable; an `input-shell` row carries `check_ms`, the check duration; `safo hooks status` counts each cause on its own line. Docs: `docs/hooks.md`. Tests: `tests/test_guard_input_split.py`.
- `safo-shared-venv` (#621, epic #527): the venv step now runs `python -I -m venv`, and every child (identity probe, venv, pip) runs with stdin closed from a fixed directory (the private build directory, `/` for the identity probe) instead of the caller's, so a `venv.py` or `pip.py` planted in the current directory cannot run during creation. Tests: `tests/test_sharedvenv.py`.
- Test fix (#616): `tests/test_sharedvenv.py` no longer compares inode numbers of a freed and a rebuilt entry (ext4 reuses a freed number at once; failed in CI on PRs 610 and 620). The rebuild test holds the old entry open so both inodes stay live and proves the rebuild by a sentinel file only the old entry had; the reuse test holds the entry open too. Tests: `tests/test_sharedvenv.py`.
- `safo-protect-threads` (#541, epic #527): turns on required conversation resolution on a repository's default branch by one GraphQL field (`updateBranchProtectionRule`), dry run by default, `--apply --backup-dir DIR` saves the rule (0600), writes, reads back and verifies every other field is unchanged (else prints the rollback, exit 6); refuses on rulesets, no or several covering rules, or an unreadable field. Separate entry point, no `TOP_LEVEL_COMMANDS` change. Docs: `docs/protect-threads.md`. Tests: `tests/test_protect_threads.py`.
- `safo-shared-venv` (#534, epic #518): one shared, read-only, hash-locked venv per lockfile, built once under a file
  lock (`pip install --require-hashes --no-deps --only-binary=:all:`, never system site-packages, atomic rename into
  place) and keyed by the lockfile hash, the interpreter identity and the acquisition policy. Prints the interpreter
  path. Strict lockfile grammar, a private copy read through a descriptor, an allowlisted child environment, isolated
  pip, owner, mode and manifest checks on reuse, root ancestor checks, interpreter binding (resolved
  once, trusted chain, re-verified on every use), whitelisted acquisition values (https URL or absolute local path, never credentials), child output never relayed, validated numeric parameters
  and a stated trust boundary. `--gc --max-age-days N` lists old
  venvs it built, `--delete` removes them. Docs: `docs/shared-venv.md`. Tests: `tests/test_sharedvenv.py`.
- `safo-remerge` (#588): a second resolver settles `pyproject.toml` conflicts when both sides only add `key = "MODULE:FUNCTION"` lines to the `[project.scripts]` table (ours first, no duplicate key, strict value pattern); every other pyproject conflict still goes to an agent. Docs: `docs/remerge.md`. Tests: `tests/test_remerge.py`.
- `safo-brief-scan` hardening (#537): `--hook` mode ignores `safo-scan-allow` markers (content cannot suppress its own findings), the marker's reason gets the full check (credentials, private data, deny list), and JSON object keys are scanned as text and never printed raw in a label. Docs: `docs/brief-scan.md`. Tests: `tests/test_briefscan.py`.
- `safo-idle-check` (#601): count a PR as ready work only when its author is the repo owner or in `trusted_authors` / `SAFO_IDLE_TRUSTED` and it is not a fork PR (`allow_forks` / `SAFO_IDLE_FORKS=1`); an unreadable author is not trusted; skipped PRs are counted in the log field `skipped_untrusted`, never listed. Docs: `docs/idle-check.md`. Tests: `tests/test_idlecheck.py`.
- `safo-brief-scan` (#537, epic #518): a standalone scan of a brief or report for credentials (the Gemini wrapper's shapes plus bearer, JWT and secret assignments) and private data (the `safo-draft` detectors and deny file); stdin, files or `--hook`; exits 1 on findings, 2 when input cannot be checked; prints type, line and a short hash only for credentials, never the value; `safo-scan-allow: REASON` suppresses one line. Separate entry point because a subcommand needs the frozen guard's `TOP_LEVEL_COMMANDS`; no hook is wired. Docs: `docs/brief-scan.md`. Tests: `tests/test_briefscan.py`.
- `idea_gate_io.run_bounded` (#600): the group kill is sent three times, 20 ms apart, while the unreaped leader still reserves the group id, and the descendant test now reports `/proc` state on failure; a CI-only miss of a forked `sleep` stays unreproduced (0 of 1,400 loaded runs). Tests: `tests/test_idea_gate_hardening.py`.
- `safo-idle-check` (#597): the block reason no longer carries PR titles, branch names or QUEUE.md text (third-party free text next to the model's instructions); a PR is `owner/repo#N` plus fixed reason codes and a queue item is its file line number only. Tests: `tests/test_idlecheck.py`.
- `safo-remerge` (#588): merges `origin/main` into a clean feature worktree and settles only both-sides-added list and table lines in the changelog's Unreleased section, `docs/home.md` and `README.md`; any other conflict aborts, restores the tree and exits 11 with the paths; runs a caller-supplied argv test command before committing; never pushes. Docs: `docs/remerge.md`. Tests: `tests/test_remerge.py`.
- `safo-eval-canary` follow-ups (#575): caps on `--busy-retries` (10), `--wait` (600) and `--repeats` (20) with a 300 s per-sleep cap and a 1800 s total busy-sleep deadline; a busy record now wins over an unreachable or malformed one within an attempt; non-boolean `passed` and non-proportion scores are refused; new folders are fsynced in their parent; temp files get unique names so a crash leftover cannot block an update; tests for hard links, concurrent writers, a parent swap, invalid UTF-8 and the exact threshold. Docs: `docs/local-eval.md`. Tests: `tests/test_evalcanary.py`.
- `safo-cards` (#591, epic #518): sets Kind, Epic, Effort (and Area and Priority defaults) on project cards from a strict-JSON table, validated against board.yaml option names, REST only (add with POST, one PATCH, a `fields=` read-back that must match), `plan` writes nothing; separate entry point, no `TOP_LEVEL_COMMANDS` change. Docs: `docs/cards.md`. Tests: `tests/test_cards.py`.
- `safo protection --all` (#541, epic #527): audits the default branch of every repository in the board file (less
  `rules.gate_exempt_repos`) against the standard: `CI green` and every security job the repository's pull-request
  workflows declare are required, a pull request is required, force pushes and deletion are off; admin bypass and
  conversation resolution are reported. One line per repository and a final count; exit 0 clean, 1 drift, 2 when a
  repository could not be read. GET only (REST), one repository at a time. `--all` and `--repo` are mutually exclusive;
  the single-repository mode is unchanged. Docs: `docs/protection-audit.md`. Tests: `tests/test_protection_all.py`.
- `safo-threads` (#587, epic #518): `list REPO PR` shows unresolved review threads, outdated ones included and marked `[outdated]`, grouped by file; `apply REPO PR FILE` replies by REST and resolves (outdated unresolved threads too) by one GraphQL mutation per thread from a strict dispositions file (unknown ids, empty or over-long bodies, duplicate ids refused before any write; bounded calls; exit codes 0, 2, 3, 4, 5). Separate entry point, `TOP_LEVEL_COMMANDS` untouched. Docs: `docs/threads.md`. Tests: `tests/test_threads.py`.
- `safo-eval-canary --truncation-probe` / `--probe-only` (#569, epic #518): sends one long prompt to the digest model through `llm-local` and alerts (exit 1) when the server's reported cut is no longer `--expected-cap` (default 4098); unreachable 3 over busy 75 over drop 1. Docs: `docs/local-eval.md`. Tests: `tests/test_evalcanary.py`.
- `safo-idle-check` (#578): a separate Stop hook that blocks the end of a turn when fewer than 6 workers run and ready work exists (PRs failing or conflicting with no agent on them, unstarted QUEUE.md items); counts workers from the subagent registry and process table, fails open loudly, caches the PR scan 60 s, logs blocks per day. Not installed by this change. Docs: `docs/idle-check.md`. Tests: `tests/test_idlecheck.py`.
- `safo-eval-canary` (#540, epic #527): runs the safo-eval fixtures on the two configured local models (read from `safo.localdraft`), compares each pass rate with a stored baseline and exits 1 with one `ALERT` line when a score drops by more than `--threshold` (default 0.10). A busy queue is retried (exit 75 if it stays busy), an unreachable server is reported (exit 3) and never scored as zero, a hostile baseline (symlink, FIFO, oversized, malformed, wrong types) is exit 2, and the baseline is written only with `--update-baseline`. Separate entry point because a `safo` subcommand needs the guard's `TOP_LEVEL_COMMANDS`. Docs: `docs/local-eval.md`. Tests: `tests/test_evalcanary.py`.
- `safo-codex-run` and the shared git config check (`safo.gitconfig`): git now runs with `GIT_NO_LAZY_FETCH=1`, so a
  partial clone is refused and a missing object is never fetched on demand. A behavior change, documented in
  `docs/codex-run.md`; test in `tests/test_codexrun.py`.
- `safo-digest` (#531, child of #518): runs `git` or `gh` (nothing else is supported; only `log`, `show`, `rev-parse`, `ls-files` and a `diff` of resolved revisions or the index, never the working tree; gh options come from a fixed list per subcommand) and prints a capped digest in a
  fixed untrusted-data frame, saving the full output to a private file. The executable must be a native program,
  root-owned under root-owned directories, opened without following symlinks and started from the verified descriptor.
  Only a short list of read-only git subcommands and gh subcommand pairs may be listed; every argument is validated
  against a per-entry option allowlist with typed values and no control characters. The repository's own config (and every submodule's)
  must be on a shared allowlist of inert keys, the same one `safo-codex-run` uses (now in `safo.gitconfig`), and
  program-running git settings are forced off at command scope. The command
  gets a minimal environment, an empty private home (recreated each run) and only inert pass-through variables from
  a fixed list. Process containment (child subreaper, `/proc`, pidfds) is mandatory: a timeout, a normal exit or a
  SIGTERM, SIGHUP or SIGINT kills the command and every descendant, and without containment nothing starts. The output
  directory and every parent are checked and re-verified before the path is printed; the path is labelled advisory.
  Digest lines are cleaned and prefixed, header fields are cleaned, and user, host, home, callsign and grid text is
  replaced (best effort, the saved file is raw). Exit 124 timeout, 125 refused. Docs: `docs/digest.md`. Tests:
  `tests/test_digest.py`, `tests/digest_driver.py`.
- `safo-codex-run` (#557): harden git config handling. The repository config check is now an allowlist and the child git environment forces more settings off. Docs: `docs/codex-run.md`. Tests: `tests/test_codexrun.py`.
- Update the sister-project rule now that the portable edition is public (#573)
- Add CLAUDE.md and AGENTS.md stating the sister-project rule (#565)
- `scripts/impacted-tests.py` (#535): prints the test files to run for changed files (arguments or `--base BASE`), by naming convention and by the reverse import closure parsed with `ast`, plus five always-run guard tests; exits 3 with `ALL` when a file maps to no test or is config, a workflow or `pyproject.toml`. Never runs repo code. CI stays the judge; agents use it only for targeted runs. Docs: `docs/impacted-tests.md`. Tests: `tests/test_impacted_tests.py`.
- `safo-activity --watch` (#554): a signal that arrives while a frame is being drawn now ends the watch before another
  frame starts (it used to draw one more full frame first, slow under load). The signal test now captures the child's
  stderr and kills and reaps the child on any exit, and a hung-child test proves the harness fails instead of hanging.
  Tests: `tests/test_activity.py`.
- `ghw` conditional reads (#532): a plain `gh api ENDPOINT` read keeps its ETag and body in `etags.json` beside the ledger (mode 0600, 64 entries, 128 KiB per body, 4 MiB, 24 hours, keyed by host, account and request) and sends `If-None-Match` next time; a 304 serves the kept body, costs no rate budget and is counted as a cache hit in the ledger and in `safo-ratebudget --by-caller`. Any cache error is a normal request. Docs: `docs/ratebudget.md`. Tests: `tests/test_ratebudget_etag.py`.
- Docs sweep (#543): `docs/local-llm.md` now describes the `llm-local` wrapper (attribution fields, caps, exit codes 3, 4 and 75, outcome logging); `docs/local-draft.md`, `docs/local-eval.md`, `docs/board-kind.md` (`reconcile --closed-only`), `docs/usage.md` (`safo spend`) and `docs/hooks.md` (the `TOP_LEVEL_COMMANDS` rule) match merged behavior.
- `safo lead-curve` (#556, phase 1, read-only): per lead session the turn count, context tokens per turn and weighted spend by turn bucket (1-100, 101-200, 201-300, 301+), the share of turns and spend past turn 200 and 400, three labeled lines on where cost climbs (the first turn where marginal spend passes 1.5x the median of turns 1-20, the turn at which 50 and 80 percent of a session's spend is reached as a median across sessions, and the weak old first-100-turn definition), and the cost of each handoff (successor's first three turns measured, the note estimated). Reuses the `safo spend` reader and weights; counts only, writes nothing. Docs: `docs/spend-report.md`. Tests: `tests/test_leadcurve.py`.
- `safo spend-post` (#538, epic #428): runs the weekly spend report and posts a short summary (counts, weighted totals,
  change since the stored baseline; measured numbers apart from labeled estimates) as one comment on an issue of a
  private repo. It asks `gh api repos/OWNER/REPO --jq .private` first and refuses unless the answer is `true`; the body
  carries no path, user or host name or transcript text and is refused if it would; the comment is never retried. No
  scheduler, setting or secret is added; a systemd timer and a cron line are shown in the docs. `safo spend` is split
  into `gather` and `run` with no change in output. Docs: `docs/spend-report.md`. Tests: `tests/test_spend_post.py`.
- `safo spend` (#510, epic #428): a read-only weekly token-spend report from the Claude transcripts, the Codex sessions
  (counted apart, never added), the `llm-local` calls log, the hook log and the `safo-draft` local-share log. Weighted
  spend by pool (lead, agents by type), cache-read and output shares, weighted tokens per lead turn and the share past
  turn 200 and 400, per merged PR from a caller-supplied date list, local use counts, and the first-turn context of
  agents. `--baseline PATH` stores the first report (exclusive create, mode 0600, never overwritten) and later runs
  print the change per line; `--json PATH` writes a new 0600 file. Counts only, bounded (files, bytes, line size, run
  time; a bound stops the run), symlinks and special files refused. Docs: `docs/spend-report.md`. Tests:
  `tests/test_spend.py`.
- `safo reconcile --max-writes N` and `--no-adds`, and the new `safo kind` (#479, phase 1 of the board 11 reconcile): a write cap that stops cleanly with exit 0, a reconcile that adds nothing, and a rule-driven Kind writer for open cards (REST snapshot, rule proposal, approved map, board-name check, journal; never Epic or Effort). Docs: `docs/board-kind.md`. Tests: `tests/test_kindwrite.py`, `tests/test_reconcile.py`.
- `safo local report` (#372, #380): read-only counts of local-model use per day, week and model from the dispatch-guard
  log, the `safo hooks status` guard counts and the `llm-local` calls and admission state, with a MISSING DATA section
  and `--json`. Nothing is written or created (the hooks log is read without its lock). Bounded reads, malformed, torn
  and future-dated rows counted, strict timestamps judged on the local date, output through the repo writer. `local run`
  keeps its required-argument error and refuses `--days` and `--json`. Reads the typed `llm-local` rows (calls by
  status and failure reason, outcomes joined by call id with accept rates, orphans) and the guard's `na_reason_class`. Docs: `docs/usage.md`, with the task-type table.
  Labels are printed only from fixed allowlists (unknown text is counted as `other`, never printed); the home directory
  must be absolute and not a symlink, and files are read only through directories that are not symlinks, owned by you
  and not writable by others (a group write only in a private group); a malformed call row is never a join
  target. Tests: `tests/test_local_report.py`, `tests/test_local_report_typed.py`, `tests/test_local_report_safety.py`.
- rmguard hardening (#424): more of what a command can hide is read or fails closed, and the cheap gate opens in more places. Warn-mode semantics are unchanged.
- `safo-file`: routing table with private repos by default and workbench for tangents (#455, epic #347; `safo.idea_gate_routes`). New `route` subcommand prints the destination repo and why (keyword and path-hint matching by code, classes product, homelab, ai-tooling, research, tangent; exit 3 when undecided); the table is data in `~/.config/safo-file/routes.toml` (trusted file, bounded, exit 2 when malformed). `issue` always looks the target repo up live (no cache) and fails closed when `gh` cannot say whether it is public; a public target takes only positively product work (`--class product` or the working repo) with no private wording after NFKC and separator normalisation, unless `--allow-public` and a `public-ok:` line are both given; `routes.toml` cannot make any class public; the lookup is repeated right before the create and, for private-workflow work, right after it (a repo that turned public gets an `EXPOSED` error, an `exposed` record and exit 2); `public-ok:` needs a real reason (12 characters, two different non-placeholder words); matching is linear in the text (word sequences in sets, keywords at most 4 words); a public target refuses text it cannot classify (invisible or format characters, combining marks, non-ASCII digits, lookalike or non-Latin letters) unless both override elements are given, and accents are folded for matching; `check` takes the tangent repo as the default parking-lot repo (`--parking-number`). Decisions are `routed` ledger records. Tests: `tests/test_idea_gate_routes.py`.
- New `safo-file` (#443, epic #347; `safo.idea_gate`), a wrapper in the style of the planned `safo file` (#348), not a guard.
  `check` matches an idea against `hooks.tracking_repos`, `gh repo list` and a pluggable memory search
  (`SAFO_MEMORY_SEARCH`), prints the top hits and requires exactly one answer: `extends:<repo>`, `new-project` (needs
  `--owner-ok`) or `tangent` (one parking-lot body with a time box; no repo, epic or card). `issue` files through `gh` with
  the body on stdin; another repo needs a `cross-project: <reason>` line outside a code fence, and another owner needs
  `--allow-other-owner`; the ledger is checked before the issue is created. `report` counts, in code, the issues whose repo
  differs from the working repo. Advisory by design for same-repo filing (docs/file.md). Tests: `tests/test_idea_gate*.py`.
  Hardening (`safo.idea_gate_io`): `gh` and the memory command run only from a trusted absolute path (not in the working
  directory, no owner but you or root, no group or other write on it or above it), with an allowlisted environment (no
  `SAFO_*`, no token or cloud variables), their own process group, capped output and a deadline; the ledger is opened
  through directory descriptors with no link followed, owner and mode checks, `pending` before and `committed` after the
  issue; `check` reads only `~/.config/safo/agents.yaml`.

- New `safo-rmguard` (#422), a separate PreToolUse hook for Bash that guards the shared dev directories
  (`~/.local/share/*-dev` and the scratchpad parent `/tmp/claude-*`) against wildcard, parent and out-of-folder deletes,
  truncation, moves and in-place edits. It judges these families only: `rm`/`rmdir`/`unlink`/`shred`, `find -delete` and
  `-exec` (with the GNU global options), `git` (read-mostly subcommands pass, every other one is judged by its work
  tree, including aliases and `GIT_WORK_TREE`), `truncate`, `rsync` and `tar` with delete options (abbreviations and
  unknown long options fail closed), `mv`, `cp`, `dd`, `tee`, `sed -i`, `perl -i`, `awk -i inplace`, `ed`, `install`,
  `ln -f`, inline `python -c`/`perl -e`/`ruby -e`/`node -e`, and truncating redirections; anything else is not covered
  (docs/rmguard.md lists it). Only an exact path strictly below `<dev>/agents/<name>/` passes; the agent folder root
  itself is removed by the owner in a batch. A command is evaluated when the cwd is in a zone or its text holds a delete
  word, a character that can build one or a zone name (also quoted or escaped); what an evaluated command makes unreadable
  (syntax error, timeout, crash) is a deny, and a command over 64 KB is decided by its first 64 KB.
  `safo-rmguard --mode warn|enforce` (default enforce, set in the hook command, never the environment): warn never blocks,
  logs redacted would-be blocks to `~/.local/share/reach-around-lead/rmguard-warn.log` through directory descriptors (no
  symlink followed) and, after `--record-integrity`, logs when the launcher or the settings entry changes. Install is an
  owner step with two documented entries: warn (no `onFailure`) and enforce (`onFailure: block` plus an owner-owned
  launcher outside the pipx environment), a residual-risk statement and a promotion threshold. It is its own module and
  entry point, so the frozen dispatch guard is untouched. Tests include a sentinel-file differential against real bash,
  git, find, rsync, tar, sed, perl and python. `tools/rmguard_replay.py` replays real Bash history in dry run.
- New `rules.tracking.exempt_authors` (#420): a list of bot-account logins (GraphQL typename `Bot`; a person with the same login is never exempt) whose pull requests need no linked issue in
  `safo audit` and `safo sync`, so Dependabot pull requests are not drift. Matching ignores case and a `[bot]` suffix; a
  pull request with no readable author is still reported. Default empty: nothing changes until a board lists a login. `safo audit` prints one NOTE naming the active entries.
  A `board.yaml` that sets the key is refused as an unknown key by a SAFO build without this change.
- Narrow the shell material rule so it fails closed (#388). The old denial stays the default for the whole submitted
  command. It is relaxed only on a positive proof from a small lexer: the protected words stand only in comments, or
  every command is on a short allowlist and writes no file. The allowlist is `echo` and `printf` to standard output,
  plain `grep`, `cat`, `head`, `tail`, `wc`, `date`, `pwd`, and `gh issue|pr` with a literal body and a short list of
  inert options, each value a known literal (no variable or command substitution) and a body, comment or title given
  once. Ordinary unquoted arguments are relaxed as well as quoted ones. The relaxation proves the command text only: the
  effective repository and host of a mutating `gh` command come from the environment and repository configuration,
  which the guard does not inspect; the threat model is an honest or text-injected model, not an attacker who controls
  the shell environment. NOT relaxed: `gh` with a body file, an attachment, a template, a repository or host selector
  visible in the command text, or stdin; commit messages; file-writing here-documents;
  ripgrep; pipes or redirects into a shell or interpreter; `eval`, `source`, inline-code interpreters, variables run as
  commands, wrappers, assignment prefixes and any form the lexer does not model. The vendor host, SDK and key variable
  are never relaxed. The part of #388 about a
  brief line over 4000 characters is NOT fixed: such a line is still refused unread, because an unread line cannot be
  shown harmless. See docs/hooks.md.

- `safo-activity` (#402): what Codex, the plan windows, the local spend ledger, the local model and
  Copilot code review are doing, read only. A new entry point (`safo.activity`; the `safo activity` mode waits for a one-word change to a frozen file, see the pull request): one line for a status
  line (cached 10 s), `--table`, `--json`, `--watch` (every 2 s) and `--events PROVIDER` (a line only on a state change,
  at most six per minute and one dropped-count line, ends after 29 minutes and on a signal). Providers: `codex` (jobs of
  the Codex plugin), `quota` (the 5 hour and weekly windows of Codex from `~/.codex/sessions`, and of Claude from
  `~/.cache/safo/claude-usage.json`, with `write_claude_usage` for a status line script to fill it; nothing wires it
  yet), `ledger` (a lenient tail reader, never the chain-verifying one; counts, action names and ages only), and the
  opt-in network providers `ollama` (one 1 s `GET /api/ps` to an endpoint from the agents config or `$LLM_LOCAL_URL`,
  never a generate call) and `copilot` (REST only through the machine's `gh` login: is a `Running Copilot Code Review`
  run queued or in progress on the head, and does `copilot-pull-request-reviewer` have a review with text or an inline
  comment on it; counts only, at most 15 pull requests, cached 60 s). With no configuration only `codex`, `quota` and
  `ledger` are read; `SAFO_ACTIVITY_PROVIDERS` or `~/.config/safo/activity.yaml` opt in the rest. Also the Claude Code
  pane `mods/ai-activity/`, which runs `safo-activity --table` only when it is on the path. Tests:
  `tests/test_activity.py` (loopback fake Ollama, fake `gh`, fixture rollouts and ledgers), `mods/ai-activity/hooks/ai-activity.test.tsx`.
  Docs: `docs/activity.md`. Process-launch hardening of the activity provider was added. Review follow-ups: the ledger tail was lowered from 2000 to 1000 lines (`LEDGER_TAIL_LINES`) in the CI-fix commit c9c97a2 so that parsing through the bounded JSON loader stays fast on a status line; a call started more than 1000 rows back can look absent. A refresh where most pull request reads fail now counts as failed and backs off; conditional requests (ETag), a 15-call budget with oldest-first rotation, paging to 10 pages, one bounded Ollama listing thread, and checks on cached counts. Earlier: views read the Copilot cache only and a single locked background refresh fetches it (call budget, rate-limit check, backoff, paging), the pane finds `gh` and `ss` again, and several smaller input and cache checks.

## 0.2.0 (2026-11-09)

- First release that carries the Gemini paid-path broker, its installer and units, the approval-binds-prompt change, the
  passkey extra, the `safo-guard` entry point and the Action trust hardening. Paid use stays disabled. The release is
  installed only from a signed annotated tag `v0.2.0` by `packaging/safo_broker_install.py`; the release notes the
  installer review reads are in the pull request that prepared the release (#341). Everything below was merged after
  v0.1.2.
- Enrollment runbook (#339): the PIN prompt stays in the terminal. Steps a2, a3 and a4 set `SSH_ASKPASS_REQUIRE=never`,
  and the a4 signing command passes the message file as an argument instead of redirecting standard input (the redirect
  made ssh-keygen ask for the PIN through a graphical askpass program). New step in a4: `scripts/sshsig_flags.py` reads
  the authenticator flags from a signature and proves the PIN was required (expect `flags=0x05`); tests in
  `tests/test_sshsig_flags.py`. Verified on 2026-11-02 with hardware keys A and B, including the flags (0x05) and the
  unplugged-key refusal.
- SAFO threat model diagram (#246): the Threat Dragon file opened as an unreadable tangle. Rebuilt the geometry only: six
  aligned boundary boxes with room around their contents, every shape inside its own boundary on a 20 px grid, flows as
  straight or right-angle lines with explicit vertices (none through a shape), short flow labels on clear stretches, and
  the shape and boundary names drawn on the canvas. Ids, names, descriptions, threats and mitigations are unchanged.
  `tests/test_safo_threat_model.py` gains a layout guard (containment, overlap, flow clearance) with a negative case.
  Checked by opening the file in Threat Dragon 2.6.2 in a headless browser (`scripts/threat_dragon_shots.py`).
- Rehearsal containment, second round (#263). Review findings are fixed: the sandbox gets a synthetic `/etc` instead of
  the host's, `bwrap` and `prlimit` are taken only from root-owned system folders (never `PATH`), and the sandbox runs
  under memory, file size, open file, CPU and task limits with a size-capped memory-backed rehearsal folder; tests show
  each limit bites. `--keep` now needs `--no-containment`. The header and `docs/gemini-enrollment.md` say what is and is
  not contained.

- `safo audit` (#389): open pull requests in the listed repositories that cannot merge as they stand. `DRIFT   CONFLICT
  owner/name#n` for `mergeable: CONFLICTING`, a `NOTE    BEHIND ...` for one behind its base, and a count note
  (`mergeability: N open pull requests, C conflicting, B behind, U not yet computed`). A `mergeable` still being
  computed (`UNKNOWN`/null) is counted, never drift; an unrecognized value exits 2. One GraphQL read per repository
  (`safo.mergeability`), never a project listing. Tests: `tests/test_audit_mergeability.py`.
- Shared GitHub API budget (#356, #358; umbrella #355, rules #204). `ghw` (new entry point, `safo.ratebudget`) is `gh`
  with a per-bucket call ledger under `~/.local/state/safo/ratebudget` (file lock): the worst counter across response
  headers and the `rate_limit` endpoint is the truth, 70% warns, 90% refuses (exit 75) until reset, `Retry-After` and
  secondary-limit answers block the bucket, writes are spaced at least one second across processes, nothing is replayed.
  `safo-ratebudget [--by-caller] [--refresh]` prints the status line and a per-caller report; a one-line cache
  (`statusline.txt`) is kept for a statusline. `safo-card` edits one project card with one REST PATCH from a persisted
  map of item, field and option ids (`safo.boardmap`) and never lists the board. Tests: `tests/test_ratebudget.py`,
  `tests/test_ratebudget_mode.py`, `tests/test_boardmap.py`. Docs: `docs/ratebudget.md`. Not wired into the dispatch
  guard (a guard file; #357). Round 2 (review): counters, blocks and the write queue are scoped by a host and
  credential fingerprint; one global write queue; a queued writer re-checks before it launches; counters are saved
  before the audit row; the state directory is made private and used by descriptor; persisted times are bounded; a
  repeated or malformed rate-limit header rejects the answer; compact option spellings count as writes; `--resolve`
  needs a positive repository match. Round 3: the scope follows the authenticated account (not the token), an
  account that cannot be told gets a conservative unknown scope, a GraphQL secondary limit sent with HTTP 200 blocks,
  `boardmap.json` is read with the same private-directory checks as it is written, and the write-slot bound is the
  queue limit. Round 4 (#367, #368): a launch gate spaces writes from the last actual launch (the child is spawned
  while the account's gate lock is held, then the lock is released), and a hostile identity cache is validated record by
  record and fails open. The real `gh` child now runs in its own process group so a timeout ends it and its children. Round 5: SIGINT, SIGTERM and
  SIGHUP are forwarded to that group while `ghw` waits (grace, SIGKILL, reap; unknown outcome, exit 128+signal); launch
  spacing is read from the monotonic clock of the same boot, and a launch recorded in the future fails closed for one
  spacing instead of being dropped; the launch gate lock is a file per account, so one account's stalled spawn does not
  block another. Round 6: the signal guard covers the whole run (handlers installed together before the gate, a
  signal at any point after a child may exist is forwarded, stopped, reaped, reported as an unknown outcome),
  `safo-card` reports a signal-interrupted PATCH as an unknown outcome (`is_unknown_outcome_exit`), a future same-boot
  monotonic launch record is repaired once, and concurrent card-map updates are merged under a lock. Round 7: modes are written as `stat.S_IRWXU` (Semgrep read the 0o700 literal as too
  permissive; same mode, no suppression), the board snapshot copies the option dicts (#373), and an oversized or
  unterminated header block is withheld instead of printed as body (#374).
- `safo-ship` (#371): on exit 3 each unresolved review thread is printed with its author, file:line, link and the first
  600 characters of the comment (control characters stripped, `[truncated]` after a cut). New `--wait-for-review SECONDS`
  (0 to 900, default 0) waits, within `--timeout` and `--max-polls`, for the automated reviewer's review of the pinned
  head before the thread check, then goes on either way with a notice if none came. It never resolves a thread and never
  merges past one. Tests: `tests/test_ship_review.py`. Docs: `docs/ship.md`.
- Dispatch guard issue check (#370): the open-issue check reads REST (`gh api repos/OWNER/REPO/issues/N`) first, so a
  rate-limited GraphQL no longer denies valid briefs; GraphQL (`gh issue view`) is the fallback, and the check fails
  closed only when both fail. A pull request number is refused as before. A positive answer is cached for five minutes
  per issue in `issue-cache.json` in the state directory; negative and error answers are never cached. The denial text
  names the source. Nothing new is denied. Tests: `tests/test_tracking_rest.py`.
- `safo-ship` (#85): the tested merge watcher, a new entry point (`safo.ship`), documented in `docs/ship.md`. It pins the
  head, waits (bounded) for a complete rollup with `CI green` and every required check, re-runs a cancelled job once and
  the EX-0001 canary at most twice, stops on unresolved review threads, merges with `--match-head-commit`, retries once on
  "Base branch was modified", and can push and open the pull request first. Tests: `tests/test_ship.py`, against a fake gh.
- Research discipline (#353), warn only, by the maintainer's explicit word of 2026-11-07 despite the guard freeze. New
  dispatch rules `research-route` (a research brief goes to an agent type that cannot search) and `research-ladder` (a
  research brief has no `research:` line; `research: n/a - <why>` turns both off for that brief), and `safo handoff
  shape` (report-not-found: a report that says not found, blocked or 403 without two listed queries or a named fallback;
  shape only, not truth). No deny path, `block` mode included. New `hooks.research` block in `agents.yaml` (`route`,
  `ladder`, `report_not_found`, `intent_keywords`, `search_types`, `na_marker`); `safo hooks status` counts both rules.
  Tests: `tests/test_research_rules.py`, `tests/test_reportshape.py`. Docs: `docs/look-before-instructing.md`.
- Lead-side research check (#84, rule `research-lead`), warn only, by the maintainer's word of 2026-11-07. New Stop hook
  `safo hooks stop`: when the final message of a turn relays "not found", "no statement found", "needs your decision"
  and the like about an external fact and the turn made no WebSearch, WebFetch or listed documentation call, it shows a
  `systemMessage` ("run a web search before relaying not found") and writes a guard-log row. It never blocks and never
  makes Claude continue (no `decision`, no `additionalContext`), honors `stop_hook_active`, reads only the last 1 MiB
  of the transcript, and fails open with the degraded notice. New `hooks.research` keys `lead_check`, `lead_phrases`,
  `search_tools`; `safo hooks status` counts the rule. The other #84 heuristics (done claims, click paths) stay unbuilt;
  `CHECKS` in `src/safo/stophook.py` is where they would go. Tests: `tests/test_stop_hook.py`. Docs: `docs/hooks.md`.
  Review fixes: a malformed transcript line inside the window or a missing/non-string `last_assistant_message` now fails
  open with the degraded notice instead of a false warning or a silent allow, and `hooks stop` is a hook for the
  stderr contract (a bad `SAFO_APPEND_LOCK_TIMEOUT` prints nothing).

- Rehearsal review fixes (#263). The rehearsal now contains the runbook text it runs: it re-runs itself inside a rootless
  bubblewrap sandbox (user, network, IPC, PID and UTS namespaces, read-only `/usr`, `/etc` and checkout, a writable
  rehearsal folder, no home folder, scrubbed environment) and refuses to run when it cannot, unless `--no-containment` is
  given, in which case every output line says `[NO CONTAINMENT]`; the header and `docs/gemini-enrollment.md` state what is
  and is not contained. R13 now takes its verdict from the real enabling preflight code path and its exit status (it used
  to ignore the service-user check), R3 is SKIPPED because it cannot do the root review, and the preflight host checks are
  stand-ins inside the rehearsal folder instead of reads of the real udev, linker, authenticator and agent state.
  `keys propose` now learns that the allowed-signers file is missing from the one hardened open, not from a separate look.

- Rootless rehearsal of the phase 7 root setup (#263): `scripts/rehearse_broker_setup.py` runs the root runbook's own
  command lines and the enrollment page's command blocks against a throwaway folder (a test-only software key, the fake
  vendor, the real preflight, client and broker start-up code) and prints a PASS, FAIL or SKIPPED row per runbook step. It
  needs no root and makes no vendor or network call; steps that need root, systemd, nftables or a hardware key are
  SKIPPED with the reason. It found four mistakes, each fixed in its own commit: `safo gemini keys propose` refused before
  the files of step d2 existed, though the page runs it first; the page said two `FAIL` lines were expected under a sample
  that shows four; runbook step 5 hard-coded the ed25519-sk key type, so a release key made with ecdsa-sk (which the page
  allows) got a line that could never verify a tag (it now has a key type placeholder and a key placeholder); and five
  places on the page still called the merged broker commands unmerged.



- Broker egress control: the nftables table now persists against removal or change from outside (#283). The root timer
  runs every ten seconds, compares the live table with the reviewed ruleset and rebuilds it in one transaction when it is
  missing or different, and does this before any lookup, so a failed lookup no longer leaves a removed table removed.
  Name lookups still happen about once a minute. Observe stays the default and still needs its explicit acknowledgement.
  Tests use a fake nft and, where available, a throwaway user and network namespace; none touches a real firewall.
- Installer hardening (#284). The installer self-test now runs the staged release in a transient systemd sandbox with an empty
  state directory when run as root, and with an empty private state directory of its own otherwise. Tests use an injected
  runner; none needs root or systemd.
- Setup hardening follow-up (#303). Enabling-gate and import-check hardening; details are tracked privately until reviewed.
- Admin `check-install` root-door checks (#293). The broker administration command now runs nine read-only checks for the
  root-door items the docs list, each answering `pass`, `warn` or `fail` in one sentence: sudo rules (sudoers and
  `sudoers.d`, aliases, groups), root-equivalent group membership, polkit rules that grant without a password, paths
  under root-run folders (and the broker's own) that the account can write, root-run units and cron jobs that run a
  replaceable file or read from the account's home, the preload file, setuid, setgid and capability files no package
  owns, and a leftover old secret-store credential. Strictly read-only (no program is run, nothing is modified except possibly access times, a final
  symbolic link is never followed), and a path that cannot be read, has the wrong owner, is open to others or hits the
  scan limit is a `fail`. A `fail` makes the command exit 1; the output ends with a `limits:` line. The enrollment
  runbook names the command in the ordering list; the broker page and the threat model (R16) describe the checks.
- Broker admin docs: what to do when start-up recovery refuses a used marker from an earlier month that has no ledger row (#278). The refusal is unchanged and is now pinned by a test; an automated repair step was deferred for a simpler design.
- Wording (#302): the remaining 2 USD per job texts now say 2.50 USD, the testing-phase job cap: `agents.yaml` (paid limit and constraint) and the generated `docs/routing.md`, `docs/hooks.md`, the two guard messages in `geminibrief.py`, and the brief grammar `JOB_CAP` (now 2.50, so a brief may declare the same cap the broker allows; the guard test boundary moved to 2.50/2.51). Kept at 2 USD on purpose: the decision 13 constant and the extra block.
- Setup-command hardening (#303). The runbook step that writes the broker configuration no longer lets file text reach a shell: the here-document delimiter is quoted and the one numeric account id is passed as an argument; a test renders every runbook command and fails if an expansion form can appear in embedded text. The enabling preflight now requires the named maintainer account in the broker config's allowed list (and warns on extra accounts), and its client-config check uses the client's own loader including the root-owned override. The no-image-library import check now rejects import indirection and walks nested packages.
- Paid Gemini broker setup gaps (#298). The runbook last step ran the preflight as `/opt/safo-broker/current/bin/python`,
  which the installer never builds (it builds `current/venv/bin/python`): the runbook, the admin docs and a new test that
  compares every interpreter path in the runbook with the installer's own constant now agree. Nothing created the broker
  config, so the service could not start: the runbook has a new step, before the socket is enabled, that writes
  `/etc/safo/broker.yaml` (root-owned, mode 0644, atomically, refusing to replace a file) from a here-document with the
  maintainer's numeric uid inserted by `id -u` at run time; `examples/broker.example.yaml` (prices from the vendor pricing
  page read 2026-10-31, "Last updated 2026-10-30 UTC") and `examples/broker-client.example.yaml` load through the real
  loaders in tests, and a test requires the runbook text and the example to be the same. The service and the preflight now
  share one loader, `safo.broker.config`. The preflight has two new checks, `broker-config` (exists, root-owned, not group
  or other writable, loads, lists an allowed uid) and `client-config` (exists, loads; new `--client-config PATH` and `--maintainer-uid N`; the enable step passes the numeric id and the
  preflight finds the home itself, reads the file by descriptor under checked parent directories, and accepts only a
  root or maintainer owner; the example `broker.yaml` ships with an empty `allowed_uids` the loader refuses); the enable step is still last and still refuses unless the preflight passes. `docs/gemini.md`
  and its pinned phrase now say 2.50 USD per job in the testing phase. A lock timeout while the issuer takes
  `issued.lock` is now answered `busy` (it was `internal`). New tests the design promised: a seeded, bounded framing fuzz
  for the protocol and the server frame reader, a static check that nothing the broker loads imports an image library
  (allow-list over the import graph), and a free-path test with a broker socket that is absent or refuses.
- Docs: the paid Gemini broker design page and its threat model now say what the code does (#273, with #256 and #270).
  Documentation only, no code change. The 2.50 USD testing-phase job cap replaces the older 2.00 USD wording; the page lists
  the reply codes and when each is returned (`month_cap` is in the list and nothing returns it; `needs_block_approval` is the
  monthly-ceiling code), the further-block flag with no per-block limit, the monotonic version and ledger head rules as
  built, the `call_sent` row, the text and image approval field sets, `none` as the thinking level of a model without levels,
  `count` fixed at 1, the typical estimate (three bytes a token) versus the reservation (one token per byte plus 64), the
  clock-backward refusal, the pre-spend hook, the 10 minute nonce versus the approval lifetime, the slot wait, the per-peer
  limits, the 256 KiB reply frame versus the 200,000 byte answer (paid but not delivered, `internal` with the receipt), the
  image metadata refusals, the month-boundary rule, the 5 percent price-table rule, the single connect deadline, the egress
  observe mode and the order rule for the enable switch, the 300 second grace cap and 360 second stop timeout, the strict
  signers file, what `check-install` covers (the rest is issue #293), and what stays unverified. The shipped units are
  quoted in full, the unit start condition on the switch is gone from the text (decided 2026-10-31), and text for things not
  built is marked "not built yet". Threat model: each planned verification now names the test files, or says not built yet.
- Review items of the phase 6 fixes (#299), all tested red first. Second round: the broker-module route detector is bounded work (whitespace squeezed before any pattern runs, no adjacent whitespace repeats, spans capped, an over-long or over-numerous line set refused unread) and checks the guard deadline per line in the Bash check, the brief scan and the oversized-event scan; the preflight judges the mode of the signers file, the switch and the egress config by the broker's rule (any root-owned file that group and others cannot write) instead of exactly 0644; and the docs now say plainly that the terminal-only start and the text patterns are defense in depth, and list what the socket allows without a signed approval. The broker client's own module entry is now a paid
  command word like `paid`: the dispatch guard denies it in a brief (also built at run time, wrapped in `eval`,
  `bash -c` or `xargs`, imported, or started by file) and the Bash check refuses it for an agent; naming the module or its
  file in prose, or checking or reading the file, stays allowed, and `safo gemini paid` is unchanged. The module also refuses to start
  directly unless a person is at a terminal (a controlling terminal, a terminal on standard input and output, no
  startup variable), so a spelling the text patterns miss still does not run for an agent; script paths are read after
  collapsing repeated slashes and dot and parent segments, and a `-m` value ending in `client` counts while the broker
  is named. The oversized-event
  scan treats it the same way, and the guard's test shape list now has an exact count with no skip. The preflight's
  allowed-signers check and its key-to-name link call the broker's own parser, so a file the broker refuses cannot pass
  the readiness check. `check-install` reads the egress config by the helper's rules (a duplicate key, a missing or bad
  host, an unknown line or a bad mode fail), with one shared table of cases run through both readers.
- Paid Gemini: the in-process paid path is deleted and the broker is the only way to a paid call (#287). Removed from
  `safo.gemini` and `safo gemini`: the paid branch of `ask`, the approval store and its records, the local `approve` and
  its dry run, the paid spend counter and quota line, the paid key read, the root-owned in-process paid switch, the
  `usage` action, and the `paid_config`, `signing`, caps, `price_source`, `price_checked` and `paid` settings of
  `gemini.yaml` (a file that still has one is refused; the new optional `image_models` list names paid-only models the free
  tier must refuse). `ask --paid`, `--approval`, `--cap` and `approve` are still parsed, only so the dispatch guard keeps
  reading them as paid steps, and the command refuses them. New: `safo gemini paid` (one paid call through the broker
  client) and `safo gemini paid-dryrun` (sign a throw-away text in the dry-run namespace and ask the broker to verify it:
  no call, no charge); the wrapper hands only these two actions the signing variables and a standard input. The dispatch
  guard now denies every paid step (it no longer looks up an approval record) and recognizes `paid` and `paid-dryrun`
  as paid actions. A test fails if any module outside `safo.broker` (other than the free-tier module and the guard's own
  deny patterns) names the vendor host, a paid model or the key header. Broker client: `run_dryrun`.
  Also in this change: the image writer takes the stricter reading of its contract (output directory mode 0700 exactly,
  an optional `expected_sha256` checked before anything is written, and `write_receipt_file` for the exclusive 0600
  `reviewed: false` sidecar, which the client now uses); the wrapper's startup-variable refusal also runs as the first
  statement of `safo.cli.run`, and the docs say precisely what it covers and what it cannot (the installed script starts
  a plain interpreter; the launcher follow-up is #267); the preflight's hardware-key check passes only when the visible
  key matches an enrolled signer (new `--key-file`), and a visible device alone is a warning; and the docs now say
  that `broker.yaml` is read once when the broker starts (a change needs a restart), while the switch, the allowed signers
  and the revocation list are read on every request. The paid API key exists only in the broker's credential.
  Migrating an existing config: the schema change means a `gemini.yaml` that still has the dropped keys
  (`price_source`, `price_checked`, `secrets.paid_config`, `caps`, `paid`, and `signing`) is refused when it loads, so
  remove them first (the signing key and principal move to `broker-client.yaml`). A helper for this exists outside the
  repository on the maintainer machine.
- Paid Gemini broker, phase 6 review items for install and units (#288): the broker unit now waits 360 seconds to stop
  (above the longest drain, which the config now caps at 300 seconds, so a stop no longer kills a call before it is
  recorded); the release signers file accepts only exact hardware key lines with `namespaces="git"` (no
  `cert-authority`, no other option, no principal list or pattern) and a signature made through a certificate is refused;
  the egress helper treats a missing `MODE` as drop, the preflight reports the egress mode and fails when the enable
  switch is being created (`--enabling`) or exists while the mode is observe, unless `--ack-observe-mode` is passed after
  an empty observe log through a full dry run, and the runbook gains a last step that creates the switch only if that
  preflight passes and says to switch to drop after the first clean real call at the latest; `check-install` now also
  checks the installed unit files against the signed release and its manifest, the release version file, the egress
  helper and the switch, and says which root-door checks it does not do (the docs are corrected to match). Paid use stays
  disabled.
- Paid Gemini broker, accounting and transport hardening (#289): a call that straddles the UTC month boundary now counts
  in the month it was reserved in and also in the later month it ended in (and, while open, at its reservation), so the
  new month's cap sees it; a price table whose per-image figure disagrees with its token price (above it, or more than
  5 percent below it) is refused at load; and the call deadline now covers the name lookup and every connect attempt
  (each attempt gets the time left, no address is tried after the deadline, a late connection is closed before any byte
  is sent). The pinned HTTP(S) connections take an optional deadline; without one they behave as before. Paid use
  stays disabled.

- Paid Gemini broker, administration command (#262): `python -I -m safo.broker.admin` with `status`, `usage`,
  `check-install`, `clear` and `reconcile`, run by root. It reads the root-owned files, then drops to the service user
  (groups emptied, group, user, read back, regain probe) before opening the ledger, so the ledger's owner rule is
  unchanged; it refuses to start unless Python is isolated. `clear` prints the call records, needs the typed call ids,
  settles an ambiguous call at its whole reservation unless root names a verified amount with a reason, and records the
  uid and time in a new `admin_action` ledger row. `reconcile` reports mismatches and can only raise a month. Paid use
  stays disabled.
- Paid Gemini broker, phase 5 (#261): the systemd units and the installer, none of it run on a real machine yet. New
  `packaging/systemd/` socket and service units for a dedicated unprivileged user (strong sandboxing, an encrypted
  credential for the paid key, the root-owned switch as a start condition), `packaging/broker-requirements.txt` (hash-locked
  wheels), `packaging/safo_broker_install.py` (`safo-broker-install`: dry run by default; verifies a signed annotated tag against a
  root-owned signers file; wheels only, with hashes required; floor and monotonic version checks; a staged, read-only,
  manifest-checked release activated by an atomic symlink swap; automatic and manual rollback; never touches the state
  directory), `safo.broker.floor` (the broker refuses to start below the root-owned version floor) and `safo.broker.runbook` (the one-time root setup as copy-paste lines with blast radius and rollback, printed
  and never run). Also an egress control for the service user (an nftables table, a refresh timer, a hosts view and a files-only name
  service configuration; observe mode first), a fixed unit policy the installer enforces, a real self-test of the staged
  release, a hardware-key requirement for release signers and a trusted-interpreter check. Paid use stays disabled.
- Gemini enrollment preparation (#263): `docs/gemini-enrollment.md`, a copy-paste maintainer runbook (enroll one or two
  FIDO2 keys for approvals, a pass or fail table for testing a second device, a separate release-signing key, the
  root-owned allowed-signers lines with the namespace restriction, rotate and revoke), each step with its blast radius,
  rollback and expected output, and every command and flag checked against the vendor pages on 2026-10-31 (unverified
  items are marked). `src/safo/gemini_preflight.py` is a read-only preflight (`python -m safo.gemini_preflight`): ssh sk
  support, libfido2, the udev rule, a visible hardware key, the allowed-signers file (root, 0644, namespace on every
  line), the enable switch, the service user and the state directory modes. It writes nothing, makes no network or
  vendor call, and prints no key or file content. It is not wired into `safo gemini` yet. Paid use stays disabled.

- Tests: the random-output tests in `tests/test_protection.py` no longer depend on chance (#247). `_random_token` draws only from `secrets.randbelow`, and the tests inject a scripted or seeded source (and spy on the default one) instead of hoping two real draws differ or that a statistic stays under a bound.
- Gemini wrapper hardening (#221): `safo gemini` refuses to run when an interpreter startup variable (`PYTHON*`) or a shell startup variable (`BASH_ENV`, `ENV`) is set, then re-runs itself as `python -I -m safo` by the absolute interpreter path, with an allow-list environment (fixed PATH, locale and temporary directory; the secret-store token for `ask` only, the signing variables for `approve` only), no shell, no inherited descriptor above 2 (standard input only for `approve`), the `safo` package that launched it pinned first on the import path, and a fresh private working directory; the child verifies its own environment and directory instead of trusting the interpreter flag, and the mode is read by the real parser. No signing provider library or askpass program is passed on. Proxies, `LD_*`, `XDG_*` and the other secret-store variables no longer reach the wrapper. See `docs/gemini.md`.
- CI: the security workflow's pip-audit now audits `requirements-passkey.txt` as well as `requirements.txt`, and `tests/test_workflows.py` fails when a hash-locked runtime requirements file at the root is left out of the audit (#216).
- Paid Gemini broker, phase 4a (#260): `src/safo/broker/imagewrite.py`, the client's safe image writer, with no socket
  or protocol dependency. `write_image` takes the type from the first bytes (png, jpeg, webp; 24 MiB by default), makes
  the file name itself from a restricted stem, a random suffix and a fixed extension, opens the output directory
  component by component with `O_NOFOLLOW | O_DIRECTORY`, writes through a 0600 temporary file relative to the
  directory descriptor, `fsync`s, links it into place without replacing anything and leaves no file behind on any
  failure. `default_output_dir` makes a private 0700 directory under the user state directory, and `print_summary`
  prints one line without opening the image. Paid use stays disabled.
- Paid Gemini broker, phase 1 (#205): the core library under `src/safo/broker/`. Integer micro-dollar arithmetic and the
  worst-case reservation (prompt bytes plus 64 tokens at one token per byte, the output cap, two interim images), the
  per-job cap (2.50 USD in the testing phase) and monthly ceiling (10 USD), the model allow-list with Pro and Nano Banana
  Pro refused, the call state machine, schema version 3 approval and ledger records parsed strictly, and a ledger that
  records the spend before a call is sent and recovers any interruption as ambiguous or settled. No socket, service or
  vendor call: paid use stays disabled. `Ledger` in `gemini.py` gains `append_many` and an overridable empty-ledger
  hook, and `valid_quote` is shared; the existing behavior is unchanged.

- Paid Gemini broker, phase 2 (#258): the call pipeline in `src/safo/broker/`, tested against a fake vendor with no
  socket and no key. Approval verification runs `ssh-keygen -Y verify` through the existing fixed-argument verifier with
  the namespace fixed in code, requires the canonical signed text and the signer named inside it, and checks revocation
  again under the ledger lock just before the spend. `begin` issues broker-chosen nonces (at most four outstanding). A
  call reserves the worst case before anything is sent, builds the request from a fixed template, sends through an
  injected transport, and settles from the reported usage; a timeout, transport error, redirect, 5xx, short, oversized
  or malformed answer, a reply for another model or unusable usage leaves the call ambiguous and the model suspended
  until root clears it. A reply over the signed output cap is a breach, recorded at the cap or the reported usage
  (whichever is higher), and suspends the model. Image replies accept only PNG, JPEG or WebP: the container is walked to
  its real end (an allow-list of segments and chunks, each with a body of exactly its shape; one image, no trailing data, no
  animation, checksums and exact decoded size where the format has them, no Exif, XMP or compressed metadata), the declared size is capped, and nothing but the checked bytes is passed on. Review fixes: the approval must come from a hardware key with a
  touch (no software opt-in in the broker path); the issued record binds the maximum, the ceiling flag, the ledger head
  and the creation time; a model with an unverified output cap is refused above 2 USD whatever the job cap is; a
  temporary file left in `issued/` by a kill no longer stops `begin` or the start-up flush. `CallLedger.settle` gains `cap_breach` and `reserve` gains a
  `pre_spend` hook. Paid use stays disabled.

- Paid Gemini broker, phase 4b (#260): the thin client, `src/safo/broker/client.py`, run as `python3 -I -m
  safo.broker.client`. It checks everything it can alone, asks the broker for `begin`, builds the signed approval text,
  shows the person that text (every signed field, the cost, and the whole prompt, escaped), signs through the existing
  `ssh-keygen -Y sign` signer, sends one `call` and reads one reply, maps every reply code to an exit status and one safe
  message, refuses a reply whose receipt does not name the request, never retries a call that may have been sent and never
  falls back to the free tier. The socket path comes from a root-owned or user file, never from the environment, and must
  be a root-owned socket. Images go through a writer with the phase 4a signature (the phase 4a writer when it is in the tree, else a
  small marked adapter) and are never opened or parsed. Not yet wired into `safo gemini`; paid use stays disabled.
- Paid Gemini broker, phase 3 (#259): the socket server in `src/safo/broker/`, tested over socketpairs and a temporary
  unix socket against the fake vendor, with injected clocks and no network. `protocol.py` is the wire format on its own
  (length-prefixed frames, the 1 MiB request and 256 KiB reply limits, a versioned envelope, strict field tables, one
  fixed sentence per reply code; a thin client imports it unchanged). The core code list gains `rate_limited`,
  `vendor_refused` and `outcome_unknown`. `server.py` takes the descriptor systemd passes (exactly one listening unix
  stream socket for this pid, else it refuses), checks the peer uid with `SO_PEERCRED` against the root-owned list,
  reads one request under a whole-frame deadline, runs the operations (`status`, `begin`, `call`, `check`, `dryrun`),
  writes one reply and closes. It fails closed: a malformed request changes no state and makes no vendor call. It
  enforces the connection caps, per-peer rate limits, one paid call in flight (released before the reply is written)
  and per-minute and per-day call budgets, checks the root-owned switch on every request, logs numbers and enumerated
  words only, and on SIGTERM lets calls in flight finish and records any still open after the grace period as
  ambiguous. `python -I -m safo.broker` wires it: the epoch, switch, key and `broker.yaml` readers, no-core and
  not-dumpable hardening, a scrubbed environment, the checked HTTPS transport to the vendor, and recovery before the
  first accept. The stop wakeup is a pipe, not a socket pair, so the unit's address-family or system-call filters never touch it; `scripts/broker_sandbox_check.py` (with an opt-in pytest wrapper, `SAFO_SANDBOX_CHECK=1`, that skips with its reason otherwise; every step has a timeout and the check a total deadline) runs the real start-up flow as a socket-activated user unit under the unit's hardening properties, in error-number and kill modes and with `~socketpair` filtered, and fails for an injected socket, socketpair or recvmsg call. Paid use stays disabled.

- Tests: the guard emit-first tests no longer depend on machine load (#251). The real-process children run with a
  generous scaled budget (15 s) and an event-driven wait of 90 s on the test side, and no assertion compares an elapsed
  time with the budget any more; what they prove is the behavior (the one complete JSON line, the exit status 0 or 2,
  the process ending by itself with the blocked call still blocked, no post-delivery step started after an overrun, the
  budget counted from the process start). The in-process tests use the injected clock, or a call that blocks until the
  test releases it, instead of a stopwatch, and the order of the budget points is checked as arithmetic for any host
  timeout. Nothing was skipped, and the guard is unchanged.
- Tests: the linear-time guard in `tests/test_gemini_constructs.py` counts executed lines instead of reading a clock, so machine speed, load and Python version cannot flip it; its negative case runs a quadratic brace scan (#248).
- Gemini approvals: hardened what a signed paid approval binds (#217). Approval payload version 2 carries a prompt digest
  (`prompt_sha256`, `prompt_bytes`) on both approval tiers; `approve` shows the digest and the whole prompt (approvals are refused above 4000 characters), the paid gate
  recomputes it from the prompt it is about to send and refuses on any mismatch, missing digest or older payload version,
  and the passkey verifier takes it through its `expect` mapping. Approvals from before this change are refused with a
  clear message. The approval display and binding are hardened further: the prompt is snapshotted once and checked again at the send boundary. Every request field and approval argument is copied once through base types at the entry (exact types only).
  Paid use stays disabled.
- Threat model for SAFO as a whole (#228): `docs/safo-threat-model.md` (assets, actors, trust boundaries, 25 ranked risks,
  each with a mitigation marked verified or inferred, a verification and a residual risk) and the OWASP Threat Dragon file
  `docs/threat-model/safo.threat-dragon.json`. The paid Gemini broker keeps its own model. Linked from the README, the wiki
  home and `docs/threat-model.md`; the wiki page is `Safo-threat-model`. `tests/test_safo_threat_model.py` keeps the page,
  the file, the links and the named tests in step.
- Action: the trust the Action places in its caller is hardened. A credential (the secret-manager fetch, a literal
  `private-key` and the `token` input) is now used only on an event the preflight positively classifies as trusted:
  `push` to the default branch or a tag, `schedule`, `workflow_dispatch`, `issues` and `workflow_run` on the default
  branch, `pull_request` from this repository, and `pull_request_target`. Any other event, and any value the preflight
  cannot read, is refused with a message naming the event. The board file and the status-body file are read from the
  revision the caller binds (new input `trusted-ref`, default the commit the run is on), from git and not from the
  working tree, and a path that leaves the tree or goes through a link is refused. The preflight prints the event, the
  ref and the trusted revision it used. The `dry-run` description now says the read-only token applies to the App path.
  What a caller must change: check the repository out before the Action in any job that passes `board-file` or
  `status-body-file` (the files must be committed, regular files, and the checked-out commit must be the trusted one);
  add `trusted-ref: ${{ github.sha }}` to say so explicitly (optional); keep credentials off events other than the
  listed ones; for a pull request from a fork under `pull_request_target`, set the new input
  `allow-fork-pull-request-target: "true"` on that job; and for a repository that is itself a fork, set
  `allow-fork-repository: "true"`. The preflight now runs before the credential-masking step, which waits for its
  verdict. Details: `docs/action.md`.
- Docs: the design and threat model for the Gemini paid-path broker (#205): a small unprivileged system service behind a
  socket unit that holds the paid key, the approval consumption records and the spend ledger, verifies the signed
  approval and makes the vendor call, with image generation as the first case. Documents only; no broker code, and
  paid use stays disabled.
- Gemini Tier 2: real WebAuthn assertion verification (ES256 and EdDSA) with the `cryptography` package, an optional
  hash-locked extra (`safo[passkeys]`). Opt-in; nothing in the approval path calls it and paid use stays disabled (#211).
- Guard: a dedicated entry point, `safo-guard` (and `python -m safo.guard`), so the hook never parses subcommands
  (#189). It reads only `--agents` and `--agents-local`, ignores every other word, and always computes the verdict.
- `safo hooks install` writes the new hook command and migrates an existing `safo hooks guard` line on a rerun.
  `safo hooks status` reports the installed form (new, legacy, mixed, absent) and takes `--settings`.
- Lines `safo hooks guard ...` already installed keep the frozen legacy routing. Re-installing the live hook is a
  separate, explicit step after the release.
