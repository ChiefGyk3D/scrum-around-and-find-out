# SIEM Wiki and Boards Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the scattered documentation of the SIEM group into PR-reviewed, topic-based wikis published through the shared GYST workflow, and track the work on four project boards, without losing a fact or publishing an identifier.

**Architecture:** A deterministic move tool (registry in, `git mv` and link rewrite out, with a no-line-lost check) does every move and merge. Writer agents do only the splits, working from a section map and the verified-facts ledgers. Each repo's pull requests land on `main` with the wiki build running but `publish: false`; the last pull request flips publishing on. The upstream GYST builder, tree gate and leak scan are built in parallel under GYST issues and swapped in by a small follow-up per repo.

**Tech Stack:** Python 3 standard library (move tool, split check, leak scan), GitHub Actions reusable workflows (GYST `wiki-publish`), `git`, `gh`, `safo`.

**Spec:** `docs/superpowers/specs/2026-10-22-siem-wiki-and-boards-design.md` (sections 5 to 15a). Epic: ChiefGyk3D/scrum-around-and-find-out#63. Packages: #64, #65, #66, #67. GYST epic: ChiefGyk3D/git-your-ship-together#165.

## Global Constraints

- Threat model before build (`docs/threat-model.md`, #71): n/a for this work. The rule covers AI-facing parts of a system, and the wiki generator, move tool and leak scan are deterministic code that parse repository files and do not feed a model; read `docs/threat-model.md` on 2026-10-26 before claiming this. If a task later adds code whose input reaches a model, that task's issue needs its own `threat-model:` line.
- Inputs not versioned: this plan cites scratchpad-only inputs (`wave1/report-A-*`, the `verified-facts-*.md` ledgers, the tool spikes under `wave1/tools/`) that are not in the repository, so the plan cannot be re-run from the repository alone.
- American English everywhere (defense, behavior, color). mother-ticker docs: no em dashes (test-enforced there).
- Never publish or commit: secrets, private or CGNAT addresses, MACs, emails, hostnames, serials, a callsign or grid square, an employer name. Placeholders: 203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24, `example.com`, `N0CALL`, `N0TST`, `FN31pr`, `<SIEM_IP>`.
- Nothing is deleted. A moved or merged file loses no non-blank line; superseded material goes to an `Archive-` page.
- Wiki page names are flat `Topic-Words-Hyphenated` with a prefix from: Suricata-, pfBlockerNG-, EVE-Forwarder-, Telegraf-, pfSense-, SIEM-, Docker-Stack-, SOAR-, CrowdSec-, Install-, Operate-, Troubleshoot-, Reference-, Project-, Archive-. Landing pages: Home, Start-Here, Glossary, FAQ.
- Topic pages use exactly these part headings, omitted when empty: `## Learn it`, `## Set it up`, `## Our settings`.
- Code, compose files and scripts beat prose; a dated CHANGELOG entry beats older prose; a live-system fact is the maintainer's. A merged page states only verified facts (ledgers `verified-facts-pfsense.md`, `verified-facts-docker-and-small-repos.md`).
- Root of each repo after the move: README, SECURITY, LICENSE, code, `.example` configs, `.github/CONTRIBUTING.md` (pointer), and CHANGELOG.md (release tooling reads it; the wiki mirrors it).
- One pull request per cluster, each linking its issue (`Refs`), never `Closes` an epic. The maintainer merges. Check the PR is open before every push.
- Every agent brief carries `issue: owner/repo#N` and a named local-model step or `local-llm: n/a - <true reason>`. Always run `llm-local` with `< /dev/null` and one request at a time on gemma4:12b.
- Subagents: `model: "sonnet"` (Haiku only for one-file mechanical edits). Opus only with the maintainer's OK. Reviewer is never the author. Security-relevant code (anything that parses untrusted files, writes a public wiki, or scans for secrets) also gets a Codex adversarial review before merge.
- `publish: false` on the wiki workflow until the final pull request of a repo.

## Review Focus

1. A split drops or duplicates a line. Test: `splitcheck.py` must pass on every split (Task 2) and fail on a deleted line.
2. A link or doc path inside a fenced block or inline code is rewritten, or a real link is not. Test: docmove fixtures (Task 2).
3. A script, workflow or message still names a moved doc (`release.sh`, the `pfsense-siem` console, installers, CI paths). Test: Task 4 adds a check that every `*.md` path string in tracked non-markdown files resolves.
4. A real value survives into a public page, or a placeholder is mistaken for one. Test: identifier scan exit 0 on every page, and exit 1 on a planted value (Task 3).
5. An old wiki URL breaks. Test: every old page name has a stub page pointing to its new home (Task 4).

---

### Task 1: Page-name registry and validator (pfsense-siem-stack)

**Files:**
- Create: `docs-migration/registry.csv`, `docs-migration/check_registry.py` (in the repo, removed in Task 11)
- Source of truth: scratchpad `wave1/report-A-*`, `report-B1-*`, `report-B2-*`, `verified-facts-pfsense.md`

**Interfaces:**
- Produces: `registry.csv` columns `repo_path,section,page,action,order` where `action` is one of `move`, `merge-into`, `split-into`, `archive-into`, `keep`, `stub`; `section` is empty or a heading range for splits.
- `check_registry.py REGISTRY --repo DIR` exits 0 when every tracked `*.md` appears at least once, every `page` matches the naming rule, no two different sources map to one page unless `merge-into` or `archive-into`, and no page collides case-insensitively; exit 2 otherwise with each offender named.

- [ ] **Step 1:** Write `test_check_registry.py` with the cases: unknown file in repo, duplicate page, bad prefix, case collision, section range overlap on one source. Run: expect FAIL (module missing).
- [ ] **Step 2:** Implement `check_registry.py`; run the tests: expect PASS.
- [ ] **Step 3:** Writer agent (route: `integration-code` for the tool, `research` for the table; Sonnet) builds `registry.csv` from the three disposition reports, resolving name collisions across reports A/B1/B2 once, with the ledger sentence noted per merge in a `notes` comment column. Local step: first-pass section tagging with `llm-local --task registry-tag --model gemma4:12b < /dev/null`; code does grouping and counting.
- [ ] **Step 4:** `python3 -I check_registry.py docs-migration/registry.csv --repo .` exit 0 on the real repo. Reviewer (Sonnet) cross-checks 10 random rows against the source files.
- [ ] **Step 5:** Commit on branch `docs/wiki-restructure-1-registry`.

### Task 2: Move tool and split check into GYST

**Files:**
- Create in `git-your-ship-together`: `scripts/docmove.py`, `scripts/splitcheck.py`, `tests/test_docmove.py`, `tests/test_splitcheck.py`
- Starting point: scratchpad `wave1/tools/docmove/` (41 tests passing; throwaway spike). Issue: new GYST issue under epic #165.

**Interfaces:**
- `python3 -I docmove.py --repo DIR --map registry.csv [--dry-run] [--subfolder wiki] [--report where-did-it-go.md] [--strict]`: validates, `git mv`s, merges in `order`, rewrites relative links and literal doc paths in tracked non-markdown files, writes the report, then checks that no non-blank line was lost. Exit 0 ok, 2 on any ambiguity.
- `python3 -I splitcheck.py --source FILE --out PAGE [PAGE ...]` exit 0 only when every non-blank source line appears in exactly one output page after removing link edits and provenance comments; exit 1 lists missing and duplicated lines by number.

- [ ] **Step 1:** Port the spike's tests into GYST's test layout; add the review-focus cases: link in fenced block, link in inline code, indented code block (the spike rewrote these: make it leave them), reference-style link defined over two lines, wiki-style `Name` links, case-colliding destination.
- [ ] **Step 2:** Run: expect the indented-block and two-line-reference tests to FAIL.
- [ ] **Step 3:** Fix `docmove.py` for those two cases; add `splitcheck.py` with tests (deleted line, duplicated line, link-only edit passes). Run all: expect PASS.
- [ ] **Step 4:** Reviewer (Sonnet) plus Codex adversarial review (it reads untrusted paths and writes files). Fix rounds capped at five.
- [ ] **Step 5:** Merge to GYST `main`; the migrations call it by commit from a checkout of GYST, no release needed.

### Task 3: Identifier scan, usable now

**Files:** GYST `scripts/identscan.py` + tests (GYST issue #174); starting point scratchpad `wave1/tools/identscan/` (66 tests passing).

**Interfaces:** `python3 -I identscan.py PATH... [--allow FILE] [--format text|json] [--all]` exit 0 clean, 1 findings, 2 cannot tell; prints `file:line:class` and a constant redacted shape, never the value.

- [ ] **Step 1:** Add `192.168.1.x`-style and `<IP>` forms and the "documentation private range" waiver with a mandatory reason; add a test that fails if any matched value appears in stdout, stderr or JSON.
- [ ] **Step 2:** Fix the quadratic hostname pattern the spike's mutation test exposed; add a timing test (a 200 KB hostile line finishes under one second).
- [ ] **Step 3:** Codex adversarial review; Sonnet review; merge. Each migration PR runs it with `warn` first, then `fail` in the final PR.

### Task 4: pfsense-siem-stack mechanical move (PR A, #64)

**Files:** every tracked `*.md` per registry; modify `scripts/release.sh`, `pfsense-siem`, `install.sh`, `setup.sh`, `install_plugins.sh`, `scripts/{status,preflight,setup_forwarder_monitoring,build-wiki,check-doc-links}.*`, `.github/workflows/{ci,wiki}.yml`, `README.md`, `ORGANIZATION.md`, `CONTRIBUTING.md`.

**Interfaces:**
- Consumes: Task 1 registry, Task 2 tools.
- Produces: `wiki/` holding the moved pages, `where-did-it-go.md`, a stub page for every old wiki page name, `.github/workflows/wiki.yml` calling GYST `wiki-publish` at the current pin with a repo-local `generate-command` and `publish: false`.

- [ ] **Step 1:** Add `tests/test_doc_paths.py::test_every_doc_path_in_code_resolves` (scans tracked non-markdown files for `*.md` path strings, asserts each exists). Run: expect FAIL after the move dry-run is applied to a clone.
- [ ] **Step 2:** `docmove.py --dry-run` on the repo, review counts, then apply for `move`, `merge-into`, `archive-into` rows only (splits wait for Tasks 5 to 8).
- [ ] **Step 3:** Fix the ~40 code references from the Codex inventory (`report-F`); CHANGELOG.md stays in the root and `release.sh` is unchanged; `.github/CONTRIBUTING.md` becomes a pointer; `.gitleaksignore` fingerprints are not rewritten.
- [ ] **Step 4:** Replace `wiki.yml` with the GYST caller; delete `scripts/build-wiki.py`'s PAGES map in favor of a small generate-command that copies `wiki/` flat; keep `scripts/check-doc-links.py` pointed at `wiki/`.
- [ ] **Step 5:** Run `identscan` (warn), link check, `test_doc_paths`, the repo's `make`/CI gate; record exit codes in the PR. Sonnet review. Commit, push, PR `Refs #64`.

### Tasks 5 to 8: pfsense page clusters (PRs B to E, #64)

Each task: one writer agent (route `integration-code`, Sonnet) writes the cluster's pages from the registry's `split-into` rows and the section maps in the reports, applying the ledger sentences and fixing the stale spots listed there; then `splitcheck.py` on every split; then `identscan`; then a fresh Sonnet reviewer (spec compliance and quality, separate verdicts). Local step per task: `llm-local --task docs-proofread --model gemma4:12b < /dev/null` over each finished page for typos only; a Claude model checks every change it suggests.

- [ ] **Task 5 Suricata (6 pages)** and **Task 6 pfBlockerNG (5 pages + whitelist data file notes)**: sources `docs/pfsense/SURICATA_*`, `LAN_MONITORING`, `config/sid/README`, `PFBLOCKERNG_*`. Test per page set: the part headings exist where sources had content; the retired SSL Blacklist IP feed appears only as a warning; `#3-dashboard-panels` anchors are gone.
- [ ] **Task 7 EVE forwarder + Telegraf (about 12 pages)**: sources `INSTALL_PFSENSE_FORWARDER`, `SURICATA_FORWARDER_MONITORING`, `LOG_ROTATION_FIX`, `GEOIP_SETUP`, `TELEGRAF_*`, `plugins/README`, `MAC_VENDOR`. Test: pages state two pidfiles, Cron-package watchdog, no sysrc, `procstat -f` and never the stale forms (grep test over the pages).
- [ ] **Task 8 Install, Operate, Troubleshoot, Reference, Project, Archive, landing pages**: the 496-line troubleshooting guide becomes a symptom start page plus per-problem pages; `Home`, `Start-Here`, `Glossary`, `FAQ`, sidebar rebuilt from the existing hand pages; public wording of the landing pages drafted by ChatGPT (non-technical copy per the maintainer's standing rule), technical facts checked by Claude. `shaping` and `LAN_MONITORING` pages use generic segment names and documentation ranges; the maintainer's real names go under `## Our settings` as placeholders. The Wazuh dashboards page uses placeholders for UIDs and the example password. Test: retention default text says 90 days and that setup.sh only displays it.

### Task 9: pfsense final gate and publish flip (PR F, #64)

- [ ] **Step 1:** `identscan` in `fail` mode; link check; `splitcheck` for every split; `where-did-it-go` count line equals the number of source files; British-spelling grep over `wiki/` returns nothing.
- [ ] **Step 2:** Remove `docs-migration/`; set `publish: true`; Codex adversarial review of the generate-command and the workflow (it reads repo files and writes a public wiki); Sonnet review.
- [ ] **Step 3:** The maintainer merges; confirm the wiki shows the new Home; stubs resolve; record the wiki URL in the issue.

### Tasks 10 to 14: siem-docker-stack (#65)

Same pattern as Tasks 1, 4, 5 to 8, 9, with these specifics:

- [ ] **Task 10 Registry and mechanical move** (`wiki/` folder, GYST caller with `publish: false`, scripts that print doc paths: `scripts/deploy-n8n-soar.sh`, `scripts/10-snapshot-setup.sh`, compose and `.env.example` comments; fix the two broken references to non-existent docs and the `pfsense_siem_stack` path).
- [ ] **Task 11 README split** (725 lines into about 15 pages plus a 90 to 110 line README) with `splitcheck.py` against the README.
- [ ] **Task 12 Integrations and SOAR pages** (CrowdSec merged with the pfsense plan, VirusTotal, JumpCloud, Twingate, n8n x3, enrichment standard, detection ownership as "live inventory, not repo-deployed"). Test: pages state OpenSearch security is enabled and use `https://` with credentials; n8n is a separate container on port 80.
- [ ] **Task 13 Operate, Troubleshoot, Project, Archive**: planning docs split; n8n ideas to `Archive-n8n-Automation-Ideas` with its numbering intact; roadmap items listed for Task 17; the shared troubleshooting start page lives here and the pfsense wiki links to it.
- [ ] **Task 14 Final gate and publish flip**, as Task 9.

### Task 15: Small repos (#66)

- [ ] **Step 1:** `jumpcloud-wazuh-bridge`: one page `SIEM-JumpCloud-Bridge` with the duplicate-ruleset warning and "the stack owns detections; the bridge's 100300-100350 set is standalone-only"; fix its roadmap license and lint claims (Apache-2.0; ruff blocking).
- [ ] **Step 2:** `mother-ticker`: page `SIEM-Mother-Ticker-Integration` (three paths, scrape job name `mother-ticker`, SD id `mt@32473`); fix the docstring SD id; keep its tests green and its no-em-dash rule; no separate wiki.
- [ ] **Step 3:** `netpulse`: PR #63 (canonical bucket, Apache-2.0) merges first; then one reference entry. Each repo's short README links the SIEM wiki.

### Task 16: CAH cross-links (#67)

- [ ] **Step 1:** Using `report-E` proposals, a Sonnet agent edits CAH `docs/wiki/*` to link to SIEM pages (link sentences only, no new facts) and the SIEM pages to CAH lessons; run CAH's own wiki tests and link checks.
- [ ] **Step 2:** Do not copy either of CAH's conflicting stage 2 status statements; record the conflict as a CAH issue.

### Task 17: Boards and cards

- [ ] **Step 1:** Merge PR #69 (board files). Finish `safo reconcile` on projects 9, 10, 11 and re-run `safo audit`.
- [ ] **Step 2:** Triage the new cards' Kind, Epic and Effort: local draft with `llm-local --task issue-triage < /dev/null`, code groups and counts, a Sonnet reviewer checks every value before any is applied (the model's verdicts are never applied directly).
- [ ] **Step 3:** File the open roadmap items from siem-docker-stack (about 60, one line each from `report-C`) as issues with `Refs #65`; never invent a Kind.
- [ ] **Step 4:** Hand the maintainer the copy-paste list of UI-only settings printed by `bootstrap` for projects 9, 10, 11.

### Task 18: Hygiene issues

- [ ] File and complete: history scan per repo (not a gate; findings mean rotate, not rewrite); `.env` in `.gitignore` for pfsense-siem-stack; dashboard JSON datasource UIDs to variables; fix the `llm-local` stdin hang (propose to the maintainer first); mother-ticker secret-scan caller check; the bridge and netpulse caller names.

### Task 19: GYST upstream and the swap

- [ ] Work GYST issues #166 to #180 in the order: #166 spike, #167 builder, #173 tree gate, #174 leak scan, then the rest. Each: Sonnet implementer, Sonnet reviewer, Codex adversarial review where it parses untrusted input. Release; then one small PR per repo re-pins and swaps the local generate-command for the upstream builder (SAFO, pfsense, docker; CAH last with a byte-level golden comparison).

## Self-Review notes

- Spec coverage: sections 5 (Tasks 1, 4 to 8), 6 (Tasks 5 to 8, 11 to 13, 15), 7 (Tasks 2, 4), 8 and 8a (Tasks 2, 3, 4, 9, 19), 9 (Tasks 3, 9, 18), 10 (ledgers feed Tasks 5 to 13), 11 (Task 17), 12 (Task 16), 13 (global constraints), 14 (Tasks 9, 14, 17).
- Not in this plan: the maintainer's merges, the view settings no API can set, and any decision still open in spec section 15.
