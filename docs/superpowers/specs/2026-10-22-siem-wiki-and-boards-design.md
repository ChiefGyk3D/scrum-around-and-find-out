# SIEM stack wiki and project boards: design

Status: draft for the maintainer's approval. Date: 2026-10-22. Epic: ChiefGyk3D/scrum-around-and-find-out#63.
Work packages: #64 (pfsense-siem-stack), #65 (siem-docker-stack), #66 (bridge, mother-ticker, netpulse), #67 (Clouds Against Humanity cross-links).
Written by the lead (Claude) from the maintainer's decisions and from ten read-only research reports. Statements marked **(my call)** are the lead's and were not decided by the maintainer.

## 1. Intent

The SIEM group's documentation grew in the order the work happened, written by Copilot sessions before the wiki and agent workflow existed. The facts are good and the layout is not: the same topic (pfBlockerNG, Suricata, the EVE JSON forwarder) is spread across many files, three files describe the layout, several pages contradict each other, and the planning notes sit beside the install guides.

The goal is a wiki a stranger can learn from, build from, and (for the maintainer) use as the record of his own settings, without publishing anything that identifies his network. The same effort ties these repos, and the other in-progress projects, into the project boards defined as code in Scrum Around and Find Out, so that nothing is hidden work.

## 2. Scope

Repos in the SIEM group: `pfsense-siem-stack`, `siem-docker-stack`, `jumpcloud-wazuh-bridge`, `mother-ticker`, `netpulse`. Related: `Clouds-Against-Humanity` (CAH), which links to the SIEM wikis and which they link back to. Tooling: the shared repo `git-your-ship-together` (GYST) for publishing and checks. Boards: four new user-owned GitHub Projects plus the existing ones.

## 3. Goals, non-goals, anti-goals

Goals
- One topic, one page set. Every fact survives once, on the page where a reader would look for it.
- Each topic page can serve three readers: someone learning it, someone building their own, and the maintainer recording his choices ("Our settings", with placeholders where a value would identify him).
- Docs are reviewed like code: markdown in the repo, pull request, published to the wiki on merge.
- Both SIEM repos call the shared GYST workflows for publishing and for the new leak check.
- Boards exist for each group and for the whole portfolio, defined as code.

Non-goals
- Changing what any tool does. The one code change allowed is repointing scripts that print or read doc paths.
- Rewriting the content for style. Pages are reorganized and de-duplicated; wording is fixed only for contradictions, stale statements, and the American-English rule.
- A Jira instance. Considered and set aside for now (the free plan caps automation at 100 rule runs a month site-wide).

Anti-goals (a failure even if it technically works)
- Any lost information. A moved or merged file with a missing line is a defect.
- Any real secret, private network detail, callsign, grid square, employer name, hostname or serial on a public page.
- A wiki edited by hand in the browser, or a docs build that cannot fail.
- Contradictions copied forward because two files were merged mechanically.

## 4. Decisions made by the maintainer

1. The wiki is the home of all documentation. Markdown stays in each repo in a wiki folder, is PR-reviewed, and is published to the GitHub wiki on merge. The repo root keeps README, SECURITY, LICENSE, code and `.example` configs.
2. Nothing is deleted. Files move with `git mv`; a where-did-it-go table accounts for every file; superseded material goes to Archive pages.
3. Publishing uses the shared GYST `wiki-publish` workflow, not a local copy. Generic improvements flow to GYST first.
4. Boards: one shared board for the SIEM group plus CAH; one board for the SIEM group alone; CAH keeps its own board; one portfolio board for everything. Mother-ticker and netpulse are part of the SIEM group.
5. Order of work: board structure, then pfsense-siem-stack, then siem-docker-stack, then the three small repos, then CAH cross-links.
6. Agents follow the SAFO routing rules. Local model first for text work; Sonnet by default; Opus only with his OK.

## 5. Wiki design

Structure rules
- GitHub wikis are flat. Page names are `Topic-Words-Hyphenated`, with a topic prefix: `Suricata-`, `pfBlockerNG-`, `EVE-Forwarder-`, `Telegraf-`, `pfSense-`, `SIEM-`, `Docker-Stack-`, `SOAR-`, `CrowdSec-`, `Install-`, `Operate-`, `Troubleshoot-`, `Reference-`, `Project-`, `Archive-`. Landing pages: `Home`, `Start-Here`, `Glossary`, `FAQ`, plus the sidebar and footer.
- **One registry.** A single `page-names` table (source file or section, page, action, order) is the source of truth. The move tool, the link rewriter and the where-did-it-go table all read it. No agent invents a name outside it.
- Topic pages carry up to three parts, named the same everywhere: Learn it, Set it up, Our settings. A part is omitted when the sources have nothing for it; the gap is recorded as a board item, not filled with invention.
- Archive pages keep dated material (tuning results, branch notes, review snapshots, an ideas chat). Anything cited by number elsewhere keeps its numbering.
- Two wikis, one per repo, linked at the top of each Home and Start-Here **(my call)**. A topic that two repos share (CrowdSec, the troubleshooting entry page) lives in the siem-docker-stack wiki, with a pointer page in the pfsense wiki, because the Docker stack is the more general backend.
- Old page names: a one-line stub page for one release pointing at the new page **(my call, see question 6)**.
- The existing hand-written pages (Home, Start-Here, Glossary, FAQ, sidebar) are the best content in pfsense-siem-stack and are the starting point for the new landing pages. The Docker repo gets the same set, written fresh.

What stays in each repo
- Root: README (a short front door), SECURITY.md, LICENSE, code, `.example` configs. GitHub reads CONTRIBUTING and SECURITY from the root or `.github/`, so CONTRIBUTING becomes a short pointer in `.github/` and the full text is a wiki page. CHANGELOG.md stays in the root because the release scripts read and rewrite it; the wiki carries a mirror **(my call, see question 1)**.
- Beside-code READMEs (scripts, tests, dashboards, Prometheus targets, certs) shrink to a pointer; the long content becomes `Reference-` pages.

## 6. Page families (from the research; the registry settles exact names)

pfsense-siem-stack (55 markdown files)
- Suricata (about 6 pages): overview, setup and rules, performance tuning, SID management, LAN monitoring, operations and troubleshooting. Duplicated memcap, rule-source, update-schedule, interface-strategy and stats text survives once.
- pfBlockerNG (about 5 pages plus the data file): overview and strategy, feed catalog, feed health and validation, whitelist and false positives, whitelist privacy notes. The retired SSL Blacklist recommendation is corrected, not copied.
- EVE forwarder (about 8 pages): overview, install, GeoIP, operations and watchdog, multi-interface, Logstash pipeline, log rotation, reference and files-on-pfSense, plus its troubleshooting.
- Telegraf (4 pages): install and configure, plugins, MAC vendor lookup, pfBlockerNG-to-OpenSearch.
- pfSense platform: upgrade guide (generic) and the dated real-run page, traffic shaping guide, measured shaping tuning, tuning results (dated), CrowdSec plan.
- SIEM backends: OpenSearch retention, operations and index templates; Grafana dashboards; Wazuh integration and dashboards; backend comparison; Graylog and legacy material to Archive.
- Install and operate: hardware requirements, new-user checklist, quick start, server install, dashboards install, management console, preventive maintenance.
- Troubleshooting: a symptom-first start page and about 15 per-problem pages, mapped section by section from the 496-line guide.
- Reference and project: configuration, field reference, architecture, repository layout, scripts, tests, roadmap, changelog mirror, contributing, release process.

siem-docker-stack (18 markdown files, no wiki yet)
- The 725-line README splits into about 15 pages: architecture, reference build, services and ports, install, security upgrade, change passwords, dashboards, hot/warm storage, pfSense integration, secrets, repository layout. A 90 to 110 line README remains.
- Integrations: CrowdSec (merged with the pfsense plan), VirusTotal cache, JumpCloud bridge, Twingate ZTNA.
- SOAR: n8n overview, deploy, gotchas, alert enrichment standard, detection ownership, local-LLM guidance.
- Operate: maintenance, backup and restore, verify foundation.
- Project: roadmap and design notes, game plan, cross-repo ownership. Open roadmap items become board cards. The n8n ideas file (a pasted chat) goes to Archive with its numbering intact.

Small repos
- `jumpcloud-wazuh-bridge`: one SIEM page plus a short README (no wiki of its own). `netpulse`: README plus one reference entry (no wiki). `mother-ticker`: one SIEM integration page now; its own wiki is a later choice for the maintainer (question 4).

## 7. How the work is done

Moves and merges are mechanical and checked; splits are writing and are reviewed.
- **Move tool** (a throwaway spike exists and passed its tests; it becomes real only through the plan): reads the registry, validates it, performs `git mv`, merges in order, rewrites every relative link and every literal doc path in scripts and workflows, writes the where-did-it-go table, and fails if any non-blank line is lost. Fenced and inline code are never rewritten.
- **Splits** (the 496-line troubleshooting guide, the 725-line README, the roadmap, the three Suricata guides) are done by writer agents from a page-by-page section map. A script checks that every non-blank source line appears on exactly one output page.
- **Code that reads docs** changes in the same pull request as the move: `scripts/release.sh` (reads CHANGELOG), the `pfsense-siem` console menu (opens three docs), installer and status scripts that print doc paths, the link checker, CI, the wiki workflow, and README, CONTRIBUTING and ORGANIZATION prose. `.gitleaksignore` fingerprints are historical and are not rewritten.
- One pull request per cluster, small enough to review. Each links its issue. The maintainer merges.

## 8. Publishing, GYST and the leak check

What exists today: GYST already has a reusable `wiki-publish.yml`. It is a transport, not a builder. The caller supplies a `generate-command` that writes the page tree; the workflow runs it with read-only permissions, then a second job with write permission pushes the tree to the wiki. It has a `publish` input that, when false, builds and uploads the tree without publishing. CAH and Scrum Around already use it with their own generators. So "call GYST" means: supply a generator and let GYST publish.

- `pfsense-siem-stack` drops its local `wiki.yml` and `build-wiki.py` PAGES map and calls GYST `wiki-publish`; `siem-docker-stack` adopts it. Callers are pinned by commit with the version comment; they currently pin v1.21.0 and GYST is at v1.23.0, so the move includes a re-pin. The local GYST checkout on this machine is 80 commits behind and is not used as a source of truth.
- GYST gains, in order: a hardened builder (lift SAFO's `gen_wiki.py`, which survived four adversarial rounds), a tree gate in the publish job (regular `.md` and image files only; no hidden files, no `.git` content, no symlinks), and a build-time **identifier leak check** that prints `file:line:class` and never the value. The research found the current publish step copies hidden files and follows symlinks by path. These are potential exposures, not demonstrated leaks.
- The leak check covers what gitleaks does not: private and CGNAT addresses, MACs, emails, internal-looking hostnames, callsign and grid shapes (context-gated), webhook URLs. Documentation ranges (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24), example domains and the standard placeholders pass. Waivers need a reason.
- Any generator that reads untrusted files and writes a public wiki gets a Codex adversarial review before merge, as the SAFO rules require.

## 8a. Sequencing and dependencies (answers the builder check)

1. **Critical path.** The repos do not wait for GYST. Step one for each SIEM repo calls the existing `wiki-publish` with a repo-local `generate-command` (a small copy of the proven SAFO builder) and `publish: false`. The upstream hardened builder, the tree gate and the leak check are GYST work done in parallel, each with its own issue and board card (the research proposed 19 one-line GYST issues; they are filed from the plan, not before). When GYST tags a release containing them, each repo re-pins and swaps its local generator for the upstream one in a small follow-up pull request **(my call)**.
2. **Where the move tool lives.** In GYST, as a script with its tests, because both SIEM repos need it and CAH may later **(my call, per the consolidate-into-GYST rule)**. The registry is a plain CSV (`repo_path,new_path,action,order`), one file per repo, kept in that repo until the migration is done. GYST owns the format.
3. **Fact verification is part of #64 and #65**, scheduled before any page cluster is written. The conflict list already exists as input (the research reports plus a retrieval pass that found 106 near-duplicate groups and 4 conflicts). Whatever code cannot settle goes to the maintainer in one batch.
4. **No half-migrated public wiki.** Pull requests land on `main` with `publish: false`, so the build runs and fails reviews but nothing is pushed to the wiki. The final pull request in each repo flips `publish` to true. Until then the wiki keeps its current content **(my call)**.
5. **Questions that block and questions that default.** Questions 2, 7 and 8 in section 15 touch privacy or legal claims, so no page they affect merges until they are answered; the stated default is the conservative one (replace with documentation values; omit the license claim and link to the LICENSE file; use placeholders). The rest proceed on their defaults.
6. **History scan** is a separate issue per repo and is not a gate for the wiki, which publishes only current content from repos that are already public. A finding means rotate the secret and tell the maintainer; no history is rewritten without his decision **(my call)**.
7. **Boards.** The agent drafts and validates the files offline. The maintainer approves the drafts, including the area-to-repo guesses. Creating the projects and the view settings no API can set are run from his own `gh` login with copy-paste commands; the work packages do not block on them except for the cards they use.
8. **Release script.** If CHANGELOG.md stays in the root (question 1 default), `release.sh` needs no change. If the maintainer moves it, that is a code change reviewed on its own.

## 9. Secrets and identifiers

Research result: across 495 tracked files in the five repos there is no live secret, private key, real-looking email or MAC, callsign, grid square or employer name. Weak vendor defaults appear in examples and must be labeled "change before use". Two pfsense pages (a VLAN plan and a traffic-shaping guide) may mirror the real network and need the maintainer's answer (question 2). Dashboard JSON hard-codes Grafana datasource UIDs from a live instance; they become variables. A history scan is still owed for all five repos; only the bridge has a recorded clean one. `.gitignore` in pfsense-siem-stack lacks a plain `.env` entry. No scanner currently covers identifier-class leaks, which is what section 8 adds.

## 10. Facts that disagree between files

More than 40 conflicts were found (watchdog location, retention default, OpenSearch security on or off, ports, versions, rule counts, license lines, bucket names, a Docker-versus-bare-metal install path). The rule: code, compose files and scripts beat prose; a dated CHANGELOG entry beats older prose; a live-system fact is the maintainer's to answer. Two verification passes settle everything the code can settle, and only the remainder reaches the maintainer. A merged page never states a fact that was not verified.

## 11. Boards

Four new user-owned projects, defined as code in this repo and kept current from the maintainer's own `gh` login (no App can write a user-owned project):
- **SIEM Stack**: the five repos; areas for Suricata, pfBlockerNG, EVE forwarder, Telegraf, SIEM backends, Docker stack, SOAR and n8n, Wiki and docs, Security and scanning, Process.
- **SIEM and CAH**: the same plus CAH, with a cross-link area.
- **All Projects**: a read-friendly portfolio of every tracked repo (25 repositories drafted), grouped by project.
- CAH keeps project 4; its definition file is corrected so the Agent field lists all seven live options (Claude, Codex, Copilot, You, ChatGPT, Ollama, RAG).
The drafts exist and pass SAFO's offline validator. Area-to-repo assignments and area-matching keywords are the lead's guesses and are reviewed before creation. Creating a project, and its view settings that no API can set, are the maintainer's steps. Every item needs a status, area, kind, epic and effort for `safo audit` to pass.

## 12. Clouds Against Humanity

Links go both ways and only link; they add no facts. The research produced a page-by-page proposal in both directions and a list of concepts each side assumes. Gaps to record, not fill: CAH has no network IDS/IPS or DNS-blocking lesson. CAH's own pages disagree about whether its stage 2 is built, and that is corrected in CAH, not copied.

## 13. Agents and routing

Per the SAFO routing table: research to Codex or Sonnet; implementation and review to Sonnet; Copilot reviews pull requests only; the local model drafts text and a Claude model checks it; ChatGPT writes the public wording (Home, Start-Here, FAQ prose); retrieval over the docs runs on the small GPU's embedder to find near-duplicate passages across files; Opus only with the maintainer's OK. Every brief carries `issue: owner/repo#N` and a named local-model step or a stated reason it does not apply. Operational findings from this work: `llm-local` reads stdin before sending and hangs forever when stdin is an open pipe (always run it with stdin from `/dev/null`; the tool should be fixed); the dispatch guard fails closed when its issue lookup cannot answer.

## 14. Done when

- Both SIEM repos publish a topic wiki from PR-reviewed markdown through the GYST workflow; roots hold only the allowed files.
- The where-did-it-go table accounts for every source file and the lossless check passes.
- No code, CI or script references a doc path that no longer exists.
- The leak check runs in CI and fails on a planted value; a history scan is recorded for each repo.
- The three smaller repos have wiki pages; CAH and the SIEM wikis link each way.
- The four boards exist, pass `safo audit`, and carry the open roadmap items as cards.

## 15. Questions only the maintainer can answer

Ranked. Each has a default; silence means the default applies.
1. Root files: keep CHANGELOG.md in the root (release tooling reads it), CONTRIBUTING as a `.github/` pointer, and mirror both on the wiki? Default yes.
2. Are the VLAN plan in the LAN-monitoring guide and the topology in the traffic-shaping guide your real network? Default: treat as real and replace with documentation ranges and generic VLAN numbers.
3. Reference hardware: two different firewalls are described as "the reference deployment" (an 8-core Atom and a 4-core Xeon D). Present both, labeled? Default yes.
4. Does mother-ticker get its own wiki? Default no: one SIEM integration page.
5. CrowdSec: supported part of the stack, or still exploratory? The docs disagree. Default: describe what the code supports and mark the rest planned.
6. Redirect stubs for old page names for one release? Default yes.
7. Real licenses for netpulse and the bridge (the docs disagree: MIT, Apache-2.0, MPL-2.0, no file).
8. Wazuh dashboards guide contains instance-specific UIDs and a password-shaped example. Replace with placeholders? Default yes.
9. Legacy forwarder scripts: archive the docs only, or also delete the scripts? Default docs only; deletion is a separate issue.
10. Donation and social block in the Docker README: keep in README (public by design)? Default yes, as a link plus the block moved to a Support page.
11. Open roadmap items (about 60) become board cards now? Default yes, after the boards exist.
12. Approve the four board drafts, including the guessed area-to-repo assignments and area keywords? They are created from your login after you say yes.
13. Add `pfsense-siem-stack` and `siem-docker-stack` to the dispatch guard's `tracking_repos` so briefs can cite issues in those repos? (An edit to your `agents.yaml`, which only you make.) Until then briefs cite the Scrum Around issues.

## 15a. Answers received (2026-10-22) and what changed

The maintainer reviewed section 15 and the verification results and answered as follows. Everything not mentioned proceeds on its stated default.

- **Q2 (real network).** Checked read-only against the live firewall: counts only, no values stored. The LAN-monitoring guide is an example topology (none of its subnets or names exist; its VLAN numbers 10, 20, 30 are common numbers that happen to be in use). The traffic-shaping guide is partly real (four of five VLAN IDs and five of 22 names exist; it contains no real addresses). Result: public pages use generic segment names and VLAN numbers, and example subnets come from documentation ranges; the maintainer's real names live under "Our settings" as placeholders.
- **Q7 (licenses).** netpulse is Apache-2.0: add the license file and correct the README. The bridge is already Apache-2.0 (its roadmap line saying MIT is stale).
- **Q8 (Wazuh dashboards guide).** Replace instance-specific UIDs and the password-shaped example with placeholders.
- **Q9 (JumpCloud rules).** The stack owns the detections; the bridge's own 100300-100350 set is documented as standalone-only.
- **Q10 (netpulse bucket).** `netpulse` is the canonical bucket and org; fix the compose defaults, the dashboard queries and the README (a code change with its own issue and review).
- **Q11 (bridge lint).** Blocking. The prose that says advisory is corrected.
- **Q12 (boards).** The four drafts are approved. Created from the maintainer's `gh` login: projects 9 (SIEM Stack), 10 (SIEM and CAH) and 11 (All Projects), all empty when created; `reconcile` fills them next. The CAH definition file gets the Agent-field correction in its own pull request. The Status options were set through the API on the three empty boards only, because the tool refuses to rewrite that field on a populated board.
- **Q13.** `pfsense-siem-stack` and `siem-docker-stack` were added to the dispatch guard's `tracking_repos` (backup of the previous file kept).
- **Approval.** These answers, with "drafts approved", are taken as approval of this design. Anything the maintainer disagrees with is corrected through this pull request before the plan is written.

Still to do by hand (no API can set them): board view grouping and the roadmap date fields on projects 9, 10 and 11, and the project workflows (item closed to Done; pull request merged to Done). The exact steps print in each board's bootstrap output.

## 16. Left to the builder

Exact page names inside the registry, section-level splits, the wording of "change before use" notes, the order of pull requests inside each package, test design for the move tool and the leak check, and how the shared builder reaches the runner in GYST (spike on the pinned workflow commit, composite action, or an inline script).

## 17. Risks

- A split drops a line: mitigated by the lossless check and review.
- A doc path used by a script is missed: mitigated by the reference inventory (about 40 locations found) and a CI check that every doc path in code resolves.
- The publish step is attacked through a crafted doc: mitigated by the tree gate and the adversarial review.
- Writer agents invent a fact: mitigated by "verified only" rules, code-wins-over-prose, and a Sonnet review of every page cluster.
- The local model hangs or misfiles: mitigated by running it with stdin closed, one request at a time, prose only.
