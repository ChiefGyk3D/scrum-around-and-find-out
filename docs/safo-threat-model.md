# SAFO threat model

> **Status: a draft model for the maintainer and a cyber-tier review (issue #228), not an audit and not a verdict.** It
> was drawn from the repository's code, tests and docs. Each statement under a risk is marked **V** (verified: the code, a test or a
> document was read for this model) or **I** (inferred or not verified). It states guarantees and non-guarantees; it
> does not describe how to attack an unfixed weakness: an Open risk states its asset, actor class, consequence, owner,
> tracking issue and what is guaranteed today, and nothing more. Unfixed, specific detail is held privately
> ([where unfixed findings live](security-findings.md)).

The machine-readable model is an [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon) v2 file kept in the
repository: [docs/threat-model/safo.threat-dragon.json](https://github.com/ChiefGyk3D/scrum-around-and-find-out/blob/main/docs/threat-model/safo.threat-dragon.json). This page is the readable form of the same risks, with the
same ids. The rule that requires a model is on [Threat model before build](threat-model.md). The paid Gemini path has its
own design-grade model,  [Gemini broker: threat model](gemini-broker-threat-model.md) and is not repeated here (risk S22 points to it).

## Scope and method

In scope: the board-as-code Action and its credentials; agent routing, `agents.yaml` as a guard file, the usage meter and
the local-model probe; the dispatch guard and hooks, including the shell-command check and its fail-closed behavior;
handoff evidence, profiles and the lead rules; `audit`, `reconcile` and `sync` writes to GitHub; the protection and
baseline checks; the install and update path; GitHub issues, pull requests and comments as untrusted input to agents; the
guard-file edit policy; configuration sync; and local model routing.

Method: assets, actors, trust boundaries, abuse cases; risks ranked by impact and by what the actor needs first (a heavy
prerequisite ranks below a moderate one anyone can reach); a mitigation and a verification for each; residual risk. Impact
scale: **Critical** (a secret or spend outside the caps, or code run with a credential), **High** (a bypass of an approval
or a rule that matters, or a leak of the maintainer's private identifiers), **Medium** (loss within a cap, or a degraded or
false-assurance state), **Low** (annoyance or a state a person reviews).

Not done: no active testing of any system; no dynamic reproduction; the Department of Internal Arguments repository, the
internals of GYST workflows other than `threat-model.yml`, the maintainer's configuration sync tool and the host's own
hook semantics were not read, so each claim about them is marked I. This is not a complete security audit.

## Assets

| Id | Asset | Class |
|---|---|---|
| A1 | Action credentials and local authentication material | Secret |
| A2 | The Project board and the issue, pull request and comment data SAFO reads and writes | Integrity; public or private by repository |
| A3 | agents.yaml, its local override, personas and templates (the rules and instruction files agents obey) | Integrity-critical, public except the override |
| A4 | Guard state and the hook wiring | Integrity; advisory telemetry |
| A5 | Handoff evidence (review reports) that informs a merge decision | Integrity |
| A6 | Releases, the Action, CI workflows, GYST pins, dependency locks, the wiki mirror | Integrity-critical, public |
| A7 | The maintainer's private identifiers and private screening data | Sensitive; not for public artifacts |
| A8 | The local model server and the production services that share its GPU | Availability |
| A9 | Prompt confidentiality and the integrity of generated results on the local model path | Sensitive; integrity-critical |
| A10 | Agent subscription headroom (Codex, Claude, Copilot) and the GitHub request budget | Cost and availability |
| A11 | Paid-provider credentials and spend (see S22) | Secret; modeled separately |

## Actors

| Actor | Can do |
|---|---|
| The maintainer | Holds the approvals and the merges. Can make mistakes: a slip, a tired touch. |
| The maintainer's own agents, including a prompt-injected one | Run commands as the maintainer's account, read untrusted text, write briefs, comment through the maintainer's identity. |
| An outside contributor | Opens issues, pull requests and comments; a fork pull request; no secrets, no write access. |
| A compromised dependency, Action or reusable workflow | Runs inside the Action job, CI or the maintainer's tooling. |
| A compromised GitHub token, or another process on the same account | Acts with the token's scope or the account's file permissions. |
| A compromised or LAN-adjacent model server | Can observe the prompts it is sent and choose its output. |
| GitHub itself | Outage, rate limits, secondary limits, API or schema changes. |

## Trust boundaries

| Boundary | What crosses it |
|---|---|
| Public GitHub content to agents | Issue, pull request and comment text is written by anyone and read by models and by SAFO. |
| The CI job (Action) | The job that holds the Action's credentials versus anything else that runs in or before it. |
| The maintainer's account and laptop | Agents and the guard share one user id: files, settings, `gh` login. |
| The local model server | Prompts leave the laptop for a LAN host that also serves production services. |
| Upstream releases | Package index, Actions, GYST workflows, DoIA releases, install sources. |
| Private configuration sync and public publishing | Files that leave the laptop for a private remote, and docs that leave for the public wiki. |

The data-flow diagram in the Threat Dragon file draws these six boundaries, the actors, five processes, the stores and the
flows between them. Open the file in Threat Dragon (desktop or web) to see it.

## Risk register

Ranked 1 (first to work on) to 25. Status is the Threat Dragon status: **Open** means a gap or a tracked residual
remains, **Mitigated** means the controls below hold and the residual is accepted.

| Rank | Id | Risk | Impact | Prerequisites | Status | Tracking |
|---|---|---|---|---|---|---|
| 1 | S01 | Prompt injection: attacker-written text reaches a model that holds tool access | High | Actor class: any contributor to a repository an agent reads. | Open | #81, #61, #123, #230 |
| 2 | S02 | Guard files, state and hook wiring share an account with the agents the guard governs | High | Actor class: a process of the maintainer's account. | Open | #61, #130, #231 |
| 3 | S03 | The maintainer's stored GitHub login is broad and shared with the account's processes | High | Actor class: a process of the maintainer's account, or theft of the login. | Open | #82, #232 |
| 4 | S05 | Action credentials and the caller's workflow: data leakage of the Action's credentials | High | Actor class: an outside contributor or a compromised dependency; the exposure depends on how the caller wires the workflow. | Open | #236, ChiefGyk3D/git-your-ship-together#251 |
| 5 | S12 | Board writes: where the board file and the events come from | Medium | Actor class: a contributor whose change is merged, or a caller that is wired loosely. | Open | #236 |
| 6 | S24 | The caller-supplied personal access token path of the Action | High | Actor class: a caller using the token input, plus a leak of the token or a broad grant. | Open | #242 |
| 7 | S04 | The approval token and the routing rules rest on model-written text | Medium | Actor class: an agent that writes a brief. | Open | #81 |
| 8 | S06 | Supply chain: an upstream release that SAFO runs or installs | Critical | Actor class: compromise of an upstream release process. | Open | #216, #162, #163, #165, #233 |
| 9 | S07 | Handoff evidence: whether a review report matches the current head and its author | High | Actor class: comment rights as the maintainer's account, or any push after a review. | Open | #106, #160 |
| 10 | S08 | Guard enforcement: error, timeout and the limits of a text scanner | Medium | Actor class: an agent with shell access. | Open | #130, #188 |
| 11 | S09 | Data leakage: maintainer private identifiers (asset A7) or unfixed-finding detail reach a public artifact | High | Actor class: the maintainer or an agent; no attacker is needed. | Open | #123, #234 |
| 12 | S10 | Data leakage to a model host: private text sent to a host that should not receive it | Medium | Actor class: an agent that writes a brief or a prompt file. | Open | docs/gemini.md, #235 |
| 13 | S23 | Local model server: confidentiality of prompts and integrity of results on the local path | Medium | Actor class: a foothold on the home network or the model server. | Open | #241 |
| 14 | S25 | Local model answer integrity: a local answer applied without review | Medium | Actor class: an ordinary model error, or the actor of S23. | Open | #243 |
| 15 | S11 | Config sync: private SAFO material pushed to a remote | Medium | Actor class: the maintainer; no attacker is needed. | Open | maintainer-only tracking |
| 16 | S13 | GitHub rate limits and outages stall the board, audits and lookups | Medium | Actor class: none needed. | Open | #204 |
| 17 | S14 | GitHub behavior or schema changes and a check's answer | Medium | Actor class: a change on GitHub's side. | Open | #238 |
| 18 | S15 | Persona, template, agents.yaml or promotion evidence is changed to steer agents | High | A merged pull request with the owner's review, or write access to the local files (S02). | Mitigated | none needed (accepted residual in docs/limits.md) |
| 19 | S16 | A convenience call to the local model evicts a production model | Medium | A routing or configuration mistake. | Mitigated | #191 |
| 20 | S17 | A write is repeated or its outcome is guessed after an ambiguous failure | Low | A network fault or a rate-limit response at the wrong moment. | Mitigated | none needed (mitigated) |
| 21 | S18 | Process rules are satisfied by form and not substance (issue line, threat-model line, linked issue) | Low | Actor class: authorship of a brief, issue or pull request. | Open | none needed (accepted) |
| 22 | S19 | The protection read-back certifies a state that did not hold at one instant | Low | Actor class: administrator rights on the repository. | Open | none needed (accepted) |
| 23 | S20 | Usage meter or outcomes log inputs are not independent evidence | Low | Actor class: a process of the maintainer's account. | Open | none needed (accepted) |
| 24 | S21 | This threat model goes stale because SAFO's own CI does not run the Threat Dragon check | Low | None. Ordinary drift. | Open | #240 |
| 25 | S22 | Paid Gemini spend outside its caps (modeled separately) | Critical | Actor class: see that model. | Open | #205, #217, docs/gemini-broker-threat-model.md |

## Risks in detail

### S01: Prompt injection: attacker-written text reaches a model that holds tool access

- **Impact:** High. **Rank:** 1. **Status:** Open. **STRIDE:** Elevation of privilege.
- **Abuse case:** Asset at risk: the maintainer's repositories, accounts and agent quota. Actor class: an outside contributor. Consequence: text an outsider wrote influences what an agent does with the maintainer's authority.
- **Prerequisites:** Actor class: any contributor to a repository an agent reads.
- **Mitigation (V verified, I inferred):**
  - **V.** In the tested cases handoff evidence ignores comments whose author is not an OWNER, MEMBER or COLLABORATOR (docs/handoff.md, src/safo/modes/handoff.py).
  - **V.** `safo profiles brief` puts task text between random-id fences and refuses a value that can close its own fence (src/safo/brief.py). It claims structure only.
  - **V.** The status headline model sees four counts and no card titles (src/safo/headline.py).
  - **V.** `audit` and the threat-model check read single anchored lines and not free text (src/safo/threatmodel.py).
  - **V.** The maintainer merges; `safo protection` reads back code-owner review and the `CI green` gate (docs/adoption.md).
- **Verification:** tests/test_handoff_check.py::test_a_report_from_an_untrusted_author_is_ignored; tests/test_brief_fill.py; tests/test_status_headline.py; `safo protection --repo OWNER/NAME` exits 0. No test can show that a model resists an instruction; none is claimed.
- **Residual risk:** Open. Owner: the maintainer. Tracked in #81, #61, #123, #230. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** #81, #61, #123, #230.

### S02: Guard files, state and hook wiring share an account with the agents the guard governs

- **Impact:** High. **Rank:** 2. **Status:** Open. **STRIDE:** Tampering.
- **Abuse case:** Asset at risk: the guard's configuration, state and hook wiring. Actor class: an agent or process running as the maintainer's account (see docs/hooks.md, same-user limit). Consequence: tool abuse by that account could change what the guard enforces. The guard is a speed bump and an audit trail, not a boundary (docs/hooks.md).
- **Prerequisites:** Actor class: a process of the maintainer's account.
- **Mitigation (V verified, I inferred):**
  - **V.** SAFO creates its state and config directories 0700 and degrades visibly when one is not owned by the user or is group or world writable (src/safo/guardlog.py; docs/hooks.md, What is stored).
  - **V.** A private agents file must be a regular file owned by the user, with no link on the way and no group or world write above it (src/safo/trust.py).
  - **V.** `safo hooks install` keeps a private backup and re-checks the settings file's identity before the replace (docs/hooks.md).
  - **V.** Under Actions an agents file or log inside the workspace is refused (docs/hooks.md, Where the local files may live).
  - **V.** CODEOWNERS names the maintainer for agents.yaml, the persona paths and the generator (.github/CODEOWNERS).
- **Verification:** tests/test_trusted_regular_file.py; tests/test_hooks_dirs.py; tests/test_localfiles_boundary.py; `safo hooks status` shows the installed form and health.
- **Residual risk:** Open. Owner: the maintainer. Tracked in #61, #130, #231. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** #61, #130, #231.

### S03: The maintainer's stored GitHub login is broad and shared with the account's processes

- **Impact:** High. **Rank:** 3. **Status:** Open. **STRIDE:** Elevation of privilege.
- **Abuse case:** Asset at risk: the maintainer's GitHub repositories and organizations. Actor class: a process running as the maintainer's account. Consequence: calls are made with more authority than SAFO needs.
- **Prerequisites:** Actor class: a process of the maintainer's account, or theft of the login.
- **Mitigation (V verified, I inferred):**
  - **V.** Under GitHub Actions SAFO does not run `gh`; the credentials are the inputs the caller passes (src/safo/credentials.py).
  - **V.** SAFO looks for `gh` on absolute PATH entries outside the checkout and strips ambient token variables from the child (credentials.py).
  - **V.** The CLI does not ask for a broader scope on the user's behalf (docs/usage.md).
  - **V.** The App credential path has its own scoped permissions and lifetime (action.yml); the personal-token path is caller-scoped and is covered by S24.
- **Verification:** tests/test_credentials.py; tests/test_gh_token.py; tests/test_cli_credentials.py.
- **Residual risk:** Open. Owner: the maintainer. Tracked in #82, #232. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** #82, #232.

### S05: Action credentials and the caller's workflow: data leakage of the Action's credentials

- **Impact:** High. **Rank:** 4. **Status:** Open. **STRIDE:** Information disclosure.
- **Abuse case:** Asset at risk: the Action's credentials. Actor class: an outside contributor or a dependency of the caller's workflow. Consequence: the credentials are exposed, or a write is steered by untrusted content.
- **Prerequisites:** Actor class: an outside contributor or a compromised dependency; the exposure depends on how the caller wires the workflow.
- **Mitigation (V verified, I inferred):**
  - **V.** For a fork's pull request the preflight refuses credential inputs (src/safo/action_preflight.py). SAFO's claim is limited to that case; see the trust boundary of the Action in docs/limits.md.
  - **V.** Credentials are masked before use, one line at a time, and the masking command prints no value (src/safo/action_mask.py).
  - **V.** The App credential path has its own scoped permissions and lifetime (action.yml); the personal-token path is caller-scoped and is covered by S24.
  - **V.** SAFO installs into a fresh hash-pinned venv, runs isolated Python and checks the venv before and after (action.yml, src/safo/venv_check.py).
  - **V.** The local modes are refused before anything is minted (action_preflight.py).
  - **V.** Inputs reach the shell through environment variables, and the actions in this repository are pinned by commit (action.yml, .github/workflows).
- **Verification:** tests/test_action.py (the fork case), tests/test_preflight.py, tests/test_mask.py, tests/test_venv_check.py, tests/test_action_isolation.py, tests/test_workflows.py.
- **Residual risk:** Open. Owner: the maintainer. Tracked in #236, ChiefGyk3D/git-your-ship-together#251. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** #236, ChiefGyk3D/git-your-ship-together#251.

### S12: Board writes: where the board file and the events come from

- **Impact:** Medium. **Rank:** 5. **Status:** Open. **STRIDE:** Tampering.
- **Abuse case:** Asset at risk: the Project board and its cards. Actor class: an outside contributor or a misconfigured caller. Consequence: a write the maintainer did not intend.
- **Prerequisites:** Actor class: a contributor whose change is merged, or a caller that is wired loosely.
- **Mitigation (V verified, I inferred):**
  - **V.** The loader refuses duplicate keys, anchors, aliases, merge keys, files over 1 MiB and nesting over 64, and caps its lists (docs/board-yaml.md).
  - **V.** The board file and the status file must resolve to a path inside the workspace (src/safo/action_preflight.py).
  - **V.** `sync` treats the event payload as a pointer, reads the live state and writes nothing when they contradict (docs/board-yaml.md).
  - **V.** `reconcile` and `sync` write what a rule can decide and print the rest as `HUMAN` lines; `bootstrap` does not edit an existing field's options (docs/no-hidden-work.md, docs/adoption.md).
  - **V.** A dry run sends no mutation (src/safo/graphql.py); the token behind it is described under S03 and S24.
  - **V.** `safo protection` checks that board.yaml and CODEOWNERS have an owner (docs/adoption.md).
  - **V.** Adoption asks for the App to be installed on selected repositories (docs/adoption.md).
- **Verification:** tests/test_schema.py, test_duplicate_keys.py, test_schema_caps.py, test_sync.py, test_reconcile.py, test_bootstrap.py, test_codeowners_check.py.
- **Residual risk:** Open. Owner: the maintainer. Tracked in #236. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** #236.

### S24: The caller-supplied personal access token path of the Action

- **Impact:** High. **Rank:** 6. **Status:** Open. **STRIDE:** Elevation of privilege.
- **Abuse case:** Asset at risk: the repositories and board the token can reach. Actor class: a caller who supplies a token, or whoever obtains it. Consequence: the token's own authority and lifetime apply, and SAFO does not narrow them.
- **Prerequisites:** Actor class: a caller using the token input, plus a leak of the token or a broad grant.
- **Mitigation (V verified, I inferred):**
  - **V.** A personal access token is refused for an organization-owned board unless `allow-token-for-org` is true (src/safo/credentials.py); a token and an App key together are refused (src/safo/action_preflight.py).
  - **V.** The token is masked before use and is not printed (src/safo/action_mask.py, src/safo/credentials.py).
  - **V.** The App credential path has its own scoped permissions and lifetime; the personal-token path is caller-scoped.
- **Verification:** tests/test_credentials.py; tests/test_cli_credentials.py; tests/test_preflight.py.
- **Residual risk:** Open. Owner: the maintainer. Tracked in #242. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** #242.

### S04: The approval token and the routing rules rest on model-written text

- **Impact:** Medium. **Rank:** 7. **Status:** Open. **STRIDE:** Spoofing.
- **Abuse case:** Asset at risk: model-tier spend and routing discipline. Actor class: a prompt-injected or careless agent. Consequence: a dispatch goes ahead that a person did not approve.
- **Prerequisites:** Actor class: an agent that writes a brief.
- **Mitigation (V verified, I inferred):**
  - **V.** `block` mode makes forgetting visible, and an unrecognized or `inherit` model needs the token (docs/hooks.md rule 1).
  - **V.** The log records the model as `unknown` and not the value sent, and does not store the brief (docs/hooks.md, What is stored).
  - **V.** Paid-provider spend is controlled separately from this token (docs/gemini.md).
- **Verification:** tests/test_guard.py; tests/test_hooks.py; `safo hooks status` shows the mode and the retained counts.
- **Residual risk:** Open. Owner: the maintainer. Tracked in #81. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee. The token is a speed bump and not proof of approval (docs/hooks.md).
- **Tracking:** #81.

### S06: Supply chain: an upstream release that SAFO runs or installs

- **Impact:** Critical. **Rank:** 8. **Status:** Open. **STRIDE:** Tampering.
- **Abuse case:** Asset at risk: the Action's credentials and the maintainer's machine. Actor class: a compromised upstream maintainer or release. Consequence: code runs with the credentials or as the guard.
- **Prerequisites:** Actor class: compromise of an upstream release process.
- **Mitigation (V verified, I inferred):**
  - **V.** One runtime dependency, hash-locked; the Action and CI install with `--require-hashes` (requirements.txt, action.yml, .github/workflows/ci.yml).
  - **V.** GYST workflows and third-party Actions are pinned by commit with the version in a comment (.github/workflows).
  - **V.** CI sets the runner egress policy to block in this repository's callers (.github/workflows/ci.yml).
  - **V.** The DoIA release is pinned in one place, scripts/doia-tag.txt, and a test fails on any other (docs/personas.md).
- **Verification:** `pip install --require-hashes -r requirements.txt` fails on any changed file; tests/test_workflows.py; tests/test_docs.py (the DoIA pin).
- **Residual risk:** Open. Owner: the maintainer. Tracked in #216, #162, #163, #165, #233. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** #216, #162, #163, #165, #233.

### S07: Handoff evidence: whether a review report matches the current head and its author

- **Impact:** High. **Rank:** 9. **Status:** Open. **STRIDE:** Spoofing.
- **Abuse case:** Asset at risk: the merge decision. Actor class: an agent commenting through the maintainer's account, or an ordinary later push. Consequence: a pull request looks reviewed when it was not reviewed at its current head.
- **Prerequisites:** Actor class: comment rights as the maintainer's account, or any push after a review.
- **Mitigation (V verified, I inferred):**
  - **V.** Comments count when the author is an OWNER, MEMBER or COLLABORATOR and the role is a reviewing role (docs/handoff.md, src/safo/modes/handoff.py).
  - **V.** The report is read from GitHub's rendered HTML (docs/handoff.md).
  - **V.** Freshness needs proof of when the head arrived; without it the answer is unknown, and equal timestamps are unknown (docs/handoff.md).
  - **V.** The pull request is read twice and a change between reads reads as unknown (docs/handoff.md).
  - **V.** The output says a report names the head; it does not say the work was approved (docs/limits.md).
- **Verification:** tests/test_handoff_check.py, test_handoff_html.py, test_handoff_timeline.py, test_handoff_snapshot.py, test_handoff_strict.py.
- **Residual risk:** Open. Owner: the maintainer. Tracked in #106, #160. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** #106, #160.

### S08: Guard enforcement: error, timeout and the limits of a text scanner

- **Impact:** Medium. **Rank:** 10. **Status:** Open. **STRIDE:** Denial of service.
- **Abuse case:** Asset at risk: the guard's rules (waiting, vendor-API use, tracking). Actor class: an agent that writes shell commands. Consequence: a rule does not apply to a call.
- **Prerequisites:** Actor class: an agent with shell access.
- **Mitigation (V verified, I inferred):**
  - **V.** The decision is computed and written first, on one clock that starts at process start, with a margin before the host timeout (docs/hooks.md, Failing safe; tests/test_guard_emit_first.py).
  - **V.** A degraded allow prints a fixed visible notice and writes an enum-only log record (docs/hooks.md).
  - **V.** The Gemini rules keep running when agents.yaml cannot be loaded, and an event too large or incomplete to check is denied (docs/hooks.md).
  - **V.** A shell command over 64 KiB, or a check that runs out of time, is denied; constructs the scanner will not guess at have their own verdicts that `block` mode denies (docs/hooks.md).
  - **V.** A slow mode file is judged in `block` (docs/hooks.md).
  - **V.** The documented limits each have a test that asserts exactly what is allowed (docs/hooks.md, Known limits).
- **Verification:** tests/test_guard_emit_first.py, test_guard_entry.py, test_guardlog_timeout.py, test_leadwait.py, test_leadwait_bash.py, test_gemini_bash.py, test_gemini_hook_errors.py.
- **Residual risk:** Open. Owner: the maintainer. Tracked in #130, #188. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** #130, #188.

### S09: Data leakage: maintainer private identifiers (asset A7) or unfixed-finding detail reach a public artifact

- **Impact:** High. **Rank:** 11. **Status:** Open. **STRIDE:** Information disclosure.
- **Abuse case:** Asset at risk: asset A7 and unfixed-finding detail. Actor class: the maintainer or an agent, by a slip. Consequence: private material appears in a public artifact.
- **Prerequisites:** Actor class: the maintainer or an agent; no attacker is needed.
- **Mitigation (V verified, I inferred):**
  - **V.** tests/test_privacy.py scans docs/, examples/, README.md and agents.yaml for the generic patterns it lists; failures do not repeat the matched text.
  - **V.** Private screening data is managed outside public artifacts (docs/privacy.md).
  - **V.** Unfixed findings are kept only in approved private channels; a public issue carries a safe summary (docs/security-findings.md).
  - **V.** The guard log does not store a brief or a prompt (docs/hooks.md).
- **Verification:** tests/test_privacy.py; the private screening check is run before publication.
- **Residual risk:** Open. Owner: the maintainer. Tracked in #123, #234. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** #123, #234.

### S10: Data leakage to a model host: private text sent to a host that should not receive it

- **Impact:** Medium. **Rank:** 12. **Status:** Open. **STRIDE:** Information disclosure.
- **Abuse case:** Asset at risk: private text in briefs and prompts. Actor class: a careless or prompt-injected agent. Consequence: material reaches a third-party service or a host the configuration did not intend.
- **Prerequisites:** Actor class: an agent that writes a brief or a prompt file.
- **Mitigation (V verified, I inferred):**
  - **V.** A Gemini step needs `gemini-material: public`; a secret-shaped string or a match for private screening data blocks it (docs/hooks.md, seventh rule).
  - **V.** Local endpoint addresses are validated at load and at connect, and a name is resolved once (src/safo/netguard.py).
  - **V.** A redirect is an error, so a prompt is not replayed to a host the configuration did not name (src/safo/ollama.py).
  - **V.** A URL with credentials is refused; endpoints come from configuration and not from the repository (docs/local-llm.md).
- **Verification:** tests/test_netguard.py; tests/test_ollama.py::test_a_redirect_is_never_followed_so_a_prompt_cannot_be_replayed_to_another_host; tests/test_gemini_guard.py; tests/test_local_run.py.
- **Residual risk:** Open. Owner: the maintainer. Tracked in docs/gemini.md, #235. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** docs/gemini.md, #235.

### S23: Local model server: confidentiality of prompts and integrity of results on the local path

- **Impact:** Medium. **Rank:** 13. **Status:** Open. **STRIDE:** Spoofing.
- **Abuse case:** Asset at risk: prompt confidentiality and result integrity on the local model path. Actor class: a compromised or LAN-adjacent model server. Consequence: prompts are observed or the output is chosen by someone other than the maintainer.
- **Prerequisites:** Actor class: a foothold on the home network or the model server.
- **Mitigation (V verified, I inferred):**
  - **V.** Address validation and DNS pinning address request forgery and rebinding (src/safo/netguard.py). Endpoint authentication is not among the guarantees.
  - **V.** A redirect is an error, so a prompt is not replayed to a host the configuration did not name (src/safo/ollama.py).
  - **V.** A URL with credentials is refused; the probe is read-only (docs/local-llm.md, docs/usage.md).
- **Verification:** tests/test_netguard.py; tests/test_ollama.py.
- **Residual risk:** Open. Owner: the maintainer. Tracked in #241. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** #241.

### S25: Local model answer integrity: a local answer applied without review

- **Impact:** Medium. **Rank:** 14. **Status:** Open. **STRIDE:** Tampering.
- **Abuse case:** Asset at risk: decisions and documents that use a local answer. Actor class: a model error or a compromised model server. Consequence: a wrong or chosen answer is applied or published.
- **Prerequisites:** Actor class: an ordinary model error, or the actor of S23.
- **Mitigation (V verified, I inferred):**
  - **V.** Code groups and counts and the model writes prose over a correct structure; a status headline is used if it is one plain line whose numbers are the computed counts (docs/local-llm.md, src/safo/headline.py).
  - **V.** Field values a reviewer checked are applied from a triage draft (docs/routing.md, issue-triage shape).
  - **V.** Review of a local answer before it is applied is a required operating procedure (docs/local-llm.md).
- **Verification:** tests/test_status_headline.py; tests/test_local_run.py.
- **Residual risk:** Open. Owner: the maintainer. Tracked in #243. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** #243.

### S11: Config sync: private SAFO material pushed to a remote

- **Impact:** Medium. **Rank:** 15. **Status:** Open. **STRIDE:** Information disclosure.
- **Abuse case:** Asset at risk: asset A7 and the maintainer's local configuration. Actor class: the maintainer, by a slip, or a wider-than-intended sync scope. Consequence: a private file leaves the laptop for a hosted remote.
- **Prerequisites:** Actor class: the maintainer; no attacker is needed.
- **Mitigation (V verified, I inferred):**
  - **V.** The rule is written: unfixed-finding detail and private screening data stay out of synced configuration trees, dotfiles repositories and published backups (docs/security-findings.md, docs/privacy.md).
  - **I.** The sync tool lives outside this repository and was not read for this model, so what it pushes is not stated here.
- **Verification:** Nothing in this repository checks it; the check is tracked under maintainer-only tracking.
- **Residual risk:** Open. Owner: the maintainer. Tracked under maintainer-only tracking. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** maintainer-only tracking.

### S13: GitHub rate limits and outages stall the board, audits and lookups

- **Impact:** Medium. **Rank:** 16. **Status:** Open. **STRIDE:** Denial of service.
- **Abuse case:** Asset at risk: availability of the board, the audits and the guard's lookups. Actor class: none; ordinary heavy use. Consequence: work stalls or, in `block` mode, a dispatch is denied.
- **Prerequisites:** Actor class: none needed.
- **Mitigation (V verified, I inferred):**
  - **V.** The client honors retry-after, the primary reset and secondary-limit or abuse messages with bounded attempts, then raises RateLimitedError (src/safo/graphql.py).
  - **V.** Pagination stops at 1000 pages and a response over 32 MiB is refused unread (graphql.py).
  - **V.** The guard's lookup has a deadline; an unanswered lookup is denied in `block` mode and a warning in `warn` (docs/no-hidden-work.md).
  - **V.** Redirects are refused, so a limit response cannot move the token to another host (graphql.py; tests/test_graphql.py).
- **Verification:** tests/test_graphql.py; tests/test_graphql_body_cap.py.
- **Residual risk:** Open. Owner: the maintainer. Tracked in #204. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** #204.

### S14: GitHub behavior or schema changes and a check's answer

- **Impact:** Medium. **Rank:** 17. **Status:** Open. **STRIDE:** Tampering.
- **Abuse case:** Asset at risk: the assurance the checks give. Actor class: GitHub, by changing its behavior. Consequence: a check could report a pass when it should say it cannot tell.
- **Prerequisites:** Actor class: a change on GitHub's side.
- **Mitigation (V verified, I inferred):**
  - **V.** Fields are read strictly: an absent, null or mistyped field is exit 2 'cannot tell' and not exit 0 (docs/adoption.md; tests/test_malformed_nodes.py, test_items_strict.py, test_protection.py).
  - **V.** A response that is not JSON, is truncated or is oversized is an error, and a mutation answer that is not understood is an unknown outcome (tests/test_graphql_framing.py).
  - **V.** `protection` reads everything twice and exits 2 on any difference (docs/adoption.md).
- **Verification:** tests/test_malformed_nodes.py; tests/test_items_strict.py; tests/test_protection.py; tests/test_graphql_framing.py.
- **Residual risk:** Open. Owner: the maintainer. Tracked in #238. The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** #238.

### S15: Persona, template, agents.yaml or promotion evidence is changed to steer agents

- **Impact:** High. **Rank:** 18. **Status:** Mitigated. **STRIDE:** Tampering.
- **Abuse case:** A pull request, or a write to the local override, changes the text that is rendered into the instruction files agents obey, or adds plausible outcome records so a profile is promoted.
- **Prerequisites:** A merged pull request with the owner's review, or write access to the local files (S02).
- **Mitigation (V verified, I inferred):**
  - **V.** CODEOWNERS covers agents.yaml, the generated harness files, personas, templates, lessons and the generator; `safo profiles verify` fails when one of those has no owner (.github/CODEOWNERS; docs/profiles.md).
  - **V.** Profile text runs through text rules, a phrase tripwire and a private-path check, and the generated diff is read by a person (docs/limits.md).
  - **V.** Render digests show a stale or edited generated file; they are not a signature (docs/limits.md).
  - **V.** The profile status stays declared in agents.yaml; promotion counts are a speed bump and the maintainer reads the evidence (docs/limits.md).
- **Verification:** tests/test_profiles_verify.py; tests/test_profile_text_rules.py; tests/test_manifest_digest.py; `make generated` fails on drift.
- **Residual risk:** A plausible harmful instruction that passes the tripwire and the review is a human judgement (docs/limits.md). Reopen when a profile line is found to have steered an agent wrongly.
- **Tracking:** none needed (accepted residual in docs/limits.md).

### S16: A convenience call to the local model evicts a production model

- **Impact:** Medium. **Rank:** 19. **Status:** Mitigated. **STRIDE:** Denial of service.
- **Abuse case:** `safo local run` or a probe loads a different model or context on a GPU shared with production services.
- **Prerequisites:** A routing or configuration mistake.
- **Mitigation (V verified, I inferred):**
  - **V.** Allow-listed models are asked for, with the `num_ctx` the resident model is loaded with; protected models are not routed to (docs/local-llm.md).
  - **V.** The probe is two read-only GETs and does not call generate (docs/usage.md).
- **Verification:** tests/test_ollama.py; tests/test_local_run.py; tests/test_routing.py; tests/test_routing_hostile.py.
- **Residual risk:** When the local server cannot be seen, the lead must stop and ask rather than route around it (#191). Reopen on any eviction of a production model.
- **Tracking:** #191.

### S17: A write is repeated or its outcome is guessed after an ambiguous failure

- **Impact:** Low. **Rank:** 20. **Status:** Mitigated. **STRIDE:** Repudiation.
- **Abuse case:** A connection drops after a mutation was sent, and the client resends it or reports success, which duplicates a card or hides a failed write.
- **Prerequisites:** A network fault or a rate-limit response at the wrong moment.
- **Mitigation (V verified, I inferred):**
  - **V.** Once a mutation has gone out it is not replayed; an ambiguous result raises UnknownOutcomeError and says to re-read state (src/safo/graphql.py, src/safo/mutation.py).
  - **V.** A reply with no written object id is an unknown outcome (mutation.py).
- **Verification:** tests/test_graphql.py::test_a_mutation_that_commits_then_drops_connection_raises_unknown_outcome and the null-payload cases.
- **Residual risk:** The caller must re-read before retrying; `status --post` notes that an unknown outcome cannot be verified automatically (docs/board-yaml.md).
- **Tracking:** none needed (mitigated).

### S18: Process rules are satisfied by form and not substance (issue line, threat-model line, linked issue)

- **Impact:** Low. **Rank:** 21. **Status:** Open. **STRIDE:** Repudiation.
- **Abuse case:** Asset at risk: the meaning of the process checks. Actor class: an author of a brief, issue or pull request. Consequence: a presence check passes without the thing it stands for.
- **Prerequisites:** Actor class: authorship of a brief, issue or pull request.
- **Mitigation (V verified, I inferred):**
  - **V.** A brief's issue must be in the listed tracking repositories and be open; an unrelated open issue does not satisfy the rule (docs/no-hidden-work.md).
  - **V.** `audit` states it does not open the model file or judge the reason; a person reads them (docs/threat-model.md).
  - **V.** The branch gate checks that the default branch requires `CI green`, pinned to the CI app (docs/no-hidden-work.md).
- **Verification:** tests/test_tracking.py; tests/test_no_hidden_work.py; tests/test_threatmodel.py; tests/test_branch_gate.py.
- **Residual risk:** These checks make absence visible; they cannot judge truth. Accepted.
- **Tracking:** none needed (accepted).

### S19: The protection read-back certifies a state that did not hold at one instant

- **Impact:** Low. **Rank:** 22. **Status:** Open. **STRIDE:** Spoofing.
- **Abuse case:** Asset at risk: the assurance the protection read-back gives. Actor class: someone with administrator rights on the repository. Consequence: the read-back reports a state that did not hold at one instant.
- **Prerequisites:** Actor class: administrator rights on the repository.
- **Mitigation (V verified, I inferred):**
  - **V.** The read is repeated in a different order and any difference is exit 2; the exit-0 output says it is not an instant (docs/adoption.md).
  - **V.** An unpinned required check prints a NOTE, and `--require-app-id` makes the pin a condition (docs/adoption.md).
  - **V.** The baseline script prints commands in plan mode and an agent does not apply it (README.md, scripts/apply-baseline.sh).
- **Verification:** tests/test_protection.py; tests/test_apply_baseline.py; tests/test_branch_gate_source.py.
- **Residual risk:** Anyone who can change the protection can defeat the check (docs/adoption.md). Accepted.
- **Tracking:** none needed (accepted).

### S20: Usage meter or outcomes log inputs are not independent evidence

- **Impact:** Low. **Rank:** 23. **Status:** Open. **STRIDE:** Tampering.
- **Abuse case:** Asset at risk: routing and promotion decisions. Actor class: a process of the maintainer's account. Consequence: a worse routing choice, which a person reviews.
- **Prerequisites:** Actor class: a process of the maintainer's account.
- **Mitigation (V verified, I inferred):**
  - **V.** The meters read through bounded readers and skip a half-written last line (the meters in src/safo/meters use the readers in src/safo/bounded.py; docs/usage.md). The exact caps were not enumerated for this model.
  - **V.** Unknown headroom does not block a route and is printed (docs/usage.md).
  - **V.** The outcomes log is validated, kept in a private directory, and promotion counts are a speed bump (docs/limits.md).
- **Verification:** tests/test_meters.py; tests/test_outcomes.py; tests/test_usage_mode.py.
- **Residual risk:** Same-user forgery is not defended (S02). The effect is a worse routing choice, which a person reviews. Accepted.
- **Tracking:** none needed (accepted).

### S21: This threat model goes stale because SAFO's own CI does not run the Threat Dragon check

- **Impact:** Low. **Rank:** 24. **Status:** Open. **STRIDE:** Repudiation.
- **Abuse case:** A prompt, agent config or guard change merges with no change to the model, because the shared check is not wired into this repository's CI.
- **Prerequisites:** None. Ordinary drift.
- **Mitigation (V verified, I inferred):**
  - **V.** The GYST `threat-model.yml` workflow exists and checks the file's shape and that it moves with the AI surface (read for this model); this repository does not call it yet (.github/workflows/ci.yml).
  - **V.** tests/test_safo_threat_model.py in this repository checks that the model file and this page agree on the risk ids and carry the required fields.
- **Verification:** tests/test_safo_threat_model.py; the GYST check run locally against the file (see the pull request).
- **Residual risk:** Until the workflow is called, the local test and review keep the model current.
- **Tracking:** #240.

### S22: Paid Gemini spend outside its caps (modeled separately)

- **Impact:** Critical. **Rank:** 25. **Status:** Open. **STRIDE:** Elevation of privilege.
- **Abuse case:** Asset at risk: the paid Gemini key and spend. Actor class: a prompt-injected agent or an attacker of the broker, as that model describes. Consequence: spend outside approval or caps. The abuse cases are in the broker design's own model and are not repeated here.
- **Prerequisites:** Actor class: see that model.
- **Mitigation (V verified, I inferred):**
  - **V.** Paid use is disabled today, and the guard denies any paid step while it is off (docs/gemini.md).
  - **V.** The design-grade model for the broker is [Gemini broker: threat model](gemini-broker-threat-model.md).
- **Verification:** See the broker model. Today: tests/test_gemini_paid_switch.py, tests/test_gemini_guard.py.
- **Residual risk:** Open. Owner: the maintainer. Tracked in #205 and #217. Modeled separately; The statements under Mitigation describe what the repository tests exercise today; they are not a wider guarantee.
- **Tracking:** #205, #217, docs/gemini-broker-threat-model.md.

## Guarantees and non-guarantees

**Caveat for everything below and under Mitigation.** The repository tests exercise this behavior under the tested
conditions. This is not a guarantee against alternate callers, host behavior, compromised dependencies, runtime changes or
untested paths.

What the repository tests exercise today:

- For a fork's pull request the Action refuses credential inputs; SAFO's claim is limited to that case (see the trust
  boundary of the Action in [Limits](limits.md)). Credentials are masked before use. The App credential path has its own
  scoped permissions and lifetime; the personal-token path is caller-scoped (S24).
- A write to GitHub is not replayed after the request went out; an ambiguous answer is an unknown outcome and the caller
  re-reads. A redirect is not followed with a token or a prompt.
- A check that cannot read GitHub's answer in full says "cannot tell" (exit 2) and does not report a pass.
- A guard error is a visible, logged degraded allow; the Gemini rules and the shell check for the vendor API deny when
  they cannot decide.
- `handoff check` says a report names the current head. It does not say the work was approved.

What SAFO does **not** guarantee:

- The dispatch guard is a speed bump and an audit trail, not a security boundary ([Hooks](hooks.md), [Limits](limits.md)).
- Model behavior stays subject to the permissions the host gives it.
- Protection against upstream compromise goes no further than hash and commit pins, and none against GitHub's own behavior.
- A local or hosted model sees what is sent to it. Endpoint authentication of the local model server is not a guarantee.
- What the configuration sync pushes is not checked from this repository.
- The process checks (an `issue:` line, a `threat-model:` line, a linked issue) make absence visible. They do not judge
  whether the thing named is right.

## Work this model asks for

Existing issues are linked in the register above. The follow-up work this model asked for is filed, under the public issue titles:

| Risk | Issue | Work |
|---|---|---|
| S01 | #230 | Fence GitHub text in briefs and local prompts; flag a brief that pastes issue, PR or comment text bare |
| S02 | #231 | Guard launcher integrity: verify the identity of the program the hook runs and report it in safo hooks status |
| S03 | #232 | safo doctor: report the scopes of the stored GitHub login and warn on more than SAFO needs |
| S05 | ChiefGyk3D/git-your-ship-together#251 | Caller lint for jobs in the Action's callers (GYST) |
| S05, S12 | #236 | Hardening: Action caller trust and provenance |
| S06 | #233 | Install and update path: pin a commit for pipx and git installs; doctor prints the installed version or commit |
| S09 | #234 | Local pre-push check that runs the private-terms scan before a public push, commit messages included |
| S10 | #235 | safo local run: refuse a prompt that carries a secret shape or a private term |
| S11 | n/a | Maintainer-only tracking |
| S14 | #238 | Scheduled read-only live audit as an API-drift canary |
| S21 | #240 | Call the GYST threat-model workflow from CI for the AI-facing paths |
| S23 | #241 | Local model endpoints: authenticated transport and an explicit trust statement |
| S24 | #242 | Action token input: document and report the token kind, expiry and repositories in the preflight where the API allows |
| S25 | #243 | Mark local answers as unreviewed drafts in the outcomes log and refuse to apply one without a recorded review |

## Keeping it honest

- The Threat Dragon file and this page are checked by `tests/test_safo_threat_model.py`: the same ids, impact, status and
  rank in both, every risk has an abuse case, mitigation, verification and residual risk, every test file and every test
  function named in a verification exists, every flow points at a cell that exists, and this page is linked from the
  README, the wiki home and [Threat model before build](threat-model.md). That test checks shape and agreement. It does
  not prove that a mitigation works or that a named test exercises the control; a reader and a review do that.
- The shared check in git-your-ship-together (`threat-model.yml`) validates the file's shape and that it moves with the AI
  surface. It was run against this file for this pull request; calling it from CI is tracked under S21 (#240).
- The wiki page is `Safo-threat-model`, generated from this file by `scripts/gen_wiki.py` like every page of `docs/`.
- Reopen a risk on the signal in its residual line. A change to the guard, the Action, `agents.yaml` or the routing
  prompts should change this model or say in the pull request why it does not.
