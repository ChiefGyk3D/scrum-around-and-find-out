# Scrum Around and Find Out

> **The hard rule: no hidden work.** Every unit of work, human or agent, has an issue (or a Jira key) and a board card
> before work starts, and every pull request links its issue (`Refs #n` or `Closes #n`). Work without a card is a defect
> of the process. `safo hooks guard`, `safo audit`, `reconcile` and `sync` enforce it; see
> [docs/no-hidden-work.md](docs/no-hidden-work.md).

SAFO is three things, built for one maintainer running a team of AI agents across a dozen repositories:

1. **A GitHub Project defined as code.** `board.yaml` names the fields, options, iterations and views. An Action and a
   command line (`safo`) apply it and keep the board current, in the modes listed under [What it does](#what-it-does).
2. **Agent routing.** `agents.yaml` records which agent should get which kind of work, from one maintainer's
   measurements: Claude Code (Sonnet, Haiku, Opus), OpenAI Codex, the GitHub Copilot coding agent and a local Ollama
   model. Commands read local usage meters and recommend an agent. They dispatch nothing.
3. **A playbook and a lessons wiki.** Why the team is run this way, who does what, and what broke along the way.

SAFO is at v0.1.2, and `main` is ahead of it (the unreleased rows are marked below). The playbook pages start at [docs/why.md](docs/why.md); the status table below says what is
released and what is still only specified.

## Status

Checked 2026-10-26 against `main` at cf53799.

| Piece | State |
|---|---|
| Python scaffold, CI on git-your-ship-together, repository files, `scripts/apply-baseline.sh` | Built, merged on `main` |
| GraphQL client (refuses redirects; never replays a mutation whose outcome is unknown), `board.yaml` schema and validator | Built, merged on `main` |
| `audit`, `bootstrap`, `reconcile`, `sync`, `status` (including `status --post`, grouped and counted in code) | Built, merged on `main` |
| `validate` and the Action (`action.yml`: a fresh hash-pinned venv, credential masking, a one-hour App token, no checkout needed) | Built, merged on `main` and released in v0.1.0. Read the trust boundary below before you call it |
| `agents-status` (the board, Codex, Copilot and the routing-guard counts in one read-only view) | Built, merged on `main` and released in v0.1.0 |
| `usage` (Codex, Claude Code, Copilot and Ollama meters, local and read-only; the agents file comes only from `--agents`, `$SAFO_AGENTS` or `~/.config/safo/agents.yaml`, never the current directory) | Built, merged on `main` and released in v0.1.0 |
| `route` (recommends an agent and a reviewer from the rules and live headroom; dispatches nothing) | Built, merged on `main` and released in v0.1.0 |
| `outcome add` and `usage --report` (a validated, private outcomes log in `~/.local/state/safo/`, summarised per agent) | Built, merged on `main` and released in v0.1.0 |
| `local run` (one prompt to the local model routing picks; never one that would evict a protected model) and the optional local-model clause on `status --post` | Built, merged on `main` and released in v0.1.0 |
| `handoff check` (is the latest review report on a pull request about its current head; read-only, shows and never blocks; the merge step that passes the reviewed head to `safo wait-ci --sha` waits for `wait-ci`) | In review on a pull request (issue #106, first unit); not yet on `main` |
| `hooks` (a Claude Code SessionStart probe and a PreToolUse guard on the Agent and Bash tools that enforce `agents.yaml` and the rule that the lead never waits (see [`docs/orchestrator.md`](docs/orchestrator.md)): warn by default, block when asked, any hook error fails open with a visible warning; the approval token is a speed bump, not proof of the maintainer's approval, because a prompt-injected model can write it; see [`docs/hooks.md`](docs/hooks.md)) | Built, merged on `main`. The guard and probe were released in v0.1.0; the lead-waits rule is on `main` since #77 and unreleased. The Agent-tool guard has run on real dispatches in warn mode (53 since 2026-10-09; see [Measurements](docs/measurements.md)), but the lead-waits rule has no measured hit rate yet and the disposable real-session smoke test that [`docs/hooks.md`](docs/hooks.md) asks for before `block` is not recorded as done |
| No hidden work (the guard needs an open `issue:` in every brief; `audit` finds pull requests with no linked issue and cards missing Kind, Epic, Effort or Area; `reconcile` and `sync` list what needs a human; see [`docs/no-hidden-work.md`](docs/no-hidden-work.md)). The pull request check that fails a pull request with no `Refs #n` is a reusable workflow in git-your-ship-together and is not built here | Built and merged on `main` (#60, issue #54); unreleased, after v0.1.2 |
| Threat model before build (`audit` and `reconcile` find issues labeled `ai-surface` with no usable `threat-model:` line; a `threat-model` routing shape; see [`docs/threat-model.md`](docs/threat-model.md)). The check that the Threat Dragon file is well formed and moves with the AI surface is a reusable workflow in git-your-ship-together and is not built here | Built and merged on `main` (#71, issue #70); unreleased, after v0.1.2 |
| The playbook pages in `docs/` and this README | Merged on `main` and released in v0.1.0 |
| The usage meter fix and the outcomes fields (the Claude meter now reads the usage fields Claude Code nests in its transcripts; outcomes records gain `model` and `credits_used`) | Built, merged on `main` and released in v0.1.2 |
| Generated docs and the wiki mirror (`scripts/gen_wiki.py`, published by `.github/workflows/wiki.yml` through GYST's `wiki-publish.yml`) | Built, merged on `main` and live: the wiki is the generated mirror of `docs/` |
| Personas (`docs/personas.md`, a description of the Department of Internal Arguments roles and how to install them, with no copies kept here) and the examples (the outcomes log, systemd units) | Built and merged on `main` |
| [Measurements](docs/measurements.md): what the first month measured, dated and aggregated | Written; read it as a soak, not a finding |
| Issue #23 roadmap: agent profiles, promotion of lessons into rules, and metrics from the outcomes log | Profiles are built in stages: the loader, evidence resolution, `profiles verify` and the rendering into `examples/harness/`, and `profiles brief` (see [Agent profiles](docs/profiles.md)); the route surface, promotion that changes selection, and metrics from the outcomes log are not built |

The design is in [`docs/superpowers/specs/2026-10-07-safo-design.md`](docs/superpowers/specs/2026-10-07-safo-design.md)
and the implementation plan is split into seven pull-request groups, listed on the
[Roadmap](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Roadmap) page.

## What it does

| Mode | Does |
|---|---|
| `validate` | Validates `board.yaml` offline; reads nothing from GitHub and makes no claim about the live board |
| `bootstrap` | Creates the fields, options, iterations and views `board.yaml` names and the project lacks. Never edits an existing field's options |
| `audit` | Compares the live board and the repositories' open work with `board.yaml`. Exit 0 clean, 1 drift, 2 cannot tell |
| `sync` | Brings the card of one issue or pull request event in line |
| `reconcile` | Adds every missing open issue and pull request, marks closed ones Done with the date, fills Area. Idempotent |
| `status` | Posts a project status update from a Markdown file, or builds it from the board with `--post`: the cards are grouped and counted in code, with an optional one-line headline on top |
| `agents-status` | One read-only view of what Claude, Codex and Copilot are doing |
| `usage` | What each agent has used and has left, from local files only: Codex windows, Claude Code tokens, Copilot sessions, Ollama reachability. `--report` summarises the outcomes log |
| `route <shape>` | Which agent a task shape should go to, from the rules in `agents.yaml` and the live headroom. Recommends; dispatches nothing |
| `outcome add` | Appends a finished task to the outcomes log |
| `handoff check <owner/repo> <pr>` | Whether the latest review report on a pull request names the head the pull request has now. Exit 0 fresh, 1 stale, 2 cannot tell. Read-only; shows, never blocks. See [Handoff](docs/handoff.md) |
| `local run` | Sends one prompt to the local model (Ollama) that routing picks, never one that would evict a protected model |
| `profiles verify` | Resolves every evidence pointer of the agent profiles in `agents.yaml` and prints each claim beside what it cites; checks CODEOWNERS covers the files the profiles are made from. Read-only |
| `hooks` | Makes Claude Code enforce `agents.yaml`: a session probe of the local model and a guard on every Agent dispatch (an explicit model, the approval token for Opus, a named local step). `install`, `mode`, `status`, `probe`, `guard` |

The Action runs the modes that talk to the board. The local modes (`usage`, `route`, `outcome`, `local`, `hooks`, `profiles`, `handoff`) read
files on a person's machine and are not allowed in the Action.

## Trust boundary

Never run untrusted code (a PR checkout, a build, a script) in the same job before the SAFO Action. With
`pull_request_target`, run SAFO in its own job with no checkout of PR code. The job/runner boundary is the trust boundary:
a same-user process from an earlier step can mutate the Action's venv or read credential-step environments.

The approval token that `safo hooks` checks is a speed bump, not proof that the maintainer said yes: a prompt-injected
model can write it. The other accepted residuals are listed in [docs/limits.md](docs/limits.md).

## Routing

These are one maintainer's measurements from a single day (2026-10-07), not vendor claims. Replace them with your own.
The shipped `agents.yaml` will encode this order, first match wins.

| Kind of work | Goes to | Why (as measured) |
|---|---|---|
| Text in, text out: summaries, triage, classification, first drafts, log digests | Local Ollama model first, then a Claude model checks anything that will be applied | Costs nothing. Good at triage drafts (114 issues in minutes). Bad at precise prose and at filing facts from structured data, so code does the grouping and counting |
| Mechanical code from a complete spec | Haiku, or Copilot for a small single-repository pull request | Haiku transcribes exactly, bugs in the spec included, so security code it transcribes still gets a full review. Every Copilot pull request needed fixes (4 of 4) |
| Code from prose, every task review, ops runbooks | Sonnet | The default for implementation and review |
| Security-sensitive or risky code | Sonnet builds it, Codex attacks it before merge | Codex's adversarial review found high-severity issues that green CI and Sonnet reviews missed, twice in one day |
| Research and plan writing | Codex, then Sonnet | Strong at both. A 3,400-line plan it wrote still needed a preflight scan (21 conflicts, 19 defects) |
| Decisions and design | The Claude lead and the maintainer | Opus only with the maintainer's OK and the reason stated |

Constraints that shape the table: Codex's sandbox could not commit inside a git worktree or open sockets, so the lead runs
the full test suite and commits its work. Its binding limit is the five-hour window, so its jobs are spaced. Copilot's
quota is credits, so it is spent on small, fully specified work behind a review gate. Details are on the
[Routing-and-limits](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Routing-and-limits) page.

## Quick start

**Works today:** `scripts/apply-baseline.sh` in plan mode. It prints every `gh` command it would run to apply the
repository baseline (branch protection, the tag ruleset, private vulnerability reporting, fork-PR approval, the Actions
allow-list, auto-merge) and changes nothing.

```sh
scripts/apply-baseline.sh                  # plan mode: print the commands
scripts/apply-baseline.sh --repo OWNER/NAME  # plan mode for another repository
```

The maintainer runs `--apply`; an agent never does.

**Since v0.1.0** (needs installing):

```sh
pip install .                                  # Python 3.11+, one dependency: PyYAML
gh auth refresh -s project
safo --board board.yaml bootstrap              # create what is missing
safo --board board.yaml audit                  # 0 clean, 1 drift, 2 cannot tell
safo --board board.yaml reconcile              # add missing items, mark closed ones Done
safo route research                            # recommend an agent for a task shape
```

As an Action, see [docs/adoption.md](docs/adoption.md): `ChiefGyk3D/scrum-around-and-find-out@<sha>` with a
bring-your-own GitHub App. There is no hosted service. The reference for the file is [docs/board-yaml.md](docs/board-yaml.md).

## Relationship to git-your-ship-together

[git-your-ship-together](https://github.com/ChiefGyk3D/git-your-ship-together) (GYST) is the delivery layer. Its CI
workflows already run this repository's checks, and its `project-sync.yml` is planned to become a thin wrapper that calls
SAFO's Action. SAFO keeps its own project-management logic: shared CI plumbing belongs in GYST, a self-contained component
keeps its logic in its own repository and GYST deploys it.

## Wiki

The wiki is a generated mirror of `docs/` (edit the files, not the wiki): `scripts/gen_wiki.py` writes the pages and
`.github/workflows/wiki.yml` publishes them on every push to `main` that touches `docs/`. The hand-written pages it
replaced are gone.

- [Home](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki)
- [Why](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Why)
- [Roles](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Roles)
- [Routing](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Routing)
- [Usage](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Usage)
- [Hooks](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Hooks)
- [Handoff](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Handoff)
- [Limits](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Limits)
- [Board](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Board)
- [Board-yaml](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Board-yaml)
- [Agents-status](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Agents-status)
- [Lessons](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Lessons)
- [Measurements](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Measurements)
- [Adoption](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Adoption)
- [Privacy](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Privacy)
- [Look-before-instructing](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Look-before-instructing)
- [Done-means-verified](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Done-means-verified)
- [Access-planning](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Access-planning)
- [Act-then-report](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Act-then-report)
- [Security-findings](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Security-findings)
- [Orchestrator](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Orchestrator)
- [Threat-model](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Threat-model)
- [Profiles](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Profiles)
- [Review-loop](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Review-loop)
- [Personas](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Personas)
- [Plugins](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Plugins)
- [Local-llm](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Local-llm)
- [No-hidden-work](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/No-hidden-work)

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
