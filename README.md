# Scrum Around and Find Out

SAFO is three things, built for one maintainer running a team of AI agents across a dozen repositories:

1. **A GitHub Project defined as code.** `board.yaml` names the fields, options, iterations and views. An Action and a
   command line (`safo`) apply it and keep the board current, in five modes: `bootstrap`, `audit`, `sync`, `reconcile`
   and `status`.
2. **Agent routing.** `agents.yaml` records which agent should get which kind of work, from one maintainer's
   measurements: Claude Code (Sonnet, Haiku, Opus), OpenAI Codex, the GitHub Copilot coding agent and a local Ollama
   model. Commands read local usage meters and recommend an agent. They dispatch nothing.
3. **A playbook and a lessons wiki.** Why the team is run this way, who does what, and what broke along the way.

This README is the interim documentation. SAFO is being built toward v0.1.0, and most of it does not exist yet. The
status table below is the honest account.

## Status

Checked 2026-10-08.

| Piece | State |
|---|---|
| Python scaffold, CI on git-your-ship-together, repository files | Built, merged on `main` |
| `scripts/apply-baseline.sh` (repository settings, run by the maintainer) | Built, merged on `main` |
| T2: GraphQL client (refuses redirects; never replays a mutation whose outcome is unknown) | Built on branch `build/group2`, not merged |
| T3: `board.yaml` schema and validator (refuses duplicate keys, aliases, anchors, merge keys, runaway nesting and oversized files) | Built on branch `build/group2`, not merged |
| `audit`, `bootstrap`, `reconcile`, `sync`, `status` modes | Planned |
| The Action (`action.yml`) | Planned |
| `safo usage` (Codex, Claude Code, Copilot and Ollama meters, local and read-only; the agents file comes only from `--agents`, `$SAFO_AGENTS` or `~/.config/safo/agents.yaml`, never the current directory) | Built on branch `build/group4`, not merged |
| `safo route` (recommends an agent and a reviewer from the rules and live headroom; dispatches nothing) | Built on branch `build/group4`, not merged |
| `safo outcome add` and `safo usage --report` (a validated, private outcomes log in `~/.local/state/safo/`, summarised per agent) | Built on branch `build/group4`, not merged |
| `safo local run` (one prompt to the local model routing picks; never one that would evict a protected model) and the optional local-model clause on `safo status --post` | Built on branch `build/group4`, not merged |
| `safo hooks` (a Claude Code SessionStart probe and a PreToolUse guard on the Agent tool that enforce `agents.yaml`: warn by default, block when asked, any hook error fails open with a visible warning; see [`docs/hooks.md`](docs/hooks.md)) | Built on branch `build/group4`, not merged; not yet exercised in a real Claude Code session |
| `agents-status` | Planned |
| Generated docs and the wiki mirror | Planned (the wiki is hand-written until then) |

The design is in [`docs/superpowers/specs/2026-10-07-safo-design.md`](docs/superpowers/specs/2026-10-07-safo-design.md)
and the implementation plan is split into seven pull-request groups, listed on the
[Roadmap](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Roadmap) page.

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

**Planned for v0.1.0** (none of these commands exist yet):

```sh
pip install .                                  # Python 3.11+, one dependency: PyYAML
gh auth refresh -s project
safo --board board.yaml bootstrap              # create what is missing
safo --board board.yaml audit                  # 0 clean, 1 drift, 2 cannot tell
safo --board board.yaml reconcile              # add missing items, mark closed ones Done
safo route research                            # recommend an agent for a task shape
```

The Action is planned as `ChiefGyk3D/scrum-around-and-find-out@<sha>` with a bring-your-own GitHub App. There is no
hosted service.

## Relationship to git-your-ship-together

[git-your-ship-together](https://github.com/ChiefGyk3D/git-your-ship-together) (GYST) is the delivery layer. Its CI
workflows already run this repository's checks, and its `project-sync.yml` is planned to become a thin wrapper that calls
SAFO's Action. SAFO keeps its own project-management logic: shared CI plumbing belongs in GYST, a self-contained component
keeps its logic in its own repository and GYST deploys it.

## Wiki

Hand-written for the pre-release; v0.1.0 will generate or extend these pages.

- [Home](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki)
- [Board-as-code](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Board-as-code)
- [The-agent-team](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/The-agent-team)
- [Routing-and-limits](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Routing-and-limits)
- [The-review-loop](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/The-review-loop)
- [Local-LLM](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Local-LLM)
- [Lessons-learned](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Lessons-learned)
- [Roadmap](https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/Roadmap)

## Licence

MIT. See [LICENSE](LICENSE).
