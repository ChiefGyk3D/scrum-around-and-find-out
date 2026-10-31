# Prerequisites

What SAFO leans on outside this repository, with the lowest version that works and how that was established. `safo doctor`
checks the same list on the machine in front of you.

Every row says **verified** (a vendor release note, a vendor file or this repository's own code was read) or **inferred**
(reasoned from how SAFO calls the tool; not confirmed against a release note). The versions in "seen" are what the
maintainer's machine reported on 2026-10-29, not requirements.

## The presence check

```sh
safo doctor
```

One line per item: `present`, `missing`, `too old` or `unreadable` (the tool ran but printed no version, or failed). The
exit code is 0 only when every **required** item is present at its minimum, and 1 otherwise. Optional tools, plugins and
skill packs are reported and never change the code.

It is read-only. The only thing it runs is `<tool> --version`, with stdin closed, a five-second timeout and a clean
environment (`PATH` and `HOME` only), so no token or account setting reaches the child. It prints the digits of the version and
nothing else the tool said. A relative or empty `PATH` entry is never searched. `llm-local` is a maintainer's wrapper with
no version flag we may call, so it is checked for presence only and never run. Plugins and packs are read from
`~/.claude/plugins/installed_plugins.json` and `~/.claude/skills/`; nothing there is executed.

## Python

| Item | Minimum | Source |
|---|---|---|
| Python | 3.11 | verified: `requires-python = ">=3.11"` in `pyproject.toml`; CI runs 3.11, 3.12, 3.13 and 3.14 |
| PyYAML | exactly 6.0.3 | verified: the only runtime dependency, pinned in `pyproject.toml` and hash-locked in `requirements.txt` |

Development tools (ruff, mypy, pytest and friends) are hash-locked in `requirements-dev.txt`; `make venv` installs them.

## External tools

| Tool | Need | Minimum | Seen | Why, and how the minimum was found |
|---|---|---|---|---|
| `git` | required | 2.5.0 | 2.47.3 | inferred. SAFO runs `git -C <dir> config --get` (old); the workflow here uses `git worktree`, added in 2.5 |
| `gh` | required | 2.57.0 | 2.100.0 | verified. `gh auth status --active` arrived in 2.57.0 (cli/cli release v2.57.0, 2024-09-16); the account-reading helpers need it. SAFO's own `gh auth token --hostname ... --user ...`, `gh issue view --json` and `gh api` calls are inferred to need less |
| `jq` | optional | none | 1.7 | inferred. Only `scripts/apply-baseline.sh` calls it, with `jq -e .`; any release that has `-e` works |
| `doppler` | optional | none | 3.77.1 | inferred. The Action fetches its key through `dopplerhq/secrets-fetch-action`, not the CLI; the CLI is for the person managing the store |
| `ollama` | optional | none | not installed | inferred. SAFO talks to the server over HTTP (`GET /api/tags`, `GET /api/ps`, generate), so the CLI is needed only on the server host. Reachability is `safo hooks probe` and `safo usage` |
| `codex` | optional | 0.164.0 | 0.164.0 | inferred. SAFO reads Codex's own session files and never runs it. 0.164.0 is the maintainer's recorded floor for the `--cyber-access-program` flag used for security reviews (see [Claude Code plugins](plugins.md)); older builds ignore that flag. Not found in a vendor release note |
| `claude` | optional | none | 2.1.312 | inferred. `safo hooks` installs a `SessionStart` and a `PreToolUse` hook into Claude Code's `settings.json`; no first version that has both was looked up |
| `llm-local` | optional | none | present | The maintainer's wrapper over the Ollama box (not published with SAFO). Briefs may name it as the local step. Presence only |

Two more version facts that are not checked by `doctor`: `gh agent-task` (used by the Copilot meter) needs gh 2.80.0
(verified: cli/cli release v2.80.0 introduces the `agent-task` command set; SAFO's own message in `safo agents-status` says
the same), and the Codex plugin needs Node 18.18 or later (see [Claude Code plugins](plugins.md)).

## Skills and plugins

All optional. SAFO works without them and nothing in the Action uses them; they are what the lead session uses to follow
the playbook. Sources are public GitHub repositories. "Pin" is the commit the maintainer's install recorded on
2026-10-29; "version" is the plugin's own number.

| Item | Source | Version / pin | Licence | Notes |
|---|---|---|---|---|
| Superpowers set | `anthropics/claude-plugins-official`, plugin `superpowers` | 7.0.0 / `bb92a7774141` | MIT (read in the plugin's `LICENSE`) | process skills: plans, TDD, worktrees, review, verification |
| Codex plugin | `openai/codex-plugin-cc`, plugin `codex@openai-codex` | 1.0.6 / `db52e28f4d9d` | Apache-2.0 (read in its `LICENSE`) | see [Claude Code plugins](plugins.md) |
| Ollama plugin | `darrylmorley/ollama-plugin-cc`, plugin `ollama@darrylmorley-ollama` | 0.11.0 / `7f7ab4521b5e` | Apache-2.0 (read in its `LICENSE`) | community maintained; see [Claude Code plugins](plugins.md) |
| DoIA packs `pack-*` | [Department of Internal Arguments](https://github.com/ChiefGyk3D/department-of-internal-arguments/tree/v0.4.0), installed by its `scripts/install.py` | tag v0.4.0 (the pin in `scripts/doia-tag.txt`) | Apache-2.0 (read in its `LICENSE`) | six packs: `pack-python-untrusted-input`, `pack-gha-security-dast`, `pack-threat-model`, `pack-rf-emcomm`, `pack-linux-platform`, `pack-local-llm-routing`. See [Personas](personas.md) |
| UI/UX skills (optional, not used by SAFO) | `ui-ux-pro-max`: `nextlevelbuilder/ui-ux-pro-max-skill`; `impeccable`: `pbakaus/impeccable` | ui-ux-pro-max vendored at commit `28b3b8dee8c9`; impeccable 4.7.0 / `864417528536` | MIT (ui-ux-pro-max, read in its `LICENSE`); Apache-2.0 (impeccable, read in its `LICENSE`) | design work only. Canva: no Canva plugin or skill was found on the maintainer's machine, so no source or pin is claimed |

An install from before v0.4.0 names the last pack `pack-ollama-local-routing`. In v0.4.0 the pack is `local-llm-routing`
(verified: `packs/local-llm-routing` at the v0.4.0 tag), so `doctor` reports `pack-local-llm-routing` as missing on a stale
install. Re-run the DoIA installer with `--update` (see [Personas](personas.md)).

## Accounts and secrets

Names only. Nothing here is a value, and `safo doctor` never reads a secret.

| What | Why | Where it comes from |
|---|---|---|
| A GitHub account that can read and write the Project | the board modes and `protection` | `gh auth login` (SAFO reads `gh auth token` for the logged-in account), or `SAFO_TOKEN` |
| A GitHub App (client id and private key) | the Action mints a one-hour installation token | inputs `client-id` and `private-key`, or Doppler, below |
| Doppler | holds the App key so no workflow carries it | project and config named by the caller (`doppler-project`, `doppler-config`), a Service Account Identity (`doppler-identity-id`, OIDC); the secret itself must be named `PROJECTS_APP_PRIVATE_KEY`. This repository's live audit uses project `projects`, config `prd` |
| Doppler service token (optional) | CI fallback when OIDC is not set up | repository secret `DOPPLER_TOKEN` |
| ChatGPT plan or OpenAI API key | the Codex plugin | `codex login`, see [Claude Code plugins](plugins.md) |
| A Claude plan | the lead session | Claude Code's own sign-in |
| An Ollama server you run | the local model | `OLLAMA_HOST`, or the endpoints in your `agents.yaml`; no account |

A config used by the Action should hold only what that job needs, because every secret in it is exported to the job. The
trust boundary around the App key is in the README.
