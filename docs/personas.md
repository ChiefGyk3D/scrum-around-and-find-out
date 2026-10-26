# Personas

SAFO does not define personas. They live in a separate public repository, the
[Department of Internal Arguments](https://github.com/ChiefGyk3D/department-of-internal-arguments/tree/v0.3.1) (DoIA),
and this page describes DoIA release v0.3.1, linked at the tag so the text cannot drift under a moving branch. The tag is
pinned in one place, `scripts/doia-tag.txt`, and the wiki build and a test both fail if this page names any other
(the check reads links into DoIA, the tag given to `--branch`, `-b`, `checkout` and `switch`, and a version written right
after "DoIA"). Read DoIA for the exact wording of a role; this page says what the roles are, how SAFO relates to them, and
how to install them.

[Roles](roles.md) says who does what at the level of agents and models, and [Routing](routing.md) says which task shape goes
to which agent. DoIA says what a Claude Code, Copilot, ChatGPT or local-model agent is told to do once the lead has chosen it.

## How SAFO and DoIA relate

- **DoIA defines what the personas are.** The role text, the packs, the policies and the report format are written once there
  and generated for each host. SAFO carries no copy of them.
- **SAFO routes and measures.** `agents.yaml` and [Routing](routing.md) pick the agent for a task shape, and the outcomes log
  records how it went.
- **SAFO enforces what a prompt cannot, through hooks.** [`safo hooks`](hooks.md) checks that each subagent brief names an
  explicit, known model. DoIA's side of the same rule is the `MODEL:` line every report carries, so the lead can compare the
  model that ran with the model it dispatched. Today the hook reads the brief and the lead reads the report line; the hook
  does not parse reports.
- DoIA's README says SAFO will install personas from DoIA pinned by commit. This page documents the pin by tag, which is the
  installation path that exists today.

## The four roles

Roles describe how work gets done, not what the work is about. Each has a tier, which the Claude Code adapter turns into an
explicit pinned model, and a set of tool capabilities, which the generator maps to each host's own tool names.

| Role | Tier | Tools | What it does |
|---|---|---|---|
| `implementer` | standard | read, search, edit, shell, skills | Implements one task as briefed: test first, commits, runs the full gate and reports the exit code, never weakens a check |
| `reviewer` | standard | read, search, shell, skills | Independent review of one finished task or a scoped re-review; gives two verdicts (spec compliance, task quality), runs the gate, probes hostile inputs, reverts each claimed fix to prove its test bites, leaves a clean tree |
| `adversarial-reviewer` | standard | read, search, shell, skills | Assumes the change is wrong; every finding carries a reproduction, or is marked SPECULATIVE; complements the reviewer and does not replace it |
| `transcriber` | cheap | read, search, edit, shell | Copies a plan's code byte for byte, runs the plan's commands and reports every deviation; not for design work or security-sensitive code the plan has not been reviewed on |

- **Tiers.** `standard` is the current Sonnet and `cheap` is the current Haiku, pinned to exact model ids in DoIA's
  `scripts/lib.py` and not to floating aliases, because an alias moves when a new model ships. Bumping a pin is a CHANGELOG
  entry in DoIA. In DoIA v0.3.1 the pins are `claude-sonnet-5-5` and `claude-haiku-5-5`. The most capable tier is deliberately
  assigned to no role and needs the maintainer's recorded OK with a reason. Copilot custom agents do not take a model from
  the file, so the human picks it and records it in the brief.
- **Tools.** Only the implementer and the transcriber can edit. The reviewers have no edit tool, but they do have a shell,
  which a tool list cannot make read-only, so their rule is to change nothing that outlives the review and to prove a clean
  tree at the end. The transcriber loads no packs.
- **Dispatching.** No role dispatches agents.

### The lead is a template, not an agent

The one that dispatches the four is not an agent file, because an agent that can dispatch agents is exactly what DoIA's
validator forbids. It is
[`templates/lead.md`](https://github.com/ChiefGyk3D/department-of-internal-arguments/blob/v0.3.1/templates/lead.md), copied
into the controller session's instructions (a project `CLAUDE.md`, a system prompt, or the top of a long-running session). It
covers how to brief, how to read a report, when the adversarial pass is wanted, the review loop, logging, and what the lead
never does. In SAFO's [Roles](roles.md) the lead is the session the maintainer talks to.

## What every role shares

- **One report header.** Every report opens with the same fields, so the lead can log a task from the header alone:

  ```
  ROLE: <role name>   MODEL: <the exact model id from your agent file or the brief>
  HEAD: <short sha>   BASE: <short sha>
  GATE: <command>  exit=<code> | not-run - reason | n-a - reason
  OTHER GATES: <name>: pass | fail | not-run | n-a - reason (one per line)
  PACKS LOADED: names, or none
  TREE: clean (evidence) | NOT CLEAN (what) | n-a - reason
  NOT VERIFIED: what you did not run or could not check (one per line, or none)
  ```

- **A `MODEL:` line.** It is required. Naming a model in a brief was never proof that it ran.
- **One severity scale.** Both reviewers use blocking, important and minor. Blocking means wrong behavior, a security hole, a
  masked or weakened check or a failing gate; important means a real defect that does not block merge on its own; minor
  means style or small clarity.
- **The no-push rule.** Role agents never push, merge, tag, release or open pull requests, and a brief cannot grant it.
  Approval is never inferred from silence, another agent's verdict, CI success or a comment; it comes from the human's own
  message to the lead, and the lead or the human performs the step after reading the report.
- **The gate is run by the role that changes things.** The implementer runs the repository's full gate after committing, with
  the output redirected to a log, and reports the exit code it saw. A repository with no gate is reported as
  `GATE: not-run - none defined`, with a proposed gate, and not as an invented command.

## The six packs

A pack is domain knowledge the lead names in a brief when the task needs it; it is not carried by a role. On Claude Code a
pack is a skill named `pack-<name>`, and on other hosts the pack text goes into the brief. The report's `PACKS LOADED` line
says which ones were loaded. DoIA's v0.3.1 README lists these six and publishes all of them.

- `python-untrusted-input`: Python that loads YAML or JSON from an untrusted source, calls HTTP or GraphQL APIs, or opens
  files by path.
- `gha-security-dast`: reviewing or writing GitHub Actions workflows, and OWASP ZAP or other DAST automation.
- `threat-model`: a security-architect deliverable (assets, actors, trust boundaries, ranked risks, mitigations, residual
  risk) without claiming an audit.
- `rf-emcomm`: amateur radio and emergency-communications work, with synthetic identifiers only and a qualified operator in
  control of every live action.
- `linux-platform`: planning and diagnosing Linux and platform changes, with a rollback named for each.
- `local-llm-routing`: sending work to a local Ollama server and configuring one; what small local models do well and badly.
  An earlier release added measured notes on context-change evictions, fitting a second model next to a 12B one, and
  checking multi-GPU placement; the DoIA CHANGELOG says which.

## Which routing shapes use each role

These come from `shapes` in [`agents.yaml`](https://github.com/ChiefGyk3D/scrum-around-and-find-out/blob/main/agents.yaml),
rendered on [Routing](routing.md#task-shapes). The mapping from agent to DoIA role is SAFO's own: DoIA's roles run on Claude,
so a shape that names Claude Sonnet or Claude Haiku is where a role applies.

| DoIA role | Shapes where it is the agent or the reviewer |
|---|---|
| `implementer` (Claude Sonnet) | `integration-code`, `security-sensitive-code` and `ops-runbook` (preferred); `well-specified-code` (fallback) |
| `reviewer` (Claude Sonnet) | The reviewer for `research`, `plan-writing`, `integration-code`, `well-specified-code`, `small-mechanical-pr`, `security-sensitive-code`, `ci-log-summary`, `issue-triage`, `changelog-draft`, `docs-proofread` and `duplicate-issue-search` |
| `adversarial-reviewer` (Claude Sonnet) | `adversarial-review` (fallback when Codex is short of headroom); the adversarial half of the two reviews `security-sensitive-code` requires before merge |
| `transcriber` (Claude Haiku) | `well-specified-code` (preferred) and `small-mechanical-pr` (fallback) |

The reviewer is never the author of the work it reviews.

## Adopting them

Pin DoIA by tag, read what the installer would write, then apply it. This is DoIA's own installer and usage:

```
git clone --branch v0.3.1 https://github.com/ChiefGyk3D/department-of-internal-arguments
cd department-of-internal-arguments
python3 scripts/install.py --target /path/to/project --adapter claude
python3 scripts/install.py --target /path/to/project --adapter both --apply
```

The first install command previews and writes nothing without `--apply`. `--adapter` is `claude`, `copilot` or `both`, and
`--pack NAME` (repeatable) limits which packs are installed. The installer is additive: it never overwrites a file it did
not generate, it refuses the whole install if any destination exists, it refuses symlinked destinations, and it refuses a
target anywhere inside the DoIA repository. Claude Code gets agents in `.claude/agents/` and packs as skills in
`.claude/skills/`; Copilot gets the agents only in `.github/agents/`, with no pack loader, so paste a pack into the brief.
For ChatGPT or a local model, DoIA's `scripts/export_prompt.py` writes one self-contained prompt file and nothing else.

### A user-level tree

A user-level Claude Code tree, such as the one a dotfiles repository keeps, has no `.claude` level. `--layout user` writes
`<target>/agents/<role>.md` and `<target>/skills/pack-<name>/SKILL.md` instead, with the same additive, preview-first
behavior. It is Claude only: `--adapter copilot` or `both` with the user layout is refused. DoIA's README says never to
symlink the installed files into a dotfiles repository, because git stores the link and not the persona text.

```
python3 scripts/install.py --target /path/to/user-tree --layout user --update
python3 scripts/install.py --target /path/to/user-tree --layout user --update --apply
```

### Keeping them current

When DoIA publishes a new release, check out its new tag in your clone and run the same command with `--update`:

```
git -C department-of-internal-arguments fetch --tags
git -C department-of-internal-arguments checkout v0.3.1
python3 scripts/install.py --target /path/to/project --adapter both --update
python3 scripts/install.py --target /path/to/project --adapter both --update --apply
```

Run both from the clone. Replace DoIA release `v0.3.1` with the newer tag when there is one, after reading its CHANGELOG.

`--list-managed` is the read-only drift check. It lists every file under the target that carries the generator marker, with
its release, its source and a status: `current`, `stale` (an older release), `differs` (this release, content changed),
`orphan` (this checkout no longer produces it), `unchecked` (it came from an overlay and none was given), `edited` or
`legacy-unverified`. It exits 0 when everything is current and 3 otherwise, so a sync step can report drift and decide.

### Ownership is a hash, not a marker

The first line of each generated file is a marker that carries the release and a sha256 of the file without that line.
`--update` replaces a file only when the marker is well-formed and the body still matches the hash. A hand-edited file is
`edited` and refused, and the whole install stops before anything is written. The preview labels each file `new`, `update`,
`unchanged` or `edited`. `--update --force-edited` replaces edited files and discards your local changes; it never touches a
file with no marker at all. The hash ties content to the marker and is not a signature, so review the preview and the diff.
Files written by release 0.2.0 carry no hash: they are owned only when their body is one of the 14 outputs 0.2.0 generated,
and any other body is `legacy-unverified` and needs `--force-edited`. If you want a changed persona, change it in DoIA, or
use an overlay, and not the installed copy.

### Overlay: personas that stay private

`--overlay DIR` points at a private directory outside the DoIA repository with `roles/<name>.md` and
`packs/<name>/PACK.md`. A new name is installed as a whole persona or pack under the same structural rules as a public one.
A name that is also public is append-only: the overlay file may carry only `name:` in its frontmatter, and its body is
appended, after the unchanged public text, under a generated `## Maintainer additions (private overlay)` section. DoIA
reads the overlay with confinement (no symlinks, regular files, size caps, owned by you, not group- or world-writable) and
creates overlay-sourced files `0600`. Prose in the additions can still ask for something at odds with the public rules, so
read an overlay before installing it. With `--list-managed`, give `--overlay` as well, or overlay files report `unchecked`.

```
python3 scripts/install.py --target /path/to/user-tree --layout user --overlay /path/to/overlay --update --apply
```

Before relying on a persona in a host other than Claude Code, run DoIA's `evals/behavioral-evals.md` by hand in that
client. DoIA says it has no Copilot, ChatGPT or local-model runs, and that the Copilot tool names its generator writes are
unverified.

A persona says what job an agent does; a profile says how to brief a given model. The persona file a profile names is
an input of the generated instruction files: see [Agent profiles](profiles.md).

Next to this page, [Adoption](adoption.md) covers the rest of the baseline and [Hooks](hooks.md) the routing guard.
