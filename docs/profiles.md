# Agent profiles

`agents.yaml` says which agent takes which task shape. A profile says how to brief that agent, and it ties every claim
about the agent to a pointer at something that was measured. The design is in
`docs/superpowers/specs/2026-10-11-agent-profiles.md`; this page is the short version of what the loader accepts today.

**Status of this page.** The profile block, the promotion settings and the migration list load and are checked, the
evidence pointers are resolved against the lessons and the outcomes log, and `safo profiles verify` works. Rendering
profiles into instruction files and `safo profiles brief` are not built yet and are not described as working here.

## The rule

No trait without a measurement. A profile is either `unmeasured`, which claims nothing about the model, or `profiled`,
which has at least one `do`, `dont` or `must_not_get` entry, each carrying a pointer to its evidence. An unmeasured
profile that lists traits is a load error, and so is a profiled one that lists none.

## What a profile holds

| Key | What it is |
|---|---|
| `status` | `unmeasured` or `profiled`. Required. |
| `persona` | A Claude agent only. The name of an installed persona file: `.claude/agents/<name>.md` or `agents/<name>.md` beside `agents.yaml`, the first that exists. |
| `brief` | Exactly one of `template` (a path under the directory of `agents.yaml`) or `inline` (one line, 4,000 characters at most). |
| `context_ceiling`, `output_cap` | A number and its evidence. How much to put in a brief, not a vendor limit. |
| `thinking` | `"off"`, `"default"` or `"on"` and its evidence. Quote `"off"` and `"on"`: bare, YAML reads them as booleans. |
| `do`, `dont` | Up to 8 entries each, `text` (one line, 300 characters at most) and `evidence`. |
| `must_not_get` | Up to 8 entries, a `shape` from `shapes` and `evidence`. |
| `review_gate` | A pull-request harness only (today the Copilot coding agent): `required: true`, `reviewer_differs: true` and `checks`, each a `code` with its own `evidence`. |
| `models` | A Copilot agent only: one layer per underlying model. |

Whether a brief is required depends on the agent. A Claude profile needs a `brief` unless it names a `persona`; Codex and
local models always need one; the Copilot form is owned by the renderer, so its brief is optional. A human takes no
profile.

Two minimal valid profiles:

```yaml
claude-sonnet:
  profile: {status: unmeasured, persona: adversarial-reviewer}
codex:
  profile:
    status: profiled
    brief: {inline: Work from this prompt alone and read state from files.}
    dont:
      - text: Expect it to commit inside a git worktree.
        evidence: "lessons:codexs-sandbox-cannot-commit-inside-a-git-worktree"
```

## Evidence pointers

A pointer is a string with a fixed form, not a sentence. Three kinds exist, and each claim accepts only some of them, so
a true but irrelevant fact cannot be cited for a trait.

- `lessons:<slug>` is the GitHub-style slug of a heading in `docs/lessons.md`.
- `outcomes:v1:<range>:<subject>:<metric><op><number>` states something about the outcomes log, for example
  `outcomes:v1:2026-10:copilot:runs>=4`. The range is at most 12 months.
- `config:<JSON Pointer>` names one non-secret endpoint field, and only for the setting it can support: an endpoint's
  `num_ctx_max` or `loaded_num_ctx` for `context_ceiling`, its `think` for `thinking`.

`do`, `dont`, `must_not_get`, `output_cap` and review checks take `lessons` or `outcomes` only. The loader checks the form
and the pairing; resolution (below) checks that the cited measurement exists and says what the pointer states. A person
still judges whether a citation is relevant to its claim, and nothing here can do that for them.

## Resolving the evidence

Resolution is a second stage that runs whenever profiles are loaded for use (`safo route`, `safo validate`, `safo
profiles verify`). It reads the files named by the top-level `evidence_sources` of `agents.yaml`:

```yaml
evidence_sources:
  lessons: docs/lessons.md      # the default
  outcomes: docs/outcomes.jsonl # no default: an outcomes pointer cannot resolve without it
```

Paths are relative to the directory of `agents.yaml`, read without following a symbolic link, and the local override
cannot set them. What each kind resolves to:

- `lessons:<slug>`: a heading of the lessons file, by its GitHub slug. Headings inside code fences are not headings, and a
  repeated heading gets `-1`, `-2` as GitHub gives it. A retitled lesson makes the pointer dangle, on purpose.
- `outcomes:v1:<range>:<subject>:<metric><op><number>`: computed over the whole range of months, for the agent or the
  agent and model. The metrics are `runs`, `fix_share`, `rounds_per_run`, `credits_per_run` and the totals of
  the four severities (critical, important, minor, unrated), each written `findings.<severity>`. A metric with no data (no
  matching records, or `credits_per_run` with no known credits) is reported as `no data`, which is neither zero nor false;
  a statement the log contradicts is reported as false. Either way the pointer does not resolve. The comparison is exact.
- `config:<JSON Pointer>`: RFC 6901, addressed to the base `agents.yaml` only, so the local override can neither satisfy
  nor change a committed claim. Only the allowlisted endpoint fields of the citing agent itself resolve (see above).

A pointer that does not resolve is an error attributed to the agent that cites it. `safo validate`, `safo profiles
verify` and (when it exists) the generator stop on any such error and have no flag to go on. `safo route` goes on: the
agent is treated as unmeasured for that run, `route` prints a `profile:` line with the reason, and every other agent
routes as before. Selection itself does not change until promotion is built.

`route` names the problem for the recommended agent only. The spec's entry in the recommendation's `skipped`
list and its `profile_status` field are not built; TODO for group 4 (route surface), together with the `--json` keys that spec
section 3.5 adds. Today `--json` gains `profile_unverified` only when the recommended agent is degraded.

Where the evidence lives: `lessons` and `outcomes` are resolved beside the `agents.yaml` that is read. In a repository
that is the checkout. For a home `~/.config/safo/agents.yaml`, copy the lessons file next to it (into a
`docs` folder of `~/.config/safo`) or set `evidence_sources` to another path under that directory. A lesson heading
that contains an inline Markdown link is slugged by the link's text, as GitHub does. Headings inside code fences, HTML comments and HTML blocks
(`<div>` up to the next blank line, `<pre>`, comments) are not headings.

## `safo profiles verify`

```
safo profiles verify [--agents FILE]
```

It prints one line per claim: where it is, the claim, the evidence kind and what the pointer resolved to (the lesson's
heading and first line, or the computed metric), so a reviewer can judge relevance. It then checks that CODEOWNERS owns
`agents.yaml`, `examples/harness/`, `.claude/agents/`, `agents/`, the lessons file, the directory of every template and
the two source files that hold the profile constants and the renderer. When an outcomes source is configured it also
reports, for each profiled agent and model layer, how many recorded outcomes qualify (a card, a review round, a date in
the window, deduplicated per card, conflicting duplicates voiding their card) against `promotion`, as information only.

CODEOWNERS is evaluated with gitignore semantics (checked against `git check-ignore` in the tests): `*`, `?`, and `**`
as a whole segment, escapes `\#`, `\ `, `\*`. A rule it cannot evaluate with confidence (a `[...]` class or a
section header, a negation, an unknown escape, a long or wildcard-heavy pattern) fails closed: `verify` names the line
and exits 2, it never drops the rule. Each required directory is probed with `.md` and `.yaml` files at two depths, so a
later rule that removes the owner for one extension is seen.

Exit 0 when everything resolves and is owned, 1 when a pointer does not resolve or a path has no owner, 2 when the file
cannot be read or fails its form checks. With `--agents FILE` the file is treated as a repository checkout (CODEOWNERS is
checked, the private-file trust policy is not applied), and this mode, being read-only, is allowed to read a file inside
`GITHUB_WORKSPACE` under Actions, so CI can run `safo profiles verify --agents agents.yaml` on a checkout. Without it the file is `~/.config/safo/agents.yaml`, held to the
private-file policy, and CODEOWNERS is not checked. Without `--agents` (the home file), a path inside the workspace is still refused under Actions, as for every other local
mode and for `safo validate`; so is a local override named with `--agents-local`.

## Text rules

Profile text ends up in files that agents obey, so every text field is one printable line that cannot become a heading,
list, quote, fence, comment or placeholder, and carries no home-directory path, drive path, `file://` URL or e-mail
address (the reserved documentation domains and `N0CALL` style placeholders are fine). A short list of phrases that try to
override instructions or send out credentials is refused as well. That list is a tripwire for accidents and the lazy
attack. It is not a filter for meaning, and a well-formed, plausibly cited, harmful instruction passes it.

A template is a file under the directory of `agents.yaml`, read without following a symbolic link, at most 16 KiB of
UTF-8. Its placeholders are `{{task}}`, `{{files_in_scope}}`, `{{acceptance_criteria}}`, `{{test_command}}` and
`{{card}}`. Each must be the whole content of its line with a blank line on both sides, appear at most once and stay
outside code fences. A template cannot hold front matter, a level-1 heading or generated-header text.

## Migration

An agent with no profile counts as unmeasured. A file that carries profiles must profile every agent that is not a human,
with one exception, and the rule holds even in a file with no profile at all: the agents in `profile_migration`. The cohort (`claude-lead`, `claude-sonnet`, `claude-opus`) and the
deadline (2026-12-31) are fixed in `src/safo/agentsfile.py`, not in the file. The list in `agents.yaml` can shrink to a
subset of the cohort as agents get a profile their lessons support, and cannot grow or name another agent. After the
deadline a non-empty list is a load error, so prune the list before 2027-01-01.

## Local files

Every private agents file (the `agents.yaml` and its local override) is read only when it is a regular file owned by you, not writable by its
group or by others, and reached without a symbolic link through directories that are yours or root's and not writable by
others. A repository checkout is not held to that rule: review is the control there. A local override file cannot carry
`profile`, `profile_migration`, `promotion` or `evidence_sources`.

## Promotion settings

`promotion` sets how many recorded outcomes make an agent promotable: `min_outcomes` (default 10), `min_distinct_dates`
(3) and `window_days` (180). The loader validates them. `qualify` (in `src/safo/qualify.py`) counts qualifying outcomes
against them and `safo profiles verify` prints the result; nothing in selection reads it yet. Outcomes are self-reported into a file
you own, so the count is a speed bump and not proof; see [Limits](limits.md).
