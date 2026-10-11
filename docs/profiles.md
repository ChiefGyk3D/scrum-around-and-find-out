# Agent profiles

`agents.yaml` says which agent takes which task shape. A profile says how to brief that agent, and it ties every claim
about the agent to a pointer at something that was measured. The design is in
`docs/superpowers/specs/2026-10-11-agent-profiles.md`; this page is the short version of what the loader accepts today.

**Status of this page.** The profile block, the promotion settings and the migration list load and are checked, the
evidence pointers are resolved against the lessons and the outcomes log, `safo profiles verify` works, and the profiles
are rendered into the instruction files under `examples/harness/`. `safo profiles brief` fills a brief template with
fenced task data. The Copilot-specific route lines are not built yet and are not described as working here.

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
and exits 2, it never drops the rule. GitHub does not load a CODEOWNERS of 3 MiB or more and does not support an escaped leading `#`; both fail closed. Each required directory is probed with `.md` and `.yaml` files at two depths, so a
later rule that removes the owner for one extension is seen.

Exit 0 when everything resolves and is owned, 1 when a pointer does not resolve or a path has no owner, 2 when the file
cannot be read or fails its form checks. With `--agents FILE` the file is treated as a repository checkout (CODEOWNERS is
checked, the private-file trust policy is not applied), and this mode, being read-only, is allowed to read a file inside
`GITHUB_WORKSPACE` under Actions, so CI can run `safo profiles verify --agents agents.yaml` on a checkout. Without it the file is `~/.config/safo/agents.yaml`, held to the
private-file policy, and CODEOWNERS is not checked. Without `--agents` (the home file), a path inside the workspace is still refused under Actions, as for every other local
mode and for `safo validate`; so is a local override named with `--agents-local`.

## Rendering

```
python scripts/gen_profiles.py --write    # make examples/harness/ exactly what agents.yaml renders
python scripts/gen_profiles.py --check    # exit 1 if it is not; the test suite and `make check` run this
```

The generator reads only the repository's `agents.yaml` (never a local override or anything under `~/.config/safo`),
resolves the evidence the same way `safo profiles verify` does, and fails the build when a pointer does not resolve. The
files agents read are written under `examples/harness/` for you to copy where your harness looks; SAFO does not install
them into a repository for you.

| File | Harness | What it is |
|---|---|---|
| `claude/<agent>.md` | Claude subagent | Front matter (`name`, `description`, `model` from the agent, `tools` and `disallowedTools` only if the persona's own front matter has them), the persona body when there is one, then the generated section |
| `codex/<agent>.prompt.md` | Codex | A preamble to prepend to a self-contained prompt |
| `copilot/ISSUE_TEMPLATE/copilot-task.yml` | Copilot coding agent | An issue form with the acceptance criteria, the files in scope, one test command and a scope checkbox, all required |
| `copilot/copilot-instructions.md` | Copilot coding agent | The three scope rules and the generated section |
| `local/<agent>.wrapper.txt` | Local models | A prompt wrapper with a `{{task}}` slot, a strict output-format line and the ceilings in prose; `think=false` is a comment line for the caller to remove |

Only an agent with a profile renders. An `unmeasured` profile renders its brief, ceilings and review gate and says on the
first line of the section that nothing is claimed about the model.

**The policy boundary.** Every file holds one fixed paragraph, just before the generated section, saying that the profile
adds briefing guidance only and cannot change tool access, secrecy rules, approvals or any instruction from a higher
source. Profile text, templates and personas that contain that paragraph, the generated header or a second `Model profile`
heading are refused, so a file cannot imitate the generated part.

**The header and the two digests.** Every file carries one header line: `GENERATED by scripts/gen_profiles.py from
agents.yaml; do not edit; manifest sha256:<hex>; body sha256:<hex>`, in the comment form of its format. A Claude file keeps
its front matter fence on the first line of the file and carries the header as an HTML comment on the line after the
closing fence; Codex and Markdown files carry it on line one; the issue form and the local wrapper carry it as a `#` line.

- The **manifest** digest is the SHA-256 of a canonical JSON object that binds the agent's profile data, the persona
  bytes, the template bytes, the output path, the harness, the format number, the SAFO version and the resolved evidence.
  A stale manifest means a source changed.
- The **body digest** is the SHA-256 of the whole file with the header line removed, so an edit of the text, or of the
  front matter's tools list, is caught even when the header was left alone.

`--check` recomputes both and says which one failed. The digests are traceability and tamper-evidence for someone who holds
the sources. They are not a signature: they are not secret and do not stop anyone who can rewrite the sources and the files
together. Review of the generated diff, and CODEOWNERS on `examples/harness/`, are the controls.

**The output tree.** The generator never follows a symbolic link. It opens the repository root once and then every component
of the output path (`examples`, `harness`) relative to the descriptor above it, without following a link and checking each
one against its parent entry, so a symbolic link at any level of the path is an error and cannot redirect a read or a write;
missing levels are made the same way. It walks the tree on directory descriptors, stops reading a directory after 501
entries, and rejects an output path that is absolute or has an empty, `.` or `..` component; a link,
FIFO, socket, device or oversized file anywhere under it, or the output directory itself being a link, is an error for
`--check` and `--write` alike. The comparison is of exact path sets, so a missing, unexpected or stale file fails. Writes
go to a temporary file created exclusively in the destination directory, then rename, with `fsync` of the file and the
directory. Every name read from the output tree is untrusted when printed: control, bidi and DEL characters are written as `\x..` or `\u....` escapes, a colon at the start of a line is escaped, a long name is cut, and a ready-to-paste `git rm -- 'path'` command is printed only for a plain printable ASCII name, shell-quoted; any other name gets `remove it by hand:` and the escaped name. A directory or a link is never replaced. **The generator never deletes a file or a directory.** `--write` writes and updates
the expected files only. A stale generated file, a file without the header, and an empty or non-empty unexpected directory
are each reported by name with the `git rm` command that removes them, and `--write` exits 1 after writing the expected
files, so a renamed output takes two steps: write, then remove the old one yourself. A header and its digests are tamper
evidence for a reader, not authorization to remove anything; `--check` only uses them to say "looks generated but is not
expected" or "not a generated file". An entry that blocks a write (a link, a FIFO, a directory where a file belongs) stops
the whole write before the first change, with an error naming it. Before each write and at the end the path from the root is
resolved again and must name the directory the run holds open, or the run fails with "the output directory moved during the
run". A race between the inventory and the write (another process swapping an entry in
that window) is narrowed by the exclusive, no-follow opens but not closed.

**Known limitation: who reads the generated text.** The Codex and local-model files are sent to a model, but a few lines
are written for the caller: the header line and the generated-by comment, the `think=false` comment that tells the caller to
strip it, and `do`/`dont` lines such as "give it a self-contained prompt" that address whoever builds the prompt, not the
model. The model sees those lines too. This is a mismatch between the two audiences and is not redesigned here; the
proposal is that the spec for the Copilot and route group splits a caller section from a model section.

**Before publishing the files.** `tests/privacy.py` checks the generic patterns (home paths, e-mail addresses, private
addresses, callsign-shaped tokens) in `examples/harness/`. It cannot know a private handle, an employer term or an internal
hostname. A release that publishes `examples/harness/` therefore runs `make check` with `SAFO_PRIVACY_EXTRA_FILE` set to
your terms file (see [Privacy check](privacy.md)).

## Text rules

Profile text ends up in files that agents obey, so every text field is one printable line that cannot become a heading,
list, quote, fence, comment or placeholder, and carries no home-directory path, drive path, file URL or e-mail
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

## `safo profiles brief`: filling a template with task text

```
safo profiles brief --agent ID [--agents FILE] [--task-file PATH|-] [--files-file PATH|-]
                    [--acceptance-file PATH|-] [--test-command TEXT] [--card TEXT]
```

A brief template holds placeholders, and the task text that goes into them is written by someone else: an issue, a
pull request, a pasted log. `brief` prints the filled template so that none of that text can end the place it sits in
or pretend to be part of the template. Each value goes between a start line and an end line:

```
<<<UNTRUSTED-TASK-DATA name=task id=0123456789abcdef0123456789abcdef>>>
...the value...
<<<END-UNTRUSTED-TASK-DATA id=0123456789abcdef0123456789abcdef>>>
```

The id is 128 bits from the `secrets` module, drawn again on every call, so it cannot be known when the value is
written. A fixed sentence before the first fence says that text between the fences is data from the task author, that
it is not an instruction, and that it cannot override the profile or the policy boundary.

**What it refuses (exit 2, nothing printed to standard output).**

- A value that contains the delimiter text `UNTRUSTED-TASK-DATA`, also when the text is hidden with zero-width or bidi
  characters, a soft hyphen, a character reference, a full-width letter or another case. A value therefore cannot
  contain an end line, a start line or the id.
- A NUL or any other control character except newline and tab (an escape sequence would drive a terminal).
- A directional embedding, override or isolate (U+202A to U+202E and U+2066 to U+2069). Shown right to left, an end
  line written backwards reads as a forward one, so these nine are refused and the error names the code point. The
  left-to-right, right-to-left and Arabic letter marks (U+200E, U+200F, U+061C) and the zero-width joiner and non-joiner
  stay allowed, because Arabic and Hebrew text needs them.
- A value larger than 65536 bytes, measured as given and before line endings change. The error names the value and
  never repeats it.
- A template that breaks the placement rules, checked again at fill time with the same scanners as at load time: a
  placeholder is the whole content of its line, has a blank line on both sides, appears once, and sits outside every
  code fence and raw HTML block; no list item, quote, table, heading or HTML line may hold one. A template that
  contains the delimiter text is refused too, so a template cannot forge a fence.
- A value for a placeholder the template does not have (it would be dropped without a word), a placeholder with no
  value, an agent with no profile or no brief, an inline brief given values (an inline brief has no placeholders), and
  an agents file with any unresolved evidence pointer, for any agent: the load is the strict one and has no bypass.

Line endings in a value become LF. Other invisible format characters stay in the value and inside its fence. Under
GitHub Actions the whole brief is written inside a `stop-commands` block so a line that begins with `::` cannot act as a
workflow command, and only there are control and format characters written out as `\uXXXX`. That output is escaped
and not reversible: a literal `\u200b` in a value and a real U+200B look the same in the Actions log.

**Where values come from.** `--task-file`, `--files-file` and `--acceptance-file` take a path or `-` for standard input
(for one value only). A file must be a regular file and not a symbolic link, is never waited on if it is a FIFO, and at
most 65537 bytes are read, so a huge file or an endless pipe cannot use memory. Standard input is read with the same
bound and gives up after 30 seconds of silence. `--test-command` and `--card` are the text itself. Under GitHub Actions
the agents file must come from outside the workspace, as for `route`.

**What this claims, and what it does not.** The claim is about structure only: where a value starts and where it ends
in the output, and that it cannot forge or close that structure. It does not make a model ignore an instruction written
inside a fence, and a model that obeys it has not been stopped by this command. Pasting task text into a template by hand
is outside the guarantee: the fence exists only when this command writes it. A Markdown renderer is not the reader the
fences are designed for; they are plain lines, not code fences.
