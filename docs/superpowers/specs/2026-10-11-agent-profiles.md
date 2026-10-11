# Agent profiles and per-harness instruction files: design

**Status:** draft for the maintainer's review, 2026-10-11.
**Scope:** items 1 and 2 of SAFO #23 (v0.2.0). Item 3 (outcomes `model` and `credits_used`) shipped in #27. Items 4
(promotion) and 5 (`safo metrics`) are not built here; section 6 fixes the seams they plug into.
**No code in this document.** It names files, fields, rules and tests; the implementation plan comes after the review.

## Why

`agents.yaml` answers "which agent for this task shape". It does not answer "how do I brief that agent", and the answer
differs a lot by agent: the measured month says Haiku transcribes a plan's bugs along with its code, every Copilot pull
request needed fixes (one a functional bug its own test hid), a local thinking model spends hundreds of tokens on one
sentence, and Codex's sandbox cannot commit in a worktree. Today those facts live in prose `strengths` and
`constraints`, in `docs/lessons.md` and in the lead's head. The lead re-types them into every brief.

This design makes the brief an artifact: a `profile` per agent, held in `agents.yaml`, every behavioural claim in it
pointing at evidence, rendered into the instruction file each harness actually reads, with a test that fails when the
rendered files drift from the profile. The rule from the issue stays the organising idea: no trait without a measurement.
The loader enforces it, so it does not depend on anyone remembering it.

## Rulings carried over

- `agents.yaml` stays the single source (design rulings 8 and 9 of the v0.1.0 spec). No second registry of agents.
- Measured, never assumed: "Inventing traits for unmeasured models" is out of scope in the issue and a loader error here.
- Generated files follow the `docs/routing.md` pattern: one pure renderer, one script with `--write` and `--check`, one
  drift test. Nothing is rendered at dispatch time.
- Pull, not push; no network code; no hosted service; real endpoints and paths stay in the git-ignored local file.

## 1. The `profile` block

### 1.1 Shape

`profile` is an optional key of an agent entry, next to `strengths` and `constraints`. Shown as the key list the loader
accepts, not as a sample to copy:

| Key | Type | Rule |
|---|---|---|
| `status` | `unmeasured` or `profiled` | Required. Default is not assumed: a profile states which it is. |
| `persona` | identifier | Optional. Names a file in `examples/personas/` (or the adopter's persona directory). Claude only. |
| `brief` | mapping | Exactly one of `template` (relative path) or `inline` (string). See 1.3. |
| `context_ceiling` | integer tokens | 1024 to 2,000,000. For a local agent, at most the endpoint's `num_ctx_max` (cross-check). |
| `output_cap` | integer tokens | 64 to 200,000, and at most `context_ceiling` when both are set. |
| `thinking` | `off`, `default`, `on` | Closed set. For a local agent it must agree with the endpoint's `think` default. |
| `do` | list of entries | Each entry `{text, evidence}`. At most 8. |
| `dont` | list of entries | Same shape. At most 8. |
| `must_not_get` | list of entries | Each `{shape, evidence}`. `shape` must exist in `shapes`. |
| `evidence` | list of pointers | Profile-level basis for the scalar settings above. Required when any scalar is set. |
| `review_gate` | mapping | Harness agents only (section 3). |
| `models` | mapping of model id to model layer | `copilot` only (section 3). |

Unknown keys, duplicate keys (rejected at compose time by the existing reader), a non-mapping, or a wrong type is a
`ConfigError` naming the dotted path, like every other block in `agentsfile.py`.

### 1.2 Relation to the existing fields

- `strengths` and `constraints` stay. They are the human-facing prose of `docs/routing.md` and are not rendered into
  instruction files. The profile is the machine-checked, rendered view. No retrofit pass: the shipped file gains
  profiles only where a lessons entry or the outcomes log supports each line.
- `model` (existing, optional string) names the model of a Claude agent and stays the model of record; the profile
  never restates it. Claude subagent files take their `model:` frontmatter from it.
- `limits` is untouched. `context_ceiling` is a briefing ceiling (how much to put in a brief), not a vendor limit.
- `endpoints` (ollama) stays authoritative for transport facts (`num_ctx_max`, `loaded_num_ctx`, `think`). The profile
  may only be stricter than the endpoint, never looser; cross-checks enforce it. Profile `context_ceiling` is not sent
  to Ollama: `safo local run` still sends exactly the loaded `num_ctx`.
- `shapes` is untouched. `must_not_get` is checked against it (1.5) so a profile cannot contradict routing silently.
- `approval_required` is untouched and still enforced only by `safo hooks`.

### 1.3 The brief

Exactly one of:

- `template`: a path relative to the directory holding `agents.yaml`. Confined to that directory by path components, no
  `..`, no absolute path, no symlink anywhere in the path (opened `O_NOFOLLOW` with a directory fd), regular file only
  (`S_ISREG` on the fd, `O_NONBLOCK` open so a FIFO cannot hang), UTF-8, at most 16 KiB, read through `bounded_read`.
- `inline`: a string of at most 4,000 characters.

Template placeholders are a closed set: `{{task}}`, `{{files_in_scope}}`, `{{acceptance_criteria}}`,
`{{test_command}}`, `{{card}}`. They are substituted by the lead at dispatch time, never by SAFO, and never evaluated.
Any other `{{...}}` is a loader error. A template containing a front-matter fence, a markdown heading of level 1, the
generated-header marker (7.3) or a control character other than newline and tab is rejected.

### 1.4 Evidence pointers

Every `do`, `dont` and `must_not_get` entry has a non-empty `evidence` string. Three forms, one grammar, parsed by one
function:

- `lessons:<slug>`: the GitHub-style slug of a heading in `docs/lessons.md` (for example
  `lessons:every-copilot-pull-request-needed-fixes`). Resolved against the lessons file by `safo profiles verify` and by
  the shipped-file test; the loader checks only the form.
- `outcomes:<agent>[/<model>]:<metric><op><number>`: a statement about the outcomes log, with `metric` one of
  `fix_share`, `rounds_per_run`, `runs`, `credits_per_run`, `findings_critical`, `findings_important` (the names of the
  `ModelSummary` fields that exist today), `op` one of `>=`, `>`, `<=`, `<`, `=`. Example form:
  `outcomes:copilot:fix_share>=1`. Resolved by `safo profiles verify --log FILE`, which recomputes the metric with
  `summarise_models` and fails if the log does not support the claim.
- `config:<dotted.path>`: a value read from `agents.yaml` itself (an endpoint's `loaded_num_ctx`, say), for ceilings that
  are configuration facts and not behaviour. Resolved by the loader.

Anything else is an error. Evidence text is data: a pointer is a form, not a sentence, so it cannot carry instructions.

### 1.5 Loader validation (the "never invent traits" rule)

Added to `parse_agents` as a `_profile` helper in the style of `_hooks` and `_endpoints`. Each rule below has a test that
goes red when the rule is deleted (checklist item 6 of the untrusted-input pack; a mutation sweep over this helper is
part of the test plan).

1. Types and bounds as in 1.1; integers reject bools; counts capped (8 per list, 8 `must_not_get`, 16 `evidence`).
2. `status: unmeasured` allows only `brief`, `context_ceiling`, `output_cap`, `thinking`, `evidence`, `review_gate`.
   `do`, `dont`, `must_not_get` and `models` on an unmeasured profile are errors: an unmeasured agent has no traits.
3. `status: profiled` requires at least one `do`, `dont` or `must_not_get` entry, each with evidence.
4. Evidence required on every list entry, and on the profile when any scalar setting is present; an entry with an empty,
   whitespace, or malformed pointer is an error naming the entry index.
5. Duplicate entries (same normalised text in `do` and `dont`, or in the same list) are errors; a `do` and a `dont`
   that are equal after case folding contradict each other.
6. `must_not_get.shape` exists in `shapes`; and that shape's `prefer` and `fallback` must not name this agent, or the
   file is self-contradictory. (A warning, not an error, for `fallback`, so a deliberate last-resort stays expressible;
   the warning shows in `safo validate` and in `docs/routing.md` generation output.)
7. Ceilings cross-checked against endpoints (1.2).
8. Text fields (section 7.3): single line, printable, at most 300 characters, no private-path
   patterns, no markup that changes document structure.
9. `persona` exists as a file in the persona directory (confined, same file rules as a template).
10. Agents of `kind: human` take no profile. `kind: ollama` takes the profile on the agent, not per endpoint.

`safo validate` already loads `agents.yaml`; it needs no new flag to report all of the above.

## 2. Rendering per harness

### 2.1 Outputs

One renderer module, `src/safo/profile_render.py`, with pure functions from `AgentsFile` (plus the persona and template
file contents, passed in, so the renderer does no I/O) to a mapping of relative path to text. Driver script
`scripts/gen_profiles.py` with `--write` and `--check`, modeled line for line on `scripts/gen_routing.py`. Output
directory `examples/harness/` (open question 3), laid out per harness:

| Path | Harness | Content |
|---|---|---|
| `claude/<agent-id>.md` | Claude subagent | Frontmatter (`name`, `description`, `model` from the agent's `model`), the persona body when `persona` is set, then the generated "Model profile" section |
| `codex/<agent-id>.prompt.md` | Codex | A prompt preamble to prepend to a self-contained prompt (Codex cannot resume across worktrees, so the preamble is the whole standing context) |
| `copilot/ISSUE_TEMPLATE/copilot-task.yml` | Copilot coding agent | A GitHub issue form (section 4) |
| `copilot/copilot-instructions.md` | Copilot coding agent | Repository-level instructions for the agent, harness layer only |
| `local/<agent-id>.wrapper.txt` | Local models | A prompt wrapper with `{{task}}`, strict output format line, ceilings in prose |

Only agents with a `profile` render. An agent with `status: unmeasured` renders the generic part only (brief,
ceilings, review gate) and the file says so in its first body line, so a reader sees that nothing is claimed.

### 2.2 What the "Model profile" section contains

Fixed template text owned by the renderer, with these slots filled from the profile and nothing else: the brief, the
ceilings as one sentence each, `thinking`, the `do` list, the `dont` list, the `must_not_get` shapes. Each list line is
the entry text; the evidence pointer is rendered as a trailing parenthesised reference so a reader of the instruction
file can find the measurement. Slot order and wording are fixed in code, not configurable, so the rendered shape can
be reviewed once.

Local wrapper specifics, from the measured local-model rules: it states the strict output format the shape needs, tells
the model that code does the grouping and counting (so it must not), and carries `think=false` as a comment line for
the caller. It never contains an endpoint URL, a model name taken from a local override, or a count the model could be
tempted to restate.

### 2.3 The generator and the drift test

`scripts/gen_profiles.py --write` writes every file; `--check` exits 1 if any file is missing, differs, or if an
unexpected file exists in the output directory (a stale file for a removed agent is drift too). `main()` takes argv and
module-level `ROOT`, `AGENTS`, `OUT` constants so the test can monkeypatch them, exactly as `test_routing_doc.py` does.

`tests/test_profile_render.py` mirrors `tests/test_routing_doc.py`: the committed tree equals the render; `--check`
passes now and fails after a hand edit of one file, after deleting one, and after adding a stray one; the rendering
names the expected agents; no em dash; no private-path pattern. The generator loads the base `agents.yaml` only and has
no `--agents-local` flag (7.4).

`make check` and the CI job that runs `gen_routing.py --check` gain a second line for `gen_profiles.py --check`.

### 2.4 Avoiding the maintainer's private paths

Three layers, all mechanical:

1. The generator reads only the repository's `agents.yaml`, never the merged local override and never anything under
   `~/.config/safo/`. Real endpoints and local overrides cannot reach a rendered file because they are not loaded.
2. The loader rejects private-path patterns in every profile text field and in templates: a leading `~/`, `/home/`,
   `/Users/`, a Windows drive prefix, and a `file://` scheme. A profile that needs to say where something lives says it
   relative to the repository root.
3. The rendered directory sits under `examples/`, which `tests/privacy.py` already scans (its `SCANNED` list covers
   `docs`, `examples`, `README.md`, `agents.yaml`), so hostnames, IPs, serials and callsign-shaped tokens fail CI even
   if layers 1 and 2 miss one. The renderer never interpolates the user's home directory or environment.

## 3. Copilot as a harness

### 3.1 Why two layers

From the measured month: the harness behaviour is stable across runs (opens a pull request, works in its own sandbox,
the brief is the issue body, the quota is credits), while the underlying model is chosen per run and changes what
goes wrong. One profile per "Copilot" would mix the two, so the profile has two layers and the outcomes log already
carries the join key (`model` on each record).

### 3.2 Schema

On the `copilot` agent:

- `profile` itself is the harness layer: `brief` (the issue template content, 3.3), `review_gate`, `evidence`, ceilings
  that apply to the issue (for example an output cap on the issue text), and `must_not_get`.
- `profile.models` is a mapping of model id to a model layer. Keys match the outcomes `IDENTIFIER` pattern, which is
  what `safo outcome --model` accepts, so the log and the profile use one vocabulary. Each model layer takes only
  `status`, `thinking`, `do`, `dont`, `must_not_get`, `evidence`, under the same rules as 1.5. A model not listed has
  no profile and, with item 4, is unmeasured for that model.
- Rendering stacks the layers: harness section first, then one subsection per listed model. Nothing in a model layer can
  override the harness `review_gate`; a model layer that tries is an unknown key.
- `models` is allowed only when `kind` is `copilot` (a constant `LAYERED_KINDS` in code, so a later agent can opt in
  by a one-line change and a test).

### 3.3 The issue template

A GitHub issue form (`.yml`), built with `yaml.safe_dump` from a fixed structure, never by string concatenation. Fields,
all required by the form:

1. Acceptance criteria, in prose, as observable behaviour (a textarea; the form's description says "behaviour, not
   implementation").
2. Files in scope (a textarea listing paths; the description says "the agent edits only these").
3. Test command (an input; one command, exactly as run in CI).
4. A checkbox the author must tick: "No new dependencies, workflow permissions or secrets are added."
5. A fixed, non-editable markdown block at the top stating the review requirement in 3.4 so the author of the issue
   sees the cost of the shortcut before filing.

The form labels and descriptions come from renderer constants. The profile can add `brief.inline` text, which is
rendered into one extra markdown block of the form, subject to section 7 limits. The form does not ask for secrets,
and the generated `copilot-instructions.md` repeats the three scope rules (files in scope, test command, no new
dependency) for the agent itself.

### 3.4 The review requirement as a routing and reviewer constraint

`review_gate` is a mapping with exactly these keys:

- `required`: must be `true` for a harness profile (a Copilot profile cannot opt out of review).
- `reviewer_differs`: must be `true`: the reviewer is a different agent from the author (already a house rule; here it
  is data).
- `checks`: a list from a closed set of codes. The first, `test_vs_behaviour`, means: the reviewer reads the stated
  acceptance criteria first, then judges whether the test would fail if the stated behaviour were broken, ideally by
  breaking it. The second, `workflow_permissions`, means: read workflow files the change touches for missing or
  excess permissions. Each code's wording is a renderer constant; each use needs evidence (the two lessons entries
  "Every Copilot pull request needed fixes" and "Copilot's quota is credits, and a reviewer still caught a startup
  failure").

Loader cross-checks (rule 6 family): every shape whose `prefer` or `fallback` names an agent with a `review_gate` must
list a non-empty `reviewer`, and no reviewer may be that agent. The shipped `small-mechanical-pr` shape satisfies it
(reviewer `claude-sonnet`). Changing that shape's reviewer to empty or to `copilot` fails `safo validate`.

### 3.5 How `safo route` surfaces it

`routing.ReviewGate` gains an optional `checks` tuple, and `route.lines` appends the codes' wording to the existing
`required review:` line, for example "required review: Claude Sonnet: ready (check the test against the stated
behaviour, not only that it passes)". When the recommended agent has a harness profile, one extra line
`brief: examples/harness/copilot/ISSUE_TEMPLATE/copilot-task.yml` (the repository-relative path of the rendered file)
is printed. `--json` output gains `profile_status` and `brief_file` keys for the recommended agent; both are additive.
Selection logic is unchanged by this spec; the only routing effect is the validated review constraint.

## 4. The remaining harnesses in brief

- **Claude subagents by model.** `claude-haiku`, `claude-sonnet`, `claude-opus` and `claude-lead` each render a subagent
  file. The persona (job) and the profile (model) stay separate inputs: a persona file is hand-written role text, the
  profile section is generated. The generated file's frontmatter `tools` and `disallowedTools` come only from the
  persona's own frontmatter, never from the profile, so a profile edit cannot widen tool access.
- **Codex.** The preamble states: self-contained prompt, read state from files, the lead commits and runs the full
  suite, space jobs against the five-hour window. Each of those is a `do` or `dont` entry with a lessons pointer, so
  none is invented text in the renderer.
- **Local models.** See 2.2.

The first shipped content is limited to what the repository already measures. Candidates with their evidence:
`claude-haiku` (transcribes a plan's bugs; Haiku-transcribed security code still gets two reviews), `copilot` (harness
layer above), `codex` (sandbox cannot commit or open sockets, cannot resume across worktrees, adversarial review found
what Sonnet reviews missed), `ollama` (think off for cheap tasks, send exactly the loaded `num_ctx`, output is a draft,
code does the grouping and counting). `claude-sonnet` gets a profile only if a measured `do` or `dont` exists;
`claude-opus` and `claude-lead` ship `unmeasured` with brief and ceilings only. That is the rule applied to the
maintainer's own file first.

## 5. Tooling surface

- `safo profiles verify [--agents FILE] [--lessons FILE] [--log FILE]`: loads, resolves every `lessons:` pointer
  against the lessons file, and with `--log` recomputes every `outcomes:` claim. Exit 1 lists unresolved or
  unsupported pointers by path. Local, read-only, no network.
- `safo validate` keeps its meaning and now also reports profile errors, because it loads the same parser.
- `scripts/gen_profiles.py --write|--check` (2.3). The CLI does not render; rendering is a repository build step like
  `gen_routing.py`, plus an adopter may run the script against their own tree.

## 6. Seams for items 4 and 5

### 6.1 Item 4: promotion

- **N lives in `agents.yaml`**, top-level `promotion: {min_outcomes: 10}`, bounds 3 to 1000, default 10. A repo-level
  key, not per agent, because the issue proposes one number; a per-agent override is a later additive key. This spec
  adds only the key and its validation; nothing reads it yet.
- **The counter is a pure function** `measured_runs(outcomes, agent_id, model=None) -> int` in `outcomes.py`, counting
  validated records with that `agent` (and `model` when given). It is the only thing item 4 needs from this work, and it
  is trivial because item 3 landed `model`. This spec specifies the signature; item 4 uses it.
- **Status is declared today, computed later.** In this spec `profile.status` is written by the maintainer.
  `safo profiles verify --log` already warns when a `profiled` agent has fewer than `min_outcomes` records ("profile
  overclaims: 4 of 10 runs"). Item 4 turns that warning into the rule and into `route` behaviour.
- **How `route` will treat unmeasured agents (item 4, stated here so the data fits):** an agent whose effective
  status is unmeasured (a profile saying so, or fewer than N logged outcomes) is skipped for every shape except
  `adversarial-review`, where it may be used as an additional reviewer but never as the sole one and never as the
  author; the skip appears in `Recommendation.skipped` with the count ("copilot: 4 of 10 outcomes"). Until item 4 ships,
  an agent with no `profile` key behaves exactly as today (a legacy agent, no routing change), so adding this feature
  cannot reroute the existing file. `Recommendation` gains a `profile_status` string now (`"legacy"`, `"unmeasured"`,
  `"profiled"`), informational only.
- The ChatGPT-side models in the issue are the intended first `unmeasured` entries; nothing here names one, because the
  repository has no measurement of them.

### 6.2 Item 5: metrics

- Profile data enters `safo metrics` only as labels and one gauge: `safo_agent_profile_status{agent,status}` (0 or 1 per
  status) and `safo_agent_profile_outcomes{agent,model}` against `promotion.min_outcomes`. Metrics never read profile
  text (`do`, `dont`, briefs), so a prompt-injection string in a profile cannot reach a dashboard or a label value.
- Labels come from validated identifiers only (agent id and the outcomes `IDENTIFIER` pattern for model), the same
  charset already enforced on the log. The model layer keys of 3.2 use that pattern so the join agent+model is lossless.
- The rendered-file digest (7.3) is not a metric; it is a repository artefact.

## 7. Threat model

Profile text is rendered into files that agents obey. That makes `agents.yaml` an instruction-injection and supply-chain
surface, not just configuration.

### 7.1 Assets, actors, boundaries

- **Assets:** the agent's behaviour (what it will and will not do), the repository's trust in a review, the
  maintainer's credentials reachable by an agent that obeys a hostile instruction.
- **Actors:** the maintainer (trusted author); a contributor whose pull request edits `agents.yaml`, a template or a
  persona; a compromised dependency or tool that writes the file; a model's own output pasted into a profile
  (self-injection through "lessons" drafted by a local model).
- **Boundaries:** repository file to rendered file to agent context. The second crossing is where a hostile string
  becomes an instruction.

### 7.2 Trust

- The authoritative file is the one the user owns. For the home copy, loading is already confined by `localfiles` (never
  the current directory; refused inside `$GITHUB_WORKSPACE` under Actions) and read through `bounded_read` (regular
  file, no symlink, size cap). The render command, when pointed at any path, additionally requires the file to be owned
  by the effective user and not group or world writable, the same private-directory standard `guardlog.trusted_dir`
  applies to SAFO's state directory.
- The repository copy that CI renders is untrusted until reviewed, because a pull request can change it. The drift test
  turns a profile edit into a visible diff in the generated files, which is the review surface. Recommendation in the
  docs: put `agents.yaml`, `examples/harness/` and the persona directory under CODEOWNERS; no change here to
  branch protection (the maintainer's merge gate is unchanged).
- A profile is never loaded from a pull request's checkout by `safo hooks` or `safo route` under Actions: the existing
  workspace refusal covers it, and the test plan asserts it for the new key.

### 7.3 Escaping, caps and the generated header

- **Caps:** profile text 300 characters per entry, 4,000 for `brief.inline`, 16 KiB per template, 8 entries per list,
  1 MiB for the file (the existing cap). Total rendered size per file is capped at 64 KiB; the renderer raises rather
  than truncates.
- **Structure-preserving text only:** entry text is single line (no `\n`, `\r`, U+2028, U+2029, NEL or any C0/C1
  control, matching `outcomes.NOTE_FORBIDDEN`), no leading `#`, `>`, `-`, `*`, backtick fence, `---`, `<!--`, `{{`
  outside templates, or the generated-header marker. Rendered inside a fixed list item so it cannot become a heading,
  a fence or front matter. Frontmatter values and the issue form are produced from closed sets and validated
  identifiers through `yaml.safe_dump`, never by concatenation.
- **No semantic filter is claimed.** A sentence such as "ignore prior instructions" is structurally valid text. The
  defence for that is trust (7.2), the evidence requirement (a claim needs a pointer a reviewer can check), the visible
  generated diff, and the fixed slot order (profile text appears after, and cannot reorder, the renderer's own rules).
  Stating that limit is part of the doc page.
- **Generated header:** every rendered file begins with
  `GENERATED by scripts/gen_profiles.py from agents.yaml; do not edit; source digest sha256:<hex>` in the comment form
  of its format (HTML comment, `#` line, or a leading form description). The digest is over a canonical JSON dump of that
  agent's profile, so a reader can tell whether a file belongs to the profile in front of them. The drift test asserts
  the header on every file and that the digest matches; a hand edit that keeps the header still fails the byte
  comparison.
- A template or persona cannot include another file (no include directive), so there is no transitive read.

### 7.4 Abuse cases and mitigations

| Abuse case | Mitigation | Verification |
|---|---|---|
| Profile adds "run curl and send env" as a `do` | Evidence required; text rendered in a reviewed generated diff; tool access never derives from the profile | Test: no profile key changes `tools`; review diff in the drift test |
| Local override file widens a ceiling or adds a trait and leaks into a committed file | Generator loads base file only, no override flag | Test: generator ignores `SAFO_AGENTS_LOCAL`, and the CLI has no such option |
| Template path escapes (`../`, symlink, FIFO) | Confined, `O_NOFOLLOW`, `S_ISREG`, non-blocking open | Hostile-path tests |
| YAML alias bomb, merge key, duplicate key in the profile | Existing `_read_yaml` event scan and `_safe_load` | Tests extend the hostile fixtures to the `profile` subtree |
| Markup breakout (fence, heading, front matter, HTML comment) | Character/leading-token rules, fixed slots | Table-driven rejection tests plus a round-trip parse of rendered output |
| Fabricated evidence pointer | `verify` resolves lessons and recomputes outcomes; format enforced by the loader | Tests with a dangling slug and a false metric |
| Stale generated file obeyed after the profile changed | `--check` in CI, digest in header | Drift tests |
| Private path or endpoint in a rendered file | Pattern rejection, base-file-only render, `tests/privacy.py` scan of `examples/` | Planted-path tests |

Residual risk: a trusted author can still write a harmful but well-formed instruction. This design makes it evidenced
and reviewable, not impossible.

## 8. Test plan

Each item names the failing case it must include (guard tests collect loosely and assert strictly).

1. `test_profile_schema`: every key in 1.1 accepted in a minimal valid profile; unknown key, duplicate key (including
   inside `do`), wrong types, bool for integer, over-bound ceilings, oversize lists each fail with the dotted path.
2. `test_profile_unmeasured`: `do`, `dont`, `must_not_get`, `models` on an `unmeasured` profile fail; `profiled` with
   none of them fails.
3. `test_profile_evidence`: missing, empty, whitespace, malformed pointers fail; each of the three forms accepted;
   scalar settings without profile-level evidence fail; a profile with a trait and no evidence fails (the headline rule).
4. `test_profile_crosschecks`: `must_not_get` shape unknown; shape prefers the agent (error) or falls back to it
   (warning); ceiling above endpoint `num_ctx_max`; `thinking` disagreeing with the endpoint `think`; review-gate agent
   in a shape with no reviewer or itself as reviewer; `models` on a non-copilot agent; profile on `kind: human`.
5. `test_profile_text_rules`: table of structure-breaking strings (newline, U+2028, `---`, fence, `#`, `<!--`, `{{`,
   header marker, `/home/`, `~/`) each rejected; ordinary punctuation accepted.
6. `test_profile_template_files`: traversal, absolute path, symlink, FIFO (with a timeout so a regression fails fast,
   not hangs), directory, oversize, non-UTF-8, unknown placeholder each give `ConfigError`, never a raw `OSError`.
7. `test_profile_hostile_yaml`: aliases, anchors, merge keys, depth, and size inside the `profile` subtree reuse the
   hostile-input fixtures of `test_agentsfile.py`.
8. `test_profile_render`: golden render for a small fixture agents file covering all four harness outputs; header and
   digest on every file; issue form parses with `yaml.safe_load` and has the required fields; generated Claude
   frontmatter parses and its `tools` equal the persona's.
9. `test_profile_drift` (mirrors `test_routing_doc.py`): committed tree equals render; `--check` passes, then fails on a
   hand edit, a deleted file, a stray file, and a stale digest; `--write` then `--check` passes.
10. `test_profile_privacy`: the render of a planted-path fixture is rejected at load; the generator ignores the local
    override; the repository's `examples/harness/` passes `tests/privacy.py`.
11. `test_profile_route`: `route` prints the `checks` wording on the required-review line for a Copilot recommendation,
    prints the brief path, `--json` has the additive keys; selection results for every shipped shape are identical before
    and after (a snapshot test: the feature changes no recommendation).
12. `test_profile_verify`: a dangling lessons slug, a false outcomes claim, and an overclaiming `profiled` status
    (fewer than `min_outcomes`) are each reported with a nonzero exit; the shipped file passes against
    `docs/lessons.md` and `examples/outcomes-2026-10.jsonl`.
13. `test_promotion_key`: `promotion.min_outcomes` bounds; `measured_runs` counts by agent and by agent+model and ignores
    other agents (this is the seam test for item 4).
14. Mutation sweep over `_profile`: delete each validation in turn in a scratch copy and run the suite; any green run is
    a survivor and blocks the PR (recorded in the PR description).
15. Docs: a new `docs/profiles.md` is covered by the existing docs tests (links, no em dash, privacy scan); `docs/personas.md`
    and `docs/routing.md` cross-link it.
16. Under `GITHUB_ACTIONS=true` with a workspace, loading a profile-bearing agents file from inside the workspace is
    refused (existing behaviour, asserted for the new key).

## 9. Non-goals

- No hosted service, webhook, or network code. Rendering and verification are local and offline.
- No automatic dispatch: SAFO still does not run agents; the rendered files are inputs the lead and the harnesses use.
- No inventing traits: no profile for a model without a lessons entry or an outcomes measurement behind each line, and
  no default `do`/`dont` text in the renderer beyond the closed `review_gate` check wording, which has its own evidence.
- No promotion logic and no change to selection in this work (item 4), no `safo metrics` (item 5).
- No semantic prompt-injection filter; no claim that the rendered text is safe against an author who is trusted.
- No retrofit of old `strengths` and `constraints` into profiles; no editing of `docs/lessons.md` entries.
- No per-endpoint profiles, no profile merging from the local override, no secrets or endpoint URLs in any profile.
- No auto-writing of rendered files into `.github/` of a consumer repo; adopters copy what they want.

## 10. Open questions for the maintainer

1. **Evidence pointers into `docs/lessons.md`: heading slugs or stable ids?** Slugs break if a heading is retitled.
   Recommend slugs now, with `safo profiles verify` and the shipped-file test failing on a dangling one, so a retitle is
   caught the same day; add explicit ids only if retitles turn out to be common.
2. **Does N=10 count per agent or per agent+model for Copilot?** Recommend per agent+model for the model layer (a new
   model starts unmeasured) and per agent for the harness layer, since the harness behaviour is the stable part; both use
   `measured_runs` with and without the `model` argument.
3. **Where do rendered files live?** Recommend `examples/harness/` (adopter-copyable, scanned by the privacy test, not
   published as wiki pages), and not installing them into this repository's own `.github/` until item 4 lands, so Copilot
   here is not briefed from a profile that has no promotion rule yet.
4. **What does an agent with no `profile` key mean before item 4?** Recommend "legacy": routes exactly as today and
   reports `profile_status: legacy`, so shipping this feature reroutes nothing; item 4 then decides whether legacy
   collapses into unmeasured.
5. **Should `safo hooks` refuse a dispatch whose agent's rendered file is stale or missing its header?** Recommend no:
   `--check` in CI already guards the repository, and a dispatch-time refusal adds a failure mode to a hook that must stay
   cheap; revisit if a stale file ever causes a bad brief.
