# Threat model before build

**The rule.** Work on an AI-facing part of a system starts with a threat model, or a stated reason none applies. The issue
carries a line of its own saying which. That is the same shape as [no hidden work](no-hidden-work.md): a record made before the
work, found by `safo audit` when it is missing.

This page is about the step. The model itself is an [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon) file
kept in the repository, and checking that the file is well formed and moves with the code is a reusable workflow in
[git-your-ship-together](https://github.com/ChiefGyk3D/git-your-ship-together) (`threat-model.yml`), not something SAFO builds.

SAFO's own model, for the whole of SAFO, is [SAFO threat model](safo-threat-model.md), kept as the Threat Dragon file
[docs/threat-model/safo.threat-dragon.json](https://github.com/ChiefGyk3D/scrum-around-and-find-out/blob/main/docs/threat-model/safo.threat-dragon.json).

## The line

An issue carrying the configured label has, on a line by itself, one of:

```
threat-model: docs/threat-model/app.threat-dragon.json
threat-model: https://example.com/models/app
threat-model: n/a - prompt wording only, no new input reaches the model
```

- A **path** is repository-relative: no leading slash, no `..` segment, and it has a `/` or a `.`. A bare word such as `tbd`,
  `todo` or `none` is not a path.
- A **URL** must use TLS (a plain `http` link is refused).
- **`n/a`** needs a dash and a reason of at least a short sentence. A bare `n/a` is refused, because it records that nobody
  thought about it.
- The line must start its line. A sentence that mentions `threat-model:` in the middle, or a quoted line, does not count.
  If an issue has several lines, one usable line is enough.

What `audit` does not do: it does not open the file, check that it exists, or judge the reason. A person reads the model and the
reason; SAFO only makes the absence visible. The file check belongs to the workflow below.

## Turning it on

In `board.yaml`:

```yaml
rules:
  threat_model:
    label: ai-surface        # the label that marks AI-facing work; empty turns the check off
    exempt_repos: []         # owner/name: issues there need no line
```

With no label configured, `audit` prints `NOTE    Threat-model check not configured: rules.threat_model.label is empty`
and makes no read for it, so a skipped check never reads as a pass. Open issues with the label are always checked; closed ones
within `rules.add_closed_days`, as for pull requests.

| Command | What it does |
|---|---|
| `safo audit` | `DRIFT   THREAT owner/repo#N is labeled 'ai-surface' and has no `threat-model:` line`, or says why the line is unusable. Exit 1 |
| `safo reconcile` | Lists the same issues as `HUMAN ...`; writes nothing for them, because no rule can decide whether a model exists |

## Who writes the model

The `threat-model` task shape in [Routing](routing.md) sends the draft to a Sonnet agent carrying the `threat-model` pack from the
[personas](personas.md) (assets, actors, trust boundaries, ranked risks, a mitigation and a verification for each, residual risk), with
a Codex adversarial review of the draft. The draft is evidence for the maintainer, never a verdict, and a model that
describes a system it was not shown is the failure to watch for. Opus only with the maintainer's OK and the reason stated.

## Keeping the file honest

The `threat-model.yml` workflow in git-your-ship-together:

- parses the Threat Dragon v2 file and fails on a missing trust boundary, a dangling flow, a duplicate id, a threat with no
  status or severity, or a `Mitigated` threat with no mitigation text;
- fails unless each topic in `required-topics` (for example prompt injection, data leakage, tool abuse) appears in some threat;
- on a pull request, fails when a file under `ai-paths` changes with no change to the model and no `threat-model: n/a - <reason>`
  line in the pull request description.

Together: SAFO makes sure the step happened before the work, and the workflow makes sure the file still exists and moved with
the code. Neither can tell that the model is true of the running system.
