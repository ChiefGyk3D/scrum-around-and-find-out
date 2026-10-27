# No hidden work

**The hard rule.** Every unit of work, human or agent, has an issue (or a Jira key) and a board card *before* work starts,
and every pull request links its issue. Work without a card is a defect of the process, not a style choice. That is the
point of Agile: nothing is hidden, and the maintainer can see all of it on the board.

File the issue first. Put it on the board. Then start. Link it from the pull request with `Refs #n` or `Closes #n`.

## Where the rule is enforced

| Where | What it does | Mode |
|---|---|---|
| `safo hooks guard` | A subagent brief must carry a line of its own, `issue: owner/repo#123` (or `issue: KEY-123`). The reference is checked read-only: it must exist and be open. | `warn` reports, `block` denies |
| `safo audit` | Exits 1 for a pull request that links no issue, a pull request or issue that is not on the board, a card with no Status, Area, Kind, Epic or Effort, a closed issue that is not Done, a Done card with no Done-on date. Each finding names the item. | read-only |
| `safo audit` (branch gate) | Exits 1 with `NO-GATE owner/name` for a listed repository whose default branch has no protection or active ruleset, is protected without the gate check (`CI green`), or allows force pushes. Exits 2 when the protection cannot be read. See [The branch gate](#the-branch-gate). | read-only |
| `safo reconcile` and `safo sync` | Add the missing cards and set Status and Done-on. What no rule can decide is printed as `HUMAN ...` and leaves the exit code at 1: a pull request with no linked issue, a missing Kind, Epic, Effort, or an Area no rule fills. | writes only what is mechanical |
| A pull request check | Fails a pull request with no `Refs #n` or `Closes #n`. Not built here: it is a reusable workflow in git-your-ship-together. | CI |

## The guard

Put this line, by itself, in every brief:

```
issue: ChiefGyk3D/example#123
```

- A GitHub reference is `owner/repo#N`. The guard runs `gh issue view N --repo owner/repo --json state`, a read, from an
  argument list with no shell. The reference must match a strict pattern first, so shell metacharacters never reach a
  process; a rejected reference is not echoed back.
- A Jira-style key, `KEY-123`, is accepted by its shape alone, because no Jira instance exists today. See the mapping below.
- No line, an invalid line, a missing or closed issue: in `block` mode the dispatch is denied with a message that says how
  to file one; in `warn` mode it is reported and allowed.
- A lookup that cannot answer (no `gh`, not logged in, a timeout) fails closed in `block` mode and is reported in `warn`
  mode. The log records the rule name (`no-issue`, `issue-unusable`, `issue-unverified`), never the brief.
- A GitHub reference must name a repository the operator listed in `hooks.tracking_repos` in `agents.yaml`; any other
  repository is `issue-unusable`, the message lists the accepted ones, and nothing is looked up. Nothing is accepted
  because of where the session happens to be running, so an unrelated open issue cannot satisfy the rule.
- The guard has a time budget. It computes a deadline two seconds before the host's 10 second hook timeout, and the
  `git` and `gh` reads get only the time left. Out of time counts as a failed lookup (`issue-unverified`), so `block`
  mode denies, and the decision is still written before the host gives up.
- Nothing is exempt by default. A repository can opt out, deliberately, in `agents.yaml`:

  ```yaml
  hooks:
    tracking_exempt_repos: [owner/scratch-repo]
    tracking_repos: [owner/other-repo]   # extra repositories a brief may cite
  ```

  The exemption applies to the session's repository, which is read once, at SessionStart, from the `origin` remote of
  the session's working directory (a read of the git configuration, no network) and bound in the guard's private state
  directory. The bound value is compared in full, owner and name, without case, and is never re-derived afterwards: a
  later `git remote set-url` or `.git/config` edit changes nothing. A second SessionStart for the same session that
  derives a different value is refused (the old binding stays) and logged as `repo-changed`. Only a SessionStart whose `source` is `startup` (the field the Claude Code hooks reference defines, with `resume`, `clear`, `compact` and `fork`) creates a binding; any other source must find the existing one or the session stays unbound and is logged as `repo-unbound`, so a binding lost to pruning is never rebuilt from a working tree the agent may have rewritten. The guard refreshes the binding's age each time it reads it, so a session that is still running is never pruned. A repository that could
  not be determined is bound as unknown and is never exempt, and so is a session that was never bound. A brief cannot
  grant the opt-out to itself. Use it for a throwaway repository, not to get past the rule.

  **The opt-out is advisory against a hostile agent with shell access.** Such an agent can edit the bound state file or
  the configuration itself, as the same user. The guard is a speed bump and an audit trail, like the approval token. What
  would close it is a second hook on the Bash and Edit tools that denies writes to the guard's state and config
  directories, `git remote` changes and `.git/config` edits; that hook does not exist yet.

How the issue lookup is injected in a test: `LocalContext.issue_lookup` takes a function `Ref -> "open" | "closed" |
"missing" | "error"`; by default it is the `gh_resolver` function of the tracking module.

## The threat-model line

The same shape of rule, for AI-facing work: an issue with the configured label carries a `threat-model:` line, and `audit`
names the ones that do not. See [Threat model before build](threat-model.md).

## The branch gate

The standing rule is that every repository's default branch requires `CI green` before its first merge. `safo audit`
reads, for each repository listed in `board.yaml`, the default branch's classic protection rule and the repository's
rulesets (a repository may be protected by either), and reports one finding per repository:

```text
DRIFT   NO-GATE acme/widgets: default branch 'main' has no branch protection and no active ruleset
DRIFT   NO-GATE acme/manuals: default branch 'main' is protected but does not require the check 'CI green' and allows force pushes
DRIFT   NO-GATE acme/tools: default branch 'main' requires the check 'CI green' and blocks force pushes, but both can be bypassed (ruleset 'protect' has 1 bypass actor (ALWAYS))
```

A ruleset counts when it is active (not disabled, not evaluate-only), targets branches, and its include patterns match the
default branch without an exclude pattern removing it. A required check matches by its own name or after a workflow
prefix: `CI green` matches `ci / CI green` and `shell / CI green`, which are the names `scripts/apply-baseline.sh`
requires. The check must also come from the CI app (`rules.gate_check_app_id`, default 15368, GitHub Actions): a required
check with no source restriction ("any app") can be satisfied by any app that posts a status with that name, and one tied
to another app is not your CI, so both are reported (`... does not require the check 'CI green' from app 15368 (classic
protection accepts it from any app)`). A name from another app or from a plain commit status that merely looks like the gate
is never credited. **What the pin does not prove:** it identifies the app that posts the check, not the workflow. Every
workflow and job in the repository runs as the same Actions app, so any of them can post `CI green`, or a lookalike such
as `evil / CI green`, and satisfy a check pinned to it. A pinned check therefore passes, with a `NOTE` saying so every time (below): nothing suppresses it.
"Unreviewed code cannot reach the default branch" holds only together with ownership of the workflow files (a CODEOWNERS
rule over the workflow directory, which `safo protection` verifies in PR #168) and the required-reviews rule; this audit
does not prove either. Note that `scripts/apply-baseline.sh` omits `app_id`, which makes GitHub
pick the app that most recently reported the check, so a repository set up that way is only as pinned as that choice; pin it
explicitly. Force pushes are blocked by a classic rule that disallows them or a ruleset with the non-fast-forward rule.
A rule that someone can get around does not hold the gate: a ruleset with any bypass actor, a force-push bypass allowance,
and (only when asked for, see below) a classic rule that does not apply to administrators. One rule nobody can bypass is
enough.

```yaml
rules:
  gate_check: CI green                # the check name; empty turns the rule off
  gate_forbid_force_push: true        # also report a default branch that allows force pushes
  gate_exempt_repos: []               # owner/name list, each listed in repositories, not evaluated for the gate
  gate_require_admin_enforced: false  # true also reports a rule that does not apply to administrators
  gate_admin_exempt_repos: []         # with the line above on: owner/name list where that is accepted
  gate_check_app_id: 15368            # the app the gate check must be pinned to (15368: GitHub Actions)
```

The rule applies only to repositories listed in `board.yaml`. It is on by default with `CI green`, because it is the
standing rule and a repository without it is what the audit exists to find; force pushes are on because a gate that
history can be rewritten around is not a gate.

**Exit codes and notes.** Exit 1 for a finding. Exit 2, `UNKNOWN NO-GATE ...`, when the protection cannot be read or the
answer cannot be trusted (a refused read, a token that cannot see the rules, a malformed or inconsistent answer, a ref
pattern GitHub does not document); cannot tell is never a pass. What was not evaluated is said in a `NOTE`, always in the
form `NO-GATE <who>: <text>`, and notes never change the exit code:

```text
NOTE    NO-GATE acme/widgets: exempt by rules.gate_exempt_repos (not evaluated)
NOTE    NO-GATE acme/widgets: gated for everyone except administrators (rules.gate_require_admin_enforced is off)
NOTE    NO-GATE acme/widgets: the repository is archived (read-only, nothing can merge); the gate was not checked, and this is not durable evidence
NOTE    NO-GATE (all repositories): the gate check is not configured, rules.gate_check is empty
NOTE    NO-GATE acme/widgets: required check is pinned to the Actions app, which every workflow in the repository can use; see docs/no-hidden-work.md
```

An archived repository and an empty one (no default branch yet) are not judged, and their clean verdict is not durable
evidence: an archive can be unarchived and an empty repository gets its first branch unprotected. An empty `gate_check`
turns the rule off and the summary line ends with `(branch gate NOT checked: rules.gate_check is empty)`, so exit 0 then
does not mean the gate was checked.

**Administrators.** "Gated" means: the check cannot be bypassed by anyone except an administrator, unless
`gate_require_admin_enforced` is on. A classic rule that does not apply to administrators (`enforce_admins` off) is not a
finding by default: the shipped baseline (`scripts/apply-baseline.sh`) sets `enforce_admins` to false and requires no
approvals, so a default that reported it would flag every repository that follows the baseline. A repository that passes
only because administrators are accepted is clean and gets the `gated for everyone except administrators` note, so the
exception is visible. Set `gate_require_admin_enforced: true` to report it (`administrators are not included
(enforce_admins is off)`); `gate_admin_exempt_repos` then accepts it per repository, still with a note. Everything else
that makes a rule bypassable stays a finding by default.

**What the token needs.** GitHub shows protection and rulesets in full only to a token that can administer the
repository: for a GitHub App the **Administration: read** repository permission, for a user token the `repo` scope. The
Projects and Issues permissions the rest of the audit uses are not enough, and the token may lack Administration: read.
Without it the audit exits 2 rather than read an empty answer as "unprotected". Details are under the implementation notes.

### Implementation notes

These describe how the read stays honest. None of it changes what the section above promises.

**Ref patterns** are matched the way GitHub does, not as Python's `fnmatch`: GitHub uses Ruby's `fnmatch` with
`FNM_PATHNAME`, so `*` never matches `/` (`release/*` does not cover `release/1/2`), `**/` spans directories
(`release/**/*` does), `[set]` works and `[^set]` does not
([branch protection rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule),
[rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository),
read 2026-10-26). A pattern whose meaning GitHub does not document is **cannot tell** (exit 2) when it decides the answer:
`**` that is not a whole directory (`release**`, a trailing `**`), any bracket expression that is not a plain set of letters, digits and a few plain characters or an ascending range of letters or digits (`[a-c]` and `[ab]` are read; `[]a]`, `[]`, `[a-]`, `[-a]`, `[z-a]`, `[^a]`, `[!a]`, `[[:alpha:]]` and `[a\]]` are cannot tell, because Ruby and Python's regex engine read several of them differently), a backslash, an unterminated `[`, a
`~` variable other than `~ALL` and `~DEFAULT_BRANCH`, and a wildcard against a branch segment that starts with a dot
(UNVERIFIED: Ruby does not match it by default; GitHub does not say).

**Bypass details.** A ruleset bypass actor counts in any mode (`ALWAYS`, `PULL_REQUEST` and `EXEMPT` all let the actor merge past a red check; `PULL_REQUEST` only avoids a direct push). Pull-request bypass allowances on a classic rule skip the review requirement, not required checks, and are not reported. A bypass list cut short by the page size is **cannot tell**, and an answer without the bypass fields is **cannot tell**, never a pass.

**Strict reading.** The audit trusts GitHub's answer only when it is complete and consistent. A connection, list or
object field that is null, absent, the wrong type or an element of the wrong type is **cannot tell** (exit 2), never an
empty list: `bypassActors: {totalCount: 0, nodes: null}` is not "nobody can bypass". Only a real list, including `[]`,
is a list. For every connection (`rulesets`, a ruleset's `rules`, its `bypassActors`) the `totalCount` must equal the
number of nodes: more in the total than listed means the read was cut short, fewer means the answer contradicts itself,
and both are cannot tell. The default branch name must be text that passes git's ref-name rules (no control character,
space or `~^:?*[\`, no `..`, `@{`, `//`, leading or trailing `/`, trailing `.` or `.lock`); it is never turned into text
with `str()`, so a null name cannot be credited with a `~DEFAULT_BRANCH` ruleset. A `data` value that is not an object,
or a repository that is missing or not an object, is cannot tell for that repository alone: the other repositories are
still judged, and any unexpected error while judging one repository is reported as `UNKNOWN NO-GATE <repo>: ... (unexpected
answer)` with fixed text, never the error text.

**Every field is typed, relevant or not.** The audit checks the type of every field the query asks for in every record it
reads before it judges any of them: relevance decides only whether a value counts. A disabled or evaluate-only ruleset,
a tag ruleset, a rule that is not a status-check rule (its `parameters` must be null or an object), a classic rule with
status checks turned off (its `requiredStatusChecks` must still be a list of objects with text contexts), an archived
repository and an empty one are all validated, and a wrongly typed field in any of them is cannot tell. The booleans
(`requiresStatusChecks`, `allowsForcePushes`, `isAdminEnforced`, `isArchived`) must be real booleans: the string `"false"`
or the number `1` is not true or false. `viewerPermission` must be one of ADMIN, MAINTAIN, WRITE, TRIAGE_PLUS, TRIAGE, READ (GitHub's `RepositoryPermission`, read by introspection on 2026-10-26; there is no NONE) and a ruleset's `target` one of BRANCH, TAG, PUSH, REPOSITORY (`RepositoryRulesetTarget`, same date): any other value, including a different case, is cannot tell, and only a BRANCH ruleset can ever be credited with the gate;
a ruleset's `name` must be text; `nameWithOwner` must be exactly one ASCII `owner/repo` in the same grammar as the board's repository list and must name the repository that was asked for, compared with ASCII-only case folding (A-Z). Unicode lowercasing is not used: the Kelvin sign would otherwise fold to an ASCII `k` and credit another repository's answer. One deliberate exception: push and repository rulesets have no ref condition, so a null `conditions`
or `refName` is normal for those targets; if present there it must still be well-formed.

**GitHub-supplied text is escaped.** Error messages from GitHub, ruleset names, bypass modes and branch names pass
through the same escaping as the CLI's other output (control and format characters written as `\xNN` or `\uNNNN`, `::`
broken), so a finding is always one physical line and cannot forge a `DRIFT` line or a workflow command.

**Token permissions in detail.** GitHub shows protection and rulesets in full only to a token that can administer the repository:
for a GitHub App the **Administration: read** repository permission, for a user token the `repo` scope. The Projects and
Issues permissions the rest of the audit uses are not enough, and the token may well lack Administration: read. Without it
GitHub answers "none" instead of "forbidden", so the audit never reads an empty answer as "unprotected" unless the token
reports ADMIN on the repository; otherwise, and on any refused or failed read, it prints `UNKNOWN NO-GATE ...` naming the
permission and exits 2. A rule that is found is trusted whatever the permission. The allowance data (force-push and pull-request bypass allowances, the admin flag, ruleset bypass actors) is the exception, and rests on an assumption: GitHub may withhold it from a token that cannot administer the repository without raising an error, so the audit reads an absent or null allowance count as cannot tell (exit 2), never as zero. An integer `0` allowance count, or an empty `bypassActors` list, means "nobody can bypass" only when `viewerPermission` is ADMIN: from any lower permission it is cannot tell whenever the verdict depends on it (a ruleset that holds the gate check or the force-push block, or a classic rule that blocks force pushes while `gate_forbid_force_push` is on). A bypass that is listed is a finding whatever the permission, and a rule that does not decide the verdict is not asked. The classic pull-request allowances never touch a required check, so they are not asked. Cannot tell is never a pass.

**Required workflows are not interpreted.** GitHub rulesets have a rule that requires a workflow to pass (rule type
`WORKFLOWS`; the GraphQL schema exposes it, introspection 2026-10-26). SAFO does not read it and it never changes a
verdict or removes the app-pin NOTE: a workflow reference names a file at a path, ref and repository, and nothing in the
GraphQL answer ties that file to a status name or proves its provenance (the workflow may be unrelated to the check, come
from another repository, sit on a mutable branch or tag, or be skipped on creation). Whether and how the audit could ever
accept a required workflow as the strongest evidence is an open design question, tracked as a follow-up, not a feature.

**Inherited rulesets.** `includeParents: true` also returns rulesets owned by the organization or enterprise. The query
reads `source { __typename }` (the `source` field of `RepositoryRuleset` is a non-null `RuleSource` union of `Repository`,
`Organization` and `Enterprise`, introspection 2026-10-26; the schema offers no field saying whether the viewer can see an
inherited ruleset's bypass list). An empty bypass list on a ruleset that is not owned by the repository is therefore never
believed, even from an ADMIN token: cannot tell (exit 2), because that list is administered at organization or enterprise
scope. A listed actor is still a finding, and a source that is absent, null or not one of those three is cannot tell.
A repository whose gate is held only by an inherited ruleset with an empty list stays at exit 2 until the rule is also set
on the repository or the organization ruleset lists its bypass actors.

**Where a required check comes from.** The query reads `requiredStatusChecks { context app { databaseId } }` for a classic rule and `requiredStatusChecks { context integrationId }` for a ruleset (field names read by GraphQL introspection on 2026-10-26: the `app` field of `RequiredStatusCheckDescription` is a nullable `App` whose `databaseId` is a nullable `Int`; the `integrationId` field of `StatusCheckConfiguration` is a nullable `Int`). A null `app` or `integrationId`, and the REST convention `-1`, mean "any source". An entry counts toward the gate only if its name matches (the name alone or after a workflow prefix) and it is pinned to `rules.gate_check_app_id`; with several entries of the same name, one pinned to the CI app is enough. If the check is required but only without a source or from another app, the finding says so. App ids are GraphQL `Int`, so an id above 2147483647 is cannot tell, and `gate_check_app_id` is capped there. The field must be present and typed: an absent `app` or `integrationId`, a non-integer or a non-positive id (other than `-1`) is cannot tell, never "any app" and never the default app. This is the same idea as the protection read-back's `--require-app-id`, which prints a NOTE when a check is unpinned; here an unpinned gate check is a finding because the audit's question is whether the gate holds.

The read uses the same GraphQL client as the rest of the audit (a second REST transport would duplicate its redirect,
retry and loopback hardening). It never writes protection: setting it is `scripts/apply-baseline.sh`, run by a repository
administrator.

## The audit and `board.yaml`

The checks read their field names from `board.yaml`:

```yaml
rules:
  status_field: Status      # as before
  area_field: Area          # as before
  done_date_field: Done on  # as before
  tracking:
    kind_field: Kind        # default Kind; empty turns the check off
    epic_field: Epic        # default Epic
    effort_field: Effort    # default Effort
    exempt_repos: []        # owner/name: pull requests there need no linked issue
```

A Kind, Epic or Effort field may be any type; only whether it holds a value is read. A field `board.yaml` does not define
is **not configured**: the audit skips that check, prints a `NOTE ... check not configured` line, and does not call the
board clean on the strength of a check it did not run. Open pull requests are always checked for a link; merged ones
within `rules.add_closed_days` days of today. A body links an issue when GitHub counts a closing reference or the text has
`Refs`, `Closes`, `Fixes` or `Resolves` followed by an issue number other than the pull request's own.

Exit codes are unchanged: 0 clean, 1 drift, 2 cannot tell.

## Jira

Jira is not in use today and there is no Jira instance. The model is tracker-neutral so one can slot in later:

| GitHub | Jira |
|---|---|
| Issue | Issue, identified by its key (`KEY-123`) |
| Project (board) | Board of a Jira project |
| Status | Status (workflow state) |
| Kind | Issue type |
| Epic | Epic link |
| Effort | Story points or original estimate |
| Area | Component |
| Done on | Resolution date |
| `Refs #n` / `Closes #n` | The key in the commit or pull request title |

The tracking module (`src/safo/tracking.py`) is the seam. A tracker is a pattern for its references and a resolver that answers `open`, `closed`,
`missing` or `error`. The guard already accepts a Jira key by shape; a Jira resolver would replace the shape check with a
lookup. Nothing here calls Jira.
