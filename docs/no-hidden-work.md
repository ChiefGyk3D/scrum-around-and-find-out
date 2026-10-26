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
```

A ruleset counts when it is active (not disabled, not evaluate-only), targets branches, and its include patterns match the
default branch without an exclude pattern removing it (`~DEFAULT_BRANCH`, `~ALL` and `refs/heads/...` globs). A required
check matches by its own name or after a workflow prefix: `CI green` matches `ci / CI green` and `shell / CI green`, which
are the names `scripts/apply-baseline.sh` requires. Force pushes are blocked by a classic rule that disallows them or a
ruleset with the non-fast-forward rule.

```yaml
rules:
  gate_check: CI green            # the check name; empty turns the rule off and the audit says "not configured"
  gate_forbid_force_push: true    # also report a default branch that allows force pushes
  gate_exempt_repos: []           # owner/name list that is not audited for the gate
  gate_require_admin_enforced: false  # true also reports a rule that does not apply to administrators
  gate_admin_exempt_repos: []     # with the line above on: owner/name list where that is accepted
```

**Ref patterns** are matched the way GitHub does, not as Python's `fnmatch`: GitHub uses Ruby's `fnmatch` with
`FNM_PATHNAME`, so `*` never matches `/` (`release/*` does not cover `release/1/2`), `**/` spans directories
(`release/**/*` does), `[set]` works and `[^set]` does not
([branch protection rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule),
[rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository),
read 2026-10-26). A pattern whose meaning GitHub does not document is **cannot tell** (exit 2) when it decides the answer:
`**` that is not a whole directory (`release**`, a trailing `**`), `[^...]` or `[!...]`, a backslash, an unterminated `[`, a
`~` variable other than `~ALL` and `~DEFAULT_BRANCH`, and a wildcard against a branch segment that starts with a dot
(UNVERIFIED: Ruby does not match it by default; GitHub does not say).

**Bypass.** A rule that someone can get around does not hold the gate. The audit reports `can be bypassed` when the only
rules carrying the check (or the force-push block) are bypassable: a classic rule that does not apply to administrators
(`enforce_admins` off), a force-push bypass allowance, or a ruleset with any bypass actor, in any mode (`ALWAYS`,
`PULL_REQUEST` and `EXEMPT` all let the actor merge past a red check; `PULL_REQUEST` only avoids a direct push). One rule
nobody can bypass is enough; a second, bypassable one adds no finding. Pull-request bypass allowances on a classic rule
skip the review requirement, not required checks, and are not reported. A bypass list cut short by the page size is
**cannot tell**, and an answer without the bypass fields is **cannot tell**, never a pass.

`enforce_admins` off (a classic rule that does not apply to administrators) is **not** a finding by default
(`gate_require_admin_enforced: false`). The maintainer's GYST repository baseline sets `enforce_admins` to false on
purpose, with no required approvals, so the owner can merge his own green pull requests; a default that reported it would
flag every tracked repository, this one included. Set `gate_require_admin_enforced: true` to report it for a board that
wants administrators held to the gate too; the finding then says `administrators are not included (enforce_admins is
off)`, and `gate_admin_exempt_repos` accepts it per repository. Everything else that makes a rule bypassable (a ruleset
bypass actor, a force-push bypass allowance) stays a finding by default. Whether the field is readable is still checked
either way: an answer without `isAdminEnforced` is cannot tell, never a pass.

Defaults and why: the rule is **on** with `CI green`, because it is the standing rule and a repository without it is
exactly what the audit exists to find; force pushes are **on** because a gate that history can be rewritten around is not a
gate. It applies only to repositories listed in `board.yaml`, never to the rest of an owner's repositories. An archived
repository is skipped with a `NOTE` (nothing can merge into it); a repository with no default branch yet (empty) is
skipped with a `NOTE`.

**What the token needs.** GitHub shows protection and rulesets in full only to a token that can administer the repository:
for a GitHub App the **Administration: read** repository permission, for a user token the `repo` scope. The Projects and
Issues permissions the rest of the audit uses are not enough, and the token may well lack Administration: read. Without it
GitHub answers "none" instead of "forbidden", so the audit never reads an empty answer as "unprotected" unless the token
reports ADMIN on the repository; otherwise, and on any refused or failed read, it prints `UNKNOWN NO-GATE ...` naming the
permission and exits 2. A rule that is found is trusted whatever the permission. Cannot tell is never a pass.

The read uses the same GraphQL client as the rest of the audit (a second REST transport would duplicate its redirect,
retry and loopback hardening). It never writes protection: setting it is `scripts/apply-baseline.sh`, run by the maintainer.

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
