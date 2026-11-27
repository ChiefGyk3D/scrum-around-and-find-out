# safo-protect-threads

`safo-protect-threads` turns on "require conversation resolution before merging" on a repository's default branch and
changes nothing else. The merge watcher ([safo-ship](ship.md)) can only make its review-thread check atomic with the
merge when branch protection requires it. It is a separate entry point, not a `safo` subcommand, so the dispatch
guard's `TOP_LEVEL_COMMANDS` is untouched. It never reads or prints a token: `gh` holds the credential, and the account
behind it needs admin rights on the repository.

```
safo-protect-threads OWNER/NAME                              # dry run: reads, prints the change, writes nothing
safo-protect-threads OWNER/NAME --apply --backup-dir DIR     # makes the change, then verifies it
```

## Why GraphQL and not the REST PUT

The REST call `PUT /repos/{owner}/{repo}/branches/{branch}/protection` replaces the whole protection: four keys are
required even when off, and every optional boolean left out resets to false. What GET returns cannot be sent back
unchanged (booleans wrapped as `{enabled}`, user, team and app objects where PUT wants logins and slugs, per-check apps,
and the signature requirement on its own endpoint). A round trip would be lossy, so this tool does not use it.

The GraphQL mutation `updateBranchProtectionRule` changes only the fields it is given. The tool passes exactly one:
`requiresConversationResolution`. Checked live and read-only on 2026-11-27: the introspection of
`UpdateBranchProtectionRuleInput` lists `requiresConversationResolution` (Boolean), and `BranchProtectionRule` exposes it
as a non-null Boolean.

## What a dry run does

1. Reads the default branch and every branch protection rule of the repository with one GraphQL query (up to 100 rules,
   each with the branches it matches).
2. Reads `GET /repos/{owner}/{repo}/rules/branches/{branch}`. A non-empty answer means a ruleset applies to the default
   branch, and the tool refuses (rulesets are a different API; it does not guess).
3. Picks the one rule that covers the default branch. No rule, more than one rule, or more rules than one page: refused.
4. Prints a diff of the rule as read against the rule with the flag set. Only that one line differs. The diff holds no
   login, team or app names (the allowances are shown as counts). If the rule's pattern is wider than the branch name, a
   NOTE says the change applies to everything the pattern matches.

If the flag is already true it says so and does nothing, with or without `--apply`.

## What `--apply` does

1. Writes the whole rule as read to a new file in `--backup-dir` (mode 0600, created exclusively, never following a
   link; the directory must exist and not be a symbolic link). Nothing is sent if that fails.
2. Sends the mutation with the one field.
3. Reads the rule again. Every field must equal what was read before, except the flag, which must be true. The fields
   compared: all of the rule's booleans, the approving-review count, the required check contexts and each check's app, the
   deployment environments, and the number of push, bypass, force-push-bypass and review-dismissal allowances.

If the read-back does not match, it prints the rollback: the same mutation with `false`, the rule id, the saved file and
the saved rule as JSON, and exits 6.

## Exit codes

| code | meaning |
| --- | --- |
| 0 | done, verified, or the flag was already true (a dry run that printed the change is also 0) |
| 2 | usage: bad `OWNER/NAME`, or `--apply` without an existing `--backup-dir` |
| 3 | refused, nothing changed: a ruleset applies, no rule or several rules cover the branch, a field of the rule cannot be read in full |
| 4 | a read failed (`gh` missing, an error, or unreadable JSON; `gh`'s error text is not shown) |
| 5 | the write failed and the read-back shows nothing changed |
| 6 | the write was sent but the read-back differs: use the printed rollback |

## Limits

- Allowance lists (who may push, bypass or dismiss) are compared by count, not by name. The mutation does not touch them;
  the count check would catch one being emptied.
- The commit-signature requirement is a field of this rule in GraphQL and is compared like the others.
- A branch protection rule that GitHub shows differently through REST and GraphQL is not reconciled here.
- Not an atomic snapshot: the read before and the read after are two requests, so a settings change by someone else in
  between shows as a mismatch (exit 6), not as success.

Sources (read 2026-11-27): the REST reference for [branch protection](https://docs.github.com/en/rest/branches/branch-protection)
and its OpenAPI description, the REST reference for [rule suites and branch rules](https://docs.github.com/en/rest/repos/rules)
(`GET /repos/{owner}/{repo}/rules/branches/{branch}`: "all active rules that apply to the specified branch"), and the
GraphQL schema read by introspection on the same day.

Tests: `tests/test_protect_threads.py` (a fake `gh` whose mutation changes only the fields it is given).
