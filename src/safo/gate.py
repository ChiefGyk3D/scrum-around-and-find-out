# SPDX-License-Identifier: Apache-2.0
"""The branch gate, read side: the default branch of each listed repository must require the gate check.

For every repository in board.yaml (less `rules.gate_exempt_repos`), read the default branch's classic protection rule
and the repository's rulesets, and report a repository whose default branch has no rule requiring `rules.gate_check`
(matched by its name alone or after a workflow prefix, `ci / CI green`), or that allows force pushes. Everything here
only reads: nothing writes protection (`scripts/apply-baseline.sh` does that, for the maintainer to run).

Both mechanisms are read because a repository may be protected by either. A read that cannot see the rules is never a
pass. GitHub shows protection and rulesets in full only to a token that can administer the repository (the
Administration: read permission of an App; `repo` scope of a user token), and GraphQL answers "none" rather than
"forbidden" to a token that cannot. So an empty answer counts as "unprotected" only when the token reports ADMIN on
the repository; otherwise it is "cannot tell" (exit 2). A rule that is found is trusted whatever the permission.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

from safo.errors import ApiError, AuthError, MalformedDataError, NotFoundError
from safo.graphql import JSON, Client
from safo.schema import Board

Q_BRANCH_GATE = """query RepoBranchGate($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    isArchived
    viewerPermission
    defaultBranchRef {
      name
      branchProtectionRule {
        requiresStatusChecks
        requiredStatusChecks { context }
        allowsForcePushes
      }
    }
    rulesets(first: 50, includeParents: true) {
      totalCount
      nodes {
        name
        enforcement
        target
        conditions { refName { include exclude } }
        rules(first: 50) {
          totalCount
          nodes {
            type
            parameters { ... on RequiredStatusChecksParameters { requiredStatusChecks { context } } }
          }
        }
      }
    }
  }
}"""

NEEDS_ADMIN = (
    "the token cannot read branch protection or rulesets here (it needs Administration: read on an App installation, "
    "or the repo scope of a user token)"
)


@dataclass
class GateResult:
    branch: str = ""
    problems: list[str] = field(default_factory=list)  # what is missing, as clauses of one sentence: drift
    unknown: str = ""  # why it cannot be told
    note: str = ""  # why the repository was not judged, which is not an error


def names_gate(context: str, gate: str) -> bool:
    """The check's own name, or the name after a workflow prefix: `CI green` and `ci / CI green` both count."""
    return context == gate or context.endswith(f" / {gate}")


def _obj(value: Any, what: str) -> JSON:
    if not isinstance(value, dict):
        raise MalformedDataError(f"{what}: GitHub's answer is not shaped as expected")
    return value


def _list(value: Any, what: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise MalformedDataError(f"{what}: GitHub's answer is not shaped as expected")
    return value


def _contexts(checks: Any, what: str) -> list[str]:
    return [str(_obj(c, what).get("context", "")) for c in _list(checks, what)]


def _ruleset_applies(rs: JSON, branch: str) -> bool:
    """An active branch ruleset whose conditions include the default branch and do not exclude it."""
    if rs.get("enforcement") != "ACTIVE" or rs.get("target") != "BRANCH":
        return False
    ref = _obj((_obj(rs.get("conditions") or {}, "ruleset conditions")).get("refName") or {}, "ruleset refName")
    full = f"refs/heads/{branch}"

    def matches(patterns: Any) -> bool:
        # `~DEFAULT_BRANCH` and `~ALL` in an exclude list remove the default branch, as in an include list.
        return any(
            p in ("~ALL", "~DEFAULT_BRANCH") or fnmatch.fnmatchcase(full, str(p))
            for p in _list(patterns, "ruleset ref")
        )

    return matches(ref.get("include")) and not matches(ref.get("exclude"))


def judge_repository(raw: JSON, gate: str, forbid_force: bool) -> GateResult:
    """Pure: one repository's facts in GitHub's GraphQL shape, the verdict out."""
    repo = _obj(raw, "repository")
    res = GateResult()
    if repo.get("isArchived") is True:
        res.note = "is archived (read-only, nothing can merge); the gate is not checked"
        return res
    ref = repo.get("defaultBranchRef")
    if ref is None:
        res.note = "has no default branch yet (empty repository); the gate is not checked"
        return res
    ref = _obj(ref, "defaultBranchRef")
    branch = res.branch = str(ref.get("name", ""))
    sets = _obj(repo.get("rulesets") or {}, "rulesets")
    nodes = [_obj(n, "ruleset") for n in _list(sets.get("nodes"), "rulesets")]
    if int(sets.get("totalCount") or 0) > len(nodes):
        res.unknown = f"default branch {branch!r}: only {len(nodes)} of {sets.get('totalCount')} rulesets were listed"
        return res

    classic = ref.get("branchProtectionRule")
    contexts: list[str] = []
    no_force = False
    protected = False
    if classic is not None:
        classic = _obj(classic, "branchProtectionRule")
        protected = True
        if classic.get("requiresStatusChecks"):
            contexts += _contexts(classic.get("requiredStatusChecks"), "requiredStatusChecks")
        no_force = classic.get("allowsForcePushes") is False
    for rs in nodes:
        if not _ruleset_applies(rs, branch):
            continue
        rules = _obj(rs.get("rules") or {}, "ruleset rules")
        if int(rules.get("totalCount") or 0) > len(_list(rules.get("nodes"), "ruleset rules")):
            res.unknown = f"default branch {branch!r}: ruleset {rs.get('name')!r} lists only some of its rules"
            return res
        protected = True
        for rule in _list(rules.get("nodes"), "ruleset rules"):
            rule = _obj(rule, "ruleset rule")
            if rule.get("type") == "REQUIRED_STATUS_CHECKS":
                params = _obj(rule.get("parameters") or {}, "rule parameters")
                contexts += _contexts(params.get("requiredStatusChecks"), "requiredStatusChecks")
            elif rule.get("type") == "NON_FAST_FORWARD":
                no_force = True

    if not protected:
        if repo.get("viewerPermission") != "ADMIN":
            res.unknown = f"default branch {branch!r}: nothing was visible, and {NEEDS_ADMIN}"
        else:
            res.problems.append("has no branch protection and no active ruleset")
        return res
    if gate and not any(names_gate(c, gate) for c in contexts):
        res.problems.append(f"is protected but does not require the check {gate!r}")
    if forbid_force and not no_force:
        res.problems.append("allows force pushes")
    return res


def read_repository(client: Client, full_name: str) -> JSON:
    owner, _, name = full_name.partition("/")
    data = client.execute(Q_BRANCH_GATE, {"owner": owner, "name": name})
    repo = data.get("repository")
    if not isinstance(repo, dict):
        raise MalformedDataError(f"{full_name}: GitHub returned no repository")
    return repo


def gate_findings(client: Client, board: Board) -> tuple[list[str], list[str], list[str]]:
    """(drift, unknown, notes) for the branch gate. An empty `rules.gate_check` turns it off, with a note."""
    rules = board.rules
    if not rules.gate_check:
        return [], [], ["Branch gate check not configured: rules.gate_check is empty"]
    exempt = {x.lower() for x in rules.gate_exempt_repos}
    drift: list[str] = []
    unknown: list[str] = []
    notes: list[str] = []
    for repo in board.repositories:
        name = repo.full_name
        if name.lower() in exempt:
            continue
        try:
            result = judge_repository(read_repository(client, name), rules.gate_check, rules.gate_forbid_force_push)
        except NotFoundError:
            unknown.append(
                f"NO-GATE {name}: the repository cannot be read with this token (is the App installed on it?)"
            )
            continue
        except MalformedDataError as err:
            unknown.append(f"NO-GATE {name}: could not read the default branch's protection ({err})")
            continue
        except (AuthError, ApiError) as err:
            unknown.append(f"NO-GATE {name}: could not read the default branch's protection ({err}); {NEEDS_ADMIN}")
            continue
        if result.unknown:
            unknown.append(f"NO-GATE {name}: {result.unknown}")
        if result.note:
            notes.append(f"NO-GATE {name} {result.note}")
        if result.problems:
            drift.append(f"NO-GATE {name}: default branch {result.branch!r} {' and '.join(result.problems)}")
    return drift, unknown, notes
