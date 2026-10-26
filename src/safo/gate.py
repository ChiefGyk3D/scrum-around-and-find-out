# SPDX-License-Identifier: Apache-2.0
"""The branch gate, read side: the default branch of each listed repository must require the gate check.

For every repository in board.yaml (less `rules.gate_exempt_repos`), read the default branch's classic protection rule
and the repository's rulesets, and report a repository whose default branch has no rule requiring `rules.gate_check`
(matched by its name alone or after a workflow prefix, `ci / CI green`), that allows force pushes, or whose rule can be
bypassed. Everything here only reads: nothing writes protection (`scripts/apply-baseline.sh` does that, for the
maintainer to run).

Both mechanisms are read because a repository may be protected by either. A read that cannot see the rules is never a
pass. GitHub shows protection and rulesets in full only to a token that can administer the repository (the
Administration: read permission of an App; `repo` scope of a user token), and GraphQL answers "none" rather than
"forbidden" to a token that cannot. So an empty answer counts as "unprotected" only when the token reports ADMIN on
the repository; otherwise it is "cannot tell" (exit 2). A rule that is found is trusted whatever the permission, except
that a rule someone can bypass does not hold the gate.

Where this module cannot be sure what GitHub means, it says "cannot tell" and the audit exits 2;
it never guesses a pass.
That covers a ref pattern whose meaning GitHub does not document, a list cut short by the page size, and a field the
answer lacks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from safo.errors import ApiError, AuthError, MalformedDataError, NotFoundError
from safo.graphql import JSON, Client
from safo.schema import Board

# Lists are read 40 at a time and a longer one is "cannot tell" (never paginated: no repository has that many).
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
        isAdminEnforced
        bypassForcePushAllowances(first: 1) { totalCount }
        bypassPullRequestAllowances(first: 1) { totalCount }
      }
    }
    rulesets(first: 40, includeParents: true) {
      totalCount
      nodes {
        name
        enforcement
        target
        conditions { refName { include exclude } }
        bypassActors(first: 40) { totalCount nodes { bypassMode } }
        rules(first: 40) {
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
    problems: list[str] = field(default_factory=list)  # clauses of one sentence about the default branch: drift
    unknown: str = ""  # why it cannot be told
    note: str = ""  # why the repository was not judged, which is not an error


class Unclear(Exception):
    """GitHub's answer or a ref pattern cannot be read with certainty: the verdict is "cannot tell"."""


# -- ref patterns ----------------------------------------------------------------------------------------------------
# GitHub matches ref patterns with Ruby's File.fnmatch and the FNM_PATHNAME flag (checked 2026-10-26):
#   https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule
#   https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository
# `*` does not match `/`; `qa/**/*` spans directories; `[set]` is allowed but not `[^set]`; no backslash quoting.
# Python's fnmatch lets `*` cross `/`, so a pattern like `release/*` would wrongly cover `release/1/2`.
# Not documented, so answered None ("cannot tell") rather than guessed: `**` that is not a whole directory (as in
# `release**` or a trailing `**`), `[^...]` and `[!...]`, a backslash, an unterminated `[`, a `~` variable other than
# ~ALL and ~DEFAULT_BRANCH, and whether a wildcard matches a segment's leading dot (Ruby does not, unless told; GitHub
# does not say).


def _regex(pattern: str, wide: bool) -> re.Pattern[str] | None:
    """The pattern as a regex, or None for undocumented syntax. `wide`: a stray `**` is `.*`, else `[^/]*`."""
    if "\\" in pattern:
        return None
    parts = pattern.split("/")
    out: list[str] = []
    for index, part in enumerate(parts):
        last = index == len(parts) - 1
        if part == "**" and not last:
            out.append("(?:[^/]+/)*")  # `**/`: zero or more directories
            continue
        piece = _segment(part, wide)
        if piece is None:
            return None
        out.append(piece if last else piece + "/")
    return re.compile("".join(out))


def _segment(part: str, wide: bool) -> str | None:
    out: list[str] = []
    i = 0
    while i < len(part):
        c = part[i]
        if c == "*":
            run = 1
            while i + run < len(part) and part[i + run] == "*":
                run += 1
            out.append(".*" if run > 1 and wide else "[^/]*")
            i += run
            continue
        if c == "?":
            out.append("[^/]")
        elif c == "[":
            end = part.find("]", i + 2)
            if end == -1 or part[i + 1] in "^!":
                return None
            body = part[i + 1 : end]
            if "[" in body:
                return None
            out.append("(?!/)[" + body + "]")
            i = end + 1
            continue
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


def ref_matches(pattern: str, ref: str) -> bool | None:
    """Does a ruleset ref pattern cover `ref` (`refs/heads/main`)? None when GitHub's meaning cannot be told."""
    if pattern in ("~ALL", "~DEFAULT_BRANCH"):  # ref is the default branch here, so both cover it
        return True
    if pattern.startswith("~"):
        return None
    if not any(c in pattern for c in "*?["):
        return None if "\\" in pattern else pattern == ref
    strict, wide = _regex(pattern, False), _regex(pattern, True)
    if strict is None or wide is None:
        return None
    hit = strict.fullmatch(ref) is not None
    if hit != (wide.fullmatch(ref) is not None):
        return None  # the two readings of a stray `**` disagree
    if hit and any(seg.startswith(".") for seg in ref.split("/")):
        return None
    return hit


def _covers(patterns: Any, ref: str) -> bool | None:
    """True if any pattern definitely covers ref, None if none does but one may, else False."""
    unclear = False
    for p in _list(patterns, "ruleset ref patterns"):
        verdict = ref_matches(str(p), ref)
        if verdict:
            return True
        unclear = unclear or verdict is None
    return None if unclear else False


# -- reading GitHub's answer -----------------------------------------------------------------------------------------


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


def _count(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MalformedDataError(f"{what}: GitHub's answer lacks a count")
    return value


def _contexts(checks: Any, what: str) -> list[str]:
    return [str(_obj(c, what).get("context", "")) for c in _list(checks, what)]


def _applies(rs: JSON, branch: str) -> bool:
    """An active branch ruleset whose conditions include the default branch and do not exclude it."""
    if rs.get("enforcement") != "ACTIVE" or rs.get("target") != "BRANCH":
        return False
    ref = _obj(_obj(rs.get("conditions") or {}, "ruleset conditions").get("refName") or {}, "ruleset refName")
    full = f"refs/heads/{branch}"
    include, exclude = _covers(ref.get("include"), full), _covers(ref.get("exclude"), full)
    if exclude is True or include is False:
        return False
    if include is None or exclude is None:
        raise Unclear(f"ruleset {rs.get('name')!r} has a ref pattern whose meaning GitHub does not document")
    return True


@dataclass
class Source:
    """One rule that holds a requirement; `bypass` says how someone gets around it, or None when nobody can."""

    label: str
    bypass: str | None


def _bypass_actors(rs: JSON) -> str | None:
    actors = _obj(rs.get("bypassActors"), f"ruleset {rs.get('name')!r} bypassActors")
    nodes = _list(actors.get("nodes"), "bypassActors")
    total = _count(actors.get("totalCount"), "bypassActors totalCount")
    if total > len(nodes):
        raise Unclear(f"ruleset {rs.get('name')!r} lists only {len(nodes)} of {total} bypass actors")
    if not nodes:
        return None
    modes = sorted({str(_obj(n, "bypass actor").get("bypassMode", "?")) for n in nodes})
    plural = "" if len(nodes) == 1 else "s"
    return f"ruleset {rs.get('name')!r} has {len(nodes)} bypass actor{plural} ({', '.join(modes)})"


def _holds(sources: list[Source]) -> tuple[bool, list[str]]:
    """(held by a source nobody can bypass, the ways round the others)."""
    return any(s.bypass is None for s in sources), [s.bypass for s in sources if s.bypass]


def judge_repository(raw: JSON, gate: str, forbid_force: bool, *, admins_accepted: bool = False) -> GateResult:
    """Pure: one repository's facts in GitHub's GraphQL shape, the verdict out."""
    res = GateResult()
    try:
        return _judge(_obj(raw, "repository"), gate, forbid_force, admins_accepted, res)
    except Unclear as err:
        res.problems = []
        res.unknown = f"default branch {res.branch!r}: {err}"
        return res


def _judge(repo: JSON, gate: str, forbid_force: bool, admins_accepted: bool, res: GateResult) -> GateResult:
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
    if _count(sets.get("totalCount"), "rulesets totalCount") > len(nodes):
        raise Unclear(f"only {len(nodes)} of {sets.get('totalCount')} rulesets were listed")

    check_sources: list[Source] = []
    force_sources: list[Source] = []
    protected = False
    classic = ref.get("branchProtectionRule")
    if classic is not None:
        classic = _obj(classic, "branchProtectionRule")
        protected = True
        bypass = _classic_bypass(classic, admins_accepted)
        if classic.get("requiresStatusChecks") and any(
            names_gate(c, gate) for c in _contexts(classic.get("requiredStatusChecks"), "requiredStatusChecks")
        ):
            check_sources.append(Source("classic", bypass))
        if classic.get("allowsForcePushes") is False:
            allowances = _count(
                _obj(classic.get("bypassForcePushAllowances"), "bypassForcePushAllowances").get("totalCount"),
                "bypassForcePushAllowances totalCount",
            )
            reasons = [bypass] if bypass else []
            if allowances:
                reasons.append(f"{allowances} actor{'' if allowances == 1 else 's'} may bypass the block")
            force_sources.append(Source("classic", "; ".join(reasons) or None))
    for rs in nodes:
        if not _applies(rs, branch):
            continue
        rules = _obj(rs.get("rules") or {}, "ruleset rules")
        listed = _list(rules.get("nodes"), "ruleset rules")
        if _count(rules.get("totalCount"), "ruleset rules totalCount") > len(listed):
            raise Unclear(f"ruleset {rs.get('name')!r} lists only some of its rules")
        protected = True
        bypass = _bypass_actors(rs)
        for rule in listed:
            rule = _obj(rule, "ruleset rule")
            if rule.get("type") == "REQUIRED_STATUS_CHECKS":
                params = _obj(rule.get("parameters") or {}, "rule parameters")
                if any(
                    names_gate(c, gate) for c in _contexts(params.get("requiredStatusChecks"), "requiredStatusChecks")
                ):
                    check_sources.append(Source(str(rs.get("name")), bypass))
            elif rule.get("type") == "NON_FAST_FORWARD":
                force_sources.append(Source(str(rs.get("name")), bypass))

    if not protected:
        if repo.get("viewerPermission") != "ADMIN":
            raise Unclear(f"nothing was visible, and {NEEDS_ADMIN}")
        res.problems.append("has no branch protection and no active ruleset")
        return res
    if gate:
        held, ways = _holds(check_sources)
        if not check_sources:
            res.problems.append(f"is protected but does not require the check {gate!r}")
        elif not held:
            res.problems.append(f"requires the check {gate!r} but it can be bypassed ({'; '.join(ways)})")
    if forbid_force:
        held, ways = _holds(force_sources)
        if not force_sources:
            res.problems.append("allows force pushes")
        elif not held:
            res.problems.append(f"force pushes are blocked but {'; '.join(ways)}")
    return res


def _classic_bypass(classic: JSON, admins_accepted: bool) -> str | None:
    enforced = classic.get("isAdminEnforced")
    if not isinstance(enforced, bool):
        raise MalformedDataError("branchProtectionRule: GitHub's answer lacks isAdminEnforced")
    if enforced or admins_accepted:
        return None
    return "administrators are not included (enforce_admins is off)"


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
    admins = {x.lower() for x in rules.gate_admin_exempt_repos}
    drift: list[str] = []
    unknown: list[str] = []
    notes: list[str] = []
    for repo in board.repositories:
        name = repo.full_name
        if name.lower() in exempt:
            continue
        try:
            result = judge_repository(
                read_repository(client, name),
                rules.gate_check,
                rules.gate_forbid_force_push,
                admins_accepted=not rules.gate_require_admin_enforced or name.lower() in admins,
            )
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
