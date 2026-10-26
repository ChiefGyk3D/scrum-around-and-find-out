# SPDX-License-Identifier: Apache-2.0
"""The branch gate, read side: the default branch of each listed repository must require the gate check.

For every repository in board.yaml (less `rules.gate_exempt_repos`), read the default branch's classic protection rule
and the repository's rulesets, and report a repository whose default branch has no rule requiring `rules.gate_check`
(matched by its name alone or after a workflow prefix, `ci / CI green`), that allows force pushes, or whose rule can be
bypassed. Everything here only reads: nothing writes protection (`scripts/apply-baseline.sh` does that, for the
maintainer to run).

"Gated" means: the check cannot be bypassed by anyone except an administrator, unless
`rules.gate_require_admin_enforced` is on, in which case an administrator who can bypass is a finding too (a repository
can be accepted with `rules.gate_admin_exempt_repos`). A repository that passes only because administrators are accepted
gets a NOTE saying so. A repository exempt from the rule, an archived one and an empty one are not evaluated; each says
so in a NOTE, and none of those is durable evidence.

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
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from safo import output
from safo.errors import ApiError, AuthError, MalformedDataError, NotFoundError
from safo.graphql import JSON, Client
from safo.schema import LOGIN, REPO_NAME, Board

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
    admins_open: bool = False  # the gate holds only because administrators are accepted as an exception


class Unclear(Exception):
    """GitHub's answer or a ref pattern cannot be read with certainty: the verdict is "cannot tell"."""


# -- ref patterns ----------------------------------------------------------------------------------------------------
# GitHub matches ref patterns with Ruby's File.fnmatch and the FNM_PATHNAME flag (checked 2026-10-26):
#   https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule
#   https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository
# `*` does not match `/`; `qa/**/*` spans directories; `[set]` is allowed but not `[^set]`; no backslash quoting.
# Python's fnmatch lets `*` cross `/`, so a pattern like `release/*` would wrongly cover `release/1/2`.
# Not documented, so answered None ("cannot tell") rather than guessed: `**` that is not a whole directory (as in
# `release**` or a trailing `**`), a bracket expression that is not a plain set or ascending letter/digit range (see
# `_bracket`), a backslash, an unterminated `[`, a `~` variable other than
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
    try:
        return re.compile("".join(out))
    except re.error:  # belt and braces: whatever the parser emitted, a bad regex is "cannot tell", never a crash
        return None


# A bracket expression is read only when it is unambiguous: literal letters, digits and a few plain characters, and
# ordinary ascending ranges of letters or of digits (a-z, A-Z, 0-9). Anything else is "cannot tell": an empty set, a
# leading `]`, a leading or trailing `-`, `^` and `!` (GitHub does not support complementing), POSIX `[:alpha:]`, a
# backslash, a nested `[`, a special character (`* ? / .`) as a member or range end, a range that is descending or spans
# kinds, an unterminated set. Python's re and Ruby's fnmatch read several of these differently (`[]a]`, `[c-a]`).
_RANGE = re.compile(r"[a-z]-[a-z]|[A-Z]-[A-Z]|[0-9]-[0-9]")
_MEMBER = re.compile(r"[A-Za-z0-9_+@=,%]")


def _bracket(part: str, i: int) -> tuple[str, int] | None:
    """(regex, index after the set) for the bracket expression at part[i], or None when it is not unambiguous."""
    end = part.find("]", i + 1)
    if end == -1:
        return None
    body = part[i + 1 : end]
    if not body:
        return None
    out: list[str] = []
    k = 0
    while k < len(body):
        if _RANGE.fullmatch(body[k : k + 3]):
            if body[k] > body[k + 2]:
                return None
            out.append(f"{re.escape(body[k])}-{re.escape(body[k + 2])}")
            k += 3
        elif _MEMBER.fullmatch(body[k]):
            out.append(re.escape(body[k]))
            k += 1
        else:
            return None
    return "(?!/)[" + "".join(out) + "]", end + 1


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
            klass = _bracket(part, i)
            if klass is None:
                return None
            out.append(klass[0])
            i = klass[1]
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
        verdict = ref_matches(_text(p, "ruleset ref pattern"), ref)
        if verdict:
            return True
        unclear = unclear or verdict is None
    return None if unclear else False


# -- reading GitHub's answer -----------------------------------------------------------------------------------------


def names_gate(context: str, gate: str) -> bool:
    """The check's own name, or the name after a workflow prefix: `CI green` and `ci / CI green` both count."""
    return context == gate or context.endswith(f" / {gate}")


def _s(text: object) -> str:
    """GitHub-supplied or exception text made safe for one log line (the CLI's own escaping); idempotent."""
    return output.line(str(text))


def _obj(value: Any, what: str) -> JSON:
    if not isinstance(value, dict):
        raise MalformedDataError(f"{what}: GitHub's answer is not shaped as expected")
    return value


def _list(value: Any, what: str) -> list[Any]:
    """A real list, including an empty one. Null, absent and every other type are malformed, never an empty list."""
    if not isinstance(value, list):
        raise MalformedDataError(f"{what}: GitHub's answer is not a list")
    return value


def _text(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise MalformedDataError(f"{what}: GitHub's answer is not text")
    return value


def _count(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MalformedDataError(f"{what}: GitHub's answer lacks a count")
    return value


def _connection(conn: Any, what: str) -> list[JSON]:
    """The nodes of a connection read in full. `totalCount` must equal the number of nodes.

    More in the total than listed means the read was cut short (cannot tell, `Unclear`); fewer means the answer
    contradicts itself (`MalformedDataError`). The query asks for no further page, so either way the verdict is UNKNOWN.
    """
    conn = _obj(conn, what)
    nodes = [_obj(n, f"{what} node") for n in _list(conn.get("nodes"), f"{what} nodes")]
    total = _count(conn.get("totalCount"), f"{what} totalCount")
    if total > len(nodes):
        raise Unclear(f"{what}: only {len(nodes)} of {total} were listed")
    if total < len(nodes):
        raise MalformedDataError(f"{what}: GitHub lists {len(nodes)} nodes but a total of {total}")
    return nodes


_BAD_REF_CHARS = set(" ~^:?*[\\")


def _branch_name(value: Any) -> str:
    """The default branch name, validated like git's own ref-name rules; GitHub's text is never stringified."""
    name = _text(value, "defaultBranchRef name")
    bad = (
        not name
        or name == "@"
        or any(unicodedata.category(c).startswith("C") or c in _BAD_REF_CHARS for c in name)
        or name.startswith("/")
        or name.endswith(("/", ".", ".lock"))
        or ".." in name
        or "//" in name
        or "@{" in name
        or any(seg.startswith(".") or seg.endswith(".lock") for seg in name.split("/"))
    )
    if bad:
        raise MalformedDataError("defaultBranchRef name: GitHub's answer is not a plausible branch name")
    return name


def _contexts(checks: Any, what: str) -> list[str]:
    return [_text(_obj(c, what).get("context"), f"{what} context") for c in _list(checks, what)]


def _applies(rs: JSON, branch: str) -> bool:
    """An active branch ruleset whose conditions include the default branch and do not exclude it."""
    if (
        _text(rs.get("enforcement"), "ruleset enforcement") != "ACTIVE"
        or _text(rs.get("target"), "ruleset target") != "BRANCH"
    ):
        return False
    ref = _obj(_obj(rs.get("conditions"), "ruleset conditions").get("refName"), "ruleset refName")
    full = f"refs/heads/{branch}"
    include, exclude = _covers(ref.get("include"), full), _covers(ref.get("exclude"), full)
    if exclude is True or include is False:
        return False
    if include is None or exclude is None:
        raise Unclear(f"ruleset {_s(rs.get('name'))!r} has a ref pattern whose meaning GitHub does not document")
    return True


# RepositoryPermission and RepositoryRulesetTarget, read from GitHub's GraphQL schema by introspection (2026-10-26).
# Anything else is "cannot tell": a value this code has not seen is not guessed at.
VIEWER_PERMISSIONS = frozenset({"ADMIN", "MAINTAIN", "WRITE", "TRIAGE_PLUS", "TRIAGE", "READ"})
RULESET_TARGETS = frozenset({"BRANCH", "TAG", "PUSH", "REPOSITORY"})
_ASCII_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _identity(value: Any) -> str:
    """The returned nameWithOwner: exactly one ASCII `owner/repo` in the board's own grammar, folded A-Z only.

    Python's `lower()` is Unicode-aware (the Kelvin sign lowercases to an ASCII k), so a comparison made with it could
    credit another repository's answer. Validate the grammar first, then fold ASCII letters and nothing else.
    """
    name = _text(value, "nameWithOwner")
    owner, _, repo = name.partition("/")
    if not (LOGIN.fullmatch(owner) and REPO_NAME.fullmatch(repo)):
        raise MalformedDataError("nameWithOwner: GitHub's answer is not an owner/repo name")
    return name.translate(_ASCII_FOLD)


def _bool(value: Any, what: str) -> bool:
    if not isinstance(value, bool):
        raise MalformedDataError(f"{what}: GitHub's answer is not true or false")
    return value


def _patterns(ref: Any, what: str) -> None:
    ref = _obj(ref, what)
    for key in ("include", "exclude"):
        for p in _list(ref.get(key), f"{what} {key}"):
            _text(p, f"{what} {key} pattern")


def _validate_ruleset(rs: JSON) -> None:
    """The type of every field asked for in one ruleset, whether or not the ruleset counts for the default branch."""
    name = _s(_text(rs.get("name"), "ruleset name"))
    _text(rs.get("enforcement"), "ruleset enforcement")
    target = _text(rs.get("target"), "ruleset target")
    if target not in RULESET_TARGETS:
        raise MalformedDataError("ruleset target: GitHub's answer is not a known target")
    cond = rs.get("conditions")
    if target in ("BRANCH", "TAG"):
        _patterns(_obj(cond, "ruleset conditions").get("refName"), "ruleset refName")
    elif cond is not None:  # push and repository rulesets have no ref condition: null is normal there
        ref = _obj(cond, "ruleset conditions").get("refName")
        if ref is not None:
            _patterns(ref, "ruleset refName")
    for actor in _connection(rs.get("bypassActors"), f"ruleset {name!r} bypassActors"):
        _text(actor.get("bypassMode"), "bypassMode")
    for rule in _connection(rs.get("rules"), f"ruleset {name!r} rules"):
        kind = _text(rule.get("type"), "rule type")
        if "parameters" not in rule:
            raise MalformedDataError("rule parameters: GitHub's answer lacks them")
        params = rule["parameters"]
        if kind == "REQUIRED_STATUS_CHECKS":
            _contexts(_obj(params, "rule parameters").get("requiredStatusChecks"), "requiredStatusChecks")
        elif params is not None:
            _obj(params, "rule parameters")


def _validate_classic(classic: JSON) -> None:
    _bool(classic.get("requiresStatusChecks"), "requiresStatusChecks")
    _contexts(classic.get("requiredStatusChecks"), "requiredStatusChecks")
    _bool(classic.get("allowsForcePushes"), "allowsForcePushes")
    _bool(classic.get("isAdminEnforced"), "isAdminEnforced")
    _allowance_count(classic, "bypassForcePushAllowances")
    _allowance_count(classic, "bypassPullRequestAllowances")


def _validate_repository(repo: JSON, requested: str | None) -> None:
    """The type of every field the query asks for, in every record read, before any of it is judged.

    Relevance decides only whether a value counts, never whether it is checked: a disabled ruleset, a rule that is
    not a status-check rule, a classic rule with checks off, an archived or empty repository are all validated.
    """
    name = _identity(repo.get("nameWithOwner"))
    if requested is not None and name != requested.translate(_ASCII_FOLD):
        raise MalformedDataError(f"{_s(requested)}: GitHub answered for a different repository")
    _bool(repo.get("isArchived"), "isArchived")
    if _text(repo.get("viewerPermission"), "viewerPermission") not in VIEWER_PERMISSIONS:
        raise MalformedDataError("viewerPermission: GitHub's answer is not a known permission")
    if "defaultBranchRef" not in repo:
        raise MalformedDataError("defaultBranchRef: GitHub's answer lacks it")
    for rs in _connection(repo.get("rulesets"), "rulesets"):
        _validate_ruleset(rs)
    ref = repo["defaultBranchRef"]
    if ref is None:
        return
    ref = _obj(ref, "defaultBranchRef")
    _branch_name(ref.get("name"))
    if "branchProtectionRule" not in ref:
        raise MalformedDataError("branchProtectionRule: GitHub's answer lacks it")
    if ref["branchProtectionRule"] is not None:
        _validate_classic(_obj(ref["branchProtectionRule"], "branchProtectionRule"))


@dataclass
class Source:
    """One rule that holds a requirement; `bypass` says how someone gets around it, or None when nobody can."""

    label: str
    bypass: str | None
    admin_open: bool = False  # `bypass` is None only because administrators are accepted as an exception


def _bypass_actors(rs: JSON) -> str | None:
    name = _s(rs.get("name"))
    nodes = _connection(rs.get("bypassActors"), f"ruleset {name!r} bypassActors")
    if not nodes:
        return None
    modes = sorted({_s(_text(n.get("bypassMode"), "bypassMode")) for n in nodes})
    plural = "" if len(nodes) == 1 else "s"
    return f"ruleset {name!r} has {len(nodes)} bypass actor{plural} ({', '.join(modes)})"


def _admin_only(sources: list[Source]) -> bool:
    """Held, but only by rules whose administrator exception was accepted."""
    return any(s.bypass is None for s in sources) and not any(s.bypass is None and not s.admin_open for s in sources)


def _holds(sources: list[Source]) -> tuple[bool, list[str]]:
    """(held by a source nobody can bypass, the ways round the others)."""
    return any(s.bypass is None for s in sources), [s.bypass for s in sources if s.bypass]


def judge_repository(
    raw: JSON, gate: str, forbid_force: bool, *, admins_accepted: bool = False, requested: str | None = None
) -> GateResult:
    """Pure: one repository's facts in GitHub's GraphQL shape, the verdict out.

    "Gated" means: the check cannot be bypassed by anyone except, when `admins_accepted`, an administrator. Such a pass
    sets `admins_open` so the caller can say so; it is never silent.
    """
    res = GateResult()
    try:
        repo = _obj(raw, "repository")
        _validate_repository(repo, requested)
        return _judge(repo, gate, forbid_force, admins_accepted, res)
    except Unclear as err:
        res.problems = []
        res.unknown = _s(f"default branch {res.branch!r}: {err}")
        return res


def _judge(repo: JSON, gate: str, forbid_force: bool, admins_accepted: bool, res: GateResult) -> GateResult:
    permission = _text(repo.get("viewerPermission"), "viewerPermission")
    if repo.get("isArchived") is True:
        res.note = (
            "is archived (read-only, nothing can merge); the gate is not checked, and this is not durable evidence"
        )
        return res
    ref = repo["defaultBranchRef"]
    if ref is None:
        res.note = (
            "has no default branch yet (empty repository); the gate is not checked, and this is not durable evidence"
        )
        return res
    ref = _obj(ref, "defaultBranchRef")
    branch = res.branch = _branch_name(ref.get("name"))
    nodes = _connection(repo.get("rulesets"), "rulesets")

    check_sources: list[Source] = []
    force_sources: list[Source] = []
    protected = False
    classic = ref["branchProtectionRule"]
    if classic is not None:
        classic = _obj(classic, "branchProtectionRule")
        protected = True
        bypass = _classic_bypass(classic, admins_accepted)
        # Allowance data is withheld from a token that cannot administer the repository, possibly without an error: an
        # absent or null count is "cannot tell" (MalformedDataError), never zero. Only an integer 0 means none.
        allowances = _allowance_count(classic, "bypassForcePushAllowances")
        _allowance_count(classic, "bypassPullRequestAllowances")
        admin_open = classic["isAdminEnforced"] is False and admins_accepted
        if classic["requiresStatusChecks"] is True and any(
            names_gate(c, gate) for c in _contexts(classic["requiredStatusChecks"], "requiredStatusChecks")
        ):
            check_sources.append(Source("classic", bypass, admin_open))
        if classic.get("allowsForcePushes") is False:
            reasons = [bypass] if bypass else []
            if allowances:
                reasons.append(f"{allowances} actor{'' if allowances == 1 else 's'} may bypass the block")
            force_sources.append(Source("classic", "; ".join(reasons) or None, admin_open))
    for rs in nodes:
        if not _applies(rs, branch):
            continue
        listed = _connection(rs.get("rules"), f"ruleset {_s(rs.get('name'))!r} rules")
        protected = True
        bypass = _bypass_actors(rs)
        for rule in listed:
            kind = _text(rule.get("type"), "rule type")
            if kind == "REQUIRED_STATUS_CHECKS":
                params = _obj(rule.get("parameters"), "rule parameters")
                if any(
                    names_gate(c, gate) for c in _contexts(params.get("requiredStatusChecks"), "requiredStatusChecks")
                ):
                    check_sources.append(Source(_s(rs.get("name")), bypass))
            elif kind == "NON_FAST_FORWARD":
                force_sources.append(Source(_s(rs.get("name")), bypass))

    if not protected:
        if permission != "ADMIN":
            raise Unclear(f"nothing was visible, and {NEEDS_ADMIN}")
        res.problems.append("has no branch protection and no active ruleset")
        return res
    if gate:
        held, ways = _holds(check_sources)
        if not check_sources:
            res.problems.append(f"is protected but does not require the check {gate!r}")
        elif not held:
            res.problems.append(_s(f"requires the check {gate!r} but it can be bypassed ({'; '.join(ways)})"))
        elif _admin_only(check_sources):
            res.admins_open = True
    if forbid_force:
        held, ways = _holds(force_sources)
        if not force_sources:
            res.problems.append("allows force pushes")
        elif not held:
            res.problems.append(_s(f"force pushes are blocked but {'; '.join(ways)}"))
        elif _admin_only(force_sources):
            res.admins_open = True
    return res


def _allowance_count(classic: JSON, key: str) -> int:
    return _count(_obj(classic.get(key), key).get("totalCount"), f"{key} totalCount")


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
    if not isinstance(data, dict):
        raise MalformedDataError(f"{full_name}: GitHub's data is not an object")
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
            notes.append(f"NO-GATE {name}: exempt by rules.gate_exempt_repos (not evaluated)")
            continue
        try:
            result = judge_repository(
                read_repository(client, name),
                rules.gate_check,
                rules.gate_forbid_force_push,
                admins_accepted=not rules.gate_require_admin_enforced or name.lower() in admins,
                requested=name,
            )
        except NotFoundError:
            unknown.append(
                f"NO-GATE {name}: the repository cannot be read with this token (is the App installed on it?)"
            )
            continue
        except MalformedDataError as err:
            unknown.append(_s(f"NO-GATE {name}: could not read the default branch's protection ({err})"))
            continue
        except (AuthError, ApiError) as err:
            unknown.append(_s(f"NO-GATE {name}: could not read the default branch's protection ({err}); {NEEDS_ADMIN}"))
            continue
        except Exception:  # one repository's odd answer must not crash the audit or skip the others
            unknown.append(f"NO-GATE {name}: could not read the default branch's protection (unexpected answer)")
            continue
        if result.unknown:
            unknown.append(_s(f"NO-GATE {name}: {result.unknown}"))
        if result.note:
            notes.append(_s(f"NO-GATE {name} {result.note}"))
        if result.admins_open and not result.problems:
            why = (
                "rules.gate_require_admin_enforced is off"
                if not rules.gate_require_admin_enforced
                else "accepted by rules.gate_admin_exempt_repos"
            )
            notes.append(f"NO-GATE {name}: gated for everyone except administrators ({why})")
        if result.problems:
            drift.append(_s(f"NO-GATE {name}: default branch {result.branch!r} {' and '.join(result.problems)}"))
    return drift, unknown, notes
