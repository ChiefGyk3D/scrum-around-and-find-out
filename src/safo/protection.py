# SPDX-License-Identifier: Apache-2.0
"""Read-only read-back of the default branch's protection (spec 8.5 row R2(a), decision M8).

The process profiles are only as strong as the review a pull request needs before it reaches the default branch, so a
check reads the protection back and says which condition does not hold. It issues GET requests only (`METHODS`), asks
for nothing beyond read access, and applies nothing.

Every field it uses is read strictly: an absent, null or mistyped value is `CannotTell` (exit 2), never an empty list
and never a quietly false condition, and a value from GitHub is never turned into text (`str()`) or echoed. A field
that GitHub legitimately omits (`required_status_checks` and `required_pull_request_reviews` on a rule that does not
require them, `bypass_pull_request_allowances` when no one may bypass) is read as "not set" only where that is its
documented and observed meaning (the live shapes are recorded in the pull request for #139).

Both mechanisms count: the classic branch protection rule and active branch rulesets that apply to the default branch.
A condition holds when either one provides it; the two "nobody is exempt" conditions must hold for every source in
effect. Rulesets in `evaluate` or `disabled` mode, and rulesets for tags, do not count.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import http.client
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from safo import __version__, bounded
from safo.codeowners import CodeownersError, Rule, covered, parse_rules
from safo.errors import SafoError

METHODS = ("GET",)  # the only verb this module can send
API_URL = "https://api.github.com"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
CHECK_NAME = "CI green"
MAX_RULESETS = 100  # one page; a full page might hide more, so it is "cannot tell"
CODEOWNERS_PLACES = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")  # GitHub's order of precedence
NAME = re.compile(r"[A-Za-z0-9_.-]+")
BRANCH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/+@=-]{0,254}")
GLOB = re.compile(r"[*?\[]")


class CannotTell(SafoError):
    """The protection could not be read in full; the answer is neither pass nor fail (exit 2)."""


@dataclasses.dataclass(frozen=True)
class Condition:
    id: str
    text: str
    ok: bool
    note: str = ""


# -- reading -------------------------------------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, hdrs: Any, newurl: str) -> Any:
        return None  # the token never follows a redirect


class Rest:
    """GET-only client. `get` returns (status, parsed JSON or None); only 200 and 404 are ever returned."""

    def __init__(self, token: str, base: str = API_URL, timeout: float = 30.0) -> None:
        parts = urllib.parse.urlsplit(base)
        if not (parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in LOOPBACK)):
            raise SafoError(f"the API URL {base!r} must be https (plain http is accepted for loopback only)")
        self._token, self._base, self._timeout = token, base.rstrip("/"), timeout

    def __repr__(self) -> str:
        return f"Rest(base={self._base!r})"

    def get(self, path: str, what: str) -> tuple[int, Any]:
        request = urllib.request.Request(  # noqa: S310 - the URL is https or loopback, checked in __init__
            self._base + path,
            method=METHODS[0],
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": f"safo/{__version__}",
            },
        )
        try:
            try:
                with urllib.request.build_opener(_NoRedirect).open(request, timeout=self._timeout) as response:
                    status, raw = response.status, response.read(bounded.MAX_BYTES + 1)
            except urllib.error.HTTPError as err:
                status, raw = err.code, err.read(bounded.MAX_BYTES + 1)
        except (OSError, http.client.HTTPException):
            raise CannotTell(f"cannot tell: the request for {what} did not complete") from None
        if status not in (200, 404):
            raise CannotTell(f"cannot tell: GitHub answered {status} to the request for {what}")
        try:
            return status, bounded.loads(raw)
        except (ValueError, RecursionError):
            if status == 404:
                return status, None
            raise CannotTell(f"cannot tell: the answer for {what} is not usable JSON") from None


# -- strict field access -------------------------------------------------------------------------------------------


def _obj(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CannotTell(f"cannot tell: {where} is missing or not an object")
    return value


def _list(parent: dict[str, Any], key: str, where: str) -> list[Any]:
    value = parent.get(key)
    if not isinstance(value, list):
        raise CannotTell(f"cannot tell: {where}.{key} is missing or not a list")
    return value


def _bool(parent: dict[str, Any], key: str, where: str) -> bool:
    value = parent.get(key)
    if not isinstance(value, bool):
        raise CannotTell(f"cannot tell: {where}.{key} is missing or not true/false")
    return value


def _str(parent: dict[str, Any], key: str, where: str) -> str:
    value = parent.get(key)
    if not isinstance(value, str):
        raise CannotTell(f"cannot tell: {where}.{key} is missing or not text")
    return value


def _strings(parent: dict[str, Any], key: str, where: str) -> list[str]:
    values = _list(parent, key, where)
    if not all(isinstance(v, str) for v in values):
        raise CannotTell(f"cannot tell: {where}.{key} holds something that is not text")
    return values


def _names_check(context: str) -> bool:
    return context == CHECK_NAME or context.endswith(" / " + CHECK_NAME)  # "<caller job> / CI green" in a reusable run


# -- the sources ---------------------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Source:
    """What one protection mechanism provides. `bypass` counts the users, teams and apps that may skip it."""

    code_owner: bool
    ci_green: bool
    up_to_date: bool
    admins_included: bool
    bypass: int
    agent_bypass: bool
    force_push_off: bool
    deletion_off: bool


def parse_classic(body: Any, agent: str) -> Source:
    top = _obj(body, "the branch protection answer")
    owner = ci = strict = False
    if "required_status_checks" in top:
        checks = _obj(top["required_status_checks"], "required_status_checks")
        strict = _bool(checks, "strict", "required_status_checks")
        if "contexts" in checks:
            _strings(checks, "contexts", "required_status_checks")
        for entry in _list(checks, "checks", "required_status_checks"):
            ci = ci or _names_check(_str(_obj(entry, "a required check"), "context", "a required check"))
    bypass, agent_hit = 0, False
    if "required_pull_request_reviews" in top:
        reviews = _obj(top["required_pull_request_reviews"], "required_pull_request_reviews")
        owner = _bool(reviews, "require_code_owner_reviews", "required_pull_request_reviews")
        if "bypass_pull_request_allowances" in reviews:
            allow = _obj(reviews["bypass_pull_request_allowances"], "bypass_pull_request_allowances")
            for kind, name in (("users", "login"), ("teams", "slug"), ("apps", "slug")):
                for entry in _list(allow, kind, "bypass_pull_request_allowances"):
                    who = _str(_obj(entry, f"a bypass {kind} entry"), name, f"a bypass {kind} entry")
                    bypass += 1
                    agent_hit = agent_hit or (kind == "users" and bool(agent) and who.lower() == agent.lower())
    admins = _bool(_obj(top.get("enforce_admins"), "enforce_admins"), "enabled", "enforce_admins")
    force = _bool(_obj(top.get("allow_force_pushes"), "allow_force_pushes"), "enabled", "allow_force_pushes")
    delete = _bool(_obj(top.get("allow_deletions"), "allow_deletions"), "enabled", "allow_deletions")
    return Source(owner, ci, strict, admins, bypass, agent_hit, not force, not delete)


def _applies(detail: dict[str, Any], branch: str) -> bool:
    ref = _obj(_obj(detail.get("conditions"), "a ruleset's conditions").get("ref_name"), "a ruleset's ref_name")
    include = _strings(ref, "include", "a ruleset's ref_name")
    exclude = _strings(ref, "exclude", "a ruleset's ref_name")
    exact = {"~DEFAULT_BRANCH", "~ALL", f"refs/heads/{branch}"}
    if any(GLOB.search(p) and p not in exact for p in exclude):
        raise CannotTell("cannot tell: a ruleset excludes branches by a pattern this check does not evaluate")
    if any(p in exact for p in exclude):
        return False
    return any(p in exact for p in include)  # a glob include is not counted: it can only make a condition fail


def parse_ruleset(detail: Any, listed: dict[str, Any], branch: str) -> Source | None:
    """The source a listed, active branch ruleset provides, or None when it does not apply to the default branch."""
    body = _obj(detail, "a ruleset")
    if body.get("id") != listed["id"] or _str(body, "target", "a ruleset") != "branch":
        raise CannotTell("cannot tell: a ruleset's detail does not match its listing")
    if _str(body, "enforcement", "a ruleset") != "active":
        raise CannotTell("cannot tell: a ruleset's detail does not match its listing")
    if not _applies(body, branch):
        return None
    bypass = len(_list(body, "bypass_actors", "a ruleset"))
    if not all(isinstance(a, dict) for a in body["bypass_actors"]):
        raise CannotTell("cannot tell: a ruleset's bypass_actors holds something that is not an object")
    owner = ci = strict = queue = force = delete = False
    for rule in _list(body, "rules", "a ruleset"):
        entry = _obj(rule, "a ruleset rule")
        kind = _str(entry, "type", "a ruleset rule")
        if kind == "pull_request":
            params = _obj(entry.get("parameters"), "the pull_request rule's parameters")
            owner = owner or _bool(params, "require_code_owner_review", "the pull_request rule")
        elif kind == "required_status_checks":
            params = _obj(entry.get("parameters"), "the required_status_checks rule's parameters")
            strict = strict or _bool(params, "strict_required_status_checks_policy", "the required_status_checks rule")
            for check in _list(params, "required_status_checks", "the required_status_checks rule"):
                ci = ci or _names_check(_str(_obj(check, "a required check"), "context", "a required check"))
        queue = queue or kind == "merge_queue"
        force = force or kind == "non_fast_forward"
        delete = delete or kind == "deletion"
    return Source(owner, ci, strict or queue, bypass == 0, bypass, False, force, delete)


# -- the questions -------------------------------------------------------------------------------------------------


def _repo_path(repo: str) -> str:
    owner, sep, name = repo.partition("/")
    if not sep or not NAME.fullmatch(owner) or not NAME.fullmatch(name) or {owner, name} & {".", ".."}:
        raise SafoError("the repository must be owner/name")
    return f"/repos/{owner}/{name}"


def default_branch(rest: Rest, base: str) -> str:
    _, body = rest.get(base, "the repository")
    name = _str(_obj(body, "the repository answer"), "default_branch", "the repository")
    if not BRANCH.fullmatch(name) or ".." in name or name.endswith(("/", ".lock")) or "//" in name:
        raise CannotTell("cannot tell: the default branch name is not one this check will put in a request")
    return name


def read_sources(rest: Rest, base: str, branch: str, agent: str) -> list[Source]:
    sources: list[Source] = []
    status, body = rest.get(f"{base}/branches/{urllib.parse.quote(branch, safe='/')}/protection", "branch protection")
    if status == 200:
        sources.append(parse_classic(body, agent))
    elif not (isinstance(body, dict) and body.get("message") == "Branch not protected"):
        raise CannotTell("cannot tell: branch protection answered 404 with something other than 'Branch not protected'")
    _, listing = rest.get(f"{base}/rulesets?per_page={MAX_RULESETS}&includes_parents=true", "the rulesets")
    if not isinstance(listing, list):
        raise CannotTell("cannot tell: the ruleset listing is not a list")
    if len(listing) >= MAX_RULESETS:
        raise CannotTell("cannot tell: a full page of rulesets may hide more")
    for item in listing:
        entry = _obj(item, "a listed ruleset")
        ident = entry.get("id")
        if not isinstance(ident, int) or isinstance(ident, bool):
            raise CannotTell("cannot tell: a listed ruleset has no numeric id")
        target, enforcement = _str(entry, "target", "a listed ruleset"), _str(entry, "enforcement", "a listed ruleset")
        if enforcement not in ("active", "evaluate", "disabled"):
            raise CannotTell("cannot tell: a listed ruleset has an enforcement this check does not know")
        if target != "branch" or enforcement != "active":
            continue
        status, detail = rest.get(f"{base}/rulesets/{ident}", "a ruleset")
        if status != 200:
            raise CannotTell("cannot tell: a listed ruleset could not be read")
        source = parse_ruleset(detail, entry, branch)
        if source is not None:
            sources.append(source)
    return sources


def read_codeowners(rest: Rest, base: str, branch: str) -> list[Rule]:
    """The rules of the first CODEOWNERS GitHub would use; no file at all is no rules (nothing covered)."""
    for place in CODEOWNERS_PLACES:
        status, body = rest.get(f"{base}/contents/{place}?ref={urllib.parse.quote(branch, safe='')}", "CODEOWNERS")
        if status == 404:
            if not (isinstance(body, dict) and body.get("message") == "Not Found"):
                raise CannotTell("cannot tell: CODEOWNERS answered 404 with something other than 'Not Found'")
            continue
        file = _obj(body, "the CODEOWNERS answer")
        if _str(file, "type", "CODEOWNERS") != "file" or _str(file, "encoding", "CODEOWNERS") != "base64":
            raise CannotTell("cannot tell: CODEOWNERS is not a file with base64 content")
        try:
            text = base64.b64decode("".join(_str(file, "content", "CODEOWNERS").split()), validate=True).decode()
            return parse_rules(text)
        except (binascii.Error, ValueError):
            raise CannotTell("cannot tell: CODEOWNERS content cannot be decoded") from None
        except CodeownersError:
            raise CannotTell("cannot tell: CODEOWNERS has a rule this check cannot evaluate") from None
    return []


# a directory is probed with the kinds of file that live in it (workflows are .yml), at two depths
PROBES = ("probe.yml", "probe.yaml", "probe.md", "probe", "sub/probe.yml")
PATHS = (
    ("codeowners-board-yaml", "board.yaml"),
    ("codeowners-codeowners-file", ".github/CODEOWNERS"),
    ("codeowners-workflows", ".github/workflows/"),
)


def evaluate(sources: list[Source], rules: list[Rule]) -> list[Condition]:
    def some(test: Callable[[Source], bool]) -> bool:
        return any(test(s) for s in sources)

    def every(test: Callable[[Source], bool]) -> bool:
        return bool(sources) and all(test(s) for s in sources)

    agent = some(lambda s: s.agent_bypass)
    conditions = [
        Condition("code-owner-review", "code-owner review is required", some(lambda s: s.code_owner)),
        Condition("ci-green", f"the `{CHECK_NAME}` check is required", some(lambda s: s.ci_green)),
        Condition(
            "up-to-date",
            "the branch must be up to date before merging (or a merge queue)",
            some(lambda s: s.up_to_date),
        ),
        Condition("admins-included", "administrators are included", every(lambda s: s.admins_included)),
        Condition(
            "no-bypass",
            "no one may bypass the rule",
            every(lambda s: s.bypass == 0),
            "the agent account is among them" if agent else "",
        ),
        Condition("no-force-push", "force pushes are off", some(lambda s: s.force_push_off)),
        Condition("no-deletion", "deleting the branch is off", some(lambda s: s.deletion_off)),
    ]
    for ident, path in PATHS:
        files = [path + probe for probe in PROBES] if path.endswith("/") else [path]
        conditions.append(Condition(ident, f"CODEOWNERS covers {path}", all(covered(rules, f) for f in files)))
    return conditions


def check(rest: Rest, repo: str, agent: str = "") -> tuple[str, int, list[Condition]]:
    """(default branch, number of protection sources found, conditions). Raises CannotTell, never guesses."""
    base = _repo_path(repo)
    branch = default_branch(rest, base)
    sources = read_sources(rest, base, branch, agent)
    return branch, len(sources), evaluate(sources, read_codeowners(rest, base, branch))
