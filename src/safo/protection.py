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
import secrets
import string
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from safo import __version__, bounded
from safo.codeowners import CodeownersError, Rule, _tokens, covered, parse_rules
from safo.errors import SafoError

METHODS = ("GET",)  # the only verb this module can send
API_URL = "https://api.github.com"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
CHECK_NAME = "CI green"
ACTIONS_APP = 15368  # GitHub Actions: the app that reports a workflow job as a check
UNPINNED = "required check is not pinned to an app (any source can satisfy it)"
MAX_RULESETS = 100  # one page; a full page might hide more, so it is "cannot tell"
CODEOWNERS_PLACES = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")  # GitHub's order of precedence
NAME = re.compile(r"[A-Za-z0-9_.-]+")
BRANCH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/+@=-]{0,254}")
SHA = re.compile(r"[0-9a-f]{40}")
GLOB = re.compile(r"[*?\[]")


class CannotTell(SafoError):
    """The protection could not be read in full; the answer is neither pass nor fail (exit 2)."""


@dataclasses.dataclass(frozen=True)
class Condition:
    id: str
    text: str
    ok: bool
    note: str = ""  # shown on a FAIL line
    warn: str = ""  # a NOTE line that never changes the exit code on its own
    matched: str = ""  # the required context that satisfied the condition


# -- reading -------------------------------------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, hdrs: Any, newurl: str) -> Any:
        return None  # the token never follows a redirect


def _body(response: Any) -> bytes:
    """The body, at most one byte over the cap. Two different Content-Length values are a response to distrust."""
    if len(set(response.headers.get_all("Content-Length") or [])) > 1:
        raise CannotTell("cannot tell: a response carried conflicting Content-Length headers")
    data: bytes = response.read(bounded.MAX_BYTES + 1)
    declared = response.headers.get("Content-Length")
    # http.client hands back what arrived when a connection closes early; a body that merely parses is not a whole one
    if declared is not None and (
        not declared.isdigit() or (len(data) != int(declared) and len(data) <= bounded.MAX_BYTES)
    ):
        raise CannotTell("cannot tell: a response body is shorter or longer than its Content-Length")
    return data


class Rest:
    """GET-only client. `get` returns (status, parsed JSON or None, lower-cased headers); only 200 and 404 are returned.

    Reads are bounded: one request, no retry, no redirect, a read timeout, and a body of at most 1 MiB.
    """

    def __init__(self, token: str, base: str = API_URL, timeout: float = 30.0) -> None:
        parts = urllib.parse.urlsplit(base)
        if not (parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in LOOPBACK)):
            raise SafoError(f"the API URL {base!r} must be https (plain http is accepted for loopback only)")
        self._token, self._base, self._timeout = token, base.rstrip("/"), timeout

    def __repr__(self) -> str:
        return f"Rest(base={self._base!r})"

    def get(self, path: str, what: str) -> tuple[int, Any, dict[str, str]]:
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
                    status, raw, head = response.status, _body(response), response.headers
            except urllib.error.HTTPError as err:
                status, raw, head = err.code, _body(err), err.headers
        except (OSError, http.client.HTTPException):
            raise CannotTell(f"cannot tell: the request for {what} did not complete") from None
        if status not in (200, 404):
            raise CannotTell(f"cannot tell: GitHub answered {status} to the request for {what}")
        headers = {"link": ",".join(head.get_all("Link") or [])}
        try:
            return status, bounded.loads(raw), headers
        except (ValueError, RecursionError):  # includes UnicodeDecodeError
            if status == 404:
                return status, None, headers
            raise CannotTell(f"cannot tell: the answer for {what} is not usable JSON") from None


def _no_next_page(headers: dict[str, str], what: str) -> None:
    """A list answered with a `rel="next"` link has more pages than were read: the read is incomplete."""
    if re.search(r"rel\s*=\s*\"?[^\",;]*\bnext\b", headers.get("link", ""), re.IGNORECASE):
        raise CannotTell(f"cannot tell: {what} has another page that was not read")


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
    """The exact name, or one workflow-name prefix and ` / `: what a reusable workflow's job is called in a caller.

    The prefix must be plain text with no control characters and no further ` / ` segment, so a lookalike context
    ("a / b / CI green", "x\\n / CI green") does not satisfy the condition.
    """
    if context == CHECK_NAME:
        return True
    prefix, sep, tail = context.partition(" / ")
    return (
        sep == " / "
        and tail == CHECK_NAME
        and 0 < len(prefix) <= 100
        and prefix == prefix.strip()
        and prefix.isprintable()
    )


Check = tuple[str, int | None]  # a matching required check: its context and the app it is pinned to (None = unpinned)


def _required_check(entry: Any, pin_key: str) -> Check | None:
    """The check if its context names `CI green`, else None. The pin must be null, absent, -1 or a positive integer."""
    row = _obj(entry, "a required check")
    context = _str(row, "context", "a required check")
    pin = row.get(pin_key)
    if pin is not None and (not isinstance(pin, int) or isinstance(pin, bool) or pin == 0 or pin < -1):
        raise CannotTell(f"cannot tell: a required check's {pin_key} is not null, -1 or a positive integer")
    if not _names_check(context):
        return None
    return context, (pin if pin is not None and pin > 0 else None)


# -- the sources ---------------------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Source:
    """What one protection mechanism provides. `bypass` counts the users, teams and apps that may skip it."""

    code_owner: bool
    ci: tuple[Check, ...]
    up_to_date: bool
    admins_included: bool
    bypass: int
    agent_bypass: bool
    force_push_off: bool
    deletion_off: bool


def parse_classic(body: Any, agent: str) -> Source:
    top = _obj(body, "the branch protection answer")
    owner = strict = False
    ci: list[Check] = []
    if "required_status_checks" in top:
        checks = _obj(top["required_status_checks"], "required_status_checks")
        strict = _bool(checks, "strict", "required_status_checks")
        if "contexts" in checks:
            _strings(checks, "contexts", "required_status_checks")
        for entry in _list(checks, "checks", "required_status_checks"):
            if (found := _required_check(entry, "app_id")) is not None:
                ci.append(found)
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
    return Source(owner, tuple(ci), strict, admins, bypass, agent_hit, not force, not delete)


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
    owner = strict = queue = force = delete = False
    ci: list[Check] = []
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
                if (found := _required_check(check, "integration_id")) is not None:
                    ci.append(found)
        queue = queue or kind == "merge_queue"
        force = force or kind == "non_fast_forward"
        delete = delete or kind == "deletion"
    return Source(owner, tuple(ci), strict or queue, bypass == 0, bypass, False, force, delete)


# -- the questions -------------------------------------------------------------------------------------------------


def _repo_path(repo: str) -> str:
    owner, sep, name = repo.partition("/")
    if not sep or not NAME.fullmatch(owner) or not NAME.fullmatch(name) or {owner, name} & {".", ".."}:
        raise SafoError("the repository must be owner/name")
    return f"/repos/{owner}/{name}"


@dataclasses.dataclass(frozen=True)
class Repo:
    """The repository document fields the read is bound to; read twice, the two must be identical."""

    id: int
    full_name: str
    default_branch: str


def read_repo(rest: Rest, base: str, repo: str) -> Repo:
    status, body, _ = rest.get(base, "the repository")
    top = _obj(body, "the repository answer")
    ident = top.get("id")
    if status != 200 or not isinstance(ident, int) or isinstance(ident, bool) or ident < 1:
        raise CannotTell("cannot tell: the repository answer has no positive numeric id")
    full_name = _str(top, "full_name", "the repository")
    if full_name.lower() != repo.lower():
        raise CannotTell("cannot tell: the repository answer is for a different repository than was asked for")
    name = _str(top, "default_branch", "the repository")
    if not BRANCH.fullmatch(name) or ".." in name or name.endswith(("/", ".lock")) or "//" in name:
        raise CannotTell("cannot tell: the default branch name is not one this check will put in a request")
    return Repo(ident, full_name, name)


def branch_head(rest: Rest, base: str, branch: str) -> str:
    """The commit the default branch points at now: CODEOWNERS and the workflow tree are read at exactly this commit."""
    status, body, _ = rest.get(f"{base}/branches/{urllib.parse.quote(branch, safe='/')}", "the default branch")
    top = _obj(body, "the branch answer")
    commit = _obj(top.get("commit"), "the branch's commit")
    sha = _str(commit, "sha", "the branch's commit")
    if status != 200 or top.get("name") != branch or not SHA.fullmatch(sha):
        raise CannotTell("cannot tell: the branch answer is not for the default branch or has no commit sha")
    return sha


def read_sources(rest: Rest, base: str, branch: str, agent: str) -> list[Source]:
    sources: list[Source] = []
    status, body, _ = rest.get(
        f"{base}/branches/{urllib.parse.quote(branch, safe='/')}/protection", "branch protection"
    )
    if status == 200:
        sources.append(parse_classic(body, agent))
    elif not (isinstance(body, dict) and body.get("message") == "Branch not protected"):
        raise CannotTell("cannot tell: branch protection answered 404 with something other than 'Branch not protected'")
    status, listing, headers = rest.get(
        f"{base}/rulesets?per_page={MAX_RULESETS}&includes_parents=true", "the rulesets"
    )
    if status != 200 or not isinstance(listing, list):
        raise CannotTell("cannot tell: the ruleset listing is not a list")
    _no_next_page(headers, "the ruleset listing")
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
        status, detail, _ = rest.get(f"{base}/rulesets/{ident}", "a ruleset")
        if status != 200:
            raise CannotTell("cannot tell: a listed ruleset could not be read")
        source = parse_ruleset(detail, entry, branch)
        if source is not None:
            sources.append(source)
    return sources


# -- CODEOWNERS ----------------------------------------------------------------------------------------------------

_LOGIN = r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9]))*"  # no leading, trailing or doubled hyphen
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def strict_owner(token: str) -> bool:
    """A CODEOWNERS owner by GitHub's own naming rules: @login (39 characters), @org/team, or an email address.

    This is the second layer. Whether the user or team exists, and can review, is GitHub's answer (the CODEOWNERS
    errors endpoint), read separately.
    """
    if len(token) > 256:
        return False
    if token.startswith("@"):
        owner, slash, team = token[1:].partition("/")
        if not (re.fullmatch(_LOGIN, owner) and len(owner) <= 39):
            return False
        return not slash or bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", team))
    return bool(_EMAIL.fullmatch(token))


def read_codeowners(rest: Rest, base: str, ref: str) -> tuple[str, str] | None:
    """(location, text) of the first CODEOWNERS GitHub would use at commit `ref`; None when there is no file."""
    for place in CODEOWNERS_PLACES:
        status, body, _ = rest.get(f"{base}/contents/{place}?ref={ref}", "CODEOWNERS")
        if status == 404:
            if not (isinstance(body, dict) and body.get("message") == "Not Found"):
                raise CannotTell("cannot tell: CODEOWNERS answered 404 with something other than 'Not Found'")
            continue
        file = _obj(body, "the CODEOWNERS answer")
        if (
            _str(file, "path", "CODEOWNERS") != place
            or _str(file, "type", "CODEOWNERS") != "file"
            or _str(file, "encoding", "CODEOWNERS") != "base64"
            or not SHA.fullmatch(_str(file, "sha", "CODEOWNERS"))
        ):
            raise CannotTell("cannot tell: the CODEOWNERS answer is not the base64 file that was asked for")
        try:
            return place, base64.b64decode("".join(_str(file, "content", "CODEOWNERS").split()), validate=True).decode()
        except (binascii.Error, ValueError):
            raise CannotTell("cannot tell: CODEOWNERS content cannot be decoded") from None
    return None


def codeowners_error_lines(rest: Rest, base: str, ref: str, place: str) -> set[int]:
    """The lines of `place` GitHub reports an error on (an owner that does not exist, a bad pattern, ...)."""
    status, body, headers = rest.get(f"{base}/codeowners/errors?ref={ref}", "the CODEOWNERS errors")
    if status != 200:
        raise CannotTell("cannot tell: the CODEOWNERS errors could not be read")
    _no_next_page(headers, "the CODEOWNERS errors")
    lines: set[int] = set()
    for item in _list(_obj(body, "the CODEOWNERS errors answer"), "errors", "the CODEOWNERS errors answer"):
        row = _obj(item, "a CODEOWNERS error")
        line = row.get("line")
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            raise CannotTell("cannot tell: a CODEOWNERS error has no line number")
        if _str(row, "path", "a CODEOWNERS error") == place:
            lines.add(line)
    return lines


def trusted_rules(text: str, bad_lines: set[int]) -> tuple[list[Rule], int]:
    """The rules, with every line GitHub reports an error on, or that names an owner failing `strict_owner`, left with
    its pattern and no owner (so it clears ownership of what it matches, the strict reading). Also how many were."""
    kept: list[str] = []
    downgraded = 0
    for number, line in enumerate(text.splitlines(), 1):
        tokens = _tokens(line)
        if tokens and (number in bad_lines or not all(strict_owner(t) for t in tokens[1:])):
            if tokens[1:]:
                downgraded += 1
            line = tokens[0]
        kept.append(line)
    try:
        return parse_rules("\n".join(kept)), downgraded
    except CodeownersError:
        raise CannotTell("cannot tell: CODEOWNERS has a rule this check cannot evaluate") from None


def _tree(
    rest: Rest, base: str, sha: str, what: str, *, recursive: bool, expect: str | None
) -> list[tuple[str, str, str]]:
    status, body, _ = rest.get(f"{base}/git/trees/{sha}" + ("?recursive=1" if recursive else ""), what)
    top = _obj(body, what)
    if status != 200 or (expect is not None and top.get("sha") != expect):
        raise CannotTell(f"cannot tell: {what} is not the tree that was asked for")
    if top.get("truncated") is not False:
        raise CannotTell(f"cannot tell: {what} is truncated or does not say whether it is")
    rows: list[tuple[str, str, str]] = []
    for item in _list(top, "tree", what):
        row = _obj(item, "a tree entry")
        path = _str(row, "path", "a tree entry")
        kind = _str(row, "type", "a tree entry")
        entry = _str(row, "sha", "a tree entry")
        if kind not in ("blob", "tree", "commit") or not SHA.fullmatch(entry):
            raise CannotTell("cannot tell: a tree entry is not one this check understands")
        if not path or not path.isprintable() or path.startswith("/"):
            raise CannotTell("cannot tell: a tree entry has a path this check will not use")
        rows.append((path, kind, entry))
    return rows


def workflow_files(rest: Rest, base: str, head: str) -> list[str]:
    """Every file under `.github/workflows/` at commit `head`, nested ones included. None at all is an empty list.

    The tree is walked one level at a time (root, `.github`, `workflows` recursively), so a large repository's root
    listing is the only big read, and a truncated listing at any step is "cannot tell".
    """
    current, expect = head, None
    for step in (".github", "workflows"):
        entries = _tree(rest, base, current, f"the tree holding {step}", recursive=False, expect=expect)
        match = [e for e in entries if e[0] == step]
        if not match:
            return []
        if match[0][1] != "tree":
            raise CannotTell(f"cannot tell: {step} is not a directory")
        current = expect = match[0][2]
    listed = _tree(rest, base, current, "the workflows tree", recursive=True, expect=expect)
    return [".github/workflows/" + path for path, kind, _ in listed if kind != "tree"]


FRESH_NAMES = 3  # rounds of random paths per run, each in every shape below
FRESH_SHAPES = ("{}.yml", "{}.yaml", "{}", "{}/{}.yml", "{}/{}.yaml", "{}/{}", "{}/{}/{}.yml")


_ALNUM = string.ascii_letters + string.digits
_ALPHABET = _ALNUM + "_.-"


def _random_token() -> str:
    """A path component of 6 to 24 characters from letters, digits, `_`, `.` and `-`, any of them first (so a leading
    dot, digit, dash or capital is as likely as a lowercase letter) and never made only of dots. Not hexadecimal: a
    class like `[0-9a-f]*` or `[a-z]*` must not own it by construction."""
    chars = [secrets.choice(_ALPHABET) for _ in range(6 + secrets.randbelow(19))]
    if not any(c in _ALNUM for c in chars):
        chars[-1] = secrets.choice(_ALNUM)
    return "".join(chars)


fresh_token: Callable[[], str] = _random_token  # replaced by a test only, to make the names reproducible


def fresh_workflow_paths() -> list[str]:
    """Paths that do not exist yet, under `.github/workflows/`, in the shapes a new workflow could take.

    Second layer behind `directory_wide_owned`. Every name and every directory component is a fresh random token (no
    fixed prefix to own), at one to three levels, with `.yml`, `.yaml` or no extension. A rule file cannot have
    anticipated them, so a rule that owns these has to own the whole directory. It is a sample, not a proof: a pattern
    that owns most but not all names can pass one run.
    """
    return [
        ".github/workflows/" + shape.format(*(fresh_token() for _ in range(shape.count("{}"))))
        for _ in range(FRESH_NAMES)
        for shape in FRESH_SHAPES
    ]


# Patterns that cover .github/workflows/ and everything that could ever be added under it, whatever it is called.
DIRECTORY_WIDE = frozenset(
    {
        "*",
        "**",
        "/**",
        ".github",
        "/.github",
        ".github/",
        "/.github/",
        ".github/**",
        "/.github/**",
        ".github/workflows",
        "/.github/workflows",
        ".github/workflows/",
        "/.github/workflows/",
        ".github/workflows/**",
        "/.github/workflows/**",
    }
)
_WILD = re.compile(r"[*?\[\\]")


def _may_touch(pattern: str) -> bool:
    """True unless the pattern's literal leading directories prove it cannot match anything under `.github/workflows`.

    Conservative: a pattern with no slash matches names at any depth, and a wildcard in one of the first two
    segments could match `.github` or `workflows`; both count as touching.
    """
    if not (pattern.startswith("/") or "/" in pattern.rstrip("/")):
        return True
    for want, segment in zip((".github", "workflows"), pattern.strip("/").split("/"), strict=False):
        if _WILD.search(segment):
            return True
        if segment != want:
            return False
    return True


def directory_wide_owned(rules: list[Rule]) -> bool:
    """The structural proof that a file added anywhere under `.github/workflows/` has an owner, whatever its name.

    The last directory-wide rule (see `DIRECTORY_WIDE`; `*` and `/.github/` count, they cover the rest of the
    repository too) must name an owner, and no later rule that could touch the directory may name none. Then for any
    path under it the last matching rule is either that rule or a later one that has an owner.
    """
    state = False
    for rule in rules:
        if rule.pattern in DIRECTORY_WIDE:
            state = rule.owned
        elif state and not rule.owned and _may_touch(rule.pattern):
            state = False
    return state


PATHS = (
    ("codeowners-board-yaml", "board.yaml"),
    ("codeowners-codeowners-file", ".github/CODEOWNERS"),
)


def ci_condition(sources: list[Source], require_app: int | None) -> Condition:
    """`CI green` is required. By name it passes, with a NOTE when a source other than GitHub Actions could satisfy it;
    with `require_app` every matching check must be pinned to that app or the condition fails."""
    checks = [c for s in sources for c in s.ci]
    expected = require_app or ACTIONS_APP
    warn = ""
    if any(app is None for _, app in checks):
        warn = UNPINNED
    elif any(app != expected for _, app in checks):
        warn = f"required check is pinned to an app, not the expected app {expected}"
    ok = bool(checks) and (require_app is None or all(app == require_app for _, app in checks))
    text = f"the `{CHECK_NAME}` check is required" + (f" and pinned to app {require_app}" if require_app else "")
    return Condition("ci-green", text, ok, warn=warn, matched=", ".join(dict.fromkeys(c for c, _ in checks)))


def evaluate(
    sources: list[Source],
    rules: list[Rule],
    require_app: int | None = None,
    workflows: list[str] | None = None,
    downgraded: int = 0,
) -> list[Condition]:
    """`workflows` is the real file list (None when there is no CODEOWNERS, so nothing is covered); an empty list is
    vacuously covered: with no workflow files there is nothing a pull request could add."""

    def some(test: Callable[[Source], bool]) -> bool:
        return any(test(s) for s in sources)

    def every(test: Callable[[Source], bool]) -> bool:
        return bool(sources) and all(test(s) for s in sources)

    agent = some(lambda s: s.agent_bypass)
    conditions = [
        Condition("code-owner-review", "code-owner review is required", some(lambda s: s.code_owner)),
        ci_condition(sources, require_app),
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
    warn = (
        f"{downgraded} CODEOWNERS line(s) name an owner GitHub or this check rejects: treated as unowned"
        if downgraded
        else ""
    )
    for ident, path in PATHS:
        conditions.append(Condition(ident, f"CODEOWNERS covers {path}", covered(rules, path), warn=warn))
        warn = ""
    files = workflows if workflows is not None else []
    fresh = fresh_workflow_paths()
    ok = workflows is not None and directory_wide_owned(rules) and all(covered(rules, f) for f in [*files, *fresh])
    conditions.append(
        Condition(
            "codeowners-workflows",
            f"CODEOWNERS covers every file under .github/workflows/ ({len(files)} now, and new ones of any name)",
            ok,
        )
    )
    return conditions


def check(rest: Rest, repo: str, agent: str = "", require_app: int | None = None) -> tuple[str, int, list[Condition]]:
    """(default branch, number of protection sources found, conditions). Raises CannotTell, never guesses."""
    base = _repo_path(repo)
    first = read_repo(rest, base, repo)
    head = branch_head(rest, base, first.default_branch)
    sources = read_sources(rest, base, first.default_branch, agent)
    found = read_codeowners(rest, base, head)
    rules: list[Rule] = []
    workflows: list[str] | None = None
    downgraded = 0
    if found is not None:
        place, text = found
        rules, downgraded = trusted_rules(text, codeowners_error_lines(rest, base, head, place))
        workflows = workflow_files(rest, base, head)
    if read_repo(rest, base, repo) != first:  # the default branch (or the repository) changed under the read
        raise CannotTell("cannot tell: the repository or its default branch changed while it was being read")
    return first.default_branch, len(sources), evaluate(sources, rules, require_app, workflows, downgraded)
