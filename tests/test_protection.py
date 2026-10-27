# SPDX-License-Identifier: Apache-2.0
"""safo protection: the read-only branch-protection read-back (spec 8.5 R2(a), #139).

A tiny loopback server stands in for the REST API and records every request. One fixture per failing condition; every
field the check reads has a null / mistyped / absent case that must be exit 2 ("cannot tell"), never an empty list.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import threading
import urllib.parse
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from cliutil import run_cli

ENV = {"SAFO_TOKEN": "t0ken", "SAFO_TOKEN_KIND": "token"}
REPO = "/repos/o/r"
OWNERS = "/.github/CODEOWNERS"
SHA = "a" * 40  # the default branch's head COMMIT
T_ROOT = "e" * 40  # the tree that commit declares (a different object from the commit)
T_DOCS = "f" * 40
T_GH = "b" * 40
T_WF = "c" * 40
BLOB = "d" * 40
GOOD_OWNERS = "/board.yaml @owner\n/.github/CODEOWNERS @owner\n/.github/workflows/ @owner\n"
OWNERS_AT = {  # a file at each location that owns itself, as the check requires of the one GitHub uses
    ".github/CODEOWNERS": GOOD_OWNERS,
    "CODEOWNERS": GOOD_OWNERS + "/CODEOWNERS @owner\n",
    "docs/CODEOWNERS": GOOD_OWNERS + "/docs/CODEOWNERS @owner\n",
}
NOT_PROTECTED = {"message": "Branch not protected"}
Route = tuple[int, dict[str, str], bytes]
Entry = Route | Callable[[], Route]  # a callable is asked on every request: a fake whose answers change
Edit = Callable[[dict[str, Any]], None]


def classic() -> dict[str, Any]:
    return {
        "required_status_checks": {
            "strict": True,
            "contexts": ["ci / CI green"],
            "checks": [{"context": "ci / CI green", "app_id": 15368}],
        },
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": True,
            "require_code_owner_reviews": True,
            "required_approving_review_count": 1,
        },
        "enforce_admins": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
    }


def git_sha(text: str) -> str:
    """The name git gives a file with this content: what a tree entry must carry for the content to be accepted."""
    data = text.encode()
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def contents(text: str, place: str = ".github/CODEOWNERS") -> dict[str, Any]:
    return {
        "type": "file",
        "path": place,
        "sha": git_sha(text),
        "encoding": "base64",
        "content": base64.encodebytes(text.encode()).decode(),
    }


def repo_doc(**over: Any) -> dict[str, Any]:
    return {"id": 42, "full_name": "o/r", "default_branch": "main", **over}


SUBTREES = {".github": T_GH, "workflows": T_WF, "docs": T_DOCS}


def tree(
    sha: str, *rows: tuple[str, str], truncated: Any = False, blobs: dict[str, str] | None = None
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "sha": sha,
        "tree": [
            {
                "path": path,
                "type": kind,
                "sha": SUBTREES.get(path) if kind == "tree" and path in SUBTREES else (blobs or {}).get(path, BLOB),
                "mode": "040000" if kind == "tree" else "100644",
            }
            for path, kind in rows
        ],
    }
    if truncated is not None:
        body["truncated"] = truncated
    return body


WORKFLOWS = (("ci.yml", "blob"), ("sub", "tree"), ("sub/x.yml", "blob"))


def j(body: Any, status: int = 200) -> Route:
    return status, {"Content-Type": "application/json"}, json.dumps(body).encode()


def world(
    owners: str | None = None,
    rows: tuple[tuple[str, str], ...] = WORKFLOWS,
    gh_rows: tuple[tuple[str, str], ...] | None = None,
    place: str = ".github/CODEOWNERS",
) -> dict[str, Route]:
    """A consistent fake repository: commit -> root tree -> .github tree -> workflows tree, CODEOWNERS at `place`."""
    owners = OWNERS_AT[place] if owners is None else owners
    blobs = {"CODEOWNERS": git_sha(owners)}
    gh = (
        gh_rows
        if gh_rows is not None
        else (("workflows", "tree"), *((("CODEOWNERS", "blob"),) if place.startswith(".github") else ()))
    )
    root = [(".github", "tree"), ("board.yaml", "blob")]
    if place == "CODEOWNERS":
        root.append(("CODEOWNERS", "blob"))
    if place == "docs/CODEOWNERS":
        root.append(("docs", "tree"))
    trees = {
        T_ROOT: tree(T_ROOT, *root, blobs=blobs),
        T_GH: tree(T_GH, *gh, blobs=blobs),
        T_WF: tree(T_WF, *rows),
    }
    if place == "docs/CODEOWNERS":
        trees[T_DOCS] = tree(T_DOCS, ("CODEOWNERS", "blob"), blobs=blobs)
    return {
        REPO: j(repo_doc()),
        f"{REPO}/branches/main": j({"name": "main", "commit": {"sha": SHA}}),
        f"{REPO}/git/commits/{SHA}": j({"sha": SHA, "tree": {"sha": T_ROOT}}),
        f"{REPO}/branches/main/protection": j(classic()),
        f"{REPO}/rulesets": j([]),
        f"{REPO}/contents/{place}": j(contents(owners, place)),
        f"{REPO}/codeowners/errors": j({"errors": []}),
        **{f"{REPO}/git/trees/{sha}": j(body) for sha, body in trees.items()},
    }


def good_routes() -> dict[str, Route]:
    return world()


@contextmanager
def serving(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


@contextmanager
def server(
    routes: Mapping[str, Entry], queries: list[tuple[str, str]] | None = None
) -> Iterator[tuple[str, list[tuple[str, str]]]]:
    seen: list[tuple[str, str]] = []

    class Request(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def handle_any(self) -> None:
            path, _, query = self.path.partition("?")
            seen.append((self.command, path))
            if queries is not None:
                queries.append((path, query))
            entry = routes.get(path, j({"message": "Not Found"}, 404))
            status, headers, body = entry() if callable(entry) else entry
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = handle_any

    with serving(Request) as url:
        yield url, seen


def check(
    routes: Mapping[str, Entry], *extra: str, queries: list[tuple[str, str]] | None = None
) -> tuple[int, str, str, list[tuple[str, str]]]:
    with server(routes, queries) as (url, seen):
        code, out, err = run_cli("protection", "--repo", "o/r", "--api-url", url, *extra, env=ENV)
    return code, out, err, seen


def with_classic(edit: Edit) -> dict[str, Route]:
    body = classic()
    edit(body)
    return {**good_routes(), f"{REPO}/branches/main/protection": j(body)}


def with_owners(text: str) -> dict[str, Route]:
    return world(text)


def drop(*keys: str) -> Edit:
    def edit(body: dict[str, Any]) -> None:
        node = body
        for key in keys[:-1]:
            node = node[key]
        del node[keys[-1]]

    return edit


def put(value: Any, *keys: str) -> Edit:
    def edit(body: dict[str, Any]) -> None:
        node = body
        for key in keys[:-1]:
            node = node[key]
        node[keys[-1]] = value

    return edit


def allowances(**lists: Any) -> Edit:
    value = {"users": [], "teams": [], "apps": [], **lists}
    return put(value, "required_pull_request_reviews", "bypass_pull_request_allowances")


def test_fully_protected_exits_zero_and_only_gets() -> None:
    code, out, err, seen = check(good_routes())
    assert (code, err) == (0, "")
    assert "FAIL" not in out and out.count("PASS") == 10
    assert seen and {method for method, _ in seen} == {"GET"}


FAILING: list[tuple[str, dict[str, Route]]] = [
    ("code-owner-review", with_classic(put(False, "required_pull_request_reviews", "require_code_owner_reviews"))),
    ("code-owner-review", with_classic(drop("required_pull_request_reviews"))),
    ("ci-green up-to-date", with_classic(drop("required_status_checks"))),
    ("ci-green", with_classic(put([{"context": "lint", "app_id": 1}], "required_status_checks", "checks"))),
    ("up-to-date", with_classic(put(False, "required_status_checks", "strict"))),
    ("admins-included", with_classic(put({"enabled": False}, "enforce_admins"))),
    ("no-bypass", with_classic(allowances(users=[{"login": "agent"}]))),
    ("no-bypass", with_classic(allowances(teams=[{"slug": "admins"}]))),
    ("no-bypass", with_classic(allowances(apps=[{"slug": "bot"}]))),
    ("no-force-push", with_classic(put({"enabled": True}, "allow_force_pushes"))),
    ("no-deletion", with_classic(put({"enabled": True}, "allow_deletions"))),
    ("codeowners-board-yaml", with_owners("/.github/CODEOWNERS @o\n/.github/workflows/ @o\n")),
    ("codeowners-codeowners-file", with_owners("/board.yaml @o\n/.github/workflows/ @o\n")),
    ("codeowners-workflows", with_owners("/board.yaml @o\n/.github/CODEOWNERS @o\n")),
    ("codeowners-workflows", with_owners(GOOD_OWNERS + "/.github/workflows/*.yml\n")),  # a later rule clears ownership
]


@pytest.mark.parametrize(("condition", "routes"), FAILING)
def test_each_failing_condition_exits_one_and_names_only_itself(condition: str, routes: dict[str, Route]) -> None:
    code, out, _, seen = check(routes)
    assert code == 1, out
    failed = [line for line in out.splitlines() if line.startswith("FAIL")]
    assert [line.split()[1].rstrip(":") for line in failed] == condition.split()
    assert {method for method, _ in seen} == {"GET"}


def test_agent_login_is_named_when_it_holds_a_bypass() -> None:
    code, out, _, _ = check(with_classic(allowances(users=[{"login": "Agent-Bot"}])), "--agent-login", "agent-bot")
    assert code == 1 and "the agent account is among them" in out


def ruleset(**over: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "id": 7,
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [],
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "pull_request", "parameters": {"require_code_owner_review": True}},
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [{"context": "CI green"}],
                },
            },
        ],
    }
    body.update(over)
    return body


def ruleset_routes(detail: Any, listed: dict[str, Any] | None = None) -> dict[str, Route]:
    return {
        **good_routes(),
        f"{REPO}/branches/main/protection": j(NOT_PROTECTED, 404),
        f"{REPO}/rulesets": j([listed or {"id": 7, "target": "branch", "enforcement": "active"}]),
        f"{REPO}/rulesets/7": j(detail),
    }


def test_a_ruleset_alone_can_satisfy_every_condition() -> None:
    code, out, _, seen = check(ruleset_routes(ruleset()))
    assert code == 0, out
    assert {method for method, _ in seen} == {"GET"}


def test_a_merge_queue_counts_as_up_to_date() -> None:
    detail = ruleset()
    detail["rules"][3]["parameters"]["strict_required_status_checks_policy"] = False
    detail["rules"].append({"type": "merge_queue", "parameters": {}})
    assert check(ruleset_routes(detail))[0] == 0


def test_a_ruleset_without_the_up_to_date_requirement_fails_it() -> None:
    detail = ruleset()
    detail["rules"][3]["parameters"]["strict_required_status_checks_policy"] = False
    code, out, _, _ = check(ruleset_routes(detail))
    assert code == 1 and "FAIL up-to-date" in out


def test_a_ruleset_without_force_push_and_deletion_rules_fails_both() -> None:
    detail = ruleset()
    detail["rules"] = detail["rules"][2:]
    code, out, _, _ = check(ruleset_routes(detail))
    assert code == 1 and "FAIL no-force-push" in out and "FAIL no-deletion" in out


def test_a_ruleset_bypass_actor_fails_no_bypass_and_admins() -> None:
    detail = ruleset(bypass_actors=[{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}])
    code, out, _, _ = check(ruleset_routes(detail))
    assert code == 1 and "FAIL no-bypass" in out and "FAIL admins-included" in out


@pytest.mark.parametrize("over", [{"enforcement": "disabled"}, {"enforcement": "evaluate"}, {"target": "tag"}], ids=str)
def test_a_ruleset_that_does_not_enforce_does_not_count(over: dict[str, Any]) -> None:
    listed = {"id": 7, "target": "branch", "enforcement": "active", **over}
    code, out, _, _ = check(ruleset_routes(ruleset(**over), listed))
    assert code == 1 and "FAIL code-owner-review" in out


def test_a_ruleset_excluding_the_default_branch_does_not_count() -> None:
    detail = ruleset(conditions={"ref_name": {"include": ["~ALL"], "exclude": ["~DEFAULT_BRANCH"]}})
    assert check(ruleset_routes(detail))[0] == 1


def test_a_ruleset_for_another_branch_does_not_count() -> None:
    detail = ruleset(conditions={"ref_name": {"include": ["refs/heads/other"], "exclude": []}})
    assert check(ruleset_routes(detail))[0] == 1


def test_unprotected_repository_exits_one() -> None:
    routes = {**good_routes(), f"{REPO}/branches/main/protection": j(NOT_PROTECTED, 404)}
    code, out, _, _ = check(routes)
    assert code == 1 and "not protected" in out
    for condition in ("code-owner-review", "ci-green", "up-to-date", "admins-included"):
        assert f"FAIL {condition}" in out


def test_unprotected_with_no_codeowners_exits_one() -> None:
    routes = {**world(gh_rows=(("workflows", "tree"),)), f"{REPO}/branches/main/protection": j(NOT_PROTECTED, 404)}
    code, out, _, seen = check(routes)
    assert code == 1 and "FAIL codeowners-board-yaml" in out and "FAIL codeowners-workflows" in out
    assert not any(path.endswith((T_WF,)) or "codeowners/errors" in path or "/contents/" in path for _, path in seen)


def cannot_tell(routes: Mapping[str, Entry]) -> None:
    code, out, err, seen = check(routes)
    assert code == 2, (out, err)
    assert "PASS" not in out  # nothing is reported as holding when the answer is unreadable
    assert "cannot tell" in out + err
    assert {method for method, _ in seen} == {"GET"}


def test_unparsable_response_is_cannot_tell() -> None:
    cannot_tell({**good_routes(), f"{REPO}/branches/main/protection": (200, {}, b"<html>not json")})


@pytest.mark.parametrize(
    "answer",
    [
        j({"message": "Resource not accessible"}, 403),
        (403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1"}, b"{}"),
        (429, {"Retry-After": "60"}, b"{}"),
        j({"message": "boom"}, 500),
        j({"message": "Not Found"}, 404),  # not "Branch not protected": the token may simply not see the repository
        j({"message": "branch not protected"}, 404),
        (301, {"Location": "http://127.0.0.1:1/x"}, b""),
        j([]),
        j(None),
        j("protected"),
    ],
    ids=str,
)
def test_error_answers_for_the_protection_read_are_cannot_tell(answer: Route) -> None:
    cannot_tell({**good_routes(), f"{REPO}/branches/main/protection": answer})


ALL_READS = [
    REPO,
    f"{REPO}/branches/main",
    f"{REPO}/branches/main/protection",
    f"{REPO}/rulesets",
    f"{REPO}/contents{OWNERS}",
    f"{REPO}/codeowners/errors",
    f"{REPO}/git/commits/{SHA}",
    f"{REPO}/git/trees/{T_ROOT}",
    f"{REPO}/git/trees/{T_GH}",
    f"{REPO}/git/trees/{T_WF}",
]


@pytest.mark.parametrize("route", ALL_READS)
def test_error_answers_anywhere_are_cannot_tell(route: str) -> None:
    cannot_tell({**good_routes(), route: j({"message": "Forbidden"}, 403)})


def test_a_duplicate_key_is_cannot_tell() -> None:
    good = json.dumps(classic())  # a complete, passing answer in which enforce_admins is then repeated
    body = ('{"enforce_admins": {"enabled": false}, ' + good[1:]).encode()
    cannot_tell({**good_routes(), f"{REPO}/branches/main/protection": (200, {}, body)})


@pytest.mark.parametrize("status", [201, 202, 403, 404, 500])
@pytest.mark.parametrize("route", ALL_READS)
def test_only_200_and_404_are_read_even_with_a_good_looking_body(route: str, status: int) -> None:
    body = good_routes()[route][2]
    cannot_tell({**good_routes(), route: (status, {}, body)})


def test_a_redirect_is_not_followed_to_a_good_answer() -> None:
    routes = good_routes()
    good = routes[f"{REPO}/branches/main/protection"]
    routes["/elsewhere"] = good
    routes[f"{REPO}/branches/main/protection"] = (302, {"Location": "/elsewhere"}, b"")
    cannot_tell(routes)


def test_codeowners_404_with_another_message_is_cannot_tell() -> None:
    cannot_tell({**good_routes(), f"{REPO}/contents{OWNERS}": j({"message": "Repository access blocked"}, 404)})


def test_a_branch_name_with_dot_dot_is_never_put_in_a_request() -> None:
    routes = {**good_routes(), REPO: j(repo_doc(default_branch="a/../b"))}
    with server(routes) as (url, seen):
        code, _, _ = run_cli("protection", "--repo", "o/r", "--api-url", url, env=ENV)
    assert code == 2 and seen == [("GET", REPO)]


BAD_FIELDS: list[tuple[str, Edit]] = [
    ("enforce_admins missing", drop("enforce_admins")),
    ("enforce_admins null", put(None, "enforce_admins")),
    ("enforce_admins.enabled string", put("true", "enforce_admins", "enabled")),
    ("enforce_admins.enabled missing", drop("enforce_admins", "enabled")),
    ("enforce_admins.enabled null", put(None, "enforce_admins", "enabled")),
    ("allow_force_pushes missing", drop("allow_force_pushes")),
    ("allow_force_pushes.enabled int", put(0, "allow_force_pushes", "enabled")),
    ("allow_deletions null", put(None, "allow_deletions")),
    ("allow_deletions.enabled string", put("false", "allow_deletions", "enabled")),
    ("strict missing", drop("required_status_checks", "strict")),
    ("strict string", put("true", "required_status_checks", "strict")),
    ("checks null", put(None, "required_status_checks", "checks")),
    ("checks missing", drop("required_status_checks", "checks")),
    ("checks dict", put({}, "required_status_checks", "checks")),
    ("checks entry null", put([None], "required_status_checks", "checks")),
    ("checks entry no context", put([{"app_id": 1}], "required_status_checks", "checks")),
    ("checks context int", put([{"context": 5}], "required_status_checks", "checks")),
    ("contexts null", put(None, "required_status_checks", "contexts")),
    ("required_status_checks null", put(None, "required_status_checks")),
    ("required_status_checks list", put([], "required_status_checks")),
    ("required_pull_request_reviews null", put(None, "required_pull_request_reviews")),
    ("codeowner flag string", put("yes", "required_pull_request_reviews", "require_code_owner_reviews")),
    ("codeowner flag null", put(None, "required_pull_request_reviews", "require_code_owner_reviews")),
    ("codeowner flag missing", drop("required_pull_request_reviews", "require_code_owner_reviews")),
    ("bypass null", put(None, "required_pull_request_reviews", "bypass_pull_request_allowances")),
    ("bypass users null", allowances(users=None)),
    (
        "bypass teams missing",
        put({"users": [], "apps": []}, "required_pull_request_reviews", "bypass_pull_request_allowances"),
    ),
    ("bypass apps string", allowances(apps="none")),
    ("bypass user without login", allowances(users=[{}])),
    ("bypass user null", allowances(users=[None])),
    ("bypass team slug int", allowances(teams=[{"slug": 1}])),
]


@pytest.mark.parametrize("edit", [e for _, e in BAD_FIELDS], ids=[n for n, _ in BAD_FIELDS])
def test_a_null_absent_or_mistyped_field_is_cannot_tell(edit: Edit) -> None:
    cannot_tell(with_classic(edit))


BAD_RULESETS: list[tuple[str, Edit]] = [
    ("bypass_actors null", lambda d: d.update(bypass_actors=None)),
    ("bypass_actors missing", lambda d: d.pop("bypass_actors")),
    ("bypass_actors dict", lambda d: d.update(bypass_actors={})),
    ("bypass entry null", lambda d: d.update(bypass_actors=[None])),
    ("rules null", lambda d: d.update(rules=None)),
    ("rules missing", lambda d: d.pop("rules")),
    ("rule null", lambda d: d.update(rules=[None])),
    ("rule type int", lambda d: d.update(rules=[{"type": 3}])),
    ("pull_request parameters null", lambda d: d["rules"][2].update(parameters=None)),
    ("pull_request flag string", lambda d: d["rules"][2]["parameters"].update(require_code_owner_review="true")),
    ("pull_request flag missing", lambda d: d["rules"][2]["parameters"].pop("require_code_owner_review")),
    ("strict policy null", lambda d: d["rules"][3]["parameters"].update(strict_required_status_checks_policy=None)),
    ("status checks null", lambda d: d["rules"][3]["parameters"].update(required_status_checks=None)),
    ("status check entry no context", lambda d: d["rules"][3]["parameters"].update(required_status_checks=[{}])),
    ("conditions null", lambda d: d.update(conditions=None)),
    ("ref_name missing", lambda d: d.update(conditions={})),
    ("include null", lambda d: d["conditions"]["ref_name"].update(include=None)),
    ("exclude null", lambda d: d["conditions"]["ref_name"].update(exclude=None)),
    ("include entry int", lambda d: d["conditions"]["ref_name"].update(include=[1])),
    ("exclude glob", lambda d: d["conditions"]["ref_name"].update(exclude=["refs/heads/rel*"])),
    ("enforcement int", lambda d: d.update(enforcement=1)),
    ("target missing", lambda d: d.pop("target")),
]


@pytest.mark.parametrize("edit", [e for _, e in BAD_RULESETS], ids=[n for n, _ in BAD_RULESETS])
def test_a_bad_ruleset_field_is_cannot_tell(edit: Edit) -> None:
    detail = ruleset()
    edit(detail)
    cannot_tell(ruleset_routes(detail))


@pytest.mark.parametrize(
    "listing",
    [
        None,
        {},
        [None],
        [{}],
        [{"id": "7", "target": "branch", "enforcement": "active"}],
        [{"id": True, "target": "branch", "enforcement": "active"}],
    ],
    ids=str,
)
def test_a_bad_ruleset_listing_is_cannot_tell(listing: Any) -> None:
    routes = ruleset_routes(ruleset())
    routes[f"{REPO}/rulesets"] = j(listing)
    cannot_tell(routes)


def test_a_non_numeric_ruleset_id_is_never_put_in_a_request() -> None:
    routes = ruleset_routes(ruleset())
    routes[f"{REPO}/rulesets"] = j([{"id": "7/x", "target": "branch", "enforcement": "active"}])
    with server(routes) as (url, seen):
        code, _, _ = run_cli("protection", "--repo", "o/r", "--api-url", url, env=ENV)
    assert code == 2 and not any("7/x" in path for _, path in seen)


def test_a_full_ruleset_page_is_cannot_tell() -> None:
    routes = ruleset_routes(ruleset())
    routes[f"{REPO}/rulesets"] = j([{"id": n, "target": "tag", "enforcement": "disabled"} for n in range(100)])
    cannot_tell(routes)


@pytest.mark.parametrize(
    "answer",
    [
        j(repo_doc(default_branch=None)),
        j(repo_doc(default_branch="")),
        j(repo_doc(default_branch=5)),
        j(repo_doc(default_branch="../x")),
        j({}),
    ],
    ids=str,
)
def test_a_bad_default_branch_is_cannot_tell(answer: Route) -> None:
    cannot_tell({**good_routes(), REPO: answer})


@pytest.mark.parametrize(
    "answer",
    [
        j(["x"]),
        j({"type": "dir", "encoding": "base64", "content": ""}),
        j({"type": "file", "encoding": "none", "content": ""}),
        j({"type": "file", "encoding": "base64", "content": None}),
        j({"type": "file", "encoding": "base64", "content": "!!!"}),
        j({"type": "file", "encoding": "base64", "content": base64.b64encode(b"\xff\xfe").decode()}),
        j({"type": "file", "encoding": "base64", "content": base64.b64encode(b"/x[a] @o\n").decode()}),
    ],
    ids=str,
)
def test_a_bad_codeowners_answer_is_cannot_tell(answer: Route) -> None:
    cannot_tell({**good_routes(), f"{REPO}/contents{OWNERS}": answer})


def test_codeowners_is_read_from_the_first_location_that_exists() -> None:
    assert check(world(place="CODEOWNERS"))[0] == 0
    assert check(world(place="docs/CODEOWNERS"))[0] == 0


@pytest.mark.parametrize("place", ["CODEOWNERS", "docs/CODEOWNERS"])
def test_the_file_in_use_must_cover_itself_not_only_the_github_directory_one(place: str) -> None:
    """Only `.github/CODEOWNERS` is owned, but the file GitHub uses is `place`: nothing covers it."""
    code, out, _, _ = check(world(GOOD_OWNERS, place=place))
    assert code == 1 and failed_ids(out) == ["codeowners-codeowners-file"]
    assert f"CODEOWNERS covers {place}" in out


def test_the_agent_login_must_be_a_login() -> None:
    code, _, err, seen = check(good_routes(), "--agent-login=--evil")
    assert code == 2 and seen == [] and "login" in err


@pytest.mark.parametrize("repo", ["o", "o/r/x", "o/ r", "../r", "o/.."])
def test_the_repo_must_be_owner_slash_name(repo: str) -> None:
    with server(good_routes()) as (url, seen):
        code, _, err = run_cli("protection", "--repo", repo, "--api-url", url, env=ENV)
    assert code == 2 and seen == [] and "owner/name" in err


def test_no_token_is_exit_two_and_sends_nothing() -> None:
    with server(good_routes()) as (url, seen):
        code, _, err = run_cli("protection", "--repo", "o/r", "--api-url", url, env={})
    assert code == 2 and seen == [] and "token" in err


def test_a_plain_http_url_is_refused_unless_loopback() -> None:
    code, _, err = run_cli("protection", "--repo", "o/r", "--api-url", "http://example.invalid", env=ENV)
    assert code == 2 and "https" in err


GH_ENV = {"SAFO_TOKEN": "t0ken", "SAFO_TOKEN_KIND": "gh"}


def refused_url(err: str) -> urllib.parse.SplitResult:
    """The URL the refusal says a gh token is sent to, parsed (never matched as a substring)."""
    match = re.fullmatch(r"error: a gh token is only sent to (\S+); --api-url cannot redirect it\n", err)
    assert match, err
    return urllib.parse.urlsplit(match.group(1))


def test_a_gh_token_is_only_sent_to_api_github_com() -> None:
    with server(good_routes()) as (url, seen):
        code, _, err = run_cli("protection", "--repo", "o/r", "--api-url", url, env=GH_ENV)
    assert code == 2 and seen == []
    target = refused_url(err)
    assert (target.scheme, target.hostname, target.port, target.username, target.path) == (
        "https",
        "api.github.com",
        None,
        None,
        "",
    )


@pytest.mark.parametrize(
    "lookalike",
    [
        "https://api.github.com.evil.example",
        "https://evil.example/api.github.com",
        "https://api.github.com@evil.example",
        "https://evil.example@api.github.com",
        "https://api.github.com:8443",
        "https://API.GITHUB.COM",
        "https://api.github.com/",
        "https://api.github.com/repos",
        "http://api.github.com",
        "https://evil.example/?h=api.github.com",
        "https://evil.example#api.github.com",
    ],
)
def test_a_gh_token_is_not_sent_to_a_lookalike_host(lookalike: str) -> None:
    # nothing listens on these names and the suite allows loopback only: a request would raise, not return
    code, out, err = run_cli("protection", "--repo", "o/r", "--api-url", lookalike, env=GH_ENV)
    assert code == 2 and out == ""
    assert refused_url(err).hostname == "api.github.com"


def test_the_token_is_sent_as_a_bearer_header_and_never_printed() -> None:
    got: list[str] = []

    class Spy(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:
            got.append(self.headers.get("Authorization", ""))
            self.send_response(403)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

    with serving(Spy) as url:
        code, out, err = run_cli("protection", "--repo", "o/r", "--api-url", url, env=ENV)
    assert code == 2 and got == ["Bearer t0ken"] and "t0ken" not in out + err


def test_github_text_is_never_echoed() -> None:
    hostile = "::error::pwned\n::add-mask::x"
    code, out, err, _ = check(with_classic(put([{"context": hostile}], "required_status_checks", "checks")))
    assert code == 1 and "pwned" not in out + err


UNPINNED = "required check is not pinned to an app (any source can satisfy it)"


def checks_with(entry: dict[str, Any]) -> dict[str, Route]:
    return with_classic(put([{"context": "ci / CI green", **entry}], "required_status_checks", "checks"))


def test_a_pinned_check_prints_no_note() -> None:
    code, out, _, _ = check(good_routes())
    assert code == 0 and "NOTE" not in out and "matched: ci / CI green" in out


@pytest.mark.parametrize("entry", [{}, {"app_id": None}, {"app_id": -1}], ids=str)
def test_an_unpinned_check_passes_by_default_with_a_note(entry: dict[str, Any]) -> None:
    code, out, _, _ = check(checks_with(entry))
    assert code == 0 and "NOTE ci-green" in out and UNPINNED in out


def test_a_check_pinned_to_another_app_passes_by_default_with_a_note() -> None:
    code, out, _, _ = check(checks_with({"app_id": 99}))
    assert code == 0 and "NOTE ci-green" in out and "not the expected app 15368" in out


@pytest.mark.parametrize(
    ("entry", "flag", "code"),
    [
        ({}, "15368", 1),
        ({"app_id": -1}, "15368", 1),
        ({"app_id": 99}, "15368", 1),
        ({"app_id": 15368}, "99", 1),
        ({"app_id": 15368}, "15368", 0),
        ({"app_id": 99}, "99", 0),
    ],
    ids=str,
)
def test_require_app_id_makes_the_pin_a_condition(entry: dict[str, Any], flag: str, code: int) -> None:
    got, out, _, _ = check(checks_with(entry), "--require-app-id", flag)
    assert got == code, out
    failed = [line.split()[1].rstrip(":") for line in out.splitlines() if line.startswith("FAIL")]
    assert failed == (["ci-green"] if code else [])
    assert ("NOTE" in out) == bool(code)


def test_every_matching_check_must_be_pinned_under_the_flag() -> None:
    checks = [{"context": "ci / CI green", "app_id": 15368}, {"context": "shell / CI green"}]
    routes = with_classic(put(checks, "required_status_checks", "checks"))
    assert check(routes)[0] == 0 and "NOTE" in check(routes)[1]
    assert check(routes, "--require-app-id", "15368")[0] == 1


@pytest.mark.parametrize("value", ["15368", True, 0, -2, 1.5, [], {}, "-1"], ids=repr)
def test_a_bad_app_id_type_is_cannot_tell(value: Any) -> None:
    cannot_tell(checks_with({"app_id": value}))


@pytest.mark.parametrize("value", ["15368", True, 0, -2, 1.5, []], ids=repr)
def test_a_bad_integration_id_type_is_cannot_tell(value: Any) -> None:
    detail = ruleset()
    detail["rules"][3]["parameters"]["required_status_checks"] = [{"context": "CI green", "integration_id": value}]
    cannot_tell(ruleset_routes(detail))


def test_a_ruleset_check_pin_is_read_from_integration_id() -> None:
    detail = ruleset()
    detail["rules"][3]["parameters"]["required_status_checks"] = [{"context": "CI green", "integration_id": 15368}]
    code, out, _, _ = check(ruleset_routes(detail), "--require-app-id", "15368")
    assert code == 0 and "NOTE" not in out
    detail["rules"][3]["parameters"]["required_status_checks"] = [{"context": "CI green"}]
    code, out, _, _ = check(ruleset_routes(detail))
    assert code == 0 and UNPINNED in out
    assert check(ruleset_routes(detail), "--require-app-id", "15368")[0] == 1


@pytest.mark.parametrize(
    "context",
    [
        "a / b / CI green",
        "x\n / CI green",
        "x\x07 / CI green",
        " / CI green",
        "xCI green",
        "CI green ",
        "ci/CI green",
        "ci /CI green",
        "ci / CI green / x",
        " a / CI green",
        "a  / CI green",
        "CI  green",
        "ci / ci green",
    ],
    ids=repr,
)
def test_lookalike_contexts_do_not_satisfy_ci_green(context: str) -> None:
    code, out, _, _ = check(
        with_classic(put([{"context": context, "app_id": 15368}], "required_status_checks", "checks"))
    )
    assert code == 1 and "FAIL ci-green" in out


@pytest.mark.parametrize("context", ["CI green", "ci / CI green", "My workflow / CI green"])
def test_the_exact_name_and_one_prefix_segment_match(context: str) -> None:
    code, out, _, _ = check(
        with_classic(put([{"context": context, "app_id": 15368}], "required_status_checks", "checks"))
    )
    assert code == 0 and f"matched: {context}" in out


@pytest.mark.parametrize("value", ["0", "-1", "abc", "1.5", " 5", "5\n", "9" * 30])
def test_a_bad_require_app_id_value_is_exit_two(value: str) -> None:
    code, _, err, seen = check(good_routes(), "--require-app-id=" + value)
    assert code == 2 and seen == [] and "app id" in err


def test_the_client_can_only_issue_get() -> None:
    from safo import protection

    assert protection.METHODS == ("GET",)


# ---- round 2: the real workflow tree, owners GitHub accepts, a stable default branch, bound responses --------------


def with_workflows(*rows: tuple[str, str], gh: tuple[tuple[str, str], ...] | None = None) -> dict[str, Route]:
    return world(rows=rows, gh_rows=gh)


PROBES_ONLY = (
    "/board.yaml @o\n/.github/CODEOWNERS @o\n"
    "/.github/workflows/probe.yml @o\n/.github/workflows/probe.yaml @o\n/.github/workflows/probe.md @o\n"
    "/.github/workflows/probe @o\n/.github/workflows/sub/probe.yml @o\n"
)


def failed_ids(out: str) -> list[str]:
    return [line.split()[1].rstrip(":") for line in out.splitlines() if line.startswith("FAIL")]


def test_owning_only_the_old_probe_names_leaves_a_real_workflow_unowned() -> None:
    routes = world(PROBES_ONLY, (("release.yml", "blob"),))
    code, out, _, _ = check(routes)
    assert code == 1 and failed_ids(out) == ["codeowners-workflows"]


def test_a_directory_rule_covers_every_real_file_including_nested_ones() -> None:
    assert check(with_workflows(("a.yml", "blob"), ("d", "tree"), ("d/deep", "tree"), ("d/deep/b.yml", "blob")))[0] == 0


def test_a_shallow_glob_leaves_a_nested_workflow_unowned() -> None:
    code, out, _, _ = check(world(GOOD_OWNERS.replace("workflows/ ", "workflows/*.yml ")))
    assert code == 1 and failed_ids(out) == ["codeowners-workflows"]


def test_a_later_rule_without_an_owner_overrides_an_earlier_owner_for_one_real_file() -> None:
    routes = with_owners(GOOD_OWNERS + "/.github/workflows/ci.yml\n")
    code, out, _, _ = check(routes)
    assert code == 1 and failed_ids(out) == ["codeowners-workflows"]


def test_a_later_rule_that_restores_an_owner_wins() -> None:
    assert (
        check(
            with_owners(
                GOOD_OWNERS.replace(
                    "/.github/workflows/ @owner", "/.github/workflows/ci.yml\n/.github/workflows/ @owner"
                )
            )
        )[0]
        == 0
    )


def test_the_workflow_tree_is_walked_level_by_level_and_only_the_last_is_recursive() -> None:
    queries: list[tuple[str, str]] = []
    assert check(good_routes(), queries=queries)[0] == 0
    trees = [(path.rsplit("/", 1)[1], query) for path, query in queries if "/git/trees/" in path]
    assert trees == [(T_ROOT, ""), (T_GH, ""), (T_WF, "recursive=1")] * 2  # two passes


@pytest.mark.parametrize("sha", [T_ROOT, T_GH, T_WF])
@pytest.mark.parametrize("truncated", [True, None, "false", 0], ids=repr)
def test_a_truncated_or_unlabelled_tree_is_cannot_tell(sha: str, truncated: Any) -> None:
    rows = {T_ROOT: ((".github", "tree"),), T_GH: (("workflows", "tree"),), T_WF: WORKFLOWS}[sha]
    cannot_tell({**good_routes(), f"{REPO}/git/trees/{sha}": j(tree(sha, *rows, truncated=truncated))})


NO_WORKFLOWS_DIR = (("CODEOWNERS", "blob"),)
FILE_OWNERS = "/board.yaml @o\n/.github/CODEOWNERS @o\n/.github/workflows/ci.yml @o\n"


def test_a_file_specific_owner_leaves_a_new_workflow_unowned() -> None:
    routes = world(FILE_OWNERS, (("ci.yml", "blob"),))
    code, out, _, _ = check(routes)
    assert code == 1 and failed_ids(out) == ["codeowners-workflows"]  # ci.yml itself is owned; release.yml would not be


def test_an_empty_workflows_directory_without_a_directory_rule_fails() -> None:
    routes = world(FILE_OWNERS, ())
    code, out, _, _ = check(routes)
    assert code == 1 and failed_ids(out) == ["codeowners-workflows"]


def test_an_absent_workflows_directory_without_a_directory_rule_fails() -> None:
    routes = world(FILE_OWNERS, (), NO_WORKFLOWS_DIR)
    code, out, _, _ = check(routes)
    assert code == 1 and failed_ids(out) == ["codeowners-workflows"]


def test_an_empty_or_absent_workflows_directory_with_a_directory_rule_passes() -> None:
    assert check(with_workflows())[0] == 0
    assert check(with_workflows(gh=NO_WORKFLOWS_DIR))[0] == 0


def test_a_glob_that_owns_only_some_new_names_fails() -> None:
    for glob in ("*.yml", "*.yaml"):
        text = GOOD_OWNERS.replace("/.github/workflows/ @owner", f"/.github/workflows/{glob} @owner")
        assert check(world(text, (("ci.yml", "blob"),)))[0] == 1


def seeded(seed: int) -> Callable[[], str]:
    import hashlib
    import itertools

    count = itertools.count()
    return lambda: hashlib.sha256(f"{seed}-{next(count)}".encode()).hexdigest()[:16]


def owning_exactly(seed: int) -> str:
    """A CODEOWNERS file written by someone who knows the fresh names of the run with this seed, and nothing else."""
    from safo import protection

    saved = protection.fresh_token
    protection.fresh_token = seeded(seed)
    try:
        names = protection.fresh_workflow_paths()
    finally:
        protection.fresh_token = saved
    return "/board.yaml @o\n/.github/CODEOWNERS @o\n" + "".join(f"/{name} @o\n" for name in names)


def test_a_rule_file_written_for_the_fresh_names_of_one_run_cannot_pass_another(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from safo import protection

    routes = world(owning_exactly(1), ())
    monkeypatch.setattr(protection, "directory_wide_owned", lambda rules: True)  # the sampling layer on its own
    monkeypatch.setattr(protection, "fresh_token", seeded(1))
    assert check(routes)[0] == 0  # proof that a fixed probe set WOULD be fooled by an engineered file
    monkeypatch.setattr(protection, "fresh_token", seeded(2))
    code, out, _, _ = check(routes)
    assert code == 1 and failed_ids(out) == ["codeowners-workflows"]


def test_sampling_alone_cannot_tell_an_engineered_file_from_a_directory_rule(monkeypatch: pytest.MonkeyPatch) -> None:
    """Under the run the file was written for, the sampled names all pass; only the structural proof fails it."""
    from safo import protection
    from safo.codeowners import covered, parse_rules

    routes = world(owning_exactly(1), ())
    monkeypatch.setattr(protection, "fresh_token", seeded(1))
    code, out, _, _ = check(routes)
    assert code == 1 and failed_ids(out) == ["codeowners-workflows"]
    monkeypatch.setattr(protection, "fresh_token", seeded(1))
    rules = parse_rules(owning_exactly(1))
    assert protection.directory_wide_owned(rules) is False
    assert all(covered(rules, x) for x in _sampled(1))


def _sampled(seed: int) -> list[str]:
    from safo import protection

    saved = protection.fresh_token
    protection.fresh_token = seeded(seed)
    try:
        return protection.fresh_workflow_paths()
    finally:
        protection.fresh_token = saved


def test_the_real_file_check_stands_on_its_own(monkeypatch: pytest.MonkeyPatch) -> None:
    from safo import protection

    monkeypatch.setattr(protection, "directory_wide_owned", lambda rules: True)
    monkeypatch.setattr(protection, "fresh_workflow_paths", lambda: [])
    code, out, _, _ = check(with_owners(GOOD_OWNERS + "/.github/workflows/ci.yml\n"))
    assert code == 1 and failed_ids(out) == ["codeowners-workflows"]


def test_the_random_tokens_are_not_hexadecimal_and_start_anywhere() -> None:
    from safo.protection import _random_token

    tokens = [_random_token() for _ in range(600)]
    assert all(6 <= len(t) <= 24 for t in tokens)
    assert all(set(t) <= set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") for t in tokens)
    assert all(any(c.isalnum() for c in t) and t not in (".", "..") for t in tokens)
    firsts = {t[0] for t in tokens}
    assert {"."} <= firsts and any(c.isdigit() for c in firsts) and any(c.isupper() for c in firsts) and "-" in firsts
    assert sum(1 for t in tokens if set(t) <= set("0123456789abcdef")) < 3  # a hex-only token is the rare accident
    assert sum(1 for t in tokens if t.islower() and t.isalpha()) < 3


def test_class_patterns_that_would_own_every_hex_or_lowercase_probe_cannot_pass() -> None:
    import re

    from safo import protection
    from safo.codeowners import Rule

    for body in ("[0-9a-f]*", "[a-z]*", "[a-z0-9]*"):
        pattern = f"/.github/workflows/{body}"
        rule = Rule(re.compile(r"\.github/workflows/" + body.replace("*", ".*")), True, pattern)
        conditions = protection.evaluate([], [rule], workflows=[])
        assert [c.ok for c in conditions if c.id == "codeowners-workflows"] == [False], body


@pytest.mark.parametrize("body", ["[0-9a-f]*", "[a-z]*"])
def test_a_class_pattern_in_a_codeowners_file_is_cannot_tell_never_a_pass(body: str) -> None:
    cannot_tell(with_owners(HEAD_OWNERS + f"/.github/workflows/{body} @o\n"))


HEAD_OWNERS = "/board.yaml @o\n/.github/CODEOWNERS @o\n"


def test_the_default_fresh_names_differ_on_every_run() -> None:
    from safo.protection import fresh_workflow_paths

    first, second = fresh_workflow_paths(), fresh_workflow_paths()
    assert first != second and len(first) == len(set(first)) == 21
    assert all(p.startswith(".github/workflows/") for p in first)
    assert {p.count("/") for p in first} == {2, 3, 4}  # flat, one deep and two deep
    assert len({p.split("/")[2][:2] for p in first}) > 8  # no fixed prefix a rule could own
    assert not any(p.split("/")[2].startswith(("zz", "probe")) for p in first)
    assert any(p.endswith(".yml") for p in first) and any(p.endswith(".yaml") for p in first)


@pytest.mark.parametrize(
    "routes",
    [
        {f"{REPO}/git/trees/{T_GH}": j(tree(T_GH, ("workflows", "blob"), ("CODEOWNERS", "blob")))},
        {f"{REPO}/git/trees/{T_ROOT}": j(tree(T_ROOT, (".github", "blob")))},
        {f"{REPO}/git/trees/{T_WF}": j(tree("9" * 40, *WORKFLOWS))},  # the tree answered is not the one asked for
        {f"{REPO}/git/trees/{T_WF}": j(tree(T_WF, ("x.yml", "symlink")))},
        {f"{REPO}/git/trees/{T_WF}": j(tree(T_WF, ("", "blob")))},
        {f"{REPO}/git/trees/{T_WF}": j(tree(T_WF, ("/abs.yml", "blob")))},
        {f"{REPO}/git/trees/{T_WF}": j(tree(T_WF, ("a\nb.yml", "blob")))},
        {f"{REPO}/git/trees/{T_WF}": j({"sha": T_WF, "truncated": False, "tree": None})},
        {f"{REPO}/git/trees/{T_WF}": j({"sha": T_WF, "truncated": False, "tree": [None]})},
        {f"{REPO}/git/trees/{T_WF}": j({"sha": T_WF, "truncated": False, "tree": [{"path": "a", "type": "blob"}]})},
    ],
    ids=range(10),
)
def test_a_tree_that_is_not_what_was_asked_for_is_cannot_tell(routes: dict[str, Route]) -> None:
    cannot_tell({**good_routes(), **routes})


# -- owners ---------------------------------------------------------------------------------------------------------


def errors_for(*lines: int, path: str = ".github/CODEOWNERS") -> Route:
    return j(
        {"errors": [{"line": n, "column": 1, "kind": "Unknown owner", "path": path, "message": "x"} for n in lines]}
    )


NO_SUCH_USER = "/board.yaml @definitely-no-such-user\n/.github/CODEOWNERS @owner\n/.github/workflows/ @owner\n"


def test_an_owner_github_reports_an_error_on_does_not_count() -> None:
    routes = {**with_owners(NO_SUCH_USER), f"{REPO}/codeowners/errors": errors_for(1)}
    code, out, _, _ = check(routes)
    assert code == 1 and failed_ids(out) == ["codeowners-board-yaml"] and "treated as unowned" in out


def test_the_same_file_with_no_error_from_github_is_accepted() -> None:
    assert check(with_owners(NO_SUCH_USER))[0] == 0  # a well-formed handle is GitHub's to judge, through the endpoint


def test_an_error_on_a_line_hides_only_that_line() -> None:
    routes = {**with_owners("* @owner\n/board.yaml @ghost\n"), f"{REPO}/codeowners/errors": errors_for(2)}
    code, out, _, _ = check(routes)
    assert code == 1 and failed_ids(out) == ["codeowners-board-yaml"]


def test_errors_are_read_at_the_commit_that_was_read() -> None:
    queries: list[tuple[str, str]] = []
    check(good_routes(), queries=queries)
    assert (f"{REPO}/codeowners/errors", f"ref={SHA}") in queries
    assert (f"{REPO}/contents{OWNERS}", f"ref={SHA}") in queries


@pytest.mark.parametrize("handle", ["@foo-", "@-foo", "@a--b", "@" + "a" * 40, "@o/", "@o/ x", "@", "@o/-", "a@b"])
def test_a_handle_that_cannot_be_a_github_name_does_not_count(handle: str) -> None:
    code, out, _, _ = check(with_owners(GOOD_OWNERS.replace("/board.yaml @owner", f"/board.yaml {handle}")))
    assert code == 1 and failed_ids(out) == ["codeowners-board-yaml"]


@pytest.mark.parametrize("handle", ["@o", "@a-b", "@" + "a" * 39, "@org/team-1", "@org/Team_x.y", "dev@example.com"])
def test_a_well_formed_owner_counts(handle: str) -> None:
    assert check(with_owners(GOOD_OWNERS.replace("@owner", handle)))[0] == 0


def test_one_bad_owner_among_good_ones_makes_the_line_unowned() -> None:
    code, out, _, _ = check(with_owners(GOOD_OWNERS.replace("/board.yaml @owner", "/board.yaml @owner @bad-")))
    assert code == 1 and failed_ids(out) == ["codeowners-board-yaml"]


@pytest.mark.parametrize(
    "answer",
    [
        j({"message": "Forbidden"}, 403),
        j({"message": "Not Found"}, 404),
        j({"errors": []}, 500),
        j({"errors": None}),
        j({}),
        j([]),
        j({"errors": [None]}),
        j({"errors": [{"path": ".github/CODEOWNERS"}]}),
        j({"errors": [{"line": "1", "path": ".github/CODEOWNERS"}]}),
        j({"errors": [{"line": 0, "path": ".github/CODEOWNERS"}]}),
        j({"errors": [{"line": True, "path": ".github/CODEOWNERS"}]}),
        j({"errors": [{"line": 1}]}),
        j({"errors": [{"line": 1, "path": 7}]}),
        (200, {"Link": '<http://x/?page=2>; rel="next"'}, b'{"errors": []}'),
    ],
    ids=range(14),
)
def test_unreadable_codeowners_errors_are_cannot_tell(answer: Route) -> None:
    cannot_tell({**good_routes(), f"{REPO}/codeowners/errors": answer})


def test_an_error_in_another_codeowners_file_is_not_this_files() -> None:
    assert check({**good_routes(), f"{REPO}/codeowners/errors": errors_for(1, path="docs/CODEOWNERS")})[0] == 0


# -- a default branch that moves, and answers that are for something else ------------------------------------------


def changing(first: Route, then: Route) -> Callable[[], Route]:
    answers = [first, then]
    return lambda: answers.pop(0) if len(answers) > 1 else answers[0]


@pytest.mark.parametrize(
    "then",
    [
        repo_doc(default_branch="develop"),
        repo_doc(id=43),
        repo_doc(full_name="o/renamed"),
        repo_doc(default_branch="Main"),
    ],
    ids=["branch", "id", "name", "spelling"],
)
def test_a_repository_that_changes_between_the_two_reads_is_cannot_tell(then: dict[str, Any]) -> None:
    code, out, err, seen = check({**good_routes(), REPO: changing(j(repo_doc()), j(then))})
    assert code == 2 and "cannot tell" in out + err
    assert [path for _, path in seen].count(REPO) == 2


def test_a_stable_repository_is_read_twice_and_passes() -> None:
    code, _, _, seen = check(good_routes())
    assert code == 0 and [path for _, path in seen].count(REPO) == 2  # once per pass; the passes must agree


def test_the_repository_name_is_compared_without_case() -> None:
    assert check({**good_routes(), REPO: j(repo_doc(full_name="O/R"))})[0] == 0


@pytest.mark.parametrize(
    "doc",
    [
        repo_doc(full_name="x/y"),
        repo_doc(full_name=None),
        repo_doc(id=None),
        repo_doc(id=0),
        repo_doc(id=-3),
        repo_doc(id=True),
        repo_doc(id="42"),
        repo_doc(id=1.5),
        {"full_name": "o/r", "default_branch": "main"},
    ],
    ids=range(9),
)
def test_a_repository_answer_for_something_else_is_cannot_tell(doc: dict[str, Any]) -> None:
    cannot_tell({**good_routes(), REPO: j(doc)})


@pytest.mark.parametrize(
    "answer",
    [
        j({"name": "other", "commit": {"sha": SHA}}),
        j({"name": "main", "commit": {"sha": "xyz"}}),
        j({"name": "main", "commit": {"sha": SHA.upper()}}),
        j({"name": "main", "commit": None}),
        j({"name": "main"}),
        j({"message": "Not Found"}, 404),
    ],
    ids=range(6),
)
def test_a_branch_answer_that_is_not_the_default_branch_is_cannot_tell(answer: Route) -> None:
    cannot_tell({**good_routes(), f"{REPO}/branches/main": answer})


@pytest.mark.parametrize(
    "answer",
    [
        j(contents(GOOD_OWNERS, "CODEOWNERS")),  # another file than the one asked for
        j({**contents(GOOD_OWNERS), "type": "dir"}),
        j({**contents(GOOD_OWNERS), "path": None}),
        j({**contents(GOOD_OWNERS), "sha": None}),
        j({**contents(GOOD_OWNERS), "sha": "zz"}),
        j({k: v for k, v in contents(GOOD_OWNERS).items() if k != "sha"}),
        j({k: v for k, v in contents(GOOD_OWNERS).items() if k != "path"}),
    ],
    ids=range(7),
)
def test_a_contents_answer_for_another_file_is_cannot_tell(answer: Route) -> None:
    cannot_tell({**good_routes(), f"{REPO}/contents{OWNERS}": answer})


# -- lists with more pages ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "link",
    [
        '<http://x/?page=2>; rel="next"',
        '<http://x/?page=2>; rel="next", <http://x/?page=9>; rel="last"',
        '<http://x/?page=1>; rel="prev", <http://x/?page=3>; rel="next"',
        "<http://x/?page=2>; rel=next",
        '<http://x/?page=2>; REL="NEXT"',
    ],
)
def test_a_listing_with_a_next_page_is_cannot_tell_even_if_short(link: str) -> None:
    cannot_tell({**good_routes(), f"{REPO}/rulesets": (200, {"Link": link}, b"[]")})


def test_a_listing_with_only_other_relations_is_read() -> None:
    link = '<http://x/?page=1>; rel="prev", <http://x/?page=1>; rel="first"'
    assert check({**good_routes(), f"{REPO}/rulesets": (200, {"Link": link}, b"[]")})[0] == 0


def test_the_ruleset_listing_asks_for_a_full_page_with_inherited_rulesets() -> None:
    queries: list[tuple[str, str]] = []
    check(good_routes(), queries=queries)
    assert (f"{REPO}/rulesets", "per_page=100&includes_parents=true") in queries


# -- the exit code ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("route", ALL_READS)
def test_a_body_that_is_not_utf8_is_cannot_tell(route: str) -> None:
    cannot_tell({**good_routes(), route: (200, {}, b'{"a": "\xff\xfe"}')})


class BrokenPipe(io.StringIO):
    def write(self, text: str) -> int:
        raise BrokenPipeError


def run_with_stream(routes: Mapping[str, Entry], out: io.StringIO) -> int:
    from safo.cli import main

    with server(routes) as (url, _):
        return main(["protection", "--repo", "o/r", "--api-url", url], env=ENV, out=out, err=io.StringIO())


def test_a_pass_whose_report_cannot_be_written_is_not_exit_zero() -> None:
    assert run_with_stream(good_routes(), BrokenPipe()) == 2


def test_a_failure_whose_report_cannot_be_written_is_still_exit_one() -> None:
    routes = with_classic(put({"enabled": False}, "enforce_admins"))
    assert run_with_stream(routes, BrokenPipe()) == 1


def test_an_unknown_whose_report_cannot_be_written_is_still_exit_two() -> None:
    assert run_with_stream({**good_routes(), REPO: j({"message": "no"}, 403)}, BrokenPipe()) == 2


def test_a_closed_output_stream_is_handled_like_a_closed_pipe() -> None:
    closed = io.StringIO()
    closed.close()
    assert run_with_stream(good_routes(), closed) == 2


def test_an_interrupt_is_exit_130_and_reports_nothing_as_a_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    from safo.modes import protection as mode

    def interrupted(*args: Any, **kwargs: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(mode, "check", interrupted)
    code, out, _ = run_cli("protection", "--repo", "o/r", env=ENV)
    assert code == 130 and "PASS" not in out


# -- the client ------------------------------------------------------------------------------------------------------


def raw_server(respond: Callable[[BaseHTTPRequestHandler], None]) -> Any:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:
            respond(self)

    return serving(Handler)


def read_with(respond: Callable[[BaseHTTPRequestHandler], None], timeout: float = 5.0) -> Any:
    from safo.protection import Rest

    with raw_server(respond) as url:
        return Rest("t0ken", url, timeout=timeout).get("/x", "a test")


def chunked(parts: list[bytes], *, broken: bool = False) -> Callable[[BaseHTTPRequestHandler], None]:
    def respond(h: BaseHTTPRequestHandler) -> None:
        h.send_response(200)
        h.send_header("Transfer-Encoding", "chunked")
        h.end_headers()
        for part in parts:
            h.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
        h.wfile.write(b"zz\r\n" if broken else b"0\r\n\r\n")
        h.close_connection = True

    return respond


def test_a_chunked_body_is_read() -> None:
    assert read_with(chunked([b'{"a":', b" 1}"]))[:2] == (200, {"a": 1})


def test_a_chunked_body_with_a_bad_chunk_is_cannot_tell() -> None:
    from safo.protection import CannotTell

    with pytest.raises(CannotTell):
        read_with(chunked([b'{"a": 1}'], broken=True))


def test_a_body_shorter_than_its_content_length_is_cannot_tell() -> None:
    from safo.protection import CannotTell

    def respond(h: BaseHTTPRequestHandler) -> None:
        h.send_response(200)
        h.send_header("Content-Length", "100")
        h.end_headers()
        h.wfile.write(b'{"a": 1}')
        h.close_connection = True

    with pytest.raises(CannotTell):
        read_with(respond)


def test_conflicting_content_lengths_are_cannot_tell() -> None:
    from safo.protection import CannotTell

    def respond(h: BaseHTTPRequestHandler) -> None:
        h.send_response(200)
        h.send_header("Content-Length", "8")
        h.send_header("Content-Length", "9")
        h.end_headers()
        h.wfile.write(b'{"a": 1}')

    with pytest.raises(CannotTell):
        read_with(respond)


def test_a_body_over_one_mebibyte_is_cannot_tell() -> None:
    from safo.protection import CannotTell

    big = b'{"a": "' + b"x" * (1024 * 1024) + b'"}'

    def respond(h: BaseHTTPRequestHandler) -> None:
        h.send_response(200)
        h.send_header("Content-Length", str(len(big)))
        h.end_headers()
        h.wfile.write(big)

    with pytest.raises(CannotTell):
        read_with(respond)


def test_a_body_that_stalls_is_cannot_tell_after_the_read_timeout() -> None:
    import time

    from safo.protection import CannotTell

    def respond(h: BaseHTTPRequestHandler) -> None:
        h.send_response(200)
        h.send_header("Content-Length", "50")
        h.end_headers()
        h.wfile.write(b'{"a"')
        h.wfile.flush()
        time.sleep(1.5)

    started = time.monotonic()
    with pytest.raises(CannotTell):
        read_with(respond, timeout=0.3)
    assert time.monotonic() - started < 1.2


# -- the structural proof (sampling is switched off in these, so only the structure can decide) ----------------------


@pytest.fixture
def no_sampling(monkeypatch: pytest.MonkeyPatch) -> None:
    from safo import protection

    monkeypatch.setattr(protection, "fresh_workflow_paths", lambda: [])


def workflow_verdict(owners: str, *rows: tuple[str, str]) -> tuple[int, list[str]]:
    routes = world(owners, (*rows,))
    code, out, _, _ = check(routes)
    return code, failed_ids(out)


HEAD = "/board.yaml @o\n/.github/CODEOWNERS @o\n"


@pytest.mark.parametrize(
    "rules",
    [
        "/.github/workflows/zz-* @o\n",
        "/.github/workflows/sub/ @o\n",
        "/.github/workflows/*.yml @o\n/.github/workflows/*.yaml @o\n",
        "/.github/workflows/ci.yml @o\n",
        "/.github/workflows/ @o\n/.github/workflows/*.yml\n",
        "/.github/workflows/ @o\n*.yml\n",
        "/.github/workflows/ @o\n/.github/workflows/release.yml\n",
        "/.github/workflows/ @o\n/.github/**/*.yml\n",
        "/.github/workflows/ @o\n/.github/workflows/ @bad-\n",
        "/.github/workflows/ @o\n/.github/workflows/\n",
        "/.github/workflows/ci.yml @o\n/.github/workflows/ @o\n/.github/workflows/ci.yml\n",
    ],
    ids=range(11),
)
@pytest.mark.usefixtures("no_sampling")
def test_without_a_directory_wide_owner_a_new_workflow_is_unowned(rules: str) -> None:
    code, failed = workflow_verdict(HEAD + rules)  # an empty directory: no real file can decide it
    assert code == 1 and failed == ["codeowners-workflows"]


@pytest.mark.parametrize(
    "rules",
    [
        "/.github/workflows/ @o\n",
        ".github/workflows/ @o\n",
        "/.github/workflows/** @o\n",
        "/.github/ @o\n",
        "/.github/** @o\n",
        "* @o\n",
        "/.github/workflows/ci.yml\n/.github/workflows/ @o\n",
        "/.github/workflows/ @o\n/docs/ \n/src/*.py\n/.gitignore\n",
        "/.github/workflows/ @o\n/.github/workflows/ci.yml @p\n",
    ],
    ids=range(9),
)
@pytest.mark.usefixtures("no_sampling")
def test_a_directory_wide_owner_covers_new_workflows(rules: str) -> None:
    code, failed = workflow_verdict(HEAD + rules)
    assert (code, failed) == (0, [])


def test_a_star_rule_covers_the_whole_repository_and_so_the_workflows() -> None:
    assert check(with_owners("* @o\n"))[0] == 0


def test_the_structural_proof_is_what_fails_a_file_specific_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    from safo import protection

    monkeypatch.setattr(protection, "fresh_workflow_paths", lambda: [])
    code, failed = workflow_verdict(FILE_OWNERS, ("ci.yml", "blob"))
    assert (code, failed) == (1, ["codeowners-workflows"])


def test_may_touch_is_conservative_but_not_everything() -> None:
    from safo.protection import _may_touch

    assert all(
        _may_touch(p)
        for p in ["*.md", "ci.yml", "/*", "/.github/*", "/.github/**/x", "**/x", "/.gith*/x", "/.github/workflows/x"]
    )
    assert not any(
        _may_touch(p)
        for p in ["/docs/x", "/src/*.py", "/.gitignore", "/.github/actions/x", "/.github/CODEOWNERS", "/board.yaml"]
    )


# -- line numbering: only "\n" ends a line --------------------------------------------------------------------------

ODD = [
    "\x0b",
    "\x0c",
    "\x1c",
    "\x1d",
    "\x1e",
    "\x85",
    "\u2028",
    "\u2029",
    "\r",
    "\x00",
    "\x07",
    "\x7f",
    "\ufeff",
    "\u200b",
]


@pytest.mark.parametrize("char", ODD, ids=[f"U+{ord(c):04X}" for c in ODD])
def test_an_odd_line_break_or_control_character_inside_a_rule_line_is_cannot_tell(char: str) -> None:
    cannot_tell(with_owners(GOOD_OWNERS.replace("/board.yaml @owner", f"/board.yaml{char}@owner")))


@pytest.mark.parametrize("char", ODD, ids=[f"U+{ord(c):04X}" for c in ODD])
def test_an_odd_line_break_between_two_rules_is_cannot_tell(char: str) -> None:
    cannot_tell(with_owners(GOOD_OWNERS.replace("@owner\n/.github/CODEOWNERS", f"@owner{char}/.github/CODEOWNERS", 1)))


def test_a_byte_order_mark_at_the_start_is_cannot_tell() -> None:
    cannot_tell(with_owners("\ufeff" + GOOD_OWNERS))


def test_a_crlf_file_works() -> None:
    assert check(with_owners(GOOD_OWNERS.replace("\n", "\r\n")))[0] == 0


def test_tabs_and_a_last_line_without_a_newline_work() -> None:
    assert check(with_owners(GOOD_OWNERS.replace("/board.yaml @owner", "/board.yaml\t@owner").rstrip("\n")))[0] == 0


def test_an_error_line_number_means_the_nth_newline_separated_line() -> None:
    text = "# header\r\n\r\n/board.yaml @ghost\r\n/.github/CODEOWNERS @owner\r\n/.github/workflows/ @owner\r\n"
    routes = {**with_owners(text), f"{REPO}/codeowners/errors": errors_for(3)}
    code, out, _, _ = check(routes)
    assert code == 1 and failed_ids(out) == ["codeowners-board-yaml"]
    routes = {**with_owners(text), f"{REPO}/codeowners/errors": errors_for(2)}  # the blank line: nothing to hide
    assert check(routes)[0] == 0


def test_codeowners_lines_splits_on_newline_only() -> None:
    from safo.protection import codeowners_lines

    assert codeowners_lines("a\r\nb\n\nc") == ["a", "b", "", "c"]
    assert codeowners_lines("a\n") == ["a"] and codeowners_lines("") == []
    for char in ODD:
        with pytest.raises(Exception, match="cannot tell"):
            codeowners_lines(f"a{char}b\n")


# -- whitespace: GitHub splits tokens on ASCII space and tab only --------------------------------------------------

SPACES = [
    "\u00a0", "\u1680", *(chr(c) for c in range(0x2000, 0x200B)), "\u202f", "\u205f", "\u3000",
    "\u180e", "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff",
]  # fmt: skip
SPACE_IDS = [f"U+{ord(c):04X}" for c in SPACES]


@pytest.mark.parametrize("char", SPACES, ids=SPACE_IDS)
@pytest.mark.parametrize(
    "line",
    [
        "/board.yaml{c}@owner",  # between the pattern and the owner: one token for GitHub, two for str.split()
        "/board{c}.yaml @owner",  # inside the pattern
        "/board.yaml @owner{c}# note",  # around a comment
        "/board.yaml @owner #{c}note",
        "{c}/board.yaml @owner",  # leading
        "/board.yaml @owner{c}",  # trailing
        "/board.yaml @ow{c}ner",  # inside the owner
    ],
    ids=range(7),
)
def test_a_non_ascii_space_or_invisible_character_is_cannot_tell(char: str, line: str) -> None:
    cannot_tell(with_owners(GOOD_OWNERS.replace("/board.yaml @owner", line.format(c=char))))


def test_tab_separated_tokens_and_comments_still_work() -> None:
    text = "/board.yaml\t\t@owner\t# a note\n/.github/CODEOWNERS \t @owner\n/.github/workflows/\t@owner @other\n"
    assert check(with_owners(text))[0] == 0


def test_ascii_tokens_splits_on_space_and_tab_only() -> None:
    from safo.protection import ascii_tokens

    assert ascii_tokens("a \t b\\ c #d e") == ["a", "b\\ c"]
    assert ascii_tokens("a\u00a0b c") == ["a\u00a0b", "c"]  # one token for GitHub; the lines are refused before this


# ---- round 3: one moment, a verified object chain, one exit-code boundary ------------------------------------


def seq(*answers: Route) -> Callable[[], Route]:
    """A route whose answer changes with each request: the first gets the first answer, ...; the last one stays."""
    left = list(answers)
    return lambda: left.pop(0) if len(left) > 1 else left[0]


def listed(ident: int = 7) -> Route:
    return j([{"id": ident, "target": "branch", "enforcement": "active"}])


NFF_AND_DELETION = {"rules": [{"type": "non_fast_forward"}, {"type": "deletion"}]}


def test_a_secure_rule_replaced_by_a_weaker_ruleset_between_the_passes_is_cannot_tell() -> None:
    """Union of two moments: the classic rule (read first) and a ruleset (read later) would have passed together."""
    routes: dict[str, Entry] = {
        **world(),
        f"{REPO}/branches/main/protection": seq(j(classic()), j(NOT_PROTECTED, 404)),
        f"{REPO}/rulesets": seq(j([]), listed()),
        f"{REPO}/rulesets/7": j(ruleset(**NFF_AND_DELETION)),
    }
    code, out, err, _ = check(routes)
    assert code == 2 and "the protection changed while it was being read" in out + err


def test_a_secure_rule_removed_right_after_it_was_read_is_not_certified() -> None:
    routes: dict[str, Entry] = {**world(), f"{REPO}/branches/main/protection": seq(j(classic()), j(NOT_PROTECTED, 404))}
    code, out, err, _ = check(routes)
    assert code == 2 and "changed while it was being read" in out + err


def test_a_ruleset_edited_between_the_two_reads_is_cannot_tell() -> None:
    bypass = ruleset(bypass_actors=[{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}])
    routes: dict[str, Entry] = {**ruleset_routes(ruleset()), f"{REPO}/rulesets/7": seq(j(ruleset()), j(bypass))}
    cannot_tell(routes)


def test_a_ruleset_that_appears_between_the_passes_is_cannot_tell() -> None:
    routes: dict[str, Entry] = {**ruleset_routes(ruleset()), f"{REPO}/rulesets": seq(j([]), listed())}
    cannot_tell(routes)


def test_the_default_branch_head_moving_between_the_passes_is_cannot_tell() -> None:
    other = "7" * 40
    first, second = {"name": "main", "commit": {"sha": SHA}}, {"name": "main", "commit": {"sha": other}}
    routes: dict[str, Entry] = {
        **world(),
        f"{REPO}/branches/main": seq(j(first), j(second)),
        f"{REPO}/git/commits/{other}": j({"sha": other, "tree": {"sha": T_ROOT}}),
    }
    cannot_tell(routes)


def test_the_codeowners_errors_changing_between_the_passes_is_cannot_tell() -> None:
    cannot_tell({**world(), f"{REPO}/codeowners/errors": seq(j({"errors": []}), errors_for(1))})


def test_a_stable_world_is_read_twice_and_passes() -> None:
    code, _, _, seen = check(world())
    paths = [path for _, path in seen]
    assert code == 0 and paths.count(f"{REPO}/branches/main/protection") == 2 and paths.count(f"{REPO}/rulesets") == 2
    assert paths.count(f"{REPO}/git/commits/{SHA}") == 2


# -- the object chain: commit -> tree -> entry -> blob ---------------------------------------------------------------


def test_the_root_tree_is_requested_by_the_tree_the_commit_declares() -> None:
    queries: list[tuple[str, str]] = []
    check(world(), queries=queries)
    paths = [path for path, _ in queries]
    assert f"{REPO}/git/trees/{T_ROOT}" in paths and f"{REPO}/git/trees/{SHA}" not in paths


def test_a_root_tree_whose_sha_is_not_the_one_the_commit_declared_is_cannot_tell() -> None:
    wrong = j(tree("9" * 40, (".github", "tree"), ("board.yaml", "blob")))
    cannot_tell({**world(), f"{REPO}/git/trees/{T_ROOT}": wrong})


@pytest.mark.parametrize(
    "answer",
    [
        j({"sha": "9" * 40, "tree": {"sha": T_ROOT}}),  # another commit than the one asked for
        j({"sha": SHA, "tree": {"sha": "xyz"}}),
        j({"sha": SHA, "tree": {"sha": T_ROOT.upper()}}),
        j({"sha": SHA, "tree": None}),
        j({"sha": SHA}),
        j({"tree": {"sha": T_ROOT}}),
        j({"sha": SHA, "tree": {"sha": T_ROOT}}, 404),
    ],
    ids=range(7),
)
def test_a_commit_answer_that_is_not_the_head_commit_is_cannot_tell(answer: Route) -> None:
    cannot_tell({**world(), f"{REPO}/git/commits/{SHA}": answer})


def test_a_crafted_tree_for_the_commit_sha_is_not_a_way_in() -> None:
    """The commit sha must not be asked for as a tree: a crafted tree answered for it is never read."""
    crafted = j(tree(SHA, (".github", "tree"), ("board.yaml", "blob")))
    queries: list[tuple[str, str]] = []
    code = check({**world(), f"{REPO}/git/trees/{SHA}": crafted}, queries=queries)[0]
    assert code == 0 and f"{REPO}/git/trees/{SHA}" not in [path for path, _ in queries]


def test_an_older_permissive_file_cannot_be_substituted_for_the_one_the_tree_names() -> None:
    older = "* @attacker\n"
    routes: dict[str, Entry] = {
        **world(),
        f"{REPO}/contents{OWNERS}": j(contents(older)),
    }  # a real older blob, the wrong sha for this tree
    cannot_tell(routes)


def test_content_that_does_not_hash_to_the_sha_it_carries_is_cannot_tell() -> None:
    forged = {**contents("* @attacker\n"), "sha": git_sha(GOOD_OWNERS)}
    cannot_tell({**world(), f"{REPO}/contents{OWNERS}": j(forged)})


def test_the_blob_is_checked_against_the_tree_entry_not_against_itself() -> None:
    """Even a file whose own sha is consistent is refused when the tree entry names another blob."""
    other = tree(T_GH, ("workflows", "tree"), ("CODEOWNERS", "blob"), blobs={"CODEOWNERS": git_sha("* @attacker\n")})
    cannot_tell({**world(), f"{REPO}/git/trees/{T_GH}": j(other)})


@pytest.mark.parametrize(
    ("tree_sha", "rows"),
    [
        (T_ROOT, ((".github", "tree"), (".github", "tree"), ("board.yaml", "blob"))),
        (T_ROOT, ((".github", "tree"), ("board.yaml", "blob"), ("board.yaml", "blob"))),
        (T_GH, (("workflows", "tree"), ("CODEOWNERS", "blob"), ("CODEOWNERS", "blob"))),
        (T_GH, (("workflows", "tree"), ("workflows", "tree"), ("CODEOWNERS", "blob"))),
        (T_WF, (("ci.yml", "blob"), ("ci.yml", "blob"))),
    ],
    ids=range(5),
)
def test_a_tree_that_names_the_same_path_twice_is_cannot_tell(tree_sha: str, rows: tuple[tuple[str, str], ...]) -> None:
    cannot_tell({**world(), f"{REPO}/git/trees/{tree_sha}": j(tree(tree_sha, *rows))})


def test_codeowners_in_two_locations_is_read_from_the_one_github_uses() -> None:
    permissive = "* @attacker\n"
    routes: dict[str, Entry] = {**world(), f"{REPO}/contents/CODEOWNERS": j(contents(permissive, "CODEOWNERS"))}
    routes[f"{REPO}/git/trees/{T_ROOT}"] = j(
        tree(
            T_ROOT,
            (".github", "tree"),
            ("board.yaml", "blob"),
            ("CODEOWNERS", "blob"),
            blobs={"CODEOWNERS": git_sha(permissive)},
        )
    )
    code, out, _, seen = check(routes)
    assert code == 0, out  # the .github file governs; the root one is never even fetched
    assert not any(path == f"{REPO}/contents/CODEOWNERS" for _, path in seen)


def test_the_root_file_beats_docs_and_docs_is_read_only_as_a_last_resort() -> None:
    routes = world(place="CODEOWNERS")
    routes[f"{REPO}/git/trees/{T_ROOT}"] = j(
        tree(
            T_ROOT,
            (".github", "tree"),
            ("board.yaml", "blob"),
            ("CODEOWNERS", "blob"),
            ("docs", "tree"),
            blobs={"CODEOWNERS": git_sha(OWNERS_AT["CODEOWNERS"])},
        )
    )
    queries: list[tuple[str, str]] = []
    assert check(routes, queries=queries)[0] == 0
    assert not any(path == f"{REPO}/git/trees/{T_DOCS}" for path, _ in queries)
    assert check(world(place="docs/CODEOWNERS"))[0] == 0


@pytest.mark.parametrize("mode_and_kind", [("120000", "blob"), ("160000", "commit"), ("040000", "tree")], ids=str)
def test_a_codeowners_entry_that_is_not_a_regular_file_is_cannot_tell(mode_and_kind: tuple[str, str]) -> None:
    mode, kind = mode_and_kind
    body = tree(T_GH, ("workflows", "tree"), ("CODEOWNERS", "blob"), blobs={"CODEOWNERS": git_sha(GOOD_OWNERS)})
    row = next(r for r in body["tree"] if r["path"] == "CODEOWNERS")
    row["mode"], row["type"] = mode, kind
    cannot_tell({**world(), f"{REPO}/git/trees/{T_GH}": j(body)})


def test_a_tree_entry_without_a_mode_is_cannot_tell() -> None:
    body = tree(T_GH, ("workflows", "tree"), ("CODEOWNERS", "blob"), blobs={"CODEOWNERS": git_sha(GOOD_OWNERS)})
    del body["tree"][1]["mode"]
    cannot_tell({**world(), f"{REPO}/git/trees/{T_GH}": j(body)})


# -- one exit-code boundary ------------------------------------------------------------------------------------------


def mode_args(url: str) -> Any:
    import argparse

    return argparse.Namespace(repo="o/r", agent_login="", require_app_id="", api_url=url)


def make_context(say: Callable[[str], None] | None = None) -> Any:
    import datetime as dt

    from safo.context import LocalContext

    class Context(LocalContext):
        def say(self, line: str = "") -> None:
            if say is not None:
                say(line)
            else:
                super().say(line)

    return Context(io.StringIO(), ENV, dt.datetime.now(dt.UTC))


def raiser(error: BaseException) -> Callable[..., Any]:
    def boom(*args: Any, **kwargs: Any) -> Any:
        raise error

    return boom


def test_a_reporting_backend_that_raises_cannot_turn_a_pass_into_one() -> None:
    from safo.modes import protection as mode

    ctx = make_context(raiser(RuntimeError("secret detail")))
    with server(good_routes()) as (url, _):
        assert mode.run(ctx, mode_args(url)) == 2


def test_a_reporting_backend_that_raises_leaves_a_computed_failure_as_one() -> None:
    from safo.modes import protection as mode

    ctx = make_context(raiser(RuntimeError("secret detail")))
    with server(with_classic(put({"enabled": False}, "enforce_admins"))) as (url, _):
        assert mode.run(ctx, mode_args(url)) == 1


@pytest.mark.parametrize(
    "error",
    [
        SystemExit(0),
        SystemExit(1),
        SystemExit(),
        GeneratorExit(),
        RuntimeError("secret detail"),
        MemoryError(),
        AssertionError("secret detail"),
    ],
    ids=lambda e: f"{type(e).__name__}-{e.args[0] if e.args else ''}",
)
def test_anything_unexpected_from_a_dependency_is_exit_two_naming_only_the_class(
    error: BaseException, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safo.modes import protection as mode

    monkeypatch.setattr(mode, "check", raiser(error))
    ctx = make_context()
    code = mode.run(ctx, mode_args("http://127.0.0.1:9"))
    out = ctx.out.getvalue()
    assert code == 2 and type(error).__name__ in out and "secret" not in out


def test_the_failure_report_failing_too_still_returns_two(monkeypatch: pytest.MonkeyPatch) -> None:
    from safo.modes import protection as mode

    monkeypatch.setattr(mode, "check", raiser(SystemExit(0)))
    assert mode.run(make_context(raiser(SystemExit(0))), mode_args("http://127.0.0.1:9")) == 2
    assert mode.run(make_context(raiser(BrokenPipeError())), mode_args("http://127.0.0.1:9")) == 2


def test_through_the_command_line_a_dependency_exit_is_two_not_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    from safo.modes import protection as mode

    monkeypatch.setattr(mode, "check", raiser(SystemExit(0)))
    code, out, _ = run_cli("protection", "--repo", "o/r", env=ENV)
    assert code == 2 and "SystemExit" in out


def test_a_deliberate_usage_error_still_reaches_the_command_line_as_a_reported_error() -> None:
    code, _, err = run_cli("protection", "--repo", "o/r", env={})
    assert code == 2 and "token" in err  # the SafoError path is unchanged: stderr, not an internal error


def test_a_commit_tree_sha_with_path_characters_is_never_put_in_a_request() -> None:
    routes = {**world(), f"{REPO}/git/commits/{SHA}": j({"sha": SHA, "tree": {"sha": "../rulesets"}})}
    code, _, _, seen = check(routes)
    assert code == 2 and not any(".." in path for _, path in seen)


@pytest.mark.parametrize(
    ("sha", "rows"),
    [(T_ROOT, ((".github", "blob"), ("board.yaml", "blob"))), (T_GH, (("workflows", "blob"), ("CODEOWNERS", "blob")))],
    ids=["github", "workflows"],
)
def test_a_file_where_a_directory_belongs_is_never_fetched_as_a_tree(
    sha: str, rows: tuple[tuple[str, str], ...]
) -> None:
    body = tree(
        sha, *rows, blobs={"CODEOWNERS": git_sha(GOOD_OWNERS)}
    )  # CODEOWNERS stays valid: only the directory is wrong
    code, _, _, seen = check({**world(), f"{REPO}/git/trees/{sha}": j(body)})
    assert code == 2 and f"{REPO}/git/trees/{BLOB}" not in [path for _, path in seen]


# ---- round 4: one moment is not provable by reading twice, but a single alternation must not forge it ----------------


class Alternating:
    """A repository an administrator flips between state A and state B on every protection read.

    A: the classic rule gives code-owner review, `CI green`, strict, admins and no bypass, but allows force pushes and
    deletion. B: the classic rule is gone and an active ruleset gives only non_fast_forward and deletion. No instant has
    every condition, yet a read that sees A for the classic rule and B for the rulesets would add them up. The state is
    chosen by the position of the request among the classic and listing reads (`phase` shifts where it starts).
    """

    def __init__(self, phase: int = 0) -> None:
        self.reads = phase

    def _is_b(self) -> bool:
        self.reads += 1
        return self.reads % 2 == 0

    def classic(self) -> Route:
        loose = classic()
        loose["allow_force_pushes"] = {"enabled": True}
        loose["allow_deletions"] = {"enabled": True}
        return j(NOT_PROTECTED, 404) if self._is_b() else j(loose)

    def listing(self) -> Route:
        return listed() if self._is_b() else j([])


def alternating_routes(phase: int) -> dict[str, Entry]:
    flip = Alternating(phase)
    return {
        **world(),
        f"{REPO}/branches/main/protection": flip.classic,
        f"{REPO}/rulesets": flip.listing,
        f"{REPO}/rulesets/7": j(ruleset(**NFF_AND_DELETION)),
    }


@pytest.mark.parametrize("phase", [0, 1], ids=["classic-in-A", "classic-in-B"])
def test_a_world_alternating_between_two_incomplete_states_is_never_certified(phase: int) -> None:
    code, out, err, _ = check(alternating_routes(phase))
    assert code == 2 and "PASS" not in out and "changed while it was being read" in out + err


def test_the_two_mechanisms_are_read_in_opposite_order_in_the_second_pass() -> None:
    _, _, _, seen = check(world())
    marks = [
        path.rsplit("/", 1)[-1] for _, path in seen if path.endswith(("/protection", "/rulesets"))
    ]  # classic, rulesets, rulesets, classic
    assert marks == ["protection", "rulesets", "rulesets", "protection"]


def varying(base: Route | dict[str, Any], then: Route | dict[str, Any]) -> Callable[[], Route]:
    return seq(base if isinstance(base, tuple) else j(base), then if isinstance(then, tuple) else j(then))


def test_a_field_this_check_does_not_use_changing_in_the_classic_rule_is_cannot_tell() -> None:
    cannot_tell({**world(), f"{REPO}/branches/main/protection": varying(classic(), {**classic(), "url": "x"})})


def test_a_field_this_check_does_not_use_changing_in_a_ruleset_is_cannot_tell() -> None:
    routes: dict[str, Entry] = {
        **ruleset_routes(ruleset()),
        f"{REPO}/rulesets/7": varying(ruleset(), {**ruleset(), "updated_at": "later"}),
    }
    cannot_tell(routes)


def test_a_field_this_check_does_not_use_changing_in_the_ruleset_listing_is_cannot_tell() -> None:
    first = [{"id": 7, "target": "branch", "enforcement": "active"}]
    then = [{"id": 7, "target": "branch", "enforcement": "active", "updated_at": "later"}]
    cannot_tell({**ruleset_routes(ruleset()), f"{REPO}/rulesets": varying(first, then)})  # type: ignore[arg-type]


# -- between the passes: every document that decides something --------------------------------------------------------


def test_codeowners_text_changing_between_the_passes_is_cannot_tell() -> None:
    other = GOOD_OWNERS + "/docs/ @owner\n"  # a file that would pass by itself
    routes: dict[str, Entry] = {
        **world(),
        f"{REPO}/contents{OWNERS}": varying(contents(GOOD_OWNERS), contents(other)),
        f"{REPO}/git/trees/{T_GH}": varying(
            tree(T_GH, ("workflows", "tree"), ("CODEOWNERS", "blob"), blobs={"CODEOWNERS": git_sha(GOOD_OWNERS)}),
            tree(T_GH, ("workflows", "tree"), ("CODEOWNERS", "blob"), blobs={"CODEOWNERS": git_sha(other)}),
        ),
    }
    cannot_tell(routes)


def test_the_codeowners_blob_changing_between_the_passes_is_cannot_tell() -> None:
    """The same text, but the tree names another blob the second time (and the file answer follows it)."""
    other = GOOD_OWNERS + "# edited\n"
    routes: dict[str, Entry] = {
        **world(),
        f"{REPO}/contents{OWNERS}": varying(contents(GOOD_OWNERS), contents(other)),
        f"{REPO}/git/trees/{T_GH}": varying(
            tree(T_GH, ("workflows", "tree"), ("CODEOWNERS", "blob"), blobs={"CODEOWNERS": git_sha(GOOD_OWNERS)}),
            tree(T_GH, ("workflows", "tree"), ("CODEOWNERS", "blob"), blobs={"CODEOWNERS": git_sha(other)}),
        ),
    }
    cannot_tell(routes)


def test_the_workflow_tree_changing_between_the_passes_is_cannot_tell() -> None:
    more = tree(T_WF, *WORKFLOWS, ("new.yml", "blob"))  # owned by the directory rule, so only a comparison can see it
    cannot_tell({**world(), f"{REPO}/git/trees/{T_WF}": varying(tree(T_WF, *WORKFLOWS), more)})


def test_the_root_listing_changing_between_the_passes_is_cannot_tell() -> None:
    first = tree(T_ROOT, (".github", "tree"), ("board.yaml", "blob"), blobs={"CODEOWNERS": git_sha(GOOD_OWNERS)})
    then = tree(T_ROOT, (".github", "tree"), ("board.yaml", "blob"), ("README.md", "blob"))
    cannot_tell({**world(), f"{REPO}/git/trees/{T_ROOT}": varying(first, then)})


def test_the_github_listing_changing_between_the_passes_is_cannot_tell() -> None:
    blobs = {"CODEOWNERS": git_sha(GOOD_OWNERS)}
    first = tree(T_GH, ("workflows", "tree"), ("CODEOWNERS", "blob"), blobs=blobs)
    then = tree(T_GH, ("workflows", "tree"), ("CODEOWNERS", "blob"), ("dependabot.yml", "blob"), blobs=blobs)
    cannot_tell({**world(), f"{REPO}/git/trees/{T_GH}": varying(first, then)})


def test_a_stable_world_reads_every_document_exactly_twice() -> None:
    code, _, _, seen = check(world())
    paths = [path for _, path in seen]
    assert code == 0
    for path in (
        REPO,
        f"{REPO}/branches/main",
        f"{REPO}/git/commits/{SHA}",
        f"{REPO}/git/trees/{T_ROOT}",
        f"{REPO}/git/trees/{T_GH}",
        f"{REPO}/git/trees/{T_WF}",
        f"{REPO}/contents{OWNERS}",
        f"{REPO}/codeowners/errors",
        f"{REPO}/branches/main/protection",
        f"{REPO}/rulesets",
    ):
        assert paths.count(path) == 2, path
    assert len(paths) == 20


# -- the error report is inside the exit-code boundary --------------------------------------------------------------


class Raising(io.StringIO):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error

    def write(self, text: str) -> int:
        raise self.error


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (SystemExit(0), 2),
        (SystemExit(), 2),
        (BrokenPipeError(), 2),
        (OSError("closed"), 2),
        (ValueError("I/O operation on closed file"), 2),
        (KeyboardInterrupt(), 130),
    ],
    ids=["exit0", "exit", "pipe", "oserror", "closed", "interrupt"],
)
def test_an_error_whose_report_cannot_be_written_keeps_a_failing_exit_code(error: BaseException, code: int) -> None:
    from safo.cli import main

    assert main(["protection", "--repo", "o/r"], env={}, out=io.StringIO(), err=Raising(error)) == code  # no token


def test_a_report_that_cannot_be_written_in_a_workflow_run_is_still_two() -> None:
    from safo.cli import main

    env = {"GITHUB_ACTIONS": "true"}
    assert main(["protection", "--repo", "o/r"], env=env, out=io.StringIO(), err=Raising(SystemExit(0))) == 2


@pytest.mark.parametrize("target", ["from_env", "from_gh", "Rest"])
@pytest.mark.parametrize(
    "error", [SystemExit(0), RuntimeError("secret"), KeyboardInterrupt()], ids=["exit0", "boom", "int"]
)
def test_a_failure_below_the_credential_lookup_or_the_client_is_never_zero(
    target: str, error: BaseException, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safo import credentials
    from safo.modes import protection as mode

    holder: Any = credentials if target != "Rest" else mode
    monkeypatch.setattr(holder, target, raiser(error))
    env = ENV if target != "from_gh" else {}
    code, out, _ = run_cli("protection", "--repo", "o/r", env=env)
    assert code == (130 if isinstance(error, KeyboardInterrupt) else 2) and "PASS" not in out
