# SPDX-License-Identifier: Apache-2.0
"""safo protection: the read-only branch-protection read-back (spec 8.5 R2(a), #139).

A tiny loopback server stands in for the REST API and records every request. One fixture per failing condition; every
field the check reads has a null / mistyped / absent case that must be exit 2 ("cannot tell"), never an empty list.
"""

from __future__ import annotations

import base64
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
SHA = "a" * 40  # the default branch's head commit
T_GH = "b" * 40
T_WF = "c" * 40
BLOB = "d" * 40
GOOD_OWNERS = "/board.yaml @owner\n/.github/CODEOWNERS @owner\n/.github/workflows/ @owner\n"
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


def contents(text: str, place: str = ".github/CODEOWNERS") -> dict[str, Any]:
    return {
        "type": "file",
        "path": place,
        "sha": BLOB,
        "encoding": "base64",
        "content": base64.encodebytes(text.encode()).decode(),
    }


def repo_doc(**over: Any) -> dict[str, Any]:
    return {"id": 42, "full_name": "o/r", "default_branch": "main", **over}


def tree(sha: str, *rows: tuple[str, str], truncated: Any = False) -> dict[str, Any]:
    body: dict[str, Any] = {
        "sha": sha,
        "tree": [
            {"path": path, "type": kind, "sha": {".github": T_GH, "workflows": T_WF}.get(path, BLOB), "mode": "100644"}
            for path, kind in rows
        ],
    }
    if truncated is not None:
        body["truncated"] = truncated
    return body


WORKFLOWS = (("ci.yml", "blob"), ("sub", "tree"), ("sub/x.yml", "blob"))


def j(body: Any, status: int = 200) -> Route:
    return status, {"Content-Type": "application/json"}, json.dumps(body).encode()


def good_routes() -> dict[str, Route]:
    trees = {
        SHA: tree(SHA, (".github", "tree"), ("board.yaml", "blob")),
        T_GH: tree(T_GH, ("workflows", "tree"), ("CODEOWNERS", "blob")),
        T_WF: tree(T_WF, *WORKFLOWS),
    }
    return {
        REPO: j(repo_doc()),
        f"{REPO}/branches/main": j({"name": "main", "commit": {"sha": SHA}}),
        f"{REPO}/branches/main/protection": j(classic()),
        f"{REPO}/rulesets": j([]),
        f"{REPO}/contents{OWNERS}": j(contents(GOOD_OWNERS)),
        f"{REPO}/codeowners/errors": j({"errors": []}),
        **{f"{REPO}/git/trees/{sha}": j(body) for sha, body in trees.items()},
    }


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
    return {**good_routes(), f"{REPO}/contents{OWNERS}": j(contents(text))}


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
    routes = {**good_routes(), f"{REPO}/branches/main/protection": j(NOT_PROTECTED, 404)}
    del routes[f"{REPO}/contents{OWNERS}"]
    code, out, _, seen = check(routes)
    assert code == 1 and "FAIL codeowners-board-yaml" in out and "FAIL codeowners-workflows" in out
    assert not any("/git/trees/" in path or "codeowners/errors" in path for _, path in seen)


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
    f"{REPO}/git/trees/{SHA}",
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


@pytest.mark.parametrize("status", [201, 202, 403, 500])
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
    routes = good_routes()
    del routes[f"{REPO}/contents{OWNERS}"]
    routes[f"{REPO}/contents/CODEOWNERS"] = j(contents(GOOD_OWNERS, "CODEOWNERS"))
    assert check(routes)[0] == 0


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


def with_workflows(*rows: tuple[str, str], gh: Any = None) -> dict[str, Route]:
    routes = good_routes()
    routes[f"{REPO}/git/trees/{T_WF}"] = j(tree(T_WF, *rows))
    if gh is not None:
        routes[f"{REPO}/git/trees/{T_GH}"] = j(gh)
    return routes


PROBES_ONLY = (
    "/board.yaml @o\n/.github/CODEOWNERS @o\n"
    "/.github/workflows/probe.yml @o\n/.github/workflows/probe.yaml @o\n/.github/workflows/probe.md @o\n"
    "/.github/workflows/probe @o\n/.github/workflows/sub/probe.yml @o\n"
)


def failed_ids(out: str) -> list[str]:
    return [line.split()[1].rstrip(":") for line in out.splitlines() if line.startswith("FAIL")]


def test_owning_only_the_old_probe_names_leaves_a_real_workflow_unowned() -> None:
    routes = {**with_workflows(("release.yml", "blob")), f"{REPO}/contents{OWNERS}": j(contents(PROBES_ONLY))}
    code, out, _, _ = check(routes)
    assert code == 1 and failed_ids(out) == ["codeowners-workflows"]


def test_a_directory_rule_covers_every_real_file_including_nested_ones() -> None:
    assert check(with_workflows(("a.yml", "blob"), ("d", "tree"), ("d/deep", "tree"), ("d/deep/b.yml", "blob")))[0] == 0


def test_a_shallow_glob_leaves_a_nested_workflow_unowned() -> None:
    routes = {
        **good_routes(),
        f"{REPO}/contents{OWNERS}": j(contents(GOOD_OWNERS.replace("workflows/ ", "workflows/*.yml "))),
    }
    code, out, _, _ = check(routes)
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
    assert trees == [(SHA, ""), (T_GH, ""), (T_WF, "recursive=1")]


@pytest.mark.parametrize("sha", [SHA, T_GH, T_WF])
@pytest.mark.parametrize("truncated", [True, None, "false", 0], ids=repr)
def test_a_truncated_or_unlabelled_tree_is_cannot_tell(sha: str, truncated: Any) -> None:
    rows = {SHA: ((".github", "tree"),), T_GH: (("workflows", "tree"),), T_WF: WORKFLOWS}[sha]
    cannot_tell({**good_routes(), f"{REPO}/git/trees/{sha}": j(tree(sha, *rows, truncated=truncated))})


NO_WORKFLOWS_DIR = tree(T_GH, ("CODEOWNERS", "blob"))
FILE_OWNERS = "/board.yaml @o\n/.github/CODEOWNERS @o\n/.github/workflows/ci.yml @o\n"


def test_a_file_specific_owner_leaves_a_new_workflow_unowned() -> None:
    routes = {**with_workflows(("ci.yml", "blob")), f"{REPO}/contents{OWNERS}": j(contents(FILE_OWNERS))}
    code, out, _, _ = check(routes)
    assert code == 1 and failed_ids(out) == ["codeowners-workflows"]  # ci.yml itself is owned; release.yml would not be


def test_an_empty_workflows_directory_without_a_directory_rule_fails() -> None:
    routes = {**with_workflows(), f"{REPO}/contents{OWNERS}": j(contents(FILE_OWNERS))}
    code, out, _, _ = check(routes)
    assert code == 1 and failed_ids(out) == ["codeowners-workflows"]


def test_an_absent_workflows_directory_without_a_directory_rule_fails() -> None:
    routes = {**with_workflows(gh=NO_WORKFLOWS_DIR), f"{REPO}/contents{OWNERS}": j(contents(FILE_OWNERS))}
    code, out, _, _ = check(routes)
    assert code == 1 and failed_ids(out) == ["codeowners-workflows"]


def test_an_empty_or_absent_workflows_directory_with_a_directory_rule_passes() -> None:
    assert check(with_workflows())[0] == 0
    assert check(with_workflows(gh=NO_WORKFLOWS_DIR))[0] == 0
    assert check({**with_workflows(), f"{REPO}/git/trees/{SHA}": j(tree(SHA, ("README.md", "blob")))})[0] == 0


def test_a_glob_that_owns_only_some_new_names_fails() -> None:
    routes = {**with_workflows(("ci.yml", "blob")), f"{REPO}/contents{OWNERS}": j(contents(GOOD_OWNERS))}
    for glob in ("*.yml", "*.yaml"):
        text = GOOD_OWNERS.replace("/.github/workflows/ @owner", f"/.github/workflows/{glob} @owner")
        assert check({**routes, f"{REPO}/contents{OWNERS}": j(contents(text))})[0] == 1


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

    routes = {**with_workflows(), f"{REPO}/contents{OWNERS}": j(contents(owning_exactly(1)))}
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

    routes = {**with_workflows(), f"{REPO}/contents{OWNERS}": j(contents(owning_exactly(1)))}
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
    assert not any("zz" in p or "probe" in p for p in first)  # no fixed prefix a rule could own
    assert any(p.endswith(".yml") for p in first) and any(p.endswith(".yaml") for p in first)


@pytest.mark.parametrize(
    "routes",
    [
        {f"{REPO}/git/trees/{T_GH}": j(tree(T_GH, ("workflows", "blob")))},
        {f"{REPO}/git/trees/{SHA}": j(tree(SHA, (".github", "blob")))},
        {f"{REPO}/git/trees/{T_WF}": j(tree("e" * 40, *WORKFLOWS))},  # the tree answered is not the one asked for
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
    assert code == 0 and [path for _, path in seen].count(REPO) == 2 and seen[-1][1] == REPO


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
    routes = {**with_workflows(*rows), f"{REPO}/contents{OWNERS}": j(contents(owners))}
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
