# SPDX-License-Identifier: Apache-2.0
"""safo protection: the read-only branch-protection read-back (spec 8.5 R2(a), #139).

A tiny loopback server stands in for the REST API and records every request. One fixture per failing condition; every
field the check reads has a null / mistyped / absent case that must be exit 2 ("cannot tell"), never an empty list.
"""

from __future__ import annotations

import base64
import json
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from cliutil import run_cli

ENV = {"SAFO_TOKEN": "t0ken", "SAFO_TOKEN_KIND": "token"}
REPO = "/repos/o/r"
OWNERS = "/.github/CODEOWNERS"
GOOD_OWNERS = "/board.yaml @owner\n/.github/CODEOWNERS @owner\n/.github/workflows/ @owner\n"
NOT_PROTECTED = {"message": "Branch not protected"}
Route = tuple[int, dict[str, str], bytes]
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


def contents(text: str) -> dict[str, Any]:
    return {"type": "file", "encoding": "base64", "content": base64.encodebytes(text.encode()).decode()}


def j(body: Any, status: int = 200) -> Route:
    return status, {"Content-Type": "application/json"}, json.dumps(body).encode()


def good_routes() -> dict[str, Route]:
    return {
        REPO: j({"default_branch": "main"}),
        f"{REPO}/branches/main/protection": j(classic()),
        f"{REPO}/rulesets": j([]),
        f"{REPO}/contents{OWNERS}": j(contents(GOOD_OWNERS)),
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
def server(routes: dict[str, Route]) -> Iterator[tuple[str, list[tuple[str, str]]]]:
    seen: list[tuple[str, str]] = []

    class Request(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def handle_any(self) -> None:
            path = self.path.split("?")[0]
            seen.append((self.command, path))
            status, headers, body = routes.get(path, j({"message": "Not Found"}, 404))
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = handle_any

    with serving(Request) as url:
        yield url, seen


def check(routes: dict[str, Route], *extra: str) -> tuple[int, str, str, list[tuple[str, str]]]:
    with server(routes) as (url, seen):
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
    routes = {
        REPO: j({"default_branch": "main"}),
        f"{REPO}/branches/main/protection": j(NOT_PROTECTED, 404),
        f"{REPO}/rulesets": j([]),
    }
    code, out, _, _ = check(routes)
    assert code == 1 and "FAIL codeowners-board-yaml" in out


def cannot_tell(routes: dict[str, Route]) -> None:
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


@pytest.mark.parametrize("route", [REPO, f"{REPO}/rulesets", f"{REPO}/contents{OWNERS}"])
def test_error_answers_anywhere_are_cannot_tell(route: str) -> None:
    cannot_tell({**good_routes(), route: j({"message": "Forbidden"}, 403)})


def test_a_duplicate_key_is_cannot_tell() -> None:
    body = b'{"enforce_admins": {"enabled": false}, "enforce_admins": {"enabled": true}}'
    cannot_tell({**good_routes(), f"{REPO}/branches/main/protection": (200, {}, body)})


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


def test_a_full_ruleset_page_is_cannot_tell() -> None:
    routes = ruleset_routes(ruleset())
    routes[f"{REPO}/rulesets"] = j([{"id": n, "target": "tag", "enforcement": "disabled"} for n in range(100)])
    cannot_tell(routes)


@pytest.mark.parametrize(
    "answer",
    [
        j({"default_branch": None}),
        j({"default_branch": ""}),
        j({"default_branch": 5}),
        j({}),
        j({"default_branch": "../x"}),
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
    routes[f"{REPO}/contents/CODEOWNERS"] = j(contents(GOOD_OWNERS))
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


def test_a_gh_token_is_only_sent_to_api_github_com() -> None:
    env = {"SAFO_TOKEN": "t0ken", "SAFO_TOKEN_KIND": "gh"}
    with server(good_routes()) as (url, seen):
        code, _, err = run_cli("protection", "--repo", "o/r", "--api-url", url, env=env)
    assert code == 2 and seen == [] and "api.github.com" in err


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


def test_the_client_can_only_issue_get() -> None:
    from safo import protection

    assert protection.METHODS == ("GET",)
