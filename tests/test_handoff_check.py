# SPDX-License-Identifier: Apache-2.0
"""`safo handoff check`: does the latest review report name the head the pull request has now?

Exit 0 fresh, 1 stale, 2 unknown. Every API answer that is null, mistyped, truncated or inconsistent is 2,
never an empty list and never a guess.
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import pytest

from fakegh import FakeGitHub
from fakegh.core import Fault, FPull, GqlError
from localcli import cli
from safo import graphql
from safo.modes import handoff

A = "a" * 40
B = "b" * 40
C = "c" * 40
REPO = "n0tst/demo"
LATE = "2026-10-20T10:00:00Z"
EARLY = "2026-10-19T10:00:00Z"
LATER = "2026-10-21T10:00:00Z"
HOME = Path("/nonexistent-home")


def report(head: str, role: str = "reviewer") -> str:
    return (
        f"ROLE: {role}   MODEL: n0tst-model\n"
        f"HEAD: {head}   BASE: 1234567\n"
        "GATE: make check  exit=0\n"
        "NOT VERIFIED: none\n"
    )


def comment(body: str, when: str = LATE, assoc: str = "OWNER") -> dict[str, Any]:
    return {"authorAssociation": assoc, "createdAt": when, "body": body}


def env_for(fake: FakeGitHub, extra: dict[str, str] | None = None) -> dict[str, str]:
    return {"SAFO_TOKEN": fake.token, "GITHUB_GRAPHQL_URL": fake.url, **(extra or {})}


def run(
    fake: FakeGitHub,
    comments: list[Any],
    head: Any = A,
    commits: list[Any] | None = None,
    extra_env: dict[str, str] | None = None,
    number: str = "7",
    repo: str = REPO,
) -> tuple[int, str, str]:
    fake.pulls[(REPO, 7)] = FPull(head=head, comments=comments, commits=commits or [])
    return cli("handoff", "check", repo, number, home=HOME, extra_env=env_for(fake, extra_env))


# -- the three verdicts ----------------------------------------------------------------------------------------


def test_a_report_at_the_current_head_is_fresh(fake: FakeGitHub) -> None:
    code, out, _ = run(fake, [comment(report(A))])
    assert code == 0 and out.startswith("FRESH") and A[:7] in out


def test_a_report_at_an_older_head_is_stale_and_prints_both_short_shas(fake: FakeGitHub) -> None:
    code, out, _ = run(fake, [comment(report(A))], head=B)
    assert code == 1 and out.startswith("STALE")
    assert "aaaaaaa" in out and "bbbbbbb" in out and A not in out and B not in out


def test_no_report_is_unknown_never_fresh(fake: FakeGitHub) -> None:
    for comments in ([], [comment("looks good to me")], [comment("HEAD: " + A)]):  # prose and a bare HEAD line
        code, out, _ = run(fake, comments)
        assert code == 2 and out.startswith("UNKNOWN") and "FRESH" not in out and "no review report" in out


def test_heads_that_differ_only_after_the_seventh_character_are_stale(fake: FakeGitHub) -> None:
    code, out, _ = run(fake, [comment(report(A))], head="a" * 39 + "b")
    assert code == 1 and out.startswith("STALE")


def test_the_newest_report_by_comment_time_counts_whatever_the_list_order(fake: FakeGitHub) -> None:
    mixed = [comment(report(B), LATER), comment(report(A), EARLY), comment(report(C), LATE)]
    assert run(fake, mixed, head=B)[0] == 0
    assert run(fake, mixed, head=A)[0] == 1


def test_reports_found_on_a_later_page_count(fake: FakeGitHub) -> None:
    fake.page_size = 2
    filler = [comment("noise", EARLY) for _ in range(4)]
    code, _, _ = run(fake, [*filler, comment(report(A), LATE)])
    assert code == 0 and fake.requests.count("HandoffComments") == 3


# -- trust ------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("assoc", ["NONE", "CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", "MANNEQUIN", "X"])
def test_a_report_from_an_untrusted_author_is_ignored(fake: FakeGitHub, assoc: str) -> None:
    code, out, _ = run(fake, [comment(report(A), assoc=assoc)])
    assert code == 2 and "FRESH" not in out


@pytest.mark.parametrize("assoc", ["OWNER", "MEMBER", "COLLABORATOR"])
def test_the_three_trusted_associations_are_read(fake: FakeGitHub, assoc: str) -> None:
    assert run(fake, [comment(report(A), assoc=assoc)])[0] == 0


def test_a_newer_forged_report_does_not_hide_the_real_one(fake: FakeGitHub) -> None:
    forged = comment(report(A), LATER, assoc="NONE")
    code, _, _ = run(fake, [comment(report(B), EARLY), forged], head=A)
    assert code == 1  # the trusted report at B is the latest; the forgery claiming A is not read


# -- the reported SHA ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["abc", "abcdef", "<short sha>", "xyzxyzx", A[:6], A + "a", "A" * 7 + "-", ""])
def test_a_sha_that_is_not_seven_to_forty_hex_is_unknown(fake: FakeGitHub, value: str) -> None:
    code, out, _ = run(fake, [comment(report(value))], commits=[A])
    assert code == 2 and "FRESH" not in out


def test_an_uppercase_full_sha_is_compared_case_insensitively(fake: FakeGitHub) -> None:
    assert run(fake, [comment(report(A.upper()))])[0] == 0


def test_a_short_sha_resolving_to_the_head_is_fresh(fake: FakeGitHub) -> None:
    code, out, _ = run(fake, [comment(report("aaaaaaa"))], commits=[C, A])
    assert code == 0 and "FRESH" in out


def test_a_short_sha_resolving_to_an_older_commit_is_stale(fake: FakeGitHub) -> None:
    code, out, _ = run(fake, [comment(report("ccccccc"))], head=A, commits=[C, A])
    assert code == 1 and "ccccccc" in out and "aaaaaaa" in out


def test_a_short_sha_matching_two_commits_is_unknown(fake: FakeGitHub) -> None:
    code, out, _ = run(fake, [comment(report("aaaaaaa"))], commits=["a" * 39 + "b", A])
    assert code == 2 and "ambiguous" in out


def test_a_short_sha_matching_no_commit_is_unknown(fake: FakeGitHub) -> None:
    assert run(fake, [comment(report("ddddddd"))], commits=[A])[0] == 2


def test_a_short_sha_with_a_truncated_commit_list_is_unknown(fake: FakeGitHub, monkeypatch: pytest.MonkeyPatch) -> None:
    fake.page_size = 1
    monkeypatch.setattr(handoff, "MAX_COMMIT_PAGES", 1)
    code, out, _ = run(fake, [comment(report("aaaaaaa"))], commits=[A, B])
    assert code == 2 and "truncated" in out


def test_a_full_sha_needs_no_commit_list(fake: FakeGitHub) -> None:
    run(fake, [comment(report(A))], head=B)
    assert "HandoffCommits" not in fake.requests


def test_a_malformed_commit_list_is_unknown(fake: FakeGitHub) -> None:
    for bad in ([None], ["not-a-sha"], [7]):
        assert run(fake, [comment(report("aaaaaaa"))], commits=bad)[0] == 2


# -- what counts as a report -----------------------------------------------------------------------------------------


def test_a_head_line_without_a_role_line_before_it_is_not_a_header(fake: FakeGitHub) -> None:
    assert run(fake, [comment("note\nHEAD: " + A + "   BASE: 1234567\n")])[0] == 2


def test_a_report_with_carriage_returns_and_a_fence_is_read(fake: FakeGitHub) -> None:
    body = "```\r\nROLE: reviewer   MODEL: m\r\nHEAD: " + A + "   BASE: 1234567\r\n```\r\n"
    assert run(fake, [comment(body)])[0] == 0


def test_two_different_heads_in_the_newest_report_are_unknown(fake: FakeGitHub) -> None:
    code, out, _ = run(fake, [comment(report(A) + "\n" + report(B))])
    assert code == 2 and "ambiguous" in out
    assert run(fake, [comment(report(A) + "\n" + report(A))])[0] == 0  # the same head twice says one thing


def test_two_reports_in_the_same_second_with_different_heads_are_unknown(fake: FakeGitHub) -> None:
    code, out, _ = run(fake, [comment(report(A)), comment(report(B))])
    assert code == 2 and "ambiguous" in out
    assert run(fake, [comment(report(A)), comment(report(A))])[0] == 0


def test_a_malformed_newest_report_is_not_skipped_for_an_older_good_one(fake: FakeGitHub) -> None:
    assert run(fake, [comment(report(A), EARLY), comment(report("<short sha>"), LATER)])[0] == 2


def test_a_head_line_with_trailing_junk_is_unknown(fake: FakeGitHub) -> None:
    assert run(fake, [comment("ROLE: reviewer\nHEAD: " + A + " and more\n")])[0] == 2


# -- strict reading: every wrong shape is 2 ------------------------------------------------------------------------


@pytest.mark.parametrize("head", [None, 7, "", "abc", B[:39], B + "0", B.upper(), "g" * 40, ["x"]])
def test_a_null_or_mistyped_or_short_pull_request_head_is_unknown(fake: FakeGitHub, head: Any) -> None:
    code, out, _ = run(fake, [comment(report(A))], head=head)
    assert code == 2 and "FRESH" not in out and "STALE" not in out


@pytest.mark.parametrize(
    "node",
    [
        None,
        "text",
        7,
        {"authorAssociation": "OWNER", "createdAt": LATE},  # no body
        {"authorAssociation": "OWNER", "createdAt": LATE, "body": None},
        {"authorAssociation": "OWNER", "createdAt": LATE, "body": 5},
        {"authorAssociation": None, "createdAt": LATE, "body": "x"},
        {"authorAssociation": 3, "createdAt": LATE, "body": "x"},
        {"authorAssociation": "OWNER", "createdAt": None, "body": "x"},
        {"authorAssociation": "OWNER", "createdAt": 20261020, "body": "x"},
        {"authorAssociation": "OWNER", "createdAt": "yesterday", "body": report(A)},
    ],
)
def test_a_bad_comment_node_makes_the_whole_read_unknown(fake: FakeGitHub, node: Any) -> None:
    code, out, _ = run(fake, [comment(report(A)), node])
    assert code == 2 and "FRESH" not in out


def test_truncated_pagination_is_unknown(fake: FakeGitHub, monkeypatch: pytest.MonkeyPatch) -> None:
    fake.page_size = 2
    monkeypatch.setattr(handoff, "MAX_COMMENT_PAGES", 2)
    comments = [comment("noise", EARLY) for _ in range(4)] + [comment(report(A), LATE)]
    code, out, _ = run(fake, comments)
    assert code == 2 and "truncated" in out and fake.requests.count("HandoffComments") == 2


def test_an_exact_fit_is_not_truncated(fake: FakeGitHub, monkeypatch: pytest.MonkeyPatch) -> None:
    fake.page_size = 2
    monkeypatch.setattr(handoff, "MAX_COMMENT_PAGES", 2)
    comments = [comment("noise", EARLY) for _ in range(3)] + [comment(report(A), LATE)]
    assert run(fake, comments)[0] == 0


def test_an_unreadable_pull_request_is_unknown(fake: FakeGitHub) -> None:
    code, out, _ = cli("handoff", "check", "n0tst/absent", "7", home=HOME, extra_env=env_for(fake))
    assert code == 2 and out.startswith("UNKNOWN")


def test_a_null_repository_answer_is_unknown(fake: FakeGitHub) -> None:
    fake.handlers["HandoffPr"] = lambda f, v: {"repository": None}
    code, out, _ = run(fake, [comment(report(A))])
    assert code == 2 and "FRESH" not in out and "could not be read" in out


def test_a_null_pull_request_answer_is_unknown(fake: FakeGitHub) -> None:
    fake.handlers["HandoffPr"] = lambda f, v: {"repository": {"pullRequest": None}}
    code, out, _ = run(fake, [comment(report(A))])
    assert code == 2 and "could not be read" in out


@pytest.mark.parametrize("status", [401, 403])
def test_a_refused_token_is_unknown(fake: FakeGitHub, status: int) -> None:
    fake.faults.append(Fault(status, times=10))
    code, out, _ = run(fake, [comment(report(A))])
    assert code == 2 and "FRESH" not in out


def test_an_unreachable_server_is_unknown(fake: FakeGitHub, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(handoff, "Client", functools.partial(graphql.Client, sleep=lambda _s: None))
    code, out, _ = run(fake, [comment(report(A))], extra_env={"GITHUB_GRAPHQL_URL": "http://127.0.0.1:9/graphql"})
    assert code == 2 and out.startswith("UNKNOWN")


def test_no_token_is_unknown(tmp_path: Path) -> None:
    code, out, _ = cli("handoff", "check", REPO, "7", home=tmp_path)
    assert code == 2 and out.startswith("UNKNOWN") and "no token" in out


def test_a_gh_token_is_never_sent_to_a_redirected_url(fake: FakeGitHub) -> None:
    code, out, _ = run(fake, [comment(report(A))], extra_env={"SAFO_TOKEN_KIND": "gh"})
    assert code == 2 and "FRESH" not in out and fake.requests == []


@pytest.mark.parametrize(
    ("repo", "number"),
    [
        ("demo", "7"),
        ("a/b/c", "7"),
        (REPO, "0"),
        (REPO, "-1"),
        (REPO, "x"),
        ("n0tst/..", "7"),
        ("n0tst/de mo", "7"),
        (REPO, "7 8"),
        (REPO, "1" * 12),
    ],
)
def test_a_malformed_reference_is_refused_before_any_request(fake: FakeGitHub, repo: str, number: str) -> None:
    code, out, _ = run(fake, [comment(report(A))], number=number, repo=repo)
    assert code == 2 and out.startswith("UNKNOWN") and fake.requests == []


# -- output and requests ------------------------------------------------------------------------------------------


def test_text_that_github_sends_back_is_escaped(fake: FakeGitHub) -> None:
    def hostile(f: FakeGitHub, v: Any) -> Any:
        raise GqlError("OTHER", "::error::injected\n::set-output name=x::y\x1b[31m")

    fake.handlers["HandoffPr"] = hostile
    code, out, err = run(fake, [comment(report(A))])
    assert code == 2 and out.startswith("UNKNOWN")
    assert "::" not in out + err and "\x1b" not in out + err and len(out.splitlines()) == 1


def test_comment_text_never_reaches_the_output(fake: FakeGitHub) -> None:
    body = report(A) + "\n::error::boom\n$(touch /tmp/n0tst)\n"
    code, out, _ = run(fake, [comment(body)], head=B)
    assert code == 1 and "boom" not in out and "touch" not in out


def test_only_read_queries_are_sent(fake: FakeGitHub) -> None:
    run(fake, [comment(report("aaaaaaa"))], head=A, commits=[A])
    assert fake.kinds and set(fake.kinds) == {"query"}
    assert fake.mutations == []
    assert set(fake.requests) == {"HandoffPr", "HandoffComments", "HandoffCommits"}


def test_the_documents_are_queries_with_no_mutation_keyword() -> None:
    for document in (handoff.PR_QUERY, handoff.COMMENTS_QUERY, handoff.COMMITS_QUERY):
        assert graphql.operation_name(document).startswith("Handoff")
        assert not graphql.is_mutation(document) and "mutation" not in document.lower()


def test_dry_run_still_reads_and_still_answers(fake: FakeGitHub) -> None:
    fake.pulls[(REPO, 7)] = FPull(head=A, comments=[comment(report(A))])
    code, out, _ = cli("--dry-run", "handoff", "check", REPO, "7", home=HOME, extra_env=env_for(fake))
    assert code == 0 and "FRESH" in out
