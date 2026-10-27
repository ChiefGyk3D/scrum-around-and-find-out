# SPDX-License-Identifier: Apache-2.0
"""`safo handoff check`, round 2: crashes are never "stale", only a reviewing role counts, code blocks and HTML
comments are not reports, the head must hold still while reading, and the shipped limits are pinned."""

from __future__ import annotations

from typing import Any

import pytest

from fakegh import FakeGitHub
from fakegh.core import Fault
from safo import graphql
from safo.errors import ApiError
from safo.modes import handoff
from test_handoff_check import EARLY, LATE, LATER, A, B, comment, report, run

# -- a crash is never "stale" -----------------------------------------------------------------------------------


def test_a_deeply_nested_answer_is_unknown_not_a_crash(fake: FakeGitHub) -> None:
    fake.faults.append(Fault(200, body="[" * 200000 + "]" * 200000, times=10, op="HandoffPr"))
    code, out, err = run(fake, [comment(report(A))])
    assert code == 2 and out.startswith("UNKNOWN") and "Traceback" not in err


@pytest.mark.parametrize(
    "body", ['{"errors": ["boom"]}', '{"errors": "boom"}', '{"errors": [1, null]}', '{"errors": {"a": 1}}']
)
def test_errors_that_are_not_objects_are_unknown_not_a_crash(fake: FakeGitHub, body: str) -> None:
    fake.faults.append(Fault(200, body=body, times=10, op="HandoffPr"))
    code, out, _ = run(fake, [comment(report(A))])
    assert code == 2 and out.startswith("UNKNOWN") and "boom" not in out


def test_an_oversized_answer_is_unknown(fake: FakeGitHub, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(graphql, "MAX_BODY", 1000)
    good = '{"data": {"repository": {"pullRequest": {"headRefOid": "' + A + '", "state": "OPEN", "isDraft": false}}}}'
    fake.faults.append(Fault(200, body=good + " " * 5000, times=10, op="HandoffPr"))
    code, out, _ = run(fake, [comment(report(A))])
    assert code == 2 and "more than" in out and "FRESH" not in out


def test_any_other_exception_is_unknown_with_only_its_class_name(
    fake: FakeGitHub, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(client: Any, variables: Any, roles: Any) -> Any:
        raise ValueError("secret ::error::text")

    monkeypatch.setattr(handoff, "verdict", boom)
    code, out, err = run(fake, [comment(report(A))])
    assert code == 2 and out == "UNKNOWN internal error (ValueError)\n"
    assert "secret" not in out + err


# -- only a reviewing role counts -------------------------------------------------------------------------------


def test_an_implementer_report_alone_is_not_a_review(fake: FakeGitHub) -> None:
    code, out, _ = run(fake, [comment(report(A, "implementer"))])
    assert code == 2 and "no review report" in out


def test_a_later_implementer_report_does_not_replace_the_review(fake: FakeGitHub) -> None:
    mixed = [comment(report(A, "reviewer"), EARLY), comment(report(B, "implementer"), LATER)]
    assert run(fake, mixed, head=A)[0] == 0
    assert run(fake, mixed, head=B)[0] == 1


def test_an_implementer_report_in_the_same_comment_is_skipped(fake: FakeGitHub) -> None:
    assert run(fake, [comment(report(A, "reviewer") + "\n" + report(B, "implementer"))], head=A)[0] == 0


@pytest.mark.parametrize("role", ["reviewer", "adversarial-reviewer"])
def test_the_two_reviewing_roles_count(fake: FakeGitHub, role: str) -> None:
    code, out, _ = run(fake, [comment(report(A, role))])
    assert code == 0 and role in out


@pytest.mark.parametrize("role", ["transcriber", "lead", "implementer"])
def test_the_other_doia_roles_do_not_count_by_default(fake: FakeGitHub, role: str) -> None:
    assert run(fake, [comment(report(A, role))])[0] == 2


def test_roles_option_overrides_the_default(fake: FakeGitHub) -> None:
    assert run(fake, [comment(report(A, "implementer"))], options=("--roles", "implementer"))[0] == 0
    assert run(fake, [comment(report(A, "reviewer"))], options=("--roles", "implementer"))[0] == 2
    both = [comment(report(A, "implementer"), EARLY), comment(report(B, "lead"), LATER)]
    assert run(fake, both, options=("--roles", "implementer,lead"), head=B)[0] == 0


@pytest.mark.parametrize("value", ["", "bogus", "reviewer,bogus", "reviewer,,lead", "Reviewer", "reviewer lead"])
def test_a_bad_roles_option_is_refused_before_any_request(fake: FakeGitHub, value: str) -> None:
    code, out, _ = run(fake, [comment(report(A))], options=("--roles", value))
    assert code == 2 and out.startswith("UNKNOWN") and fake.requests == []


@pytest.mark.parametrize("role", ["wizard", "<role name>", "", "REVIEWER"])
def test_an_unreadable_role_in_the_newest_report_is_unknown_not_skipped(fake: FakeGitHub, role: str) -> None:
    body = f"ROLE: {role}   MODEL: m\nHEAD: {B}   BASE: 1234567\n"
    code, out, _ = run(fake, [comment(report(A), EARLY), comment(body, LATER)])
    assert code == 2 and "FRESH" not in out


def test_the_output_names_the_role_and_the_verdict_and_never_says_approved(fake: FakeGitHub) -> None:
    for verdict in ("SHIP", "SHIP WITH CHANGES", "DO NOT SHIP", "FINDINGS", "APPROVE", "NOT ATTACKED"):
        code, out, _ = run(fake, [comment(report(A, "adversarial-reviewer", verdict))])
        assert code == 0 and "adversarial-reviewer" in out and f"VERDICT {verdict}" in out
        assert "names the current head" in out and "approved" not in out.lower()
    code, out, _ = run(fake, [comment(report(A))])
    assert "VERDICT" not in out


def test_a_verdict_outside_the_list_is_never_echoed(fake: FakeGitHub) -> None:
    code, out, _ = run(fake, [comment(report(A, verdict="::error::boom $(x)"))])
    assert code == 0 and "boom" not in out and "VERDICT" not in out


def test_a_verdict_of_a_later_report_is_not_borrowed(fake: FakeGitHub) -> None:
    body = report(A) + "\n" + report(B, "implementer", "FINDINGS")
    code, out, _ = run(fake, [comment(body)])
    assert code == 0 and "FINDINGS" not in out


# -- minimized, edited, state -----------------------------------------------------------------------------------


def test_a_minimized_comment_is_ignored(fake: FakeGitHub) -> None:
    hidden = comment(report(B), LATER, minimized=True)
    assert run(fake, [comment(report(A), EARLY), hidden], head=A)[0] == 0
    assert run(fake, [hidden], head=B)[0] == 2


def test_the_later_of_created_and_edited_orders_the_comments(fake: FakeGitHub) -> None:
    edited = comment(report(B), EARLY, edited=LATER)
    plain = comment(report(A), LATE)
    assert run(fake, [edited, plain], head=B)[0] == 0
    assert run(fake, [edited, plain], head=A)[0] == 1
    old_edit = comment(report(B), EARLY, edited=EARLY)
    assert run(fake, [old_edit, plain], head=A)[0] == 0


@pytest.mark.parametrize(
    ("state", "draft", "suffix"),
    [("OPEN", True, "(draft)"), ("CLOSED", False, "(closed)"), ("MERGED", False, "(merged)"), ("OPEN", False, "")],
)
def test_the_state_of_the_pull_request_is_shown(fake: FakeGitHub, state: str, draft: bool, suffix: str) -> None:
    code, out, _ = run(fake, [comment(report(A))], state=state, draft=draft)
    assert code == 0 and (suffix in out if suffix else "(" not in out)
    code, out, _ = run(fake, [comment(report(A))], head=B, state=state, draft=draft)
    assert code == 1 and (suffix in out if suffix else "(" not in out)


@pytest.mark.parametrize(
    ("state", "draft"), [("OPENED", False), (None, False), (3, False), ("OPEN", None), ("OPEN", "no")]
)
def test_a_bad_state_or_draft_flag_is_unknown(fake: FakeGitHub, state: Any, draft: Any) -> None:
    assert run(fake, [comment(report(A))], state=state, draft=draft)[0] == 2


# -- code blocks and HTML comments are not reports ----------------------------------------------------------------


def test_a_report_in_a_code_fence_is_not_a_report(fake: FakeGitHub) -> None:
    assert run(fake, [comment("```\n" + report(A) + "```\n")])[0] == 2
    assert run(fake, [comment("~~~text\n" + report(A) + "~~~\n")])[0] == 2
    assert run(fake, [comment("```\r\n" + report(A).replace("\n", "\r\n") + "```\r\n")])[0] == 2


def test_an_unclosed_fence_hides_the_rest(fake: FakeGitHub) -> None:
    assert run(fake, [comment("```\n" + report(A))])[0] == 2


def test_quoting_an_old_report_in_a_fence_does_not_become_the_newest(fake: FakeGitHub) -> None:
    reply = comment("Earlier I said:\n```\n" + report(B) + "```\n", LATER)
    assert run(fake, [comment(report(A), EARLY), reply], head=A)[0] == 0


def test_a_report_after_a_closed_fence_still_counts(fake: FakeGitHub) -> None:
    assert run(fake, [comment("```\ncode\n```\n" + report(A))])[0] == 0


def test_a_report_in_an_html_comment_is_not_a_report(fake: FakeGitHub) -> None:
    assert run(fake, [comment("<!--\n" + report(A) + "-->\n")])[0] == 2
    assert run(fake, [comment("<!-- " + report(A).replace("\n", " ").strip() + " -->")])[0] == 2
    assert run(fake, [comment("<!--\n" + report(A))])[0] == 2  # never closed: the rest is hidden
    assert run(fake, [comment("<!-- x\n-->\n" + report(A))])[0] == 0  # closed: what follows counts
    assert run(fake, [comment("<!-- a --> text\n" + report(A))])[0] == 0


def test_a_fence_inside_an_html_comment_does_not_open_a_fence(fake: FakeGitHub) -> None:
    assert run(fake, [comment("<!--\n```\n-->\n" + report(A))])[0] == 0


def test_a_blockquoted_report_is_not_a_report(fake: FakeGitHub) -> None:
    assert run(fake, [comment("".join("> " + line + "\n" for line in report(A).splitlines()))])[0] == 2


# -- the head must not move while reading -------------------------------------------------------------------------


def test_the_head_is_read_again_after_the_comments(fake: FakeGitHub) -> None:
    run(fake, [comment(report(A))])
    assert fake.requests == [
        "HandoffPr",
        "HandoffComments",
        "HandoffTimeline",
        "HandoffPr",
        "HandoffTimeline",
        "HandoffComments",
    ]


def test_a_head_that_moves_while_reading_is_unknown(fake: FakeGitHub) -> None:
    heads = iter([A, B, B])
    fake.handlers["HandoffPr"] = lambda f, v: {
        "repository": {
            "pullRequest": {
                "headRefOid": next(heads),
                "baseRefName": "main",
                "baseRefOid": "d" * 40,
                "state": "OPEN",
                "isDraft": False,
            }
        }
    }
    code, out, _ = run(fake, [comment(report(A))])
    assert code == 2 and "changed while it was being read" in out and "FRESH" not in out and "STALE" not in out


# -- the client itself: a hostile answer is an ApiError, whoever calls it -----------------------------------------


def test_the_client_refuses_deep_json_with_an_api_error(fake: FakeGitHub, client: graphql.Client) -> None:
    fake.faults.append(Fault(200, body="[" * 200000 + "]" * 200000, times=10, op="HandoffPr"))
    with pytest.raises(ApiError, match="nested too deeply"):
        client.execute(handoff.PR_QUERY, {"owner": "n0tst", "name": "demo", "number": 7})


@pytest.mark.parametrize("body", ['{"errors": ["boom"]}', '{"errors": "boom"}', '{"errors": [1, null]}'])
def test_the_client_refuses_errors_that_are_not_objects_with_an_api_error(
    fake: FakeGitHub, client: graphql.Client, body: str
) -> None:
    fake.faults.append(Fault(200, body=body, times=10, op="HandoffPr"))
    with pytest.raises(ApiError, match="not a list of objects"):
        client.execute(handoff.PR_QUERY, {"owner": "n0tst", "name": "demo", "number": 7})


# -- the shipped limits -------------------------------------------------------------------------------------------


def test_the_shipped_page_limits() -> None:
    assert (handoff.MAX_COMMENT_PAGES, handoff.MAX_COMMIT_PAGES) == (10, 3)


def test_three_pages_of_commits_resolve_and_a_fourth_is_truncated(fake: FakeGitHub) -> None:
    others = [f"{i:040x}" for i in range(1, 300)]
    assert run(fake, [comment(report("aaaaaaa"))], head=A, commits=[*others, A])[0] == 0  # 300 commits, 3 pages
    assert fake.requests.count("HandoffCommits") == 3
    code, out, _ = run(fake, [comment(report("aaaaaaa"))], head=A, commits=[*others, A, B])
    assert code == 2 and "truncated" in out
