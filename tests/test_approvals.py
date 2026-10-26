# SPDX-License-Identifier: Apache-2.0
"""The approval reader (spec 3.2, "The approval test"): approved, open with a reason, or UNKNOWN; never a guess."""

from __future__ import annotations

import datetime as dt
import io
from collections.abc import Callable
from typing import Any, cast

import pytest

from fakegh import FakeGitHub
from fakegh.approval_ops import closed_event, issue_node, put
from fakegh.core import JSON, GqlError
from safo import approvals
from safo.approvals import Approver, Check, Read, Unread, Verdict, read_issues, verdict
from safo.context import Context
from safo.graphql import Client

APPROVERS = (Approver("approver-one", 1001), Approver("approver-two", 1002))
GATE = "GATE acme/gates#21 (Design gate)"
START = dt.date(2026, 11, 2)
REF = "acme/gates#21"


def check(**over: Any) -> Check:
    base: dict[str, Any] = {
        "kind": "change",
        "ref": REF,
        "subject": "SCOPE acme/gates#21",
        "approvers": APPROVERS,
        "entry": "acme/app#55",
        "frozen": START,
    }
    base.update(over)
    return Check(**base)


def gate(**over: Any) -> Check:
    return check(kind="gate", subject=GATE, entry=None, frozen=None, **over)


def judge(
    fake: FakeGitHub, client: Client, node: JSON, chk: Check | None = None, via_app: bool | None = False
) -> Verdict:
    put(fake, node, repo="acme/gates", number=21)
    chk = chk or check()
    return verdict(chk, read_issues(client, [chk.ref])[chk.ref], via_app)


def never_approved(v: Verdict) -> None:
    assert v.state != "approved" and not v.approved


def user(login: str, db_id: object = 1001) -> JSON:
    return {"__typename": "User", "login": login, "databaseId": db_id}


def close_with(**over: object) -> JSON:
    return issue_node(timelineItems={"totalCount": 1, "nodes": [closed_event(**over)]})


class Spy:
    """A client that records every document and variables it is asked to send."""

    def __init__(self, inner: Client) -> None:
        self.inner = inner
        self.sent: list[tuple[str, dict[str, Any]]] = []

    def execute(self, document: str, variables: Any = None, **kw: Any) -> JSON:
        self.sent.append((document, dict(variables or {})))
        return self.inner.execute(document, variables, **kw)


# -- approved, and the actor table: one test per row, exact text -----------------------------------------------------


def test_a_manual_completed_close_by_an_approver_is_approved(fake: FakeGitHub, client: Client) -> None:
    v = judge(fake, client, issue_node())
    assert v.state == "approved" and v.approved and v.lines == ()
    assert v.closed_at == dt.datetime(2026, 11, 5, 12, 0, tzinfo=dt.UTC) and v.approver == "approver-one"


def actor_of(typename: str, login: str) -> JSON:
    return {"__typename": typename, "login": login}


ENT = "an enterprise-managed account, which process.approvers cannot name yet"
ACTOR_ROWS: list[tuple[str, JSON | None, str]] = [
    (
        "same login, another id",
        user("approver-one", 777),
        "by @approver-one, whose id is not the approver's id for that login",
    ),
    ("not an approver", user("octocat", 5), "by octocat, who is not in process.approvers"),
    ("bot", actor_of("Bot", "robo[bot]"), "by a bot (robo[bot]); an approval is a person's"),
    ("mannequin", actor_of("Mannequin", "ghost-import"), "by an imported placeholder account"),
    ("organization", actor_of("Organization", "acme"), "by an organization account"),
    ("enterprise", actor_of("EnterpriseUserAccount", "ent_user"), f"by {ENT}"),
    ("deleted account", None, "by an account that no longer exists"),
]


@pytest.mark.parametrize(("name", "actor", "text"), ACTOR_ROWS, ids=[r[0] for r in ACTOR_ROWS])
def test_the_actor_table_row_has_its_exact_line(
    fake: FakeGitHub, client: Client, name: str, actor: JSON | None, text: str
) -> None:
    v = judge(fake, client, close_with(actor=actor), gate())
    assert v.state == "open" and v.lines == (f"DRIFT   {GATE} was closed {text}; it counts as open",)
    never_approved(v)


def test_a_renamed_approver_is_approved_and_the_note_names_both_logins(fake: FakeGitHub, client: Client) -> None:
    v = judge(fake, client, close_with(actor=user("new-name", 1001)), gate())
    assert v.approved
    assert v.lines == (f"NOTE    {GATE} closed by @new-name, who is approver @approver-one (renamed)",)


def test_login_comparison_is_ascii_only_so_a_kelvin_sign_is_not_the_approver_login(
    fake: FakeGitHub, client: Client
) -> None:
    other = gate(approvers=(Approver("kevin", 4242),))
    kelvin = judge(fake, client, close_with(actor=user("\u212aevin", 1)), other)
    assert (
        kelvin.state == "open"
        and "whose id is not" not in kelvin.lines[0]
        and "not in process.approvers" in kelvin.lines[0]
    )
    # the same name in ASCII capitals is the "same login, another id" row
    real = judge(fake, client, close_with(actor=user("KEVIN", 1)), other)
    assert "whose id is not the approver's id" in real.lines[0]
    # a Kelvin-sign login with the approver's id is approved by id, and prints as a rename
    by_id = judge(fake, client, close_with(actor=user("\u212aevin", 4242)), other)
    assert by_id.approved and "(renamed)" in by_id.lines[0]


@pytest.mark.parametrize(
    ("login", "ident"),
    [
        ("ok", True),
        ("ok", 0),
        ("ok", -4),
        ("ok", "1"),
        ("ok", 1.0),
        ("two words", 1),
        ("\u212aevin", 1),
        ("", 1),
        ("-lead", 1),
    ],
)
def test_an_approver_with_a_bad_id_or_login_is_refused(login: str, ident: object) -> None:
    with pytest.raises(ValueError, match="approver"):
        Approver(login, cast(Any, ident))


# -- closers, close reasons, edits, the App cross-check --------------------------------------------------------------


@pytest.mark.parametrize(
    ("closer", "text"),
    [
        (
            {"__typename": "PullRequest", "number": 60, "repository": {"nameWithOwner": "acme/app"}},
            "through a pull request (acme/app#60), not by hand",
        ),
        ({"__typename": "Commit"}, "through a commit, not by hand"),
        ({"__typename": "ProjectV2"}, "by a project workflow, not by hand"),
    ],
)
def test_a_close_with_a_closer_stays_open_even_for_an_approver(
    fake: FakeGitHub, client: Client, closer: JSON, text: str
) -> None:
    v = judge(fake, client, close_with(closer=closer), gate())
    assert v.state == "open" and v.lines == (f"DRIFT   {GATE} was closed {text}; it counts as open",)


def test_a_reopened_then_reclosed_issue_reads_the_newest_close(fake: FakeGitHub, client: Client) -> None:
    newest = closed_event(actor=user("octocat", 5), createdAt="2026-11-09T08:00:00Z")
    node = issue_node(timelineItems={"totalCount": 2, "nodes": [newest]})
    v = judge(fake, client, node, gate())
    assert v.state == "open" and "octocat" in v.lines[0]
    spy = Spy(client)
    read_issues(spy, [REF])
    document, variables = spy.sent[0]
    assert "itemTypes: [CLOSED_EVENT], last: 1" in document
    assert "acme" not in document and "gates" not in document and variables["o0"] == "acme"


@pytest.mark.parametrize(
    ("over", "reason"),
    [
        ({"stateReason": "NOT_PLANNED"}, "as not planned"),
        ({"stateReason": "DUPLICATE"}, "as a duplicate"),
        ({"duplicateOf": {"id": "I_x"}}, "as a duplicate"),
    ],
)
def test_not_planned_and_duplicate_closes_are_open(fake: FakeGitHub, client: Client, over: JSON, reason: str) -> None:
    v = judge(fake, client, close_with(**over), gate())
    assert v.state == "open" and v.lines == (f"DRIFT   {GATE} was closed {reason}; it counts as open",)


def test_an_issue_edited_after_its_approval_is_open_and_an_edit_at_the_close_is_not(
    fake: FakeGitHub, client: Client
) -> None:
    v = judge(fake, client, issue_node(lastEditedAt="2026-11-09T10:00:00Z"), gate())
    assert v.state == "open"
    assert v.lines == (
        f"DRIFT   {GATE} was edited on 2026-11-09 after it was approved on 2026-11-05; it counts as open",
    )
    assert judge(fake, client, issue_node(lastEditedAt="2026-11-05T12:00:00Z"), gate()).approved
    assert judge(fake, client, issue_node(lastEditedAt="2026-11-04T12:00:00Z"), gate()).approved


def test_a_close_through_a_github_app_is_open_and_an_unread_rest_event_is_unknown(
    fake: FakeGitHub, client: Client
) -> None:
    v = judge(fake, client, issue_node(), gate(), via_app=True)
    assert v.state == "open" and v.lines == (f"DRIFT   {GATE} was closed through a GitHub App; it counts as open",)
    unread = judge(fake, client, issue_node(), gate(), via_app=None)
    assert unread.state == "unknown" and unread.lines[0].startswith(f"UNKNOWN {GATE}")
    never_approved(unread)


def test_the_rest_event_is_read_strictly() -> None:
    at = dt.datetime(2026, 11, 5, 12, 0, tzinfo=dt.UTC)
    base: dict[str, Any] = {"event": "closed", "created_at": "2026-11-05T12:00:00Z", "performed_via_github_app": None}
    app = {**base, "performed_via_github_app": {"id": 9}}
    earlier = {**base, "created_at": "2026-11-01T12:00:00Z", "performed_via_github_app": {"id": 9}}
    assert approvals.via_app_from_events([{"event": "labeled"}, base], at) is False
    assert approvals.via_app_from_events([earlier, app], at) is True
    assert approvals.via_app_from_events([earlier, base], at) is False  # the newest closed event decides
    bad_cases: list[Any] = [
        [], [{"event": "labeled"}], [{**base, "created_at": "2026-11-05T12:00:01Z"}], [{"event": "closed"}],
        [{**base, "performed_via_github_app": "x"}], None, [3], [{**base, "created_at": 5}],
    ]  # fmt: skip
    for bad in bad_cases:
        assert approvals.via_app_from_events(bad, at) is None


# -- UNKNOWN is never a pass -------------------------------------------------------------------------------------------


def test_a_missing_issue_is_unknown(fake: FakeGitHub, client: Client) -> None:
    read = read_issues(client, [REF])[REF]
    v = verdict(gate(), read, False)
    assert isinstance(read, Unread) and v.state == "unknown"
    assert v.lines == (f"UNKNOWN {GATE} cannot be read with this token, so no card's gate order can be told",)
    never_approved(v)


def test_an_answer_that_is_not_not_found_is_unknown_and_names_only_the_class(fake: FakeGitHub, client: Client) -> None:
    def refuse(_fake: FakeGitHub, _v: JSON) -> JSON:
        raise GqlError("FORBIDDEN", "secret-detail-from-github")

    fake.handlers["ApprovalIssues"] = refuse
    v = verdict(gate(), read_issues(client, [REF])[REF], False)
    assert v.state == "unknown" and "ApiError" in v.lines[0] and "secret-detail" not in v.lines[0]
    never_approved(v)


def test_a_transferred_issue_is_unknown(fake: FakeGitHub, client: Client) -> None:
    put(fake, issue_node(repo="acme/other", number=9), repo="acme/gates", number=21)
    v = verdict(gate(), read_issues(client, [REF])[REF], False)
    assert v.state == "unknown"
    assert v.lines == (f"UNKNOWN {GATE} now answers as acme/other#9; update process.gates",)
    never_approved(v)


def test_a_closed_issue_with_no_close_event_is_unknown(fake: FakeGitHub, client: Client) -> None:
    v = judge(fake, client, issue_node(timelineItems={"totalCount": 0, "nodes": []}), gate())
    assert v.state == "unknown"
    assert v.lines == (f"UNKNOWN {GATE} is closed but has no close event; its approval cannot be told",)
    never_approved(v)


def test_a_pull_request_in_place_of_an_issue_is_drift_and_never_approved(fake: FakeGitHub, client: Client) -> None:
    node = {"__typename": "PullRequest", "number": 21, "repository": {"nameWithOwner": "acme/gates"}}
    v = judge(fake, client, node, gate())
    assert v.state == "open" and v.lines == (f"DRIFT   {GATE} is a pull request; a gate is an issue",)
    never_approved(v)


def test_an_open_issue_is_open_not_approved(fake: FakeGitHub, client: Client) -> None:
    v = judge(fake, client, issue_node(state="OPEN", timelineItems={"totalCount": 0, "nodes": []}), gate())
    assert v.state == "open" and v.lines == (f"NOTE    {GATE} is not closed; it counts as open",)


def _without(key: str) -> Callable[[JSON], JSON]:
    return lambda n: {k: v for k, v in n.items() if k != key}


def _timeline(count: object, nodes: object) -> Callable[[JSON], JSON]:
    return lambda n: {**n, "timelineItems": {"totalCount": count, "nodes": nodes}}


def _event(**over: object) -> Callable[[JSON], JSON]:
    return _timeline(1, [closed_event(**over)])


def _event_without(key: str) -> Callable[[JSON], JSON]:
    return _timeline(1, [{k: v for k, v in closed_event().items() if k != key}])


def _field(**over: object) -> Callable[[JSON], JSON]:
    return lambda n: {**n, **over}


MALFORMED: dict[str, Callable[[JSON], JSON]] = {
    "typename other": _field(__typename="Repository"),
    "state weird": _field(state="MERGED"),
    "title null": _field(title=None),
    "body missing": _without("body"),
    "body number": _field(body=5),
    "createdAt not a date": _field(createdAt="yesterday"),
    "createdAt not utc": _field(createdAt="2026-11-03T09:00:00+02:00"),
    "lastEditedAt number": _field(lastEditedAt=7),
    "lastEditedAt missing": _without("lastEditedAt"),
    "association missing": _without("authorAssociation"),
    "association null": _field(authorAssociation=None),
    "association number": _field(authorAssociation=3),
    "association unknown word": _field(authorAssociation="BOSS"),
    "repository missing": _without("repository"),
    "repository name bad": _field(repository={"nameWithOwner": "no slash"}),
    "number mismatch type": _field(number="21"),
    "timeline null": _field(timelineItems=None),
    "timeline list": _field(timelineItems=[]),
    "count missing": _field(timelineItems={"nodes": [closed_event()]}),
    "count string": _timeline("1", [closed_event()]),
    "count bool": _timeline(True, [closed_event()]),
    "count above nodes": _timeline(2, []),
    "nodes without count": _timeline(0, [closed_event()]),
    "two nodes for last 1": _timeline(2, [closed_event(), closed_event()]),
    "nodes null": _timeline(1, None),
    "null node": _timeline(1, [None]),
    "reason number": _event(stateReason=1),
    "reason unknown word": _event(stateReason="DONE"),
    "reason null": _event(stateReason=None),
    "event time bad": _event(createdAt="soon"),
    "closer missing": _event_without("closer"),
    "closer typename unknown": _event(closer={"__typename": "Gist"}),
    "closer not object": _event(closer="PullRequest"),
    "duplicateOf missing": _event_without("duplicateOf"),
    "duplicateOf string": _event(duplicateOf="x"),
    "actor missing": _event_without("actor"),
    "actor typename unknown": _event(actor={"__typename": "Alien", "login": "x"}),
    "actor not object": _event(actor="octocat"),
    "actor login missing": _event(actor={"__typename": "Bot"}),
    "actor login number": _event(actor={"__typename": "Bot", "login": 4}),
    "user id missing": _event(actor={"__typename": "User", "login": "approver-one"}),
    "user id string": _event(actor=user("approver-one", "1001")),
    "user id bool": _event(actor=user("approver-one", True)),
    "user id zero": _event(actor=user("approver-one", 0)),
    "user id float": _event(actor=user("approver-one", 1001.0)),
}


@pytest.mark.parametrize("name", list(MALFORMED))
def test_a_malformed_node_is_unknown_never_approved_or_empty(fake: FakeGitHub, client: Client, name: str) -> None:
    v = judge(fake, client, MALFORMED[name](issue_node()), gate())
    assert v.state == "unknown", name
    assert v.lines and v.lines[0].startswith(f"UNKNOWN {GATE}")
    never_approved(v)


def test_a_verdict_that_crashes_is_unknown_with_only_the_class_name(fake: FakeGitHub, client: Client) -> None:
    put(fake, issue_node())
    read = read_issues(client, [REF])[REF]
    v = verdict(gate(approvers=cast(Any, 5)), read, False)
    assert v.state == "unknown" and v.lines == (f"UNKNOWN {GATE} could not be judged (TypeError)",)
    never_approved(v)


# -- the entry (M13), the freeze, the author ---------------------------------------------------------------------------


M13 = (
    "DRIFT   SCOPE the change adding acme/app#55 cites acme/gates#21, which does not mention acme/app#55; "
    "the approval is not for this change"
)


def test_an_approval_that_does_not_name_its_entry_is_not_for_this_change(fake: FakeGitHub, client: Client) -> None:
    v = judge(fake, client, issue_node(title="Change: something", body="Approve the thing."))
    assert v.state == "open" and v.lines == (M13,)


@pytest.mark.parametrize(
    ("title", "body", "counts"),
    [
        ("add acme/app#55", "", True),
        ("x", "see acme/app#55.", True),
        ("x", "(acme/app#55)", True),
        ("x", "acme/app#555", False),
        ("x", "acme/app#5", False),
        ("x", "other-acme/app#55", False),
        ("x", "acme/app#55/extra", False),
        ("x", "ACME/APP#55", False),
        ("x", "acme/app\uff03" + "55", False),
    ],
)
def test_the_entry_must_appear_as_a_whole_token(
    fake: FakeGitHub, client: Client, title: str, body: str, counts: bool
) -> None:
    v = judge(fake, client, issue_node(title=title, body=body))
    assert v.approved is counts, (title, body)


def test_a_removal_names_its_verb(fake: FakeGitHub, client: Client) -> None:
    v = judge(fake, client, issue_node(title="t", body="b"), check(action="removing"))
    assert v.lines == (M13.replace("adding", "removing"),)


def test_no_issue_text_reaches_a_line(fake: FakeGitHub, client: Client) -> None:
    sentinel = "SENTINEL-TEXT-9f2c"
    lines: tuple[str, ...] = judge(fake, client, issue_node(title=sentinel, body=sentinel)).lines
    for node in (
        close_with(actor=None),
        close_with(stateReason="NOT_PLANNED"),
        issue_node(lastEditedAt="2026-12-01T00:00:00Z"),
    ):
        lines += judge(fake, client, {**node, "title": sentinel, "body": sentinel}).lines
    assert len(lines) == 4 and not any(sentinel in line for line in lines)


def test_a_change_issue_created_before_the_freeze_is_open(fake: FakeGitHub, client: Client) -> None:
    before = judge(fake, client, issue_node(createdAt="2026-11-01T23:59:59Z"))
    assert before.state == "open" and before.lines == (
        "DRIFT   SCOPE acme/gates#21 was created before the baseline froze on 2026-11-02; it counts as open",
    )
    assert judge(fake, client, issue_node(createdAt="2026-11-02T00:00:00Z")).approved


def test_the_freeze_issue_must_close_by_the_end_of_the_frozen_day(fake: FakeGitHub, client: Client) -> None:
    freeze = check(kind="freeze", entry=None)
    assert judge(fake, client, close_with(createdAt="2026-11-02T23:59:59Z"), freeze).approved
    v = judge(fake, client, close_with(createdAt="2026-11-03T00:00:00Z"), freeze)
    assert v.state == "open"
    assert v.lines == (
        "DRIFT   SCOPE acme/gates#21 was closed after the baseline froze on 2026-11-02; it counts as open",
    )


def test_a_change_check_without_its_entry_or_its_date_is_unknown_not_approved(fake: FakeGitHub, client: Client) -> None:
    for chk in (check(entry=None), check(frozen=None), check(kind="freeze", frozen=None), check(kind="other")):
        v = judge(fake, client, issue_node(), chk)
        assert v.state == "unknown", chk
        never_approved(v)


@pytest.mark.parametrize("association", ["OWNER", "MEMBER", "COLLABORATOR"])
def test_issues_from_owners_members_and_collaborators_are_trusted(
    fake: FakeGitHub, client: Client, association: str
) -> None:
    assert judge(fake, client, issue_node(authorAssociation=association)).approved


@pytest.mark.parametrize("association", ["CONTRIBUTOR", "FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "MANNEQUIN", "NONE"])
def test_an_issue_from_anyone_else_is_open(fake: FakeGitHub, client: Client, association: str) -> None:
    v = judge(fake, client, issue_node(authorAssociation=association))
    assert v.state == "open" and v.lines == (
        "DRIFT   SCOPE acme/gates#21 was opened by an account that is not an owner, member or collaborator; "
        "it counts as open",
    )


# -- output goes through ctx.say ---------------------------------------------------------------------------------------


def test_lines_reach_the_log_only_through_say_and_are_escaped(fake: FakeGitHub, client: Client) -> None:
    hostile = "a::b\x1b[31m\u202e"
    v = judge(fake, client, close_with(actor={"__typename": "Bot", "login": hostile}), gate())
    out = io.StringIO()
    ctx = Context(board=cast(Any, None), client=client, out=out, today=dt.date(2026, 11, 6), env={})
    approvals.emit(ctx, v)
    text = out.getvalue()
    assert "::" not in text and "\x1b" not in text and "\u202e" not in text
    assert "a:\\x3ab\\x1b[31m\\u202e" in text and text.endswith("\n")


# -- the read: batching, dedupe, bounds -------------------------------------------------------------------------------


def test_120_distinct_references_are_read_in_three_queries_and_duplicates_once(
    fake: FakeGitHub, client: Client
) -> None:
    for n in range(1, 121):
        put(fake, issue_node(number=n))
    got = read_issues(client, [f"acme/gates#{n}" for n in range(1, 121)])
    assert fake.requests.count("ApprovalIssues") == 3 and len(got) == 120
    assert all(isinstance(r, Read) for r in got.values())
    spy = Spy(client)
    again = read_issues(spy, ["acme/gates#1", "acme/gates#1", "ACME/Gates#1"])
    assert len(spy.sent) == 1 and len(spy.sent[0][1]) == 3 and len(again) == 2  # one alias: o0, n0, i0


def test_one_missing_issue_does_not_hide_the_others_and_a_pathless_error_hides_all(
    fake: FakeGitHub, client: Client
) -> None:
    put(fake, issue_node(number=1))
    got = read_issues(client, ["acme/gates#1", "acme/gates#2"])
    assert isinstance(got["acme/gates#1"], Read) and isinstance(got["acme/gates#2"], Unread)

    def broken(_fake: FakeGitHub, _v: JSON) -> JSON:
        raise GqlError("NOT_FOUND", "no path given", {"r0": None, "r1": None})

    fake.handlers["ApprovalIssues"] = broken
    again = read_issues(client, ["acme/gates#1", "acme/gates#2"])
    assert all(isinstance(r, Unread) for r in again.values())

    def pathless_beside_good_data(_fake: FakeGitHub, _v: JSON) -> JSON:
        good = issue_node(number=1)
        raise GqlError("NOT_FOUND", "no path given", {"r0": {"issueOrPullRequest": good}, "r1": None})

    fake.handlers["ApprovalIssues"] = pathless_beside_good_data
    tainted = read_issues(client, ["acme/gates#1", "acme/gates#2"])
    assert all(isinstance(r, Unread) for r in tainted.values())  # an error that names no alias taints the batch


def test_references_are_validated_and_variables_not_interpolated(fake: FakeGitHub, client: Client) -> None:
    hostile = [
        "acme/gates#1) { x } #",
        "acme/gates#0",
        "acme/gates#99999999999",
        "no-hash",
        "a b/c#1",
        "\uff41cme/gates#1",
    ]
    put(fake, issue_node(number=1))
    got = read_issues(client, [*hostile, "acme/gates#1"])
    assert fake.requests == ["ApprovalIssues"]  # one query, for the valid reference only
    assert all(isinstance(got[h], Unread) for h in hostile) and isinstance(got["acme/gates#1"], Read)


def test_more_references_than_the_cap_are_cannot_tell_not_dropped(
    fake: FakeGitHub, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(approvals, "MAX_REFS", 2)
    for n in (1, 2, 3):
        put(fake, issue_node(number=n))
    got = read_issues(client, ["acme/gates#1", "acme/gates#2", "acme/gates#3"])
    assert isinstance(got["acme/gates#1"], Read) and isinstance(got["acme/gates#3"], Unread)
    assert verdict(gate(), got["acme/gates#3"], False).state == "unknown"
