# SPDX-License-Identifier: Apache-2.0
"""Pull request reads for `handoff check`: the head, the comments with their author association, the commit list."""

from __future__ import annotations

from fakegh.core import JSON, FakeGitHub, FPull, GqlError, handler


def _pull(fake: FakeGitHub, v: JSON) -> FPull:
    found = fake.pulls.get((f"{v['owner']}/{v['name']}".lower(), int(v["number"])))
    if found is None:
        raise GqlError(
            "NOT_FOUND", f"Could not resolve to a PullRequest with the number of {v['number']}.", {"repository": None}
        )
    return found


@handler("HandoffPr")
def pr_head(fake: FakeGitHub, v: JSON) -> JSON:
    found = _pull(fake, v)
    return {"repository": {"pullRequest": {"headRefOid": found.head, "state": found.state, "isDraft": found.draft}}}


@handler("HandoffComments")
def pr_comments(fake: FakeGitHub, v: JSON) -> JSON:
    return {"repository": {"pullRequest": {"comments": fake.connection(_pull(fake, v).comments, v)}}}


@handler("HandoffTimeline")
def pr_timeline(fake: FakeGitHub, v: JSON) -> JSON:
    found = _pull(fake, v)
    commit = found.last_commit if found.last_commit is not None else {"oid": found.head, "committedDate": found.pushed}
    return {
        "repository": {
            "pullRequest": {
                "timelineItems": {"pageInfo": {"hasPreviousPage": found.more_events}, "nodes": found.events},
                "commits": {"nodes": [{"commit": commit}]},
            }
        }
    }


@handler("HandoffCommits")
def pr_commits(fake: FakeGitHub, v: JSON) -> JSON:
    nodes = [{"commit": {"oid": oid}} for oid in _pull(fake, v).commits]
    return {"repository": {"pullRequest": {"commits": fake.connection(nodes, v)}}}
