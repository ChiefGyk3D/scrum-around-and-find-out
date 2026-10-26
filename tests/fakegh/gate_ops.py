# SPDX-License-Identifier: Apache-2.0
"""The fake's answer to the branch-gate read: default branch, classic protection rule and rulesets of one repository."""

from __future__ import annotations

from fakegh.core import JSON, FakeGitHub, GqlError, handler


@handler("RepoBranchGate")
def branch_gate(fake: FakeGitHub, v: JSON) -> JSON:
    repo = fake.repos.get(f"{v['owner']}/{v['name']}".lower())
    if repo is None or not repo.installed:
        raise GqlError(
            "NOT_FOUND",
            f"Could not resolve to a Repository with the name '{v['owner']}/{v['name']}'.",
            {"repository": None},
        )
    if repo.viewer_permission == "NONE":
        raise GqlError("FORBIDDEN", "Resource not accessible by integration", {"repository": None})
    branch = None
    if repo.default_branch is not None:
        branch = {"name": repo.default_branch, "branchProtectionRule": repo.protection}
    return {
        "repository": {
            "nameWithOwner": repo.full_name,
            "isArchived": repo.archived,
            "viewerPermission": repo.viewer_permission,
            "defaultBranchRef": branch,
            "rulesets": {"totalCount": len(repo.rulesets), "nodes": repo.rulesets},
        }
    }
