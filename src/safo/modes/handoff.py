# SPDX-License-Identifier: Apache-2.0
"""handoff check: is the latest review report about the head the pull request has now?

Read-only: three GraphQL queries and nothing else. It finds the newest report in the pull request's comments whose
header has a `HEAD:` line (the DoIA report header), and compares that SHA to the pull request's current head.

    exit 0  FRESH    the report names the current head
    exit 1  STALE    the report names an older head
    exit 2  UNKNOWN  no report, an unusable SHA, or an answer from GitHub that cannot be read in full

This proves staleness, not authorship: every agent comments through the maintainer's account, so a forged line from
that account reads as fresh. Only comments by an OWNER, MEMBER or COLLABORATOR are read, so a fork contributor's
comment cannot make a pull request look reviewed. Nothing here blocks a merge or invalidates anything.
"""

from __future__ import annotations

import argparse
import itertools
import re
from collections.abc import Mapping
from typing import Any

from safo import credentials
from safo.context import LocalContext
from safo.errors import EXIT_DRIFT, EXIT_OK, EXIT_UNKNOWN, ApiError, ConfigError, MalformedDataError, SafoError
from safo.graphql import GRAPHQL_URL, Client
from safo.modes import LocalMode, register_local
from safo.modes.reconcile import safe

FRESH, STALE, UNKNOWN = "FRESH", "STALE", "UNKNOWN"
TRUSTED = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
MAX_COMMENT_PAGES = 10  # 100 comments a page: a longer thread is unknown, never half read
MAX_COMMIT_PAGES = 3  # GitHub lists at most 250 commits of a pull request
REPO = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100})")
NUMBER = re.compile(r"[1-9][0-9]{0,8}")
FULL_SHA = re.compile(r"[0-9a-f]{40}")
SHA = re.compile(r"[0-9a-fA-F]{7,40}")  # fewer than 7 characters is never enough to name a commit
TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
ROLE_LINE = re.compile(r"ROLE:[ \t].*")
HEAD_LINE = re.compile(r"HEAD:[ \t]+(\S+)(?:[ \t]+BASE:[ \t]+\S+)?[ \t]*")

PR_QUERY = """query HandoffPr($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) { pullRequest(number: $number) { headRefOid } }
}"""
COMMENTS_QUERY = """query HandoffComments($owner: String!, $name: String!, $number: Int!, $endCursor: String) {
  repository(owner: $owner, name: $name) { pullRequest(number: $number) {
    comments(first: 100, after: $endCursor) {
      pageInfo { hasNextPage endCursor }
      nodes { authorAssociation createdAt body }
    }
  } }
}"""
COMMITS_QUERY = """query HandoffCommits($owner: String!, $name: String!, $number: Int!, $endCursor: String) {
  repository(owner: $owner, name: $name) { pullRequest(number: $number) {
    commits(first: 100, after: $endCursor) {
      pageInfo { hasNextPage endCursor }
      nodes { commit { oid } }
    }
  } }
}"""


class Unknown(Exception):
    """The question cannot be answered. The reason is ours, never GitHub's text."""


def _bad(what: str) -> Unknown:
    return Unknown(what)


def pages_bounded(client: Client, document: str, variables: Mapping[str, Any], path: list[str], limit: int, what: str,
                  require: tuple[str, ...] = ()) -> list[dict[str, Any]]:  # fmt: skip
    """Every node of a connection, or Unknown when it needs more than `limit` pages."""
    nodes: list[dict[str, Any]] = []
    for count, page in enumerate(client.pages(document, variables, path, require), start=1):
        nodes.extend(page["nodes"])
        if page["pageInfo"]["hasNextPage"] and count >= limit:
            raise _bad(f"the {what} are truncated (more than {limit} pages), so the newest cannot be known")
    return nodes


def head_of(client: Client, variables: Mapping[str, Any]) -> str:
    data = client.execute(PR_QUERY, variables)
    repository = data.get("repository") if isinstance(data, dict) else None
    pull = repository.get("pullRequest") if isinstance(repository, dict) else None
    if not isinstance(pull, dict):
        raise _bad("the pull request could not be read")
    head = pull.get("headRefOid")
    if not isinstance(head, str) or not FULL_SHA.fullmatch(head):
        raise _bad("the pull request head is missing or is not a full SHA")
    return head


def reports(nodes: list[dict[str, Any]]) -> list[tuple[str, set[str | None]]]:
    """(time, heads) for each trusted comment holding a report header, oldest first.

    Every node is checked for its three fields first, trusted or not: one wrong shape poisons the whole read.
    """
    found: list[tuple[str, set[str | None]]] = []
    for node in nodes:
        association, created, body = node.get("authorAssociation"), node.get("createdAt"), node.get("body")
        if not isinstance(association, str) or not isinstance(created, str) or not isinstance(body, str):
            raise MalformedDataError("a comment lacks authorAssociation, createdAt or body as text")
        if association not in TRUSTED:
            continue
        heads = report_heads(body)
        if not heads:
            continue
        if not TIME.fullmatch(created):
            raise MalformedDataError("a comment's createdAt is not a timestamp")
        found.append((created, heads))
    return sorted(found, key=lambda entry: entry[0])


def report_heads(body: str) -> set[str | None]:
    """The HEAD value of each report header in a comment (a ROLE line, then the HEAD line); None when unusable."""
    lines = [text.rstrip("\r") for text in body.split("\n")]
    heads: set[str | None] = set()
    for before, after in itertools.pairwise(lines):
        if not ROLE_LINE.fullmatch(before.strip()) or not after.strip().startswith("HEAD:"):
            continue
        match = HEAD_LINE.fullmatch(after.strip())
        value = match.group(1) if match else None
        heads.add(value.lower() if value and SHA.fullmatch(value) else None)
    return heads


def resolve(client: Client, variables: Mapping[str, Any], reported: str) -> str:
    """The full SHA a report names: itself when it is full, else the one commit of the pull request it prefixes."""
    if len(reported) == 40:
        return reported
    nodes = pages_bounded(client, COMMITS_QUERY, variables, ["repository", "pullRequest", "commits"], MAX_COMMIT_PAGES,
                          "commits", ())  # fmt: skip
    oids: list[str] = []
    for node in nodes:
        commit = node.get("commit")
        oid = commit.get("oid") if isinstance(commit, dict) else None
        if not isinstance(oid, str) or not FULL_SHA.fullmatch(oid):
            raise MalformedDataError("a commit has no full oid")
        oids.append(oid)
    matches = {oid for oid in oids if oid.startswith(reported)}
    if len(matches) > 1:
        raise _bad(f"the short SHA {reported} is ambiguous among the commits of the pull request")
    if not matches:
        raise _bad(f"the short SHA {reported} is not a commit of the pull request")
    return matches.pop()


def verdict(client: Client, variables: Mapping[str, Any]) -> tuple[str, str]:
    """(FRESH | STALE, message), or raises Unknown / SafoError."""
    head = head_of(client, variables)
    nodes = pages_bounded(client, COMMENTS_QUERY, variables, ["repository", "pullRequest", "comments"],
                          MAX_COMMENT_PAGES, "comments", ("authorAssociation", "createdAt", "body"))  # fmt: skip
    found = reports(nodes)
    if not found:
        raise _bad("no review report from an owner, member or collaborator has a HEAD line")
    newest = [entry for entry in found if entry[0] == found[-1][0]]
    heads: set[str | None] = set().union(*(entry[1] for entry in newest))
    if len(heads) != 1:
        raise _bad("the newest report names more than one HEAD, so it is ambiguous")
    reported = heads.pop()
    if reported is None:
        raise _bad("the newest report's HEAD is not a SHA of 7 to 40 hex characters")
    full = resolve(client, variables, reported)
    if full == head:
        return FRESH, f"reviewed {full[:7]} is the current head"
    return STALE, f"reviewed {full[:7]}, pull request head is {head[:7]}"


def make_client(env: Mapping[str, str]) -> Client:
    creds = credentials.from_env(env) or credentials.from_gh(env, env.get("SAFO_GH_USER", "").strip())
    if creds is None:
        raise credentials.NoTokenError("no token: set SAFO_TOKEN, or log in with `gh auth login`")
    url = env.get("GITHUB_GRAPHQL_URL", "").strip() or GRAPHQL_URL
    if creds.kind == credentials.GH and url != GRAPHQL_URL:
        raise ConfigError(f"a gh token is only sent to {GRAPHQL_URL}; GITHUB_GRAPHQL_URL cannot redirect it")
    return Client(creds.token, url)


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    if args.action != "check":
        raise ConfigError("the only handoff action is `check`")
    try:
        match = REPO.fullmatch(args.repo)
        if not match or match.group(2) in (".", "..") or not NUMBER.fullmatch(args.pr):
            raise _bad("expected <owner/repo> and a pull request number")
        variables = {"owner": match.group(1), "name": match.group(2), "number": int(args.pr)}
        state, message = verdict(make_client(ctx.env), variables)
    except Unknown as why:
        ctx.say(f"{UNKNOWN} {why}")
        return EXIT_UNKNOWN
    except (SafoError, ApiError) as error:
        ctx.say(f"{UNKNOWN} {safe(str(error))[:300]}")
        return EXIT_UNKNOWN
    ctx.say(f"{state} {message}")
    return EXIT_OK if state == FRESH else EXIT_DRIFT


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("action", choices=["check"])
    parser.add_argument("repo", help="owner/repo")
    parser.add_argument("pr", help="the pull request number")


register_local(
    LocalMode(
        "handoff", "check whether the latest review report names the pull request's current head", add_arguments, run
    )
)
