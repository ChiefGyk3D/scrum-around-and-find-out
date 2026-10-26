# SPDX-License-Identifier: Apache-2.0
"""handoff check: does the latest review report name the head the pull request has now?

Read-only: GraphQL queries and nothing else. It finds the newest report by a reviewing role in the pull request's
comments (the DoIA report header: a `ROLE:` line, then `HEAD: <sha>   BASE: <sha>`) and compares that SHA to the pull
request's current head.

    exit 0  FRESH    the report names the current head
    exit 1  STALE    the report names an older head
    exit 2  UNKNOWN  no report, an unusable SHA, a crash, or an answer from GitHub that cannot be read in full

Exit 1 means one thing only: a report was read in full and its head is not the current one. Anything that goes wrong
on the way is exit 2.

This proves staleness, not authorship: every agent comments through the maintainer's account, so a forged line from
that account reads as fresh. Only comments by an OWNER, MEMBER or COLLABORATOR are read, so a fork contributor's
comment cannot make a pull request look reviewed. It does not say the review approved anything. Nothing here blocks a
merge or invalidates anything.
"""

from __future__ import annotations

import argparse
import re
from collections.abc import Mapping
from typing import Any

from safo import credentials
from safo.context import LocalContext
from safo.errors import EXIT_DRIFT, EXIT_OK, EXIT_UNKNOWN, ConfigError, MalformedDataError, SafoError
from safo.graphql import GRAPHQL_URL, Client
from safo.modes import LocalMode, register_local
from safo.modes.reconcile import safe

FRESH, STALE, UNKNOWN = "FRESH", "STALE", "UNKNOWN"
TRUSTED = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
ROLES = ("implementer", "reviewer", "adversarial-reviewer", "transcriber", "lead")  # the DoIA report roles
DEFAULT_ROLES = ("reviewer", "adversarial-reviewer")
VERDICTS = frozenset({"SHIP", "SHIP WITH CHANGES", "DO NOT SHIP", "FINDINGS", "APPROVE", "NOT ATTACKED"})
STATES = frozenset({"OPEN", "CLOSED", "MERGED"})
MAX_COMMENT_PAGES = 10  # 100 comments a page: a longer thread is unknown, never half read
MAX_COMMIT_PAGES = 3  # GitHub lists at most 250 commits of a pull request
VERDICT_WINDOW = 12  # lines after the HEAD line searched for a VERDICT line
REPO = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100})")
NUMBER = re.compile(r"[1-9][0-9]{0,8}")
FULL_SHA = re.compile(r"[0-9a-f]{40}")
SHA = re.compile(r"[0-9a-fA-F]{7,40}")  # fewer than 7 characters is never enough to name a commit
TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
HEAD_LINE = re.compile(r"HEAD:[ \t]+(\S+)(?:[ \t]+BASE:[ \t]+\S+)?[ \t]*")
CLASS_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,60}")

PR_QUERY = """query HandoffPr($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) { pullRequest(number: $number) { headRefOid state isDraft } }
}"""
COMMENTS_QUERY = """query HandoffComments($owner: String!, $name: String!, $number: Int!, $endCursor: String) {
  repository(owner: $owner, name: $name) { pullRequest(number: $number) {
    comments(first: 100, after: $endCursor) {
      pageInfo { hasNextPage endCursor }
      nodes { authorAssociation createdAt lastEditedAt isMinimized body }
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

Entry = tuple[str | None, str | None, str | None]  # (role, head, verdict); None when unusable (the verdict: absent)


class Unknown(Exception):
    """The question cannot be answered. The reason is ours, never GitHub's text."""


def _bad(what: str) -> Unknown:
    return Unknown(what)


def pages_bounded(
    client: Client,
    document: str,
    variables: Mapping[str, Any],
    path: list[str],
    limit: int,
    what: str,
    require: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Every node of a connection, or Unknown when it needs more than `limit` pages."""
    nodes: list[dict[str, Any]] = []
    for count, page in enumerate(client.pages(document, variables, path, require), start=1):
        nodes.extend(page["nodes"])
        if page["pageInfo"]["hasNextPage"] and count >= limit:
            raise _bad(f"the {what} are truncated (more than {limit} pages), so the newest cannot be known")
    return nodes


def read_pull(client: Client, variables: Mapping[str, Any]) -> tuple[str, str]:
    """(head, flags): the full head SHA, and "" or " (draft)", " (closed)", " (merged)"."""
    data = client.execute(PR_QUERY, variables)
    repository = data.get("repository") if isinstance(data, dict) else None
    pull = repository.get("pullRequest") if isinstance(repository, dict) else None
    if not isinstance(pull, dict):
        raise _bad("the pull request could not be read")
    head, state, draft = pull.get("headRefOid"), pull.get("state"), pull.get("isDraft")
    if not isinstance(head, str) or not FULL_SHA.fullmatch(head):
        raise _bad("the pull request head is missing or is not a full SHA")
    if not isinstance(state, str) or state not in STATES or not isinstance(draft, bool):
        raise _bad("the pull request state or draft flag is missing or not recognized")
    flags = " (merged)" if state == "MERGED" else " (closed)" if state == "CLOSED" else " (draft)" if draft else ""
    return head, flags


def visible_lines(body: str) -> list[str]:
    """The lines of a comment that are not inside a fenced code block or an HTML comment, stripped.

    A report pasted into either is a quotation, not a report. An unclosed fence or comment hides the rest.
    """
    lines: list[str] = []
    fence: str | None = None
    in_comment = False
    for raw in body.split("\n"):
        line = raw.rstrip("\r")
        if fence is not None:
            if line.lstrip(" ").startswith(fence):
                fence = None
            continue
        text, rest = "", line
        while True:
            if in_comment:
                end = rest.find("-->")
                if end < 0:
                    break
                rest, in_comment = rest[end + 3 :], False
            else:
                start = rest.find("<!--")
                if start < 0:
                    text += rest
                    break
                text, rest, in_comment = text + rest[:start], rest[start + 4 :], True
        opener = text.lstrip(" ")[:3]
        if opener in ("```", "~~~"):
            fence = opener
            continue
        lines.append(text.strip())
    return lines


def report_entries(body: str) -> list[Entry]:
    """One entry per report header in a comment: a `ROLE:` line immediately followed by a `HEAD:` line."""
    lines = visible_lines(body)
    entries: list[Entry] = []
    for index, line in enumerate(lines[:-1]):
        if not line.startswith("ROLE:") or not lines[index + 1].startswith("HEAD:"):
            continue
        words = line[len("ROLE:") :].split()
        role = words[0] if words and words[0] in ROLES else None
        match = HEAD_LINE.fullmatch(lines[index + 1])
        head = match.group(1) if match and SHA.fullmatch(match.group(1)) else None
        block: list[str] = []
        for after in lines[index + 2 : index + 2 + VERDICT_WINDOW]:
            if after.startswith("ROLE:"):
                break
            block.append(after)
        said = {after[len("VERDICT:") :].strip() for after in block if after.startswith("VERDICT:")}
        verdict_text = said.pop() if len(said) == 1 else None
        entries.append((role, head.lower() if head else None, verdict_text if verdict_text in VERDICTS else None))
    return entries


def newest_report(nodes: list[dict[str, Any]], roles: tuple[str, ...]) -> list[Entry]:
    """The entries of the newest trusted, visible comment that holds a report of a counted (or unreadable) role.

    Every node is checked for its fields first, trusted or not: one wrong shape poisons the whole read. A comment is
    dated by the later of its creation and its last edit.
    """
    found: list[tuple[str, list[Entry]]] = []
    for node in nodes:
        association, created, edited = node.get("authorAssociation"), node.get("createdAt"), node.get("lastEditedAt")
        body, minimized = node.get("body"), node.get("isMinimized")
        if not isinstance(association, str) or not isinstance(created, str) or not isinstance(body, str):
            raise MalformedDataError("a comment lacks authorAssociation, createdAt or body as text")
        if not isinstance(minimized, bool) or "lastEditedAt" not in node:
            raise MalformedDataError("a comment lacks isMinimized as a boolean or lastEditedAt")
        if not TIME.fullmatch(created) or not (edited is None or (isinstance(edited, str) and TIME.fullmatch(edited))):
            raise MalformedDataError("a comment's createdAt or lastEditedAt is not a timestamp")
        if minimized or association not in TRUSTED:
            continue
        entries = [entry for entry in report_entries(body) if entry[0] is None or entry[0] in roles]
        if entries:
            found.append((max(created, edited or created), entries))
    if not found:
        return []
    latest = max(when for when, _ in found)
    return [entry for when, entries in found if when == latest for entry in entries]


def resolve(client: Client, variables: Mapping[str, Any], reported: str) -> str:
    """The full SHA a report names: itself when it is full, else the one commit of the pull request it prefixes."""
    if len(reported) == 40:
        return reported
    nodes = pages_bounded(
        client, COMMITS_QUERY, variables, ["repository", "pullRequest", "commits"], MAX_COMMIT_PAGES, "commits"
    )
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


def verdict(client: Client, variables: Mapping[str, Any], roles: tuple[str, ...]) -> tuple[str, str]:
    """(FRESH | STALE, message), or raises Unknown / SafoError."""
    head, flags = read_pull(client, variables)
    nodes = pages_bounded(
        client,
        COMMENTS_QUERY,
        variables,
        ["repository", "pullRequest", "comments"],
        MAX_COMMENT_PAGES,
        "comments",
        ("authorAssociation", "createdAt", "isMinimized", "body"),
    )
    newest = newest_report(nodes, roles)
    if not newest:
        raise _bad(f"no review report ({', '.join(roles)}) from an owner, member or collaborator has a HEAD line")
    if len(set(newest)) != 1:
        raise _bad("the newest report names more than one role, HEAD or verdict, so it is ambiguous")
    role, reported, said = newest[0]
    if role is None or reported is None:
        raise _bad("the newest report's ROLE or HEAD is unreadable (a HEAD must be 7 to 40 hex characters)")
    full = resolve(client, variables, reported)
    if read_pull(client, variables)[0] != head:
        raise _bad("the head moved while reading, so nothing was compared")
    label = f"{role} report" + (f" VERDICT {said}" if said else "")
    if full == head:
        return FRESH, f"{label} names the current head {full[:7]}{flags}"
    return STALE, f"{label} names {full[:7]}, the pull request head is {head[:7]}{flags}"


def make_client(env: Mapping[str, str]) -> Client:
    creds = credentials.from_env(env) or credentials.from_gh(env, env.get("SAFO_GH_USER", "").strip())
    if creds is None:
        raise credentials.NoTokenError("no token: set SAFO_TOKEN, or log in with `gh auth login`")
    url = env.get("GITHUB_GRAPHQL_URL", "").strip() or GRAPHQL_URL
    if creds.kind == credentials.GH and url != GRAPHQL_URL:
        raise ConfigError(f"a gh token is only sent to {GRAPHQL_URL}; GITHUB_GRAPHQL_URL cannot redirect it")
    return Client(creds.token, url)


def parse_roles(text: str | None) -> tuple[str, ...]:
    if text is None:
        return DEFAULT_ROLES
    names = tuple(text.split(","))
    if not names or any(name not in ROLES for name in names):
        raise _bad(f"--roles takes a comma list of: {', '.join(ROLES)}")
    return names


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    if args.action != "check":
        raise ConfigError("the only handoff action is `check`")
    try:
        roles = parse_roles(args.roles)
        match = REPO.fullmatch(args.repo)
        if not match or match.group(2) in (".", "..") or not NUMBER.fullmatch(args.pr):
            raise _bad("expected <owner/repo> and a pull request number")
        variables = {"owner": match.group(1), "name": match.group(2), "number": int(args.pr)}
        state, message = verdict(make_client(ctx.env), variables, roles)
    except Unknown as why:
        ctx.say(f"{UNKNOWN} {why}")
        return EXIT_UNKNOWN
    except SafoError as error:
        ctx.say(f"{UNKNOWN} {safe(str(error))[:300]}")
        return EXIT_UNKNOWN
    except Exception as error:  # a crash must read as "cannot tell" (2), never as stale (1)
        name = type(error).__name__
        ctx.say(f"{UNKNOWN} internal error ({name if CLASS_NAME.fullmatch(name) else 'Exception'})")
        return EXIT_UNKNOWN
    ctx.say(f"{state} {message}")
    return EXIT_OK if state == FRESH else EXIT_DRIFT


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("action", choices=["check"])
    parser.add_argument("repo", help="owner/repo")
    parser.add_argument("pr", help="the pull request number")
    parser.add_argument(
        "--roles",
        default=None,
        help=f"roles whose report counts as a review, comma list (default: {','.join(DEFAULT_ROLES)})",
    )


register_local(
    LocalMode(
        "handoff", "check whether the latest review report names the pull request's current head", add_arguments, run
    )
)
