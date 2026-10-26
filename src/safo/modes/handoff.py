# SPDX-License-Identifier: Apache-2.0
"""handoff check: does the latest review report name the head the pull request has now, and was it written after?

Read-only: GraphQL queries and nothing else. It finds the newest report by a reviewing role in the pull request's
comments (the DoIA report header: a `ROLE:` line, then `HEAD: <sha>   BASE: <sha>`), compares that SHA to the pull
request's current head, and checks that the report was posted no earlier than the moment that commit became the head.

    exit 0  FRESH    the report names the current head and is not older than it
    exit 1  STALE    the report names an older head, predates the head, or predates a base change
    exit 2  UNKNOWN  no report, an unusable SHA, a crash, or an answer from GitHub that cannot be read in full

Exit 1 means one thing only: a report was read in full and it is not current. Anything that goes wrong on the way is
exit 2, and a failure to print the answer never changes the exit code.

A report is read from the HTML GitHub rendered from the comment (`bodyHTML`), never from the raw Markdown, and only
out of the text of a top-level paragraph. What a person sees as code, a quotation, a list, a table or a collapsed
block is not a report.

This proves staleness, not authorship: every agent comments through the maintainer's account, so a forged line from
that account reads as fresh. Only comments by an OWNER, MEMBER or COLLABORATOR are read, so a fork contributor's
comment cannot make a pull request look reviewed. It does not say the review approved anything. Nothing here blocks a
merge or invalidates anything.
"""

from __future__ import annotations

import argparse
import re
from collections.abc import Mapping
from html.parser import HTMLParser
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
MAX_HTML = 200_000  # characters of one comment's rendered HTML that are read; more is unknown
MAX_DEPTH = 50  # elements open at once in that HTML; deeper is unknown
VERDICT_WINDOW = 12  # lines after the HEAD line searched for a VERDICT line
# Void elements have no end tag. Inline elements keep a paragraph's text readable; text inside any other element
# (code, span, an unknown tag) is dropped, so an unrecognized wrapper never makes a report.
VOID = frozenset({"br", "hr", "img", "input", "meta", "link", "wbr", "source", "area", "base", "col", "embed", "track"})
INLINE = frozenset({"a", "strong", "em", "b", "i", "del", "s", "g-emoji"})
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
      nodes { authorAssociation createdAt lastEditedAt isMinimized bodyHTML }
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
TIMELINE_QUERY = """query HandoffTimeline($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) { pullRequest(number: $number) {
    timelineItems(itemTypes: [HEAD_REF_FORCE_PUSHED_EVENT, BASE_REF_CHANGED_EVENT], last: 50) {
      pageInfo { hasPreviousPage }
      nodes {
        __typename
        ... on HeadRefForcePushedEvent { createdAt afterCommit { oid } }
        ... on BaseRefChangedEvent { createdAt }
      }
    }
    commits(last: 1) { nodes { commit { oid committedDate } } }
  } }
}"""

Entry = tuple[str | None, str | None, str | None]  # (role, head, verdict); None when unusable (the verdict: absent)


class Unknown(Exception):
    """The question cannot be answered. The reason is ours, never GitHub's text."""


class UnreadableHtml(MalformedDataError):
    """A comment's HTML is too big, nested too deeply or not well formed. The message never quotes the HTML."""


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


def pull_of(data: Any) -> dict[str, Any]:
    repository = data.get("repository") if isinstance(data, dict) else None
    pull = repository.get("pullRequest") if isinstance(repository, dict) else None
    if not isinstance(pull, dict):
        raise _bad("the pull request could not be read")
    return pull


def read_pull(client: Client, variables: Mapping[str, Any]) -> tuple[str, str]:
    """(head, flags): the full head SHA, and "" or " (draft)", " (closed)", " (merged)"."""
    pull = pull_of(client.execute(PR_QUERY, variables))
    head, state, draft = pull.get("headRefOid"), pull.get("state"), pull.get("isDraft")
    if not isinstance(head, str) or not FULL_SHA.fullmatch(head):
        raise _bad("the pull request head is missing or is not a full SHA")
    if not isinstance(state, str) or state not in STATES or not isinstance(draft, bool):
        raise _bad("the pull request state or draft flag is missing or not recognized")
    flags = " (merged)" if state == "MERGED" else " (closed)" if state == "CLOSED" else " (draft)" if draft else ""
    return head, flags


class _Reader(HTMLParser):
    """The text of top-level paragraphs, one line per `<br>` or newline, and nothing else.

    A paragraph is read only when it is a direct child of the document. Inside it only plain inline elements keep the
    text readable. Every other element (pre, code, blockquote, details, summary, li, table, script, style, template,
    div, an unknown tag, anything with `hidden`) makes its text, and any paragraph inside it, unreadable. HTML comments
    and declarations are dropped. Mismatched or unclosed tags, too much nesting and too much text are errors.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, bool]] = []  # (tag, text inside it is readable)
        self.text: list[str] = []
        self.lines: list[str] = []
        self.after_br = False  # GitHub writes `<br>` and then a newline: the pair is one line break

    def _readable(self) -> bool:
        return bool(self.stack) and all(ok for _, ok in self.stack)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.after_br = False
        if tag in VOID:
            if tag == "br" and self._readable():
                self.text.append("\n")
                self.after_br = True
            return
        if len(self.stack) >= MAX_DEPTH:
            raise UnreadableHtml("a comment's HTML is nested too deeply")
        visible = not any(name == "hidden" for name, _ in attrs)
        ok = tag == "p" and visible if not self.stack else self._readable() and tag in INLINE and visible
        self.stack.append((tag, ok))

    def handle_endtag(self, tag: str) -> None:
        self.after_br = False
        if tag in VOID:
            return
        if not self.stack or self.stack[-1][0] != tag:
            raise UnreadableHtml("a comment's HTML is not well formed")
        _, ok = self.stack.pop()
        if not self.stack:
            if ok:
                self.lines.extend(line.strip() for line in "".join(self.text).split("\n"))
                self.lines.append("")
            self.text.clear()

    def handle_data(self, data: str) -> None:
        if self.after_br and data.startswith("\n"):
            data = data[1:]
        self.after_br = False
        if self._readable():
            self.text.append(data)


def report_lines(html: str) -> list[str]:
    """The lines of the top-level paragraphs of rendered HTML, a blank line after each paragraph."""
    if len(html) > MAX_HTML:
        raise UnreadableHtml("a comment's HTML is too large")
    reader = _Reader()
    reader.feed(html)
    reader.close()
    if reader.stack:
        raise UnreadableHtml("a comment's HTML is not well formed")
    return reader.lines


def report_entries(lines: list[str]) -> list[Entry]:
    """One entry per report header: a `ROLE:` line immediately followed by a `HEAD:` line."""
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


def newest_report(nodes: list[dict[str, Any]], roles: tuple[str, ...]) -> tuple[str, list[Entry]] | None:
    """(time, entries) of the newest trusted, visible comment holding a report of a counted (or unreadable) role.

    Every node is checked for its fields first, trusted or not: one wrong shape poisons the whole read. A comment is
    dated by the later of its creation and its last edit.
    """
    found: list[tuple[str, list[Entry]]] = []
    for node in nodes:
        association, created, edited = node.get("authorAssociation"), node.get("createdAt"), node.get("lastEditedAt")
        html, minimized = node.get("bodyHTML"), node.get("isMinimized")
        if not isinstance(association, str) or not isinstance(created, str) or not isinstance(html, str):
            raise MalformedDataError("a comment lacks authorAssociation, createdAt or bodyHTML as text")
        if not isinstance(minimized, bool) or "lastEditedAt" not in node:
            raise MalformedDataError("a comment lacks isMinimized as a boolean or lastEditedAt")
        if not TIME.fullmatch(created) or not (edited is None or (isinstance(edited, str) and TIME.fullmatch(edited))):
            raise MalformedDataError("a comment's createdAt or lastEditedAt is not a timestamp")
        if minimized or association not in TRUSTED or "ROLE" not in html:
            continue
        try:
            lines = report_lines(html)
        except UnreadableHtml as error:
            raise UnreadableHtml(f"a comment that mentions a ROLE cannot be read ({error})") from None
        entries = [entry for entry in report_entries(lines) if entry[0] is None or entry[0] in roles]
        if entries:
            found.append((max(created, edited or created), entries))
    if not found:
        return None
    latest = max(when for when, _ in found)
    return latest, [entry for when, entries in found if when == latest for entry in entries]


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


def read_timeline(client: Client, variables: Mapping[str, Any], head: str) -> tuple[str, str | None]:
    """(since, base_changed): when `head` last became the head, and when the base last changed (or None).

    `since` is the time of the latest force-push whose result is `head`; with none, it is the committedDate of the head
    commit, which its author controls: a floor, not proof. A timeline too long to read in full is unknown.
    """
    pull = pull_of(client.execute(TIMELINE_QUERY, variables))
    items = pull.get("timelineItems")
    info = items.get("pageInfo") if isinstance(items, dict) else None
    more = info.get("hasPreviousPage") if isinstance(info, dict) else None
    nodes = items.get("nodes") if isinstance(items, dict) else None
    if not isinstance(more, bool) or not isinstance(nodes, list):
        raise MalformedDataError("the pull request timeline lacks hasPreviousPage or its nodes")
    if more:
        raise _bad("the pull request timeline is truncated (more than 50 events), so when the head arrived is unknown")
    forced: list[str] = []
    rebased: list[str] = []
    for node in nodes:
        kind = node.get("__typename") if isinstance(node, dict) else None
        created = node.get("createdAt") if isinstance(node, dict) else None
        if kind not in ("HeadRefForcePushedEvent", "BaseRefChangedEvent"):
            raise MalformedDataError("a timeline event is not a force-push or a base change")
        if not isinstance(created, str) or not TIME.fullmatch(created):
            raise MalformedDataError("a timeline event has no timestamp")
        if kind == "BaseRefChangedEvent":
            rebased.append(created)
            continue
        after = node.get("afterCommit")
        oid = after.get("oid") if isinstance(after, dict) else None
        if not isinstance(oid, str) or not FULL_SHA.fullmatch(oid):
            raise MalformedDataError("a force-push event has no full commit oid")
        if oid == head:
            forced.append(created)
    if forced:
        since = max(forced)
    else:
        commits = pull.get("commits")
        rows = commits.get("nodes") if isinstance(commits, dict) else None
        commit = (
            rows[0].get("commit") if isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict) else None
        )
        date = commit.get("committedDate") if isinstance(commit, dict) else None
        if (
            not isinstance(commit, dict)
            or commit.get("oid") != head
            or not isinstance(date, str)
            or not TIME.fullmatch(date)
        ):
            raise _bad("when the head commit arrived could not be established")
        since = date
    return since, max(rebased) if rebased else None


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
        ("authorAssociation", "createdAt", "isMinimized", "bodyHTML"),
    )
    newest = newest_report(nodes, roles)
    if newest is None:
        raise _bad(f"no review report ({', '.join(roles)}) from an owner, member or collaborator has a HEAD line")
    when, entries = newest
    if len(set(entries)) != 1:
        raise _bad("the newest report names more than one role, HEAD or verdict, so it is ambiguous")
    role, reported, said = entries[0]
    if role is None or reported is None:
        raise _bad("the newest report's ROLE or HEAD is unreadable (a HEAD must be 7 to 40 hex characters)")
    full = resolve(client, variables, reported)
    since, rebased = read_timeline(client, variables, head) if full == head else (None, None)
    if read_pull(client, variables)[0] != head:
        raise _bad("the head moved while reading, so nothing was compared")
    label = f"{role} report" + (f" VERDICT {said}" if said else "")
    if since is None:
        return STALE, f"{label} names {full[:7]}, the pull request head is {head[:7]}{flags}"
    if when < since:
        return STALE, f"{label} names the current head {head[:7]} but was posted before it became the head{flags}"
    if rebased is not None and rebased > when:
        return STALE, f"{label} names the current head {head[:7]} but the base branch changed after it{flags}"
    return FRESH, f"{label} names the current head {head[:7]}{flags}"


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


def class_name(error: BaseException) -> str:
    name = type(error).__name__
    return name if CLASS_NAME.fullmatch(name) else "Exception"


def decide(ctx: LocalContext, args: argparse.Namespace) -> tuple[int, str]:
    """(exit code, the line to print). Everything that can fail except the printing happens here."""
    try:
        roles = parse_roles(args.roles)
        match = REPO.fullmatch(args.repo)
        if not match or match.group(2) in (".", "..") or not NUMBER.fullmatch(args.pr):
            raise _bad("expected <owner/repo> and a pull request number")
        variables = {"owner": match.group(1), "name": match.group(2), "number": int(args.pr)}
        state, message = verdict(make_client(ctx.env), variables, roles)
    except Unknown as why:
        return EXIT_UNKNOWN, f"{UNKNOWN} {why}"
    except SafoError as error:
        return EXIT_UNKNOWN, f"{UNKNOWN} {safe(str(error))[:300]}"
    return (EXIT_OK if state == FRESH else EXIT_DRIFT), f"{state} {message}"


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    if args.action != "check":
        raise ConfigError("the only handoff action is `check`")
    try:
        code, line = decide(ctx, args)
    except KeyboardInterrupt:
        raise
    except BaseException as error:  # a crash is "cannot tell" (2), never "stale" (1)
        code, line = EXIT_UNKNOWN, f"{UNKNOWN} internal error ({class_name(error)})"
    try:
        ctx.say(line)
    except KeyboardInterrupt:
        raise
    except BaseException:
        return code  # a closed or broken stream must not change the answer: the exit code is the answer
    return code


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
