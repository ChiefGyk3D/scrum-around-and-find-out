# SPDX-License-Identifier: MIT
"""status: post a project status update, from a body file or built from the board.

`--body-file FILE` posts the Markdown you wrote. `--post` builds the update: the cards are grouped and counted in
code (statusgroups.py) and a one-line headline sits on top. The headline is a template here; with a local model
reachable, a later step lets it write that one line and nothing else. The body and every number in it come from code.

Exit codes: 0 posted (or printed), 1 a dry run with the post pending, or an update that had to leave cards out
(each is said in a WARNING line and in the update itself), 2 the run cannot tell (a read that is not shaped as
asked, a short listing, an unknown outcome). An unknown outcome is never retried.
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import secrets
from pathlib import Path
from typing import Any

from safo.bounded import NotRegularFileError, read_bounded
from safo.context import Context
from safo.errors import (
    EXIT_DRIFT,
    EXIT_OK,
    EXIT_UNKNOWN,
    ApiError,
    ConfigError,
    MalformedDataError,
    RateLimitedError,
    SafoError,
    UnknownOutcomeError,
)
from safo.items import _canonical_repo, _field_value
from safo.live import LiveBoard, load_live
from safo.modes import Mode, register
from safo.modes.reconcile import controls, safe, say
from safo.mutation import mutate
from safo.statusgroups import SECTION_LIMIT, Row, group_rows, render_body, template_headline
from safo.values import utc_timestamp, whole_number

STATES = ("INACTIVE", "ON_TRACK", "AT_RISK", "OFF_TRACK", "COMPLETE")
DEFAULT_SINCE_DAYS = 7
MAX_BODY_BYTES = 65_536  # GitHub's own limit on an update body
MAX_LIMIT = 50
_DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")

M_STATUS_UPDATE = """mutation StatusUpdate($input: CreateProjectV2StatusUpdateInput!) {
  createProjectV2StatusUpdate(input: $input) { statusUpdate { id project { id } } }
}"""

Q_STATUS_ITEMS = """query StatusItems(
  $id: ID!, $statusField: String!, $agentField: String!, $endCursor: String
) {
  node(id: $id) { ... on ProjectV2 { items(first: 100, after: $endCursor) {
    totalCount
    pageInfo { hasNextPage endCursor }
    nodes {
      id
      status: fieldValueByName(name: $statusField) { ... on ProjectV2ItemFieldSingleSelectValue { name } }
      agent: fieldValueByName(name: $agentField) { ... on ProjectV2ItemFieldSingleSelectValue { name } }
      content {
        __typename
        ... on Issue { number title closedAt repository { nameWithOwner } }
        ... on PullRequest { number title closedAt mergedAt repository { nameWithOwner } }
        ... on DraftIssue { title updatedAt }
      }
    }
  } } }
}"""


def _day(content: dict[str, Any], key: str, what: str) -> dt.date | None:
    """A timestamp key of a card: explicit null is no date, a missing key or a bad value is MalformedDataError."""
    if key not in content:
        raise MalformedDataError(f"{what}: {key} was not sent")
    value = content[key]
    return None if value is None else utc_timestamp(value, f"{what} {key}").date()


def _row(node: dict[str, Any]) -> Row | None:
    """One card as a Row, or None when the token cannot read its content (the caller counts those)."""
    what = "a board item"
    if "content" not in node:
        raise MalformedDataError(f"{what}: the content was not sent")
    status = _field_value(node, "status", "name", what) or ""
    agent = _field_value(node, "agent", "name", what) or ""
    content = node["content"]
    if content is None:
        return None
    if not isinstance(content, dict):
        raise MalformedDataError(f"{what}: the content is {type(content).__name__}, not an object")
    kind = content.get("__typename")
    if kind not in ("Issue", "PullRequest", "DraftIssue"):
        raise MalformedDataError(f"{what}: the content is of a kind safo does not read")
    title = content.get("title")
    if not isinstance(title, str):
        raise MalformedDataError(f"{what}: the content has no title")
    if kind == "DraftIssue":
        return Row("", 0, title, status, agent, _day(content, "updatedAt", "a draft card"))
    number = whole_number(content.get("number"), "board item content number")
    if number < 1:
        raise MalformedDataError("board item content number: expected a whole number of at least 1")
    repo = _canonical_repo(content, what)
    when = _day(content, "closedAt", what)
    if kind == "PullRequest":
        when = _day(content, "mergedAt", what) or when
    return Row(repo, number, title, status, agent, when)


def read_rows(ctx: Context, live: LiveBoard) -> tuple[list[Row], int]:
    """Every card on the board as a Row, and how many cards could not be read.

    The listing must agree with itself and with the project: the same total on every page, no repeated card,
    nothing short. A card whose content the token cannot read is counted, never guessed.
    """
    rules = ctx.board.rules
    for name in (rules.status_field, ctx.board.agents.field):
        found = live.fields.get(name)
        if found is not None and found.type != "single_select":
            raise ConfigError(
                f"the field {safe(name)!r} is a {safe(found.type)} field on the project, but the status update reads "
                "it as a single select"
            )
    live.field(rules.status_field)
    agent_field = ctx.board.agents.field if ctx.board.agents.field in live.fields else "-"
    variables = {"id": live.id, "statusField": rules.status_field, "agentField": agent_field}
    rows: list[Row] = []
    unreadable = 0
    listed = 0
    total: int | None = None
    ids: set[str] = set()
    for page in ctx.client.pages(Q_STATUS_ITEMS, variables, ("node", "items"), ("id",)):
        page_total = whole_number(page.get("totalCount"), "the board listing totalCount")
        if total is not None and page_total != total:
            raise MalformedDataError("StatusItems: the item count changes between pages")
        total = page_total
        for node in page["nodes"]:
            listed += 1
            card_id = node["id"]
            if not isinstance(card_id, str) or not card_id:
                raise MalformedDataError("StatusItems: a card's id is not a non-empty string")
            if card_id in ids:
                raise MalformedDataError("StatusItems: a card is listed twice")
            ids.add(card_id)
            row = _row(node)
            if row is None:
                unreadable += 1
            else:
                rows.append(row)
    if total is None or total < listed:
        raise MalformedDataError("StatusItems: the listing holds more cards than its own total")
    expected = max(total, live.items_total)
    if listed < expected:
        # A short listing would write a status update that silently leaves cards out of its counts.
        raise ApiError(
            f"the board listing returned {listed} of {expected} items, so the update would miss cards; "
            "run again in a minute"
        )
    return rows, unreadable


def build_post(ctx: Context, args: argparse.Namespace, live: LiveBoard) -> tuple[str, int]:
    """The update body and the number of cards it could not cover."""
    rows, unreadable = read_rows(ctx, live)
    groups = group_rows(rows, ctx.board, _since(ctx, args), args.human_agent)
    notes = []
    if unreadable:
        notes.append(f"{unreadable} card(s) on the board could not be read with this token and are not counted above.")
    return render_body(template_headline(groups), groups, args.limit, notes), unreadable


def _since(ctx: Context, args: argparse.Namespace) -> dt.date:
    if not args.since:
        return ctx.today - dt.timedelta(days=DEFAULT_SINCE_DAYS)
    return _date_option(args.since, "--since")


def _date_option(value: str, flag: str) -> dt.date:
    if _DAY.fullmatch(value):  # fromisoformat alone also takes 20261008 and 2026-W41-4
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            pass
    raise ConfigError(f"{flag}: expected a date as YYYY-MM-DD")


def read_body(path_text: str) -> str:
    try:
        raw = read_bounded(Path(path_text), MAX_BODY_BYTES + 1)
    except NotRegularFileError:
        raise ConfigError(f"cannot read the status body {safe(path_text)}: it is not a regular file") from None
    except OSError as err:
        raise ConfigError(f"cannot read the status body {safe(path_text)}: {safe(str(err.strerror))}") from None
    if len(raw) > MAX_BODY_BYTES:
        raise ConfigError(f"the status body {safe(path_text)} is longer than {MAX_BODY_BYTES} bytes")
    try:
        body = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ConfigError(f"the status body {safe(path_text)} is not UTF-8 text") from None
    if not body:
        raise ConfigError(f"the status body {safe(path_text)} is empty")
    return body


def post_update(ctx: Context, live: LiveBoard, body: str, args: argparse.Namespace) -> int:
    update: dict[str, Any] = {"projectId": live.id, "status": args.state, "body": body}
    for key, value, flag in (
        ("startDate", args.start_date, "--start-date"),
        ("targetDate", args.target_date, "--target-date"),
    ):
        if value:
            update[key] = _date_option(value, flag).isoformat()
    where = f"{ctx.board.project.owner}/{ctx.board.project.number}"
    try:
        data = mutate(
            ctx.client,
            M_STATUS_UPDATE,
            {"input": update},
            dry_result={},
            returns=("createProjectV2StatusUpdate", "statusUpdate"),
        )
        if not ctx.client.dry_run:
            owner = data["createProjectV2StatusUpdate"]["statusUpdate"].get("project")
            if not isinstance(owner, dict) or owner.get("id") != live.id:
                raise UnknownOutcomeError(
                    "StatusUpdate: the reply does not say the update belongs to this project, so it is not known "
                    "what was written; check the project's updates before posting again",
                    data=data,
                    errors=[],
                    status=200,
                )
    except (UnknownOutcomeError, RateLimitedError):
        # The reread covers board metadata only: it cannot say whether the update landed.
        say(
            ctx,
            "status update: unknown outcome: re-run after checking the board; check existing updates before posting",
        )
        try:
            again = load_live(ctx.client, ctx.board.project)
            say(ctx, f"observed: the project is readable ({again.items_total} items); the update itself cannot be read")
        except SafoError as err:
            say(ctx, f"live reread failed; no further writes ({type(err).__name__})")
        say(ctx, "NOT ATTEMPTED a second post of the update (an unknown outcome is never replayed)")
        return EXIT_UNKNOWN
    if ctx.client.dry_run:
        say(ctx, f"WOULD post a {args.state} status update to {where}")
        return EXIT_DRIFT
    say(ctx, f"posted a {args.state} status update to {where}")
    return EXIT_OK


def check_options(args: argparse.Namespace) -> None:
    """Every option is checked before the first request, so a bad one never follows a read."""
    if bool(args.post) == bool(args.body_file):
        raise ConfigError(
            "give exactly one of --body-file FILE (post what you wrote) and --post (build it from the board)"
        )
    if args.print_only and not args.post:
        raise ConfigError("--print only goes with --post; without it, --body-file would be posted")
    if not 1 <= args.limit <= MAX_LIMIT:
        raise ConfigError(f"--limit: expected a number from 1 to {MAX_LIMIT}")
    for value, flag in (
        (args.since, "--since"),
        (args.start_date, "--start-date"),
        (args.target_date, "--target-date"),
    ):
        if value:
            _date_option(value, flag)


def print_block(ctx: Context, body: str) -> None:
    """Show text that came from GitHub inside `::stop-commands::`, so no line of it can act as a workflow command.

    The token is fresh each time and unknown to whoever wrote the text.
    """
    token = secrets.token_hex(16)
    ctx.say(f"::stop-commands::{token}")
    for line in body.rstrip("\n").splitlines():
        ctx.say(controls(line))
    ctx.say(f"::{token}::")


def run(ctx: Context, args: argparse.Namespace) -> int:
    check_options(args)
    try:
        if args.post:
            live = load_live(ctx.client, ctx.board.project)
            body, unreadable = build_post(ctx, args, live)
        else:
            body, unreadable = read_body(args.body_file), 0
            live = load_live(ctx.client, ctx.board.project)
    except RateLimitedError:
        say(ctx, "rate limited before the update was sent; nothing was changed; try again later")
        return EXIT_DRIFT
    if unreadable:
        say(ctx, f"WARNING {unreadable} card(s) could not be read; the update says so and does not count them")
    if args.print_only:
        print_block(ctx, body)
        return EXIT_DRIFT if unreadable else EXIT_OK
    code = post_update(ctx, live, body, args)
    return code if code != EXIT_OK or not unreadable else EXIT_DRIFT


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--body-file", default="", help="Markdown file holding the update")
    parser.add_argument("--post", action="store_true", help="build the update from the board instead of a file")
    parser.add_argument(
        "--print", dest="print_only", action="store_true", help="with --post: print the update, send nothing"
    )
    parser.add_argument("--since", default="", help="with --post: YYYY-MM-DD (default: seven days ago)")
    parser.add_argument("--human-agent", default="You", help="with --post: the Agent value that means the maintainer")
    parser.add_argument("--limit", type=int, default=SECTION_LIMIT, help="with --post: cards listed per section")
    parser.add_argument("--state", choices=STATES, default="ON_TRACK")
    parser.add_argument("--start-date", default="", help="YYYY-MM-DD")
    parser.add_argument("--target-date", default="", help="YYYY-MM-DD")


register(Mode("status", "post a project status update, from a body file or built from the board", add_arguments, run))
