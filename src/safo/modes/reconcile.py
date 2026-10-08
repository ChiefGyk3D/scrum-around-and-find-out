# SPDX-License-Identifier: MIT
"""reconcile: discover identities before adding; repair blanks without resetting manual values.

Exit codes: 0 the board is current (or the changes were applied), 1 changes are needed or something was left
(a dry run with work pending, a rate limit that did not clear, an open card sitting in Done), 2 the run cannot
tell (an unknown outcome, an unreadable repository, cards the listing did not show, a payload not shaped as asked).
After an unknown outcome nothing more is written: the run re-reads, says what it saw and stops.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field

from safo.apply import Applier
from safo.context import Context
from safo.errors import (
    EXIT_DRIFT,
    EXIT_OK,
    EXIT_UNKNOWN,
    ApiError,
    AuthError,
    ConfigError,
    NotFoundError,
    RateLimitedError,
    SafoError,
    UnknownOutcomeError,
)
from safo.items import (
    Q_ITEM_VALUE,
    Content,
    ItemState,
    collect_work,
    content_exists,
    discover_items,
    find_item,
    list_board_items,
    read_defaults,
)
from safo.live import LiveBoard, load_live
from safo.modes import Mode, register
from safo.plan import Plan, build_plan
from safo.rules import area_for, done_day, target_status
from safo.schema import Board, Repository

SHOWN = 20  # how many cards a "not attempted" line names before it counts the rest


@dataclass
class Outcome:
    applied: list[str] = field(default_factory=list)
    vanished: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)
    observed: list[str] = field(default_factory=list)
    not_attempted: list[str] = field(default_factory=list)
    verified: list[tuple[str, str]] = field(default_factory=list)
    seen: set[str] = field(default_factory=set)  # item ids the run actually read: listed, or looked up by content


def validate(board: Board, live: LiveBoard) -> None:
    """Every name a run will use exists on the project, checked before the first mutation."""
    rules = board.rules
    s = rules.status
    statuses = [s.opened, s.reopened, s.closed, s.merged] + [n for n in (s.opened_pr, s.draft_pr) if n]
    for status in statuses:
        live.option_id(rules.status_field, status)
    if rules.done_date_field and live.field(rules.done_date_field).type != "date":
        raise ConfigError(f"the field {rules.done_date_field!r} is not a date field on the project")
    for field_name, option in rules.new_item_defaults:
        live.option_id(field_name, option)
    for repo in board.repositories:
        for area in [repo.default_area, *(r.area for r in repo.area_rules)]:
            if area:
                live.option_id(rules.area_field, area)


def initialize(
    ctx: Context,
    live: LiveBoard,
    repo: Repository,
    content: Content,
    item: ItemState,
    action: str = "reconcile",
    did: list[str] | None = None,
) -> list[str]:
    """Blank-default repair policy applies to every card; nonblank manual defaults are never overwritten.

    Each write is appended to `did` once it succeeded, so a caller that is stopped halfway still knows what landed.
    """
    rules = ctx.board.rules
    applier = Applier(ctx.client, live)
    did = [] if did is None else did
    target = target_status(rules, content, action, item.status)
    if target:
        applier.set_select(item.id, rules.status_field, target)
        did.append(f"Status = {target}")
    if rules.done_date_field:
        if not content.is_open and item.done is None:
            applier.set_date(item.id, rules.done_date_field, done_day(content, ctx.today))
            did.append("Done date filled")
        elif content.is_open and action == "reopened" and item.done is not None:
            applier.clear(item.id, rules.done_date_field)
            did.append(f"{rules.done_date_field} cleared")
    area = area_for(repo, content)
    if item.area is None and area:
        applier.set_select(item.id, rules.area_field, area)
        did.append(f"Area = {area}")
    for name, option in rules.new_item_defaults:
        if item.values.get(name) is None:
            applier.set_select(item.id, name, option)
            did.append(f"{name} = {option}")
    return did


def _verb(added: bool, dry: bool) -> str:
    if dry:
        return "WOULD ADD" if added else "WOULD UPDATE"
    return "ADDED" if added else "UPDATED"


def _label(repo: Repository, content: Content) -> str:
    return f"{repo.full_name}#{content.number}"


def _observe(
    ctx: Context, live: LiveBoard, content: Content, label: str, previous: ItemState | None, out: Outcome
) -> None:
    """Re-read one card after an unknown outcome and say what it looks like now. Never writes."""
    try:
        try:
            item = find_item(ctx.client, ctx.board, live, content.id)
        except NotFoundError:
            item = None  # GitHub answers null for a deleted issue or pull request
        exists = content_exists(ctx.client, content.id)
        gone = not exists
        if item is None and previous is not None and exists:
            gone = (
                ctx.client.execute(Q_ITEM_VALUE, {"id": previous.id, "name": ctx.board.rules.status_field}).get("node")
                is None
            )
    except Exception as err:  # any failure of the reread still ends in a visible line and exit 2
        detail = f": {err}" if isinstance(err, SafoError) else ""
        out.observed.append(f"live reread failed; no further writes ({type(err).__name__}{detail})")
        return
    if item is not None:
        out.observed.append(
            f"observed {label}: on the board, Status {item.status!r}, Area {item.area!r}, Done on {item.done!r}"
        )
    elif gone:
        out.vanished.append(label)
        out.observed.append(f"observed {label}: the card or its issue no longer exists")
    else:
        out.observed.append(f"observed {label}: not on the board")


def apply_plan(
    ctx: Context, live: LiveBoard, plan: Plan, work: dict[str, list[Content]], listed: list[ItemState]
) -> Outcome:
    out = Outcome()
    dry = ctx.client.dry_run
    repos = {r.full_name.lower(): r for r in ctx.board.repositories}
    skipped = {u.lower() for u in plan.unreachable}
    contents: dict[str, Content] = {}
    for rows in work.values():
        for c in rows:
            contents.setdefault(c.id, c)
    by_content: dict[str, ItemState] = {}
    for i in listed:
        if i.content and i.content.repo.lower() in repos and i.content.repo.lower() not in skipped:
            contents.setdefault(i.content.id, i.content)
            by_content.setdefault(i.content.id, i)
    by_content.update(discover_items(ctx.client, ctx.board, live, [cid for cid in contents if cid not in by_content]))
    out.seen = {i.id for i in by_content.values()}
    pending = list(contents.values())
    applier = Applier(ctx.client, live)
    for index, content in enumerate(pending):
        repo = repos[content.repo.lower()]
        label = _label(repo, content)
        did: list[str] = []
        added = False
        previous = by_content.get(content.id)
        try:
            item = previous
            if item is not None:
                try:
                    item.values = read_defaults(ctx.client, ctx.board, item.id)
                except NotFoundError:
                    out.vanished.append(label)  # a read proved the card is gone since it was listed: nothing to fix
                    continue
            else:
                if not content_exists(ctx.client, content.id):
                    out.vanished.append(label)
                    continue
                item_id = applier.add(content.id)
                if dry:
                    item = ItemState(item_id, content, None, None, None)
                else:
                    # Verified by identity: the card for this very content must exist and be the one acknowledged.
                    item = find_item(ctx.client, ctx.board, live, content.id)
                    if item is None or item.id != item_id:
                        raise UnknownOutcomeError(f"{label}: the added card cannot be found on the board")
                    out.verified.append((content.id, item.id))
                added = True
            initialize(ctx, live, repo, content, item, did=did)
        except (UnknownOutcomeError, RateLimitedError, ApiError, AuthError) as err:
            if did or added:
                out.applied.append(f"{_verb(added, dry)} {label}: {'; '.join(did)} (then stopped)")
            if isinstance(err, UnknownOutcomeError):
                out.unknown.append(f"{label}: unknown outcome: re-run after checking the board")
                _observe(ctx, live, content, label, previous, out)
            elif isinstance(err, RateLimitedError):
                out.failed.append(f"FAILED {label}: stopped: still rate limited")
            elif isinstance(err, AuthError):
                out.unknown.append(f"{label}: stopped: {err}")
            else:
                out.unknown.append(f"{label}: stopped: cannot read live state ({type(err).__name__})")
            out.not_attempted = [_label(repos[c.repo.lower()], c) for c in pending[index + 1 :]]
            break
        if did or added:
            out.applied.append(f"{_verb(added, dry)} {label}: {'; '.join(did)}")
    return out


def verify_adds(ctx: Context, live: LiveBoard, out: Outcome) -> str | None:
    """Read the board again: every acknowledged add must now be there as the card the add returned."""
    if ctx.client.dry_run or not out.verified:
        return None
    try:
        refreshed = {i.content.id: i for i in list_board_items(ctx.client, ctx.board, live) if i.content}
        for content_id, item_id in out.verified:
            item = refreshed.get(content_id)
            if item is None:
                item = find_item(ctx.client, ctx.board, live, content_id)
            if item is None or item.id != item_id:
                return "unknown outcome: re-run after checking the board"
        # Supporting observation only, never a substitute for the identity checks above.
        ctx.say(f"items.totalCount after verified adds: {load_live(ctx.client, ctx.board.project).items_total}")
    except ApiError as err:
        return f"unknown outcome: re-run after checking the board (the adds could not be re-read: {type(err).__name__})"
    return None


def _not_attempted(names: list[str]) -> str:
    shown = ", ".join(names[:SHOWN])
    more = f" and {len(names) - SHOWN} more" if len(names) > SHOWN else ""
    return f"NOT ATTEMPTED {shown}{more}"


def run(ctx: Context, args: argparse.Namespace) -> int:
    dry = ctx.client.dry_run
    live = load_live(ctx.client, ctx.board.project)
    validate(ctx.board, live)
    items = list_board_items(ctx.client, ctx.board, live)
    work, unreachable = collect_work(ctx.client, ctx.board, ctx.today)
    plan = build_plan(ctx.board, items, work, unreachable, ctx.today)
    if any(i.content is None and i.content_type != "DraftIssue" for i in items):
        ctx.say("UNKNOWN inaccessible content; no mutations sent")
        return EXIT_UNKNOWN
    counts: dict[str, int] = {}
    labels: dict[str, str] = {}
    for i in items:
        if i.content:
            counts[i.content.id] = counts.get(i.content.id, 0) + 1
            labels[i.content.id] = f"{i.content.repo}#{i.content.number}"
    for content_id, n in counts.items():
        if n > 1:
            plan.anomalies.append(
                f"{labels[content_id]} is on the board {n} times; safo repairs one card and leaves the rest"
            )
    out = apply_plan(ctx, live, plan, work, items)
    problem = verify_adds(ctx, live, out)
    # The listing lags behind items.totalCount, and a lookup by content id covers only the work this run knows about.
    # Cards that neither reached cannot be named: the run cannot say the board is current.
    listed_ids = {i.id for i in items}
    unread = live.items_total - len(listed_ids | out.seen)
    for line in out.applied:
        ctx.say(line)
    for line in out.vanished:
        ctx.say(f"VANISHED {line}")
    for line in out.unknown + out.observed + out.failed:
        ctx.say(line)
    if out.not_attempted:
        ctx.say(_not_attempted(out.not_attempted))
    for name in unreachable:
        ctx.say(f"UNREACHABLE {name}: the token cannot read it (is the App installed on it?)")
    for line in plan.anomalies:
        ctx.say(f"NOTE {line}")
    if problem:
        ctx.say(problem)
    if unread > 0:
        looked_up = len(out.seen - listed_ids)
        ctx.say(
            f"UNKNOWN {unread} of {live.items_total} items on the project were not read (the listing lags or hides "
            f"them, so they cannot be named): {len(listed_ids)} read from the listing, {looked_up} looked up through "
            "their issue or pull request. Only the items that were read were worked on; those changes were applied "
            "as listed above. Cannot tell whether the board is current; run again in a minute"
        )
    if out.unknown or problem or unreachable or unread > 0:
        return EXIT_UNKNOWN
    if plan.anomalies or out.failed or (dry and out.applied):
        return EXIT_DRIFT
    if not out.applied and not out.vanished:
        ctx.say("nothing to do: the board is current")
    return EXIT_OK


def add_arguments(parser: argparse.ArgumentParser) -> None:
    del parser


register(Mode("reconcile", "add missing work and repair blank values", add_arguments, run))
