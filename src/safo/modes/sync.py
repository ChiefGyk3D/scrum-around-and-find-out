# SPDX-License-Identifier: MIT
"""sync: one issue or pull request event in, that one card brought in line. Same rules as reconcile.

Ported from GYST's project_sync.py. The event payload is read as JSON data and never expanded into a
shell; only the node id, state, draft flag, dates and the repository name are used. Area comes from the
repository's `default_area` alone, so a pull request's title is never read.

Exit codes: 0 the card is current (or the changes were applied, or the event changes no card), 1 a dry run with
work pending, a rate limit that did not clear, or an event for a repository board.yaml does not list (a NOTE, and
nothing is sent), 2 the run cannot tell (a payload not shaped as asked, a read that fails or contradicts itself,
an unknown outcome, a card that vanished). After an unknown outcome nothing more is written: the run re-reads,
says what it saw, names what it did not attempt and stops. A mutation is never sent twice.
"""

from __future__ import annotations

import argparse
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from safo.apply import Applier
from safo.bounded import read_json
from safo.context import Context
from safo.errors import (
    EXIT_DRIFT,
    EXIT_OK,
    EXIT_UNKNOWN,
    ApiError,
    ConfigError,
    NotFoundError,
    RateLimitedError,
    SafoError,
    UnknownOutcomeError,
)
from safo.items import Content, ItemState, content_exists, find_item, mismatched_fields
from safo.live import LiveBoard, load_live
from safo.modes import Mode, register
from safo.modes.reconcile import Outcome, Write, _observe, _refuse_future, desired_writes, safe, say, validate
from safo.schema import Repository
from safo.values import utc_timestamp, whole_number

ISSUE_ACTIONS = {"opened", "reopened", "closed", "edited"}
PR_ACTIONS = {"opened", "reopened", "ready_for_review", "converted_to_draft", "closed"}
CLIP = 100  # the longest payload text a message repeats


def clip(text: str) -> str:
    """Payload text for a message: escaped, and short."""
    return safe(text[:CLIP]) + ("..." if len(text) > CLIP else "")


def content_from_event(event_name: str, payload: Any) -> Content:
    """The content an event names, or ConfigError / MalformedDataError. The title and labels are never read."""
    if not isinstance(payload, dict):
        raise ConfigError("event payload must be an object")
    repository = payload.get("repository")
    key = "pull_request" if "pull_request" in payload else "issue"
    raw = payload.get(key)
    if raw is None:
        raise ConfigError(f"the {clip(event_name) or 'event'} payload carries neither an issue nor a pull request")
    if not isinstance(repository, dict) or not isinstance(repository.get("full_name"), str):
        raise ConfigError("event repository.full_name must be a string")
    if not isinstance(payload.get("action"), str) or not isinstance(raw, dict):
        raise ConfigError("event action and content have invalid types")
    number = raw.get("number")
    if (
        not isinstance(raw.get("node_id"), str)
        or not raw["node_id"]
        or type(number) is not int
        or raw.get("state") not in ("open", "closed")
        or (raw.get("closed_at") is not None and not isinstance(raw["closed_at"], str))
        or any(k in raw and type(raw[k]) is not bool for k in ("draft", "merged"))
    ):
        raise ConfigError("event content has missing keys or invalid types")
    number = whole_number(number, "the event's issue or pull request number")
    if number < 1:
        raise ConfigError("event content has missing keys or invalid types")
    closed_at = None
    if raw.get("closed_at") is not None:
        closed_at = utc_timestamp(raw["closed_at"], "the event's closed_at").strftime("%Y-%m-%dT%H:%M:%SZ")
    if raw.get("merged") is True and raw["state"] != "closed":
        raise ConfigError("event content says merged but not closed")
    repo = repository["full_name"]
    if key == "pull_request":
        state = "merged" if raw.get("merged") else raw["state"]
        return Content(raw["node_id"], "pr", state, bool(raw.get("draft")), closed_at, number, repo)
    return Content(raw["node_id"], "issue", raw["state"], False, closed_at, number, repo)


def read_event(path_text: str) -> Any:
    path = Path(path_text)
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):  # a FIFO would block the read
            raise ConfigError(f"cannot read the event payload {clip(path_text)}: it is not a regular file")
        return read_json(path)
    except (OSError, ValueError, UnicodeError) as err:
        raise ConfigError(f"cannot read the event payload {clip(path_text)}: {err.__class__.__name__}") from None


def _report(ctx: Context, number: int, did: list[str], added: bool) -> None:
    if ctx.client.dry_run:
        head = f"WOULD add #{number}" if added else f"WOULD update #{number}"
    else:
        head = f"added #{number}" if added else f"updated #{number}"
    say(ctx, head + ("; " if added and did else ": " if did else "") + "; ".join(did))


def run(ctx: Context, args: argparse.Namespace) -> int:
    event_name = args.event_name or ctx.env.get("GITHUB_EVENT_NAME", "")
    path = args.event_path or ctx.env.get("GITHUB_EVENT_PATH", "")
    if not path:
        raise ConfigError(
            f"the {clip(event_name) or 'sync'} event has no payload file: pass --event-path or set GITHUB_EVENT_PATH"
        )
    payload = read_event(path)
    content = content_from_event(event_name, payload)
    action = str(payload["action"])
    allowed = PR_ACTIONS if content.kind == "pr" else ISSUE_ACTIONS
    if action not in allowed:
        say(ctx, f"{clip(event_name) or 'event'} action {clip(action)!r} does not change a card; nothing to do")
        return EXIT_OK
    repo = next((r for r in ctx.board.repositories if r.full_name.lower() == content.repo.lower()), None)
    if repo is None:
        say(
            ctx,
            f"NOTE repository {clip(content.repo)} is not listed in board.yaml; nothing was sent "
            "(add it under repositories)",
        )
        return EXIT_DRIFT
    _refuse_future(ctx.today, [content])
    live = load_live(ctx.client, ctx.board.project)
    validate(ctx.board, live)
    label = f"{repo.full_name}#{content.number}"
    try:
        item = find_item(ctx.client, ctx.board, live, content.id)
    except NotFoundError:
        if not content_exists(ctx.client, content.id):
            say(ctx, f"VANISHED {label} (confirmed by read)")
        else:
            say(ctx, f"{label}: the card could not be read, though the issue or pull request exists")
        return EXIT_UNKNOWN
    return apply_event(ctx, live, repo, content, action, item, label)


@dataclass
class Progress:
    """How far one card got, so a stop can say what landed, what is unknown and what was never tried."""

    added: bool = False  # the add is part of this run
    acked: bool = False  # the add was acknowledged and the card found, as the card the add returned
    did: list[str] = field(default_factory=list)
    writes: list[Write] = field(default_factory=list)
    failed: Write | None = None  # the write in flight


def apply_event(
    ctx: Context, live: LiveBoard, repo: Repository, content: Content, action: str, item: ItemState | None, label: str
) -> int:
    """Add the card if it is absent, then make at most one write per field, in order. Stops at the first doubt."""
    applier = Applier(ctx.client, live)
    dry = ctx.client.dry_run
    progress = Progress(added=item is None)
    previous = item
    try:
        if item is None:
            item_id = applier.add(content.id)
            if dry:
                item = ItemState(item_id, content, None, None, None)
            else:
                item = find_item(ctx.client, ctx.board, live, content.id)
                if item is None or item.id != item_id:
                    raise UnknownOutcomeError(f"{label}: the added card cannot be found on the board")
        progress.acked = True
        refused = frozenset(mismatched_fields(ctx.board, live))
        progress.writes = desired_writes(ctx.board, repo, content, item, action, ctx.today, refused)
        for write in progress.writes:
            progress.failed = write
            if write.kind == "select":
                applier.set_select(item.id, write.field, write.value)
            elif write.kind == "date":
                applier.set_date(item.id, write.field, write.value)
            else:
                applier.clear(item.id, write.field)
            progress.did.append(write.text)
            progress.failed = None
    except SafoError as err:
        return stopped(ctx, live, content, label, err, progress, previous)
    if not progress.did and not progress.added:
        say(ctx, f"#{content.number}: already current")
        return EXIT_OK
    _report(ctx, content.number, progress.did, progress.added)
    return EXIT_DRIFT if dry else EXIT_OK


def stopped(
    ctx: Context, live: LiveBoard, content: Content, label: str, err: SafoError, p: Progress, previous: ItemState | None
) -> int:
    """Something went wrong after the run began: say what landed, what is unknown, what was not tried. Never writes."""
    if p.acked and (p.added or p.did):
        landed = (["added"] if p.added else []) + p.did
        say(ctx, f"applied {label}: {'; '.join(landed)} (then stopped)")
    if p.acked:
        attempted = len(p.did) + (1 if p.failed is not None else 0)
        pending = [w.text for w in p.writes[attempted:]]
    else:
        pending = [f"every field write for {label} (they follow the add)"]
    if p.failed is not None:
        verdict = "unknown" if isinstance(err, UnknownOutcomeError) else "not applied"
        say(ctx, f"{label}: {p.failed.text}: {verdict}")
    if isinstance(err, RateLimitedError):
        say(ctx, f"FAILED {label}: stopped: still rate limited")
        code = EXIT_DRIFT
    elif isinstance(err, UnknownOutcomeError):
        say(ctx, f"{label}: unknown outcome: re-run after checking the board")
        out = Outcome()
        _observe(ctx, live, content, label, previous, out)
        for line in out.vanished:
            say(ctx, f"VANISHED {line}")
        for line in out.observed:
            say(ctx, line)
        code = EXIT_UNKNOWN
    else:
        kind = "cannot read live state" if isinstance(err, ApiError) else "refused"
        say(ctx, f"{label}: stopped: {kind} ({type(err).__name__})")
        code = EXIT_UNKNOWN
    if pending:
        say(ctx, f"NOT ATTEMPTED {'; '.join(pending)}")
    return code


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--event-path", default="", help="the event payload (default: $GITHUB_EVENT_PATH)")
    parser.add_argument("--event-name", default="", help="the event name, for messages (default: $GITHUB_EVENT_NAME)")


register(Mode("sync", "bring the card of one issue or pull request event in line", add_arguments, run))
