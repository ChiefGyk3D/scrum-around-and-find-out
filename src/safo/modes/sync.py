# SPDX-License-Identifier: MIT
"""sync: one issue or pull request event in, that one card brought in line. Same rules as reconcile.

Ported from GYST's project_sync.py. The event payload is only a pointer: its node id says which issue or pull request
to look at, its action is a hint, and its repository name is checked against what GitHub says. State, draft flag,
dates, number and repository all come from a live read of that node, so a replayed or edited payload cannot write
state the content no longer has. The title is never read: Area comes from the repository's `default_area` alone.

Exit codes: 0 the card is current (or the changes were applied, or the event changes no card), 1 a dry run with
work pending, a rate limit that ended the run before any write was sent, or a NOTE (an event for a repository
board.yaml does not list, a node that is not in the repository the payload names, an action that contradicts the
live state): nothing is written for a NOTE. 2 the run cannot tell: a payload not shaped as asked, a read that fails
or contradicts itself, an unknown outcome (a rate limit after a write was sent is one), a card that vanished. After
an unknown outcome nothing more is written: the run re-reads, says what it saw, names what it did not attempt and
stops. A mutation is never sent twice.
"""

from __future__ import annotations

import argparse
import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from safo.apply import Applier
from safo.bounded import MAX_BYTES, NotRegularFileError, loads, read_bounded
from safo.context import Context
from safo.errors import (
    EXIT_DRIFT,
    EXIT_OK,
    EXIT_UNKNOWN,
    ApiError,
    ConfigError,
    MalformedDataError,
    NotFoundError,
    RateLimitedError,
    SafoError,
    UnknownOutcomeError,
)
from safo.items import Content, ItemState, _canonical_repo, content_from_node, find_item, mismatched_fields
from safo.live import LiveBoard, load_live
from safo.modes import Mode, register
from safo.modes.reconcile import Outcome, Write, _observe, _refuse_future, desired_writes, safe, say, validate
from safo.schema import Repository

ISSUE_ACTIONS = {"opened", "reopened", "closed", "edited"}
PR_ACTIONS = {"opened", "reopened", "ready_for_review", "converted_to_draft", "closed"}
CLIP = 100  # the longest payload text a message repeats

Q_SYNC_CONTENT = """query SyncContent($id: ID!) {
  node(id: $id) {
    __typename
    ... on Issue { id number state closedAt repository { nameWithOwner } }
    ... on PullRequest { id number state isDraft merged closedAt repository { nameWithOwner } }
  }
}"""


def clip(text: str) -> str:
    """Payload text for a message: escaped, and short."""
    return safe(text[:CLIP]) + ("..." if len(text) > CLIP else "")


@dataclass(frozen=True)
class Pointer:
    """What an event payload is trusted for: which node, what the event says happened, and where it says it is."""

    action: str
    repo: str  # the payload's repository.full_name
    node_id: str
    kind: str  # issue | pr


def pointer_from_event(event_name: str, payload: Any) -> Pointer:
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
    node_id = raw.get("node_id")
    if not isinstance(node_id, str) or not node_id:
        raise ConfigError("event content has no node_id")
    return Pointer(payload["action"], repository["full_name"], node_id, "pr" if key == "pull_request" else "issue")


def read_event(path_text: str) -> Any:
    try:
        return loads(read_bounded(Path(path_text), MAX_BYTES + 1))
    except NotRegularFileError:
        raise ConfigError(f"cannot read the event payload {clip(path_text)}: it is not a regular file") from None
    except (OSError, ValueError, UnicodeError) as err:
        raise ConfigError(f"cannot read the event payload {clip(path_text)}: {err.__class__.__name__}") from None


def read_live(ctx: Context, node_id: str) -> Content | None:
    """The issue or pull request itself, as GitHub says it is now; None only for a clean null (deleted)."""
    data = ctx.client.execute(Q_SYNC_CONTENT, {"id": node_id})
    if "node" not in data:
        raise MalformedDataError("SyncContent: the answer has no node")
    node = data["node"]
    if node is None:
        return None
    if not isinstance(node, dict):
        raise MalformedDataError("SyncContent: the node is not an object")
    typename = node.get("__typename")
    if typename not in ("Issue", "PullRequest"):
        raise MalformedDataError("SyncContent: the node is neither an issue nor a pull request")
    if node.get("id") != node_id:
        raise MalformedDataError("SyncContent: the answer is for another node than the one asked for")
    if "closedAt" not in node:
        raise MalformedDataError("SyncContent: closedAt was not sent")
    if typename == "PullRequest" and not all(isinstance(node.get(k), bool) for k in ("isDraft", "merged")):
        raise MalformedDataError("SyncContent: isDraft or merged is missing or not a boolean")
    content = content_from_node(node, _canonical_repo(node, "the event's content"), typename)
    if content.number < 1:
        raise MalformedDataError("SyncContent: the number is not a whole number of at least 1")
    # Whatever else came with the node, the title and labels are never read: Area comes from default_area alone.
    return dataclasses.replace(content, title="", labels=())


def contradiction(action: str, content: Content) -> str | None:
    """Why the event's action cannot be applied to the content as it is now, or None."""
    state = content.state + (", draft" if content.draft else "")
    if action == "closed":
        ok = not content.is_open
    elif action in ("opened", "reopened"):
        ok = content.is_open
    elif action == "ready_for_review":
        ok = content.is_open and not content.draft
    elif action == "converted_to_draft":
        ok = content.is_open and content.draft
    else:
        ok = True  # an edit is taken at whatever state the content has now
    return None if ok else f"the {action} event does not match the live state ({state})"


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
    pointer = pointer_from_event(event_name, payload)
    allowed = PR_ACTIONS if pointer.kind == "pr" else ISSUE_ACTIONS
    if pointer.action not in allowed:
        say(ctx, f"{clip(event_name) or 'event'} action {clip(pointer.action)!r} does not change a card; nothing to do")
        return EXIT_OK
    if not any(r.full_name.lower() == pointer.repo.lower() for r in ctx.board.repositories):
        say(
            ctx,
            f"NOTE repository {clip(pointer.repo)} is not listed in board.yaml; nothing was sent "
            "(add it under repositories)",
        )
        return EXIT_DRIFT
    try:
        return follow_pointer(ctx, pointer)
    except RateLimitedError:
        say(ctx, "rate limited before any write was sent; nothing was changed; try again later")
        return EXIT_DRIFT


def follow_pointer(ctx: Context, pointer: Pointer) -> int:
    content = read_live(ctx, pointer.node_id)
    if content is None:
        say(ctx, f"VANISHED {clip(pointer.repo)} content {clip(pointer.node_id)} (confirmed by read)")
        return EXIT_UNKNOWN
    repo = next((r for r in ctx.board.repositories if r.full_name.lower() == content.repo.lower()), None)
    if repo is None or content.repo.lower() != pointer.repo.lower():
        say(
            ctx,
            f"NOTE #{content.number} is in {safe(content.repo)}, but the event names {clip(pointer.repo)}"
            + (" and board.yaml does not list it" if repo is None else "")
            + "; nothing was written",
        )
        return EXIT_DRIFT
    label = f"{repo.full_name}#{content.number}"
    if (content.kind == "pr") != (pointer.kind == "pr"):
        say(ctx, f"NOTE {label}: the event names a {pointer.kind}, but it is a {content.kind}; nothing was written")
        return EXIT_DRIFT
    reason = contradiction(pointer.action, content)
    if reason:
        say(ctx, f"NOTE {label}: {reason}; nothing was written")
        return EXIT_DRIFT
    _refuse_future(ctx.today, [content])
    live = load_live(ctx.client, ctx.board.project)
    validate(ctx.board, live)
    try:
        item = find_item(ctx.client, ctx.board, live, content.id)
    except NotFoundError:
        say(ctx, f"{label}: the card could not be read, though the issue or pull request exists")
        return EXIT_UNKNOWN
    return apply_event(ctx, live, repo, content, pointer.action, item, label)


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
    if isinstance(err, UnknownOutcomeError | RateLimitedError):
        # A rate limit after a write went out leaves the board half done: as unknown as a lost reply.
        why = " (rate limited)" if isinstance(err, RateLimitedError) else ""
        say(ctx, f"{label}: unknown outcome{why}: re-run after checking the board")
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
