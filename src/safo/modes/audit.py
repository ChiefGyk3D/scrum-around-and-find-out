# SPDX-License-Identifier: MIT
"""audit: compare the live board with board.yaml and the listed repositories' open work."""

from __future__ import annotations

import argparse
import datetime as dt
from dataclasses import dataclass, field

from safo.context import Context
from safo.errors import EXIT_DRIFT, EXIT_OK, EXIT_UNKNOWN, ConfigError, NotFoundError
from safo.items import collect_work, list_board_items
from safo.live import LiveBoard, LiveField, load_live
from safo.modes import Mode, register
from safo.plan import build_plan
from safo.schema import Board, Field


@dataclass
class Findings:
    drift: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        # A question that could not be asked outranks drift: the audit is incomplete, and says so.
        if self.unknown:
            return EXIT_UNKNOWN
        return EXIT_DRIFT if self.drift else EXIT_OK


def expected_starts(f: Field) -> list[dt.date]:
    if f.start is None:
        raise ConfigError(f"iteration field {f.name!r} has no start date")
    return [f.start + dt.timedelta(days=f.duration_days * i) for i in range(f.count)]


def compare_field(f: Field, live: LiveField | None, out: Findings) -> None:
    if live is None:
        out.drift.append(f"field {f.name!r} is missing from the project")
        return
    if live.type != f.type:
        out.drift.append(f"field {f.name!r} is {live.type} on the project but {f.type} in board.yaml")
        return
    if f.type == "single_select":
        want = [o.name for o in f.options]
        have = [o.name for o in live.options]
        for name in want:
            if name not in have:
                out.drift.append(
                    f"field {f.name!r} lacks the option {name!r}; add it in the project's settings "
                    "(safo never edits an existing field's options)"
                )
        for name in have:
            if name not in want:
                out.drift.append(f"field {f.name!r} has the option {name!r}, which board.yaml does not list")
        if sorted(want) == sorted(have) and want != have:
            out.notes.append(f"field {f.name!r}: the options are in a different order than board.yaml")
        for o in f.options:
            found = live.option(o.name)
            if found and (found.color != o.color or found.description != o.description):
                out.notes.append(
                    f"field {f.name!r} option {o.name!r}: live colour/description "
                    f"{found.color}/{found.description!r}, board.yaml {o.color}/{o.description!r}"
                )
    elif f.type == "iteration":
        starts = {dt.date.fromisoformat(i.start) for i in live.iterations}
        missing = [d for d in expected_starts(f) if d not in starts]
        if missing:
            out.drift.append(
                f"field {f.name!r} lacks the iterations starting {', '.join(d.isoformat() for d in missing)}"
            )
        if any(i.duration != f.duration_days for i in live.iterations):
            out.drift.append(f"field {f.name!r} has an iteration whose duration is not {f.duration_days} days")


def compare_structure(board: Board, live: LiveBoard, out: Findings) -> None:
    for f in board.fields:
        compare_field(f, live.fields.get(f.name), out)
    for v in board.views:
        found = live.views.get(v.name)
        if found is None:
            out.drift.append(f"view {v.name!r} is missing from the project")
            continue
        if found.layout != v.layout:
            out.drift.append(f"view {v.name!r} is a {found.layout} layout on the project but {v.layout} in board.yaml")
        if " ".join(found.filter.split()) != " ".join(v.filter.split()):
            out.drift.append(f"view {v.name!r} has the filter {found.filter!r}, board.yaml says {v.filter!r}")
    wanted = {v.name for v in board.views}
    for name in live.views:
        if name not in wanted:
            out.notes.append(f"view {name!r} exists on the project but not in board.yaml")


def run(ctx: Context, args: argparse.Namespace) -> int:
    board = ctx.board
    findings = Findings()
    try:
        live = load_live(ctx.client, board.project)
    except NotFoundError as err:
        ctx.say(f"UNKNOWN {err}")
        return EXIT_UNKNOWN
    compare_structure(board, live, findings)
    items = list_board_items(ctx.client, board, live)
    work, unreachable = collect_work(ctx.client, board, ctx.today)
    for name in unreachable:
        findings.unknown.append(f"repository {name} cannot be read with this token (is the App installed on it?)")
    for item in items:
        if item.content is None and item.content_type != "DraftIssue":
            findings.unknown.append(f"card {item.id} has inaccessible content")
    plan = build_plan(board, items, work, unreachable, ctx.today)
    findings.drift += plan.lines() + plan.anomalies
    ctx.say(
        f"audit {board.project.owner}/{board.project.number}: "
        f"{len(live.fields)} fields, {len(live.views)} views, {live.items_total} items"
    )
    for text in findings.drift:
        ctx.say(f"DRIFT   {text}")
    for text in findings.unknown:
        ctx.say(f"UNKNOWN {text}")
    for text in findings.notes:
        ctx.say(f"NOTE    {text}")
    if board.ui_only:
        ctx.say("UI-only settings (no API can read or set these; check by eye):")
        for text in board.ui_only:
            ctx.say(f"  - {text}")
    ctx.say(
        "clean" if findings.exit_code == EXIT_OK else f"{len(findings.drift)} drift, {len(findings.unknown)} unknown"
    )
    return findings.exit_code


def add_arguments(parser: argparse.ArgumentParser) -> None:
    del parser  # audit has no options of its own


register(
    Mode(
        "audit",
        "compare the live board with board.yaml and the repositories (exit 0 clean, 1 drift, 2 cannot tell)",
        add_arguments,
        run,
    )
)
