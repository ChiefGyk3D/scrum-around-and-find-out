# SPDX-License-Identifier: MIT
"""What reconcile would change, as data. `audit` prints it; `reconcile` applies it."""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from safo.items import Content, ItemState
from safo.rules import area_for, done_day, done_names, done_status, open_status
from safo.schema import Board, Repository


@dataclass(frozen=True)
class Add:
    content: Content
    status: str
    area: str | None
    done_on: str | None


@dataclass(frozen=True)
class Flip:
    """A closed or merged item that is not Done."""

    item: ItemState
    content: Content
    status: str
    done_on: str


@dataclass(frozen=True)
class DateFill:
    """A Done item with no Done-on date."""

    item: ItemState
    content: Content
    done_on: str


@dataclass(frozen=True)
class FillStatus:
    item: ItemState
    content: Content
    status: str


@dataclass(frozen=True)
class FillArea:
    item: ItemState
    content: Content
    area: str


@dataclass
class Plan:
    adds: list[Add] = field(default_factory=list)
    flips: list[Flip] = field(default_factory=list)
    date_fills: list[DateFill] = field(default_factory=list)
    status_fills: list[FillStatus] = field(default_factory=list)
    area_fills: list[FillArea] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)  # reported, never changed: an open item sitting in Done
    unreachable: list[str] = field(default_factory=list)  # repositories the token could not read

    @property
    def changes(self) -> int:
        return len(self.adds) + len(self.flips) + len(self.date_fills) + len(self.status_fills) + len(self.area_fills)

    def lines(self) -> list[str]:
        out = [
            f"ADD {a.content.repo}#{a.content.number} -> {a.status}" + (f", {a.area}" if a.area else "")
            for a in self.adds
        ]
        out += [
            f"DONE {f.content.repo}#{f.content.number} {f.item.status} -> {f.status} on {f.done_on}" for f in self.flips
        ]
        out += [f"DATE {d.content.repo}#{d.content.number} Done on {d.done_on}" for d in self.date_fills]
        out += [f"STATUS {s.content.repo}#{s.content.number} -> {s.status}" for s in self.status_fills]
        out += [f"AREA {a.content.repo}#{a.content.number} -> {a.area}" for a in self.area_fills]
        return out


def build_plan(
    board: Board,
    items: Sequence[ItemState],
    work: Mapping[str, Sequence[Content]],
    unreachable: Sequence[str],
    today: dt.date,
) -> Plan:
    """`work` maps a listed repository's lower-case owner/name to its open (and recently closed) contents."""
    rules = board.rules
    repos: dict[str, Repository] = {r.full_name.lower(): r for r in board.repositories}
    on_board = {i.content.id: i for i in items if i.content is not None}
    plan = Plan(unreachable=list(unreachable))

    for key, contents in work.items():
        owner = repos[key]
        for c in contents:
            if c.repo.lower() != key:
                plan.anomalies.append(
                    f"{c.repo}#{c.number} was listed under {owner.full_name} but GitHub says it belongs to {c.repo} "
                    "(renamed or transferred): not added; update repositories in board.yaml"
                )
                continue
            if c.id in on_board:
                continue
            if c.is_open:
                plan.adds.append(Add(c, open_status(rules, c), area_for(owner, c), None))
            else:
                plan.adds.append(Add(c, done_status(rules, c), area_for(owner, c), done_day(c, today)))

    skipped = {u.lower() for u in unreachable}
    for item in items:
        content = item.content
        if content is None or content.repo.lower() in skipped or content.repo.lower() not in repos:
            continue
        repo = repos[content.repo.lower()]
        if not content.is_open:
            if item.status != done_status(rules, content):
                plan.flips.append(Flip(item, content, done_status(rules, content), done_day(content, today)))
            elif rules.done_date_field and item.done is None:
                plan.date_fills.append(DateFill(item, content, done_day(content, today)))
            continue
        if item.status in done_names(rules):
            plan.anomalies.append(
                f"{content.repo}#{content.number} is open but its status is {item.status}; safo never reopens a card"
            )
        if item.status is None:
            plan.status_fills.append(FillStatus(item, content, open_status(rules, content)))
        if item.area is None:
            area = area_for(repo, content)
            if area:
                plan.area_fills.append(FillArea(item, content, area))
    return plan
