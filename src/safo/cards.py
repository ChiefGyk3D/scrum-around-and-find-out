# SPDX-License-Identifier: Apache-2.0
"""safo-cards: set Kind, Epic, Effort (and Area, Priority defaults) on project cards from a table, REST only (#591).

    safo-cards plan  TABLE.json [--board board.yaml]
    safo-cards apply TABLE.json [--board board.yaml] [--max-writes N]

The table is strict JSON: `{"cards": [{"repo": "owner/name", "issue": 7, "kind": "Story", "epic": "text",
"effort": "M", "area": "Core", "priority": "P2 later"}]}`; `area` and `priority` are optional. Every value is checked
against the option names in board.yaml (and the repository against its repositories list) before anything is sent; one
bad entry refuses the whole table. Area falls back to the repository's `default_area` and Priority to
`rules.new_item_defaults`, only when the card has none.

Nothing lists the board. Per card: the persisted item id (or one REST lookup by title); a card that is not on the board
is added with one POST (`plan` says WOULD ADD and sends nothing); one PATCH carries the fields that differ; one read
(`fields=` list) after each PATCH must show every value, or the run stops with an error. The first failure stops the
run, an unknown outcome is never replayed, and every call goes through the shared budget (`ghw` rules). Output holds
card references, field names and values from the table, never a response body or a token.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import quote

from safo import boardmap, bounded
from safo.credentials import find_gh
from safo.errors import EXIT_OK, ApiError, ConfigError, MalformedDataError, SafoError, UnknownOutcomeError
from safo.kindwrite import _plain
from safo.modes.reconcile import safe
from safo.ratebudget import state_dir
from safo.schema import Board, Field, load_board

MAX_TABLE_BYTES = 262_144
MAX_ROWS = 500
MAX_EPIC = 200
ROW_KEYS = frozenset({"repo", "issue", "kind", "epic", "effort", "area", "priority"})
REQUIRED = ("repo", "issue", "kind", "epic", "effort")
_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}")


@dataclass(frozen=True)
class Row:
    key: str  # owner/repo#N
    wanted: Mapping[str, str]  # field name -> option name or text, only the fields this card is to hold
    explicit: frozenset[str]  # fields the table named itself (the rest are defaults: set only when empty)


def _board_path(env: Mapping[str, str], given: str | None) -> Path:
    if given:
        return Path(given)
    if not env.get("HOME"):
        raise ConfigError("no board file: pass --board or set HOME")
    return Path(env["HOME"]) / ".config" / "safo" / "board.yaml"


def project_path(board: Board) -> str:
    p = board.project
    return f"{'users' if p.owner_type == 'user' else 'orgs'}/{p.owner}/projectsV2/{p.number}"


def _field(board: Board, name: str) -> Field:
    found = board.field_named(name)
    if found is None:
        raise ConfigError(f"board.yaml has no field named {name}")
    return found


def field_names(board: Board) -> dict[str, str]:
    """Role -> the board's own field name (Kind, Epic and Effort come from rules.tracking)."""
    t = board.rules.tracking
    names = {
        "kind": t.kind_field,
        "epic": t.epic_field,
        "effort": t.effort_field,
        "area": board.rules.area_field,
        "priority": "Priority",
    }
    for role in ("kind", "epic", "effort"):
        if not names[role]:
            raise ConfigError(f"board.yaml does not configure the {role} field; safo-cards needs it")
    return names


def _option(board: Board, field_name: str, value: object, what: str) -> str:
    spec = _field(board, field_name)
    names = [o.name for o in spec.options]
    if not isinstance(value, str) or value not in names:
        raise ConfigError(f"{what}: not one of the board's {field_name} options ({', '.join(names)})")
    return value


def load_table(path: Path, board: Board) -> list[Row]:
    """Rows from the table file. One bad row refuses the whole table, naming the row and the part, not the value."""
    try:
        raw = bounded.read_bounded(path, MAX_TABLE_BYTES + 1)
    except OSError as problem:
        raise ConfigError(f"the table cannot be read ({type(problem).__name__}); a symlink is refused") from problem
    try:
        data = bounded.loads(raw, MAX_TABLE_BYTES)
    except (ValueError, RecursionError) as problem:
        raise ConfigError(f"the table is not valid JSON within its limits ({type(problem).__name__})") from problem
    if not isinstance(data, dict) or set(data) != {"cards"} or not isinstance(data["cards"], list):
        raise ConfigError('the table must be {"cards": [ ... ]}')
    if not data["cards"] or len(data["cards"]) > MAX_ROWS:
        raise ConfigError(f"the table needs 1 to {MAX_ROWS} cards")
    names = field_names(board)
    repos = {r.full_name: r for r in board.repositories}
    defaults = dict(board.rules.new_item_defaults)
    rows: list[Row] = []
    seen: set[str] = set()
    for n, entry in enumerate(data["cards"], 1):
        where = f"card {n}"
        if not isinstance(entry, dict) or set(entry) - ROW_KEYS or any(k not in entry for k in REQUIRED):
            raise ConfigError(
                f"{where}: needs repo, issue, kind, epic, effort (optionally area, priority) and nothing else"
            )
        repo, issue = entry["repo"], entry["issue"]
        if not isinstance(repo, str) or not _REPO.fullmatch(repo) or repo not in repos:
            raise ConfigError(f"{where}: repo is not one of board.yaml's repositories")
        if isinstance(issue, bool) or not isinstance(issue, int) or not 0 < issue < 10**9:
            raise ConfigError(f"{where}: issue must be a positive whole number")
        key = f"{repo}#{issue}"
        if key in seen:
            raise ConfigError(f"{where}: {key} appears twice")
        seen.add(key)
        epic = entry["epic"]
        if not isinstance(epic, str) or not epic.strip() or len(epic) > MAX_EPIC or not epic.isprintable():
            raise ConfigError(f"{where}: epic must be plain printable text of 1 to {MAX_EPIC} characters")
        wanted = {
            names["kind"]: _option(board, names["kind"], entry["kind"], f"{where}: kind"),
            names["epic"]: epic.strip(),
            names["effort"]: _option(board, names["effort"], entry["effort"], f"{where}: effort"),
        }
        explicit = set(wanted)
        for role, fallback in (("area", repos[repo].default_area), ("priority", defaults.get(names["priority"]))):
            if role in entry:
                wanted[names[role]] = _option(board, names[role], entry[role], f"{where}: {role}")
                explicit.add(names[role])
            elif fallback is not None:
                wanted[names[role]] = _option(board, names[role], fallback, f"{where}: default {role}")
        rows.append(Row(key, wanted, frozenset(explicit)))
    return rows


# reads and the one add


def _get(transport: boardmap.Transport, path: str, what: str) -> Any:
    reply = transport("GET", path, None)
    if not reply.ok:
        raise ApiError(f"{what}: the read failed ({safe(reply.error or 'no detail')})")
    try:
        return bounded.loads(reply.body)
    except (ValueError, RecursionError) as problem:
        raise MalformedDataError(f"{what}: the answer is not valid JSON") from problem


def learn_fields(board: boardmap.BoardMap, transport: boardmap.Transport, names: Sequence[str]) -> None:
    """One read of the project's field list: ids, kinds and option ids of the wanted fields (never the items)."""
    listing = _get(transport, f"{board.project}/fields?per_page=100", "the field list")
    if not isinstance(listing, list):
        raise MalformedDataError("the field list: expected a list")
    for name in names:
        entry = next((e for e in listing if isinstance(e, dict) and e.get("name") == name), None)
        if entry is None:
            raise ApiError(f"the project has no field named {name}")
        kind = "single_select" if isinstance(entry.get("options"), list) else "text"
        options: dict[str, str] = {}
        for option in entry.get("options") or []:
            label = boardmap._option_name(option.get("name")) if isinstance(option, dict) else None
            option_id = option.get("id") if isinstance(option, dict) else None
            if label is not None and isinstance(option_id, str) and boardmap.OPTION_ID.fullmatch(option_id):
                options[label] = option_id
        board.fields[name] = boardmap.Field(boardmap.check_id(entry.get("id"), f"field {name} id"), kind, options)


def current_values(
    board: boardmap.BoardMap, transport: boardmap.Transport, key: str, item_id: int, names: Sequence[str]
) -> dict[str, Any]:
    """The card's values for `names` (None for an empty one): one REST read with a comma-separated `fields=` list."""
    ids = ",".join(str(board.fields[n].id) for n in names)
    item = _get(transport, f"{board.project}/items/{item_id}?fields={ids}", key)
    listed = item.get("fields") if isinstance(item, dict) else None
    if not isinstance(listed, list):
        raise MalformedDataError(f"{key}: the card read has no field values")
    found: dict[str, Any] = {n: None for n in names}
    for entry in listed:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            by_id = {board.fields[n].id: n for n in names}
            raw_id = entry.get("id")
            name = by_id.get(raw_id) if isinstance(raw_id, int) else None
        if name in found:
            found[name] = _plain(entry.get("value"))
    return found


def find_item(board: boardmap.BoardMap, transport: boardmap.Transport, key: str) -> int | None:
    """The card's item id: the persisted map, else the title lookup. None when the card is not on the board."""
    if key in board.items:
        return board.items[key]
    owner, repo, number = boardmap.parse_key(key)
    issue = _get(transport, f"repos/{owner}/{repo}/issues/{number}", key)
    title = issue.get("title") if isinstance(issue, dict) else None
    if not isinstance(title, str) or not title:
        raise MalformedDataError(f"{key}: the issue has no title")
    listing = _get(transport, f"{board.project}/items?q={quote(title, safe='')}&per_page=50", key)
    if not isinstance(listing, list):
        raise MalformedDataError(f"{key}: the item lookup is not a list")
    found: set[int] = set()
    for entry in listing:
        content = entry.get("content") if isinstance(entry, dict) else None
        if not isinstance(content, dict) or content.get("number") != number or isinstance(content.get("number"), bool):
            continue
        item_id = entry.get("id")
        if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id < 1:
            raise MalformedDataError(f"{key}: an item has no usable id")
        if boardmap._repo_matches(content, owner, repo) is True:
            found.add(item_id)
    if len(found) > 1:
        raise MalformedDataError(f"{key}: {len(found)} board items match; stopped")
    if not found:
        return None
    (item_id,) = found
    board.items[key] = item_id
    return item_id


def add_item(board: boardmap.BoardMap, transport: boardmap.Transport, key: str) -> int:
    """One POST adds the issue to the project. Never replayed: a lost reply is an unknown outcome."""
    owner, repo, number = boardmap.parse_key(key)
    body = json.dumps({"type": "Issue", "owner": owner, "repo": repo, "number": number}, separators=(",", ":"))
    try:
        reply = transport("POST", f"{board.project}/items", body)
    except (OSError, TimeoutError) as problem:
        raise UnknownOutcomeError(f"{key}: the add may or may not have been applied; re-run plan", problem) from problem
    if not reply.ok:
        raise ApiError(f"{key}: GitHub refused the add ({safe(reply.error or 'no detail')})")
    try:
        data = bounded.loads(reply.body)
    except (ValueError, RecursionError) as problem:
        raise UnknownOutcomeError(f"{key}: the add answered something unreadable; re-run plan", problem) from problem
    item_id = data.get("id") if isinstance(data, dict) else None
    if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id < 1:
        raise UnknownOutcomeError(f"{key}: the add gave no item id; re-run plan")
    board.items[key] = item_id
    return item_id


# the run


def _differs(old: Any, new: str) -> bool:
    return bool(old != new)


@dataclass
class Result:
    written: int = 0
    added: int = 0
    unchanged: int = 0
    would: int = 0
    capped: bool = False


def run_rows(
    rows: Sequence[Row],
    board: boardmap.BoardMap,
    transport: boardmap.Transport,
    *,
    say: Callable[[str], None],
    plan: bool,
    max_writes: int | None,
) -> Result:
    names = list(dict.fromkeys(n for r in rows for n in r.wanted))
    learn_fields(board, transport, names)
    result = Result()
    for row in rows:
        if max_writes is not None and result.written + result.added >= max_writes:
            result.capped = True
            say(f"stopped at the write cap ({max_writes}); re-run to continue (it is idempotent)")
            break
        item_id = find_item(board, transport, row.key)
        old: dict[str, Any]
        if item_id is None:
            if plan:
                result.would += 1
                say(f"WOULD ADD {row.key}: " + "; ".join(f"{k}={v}" for k, v in row.wanted.items()))
                continue
            item_id = add_item(board, transport, row.key)
            result.added += 1
            say(f"ADDED {row.key}")
            if max_writes is not None and result.written + result.added >= max_writes:
                result.capped = True  # the add used the cap; the next run sets the fields from the remembered item id
                say(f"stopped at the write cap ({max_writes}); re-run to continue (it is idempotent)")
                break
            old = {n: None for n in names}
        else:
            old = current_values(board, transport, row.key, item_id, names)
        edits = {
            k: v for k, v in row.wanted.items() if _differs(old.get(k), v) and (k in row.explicit or old.get(k) is None)
        }
        if not edits:
            result.unchanged += 1
            say(f"OK {row.key}: nothing to change")
            continue
        shown = "; ".join(f"{k}: {old.get(k)!r} -> {v!r}" for k, v in edits.items())
        if plan:
            result.would += 1
            say(f"WOULD SET {row.key}: {safe(shown)}")
            continue
        boardmap.edit_card(board, transport, row.key, edits)
        after = current_values(board, transport, row.key, item_id, list(edits))
        bad = [k for k, v in edits.items() if after.get(k) != v]
        if bad:
            raise ApiError(f"{row.key}: read-back does not match after the write ({', '.join(bad)}); stopped")
        result.written += 1
        say(f"SET {row.key}: {safe(shown)} (read back)")
    return result


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="safo-cards", description="set Kind, Epic and Effort on project cards, REST only")
    p.add_argument("mode", choices=("plan", "apply"), help="plan prints what would change and writes nothing")
    p.add_argument("table", help="the table file (strict JSON)")
    p.add_argument("--board", default=None, help="board.yaml (default: ~/.config/safo/board.yaml)")
    p.add_argument("--max-writes", type=int, default=None, help="stop cleanly after this many writes or adds")
    return p


def main(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    out: TextIO,
    err: TextIO,
    transport: boardmap.Transport | None = None,
) -> int:
    args = parser().parse_args(argv)

    def say(line: str) -> None:
        out.write(safe(line) + "\n")

    path = state_dir(env) / boardmap.MAP_NAME if "HOME" in env or "XDG_STATE_HOME" in env else None
    try:
        if args.max_writes is not None and args.max_writes < 1:
            raise ConfigError("--max-writes must be at least 1")
        if path is None:
            raise ConfigError("no state directory: set HOME or XDG_STATE_HOME")
        config = load_board(_board_path(env, args.board), check_fields=False)
        rows = load_table(Path(args.table), config)
        board = boardmap.load(path)
        if board.project != project_path(config):
            raise ConfigError("the board map belongs to another project than board.yaml; stopped")
        before = boardmap.to_json(board)
        send = transport or boardmap.gh_transport(env, gh=find_gh(env, home_ok=True))
        try:
            result = run_rows(rows, board, send, say=say, plan=args.mode == "plan", max_writes=args.max_writes)
        finally:
            boardmap.merge_save(path, before, board)
    except SafoError as problem:
        err.write(f"safo-cards: {safe(str(problem))}\n")
        return problem.exit_code
    say(
        f"{args.mode}: {result.written} written, {result.added} added, {result.unchanged} unchanged, "
        f"{result.would} would change"
    )
    return EXIT_OK


def entry() -> None:
    raise SystemExit(main(sys.argv[1:], env=os.environ, out=sys.stdout, err=sys.stderr))
