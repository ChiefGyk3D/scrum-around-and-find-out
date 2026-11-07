# SPDX-License-Identifier: Apache-2.0
"""A persisted map of issue -> project item id, and the numeric field and option ids, so a card edit is one REST PATCH.

On 2026-11-07 a whole-board listing cost about 600 GraphQL points and was made about 200 times in one day (#358, #355).
The user-owned board answers REST on the `core` bucket: `PATCH users/<owner>/projectsV2/<n>/items/<item id>` with
`{"fields": [{"id": <numeric field id>, "value": <option id | text | null>}]}` (verified 2026-11-07, read back
before and after; see the project-board-rest-api memory note).
Nothing here lists the board: an unmapped card is a `MapMiss`, and the one way to learn an item id is
`resolve_item`, which asks the REST item finder (`items?q=<title>`) once and caches the answer only when exactly one
item matches the issue's number and repository.

UNVERIFIED: the shape of the REST items listing (`id`, `content.number`, `content.repository_url`) is read
defensively as documented and has not been exercised against the live board by this code; a listing that does not
match gives `MalformedDataError`, never a guess. The kind of the Epic field (`text`) is likewise unverified: a wrong
kind shows up as a 422 on the first edit and is fixed in the map file.
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

from safo import bounded, ratebudget
from safo.errors import ApiError, ConfigError, MalformedDataError, RateLimitedError, UnknownOutcomeError

DEFAULT_PROJECT = "users/ChiefGyk3D/projectsV2/3"
MAX_MAP_BYTES = 524_288
MAX_ITEMS = 5000
MAP_NAME = "boardmap.json"

_PROJECT = re.compile(r"(users|orgs)/[A-Za-z0-9][A-Za-z0-9-]{0,38}/projectsV2/[0-9]{1,9}")
_KEY = re.compile(r"([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100})#([1-9][0-9]{0,8})")
_FIELD_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,39}")
OPTION_ID = re.compile(r"[0-9a-f]{8}")
_KINDS = ("single_select", "text")


class MapMiss(ConfigError):
    """The card is not in the map. The fix is to map it (one read), not to list the board."""


@dataclass
class Field:
    id: int
    kind: str = "single_select"
    options: dict[str, str] = field(default_factory=dict)  # option name -> option id


@dataclass
class BoardMap:
    project: str
    fields: dict[str, Field]
    items: dict[str, int]  # "owner/repo#N" -> project item id


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    body: str


@dataclass(frozen=True)
class Reply:
    ok: bool
    body: bytes
    error: str = ""


Transport = Callable[[str, str, str | None], Reply]


def default_map() -> BoardMap:
    """Project 3 of ChiefGyk3D with the numeric ids known on 2026-11-07; option ids other than Effort are learned."""
    return BoardMap(
        DEFAULT_PROJECT,
        {
            "Status": Field(423617716),
            "Kind": Field(435739141),
            "Effort": Field(435739176, options={"S": "4c1e9022", "M": "a22f24ba", "L": "4d2af34c"}),
            "Epic": Field(435739203, kind="text"),
        },
        {},
    )


def parse_key(key: str) -> tuple[str, str, int]:
    match = _KEY.fullmatch(key)
    if match is None:
        raise ConfigError("an issue is written owner/repo#N, with N at least 1")
    return match.group(1), match.group(2), int(match.group(3))


def check_id(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 10**15:
        raise ConfigError(f"the board map: {what} must be a positive whole number")
    return value


def from_json(data: Any) -> BoardMap:
    """Validate a loaded map. Every problem is a ConfigError that names the part and never echoes a value."""
    if not isinstance(data, dict) or set(data) - {"project", "fields", "items"}:
        raise ConfigError("the board map: expected an object with project, fields and items")
    project = data.get("project")
    if not isinstance(project, str) or not _PROJECT.fullmatch(project):
        raise ConfigError("the board map: project must look like users/<login>/projectsV2/<number>")
    raw_fields, raw_items = data.get("fields"), data.get("items")
    if not isinstance(raw_fields, dict) or not isinstance(raw_items, dict) or len(raw_items) > MAX_ITEMS:
        raise ConfigError("the board map: fields and items must be objects (items at most 5000)")
    fields: dict[str, Field] = {}
    for name, entry in raw_fields.items():
        if not _FIELD_NAME.fullmatch(str(name)) or not isinstance(entry, dict):
            raise ConfigError("the board map: a field is named in plain words and is an object")
        kind = entry.get("kind", "single_select")
        options = entry.get("options", {})
        if kind not in _KINDS or not isinstance(options, dict):
            raise ConfigError(f"the board map: field {name}: kind is single_select or text, options an object")
        for label, option_id in options.items():
            if not isinstance(label, str) or not isinstance(option_id, str) or not OPTION_ID.fullmatch(option_id):
                raise ConfigError(f"the board map: field {name}: an option id is 8 lowercase hex digits")
        fields[str(name)] = Field(check_id(entry.get("id"), f"field {name} id"), kind, dict(options))
    items: dict[str, int] = {}
    for key, item_id in raw_items.items():
        parse_key(str(key))
        items[str(key)] = check_id(item_id, "an item id")
    return BoardMap(project, fields, items)


def to_json(board: BoardMap) -> dict[str, Any]:
    return {
        "project": board.project,
        "fields": {n: {"id": f.id, "kind": f.kind, "options": f.options} for n, f in sorted(board.fields.items())},
        "items": dict(sorted(board.items.items())),
    }


def load(path: Path) -> BoardMap:
    """The map at `path`, or the default when there is no directory or no file. Anything unsafe is a ConfigError.

    Read the way `save` writes: the directory is opened without following a symlink and must be ours (repaired to
    0700), and the file is opened relative to it, without following a link, must be a regular file of ours with one
    link. A big or malformed file is refused too.
    """
    name = path.name
    try:
        dfd = ratebudget.open_private_dir(path.parent, create=False)
    except FileNotFoundError:
        return default_map()
    except OSError as problem:  # a symlinked or foreign directory
        raise ConfigError(f"the board map directory is not safe to read ({type(problem).__name__})") from problem
    try:
        raw = ratebudget.read_private(dfd, name, MAX_MAP_BYTES)
    except FileNotFoundError:
        return default_map()
    except OSError as problem:  # a symlink, a special file, another user's file, a hard link
        raise ConfigError(f"the board map {name} is not safe to read ({type(problem).__name__})") from problem
    finally:
        os.close(dfd)
    if len(raw) > MAX_MAP_BYTES:
        raise ConfigError(f"the board map {name} is larger than {MAX_MAP_BYTES} bytes")
    try:
        return from_json(bounded.loads(raw))
    except (ValueError, RecursionError) as problem:  # JSON errors, duplicate keys, nesting, encoding
        raise ConfigError(f"the board map {name} is not valid JSON ({type(problem).__name__})") from problem


def save(board: BoardMap, path: Path) -> None:
    """Atomically write the map into a private directory (created, or repaired to 0700)."""
    ratebudget.write_private(path, json.dumps(to_json(board), indent=1, sort_keys=True).encode() + b"\n")


def map_path(env: Mapping[str, str]) -> Path:
    return ratebudget.state_dir(env) / MAP_NAME


# requests


def _value(spec: Field, name: str, value: str | None) -> str | None:
    if value is None:
        return None  # clears the field
    if spec.kind == "text":
        return value
    if value in spec.options:
        return spec.options[value]
    if OPTION_ID.fullmatch(value):
        return value
    known = ", ".join(sorted(spec.options)) or "none learned"
    raise ConfigError(f"{name}: {value!r} is not an option id or a known option name ({known}); learn it with --option")


def build_request(board: BoardMap, key: str, edits: Mapping[str, str | None]) -> Request:
    """The one PATCH for these edits. Raises MapMiss when the card is unmapped; never reads anything."""
    parse_key(key)
    if not edits:
        raise ConfigError("nothing to change: give at least one Field=Value")
    item_id = board.items.get(key)
    if item_id is None:
        raise MapMiss(
            f"{key} is not in the board map; add it with --item-id N, or look it up once with --resolve "
            "(two REST reads, then it is remembered); a board listing is never made"
        )
    body = []
    for name, value in edits.items():
        spec = board.fields.get(name)
        if spec is None:
            raise ConfigError(f"unknown field {name!r}; the map knows {', '.join(sorted(board.fields))}")
        body.append({"id": spec.id, "value": _value(spec, name, value)})
    return Request("PATCH", f"{board.project}/items/{item_id}", json.dumps({"fields": body}, separators=(",", ":")))


def edit_card(board: BoardMap, transport: Transport, key: str, edits: Mapping[str, str | None]) -> None:
    """One PATCH. A refusal is an ApiError; a transport failure after the send is an unknown outcome, never replayed."""
    request = build_request(board, key, edits)
    try:
        reply = transport(request.method, request.path, request.body)
    except (OSError, TimeoutError) as problem:
        raise UnknownOutcomeError(
            f"{key}: the edit may or may not have been applied; re-read the card", problem
        ) from problem
    if not reply.ok:
        raise ApiError(f"{key}: GitHub refused the edit ({reply.error or 'no detail'})")


# finding an item id, once


def _json_list(reply: Reply, what: str) -> list[Any]:
    if not reply.ok:
        raise ApiError(f"{what}: the read failed ({reply.error or 'no detail'})")
    try:
        data = bounded.loads(reply.body)
    except (ValueError, RecursionError) as problem:
        raise MalformedDataError(f"{what}: the answer is not valid JSON") from problem
    if not isinstance(data, list):
        raise MalformedDataError(f"{what}: expected a list")
    return data


def _repo_matches(content: Mapping[str, Any], owner: str, repo: str) -> bool | None:
    """True, False, or None when the item says nothing about its repository."""
    url = content.get("repository_url")
    if isinstance(url, str):
        return url.lower().rstrip("/").endswith(f"/repos/{owner}/{repo}".lower())
    nested = content.get("repository")
    if isinstance(nested, dict) and isinstance(nested.get("full_name"), str):
        return bool(nested["full_name"].lower() == f"{owner}/{repo}".lower())
    return None


def resolve_item(board: BoardMap, transport: Transport, key: str) -> int:
    """The item id for `key`: the map's, else two REST reads (the issue, then the item finder), cached if unique."""
    owner, repo, number = parse_key(key)
    if key in board.items:
        return board.items[key]
    issue_reply = transport("GET", f"repos/{owner}/{repo}/issues/{number}", None)
    if not issue_reply.ok:
        raise ApiError(f"{key}: the issue read failed ({issue_reply.error or 'no detail'})")
    try:
        issue = bounded.loads(issue_reply.body)
    except (ValueError, RecursionError) as problem:
        raise MalformedDataError(f"{key}: the issue answer is not valid JSON") from problem
    title = issue.get("title") if isinstance(issue, dict) else None
    if not isinstance(title, str) or not title:
        raise MalformedDataError(f"{key}: the issue has no title")
    listing = _json_list(transport("GET", f"{board.project}/items?q={quote(title, safe='')}&per_page=50", None), key)
    found: set[int] = set()
    for entry in listing:
        content = entry.get("content") if isinstance(entry, dict) else None
        if not isinstance(content, dict) or content.get("number") != number or isinstance(content.get("number"), bool):
            continue
        item_id = entry.get("id")
        if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id < 1:
            raise MalformedDataError(f"{key}: an item has no usable id")
        if _repo_matches(content, owner, repo) is not True:  # no repository identity is no match
            continue
        found.add(item_id)
    if len(found) != 1:
        raise MalformedDataError(f"{key}: {len(found)} board items match; map it with --item-id")
    (item_id,) = found
    board.items[key] = item_id
    return item_id


# the real transport: gh through the shared budget


def gh_transport(
    env: Mapping[str, str],
    *,
    run: Callable[..., Any] = subprocess.run,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
    gh: str | None = None,
) -> Transport:
    """`gh api` through `ratebudget.main`: spaced writes, the ledger, the headroom check, one call and no replay."""

    def send(method: str, path: str, body: str | None) -> Reply:
        argv = (
            ["api"] + (["-X", method] if method != "GET" else []) + [path] + ([] if body is None else ["--input", "-"])
        )
        out, err = io.StringIO(), io.StringIO()
        code = ratebudget.main(argv, env=env, out=out, err=err, run=run, sleep=sleep, clock=clock, gh=gh, stdin=body)
        if code == ratebudget.EXIT_THROTTLED:
            raise RateLimitedError(err.getvalue().strip() or "rate limited")
        if code == ratebudget.EXIT_UNKNOWN_OUTCOME:
            raise TimeoutError(err.getvalue().strip() or "outcome unknown")
        text = (out.getvalue() + err.getvalue())[:300]
        return Reply(code == 0, out.getvalue().encode(), "" if code == 0 else f"exit {code}: {text}")

    return send
