# SPDX-License-Identifier: Apache-2.0
"""Kind for a board's open cards, from rules and an approved map (#479, phase 1 of the board 11 reconcile).

Three steps, each its own command line option of `safo kind`:

1. `--read-board`: read the whole board once, by REST pages (never GraphQL), a pause between pages, into a private
   snapshot directory (0700, files 0600). A new read keeps the earlier one beside it as `items-<stamp>.json`.
2. `--propose FILE`: from that snapshot, rules give a Kind to each OPEN card whose Kind is empty: first its labels
   (bug, enhancement or feature, documentation, chore, dependencies or ci, epic, release), then its title prefix
   (`feat:`, `fix:`, `docs:`, `Epic:` ...), then Dependabot and `Bump` pull requests. Anything the rules do not name is
   RESIDUE: it is listed and never written. The proposal is a plain `{"owner/repo#N": "Kind"}` file for a human to read.
3. `--map FILE`: write an approved map. Every value must be one of the board's own Kind option names, or the whole
   map is refused before anything is sent. A card is written only when it is open and its Kind is empty; one REST PATCH
   carries the Kind field and nothing else (never Epic, never Effort). `--max-writes N` stops after N writes, exit 0.

Nothing is written without `--map`; `--dry-run` sends nothing at all. A refusal from GitHub is answered once with a
re-read of the field's option ids (a board that regenerated them) and one retry; a lost reply is an unknown outcome and
stops the run (the write may have landed, so it is never replayed). Every write is journaled (old and new value).
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import stat
import subprocess
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from safo import boardmap, bounded
from safo.errors import ApiError, ConfigError, UnknownOutcomeError

KIND = "Kind"
ITEMS = "items.json"
FIELDS = "fields.json"
JOURNAL = "kind-writes.jsonl"
MAX_MAP_BYTES = 1_048_576
MAX_SNAPSHOT_BYTES = bounded.MAX_FILE_BYTES
MAX_PAGES = 50
PAUSE_SECONDS = 2.0
WANTED_FIELDS = ("Status", "Area", "Priority", "Kind", "Epic", "Effort", "Done on")

# Labels, first match in this order wins when a card holds several that disagree.
LABEL_ORDER: tuple[tuple[str, str], ...] = (
    ("epic", "Epic"),
    ("release", "Release"),
    ("bug", "Bug"),
    ("enhancement", "Feature"),
    ("feature", "Feature"),
    ("documentation", "Docs"),
    ("chore", "Chore"),
    ("dependencies", "Chore"),
    ("ci", "Chore"),
)
PREFIX_KIND: dict[str, str] = {
    "epic": "Epic",
    "release": "Release",
    "feat": "Feature",
    "feature": "Feature",
    "fix": "Bug",
    "bug": "Bug",
    "bugfix": "Bug",
    "docs": "Docs",
    "doc": "Docs",
    "chore": "Chore",
    "ci": "Chore",
    "build": "Chore",
    "deps": "Chore",
    "lesson": "Lesson",
    "decision": "Decision",
    "adr": "Decision",
}
_PREFIX = re.compile(r"\s*([A-Za-z]+)\s*(?:\([^)]{0,60}\))?!?\s*:")
_REPO_URL = re.compile(r"/repos/([A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100})(?:/|$)")
_BUMP = re.compile(r"\s*bump\s", re.IGNORECASE)
_OPTION_NAME = re.compile(r"[A-Za-z][A-Za-z ]{0,30}")


@dataclass(frozen=True)
class Card:
    key: str  # owner/repo#N
    item_id: int  # the project item id, the number a REST PATCH uses
    type: str  # Issue | PullRequest
    state: str  # open | closed
    title: str
    labels: tuple[str, ...]
    author: str
    values: Mapping[str, Any]  # field name -> current value (option name, text, number, date) or None
    closed_at: str | None = None
    merged: bool = False

    @property
    def kind(self) -> str | None:
        value = self.values.get(KIND)
        return value if isinstance(value, str) else None


# the rules


def classify(card: Card, allowed: frozenset[str]) -> tuple[str, str] | None:
    """(Kind, rule name) for a card, or None. A Kind the board does not have is never proposed."""
    held = {label.lower() for label in card.labels}
    for label, kind in LABEL_ORDER:
        if label in held:
            return (kind, f"label:{label}") if kind in allowed else None
    match = _PREFIX.match(card.title)
    if match and match.group(1).lower() in PREFIX_KIND:
        word = match.group(1).lower()
        kind = PREFIX_KIND[word]
        return (kind, f"prefix:{word}") if kind in allowed else None
    if card.type == "PullRequest":
        if card.author == "dependabot[bot]":
            return ("Chore", "author:dependabot") if "Chore" in allowed else None
        if _BUMP.match(card.title):
            return ("Chore", "title:bump") if "Chore" in allowed else None
    return None


@dataclass
class Proposal:
    hits: dict[str, tuple[str, str]] = field(default_factory=dict)  # key -> (Kind, rule)
    residue: list[str] = field(default_factory=list)

    def by_rule(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _, rule in self.hits.values():
            counts[rule] = counts.get(rule, 0) + 1
        return dict(sorted(counts.items()))

    def by_kind(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for kind, _ in self.hits.values():
            counts[kind] = counts.get(kind, 0) + 1
        return dict(sorted(counts.items()))


def propose(cards: Sequence[Card], allowed: frozenset[str]) -> Proposal:
    """Rules for the open cards whose Kind is empty. Closed cards and cards with a Kind are not this step's business."""
    result = Proposal()
    for card in cards:
        if card.state != "open" or card.kind is not None:
            continue
        hit = classify(card, allowed)
        if hit is None:
            result.residue.append(card.key)
        else:
            result.hits[card.key] = hit
    return result


# the snapshot


def _text(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"the snapshot: {what} is not text")
    return value


def _plain(value: Any) -> Any:
    """A field value as plain data: a select's option name, a text's string, a number or date as it is."""
    if isinstance(value, dict):
        name = value.get("name")
        if isinstance(name, dict) and isinstance(name.get("raw"), str):
            return name["raw"]
        if isinstance(value.get("raw"), str):
            return value["raw"]
        if isinstance(value.get("title"), str):
            return value["title"]
        return str(sorted(value))  # an unknown shape is kept as a present value, never as a blank
    return value


def cards_from_raw(raw: Any) -> list[Card]:
    """Cards from the REST items listing. Any item that is not shaped as expected refuses the whole snapshot."""
    if not isinstance(raw, list):
        raise ConfigError("the snapshot: items must be a list")
    cards: list[Card] = []
    seen: set[str] = set()
    for item in raw:
        try:
            content = item["content"]
            item_id = item["id"]
            if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id < 1:
                raise ConfigError("the snapshot: an item has no usable id")
            # An issue names its repository in `repository_url`; a pull request does not, but its `url` carries it.
            where = _text(content.get("repository_url") or content["url"], "the card url")
            found = _REPO_URL.search(where.split("?", 1)[0])
            if found is None:
                raise ConfigError("the snapshot: a card url does not name its repository")
            repo = found.group(1)
            number = content["number"]
            if isinstance(number, bool) or not isinstance(number, int) or number < 1:
                raise ConfigError("the snapshot: a card has no usable number")
            key = f"{repo}#{number}"
            boardmap.parse_key(key)
            state = _text(content["state"], "state")
            if state not in ("open", "closed"):
                raise ConfigError("the snapshot: a card state is neither open nor closed")
            labels = tuple(_text(label["name"], "a label") for label in content.get("labels") or [])
            user = content.get("user")
            author = user.get("login", "") if isinstance(user, dict) else ""
            values = {_text(f["name"], "a field name"): _plain(f.get("value")) for f in item["fields"]}
            closed = content.get("closed_at")
            card = Card(
                key,
                item_id,
                _text(item["content_type"], "content_type"),
                state,
                _text(content["title"], "title"),
                labels,
                author if isinstance(author, str) else "",
                values,
                closed if isinstance(closed, str) else None,
                bool(content.get("merged_at")),
            )
        except ConfigError:
            raise
        except (KeyError, TypeError, AttributeError, IndexError, ValueError):
            raise ConfigError("the snapshot: an item is not shaped as expected") from None
        if key in seen:
            raise ConfigError(f"the snapshot: {key} appears twice")
        seen.add(key)
        cards.append(card)
    return cards


def kind_options(fields: Any) -> tuple[int, dict[str, str]]:
    """(the Kind field's numeric id, option name -> option id) from the REST field listing."""
    if not isinstance(fields, list):
        raise ConfigError("the field listing is not a list")
    for entry in fields:
        if isinstance(entry, dict) and entry.get("name") == KIND and isinstance(entry.get("options"), list):
            field_id = boardmap.check_id(entry.get("id"), "the Kind field id")
            options: dict[str, str] = {}
            for option in entry["options"]:
                name = option.get("name") if isinstance(option, dict) else None
                label = name.get("raw") if isinstance(name, dict) else name
                option_id = option.get("id") if isinstance(option, dict) else None
                if not isinstance(label, str) or not _OPTION_NAME.fullmatch(label):
                    raise ConfigError("a Kind option name is not plain words")
                if not isinstance(option_id, str) or not boardmap.OPTION_ID.fullmatch(option_id):
                    raise ConfigError("a Kind option id is not 8 hex digits")
                options[label] = option_id
            return field_id, options
    raise ConfigError("the board has no Kind field with options")


def _read_private(directory: Path, name: str, limit: int) -> bytes:
    try:
        return bounded.read_bounded(directory / name, limit + 1)
    except OSError as problem:  # missing, a symlink, a FIFO
        raise ConfigError(f"{name} in the snapshot directory cannot be read ({type(problem).__name__})") from problem


def _json(raw: bytes, limit: int, what: str) -> Any:
    try:
        return bounded.loads(raw, limit)
    except (ValueError, RecursionError) as problem:
        raise ConfigError(f"{what} is not valid JSON within its limits ({type(problem).__name__})") from problem


def load_cards(directory: Path) -> list[Card]:
    return cards_from_raw(_json(_read_private(directory, ITEMS, MAX_SNAPSHOT_BYTES), MAX_SNAPSHOT_BYTES, ITEMS))


def load_fields(directory: Path) -> Any:
    return _json(_read_private(directory, FIELDS, MAX_SNAPSHOT_BYTES), MAX_SNAPSHOT_BYTES, FIELDS)


def _private_dir(path: Path) -> int:
    path.mkdir(mode=stat.S_IRWXU, parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    if os.fstat(fd).st_uid != os.geteuid():
        os.close(fd)
        raise ConfigError("the snapshot directory is not ours")
    os.fchmod(fd, stat.S_IRWXU)
    return fd


def _write_private(dfd: int, name: str, data: bytes) -> None:
    """Atomically: a temporary file in the same directory, 0600, then a rename over the name."""
    tmp = f".{name}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)


_NEXT = re.compile(r'<(https://api\.github\.com/[^>]+)>;\s*rel="next"')
_STAMP = re.compile(r"[^0-9TZ]")


def _get(run: Callable[..., Any], gh: str, path: str) -> tuple[str, Any]:
    done = run([gh, "api", "-i", path], capture_output=True, text=True, timeout=120)
    if done.returncode != 0:
        raise ApiError(f"the board read failed (exit {done.returncode}): {str(done.stderr)[:200]}")
    text = str(done.stdout)
    head, sep, body = text.partition("\r\n\r\n") if "\r\n\r\n" in text else text.partition("\n\n")
    if not sep:
        raise ApiError("the board read answered without a body")
    try:
        return head, bounded.loads(body, MAX_SNAPSHOT_BYTES)
    except (ValueError, RecursionError) as problem:
        raise ApiError(f"the board read answered something that is not JSON ({type(problem).__name__})") from problem


def read_board(
    project: str,
    target: Path,
    *,
    run: Callable[..., Any] = subprocess.run,
    gh: str,
    sleep: Callable[[float], None] = time.sleep,
    now: str,
    max_pages: int = MAX_PAGES,
) -> int:
    """Read every item of the project by REST into `target`, one page at a time. Saved only once the read is whole."""
    _, fields = _get(run, gh, f"{project}/fields?per_page=100")
    if not isinstance(fields, list):
        raise ApiError("the field listing is not a list")
    ids = {f["name"]: f["id"] for f in fields if isinstance(f, dict) and f.get("name") in WANTED_FIELDS}
    if set(ids) != set(WANTED_FIELDS):
        raise ApiError("the project is missing one of the fields this read needs")
    query = "&".join(f"fields[]={ids[name]}" for name in WANTED_FIELDS)
    path: str | None = f"{project}/items?per_page=100&{query}"
    items: list[Any] = []
    pages = 0
    while path is not None:
        if pages >= max_pages:
            raise ApiError(f"the board has more than {max_pages} pages; stopped, nothing saved")
        head, page = _get(run, gh, path)
        if not isinstance(page, list) or any(
            not isinstance(i, dict) or not isinstance(i.get("fields"), list) for i in page
        ):
            raise ApiError("a board page is not a list of items with their field values; nothing saved")
        items.extend(page)
        pages += 1
        link = _NEXT.search(head)
        path = link.group(1).removeprefix("https://api.github.com") if link else None
        if path is not None:
            sleep(PAUSE_SECONDS)
    dfd = _private_dir(target)
    try:
        if (target / ITEMS).exists():
            os.replace(ITEMS, f"items-{_STAMP.sub('', now)}.json", src_dir_fd=dfd, dst_dir_fd=dfd)
        _write_private(dfd, FIELDS, json.dumps(fields).encode())
        _write_private(dfd, ITEMS, json.dumps(items).encode())
        note = f"board snapshot read by REST at {now}: {len(items)} items in {pages} pages. Private data.\n"
        _write_private(dfd, "README", note.encode())
    finally:
        os.close(dfd)
    return len(items)


# the approved map


def load_map(path: Path, allowed: frozenset[str]) -> dict[str, str]:
    """An approved `{"owner/repo#N": "Kind"}` file. One bad entry refuses the whole file: nothing is half-approved."""
    try:
        raw = bounded.read_bounded(path, MAX_MAP_BYTES + 1)
    except OSError as problem:
        raise ConfigError(
            f"the map cannot be read ({type(problem).__name__}); a symlink or a special file is refused"
        ) from problem
    if len(raw) > MAX_MAP_BYTES:
        raise ConfigError(f"the map is larger than {MAX_MAP_BYTES} bytes")
    data = _json(raw, MAX_MAP_BYTES, "the map")
    if not isinstance(data, dict):
        raise ConfigError("the map must be an object of owner/repo#N to Kind")
    bad: list[str] = []
    for key, value in data.items():
        try:
            boardmap.parse_key(key)
        except ConfigError:
            bad.append("an entry whose key is not owner/repo#N")
            continue
        if not isinstance(value, str) or value not in allowed:
            bad.append(key)  # the card, never the value: a value may be anything
    if bad:
        shown = ", ".join(bad[:5]) + (f" and {len(bad) - 5} more" if len(bad) > 5 else "")
        raise ConfigError(f"the map is refused, nothing written: {len(bad)} entries are not a board Kind ({shown})")
    return {str(k): str(v) for k, v in data.items()}


# the writer


@dataclass
class Result:
    written: int = 0
    would_write: int = 0
    capped: bool = False
    skipped_closed: int = 0
    skipped_set: int = 0
    skipped_unknown: int = 0


def refresh_options(board: boardmap.BoardMap, transport: boardmap.Transport) -> bool:
    """Re-read the Kind field's option ids (one REST read). True when any id differs from the map's."""
    reply = transport("GET", f"{board.project}/fields?per_page=100", None)
    if not reply.ok:
        raise ApiError(f"the field re-read failed ({reply.error or 'no detail'})")
    try:
        data = bounded.loads(reply.body)
    except (ValueError, RecursionError) as problem:
        raise ApiError("the field re-read is not valid JSON") from problem
    try:
        _, fresh = kind_options(data)
    except ConfigError as problem:
        raise ApiError(f"the field re-read is not usable: {problem}") from problem
    changed = fresh != board.fields[KIND].options
    board.fields[KIND].options = fresh
    return changed


def apply_map(
    cards: Sequence[Card],
    mapping: Mapping[str, str],
    board: boardmap.BoardMap,
    transport: boardmap.Transport,
    *,
    say: Callable[[str], None],
    dry_run: bool,
    max_writes: int | None,
    journal: TextIO,
) -> Result:
    """Write each approved Kind to an open card whose Kind is empty. See the module text for the guarantees."""
    allowed = frozenset(board.fields[KIND].options)
    wrong = sorted(k for k, v in mapping.items() if v not in allowed)
    if wrong:
        raise ConfigError(f"{len(wrong)} map entries are not a board Kind; nothing written")
    by_key = {c.key: c for c in cards}
    result = Result()
    refreshed = False
    for key in sorted(mapping):
        card = by_key.get(key)
        if card is None:
            result.skipped_unknown += 1
            say(f"SKIP {key}: not on the board snapshot")
            continue
        if card.state != "open":
            result.skipped_closed += 1
            say(f"SKIP {key}: it is closed (phase 1 writes open cards only)")
            continue
        if card.kind is not None:
            result.skipped_set += 1
            say(f"SKIP {key}: it already has a Kind")
            continue
        if max_writes is not None and result.written + result.would_write >= max_writes:
            result.capped = True
            say(f"stopped at the write cap ({max_writes}), re-run to continue (it is idempotent)")
            break
        board.items[key] = card.item_id
        value = mapping[key]
        if dry_run:
            result.would_write += 1
            say(f"WOULD SET {key} Kind = {value}")
            continue
        try:
            boardmap.edit_card(board, transport, key, {KIND: value})
        except ApiError as problem:
            if isinstance(problem, UnknownOutcomeError) or refreshed:
                raise
            refreshed = True
            if not refresh_options(board, transport):
                raise  # the ids are what GitHub holds, so the refusal is not a stale option
            boardmap.edit_card(board, transport, key, {KIND: value})  # once: a second refusal stops the run
        result.written += 1
        journal.write(json.dumps({"key": key, "item": card.item_id, "field": KIND, "old": None, "new": value}) + "\n")
        journal.flush()
        say(f"SET {key} Kind = {value}")
    if not result.capped and result.written == 0 and result.would_write == 0:
        say("nothing to write: every card in the map is already done or skipped")
    return result


@contextlib.contextmanager
def open_journal(directory: Path) -> Iterator[TextIO]:
    """The append-only write journal inside the private snapshot directory."""
    dfd = _private_dir(directory)
    try:
        fd = os.open(JOURNAL, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    finally:
        os.close(dfd)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        yield handle


def write_new_file(path: Path, text: str) -> None:
    """A private (0600) new file; an existing file is never overwritten."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise ConfigError("that output file already exists; name a new one (nothing is overwritten)") from None
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
