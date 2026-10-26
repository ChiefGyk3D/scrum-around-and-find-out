# SPDX-License-Identifier: Apache-2.0
"""The approval reader: is this issue an approval? (spec 3.2, "The approval test", lines 1-8 and 4b)

Two halves. `read_issues` fetches issues in batches of at most 50 aliased reads, with GraphQL variables and no
string interpolation, and reads every answer strictly: a null, absent, mistyped or inconsistent field makes that issue
`Unread`, never an empty list. `verdict` is pure: it returns `approved`, `open` (with the reason line) or `unknown`.

Rules this module holds to:

- An answer that cannot be told is `unknown`, never a pass. A crash inside `verdict` is `unknown` and names only the
  exception class.
- Identity is the immutable `databaseId`. A login is compared only for the wording of a line, and only after it passes
  the ASCII grammar; case is folded over A-Z only (`str.lower` turns the Kelvin sign into `k`).
- The issue must come from an owner, member or collaborator, and a change approval must name its entry (M13).
- No text from the issue reaches a line, except logins, which `emit` writes through `ctx.say` (escaped).

The REST cross-check (4b) is split: `verdict` takes a `CrossCheck`, and `cross_check_from_events` reads the REST
events strictly; the REST transport is a follow-up unit (the 400-line budget of #136).
"""

from __future__ import annotations

import datetime as dt
import enum
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from safo.errors import NotFoundError

JSON = dict[str, Any]
BATCH = 50
MAX_REFS = 1000
TRUSTED_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
KINDS = ("gate", "change", "freeze")
_NOUN = {
    "gate": "a gate is an issue",
    "change": "a change approval is an issue",
    "freeze": "the freeze record is an issue",
}
_TAIL = {"gate": "no card's gate order can be told", "change": "its approval cannot be told"}
_ACTORS = ("User", "Bot", "Mannequin", "Organization", "EnterpriseUserAccount")
_REASONS = ("COMPLETED", "NOT_PLANNED", "DUPLICATE")
_CLOSERS = ("PullRequest", "Commit", "ProjectV2")
_LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}")
_REPO = re.compile(r"([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100})")
_REF = re.compile(r"([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100})#([1-9][0-9]{0,9})")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_UPPER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")

_CLOSE_FIELDS = """createdAt stateReason
closer { __typename ... on PullRequest { number repository { nameWithOwner } } }
duplicateOf { id } actor { __typename login ... on User { databaseId } }"""
_ISSUE_FIELDS = f"""number state title body createdAt lastEditedAt authorAssociation repository {{ nameWithOwner }}
timelineItems: timelineItems(itemTypes: [CLOSED_EVENT], last: 1) {{
totalCount nodes {{ ... on ClosedEvent {{ {_CLOSE_FIELDS} }} }} }}
changes: timelineItems(itemTypes: [RENAMED_TITLE_EVENT, REOPENED_EVENT], last: 1) {{
totalCount nodes {{ __typename ... on RenamedTitleEvent {{ createdAt }} ... on ReopenedEvent {{ createdAt }} }} }}"""


class Executes(Protocol):
    def execute(self, document: str, variables: Mapping[str, Any] | None = None) -> JSON: ...


class _Malformed(Exception):
    """An answer is not what it must be. The message names the field, never the value."""


def fold(text: str) -> str | None:
    """A login folded over A-Z only, or None when it is not an ASCII login (so it can never equal one)."""
    return text.translate(_UPPER) if _LOGIN.fullmatch(text) else None


def _fold_ref(text: str) -> str:
    return text.translate(_UPPER)


def parse_ref(text: str) -> tuple[str, str, int] | None:
    """(owner, repo, number) for `owner/repo#N` in strict ASCII, else None. N fits a GraphQL Int."""
    match = _REF.fullmatch(text) if isinstance(text, str) else None
    if match is None or int(match.group(3)) > 2_147_483_647:
        return None
    return match.group(1), match.group(2), int(match.group(3))


@dataclass(frozen=True)
class Approver:
    login: str
    id: int

    def __post_init__(self) -> None:
        if not isinstance(self.login, str) or not _LOGIN.fullmatch(self.login):
            raise ValueError("approver login is not an ASCII GitHub login")
        if type(self.id) is not int or self.id < 1:
            raise ValueError("approver id must be a positive integer (the user's databaseId)")


@dataclass(frozen=True)
class Check:
    """What one approval issue must satisfy. `subject` is the text that opens each line, for example
    `GATE acme/gates#2 (Design gate)`; it comes from board.yaml, never from GitHub."""

    kind: str  # gate | change | freeze
    ref: str
    subject: str
    approvers: tuple[Approver, ...]
    entry: str | None = None  # change: the reference this approval must name (M13)
    action: str = "adding"  # change: `adding` or `removing`, for the M13 line
    frozen: dt.date | None = None  # change: created on or after it (UTC); freeze: closed on or before its end


@dataclass(frozen=True)
class Close:
    at: dt.datetime
    reason: str
    closer: str | None  # None is a manual close; otherwise `a pull request (owner/repo#N)` and the like
    duplicate: bool
    actor_type: str | None
    login: str | None
    db_id: int | None


@dataclass(frozen=True)
class Read:
    kind: str  # Issue | PullRequest
    repo: str
    number: int
    state: str = ""
    title: str = ""
    body: str = ""
    created_at: dt.datetime | None = None
    edited_at: dt.datetime | None = None
    association: str = ""
    close: Close | None = None
    changed: tuple[str, dt.datetime] | None = None  # the newest rename or reopen: (`renamed`|`reopened`, when)


@dataclass(frozen=True)
class Unread:
    kind: str  # notfound | error | malformed | invalid | truncated
    detail: str = ""


@dataclass(frozen=True)
class Verdict:
    state: str  # approved | open | unknown
    lines: tuple[str, ...] = ()
    closed_at: dt.datetime | None = None
    approver: str | None = None

    @property
    def approved(self) -> bool:
        return self.state == "approved"


# -- reading ---------------------------------------------------------------------------------------------------------


def _ts(value: Any) -> dt.datetime:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise _Malformed("a time is not YYYY-MM-DDTHH:MM:SSZ")
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)


def _obj(value: Any, what: str) -> JSON:
    if not isinstance(value, dict):
        raise _Malformed(f"{what} is not an object")
    return value


def _str(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise _Malformed(f"{what} is not a string")
    return value


def _need(node: JSON, key: str) -> Any:
    if key not in node:
        raise _Malformed(f"{key} is absent")
    return node[key]


def _repo_name(node: JSON) -> str:
    name = _str(_need(_obj(_need(node, "repository"), "repository"), "nameWithOwner"), "nameWithOwner")
    if not _REPO.fullmatch(name):
        raise _Malformed("nameWithOwner is not owner/name")
    return name


def _count(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise _Malformed("totalCount is not a count")
    return value


def _last_one(connection: JSON, what: str) -> list[Any]:
    """The nodes of a `last: 1` connection: one exactly when totalCount says any exist. Anything else is truncation
    or inconsistency, which cannot be told."""
    nodes = _need(connection, "nodes")
    if not isinstance(nodes, list) or len(nodes) != min(_count(_need(connection, "totalCount")), 1):
        raise _Malformed(f"{what}: totalCount disagrees with its nodes")
    return nodes


def _close(node: JSON) -> Close:
    reason = _need(node, "stateReason")
    if reason not in _REASONS:
        raise _Malformed("stateReason is not a close reason")
    closer_raw = _need(node, "closer")
    closer: str | None = None
    if closer_raw is not None:
        kind = _str(_need(_obj(closer_raw, "closer"), "__typename"), "closer type")
        if kind not in _CLOSERS:
            raise _Malformed("closer type is unknown")
        closer = {"Commit": "a commit", "ProjectV2": "a project workflow"}.get(kind, "")
        if kind == "PullRequest":
            number = _need(closer_raw, "number")
            if type(number) is not int or number < 1:
                raise _Malformed("closer number is not a number")
            closer = f"a pull request ({_repo_name(closer_raw)}#{number})"
    dup = _need(node, "duplicateOf")
    if dup is not None:
        _str(_need(_obj(dup, "duplicateOf"), "id"), "duplicateOf id")
    actor = _need(node, "actor")
    actor_type = login = None
    db_id: int | None = None
    if actor is not None:
        actor = _obj(actor, "actor")
        actor_type = _str(_need(actor, "__typename"), "actor type")
        if actor_type not in _ACTORS:
            raise _Malformed("actor type is unknown")
        login = _str(_need(actor, "login"), "actor login")
        if actor_type == "User":
            db_id = _need(actor, "databaseId")
            if type(db_id) is not int or db_id < 1:
                raise _Malformed("databaseId is not a positive integer")
    return Close(_ts(_need(node, "createdAt")), str(reason), closer, dup is not None, actor_type, login, db_id)


def parse_node(node: Any) -> Read:
    """One issue or pull request exactly as asked for, or _Malformed."""
    node = _obj(node, "the answer")
    kind = _need(node, "__typename")
    number = _need(node, "number")
    if kind not in ("Issue", "PullRequest") or type(number) is not int:
        raise _Malformed("the answer is not an issue or pull request")
    if kind == "PullRequest":
        return Read("PullRequest", _repo_name(node), number)
    state = _need(node, "state")
    if state not in ("OPEN", "CLOSED"):
        raise _Malformed("state is not OPEN or CLOSED")
    association = _str(_need(node, "authorAssociation"), "authorAssociation")
    if association not in {
        *TRUSTED_ASSOCIATIONS,
        "CONTRIBUTOR",
        "FIRST_TIMER",
        "FIRST_TIME_CONTRIBUTOR",
        "MANNEQUIN",
        "NONE",
    }:
        raise _Malformed("authorAssociation is not a known value")
    edited = _need(node, "lastEditedAt")
    timeline = _obj(_need(node, "timelineItems"), "timelineItems")
    nodes = _last_one(timeline, "timelineItems")
    changes = _last_one(_obj(_need(node, "changes"), "changes"), "changes")
    changed: tuple[str, dt.datetime] | None = None
    if changes:
        event = _obj(changes[0], "a rename or reopen event")
        word = {"RenamedTitleEvent": "renamed", "ReopenedEvent": "reopened"}.get(str(_need(event, "__typename")))
        if word is None:
            raise _Malformed("a change event is neither a rename nor a reopen")
        changed = (word, _ts(_need(event, "createdAt")))
    return Read(
        "Issue", _repo_name(node), number, str(state), _str(_need(node, "title"), "title"),
        _str(_need(node, "body"), "body"), _ts(_need(node, "createdAt")), None if edited is None else _ts(edited),
        association, _close(_obj(nodes[0], "a close event")) if nodes else None, changed,
    )  # fmt: skip


def _document(count: int) -> str:
    variables = ", ".join(f"$o{i}: String!, $n{i}: String!, $i{i}: Int!" for i in range(count))
    aliases = "\n".join(
        f"  r{i}: repository(owner: $o{i}, name: $n{i}) {{ issueOrPullRequest(number: $i{i}) {{ __typename\n"
        f"    ... on Issue {{ {_ISSUE_FIELDS} }}\n"
        f"    ... on PullRequest {{ number repository {{ nameWithOwner }} }} }} }}"
        for i in range(count)
    )
    return f"query ApprovalIssues({variables}) {{\n{aliases}\n}}"


def _read_batch(client: Executes, batch: list[tuple[str, str, int]]) -> list[Read | Unread]:
    variables: JSON = {}
    for i, (owner, name, number) in enumerate(batch):
        variables |= {f"o{i}": owner, f"n{i}": name, f"i{i}": number}
    aliases = {f"r{i}" for i in range(len(batch))}
    absent: set[str] = set()
    try:
        try:
            data: Any = client.execute(_document(len(batch)), variables)
        except NotFoundError as err:
            data = err.data
            for error in err.errors:
                path = error.get("path") if isinstance(error, dict) else None
                if not isinstance(path, list) or not path or path[0] not in aliases:
                    return [Unread("error", "NotFoundError")] * len(batch)  # an error that names no alias taints all
                absent.add(path[0])
    except Exception as err:
        return [Unread("error", type(err).__name__)] * len(batch)
    out: list[Read | Unread] = []
    for i in range(len(batch)):
        entry = data.get(f"r{i}") if isinstance(data, dict) else None
        if f"r{i}" in absent or (isinstance(entry, dict) and entry.get("issueOrPullRequest") is None):
            out.append(Unread("notfound"))
            continue
        try:
            out.append(parse_node(_obj(entry, "the alias")["issueOrPullRequest"]))
        except _Malformed:
            out.append(Unread("malformed", "malformed answer"))
        except Exception as err:
            out.append(Unread("error", type(err).__name__))
    return out


def read_issues(client: Executes, refs: Iterable[str]) -> dict[str, Read | Unread]:
    """Every reference given, mapped to what was read. Distinct references (case folded) are read once, at most 50
    to a query and MAX_REFS in all; the rest are `Unread("truncated")`, never dropped."""
    out: dict[str, Read | Unread] = {}
    wanted: dict[str, tuple[str, str, int]] = {}
    given: dict[str, list[str]] = {}
    for ref in refs:
        parts = parse_ref(ref)
        if parts is None:
            out[ref] = Unread("invalid", "not a valid reference")
            continue
        key = _fold_ref(ref)
        if key not in wanted and len(wanted) >= MAX_REFS:
            out[ref] = Unread("truncated", "more references than are read in one run")
            continue
        wanted.setdefault(key, parts)
        given.setdefault(key, []).append(ref)
    keys = list(wanted)
    for start in range(0, len(keys), BATCH):
        chunk = keys[start : start + BATCH]
        for key, result in zip(chunk, _read_batch(client, [wanted[k] for k in chunk]), strict=True):
            for ref in given[key]:
                out[ref] = result
    return out


class CrossCheck(enum.Enum):
    """The REST cross-check (4b). A type, not a boolean: it has no default and no truthiness, so no falsey value (0, "",
    [], False) can stand for "checked and manual". Only VERIFIED_MANUAL, from a complete matching REST read, passes."""

    VERIFIED_MANUAL = "verified_manual"
    VERIFIED_APP = "verified_app"
    UNCHECKED = "unchecked"

    def __bool__(self) -> bool:
        raise TypeError("a CrossCheck is not a boolean")


def cross_check_from_events(events: Any, close_at: dt.datetime) -> CrossCheck:
    """From the REST issue events: did a GitHub App perform the newest `closed` event (4b)? UNCHECKED when it cannot be
    told: no such event, a field missing or mistyped, or the event is not the close GraphQL showed (`close_at`)."""
    if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
        return CrossCheck.UNCHECKED
    try:
        closed = [(_ts(e.get("created_at")), e) for e in events if e.get("event") == "closed"]
    except _Malformed:
        return CrossCheck.UNCHECKED
    if not closed:
        return CrossCheck.UNCHECKED
    newest = max(at for at, _ in closed)
    flags = {
        ("performed_via_github_app" in e, e.get("performed_via_github_app") is not None)
        for at, e in closed
        if at == newest
    }
    if newest != close_at or len(flags) != 1 or not next(iter(flags))[0]:
        return CrossCheck.UNCHECKED
    app = next(e for at, e in closed if at == newest)["performed_via_github_app"]
    if app is None:
        return CrossCheck.VERIFIED_MANUAL
    return CrossCheck.VERIFIED_APP if isinstance(app, dict) else CrossCheck.UNCHECKED


# -- judging ---------------------------------------------------------------------------------------------------------


def verdict(chk: Check, read: Read | Unread, cross_check: CrossCheck) -> Verdict:
    """The approval test. `cross_check` is the 4b result (`cross_check_from_events`), required: anything but
    CrossCheck.VERIFIED_MANUAL cannot approve."""
    try:
        return _verdict(chk, read, cross_check)
    except Exception as err:  # a crash is never an approval and never "stale"; the class name only
        return Verdict("unknown", (f"UNKNOWN {chk.subject} could not be judged ({type(err).__name__})",))


def _verdict(chk: Check, read: Read | Unread, cross_check: CrossCheck) -> Verdict:
    s = chk.subject

    def unknown(text: str) -> Verdict:
        return Verdict("unknown", (f"UNKNOWN {s} {text}",))

    def refuse(text: str, prefix: str = "DRIFT   ") -> Verdict:
        return Verdict("open", (f"{prefix}{s} {text}; it counts as open",))

    parts = parse_ref(chk.ref)
    if chk.kind not in KINDS or parts is None:
        return unknown("is not configured as a gate, change or freeze issue")
    if chk.kind == "change" and (chk.frozen is None or chk.entry is None or parse_ref(chk.entry) is None):
        return unknown("is a change approval with no freeze date or entry to check")
    if chk.kind == "freeze" and chk.frozen is None:
        return unknown("is the freeze issue with no freeze date to check")
    if isinstance(read, Unread):
        if read.kind == "notfound":
            return unknown(f"cannot be read with this token, so {_TAIL.get(chk.kind, _TAIL['change'])}")
        return unknown(f"could not be read ({read.detail}), so {_TAIL.get(chk.kind, _TAIL['change'])}")
    if read.kind != "Issue":
        return Verdict("open", (f"DRIFT   {s} is a pull request; {_NOUN[chk.kind]}",))
    if _fold_ref(f"{read.repo}#{read.number}") != _fold_ref(chk.ref):
        return unknown(f"now answers as {read.repo}#{read.number}; update process.gates")
    if read.state != "CLOSED":
        return Verdict("open", (f"NOTE    {s} is not closed; it counts as open",))
    close = read.close
    if close is None or read.created_at is None:
        return unknown("is closed but has no close event; its approval cannot be told")
    created = read.created_at
    later = [t for t in (read.edited_at, read.changed[1] if read.changed else None) if t is not None]
    if close.at < created or any(t < created for t in later):  # an event before the issue existed cannot be true
        return unknown("has timestamps that cannot be true; its approval cannot be told")
    if close.reason == "NOT_PLANNED":
        return refuse("was closed as not planned")
    if close.reason == "DUPLICATE" or close.duplicate:
        return refuse("was closed as a duplicate")
    if close.closer is not None:
        return refuse(
            f"was closed through {close.closer}, not by hand".replace(
                "through a project workflow", "by a project workflow"
            )
        )
    if cross_check is CrossCheck.VERIFIED_APP:
        return refuse("was closed through a GitHub App")
    if cross_check is not CrossCheck.VERIFIED_MANUAL:  # UNCHECKED, or not a CrossCheck at all
        return unknown("close could not be cross-checked against the REST event, so it cannot be told")
    if read.association not in TRUSTED_ASSOCIATIONS:
        return refuse("was opened by an account that is not an owner, member or collaborator")
    note: tuple[str, ...] = ()
    login = close.login or ""
    if close.actor_type is None:
        return refuse("was closed by an account that no longer exists")
    if close.actor_type == "Bot":
        return refuse(f"was closed by a bot ({login}); an approval is a person's")
    if close.actor_type != "User":
        what = {
            "Mannequin": "an imported placeholder account",
            "Organization": "an organization account",
            "EnterpriseUserAccount": "an enterprise-managed account, which process.approvers cannot name yet",
        }[close.actor_type]
        return refuse(f"was closed by {what}")
    match = next((a for a in chk.approvers if a.id == close.db_id), None)
    if match is None:
        mine = fold(login)
        if mine is not None and any(fold(a.login) == mine for a in chk.approvers):
            return refuse(f"was closed by @{login}, whose id is not the approver's id for that login")
        return refuse(f"was closed by {login}, who is not in process.approvers")
    if fold(login) != fold(match.login) or fold(login) is None:
        note = (f"NOTE    {s} closed by @{login}, who is approver @{match.login} (renamed)",)
    # timestamps have one-second resolution, so an edit in the same second as the close cannot be ordered: refuse it
    if read.edited_at is not None and read.edited_at >= close.at:
        return refuse(f"was edited on {read.edited_at.date()} after it was approved on {close.at.date()}")
    if read.changed is not None and read.changed[1] >= close.at:
        word, when = read.changed
        return refuse(f"was {word} on {when.date()} after it was approved on {close.at.date()}")
    if chk.frozen is not None:
        start = dt.datetime.combine(chk.frozen, dt.time(), tzinfo=dt.UTC)
        if chk.kind == "change" and read.created_at < start:
            return refuse(f"was created before the baseline froze on {chk.frozen}")
        if chk.kind == "freeze" and close.at >= start + dt.timedelta(days=1):
            return refuse(f"was closed after the baseline froze on {chk.frozen}")
    if chk.kind == "change":
        found = _entry_state(read.body, str(chk.entry))
        if found.startswith("structure:"):
            return unknown(
                f"has Markdown structure in its body ({found[10:]}); an approval body must be plain paragraphs, "
                "so its entry cannot be told"
            )
        if found == "unusual":
            return unknown(
                "has unusual characters in its body; an approval body must be printable ASCII text, "
                "so its entry cannot be told"
            )
        if found == "html":
            return unknown("has raw HTML in its body; an approval body must be plain text, so its entry cannot be told")
        if found != "named":
            return Verdict(
                "open",
                (
                    f"DRIFT   SCOPE the change {chk.action} {chk.entry} cites {chk.ref}, which does not mention "
                    f"{chk.entry} on its own `Entry:` line; the approval is not for this change",
                ),
            )
    return Verdict("approved", note, close.at, login)


_ENTRY_LINE = re.compile(r"Entry: ([A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}#[1-9][0-9]{0,9})")
_HTML = re.compile(r"<[A-Za-z/!?]")
# The approval body grammar is deliberately narrow: plain paragraphs only. Rather than model CommonMark containers,
# fences and multi-line constructs (where a parser differential would hide or show a line), any Markdown structure
# anywhere in the body makes the answer UNKNOWN. Checked per line, in this order; the first hit names the class.
_STRUCTURE = (
    ("fence", re.compile(r".*(```|~~~)")),
    ("thematic break", re.compile(r" {0,3}([-*_])([ \t]*\1){2,}[ \t]*")),
    ("heading", re.compile(r" {0,3}(#{1,6}([ \t]|$)|(=+|-+)[ \t]*$)")),
    ("list or quote", re.compile(r"[ \t]*>|\s{0,3}([-*+]|[0-9]{1,9}[.)])([ \t]|$)")),
    ("table", re.compile(r".*\|")),
    ("brackets", re.compile(r".*[\[\]]")),  # links, images, reference and footnote definitions all need one
    ("indented code", re.compile(r"( {0,3}\t| {4})[ \t]*\S")),
    ("line continuation", re.compile(r".*\\$")),
)


_BLANK = re.compile(r"[ \t]*")  # CommonMark's blank line; never str.strip(), which also strips NBSP and the like


def _lines(body: str) -> list[str] | None:
    """The lines of `body`, or None when it holds anything but printable ASCII, tab, and \\n or \\r\\n line ends
    (so no NBSP, bidi mark, zero-width character, NEL, LS, PS, VT, FF or lone CR can reach the matchers)."""
    text = body.replace("\r\n", "\n")
    if not all(c in "\t\n" or " " <= c <= "~" for c in text):
        return None
    return text.split("\n")


def body_problem(body: str) -> str | None:
    """`unusual` (a character outside printable ASCII), `html`, or the class of the first Markdown structure found in
    `body` (never its content), or None when it is plain paragraphs. Raw HTML counts anywhere, even inside code."""
    lines = _lines(body)
    if lines is None:
        return "unusual"
    if any(_HTML.search(line) for line in lines):
        return "html"
    for line in lines:
        for name, pattern in _STRUCTURE:
            if pattern.match(line):
                return name
    return None


def _folded(parts: tuple[str, str, int]) -> tuple[str, str, int]:
    return parts[0].translate(_UPPER), parts[1].translate(_UPPER), parts[2]


def _entry_state(body: str, entry: str) -> str:
    """`html` or `structure:<class>` when the body is not plain paragraphs (see `body_problem`); else `named` when
    exactly one line starts `Entry:` at column 0, it stands alone as a paragraph (a blank line or the start of the body
    before it, a blank line or the end after it) and is exactly `Entry: owner/repo#N` for `entry`; else `missing`.
    The repository is compared after the ASCII-only fold, the number as an integer."""
    problem = body_problem(body)
    if problem in ("html", "unusual"):
        return problem
    if problem:
        return f"structure:{problem}"
    lines = _lines(body) or []
    at = [i for i, line in enumerate(lines) if line.startswith("Entry:")]
    if len(at) != 1:
        return "missing"
    i = at[0]
    alone = (i == 0 or bool(_BLANK.fullmatch(lines[i - 1]))) and (
        i == len(lines) - 1 or bool(_BLANK.fullmatch(lines[i + 1]))
    )
    match = _ENTRY_LINE.fullmatch(lines[i]) if alone else None
    got = parse_ref(match.group(1)) if match else None
    want = parse_ref(entry)
    if got is None or want is None:
        return "missing"
    return "named" if _folded(got) == _folded(want) else "missing"


class Says(Protocol):
    def say(self, line: str = "") -> None: ...


def emit(ctx: Says, v: Verdict) -> None:
    """Write the lines through `ctx.say`, which escapes them: a login may hold `::` and control characters."""
    for line in v.lines:
        ctx.say(line)
