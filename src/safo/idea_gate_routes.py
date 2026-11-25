# SPDX-License-Identifier: Apache-2.0
"""The routing table of `safo-file` (issue #455): which repository a piece of work belongs in, decided by code.

Nothing here talks to a model or to the network. The table is DATA: built-in defaults, optionally replaced class by
class from `~/.config/safo-file/routes.toml` (its own directory, never under `~/.config/safo`, which holds guard files).

Classes and their default destinations: `product` (the working repo when it is a tracked product repo), `homelab`
(ChiefGyk3D/homelab-ops), `ai-tooling` (ChiefGyk3D/AI-Shit), `research` (ChiefGyk3D/research-notes) and `tangent`
(ChiefGyk3D/workbench, which is also the fallback when nothing matches and the default parking-lot repo).

Matching is by keyword (a whole word or phrase, case-insensitive) and by path hint (a whole path segment of a
path-like word, such as `infra/main.tf`). A class scores one point per distinct keyword and per distinct hint it
matched; the highest score wins. A tie goes to a private class over a public one, then to the class that comes first
in the table (the built-in order is product, homelab, ai-tooling, research, tangent; a class the file adds comes after
them, in file order). No match at all is "undecided": the destination is then only the default.

Routes file rules (the same trust rules as the ledger): a regular file owned by you, not writable by group or others, no
symbolic link at any component, every directory above it owned by you or root and closed to others, at most 64 KB,
valid UTF-8 and TOML, only the keys below. An absent file means the defaults; anything else wrong is an error.

    [classes.homelab]            # a built-in class: the keys given REPLACE the default value
    repo = "owner/name"          # required for a new class; not allowed for `product`
    private = true               # default true; `product` is never private
    keywords = ["proxmox", "side project"]
    paths = ["infra", "ops/runner"]
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import os
import re
import tomllib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from safo import idea_gate_io as gio
from safo.errors import SafoError
from safo.trust import read_trusted_regular_file

OWNER = re.compile(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*")  # GitHub: no leading, trailing or doubled hyphen
NAME = re.compile(r"[A-Za-z0-9._-]{1,100}")
CLASS_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}")
KEYWORD = re.compile(r"[a-z0-9][a-z0-9 ._+-]{0,63}")
HINT_SEGMENT = re.compile(r"[a-z0-9._-]{1,64}")

PRODUCT = "product"
FALLBACK = "tangent"
ROUTES_LIMIT = 65_536
MAX_CLASSES = 32
MAX_TERMS = 200
TEXT_LIMIT = 20_000  # characters of a description that are matched
MATCHED_SHOWN = 20  # matched terms that are printed or recorded
VISIBILITY_TTL = 300  # seconds a cached repo visibility answer is believed
VISIBILITY_LIMIT = 1_048_576
CLASS_KEYS = frozenset({"repo", "private", "keywords", "paths"})
PATH_STRIP = "\"'()[]{}<>,;:!?"


def is_repo(name: str) -> bool:
    owner, sep, repo = name.partition("/")
    return (
        bool(sep)
        and len(owner) <= 39
        and bool(OWNER.fullmatch(owner))
        and bool(NAME.fullmatch(repo))
        and (repo not in (".", ".."))
    )


@dataclass(frozen=True)
class RouteClass:
    name: str
    repo: str  # "" for the product class: its repo is the working repo
    private: bool
    keywords: tuple[str, ...]
    paths: tuple[str, ...]


@dataclass(frozen=True)
class RouteTable:
    classes: tuple[RouteClass, ...]

    def get(self, name: str) -> RouteClass | None:
        return next((c for c in self.classes if c.name == name), None)

    @property
    def fallback(self) -> RouteClass:
        found = self.get(FALLBACK)
        if found is None:  # cannot happen for a table built here; a hand-built one is a bug
            raise SafoError(f"the routing table has no {FALLBACK} class")
        return found


def _t(text: str) -> tuple[str, ...]:
    return tuple(text.split(","))


DEFAULTS = (
    RouteClass(
        PRODUCT,
        "",
        False,
        _t(
            "bug,bugfix,feature,refactor,parser,endpoint,api,cli,ui,unit test,tests,regression,crash,function,"
            "library,code,compile"
        ),
        _t("src,tests,lib,cmd,pkg"),
    ),
    RouteClass(
        "homelab",
        "ChiefGyk3D/homelab-ops",
        True,
        _t(
            "homelab,infra,infrastructure,runner,runners,ops,ansible,terraform,opentofu,proxmox,vlan,firewall,"
            "pfsense,dns,nas,vm,vms,backup,backups,systemd,router,grafana,monitoring,kubernetes,k8s,docker host"
        ),
        _t("infra,ansible,terraform,tofu,proxmox,systemd,etc"),
    ),
    RouteClass(
        "ai-tooling",
        "ChiefGyk3D/AI-Shit",
        True,
        _t(
            "claude,codex,copilot,mcp,skill,skills,prompt,prompts,ollama,llm,dotfiles,claude.md,agents.md,"
            "settings.json,slash command,subagent,subagents"
        ),
        _t(".claude,.codex,dotfiles,skills,prompts"),
    ),
    RouteClass(
        "research",
        "ChiefGyk3D/research-notes",
        True,
        _t(
            "research,evaluate,evaluation,evaluating,compare,comparison,benchmark,benchmarks,survey,paper,papers,"
            "spike,investigate,investigation,study,prior art,tradeoff,tradeoffs,literature"
        ),
        _t("research,notes,papers"),
    ),
    RouteClass(
        FALLBACK,
        "ChiefGyk3D/workbench",
        True,
        _t(
            "tangent,tangents,random,experiment,experiments,idea,ideas,tinker,side project,someday,maybe,what if,"
            "curiosity,playground"
        ),
        _t("scratch,playground,sandbox"),
    ),
)


def default_table() -> RouteTable:
    return RouteTable(DEFAULTS)


# ---- the routes file ---------------------------------------------------------------------------------------------


def routes_path(home: str) -> Path:
    return Path(home) / ".config" / "safo-file" / "routes.toml"


def _bad(why: str) -> SafoError:
    return SafoError(f"the routes file: {why}")


def _terms(value: object, key: str, name: str, *, path: bool) -> tuple[str, ...]:
    if not (isinstance(value, list) and len(value) <= MAX_TERMS):
        raise _bad(f"class {name}: {key} must be a list of at most {MAX_TERMS} strings")
    seen: dict[str, None] = {}
    for item in value:
        if not isinstance(item, str):
            raise _bad(f"class {name}: {key} must be a list of strings")
        term = " ".join(item.lower().split())
        if path:
            term = term.strip("/")
            ok = bool(term) and all(HINT_SEGMENT.fullmatch(s) and s not in (".", "..") for s in term.split("/"))
        else:
            ok = bool(KEYWORD.fullmatch(term)) and not term.endswith(" ")
        if not ok:
            raise _bad(f"class {name}: {key} has an entry that is empty or uses characters that are not allowed")
        seen[term] = None
    return tuple(seen)


def _merge(table: dict[str, object]) -> RouteTable:
    unknown = set(table) - {"classes"}
    if unknown:
        raise _bad(f"unknown key {sorted(unknown)[0]!r}")
    given = table.get("classes", {})
    if not isinstance(given, dict) or len(given) > MAX_CLASSES:
        raise _bad(f"classes must be a table of at most {MAX_CLASSES} classes")
    merged = {c.name: c for c in DEFAULTS}
    for name, spec in given.items():
        if not CLASS_NAME.fullmatch(name):
            raise _bad("a class name is lowercase letters, digits and hyphens, starting with a letter")
        if not isinstance(spec, dict):
            raise _bad(f"class {name} must be a table")
        extra = set(spec) - CLASS_KEYS
        if extra:
            raise _bad(f"unknown key {sorted(extra)[0]!r} in class {name}")
        base = merged.get(name)
        repo = spec.get("repo", base.repo if base else "")
        private = spec.get("private", base.private if base else True)
        if not isinstance(private, bool):
            raise _bad(f"class {name}: private must be true or false")
        if name == PRODUCT:
            if "repo" in spec or "private" in spec:
                raise _bad("the product class takes no repo and is never private: its repo is the working repo")
        elif not (isinstance(repo, str) and is_repo(repo)):
            raise _bad(f"class {name} needs a repo written as owner/name")
        keywords = _terms(spec["keywords"], "keywords", name, path=False) if "keywords" in spec else None
        paths = _terms(spec["paths"], "paths", name, path=True) if "paths" in spec else None
        merged[name] = RouteClass(
            name,
            str(repo),
            private,
            keywords if keywords is not None else (base.keywords if base else ()),
            paths if paths is not None else (base.paths if base else ()),
        )
    return RouteTable(tuple(merged.values()))


def load_table(home: str) -> RouteTable:
    """The table for this HOME: the defaults when the file is absent, else the validated file. Never the environment."""
    path = routes_path(home)
    try:
        os.lstat(path)
    except OSError:
        return default_table()
    try:
        raw = read_trusted_regular_file(path, ROUTES_LIMIT)
    except SafoError as problem:
        raise _bad(str(problem)) from None
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise _bad("not valid UTF-8") from None
    except tomllib.TOMLDecodeError as problem:
        raise _bad(f"not valid TOML ({problem})") from None
    return _merge(data)


# ---- matching ----------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    cls: RouteClass
    repo: str  # the destination
    how: str  # "explicit", "matched" or "default"
    matched: tuple[str, ...]
    reason: str
    decided: bool


def _norm(text: str) -> str:
    return " ".join(text[:TEXT_LIMIT].lower().split())


def _word_hits(text: str, terms: Sequence[str]) -> list[str]:
    return [t for t in terms if re.search(rf"(?<![a-z0-9]){re.escape(t)}(?![a-z0-9])", text)]


def _path_hits(text: str, hints: Sequence[str]) -> list[str]:
    tokens = [t.strip(PATH_STRIP).rstrip(".") for t in text.split()]
    shaped = [f"/{t.strip('/')}/" for t in tokens if "/" in t or re.search(r"[a-z0-9]\.[a-z0-9]", t)]
    return [h for h in hints if any(f"/{h}/" in s for s in shaped)]


def classify(table: RouteTable, text: str) -> tuple[RouteClass, tuple[str, ...]] | None:
    """The winning class and what it matched, or None when nothing matched. Deterministic: see the module docstring."""
    plain = _norm(text)
    best: tuple[tuple[int, bool, int], RouteClass, tuple[str, ...]] | None = None
    for index, cls in enumerate(table.classes):
        found = [f"keyword {k}" for k in _word_hits(plain, cls.keywords)]
        found += [f"path {p}" for p in _path_hits(plain, cls.paths)]
        if not found:
            continue
        rank = (-len(found), not cls.private, index)
        if best is None or rank < best[0]:
            best = (rank, cls, tuple(found))
    return None if best is None else (best[1], best[2])


def find_class(table: RouteTable, name: str) -> RouteClass:
    found = table.get(name)
    if found is None:
        known = ", ".join(c.name for c in table.classes)
        raise SafoError(f"unknown class {name!r}; the table has: {known}")
    return found


def decide(
    table: RouteTable,
    text: str,
    explicit: str | None,
    working: str,
    tracked: Callable[[], Sequence[str]],
) -> Decision:
    """Where this work goes. `tracked` is only called when the product class needs it."""
    matched: tuple[str, ...] = ()
    if explicit:
        cls, how, why = find_class(table, explicit), "explicit", f"explicit class {explicit}"
    else:
        hit = classify(table, text)
        if hit is None:
            fb = table.fallback
            return Decision(
                fb, fb.repo, "default", (), "no keyword or path hint matched; pass --class to decide", False
            )
        cls, matched = hit
        how, why = "matched", "matched " + ", ".join(matched[:MATCHED_SHOWN])
    if cls.name != PRODUCT:
        return Decision(cls, cls.repo, how, matched[:MATCHED_SHOWN], why, True)
    if working.lower() in {t.lower() for t in tracked()}:
        return Decision(cls, working, how, matched[:MATCHED_SHOWN], why, True)
    fb = table.fallback
    return Decision(
        cls, fb.repo, "default", matched[:MATCHED_SHOWN], f"{why}, but {working} is not a tracked product repo", False
    )


# ---- repository visibility, cached beside the ledger -------------------------------------------------------------


def _fresh_answer(path: Path, key: str, now: dt.datetime) -> bool | None:
    """The newest cached answer for `key` that is younger than the TTL, or None. An untrusted, unreadable, oversize or
    corrupt cache is ignored (asking again is always safe); it is never believed."""
    try:
        os.lstat(path)
        text = read_trusted_regular_file(path, VISIBILITY_LIMIT).decode("utf-8", "replace")
    except (OSError, SafoError):
        return None
    answer: bool | None = None
    for raw in text.splitlines():
        try:
            e = json.loads(raw)
            when = dt.datetime.fromisoformat(e["ts"])
            ok = (
                e["repo"] == key
                and isinstance(e["public"], bool)
                and 0 <= (now - when).total_seconds() <= VISIBILITY_TTL
            )
        except (ValueError, KeyError, TypeError):
            continue
        answer = e["public"] if ok else answer
    return answer


def cached_visibility(path: Path, repo: str, now: dt.datetime, fetch: Callable[[str], bool]) -> bool:
    """True when `repo` is public. `fetch` asks GitHub and raises a SafoError on any doubt (the caller fails closed).
    The answer is appended to `path` (next to the ledger, same trust rules) and believed for VISIBILITY_TTL seconds."""
    key = repo.lower()
    hit = _fresh_answer(path, key, now)
    if hit is not None:
        return hit
    public = fetch(repo)
    with contextlib.suppress(OSError, SafoError, TimeoutError):  # the cache is an optimization, not an answer
        if not path.exists() or path.stat().st_size < VISIBILITY_LIMIT // 2:  # a cache grown past this is left alone
            fd = gio.open_ledger(path)
            try:
                line = json.dumps({"repo": key, "public": public, "ts": now.isoformat()}) + "\n"
                gio.write_all(fd, line.encode())
            finally:
                os.close(fd)
    return public
