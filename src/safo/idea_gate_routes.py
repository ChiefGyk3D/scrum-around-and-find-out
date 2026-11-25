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
    keywords = ["proxmox", "side project"]
    paths = ["infra", "ops/runner"]

Every class except `product` is ALWAYS private: the file cannot set a `private` key (it is refused, exit 2),
so it cannot turn off the public-repo refusal. It may change destinations, keywords and path hints only.

Normalisation before matching (text and terms alike): Unicode NFKC, case fold, every format character (zero-width
marks, soft hyphen, bidirectional marks) removed, and runs of whitespace, hyphens, underscores and dots read as one
space; then whole words only.
"""

from __future__ import annotations

import os
import re
import tomllib
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

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
TEXT_LIMIT = 1_048_576  # characters matched; more than this is unclassified (refused for a public target)
MATCHED_SHOWN = 20  # matched terms that are printed or recorded
CLASS_KEYS = frozenset({"repo", "keywords", "paths"})
SEPARATORS = re.compile(r"[\s._-]+")
WORD = re.compile(r"\w+")
MAX_WORDS = 4  # words in a keyword, segments in a path hint: bounds the work per position of the text
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
            long = len(term.split("/")) > MAX_WORDS
        else:
            ok = bool(KEYWORD.fullmatch(term)) and not term.endswith(" ")
            long = len(_words(_norm(term))) > MAX_WORDS
        if ok and long:
            raise _bad(f"class {name}: {key} entries have at most {MAX_WORDS} words or path segments")
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
        if "private" in spec:
            raise _bad(f"class {name}: private cannot be set; every class except product is always private")
        extra = set(spec) - CLASS_KEYS
        if extra:
            raise _bad(f"unknown key {sorted(extra)[0]!r} in class {name}")
        base = merged.get(name)
        repo = spec.get("repo", base.repo if base else "")
        if name == PRODUCT:
            if "repo" in spec:
                raise _bad("the product class takes no repo: its repo is the working repo")
        elif not (isinstance(repo, str) and is_repo(repo)):
            raise _bad(f"class {name} needs a repo written as owner/name")
        keywords = _terms(spec["keywords"], "keywords", name, path=False) if "keywords" in spec else None
        paths = _terms(spec["paths"], "paths", name, path=True) if "paths" in spec else None
        merged[name] = RouteClass(
            name,
            str(repo),
            name != PRODUCT,
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


def _fold(text: str) -> str:
    """NFKD, no format characters (zero-width, soft hyphen, bidi marks) and no combining marks (so an accent does not
    hide a word: o-acute folds to o), case folded."""
    plain = unicodedata.normalize("NFKD", text)
    return "".join(c for c in plain if unicodedata.category(c) not in ("Cf", "Mn")).casefold()


def _norm(text: str) -> str:
    return SEPARATORS.sub(" ", _fold(text)).strip()


HAZARDS = (
    "control characters",
    "invisible or format characters (zero-width, bidirectional, tag)",
    "combining marks or variation selectors",
    "private-use or unassigned characters",
    "letters or numerals outside accented Latin (Cyrillic, Greek, CJK, non-ASCII digits)",
)


def _hazard(char: str) -> int:
    """The index in HAZARDS of what makes this character able to hide a word, or -1 when it cannot."""
    kind = unicodedata.category(char)
    if kind == "Cc":
        return -1 if char in "\t\n\r" else 0
    if kind == "Cf":
        return 1
    if kind in ("Mn", "Me"):
        return 2
    if kind in ("Co", "Cn", "Cs"):
        return 3
    if kind[0] in "LN" and not char.isascii():
        parts = unicodedata.normalize("NFD", char)  # an ASCII letter and accents: e-acute, n-tilde, u-diaeresis
        accented = kind[0] == "L" and len(parts) > 1 and parts[0].isascii()
        return -1 if accented and all(unicodedata.category(m) == "Mn" for m in parts[1:]) else 4
    return -1


def unclassifiable(text: str) -> str:
    """ "" when the text is plain enough to classify, else the class of character that can hide a word from the matcher
    (never the character itself). After NFKC only ASCII, accented Latin letters, and symbols, punctuation and spaces
    pass. One pass over the distinct characters, so it is linear in the text."""
    found = [h for h in map(_hazard, set(unicodedata.normalize("NFKC", text))) if h >= 0]
    return HAZARDS[min(found)] if found else ""


def _words(text: str) -> tuple[str, ...]:
    return tuple(WORD.findall(text))


def _grams(tokens: Sequence[str], lengths: set[int], wanted: set[tuple[str, ...]]) -> set[tuple[str, ...]]:
    """Which of the `wanted` word sequences occur in `tokens`: one pass per distinct length, never one per term."""
    found: set[tuple[str, ...]] = set()
    for size in sorted(lengths):
        if size == 1:
            found |= {(t,) for t in set(tokens)} & wanted
            continue
        for at in range(len(tokens) - size + 1):
            gram = tuple(tokens[at : at + size])
            if gram in wanted:
                found.add(gram)
    return found


def matching(table: RouteTable, text: str) -> list[tuple[RouteClass, tuple[str, ...]]]:
    """Every class that matched, in table order, with what it matched. The whole text is scanned, in time linear in its
    size: it is normalised once and split into words once, and the keywords and path hints of every class are looked
    up as word sequences in sets. A keyword matches whole words; punctuation only separates them, so `side, project`
    and `c++` (the word `c`) match too, which can only add private matches, never lose one."""
    folded = _fold(text)
    plain = SEPARATORS.sub(" ", folded).strip()
    words = {c.name: [(_norm(k), _words(_norm(k))) for k in c.keywords] for c in table.classes}
    wanted_words = {w for ws in words.values() for _, w in ws if w}
    tokens = _words(plain)
    present = _grams(tokens, {len(w) for w in wanted_words}, wanted_words)
    wanted_paths = {tuple(h.split("/")) for c in table.classes for h in c.paths}
    segments = [
        t.strip("/").split("/")
        for t in (w.strip(PATH_STRIP).rstrip(".") for w in folded.split())
        if "/" in t or re.search(r"[a-z0-9]\.[a-z0-9]", t)
    ]
    here: set[tuple[str, ...]] = set()
    for seg in segments:
        here |= _grams(seg, {len(h) for h in wanted_paths}, wanted_paths)
    out: list[tuple[RouteClass, tuple[str, ...]]] = []
    for cls in table.classes:
        kw = dict.fromkeys(label for label, w in words[cls.name] if w and w in present)
        found = [f"keyword {k}" for k in kw] + [f"path {h}" for h in cls.paths if tuple(h.split("/")) in here]
        if found:
            out.append((cls, tuple(found)))
    return out


def classify(table: RouteTable, text: str) -> tuple[RouteClass, tuple[str, ...]] | None:
    """The winning class and what it matched, or None when nothing matched. Deterministic: see the module docstring."""
    ranked = [((-len(m), not c.private, i), c, m) for i, (c, m) in enumerate(matching(table, text))]
    return None if not ranked else min(ranked, key=lambda r: r[0])[1:]


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
