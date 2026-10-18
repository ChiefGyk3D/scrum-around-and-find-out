#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write a flat GitHub wiki tree that mirrors docs/.

scripts/gen_wiki.py --out DIR [--commit SHA]

docs/home.md becomes Home.md and every other docs/*.md becomes a Title-Case-Hyphenated page (board-yaml.md becomes
Board-yaml.md). docs/superpowers/ is not published. Relative links between pages are rewritten to wiki links; a link
to a docs file that is not a page is an error, and a link out of docs/ points at the file on GitHub. The output is
deterministic: the same docs and commit always write the same bytes.

--out must be inside the repository and either not exist, be empty, or hold exactly the files a previous run wrote.
A run records what it wrote in .<out name>.gen_wiki beside the tree (not inside it, because the publish step copies
the whole tree), and only those files are replaced; any other file, or no record, makes the run refuse.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import os
import posixpath
import re
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/ChiefGyk3D/scrum-around-and-find-out"
OUT_NAME = "wiki-out"

_SCHEME = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*:|//)")
_REFDEF = re.compile(r"[ ]*(?:(?:>|[-*+]|\d{1,9}[.)])[ ]*)*\[(?:[^\]\\]|\\.)+\]:[ \t]*")
_ATTR = re.compile(
    r"(?<=[\s<\"'])((?:xlink:)?(?:href|src|srcset|poster|formaction|action))[ \t]*=[ \t]*", re.IGNORECASE
)
_FENCE = re.compile(r" {0,3}(`{3,}|~{3,})(.*)")
MAX_LINE = 20_000
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.md$")
_LABEL_META = re.compile(r"([\\\[\]<>`|*_&])")


class WikiError(Exception):
    """A problem with the docs or the arguments; the message says what to fix."""


def page_name(filename: str) -> str:
    stem = filename.removesuffix(".md")
    if stem == "home":
        return "Home"
    return stem[:1].upper() + stem[1:]


def _refuse_symlinks(docs: Path) -> None:
    """No symbolic link anywhere under docs/ (or docs/ itself): a link could publish a file from outside it."""
    if docs.is_symlink():
        raise WikiError(f"{docs} is a symbolic link; refusing to read through it")
    for here, dirs, names in os.walk(docs, followlinks=False):
        for name in sorted(dirs + names):
            path = Path(here) / name
            if path.is_symlink():
                raise WikiError(f"{path.relative_to(docs.parent)} is a symbolic link; refusing to publish through it")


def _after_listing() -> None:
    """Runs between listing docs/ and reading it; the tests swap paths here."""


def _read_docs(docs: Path) -> dict[str, str]:
    """Map each docs/*.md filename to its text, reading by descriptor so a swapped path is never followed."""
    _refuse_symlinks(docs)
    try:
        root_fd = os.open(docs.parent, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as err:
        raise WikiError(f"cannot read the repository {docs.parent}: {err.strerror or err}") from err
    try:
        try:
            docs_fd = _open_dir(docs.name, root_fd)
        except FileNotFoundError as err:
            raise WikiError(f"cannot read the docs directory {docs}: {err.strerror or err}") from err
        try:
            return _read_pages(docs, docs_fd)
        finally:
            os.close(docs_fd)
    finally:
        os.close(root_fd)


def _read_pages(docs: Path, docs_fd: int) -> dict[str, str]:
    ident = os.fstat(docs_fd)
    names = []
    for name in sorted(os.listdir(docs_fd)):
        found = _lstat(name, docs_fd)
        if found is None or not name.endswith(".md"):
            continue
        if stat.S_ISLNK(found.st_mode):
            raise WikiError(f"docs/{name} is a symbolic link; refusing to publish through it")
        if stat.S_ISREG(found.st_mode):
            names.append(name)
    if not names:
        raise WikiError(f"no docs/*.md pages in {docs}")
    _after_listing()
    texts: dict[str, str] = {}
    for name in names:
        raw = _read(name, docs_fd)
        if raw is None:
            raise WikiError(f"cannot read docs/{name}: it disappeared")
        try:
            texts[name] = raw.decode("utf-8")
        except UnicodeDecodeError as err:
            raise WikiError(f"cannot read docs/{name}: {err}") from err
    try:
        now = os.stat(docs)
        same = docs.resolve() == docs and (now.st_dev, now.st_ino) == (ident.st_dev, ident.st_ino)
    except OSError:
        same = False
    if not same:
        raise WikiError(f"{docs} changed while gen_wiki was running (a path was swapped); refusing")
    if "home.md" not in texts:
        raise WikiError("docs/home.md is missing: it becomes the wiki's Home page")
    return texts


def _resolve(target: str, source: str, pages: dict[str, str], root: Path, blob: str, image: bool) -> str:
    """The wiki destination for a link target written in docs/<source>, or a clear error."""
    where = f"docs/{source}: link '{target}'"
    if target == "":
        raise WikiError(f"{where} has an empty target")
    if target.startswith("#") or _SCHEME.match(target):
        return target
    if "\\" in target or "&" in target or "\x00" in target:
        raise WikiError(
            f"{where} uses an escape or entity, which this generator does not support; write the plain path"
        )
    path, hash_, frag = target.partition("#")
    suffix = hash_ + frag
    joined = posixpath.normpath(posixpath.join("docs", path))
    if joined.startswith("..") or joined == "docs":
        raise WikiError(f"{where} leaves the repository or points at docs/ itself")
    name = joined[len("docs/") :] if joined.startswith("docs/") else None
    if name is not None and "/" not in name and name in pages:
        if image:
            raise WikiError(f"{where} is an image but points at the page docs/{name}")
        return pages[name] + suffix
    if joined.endswith(".md") and (name is not None):
        raise WikiError(f"{where} points at docs/{name}, which is not a wiki page")
    if name is not None and "/" in name and image is False:
        raise WikiError(f"{where} points into {joined}, which is not published")
    full = root / joined
    if not full.exists():
        raise WikiError(f"{where} points at {joined}, which does not exist")
    if full.is_symlink() or root.resolve() not in full.resolve().parents:
        raise WikiError(f"{where} points at {joined}, which is a symbolic link or resolves outside the repository")
    return f"{blob}/{quote(joined)}{'?raw=true' if image else ''}{suffix}"


class _Ctx:
    def __init__(self, source: str, pages: dict[str, str], root: Path, blob: str) -> None:
        self.source, self.pages, self.root, self.blob = source, pages, root, blob

    def fix(self, target: str, image: bool) -> str:
        return _resolve(target, self.source, self.pages, self.root, self.blob, image)

    def fail(self, why: str) -> WikiError:
        return WikiError(f"docs/{self.source}: {why}")


def _parse_destination(line: str, start: int, ctx: _Ctx) -> tuple[int, int, str, int]:
    """Parse a link destination at `start`: (span start, span end, target, index after it)."""
    j = start
    while j < len(line) and line[j] in " \t":
        j += 1
    if j < len(line) and line[j] == "<":
        k = line.find(">", j + 1)
        if k < 0:
            raise ctx.fail(f"an unclosed <destination> in: {line.strip()[:80]}")
        return j, k + 1, line[j + 1 : k], k + 1
    depth = 0
    k = j
    while k < len(line) and line[k] not in " \t":
        if line[k] == "(":
            depth += 1
        elif line[k] == ")":
            if depth == 0:
                break
            depth -= 1
        k += 1
    return j, k, line[j:k], k


def _skip_title(line: str, i: int, ctx: _Ctx) -> int:
    """Skip optional whitespace and a quoted title; return the index after them."""
    while i < len(line) and line[i] in " \t":
        i += 1
    if i >= len(line):
        return i
    if line[i] in "\"'(":
        end = ")" if line[i] == "(" else line[i]
        k = i + 1
        while k < len(line) and line[k] != end:
            k += 2 if line[k] == "\\" else 1
        if k >= len(line):
            raise ctx.fail(f"an unterminated link title in: {line.strip()[:80]}")
        i = k + 1
        while i < len(line) and line[i] in " \t":
            i += 1
    return i


def _mask_code(line: str) -> str:
    """Replace every code span (CommonMark: a run of N backticks to the next run of exactly N) with NULs.

    One pass finds the backtick runs, one pass pairs each run with the next run of the same length, so the whole
    line costs O(n). An unmatched run is literal text, and a backtick after an odd number of backslashes is escaped.
    """
    runs: list[tuple[int, int]] = []  # (start, length)
    i, n = 0, len(line)
    while i < n:
        if line[i] != "`":
            i += 1
            continue
        j = i
        while j < n and line[j] == "`":
            j += 1
        start = i + 1 if _escaped(line, i) else i
        if j > start:
            runs.append((start, j - start))
        i = j
    following: list[int] = [-1] * len(runs)  # index of the next run with the same length
    latest: dict[int, int] = {}
    for k in range(len(runs) - 1, -1, -1):
        following[k] = latest.get(runs[k][1], -1)
        latest[runs[k][1]] = k
    chars = list(line)
    k = 0
    while k < len(runs):
        close = following[k]
        if close < 0:
            k += 1
            continue
        for x in range(runs[k][0], runs[close][0] + runs[close][1]):
            chars[x] = "\x00"
        k = close + 1
    return "".join(chars)


def _escaped(text: str, i: int) -> bool:
    """True if the character at `i` is preceded by an odd number of backslashes."""
    n = 0
    while i - n - 1 >= 0 and text[i - n - 1] == "\\":
        n += 1
    return n % 2 == 1


def _bracket_openers(mask: str) -> dict[int, int]:
    """Map the index of each unescaped `]` to the index of the unescaped `[` it closes, in one forward pass."""
    stack: list[int] = []
    found: dict[int, int] = {}
    escaped = False
    for i, ch in enumerate(mask):
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == "[":
            stack.append(i)
        elif ch == "]" and stack:
            found[i] = stack.pop()
    return found


def _rewrite_line(line: str, ctx: _Ctx) -> str:
    mask = _mask_code(line)
    edits: list[tuple[int, int, str]] = []
    definition = _REFDEF.match(mask)
    if definition:
        d0, d1, target, after = _parse_destination(line, definition.end(), ctx)
        if _skip_title(line, after, ctx) != len(line.rstrip()):
            raise ctx.fail(f"cannot read the reference definition: {line.strip()[:80]}")
        edits.append((d0, d1, ctx.fix(target, False)))
    else:
        openers = _bracket_openers(mask)
        pos = 0
        for at in sorted(openers):
            if at < pos or mask[at + 1 : at + 2] != "(":
                continue
            opener = openers[at]
            image = opener > 0 and mask[opener - 1] == "!" and not _escaped(mask, opener - 1)
            d0, d1, target, after = _parse_destination(line, at + 2, ctx)
            end = _skip_title(line, after, ctx)
            if end >= len(line) or line[end] != ")":
                raise ctx.fail(
                    f"a link that is not closed on its line (multi-line links are not supported): {line.strip()[:80]}"
                )
            edits.append((d0, d1, ctx.fix(target, image)))
            pos = end + 1
    for attr in _ATTR.finditer(mask):
        if any(a <= attr.start() < b for a, b, _ in edits):
            continue
        name = attr.group(1).lower()
        value = line[attr.end() :]
        quote_char = value[:1]
        if name not in ("href", "src") or quote_char not in ("'", '"'):
            raise ctx.fail(
                f"HTML attribute {name}= is not supported here (use href or src, quoted): {line.strip()[:80]}"
            )
        close = value.find(quote_char, 1)
        if close < 0:
            raise ctx.fail(f"an unterminated HTML attribute in: {line.strip()[:80]}")
        edits.append((attr.end() + 1, attr.end() + close, ctx.fix(value[1:close], name == "src")))
    for a, b, new in sorted(edits, reverse=True):
        line = line[:a] + new + line[b:]
    return line


def _fence_open(line: str) -> str | None:
    """The fence a line opens (CommonMark: up to 3 spaces; a backtick fence's info string has no backtick)."""
    m = _FENCE.fullmatch(line)
    if not m or (m[1][0] == "`" and "`" in m[2]):
        return None
    return m[1]


def _fence_closes(line: str, fence: str) -> bool:
    """A closer is the same character, at least as long, up to 3 spaces of indent and only spaces after."""
    m = re.fullmatch(r" {0,3}(`{3,}|~{3,})[ \t]*", line)
    return bool(m and m[1][0] == fence[0] and len(m[1]) >= len(fence))


_QUOTE = re.compile(r" {0,3}>[ ]?")
_ITEM = re.compile(r"( *)([-*+]|\d{1,9}[.)])( +|$)")
_BLOCK_START = re.compile(r"#{1,6}(?:[ \t]|$)|(?:[-*_][ \t]*){3,}$|[=-]+[ \t]*$")


class _Blocks:
    """Tell code from prose line by line, following CommonMark for the containers this repository could use.

    Handled: fenced blocks at the top level, inside blockquotes (any depth) and inside list items (any depth,
    on the marker line or a continuation line), and indented code blocks (4+ columns, tabs to 4-column stops,
    not continuing a paragraph), also inside quotes and list items. Refused, not guessed: a fence or indented
    block inside a blockquote that is itself inside a list item.
    """

    def __init__(self, fail: Callable[[str], WikiError]) -> None:
        self.fail = fail
        self.lists: list[int] = []
        self.fence: tuple[str, int, int] | None = None  # (fence, quote depth, content column)
        self.paragraph = False

    def is_code(self, line: str) -> bool:
        ex = line.expandtabs(4)
        if self.fence is not None:
            if self._in_fence(ex, self.fence):
                return True
            self.fence = None
        rest, quotes = ex, 0
        while m := _QUOTE.match(rest):
            rest, quotes = rest[m.end() :], quotes + 1
        if not rest.strip():
            self.paragraph = False
            return False
        indent = len(rest) - len(rest.lstrip(" "))
        while self.lists and self.lists[-1] > indent:
            self.lists.pop()
        col = self.lists[-1] if self.lists else 0
        rest = rest[col:]
        started = False
        in_list_quote = False
        while True:
            if len(rest) - len(rest.lstrip(" ")) >= 4:
                break
            if item := _ITEM.match(rest):
                width = len(item[1]) + len(item[2])
                gap = len(item[3])
                gap = 1 if gap == 0 or gap > 4 else gap
                col += width + gap
                self.lists.append(col)
                rest, started = rest[width + gap :], True
            elif (m := _QUOTE.match(rest)) and self.lists:
                rest, in_list_quote = rest[m.end() :], True
            else:
                break
        deep = len(rest) - len(rest.lstrip(" ")) >= 4
        if deep and (not self.paragraph or started):
            if in_list_quote:
                raise self.fail("code inside a blockquote inside a list item is not supported; restructure it")
            return True
        if deep:
            self.paragraph = True
            return False
        opened = _fence_open(rest)
        if opened is not None:
            if in_list_quote:
                raise self.fail(
                    "a fenced block inside a blockquote inside a list item is not supported; restructure it"
                )
            self.fence = (opened, quotes, col)
            self.paragraph = False
            return True
        self.paragraph = bool(rest.strip()) and not _BLOCK_START.match(rest.lstrip(" "))
        return False

    def _in_fence(self, ex: str, state: tuple[str, int, int]) -> bool:
        fence, quotes, col = state
        rest = ex
        for _ in range(quotes):
            m = _QUOTE.match(rest)
            if not m:
                return False
            rest = rest[m.end() :]
        if not rest.strip():
            return True
        if len(rest) - len(rest.lstrip(" ")) < col:
            return False
        if _fence_closes(rest[col:], fence):
            self.fence = None
            self.paragraph = False
        return True


def rewrite_links(text: str, source: str, pages: dict[str, str], root: Path, blob: str) -> str:
    """Rewrite links, images, reference definitions and href/src attributes outside code."""
    ctx = _Ctx(source, pages, root, blob)
    out: list[str] = []
    number = 0

    def fail(why: str) -> WikiError:
        return ctx.fail(f"line {number}: {why}")

    blocks = _Blocks(fail)
    for number, line in enumerate(text.split("\n"), 1):
        if len(line) > MAX_LINE:
            raise ctx.fail(f"line {number} is longer than {MAX_LINE} characters; refusing to scan it")
        out.append(line if blocks.is_code(line) else _rewrite_line(line, ctx))
    return "\n".join(out)


def _heading_text(line: str) -> str | None:
    """The text of an ATX level-1 heading, found without a backtracking pattern, or None."""
    if not line.startswith("#") or not line[1:2].isspace():
        return None
    body = line[1:].strip()
    bare = body.rstrip("#")
    if bare != body and (not bare or bare[-1].isspace()):
        body = bare.rstrip()
    return body or None


def _title(text: str, fallback: str) -> str:
    blocks = _Blocks(lambda why: WikiError(why))
    for line in text.split("\n"):
        if not blocks.is_code(line) and (heading := _heading_text(line)) is not None:
            return heading
    return fallback


def _escape_label(text: str) -> str:
    """Backslash-escape what could close the label or start markup, so a heading is only ever text."""
    return _LABEL_META.sub(lambda m: "\\" + m[1], text)


def _reading_order(home: str, names: set[str]) -> list[str]:
    """Page names linked from the rewritten home page's 'Read in this order' section, in list order."""
    section = re.split(r"^## ", home, flags=re.MULTILINE)
    body = next((x for x in section if x.startswith("Read in this order")), "")
    found: list[str] = []
    for m in re.finditer(r"\]\(([A-Za-z0-9._-]+)(?=[#\s)])", body):
        if m[1] in names and m[1] not in found:
            found.append(m[1])
    return found


def render(docs: Path, root: Path, commit: str | None, repo_url: str = REPO_URL) -> dict[str, str]:
    """Return {wiki filename: text} for every page and the sidebar."""
    if commit is not None and not _SHA.match(commit):
        raise WikiError(f"--commit must be the full 40 hex character commit id, not {commit!r}")
    short = commit[:7].lower() if commit else "an unknown commit"
    texts = _read_docs(docs)
    pages: dict[str, str] = {}
    for filename in texts:
        if not _FILE.match(filename):
            raise WikiError(
                f"docs/{filename}: file name must match [A-Za-z0-9][A-Za-z0-9._-]*.md to become a wiki page"
            )
        name = page_name(filename)
        if name.casefold() in {n.casefold() for n in pages.values()}:
            raise WikiError(
                f"docs/{filename} maps to the page name {name}, which another file already uses "
                "(names are compared ignoring case)"
            )
        pages[filename] = name
    blob = f"{repo_url}/blob/{commit.lower() if commit else 'main'}"
    result: dict[str, str] = {}
    titles: dict[str, str] = {}
    for filename, text in texts.items():
        name = pages[filename]
        body = rewrite_links(text, filename, pages, root, blob)
        notice = f"> Generated from docs/{filename} at {short}. Edit the repository file, not the wiki.\n\n"
        result[f"{name}.md"] = notice + body
        titles[name] = _title(text, name)
    ordered = ["Home", *[n for n in _reading_order(result["Home.md"], set(pages.values())) if n != "Home"]]
    ordered += sorted(n for n in pages.values() if n not in ordered)
    result["_Sidebar.md"] = "".join(f"- [{_escape_label(titles[n])}]({n})\n" for n in ordered)
    return result


_OWNED_NAME = re.compile(r"^[A-Za-z0-9._-]+\.md$")


_HEADER = "gen_wiki-v1"
_HASH = re.compile(r"^[0-9a-f]{64}$")


def _record_name(out_name: str) -> str:
    """The record of what a run wrote, kept beside the tree, not in it: the publish step copies the whole tree."""
    return f".{out_name}.gen_wiki"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _record_body(hashes: dict[str, str]) -> str:
    lines = [f"{name} {hashes[name]}" for name in sorted(hashes)]
    return f"{_HEADER} {_digest(chr(10).join(lines).encode())}\n" + "".join(f"{x}\n" for x in lines)


# Everything below works on directory file descriptors opened once with O_NOFOLLOW, so a path swapped for a
# symbolic link after the checks cannot redirect a write, a read or a delete.


def _lstat(name: str, dir_fd: int) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _open_dir(name: str, dir_fd: int) -> int:
    try:
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
    except OSError as err:
        if err.errno in (errno.ELOOP, errno.ENOTDIR):
            raise WikiError(f"{name} is a symbolic link or not a directory; refusing to write through it") from err
        raise


def _read(name: str, dir_fd: int) -> bytes | None:
    """The bytes of a regular file, or None if it is absent; a symbolic link or a non-regular file is an error."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as err:
        raise WikiError(f"{name} is a symbolic link or cannot be read: {err.strerror}") from err
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise WikiError(f"{name} is not a regular file; refusing to read it")
        return handle.read()


def _write(dir_fd: int, name: str, data: bytes) -> None:
    """Write through a new temporary file and rename it over `name`, never following a link at either path."""
    tmp = f".{name}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp, dir_fd=dir_fd)
        raise


def _owned(parent_fd: int, out_name: str) -> dict[str, str] | None:
    """{name: sha256} of what a previous run wrote into the tree, or None if there is no valid, intact record."""
    try:
        raw = _read(_record_name(out_name), parent_fd)
        text = raw.decode("utf-8") if raw is not None else ""
    except (WikiError, UnicodeDecodeError):
        return None
    head, _, rest = text.partition("\n")
    hashes: dict[str, str] = {}
    for line in rest.split("\n"):
        if not line:
            continue
        name, _, digest = line.partition(" ")
        if not _OWNED_NAME.match(name) or not _HASH.match(digest) or name in hashes:
            return None
        hashes[name] = digest
    if not hashes or text != _record_body(hashes) or head.split(" ")[0] != _HEADER:
        return None
    return hashes


def _after_checks() -> None:
    """Runs between the checks and the writes; the tests swap paths here."""


class _Target:
    """The validated output directory and its parent, held open by file descriptor."""

    def __init__(self, resolved: Path, parent_fd: int, out_fd: int) -> None:
        self.resolved, self.parent_fd, self.out_fd = resolved, parent_fd, out_fd
        self.name = resolved.name
        self.ids = (self._id(parent_fd), self._id(out_fd))

    @staticmethod
    def _id(fd: int) -> tuple[int, int]:
        st = os.fstat(fd)
        return st.st_dev, st.st_ino

    def close(self) -> None:
        os.close(self.out_fd)
        os.close(self.parent_fd)

    def verify(self) -> None:
        """Fail unless the path still leads to the directories that were opened and checked."""
        try:
            same = self.resolved.resolve() == self.resolved and (
                (os.stat(self.resolved.parent).st_dev, os.stat(self.resolved.parent).st_ino) == self.ids[0]
                and (os.stat(self.resolved).st_dev, os.stat(self.resolved).st_ino) == self.ids[1]
            )
        except OSError:
            same = False
        if not same:
            raise WikiError(f"{self.resolved} changed while gen_wiki was running (a path was swapped); refusing")


def _open_target(out: Path, root: Path) -> _Target:
    """Resolve --out, refuse anything outside the repository, and open it (creating it) by descriptor."""
    root = root.resolve()
    if out.is_symlink():
        raise WikiError(f"--out {out} is a symbolic link")
    resolved = out.resolve()
    if resolved == root or root not in resolved.parents:
        raise WikiError(f"--out {out} must be a directory inside the repository {root}")
    current = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        parts = resolved.relative_to(root).parts
        for part in parts[:-1]:
            try:
                nxt = _open_dir(part, current)
            except FileNotFoundError:
                os.mkdir(part, dir_fd=current)
                nxt = _open_dir(part, current)
            os.close(current)
            current = nxt
        name = parts[-1]
        record = _lstat(_record_name(name), current)
        if record is not None and not stat.S_ISREG(record.st_mode):
            raise WikiError(f"the ownership record for {out} is a symbolic link or not a regular file; refusing")
        existing = _lstat(name, current)
        if existing is None:
            os.mkdir(name, dir_fd=current)
        elif not stat.S_ISDIR(existing.st_mode):
            raise WikiError(f"--out {out} exists and is not a directory")
        return _Target(resolved, current, _open_dir(name, current))
    except BaseException:
        os.close(current)
        raise


def _check_clean(target: _Target, out: Path) -> dict[str, str]:
    """What a previous run owns in a non-empty tree; refuse a tree that holds anything else or was edited."""
    entries = os.listdir(target.out_fd)
    if not entries:
        return {}
    owned = _owned(target.parent_fd, target.name)
    if owned is None:
        raise WikiError(f"--out {out} is not empty and was not written by gen_wiki; refusing to write into it")
    stray = []
    for entry in entries:
        found = _lstat(entry, target.out_fd)
        if entry not in owned or found is None or not stat.S_ISREG(found.st_mode):
            stray.append(entry)
    if stray:
        raise WikiError(f"--out {out} holds files not written by gen_wiki ({', '.join(sorted(stray))}); refusing")
    changed = [n for n, digest in owned.items() if _digest(_read(n, target.out_fd) or b"") != digest and n in entries]
    if changed:
        raise WikiError(f"--out {out}: {', '.join(sorted(changed))} changed since gen_wiki wrote it; refusing")
    return owned


def generate(root: Path, out: Path, commit: str | None, repo_url: str = REPO_URL) -> list[str]:
    root = root.resolve()
    pages = render(root / "docs", root, commit, repo_url)
    target = _open_target(out, root)
    try:
        owned = _check_clean(target, out)
        _after_checks()
        target.verify()
        for old in owned:
            found = _lstat(old, target.out_fd)
            if found is not None and stat.S_ISREG(found.st_mode):
                os.unlink(old, dir_fd=target.out_fd)
        data = {name: text.encode("utf-8") for name, text in pages.items()}
        for name, raw in data.items():
            _write(target.out_fd, name, raw)
        target.verify()
        record = _record_body({n: _digest(r) for n, r in data.items()})
        _write(target.parent_fd, _record_name(target.name), record.encode())
        target.verify()
    finally:
        target.close()
    return sorted(pages)


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True, type=Path, help="directory to write the wiki tree into")
    parser.add_argument("--commit", help="the commit the pages were generated from")
    args = parser.parse_args(argv)
    try:
        names = generate(root, args.out, args.commit)
    except WikiError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    print(f"wrote {len(names)} files to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
