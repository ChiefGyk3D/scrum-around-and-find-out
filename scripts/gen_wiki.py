#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
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
import hashlib
import os
import posixpath
import re
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/ChiefGyk3D/scrum-around-and-find-out"
OUT_NAME = "wiki-out"

_SCHEME = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*:|//)")
_LINK = re.compile(r"\]\(([^)\s]+)\)")
_REFDEF = re.compile(r" {0,3}\[(?:[^\]\\]|\\.)+\]:[ \t]*")
_ATTR = re.compile(
    r"(?<=[\s<\"'])((?:xlink:)?(?:href|src|srcset|poster|formaction|action))[ \t]*=[ \t]*", re.IGNORECASE
)
_CODE_SPAN = re.compile(r"(`+)(?:(?!\1).)+?\1")
_FENCE = re.compile(r" {0,3}(`{3,}|~{3,})(.*)")
MAX_LINE = 20_000
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.md$")
_LABEL_META = re.compile(r"([\\\[\]<>`|*_&])")
_HEADING = re.compile(r"^#\s+(.+?)\s*#*\s*$")


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


def _read_docs(docs: Path) -> dict[str, str]:
    """Map each docs/*.md filename to its text."""
    _refuse_symlinks(docs)
    try:
        files = sorted(p for p in docs.iterdir() if p.is_file() and p.suffix == ".md")
    except OSError as err:
        raise WikiError(f"cannot read the docs directory {docs}: {err.strerror or err}") from err
    if not files:
        raise WikiError(f"no docs/*.md pages in {docs}")
    texts: dict[str, str] = {}
    base = docs.resolve()
    for path in files:
        if base not in path.resolve().parents:
            raise WikiError(f"{path.name} resolves outside docs/")
        try:
            texts[path.name] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as err:
            raise WikiError(f"cannot read {path.name}: {err}") from err
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
    return _CODE_SPAN.sub(lambda m: "\x00" * len(m.group(0)), line)


def _bracket_openers(mask: str) -> dict[int, int]:
    """Map the index of each `]` to the index of the `[` it closes, in one forward pass."""
    stack: list[int] = []
    found: dict[int, int] = {}
    for i, ch in enumerate(mask):
        if ch == "[":
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
            image = opener > 0 and mask[opener - 1] == "!"
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


def rewrite_links(text: str, source: str, pages: dict[str, str], root: Path, blob: str) -> str:
    """Rewrite links, images, reference definitions and href/src attributes outside code."""
    ctx = _Ctx(source, pages, root, blob)
    out: list[str] = []
    fence: str | None = None
    for number, line in enumerate(text.split("\n"), 1):
        if len(line) > MAX_LINE:
            raise ctx.fail(f"line {number} is longer than {MAX_LINE} characters; refusing to scan it")
        if fence is not None:
            if _fence_closes(line, fence):
                fence = None
            out.append(line)
        elif (opened := _fence_open(line)) is not None:
            fence = opened
            out.append(line)
        else:
            out.append(_rewrite_line(line, ctx))
    return "\n".join(out)


def _title(text: str, fallback: str) -> str:
    fence: str | None = None
    for line in text.split("\n"):
        if fence is not None:
            if _fence_closes(line, fence):
                fence = None
        elif (opened := _fence_open(line)) is not None:
            fence = opened
        elif m := _HEADING.match(line):
            return m[1]
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
        if name in pages.values():
            raise WikiError(f"docs/{filename} maps to the page name {name}, which another file already uses")
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


def manifest_path(out: Path) -> Path:
    """The record of what a run wrote, kept beside the tree, not in it: the publish step copies the whole tree."""
    return out.parent / f".{out.name}.gen_wiki"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _record_body(hashes: dict[str, str]) -> str:
    lines = [f"{name} {hashes[name]}" for name in sorted(hashes)]
    return f"{_HEADER} {_digest(chr(10).join(lines).encode())}\n" + "".join(f"{x}\n" for x in lines)


def _check_record_kind(out: Path) -> Path:
    record = manifest_path(out)
    if record.is_symlink() or (record.exists() and not record.is_file()):
        raise WikiError(f"the ownership record {record} is a symbolic link or not a regular file; refusing")
    return record


def _owned(out: Path) -> dict[str, str] | None:
    """{name: sha256} of what a previous run wrote into `out`, or None if there is no valid, intact record."""
    record = _check_record_kind(out)
    try:
        text = record.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
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


def _regular(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def check_out(out: Path, root: Path) -> Path:
    """Resolve --out and refuse anything that could clobber more than a previous run's own, unchanged output."""
    root = root.resolve()
    if out.is_symlink():
        raise WikiError(f"--out {out} is a symbolic link")
    resolved = out.resolve()
    if resolved == root or root not in resolved.parents:
        raise WikiError(f"--out {out} must be a directory inside the repository {root}")
    _check_record_kind(resolved)
    if not resolved.exists():
        return resolved
    if not resolved.is_dir():
        raise WikiError(f"--out {out} exists and is not a directory")
    entries = list(resolved.iterdir())
    if not entries:
        return resolved
    owned = _owned(resolved)
    if owned is None:
        raise WikiError(f"--out {out} is not empty and was not written by gen_wiki; refusing to write into it")
    stray = [e.name for e in entries if e.name not in owned or not _regular(e)]
    if stray:
        raise WikiError(f"--out {out} holds files not written by gen_wiki ({', '.join(sorted(stray))}); refusing")
    changed = [n for n in owned if (resolved / n).exists() and _digest((resolved / n).read_bytes()) != owned[n]]
    if changed:
        raise WikiError(f"--out {out}: {', '.join(sorted(changed))} changed since gen_wiki wrote it; refusing")
    return resolved


def _write(directory: Path, name: str, data: bytes) -> None:
    """Write through a new temporary file and rename it over `name`, never following a link at either path."""
    tmp = directory / f".{name}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, directory / name)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def generate(root: Path, out: Path, commit: str | None, repo_url: str = REPO_URL) -> list[str]:
    root = root.resolve()
    pages = render(root / "docs", root, commit, repo_url)
    target = check_out(out, root)
    owned = _owned(target) if target.exists() and any(target.iterdir()) else None
    target.mkdir(parents=True, exist_ok=True)
    for old in owned or ():
        path = target / old
        if _regular(path):
            path.unlink()
    data = {name: text.encode("utf-8") for name, text in pages.items()}
    for name, raw in data.items():
        _write(target, name, raw)
    _write(target.parent, manifest_path(target).name, _record_body({n: _digest(r) for n, r in data.items()}).encode())
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
