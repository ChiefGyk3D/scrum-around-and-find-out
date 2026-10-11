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
import os
import posixpath
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/ChiefGyk3D/scrum-around-and-find-out"
OUT_NAME = "wiki-out"

_SCHEME = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*:|//)")
_LINK = re.compile(r"\]\(([^)\s]+)\)")
_CODE_SPAN = re.compile(r"(`+)(?:(?!\1).)+?\1")
_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
_SHA = re.compile(r"^[0-9a-fA-F]{4,40}$")
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


def _rewrite_target(target: str, source: str, pages: dict[str, str], root: Path, blob: str) -> str:
    if target.startswith("#") or _SCHEME.match(target):
        return target
    path, hash_, frag = target.partition("#")
    suffix = hash_ + frag
    joined = posixpath.normpath(posixpath.join("docs", path))
    if joined.startswith("docs/") and "/" not in joined[len("docs/") :]:
        name = joined[len("docs/") :]
        if name in pages:
            return pages[name] + suffix
        raise WikiError(f"docs/{source}: link '{target}' points at docs/{name}, which is not a wiki page")
    if joined == "docs" or joined.startswith("docs/") or joined.startswith(".."):
        if joined.startswith("docs/"):
            raise WikiError(f"docs/{source}: link '{target}' points into {joined}, which is not published")
        raise WikiError(f"docs/{source}: link '{target}' leaves the repository")
    if not (root / joined).exists():
        raise WikiError(f"docs/{source}: link '{target}' points at {joined}, which does not exist")
    return f"{blob}/{joined}{suffix}"


def rewrite_links(text: str, source: str, pages: dict[str, str], root: Path, blob: str) -> str:
    """Rewrite links outside fenced blocks and inline code spans."""
    out: list[str] = []
    fence: str | None = None
    for line in text.split("\n"):
        m = _FENCE.match(line)
        if fence is not None:
            if m and m[1][0] == fence[0] and len(m[1]) >= len(fence) and line.strip() == m[1]:
                fence = None
            out.append(line)
            continue
        if m:
            fence = m[1]
            out.append(line)
            continue
        pieces: list[str] = []
        pos = 0
        for span in _CODE_SPAN.finditer(line):
            pieces.append(_sub(line[pos : span.start()], source, pages, root, blob))
            pieces.append(span.group(0))
            pos = span.end()
        pieces.append(_sub(line[pos:], source, pages, root, blob))
        out.append("".join(pieces))
    return "\n".join(out)


def _sub(segment: str, source: str, pages: dict[str, str], root: Path, blob: str) -> str:
    return _LINK.sub(lambda m: f"]({_rewrite_target(m[1], source, pages, root, blob)})", segment)


def _title(text: str, fallback: str) -> str:
    in_fence = False
    for line in text.split("\n"):
        if _FENCE.match(line):
            in_fence = not in_fence
        elif not in_fence and (m := _HEADING.match(line)):
            return m[1]
    return fallback


def _reading_order(home: str, pages: dict[str, str]) -> list[str]:
    """Page names linked from home.md's 'Read in this order' section, in list order."""
    section = re.split(r"^## ", home, flags=re.MULTILINE)
    body = next((s for s in section if s.startswith("Read in this order")), "")
    names: list[str] = []
    for m in _LINK.finditer(body):
        target = m[1].partition("#")[0]
        page = pages.get(target)
        if page and page not in names:
            names.append(page)
    return names


def render(docs: Path, root: Path, commit: str | None, repo_url: str = REPO_URL) -> dict[str, str]:
    """Return {wiki filename: text} for every page and the sidebar."""
    if commit is not None and not _SHA.match(commit):
        raise WikiError(f"--commit must be a hex commit id, not {commit!r}")
    short = commit[:7].lower() if commit else "an unknown commit"
    texts = _read_docs(docs)
    pages: dict[str, str] = {}
    for filename in texts:
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
    ordered = ["Home", *[n for n in _reading_order(texts["home.md"], pages) if n != "Home"]]
    ordered += sorted(n for n in pages.values() if n not in ordered)
    result["_Sidebar.md"] = "".join(f"- [{titles[n]}]({n})\n" for n in ordered)
    return result


_OWNED_NAME = re.compile(r"^[A-Za-z0-9._-]+\.md$")


def manifest_path(out: Path) -> Path:
    """The record of what a run wrote, kept beside the tree, not in it: the publish step copies the whole tree."""
    return out.parent / f".{out.name}.gen_wiki"


def _owned(out: Path) -> set[str] | None:
    """The file names a previous run wrote into `out`, or None if there is no valid record."""
    try:
        names = manifest_path(out).read_text(encoding="utf-8").split("\n")
    except (OSError, UnicodeDecodeError):
        return None
    listed = {n for n in names if n}
    if not listed or not all(_OWNED_NAME.match(n) for n in listed):
        return None
    return listed


def check_out(out: Path, root: Path) -> Path:
    """Resolve --out and refuse anything that could clobber more than a previous run's own output."""
    root = root.resolve()
    if out.is_symlink():
        raise WikiError(f"--out {out} is a symbolic link")
    resolved = out.resolve()
    if resolved == root or root not in resolved.parents:
        raise WikiError(f"--out {out} must be a directory inside the repository {root}")
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
    stray = [e.name for e in entries if e.name not in owned or e.is_symlink() or not e.is_file()]
    if stray:
        raise WikiError(f"--out {out} holds files not written by gen_wiki ({', '.join(sorted(stray))}); refusing")
    return resolved


def generate(root: Path, out: Path, commit: str | None, repo_url: str = REPO_URL) -> list[str]:
    root = root.resolve()
    pages = render(root / "docs", root, commit, repo_url)
    target = check_out(out, root)
    owned = _owned(target) if target.exists() else None
    target.mkdir(parents=True, exist_ok=True)
    for old in owned or ():
        (target / old).unlink(missing_ok=True)
    for name, text in pages.items():
        (target / name).write_text(text, encoding="utf-8", newline="\n")
    manifest_path(target).write_text("".join(f"{n}\n" for n in sorted(pages)), encoding="utf-8")
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
