# SPDX-License-Identifier: Apache-2.0
"""Every docs page is linked from the README, and from docs/home.md, so the wiki list cannot drift from docs/."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
DOCS = ROOT / "docs"
WIKI = "https://github.com/ChiefGyk3D/scrum-around-and-find-out/wiki/"


def pages() -> list[str]:
    return sorted(p.name for p in DOCS.glob("*.md") if p.name != "home.md")


def wiki_name(filename: str) -> str:
    stem = filename.removesuffix(".md")
    return stem[:1].upper() + stem[1:]


def unlinked_from_readme(readme: str, names: list[str]) -> list[str]:
    """Pages with neither a docs/<file> link nor a wiki/<Page> link in the README."""
    missing = []
    for name in names:
        in_docs = re.search(rf"\]\(docs/{re.escape(name)}(?:#[^)]*)?\)", readme)
        in_wiki = re.search(rf"\]\({re.escape(WIKI + wiki_name(name))}(?:#[^)]*)?\)", readme)
        if not (in_docs or in_wiki):
            missing.append(name)
    return missing


def unlinked_from_home(home: str, names: list[str]) -> list[str]:
    return [n for n in names if not re.search(rf"\]\({re.escape(n)}(?:#[^)]*)?\)", home)]


def wiki_list(readme: str) -> str:
    return readme.split("\n## Wiki", 1)[1].split("\n## ", 1)[0]


def test_pages_are_collected() -> None:
    assert len(pages()) >= 20  # a collection that finds nothing must not pass


def test_the_wiki_list_names_every_page() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    only_wiki = re.sub(r"\]\(docs/[^)]*\)", "](x)", wiki_list(readme))
    assert unlinked_from_readme(only_wiki, pages()) == []


def test_every_docs_page_is_linked_from_the_readme() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert unlinked_from_readme(readme, pages()) == []


def test_every_docs_page_is_linked_from_home() -> None:
    home = (DOCS / "home.md").read_text(encoding="utf-8")
    assert unlinked_from_home(home, pages()) == []


def test_the_guard_bites() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    home = (DOCS / "home.md").read_text(encoding="utf-8")
    cut = readme.replace(f"- [Orchestrator]({WIKI}Orchestrator)\n", "")
    assert cut != readme
    assert unlinked_from_readme(re.sub(r"\]\(docs/[^)]*\)", "](x)", cut), pages()) == ["orchestrator.md"]
    assert unlinked_from_home(home.replace("](threat-model.md)", "](x.md)"), pages()) == ["threat-model.md"]
