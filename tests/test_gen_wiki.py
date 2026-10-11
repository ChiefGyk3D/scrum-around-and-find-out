# SPDX-License-Identifier: MIT
"""scripts/gen_wiki.py mirrors docs/ into a flat wiki tree, and refuses anything that could damage the result."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).parent.parent
SHA = "0123456789abcdef0123456789abcdef01234567"


def load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gen_wiki", ROOT / "scripts" / "gen_wiki.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gw = load_script()

HOME = """# Home

## Read in this order

- [Zed](zed.md): last alphabetically, first in the list.
- [Board yaml](board-yaml.md#fields): a fragment.

Done.
"""


def make_repo(tmp_path: Path, pages: dict[str, str] | None = None) -> Path:
    repo = tmp_path / "repo"
    docs = repo / "docs"
    docs.mkdir(parents=True)
    for name, text in (
        pages
        if pages is not None
        else {"home.md": HOME, "zed.md": "# Zed\n", "board-yaml.md": "# B\n", "alpha.md": "# Alpha\n"}
    ).items():
        (docs / name).write_text(text, encoding="utf-8")
    return repo


def run(repo: Path, out: Path | None = None, commit: str | None = SHA) -> dict[str, str]:
    target = out or repo / "wiki-out"
    gw.generate(repo, target, commit)
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(target.iterdir())}


def test_names_map_home_and_title_case_hyphenated(tmp_path: Path) -> None:
    got = run(make_repo(tmp_path))
    assert set(got) == {"Home.md", "Zed.md", "Board-yaml.md", "Alpha.md", "_Sidebar.md"}


def test_superpowers_is_not_published(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    (repo / "docs" / "superpowers" / "specs").mkdir(parents=True)
    (repo / "docs" / "superpowers" / "specs" / "plan.md").write_text("# secret plan\n")
    got = run(repo)
    assert not any("plan" in n.lower() for n in got) and "Superpowers.md" not in got
    assert all("secret plan" not in t for t in got.values())


def test_each_page_starts_with_one_line_notice(tmp_path: Path) -> None:
    got = run(make_repo(tmp_path))
    assert got["Zed.md"].startswith(
        "> Generated from docs/zed.md at 0123456. Edit the repository file, not the wiki.\n\n# Zed\n"
    )
    assert got["Home.md"].startswith("> Generated from docs/home.md at 0123456.")


def test_links_are_rewritten_with_fragments(tmp_path: Path) -> None:
    got = run(make_repo(tmp_path))
    assert "[Zed](Zed): last" in got["Home.md"]
    assert "[Board yaml](Board-yaml#fields)" in got["Home.md"]
    assert ".md)" not in got["Home.md"]


def test_dot_slash_and_nested_style_links_resolve(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, {"home.md": "# H\n[a](./alpha.md) [b](sub/../alpha.md#x)\n", "alpha.md": "# A\n"})
    text = run(repo)["Home.md"]
    assert "[a](Alpha)" in text and "[b](Alpha#x)" in text


def test_external_and_anchor_links_are_untouched(tmp_path: Path) -> None:
    src = "# H\n[w](https://example.com/x.md) [m](mailto:a@b.c) [p](//cdn.example/y.md) [h](#here)\n"
    repo = make_repo(tmp_path, {"home.md": src})
    assert src in run(repo)["Home.md"]


def test_code_spans_and_fences_are_untouched(tmp_path: Path) -> None:
    src = (
        "# H\n`[x](missing.md)` and ``[y](nope.md)`` then [ok](alpha.md)\n\n"
        "```md\n[z](also-missing.md)\n```\n\n~~~\n[q](gone.md)\n~~~\n[after](alpha.md)\n"
    )
    repo = make_repo(tmp_path, {"home.md": src, "alpha.md": "# A\n"})
    text = run(repo)["Home.md"]
    assert "`[x](missing.md)`" in text and "``[y](nope.md)``" in text
    assert "[z](also-missing.md)" in text and "[q](gone.md)" in text
    assert "[ok](Alpha)" in text and "[after](Alpha)" in text


def test_a_link_after_a_closed_fence_is_checked_again(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, {"home.md": "# H\n```\nx\n```\n[bad](missing.md)\n"})
    with pytest.raises(gw.WikiError, match=r"missing\.md"):
        gw.generate(repo, repo / "wiki-out", SHA)


@pytest.mark.parametrize("target", ["missing.md", "superpowers/specs/plan.md", "notes.txt", "../../etc/passwd"])
def test_unmapped_links_fail_and_write_nothing(tmp_path: Path, target: str) -> None:
    repo = make_repo(tmp_path, {"home.md": f"# H\n[bad]({target})\n"})
    (repo / "docs" / "superpowers").mkdir()
    (repo / "docs" / "superpowers" / "x.md").write_text("x")
    with pytest.raises(gw.WikiError):
        gw.generate(repo, repo / "wiki-out", SHA)
    assert not (repo / "wiki-out").exists() or not list((repo / "wiki-out").iterdir())


def test_unmapped_link_exits_one_with_a_clear_message(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = make_repo(tmp_path, {"home.md": "# H\n[bad](missing.md)\n"})
    assert gw.main(["--out", str(repo / "wiki-out")], root=repo) == 1
    err = capsys.readouterr().err
    assert "docs/home.md" in err and "missing.md" in err


def test_a_link_out_of_docs_points_at_the_file_on_github(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, {"home.md": "# H\n[e](../examples/x.yaml)\n"})
    (repo / "examples").mkdir()
    (repo / "examples" / "x.yaml").write_text("a: 1\n")
    assert f"]({gw.REPO_URL}/blob/{SHA}/examples/x.yaml)" in run(repo)["Home.md"]
    (repo / "examples" / "x.yaml").unlink()
    with pytest.raises(gw.WikiError, match="does not exist"):
        gw.generate(repo, repo / "wiki-out", SHA)


def test_missing_empty_or_homeless_docs_fail(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(gw.WikiError, match="cannot read"):
        gw.generate(repo, repo / "wiki-out", SHA)
    empty = make_repo(tmp_path / "e", {})
    with pytest.raises(gw.WikiError, match="no docs"):
        gw.generate(empty, empty / "wiki-out", SHA)
    homeless = make_repo(tmp_path / "h", {"alpha.md": "# A\n"})
    with pytest.raises(gw.WikiError, match=r"home\.md"):
        gw.generate(homeless, homeless / "wiki-out", SHA)


def test_a_bad_commit_is_refused(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    for bad in ("main; rm -rf /", "zzzz", "", "a" * 41):
        with pytest.raises(gw.WikiError, match="commit"):
            gw.generate(repo, repo / "wiki-out", bad)


def test_output_is_deterministic_and_regenerating_removes_stale_pages(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    first = run(repo)
    assert run(repo) == first
    (repo / "docs" / "alpha.md").unlink()
    second = run(repo)
    assert "Alpha.md" not in second and second["Zed.md"] == first["Zed.md"]


def test_sidebar_is_home_then_reading_order_then_the_rest_alphabetically(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        {
            "home.md": HOME,
            "zed.md": "# Zed\n",
            "board-yaml.md": "# B\n",
            "alpha.md": "# Alpha\n",
            "beta.md": "# Beta\n",
        },
    )
    sidebar = run(repo)["_Sidebar.md"]
    assert re.findall(r"\]\((\S+)\)", sidebar) == ["Home", "Zed", "Board-yaml", "Alpha", "Beta"]
    assert sidebar.splitlines()[0] == "- [Home](Home)"


def test_out_must_be_inside_the_repo(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    for bad in (tmp_path / "elsewhere", repo, repo.parent, repo / ".." / "x"):
        with pytest.raises(gw.WikiError, match="inside the repository"):
            gw.generate(repo, bad, SHA)
    assert not (tmp_path / "elsewhere").exists() and not (tmp_path / "x").exists()


def test_out_through_a_symlink_is_refused(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = repo / "wiki-out"
    link.symlink_to(outside)
    with pytest.raises(gw.WikiError, match="symbolic link"):
        gw.generate(repo, link, SHA)
    assert list(outside.iterdir()) == []


def test_out_with_foreign_files_is_refused_and_survives(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    mine = repo / "precious"
    mine.mkdir()
    (mine / "keep.txt").write_text("keep")
    with pytest.raises(gw.WikiError, match="not empty"):
        gw.generate(repo, mine, SHA)
    assert (mine / "keep.txt").read_text() == "keep"
    named = repo / "wiki-out"
    named.mkdir()
    (named / "Old.md").write_text("old")
    (named / "notes.txt").write_text("keep")
    with pytest.raises(gw.WikiError, match="more than a previous wiki tree"):
        gw.generate(repo, named, SHA)
    assert (named / "Old.md").exists() and (named / "notes.txt").exists()


def test_a_previous_tree_in_wiki_out_is_replaced(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    named = repo / "wiki-out"
    named.mkdir()
    (named / "Old.md").write_text("old")
    got = run(repo)
    assert "Old.md" not in got and "Home.md" in got
    empty = repo / "other"
    empty.mkdir()
    assert "Home.md" in run(repo, empty)


# The real tree.


def test_the_real_docs_generate_and_every_internal_link_resolves(tmp_path: Path) -> None:
    out = ROOT / "wiki-out"
    if out.exists():
        pytest.skip("wiki-out holds a local run; remove it to run this test")
    try:
        got = run(ROOT, out)
    finally:
        for p in out.glob("*.md"):
            p.unlink()
        if out.exists():
            out.rmdir()
    assert "Home.md" in got and "_Sidebar.md" in got
    assert len(got) >= len(list((ROOT / "docs").glob("*.md"))) + 1
    names = {n.removesuffix(".md") for n in got}
    checked = 0
    for filename, text in got.items():
        stripped = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
        stripped = re.sub(r"`[^`]*`", "", stripped)
        for target in re.findall(r"\]\(([^)\s]+)\)", stripped):
            if re.match(r"^([A-Za-z][A-Za-z0-9+.-]*:|//|#)", target):
                continue
            checked += 1
            assert target.partition("#")[0] in names, f"{filename}: {target}"
    assert checked > 10
    assert not any(".md)" in re.sub(r"`[^`]*`", "", t) for t in got.values())


# Symlinks under docs/ never leak their targets.


def test_a_symlinked_page_is_refused_and_its_content_never_written(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    secret = tmp_path / "secret.md"
    secret.write_text("# Secret\nTOP-SECRET-TOKEN\n")
    (repo / "docs" / "leak.md").symlink_to(secret)
    with pytest.raises(gw.WikiError, match="symbolic link"):
        gw.generate(repo, repo / "wiki-out", SHA)
    assert not (repo / "wiki-out").exists()


def test_a_symlink_to_a_system_file_is_refused(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    (repo / "docs" / "passwd.md").symlink_to("/etc/passwd")
    with pytest.raises(gw.WikiError, match="symbolic link"):
        gw.generate(repo, repo / "wiki-out", SHA)


def test_a_symlinked_subdirectory_is_refused(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.md").write_text("TOP-SECRET-TOKEN")
    (repo / "docs" / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(gw.WikiError, match="symbolic link"):
        gw.generate(repo, repo / "wiki-out", SHA)


def test_a_symlinked_docs_directory_is_refused(tmp_path: Path) -> None:
    real = make_repo(tmp_path / "real")
    repo = tmp_path / "repo2"
    repo.mkdir()
    (repo / "docs").symlink_to(real / "docs", target_is_directory=True)
    with pytest.raises(gw.WikiError, match="symbolic link"):
        gw.generate(repo, repo / "wiki-out", SHA)


def test_a_symlink_in_the_unpublished_tree_is_refused_too(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    (repo / "docs" / "superpowers").mkdir()
    (repo / "docs" / "superpowers" / "l.md").symlink_to("/etc/passwd")
    with pytest.raises(gw.WikiError, match="symbolic link"):
        gw.generate(repo, repo / "wiki-out", SHA)
