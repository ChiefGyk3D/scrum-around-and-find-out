# SPDX-License-Identifier: MIT
"""scripts/gen_wiki.py mirrors docs/ into a flat wiki tree, and refuses anything that could damage the result."""

from __future__ import annotations

import contextlib
import importlib.util
import os
import re
import shutil
import time
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


def test_a_wiki_out_by_name_alone_is_never_cleaned(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    named = repo / "archive" / "wiki-out"
    named.mkdir(parents=True)
    (named / "notes.md").write_text("my notes")
    with pytest.raises(gw.WikiError, match="not written by gen_wiki"):
        gw.generate(repo, named, SHA)
    assert (named / "notes.md").read_text() == "my notes"
    assert gw.main(["--out", str(named)], root=repo) == 1
    assert (named / "notes.md").read_text() == "my notes"


def test_a_previous_generator_tree_is_replaced_but_extra_files_stop_it(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    first = run(repo)
    named = repo / "wiki-out"
    (named / "Stale.md").write_text("added by hand")
    with pytest.raises(gw.WikiError, match="not written by gen_wiki"):
        gw.generate(repo, named, SHA)
    assert (named / "Stale.md").exists() and (named / "Home.md").exists()
    (named / "Stale.md").unlink()
    (repo / "docs" / "alpha.md").unlink()
    second = run(repo)
    assert "Alpha.md" in first and "Alpha.md" not in second


def test_the_ownership_record_is_not_inside_the_published_tree(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    got = run(repo)
    assert set(got) == {"Home.md", "Zed.md", "Board-yaml.md", "Alpha.md", "_Sidebar.md"}
    assert [p.name for p in (repo / "wiki-out").iterdir() if p.name.startswith(".")] == []


def test_a_forged_ownership_record_cannot_name_other_paths(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    named = repo / "wiki-out"
    named.mkdir()
    (named / "x.md").write_text("mine")
    (repo / ".wiki-out.gen_wiki").write_text("../../etc/passwd\nx.md\n")
    with pytest.raises(gw.WikiError, match="not written by gen_wiki"):
        gw.generate(repo, named, SHA)
    assert (named / "x.md").read_text() == "mine"


# The real tree.


def test_the_real_docs_generate_and_every_internal_link_resolves(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(ROOT / "docs", repo / "docs")
    shutil.copytree(ROOT / "examples", repo / "examples")
    got = run(repo, repo / "wiki-out")
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


# Commit, names, sidebar labels.


@pytest.mark.parametrize("bad", ["abcd", "0123456", "a" * 39, "a" * 41, "", "g" * 40, "main"])
def test_commit_must_be_exactly_forty_hex_characters(tmp_path: Path, bad: str) -> None:
    repo = make_repo(tmp_path)
    with pytest.raises(gw.WikiError, match="40"):
        gw.generate(repo, repo / "wiki-out", bad)
    assert not (repo / "wiki-out").exists()


def test_no_commit_is_a_local_run(tmp_path: Path) -> None:
    got = run(make_repo(tmp_path), commit=None)
    assert got["Home.md"].startswith("> Generated from docs/home.md at an unknown commit.")


def test_an_uppercase_commit_is_written_in_lower_case(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, {"home.md": "# H\n[e](../examples/x.yaml)\n"})
    (repo / "examples").mkdir()
    (repo / "examples" / "x.yaml").write_text("a: 1\n")
    upper = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
    text = run(repo, commit=upper)["Home.md"]
    assert f"/blob/{upper.lower()}/examples/x.yaml" in text
    assert upper not in text and "at abcdef0." in text


@pytest.mark.parametrize("name", ["my page.md", "a#b.md", "a?b.md", "a%20b.md", "_side.md", ".hidden.md", "é.md"])
def test_unsafe_file_names_are_refused(tmp_path: Path, name: str) -> None:
    repo = make_repo(tmp_path)
    (repo / "docs" / name).write_text("# X\n")
    with pytest.raises(gw.WikiError, match="file name"):
        gw.generate(repo, repo / "wiki-out", SHA)


def test_names_that_differ_only_in_case_collide(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, {"home.md": "# H\n", "foo.md": "# a\n", "Foo.md": "# b\n"})
    with pytest.raises(gw.WikiError, match="already uses"):
        gw.generate(repo, repo / "wiki-out", SHA)


def test_a_page_listed_twice_in_the_reading_order_appears_once(tmp_path: Path) -> None:
    home = "# H\n\n## Read in this order\n\n- [Z](zed.md)\n- [Z again](zed.md#x)\n- [A](alpha.md)\n"
    repo = make_repo(tmp_path, {"home.md": home, "zed.md": "# Zed\n", "alpha.md": "# Alpha\n"})
    assert re.findall(r"\]\((\S+)\)", run(repo)["_Sidebar.md"]) == ["Home", "Zed", "Alpha"]


def test_a_hostile_heading_cannot_forge_a_sidebar_link(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, {"home.md": "# H\n", "zed.md": "# Safe](https://attacker.invalid) <b>`x`|y\n"})
    sidebar = run(repo)["_Sidebar.md"]
    line = sidebar.splitlines()[1]
    shape = re.fullmatch(r"- \[((?:\\.|[^\]\\])*)\]\(Zed\)", line)
    assert shape, line
    assert "<b>" not in line and "\\]" in line
    assert [m for m in re.findall(r"(?<!\\)\]\(([^)]*)\)", line)] == ["Zed"]


# Link forms: rewritten correctly, or refused loudly. Samples are written out by hand, not derived from the script.


def home_with(tmp_path: Path, body: str, extra: dict[str, bytes] | None = None) -> Path:
    repo = make_repo(tmp_path, {"home.md": f"# H\n\n{body}\n", "alpha.md": "# A\n"})
    for rel, data in (extra or {}).items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_bytes(data)
    return repo


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('[t](alpha.md "the title")', '[t](Alpha "the title")'),
        ("[t](alpha.md 'single')", "[t](Alpha 'single')"),
        ("[t](alpha.md (paren))", "[t](Alpha (paren))"),
        ('[t](alpha.md#frag "ti")', '[t](Alpha#frag "ti")'),
        ("[x](<alpha.md>)", "[x](Alpha)"),
        ("[x](<alpha.md#f> 'T')", "[x](Alpha#f 'T')"),
        ("[`code`](alpha.md)", "[`code`](Alpha)"),
        ("[a](alpha.md) and [b](alpha.md)", "[a](Alpha) and [b](Alpha)"),
        ("[r]: alpha.md", "[r]: Alpha"),
        ('  [r2]: <alpha.md#z> "Title"', '  [r2]: Alpha#z "Title"'),
        ('<a href="alpha.md#x">t</a>', '<a href="Alpha#x">t</a>'),
        ("<a class='c' href='alpha.md'>t</a>", "<a class='c' href='Alpha'>t</a>"),
        ("[t][r]", "[t][r]"),
        ('[t](https://e.example/a.md "x")', '[t](https://e.example/a.md "x")'),
        ('<a href="https://e.example/a.md">t</a>', '<a href="https://e.example/a.md">t</a>'),
        ("[a]: https://e.example/a.md", "[a]: https://e.example/a.md"),
    ],
)
def test_link_forms_are_rewritten(tmp_path: Path, source: str, expected: str) -> None:
    text = run(home_with(tmp_path, source))["Home.md"]
    assert expected in text
    if "alpha" in source:
        assert "alpha.md" not in text


def test_images_with_local_targets_become_blob_urls(tmp_path: Path) -> None:
    repo = home_with(
        tmp_path,
        '![shot](pic.png) ![ex](../examples/p.png "cap")\n\n'
        '<img src="pic.png" alt="x">\n\n[![badge](../examples/p.png)](alpha.md)',
        {"docs/pic.png": b"x", "examples/p.png": b"y"},
    )
    text = run(repo)["Home.md"]
    blob = f"{gw.REPO_URL}/blob/{SHA}"
    assert f"![shot]({blob}/docs/pic.png?raw=true)" in text
    assert f'![ex]({blob}/examples/p.png?raw=true "cap")' in text
    assert f'<img src="{blob}/docs/pic.png?raw=true"' in text
    assert f"[![badge]({blob}/examples/p.png?raw=true)](Alpha)" in text


def test_a_missing_image_is_an_error_naming_it(tmp_path: Path) -> None:
    repo = home_with(tmp_path, "![x](nope.png)")
    with pytest.raises(gw.WikiError, match=r"nope\.png"):
        gw.generate(repo, repo / "wiki-out", SHA)


@pytest.mark.parametrize(
    "source",
    [
        "<a href=alpha.md>t</a>",
        "[t](alpha.md",
        "[t](alpha\\_x.md)",
        '[t](alpha.md "unclosed)',
        "[t](a&amp;b.md)",
        '<img srcset="alpha.md 2x">',
        "[t](",
        "[t](<alpha.md)",
        '[t](missing.md "title")',
        "[t]: missing.md",
        '<a href="missing.md">t</a>',
        '<a href="">t</a>',
        "[t]()",
    ],
)
def test_unsupported_or_broken_forms_fail_loudly(tmp_path: Path, source: str) -> None:
    repo = home_with(tmp_path, source)
    with pytest.raises(gw.WikiError):
        gw.generate(repo, repo / "wiki-out", SHA)
    assert gw.main(["--out", str(repo / "wiki-out")], root=repo) == 1


def test_a_link_split_across_lines_fails_loudly(tmp_path: Path) -> None:
    repo = home_with(tmp_path, "[t](\nalpha.md)")
    with pytest.raises(gw.WikiError):
        gw.generate(repo, repo / "wiki-out", SHA)


def test_code_is_left_alone_for_every_form(tmp_path: Path) -> None:
    body = (
        '`[a](nope.md)` `<a href="nope.md">` `[r]: nope.md`\n\n'
        '```html\n<a href="nope.md">x</a>\n[r]: nope.md\n![i](nope.png)\n```\n'
    )
    text = run(home_with(tmp_path, body))["Home.md"]
    assert body in text


def test_reading_order_follows_titled_and_angle_links(tmp_path: Path) -> None:
    home = "# H\n\n## Read in this order\n\n- [Z](<zed.md> \"t\")\n- [A](alpha.md 'x')\n- [B](board-yaml.md#f)\n"
    repo = make_repo(tmp_path, {"home.md": home, "zed.md": "# Zed\n", "alpha.md": "# A\n", "board-yaml.md": "# B\n"})
    assert re.findall(r"\]\((\S+)\)", run(repo)["_Sidebar.md"]) == ["Home", "Zed", "Alpha", "Board-yaml"]


# Round 2: the ownership record, fences, and linear scanning.


def test_a_symlinked_record_is_refused_and_its_target_never_written(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    readme = repo / "README.md"
    readme.write_bytes(b"# precious readme\n")
    (repo / ".wiki-out.gen_wiki").symlink_to(readme)
    for existing in (False, True):
        if existing:
            (repo / "wiki-out").mkdir()
        with pytest.raises(gw.WikiError, match="ownership record"):
            gw.generate(repo, repo / "wiki-out", SHA)
        assert readme.read_bytes() == b"# precious readme\n"
    assert not list((repo / "wiki-out").iterdir())


def test_a_record_that_is_not_a_regular_file_is_refused(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    (repo / ".wiki-out.gen_wiki").mkdir()
    with pytest.raises(gw.WikiError, match="ownership record"):
        gw.generate(repo, repo / "wiki-out", SHA)


def test_a_forged_record_cannot_delete_an_unrelated_file(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    publish = repo / "publish"
    publish.mkdir()
    (publish / "Notes.md").write_text("my notes")
    (repo / ".publish.gen_wiki").write_text("Notes.md\n")
    with pytest.raises(gw.WikiError, match="not written by gen_wiki"):
        gw.generate(repo, publish, SHA)
    (repo / ".publish.gen_wiki").write_text(f"gen_wiki-v1 {'0' * 64}\nNotes.md {'1' * 64}\n")
    with pytest.raises(gw.WikiError, match="not written by gen_wiki"):
        gw.generate(repo, publish, SHA)
    assert (publish / "Notes.md").read_text() == "my notes"


def test_a_modified_generated_file_stops_the_cleanup(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    run(repo)
    page = repo / "wiki-out" / "Zed.md"
    page.write_text("edited by hand")
    with pytest.raises(gw.WikiError, match="changed since"):
        gw.generate(repo, repo / "wiki-out", SHA)
    assert page.read_text() == "edited by hand" and (repo / "wiki-out" / "Home.md").exists()


def test_a_tampered_record_is_refused(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    run(repo)
    record = repo / ".wiki-out.gen_wiki"
    record.write_text(record.read_text().replace("Zed.md ", "Zed.md 0", 1))
    with pytest.raises(gw.WikiError, match="not written by gen_wiki"):
        gw.generate(repo, repo / "wiki-out", SHA)


def test_a_normal_rerun_replaces_its_own_output_and_a_symlinked_page_is_replaced_not_followed(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    first = run(repo)
    assert run(repo) == first
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched")
    (repo / "wiki-out" / "Zed.md").unlink()
    (repo / "wiki-out" / "Zed.md").symlink_to(victim)
    with pytest.raises(gw.WikiError):
        gw.generate(repo, repo / "wiki-out", SHA)
    assert victim.read_text() == "untouched"


# Fences follow CommonMark.


def render_home(tmp_path: Path, body: str) -> str:
    repo = make_repo(tmp_path, {"home.md": f"# H\n\n{body}", "alpha.md": "# A\n"})
    return run(repo)["Home.md"]


def test_a_backtick_opener_with_a_backtick_in_the_info_string_is_not_a_fence(tmp_path: Path) -> None:
    text = render_home(tmp_path, "``` bad`info\n[l](alpha.md)\n[m](alpha.md)\n")
    assert "[l](Alpha)" in text and "[m](Alpha)" in text
    assert "alpha.md" not in text.split("bad`info", 1)[1]


def test_a_tilde_opener_may_have_a_backtick_in_its_info_string(tmp_path: Path) -> None:
    text = render_home(tmp_path, "~~~ ok`info\n[l](nope.md)\n~~~\n[m](alpha.md)\n")
    assert "[l](nope.md)" in text and "[m](Alpha)" in text


def test_a_longer_closer_closes_and_a_shorter_one_does_not(tmp_path: Path) -> None:
    text = render_home(tmp_path, "```\n[a](nope.md)\n``\n[b](nope.md)\n`````\n[c](alpha.md)\n")
    assert "[a](nope.md)" in text and "[b](nope.md)" in text and "[c](Alpha)" in text


def test_a_closer_of_another_character_or_with_trailing_text_does_not_close(tmp_path: Path) -> None:
    text = render_home(tmp_path, "```\n~~~\n[a](nope.md)\n``` x\n[b](nope.md)\n```  \n[c](alpha.md)\n")
    assert "[a](nope.md)" in text and "[b](nope.md)" in text and "[c](Alpha)" in text


def test_indent_over_three_spaces_is_not_a_fence(tmp_path: Path) -> None:
    text = render_home(tmp_path, "    ```\n[a](alpha.md)\n   ```\n[b](nope.md)\n   ```\n[c](alpha.md)\n")
    assert "[a](Alpha)" in text and "[b](nope.md)" in text and "[c](Alpha)" in text


def test_an_unclosed_fence_makes_the_rest_of_the_page_code(tmp_path: Path) -> None:
    text = render_home(tmp_path, "```\n[a](nope.md)\n[b](alpha.md)\n")
    assert "[a](nope.md)" in text and "[b](alpha.md)" in text


def test_a_fence_like_line_in_a_heading_search_does_not_hide_the_title(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, {"home.md": "``` bad`info\n# Real title\n", "alpha.md": "# A\n"})
    assert run(repo)["_Sidebar.md"].splitlines()[0] == "- [Real title](Home)"


# Scanning is linear and lines are capped.


def test_pathological_lines_finish_quickly(tmp_path: Path) -> None:
    for payload in (
        "- " * 9_000,
        "-  " * 6_000 + "x",
        "> " * 9_000,
        "1. " * 6_000 + "[",
        "](" * 10_000,
        "[](" * 6_000,
        "[" * 15_000 + "](x",
        "`a" * 9_000,
        "<a href=" * 2_500,
    ):
        assert len(payload) <= gw.MAX_LINE
        repo = make_repo(tmp_path / str(abs(hash(payload))), {"home.md": f"# H\n{payload}\n"})
        started = time.monotonic()
        with contextlib.suppress(gw.WikiError):  # the point is the time taken, not the verdict
            gw.generate(repo, repo / "wiki-out", SHA)
        assert time.monotonic() - started < 3, payload[:6]


def test_a_very_long_valid_line_is_linear(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, {"home.md": "# H\n" + "[a](alpha.md) " * 1400 + "\n", "alpha.md": "# A\n"})
    started = time.monotonic()
    text = run(repo)["Home.md"]
    assert time.monotonic() - started < 3 and text.count("(Alpha)") == 1400


def test_a_line_over_the_cap_is_refused_in_and_out_of_fences(tmp_path: Path) -> None:
    for body in ("x" * 20_001, "```\n" + "x" * 20_001 + "\n```"):
        repo = make_repo(tmp_path / str(len(body)), {"home.md": f"# H\n{body}\n"})
        with pytest.raises(gw.WikiError, match="longer than 20000"):
            gw.generate(repo, repo / "wiki-out", SHA)
    repo = make_repo(tmp_path / "ok", {"home.md": "# H\n" + "x" * 20_000 + "\n"})
    assert "Home.md" in run(repo)


# Round 3: collisions ignoring case, backslash escapes.


def test_names_that_differ_only_in_case_collide_even_when_the_output_differs(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, {"home.md": "# H\n", "foo.md": "# a\n", "FOO.md": "# b\n"})
    with pytest.raises(gw.WikiError, match="ignoring case"):
        gw.generate(repo, repo / "wiki-out", SHA)
    assert not (repo / "wiki-out").exists()


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("[a\\]](alpha.md)", "[a\\]](Alpha)"),
        ("[a\\[b](alpha.md)", "[a\\[b](Alpha)"),
        ("\\[not a link](alpha.md)", "\\[not a link](alpha.md)"),
        ("\\\\[x](alpha.md)", "\\\\[x](Alpha)"),
        ("x \\] y [z](alpha.md)", "x \\] y [z](Alpha)"),
        ("\\![img](alpha.md)", "\\![img](Alpha)"),
    ],
)
def test_backslash_escapes_in_brackets(tmp_path: Path, source: str, expected: str) -> None:
    assert expected in run(home_with(tmp_path, source))["Home.md"]


# Code inside block containers.


@pytest.mark.parametrize(
    ("body", "kept", "rewritten"),
    [
        ("> ```\n> [x](nope.md)\n> ```\n\n[ok](alpha.md)\n", ["[x](nope.md)"], ["[ok](Alpha)"]),
        ("> > ```\n> > [x](nope.md)\n> > ```\n[ok](alpha.md)\n", ["[x](nope.md)"], ["[ok](Alpha)"]),
        ("> ```\n> [x](nope.md)\n[ok](alpha.md)\n", ["[x](nope.md)"], ["[ok](Alpha)"]),
        ("- ```\n  [x](nope.md)\n  ```\n- [ok](alpha.md)\n", ["[x](nope.md)"], ["[ok](Alpha)"]),
        ("1. ```\n   [x](nope.md)\n   ```\n2. [ok](alpha.md)\n", ["[x](nope.md)"], ["[ok](Alpha)"]),
        ("- item\n\n  ```\n  [x](nope.md)\n  ```\n\n[ok](alpha.md)\n", ["[x](nope.md)"], ["[ok](Alpha)"]),
        ("- a\n  - b\n\n    ~~~\n    [x](nope.md)\n    ~~~\n\n  [ok](alpha.md)\n", ["[x](nope.md)"], ["[ok](Alpha)"]),
        ("- ```\n  [x](nope.md)\n[ok](alpha.md)\n", ["[x](nope.md)"], ["[ok](Alpha)"]),
        ("> ```\n> [x](alpha.md)\n> ```\n", ["[x](alpha.md)"], []),
        ("- ```\n  [x](alpha.md)\n  ```\n", ["[x](alpha.md)"], []),
        ("para\n\n    [x](nope.md)\n\n[ok](alpha.md)\n", ["    [x](nope.md)"], ["[ok](Alpha)"]),
        ("para\n\n\t[x](nope.md)\n\n[ok](alpha.md)\n", ["\t[x](nope.md)"], ["[ok](Alpha)"]),
        ("para\n\n    [x](alpha.md)\n", ["    [x](alpha.md)"], []),
        ("para\n\n    one\n\n    [x](nope.md)\n", ["    [x](nope.md)"], []),
        ("# T\n    [x](nope.md)\n", ["    [x](nope.md)"], []),
        ("- item\n\n      [x](nope.md)\n\n- [ok](alpha.md)\n", ["      [x](nope.md)"], ["[ok](Alpha)"]),
        ("> para\n>\n>     [x](nope.md)\n", [">     [x](nope.md)"], []),
        # Not code: a paragraph continuation, a nested list, a fence indented by 4 relative to the item.
        ("para\n    [x](alpha.md)\n", [], ["    [x](Alpha)"]),
        ("- a\n  - b [x](alpha.md)\n", [], ["[x](Alpha)"]),
        ("> [r]: alpha.md\n", [], ["> [r]: Alpha"]),
        ("- [r]: alpha.md\n", [], ["- [r]: Alpha"]),
    ],
)
def test_code_inside_containers(tmp_path: Path, body: str, kept: list[str], rewritten: list[str]) -> None:
    text = render_home(tmp_path, body)
    for fragment in kept:
        assert fragment in text, fragment
    for fragment in rewritten:
        assert fragment in text, fragment


@pytest.mark.parametrize("body", ["- > ```\n  > [x](nope.md)\n  > ```\n", "1. > ~~~\n   > [x](nope.md)\n"])
def test_a_fence_in_a_quote_in_a_list_is_refused_naming_file_and_line(tmp_path: Path, body: str) -> None:
    repo = make_repo(tmp_path, {"home.md": f"# H\n\n{body}", "alpha.md": "# A\n"})
    with pytest.raises(gw.WikiError, match=r"docs/home\.md.*line 3"):
        gw.generate(repo, repo / "wiki-out", SHA)
    assert gw.main(["--out", str(repo / "wiki-out")], root=repo) == 1


def test_a_missing_target_in_code_never_aborts_and_a_live_one_beside_it_still_does(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, {"home.md": "# H\n\n    [x](nope.md)\n\n[bad](nope.md)\n"})
    with pytest.raises(gw.WikiError, match=r"nope\.md"):
        gw.generate(repo, repo / "wiki-out", SHA)


def test_a_heading_in_indented_code_is_not_the_title(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, {"home.md": "# H\n", "zed.md": "intro\n\n    # fake\n\n# Real\n"})
    assert "- [Real](Zed)" in run(repo)["_Sidebar.md"]


# The output directory is opened once and used by file descriptor, so a swap after the checks cannot redirect writes.


def snapshot(directory: Path) -> dict[str, bytes]:
    return {str(p.relative_to(directory)): p.read_bytes() for p in sorted(directory.rglob("*")) if p.is_file()}


def make_external(tmp_path: Path, *, nested: bool) -> Path:
    external = tmp_path / "external"
    target = external / "wiki-out" if nested else external
    target.mkdir(parents=True)
    for name in ("Home.md", "Zed.md", "_Sidebar.md"):
        (target / name).write_bytes(b"PRECIOUS " + name.encode())
    return external


def test_swapping_the_out_directory_for_a_symlink_after_the_checks_cannot_redirect_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_repo(tmp_path)
    (repo / "wiki-out").mkdir()
    external = make_external(tmp_path, nested=False)
    before = snapshot(external)

    def swap() -> None:
        (repo / "wiki-out").rename(repo / "moved")
        (repo / "wiki-out").symlink_to(external, target_is_directory=True)

    monkeypatch.setattr(gw, "_after_checks", swap)
    with pytest.raises(gw.WikiError, match="changed while"):
        gw.generate(repo, repo / "wiki-out", SHA)
    assert snapshot(external) == before


def test_swapping_a_parent_directory_for_a_symlink_after_the_checks_cannot_redirect_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_repo(tmp_path)
    (repo / "sub" / "wiki-out").mkdir(parents=True)
    external = make_external(tmp_path, nested=True)
    before = snapshot(external)

    def swap() -> None:
        (repo / "sub").rename(repo / "sub_moved")
        (repo / "sub").symlink_to(external, target_is_directory=True)

    monkeypatch.setattr(gw, "_after_checks", swap)
    with pytest.raises(gw.WikiError, match="changed while"):
        gw.generate(repo, repo / "sub" / "wiki-out", SHA)
    assert snapshot(external) == before


def test_swapping_the_record_for_a_symlink_after_the_checks_cannot_overwrite_its_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_repo(tmp_path)
    readme = repo / "README.md"
    readme.write_bytes(b"# readme\n")

    monkeypatch.setattr(gw, "_after_checks", lambda: (repo / ".wiki-out.gen_wiki").symlink_to(readme))
    gw.generate(repo, repo / "wiki-out", SHA)
    assert readme.read_bytes() == b"# readme\n"
    assert not (repo / ".wiki-out.gen_wiki").is_symlink()


def test_a_directory_swapped_for_a_symlink_is_also_refused_before_any_write(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    external = make_external(tmp_path, nested=True)
    (repo / "sub").symlink_to(external, target_is_directory=True)
    before = snapshot(external)
    with pytest.raises(gw.WikiError):
        gw.generate(repo, repo / "sub" / "wiki-out", SHA)
    assert snapshot(external) == before


# Round 4: code spans in linear time, and docs read by descriptor.


@pytest.mark.parametrize(
    ("body", "kept", "rewritten"),
    [
        ("``a`b[x](nope.md)`` [ok](alpha.md)", ["``a`b[x](nope.md)``"], ["[ok](Alpha)"]),
        ("`` [ok](alpha.md)", [], ["[ok](Alpha)"]),
        ("`a [ok](alpha.md)", [], ["[ok](Alpha)"]),
        ("```a`` [ok](alpha.md)", [], ["[ok](Alpha)"]),
        ("``a` [x](nope.md) `b`` [ok](alpha.md)", ["``a` [x](nope.md) `b``"], ["[ok](Alpha)"]),
        ("`one` and `[x](nope.md)` and [ok](alpha.md)", ["`[x](nope.md)`"], ["[ok](Alpha)"]),
        ("\\`[ok](alpha.md)`", [], ["[ok](Alpha)"]),
        ("`a` ``b`` ```c``` [ok](alpha.md)", ["`a` ``b`` ```c```"], ["[ok](Alpha)"]),
    ],
)
def test_code_spans_follow_commonmark(tmp_path: Path, body: str, kept: list[str], rewritten: list[str]) -> None:
    text = render_home(tmp_path, body + "\n")
    for fragment in kept + rewritten:
        assert fragment in text, fragment


def test_hostile_backtick_lines_are_scanned_in_linear_time(tmp_path: Path) -> None:
    payloads = [
        "`" * 10_000 + "a" * 10_000,
        "`" * 20_000,
        "`a" * 10_000,
        "`" + "a" * 19_999,
        "".join("`" * (i % 7 + 1) + "ab" for i in range(4_000))[:20_000],
        "`" * 5_000 + " text " * 2_500,
        "``" + "`a" * 9_990,
        "[x](" + "`" * 10_000 + "a" * 9_900,
    ]
    for number, payload in enumerate(payloads):
        assert len(payload) <= gw.MAX_LINE
        repo = make_repo(tmp_path / str(number), {"home.md": f"# H\n{payload}\n"})
        started = time.monotonic()
        with contextlib.suppress(gw.WikiError):  # the point is the time taken, not the verdict
            gw.generate(repo, repo / "wiki-out", SHA)
        assert time.monotonic() - started < 1, (number, payload[:12])


def test_other_regexes_are_linear_on_twenty_thousand_character_lines(tmp_path: Path) -> None:
    payloads = [
        "# x" + " " * 19_990 + "y",
        "# " + "a " * 9_990,
        "[" + "a" * 19_990 + "]: ",
        "[" + "\\]" * 9_990 + "]: x.md",
        "- " * 9_990 + "[r]: x",
        "-" + " " * 19_990 + "-",
        "<a " + 'href="x" ' * 2_000,
        "    " + "\t" * 19_000,
        "> " * 9_990 + "```",
        "[a](" + "(" * 19_990,
    ]
    for number, payload in enumerate(payloads):
        repo = make_repo(tmp_path / str(number), {"home.md": f"{payload}\n", "zed.md": f"{payload}\n\n# T\n"})
        started = time.monotonic()
        with contextlib.suppress(gw.WikiError):  # the point is the time taken, not the verdict
            gw.generate(repo, repo / "wiki-out", SHA)
        assert time.monotonic() - started < 1, (number, payload[:12])


def swap_to_outside(tmp_path: Path) -> Path:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "home.md").write_text("# H\nOUTSIDE-SECRET\n")
    return outside


def no_secret_anywhere(repo: Path) -> bool:
    return not any(b"OUTSIDE-SECRET" in p.read_bytes() for p in repo.rglob("*") if p.is_file() and not p.is_symlink())


def test_a_docs_file_swapped_for_a_symlink_after_the_listing_is_never_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_repo(tmp_path)
    outside = swap_to_outside(tmp_path)

    def swap() -> None:
        (repo / "docs" / "home.md").unlink()
        (repo / "docs" / "home.md").symlink_to(outside / "home.md")

    monkeypatch.setattr(gw, "_after_listing", swap)
    with pytest.raises(gw.WikiError, match=r"home\.md"):
        gw.generate(repo, repo / "wiki-out", SHA)
    assert no_secret_anywhere(repo)


def test_the_docs_directory_swapped_for_a_symlink_after_the_listing_is_never_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_repo(tmp_path)
    outside = swap_to_outside(tmp_path)

    def swap() -> None:
        (repo / "docs").rename(repo / "docs_moved")
        (repo / "docs").symlink_to(outside, target_is_directory=True)

    monkeypatch.setattr(gw, "_after_listing", swap)
    with pytest.raises(gw.WikiError, match="changed while"):
        gw.generate(repo, repo / "wiki-out", SHA)
    assert no_secret_anywhere(repo)


def test_a_docs_file_swapped_for_a_fifo_does_not_hang(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = make_repo(tmp_path)

    def swap() -> None:
        (repo / "docs" / "alpha.md").unlink()
        os.mkfifo(repo / "docs" / "alpha.md")

    monkeypatch.setattr(gw, "_after_listing", swap)
    with pytest.raises(gw.WikiError, match=r"alpha\.md"):
        gw.generate(repo, repo / "wiki-out", SHA)


def test_heading_titles_are_read_correctly(tmp_path: Path) -> None:
    repo = make_repo(
        tmp_path,
        {
            "home.md": "#  Spaced   title  ##  \n",
            "a.md": "# C#\n",
            "b.md": "#nospace\n\n#\tTabbed\n",
            "c.md": "# \n\nplain\n",
        },
    )
    sidebar = run(repo)["_Sidebar.md"]
    assert "- [Spaced   title](Home)" in sidebar and "- [C\\#](A)" not in sidebar and "- [C#](A)" in sidebar
    assert "- [Tabbed](B)" in sidebar and "- [C](C)" in sidebar
