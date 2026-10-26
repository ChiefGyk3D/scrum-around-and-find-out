# SPDX-License-Identifier: Apache-2.0
"""The README's table of modes and the modes that exist cannot drift apart, and the docs keep their promises."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType

import pytest

from safo.modes import load_all

ROOT = Path(__file__).parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
PAGES = (
    "home",
    "why",
    "roles",
    "handoff",
    "review-loop",
    "local-llm",
    "plugins",
    "limits",
    "board",
    "agents-status",
    "usage",
    "lessons",
    "measurements",
    "adoption",
    "personas",
    "profiles",
    "orchestrator",
)
EM_DASH = "\N{EM DASH}"


def section(text: str, heading: str) -> str:
    return text.split(f"## {heading}", 1)[1].split("\n## ", 1)[0]


def readme_modes(text: str) -> set[str]:
    rows = re.finditer(r"^\| `([^`|]+)` \|", section(text, "What it does"), re.MULTILINE)
    return {m[1].split()[0] for m in rows}


def squash(text: str) -> str:
    return re.sub(r"\s+", " ", text).lower()


def public_pages() -> list[Path]:
    return [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]


def test_every_mode_in_the_readme_exists_and_every_mode_is_in_the_readme() -> None:
    assert readme_modes(README) == set(load_all())


def test_the_mode_check_bites_in_both_directions() -> None:
    extra = README.replace("| `bootstrap` |", "| `invented` | nothing |\n| `bootstrap` |", 1)
    assert readme_modes(extra) != set(load_all())
    missing = "\n".join(x for x in README.splitlines() if not x.startswith("| `audit` |"))
    assert readme_modes(missing) != set(load_all())
    with pytest.raises(IndexError):
        readme_modes("# no such section")


def test_the_readme_names_the_licence_and_where_the_playbook_starts() -> None:
    assert "Apache-2.0" in README and "docs/why.md" in README and "docs/adoption.md" in README


def test_the_status_table_matches_what_is_built() -> None:
    status = section(README, "Status")
    assert "Planned" not in status and "planned" not in status
    assert "`action.yml`" in status
    for name in load_all():
        assert name in status, name


def test_every_playbook_page_exists_and_the_home_page_links_to_each() -> None:
    home = (ROOT / "docs" / "home.md").read_text(encoding="utf-8")
    for page in PAGES:
        assert (ROOT / "docs" / f"{page}.md").is_file(), page
        if page != "home":
            assert f"({page}.md)" in home, page


@pytest.mark.parametrize("path", public_pages(), ids=lambda p: str(p.relative_to(ROOT)))
def test_no_em_dash_anywhere_in_the_public_pages(path: Path) -> None:
    assert EM_DASH not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("path", public_pages(), ids=lambda p: str(p.relative_to(ROOT)))
def test_every_relative_link_resolves(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if re.match(r"[a-z]+:", target) or target.startswith("#"):
            continue
        assert (path.parent / target.split("#", 1)[0]).exists(), f"{path.name}: {target}"


TRUST = (
    "never run untrusted code",
    "in the same job before the safo action",
    "pull_request_target",
    "in its own job with no checkout of pr code",
    "the job/runner boundary is the trust boundary",
    "a same-user process from an earlier step can mutate the action's venv",
    "read credential-step environments",
)


@pytest.mark.parametrize("name", ["README.md", "docs/limits.md", "docs/adoption.md"])
def test_the_trust_boundary_is_stated_plainly(name: str) -> None:
    text = squash((ROOT / name).read_text(encoding="utf-8"))
    for phrase in TRUST:
        assert phrase in text, f"{name}: {phrase}"


def test_the_accepted_residuals_are_written_down() -> None:
    limits = squash((ROOT / "docs" / "limits.md").read_text(encoding="utf-8"))
    for phrase in (
        "speed bump",
        "not proof",
        "(hooks.md)",
        "--agents",
        "--log",
        "current directory",
        "the user's own choice",
        "narrowed, not closed",
        "`gh` fallback is off under actions",
        "local modes are not allowed in the action",
    ):
        assert phrase in limits, phrase


def test_the_lessons_are_seeded_with_the_dated_ones() -> None:
    lessons = (ROOT / "docs" / "lessons.md").read_text(encoding="utf-8")
    for needle in ("updateProjectV2Field", "$endCursor", "createProjectV2View", "git show", "bypassForcePushActorIds"):
        assert needle in lessons, needle


def test_the_usage_page_records_that_code_counts_and_the_model_writes_prose() -> None:
    usage = squash((ROOT / "docs" / "usage.md").read_text(encoding="utf-8"))
    assert "code does the grouping and the counting" in usage


DOIA = "https://github.com/ChiefGyk3D/department-of-internal-arguments"
DOIA_ROLES = ("implementer", "reviewer", "adversarial-reviewer", "transcriber")
DOIA_PACKS = (
    "python-untrusted-input",
    "gha-security-dast",
    "threat-model",
    "rf-emcomm",
    "linux-platform",
    "local-llm-routing",
)


def load_gen_wiki() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gen_wiki_docs", ROOT / "scripts" / "gen_wiki.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN_WIKI = load_gen_wiki()
DOIA_TAG = GEN_WIKI.read_doia_tag()


def doia_links(text: str) -> list[str]:
    return re.findall(r"\]\((" + re.escape(DOIA) + r"[^)\s]*)\)", text)


def moving_doia_links(text: str) -> list[str]:
    """Links to DoIA that are not pinned at a tag: a bare repository link, or one at a branch."""
    return [x for x in doia_links(text) if not re.search(r"/(?:tree|blob)/v\d+\.\d+\.\d+(?:/|$)", x)]


def shapes_named(text: str) -> set[str]:
    names = set(re.findall(r"`([a-z]+(?:-[a-z]+)+)`", section(text, "Which routing shapes use each role")))
    return names - set(DOIA_ROLES)


def test_personas_reference_doia_at_a_tag_and_carry_no_copies() -> None:
    page = (ROOT / "docs" / "personas.md").read_text(encoding="utf-8")
    assert doia_links(page) and f"{DOIA}/tree/{DOIA_TAG}" in page
    assert moving_doia_links(page) == []
    assert not (ROOT / "examples" / "personas").exists()
    assert "examples/personas" not in "\n".join(p.read_text(encoding="utf-8") for p in public_pages())
    for old in ("disallowedTools", "model: sonnet", "model: haiku"):
        assert old not in page, old


def test_the_tag_guard_bites() -> None:
    assert moving_doia_links(f"[x]({DOIA})") == [f"{DOIA}"]
    assert moving_doia_links(f"[x]({DOIA}/tree/main)") == [f"{DOIA}/tree/main"]
    assert moving_doia_links(f"[x]({DOIA}/blob/main/README.md)")
    assert moving_doia_links(f"[x]({DOIA}/blob/v0.2.0/templates/lead.md)") == []


def test_the_pinned_doia_tag_is_one_value_and_the_page_uses_only_it() -> None:
    assert re.fullmatch(r"v\d+\.\d+\.\d+", DOIA_TAG)
    page = (ROOT / "docs" / "personas.md").read_text(encoding="utf-8")
    refs = GEN_WIKI.doia_tag_refs(page)
    assert refs, "the page names no DoIA tag at all"
    assert set(refs) == {DOIA_TAG}


def test_the_doia_tag_guard_bites() -> None:
    page = (ROOT / "docs" / "personas.md").read_text(encoding="utf-8")
    stale = page.replace(DOIA_TAG, "v0.2.0")
    assert set(GEN_WIKI.doia_tag_refs(stale)) == {"v0.2.0"}
    assert DOIA_TAG not in GEN_WIKI.doia_tag_refs(stale)
    mixed = page.replace(DOIA_TAG, "v0.2.0", 1)
    assert set(GEN_WIKI.doia_tag_refs(mixed)) == {DOIA_TAG, "v0.2.0"}
    with pytest.raises(GEN_WIKI.WikiError, match=r"v0\.2\.0"):
        GEN_WIKI.check_doia_tag({"personas.md": mixed}, DOIA_TAG)
    GEN_WIKI.check_doia_tag({"personas.md": page}, DOIA_TAG)


DOIA_URL = "https://github.com/ChiefGyk3D/department-of-internal-arguments"


@pytest.mark.parametrize(
    "text",
    [
        "DoIA v0.3.1-rc1 is out.",
        "DoIA v0.3.1.2 is out.",
        "DoIA xv0.2.0 is out.",
        "DoIA v0.3.1+build5 is out.",
        f"[x]({DOIA_URL}/tree/v0.3.1-rc1)",
        "clone --branch v0.3.1.2 here",
        "then checkout v0.2.0",
        f"[x]({DOIA_URL}/blob/v0.2.0/templates/lead.md)",
        "This page describes Department of Internal Arguments v0.2.0.",
    ],
)
def test_a_doia_reference_that_is_not_exactly_the_pin_fails(text: str) -> None:
    with pytest.raises(GEN_WIKI.WikiError, match=r"scripts/doia-tag\.txt"):
        GEN_WIKI.check_doia_tag({"personas.md": text}, "v0.3.1")


@pytest.mark.parametrize(
    "text",
    [
        "DoIA v0.3.1 is out.",
        "DoIA v0.3.1, then more.",
        "(DoIA v0.3.1) is out.",
        "DoIA v0.3.1.",
        f"[x]({DOIA_URL}/tree/v0.3.1)",
        "clone --branch v0.3.1 url",
        "-C dir checkout v0.3.1",
        "DoIA v0.3.1 needs Python v3.12.1 and uses actions/checkout@v4.1.0 from another project.",
        "Python v3.12.1 here.\n\nAnd actions/checkout@v4.1.0 there.",
        "See [other](https://github.com/example/other/tree/v9.9.9) for the other project.",
    ],
)
def test_other_versions_and_the_exact_pin_pass(text: str) -> None:
    GEN_WIKI.check_doia_tag({"personas.md": text}, "v0.3.1")


def test_a_missing_personas_page_fails_loudly_when_required() -> None:
    with pytest.raises(GEN_WIKI.WikiError, match=r"personas\.md"):
        GEN_WIKI.check_doia_tag({"home.md": "# H\n"}, "v0.3.1", require_page=True)
    GEN_WIKI.check_doia_tag({"home.md": "# H\n"}, "v0.3.1")


def test_a_renamed_page_is_still_checked() -> None:
    with pytest.raises(GEN_WIKI.WikiError, match=r"scripts/doia-tag\.txt"):
        GEN_WIKI.check_doia_tag({"people.md": "DoIA v0.2.0."}, "v0.3.1")


def test_the_build_of_this_repository_requires_the_personas_page(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "home.md").write_text("# H\n", encoding="utf-8")
    with pytest.raises(GEN_WIKI.WikiError, match=r"personas\.md"):
        GEN_WIKI.render(docs, ROOT, None)


def test_personas_describe_the_pinned_release() -> None:
    page = (ROOT / "docs" / "personas.md").read_text(encoding="utf-8")
    for phrase in (
        "claude-sonnet-5-5",
        "claude-haiku-5-5",
        "--layout user",
        "--overlay",
        "--list-managed",
        "--force-edited",
        "DoIA release v0.3.1 added measured notes",
    ):
        assert phrase in page, phrase


def test_personas_name_every_role_pack_and_the_shared_rules() -> None:
    page = (ROOT / "docs" / "personas.md").read_text(encoding="utf-8")
    for name in (*DOIA_ROLES, *DOIA_PACKS):
        assert f"`{name}`" in page, name
    for phrase in ("`MODEL:`", "blocking", "important", "minor", "never push", "templates/lead.md", "--update"):
        assert phrase in page, phrase
    assert "install.py" in page and f"--branch {DOIA_TAG}" in page


def test_every_shape_the_personas_page_names_exists_in_agents_yaml() -> None:
    import yaml

    page = (ROOT / "docs" / "personas.md").read_text(encoding="utf-8")
    real = set(yaml.safe_load((ROOT / "agents.yaml").read_text(encoding="utf-8"))["shapes"])
    named = shapes_named(page)
    assert named and named <= real, named - real
    assert shapes_named(page.replace("`adversarial-review`", "`no-such-shape`")) - real == {"no-such-shape"}


def test_the_profiles_page_describes_the_rendering_and_the_other_pages_link_to_it() -> None:
    page = squash((ROOT / "docs" / "profiles.md").read_text(encoding="utf-8"))
    for phrase in (
        "examples/harness/",
        "scripts/gen_profiles.py --check",
        "manifest",
        "body digest",
        "policy boundary",
        "not a signature",
        "make check",
        "never follows a symbolic link",
    ):
        assert phrase in page, phrase
    assert (
        "rendering profiles into instruction files" not in page
        and "not built yet" not in page.split("safo profiles brief")[0]
    )
    for name in ("personas", "limits", "routing", "home"):
        text = (ROOT / "docs" / f"{name}.md").read_text(encoding="utf-8")
        assert "(profiles.md)" in text, name


def test_the_release_checklist_runs_the_privacy_supplement() -> None:
    for name in ("privacy", "profiles"):
        text = squash((ROOT / "docs" / f"{name}.md").read_text(encoding="utf-8"))
        assert "safo_privacy_extra_file" in text and "examples/harness" in text, name
