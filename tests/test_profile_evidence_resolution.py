# SPDX-License-Identifier: MIT
"""Spec test 4: load_verified_agents resolves every pointer; strict callers fail on the same inputs."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from evdata import LESSON_HEADINGS, lessons_text, rec, repo
from localcli import cli
from profiledata import LESSON, OTHER_LESSON, claim, doc, profile, put
from safo.errors import ConfigError
from safo.evidence import VerifiedAgents, lesson_sections, load_verified_agents

BOARD = Path(__file__).parent / "data" / "board.yaml"


def copilot_cites(d: dict[str, Any], pointer: str) -> dict[str, Any]:
    profile(d, "copilot").update(status="profiled", do=[claim("Give it small pull requests.", pointer)])
    return d


def verified(path: Path) -> VerifiedAgents:
    return load_verified_agents(path, trusted=False)


def test_a_clean_file_resolves_every_pointer(tmp_path: Path) -> None:
    v = verified(repo(tmp_path))
    v.require_clean()
    assert v.errors_by_agent == {}
    fields = {r.field for r in v.resolutions}
    assert "agents.codex.profile.dont[0]" in fields and "agents.claude-haiku.profile.dont[0]" in fields
    one = next(r for r in v.resolutions if r.field == "agents.codex.profile.dont[0]")
    assert one.kind == "lessons"
    assert one.subject.startswith("Codex's sandbox cannot commit inside a git worktree")
    assert "The measured fact." in one.subject  # the heading and the first line, side by side
    assert len(one.excerpt_digest) == 64


def test_the_excerpt_digest_follows_the_lesson_text(tmp_path: Path) -> None:
    path = repo(tmp_path)
    before = next(r for r in verified(path).resolutions if r.field == "agents.codex.profile.dont[0]")
    put(tmp_path, "docs/lessons.md", lessons_text(body="A changed fact."))
    after = next(r for r in verified(path).resolutions if r.field == "agents.codex.profile.dont[0]")
    assert before.excerpt_digest != after.excerpt_digest and before.subject != after.subject


def test_a_dangling_slug_is_an_error_for_the_citing_agent_only(tmp_path: Path) -> None:
    d = doc()
    profile(d, "codex")["dont"] = [claim("Some claim.", "lessons:no-such-lesson")]
    v = verified(repo(tmp_path, d))
    assert set(v.errors_by_agent) == {"codex"}
    assert "dont[0]" in v.errors_by_agent["codex"][0] and "no-such-lesson" in v.errors_by_agent["codex"][0]
    with pytest.raises(ConfigError, match="codex"):
        v.require_clean()


def test_a_retitled_heading_dangles(tmp_path: Path) -> None:
    path = repo(
        tmp_path, lessons=["Codex's sandbox cannot commit in a worktree", OTHER_LESSON.split(":")[1].replace("-", " ")]
    )
    v = verified(path)
    assert "codex" in v.errors_by_agent


def test_headings_inside_a_code_fence_are_not_headings() -> None:
    text = "## Real\n\n```\n### Fenced heading\n```\n\n### After\n"
    assert set(lesson_sections(text)) == {"real", "after"}


def test_a_repeated_heading_gets_the_github_suffix() -> None:
    assert set(lesson_sections("### Same\n\na\n\n### Same\n\nb\n")) == {"same", "same-1"}


def test_an_atx_heading_loses_its_closing_hashes_and_a_level_one_counts() -> None:
    assert set(lesson_sections("# Top ##\n\n## Next ###  \n")) == {"top", "next"}


def test_a_hostile_heading_line_does_not_make_the_scan_quadratic() -> None:
    hostile = "# a" + " " * 300_000 + "x\n\n### Real\n\nbody\n"
    start = time.monotonic()
    sections = lesson_sections(hostile)
    assert time.monotonic() - start < 10, "a heading line of 300,000 spaces took far too long"
    assert "real" in sections and len(sections) == 1  # the long line is body text, not a heading


def test_unknown_agent_and_unknown_model_in_an_outcomes_pointer(tmp_path: Path) -> None:
    for subject, text in [("nobody", "nobody"), ("copilot/ghost", "ghost")]:
        d = copilot_cites(doc(), f"outcomes:v1:2026-10:{subject}:runs>=1")
        v = verified(repo(tmp_path, d, outcomes=[rec(1)]))
        assert set(v.errors_by_agent) == {"copilot"}, subject
        assert text in v.errors_by_agent["copilot"][0]


def test_a_known_model_layer_resolves(tmp_path: Path) -> None:
    d = copilot_cites(doc(), "outcomes:v1:2026-10:copilot/gpt-5.1:runs>=1")
    profile(d, "copilot")["models"] = {"gpt-5.1": {"status": "unmeasured"}}
    v = verified(repo(tmp_path, d, outcomes=[rec(1, model="gpt-5.1")]))
    v.require_clean()
    [r] = [x for x in v.resolutions if x.kind == "outcomes"]
    assert r.subject == "copilot/gpt-5.1 2026-10: runs = 1 (claim runs>=1 holds)"


def test_a_model_layer_claim_is_resolved_too(tmp_path: Path) -> None:
    d = doc()
    profile(d, "copilot").update(status="profiled", do=[claim("Small pull requests.", LESSON)])
    profile(d, "copilot")["models"] = {
        "gpt-5.1": {"status": "profiled", "dont": [claim("Trust its tests.", "lessons:gone")]}
    }
    v = verified(repo(tmp_path, d))
    assert set(v.errors_by_agent) == {"copilot"} and "models.gpt-5.1.dont[0]" in v.errors_by_agent["copilot"][0]


def test_an_outcomes_claim_that_is_false_or_has_no_data_is_an_error_and_says_which(tmp_path: Path) -> None:
    d = copilot_cites(doc(), "outcomes:v1:2026-10:copilot:runs>=4")
    v = verified(repo(tmp_path, d, outcomes=[rec(1), rec(2)]))
    assert "false" in v.errors_by_agent["copilot"][0] and "runs = 2" in v.errors_by_agent["copilot"][0]
    d = copilot_cites(doc(), "outcomes:v1:2026-09:copilot:runs>=0")
    v = verified(repo(tmp_path / "b", d, outcomes=[rec(1)]))
    assert "no data" in v.errors_by_agent["copilot"][0]
    d = copilot_cites(doc(), "outcomes:v1:2026-10:copilot:credits_per_run<=5")
    v = verified(repo(tmp_path / "c", d, outcomes=[rec(1)]))
    assert "no data" in v.errors_by_agent["copilot"][0]


@pytest.mark.parametrize(
    "pointer",
    [
        "outcomes:v1:2025-09..2026-10:copilot:runs>=1",  # 14 months
        "outcomes:v1:2026-10:copilot:runs",  # no operator
        "outcomes:v2:2026-10:copilot:runs>=1",
    ],
)
def test_a_range_over_twelve_months_or_a_bad_grammar_raises_from_the_loader(tmp_path: Path, pointer: str) -> None:
    path = repo(tmp_path, copilot_cites(doc(), pointer), outcomes=[rec(1)])
    with pytest.raises(ConfigError, match="copilot"):
        verified(path)


def test_a_missing_source_file_is_an_error_for_the_agents_that_cite_it(tmp_path: Path) -> None:
    v = verified(repo(tmp_path, lessons=None))
    assert set(v.errors_by_agent) == {"codex", "claude-haiku"}
    assert "lessons" in v.errors_by_agent["codex"][0]


def test_an_outcomes_pointer_with_no_outcomes_source(tmp_path: Path) -> None:
    v = verified(repo(tmp_path, copilot_cites(doc(), "outcomes:v1:2026-10:copilot:runs>=1")))
    assert set(v.errors_by_agent) == {"copilot"} and "evidence_sources.outcomes" in v.errors_by_agent["copilot"][0]


def test_an_outcomes_pointer_with_a_missing_log_file(tmp_path: Path) -> None:
    d = copilot_cites(doc(), "outcomes:v1:2026-10:copilot:runs>=1")
    v = verified(repo(tmp_path, d, sources={"outcomes": "docs/absent.jsonl"}))
    assert set(v.errors_by_agent) == {"copilot"}


def test_a_source_that_escapes_the_repository_is_refused(tmp_path: Path) -> None:
    d = doc()
    d["evidence_sources"] = {"lessons": "../lessons.md"}
    with pytest.raises(ConfigError, match=r"evidence_sources\.lessons"):
        verified(repo(tmp_path, d, lessons=None))


def test_a_symbolic_link_source_is_not_followed(tmp_path: Path) -> None:
    path = repo(tmp_path, doc(), lessons=None)
    put(tmp_path / "elsewhere", "lessons.md", lessons_text())
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "lessons.md").symlink_to(tmp_path / "elsewhere" / "lessons.md")
    assert "codex" in verified(path).errors_by_agent


def test_evidence_sources_validates_its_keys(tmp_path: Path) -> None:
    for bad in ({"other": "x"}, {"lessons": "/etc/passwd"}, {"lessons": ""}, {"outcomes": 3}, "docs/lessons.md"):
        d = doc()
        d["evidence_sources"] = bad
        with pytest.raises(ConfigError, match="evidence_sources"):
            verified(repo(tmp_path, d))


def test_an_agent_without_a_profile_is_migrating_only_while_it_is_listed(tmp_path: Path) -> None:
    import dataclasses

    v = verified(repo(tmp_path))
    assert v.status_of("claude-lead") == "migrating"
    unlisted = dataclasses.replace(v, agents=dataclasses.replace(v.agents, profile_migration=()))
    assert unlisted.status_of("claude-lead") == "unmeasured"


def test_an_empty_heading_is_not_a_lesson() -> None:
    assert lesson_sections("###  \n\nbody\n\n#\n") == {}


def test_the_local_override_cannot_carry_evidence_sources(tmp_path: Path) -> None:
    path = repo(tmp_path)
    local = tmp_path / "local.yaml"
    local.write_text("evidence_sources: {lessons: elsewhere.md}\n")
    local.chmod(0o600)
    with pytest.raises(ConfigError, match="local override"):
        load_verified_agents(path, local, trusted=False)


def test_an_invalid_outcomes_log_is_a_source_error_not_a_crash(tmp_path: Path) -> None:
    d = copilot_cites(doc(), "outcomes:v1:2026-10:copilot:runs>=1")
    path = repo(tmp_path, d, outcomes=[rec(1)])
    put(tmp_path, "docs/outcomes.jsonl", "not json\n")
    v = verified(path)
    assert set(v.errors_by_agent) == {"copilot"}


def test_verified_agents_carries_the_parsed_document(tmp_path: Path) -> None:
    v = verified(repo(tmp_path))
    assert v.agents.agent("codex").profile is not None


def test_status_of_an_agent_follows_its_errors(tmp_path: Path) -> None:
    d = doc()
    profile(d, "codex")["dont"] = [claim("Some claim.", "lessons:no-such-lesson")]
    v = verified(repo(tmp_path, d))
    assert v.status_of("codex") == "unmeasured"
    assert v.status_of("claude-haiku") == "profiled"
    assert v.status_of("claude-lead") == "migrating"
    assert v.status_of("maintainer") == "none"


# -- the strict callers fail on the same inputs ----------------------------------------------------------------


def dangling(tmp_path: Path) -> Path:
    d = doc()
    profile(d, "codex")["dont"] = [claim("Some claim.", "lessons:no-such-lesson")]
    return repo(tmp_path, d)


def test_validate_fails_on_a_dangling_pointer_and_passes_on_a_clean_file(tmp_path: Path, _private_home: Path) -> None:
    code, out, err = cli("--board", str(BOARD), "validate", "--agents", str(dangling(tmp_path)), home=_private_home)
    assert code == 2 and "no-such-lesson" in err and "configuration valid" not in out
    clean = tmp_path / "clean"
    code, out, err = cli("--board", str(BOARD), "validate", "--agents", str(repo(clean)), home=_private_home)
    assert code == 0 and "configuration valid" in out and "agents file valid" in out, err


def test_validate_without_an_agents_file_is_unchanged(_private_home: Path) -> None:
    code, out, _ = cli("--board", str(BOARD), "validate", home=_private_home)
    assert code == 0 and out.strip() == "configuration valid (offline; live board not audited)"


def test_validate_reads_the_default_home_file_when_it_exists(_private_home: Path, tmp_path: Path) -> None:
    config = _private_home / ".config" / "safo"
    config.mkdir(parents=True)
    path = dangling(tmp_path)
    put(config, "docs/lessons.md", (tmp_path / "docs" / "lessons.md").read_bytes())
    (config / "agents.yaml").write_bytes(path.read_bytes())
    (config / "agents.yaml").chmod(0o600)
    code, _, err = cli("--board", str(BOARD), "validate", home=_private_home)
    assert code == 2 and "no-such-lesson" in err


def test_verify_fails_on_the_same_dangling_input(tmp_path: Path, _private_home: Path) -> None:
    code, out, _ = cli("profiles", "verify", "--agents", str(dangling(tmp_path)), home=_private_home)
    assert code == 1 and "no-such-lesson" in out


def test_the_strict_callers_all_go_through_require_clean(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, _private_home: Path
) -> None:
    """With require_clean a no-op the strict callers go green on a dangling pointer: they rely on it alone."""
    bad = dangling(tmp_path)
    monkeypatch.setattr(VerifiedAgents, "require_clean", lambda self: None)
    code, _, _ = cli("--board", str(BOARD), "validate", "--agents", str(bad), home=_private_home)
    assert code == 0, "validate relies on require_clean and nothing else"
    code, _, _ = cli("profiles", "verify", "--agents", str(bad), home=_private_home)
    assert code == 0, "verify relies on require_clean and nothing else"


def test_the_shipped_file_resolves_against_the_shipped_lessons() -> None:
    root = Path(__file__).parent.parent
    v = load_verified_agents(root / "agents.yaml", trusted=False)
    v.require_clean()
    assert len(v.resolutions) >= 12
    assert LESSON_HEADINGS  # the fixture headings are real ones


def test_a_model_that_is_not_a_layer_is_refused_even_when_the_log_has_records_for_it(tmp_path: Path) -> None:
    d = copilot_cites(doc(), "outcomes:v1:2026-10:copilot/ghost:runs>=1")
    v = verified(repo(tmp_path, d, outcomes=[rec(1, model="ghost")]))
    assert "not a model layer" in v.errors_by_agent["copilot"][0]


def test_a_statement_that_is_not_a_metric_comparison_does_not_resolve() -> None:
    import safo.agentsfile as af
    from safo.evidence import EvidenceError, resolve_outcomes

    parsed = af.parse_agents(doc())
    with pytest.raises(EvidenceError, match="not <metric><op><number>"):
        resolve_outcomes("v1:2026-10:copilot:speed>=1", [rec(1)], parsed)


def test_an_oversize_lessons_file_or_outcomes_log_is_refused(tmp_path: Path) -> None:
    from safo.evidence import MAX_LESSONS
    from safo.outcomes import MAX_LOG_BYTES

    path = repo(tmp_path)
    put(tmp_path, "docs/lessons.md", "x" * (MAX_LESSONS + 1))
    assert "larger than" in verified(path).errors_by_agent["codex"][0]
    d = copilot_cites(doc(), "outcomes:v1:2026-10:copilot:runs>=1")
    path = repo(tmp_path / "b", d, outcomes=[rec(1)])
    put(tmp_path / "b", "docs/outcomes.jsonl", "\n" * (MAX_LOG_BYTES + 1))
    assert "larger than" in verified(path).errors_by_agent["copilot"][0]


def test_a_review_check_that_dangles_is_an_error(tmp_path: Path) -> None:
    d = doc()
    profile(d, "copilot")["review_gate"] = {
        "required": True,
        "reviewer_differs": True,
        "checks": [{"code": "test_vs_behaviour", "evidence": "lessons:gone"}],
    }
    v = verified(repo(tmp_path, d))
    assert "review_gate.checks[0]" in v.errors_by_agent["copilot"][0]


def test_headings_inside_html_comments_and_blocks_are_not_headings() -> None:
    text = (
        "<!--\n### Hidden in a comment\n-->\n\n"
        "<div>\n### Hidden heading\n</div>\n\n"
        "<!-- one line -->\n### Visible one\n\n"
        "<!--\n### Hidden again\n--!>\n\n"
        "<pre>\n### In pre\n</pre>\n\n"
        "### Visible two\n\n"
        "```\n### Fenced\n```\n"
    )
    assert set(lesson_sections(text)) == {"visible-one", "visible-two"}


def test_a_blank_line_ends_a_div_block_so_the_next_heading_counts() -> None:
    assert set(lesson_sections("<div>\ntext\n\n### After the blank\n")) == {"after-the-blank"}


def test_a_hostile_closing_hash_heading_file_is_scanned_in_linear_time() -> None:
    line = "# a" + " " * 985 + "b" + " #" * 3
    text = (line + "\n") * 3000
    start = time.monotonic()
    lesson_sections(text)
    assert time.monotonic() - start < 10
    line = "# " + "a #" * 330
    start = time.monotonic()
    lesson_sections((line + "\n") * 1000)
    assert time.monotonic() - start < 10


def test_a_closing_sequence_is_stripped_by_hand_like_commonmark() -> None:
    assert set(lesson_sections("## Foo ##   \n### Bar#\n#### Baz \\#\n##### ###\n###### x #\t\n")) == {
        "foo",
        "bar",
        "baz-",
        "x",
    }


def test_slugify_keeps_the_text_of_a_link() -> None:
    from safo.profile import slugify

    assert slugify("See [the docs](https://example.com/x) now") == "see-the-docs-now"
    assert slugify("[a](b)[c](d)") == "ac"
    assert slugify("[unclosed](") == "unclosed"
    assert slugify("[" * 5000 + "x") == "x"


@pytest.mark.parametrize(
    ("line", "text"),
    [
        ("# One", "One"),
        ("###### Six", "Six"),
        ("####### Seven", ""),
        ("#NoSpace", ""),
        ("#", ""),
        ("   ### Three spaces", "Three spaces"),
        ("    ### Four spaces", ""),
        ("## Foo#", "Foo#"),
        ("## Foo ##", "Foo"),
        ("## Foo ## x", "Foo ## x"),
        ("## ###", ""),
        ("##\tTab", "Tab"),
        ("not a heading", ""),
    ],
)
def test_heading_text(line: str, text: str) -> None:
    from safo.evidence import heading_text

    assert heading_text(line) == text
