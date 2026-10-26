# SPDX-License-Identifier: Apache-2.0
"""Caller guidance and model instructions are two files from one source, and they compose (issue #107).

The positive tests state what each file must hold from the profile itself, not from the composition check, so a check
that passes everything would still fail here. The negative tests tamper with a render and prove each guard bites.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from gendata import ROOT, scratch
from renderdata import verified, with_profile
from safo.evidence import VerifiedAgents, load_verified_agents
from safo.profile import BOUNDARY_PARAGRAPH
from safo.profile_compose import caller_path, composition_problems
from safo.profile_render import (
    CALL_SETTING,
    CALLER_USE,
    REVIEW_WORDING,
    TRACKING_RULE,
    UNMEASURED_LINE,
    Rendered,
    render_harness,
)

HARNESS = {"claude": "claude", "codex": "codex", "ollama": "local", "copilot": "copilot"}


def text(files: dict[str, Rendered], path: str) -> str:
    return " ".join(files[path].data.decode("utf-8").split())


def model_path(files: dict[str, Rendered], agent_id: str) -> str:
    return next(p for p, r in files.items() if r.agent_id == agent_id and r.role == "model" and not p.endswith(".yml"))


def tamper(files: dict[str, Rendered], path: str, edit: Callable[[str], str]) -> dict[str, Rendered]:
    """The same render with one file's text edited (the digests are stale, which the composition check ignores)."""
    out = dict(files)
    out[path] = replace(files[path], data=edit(files[path].data.decode("utf-8")).encode("utf-8"))
    return out


def shipped() -> VerifiedAgents:
    v = load_verified_agents(ROOT / "agents.yaml", None, trusted=False)
    v.require_clean()
    return v


@pytest.fixture
def fixture_v(tmp_path: Path) -> VerifiedAgents:
    return verified(tmp_path)


# -- both outputs come from the same source ------------------------------------------------------------------------


def test_the_shipped_profiles_compose() -> None:
    v = shipped()
    files = render_harness(v)
    assert any(r.role == "caller" for r in files.values()), "the shipped profiles render a caller file"
    assert composition_problems(v, files) == []


def test_the_fixture_composes_in_both_copilot_modes(fixture_v: VerifiedAgents, tmp_path: Path) -> None:
    assert composition_problems(fixture_v, render_harness(fixture_v)) == []
    review = with_profile(verified(tmp_path / "r"), "copilot", harness_mode="review")
    assert composition_problems(review, render_harness(review)) == []


def test_every_profiled_agent_has_exactly_one_model_file_and_one_caller_file(fixture_v: VerifiedAgents) -> None:
    files = render_harness(fixture_v)
    for agent in fixture_v.agents.agents:
        if agent.profile is None:
            continue
        mine = [r for r in files.values() if r.agent_id == agent.id and not r.path.endswith(".yml")]
        assert sorted(r.role for r in mine) == ["caller", "model"], agent.id
        assert caller_path(HARNESS[agent.kind], agent.id) in files


# -- required sections, derived from the profile -------------------------------------------------------------------


def test_every_caller_section_the_profile_requires_is_in_the_caller_file(fixture_v: VerifiedAgents) -> None:
    files = render_harness(fixture_v)
    checked = 0
    for agent in fixture_v.agents.agents:
        p = agent.profile
        if p is None:
            continue
        c = text(files, caller_path(HARNESS[agent.kind], agent.id))
        for claim in (*p.do, *p.dont):
            assert claim.text in c and claim.evidence.raw in c
            checked += 1
        for shape in p.must_not_get:
            assert shape.shape in c and shape.evidence.raw in c
        for x in (p.context_ceiling, p.output_cap, p.thinking):
            if x is not None:
                assert x.evidence.raw in c
        if p.review_gate is not None:
            assert "### Review gate" in c and all(k.evidence.raw in c for k in p.review_gate.checks)
        for name, _layer in p.models:
            assert f"### Model layer: {name}" in c
        if p.status == "unmeasured":
            assert UNMEASURED_LINE in c
        assert CALLER_USE[HARNESS[agent.kind]].format(model=model_path(files, agent.id)) in c
    assert checked >= 4


def test_every_model_instruction_the_profile_requires_is_in_the_model_file(fixture_v: VerifiedAgents) -> None:
    files = render_harness(fixture_v)
    briefs = 0
    for agent in fixture_v.agents.agents:
        p = agent.profile
        if p is None:
            continue
        m = text(files, model_path(files, agent.id))
        assert " ".join(BOUNDARY_PARAGRAPH.split()) in m
        if p.brief is not None and (p.brief.inline or p.brief.template_text).strip():
            assert " ".join((p.brief.inline or p.brief.template_text).split()) in m
            briefs += 1
        if agent.kind in ("claude", "codex"):
            assert TRACKING_RULE in m
    assert briefs >= 3


def test_no_caller_text_is_in_a_model_file_and_no_model_text_is_in_a_caller_file(fixture_v: VerifiedAgents) -> None:
    files = render_harness(fixture_v)
    for agent in fixture_v.agents.agents:
        p = agent.profile
        if p is None:
            continue
        m, c = text(files, model_path(files, agent.id)), text(files, caller_path(HARNESS[agent.kind], agent.id))
        for claim in (*p.do, *p.dont):
            assert claim.text not in m and claim.text not in " ".join(BOUNDARY_PARAGRAPH.split()), agent.id
        assert UNMEASURED_LINE not in m and "(`lessons:" not in m and "think=" not in m
        assert " ".join(BOUNDARY_PARAGRAPH.split()) not in c and TRACKING_RULE not in c
        if p.brief is not None and p.brief.inline:
            assert p.brief.inline not in c


def test_the_review_wording_is_the_models_in_review_mode_and_the_callers_otherwise(tmp_path: Path) -> None:
    wording = REVIEW_WORDING["test_vs_behaviour"]
    issue = render_harness(verified(tmp_path / "i"))
    review = render_harness(with_profile(verified(tmp_path / "r"), "copilot", harness_mode="review"))
    assert wording in text(issue, "caller/copilot/copilot.md") and wording not in text(
        issue, "copilot/copilot-instructions.md"
    )
    assert wording in text(review, "copilot/copilot-instructions.md") and wording not in text(
        review, "caller/copilot/copilot.md"
    )


# -- the guards bite (each one is a tampered render) ---------------------------------------------------------------


def problems_after(v: VerifiedAgents, path: str, edit: Callable[[str], str]) -> list[str]:
    return composition_problems(v, tamper(render_harness(v), path, edit))


def test_caller_text_added_to_a_model_file_is_a_leak(fixture_v: VerifiedAgents) -> None:
    out = problems_after(fixture_v, "codex/codex.prompt.md", lambda t: t + "\nGive it a self-contained prompt.\n")
    assert any("caller-only text leaked into the model file" in x for x in out), out


def test_an_evidence_pointer_in_a_model_file_is_flagged(fixture_v: VerifiedAgents) -> None:
    out = problems_after(fixture_v, "local/ollama.wrapper.txt", lambda t: t + "\nSee (`lessons:anything`)\n")
    assert any("evidence pointer is in the model file" in x for x in out), out


def test_the_call_setting_in_the_model_file_is_a_leak(fixture_v: VerifiedAgents) -> None:
    out = problems_after(
        fixture_v, "local/ollama.wrapper.txt", lambda t: t + "\n" + CALL_SETTING.format(flag="false") + "\n"
    )
    assert any("leaked into the model file" in x for x in out), out


def test_a_caller_section_heading_in_a_model_file_is_flagged(fixture_v: VerifiedAgents) -> None:
    out = problems_after(fixture_v, "codex/codex.prompt.md", lambda t: t + "\n### Limits\n")
    assert any("caller section heading in the model file" in x for x in out), out


def test_model_text_added_to_a_caller_file_is_a_leak(fixture_v: VerifiedAgents) -> None:
    out = problems_after(fixture_v, "caller/codex/codex.md", lambda t: t + "\n" + TRACKING_RULE + "\n")
    assert any("model instruction leaked into the caller file" in x for x in out), out
    out = problems_after(fixture_v, "caller/claude/claude-haiku.md", lambda t: t + "\n" + BOUNDARY_PARAGRAPH + "\n")
    assert any("model instruction leaked into the caller file" in x for x in out), out


def test_the_brief_in_a_caller_file_is_a_leak(fixture_v: VerifiedAgents) -> None:
    out = problems_after(fixture_v, "caller/local/ollama.md", lambda t: t + "\nAnswer in the format asked for.\n")
    assert any("model instruction leaked into the caller file" in x for x in out), out


def test_a_model_section_heading_in_a_caller_file_is_flagged(fixture_v: VerifiedAgents) -> None:
    out = problems_after(fixture_v, "caller/codex/codex.md", lambda t: t + "\n### Brief\n")
    assert any("model section heading in the caller file" in x for x in out), out


def test_a_missing_caller_section_is_reported(fixture_v: VerifiedAgents) -> None:
    out = problems_after(fixture_v, "caller/codex/codex.md", lambda t: t.replace("### Do not", "### Dont"))
    assert any("required caller section '### Do not' is missing" in x for x in out), out


def test_a_dropped_caller_claim_is_reported(fixture_v: VerifiedAgents) -> None:
    out = problems_after(fixture_v, "caller/local/ollama.md", lambda t: t.replace("Treat its output as a draft.", ""))
    assert any("required caller text is missing" in x for x in out), out


def test_a_missing_model_instruction_is_reported(fixture_v: VerifiedAgents) -> None:
    out = problems_after(fixture_v, "codex/codex.prompt.md", lambda t: t.replace("Work from this prompt alone.", ""))
    assert any("required model text is missing" in x for x in out), out
    out = problems_after(fixture_v, "claude/claude-haiku.md", lambda t: t.replace("No hidden work", "Hidden work"))
    assert any("required model text is missing" in x for x in out), out


def test_a_missing_or_orphan_caller_file_is_reported(fixture_v: VerifiedAgents) -> None:
    files = render_harness(fixture_v)
    gone = {k: r for k, r in files.items() if k != "caller/codex/codex.md"}
    assert any("codex: the caller file of the pair is missing" in x for x in composition_problems(fixture_v, gone))
    orphan = {**files, "caller/codex/other.md": files["caller/codex/codex.md"]}
    assert any("no model file to pair with" in x for x in composition_problems(fixture_v, orphan))
    nomodel = {k: r for k, r in files.items() if k != "codex/codex.prompt.md"}
    assert any("model file of the pair is missing" in x for x in composition_problems(fixture_v, nomodel))


def test_the_header_is_the_one_line_both_files_carry(fixture_v: VerifiedAgents) -> None:
    files = render_harness(fixture_v)
    for agent in ("codex", "ollama"):
        m, c = (
            files[model_path(files, agent)],
            files[caller_path(HARNESS[next(a.kind for a in fixture_v.agents.agents if a.id == agent)], agent)],
        )
        assert m.data.count(b"GENERATED by scripts/gen_profiles.py") == 1
        assert c.data.count(b"GENERATED by scripts/gen_profiles.py") == 1
    assert composition_problems(fixture_v, files) == []


# -- the generator refuses a render that does not compose, in both modes -------------------------------------------


def test_the_generator_refuses_to_write_or_pass_files_that_do_not_compose(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = scratch(tmp_path, monkeypatch)
    assert script.main(["--write"]) == 0
    real = script.render_harness

    def leaky(v: VerifiedAgents) -> dict[str, Rendered]:
        files = real(v)
        return tamper(files, "codex/codex.prompt.md", lambda t: t + "\nGive it a self-contained prompt.\n")

    monkeypatch.setattr(script, "render_harness", leaky)
    capsys.readouterr()
    assert script.main(["--check"]) == 1
    err = capsys.readouterr().err
    assert "leaked into the model file" in err and "do not compose" in err
    before = {p: p.read_bytes() for p in out.rglob("*") if p.is_file()}
    assert script.main(["--write"]) == 1
    assert {p: p.read_bytes() for p in out.rglob("*") if p.is_file()} == before, "nothing is written when it fails"
