# SPDX-License-Identifier: Apache-2.0
"""The manifest and body digests (spec 8.13): each input moves the manifest, and a hand edit moves the body digest."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

import safo.profile_render as pr
from profiledata import claim
from renderdata import PERSONA, TEMPLATE, profile_of, verified, with_profile
from safo.evidence import VerifiedAgents
from safo.profile_render import compare, manifest_digest, render_harness

CODEX = "codex/codex.prompt.md"
CLAUDE = "claude/claude-sonnet.md"


def digest(v: VerifiedAgents, path: str) -> str:
    r = render_harness(v)[path]
    return r.manifest


def test_the_manifest_digest_is_stable_across_renders(tmp_path: Path) -> None:
    assert digest(verified(tmp_path / "a"), CODEX) == digest(verified(tmp_path / "b"), CODEX)


def test_only_a_persona_changes_the_manifest(tmp_path: Path) -> None:
    base = verified(tmp_path / "a")
    other = verified(tmp_path / "b", persona=PERSONA.replace("Find what", "Look for what"))
    assert digest(base, CLAUDE) != digest(other, CLAUDE)
    assert digest(base, CODEX) == digest(other, CODEX)  # another agent's manifest does not move


def test_only_a_template_changes_the_manifest(tmp_path: Path) -> None:
    base = verified(tmp_path / "a")
    other = verified(tmp_path / "b", template=TEMPLATE.replace("Work from", "Start from"))
    assert digest(base, CODEX) != digest(other, CODEX)
    assert digest(base, CLAUDE) == digest(other, CLAUDE)


def test_only_the_output_path_changes_the_manifest(tmp_path: Path) -> None:
    v = verified(tmp_path)
    agent = v.agents.agent("codex")
    assert manifest_digest("codex/codex.prompt.md", "codex", agent, v.resolutions) != manifest_digest(
        "codex/renamed.prompt.md", "codex", agent, v.resolutions
    )


def test_only_the_harness_changes_the_manifest(tmp_path: Path) -> None:
    v = verified(tmp_path)
    agent = v.agents.agent("codex")
    assert manifest_digest("p.md", "codex", agent, v.resolutions) != manifest_digest(
        "p.md", "local", agent, v.resolutions
    )


def test_only_render_format_changes_the_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    v = verified(tmp_path)
    before = digest(v, CODEX)
    monkeypatch.setattr(pr, "RENDER_FORMAT", pr.RENDER_FORMAT + 1)
    assert digest(v, CODEX) != before


def test_only_the_renderer_version_changes_the_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    v = verified(tmp_path)
    before = digest(v, CODEX)
    monkeypatch.setattr(pr, "__version__", "9.9.9")
    assert digest(v, CODEX) != before


def test_only_profile_text_changes_the_manifest(tmp_path: Path) -> None:
    v = verified(tmp_path)
    p = profile_of(v, "codex")
    changed = with_profile(v, "codex", dont=(replace(p.dont[0], text="Expect it to commit sometimes."),))
    assert digest(v, CODEX) != digest(changed, CODEX)


def test_only_a_resolved_evidence_record_changes_the_manifest(tmp_path: Path) -> None:
    v = verified(tmp_path)
    moved = tuple(
        replace(r, excerpt_digest="0" * 64) if r.field == "agents.codex.profile.dont[0]" else r for r in v.resolutions
    )
    assert any(a != b for a, b in zip(moved, v.resolutions, strict=True))
    assert digest(v, CODEX) != digest(replace(v, resolutions=moved), CODEX)
    other_agent = tuple(
        replace(r, excerpt_digest="0" * 64) if r.field.startswith("agents.ollama.") else r for r in v.resolutions
    )
    assert digest(v, CODEX) == digest(
        replace(v, resolutions=other_agent), CODEX
    )  # evidence of another agent: no change


def test_only_the_agent_model_changes_the_manifest(tmp_path: Path) -> None:
    v = verified(tmp_path)
    haiku = v.agents.agent("claude-haiku")
    assert manifest_digest("p.md", "claude", haiku, v.resolutions) != manifest_digest(
        "p.md", "claude", replace(haiku, model="opus"), v.resolutions
    )


def test_a_hand_edit_of_the_body_that_keeps_the_header_is_a_body_digest_failure(tmp_path: Path) -> None:
    r = render_harness(verified(tmp_path))[CODEX]
    edited = r.data.replace(b"Prepend this preamble", b"Ignore this preamble")
    assert edited != r.data
    problems = compare(r, edited)
    assert len(problems) == 1 and "body digest" in problems[0] and "edited" in problems[0]
    assert compare(r, r.data) == []


def test_an_edit_of_only_the_front_matter_tools_is_a_body_digest_failure(tmp_path: Path) -> None:
    r = render_harness(verified(tmp_path))[CLAUDE]
    edited = r.data.replace(b"tools: Read, Grep, Glob", b"tools: Bash")
    assert edited != r.data
    problems = compare(r, edited)
    assert len(problems) == 1 and "body digest" in problems[0]


def test_a_stale_manifest_means_the_sources_changed(tmp_path: Path) -> None:
    r = render_harness(verified(tmp_path / "a"))[CODEX]
    newer = render_harness(verified(tmp_path / "b", template=TEMPLATE.replace("Work from", "Start from")))[CODEX]
    problems = compare(newer, r.data)  # an old file (consistent with itself) against the new render
    assert any("manifest digest" in p and "sources changed" in p for p in problems)
    assert not any("body digest" in p for p in problems)


def test_a_file_whose_digests_were_recomputed_after_an_edit_still_differs_from_the_render(tmp_path: Path) -> None:
    r = render_harness(verified(tmp_path))[CODEX]
    body, _, _ = pr.split_header(CODEX, r.data)
    forged_body = body.replace(b"Prepend this", b"Skip this")
    assert forged_body != body
    found = re.search(rb"<!-- GENERATED[^\n]*-->", r.data)
    assert found
    line = re.sub(
        rb"body sha256:[0-9a-f]{64}", b"body sha256:" + hashlib.sha256(forged_body).hexdigest().encode(), found.group(0)
    )
    forged = line + b"\n" + forged_body  # a file whose digests were rewritten to match its edited text
    assert pr.split_header(CODEX, forged)[0] == forged_body
    problems = compare(r, forged)
    assert len(problems) == 1 and "differs from the render" in problems[0]


BAD_HEADERS: list[tuple[Callable[[bytes], bytes], str]] = [
    (lambda d: d.replace(b"<!-- GENERATED", b"<!-- GENERATEd", 1), "has no generated header"),
    (lambda d: b"\n" + d, "malformed or not where its format puts it"),
    (
        lambda d: d + b"<!-- GENERATED by scripts/gen_profiles.py from agents.yaml; do not edit -->\n",
        "more than one generated header",
    ),
    (lambda d: re.sub(rb"manifest sha256:[0-9a-f]{64}", b"manifest sha256:zz", d), "malformed"),
    (lambda d: d.replace(b"; body sha256:", b"; body sha255:"), "malformed"),
    (lambda d: b"", "has no generated header"),
]


@pytest.mark.parametrize("mutate,message", BAD_HEADERS)
def test_a_missing_misplaced_duplicated_or_malformed_header_is_reported(
    tmp_path: Path, mutate: Callable[[bytes], bytes], message: str
) -> None:
    r = render_harness(verified(tmp_path))[CODEX]
    problems = compare(r, mutate(r.data))
    assert len(problems) == 1 and message in problems[0]


def test_a_header_inside_the_body_of_a_claude_file_does_not_count_as_the_header(tmp_path: Path) -> None:
    r = render_harness(verified(tmp_path))[CLAUDE]
    header = re.search(rb"<!-- GENERATED[^\n]*-->\n", r.data)
    assert header
    moved = r.data.replace(header.group(0), b"") + header.group(0)
    problems = compare(r, moved)
    assert len(problems) == 1 and "header" in problems[0]


def test_claim_helper_is_importable() -> None:
    assert claim("x")["text"] == "x"
