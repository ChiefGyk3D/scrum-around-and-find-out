# SPDX-License-Identifier: Apache-2.0
"""Gemini in the roster (#200, #196): a free-only provider for public-material research, never for private work."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from safo.agentsfile import KINDS, AgentsFile, load_agents
from safo.gemini import VENDOR_HOST, parse_config
from safo.routing import CARD_LABELS, recommend
from safo.schema import load_board

ROOT = Path(__file__).parent.parent
BOARDS = sorted((ROOT / "boards").glob("*.board.yaml"))
SHAPE = "public-source-research"


def shipped() -> AgentsFile:
    return load_agents(ROOT / "agents.yaml")


def squash(text: str) -> str:
    return re.sub(r"\s+", " ", text).lower()


def test_gemini_is_a_kind_with_a_card_label() -> None:
    assert "gemini" in KINDS and CARD_LABELS["gemini"] == "Gemini"


def test_the_agent_is_free_only_for_public_material_and_says_how_it_stops() -> None:
    gemini = shipped().agent("gemini")
    assert gemini.kind == "gemini" and gemini.endpoints == ()
    assert gemini.profile is not None and gemini.profile.status == "unmeasured"
    text = squash(" ".join([gemini.role, *gemini.constraints, *gemini.strengths, *(v for _, v in gemini.limits)]))
    for phrase in (
        "public",
        "free",
        "training",
        "429",
        "never falls through",
        "approval record",
        "paid use is disabled",
        "2 usd",
        "10 usd",
        "image generation is paid",
        "private",
        "adversarial",
    ):
        assert phrase in text, phrase


def test_public_source_research_routes_to_gemini_with_a_claude_review() -> None:
    doc = shipped()
    shape = doc.shape(SHAPE)
    assert shape.prefer == ("gemini",) and "gemini" not in shape.fallback
    assert shape.fallback, "a fallback exists for when the free quota is spent"
    r = recommend(doc, SHAPE, {})
    assert (r.agent, r.card_label) == ("gemini", "Gemini")
    assert r.reviewer and r.reviewer != "gemini"
    assert "claude-sonnet" in shape.reviewer
    note = squash(shape.note)
    assert "public" in note and "source" in note


def test_gemini_is_in_no_other_chain() -> None:
    doc = shipped()
    others = {s.name: s.chain + s.reviewer for s in doc.shapes if s.name != SHAPE}
    assert len(others) >= 15, "the guard collected the other shapes"
    assert [name for name, chain in others.items() if "gemini" in chain] == []


def test_the_guard_bites_when_gemini_is_added_to_a_private_shape() -> None:
    chain = {"security-sensitive-code": ("claude-sonnet", "gemini")}
    assert [n for n, c in chain.items() if "gemini" in c] == ["security-sensitive-code"]


@pytest.mark.parametrize("path", BOARDS, ids=lambda p: p.name)
def test_every_shipped_board_lists_the_gemini_option_after_rag(path: Path) -> None:
    board = load_board(path)
    field = next(f for f in board.fields if f.name == board.agents.field)
    names = [o.name for o in field.options]
    assert names[-2:] == ["RAG", "Gemini"]


def test_the_example_files_list_the_gemini_option() -> None:
    for name in ("examples/safo.yaml", "examples/renegade-penguin.yaml"):
        assert "name: Gemini" in (ROOT / name).read_text(encoding="utf-8"), name


def test_the_gemini_page_states_the_gates_and_is_linked() -> None:
    page = squash((ROOT / "docs" / "gemini.md").read_text(encoding="utf-8"))
    for phrase in (
        "free-only",
        "public material",
        "used for training",
        "429",
        "never falls through to paid",
        "approval record",
        "signed approval",
        "hardware",
        "single-use",
        "2 usd per job",
        "10 usd per month",
        "ledger",
        "midnight pacific",
        "price_checked",
        "redirect",
        "not replayed",
        "doppler",
        "prd_paid",
        "image generation is paid-only",
        "safo gemini approve",
        "same user",
        "social engineering",
        "terminal",
        "fixed locations",
        "private terms",
    ):
        assert phrase in page, phrase
    routing = (ROOT / "docs" / "routing.md").read_text(encoding="utf-8")
    assert "gemini.md" in routing and "public-source-research" in routing
    hooks = squash((ROOT / "docs" / "hooks.md").read_text(encoding="utf-8"))
    assert "gemini-paid" in hooks and "gemini-material" in hooks and "even in warn mode" in hooks
    assert "not a sandbox" in hooks and "raw sdk use" in hooks


def test_the_example_config_parses_with_the_vendor_endpoint_and_tiny_free_limits() -> None:
    data = yaml.safe_load((ROOT / "examples" / "gemini.example.yaml").read_text(encoding="utf-8"))
    cfg = parse_config(data, "example", Path("/nonexistent"))
    assert cfg.endpoint == f"https://{VENDOR_HOST}" and cfg.job_cap == 2 and cfg.month_cap == 10
    assert cfg.free and all(f.rpm == 1 and f.rpd == 1 for f in cfg.free.values()), "an uncopied example cannot overrun"
    assert set(cfg.free) <= set(cfg.prices)
    assert str(cfg.ledger).endswith("gemini-spend-ledger.jsonl")


def test_the_docs_are_honest_about_the_guard_and_the_terms() -> None:
    hooks = squash((ROOT / "docs" / "hooks.md").read_text(encoding="utf-8"))
    gemini = squash((ROOT / "docs" / "gemini.md").read_text(encoding="utf-8"))
    assert "the gemini rules do not fail open" in hooks and "denied** with the diagnostic kept" in hooks
    assert "an unreadable event that carries a gemini marker is denied" in gemini
    assert "above 1 mib the whole hook fails open" not in hooks + gemini
    assert "safo_privacy_extra_file`, else" not in hooks and "no environment variable changes it" in hooks
    assert "that is the whole claim" in hooks and "is not seen" in hooks
    assert "cannot hide its name" not in hooks + gemini and "fails closed on shell forms" not in gemini
    assert "killed after a few seconds" in gemini and "multiply to more than 10000" in gemini
    assert "child process" in gemini
