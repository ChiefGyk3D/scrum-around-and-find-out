# SPDX-License-Identifier: Apache-2.0
"""#55: the Agent field's extended option list and the agents it names (seven in all)

Four layers, each with its own tests: the shipped boards carry the list (1), audit and bootstrap report drift on it and
never wipe a value (1), `agents-status` shows each agent's working and waiting cards and reports an Agent value the
board does not list instead of guessing (2), and the routing rules know all three newer agents (2). The docs for the
"Agents at work" view say what it groups and shows (3).
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pytest

from agentsdata import agents_dict, agents_with
from fakegh import FakeGitHub
from fakegh.core import FItem, FOption, FProject
from safo.agentsfile import KINDS, AgentsFile, load_agents, parse_agents
from safo.errors import ConfigError
from safo.graphql import Client
from safo.modes.agents_status import run as status_run
from safo.modes.audit import run as audit_run
from safo.modes.bootstrap import run as bootstrap_run
from safo.ollama import Probe
from safo.routing import CARD_LABELS, recommend
from safo.schema import Board, load_board
from world import build_world, load_test_board, make_context

ROOT = Path(__file__).parent.parent
SIEM = ROOT / "boards" / "siem-stack.board.yaml"
BOARDS = sorted((ROOT / "boards").glob("*.board.yaml"))
ORIGINAL = ("Claude", "Codex", "Copilot", "You")
EXTENDED = (*ORIGINAL, "ChatGPT", "Ollama", "RAG", "Gemini")
NEWER = ("ChatGPT", "Ollama", "RAG", "Gemini")


def agent_options(board: Board) -> tuple[str, ...]:
    field = next(f for f in board.fields if f.name == board.agents.field)
    return tuple(o.name for o in field.options)


def status_args(tmp_path: Path) -> argparse.Namespace:
    return argparse.Namespace(
        hours=12.0, codex_dir=str(tmp_path / "none"), no_codex=True, no_copilot=True, no_guard=True
    )


def shipped() -> AgentsFile:
    return load_agents(ROOT / "agents.yaml")


# 1. the schema, bootstrap and audit ----------------------------------------------------------------------------------


def test_the_shipped_boards_were_collected() -> None:
    assert len(BOARDS) == 3, "the guard below must collect the three boards"


@pytest.mark.parametrize("path", BOARDS, ids=lambda p: p.name)
def test_every_shipped_board_lists_the_extended_agent_options_in_order(path: Path) -> None:
    board = load_board(path)
    assert board.agents.field == "Agent"
    assert agent_options(board) == EXTENDED


def test_the_guard_on_the_shipped_boards_bites_when_an_option_is_missing(tmp_path: Path) -> None:
    text = SIEM.read_text(encoding="utf-8")
    cut = tmp_path / "cut.board.yaml"
    cut.write_text(re.sub(r'\n +- \{name: "RAG"[^\n]*', "", text), encoding="utf-8")
    assert agent_options(load_board(cut)) == (*ORIGINAL, "ChatGPT", "Ollama", "Gemini")


def old_project(fake: FakeGitHub, board: Board) -> tuple[FProject, FItem]:
    """The live project as it was before the three options were added, with a card holding a value."""
    _, project = build_world(fake, board)
    agent = fake.field(project, "Agent")
    agent.options = [o for o in agent.options if o.name in ORIGINAL]
    card = fake.add_content(board.repositories[0].full_name, "Issue", 1, "Keeps its value")
    item = fake.add_item(project, card, Status="In progress", Agent="Codex")
    return project, item


def test_audit_reports_the_missing_agent_options_as_drift_and_changes_nothing(fake: FakeGitHub, client: Client) -> None:
    board = load_board(SIEM)
    _, item = old_project(fake, board)
    before = dict(item.values)
    ctx, out = make_context(fake, board, client)
    assert audit_run(ctx, argparse.Namespace()) == 1
    text = out.getvalue()
    for name in NEWER:
        assert f"DRIFT   field 'Agent' lacks the option '{name}'" in text
    assert "never edits an existing field's options" in text
    assert fake.mutations == []
    assert item.values == before


def test_bootstrap_refuses_to_edit_the_agent_options_and_every_value_survives(fake: FakeGitHub, client: Client) -> None:
    board = load_board(SIEM)
    project, item = old_project(fake, board)
    before = dict(item.values)
    ctx, out = make_context(fake, board, client)
    assert bootstrap_run(ctx, argparse.Namespace()) == 1
    text = out.getvalue()
    for name in NEWER:
        assert f"REFUSED field 'Agent' lacks the option '{name}'" in text
    assert "UpdateField" not in fake.requests
    assert item.values == before
    assert [o.name for o in fake.field(project, "Agent").options] == list(ORIGINAL)


def test_a_live_option_the_board_does_not_list_is_drift_not_a_deletion(fake: FakeGitHub, client: Client) -> None:
    board = load_board(SIEM)
    _, project = build_world(fake, board)
    fake.field(project, "Agent").options.append(FOption("OPT_G", "Mistral"))
    ctx, out = make_context(fake, board, client)
    assert audit_run(ctx, argparse.Namespace()) == 1
    assert "DRIFT   field 'Agent' has the option 'Mistral', which board.yaml does not list" in out.getvalue()
    assert fake.mutations == []


def test_the_extended_list_on_the_live_project_has_no_agent_drift(fake: FakeGitHub, client: Client) -> None:
    board = load_board(SIEM)
    build_world(fake, board)
    ctx, out = make_context(fake, board, client)
    audit_run(ctx, argparse.Namespace())
    lines = out.getvalue().splitlines()
    assert any(line.startswith(("DRIFT", "NOTE", "clean")) for line in lines) or lines, "audit printed something"
    assert not [line for line in lines if line.startswith("DRIFT") and "'Agent'" in line]


# 2. agents-status ----------------------------------------------------------------------------------------------------


def siem_world(fake: FakeGitHub) -> tuple[Board, FProject]:
    board = load_board(SIEM)
    _, project = build_world(fake, board)
    return board, project


def run_status(fake: FakeGitHub, client: Client, board: Board, tmp_path: Path) -> str:
    ctx, out = make_context(fake, board, client)
    assert status_run(ctx, status_args(tmp_path)) == 0
    assert fake.mutations == []
    return out.getvalue()


def test_chatgpt_ollama_and_rag_cards_show_as_working_and_as_waiting(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    board, project = siem_world(fake)
    repo = board.repositories[0].full_name
    cards = [("ChatGPT", "In progress"), ("Ollama", "Next"), ("RAG", "In review"), ("Ollama", "Blocked")]
    for number, (agent, status) in enumerate(cards, start=1):
        card = fake.add_content(repo, "Issue", number, f"{agent} {status}")
        fake.add_item(project, card, Status=status, Agent=agent)
    text = run_status(fake, client, board, tmp_path)
    assert f"  ChatGPT      In progress  {repo}#1  ChatGPT In progress" in text
    assert f"  Ollama       Next         {repo}#2  Ollama Next" in text
    assert f"  RAG          In review    {repo}#3  RAG In review" in text
    waiting = text.split("Waiting on you", 1)[1].split("\n", 2)[1]
    assert waiting.startswith(f"  Ollama       {repo}#4  Ollama Blocked"), "a waiting card names the agent it waits on"
    assert "unknown agent" not in text.lower()


def test_an_agent_value_the_board_does_not_list_is_reported_not_guessed(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    board, project = siem_world(fake)
    fake.field(project, "Agent").options.append(FOption("OPT_G", "Mistral"))
    repo = board.repositories[0].full_name
    working = fake.add_content(repo, "Issue", 1, "Handled by someone new")
    blocked = fake.add_content(repo, "Issue", 2, "Stuck with someone new")
    plain = fake.add_content(repo, "Issue", 3, "No agent yet")
    fake.add_item(project, working, Status="In progress", Agent="Mistral")
    fake.add_item(project, blocked, Status="Blocked", Agent="Mistral")
    fake.add_item(project, plain, Status="Next")
    text = run_status(fake, client, board, tmp_path)
    assert f"  Mistral (unknown agent) In progress  {repo}#1" in text
    assert f"  Mistral (unknown agent) {repo}#2" in text
    assert "Unknown agent values (not options of Agent in board.yaml): Mistral" in text
    assert f"  unassigned   Next         {repo}#3" in text
    assert "unassigned (unknown" not in text, "a card with no agent is unassigned, not an unknown agent"


def test_a_board_with_only_listed_agents_prints_no_unknown_line(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    board, project = siem_world(fake)
    card = fake.add_content(board.repositories[0].full_name, "Issue", 1, "t")
    fake.add_item(project, card, Status="In progress", Agent="Claude")
    assert "Unknown agent values" not in run_status(fake, client, board, tmp_path)


def test_a_hostile_agent_name_is_written_escaped(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    board, project = siem_world(fake)
    hostile = "Evil\x1b[31m::error::x‮"
    fake.field(project, "Agent").options.append(FOption("OPT_H", hostile))
    card = fake.add_content(board.repositories[0].full_name, "Issue", 1, "t")
    fake.add_item(project, card, Status="In progress", Agent=hostile)
    text = run_status(fake, client, board, tmp_path)
    assert "\x1b" not in text and "‮" not in text and "::error::" not in text
    assert "\\x1b" in text and "\\u202e" in text


def test_the_note_on_agents_without_a_session_to_list_names_each_board_agent_that_has_none(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    board, _ = siem_world(fake)
    tail = run_status(fake, client, board, tmp_path).split("Subagents run inside", 1)[1]
    for name in NEWER:
        assert f"Agent = {name}" in tail


def test_the_note_names_only_agents_the_board_lists(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    board = load_test_board()  # its Agent field has Claude and Codex only
    build_world(fake, board)
    text = run_status(fake, client, board, tmp_path)
    assert "ChatGPT" not in text and "Ollama" not in text and "RAG" not in text


# 2. routing rules ----------------------------------------------------------------------------------------------------


def test_every_kind_has_a_card_label_that_is_an_option_of_the_agent_field() -> None:
    assert set(KINDS) == set(CARD_LABELS), "a kind without a card label would crash safo route"
    assert set(CARD_LABELS.values()) <= set(EXTENDED)
    assert CARD_LABELS["ollama"] == "Ollama" and CARD_LABELS["rag"] == "RAG" and CARD_LABELS["chatgpt"] == "ChatGPT"
    assert CARD_LABELS["gemini"] == "Gemini"


def test_rag_is_an_agent_with_no_endpoints_and_an_honest_unmeasured_profile() -> None:
    rag = shipped().agent("rag")
    assert rag.kind == "rag" and rag.endpoints == ()
    assert rag.profile is not None and rag.profile.status == "unmeasured"
    role = rag.role.lower()
    assert "retrieval" in role and "docs" in role and "issues" in role


def test_retrieval_work_routes_to_rag_and_the_card_says_rag() -> None:
    a = shipped()
    shape = a.shape("project-retrieval")
    assert shape.prefer == ("rag",) and shape.fallback and "rag" not in shape.fallback
    r = recommend(a, "project-retrieval", {})
    assert (r.agent, r.card_label) == ("rag", "RAG")
    assert r.reviewer and r.reviewer != "rag", "the reviewer is not the author"


def test_a_local_model_that_is_chosen_is_labeled_ollama_on_the_card() -> None:
    up = {
        "instance-a": Probe("instance-a", "http://127.0.0.1:9", True, ("small-4b-agent",), ()),
        "instance-b": Probe("instance-b", "http://127.0.0.1:9", True, (), ()),
    }
    r = recommend(agents_with(), "changelog-draft", {}, up)
    assert r.agent == "ollama" and r.card_label == "Ollama"


def test_language_work_still_routes_to_chatgpt_with_the_chatgpt_label() -> None:
    r = recommend(shipped(), "prose-in-voice", {})
    assert (r.agent, r.card_label) == ("chatgpt", "ChatGPT")


def test_an_unknown_agent_name_in_a_shape_or_a_lookup_is_refused_by_name() -> None:
    d = agents_dict()
    d["shapes"]["research"]["prefer"] = ["mistral"]
    with pytest.raises(ConfigError, match="mistral"):
        parse_agents(d)
    with pytest.raises(ConfigError, match="no agent 'mistral'"):
        parse_agents(agents_dict()).agent("mistral")


def test_an_unknown_kind_is_refused_and_a_rag_agent_may_not_have_endpoints() -> None:
    d = agents_dict()
    d["agents"]["rag"]["kind"] = "mistral"
    with pytest.raises(ConfigError, match="kind"):
        parse_agents(d)
    d = agents_dict()
    d["agents"]["rag"]["endpoints"] = d["agents"]["ollama"]["endpoints"]
    with pytest.raises(ConfigError, match="only an ollama agent has endpoints"):
        parse_agents(d)


# 3. the documentation ------------------------------------------------------------------------------------------------


def squash(text: str) -> str:
    return re.sub(r"\s+", " ", text).lower()


def test_the_agents_at_work_view_is_documented_as_grouped_by_agent_and_listing_working_and_waiting_cards() -> None:
    board_md = squash((ROOT / "docs" / "board.md").read_text(encoding="utf-8"))
    assert "## the agents at work view" in board_md
    body = board_md.split("## the agents at work view", 1)[1].split(" ## ", 1)[0]
    assert "grouped by agent" in body
    assert "every card that is not done" in body
    assert "agents.working" in body and "agents.waiting" in body
    for name in ("claude", "codex", "copilot", "chatgpt", "ollama", "rag"):
        assert name in body
    status_md = squash((ROOT / "docs" / "agents-status.md").read_text(encoding="utf-8"))
    assert "unknown agent" in status_md and "waiting on you" in status_md
