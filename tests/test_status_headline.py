# SPDX-License-Identifier: MIT
"""status --post: counts rendered in code, optional exact validated model prose."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from agentsdata import A_MODELS, B_MODELS, write_agents
from fakegh import FakeGitHub
from fakeollama import FakeOllama
from safo.graphql import Client
from safo.modes.status import run
from test_status import ns, populate
from world import build_world, load_test_board, make_context

TEMPLATE = "2 done since 2026-10-06, 1 in progress, 2 waiting on the maintainer, 1 next."


def headline_of(fake: FakeGitHub) -> str:
    return str(fake.mutations_named("StatusUpdate")[0].variables["input"]["body"]).split("\n", 1)[0]


def post(fake: FakeGitHub, client: Client, agents: Path | str, **over: Any) -> str:
    _, project = build_world(fake)
    populate(fake, project)
    ctx, _ = make_context(fake, load_test_board(), client)
    ctx.env = {"HOME": os.environ["HOME"]}  # the private HOME every test runs with
    assert run(ctx, ns(post=True, since="2026-10-06", agents=str(agents), **over)) == 0
    return headline_of(fake)


def test_a_reachable_local_model_writes_the_headline_and_the_counts_stay_the_codes(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS[:1]).serve() as b:
        a.reply["response"] = "A steady week."
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        line = post(fake, client, agents)
        assert [g["model"] for g in a.generates] == ["small-4b-agent"] and b.generates == []
        sent = a.generates[0]
    assert line == TEMPLATE + " A steady week."
    body = fake.mutations_named("StatusUpdate")[0].variables["input"]["body"]
    assert "**Done since 2026-10-06** (2)" in body and "**Waiting on the maintainer** (2)" in body
    assert sent["think"] is False and sent["options"] == {"num_ctx": 8192}, (
        "the model's own loaded context, no thinking"
    )
    assert "Cards done since 2026-10-06: 2." in sent["prompt"]
    assert "Shipped audit" not in sent["prompt"] and "acme" not in sent["prompt"], "the model sees counts, not cards"


@pytest.mark.parametrize(
    "reply",
    [
        "7 cards were done this week.",
        "Great week, see https://example.invalid/x",
        "Thanks @octocat for the week.",
        "A line\nAnother line has the wrong 9",
        "",
        "   ",
        "x" * 200,
        "A steady week",
        "a steady week.",
        "A steady week.\r",
        "'A steady week.'",
    ],
    ids=[
        "wrong-number",
        "link",
        "mention",
        "second-line-ignored-first-wrong",
        "empty",
        "whitespace",
        "too-long",
        "no-period",
        "wrong-case",
        "carriage-return",
        "quoted",
    ],
)
def test_a_headline_that_is_not_one_plain_line_over_the_computed_counts_falls_back_to_the_template(
    fake: FakeGitHub, client: Client, tmp_path: Path, reply: str
) -> None:
    if reply.startswith("A line"):
        reply = "7 cards done\nA quiet week."
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS[:1]).serve() as b:
        a.reply["response"] = reply
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        assert post(fake, client, agents) == TEMPLATE


def test_a_two_line_answer_is_rejected_in_full(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS[:1]).serve() as b:
        a.reply["response"] = "A quiet week.\nHere is some more explanation nobody asked for."
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        assert post(fake, client, agents) == TEMPLATE


def test_an_unreachable_endpoint_gives_the_template(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    assert post(fake, client, write_agents(tmp_path / "agents.yaml")) == TEMPLATE


def test_an_endpoint_that_goes_away_mid_request_gives_the_template(
    fake: FakeGitHub, client: Client, tmp_path: Path
) -> None:
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS[:1]).serve() as b:
        a.drop_generate = True
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        assert post(fake, client, agents) == TEMPLATE
        assert len(a.generates) == 1


def test_a_missing_agents_file_gives_the_template(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    assert post(fake, client, tmp_path / "absent.yaml") == TEMPLATE


def test_no_local_asks_no_endpoint_at_all(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS[:1]).serve() as b:
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        assert post(fake, client, agents, no_local=True) == TEMPLATE
        assert a.requests == [] and b.requests == []


@pytest.mark.parametrize("failure", [OSError, TimeoutError, UnicodeError, ValueError])
def test_operational_headline_failures_fall_back(
    fake: FakeGitHub, client: Client, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: type[Exception]
) -> None:
    import safo.headline as headline

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise failure("sentinel operational detail")

    monkeypatch.setattr(headline, "load_agents_for", fail)
    assert post(fake, client, tmp_path / "agents.yaml") == TEMPLATE


def test_under_actions_no_local_model_is_ever_asked(fake: FakeGitHub, client: Client, tmp_path: Path) -> None:
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS[:1]).serve() as b:
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        _, project = build_world(fake)
        populate(fake, project)
        ctx, _ = make_context(fake, load_test_board(), client)
        ctx.env = {"HOME": os.environ["HOME"], "GITHUB_ACTIONS": "true"}
        assert run(ctx, ns(post=True, since="2026-10-06", agents=str(agents))) == 0
        assert headline_of(fake) == TEMPLATE and a.requests == [] and b.requests == []
