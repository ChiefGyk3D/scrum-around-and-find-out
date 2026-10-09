# SPDX-License-Identifier: MIT
"""local run: one prompt to the local LLM routing picks, never one that would evict a protected model."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsdata import A_MODELS, B_MODELS, write_agents
from fakeollama import FakeOllama
from localcli import cli, local_run


def test_local_run_sends_one_prompt_with_think_off_and_logs_the_outcome(_private_home: Path, tmp_path: Path) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("Summarise this log in one sentence.")
    log = tmp_path / "outcomes.jsonl"
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS).serve() as b:
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        code, out, _ = cli(
            "local", "run", "--shape", "ci-log-summary", "--prompt-file", str(prompt), "--agents", str(agents),
            "--log", str(log), home=_private_home,
        )  # fmt: skip
        assert code == 0, out
        assert b.generates == [] and len(a.generates) == 1, "the guard endpoint is untouched"
        body = a.generates[0]
        assert body["model"] == "small-4b-agent" and body["think"] is False and "keep_alive" not in body
        assert body["options"] == {"num_ctx": 8192}, "exactly the context the model is loaded with"
        assert body["prompt"] == "Summarise this log in one sentence."
    assert "A short answer." in out and "50 tok/s" in out
    row = json.loads(log.read_text())
    assert (row["agent"], row["shape"], row["review_rounds"], row["requests"], row["tokens"]) == (
        "ollama",
        "ci-log-summary",
        0,
        1,
        140,
    )
    assert "a draft until a Claude model reviews it" in row["note"]


def test_local_run_honours_an_explicit_think_flag(_private_home: Path, tmp_path: Path) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("x")
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS).serve() as b:
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        local_run("docs-proofread", prompt, agents, tmp_path / "o.jsonl", _private_home, "--think")
        assert a.generates[0]["think"] is True and b.generates == []


def test_local_run_never_asks_the_shared_endpoint_for_another_model(_private_home: Path, tmp_path: Path) -> None:
    """Review focus: a request that would evict a protected model is refused before anything is sent."""
    prompt = tmp_path / "p.txt"
    prompt.write_text("x")
    with FakeOllama(A_MODELS, A_MODELS).serve() as a:
        agents = write_agents(tmp_path / "agents.yaml", a.url)  # instance-b stays unreachable
        code, out, _ = cli(
            "local", "run", "--shape", "ci-log-summary", "--prompt-file", str(prompt), "--model", "small-7b",
            "--agents", str(agents), "--log", str(tmp_path / "o.jsonl"), home=_private_home,
        )  # fmt: skip
        assert code == 1 and a.generates == []
        assert "could evict a protected one" in out and "hand it to claude-haiku instead (nothing was sent)" in out
        code, out, _ = cli(
            "local", "run", "--shape", "ci-log-summary", "--prompt-file", str(prompt), "--num-ctx", "65536",
            "--agents", str(agents), "--log", str(tmp_path / "o.jsonl"), home=_private_home,
        )  # fmt: skip
        assert code == 1 and a.generates == [], "a smaller context than the loaded one would reload the model too"
    assert "num_ctx 65536 is not the 8192 small-4b-agent is loaded with" in out
    assert not (tmp_path / "o.jsonl").exists()


def test_local_run_when_the_endpoint_goes_away_mid_task_names_the_fallback(_private_home: Path, tmp_path: Path) -> None:
    """Review focus: reachable at the probe, gone by the request."""
    prompt = tmp_path / "p.txt"
    prompt.write_text("x")
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS).serve() as b:
        a.drop_generate = True
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        code, out, _ = local_run("ci-log-summary", prompt, agents, tmp_path / "o.jsonl", _private_home)
    assert code == 1 and "stopped answering" in out and "hand it to claude-haiku instead" in out
    assert not (tmp_path / "o.jsonl").exists(), "a failed request is not an outcome"


def test_local_run_rejects_a_non_local_shape_and_a_missing_prompt(_private_home: Path, tmp_path: Path) -> None:
    agents = write_agents(tmp_path / "agents.yaml")
    prompt = tmp_path / "p.txt"
    prompt.write_text("x")
    code, _, err = cli(
        "local", "run", "--shape", "research", "--prompt-file", str(prompt), "--agents", str(agents), home=_private_home
    )
    assert code == 2 and "has no local agent in its chain" in err
    code, _, err = cli(
        "local",
        "run",
        "--shape",
        "ci-log-summary",
        "--prompt-file",
        str(tmp_path / "no"),
        "--agents",
        str(agents),
        home=_private_home,
    )
    assert code == 2 and "cannot read the prompt file" in err


@pytest.mark.parametrize("case", ["dry-run", "oversized", "embedding"])
def test_local_execution_guards_precede_probes_generation_and_logging(
    _private_home: Path, tmp_path: Path, case: str
) -> None:
    prompt = tmp_path / "prompt.txt"
    prompt.write_bytes(b"a" * (1_048_577 if case == "oversized" else 1))
    log = tmp_path / "absent" / "outcomes.jsonl"
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS).serve() as b:
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        argv = ["--dry-run"] if case == "dry-run" else []
        shape = "duplicate-issue-search" if case == "embedding" else "ci-log-summary"
        code, _, _ = cli(
            *argv,
            "local",
            "run",
            "--shape",
            shape,
            "--prompt-file",
            str(prompt),
            "--agents",
            str(agents),
            "--log",
            str(log),
            home=_private_home,
        )
        assert code == (0 if case == "dry-run" else 2)
        assert a.requests == [] and b.requests == []
    assert not log.exists() and not log.parent.exists()


def test_prompt_read_is_bounded_before_rejecting_oversized_input(
    _private_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safo.bounded import read_bounded
    from safo.modes import local

    prompt = tmp_path / "oversized.txt"
    prompt.write_bytes(b"a" * 1_048_577)
    agents = write_agents(tmp_path / "agents.yaml")
    limits: list[int] = []

    def spy(path: Path, limit: int) -> bytes:
        assert 0 < limit <= 1_048_577, "unbounded prompt read"
        limits.append(limit)
        return read_bounded(path, limit)

    monkeypatch.setattr(local, "read_bounded", spy)
    code, _, _ = local_run("ci-log-summary", prompt, agents, tmp_path / "outcomes.jsonl", _private_home)
    assert code == 2 and limits == [1_048_577]
    assert not (tmp_path / "outcomes.jsonl").exists()


def test_a_prompt_that_is_a_symlink_or_a_fifo_is_refused_without_following_or_waiting(
    _private_home: Path, tmp_path: Path
) -> None:
    import os

    real = tmp_path / "real.txt"
    real.write_text("secret")
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    fifo = tmp_path / "fifo.txt"
    os.mkfifo(fifo)
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS).serve() as b:
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        for bad in (link, fifo, tmp_path):
            code, _, err = local_run("ci-log-summary", bad, agents, tmp_path / "o.jsonl", _private_home)
            assert code == 2 and "cannot read the prompt file" in err
        assert a.requests == [] and b.requests == []


def test_a_prompt_that_is_not_utf8_is_sent_with_replacement_characters(_private_home: Path, tmp_path: Path) -> None:
    prompt = tmp_path / "p.bin"
    prompt.write_bytes(b"ok \xff\xfe done")
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS).serve() as b:
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        code, _, _ = local_run("ci-log-summary", prompt, agents, tmp_path / "o.jsonl", _private_home)
        assert code == 0 and a.generates[0]["prompt"] == "ok \ufffd\ufffd done"


def test_the_models_answer_cannot_start_a_workflow_command(_private_home: Path, tmp_path: Path) -> None:
    prompt = tmp_path / "p.txt"
    prompt.write_text("x")
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS).serve() as b:
        a.reply["response"] = "hello\n::set-output name=x::y\n::error::boom\x1b[31m"
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        code, out, _ = local_run("ci-log-summary", prompt, agents, tmp_path / "o.jsonl", _private_home)
    assert code == 0 and "\x1b" not in out
    opener, closer = out.index("::stop-commands::"), out.rindex("::")
    for needle in ("::set-output", "::error::boom"):
        assert opener < out.index(needle) < closer, "the command text appears only inside the stop-commands block"
    assert out.count("::stop-commands::") == 1


def test_local_run_under_actions_refuses_an_outcomes_log_in_the_workspace(_private_home: Path, tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    prompt = tmp_path / "p.txt"
    prompt.write_text("x")
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS).serve() as b:
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        env = {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(ws)}
        code, _, err = cli(
            "local", "run", "--shape", "ci-log-summary", "--prompt-file", str(prompt), "--agents", str(agents),
            "--log", str(ws / "o.jsonl"), home=_private_home, extra_env=env,
        )  # fmt: skip
        assert code == 2 and "GITHUB_WORKSPACE" in err and a.generates == []
