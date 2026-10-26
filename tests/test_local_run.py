# SPDX-License-Identifier: Apache-2.0
"""local run: one prompt to the local LLM routing picks, never one that would evict a protected model."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentsdata import A_MODELS, B_MODELS, write_agents
from fakeollama import OMIT, FakeOllama
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
    assert row["model"] == "small-4b-agent", "the model is a field, not only words in the note"


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


def _run_answering(home: Path, tmp_path: Path, answered: object) -> tuple[int, str, Path]:
    prompt = tmp_path / "p.txt"
    prompt.write_text("x")
    log = tmp_path / "o.jsonl"
    with FakeOllama(A_MODELS, A_MODELS).serve() as a, FakeOllama(B_MODELS, B_MODELS).serve() as b:
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        a.answer_model = answered
        code, out, _ = local_run("ci-log-summary", prompt, agents, log, home)
    return code, out, log


def test_the_implicit_latest_tag_is_the_same_model(_private_home: Path, tmp_path: Path) -> None:
    code, _, log = _run_answering(_private_home, tmp_path, "small-4b-agent:latest")
    assert code == 0 and json.loads(log.read_text())["model"] == "small-4b-agent", "the routed name is recorded"


@pytest.mark.parametrize(
    "answered",
    ["other-model", "small-4b-agent:7b", "small-4b-agent-8b", "resident-12b-thinking", "SMALL-4B-AGENT",
     "small-4b-agent:latest:latest", "small-4b-agent:Latest", ":latest", "latest"],
)  # fmt: skip
def test_a_different_reported_model_fails_closed_and_writes_nothing(
    _private_home: Path, tmp_path: Path, answered: str
) -> None:
    code, out, log = _run_answering(_private_home, tmp_path, answered)
    assert code == 3 and "model mismatch" in out and "small-4b-agent" in out
    assert "A short answer." not in out and not log.exists()


@pytest.mark.parametrize("answered", ["", None, OMIT, 5, ["small-4b-agent"], {"n": 1}, True])
def test_no_usable_reported_model_fails_closed_and_is_never_replaced_by_the_request(
    _private_home: Path, tmp_path: Path, answered: object
) -> None:
    code, out, log = _run_answering(_private_home, tmp_path, answered)
    assert code == 3 and "reported no model" in out and "A short answer." not in out and not log.exists()


def test_a_hostile_reported_name_is_escaped_and_capped_in_the_error(_private_home: Path, tmp_path: Path) -> None:
    hostile = "x\ny\x1b[31m::set-output name=a::b\u2028" + "z" * 500
    code, out, log = _run_answering(_private_home, tmp_path, hostile)
    assert code == 3 and not log.exists()
    assert out.count("\n") == 1, "one line only"
    assert "\x1b" not in out and "\u2028" not in out and "::set-output" not in out and "z" * 100 not in out
    assert "\\x0a" in out or "\\n" in out  # repr or escape: never a raw newline inside the line


def _run_with_routed(home: Path, tmp_path: Path, routed: str, answered: object = None) -> tuple[int, str, Path, str]:
    prompt = tmp_path / "p.txt"
    prompt.write_text("x")
    log = tmp_path / "o.jsonl"
    models = ["resident-12b-thinking", routed]
    with FakeOllama(models, models).serve() as a, FakeOllama(B_MODELS, B_MODELS).serve() as b:
        agents = write_agents(tmp_path / "agents.yaml", a.url, b.url)
        agents.write_text(agents.read_text().replace("small-4b-agent", json.dumps(routed)))
        a.answer_model = routed if answered is None else answered
        code, out, _ = local_run("ci-log-summary", prompt, agents, log, home)
        sent = a.generates[0]["model"] if a.generates else ""
    return code, out, log, sent


@pytest.mark.parametrize("routed", ["hf.co/org/m:Q4_K_M", "m" * 129, "a/b/" + "c" * 200])
def test_a_routed_model_that_cannot_be_a_label_is_recorded_as_null_with_the_name_in_the_note(
    _private_home: Path, tmp_path: Path, routed: str
) -> None:
    code, out, log, sent = _run_with_routed(_private_home, tmp_path, routed)
    row = json.loads(log.read_text())
    assert code == 0 and sent == routed and "A short answer." in out and "error" not in out
    if routed.startswith("hf.co"):
        assert row["model"] == routed, "a slashed label is recordable"
    else:
        assert "model" not in row and routed[:60] in row["note"] and routed not in row["note"], "capped"


def test_a_non_recordable_name_with_control_characters_is_escaped_in_the_note(
    _private_home: Path, tmp_path: Path
) -> None:
    routed = "bad\x1b[0m::name"
    code, out, log, _ = _run_with_routed(_private_home, tmp_path, routed)
    row = json.loads(log.read_text())
    assert code == 0 and "model" not in row and "\\x1b" in row["note"] and "\x1b" not in row["note"]
    assert "::name" not in row["note"] and "A short answer." in out


def test_the_latest_tag_is_ignored_in_both_directions(_private_home: Path, tmp_path: Path) -> None:
    for answered in ("m1:latest", "m1"):
        code, _, log, _ = _run_with_routed(_private_home, tmp_path, "m1:latest", answered)
        assert code == 0 and json.loads(log.read_text())["model"] == "m1:latest"
        log.unlink()
    code, _, log, _ = _run_with_routed(_private_home, tmp_path, "m1:latest", "m1:7b")
    assert code == 3 and not log.exists()
