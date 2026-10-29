# SPDX-License-Identifier: Apache-2.0
"""`safo gemini quota|approve|ask` end to end against a fake Gemini and a fake secret tool (#200)."""

from __future__ import annotations

import datetime as dt
import io
from collections.abc import Iterator
from pathlib import Path

import pytest

from geminidata import FAKE_KEY, MODEL, NOW, FakeGemini, ledger_rows, seed, start_row, write_config
from safo.cli import main
from safo.gemini import gemini_state_dir


@pytest.fixture
def server() -> Iterator[FakeGemini]:
    with FakeGemini().serve() as fake:
        yield fake


class Rig:
    def __init__(self, tmp_path: Path, home: Path, server: FakeGemini) -> None:
        self.tmp = tmp_path
        self.home = home
        self.server = server
        self.ledger = tmp_path / "data" / "ledger.jsonl"
        self.config = write_config(tmp_path / "gemini.yaml", server.url, self.ledger)
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.asked = tmp_path / "doppler-asked.txt"
        script = self.bin / "doppler"
        script.write_text(f'#!/bin/sh\necho "$@" >> {self.asked}\nprintf "%s" "{FAKE_KEY}"\n')
        script.chmod(0o755)
        self.prompt = tmp_path / "prompt.txt"
        self.prompt.write_text("Summarize the public changelog.")

    def run(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        env = {"HOME": str(self.home), "PATH": str(self.bin)}
        code = main(["gemini", *argv], env=env, out=out, err=err, now=NOW)
        return code, out.getvalue(), err.getvalue()

    def base(self) -> list[str]:
        return ["--config", str(self.config), "--model", MODEL]

    def approvals(self) -> list[Path]:
        folder = gemini_state_dir({"HOME": str(self.home)}) / "approvals"
        return sorted(folder.glob("*.json")) if folder.exists() else []


@pytest.fixture
def rig(tmp_path: Path, _private_home: Path, server: FakeGemini) -> Rig:
    return Rig(tmp_path, _private_home, server)


def quoted_at() -> str:
    return (NOW - dt.timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")


def approve_args(rig: Rig, *extra: str) -> list[str]:
    return [
        "approve",
        *rig.base(),
        "--prompt-file",
        str(rig.prompt),
        "--max-output-tokens",
        "400",
        "--max-usd",
        "1.50",
        "--job",
        "job-1",
        "--quote",
        "go ahead, up to one fifty",
        "--quoted-at",
        quoted_at(),
        *extra,
    ]


def test_quota_prints_the_free_line(rig: Rig) -> None:
    code, out, _ = rig.run("quota", *rig.base())
    assert code == 0 and f"QUOTA free {MODEL}" in out and "requests per day 0 of 5" in out
    assert rig.server.requests == []


def test_ask_free_prints_the_line_the_answer_and_the_usage(rig: Rig) -> None:
    code, out, _ = rig.run("ask", *rig.base(), "--prompt-file", str(rig.prompt), "--material", "public")
    assert code == 0
    assert f"QUOTA free {MODEL}" in out and "A cited answer." in out and "::stop-commands::" in out
    assert "tokens 10 in, 20 out" in out and "cost 0.000000 USD" in out
    assert FAKE_KEY not in out
    assert "prd_paid" not in rig.asked.read_text() and "prd" in rig.asked.read_text()


def test_ask_requires_the_public_material_statement(rig: Rig) -> None:
    code, _, err = rig.run("ask", *rig.base(), "--prompt-file", str(rig.prompt))
    assert code == 2 and "public" in err
    code, _, err = rig.run("ask", *rig.base(), "--prompt-file", str(rig.prompt), "--material", "private")
    assert code == 2 and rig.server.requests == []


def test_a_429_exits_three_and_never_asks_for_the_paid_key(rig: Rig) -> None:
    rig.server.status = 429
    code, _, err = rig.run("ask", *rig.base(), "--prompt-file", str(rig.prompt), "--material", "public")
    assert code == 3 and "QUOTA free" in err and "stopped" in err
    assert len(rig.server.requests) == 1
    assert "prd_paid" not in rig.asked.read_text()


def test_an_ambiguous_outcome_exits_four(rig: Rig) -> None:
    rig.server.drop = True
    code, _, err = rig.run("ask", *rig.base(), "--prompt-file", str(rig.prompt), "--material", "public")
    assert code == 4 and "not repeated" in err and len(rig.server.requests) == 1


def test_a_paid_ask_without_an_approval_is_refused_before_the_paid_key_is_read(rig: Rig) -> None:
    code, _, err = rig.run(
        "ask", *rig.base(), "--paid", "--job", "job-1", "--prompt-file", str(rig.prompt), "--material", "public"
    )
    assert code == 2 and "approval" in err
    assert not rig.asked.exists() and rig.server.requests == []


def test_approve_prints_the_quota_line_first_then_the_record_id(rig: Rig) -> None:
    code, out, _ = rig.run(*approve_args(rig))
    assert code == 0
    assert out.index("QUOTA paid") < out.index("approval record")
    assert len(rig.approvals()) == 1
    record_id = rig.approvals()[0].stem
    assert record_id in out


def test_the_whole_paid_flow_spends_once(rig: Rig) -> None:
    rig.run(*approve_args(rig))
    record_id = rig.approvals()[0].stem
    ask = [
        "ask",
        *rig.base(),
        "--paid",
        "--job",
        "job-1",
        "--approval",
        record_id,
        "--prompt-file",
        str(rig.prompt),
        "--max-output-tokens",
        "400",
        "--material",
        "public",
    ]
    code, out, _ = rig.run(*ask)
    assert code == 0 and "cost 0.000083 USD" in out
    assert "prd_paid" in rig.asked.read_text()
    code, _, err = rig.run(*ask)
    assert code == 2 and "already used" in err
    assert len(rig.server.requests) == 1
    assert [r["type"] for r in ledger_rows(rig.ledger)] == ["call_start", "call_end"]


def test_approve_refuses_when_the_quota_line_cannot_be_made(rig: Rig) -> None:
    rig.config = write_config(rig.tmp / "nolimits.yaml", rig.server.url, rig.ledger, paid={})
    code, _, err = rig.run(*approve_args(rig))
    assert code == 2 and "quota line" in err
    assert rig.approvals() == []


def test_approve_refuses_more_than_two_dollars_and_an_estimate_over_the_amount(rig: Rig) -> None:
    args = approve_args(rig)
    args[args.index("1.50")] = "2.50"
    code, _, _ = rig.run(*args)
    assert code == 2 and rig.approvals() == []
    args = approve_args(rig)
    args[args.index("1.50")] = "0.001"
    code, _, err = rig.run(*args)
    assert code == 2 and "approved" in err and rig.approvals() == []
    args = approve_args(rig)
    args[args.index("400")] = "900000"
    code, _, err = rig.run(*args)
    assert code == 2 and "job cap" in err and rig.approvals() == []


def test_approve_beyond_the_ceiling_needs_the_flag_and_says_so(rig: Rig) -> None:
    seed(rig.ledger, start_row(NOW - dt.timedelta(days=1), tier="paid", usd=9.999, call_id="p"))
    code, _, err = rig.run(*approve_args(rig))
    assert code == 2 and "ceiling" in err and rig.approvals() == []
    code, out, _ = rig.run(*approve_args(rig, "--beyond-ceiling"))
    assert code == 0 and "beyond ceiling: YES" in out and len(rig.approvals()) == 1


def test_a_prompt_file_over_the_cap_is_refused(rig: Rig) -> None:
    rig.prompt.write_text("x" * 300_000)
    code, _, err = rig.run("ask", *rig.base(), "--prompt-file", str(rig.prompt), "--material", "public")
    assert code == 2 and "prompt" in err and rig.server.requests == []
