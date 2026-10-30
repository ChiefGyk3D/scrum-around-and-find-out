# SPDX-License-Identifier: Apache-2.0
"""`safo gemini quota|approve|ask` end to end against a fake Gemini and a fake secret tool (#200).

The config, the approval folder and the private-terms file are at fixed locations that no flag or variable can move;
the autouse `gemini_locations` fixture is the test-only seam that points them into a temporary directory.
"""

from __future__ import annotations

import datetime as dt
import io
from collections.abc import Iterator
from pathlib import Path

import pytest

from geminidata import (
    FAKE_KEY,
    MODEL,
    NOW,
    FakeGemini,
    ledger_rows,
    make_key,
    seed,
    signers_line,
    start_row,
    write_config,
)
from safo.cli import main
from safo.context import LocalContext
from safo.errors import ConfigError
from safo.gemini import GeminiConfig, Locations, load_config, open_store
from safo.modes.gemini import approve_flow, brief_namespace


@pytest.fixture
def server() -> Iterator[FakeGemini]:
    with FakeGemini().serve() as fake:
        yield fake


class Rig:
    def __init__(self, tmp_path: Path, home: Path, server: FakeGemini, locations: Locations) -> None:
        self.tmp = tmp_path
        self.home = home
        self.server = server
        self.locations = locations
        self.ledger = tmp_path / "data" / "ledger.jsonl"
        self.signing = {"key": str(locations.home / "key"), "principal": "test-key-a"}
        self.config = write_config(locations.config, server.url, self.ledger, signing=self.signing)
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
        return ["--model", MODEL]

    def approvals(self) -> list[Path]:
        folder = self.locations.approvals
        return sorted(folder.glob("*.json")) if folder.exists() else []

    def cfg(self) -> GeminiConfig:
        return load_config(self.config)

    def approve(self, *extra: str, interactive: bool = True, answer: str = "approve job-1") -> tuple[int, str]:
        """The approval a person gives at a terminal: the seam is a function argument, not a flag or a variable."""
        args = brief_namespace(approve_args(self, *extra))
        out = io.StringIO()
        ctx = LocalContext(out, {"HOME": str(self.home), "PATH": str(self.bin)}, NOW)
        req = __import__("safo.modes.gemini", fromlist=["_request"])._request(args)
        try:
            code = approve_flow(
                ctx,
                args,
                self.cfg(),
                open_store(self.locations, self.ledger, self.signing["key"], "test-key-a", ctx.env),
                req,
                interactive=interactive,
                confirm=lambda prompt: (out.write(prompt), answer)[1],
            )
        except Exception as err:
            return -1, out.getvalue() + f"[{type(err).__name__}: {err}]"
        return code, out.getvalue()


@pytest.fixture
def rig(tmp_path: Path, _private_home: Path, server: FakeGemini, gemini_locations: Locations) -> Rig:
    return Rig(tmp_path, _private_home, server, gemini_locations)


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


def test_there_is_no_flag_or_variable_that_moves_the_config_or_the_ceiling(rig: Rig) -> None:
    for flag in ("--config", "--beyond-ceiling", "--ledger"):
        with pytest.raises(SystemExit):
            main(["gemini", "quota", flag, "x", "--model", MODEL], env={"HOME": str(rig.home), "PATH": ""}, now=NOW)


def test_the_environment_cannot_redirect_the_config(rig: Rig, tmp_path: Path) -> None:
    other = write_config(tmp_path / "other.yaml", rig.server.url, tmp_path / "fresh-ledger.jsonl")
    out, err = io.StringIO(), io.StringIO()
    env = {
        "HOME": str(tmp_path / "nowhere"),
        "PATH": "",
        "SAFO_GEMINI_CONFIG": str(other),
        "XDG_DATA_HOME": str(tmp_path),
    }
    assert main(["gemini", "quota", *rig.base()], env=env, out=out, err=err, now=NOW) == 0
    seed(rig.ledger, start_row(NOW - dt.timedelta(seconds=10), call_id="x"))
    out = io.StringIO()
    main(["gemini", "quota", *rig.base()], env=env, out=out, err=err, now=NOW)
    assert "requests per minute 1 of 3" in out.getvalue(), (
        "the fixed config's ledger is used, not the one in the variable"
    )


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
    argv = ["ask", *rig.base(), "--paid", "--job", "job-1", "--prompt-file", str(rig.prompt), "--material", "public"]
    code, _, err = rig.run(*argv)
    assert code == 2 and "approval" in err
    assert not rig.asked.exists() and rig.server.requests == []


# -- approval needs a person at a terminal ---------------------------------------------------------------------------


def test_the_cli_approve_refuses_without_a_terminal_and_writes_nothing(rig: Rig) -> None:
    code, out, err = rig.run(*approve_args(rig))
    assert code == 2 and "terminal" in err and rig.approvals() == []
    assert "QUOTA paid" in out, "the line is shown, but nothing is written"


def test_approve_prints_the_quota_line_first_asks_for_the_phrase_then_writes(rig: Rig) -> None:
    code, out = rig.approve()
    assert code == 0, out
    assert out.index("QUOTA paid") < out.index("type exactly") < out.index("approval record")
    assert "approve job-1" in out
    assert len(rig.approvals()) == 1 and rig.approvals()[0].stem in out


@pytest.mark.parametrize("answer", ["", "yes", "approve job-2", "APPROVE JOB-1"])
def test_a_wrong_confirmation_writes_nothing(rig: Rig, answer: str) -> None:
    code, _ = rig.approve(answer=answer)
    assert code != 0 and rig.approvals() == []


def test_non_interactive_streams_cannot_approve(rig: Rig) -> None:
    code, out = rig.approve(interactive=False)
    assert code != 0 and "terminal" in out and rig.approvals() == []


def test_the_whole_paid_flow_spends_once(rig: Rig) -> None:
    rig.approve()
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
    write_config(rig.locations.config, rig.server.url, rig.ledger, paid={})
    code, out = rig.approve()
    assert code != 0 and "quota line" in out and rig.approvals() == []


def test_approve_refuses_more_than_two_dollars_and_an_estimate_over_the_amount(rig: Rig) -> None:
    args = approve_args(rig)
    args[args.index("1.50")] = "2.50"
    ns = brief_namespace(args)
    assert ns.max_usd == "2.50"
    code, out = rig.approve("--max-usd", "2.50")  # the last --max-usd wins
    assert code != 0 and rig.approvals() == []
    code, out = rig.approve("--max-usd", "0.001")
    assert code != 0 and "approved" in out and rig.approvals() == []
    code, out = rig.approve("--max-output-tokens", "900000")
    assert code != 0 and "job cap" in out and rig.approvals() == []


def test_the_ceiling_flag_comes_from_the_ledger_not_from_the_caller(rig: Rig) -> None:
    code, out = rig.approve()
    assert code == 0 and '"beyond_ceiling":false' in rig.approvals()[0].read_text().replace("\\", "")
    seed(rig.ledger, start_row(NOW - dt.timedelta(days=1), tier="paid", usd=9.999, call_id="p"))
    code, out = rig.approve()
    assert code == 0 and "beyond ceiling: YES" in out
    newest = sorted(rig.approvals(), key=lambda p: p.stat().st_mtime_ns)[-1]
    assert '"beyond_ceiling":true' in newest.read_text().replace("\\", "")


def test_a_prompt_file_over_the_cap_is_refused(rig: Rig) -> None:
    rig.prompt.write_text("x" * 300_000)
    code, _, err = rig.run("ask", *rig.base(), "--prompt-file", str(rig.prompt), "--material", "public")
    assert code == 2 and "prompt" in err and rig.server.requests == []


@pytest.mark.parametrize("flag", ["--cap", "--max-usd"])
@pytest.mark.parametrize("value", ["nan", "inf", "-1", "abc"])
def test_a_non_finite_amount_is_a_clean_error(rig: Rig, flag: str, value: str) -> None:
    if flag == "--cap":
        code, _, err = rig.run(
            "ask",
            *rig.base(),
            "--paid",
            "--job",
            "j",
            "--approval",
            "abcdefgh12",
            "--cap",
            value,
            "--prompt-file",
            str(rig.prompt),
            "--material",
            "public",
        )
        assert code == 2 and "Traceback" not in err
    else:
        code, out = rig.approve("--max-usd", value)
        assert code != 0 and "InvalidOperation" not in out
    assert rig.server.requests == []


def test_the_cli_enforces_the_cap_it_is_given(rig: Rig) -> None:
    seed(rig.ledger, [])
    rig.approve()
    record_id = rig.approvals()[0].stem
    code, _, err = rig.run(
        "ask",
        *rig.base(),
        "--paid",
        "--job",
        "job-1",
        "--approval",
        record_id,
        "--cap",
        "0.000001",
        "--prompt-file",
        str(rig.prompt),
        "--material",
        "public",
    )
    assert code == 2 and "cap" in err and rig.server.requests == []


def test_config_error_type_is_clean(rig: Rig) -> None:
    assert issubclass(ConfigError, Exception)


# -- keys, dry run and usage (#200) -----------------------------------------------------------------------------------


def test_keys_list_check_and_propose_are_read_only(rig: Rig, tmp_path: Path) -> None:
    signers = rig.locations.signers
    before = signers.read_bytes()
    code, out, _ = rig.run("keys", "list")
    assert code == 0 and "test-key-a" in out and "SHA256:" in out and "usable" in out
    code, out, _ = rig.run("keys", "check")
    assert code == 0 and "WARNING" in out and "only one usable key" in out
    other = make_key(tmp_path / "other")
    code, out, _ = rig.run("keys", "propose", str(other) + ".pub", "--label", "backup-1")
    assert code == 0 and 'backup-1 namespaces="safo-gemini-approval"' in out and "nothing was written" in out
    assert signers.read_bytes() == before and not rig.locations.revoked.exists()


def test_keys_propose_needs_a_label_and_a_file(rig: Rig) -> None:
    code, _, err = rig.run("keys", "propose")
    assert code == 2 and "label" in err


def test_keys_check_fails_when_a_key_is_unsafe(rig: Rig) -> None:
    rig.locations.signers.write_text(
        signers_line(
            "test-key-a", rig.locations.home / "key.pub", options='no-touch-required,namespaces="safo-gemini-approval"'
        )
        + "\n"
    )
    code, _, err = rig.run("keys", "check")
    assert code == 2 and "no-touch-required" in err


def test_the_dry_run_signs_and_checks_a_dummy_without_writing_anything(rig: Rig) -> None:
    before = rig.ledger.exists()
    args = brief_namespace(approve_args(rig))
    out = io.StringIO()
    ctx = LocalContext(out, {"HOME": str(rig.home), "PATH": str(rig.bin)}, NOW, dry_run=True)
    req = __import__("safo.modes.gemini", fromlist=["_request"])._request(args)
    store = open_store(rig.locations, rig.ledger, rig.signing["key"], "test-key-a", ctx.env)
    code = approve_flow(ctx, args, rig.cfg(), store, req, interactive=True, confirm=lambda p: "approve job-1")
    assert code == 0 and "dry run: the signature verifies" in out.getvalue() and "test-key-a" in out.getvalue()
    assert rig.approvals() == [] and rig.ledger.exists() == before


def test_approve_tells_the_person_when_to_touch_the_key(rig: Rig) -> None:
    code, out = rig.approve()
    assert code == 0
    assert (
        out.index("QUOTA paid")
        < out.index("quote of his message")
        < out.index("will blink")
        < out.index("type exactly")
    )
    assert "signed by test-key-a" in out


def test_usage_adds_a_chained_row_that_counts_toward_the_month(rig: Rig) -> None:
    code, _, _ = rig.run("usage", "--amount-usd", "1.25", "--on-date", "2026-10-29", "--note", "vendor page")
    assert code == 0
    rows = ledger_rows(rig.ledger, everything=True)
    assert [r["type"] for r in rows] == ["chain_start", "usage"] and rows[1]["prev_hash"] == rows[0]["hash"]
    _, out, _ = rig.run("quota", *rig.base(), "--paid")
    assert "spent 1.25 of 10.00" in out
    for bad in (
        ["--amount-usd", "x"],
        ["--amount-usd", "1", "--on-date", "soon"],
        ["--amount-usd", "1", "--on-date", "2026-10-29"],
    ):
        code, _, _err = rig.run("usage", *bad, "--note", "") if bad[-1] != "2026-10-29" else rig.run("usage", *bad)
        assert code == 2


def test_the_guard_parser_still_needs_a_model_for_the_money_actions() -> None:
    from safo.modes.gemini import BriefParseError

    with pytest.raises(BriefParseError):
        brief_namespace(["ask", "--paid"])
    assert brief_namespace(["keys", "list"]).keys_action == "list"


def test_a_stray_word_after_a_money_action_is_refused_like_any_unknown_argument(rig: Rig) -> None:
    from safo.modes.gemini import BriefParseError

    with pytest.raises(BriefParseError, match="unrecognized"):
        brief_namespace(["ask", "list", "--model", MODEL])
    code, _, err = rig.run("quota", "list", *rig.base())
    assert code == 2 and "unrecognized" in err
