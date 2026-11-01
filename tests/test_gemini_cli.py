# SPDX-License-Identifier: Apache-2.0
"""`safo gemini quota|ask` and the keys commands end to end against a fake Gemini and a fake secret tool (#200).

The config, the approval folder and the private-terms file are at fixed locations that no flag or variable can move;
the autouse `gemini_locations` fixture is the test-only seam that points them into a temporary directory.
"""

from __future__ import annotations

import datetime as dt
import io
import os
import shutil
import socket
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from geminidata import (
    FAKE_KEY,
    MODEL,
    NOW,
    FakeGemini,
    make_key,
    seed,
    signers_line,
    start_row,
    write_config,
)
from safo.broker import client
from safo.cli import main
from safo.errors import ConfigError
from safo.gemini import GeminiConfig, Locations, load_config
from safo.modes.gemini import brief_namespace


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
        self.config = write_config(locations.config, server.url, self.ledger)
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

    def cfg(self) -> GeminiConfig:
        return load_config(self.config)


@pytest.fixture
def rig(tmp_path: Path, _private_home: Path, server: FakeGemini, gemini_locations: Locations) -> Rig:
    return Rig(tmp_path, _private_home, server, gemini_locations)


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
    assert "prd" in rig.asked.read_text().split()


def test_ask_requires_the_public_material_statement(rig: Rig) -> None:
    code, _, err = rig.run("ask", *rig.base(), "--prompt-file", str(rig.prompt))
    assert code == 2 and "public" in err
    code, _, err = rig.run("ask", *rig.base(), "--prompt-file", str(rig.prompt), "--material", "private")
    assert code == 2 and rig.server.requests == []


def test_a_429_exits_three_and_asks_for_the_free_key_only(rig: Rig) -> None:
    rig.server.status = 429
    code, _, err = rig.run("ask", *rig.base(), "--prompt-file", str(rig.prompt), "--material", "public")
    assert code == 3 and "QUOTA free" in err and "stopped" in err
    assert len(rig.server.requests) == 1
    assert rig.asked.read_text().split().count("prd") == 1


def test_an_ambiguous_outcome_exits_four(rig: Rig) -> None:
    rig.server.drop = True
    code, _, err = rig.run("ask", *rig.base(), "--prompt-file", str(rig.prompt), "--material", "public")
    assert code == 4 and "not repeated" in err and len(rig.server.requests) == 1


# -- approval needs a person at a terminal ---------------------------------------------------------------------------


def test_a_prompt_file_over_the_cap_is_refused(rig: Rig) -> None:
    rig.prompt.write_text("x" * 300_000)
    code, _, err = rig.run("ask", *rig.base(), "--prompt-file", str(rig.prompt), "--material", "public")
    assert code == 2 and "prompt" in err and rig.server.requests == []


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


@pytest.fixture(params=["absent", "refuses"])
def dead_socket(request: pytest.FixtureRequest, rig: Rig, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """A broker socket that does not exist, or one that exists and refuses (a socket file nobody listens on); the user
    client config names it. Returns the list of broker connection attempts the free path makes (it must stay empty)."""
    folder = Path(tempfile.mkdtemp(prefix="sd"))
    path = folder / "b.sock"
    if request.param == "refuses":
        dead = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        dead.bind(str(path))
        dead.close()  # the file stays, nothing listens: connect is refused
    config = rig.home / ".config" / "safo"
    config.mkdir(parents=True, exist_ok=True)
    config.chmod(0o700)
    (config / "broker-client.yaml").write_text(f"version: 1\nsocket: {path}\n")
    (config / "broker-client.yaml").chmod(0o600)
    attempts: list[str] = []
    real = client.connect_unix

    def spy(target: str, **kw: Any) -> socket.socket:
        attempts.append(target)
        return real(target, **kw)

    monkeypatch.setattr(client, "connect_unix", spy)
    monkeypatch.setattr(client, "ROOT_CONFIG", str(folder / "none.yaml"))
    monkeypatch.setattr(client, "DEFAULT_SOCKET", str(path))
    request.addfinalizer(lambda: shutil.rmtree(folder, ignore_errors=True))
    return attempts


def test_the_free_path_works_when_the_broker_socket_is_absent_or_refuses(rig: Rig, dead_socket: list[str]) -> None:
    """#298 (5): the free tier never touches the broker, so a dead broker cannot take it down."""
    code, out, _ = rig.run("quota", *rig.base())
    assert code == 0 and f"QUOTA free {MODEL}" in out
    code, out, err = rig.run("ask", *rig.base(), "--prompt-file", str(rig.prompt), "--material", "public")
    assert code == 0, err
    assert "A cited answer." in out and "cost 0.000000 USD" in out
    assert dead_socket == [], "the free path opened a connection to the broker"
    assert len(rig.server.requests) == 1  # and the free request really went to the (fake) free endpoint


def test_the_dead_socket_is_really_dead_and_the_spy_sees_a_broker_connection(
    rig: Rig, dead_socket: list[str]
) -> None:
    """The negative case: the same fixture makes a broker connection fail and be recorded, so the empty list above
    means something."""
    cfg = client.load_client_config(home=rig.home)
    with pytest.raises(client.ClientError, match="not reachable"):
        client.connect_unix(cfg.socket, owner=os.geteuid())
    assert dead_socket == [cfg.socket]
