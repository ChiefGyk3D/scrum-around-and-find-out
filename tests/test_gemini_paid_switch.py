# SPDX-License-Identifier: Apache-2.0
"""The paid path is off unless a root-owned switch file says it is on (#200).

The free path needs no root file at all. The switch is read with the same ownership walk as the trust files; no flag,
environment variable or user-editable config can turn it on (only the test seam, a function argument, can move it).
"""

from __future__ import annotations

import dataclasses
import io
import os
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from geminidata import MODEL, NOW, FakeGemini, write_config
from safo import gemini
from safo.cli import main
from safo.gemini import PAID_DISABLED, Locations, RefusedError, paid_enabled

ROOT = Path(__file__).parent.parent


@pytest.fixture
def server() -> Iterator[FakeGemini]:
    with FakeGemini().serve() as fake:
        yield fake


def switch(loc: Locations, text: str = "enabled\n", mode: int = 0o644) -> Path:
    loc.paid_switch.write_text(text)
    loc.paid_switch.chmod(mode)
    return loc.paid_switch


def test_the_shipped_default_is_a_root_owned_file_under_the_trust_directory(tmp_path: Path) -> None:
    real = Locations(tmp_path, tmp_path / "c", tmp_path / "a", tmp_path / "t")
    assert str(real.paid_switch) == "/etc/safo/gemini-paid-enabled" and real.trust_uid == 0


def test_an_enabled_switch_turns_the_paid_path_on(gemini_locations: Locations) -> None:
    switch(gemini_locations)
    assert paid_enabled() is True


@pytest.mark.parametrize("text", ["", "disabled\n", "yes\n", "enabled please\n", "ENABLED\n", "# enabled\n"])
def test_only_the_word_enabled_counts(gemini_locations: Locations, text: str) -> None:
    switch(gemini_locations, text)
    assert paid_enabled() is False


def test_an_absent_switch_means_disabled(gemini_locations: Locations) -> None:
    gemini_locations.paid_switch.unlink(missing_ok=True)
    assert paid_enabled() is False


def test_a_switch_the_wrong_account_owns_is_ignored(
    gemini_locations: Locations, monkeypatch: pytest.MonkeyPatch
) -> None:
    switch(gemini_locations)
    monkeypatch.setattr(
        gemini, "fixed_locations", lambda: dataclasses.replace(gemini_locations, trust_uid=os.geteuid() + 1)
    )
    assert paid_enabled() is False


@pytest.mark.parametrize("mode", [0o664, 0o646, 0o666])
def test_a_group_or_world_writable_switch_is_ignored(gemini_locations: Locations, mode: int) -> None:
    switch(gemini_locations, mode=mode)
    assert paid_enabled() is False


def test_a_switch_in_a_writable_directory_is_ignored(
    gemini_locations: Locations, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loose = tmp_path / "loose"
    loose.mkdir()
    shutil.copy(switch(gemini_locations), loose / "enabled")
    loose.chmod(0o777)
    moved = dataclasses.replace(gemini_locations, paid_switch=loose / "enabled")
    monkeypatch.setattr(gemini, "fixed_locations", lambda: moved)
    try:
        assert paid_enabled() is False
    finally:
        loose.chmod(0o700)


def test_a_symlink_to_a_switch_in_a_writable_place_is_ignored(gemini_locations: Locations, tmp_path: Path) -> None:
    elsewhere = tmp_path / "w"
    elsewhere.mkdir()
    elsewhere.chmod(0o777)
    real = elsewhere / "enabled"
    real.write_text("enabled\n")
    link = gemini_locations.paid_switch
    link.unlink(missing_ok=True)
    link.symlink_to(real)
    try:
        assert paid_enabled() is False
    finally:
        elsewhere.chmod(0o700)


def test_nothing_on_the_command_line_or_in_the_environment_can_enable_it(
    gemini_locations: Locations, server: FakeGemini, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SAFO_GEMINI_PAID", "1")
    monkeypatch.setenv("SAFO_GEMINI_PAID_ENABLED", "enabled")
    gemini_locations.paid_switch.unlink(missing_ok=True)
    write_config(gemini_locations.config, server.url, gemini_locations.home / "ledger.jsonl")
    prompt = gemini_locations.home / "p.txt"
    prompt.write_text("Summarize the public changelog.")
    env = {
        "HOME": str(gemini_locations.home),
        "PATH": "",
        "SAFO_GEMINI_PAID": "1",
        "SAFO_GEMINI_PAID_ENABLED": "enabled",
    }
    for extra in ([], ["--paid-enabled"], ["--enable-paid"]):
        out, err = io.StringIO(), io.StringIO()
        argv = [
            "gemini",
            "ask",
            "--model",
            MODEL,
            "--paid",
            "--job",
            "j",
            "--approval",
            "abcdefgh12",
            "--prompt-file",
            str(prompt),
            "--material",
            "public",
            *extra,
        ]
        try:
            code = main(argv, env=env, out=out, err=err, now=NOW)
        except SystemExit as stop:
            code = int(stop.code or 0)
        assert code == 2 and not server.requests
        if not extra:
            assert "paid use is disabled" in err.getvalue() and "#NNN" in err.getvalue()


def test_ask_paid_and_approve_are_refused_while_it_is_off(gemini_locations: Locations, server: FakeGemini) -> None:
    from safo.gemini import ApprovalStore, Request, ask

    gemini_locations.paid_switch.unlink(missing_ok=True)
    cfg = gemini.load_config(write_config(gemini_locations.config, server.url, gemini_locations.home / "l.jsonl"))
    req = Request(model=MODEL, prompt="x", tier="paid", job="j", approval="abcdefgh12", max_output_tokens=10)
    with pytest.raises(RefusedError, match="paid use is disabled"):
        ask(
            cfg,
            req,
            store=ApprovalStore(gemini_locations.approvals),
            key_for=lambda tier: "FAKE-KEY-for-tests-0123456789",
            now=NOW,
        )
    assert server.requests == []
    assert "#NNN" in PAID_DISABLED


def test_the_free_path_needs_no_root_file_at_all(
    gemini_locations: Locations, server: FakeGemini, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bare = dataclasses.replace(
        gemini_locations,
        signers=tmp_path / "none" / "signers",
        revoked=tmp_path / "none" / "revoked",
        paid_switch=tmp_path / "none" / "paid",
        revocation_required=True,
    )
    monkeypatch.setattr(gemini, "fixed_locations", lambda: bare)
    write_config(bare.config, server.url, tmp_path / "data" / "ledger.jsonl")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    doppler = bin_dir / "doppler"
    doppler.write_text('#!/bin/sh\nprintf "%s" "FAKE-KEY-for-tests-0123456789"\n')
    doppler.chmod(0o755)
    prompt = tmp_path / "p.txt"
    prompt.write_text("Summarize the public changelog.")
    env = {"HOME": str(bare.home), "PATH": str(bin_dir)}
    for argv in (
        ["gemini", "quota", "--model", MODEL],
        ["gemini", "ask", "--model", MODEL, "--prompt-file", str(prompt), "--material", "public"],
        ["gemini", "keys", "check"],
        ["gemini", "keys", "list"],
    ):
        out, err = io.StringIO(), io.StringIO()
        assert main(argv, env=env, out=out, err=err, now=NOW) == 0, (argv, err.getvalue())
    assert len(server.requests) == 1


def test_the_example_config_serves_a_free_only_user_with_no_keys(tmp_path: Path, gemini_locations: Locations) -> None:
    target = gemini_locations.config
    shutil.copy(ROOT / "examples" / "gemini.example.yaml", target)
    target.chmod(0o600)
    cfg = gemini.load_config(target, gemini_locations.home)
    assert cfg.signing_key == "" and cfg.free and cfg.endpoint.startswith("https://")
    out, err = io.StringIO(), io.StringIO()
    env = {"HOME": str(gemini_locations.home), "PATH": ""}
    assert main(["gemini", "quota", "--model", "gemini-3.6-flash"], env=env, out=out, err=err, now=NOW) == 0, (
        err.getvalue()
    )
    assert "QUOTA free" in out.getvalue()


def test_issuing_an_approval_is_refused_while_it_is_off_even_without_the_cli(
    gemini_locations: Locations, server: FakeGemini
) -> None:
    import datetime as dt
    from decimal import Decimal

    gemini_locations.paid_switch.unlink()
    cfg = gemini.load_config(write_config(gemini_locations.config, server.url, gemini_locations.home / "l.jsonl"))
    store = gemini.open_store(gemini_locations, cfg.ledger, str(gemini_locations.home / "key"), "test-key-a")
    with pytest.raises(RefusedError, match="paid use is disabled"):
        store.issue(
            model=MODEL,
            max_usd=Decimal("1"),
            job="j",
            quote="yes",
            quoted_at=NOW - dt.timedelta(minutes=1),
            now=NOW,
            ttl_minutes=10,
            beyond_ceiling=False,
        )
    assert not store.folder.exists() or list(store.folder.glob("*.json")) == []
