# SPDX-License-Identifier: Apache-2.0
"""Tests for safo-brief-scan (#537): secret and private-data shapes, redaction, bounds, fail closed, allow marker.

Every fake credential is built here from parts at run time, so no complete token sits in the repository.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from safo import briefscan as bs

GH = "gh" + "p_" + "A1b2" * 9
AWS = "AK" + "IA" + "ABCDEFGH12345678"
PEM = "-----BEGIN " + "RSA PRIVATE" + " KEY-----"
JWT = ".".join(["ey" + "J" + "hbGciOiJIUzI1NiJ9", "ey" + "J" + "zdWIiOiIxMjM0NTY3ODkwIn0", "abcDEF123456_-xyz"])
BEARER = "Authorization: Bearer " + "q7Zr" * 8
ASSIGN = "api_" + "key = " + "Zx81Qa" * 4
CALL = "K1" + "ABC"
GRID = "FN" + "42ab"
NAS = "nas" + "-01." + "lan"
IP = ".".join(["192", "168", "7", "9"])


def scan(text: str, env: dict[str, str] | None = None, tmp: Path | None = None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    home = {"HOME": str(tmp or "/nonexistent-home")}
    code = bs.main([], io.BytesIO(text.encode()), out, err, {**home, **(env or {})})
    return code, out.getvalue(), err.getvalue()


@pytest.mark.parametrize(
    "secret,kind",
    [
        (GH, "credential"),
        (AWS, "credential"),
        (PEM, "credential"),
        (JWT, "jwt"),
        (BEARER, "bearer"),
        (ASSIGN, "assignment"),
    ],
)
def test_a_credential_shape_is_found_and_never_printed(secret: str, kind: str) -> None:
    code, out, err = scan(f"line one\nhere: {secret}\n")
    assert code == 1
    assert kind in err and "<stdin>:2:" in err
    assert secret not in err + out
    assert secret.split()[-1] not in err + out
    assert out == ""


@pytest.mark.parametrize(
    "text,kind",
    [(NAS, "hostname"), (IP, "ip-address"), (f"de {CALL} calling", "callsign"), (f"grid {GRID}", "grid-square")],
)
def test_private_data_is_found_without_a_hash_or_the_value(text: str, kind: str) -> None:
    code, _, err = scan(text)
    assert code == 1 and kind in err
    assert text.split()[-1] not in err
    assert "[-]" in err  # low entropy classes carry no hash


def test_a_credential_finding_carries_a_short_stable_hash_prefix() -> None:
    _, _, a = scan(GH)
    _, _, b = scan("x " + GH)
    tag = a.split("[")[1].split("]")[0]
    assert len(tag) == 6 and all(c in "0123456789abcdef" for c in tag)
    assert f"[{tag}]" in b


def test_placeholders_and_plain_prose_pass() -> None:
    text = "callsign N0CALL and N0TST at FN31pr, token $TOKEN, password: <value>, api_key=xxxxxxxxxxxxxxxxxxxx\n"
    assert scan(text)[0] == 0


def test_markdown_and_html_in_a_brief_are_not_findings() -> None:
    assert scan("see [link](https://example.com) and <b>bold</b> — fine\n")[0] == 0


def test_a_fullwidth_lookalike_is_not_a_bypass() -> None:
    wide = "".join(chr(ord(c) + 0xFEE0) if c.isascii() and c.isalnum() else c for c in AWS)
    assert wide != AWS
    assert scan(wide)[0] == 1


def test_the_private_deny_file_is_applied_and_named_by_label_only(tmp_path: Path) -> None:
    deny = tmp_path / "deny.txt"
    deny.write_text("# c\nplum" + "berry-shed\n")
    deny.chmod(0o600)
    code, _, err = scan("we met at the plum" + "berry shed today", {"SAFO_DRAFT_DENY_FILE": str(deny)}, tmp_path)
    assert code == 1 and "deny-list #2" in err
    assert "plum" not in err


def test_a_bad_deny_file_fails_closed(tmp_path: Path) -> None:
    code, _, err = scan("hello", {"SAFO_DRAFT_DENY_FILE": str(tmp_path / "missing")}, tmp_path)
    assert code == 2 and err.strip()


def test_the_allow_marker_with_a_reason_suppresses_only_its_own_line() -> None:
    text = f"{AWS} safo-scan-allow: documented example key\n{AWS}\n"
    code, _, err = scan(text)
    assert code == 1
    assert "<stdin>:2:" in err and "<stdin>:1:" not in err.split("allowed")[0]
    assert "allowed: 1 (line 1)" in err
    assert "documented example" not in err


def test_the_allow_marker_alone_passes_with_a_count() -> None:
    code, _, err = scan(f"{NAS} safo-scan-allow: docs example host\n")
    assert code == 0 and "allowed: 1" in err


@pytest.mark.parametrize("marker", ["safo-scan-allow:", "safo-scan-allow: short", "safo-scan-allow:    "])
def test_a_marker_without_a_real_reason_suppresses_nothing(marker: str) -> None:
    code, _, err = scan(f"{AWS} {marker}\n")
    assert code == 1
    assert "allow-marker-without-reason" in err and "credential" in err


def test_a_credential_hidden_in_the_reason_is_still_found() -> None:
    code, _, err = scan(f"{NAS} safo-scan-allow: because {AWS} was shown\n")
    assert code == 1 and "credential" in err
    assert AWS not in err


def test_oversize_input_is_exit_2_not_a_partial_scan() -> None:
    code, _, err = scan("a" * (bs.MAX_BYTES + 1))
    assert code == 2 and "limit" in err
    assert scan("a" * bs.MAX_BYTES)[0] == 0


def test_invalid_utf8_is_exit_2() -> None:
    out, err = io.StringIO(), io.StringIO()
    assert bs.main([], io.BytesIO(b"ok \xff\xfe"), out, err, {"HOME": "/nonexistent-home"}) == 2


def test_files_are_scanned_and_unreadable_files_fail_closed(tmp_path: Path) -> None:
    good, bad = tmp_path / "good.md", tmp_path / "bad.md"
    good.write_text("nothing here\n")
    bad.write_text(f"x\n{GH}\n")
    out, err = io.StringIO(), io.StringIO()
    env = {"HOME": str(tmp_path)}
    assert bs.main([str(good)], io.BytesIO(), out, err, env) == 0
    assert bs.main([str(good), str(bad)], io.BytesIO(), out, err, env) == 1
    assert f"{bad}:2:" in err.getvalue()
    assert bs.main([str(tmp_path / "nope")], io.BytesIO(), out, err, env) == 2
    assert bs.main([str(tmp_path)], io.BytesIO(), out, err, env) == 2


def test_a_symlink_and_a_fifo_are_refused(tmp_path: Path) -> None:
    real = tmp_path / "real.md"
    real.write_text("fine\n")
    link = tmp_path / "link.md"
    link.symlink_to(real)
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    env = {"HOME": str(tmp_path)}
    for p in (link, fifo):
        out, err = io.StringIO(), io.StringIO()
        assert bs.main([str(p)], io.BytesIO(), out, err, env) == 2


def test_a_finding_in_one_file_is_not_hidden_by_an_unreadable_one(tmp_path: Path) -> None:
    bad = tmp_path / "bad.md"
    bad.write_text(GH)
    out, err = io.StringIO(), io.StringIO()
    code = bs.main([str(tmp_path / "gone"), str(bad)], io.BytesIO(), out, err, {"HOME": str(tmp_path)})
    assert code == 2 and "credential" in err.getvalue()


def hook(doc: object, raw: bytes | None = None) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    data = raw if raw is not None else json.dumps(doc).encode()
    code = bs.main(["--hook"], io.BytesIO(data), out, err, {"HOME": "/nonexistent-home"})
    return code, err.getvalue()


def test_hook_mode_blocks_a_secret_in_any_tool_input_string_with_exit_2() -> None:
    code, err = hook({"tool_name": "Agent", "tool_input": {"prompt": f"do it\nkey {GH}", "n": {"x": [AWS]}}})
    assert code == 2
    assert "tool_input.prompt:2:" in err and "tool_input.n.x[0]:1:" in err
    assert GH not in err and AWS not in err


def test_hook_mode_passes_a_clean_call_and_only_scans_tool_input() -> None:
    assert hook({"tool_name": "Agent", "tool_input": {"prompt": "write the tests"}, "cwd": "/home/x/" + NAS})[0] == 0


@pytest.mark.parametrize("raw", [b"not json", b"[1]", b'{"tool_input": 5}', b'{"a":1,"a":2}', b"{" * 200 + b"}" * 200])
def test_hook_mode_fails_closed_on_hostile_json(raw: bytes) -> None:
    assert hook(None, raw)[0] == 2


def test_the_entry_point_is_registered() -> None:
    text = (Path(__file__).parent.parent / "pyproject.toml").read_text()
    assert 'safo-brief-scan = "safo.briefscan:run"' in text


def test_the_scan_collects_something_and_a_clean_text_does_not() -> None:
    # guard negative case: the detectors are live (a secret is found) and the same text without it is clean
    assert scan(f"k {GH}")[0] == 1
    assert scan("k nothing")[0] == 0


def test_a_fullwidth_credential_in_the_allow_reason_is_still_found() -> None:
    wide = "".join(chr(ord(c) + 0xFEE0) if c.isascii() and c.isalnum() else c for c in AWS)
    code, _, err = scan(f"{NAS} safo-scan-allow: because {wide} was shown\n")
    assert code == 1 and "credential" in err


def test_a_hook_key_with_control_characters_cannot_forge_a_diagnostic_line() -> None:
    key = "prompt" + chr(10) + "INJECTED:1: credential [abc123]" + chr(13) + chr(27) + "[2J"
    code, err = hook({"tool_input": {key: GH}})
    assert code == 2
    lines = [ln for ln in err.splitlines() if ln.startswith("tool_input")]
    assert len(lines) == 1 and "credential" in lines[0]
    assert not any(ln.startswith("INJECTED") for ln in err.splitlines())
    assert chr(27) not in err and chr(13) not in err
