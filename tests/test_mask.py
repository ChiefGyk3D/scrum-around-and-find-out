# SPDX-License-Identifier: MIT
"""Secrets are masked before anything can print them, and masking itself is the one place a command is written."""

from __future__ import annotations

import io
import subprocess
import sys
from pathlib import Path

import pytest

from safo import action_mask, output

ROOT = Path(__file__).parent.parent
PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAabcdefgh\n"
    "ijklmnopqrstuvwxyz0123456789\n-----END RSA PRIVATE KEY-----\n"
)


def test_each_line_of_a_multi_line_value_is_masked_and_blank_lines_are_not() -> None:
    out = io.StringIO()
    output.mask(out, "line-one-secret\n\n  line-two-secret  \r\n")
    assert out.getvalue() == "::add-mask::line-one-secret\n::add-mask::line-two-secret\n"


def test_nothing_is_written_for_an_empty_value() -> None:
    out = io.StringIO()
    output.mask(out, "")
    output.mask(out, " \n\t\n")
    assert out.getvalue() == ""


def test_a_value_cannot_smuggle_a_second_command() -> None:
    out = io.StringIO()
    output.mask(out, "abcdefgh::set-env name=X::y")
    assert out.getvalue() == "::add-mask::abcdefgh::set-env name=X::y\n"  # one line, one command: the text is the mask
    assert out.getvalue().count("\n") == 1


def test_the_named_variables_are_masked_and_others_are_not() -> None:
    out = io.StringIO()
    action_mask.mask_env(
        {"PRIVATE_KEY": PEM, "TOKEN": "ghp_fine_grained_token", "MINTED_TOKEN": "ghs_installation", "PATH": "/bin"}, out
    )
    text = out.getvalue()
    for secret in (
        "MIIEowIBAAKCAQEAabcdefgh",
        "ghp_fine_grained_token",
        "ghs_installation",
        "-----BEGIN RSA PRIVATE KEY-----",
    ):
        assert f"::add-mask::{secret}" in text, secret
    assert "/bin" not in text


def test_the_masking_command_prints_only_commands_never_a_value_on_its_own() -> None:
    run = subprocess.run(
        [sys.executable, "-m", "safo.action_mask"],
        env={"PYTHONPATH": str(ROOT / "src"), "PRIVATE_KEY": PEM, "TOKEN": ""},
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0 and run.stderr == ""
    assert all(line.startswith("::add-mask::") for line in run.stdout.splitlines()) and run.stdout


def test_a_step_output_is_one_line_named_without_an_equals_sign(tmp_path: Path) -> None:
    target = tmp_path / "out"
    output.set_output(str(target), "repositories", "a,b")
    output.set_output(str(target), "second", "c")
    assert target.read_text() == "repositories=a,b\nsecond=c\n"
    hostile = [("n", "a\nrepositories=evil"), ("n", "a\rb"), ("a=b", "v"), ("a\nb", "v"), ("a\rb", "v"), ("", "v")]
    hostile += [("a\x00b", "v"), ("n", "a\x00b"), ("a\tb", "v"), ("n", "a\x1bb"), ("a\x7fb", "v"), ("n", "a\u2028b")]
    hostile += [("a\u2029b", "v"), ("a\x85b", "v"), ("n", "\x85")]
    for name, value in hostile:
        with pytest.raises(ValueError, match="one line"):
            output.set_output(str(target), name, value)
    assert target.read_text() == "repositories=a,b\nsecond=c\n"
