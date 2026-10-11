# SPDX-License-Identifier: MIT
"""Names from the output tree are untrusted: escaped when printed, and a command is built only for safe ones."""

from __future__ import annotations

import shlex
import unicodedata
from pathlib import Path

import pytest

import safo.harness_tree as ht
from gendata import scratch
from test_generator_filesystem import run

PLAIN = {
    "with space.md": "with space.md",
    "semi;colon.md": "semi;colon.md",
    "$(touch pwned).md": "$(touch pwned).md",
    "back`tick`.md": "back`tick`.md",
    "-rf": "-rf",
    "it's.md": "it's.md",
    "amp&pipe|.md": "amp&pipe|.md",
}
ESCAPED = {
    "line\nbreak.md": "line\\x0abreak.md",
    "esc\x1b[31mred.md": "esc\\x1b[31mred.md",
    "bidi‮exe.md": "bidi\\u202eexe.md",
    "nul-ish\x7f.md": "nul-ish\\x7f.md",
    "::error::forged.md": "\\x3a\\x3aerror::forged.md",
    "back\\slash.md": "back\\\\slash.md",
    "tab\there.md": "tab\\x09here.md",
    f"sep{chr(0x2028)}line.md": "sep\\u2028line.md",
    "emoji-\U000e0041.md": "emoji-\\U000e0041.md",
}


def bad_chars(text: str) -> list[str]:
    return [
        repr(c)
        for c in text
        if c != "\n" and (ord(c) < 0x20 or ord(c) == 0x7F or unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp"))
    ]


@pytest.mark.parametrize("name,expected", [*PLAIN.items(), *ESCAPED.items()])
def test_shown_escapes_exactly_what_is_dangerous(name: str, expected: str) -> None:
    assert ht.shown(name) == expected
    assert bad_chars(ht.shown(name)) == [] and "\n" not in ht.shown(name)


def test_shown_cuts_a_long_name_and_leaves_ordinary_names_alone() -> None:
    assert ht.shown("a" * 500) == "a" * (ht.MAX_SHOWN - 3) + "..."
    assert ht.shown("a" * ht.MAX_SHOWN) == "a" * ht.MAX_SHOWN
    assert ht.shown("claude/claude-haiku.md") == "claude/claude-haiku.md" and ht.shown("a:b") == "a:b"
    assert ht.shown(":x") == "\\x3ax"


def printed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], flag: str) -> str:
    script, out = scratch(tmp_path, monkeypatch)
    assert script.main(["--write"]) == 0
    capsys.readouterr()
    for name in [*PLAIN, *ESCAPED, "x" * 200 + ".md"]:
        (out / "claude" / name).write_text("mine\n")
        (out / f"d {name}").mkdir()
        (out / f"d {name}" / "inner.md").write_text("mine\n")
    (out / "::error::top.md").write_text("mine\n")
    (out / "claude" / "link\nlink.md").symlink_to(out / "claude" / "with space.md")
    code, err = run(script, flag, capsys)
    assert code == 1
    return err


@pytest.mark.parametrize("flag", ["--check", "--write"])
def test_every_printed_line_is_one_error_line_without_raw_control_characters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], flag: str
) -> None:
    err = printed(tmp_path, monkeypatch, capsys, flag)
    assert bad_chars(err) == []
    for line in err.splitlines():
        assert line.startswith("error:"), repr(line)
        assert not line.removeprefix("error: ").startswith("::")
    assert "\\x0a" in err and "\\x1b[31m" in err and "\\u202e" in err and "claude/::error::forged.md" in err
    assert "\\x3a\\x3aerror::top.md: unexpected file" in err, "colons at the start of a line are escaped"
    assert "..." in err, "the 200 character name is cut"


@pytest.mark.parametrize("flag", ["--check", "--write"])
def test_a_ready_command_exists_only_for_safe_names_and_is_safely_quoted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], flag: str
) -> None:
    err = printed(tmp_path, monkeypatch, capsys, flag)
    commands = []
    for line in err.splitlines():
        if "remove it with: git rm" in line:
            tail = line.split("remove it with: ", 1)[1].split(" (an empty", 1)[0]
            commands.append(shlex.split(tail))
        else:
            assert "git rm" not in line and "rmdir" not in line, f"a command for a name that needed escaping: {line!r}"
    for name in PLAIN:
        full = f"examples/harness/claude/{name}"
        assert ["git", "rm", "--", full] in commands, name
        assert ["git", "rm", "-r", "--", f"examples/harness/d {name}"] in commands, name
    for argv in commands:
        assert argv[:2] == ["git", "rm"] and "--" in argv
        assert all("\n" not in a and "\x1b" not in a for a in argv)
    escaped_lines = [x for x in err.splitlines() if "remove it by hand: " in x]
    assert len(escaped_lines) >= len(ESCAPED), "an escaped name gets 'remove it by hand' and the escaped name only"


def test_a_leading_dash_name_cannot_become_an_option() -> None:
    rel = "-odd"
    assert "git rm -- " in ht._file_hint(rel, "x.md") and "-- -odd/x.md" in ht._file_hint(rel, "x.md")
    assert ht._file_hint("out", "bad\nname.md").startswith("remove it by hand: out/bad\\x0aname.md")
    assert "git rm -r -- " in ht._dir_hint("out", "d") and "rmdir -- out/d" in ht._dir_hint("out", "d")
    assert ht._dir_hint("out", "d\x1b").startswith("remove it by hand")
    assert ht._file_hint("out", "é.md").startswith("remove it by hand")
    assert ht._file_hint("out", "n" * 200 + ".md").startswith("remove it by hand")
