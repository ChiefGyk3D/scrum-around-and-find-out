# SPDX-License-Identifier: MIT
"""One output path: every line safo prints goes through safo.output, and a test walks the source to keep it so."""

from __future__ import annotations

import argparse
import ast
import io
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import safo
from fakegh import FakeGitHub
from safo import output
from safo.errors import UnknownOutcomeError
from safo.graphql import Client
from safo.modes.audit import run as audit_run
from safo.modes.bootstrap import run as bootstrap_run
from world import build_world, load_test_board, make_context

SRC = Path(safo.__file__).parent
HOME = "output.py"  # the one module allowed to write to a stream


def offenders(source: str) -> list[str]:
    """Where a source writes to a stream itself: a print call, or a write on sys.stdout / sys.stderr."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "print":
            found.append(f"print at line {node.lineno}")
        elif (
            isinstance(func, ast.Attribute)
            and func.attr in {"write", "writelines"}
            and isinstance(func.value, ast.Attribute)
            and func.value.attr in {"stdout", "stderr"}
            and isinstance(func.value.value, ast.Name)
            and func.value.value.id == "sys"
        ):
            found.append(f"sys.{func.value.attr}.{func.attr} at line {node.lineno}")
    return found


def test_nothing_in_the_package_writes_to_a_stream_outside_the_output_module() -> None:
    files = sorted(SRC.rglob("*.py"))
    assert any(f.name == HOME for f in files) and len(files) > 10, "the walk must really see the package"
    problems = {
        str(f.relative_to(SRC)): hits
        for f in files
        if f.relative_to(SRC) != Path(HOME) and (hits := offenders(f.read_text(encoding="utf-8")))
    }
    assert problems == {}


@pytest.mark.parametrize(
    "source",
    [
        "print('x')",
        "def f():\n    print(x, file=y)",
        "import sys\nsys.stdout.write('x')",
        "import sys\nsys.stderr.write('x')",
        "import sys\nsys.stderr.writelines(['x'])",
    ],
)
def test_the_checker_catches_each_way_of_writing_to_a_stream(source: str) -> None:
    assert offenders(source)


@pytest.mark.parametrize(
    "source", ["out.write('x')", "self.print_all()", "import sys\nout = sys.stdout", "x = print", "log.info('x')"]
)
def test_the_checker_leaves_other_code_alone(source: str) -> None:
    assert offenders(source) == []


def test_the_output_module_is_where_the_printing_is() -> None:
    assert offenders((SRC / HOME).read_text(encoding="utf-8")), "if output.py stops printing, this guard is stale"


# -- line: no control, format or double-colon character reaches a log line --------------------------------------


def test_a_line_loses_controls_format_characters_and_every_double_colon() -> None:
    text = "a\nb\x1b[2J\x00c\u061cd\u200be\ue000::error::f %0A::warning::g ::stop-commands::x\U000e0001"
    shown = output.line(text)
    assert "::" not in shown and "\n" not in shown and "\x1b" not in shown
    assert not any(ch in shown for ch in "\x00\u061c\u200b\ue000\U000e0001")
    assert "\\x0a" in shown and "\\u061c" in shown and "\\U000e0001" in shown and "%0A" in shown


def test_the_c1_controls_and_the_line_and_paragraph_separators_are_written_out() -> None:
    assert output.line("a\x85b\x9fc\x7fd") == "a\\x85b\\x9fc\\x7fd"
    assert output.line("a" + chr(0x2028) + "b" + chr(0x2029)) == "a\\u2028b\\u2029"


def test_a_line_is_unchanged_when_there_is_nothing_to_escape() -> None:
    assert output.line("ready: 3 of 4 (75%) `x` -> 'y'") == "ready: 3 of 4 (75%) `x` -> 'y'"


def test_escaping_a_line_twice_changes_nothing_more() -> None:
    once = output.line("a\n::b\u200b")
    assert output.line(once) == once


def test_write_puts_one_escaped_line_on_the_stream() -> None:
    out = io.StringIO()
    output.write(out, "x ::error::y\nz")
    assert out.getvalue() == "x :\\x3aerror:\\x3ay\\x0az\n"


def test_the_error_annotation_is_the_one_place_a_command_is_written_and_its_text_is_escaped() -> None:
    out = io.StringIO()
    output.annotation(out, "boom\n::error::forged")
    assert out.getvalue() == "::error title=safo::boom\\x0a:\\x3aerror:\\x3aforged\n"


# -- block: untrusted multi-line text between stop and resume markers, resumed even on failure ----------------


MARKER = re.compile(r"::stop-commands::([0-9a-f]{32})")


def test_a_block_is_wrapped_in_stop_commands_with_a_fresh_token_and_keeps_double_colons() -> None:
    first, second = io.StringIO(), io.StringIO()
    for out in (first, second):
        output.block(out, ["a ::error::b", "c\x1b[2J"])
    lines = first.getvalue().splitlines()
    opened = MARKER.fullmatch(lines[0])
    assert opened and lines[-1] == f"::{opened.group(1)}::"
    assert lines[1:-1] == ["a ::error::b", "c\\x1b[2J"]
    assert first.getvalue().splitlines()[0] != second.getvalue().splitlines()[0]


def test_a_block_escapes_format_characters_in_its_lines() -> None:
    out = io.StringIO()
    output.block(out, ["a\u202eb"])
    assert "\u202e" not in out.getvalue() and "a\\u202eb" in out.getvalue()


class FailsOnce(io.StringIO):
    """A stream whose first write of body text fails, and that works again afterwards."""

    def __init__(self) -> None:
        super().__init__()
        self.failed = False

    def write(self, text: str) -> int:
        if "body" in text and not self.failed:
            self.failed = True
            raise OSError("broken pipe")
        return super().write(text)


def resumed(text: str) -> bool:
    lines = text.splitlines()
    opened = MARKER.fullmatch(lines[0])
    return bool(opened) and lines[-1] == f"::{opened.group(1)}::" if opened else False


def test_the_resume_marker_is_written_even_when_a_body_write_fails() -> None:
    out = FailsOnce()
    with pytest.raises(OSError, match="broken pipe"):
        output.block(out, ["body one", "body two"])
    assert resumed(out.getvalue()) and "body" not in out.getvalue()


def test_the_resume_marker_is_written_even_when_formatting_the_body_fails() -> None:
    out = io.StringIO()

    def lines() -> Iterator[str]:
        yield "first"
        raise ValueError("formatting failed")

    with pytest.raises(ValueError, match="formatting failed"):
        output.block(out, lines())
    assert resumed(out.getvalue()) and "first" in out.getvalue()


def test_nothing_is_opened_when_the_body_cannot_even_start() -> None:
    class Refuses(io.StringIO):
        def write(self, text: str) -> int:
            raise OSError("closed")

    stream = Refuses()
    with pytest.raises(OSError):
        output.block(stream, ["x"])


def test_no_resume_marker_is_written_for_an_opening_marker_that_never_went_out() -> None:
    class FailsFirst(io.StringIO):
        failed = False

        def write(self, text: str) -> int:
            if not self.failed:
                self.failed = True
                raise OSError("closed")
            return super().write(text)

    stream = FailsFirst()
    with pytest.raises(OSError):
        output.block(stream, ["x"])
    assert stream.getvalue() == ""


def test_a_context_block_writes_to_the_context_stream() -> None:
    fake = FakeGitHub()
    ctx, out = make_context(fake, load_test_board(), Client("t", "http://127.0.0.1:1/graphql"))
    ctx.block(["x"])
    assert resumed(out.getvalue())
    ctx.say("a ::b")
    assert out.getvalue().splitlines()[-1] == "a :\\x3ab"


# -- the two inputs that got past: an audit view name, and bootstrap's live filter and unknown-outcome error -----

FORGED = "x ::error::FORGED"


def test_an_audit_of_a_live_view_named_like_a_command_prints_no_command(fake: FakeGitHub, client: Client) -> None:
    _, project = build_world(fake)
    fake.add_view(project, FORGED, "BOARD_LAYOUT", "-status:Done")
    ctx, out = make_context(fake, load_test_board(), client)
    audit_run(ctx, argparse.Namespace())
    assert "FORGED" in out.getvalue() and "::" not in out.getvalue()


def test_a_bootstrap_that_meets_a_live_filter_with_a_command_in_it_prints_no_command(
    fake: FakeGitHub, client: Client
) -> None:
    board, project = build_world(fake)
    next(v for v in project.views if v.name == "Board").filter = "x\n::error::FORGED"
    ctx, out = make_context(fake, board, client)
    bootstrap_run(ctx, argparse.Namespace())
    assert "FORGED" in out.getvalue() and "::" not in out.getvalue()
    assert not any(line.startswith("::") for line in out.getvalue().splitlines())


def test_bootstrap_prints_no_command_from_an_unknown_outcome_error_text(
    fake: FakeGitHub, client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = load_test_board()
    fake.add_owner(board.project.owner_type, board.project.owner)
    fake.add_project(board.project.owner_type, board.project.owner, 1, board.project.title)
    real = client.execute

    def execute(document: str, variables: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        if document.lstrip().startswith("mutation"):
            raise UnknownOutcomeError("lost\n::error::FORGED", data=None, errors=[], status=502)
        return real(document, variables, **kwargs)

    monkeypatch.setattr(client, "execute", execute)
    ctx, out = make_context(fake, board, client)
    assert bootstrap_run(ctx, argparse.Namespace()) == 2
    assert "FORGED" in out.getvalue() and "::" not in out.getvalue()
