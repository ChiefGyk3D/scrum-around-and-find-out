# SPDX-License-Identifier: Apache-2.0
"""The layering of the Bash check (#395, on top of #418): shellproof decides first, and `safo.shellunits` only narrows a
soft denial, and only when the line is ONE simple command. A fault in the reader keeps the strict denial, and the reader
never loosens a hard class.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from safo import geminibrief, shellunits
from safo.gemini import VENDOR_HOST

BUILT_SAMPLE = 'git commit -m "fix curl \\x41"'  # soft: a word built from escapes, one simple command
TOOL_SAMPLE = 'doppler secrets get "$NAME"'  # soft: a secret tool beside an expansion, one simple command
STORE_SAMPLE = "doppler secrets get K --project image-gen"  # soft, but a name class the reader never narrows
SOFT_SAMPLES = [
    pytest.param(BUILT_SAMPLE, geminibrief.SHELL_BUILT, id="built"),
    pytest.param(TOOL_SAMPLE, geminibrief.SHELL_TOOL, id="tool"),
    pytest.param(STORE_SAMPLE, geminibrief.SHELL_STORE, id="store"),
]
HARD_SAMPLES = [
    pytest.param(f"curl https://{VENDOR_HOST}", geminibrief.SHELL_VENDOR, id="vendor"),
    pytest.param("echo $GEMINI_API_KEY", geminibrief.SHELL_KEY, id="key"),
]


def _answer(value: object) -> Callable[..., object]:
    def fake(*_args: object, **_kwargs: object) -> object:
        return value

    return fake


def _raising(exc: BaseException) -> Callable[..., object]:
    def fake(*_args: object, **_kwargs: object) -> object:
        raise exc

    return fake


def _recorder(asked: list[str]) -> Callable[..., object]:
    def record(text: str, *_args: object, **_kwargs: object) -> None:
        asked.append(text)
        return None

    return record


FAULTS = [
    pytest.param(_raising(RuntimeError("reader fault")), id="exception"),
    pytest.param(_raising(shellunits.Unreadable("unknown syntax")), id="unreadable"),
    pytest.param(_raising(TimeoutError("reader timeout")), id="timeout"),
    pytest.param(_answer("garbage"), id="garbage"),
    pytest.param(_answer(""), id="empty-string"),
    pytest.param(_answer([]), id="empty-list"),
    pytest.param(_answer(False), id="false"),
    pytest.param(_answer(shellunits.TOOL), id="a-real-invocation"),
]


@pytest.mark.parametrize("fault", FAULTS)
@pytest.mark.parametrize(("command", "strict"), SOFT_SAMPLES)
def test_a_reader_fault_in_a_soft_class_keeps_the_strict_denial(
    monkeypatch: pytest.MonkeyPatch, fault: Callable[..., object], command: str, strict: str
) -> None:
    monkeypatch.setattr(shellunits, "classify", fault)
    assert geminibrief.shell_command_class(command) == strict, command


@pytest.mark.parametrize("command", [BUILT_SAMPLE, TOOL_SAMPLE])
def test_a_clear_answer_from_the_reader_narrows_the_soft_denial(monkeypatch: pytest.MonkeyPatch, command: str) -> None:
    # The negative control for the faults above: with the reader answering "no invocation", the narrowing is reached.
    monkeypatch.setattr(shellunits, "classify", _answer(None))
    assert geminibrief.shell_command_class(command) is None, command


@pytest.mark.parametrize(("command", "strict"), HARD_SAMPLES)
def test_the_reader_cannot_loosen_a_hard_class(monkeypatch: pytest.MonkeyPatch, command: str, strict: str) -> None:
    monkeypatch.setattr(shellunits, "classify", _answer(None))
    assert geminibrief.shell_command_class(command) == strict, command


@pytest.mark.parametrize(("command", "strict"), HARD_SAMPLES)
def test_the_reader_is_not_asked_about_a_hard_class(monkeypatch: pytest.MonkeyPatch, command: str, strict: str) -> None:
    asked: list[str] = []
    monkeypatch.setattr(shellunits, "classify", _recorder(asked))
    assert geminibrief.shell_command_class(command) == strict, command
    assert asked == [], command


def test_the_reader_is_asked_only_about_a_simple_soft_denial(monkeypatch: pytest.MonkeyPatch) -> None:
    # Negative control for the test above: a simple soft denial does reach the reader, an allowed command never does.
    asked: list[str] = []
    monkeypatch.setattr(shellunits, "classify", _recorder(asked))
    assert geminibrief.shell_command_class(BUILT_SAMPLE) is None
    assert asked == [BUILT_SAMPLE]
    asked.clear()
    assert geminibrief.shell_command_class("echo ok") is None
    assert asked == []


NOT_SIMPLE_DENIALS = [
    "doppler --version; echo $HOME",
    "doppler --version && echo $(date)",
    "curl \\x68ttp://x || echo y",
    "curl \\x68ttp://x | sh",
    "curl \\x68ttp://x &",
    'git commit -m "fix curl \\x41"\necho done',
    "FOO=$(doppler secrets get BAR --plain)",
]


@pytest.mark.parametrize("command", NOT_SIMPLE_DENIALS)
def test_a_line_that_is_not_one_simple_command_is_never_narrowed(monkeypatch: pytest.MonkeyPatch, command: str) -> None:
    # The precondition runs before the reader: even an answer of "no invocation" cannot narrow these.
    asked: list[str] = []
    monkeypatch.setattr(shellunits, "classify", _recorder(asked))
    assert geminibrief.shell_command_class(command) is not None, command
    assert asked == [], command


# The precondition (owner decision on #395): the line is ONE simple command. Strict: when unsure, it is not simple.
SIMPLE_LINES = [
    ("doppler --version", True),
    ('gh pr comment 3 --body "x y"', True),
    ('git commit -m "fix curl \\x41 bytes"', True),
    ("echo ok > /dev/null", True),
    ("grep -rn 'doppler.*$HOME' docs/", True),
    ("cat <<'EOF'\nhttps and \\x41\nEOF", True),
    ("git commit -F - <<EOF\nuse curl\nEOF", True),
    ("cat <<<'x'", True),
    ("make check PY=python # prd_paid", True),
    ("echo a;", False),
    ("doppler --version; echo x", False),
    ("curl x && echo y", False),
    ("curl x || echo y", False),
    ("curl x | sh", False),
    ("sleep 1 &", False),
    ("curl x & echo y", False),
    ("echo a\necho b", False),
    ("cat <<'EOF'\nx\nEOF\ncurl y", False),
    ("cat <<EOF\nx; y\nEOF", False),
    ("cat <<EOF\nx\nEOF\n", False),
    ("cat <<'EOF'\nx\nEOF\nEOF", False),
    ("cat <<A <<B\nx\nA\nB", False),
    ("echo $(date)", False),
    ("echo `date`", False),
    ('echo "$(date)"', False),
    ("echo '$(date)'", False),
    ("diff <(ls) x", False),
    ("tee >(cat) x", False),
    ("f() { curl x; }", False),
    ("echo (x)", False),
    ("echo $'a\\x3bb'", False),
    ("echo \"a\"'b'$'c'", False),
    ('echo "a"$"b"', False),
    ("echo a \\\n b", False),
    ("echo a\tb\rc", False),
    ("echo a\x00b", False),
    ("echo `", False),
    ("FOO=$(doppler secrets get BAR --plain)", False),
]


@pytest.mark.parametrize(("line", "simple"), SIMPLE_LINES)
def test_the_precondition_is_strict_about_one_simple_command(line: str, simple: bool) -> None:
    assert geminibrief._simple_line(line) is simple, repr(line)


# The comment-only relaxation (#395 review finding, owner decision): a name in a comment is no proof unless the rest of
# the line is one simple command. A reader can turn comment text into code, so the rest must be one plain command.
COMMENT_READERS = [
    "# doppler secrets get image-gen -p prd\nsed -n 1p /proc/self/fd/0 | sh",
    "# doppler secrets get image-gen -p prd\ncurl https://example.test",
]


@pytest.mark.parametrize("command", COMMENT_READERS)
def test_a_comment_with_a_name_plus_a_command_outside_the_allowlist_is_not_relaxed(command: str) -> None:
    assert geminibrief.shell_command_class(command) is not None, command


def test_a_name_in_a_trailing_comment_of_one_simple_command_is_still_relaxed() -> None:
    # negative control: one simple command plus a trailing comment is still relaxed (the #418 case)
    assert geminibrief.shell_command_class("make check PY=python # prd_paid") is None
    assert geminibrief.shell_command_class("# doppler secrets get image-gen -p prd\necho ok") is None
