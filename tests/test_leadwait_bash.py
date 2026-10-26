# SPDX-License-Identifier: Apache-2.0
"""The scanner against the real `bash`: a differential test for heredocs, and a syntax check of every fixture.

Nothing here ever runs a wait. The heredoc fixtures are executed with a harmless `printf` where the scanner
fixtures have `sleep 60`; the scanner fixtures are only parsed (`bash -n`, which executes nothing).

If `bash` is missing the module is skipped with a stated reason, except under CI (the `CI` environment variable is
set, as on GitHub Actions), where a missing bash is a FAILURE: the runners have it, and a silent skip would turn the
differential check off without anyone noticing.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from safo import leadwait
from test_leadwait import (
    BLOCKING,
    BODY_EXPANSION,
    BODY_OPAQUE,
    LOOKALIKES,
    NOT_AT_POSITION,
    POSITIONS,
    ROUND3_FIXTURES,
    SYNTAX_FIXTURES,
    THRESHOLD,
)

BASH = shutil.which("bash")


@pytest.fixture(scope="module", autouse=True)
def _bash_is_available() -> None:
    if BASH is None:
        if os.environ.get("CI"):
            pytest.fail("bash is expected on CI and was not found: the differential test would silently not run")
        pytest.skip("bash is not installed here; the differential test needs the real shell")


def bash_c(script: str) -> str:
    """Run a script under the real bash and return its standard output. Only harmless fixtures are passed in."""
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell; a harmless fixture is the one argument to bash -c
        [BASH or "bash", "--noprofile", "--norc", "-c", script],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )
    assert done.returncode == 0, done.stderr
    return done.stdout


def bash_syntax_ok(script: str) -> bool:
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell; bash -n only parses and never executes
        [BASH or "bash", "--noprofile", "--norc", "-n", "-c", script],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )
    return done.returncode == 0


SPELLINGS = ["EOF", "'EOF'", '"EOF"', "\\EOF", "E'OF'", 'E"O"F', "EO\\F", "$'EOF'", '$"EOF"', "E$'O'F"]


def bash_quoted(spelling: str) -> bool:
    """Ask the real bash whether this delimiter spelling counts as quoted: an unquoted body expands `$X`, a quoted one
    does not. (No hard-coded table: the shell is the oracle.)"""
    out = bash_c(f"X=EXPANDED\ncat <<{spelling}\n$X\nEOF\n")
    assert out in ("EXPANDED\n", "$X\n"), out
    return out == "$X\n"


# Body lines that look like terminators but are not (a prefix, a suffix, a leading space, a lone E).
BODY = ["harmless text", "E", "EOFX", " EOF", "XEOF", "# lead-wait: ok - waiting for an intentionally approved op"]


def fixture(op: str, spelling: str, after: str, tabs: bool) -> tuple[str, str]:
    """(command, expected body as bash hands it to cat). With tabs, lines are tab-indented and `<<-` strips them."""
    indent = "\t" if tabs else ""
    body = "".join(f"{indent}{line}\n" for line in BODY)
    command = f"cat <<{op}{spelling}\n{body}{indent}EOF\n{after}"
    return command, "".join(f"{line}\n" for line in BODY) if tabs else body


@pytest.mark.parametrize("spelling", SPELLINGS)
@pytest.mark.parametrize(("op", "tabs"), [("", False), ("-", False), ("-", True)])
def test_the_tokenizer_takes_the_same_heredoc_body_as_bash(spelling: str, op: str, tabs: bool) -> None:
    run, expected_body = fixture(op, spelling, "printf 'AFTER\\n'", tabs)
    # What bash feeds to cat, then the line after the terminator.
    assert bash_c(run) == expected_body + "AFTER\n"
    # What the tokenizer treats as the body: the same text, and the part after it is outside.
    assert leadwait.heredoc_bodies(run) == (expected_body,)
    assert leadwait.heredoc_quoted(run) == (bash_quoted(spelling),)
    # The same shape with a wait after the terminator: the wait is code, the marker line in the body is not.
    scan, _ = fixture(op, spelling, "sleep 60", tabs)
    assert bash_syntax_ok(scan)
    assert leadwait.find_waits(scan, THRESHOLD) == ("long-sleep",)
    assert leadwait.marker_reason(scan) == ""


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_a_wait_inside_the_body_is_data_and_a_substitution_runs_only_when_unquoted(spelling: str) -> None:
    quoted = bash_quoted(spelling)
    script = f"cat <<{spelling}\nsleep 60\n$(sleep 61)\nEOF\ntrue"
    assert bash_syntax_ok(script)  # parsed, never run: the body would run `sleep 61` when unquoted
    assert leadwait.find_waits(script, THRESHOLD) == (() if quoted else ("long-sleep",))


def test_two_heredocs_on_one_line_take_their_bodies_in_order() -> None:
    run = "cat <<A; cat <<'B'\nfirst\nA\nsecond\nB\nprintf 'AFTER\\n'"
    assert bash_c(run) == "first\nsecond\nAFTER\n"
    assert leadwait.heredoc_bodies(run) == ("first\n", "second\n")
    assert leadwait.heredoc_quoted(run) == (False, True)


@pytest.mark.parametrize("command", sorted(set(SYNTAX_FIXTURES + ROUND3_FIXTURES)))
def test_every_new_scanner_fixture_is_valid_bash(command: str) -> None:
    assert bash_syntax_ok(command), command


def test_every_earlier_scanner_fixture_is_valid_bash_or_is_listed_as_not() -> None:
    """Earlier fixtures too. The two lists below hold fixtures that are deliberately not complete bash, with why."""
    deliberately_invalid: dict[str, str] = {}
    pool = (
        [c for c, _ in BLOCKING]
        + list(LOOKALIKES)
        + [c for c, _ in POSITIONS]
        + list(NOT_AT_POSITION)
        + [c for c, _ in BODY_EXPANSION]
        + list(BODY_OPAQUE)
    )
    bad = [c for c in sorted(set(pool)) if c not in deliberately_invalid and not bash_syntax_ok(c)]
    assert bad == []


# Round 3: backslash-newline (bash removes it before it tokenizes, with exceptions) and here-strings. Each template
# has an {after} line: the run form prints a sentinel, the scan form has a wait there. Nothing waits when run.
CONTINUATION_TEMPLATES = {
    "delimiter split": "cat <<E\\\nOF\nbody\nEOF\n{after}",
    "split delimiter stays unquoted": "cat <<E\\\nOF\nx\nEO\\\nF\n{after}",
    "delimiter split in double quotes": 'cat <<"E\\\nOF"\nbody\nEOF\n{after}',
    "unquoted body joins lines": "cat <<EOF\na\\\nb\nEOF\n{after}",
    "quoted body keeps the backslash": "cat <<'EOF'\na\\\nb\nEOF\n{after}",
    "unquoted terminator formed by a continuation": "cat <<EOF\nx\nEO\\\nF\n{after}",
    "quoted terminator is not formed by one": "cat <<'EOF'\nx\nEO\\\nF\nEOF\n{after}",
    "operator split": "cat <\\\n<EOF\nhi\nEOF\n{after}",
    "tab-stripped body with a continuation": "cat <<-EOF\n\ta\\\n\tb\n\tEOF\n{after}",
    "here-string then heredoc": "cat <<<\"x\" <<'EOF'\nbody\nEOF\n{after}",
    "here-string alone": 'cat <<< "x"\n{after}',
}


@pytest.mark.parametrize("name", list(CONTINUATION_TEMPLATES))
def test_continuations_and_here_strings_are_read_the_way_bash_reads_them(name: str) -> None:
    template = CONTINUATION_TEMPLATES[name]
    run = template.format(after="printf 'AFTER\\n'")
    scan = template.format(after="sleep 60")
    out = bash_c(run)
    assert out.endswith("AFTER\n")
    # Whatever bash fed to cat is exactly the body the tokenizer skipped (or nothing, for a here-string alone).
    skipped = "".join(leadwait.heredoc_bodies(run))
    if name == "here-string alone":
        assert skipped == "" and out == "x\nAFTER\n"
    elif name == "here-string then heredoc":
        assert skipped == "body\n" and out == "body\nAFTER\n"
    else:
        assert out == skipped + "AFTER\n"
    assert bash_syntax_ok(scan)
    assert leadwait.find_waits(scan, THRESHOLD) == ("long-sleep",)  # the wait after the terminator is code


def test_a_comment_does_not_continue_and_a_split_command_name_is_one_word() -> None:
    assert bash_c("echo a # c \\\nprintf 'AFTER\\n'") == "a\nAFTER\n"  # bash ran the next line
    assert leadwait.find_waits("echo a # c \\\nsleep 60", THRESHOLD) == ("long-sleep",)
    assert bash_syntax_ok("sl\\\neep 60")
    assert leadwait.find_waits("sl\\\neep 60", THRESHOLD) == ("long-sleep",)
