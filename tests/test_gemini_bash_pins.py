# SPDX-License-Identifier: Apache-2.0
"""Pins for the option lists and the comment reader, each isolating ONE fault (#388, reviewer additions).

Every command carries a valid literal body (or a plain positional) so that the only reason to deny it is the option
under test: if that option were added to a verb's list, the command would be allowed and the test would go red. Shapes
are built from fragments at run time.
"""

from __future__ import annotations

import pytest

from safo import geminibrief

GH = "g" + "h"
TEXT = "dop" + "pler pr" + "d"
HOST = "github." + "example/owner/repo"
GET = "dop" + "pler secrets get $K"
SH = "ba" + "sh"
FILE = "notes" + ".md"


def denied(command: str) -> bool:
    return geminibrief.shell_command_class(command) is not None


BODY_VERBS = [
    ("issue", "create", ""),
    ("pr", "create", ""),
    ("issue", "edit", "5 "),
    ("pr", "edit", "3 "),
    ("pr", "review", "3 "),
]
FILE_OPTIONS = [f"--body-file {FILE}", f"-F {FILE}", f"--body-file={FILE}"]
HOST_OPTIONS = [f"-R {HOST}", f"--repo {HOST}", f"--repo={HOST}", f"--hostname {HOST}"]


@pytest.mark.parametrize(("area", "verb", "num"), BODY_VERBS)
@pytest.mark.parametrize("option", FILE_OPTIONS + HOST_OPTIONS)
def test_a_body_file_or_host_option_is_denied_next_to_a_valid_literal_body(
    area: str, verb: str, num: str, option: str
) -> None:
    assert denied(f"{GH} {area} {verb} {num}-b '{TEXT}' {option}"), (area, verb, option)


@pytest.mark.parametrize("option", FILE_OPTIONS + HOST_OPTIONS)
@pytest.mark.parametrize("verb", ["close", "reopen"])
def test_a_body_file_or_host_option_is_denied_on_close_and_reopen(verb: str, option: str) -> None:
    assert denied(f"{GH} issue {verb} 5 -c '{TEXT}' {option}"), (verb, option)


@pytest.mark.parametrize("verb", ["view", "list", "ready"])
@pytest.mark.parametrize(
    "option",
    ["--web", "-w", f"-R {HOST}", f"--repo {HOST}", f"--repo={HOST}", f"--hostname {HOST}", "--json body", "-c x"],
)
def test_a_read_only_verb_takes_no_option_at_all(verb: str, option: str) -> None:
    # the only fault is the option: the positional is a plain number and the protected words sit in a separate echo
    num = "" if verb == "list" else "5 "
    assert denied(f"echo '{TEXT}'; {GH} issue {verb} {num}{option}"), (verb, option)
    assert denied(f"echo '{TEXT}'; {GH} pr {verb} {num}{option}"), (verb, option)


def test_the_read_only_verbs_alone_are_allowed() -> None:
    for verb, num in (("view", "5 "), ("list", ""), ("ready", "5 ")):
        assert geminibrief.shell_command_class(f"echo '{TEXT}'; {GH} pr {verb} {num}".rstrip()) is None, verb


@pytest.mark.parametrize(
    "command",
    [
        f"echo x '#' ; {GET}",
        f'echo x "#" ; {GET}',
        f"echo x '# y' ; {GET}",
        f"echo x \\# ; {GET}",
        f"echo  '#'; {GET}",
        f"echo x\t'#'; {GET}",
    ],
)
def test_a_quoted_or_escaped_hash_after_whitespace_is_not_a_comment(command: str) -> None:
    assert denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        f"{SH} <<'EOF'\n# {TEXT}\nEOF",
        f"{SH} <<EOF\n# {TEXT}\nEOF",
        f"make check <<'EOF'\n# {TEXT}\nEOF",
        f"cat <<'EOF' | {SH}\n# {TEXT}\nEOF",
        f"{SH} <<'EOF'\nx\n  # {TEXT}\nEOF",
    ],
)
def test_a_hash_line_in_a_heredoc_body_is_not_a_comment(command: str) -> None:
    # the body is run by the shell that reads it; none of these is allowed because the line looks like a comment
    assert denied(command), command
