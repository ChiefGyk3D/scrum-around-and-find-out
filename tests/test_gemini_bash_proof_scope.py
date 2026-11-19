# SPDX-License-Identifier: Apache-2.0
"""The proof never relaxes the denial for a command that writes text to a file or can start an editor or hooks (#388).

Each protected word and each shape is built from fragments at run time. Every command here carries the secret tool and
a config name (so the old rule denies it) plus one construct that must keep that denial.
"""

from __future__ import annotations

import pytest

from safo import geminibrief

TOOL = "dop" + "pler"
CFG = "pr" + "d"
PAID = "prd" + "_paid"
TEXT = f"{TOOL} {CFG}"
GIT = "gi" + "t"
GH = "g" + "h"
RG = "r" + "g"


def denied(command: str) -> bool:
    return geminibrief.shell_command_class(command) is not None


@pytest.mark.parametrize(
    "command",
    [
        f"echo '{TEXT}' > .git/hooks/pre-commit",
        f"echo '{TEXT}' >> .git/config",
        f"echo '{TEXT}' > ~/.bashrc",
        f"echo '{TEXT}' > ../outside.txt",
        f"echo '{TEXT}' > notes/x.md",
        f"echo '{TEXT}' >> notes/x.md",
        f"printf '%s' '{TEXT}' > .envrc",
        f"cat > notes/x.md <<'EOF'\n{TEXT}\nEOF",
        f"cat >> .git/hooks/post-commit <<'EOF'\n{TEXT}\nEOF",
        f"cat <<'EOF' > ~/.profile\n{TEXT}\nEOF",
        f"echo '{TEXT}' &> notes/x.md",
        f"echo '{TEXT}' 2> notes/err.txt",
        f"echo '{TEXT}' 1>notes/out.txt",
        f"grep -n x file > .git/hooks/x # {TEXT}",
        f"make check > .git/hooks/pre-commit # {TEXT}",
        f"make check >> notes/x.md # {TEXT}",
    ],
)
def test_a_command_that_writes_to_a_file_keeps_the_denial(command: str) -> None:
    assert denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        f"echo '{TEXT}' > /dev/null",
        f"echo '{TEXT}' 2>&1",
        f"echo '{TEXT}' 2> /dev/null",
        f"echo '{TEXT}' > /dev/stdout",
        f"echo '{TEXT}' >&2",
        f"make check > /dev/null # {TEXT}",
    ],
)
def test_output_to_the_null_device_or_the_standard_streams_is_allowed(command: str) -> None:
    assert geminibrief.shell_command_class(command) is None, command


@pytest.mark.parametrize(
    "command",
    [
        f"{GIT} commit -m '{TEXT}'",
        f'{GIT} commit -m "{TEXT}"',
        f"{GIT} commit --message='{TEXT}'",
        f"{GIT} commit -am '{TEXT}'",
        f"{GIT} commit -e -m '{TEXT}'",
        f"{GIT} commit --edit -m '{TEXT}'",
        f"{GIT} commit --amend '{TEXT}'",
        f"{GIT} -C . commit -m '{TEXT}'",
        f"{GIT} commit -F - <<'EOF'\n{TEXT}\nEOF",
    ],
)
def test_a_commit_is_never_proven_harmless_it_can_run_hooks_or_an_editor(command: str) -> None:
    assert denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        f"{GH} issue comment 5 '{TEXT}'",
        f"{GH} issue comment 5 --editor --body '{TEXT}'",
        f"{GH} issue comment 5 -e -b '{TEXT}'",
        f"{GH} pr create --title '{TEXT}'",
        f"{GH} pr create --title '{TEXT}' --editor",
        f"{GH} pr edit 3 --title '{TEXT}'",
        f"{GH} pr review 3 --comment '{TEXT}'",
        f"{GH} pr comment 3 --body '{TEXT}' --editor",
        f"{GH} pr comment 3 $OPT --body '{TEXT}'",
        f"{GH} issue comment 5 --body '{TEXT}' -we",
    ],
)
def test_a_code_host_verb_that_can_start_an_editor_needs_a_body_and_no_editor_option(command: str) -> None:
    assert denied(command), command


@pytest.mark.parametrize(
    "command",
    [
        f"{GH} issue comment 5 --body '{TEXT}'",
        f"{GH} issue comment 5 -b '{TEXT}'",
        f"{GH} pr comment 3 --body-file notes/{PAID}.md",
        f"{GH} pr comment 3 -F notes/{PAID}.md",
        f"{GH} pr create --title 'x' --body '{TEXT}'",
        f"{GH} pr edit 3 --body '{TEXT}'",
        f"{GH} pr review 3 --comment --body '{TEXT}'",
        f"{GH} issue close 5 --comment '{TEXT}'",
    ],
)
def test_a_code_host_verb_with_a_body_option_is_allowed(command: str) -> None:
    assert geminibrief.shell_command_class(command) is None, command


@pytest.mark.parametrize(
    "command",
    [
        f"{RG} -n '{TEXT}' docs",
        f"{RG} --pre=x -n '{TEXT}' .",
        f"{RG} -n '{TEXT}' ~/*",
        f"{RG} -n '{TEXT}' docs/{{a,b}}",
        f"{RG} -n '{TEXT}' docs/*.md",
        f"{RG} -n '{TEXT}' docs/?.md",
        f"{RG} -n '{TEXT}' docs/[ab].md",
        f"{RG} -n '{TEXT}' ~",
        f"{RG} {{--pre=x,}} '{TEXT}' .",
        f"{RG} -n '{TEXT}' docs/$X",
        f"{RG} -n '{TEXT}' | head -n 1",
    ],
)
def test_the_recursive_search_tool_is_not_on_the_allowlist(command: str) -> None:
    assert denied(command), command


def test_plain_grep_with_prose_is_still_allowed() -> None:
    assert geminibrief.shell_command_class(f"grep -rn '{TEXT}' docs") is None
    assert geminibrief.shell_command_class(f"cat docs/x.md | grep -c '{TEXT}'") is None
