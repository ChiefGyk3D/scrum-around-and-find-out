# SPDX-License-Identifier: Apache-2.0
"""Dispatch guard coverage for shell commands (#209).

A Bash call that names the vendor API host, its SDK, the key variable or the secret-store project and config names is
denied. There is no exemption: not the wrapper, not a working directory, not this repository. The guard is a speed
bump; the wrapper holds the real gates. Names are built at run time so scanners stay quiet about this file.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from geminidata import write_config
from hooksdata import agents_file, hooks, read_log
from safo import geminibrief
from safo.gemini import Locations

HOST = "generative" + "language" + ".googleapis" + ".com"
KEY = "GEMINI" + "_API" + "_KEY"
PAID = "prd" + "_paid"
PROJECT = "image" + "-gen"
SDK = "google" + ".generative" + "ai"
REPO = Path(__file__).resolve().parent.parent


def event(command: str, cwd: Path | None = None, **extra: Any) -> str:
    data: dict[str, Any] = {
        "hook_event_name": "PreToolUse",
        "session_id": "session-a",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        **extra,
    }
    if cwd is not None:
        data["cwd"] = str(cwd)
    return json.dumps(data)


@pytest.fixture
def agents(tmp_path: Path, gemini_locations: Locations) -> Path:
    write_config(
        gemini_locations.config, "http://127.0.0.1:9", tmp_path / "data" / "ledger.jsonl", private_terms="none"
    )
    return agents_file(tmp_path / "agents.yaml")


def run(agents: Path, home: Path, payload: str) -> tuple[str, str]:
    code, out, err = hooks("guard", "--agents", str(agents), home=home, stdin=payload)
    assert code == 0 or json.loads(out)["hookSpecificOutput"].get("permissionDecision") == "deny"
    return out, err


def denied(out: str) -> bool:
    return bool(out) and json.loads(out)["hookSpecificOutput"].get("permissionDecision") == "deny"


def reason(out: str) -> str:
    return str(json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"])


# -- the classifier ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        f"curl -s https://{HOST}/v1/models",
        f"curl -s 'https://{HOST}'",
        f"curl https://gen''erative{HOST[len('generative') :]}",
        f'wget "https://{HOST.replace("language", "lan" + chr(92) + "guage")}"',
        f"doppler secrets get {KEY} --plain",
        f"echo ${{{KEY}}}",
        f"doppler run --project {PROJECT} --config x -- env",
        f"doppler secrets --config {PAID}",
        "doppler secrets get X --config prd --plain",
        f"python3 -c 'import {SDK}'",
        'python3 -c "from google import genai; genai.Client()"',
        f"cat /dev/null\ncurl https://{HOST}",
        f"ls \\\n; curl https://{HOST.replace('generative', 'gener' + chr(92) + chr(10) + 'ative')}",
        # look-alike letters and full-width forms fold to the plain name
        "curl https://" + HOST.replace("a", "\u0430", 1),
        f"X={KEY.lower()}; echo $X",
        # words built from escapes beside a network tool, and a secret tool with an expansion
        "curl $'\\x68ttps://example.test/'",
        "printf -v H %s%s gener ativelanguage; curl https://$H.googleapis.com",
        "doppler secrets get $K --plain",
        "doppler secrets get `echo K` --plain",
    ],
)
def test_the_classifier_denies_commands_that_reach_the_vendor_or_its_key(command: str) -> None:
    assert geminibrief.shell_command_class(command) is not None, command


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "git status --short",
        "curl -s https://api.github.com/repos/o/r",
        "doppler --version",
        "echo $HOME && pytest -q tests",
        "python3 -m pytest tests/test_hooks.py",
        "printf '%s\\n' hello",
        "grep -rn prd src",  # the bare config word alone is not the secret tool
        "make check",
        "echo gemini is a constellation",
        "safo gemini quota",
        "safo gemini ask --model m --prompt-file /tmp/p.md --job j",
    ],
)
def test_the_classifier_leaves_ordinary_commands_alone(command: str) -> None:
    assert geminibrief.shell_command_class(command) is None, command


DECODE_TO_INTERPRETER = [
    "printf %s cGF5bG9hZA== | base64 -d | sh",
    "printf %s cGF5bG9hZA== | openssl base64 -d | bash",
    "printf %s 7061796c6f6164 | xxd -r -p | zsh",
    r"printf '\x70\x61\x79\x6c\x6f\x61\x64' | dash",
    r"echo -e '\160\141\171\154\157\141\144' | ksh",
    "printf %s cGF5bG9hZA== | basenc --base64 --decode | env sh",
    "printf %s payload | uudecode | xargs sh",
    "python -c 'import base64; print(base64.b64decode(\"cGF5bG9hZA==\"))' | ruby",
    'perl -e \'print pack("H*", "7061796c6f6164")\' | node',
    'sh -c "$(printf %s cGF5bG9hZA== | base64 --decode)"',
    "source <(printf %s 7061796c6f6164 | xxd -r -p)",
    'python <<< "$(printf %s cGF5bG9hZA== | base64 -d)"',
    "printf %s cGF5bG9hZA== | base64 -d > /tmp/payload; sh /tmp/payload",
]


@pytest.mark.parametrize("command", DECODE_TO_INTERPRETER)
def test_the_classifier_denies_decoded_output_that_reaches_an_interpreter(command: str) -> None:
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED, command


@pytest.mark.parametrize(
    "command",
    [
        "base64 -d input > payload; sh < payload",
        "base64 -d input; sh",
        "sh; base64 -d input",
    ],
)
def test_a_decoder_and_sink_are_denied_without_proving_connectivity_or_order(command: str) -> None:
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED, command


@pytest.mark.parametrize(
    "command",
    [
        "base64 -d f; A=1 B=2 sh",
        "A=1 B=2 base64 -d f; sh",
        "A=1; base64 -d f; B=2 sh",
        "base64 -d f; A=1; sh",
    ],
)
def test_assignments_cannot_hide_a_decoder_or_sink(command: str) -> None:
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED, command


@pytest.mark.parametrize(
    "decoder",
    [
        "base64 -di f",
        "xxd -rp f",
        "base64 --dec f",
        "base64 --decode= f",
        "openssl enc -d -base64 f",
        "openssl base64 -d f",
        "basenc --base64 -d f",
        "uudecode f",
    ],
)
def test_decoder_option_forms_are_denied_with_a_sink(decoder: str) -> None:
    command = f"{decoder}; sh"
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED, command


@pytest.mark.parametrize(
    "decoder",
    [
        "base64 --d f",
        "base64 --de f",
        "base64 --decode=x f",
        "openssl base64 --d f",
        "openssl enc --base64 -d f",
        "xxd --rev f",
        "xxd --r f",
        "base64 -- -d f",
    ],
)
@pytest.mark.parametrize("separator", ["; ", " | "])
def test_decoder_names_are_denied_with_a_sink_regardless_of_option_spelling(decoder: str, separator: str) -> None:
    command = f"{decoder}{separator}sh"
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED, command


@pytest.mark.parametrize(
    "command",
    [
        "{ base64 -d f; }; sh",
        "(base64 -d f); sh",
        "if true; then base64 -d f; else sh; fi",
        "while false; do base64 -d f; done; sh",
        "for x in f; do base64 -d f; done; sh",
        "case x in x) base64 -d f;; y) sh;; esac",
        "f() { base64 -d f; }; sh",
    ],
)
def test_compound_constructs_cannot_separate_a_decoder_from_a_sink(command: str) -> None:
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED, command


DECODE_WRAPPERS = (
    "command",
    "builtin",
    "exec",
    "nice",
    "nohup",
    "timeout",
    "stdbuf",
    "time",
    "sudo",
    "doas",
    "busybox",
    "setsid",
    "chrt",
    "ionice",
    "taskset",
    "unbuffer",
    "env",
    "xargs",
    "!",
)


@pytest.mark.parametrize("wrapper", DECODE_WRAPPERS)
@pytest.mark.parametrize("wrapped", ["sink", "decoder"])
def test_wrappers_cannot_hide_a_decoder_or_sink(wrapper: str, wrapped: str) -> None:
    command = f"base64 -d input; {wrapper} sh" if wrapped == "sink" else f"{wrapper} base64 -d input; sh"
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED, command


@pytest.mark.parametrize(
    "wrapped_sink",
    [
        "taskset -c 0 sh",
        "chrt -f 1 sh",
        "sudo -u x -- sh",
        "doas -u x sh",
        "timeout -k 1 5 sh",
        "busybox sh",
        "time -p sh",
    ],
)
def test_wrapper_option_parsing_cannot_hide_a_sink_name(wrapped_sink: str) -> None:
    command = f"base64 -d input; {wrapped_sink}"
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED, command


@pytest.mark.parametrize(
    "command",
    [
        "/usr/bin/base64 -d f; sh",
        "base64 -d f; ./sh",
        "base64 -d f; \\sh",
        'base64 -d f; "sh"',
        "'base64' -d f; sh",
        'base64 -d f; "$(printf sh)"',
    ],
)
def test_static_spellings_and_a_dynamic_command_word_are_denied(command: str) -> None:
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED, command


@pytest.mark.parametrize(
    "command",
    [
        "base64 -d f; $x",
        r"base64 -d f; $'\163\150'",
        "base64 -d f; s?",
        "base64 -d f; ${s}h",
        "base64 -d f; ''",
        "base64 -d f; $(printf sh)",
        "base64 -d f; <(printf sh)",
    ],
)
def test_a_decoder_and_any_non_static_command_word_are_denied(command: str) -> None:
    assert geminibrief.relevant(command), command
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED, command


def test_a_dynamic_argument_without_a_decoder_is_allowed() -> None:
    assert geminibrief.shell_command_class("python3 -c 'print(1)' $X") is None


def test_an_unreadable_command_with_a_decoder_and_sink_is_denied() -> None:
    command = 'base64 -d f; sh "'
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED


def test_a_newline_is_a_decoder_and_sink_boundary() -> None:
    command = "base64 -d f\nsh"
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED


def test_an_inline_interpreter_that_decodes_and_executes_is_denied() -> None:
    command = "python3 -c 'import base64; exec(base64.b64decode(x))'"
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED


def test_a_plain_inline_interpreter_is_allowed() -> None:
    assert geminibrief.shell_command_class("python3 -c 'print(1)'") is None


@pytest.mark.parametrize(
    "command",
    [
        r"find . -exec base64 -d f \; -exec sh \;",
        r"find . -execdir sh -c x \; -exec base64 -d {} \;",
        r"find . -ok sh \; -exec base64 -d {} \;",
        "xargs base64 -d f | xargs sh",
        "parallel base64 -d ::: f ::: sh",
        "env -S 'base64 -d f' sh",
        "env -S 'sh' base64 -d f",
    ],
)
def test_exec_style_carriers_cannot_hide_decoder_or_sink_arguments(command: str) -> None:
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED, command


@pytest.mark.parametrize(
    "command",
    [
        "echo base64 | sh",
        "printf '%s' xxd | bash",
    ],
)
def test_decoder_names_in_non_decoder_arguments_are_denied_with_a_sink(command: str) -> None:
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED, command


@pytest.mark.parametrize(
    "command",
    [
        "find . -name '*.txt'",
        "xargs wc -l",
        "base64 -d f > out",
        "echo hello",
        "python3 -c 'print(1)'",
    ],
)
def test_carriers_and_decoders_without_a_decoder_sink_pair_are_allowed(command: str) -> None:
    assert geminibrief.shell_command_class(command) is None, command


@pytest.mark.parametrize(
    "sink",
    [
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "fish",
        "csh",
        "tcsh",
        "ash",
        "rc",
        "mksh",
        "pwsh",
        "powershell",
        "eval",
        "source",
        ".",
        "env",
        "xargs",
        "python",
        "perl",
        "ruby",
        "node",
        "nodejs",
        "busybox",
        "php",
        "lua",
        "luajit",
        "awk",
        "gawk",
        "mawk",
        "nawk",
        "tclsh",
        "wish",
        "expect",
        "julia",
        "r",
        "rscript",
        "groovy",
        "scala",
        "java",
        "jshell",
        "deno",
        "bun",
        "go",
        "gcc",
        "cc",
        "tcc",
        "make",
        "cmake",
        "npm",
        "npx",
        "pip",
        "pip3",
        "uv",
        "ssh",
        "nc",
        "ncat",
        "socat",
        "telnet",
        "at",
        "batch",
        "crontab",
        "exec",
        "command",
        "builtin",
        "trap",
        "time",
        "coproc",
        "script",
        "screen",
        "tmux",
        "watch",
    ],
)
def test_every_decode_sink_is_denied_next_to_a_decoder(sink: str) -> None:
    command = f"base64 -d f; {sink}"
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED, command


@pytest.mark.parametrize("sink", ["python3.12", "ruby3", "php8", "/usr/bin/lua5.4"])
def test_versioned_decode_sink_basenames_are_denied(sink: str) -> None:
    command = f"base64 -d f; {sink}"
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED, command


@pytest.mark.parametrize("command", DECODE_TO_INTERPRETER)
def test_the_prefilter_selects_every_decode_to_interpreter_shape(command: str) -> None:
    assert geminibrief.relevant(command), command


@pytest.mark.parametrize(
    "command",
    [
        "printf %s cGF5bG9hZA== | base64 -d > /tmp/payload",
        "printf %s cGF5bG9hZA== | base64 -d | wc -c",
        "printf %s cGF5bG9hZA== | base64 -d | cat",
        "printf '%s' payload",
        "echo payload",
        "base64 -d f; fisherman",
        "base64 -d f; java-home",
        "base64 -d f; npmrc",
        "base64 -d f; ssh-keygen",
        "base64 -d f; watcher",
    ],
)
def test_the_classifier_allows_decode_lookalikes_with_no_sink_word(command: str) -> None:
    assert geminibrief.shell_command_class(command) is None, command


def test_a_decode_lookalike_with_a_sink_word_elsewhere_is_denied() -> None:
    command = "base64 -d input > /tmp/payload; echo $(date); python report.py"
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED


@pytest.mark.parametrize(
    "hostile",
    [
        "printf '\\x41' | base64 -d | xargs " + "-n 1 " * 10_000,
        "printf '\\x41' | base64 -d " + "> " * 20_000,
        "printf '\\x41' | base64 -d | sh '" + "x" * 60_000,
    ],
)
def test_decode_classification_is_bounded_on_pathological_input(hostile: str) -> None:
    command = hostile[: geminibrief.SHELL_CAP]
    start = time.process_time()
    try:
        geminibrief.shell_command_class(command)
    except Exception as err:  # pragma: no cover - the assertion records the hostile case if the guard ever raises
        pytest.fail(f"classification raised {type(err).__name__}: {err}")
    assert time.process_time() - start < 2.0


def test_more_than_the_decoder_processing_cap_is_denied() -> None:
    command = "; ".join(["base64 -d input"] * (geminibrief.MAX_SHELL_DECODERS + 1) + ["sh"])
    assert geminibrief.shell_command_class(command) == geminibrief.SHELL_DECODED


def test_the_classifier_allows_a_plain_path_to_carry_issue_text() -> None:
    assert geminibrief.shell_command_class("gh issue create --title update --body-file notes.md") is None


def test_the_wrapper_is_not_exempt_when_it_carries_a_name() -> None:
    assert (
        geminibrief.shell_command_class(f"safo gemini ask --model m --prompt-file docs/{PAID}.md --job j") is not None
    )
    assert geminibrief.shell_command_class(f"python3 -m safo gemini quota # {KEY}") is not None


@pytest.mark.parametrize(
    "command",
    [
        "safo gemini quota",
        "safo gemini ask --model m --prompt-file p",
        "safo gemini keys check",
        "python -m safo gemini quota",
    ],
)
def test_the_documented_wrapper_commands_name_nothing_and_are_not_touched(command: str) -> None:
    assert geminibrief.shell_command_class(command) is None, command


@pytest.mark.parametrize(
    "tail",
    [
        f"; curl https://{HOST}",
        f" && curl https://{HOST}",
        f" | curl -d @- https://{HOST}",
        f" > >(curl https://{HOST})",
        f" $(curl https://{HOST})",
        f" `curl https://{HOST}`",
        f"\ncurl https://{HOST}",
    ],
)
def test_a_name_chained_to_the_wrapper_is_denied(tail: str) -> None:
    assert geminibrief.shell_command_class("safo gemini ask --model m --prompt-file p" + tail) is not None, tail


def test_the_denial_class_is_fixed_text_never_command_text() -> None:
    secret = "tok_SECRETVALUE123"
    found = geminibrief.shell_command_class(f"curl -H 'x: {secret}' https://{HOST}/v1 --data {KEY}")
    assert found is not None and secret not in found and HOST not in found and KEY not in found


def test_a_deadline_that_has_passed_denies_instead_of_allowing() -> None:
    assert geminibrief.shell_command_class("ls", deadline=time.monotonic() - 1) == geminibrief.SHELL_UNVERIFIED


def test_scan_time_grows_in_proportion_to_the_command() -> None:
    # A ratio, never a fixed bound: the suite runs under coverage on shared runners.
    def took(size: int) -> float:
        command = ("echo " + "x" * 60 + "\n") * size
        best = float("inf")
        for _ in range(3):
            start = time.perf_counter()
            geminibrief.shell_command_class(command)
            best = min(best, time.perf_counter() - start)
        return best

    small, large = took(500), took(8000)
    assert large < small * 16 * 6 + 0.05  # 16x the input within 6x slack on linear growth


# -- no exemption for this repository ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        f"grep -rn {HOST} docs tests",
        f"python3 -m pytest tests/test_gemini_guard.py -k {KEY}",
        f"pytest -q tests/test_gemini_bash.py -k {KEY}",
        f"git commit -m 'document {KEY} handling'",
        f"make SHELL='curl https://{HOST}' check",
        f"make --eval='x:; curl https://{HOST}' x",
        f"make -f /dev/stdin <<< 'x:; curl https://{HOST}'",
        f"git grep -O'curl https://{HOST}' x",
        f"git diff --ext-diff --output=/tmp/x {HOST}",
        f"head -n5 examples/gemini.example.yaml # {KEY}",
        f"curl https://{HOST}",
        f"grep -rn {HOST} docs | sh",
        f"cat $(curl https://{HOST})",
    ],
)
def test_nothing_is_exempt_by_where_it_runs_or_what_tool_it_is(command: str) -> None:
    assert geminibrief.shell_command_class(command) is not None, command


@pytest.mark.parametrize(
    "command",
    [
        f"cat docs/gemini-keys.md | grep {PROJECT}",
        f"make check PY=python # {PAID}",
        f"cat ~/.config/safo/gemini.yaml # {PAID}",
        f"grep -rn . ~/.config/safo # {PROJECT}",
    ],
)
def test_a_name_in_a_path_a_pattern_or_a_comment_is_proven_harmless(command: str) -> None:
    # #388 (converted from four cases that sat in the denying list above): the command is made of allowlisted text
    # commands, or the name sits in a comment; the same names given to the secret tool stay denied
    # (test_the_classifier_denies_commands_that_reach_the_vendor_or_its_key, tests/test_gemini_bash_narrow.py).
    assert geminibrief.shell_command_class(command) is None, command


def test_the_function_takes_no_working_directory() -> None:
    # a spoofed checkout (marker files made anywhere) buys nothing: there is no argument to carry one
    call: Any = geminibrief.shell_command_class
    with pytest.raises(TypeError):
        call(f"grep {HOST} x", cwd=REPO)


def test_the_hook_ignores_the_cwd_even_inside_a_real_checkout(_private_home: Path, agents: Path) -> None:
    assert denied(run(agents, _private_home, event(f"grep -rn {HOST} docs", cwd=REPO))[0])


def test_a_directory_with_spoofed_marker_files_is_denied(_private_home: Path, agents: Path, tmp_path: Path) -> None:
    fake = tmp_path / "fake"
    (fake / "src" / "safo").mkdir(parents=True)
    (fake / "src" / "safo" / "geminibrief.py").write_text("")
    (fake / "pyproject.toml").write_text("")
    # #388 (converted): a bare config name in a cat is proven text and is no denial in any directory; a real route is
    assert not denied(run(agents, _private_home, event(f"cat {PAID}", cwd=fake))[0])
    assert denied(run(agents, _private_home, event(f"curl https://{HOST}", cwd=fake))[0])


@pytest.mark.parametrize("command", ["make check", "make lint typecheck test", "pytest -q tests", "git status --short"])
def test_this_repos_normal_commands_are_not_denied_without_an_exemption(command: str) -> None:
    assert geminibrief.shell_command_class(command) is None, command


# -- the hook ----------------------------------------------------------------------------------------------------


def test_the_hook_denies_a_shell_call_to_the_vendor_even_in_warn_mode(_private_home: Path, agents: Path) -> None:
    out, _ = run(agents, _private_home, event(f"curl https://{HOST}/v1/models"))
    assert denied(out)
    text = reason(out)
    assert "gemini-material" in text and "wrapper" in text and "docs/gemini.md" in text
    assert HOST not in text and "curl" not in text
    row = read_log(_private_home)[-1]
    assert (row["decision"], row["diagnostic"], row["health"]) == ("deny", "gemini-deny", "healthy")  # #364


def test_the_hook_denies_for_a_sub_agent_call_too(_private_home: Path, agents: Path) -> None:
    out, _ = run(agents, _private_home, event(f"doppler secrets get {KEY}", agent_id="a1"))
    assert denied(out)


def test_the_hook_allows_the_wrapper_and_an_ordinary_command(_private_home: Path, agents: Path) -> None:
    for command in ("safo gemini quota", "ls -la", "pytest -q"):
        assert run(agents, _private_home, event(command)) == ("", ""), command


def test_a_background_call_is_still_checked(_private_home: Path, agents: Path) -> None:
    payload = json.loads(event(f"curl https://{HOST}"))
    payload["tool_input"]["run_in_background"] = True
    assert denied(run(agents, _private_home, json.dumps(payload))[0])


def test_a_malformed_shell_event_is_still_the_usual_degraded_path(_private_home: Path, agents: Path) -> None:
    payload = json.loads(event("ls"))
    payload["tool_input"] = {"command": 5}
    out, _ = run(agents, _private_home, json.dumps(payload))
    assert not denied(out)


# -- a renamed or hijacked wrapper gains nothing ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        f"alias safo='curl'; safo gemini ask --prompt {HOST}",
        f'safo() {{ curl "$@"; }}; safo https://{HOST}',
        f"PYTHONPATH=/x python3 -m safo gemini quota {KEY}",
    ],
)
def test_a_hijacked_wrapper_name_is_denied_by_the_names_in_the_text(command: str) -> None:
    assert geminibrief.shell_command_class(command) is not None, command


def test_a_command_over_the_size_cap_is_denied_unread() -> None:
    assert geminibrief.shell_command_class("x" * (geminibrief.SHELL_CAP + 1)) == geminibrief.SHELL_UNVERIFIED
    assert geminibrief.shell_command_class("ls " + "x" * 1000) is None


def test_an_eight_megabyte_line_is_denied_fast_relative_to_a_small_command() -> None:
    def took(command: str) -> tuple[float, str | None]:
        start = time.perf_counter()
        for _ in range(3):
            result = geminibrief.shell_command_class(command)
        return (time.perf_counter() - start) / 3, result

    small, _ = took("x" * 60_000)
    big, result = took("x" * 8_000_000)
    assert result == geminibrief.SHELL_UNVERIFIED
    assert big < small * 20 + 0.05  # refused by length: never scales with the 8 MB (a ratio, not a fixed bound)


# -- a failing check denies (round 3) --------------------------------------------------------------------------------


@pytest.mark.parametrize("error", [RuntimeError, ValueError, RecursionError, MemoryError])
@pytest.mark.parametrize("mode", ["warn", "block"])
def test_an_error_in_the_check_denies_with_fixed_text(
    error: type[Exception], mode: str, _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hooksdata import set_mode

    def boom(*_args: Any, **_kwargs: Any) -> str:
        raise error("tok_EXCEPTIONTEXT123")

    monkeypatch.setattr(geminibrief, "shell_command_class", boom)
    set_mode(_private_home, mode)
    command = f"echo tok_COMMANDTEXT456 {KEY}"
    out, _ = run(agents, _private_home, event(command))
    assert denied(out)
    text = reason(out)
    assert "could not be checked in time" in text and "wrapper" in text
    logged = json.dumps(read_log(_private_home)) + out
    assert "EXCEPTIONTEXT" not in logged and "COMMANDTEXT" not in logged and KEY not in logged
    assert read_log(_private_home)[-1]["decision"] == "error"


def test_the_error_denial_is_not_a_blanket_deny(_private_home: Path, agents: Path) -> None:
    assert run(agents, _private_home, event("ls -la")) == ("", "")


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
def test_an_interrupt_is_not_swallowed_by_the_check(
    error: type[BaseException], _private_home: Path, agents: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safo.modes import hooks as hooks_mode

    def boom(*_args: Any, **_kwargs: Any) -> str:
        raise error()

    monkeypatch.setattr(geminibrief, "shell_command_class", boom)
    with pytest.raises(error):
        hooks_mode.shell_vendor_check(json.loads(event("ls")))
