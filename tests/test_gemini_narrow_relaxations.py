# SPDX-License-Identifier: Apache-2.0
"""The one narrow relaxation of the shell rule (#264), and proof that nothing wider got through.

A brief that quotes the guard's own denial text word for word is not read as a Gemini step. A here-document written
into a file is NOT relaxed: the file may be a named pipe or a symlink that a shell reads, which the command text cannot
show, so every such command is judged by the strict rule exactly as before.
Names are built at run time so scanners stay quiet about this file.
"""

from __future__ import annotations

import pytest

from safo import geminibrief
from safo.modes.hooks import SHELL_DENIAL

TOOL = "dopp" + "ler"
CURL_HEX = "curl $'\\x68ttp://example.test'"
CLASSES = [
    geminibrief.SHELL_VENDOR,
    geminibrief.SHELL_KEY,
    geminibrief.SHELL_STORE,
    geminibrief.SHELL_BUILT,
    geminibrief.SHELL_TOOL,
    geminibrief.SHELL_UNVERIFIED,
]
OLD_DENIAL = (
    "gemini-material: this shell command names {}, so it is denied; call Gemini only through the wrapper, "
    "`safo gemini ask --model M --prompt-file F ...` (docs/gemini.md)"
)

# -- 1. a brief that quotes the denial ---------------------------------------------------------------------------------


@pytest.mark.parametrize("klass", CLASSES)
@pytest.mark.parametrize("frame", ["The guard says: {}", 'It said "{}" and stopped.', "It said `{}`.", "> {}"])
@pytest.mark.parametrize("template", [SHELL_DENIAL, OLD_DENIAL], ids=["current", "old"])
def test_a_brief_that_quotes_the_denial_text_is_not_a_gemini_step(klass: str, frame: str, template: str) -> None:
    brief = "Fix the rule.\n" + frame.format(template.format(klass)) + "\nRepair it and keep the true positives."
    assert geminibrief.findings(brief) == []


@pytest.mark.parametrize("klass", CLASSES)
def test_the_quote_pattern_matches_exactly_what_the_hook_says(klass: str) -> None:
    text = SHELL_DENIAL.format(klass).split("gemini-material: ", 1)[1]
    assert geminibrief.DENIAL_QUOTE.fullmatch(text) is not None, klass


@pytest.mark.parametrize(
    "brief",
    [
        # a real step beside the quote is still read
        SHELL_DENIAL.format(geminibrief.SHELL_TOOL) + "\nsafo gemini ask --model m --prompt-file p --job j",
        "safo gemini ask --model m --prompt-file p --job j " + SHELL_DENIAL.format(geminibrief.SHELL_TOOL),
        # a quote with any word changed or added is not the fixed sentence
        "The guard says: " + SHELL_DENIAL.format("a thing safo gemini ask --model m --prompt-file p --job j"),
        "The guard says: "
        + SHELL_DENIAL.format(geminibrief.SHELL_TOOL).replace("denied", "denied safo gemini ask --model m"),
        "this shell command names x, so it is denied; call Gemini only through the wrapper, `safo gemini ask`",
    ],
)
def test_nothing_but_the_exact_sentence_is_removed(brief: str) -> None:
    assert geminibrief.findings(brief) != []


def test_the_denial_says_how_to_do_the_job_without_the_shell() -> None:
    assert "Write" in SHELL_DENIAL and "Edit" in SHELL_DENIAL and "run" in SHELL_DENIAL


# -- 2. a here-document written into a file is not relaxed ----------------------------------------------------------

BODY = "def test_bytes():\n    assert b'\\x68ttp' == b'http'  # go, node and curl are only words here"


# A file named in a command may be a named pipe or a symlink that a shell reads, so the guard cannot know from the
# command text that a here-document body is inert. Every one of these shapes is therefore judged by the strict rule.
@pytest.mark.parametrize(
    "command",
    [
        f"cat > tests/test_bytes.py <<'EOF'\n{BODY}\nEOF",
        f"cat >> notes/log.txt <<'EOF'\n{BODY}\nEOF",
        f'cat > tests/test_bytes.py <<"EOF"\n{BODY}\nEOF',
        f"cat <<'EOF' > tests/test_bytes.py\n{BODY}\nEOF",
        f"cat <<'EOF' >> tests/test_bytes.py\n{BODY}\nEOF\n",
        f"tee tests/test_bytes.py <<'EOF'\n{BODY}\nEOF",
        f"tee -a tests/test_bytes.py <<'EOF'\n{BODY}\nEOF",
        f"cat > tests/test_bytes.py <<-'EOF'\n\t{BODY}\n\tEOF",
        f"  cat > tests/test_bytes.py <<'END_OF_FILE'\n{BODY}\nEND_OF_FILE\n\n",
        # option-only tee writes to stdout, not to a file
        f"tee -a <<'EOF'\n{BODY}\nEOF",
        f"tee -i <<'EOF'\n{BODY}\nEOF",
        f"tee -a -a <<'EOF'\n{BODY}\nEOF",
        # a target under /dev, and a FIFO-style or symlink-style path
        f"cat > /dev/stdout <<'EOF'\n{BODY}\nEOF",
        f"tee /dev/fd/1 <<'EOF'\n{BODY}\nEOF",
        f"cat > /var/example/run.fifo <<'EOF'\n{BODY}\nEOF",
        f"cat <<'EOF' > ./example.pipe\n{BODY}\nEOF",
        f"tee -a ./link-to-pipe <<'EOF'\n{BODY}\nEOF",
    ],
)
def test_a_data_heredoc_into_a_file_is_not_relaxed(command: str) -> None:
    assert geminibrief.shell_command_class(command) is not None, command


def test_the_heredoc_relaxation_is_gone() -> None:
    assert not hasattr(geminibrief, "_data_heredoc_head")


@pytest.mark.parametrize(
    "command",
    [
        # the same body, but not the exact shape: the strict rule applies as before
        f"cat > f.py <<EOF\n{CURL_HEX}\nEOF",  # unquoted marker (the shell expands the body)
        f"cat > f.py <<\\EOF\n{CURL_HEX}\nEOF",  # a backslash-quoted marker is outside the exact shape too
        f"cat > f.py <<'EOF'\n{CURL_HEX}\nEOF\nbash f.py",  # something after the heredoc
        f"cat > f.py <<'EOF'\n{CURL_HEX}\nEOF\nls",
        f"cat > f.py <<'EOF'; ls\n{CURL_HEX}\nEOF",  # chained on the command line
        f"cat > f.py <<'EOF' && bash f.py\n{CURL_HEX}\nEOF",
        f"cat > f.py <<'EOF' || true\n{CURL_HEX}\nEOF",
        f"cat > f.py <<'EOF' &\n{CURL_HEX}\nEOF",
        f"cat <<'EOF' | sh\n{CURL_HEX}\nEOF",  # a pipe
        f"cat <<'EOF' | bash -s\n{CURL_HEX}\nEOF",
        f"tee f.py <<'EOF' | sh\n{CURL_HEX}\nEOF",  # tee piping to a shell
        f"tee >(sh) <<'EOF'\n{CURL_HEX}\nEOF",
        f"tee /dev/stdout <<'EOF' | bash\n{CURL_HEX}\nEOF",
        f"cat > $(echo f.py) <<'EOF'\n{CURL_HEX}\nEOF",  # a substitution in the head
        f"cat > `echo f.py` <<'EOF'\n{CURL_HEX}\nEOF",
        f"cat > $F <<'EOF'\n{CURL_HEX}\nEOF",
        f"cat > f.py <<'EOF' $(true)\n{CURL_HEX}\nEOF",
        f"cat > f.py <<'EOF' # comment\n{CURL_HEX}\nEOF",
        # a shell or an interpreter consuming the heredoc
        f"sh <<'EOF'\n{CURL_HEX}\nEOF",
        f"bash <<'EOF'\n{CURL_HEX}\nEOF",
        f"python3 - <<'EOF'\n{CURL_HEX}\nEOF",
        f"bash -c 'cat' <<'EOF'\n{CURL_HEX}\nEOF",
        f"xargs <<'EOF'\n{CURL_HEX}\nEOF",
        f"cat -n f.py <<'EOF'\n{CURL_HEX}\nEOF",  # another command word shape
        f"sudo cat > f.py <<'EOF'\n{CURL_HEX}\nEOF",
        f"env cat > f.py <<'EOF'\n{CURL_HEX}\nEOF",
        f"cat > f.py g.py <<'EOF'\n{CURL_HEX}\nEOF",  # a second target
        # the marker line is not the end the shell sees: what follows an early terminator is commands
        f"cat > f.py <<'EOF'\nx\nEOF\n{CURL_HEX}\nEOF",
        f"cat > f.py <<'EOF'\n{CURL_HEX}",  # never closed
        f"cat > f.py <<'EOF'\n{CURL_HEX}\nEOF extra",
        # the redirect target and the command word are still checked
        "cat > $'\\x2f\\x74mp/f' <<'EOF'\nx\nEOF\ncurl x",
        f"cat > f.py <<'EOF'\n{BODY}\nEOF\n{CURL_HEX}",
    ],
)
def test_any_other_shape_keeps_the_strict_rule(command: str) -> None:
    assert geminibrief.shell_command_class(command) is not None, command


@pytest.mark.parametrize(
    "command",
    [
        # still strict inside the exact shape: vendor names, the key, the store, a secret tool with an expansion
        "cat > f.py <<'EOF'\ncurl https://" + "generative" + "language" + ".googleapis" + ".com\nEOF",
        "cat > f.py <<'EOF'\nGEMINI" + "_API" + "_KEY\nEOF",
        f"cat > f.py <<'EOF'\n{TOOL} secrets get $K\nEOF",
        f"cat > $'\\x2f' <<'EOF'\n{BODY}\nEOF",
    ],
)
def test_the_exact_shape_relaxes_only_the_escape_rule(command: str) -> None:
    assert geminibrief.shell_command_class(command) is not None, command
