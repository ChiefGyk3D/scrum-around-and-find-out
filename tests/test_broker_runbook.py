# SPDX-License-Identifier: Apache-2.0
"""The one-time root setup runbook: full copy-paste lines for the maintainer, never run, no secret, no real host."""

from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path

import safo_broker_install as install
from safo.broker import runbook

KEY_TYPE = "sk-ssh-ed25519@openssh.com"  # a key type name, not a host


def text() -> str:
    return runbook.render(maintainer="MAINTAINER_LOGIN")


def grouped(lines: list[str]) -> list[str]:
    """Commands from lines: one `ssh ...` line is one command; a command with a here-document runs over several
    lines and ends where its single quotes balance (a line holding only the closing quote). Any other line stands
    alone."""
    out: list[str] = []
    open_command: list[str] = []
    for line in lines:
        if open_command:
            open_command.append(line)
            if "\n".join(open_command).count("'") % 2 == 0:
                out.append("\n".join(open_command))
                open_command = []
        elif line.startswith("ssh ") and line.count("'") % 2 == 1:
            open_command = [line]
        else:
            out.append(line)
    assert not open_command, "a command was never closed"
    return out


def command_lines(doc: str) -> list[str]:
    """Every command in the document (a here-document command is one entry, its lines joined by newlines)."""
    return [c for c in grouped(doc.splitlines()) if c.startswith("ssh ")]


def test_the_runbook_has_the_steps_in_order() -> None:
    doc = text()
    order = [
        "groupadd",
        "useradd",
        "usermod",
        "/etc/safo",
        "/opt/safo-broker",
        "safo-broker-install",
        "systemd-creds encrypt",
        "broker-release-signers",
        "broker-min-version",
        "enable",
    ]
    positions = [doc.index(x) for x in order]
    assert positions == sorted(positions)
    assert len(command_lines(doc)) >= 12


def test_every_step_names_its_blast_radius_and_rollback() -> None:
    doc = text()
    steps = re.split(r"^### Step ", doc, flags=re.MULTILINE)[1:]
    assert len(steps) >= 8
    for step in steps:
        assert "Blast radius:" in step, step.splitlines()[0]
        assert "Rollback:" in step, step.splitlines()[0]
        assert any(line.startswith("ssh -t host 'sudo env -i PATH=") for line in step.splitlines()), step.splitlines()[
            0
        ]


def test_every_command_is_a_full_ssh_sudo_line_with_the_host_placeholder() -> None:
    lines = command_lines(text())
    assert lines
    for line in lines:
        assert line.startswith("ssh -t host 'sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "), line
        assert line.endswith("'"), line
        assert line.count("\n") == 0 or line.endswith("\nEOF\n'"), line  # only a here-document spans lines
        outer = shlex.split(line)
        assert outer[:3] == ["ssh", "-t", "host"], line
        assert len(outer) == 4, f"the remote command must be one quoted argument: {line}"


def code_lines(doc: str) -> list[str]:
    """The commands inside the fenced blocks (a here-document command counts once)."""
    blocks: list[list[str]] = []
    inside = False
    for line in doc.splitlines():
        if line.startswith("```"):
            inside = not inside
            if inside:
                blocks.append([])
        elif inside:
            blocks[-1].append(line)
    return [command for block in blocks for command in grouped(block)]


def test_every_line_in_a_code_block_is_a_full_ssh_line() -> None:
    lines = code_lines(text())
    assert len(lines) >= 12
    for line in lines:
        assert line.startswith("ssh -t host 'sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "), (
            line
        )  # no bare sudo, no root prompt, no comment lines


def test_the_key_is_read_on_the_remote_tty_and_never_appears() -> None:
    doc = text()
    cred = next(line for line in command_lines(doc) if "systemd-creds encrypt" in line)
    remote = shlex.split(cred)[3]
    assert remote.startswith(f"sudo {runbook.ENV} bash -c ")
    # let a local shell do the remote parse: print the script exactly as bash would receive it
    done = subprocess.run(  # noqa: S603 - fixed argv, local sh evaluating a test string, no secret
        ["/bin/sh", "-c", "printf %s " + remote.removeprefix(f"sudo {runbook.ENV} bash -c ")],
        capture_output=True,
        text=True,
        check=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
    )
    script = done.stdout
    assert "read -rs" in script
    assert (
        'printf %s "$K" | systemd-creds encrypt --name=paid-key --with-key=host - /etc/safo/broker/paid-key' in script
    )
    assert "unset K" in script
    assert "set -euo pipefail" in script
    assert script.rindex("systemd-creds decrypt") < script.index(
        "mv /etc/safo/broker/paid-key.new /etc/safo/broker/paid-key"
    )
    assert "host+tpm2" in doc  # the TPM variant is mentioned


def switch_lines(doc: str) -> list[str]:
    return [line for line in command_lines(doc) if "gemini-paid-enabled" in line]


def test_the_switch_is_left_off_until_the_last_step() -> None:
    doc = text()
    assert "gemini-paid-enabled" in doc  # the text says it stays off
    assert "OFF" in doc
    creators = [x for x in switch_lines(doc) if "printf" in x or ">" in x]
    assert len(creators) == 1, "exactly one command creates the switch"
    last = doc.rindex("### Step ")
    assert doc.index(creators[0]) > last, "and it is in the last step"


def test_the_line_that_creates_the_switch_cannot_run_unless_the_preflight_passes() -> None:
    doc = text()
    line = next(x for x in switch_lines(doc) if "printf" in x)
    pre = "safo.gemini_preflight --enabling"
    assert pre in line
    assert "/opt/safo-broker/current/venv/bin/python -I -m" in line  # root runs the installed, reviewed copy, isolated
    assert line.index(pre) < line.index("&&") < line.index("printf") < line.index("gemini-paid-enabled")
    assert line.count("&&") >= 2 and "||" not in line and ";" not in line
    assert "--ack-observe-mode" not in line  # the acknowledgement is never in a pasteable line


def test_the_switch_step_explains_the_acknowledgement_its_evidence_blast_radius_and_rollback() -> None:
    doc = text()
    step = doc[doc.rindex("### Step ") :]
    assert "--ack-observe-mode" in step
    assert "empty" in step and "dry run" in step  # the minimum evidence
    assert "first clean real call" in step and "drop" in step
    assert "Blast radius:" in step and "Rollback:" in step
    assert step.index("Rollback:") < step.index("rm /etc/safo/gemini-paid-enabled")


def test_the_drop_step_comes_before_the_switch_and_says_drop_at_the_latest_after_the_first_clean_call() -> None:
    doc = text()
    assert doc.index("MODE=drop") < doc.rindex("### Step ")
    drop = next(
        x
        for x in re.split(r"^### Step ", doc, flags=re.MULTILINE)
        if x.splitlines()[0:1] and "drop mode" in x.splitlines()[0]
    )
    assert "first clean real call" in drop and "at the latest" in drop


def test_the_observe_week_wording_no_longer_treats_observe_as_a_safe_state_for_paid_use() -> None:
    doc = text()
    assert "In observe mode nothing is blocked" in doc  # still said, but now with the consequence
    assert "does not stop the key leaving" in doc or "could send the key" in doc


def test_the_allowed_signers_file_is_created_with_the_git_namespace_and_a_placeholder_key(tmp_path: Path) -> None:
    doc = text()
    line = next(line for line in command_lines(doc) if "printf" in line and "broker-release-signers" in line)
    assert "PASTE_RELEASE_PUBLIC_KEY_HERE" in line
    assert "0644" in line
    # run the quoting chain locally against a temporary path (no sudo, no real file): the file must hold the quotes
    remote = shlex.split(line)[3].removeprefix("sudo ")
    target = tmp_path / "signers"
    remote = remote.replace("/etc/safo/broker-release-signers", str(target))
    subprocess.run(["sh", "-c", remote], check=True, stdin=subprocess.DEVNULL, timeout=30)  # noqa: S603, S607 - fixed test string, temp path
    assert (
        target.read_text()
        == 'release-signer namespaces="git" sk-ssh-ed25519@openssh.com PASTE_RELEASE_PUBLIC_KEY_HERE\n'
    )
    assert oct(target.stat().st_mode & 0o777) == "0o644"


def test_no_secret_no_real_host_no_address() -> None:
    doc = text()
    assert "AIza" not in doc
    assert not re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY", doc)
    assert not re.search(r"ssh-(ed25519|rsa) AAAA[0-9A-Za-z+/]{20,}", doc)
    assert not re.search(r"sk-[A-Za-z0-9]{20,}", doc)
    assert not re.search(r"\b[A-Za-z0-9_-]{32,}\b", doc.replace("/", " ")), "a long token-like string"
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", re.sub(r"203\.0\.113\.\d{1,3}", "", doc)), "an IPv4 address"
    assert not re.search(r"\b[0-9a-f]{2}(:[0-9a-f]{2}){5}\b", doc), "a MAC address"
    models = re.findall(r"^    (gemini-[a-z0-9.-]+):", runbook.BROKER_CONFIG, re.MULTILINE)  # model names have dots
    assert len(models) >= 2
    for model in models:
        doc = doc.replace(model, "MODEL")
    hosts = {h for h in re.findall(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b", doc.replace(KEY_TYPE, ""))}
    allowed_suffixes: tuple[str, ...] = (".conf", ".timer", ".new", ".py", ".sock", ".socket", ".service")
    allowed_suffixes = (*allowed_suffixes, ".yaml", ".log", ".md", ".sha256", ".invalid")
    for h in hosts:
        if re.fullmatch(r"[0-9.]+", h):
            continue
        assert h.endswith(allowed_suffixes), f"looks like a hostname: {h}"
    assert " host " in doc  # the placeholder is what is used
    assert "@" not in re.sub(r"MAINTAINER_LOGIN", "", doc.replace("ssh -t host", "").replace(KEY_TYPE, "")), (
        "no user@host forms"
    )


def test_the_maintainer_login_is_validated() -> None:
    import pytest

    for bad in ("a b", "x;rm -rf /", "$(id)", "", "a'b", "-oProxyCommand=x", "x" * 40):
        with pytest.raises(ValueError, match="login"):
            runbook.render(maintainer=bad)
    assert "alice" in runbook.render(maintainer="alice")


def test_the_runbook_module_cannot_run_anything() -> None:
    source = Path(runbook.__file__).read_text()
    for banned in ("subprocess", "os.system", "os.exec", "os.popen", "import pty"):
        assert banned not in source
    # and the installer's plan command only prints it
    plan_src = Path(install.__file__).read_text().split("def cmd_plan", 1)[1].split("\ndef ", 1)[0]
    assert "run(" not in plan_src
    assert "subprocess" not in plan_src


def test_the_quoting_survives_a_local_shell_parse() -> None:
    """Every line parses as exactly one ssh invocation with one remote command; the remote command parses too."""
    for line in command_lines(text()):
        remote = shlex.split(line)[3]
        shlex.split(remote)  # raises on unbalanced quotes


def test_the_installer_is_read_and_installed_from_one_root_owned_copy() -> None:
    """Never hash a file in a folder the maintainer can write and then copy it in a second command."""
    doc = text()
    lines = command_lines(doc)
    stage = "/var/lib/safo-broker-install/stage/safo-broker-install"
    take = next(i for i, line in enumerate(lines) if "packaging/safo_broker_install.py" in line)
    hash_ = next(i for i, line in enumerate(lines) if "sha256sum" in line)
    final = next(
        i
        for i, line in enumerate(lines)
        if "/usr/local/sbin/safo-broker-install'" in line and "install -m 0755" in line
    )
    assert take < hash_ < final
    assert stage in lines[hash_]
    assert stage in lines[final]
    assert "reviewed/checkout" not in lines[hash_]
    assert "reviewed/checkout" not in lines[final]
    installer = [x for x in lines if "safo_broker_install.py" in x]
    assert sum("reviewed/checkout" in line for line in installer) == 1  # the checkout is read exactly once


def test_root_commands_run_with_a_fixed_environment_and_a_locked_down_pager() -> None:
    lines = command_lines(text())
    assert lines
    for line in lines:
        assert " env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin " in line, line
    pager = next(line for line in lines if " less " in line)
    for need in ("LESSSECURE=1", "LESSOPEN= ", "LESSCLOSE= "):
        assert need in pager
    # nothing relies on an unqualified program name picked up from the remote session: the PATH is the fixed one
    assert not any("PATH=$" in line or 'PATH="$' in line for line in lines)


INTERPRETER = re.compile(r"/opt/safo-broker/[A-Za-z0-9_./-]*/python[0-9.]*")


def test_every_interpreter_path_in_the_runbook_is_the_one_the_installer_builds() -> None:
    """#298 (1): the runbook named current/bin/python; the installer builds only current/venv/bin/python."""
    named = set(INTERPRETER.findall(text()))
    assert named, "the runbook names the installed interpreter at least once (the enable step)"
    built = install.RELEASE_INTERPRETER
    assert built == f"{install.UNIT_EXEC_PREFIX}/venv/bin/python"
    assert named == {built}
    # the installer really creates venv/bin/python inside a release, and `current` points at that release
    source = Path(install.__file__).read_text()
    assert 'stage / "venv" / "bin" / "python"' in source
    # and the unit files the installer writes use the same interpreter
    units = [path.read_text() for path in sorted((Path(install.__file__).parent / "systemd").glob("*.service"))]
    assert any(f"ExecStart={built} -I -m safo.broker\n" in unit for unit in units)


def config_step(doc: str) -> str:
    return next(
        x for x in re.split(r"^### Step ", doc, flags=re.MULTILINE)[1:] if "broker configuration" in x.splitlines()[0]
    )


def test_a_step_creates_the_broker_config_before_the_socket_and_the_enable_switch() -> None:
    """#298 (2): nothing created /etc/safo/broker.yaml, so the service could not start."""
    doc = text()
    step = config_step(doc)
    assert doc.index(step) < doc.index("systemctl enable --now safo-broker.socket") < doc.rindex("### Step ")
    assert "Blast radius:" in step and "Rollback:" in step
    assert "rm -f /etc/safo/broker.yaml" in step[step.index("Rollback:") :]
    command = next(c for c in command_lines(step) if "broker.yaml.new" in c)
    assert "install -m 0644 -o root -g root /dev/stdin /etc/safo/broker.yaml.new" in command  # root-owned, 0644
    assert command.index("test ! -e /etc/safo/broker.yaml") < command.index("install -m 0644") < command.index("mv ")
    assert "mv /etc/safo/broker.yaml.new /etc/safo/broker.yaml" in command  # atomic: a rename in one directory
    assert '<<"EOF"\n' in command and command.endswith("\nEOF\n'")  # a quoted here-document, closed
    assert command.count("$(id -u MAINTAINER_LOGIN)") == 1  # the number is asked of the machine at run time
    assert command.index("$(id -u MAINTAINER_LOGIN)") < command.index('<<"EOF"')  # ... outside the file text
    assert "allowed_uids: [ACCOUNT_UID_HERE]" in command  # the file text carries a mark, never an expansion
    assert "MAINTAINER_LOGIN]" not in command  # never the name in the list
    note = step[step.index("Note:") :]
    assert "~/.config/safo/broker-client.yaml" in note and "0600" in note  # and the user's own client config


def test_the_config_here_document_runs_and_writes_a_root_file_with_the_account_id(tmp_path: Path) -> None:
    """Run the remote command in a local shell against a temporary path: the file holds the real id, mode 0644."""
    import getpass
    import os

    login = getpass.getuser()
    if not runbook.LOGIN.fullmatch(login):
        import pytest

        pytest.skip("the local login name is not a plain login name")
    doc = runbook.render(maintainer=login)
    command = next(c for c in command_lines(config_step(doc)) if "broker.yaml.new" in c)
    remote = shlex.split(command)[3].removeprefix("sudo " + runbook.ENV + " ")
    target = tmp_path / "broker.yaml"
    head, body = remote.split('<<"EOF"\n', 1)  # only the command is pointed at the temporary path, not the text
    local = head.replace("-o root -g root ", "").replace("/etc/safo/broker.yaml", str(target)) + '<<"EOF"\n' + body
    subprocess.run(["sh", "-c", local], check=True, stdin=subprocess.DEVNULL, timeout=30)  # noqa: S603, S607 - fixed test string, temp path
    assert target.read_text() == runbook.broker_config(str(os.getuid()))
    assert oct(target.stat().st_mode & 0o777) == "0o644" and not (tmp_path / "broker.yaml.new").exists()
    again = subprocess.run(["sh", "-c", local], check=False, stdin=subprocess.DEVNULL, timeout=30)  # noqa: S603, S607 - same
    assert again.returncode != 0, "a second run refuses to replace the file"
    assert target.read_text() == runbook.broker_config(str(os.getuid()))


def test_the_enable_step_is_still_last_and_its_preflight_checks_the_users_client_config() -> None:
    doc = text()
    line = next(x for x in switch_lines(doc) if "printf" in x)
    # the preflight is told WHO the maintainer is by number; it looks the home up itself, in Python. No value read from
    # a data file (the passwd file) ever reaches the root shell's command line.
    assert "--maintainer-uid $(id -u MAINTAINER_LOGIN)" in line
    assert line.index("--maintainer-uid") < line.index("&&")
    for banned in ("getent", "cut ", "--client-config", "/etc/passwd", "~"):
        assert banned not in line, banned
    assert line.count("$(") == 1  # the one expansion is the numeric id
    assert doc.rindex("### Step ") < doc.index(line)


# -- setup-command hardening (#303): embedded file text never reaches a shell as code ----------------------------------

EXPANSION_CHARS = ("$", "`", "\\")
HEREDOC_START = re.compile(r"<<-?(?P<delim>\S+)\n")


def heredocs(command: str) -> list[tuple[str, str, str]]:
    """(the raw delimiter word, its body, the command words before it) for every here-document in one command."""
    found = []
    for match in HEREDOC_START.finditer(command):
        word = match.group("delim")
        name = word.strip("\"'\\")
        rest = command[match.end() :]
        body = rest.split("\n" + name + "\n", 1)[0] + "\n" if ("\n" + name + "\n") in rest else rest
        found.append((word, body, command[: match.start()]))
    return found


def embedded_problems(commands: list[str]) -> list[str]:
    """Ways here-document text could be read by a shell: an unquoted delimiter, or an expansion form in the body."""
    problems = []
    for command in commands:
        for word, body, _ in heredocs(command):
            if word[0] not in "\"'\\":
                problems.append(f"unquoted delimiter {word}")
            problems += [f"{ch!r} in the embedded text" for ch in EXPANSION_CHARS if ch in body]
    return problems


def test_no_runbook_command_can_expand_embedded_text() -> None:
    commands = command_lines(text())
    assert any(heredocs(c) for c in commands), "the runbook has a here-document to judge"
    assert not embedded_problems(commands)
    # the source text itself has no expansion form either, so it is also safe if some other writer quotes it differently
    assert not [ch for ch in EXPANSION_CHARS if ch in runbook.BROKER_CONFIG]
    assert runbook.BROKER_CONFIG.count(runbook.UID_MARK) == 1


def test_the_embedded_text_check_bites() -> None:
    good = text()
    config = next(c for c in command_lines(good) if "broker.yaml.new" in c)
    assert not embedded_problems([config])
    assert embedded_problems([config.replace('<<"EOF"', "<<EOF")]), "an unquoted delimiter"
    for form in ("$(touch x)", "`touch x`", "${HOME}", "$HOME", "\\$x"):
        poisoned = config.replace("server:\n", f"# {form}\nserver:\n", 1)
        assert poisoned != config
        assert embedded_problems([poisoned]), form


def test_the_only_expansion_outside_embedded_text_is_the_numeric_id() -> None:
    for command in command_lines(text()):
        for _, _, head in heredocs(command):
            assert head.count("$(") == 1 and "$(id -u MAINTAINER_LOGIN)" in head, head
            assert "`" not in head


def test_the_config_command_does_not_run_embedded_text_at_all(tmp_path: Path) -> None:
    """Run the real command with a poisoned config text: nothing in the text is expanded or executed."""
    import getpass

    login = getpass.getuser()
    if not runbook.LOGIN.fullmatch(login):
        import pytest

        pytest.skip("the local login name is not a plain login name")
    marker = tmp_path / "ran"
    poison = f"# $(touch {marker}) `touch {marker}` ${{HOME}} \\n\n"
    command = next(c for c in command_lines(runbook.render(maintainer=login)) if "broker.yaml.new" in c)
    remote = shlex.split(command)[3].removeprefix("sudo " + runbook.ENV + " ")
    head, body = remote.split('<<"EOF"\n', 1)
    target = tmp_path / "broker.yaml"
    local = (
        head.replace("-o root -g root ", "").replace("/etc/safo/broker.yaml", str(target)) + '<<"EOF"\n' + poison + body
    )
    subprocess.run(["sh", "-c", local], check=True, stdin=subprocess.DEVNULL, timeout=30)  # noqa: S603, S607 - fixed test string, temp path
    assert not marker.exists()
    assert target.read_text().startswith(poison)
