# SPDX-License-Identifier: Apache-2.0
"""The one-time root setup runbook: full copy-paste lines for the maintainer, never run, no secret, no real host."""

from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path

from safo.broker import install, runbook


def text() -> str:
    return runbook.render(maintainer="MAINTAINER_LOGIN")


def command_lines(doc: str) -> list[str]:
    return [line for line in doc.splitlines() if line.startswith("ssh ")]


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
        assert any(line.startswith("ssh -t host 'sudo ") for line in step.splitlines()), step.splitlines()[0]


def test_every_command_is_a_full_ssh_sudo_line_with_the_host_placeholder() -> None:
    lines = command_lines(text())
    assert lines
    for line in lines:
        assert line.startswith("ssh -t host 'sudo "), line
        assert line.endswith("'"), line
        outer = shlex.split(line)
        assert outer[:3] == ["ssh", "-t", "host"], line
        assert len(outer) == 4, f"the remote command must be one quoted argument: {line}"


def code_lines(doc: str) -> list[str]:
    out: list[str] = []
    inside = False
    for line in doc.splitlines():
        if line.startswith("```"):
            inside = not inside
        elif inside:
            out.append(line)
    return out


def test_every_line_in_a_code_block_is_a_full_ssh_line() -> None:
    lines = code_lines(text())
    assert len(lines) >= 12
    for line in lines:
        assert line.startswith("ssh -t host 'sudo "), line  # no bare sudo, no root prompt, no comment lines


def test_the_key_is_read_on_the_remote_tty_and_never_appears() -> None:
    doc = text()
    cred = next(line for line in command_lines(doc) if "systemd-creds encrypt" in line)
    remote = shlex.split(cred)[3]
    assert remote.startswith("sudo bash -c ")
    # let a local shell do the remote parse: print the script exactly as bash would receive it
    done = subprocess.run(  # noqa: S603 - fixed argv, local sh evaluating a test string, no secret
        ["/bin/sh", "-c", "printf %s " + remote.removeprefix("sudo bash -c ")],
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
    assert "chmod 0600 /etc/safo/broker/paid-key" in script
    assert "host+tpm2" in doc  # the TPM variant is mentioned


def test_the_switch_is_left_off() -> None:
    doc = text()
    assert "gemini-paid-enabled" in doc  # the text says it stays off
    for line in command_lines(doc):
        assert "gemini-paid-enabled" not in line, "no command may create the switch"
    assert "OFF" in doc


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
    assert target.read_text() == 'release-signer namespaces="git" ssh-ed25519 PASTE_RELEASE_PUBLIC_KEY_HERE\n'
    assert oct(target.stat().st_mode & 0o777) == "0o644"


def test_no_secret_no_real_host_no_address() -> None:
    doc = text()
    assert "AIza" not in doc
    assert not re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY", doc)
    assert not re.search(r"ssh-(ed25519|rsa) AAAA[0-9A-Za-z+/]{20,}", doc)
    assert not re.search(r"sk-[A-Za-z0-9]{20,}", doc)
    assert not re.search(r"\b[A-Za-z0-9_-]{32,}\b", doc.replace("/", " ")), "a long token-like string"
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", doc), "an IPv4 address"
    assert not re.search(r"\b[0-9a-f]{2}(:[0-9a-f]{2}){5}\b", doc), "a MAC address"
    hosts = {h for h in re.findall(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b", doc)}
    allowed_suffixes = (".py", ".sock", ".socket", ".service", ".yaml", ".log", ".md", ".sha256", ".invalid")
    for h in hosts:
        if re.fullmatch(r"[0-9.]+", h):
            continue
        assert h.endswith(allowed_suffixes), f"looks like a hostname: {h}"
    assert " host " in doc  # the placeholder is what is used
    assert "@" not in re.sub(r"MAINTAINER_LOGIN", "", doc.replace("ssh -t host", "")), "no user@host forms"


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
