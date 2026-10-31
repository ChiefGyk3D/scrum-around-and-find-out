# SPDX-License-Identifier: Apache-2.0
"""The installer's fixed policy on unit files: an allowlist over a strict parser.

The parser refuses everything systemd and a line-splitting checker could read differently, so a unit that passes cannot
resolve to other values in systemd. Every key must be pinned exactly or be in a short list of harmless ones.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import safo_broker_install as install
from safo_broker_install import InstallError
from unitdata import HARMLESS_KEYS, REQUIRED_BY_UNIT, read

NAMES = tuple(REQUIRED_BY_UNIT)


def shipped() -> dict[str, str]:
    return {n: read(n) for n in NAMES}


def refused(name: str, text: str | bytes, match: str = "unit policy") -> str:
    units: dict[str, str | bytes] = dict(shipped())
    units[name] = text
    with pytest.raises(InstallError, match=match) as exc:
        install.enforce_unit_policy(units)
    return str(exc.value)


def test_the_installer_manages_exactly_these_units() -> None:
    assert install.UNIT_NAMES == NAMES
    assert set(install.UNIT_POLICY) == set(NAMES)


def test_the_installer_tables_equal_the_pinned_tests_tables() -> None:
    for name, rows in REQUIRED_BY_UNIT.items():
        assert install.UNIT_POLICY[name] == rows, name
    assert set(install.HARMLESS_KEYS) == set(HARMLESS_KEYS)


def test_the_shipped_units_pass() -> None:
    install.enforce_unit_policy(dict(shipped()))
    install.enforce_unit_policy({n: read(n).encode() for n in NAMES})


def test_a_missing_unit_is_refused() -> None:
    units = shipped()
    del units["safo-broker-egress.service"]
    with pytest.raises(InstallError, match="missing"):
        install.enforce_unit_policy(dict(units))


# ---- parser differential shapes: refused outright -----------------------------------------------------------------


SHAPES = {
    "carriage return": "\r",
    "nul": "\x00",
    "vertical tab": "\x0b",
    "form feed": "\x0c",
    "escape": "\x1b",
    "next line": "\x85",
    "line separator": "\u2028",
    "paragraph separator": "\u2029",
    "zero width space": "\u200b",
    "bidi override": "\u202e",
    "non-breaking space": "\xa0",
    "latin letter": "é",
    "delete": "\x7f",
}


@pytest.mark.parametrize("shape", sorted(SHAPES))
@pytest.mark.parametrize("place", ["own-line", "in-value", "in-comment"])
def test_separator_and_control_characters_are_refused_everywhere(shape: str, place: str) -> None:
    ch = SHAPES[shape]
    text = read("safo-broker.service")
    if place == "own-line":
        text = text.replace("[Service]\n", f"[Service]\n{ch}\n", 1)
    elif place == "in-value":
        text = text.replace("NoNewPrivileges=yes", f"NoNewPrivileges=yes{ch}PrivateTmp=no", 1)
    else:
        text = text.replace("[Service]\n", f"[Service]\n# note {ch} here\n", 1)
    refused("safo-broker.service", text)


def test_a_carriage_return_cannot_hide_a_second_assignment() -> None:
    text = read("safo-broker.service").replace("NoNewPrivileges=yes\n", "NoNewPrivileges=yes\rNoNewPrivileges=no\n", 1)
    refused("safo-broker.service", text)


@pytest.mark.parametrize("data", [b"\xff\xfe", b"[Unit]\nDescription=\xc3\x28\n", b"\xed\xa0\x80"])
def test_invalid_utf8_is_refused(data: bytes) -> None:
    refused("safo-broker.socket", data, "UTF-8")


def test_a_utf8_bom_is_refused() -> None:
    refused("safo-broker.socket", b"\xef\xbb\xbf" + read("safo-broker.socket").encode())


@pytest.mark.parametrize(
    "tail",
    ["\\", " \\", "\\\\", "ProtectSystem=strict\\", "x=\\\nno", "# comment \\"],
)
def test_any_backslash_is_refused(tail: str) -> None:
    text = read("safo-broker.service").rstrip("\n") + f"\n{tail}\n"
    refused("safo-broker.service", text)


def test_a_backslash_inside_a_value_is_refused() -> None:
    text = read("safo-broker.service").replace("Description=SAFO Gemini broker", "Description=SAFO \\x41 broker", 1)
    refused("safo-broker.service", text)


@pytest.mark.parametrize(
    "extra",
    [
        "[Service]\nPrivateTmp=no\n",  # a second section of the same name
        "[Unit]\nDescription=again\n",
        "[service]\nPrivateTmp=no\n",  # case variation of a section
        "[SERVICE]\nPrivateTmp=no\n",
        "[Install]\nWantedBy=multi-user.target\n",  # a section this unit does not have
        "[X-Anything]\nA=b\n",
        "[Service \nPrivateTmp=no\n",
        "[]\nA=b\n",
    ],
)
def test_second_or_unknown_sections_are_refused(extra: str) -> None:
    refused("safo-broker.service", read("safo-broker.service").rstrip("\n") + "\n" + extra)


def test_a_setting_before_any_section_is_refused() -> None:
    refused("safo-broker.socket", "Accept=no\n" + read("safo-broker.socket"))


@pytest.mark.parametrize(
    "line", ["nonewprivileges=no", "NONEWPRIVILEGES=no", "noNewPrivileges=no", "Nonewprivileges=no"]
)
def test_key_case_variations_are_refused(line: str) -> None:
    text = read("safo-broker.service").replace("[Service]\n", f"[Service]\n{line}\n", 1)
    refused("safo-broker.service", text, "allowed")


@pytest.mark.parametrize(
    "line", ["this is not a setting", "=value", "Key Name=1", "9Key=1", "Key-Name=1", "NoNewPrivileges"]
)
def test_a_line_that_is_not_a_setting_is_refused(line: str) -> None:
    refused("safo-broker.service", read("safo-broker.service").replace("[Service]\n", f"[Service]\n{line}\n", 1))


def test_a_pinned_key_given_twice_or_overridden_later_is_refused() -> None:
    base = read("safo-broker.service")
    refused(
        "safo-broker.service", base.replace("NoNewPrivileges=yes\n", "NoNewPrivileges=yes\nNoNewPrivileges=yes\n", 1)
    )
    refused("safo-broker.service", base.rstrip("\n") + "\nNoNewPrivileges=no\n")
    refused("safo-broker.service", base.rstrip("\n") + "\nSystemCallFilter=\n")
    refused("safo-broker.service", base.rstrip("\n") + "\nCapabilityBoundingSet=CAP_SYS_ADMIN\n")


def test_whitespace_around_the_equals_sign_cannot_hide_a_value() -> None:
    base = read("safo-broker.service")
    refused("safo-broker.service", base.rstrip("\n") + "\nNoNewPrivileges   =   no\n")
    refused("safo-broker.service", base.rstrip("\n") + "\n\tPrivateTmp\t=\tno\n")


# ---- the allowlist -------------------------------------------------------------------------------------------------


DENYLISTED = [
    "LoadCredential=paid:/etc/shadow",
    "SetCredential=a:b",
    "ImportCredential=*",
    "LoadCredentialEncrypted=other:/etc/safo/broker/other",
    "StandardInput=file:/etc/shadow",
    "StandardOutput=file:/etc/safo/gemini-paid-enabled",
    "StandardError=socket",
    "RootDirectory=/",
    "RootImage=/x.img",
    "MountImages=/x.img:/mnt",
    "ExtensionImages=/x.img",
    "ExtensionDirectories=/x",
    "WorkingDirectory=/etc",
    "OnFailure=evil.service",
    "OnSuccess=evil.service",
    "ExecStartPost=/bin/true",
    "ExecStop=/bin/true",
    "ExecReload=/bin/true",
    "ExecCondition=/bin/true",
    "ExecStopPost=/bin/true",
    "ExecStartPre=/bin/true",
    "ExecStart=/bin/true",
    "ExecStartPre=+/bin/true",
    "ExecStartPre=-/bin/true",
    "ExecStartPre=!/bin/true",
    "ExecStartPre=!!/bin/true",
    "ExecStartPre=:/bin/true",
    "ExecStartPre=|/bin/true",
    "ExecStartPre=@/bin/true x",
    "DynamicUser=yes",
    "PrivateUsers=yes",
    "EnvironmentFile=/etc/x",
    "PassEnvironment=HOME",
    "UnsetEnvironment=X",
    "PermissionsStartOnly=yes",
    "BindPaths=/etc",
    "BindReadOnlyPaths=/etc:/etc/hosts",
    "BindReadOnlyPaths=/etc/safo/egress/hosts:/etc/passwd",
    "TemporaryFileSystem=/etc",
    "InaccessiblePaths=/",
    "SupplementaryGroups=disk",
    "Slice=system.slice",
    "Delegate=yes",
    "KillMode=none",
    "SuccessAction=exit",
    "FailureAction=reboot",
    "Nice=-20",
    "OOMScoreAdjust=-1000",
    "SecureBits=keep-caps",
    "AppArmorProfile=unconfined",
    "SELinuxContext=system_u:system_r:unconfined_t:s0",
    "IPAddressAllow=any",
    "IPAddressDeny=",
    "PrivateNetwork=no",
    "NetworkNamespacePath=/proc/1/ns/net",
    "JoinsNamespaceOf=other.service",
    "ProtectProc=default",
    "SystemCallFilter=@privileged",
    "UtmpIdentifier=x",
    "PAMName=login",
    "TTYPath=/dev/tty1",
    "ConfigurationDirectory=x",
    "RuntimeDirectory=x",
    "CacheDirectory=x",
    "LogsDirectory=x",
    "ExecPaths=/",
    "NoExecPaths=/",
    "Environment=LD_PRELOAD=/tmp/x",
    "LimitCORE=infinity",
    "TasksMax=infinity",
    "MemoryMax=infinity",
    "Restart=always",
    "SomethingUnknown=1",
    "X-Custom=1",
]


@pytest.mark.parametrize("line", DENYLISTED)
def test_every_unknown_or_dangerous_key_is_refused(line: str) -> None:
    text = read("safo-broker.service").replace("[Service]\n", f"[Service]\n{line}\n", 1)
    message = refused("safo-broker.service", text)
    assert line.split("=")[0] in message


@pytest.mark.parametrize(
    "line",
    [
        "PartOf=other.service",
        "Requisite=x.service",
        "BindsTo=x.service",
        "Conflicts=x.service",
        "Upholds=x.service",
        "OnFailure=x.service",
        "Alias=x",
    ],
)
def test_unit_section_keys_beyond_the_harmless_list_are_refused(line: str) -> None:
    text = read("safo-broker.service").replace("[Unit]\n", f"[Unit]\n{line}\n", 1)
    refused("safo-broker.service", text)


@pytest.mark.parametrize("section_key", sorted(HARMLESS_KEYS))
def test_the_harmless_keys_are_allowed(section_key: tuple[str, str]) -> None:
    section, key = section_key
    text = read("safo-broker.service").replace(
        f"[{section}]\n", f"[{section}]\n{key}=a-value-without-power.service\n", 1
    )
    install.enforce_unit_policy({**shipped(), "safo-broker.service": text})


def test_the_socket_and_timer_units_are_held_to_the_same_rules() -> None:
    refused(
        "safo-broker.socket", read("safo-broker.socket").replace("[Socket]\n", "[Socket]\nExecStartPre=/bin/true\n", 1)
    )
    refused("safo-broker.socket", read("safo-broker.socket").replace("SocketMode=0660", "SocketMode=0666"))
    refused(
        "safo-broker-egress-refresh.timer",
        read("safo-broker-egress-refresh.timer").replace("[Timer]\n", "[Timer]\nOnCalendar=*:*:*\n", 1),
    )
    refused(
        "safo-broker-egress.service",
        read("safo-broker-egress.service").replace(
            "CapabilityBoundingSet=CAP_NET_ADMIN", "CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN"
        ),
    )
    refused(
        "safo-broker-egress-refresh.service",
        read("safo-broker-egress-refresh.service").replace("egress refresh\n", "egress refresh --anything\n", 1),
    )


def test_the_bind_mount_of_the_hosts_view_is_pinned_to_its_exact_source_and_target() -> None:
    install.enforce_unit_policy(dict(shipped()))
    base = read("safo-broker.service")
    assert "BindReadOnlyPaths=/etc/safo/egress/hosts:/etc/hosts\n" in base
    refused(
        "safo-broker.service",
        base.replace("/etc/safo/egress/hosts:/etc/hosts", "/etc/safo/egress/hosts:/etc/hosts:rbind"),
    )
    refused("safo-broker.service", base.replace("/etc/safo/egress/hosts:/etc/hosts", "/etc/hosts:/etc/hosts"))
    refused("safo-broker.service", base.replace("BindReadOnlyPaths=/etc/safo/egress/hosts:/etc/hosts\n", ""))
    refused("safo-broker.service", base.replace("BindReadOnlyPaths=", "BindPaths="))
    refused("safo-broker.service", base.rstrip("\n") + "\nBindReadOnlyPaths=/etc/safo/broker:/mnt\n")


def test_dropping_any_pinned_line_from_any_unit_is_refused() -> None:
    count = 0
    for name, rows in REQUIRED_BY_UNIT.items():
        text = read(name)
        for _section, key, value in rows:
            lines = text.split("\n")
            cut = [x for x in lines if x.strip() != f"{key}={value}"]
            assert len(cut) == len(lines) - 1, (name, key, value)
            message = refused(name, "\n".join(cut))
            assert key in message
            count += 1
    assert count > 100


# ---- mutation checks on the allowlist itself -----------------------------------------------------------------------


def test_the_checker_bites_when_the_allowlist_is_widened(monkeypatch: pytest.MonkeyPatch) -> None:
    text = read("safo-broker.service").replace("[Service]\n", "[Service]\nLoadCredential=a:/etc/shadow\n", 1)
    units = {**shipped(), "safo-broker.service": text}
    with pytest.raises(InstallError):
        install.enforce_unit_policy(dict(units))
    widened = (*install.UNIT_POLICY["safo-broker.service"], ("Service", "LoadCredential", "a:/etc/shadow"))
    monkeypatch.setattr(install, "UNIT_POLICY", {**install.UNIT_POLICY, "safo-broker.service": widened})
    install.enforce_unit_policy(dict(units))  # with the key pinned the same text passes: the guard really is the table


def test_the_checker_bites_when_the_harmless_list_is_widened(monkeypatch: pytest.MonkeyPatch) -> None:
    text = read("safo-broker.service").replace("[Unit]\n", "[Unit]\nOnFailure=x.service\n", 1)
    units = {**shipped(), "safo-broker.service": text}
    with pytest.raises(InstallError):
        install.enforce_unit_policy(dict(units))
    monkeypatch.setattr(install, "HARMLESS_KEYS", (*install.HARMLESS_KEYS, ("Unit", "OnFailure")))
    install.enforce_unit_policy(dict(units))


# ---- the installer applies it after the signature, before anything is built ----------------------------------------


def test_the_installer_refuses_a_release_with_a_hidden_override(tmp_path: Path) -> None:
    from installdata import make_world

    world = make_world(tmp_path)
    sneaky = read("safo-broker.service").replace(
        "NoNewPrivileges=yes\n", "NoNewPrivileges=yes\rNoNewPrivileges=no\n", 1
    )
    world.release("1.0.0", units={"safo-broker.service": sneaky})
    with pytest.raises(InstallError, match="unit policy"):
        install.install("1.0.0", world.layout, world.hooks(), apply=True, out=lambda s: None)
    assert not (world.layout.opt_dir / "current").exists()


# ---- what systemd itself makes of the staged units (never started) ----------------------------------------------


ANALYZE = shutil.which("systemd-analyze")


@pytest.mark.skipif(ANALYZE is None, reason="systemd-analyze is not installed here; the systemd cross-check is not run")
def test_systemd_agrees_that_the_shipped_units_are_clean_and_within_their_exposure_budget(tmp_path: Path) -> None:
    release = tmp_path / "rel"
    (release / "venv" / "bin").mkdir(parents=True)
    py = release / "venv" / "bin" / "python"
    py.write_text("#!/bin/sh\n")
    py.chmod(0o755)
    units = release / "units"
    units.mkdir()
    for name in NAMES:
        (units / name).write_text(read(name))
    install.default_verify_units(units, release)  # raises on any warning, any unknown key, or a score over budget


@pytest.mark.skipif(ANALYZE is None, reason="systemd-analyze is not installed here; the systemd cross-check is not run")
def test_the_systemd_cross_check_refuses_a_weakened_service_even_if_the_policy_were_bypassed(tmp_path: Path) -> None:
    release = tmp_path / "rel"
    (release / "venv" / "bin").mkdir(parents=True)
    py = release / "venv" / "bin" / "python"
    py.write_text("#!/bin/sh\n")
    py.chmod(0o755)
    units = release / "units"
    units.mkdir()
    for name in NAMES:
        text = read(name)
        if name == "safo-broker.service":
            for weaker in (
                "ProtectSystem=strict",
                "PrivateDevices=yes",
                "ProtectKernelTunables=yes",
                "RestrictNamespaces=yes",
                "MemoryDenyWriteExecute=yes",
                "NoNewPrivileges=yes",
                "LockPersonality=yes",
                "ProtectHome=yes",
                "PrivateTmp=yes",
            ):
                text = text.replace(weaker + "\n", "")
        (units / name).write_text(text)
    with pytest.raises(InstallError, match="exposure"):
        install.default_verify_units(units, release)
