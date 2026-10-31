# SPDX-License-Identifier: Apache-2.0
"""The hardening the broker's systemd units must carry, and a parser that checks a unit text against it."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
UNIT_DIR = REPO / "packaging" / "systemd"

# (section, key, value): every line must be present exactly as written. Multi-valued keys list each value.
REQUIRED_SERVICE: tuple[tuple[str, str, str], ...] = (
    ("Unit", "Requires", "safo-broker.socket"),
    ("Unit", "ConditionPathExists", "/etc/safo/gemini-paid-enabled"),
    ("Unit", "StartLimitIntervalSec", "60"),
    ("Unit", "StartLimitBurst", "5"),
    ("Service", "Type", "simple"),
    ("Service", "User", "safo-broker"),
    ("Service", "Group", "safo-broker"),
    ("Service", "ExecStartPre", "/opt/safo-broker/current/venv/bin/python -I -m safo.broker.floor"),
    ("Service", "ExecStart", "/opt/safo-broker/current/venv/bin/python -I -m safo.broker"),
    ("Service", "LoadCredentialEncrypted", "paid-key:/etc/safo/broker/paid-key"),
    ("Service", "StateDirectory", "safo-broker"),
    ("Service", "StateDirectoryMode", "0700"),
    ("Service", "ReadWritePaths", "/var/lib/safo-broker"),
    ("Service", "ReadOnlyPaths", "/etc/safo /opt/safo-broker"),
    ("Service", "UMask", "0077"),
    ("Service", "Environment", "PYTHONDONTWRITEBYTECODE=1"),
    ("Service", "NoNewPrivileges", "yes"),
    ("Service", "CapabilityBoundingSet", ""),
    ("Service", "AmbientCapabilities", ""),
    ("Service", "PrivateTmp", "yes"),
    ("Service", "PrivateDevices", "yes"),
    ("Service", "PrivateMounts", "yes"),
    ("Service", "ProtectSystem", "strict"),
    ("Service", "ProtectHome", "yes"),
    ("Service", "ProtectProc", "invisible"),
    ("Service", "ProcSubset", "pid"),
    ("Service", "ProtectKernelTunables", "yes"),
    ("Service", "ProtectKernelModules", "yes"),
    ("Service", "ProtectKernelLogs", "yes"),
    ("Service", "ProtectControlGroups", "yes"),
    ("Service", "ProtectClock", "yes"),
    ("Service", "ProtectHostname", "yes"),
    ("Service", "RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"),
    ("Service", "RestrictNamespaces", "yes"),
    ("Service", "RestrictRealtime", "yes"),
    ("Service", "RestrictSUIDSGID", "yes"),
    ("Service", "LockPersonality", "yes"),
    ("Service", "MemoryDenyWriteExecute", "yes"),
    ("Service", "SystemCallArchitectures", "native"),
    ("Service", "SystemCallFilter", "@system-service"),
    ("Service", "SystemCallFilter", "~@privileged @resources"),
    ("Service", "SystemCallErrorNumber", "EPERM"),
    ("Service", "DevicePolicy", "closed"),
    ("Service", "KeyringMode", "private"),
    ("Service", "RemoveIPC", "yes"),
    ("Service", "LimitCORE", "0"),
    ("Service", "LimitNOFILE", "64"),
    ("Service", "TasksMax", "32"),
    ("Service", "MemoryMax", "512M"),
    ("Service", "TimeoutStartSec", "30s"),
    ("Service", "TimeoutStopSec", "15s"),
    ("Service", "Restart", "on-failure"),
    ("Service", "RestartSec", "2s"),
)

REQUIRED_SOCKET: tuple[tuple[str, str, str], ...] = (
    ("Socket", "ListenStream", "/run/safo-broker.sock"),
    ("Socket", "SocketUser", "root"),
    ("Socket", "SocketGroup", "safo-broker-clients"),
    ("Socket", "SocketMode", "0660"),
    ("Socket", "Accept", "no"),
    ("Socket", "Backlog", "16"),
    ("Install", "WantedBy", "sockets.target"),
)

# Keys that must never appear: each would widen the sandbox or add a way around it.
FORBIDDEN_SERVICE_KEYS = ("DynamicUser", "PrivateUsers", "EnvironmentFile", "PermissionsStartOnly", "PassEnvironment")


def parse_unit(text: str) -> list[tuple[str, str, str]]:
    """Return (section, key, value) triples in file order. Comments and blank lines are skipped."""
    out: list[tuple[str, str, str]] = []
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        key, sep, value = line.partition("=")
        if sep:
            out.append((section, key.strip(), value.strip()))
    return out


def missing(text: str, required: tuple[tuple[str, str, str], ...]) -> list[str]:
    """Return the required lines that are absent from `text`, formatted as `Section: Key=Value`."""
    have = set(parse_unit(text))
    return [f"{s}: {k}={v}" for s, k, v in required if (s, k, v) not in have]


def read(name: str) -> str:
    return (UNIT_DIR / name).read_text()
