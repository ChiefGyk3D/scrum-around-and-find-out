# SPDX-License-Identifier: Apache-2.0
"""The hardening the broker's systemd units must carry, and a parser that checks a unit text against it."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
UNIT_DIR = REPO / "packaging" / "systemd"

# (section, key, value): every line must be present exactly as written. Multi-valued keys list each value.
REQUIRED_SERVICE: tuple[tuple[str, str, str], ...] = (
    ("Unit", "Requires", "safo-broker.socket"),
    ("Unit", "BindsTo", "safo-broker-egress.service"),
    ("Unit", "After", "network-online.target safo-broker.socket safo-broker-egress.service"),
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
    ("Service", "BindReadOnlyPaths", "/etc/safo/egress/hosts:/etc/hosts"),
    ("Service", "BindReadOnlyPaths", "/opt/safo-broker/current/meta/packaging/etc/nsswitch.conf:/etc/nsswitch.conf"),
    (
        "Service",
        "InaccessiblePaths",
        "-/run/systemd/resolve -/run/dbus -/run/nscd -/run/avahi-daemon -/run/systemd/private",
    ),
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
    ("Service", "RestrictAddressFamilies", "AF_UNIX AF_INET"),
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

REQUIRED_EGRESS: tuple[tuple[str, str, str], ...] = (
    ("Unit", "Before", "safo-broker.service"),
    ("Unit", "After", "network-online.target"),
    ("Service", "Type", "oneshot"),
    ("Service", "RemainAfterExit", "yes"),
    ("Service", "ExecStart", "/usr/local/sbin/safo-broker-egress load"),
    ("Service", "ExecStart", "-/usr/local/sbin/safo-broker-egress refresh"),
    ("Service", "ExecStop", "/usr/local/sbin/safo-broker-egress unload"),
    ("Service", "TimeoutStartSec", "60s"),
    ("Service", "TimeoutStopSec", "30s"),
    ("Service", "UMask", "0077"),
    ("Service", "NoNewPrivileges", "yes"),
    ("Service", "CapabilityBoundingSet", "CAP_NET_ADMIN"),
    ("Service", "PrivateTmp", "yes"),
    ("Service", "PrivateDevices", "yes"),
    ("Service", "ProtectSystem", "strict"),
    ("Service", "ProtectHome", "yes"),
    ("Service", "ReadWritePaths", "/etc/safo/egress"),
    ("Service", "ProtectKernelTunables", "yes"),
    ("Service", "ProtectKernelModules", "yes"),
    ("Service", "ProtectKernelLogs", "yes"),
    ("Service", "ProtectControlGroups", "yes"),
    ("Service", "ProtectClock", "yes"),
    ("Service", "ProtectHostname", "yes"),
    ("Service", "RestrictAddressFamilies", "AF_UNIX AF_NETLINK AF_INET"),
    ("Service", "RestrictNamespaces", "yes"),
    ("Service", "RestrictRealtime", "yes"),
    ("Service", "RestrictSUIDSGID", "yes"),
    ("Service", "LockPersonality", "yes"),
    ("Service", "MemoryDenyWriteExecute", "yes"),
    ("Service", "SystemCallArchitectures", "native"),
    ("Service", "SystemCallFilter", "@system-service"),
    ("Service", "SystemCallErrorNumber", "EPERM"),
    ("Install", "WantedBy", "multi-user.target"),
)

REQUIRED_REFRESH: tuple[tuple[str, str, str], ...] = (
    ("Unit", "Requires", "safo-broker-egress.service"),
    ("Unit", "After", "safo-broker-egress.service network-online.target"),
    ("Service", "Type", "oneshot"),
    ("Service", "ExecStart", "/usr/local/sbin/safo-broker-egress refresh"),
    ("Service", "TimeoutStartSec", "60s"),
    ("Service", "UMask", "0077"),
    ("Service", "NoNewPrivileges", "yes"),
    ("Service", "CapabilityBoundingSet", "CAP_NET_ADMIN"),
    ("Service", "PrivateTmp", "yes"),
    ("Service", "PrivateDevices", "yes"),
    ("Service", "ProtectSystem", "strict"),
    ("Service", "ProtectHome", "yes"),
    ("Service", "ReadWritePaths", "/etc/safo/egress"),
    ("Service", "ProtectKernelTunables", "yes"),
    ("Service", "ProtectKernelModules", "yes"),
    ("Service", "ProtectKernelLogs", "yes"),
    ("Service", "ProtectControlGroups", "yes"),
    ("Service", "ProtectClock", "yes"),
    ("Service", "ProtectHostname", "yes"),
    ("Service", "RestrictAddressFamilies", "AF_UNIX AF_NETLINK AF_INET"),
    ("Service", "RestrictNamespaces", "yes"),
    ("Service", "RestrictRealtime", "yes"),
    ("Service", "RestrictSUIDSGID", "yes"),
    ("Service", "LockPersonality", "yes"),
    ("Service", "MemoryDenyWriteExecute", "yes"),
    ("Service", "SystemCallArchitectures", "native"),
    ("Service", "SystemCallFilter", "@system-service"),
    ("Service", "SystemCallErrorNumber", "EPERM"),
)

REQUIRED_TIMER: tuple[tuple[str, str, str], ...] = (
    ("Timer", "OnBootSec", "1min"),
    ("Timer", "OnUnitActiveSec", "5min"),
    ("Timer", "AccuracySec", "10s"),
    ("Timer", "Unit", "safo-broker-egress-refresh.service"),
    ("Install", "WantedBy", "timers.target"),
)

REQUIRED_BY_UNIT = {
    "safo-broker.service": REQUIRED_SERVICE,
    "safo-broker.socket": REQUIRED_SOCKET,
    "safo-broker-egress.service": REQUIRED_EGRESS,
    "safo-broker-egress-refresh.service": REQUIRED_REFRESH,
    "safo-broker-egress-refresh.timer": REQUIRED_TIMER,
}

# Keys a release may add without being pinned: they describe or order the unit and grant nothing.
HARMLESS_KEYS = (("Unit", "Description"), ("Unit", "Documentation"))

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
