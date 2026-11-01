# SPDX-License-Identifier: Apache-2.0
"""The broker's unit files carry every hardening line the design requires, and systemd accepts them."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from unitdata import (
    FORBIDDEN_SERVICE_KEYS,
    REQUIRED_BY_UNIT,
    REQUIRED_SERVICE,
    REQUIRED_SOCKET,
    UNIT_DIR,
    missing,
    parse_unit,
    read,
)

ANALYZE = shutil.which("systemd-analyze")
ALL_REQUIRED = [(unit, r) for unit, rows in REQUIRED_BY_UNIT.items() for r in rows]


def test_the_unit_files_exist_and_are_collected() -> None:
    assert sorted(p.name for p in UNIT_DIR.iterdir()) == sorted(REQUIRED_BY_UNIT)
    assert len(ALL_REQUIRED) > 50  # the guard looks at something


def test_service_has_every_required_line() -> None:
    assert missing(read("safo-broker.service"), REQUIRED_SERVICE) == []


def test_socket_has_every_required_line() -> None:
    assert missing(read("safo-broker.socket"), REQUIRED_SOCKET) == []


@pytest.mark.parametrize("unit", sorted(REQUIRED_BY_UNIT))
def test_every_unit_has_every_required_line(unit: str) -> None:
    assert missing(read(unit), REQUIRED_BY_UNIT[unit]) == []


@pytest.mark.parametrize(("unit", "line"), ALL_REQUIRED, ids=[f"{u}:{r[1]}={r[2]}"[:70] for u, r in ALL_REQUIRED])
def test_removing_any_required_line_is_caught(unit: str, line: tuple[str, str, str]) -> None:
    """The negative case: delete exactly one required line from a copy of the shipped file, and the check names it."""
    section, key, value = line
    required = REQUIRED_BY_UNIT[unit]
    kept: list[str] = []
    removed = 0
    current = ""
    for raw in read(unit).splitlines():
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1]
        if current == section and stripped == f"{key}={value}":
            removed += 1
            continue
        kept.append(raw)
    assert removed == 1
    assert missing("\n".join(kept), required) == [f"{section}: {key}={value}"]


def test_a_weakened_value_is_caught() -> None:
    weak = read("safo-broker.service").replace("ProtectSystem=strict", "ProtectSystem=full")
    assert missing(weak, REQUIRED_SERVICE) == ["Service: ProtectSystem=strict"]


def test_service_has_no_forbidden_key() -> None:
    triples = parse_unit(read("safo-broker.service"))
    keys = {k for _, k, _ in triples}
    for bad in FORBIDDEN_SERVICE_KEYS:
        assert bad not in keys, bad
    assert [v for s, k, v in triples if k == "Environment"] == ["PYTHONDONTWRITEBYTECODE=1"]
    # the only writable path is the state directory
    assert [v for s, k, v in triples if k == "ReadWritePaths"] == ["/var/lib/safo-broker"]
    # the bind mounts are read-only: the hosts view and a files-only nsswitch
    binds = [v for s, k, v in triples if k in ("BindPaths", "BindReadOnlyPaths")]
    assert binds[0] == "/etc/safo/egress/hosts:/etc/hosts"
    assert [k for s, k, v in triples if k == "BindReadOnlyPaths"]
    assert [v for s, k, v in triples if k == "RestrictAddressFamilies"] == ["AF_INET"]
    # no address allow or deny list (the vendor addresses are not fixed; the design says so)
    assert not {"IPAddressAllow", "IPAddressDeny"} & keys


def test_the_key_never_appears_in_a_unit() -> None:
    for name in REQUIRED_BY_UNIT:
        text = read(name)
        assert "AIza" not in text
        assert "Environment=" not in text.replace("Environment=PYTHONDONTWRITEBYTECODE=1", "")


def test_service_exec_runs_isolated_from_the_release_link() -> None:
    exec_lines = [v for s, k, v in parse_unit(read("safo-broker.service")) if k == "ExecStart"]
    assert exec_lines == ["/opt/safo-broker/current/venv/bin/python -I -m safo.broker"]


def _stage(tmp_path: Path) -> Path:
    """Copy the units next to a stub interpreter so systemd-analyze can resolve ExecStart."""
    stub = tmp_path / "bin" / "python"
    stub.parent.mkdir()
    stub.write_text("#!/bin/sh\n")
    stub.chmod(0o755)
    out = tmp_path / "units"
    out.mkdir()
    for name in REQUIRED_BY_UNIT:
        text = read(name).replace("/opt/safo-broker/current/venv/bin/python", str(stub))
        text = text.replace("/usr/local/sbin/safo-broker-egress", str(stub))
        (out / name).write_text(text)
    return out


@pytest.mark.skipif(
    ANALYZE is None, reason="systemd-analyze is not installed on this machine; unit syntax is not checked here"
)
def test_systemd_analyze_verify_accepts_the_units(tmp_path: Path) -> None:
    out = _stage(tmp_path)
    done = subprocess.run(  # noqa: S603 - absolute-or-PATH systemd-analyze, fixed argv, no shell, files in tmp_path
        [str(ANALYZE), "verify", "--man=no", *(str(out / n) for n in REQUIRED_BY_UNIT)],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert "Unknown key" not in done.stderr
    assert "Unknown section" not in done.stderr


@pytest.mark.skipif(
    ANALYZE is None, reason="systemd-analyze is not installed on this machine; the exposure score is not checked here"
)
def test_systemd_analyze_security_score_is_ok(tmp_path: Path) -> None:
    out = _stage(tmp_path)
    done = subprocess.run(  # noqa: S603 - same as above, offline mode reads only the file
        [str(ANALYZE), "security", "--offline=true", "--no-pager", str(out / "safo-broker.service")],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    last = done.stdout.strip().splitlines()[-1]
    assert "Overall exposure level" in last
    score = float(last.split(":")[1].split()[0])
    assert score <= 2.0, last  # the design recorded 1.2; a rise past 2.0 means a hardening line was lost


# ---- ordering and name resolution (review round) ---------------------------------------------------------------------

NSSWITCH = UNIT_DIR.parent / "etc" / "nsswitch.conf"
HIDDEN_PATHS = [
    "-/run/systemd/resolve",
    "-/run/dbus",
    "-/run/nscd",
    "-/run/avahi-daemon",
    "-/run/systemd/private",
]


def values(unit: str, key: str) -> list[str]:
    return [v for _s, k, v in parse_unit(read(unit)) if k == key]


def test_the_broker_is_bound_to_and_ordered_after_the_egress_rules() -> None:
    assert values("safo-broker.service", "BindsTo") == ["safo-broker-egress.service"]
    assert values("safo-broker.service", "Requires") == ["safo-broker.socket"]
    assert values("safo-broker.service", "After") == [
        "network-online.target safo-broker.socket safo-broker-egress.service"
    ]
    assert values("safo-broker-egress.service", "Before") == ["safo-broker.service"]
    assert values("safo-broker-egress-refresh.service", "After") == ["safo-broker-egress.service network-online.target"]


def test_the_broker_cannot_reach_a_resolver_bus_or_cache_socket() -> None:
    assert values("safo-broker.service", "InaccessiblePaths") == [" ".join(HIDDEN_PATHS)]
    # the only mounts over /etc are the generated hosts view and a files-only name service configuration
    assert values("safo-broker.service", "BindReadOnlyPaths") == [
        "/etc/safo/egress/hosts:/etc/hosts",
        "/opt/safo-broker/current/meta/packaging/etc/nsswitch.conf:/etc/nsswitch.conf",
    ]
    assert not {"IPAddressAllow", "BindPaths"} & {k for _s, k, _v in parse_unit(read("safo-broker.service"))}


def test_the_name_service_configuration_reads_files_only() -> None:
    lines = [x.strip() for x in NSSWITCH.read_text().splitlines() if x.strip() and not x.strip().startswith("#")]
    assert lines
    for line in lines:
        db, _, sources = line.partition(":")
        assert sources.split() == ["files"], line
        assert db in {
            "hosts",
            "passwd",
            "group",
            "shadow",
            "gshadow",
            "networks",
            "protocols",
            "services",
            "ethers",
            "rpc",
        }, db
    assert any(x.startswith("hosts:") for x in lines)


UNSHARE = shutil.which("unshare")


def _can_unshare_mounts() -> bool:
    if not UNSHARE:
        return False
    done = subprocess.run(  # noqa: S603 - fixed argv, harmless probe in a private namespace
        [UNSHARE, "-Urm", "true"], capture_output=True, stdin=subprocess.DEVNULL, timeout=30, check=False
    )
    return done.returncode == 0


def test_in_a_private_mount_namespace_only_the_vendor_host_resolves(tmp_path: Path) -> None:
    """The unit's two bind mounts, reproduced in a throwaway user and mount namespace (no root, nothing on this machine
    changes): the generated hosts view plus the files-only nsswitch. The vendor host resolves; any other name does
    not. Not exercised here: the InaccessiblePaths (asserted from the unit text above) and systemd's own mount ordering.
    """
    if not _can_unshare_mounts():
        pytest.skip("unprivileged user and mount namespaces are unavailable here; name resolution is not exercised")
    import sys

    import safo_broker_egress as egress

    host = "api.vendor.example.invalid"
    hosts = tmp_path / "hosts"
    hosts.write_bytes(egress.hosts_content(host, ["142.250.80.10"]))
    code = (
        "import socket,sys\n"
        f"print(socket.getaddrinfo({host!r}, 443, family=socket.AF_INET)[0][4][0])\n"
        "try:\n"
        "    socket.getaddrinfo('other.example.invalid', 443, family=socket.AF_INET)\n"
        "except socket.gaierror:\n"
        "    print('other-failed')\n"
        "else:\n"
        "    print('other-resolved')\n"
    )
    script = tmp_path / "check.py"
    script.write_text(code)
    shell = (
        f"mount --bind {hosts} /etc/hosts && mount --bind {NSSWITCH} /etc/nsswitch.conf && {sys.executable} -I {script}"
    )
    done = subprocess.run(  # noqa: S603 - fixed argv; the mounts exist only inside the private namespace
        [str(UNSHARE), "-Urm", "/bin/sh", "-c", shell],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=60,
        check=False,
    )
    if done.returncode != 0 and "mount" in done.stderr:
        pytest.skip(f"bind mounts are not permitted in a user namespace here ({done.stderr.strip()[:80]})")
    assert done.stdout.split() == ["142.250.80.10", "other-failed"], (done.stdout, done.stderr)


# ---- the switch is read by the broker on every request, not by a start condition (issue 270, decision 1) ------------


def test_the_service_has_no_start_condition_so_status_and_dry_run_can_answer_with_the_switch_absent() -> None:
    for unit in REQUIRED_BY_UNIT:
        keys = {k for _s, k, _v in parse_unit(read(unit))}
        assert not {k for k in keys if k.startswith(("Condition", "Assert"))}, unit
    assert "paid-enabled" not in "\n".join(
        line for line in read("safo-broker.service").splitlines() if not line.lstrip().startswith("#")
    )


def test_the_egress_units_run_the_separately_installed_root_helper_not_the_release() -> None:
    for unit in ("safo-broker-egress.service", "safo-broker-egress-refresh.service"):
        execs = [v for _s, k, v in parse_unit(read(unit)) if k.startswith("Exec")]
        assert execs
        for line in execs:
            assert line.lstrip("-").startswith("/usr/local/sbin/safo-broker-egress "), line
            assert "/opt/safo-broker" not in line
            assert "--rules" not in line


def test_the_broker_allows_only_ipv4_through_socket_calls() -> None:
    """The line limits socket() only; socketpair() and io_uring are not covered, so it is one layer, not a proof. A
    server that needs Unix sockets needs a reviewed policy change."""
    assert values("safo-broker.service", "RestrictAddressFamilies") == ["AF_INET"]


def test_the_broker_cannot_receive_descriptors_over_its_listener() -> None:
    """A socket handed over with SCM_RIGHTS keeps its creator's uid, which the egress rule does not match, so the
    receive calls that carry descriptors are denied. Plain reads and recv on the inherited listener are unaffected."""
    filters = values("safo-broker.service", "SystemCallFilter")
    assert filters == ["@system-service", "~@privileged @resources", "~recvmsg recvmmsg"]


def test_the_egress_table_is_checked_every_ten_seconds_and_the_set_is_resolved_about_every_minute() -> None:
    """The timer runs `tick`: a cheap check of the live table every ten seconds, and the lookup only once the hosts view
    is a minute old (the helper tests pin that rule)."""
    assert values("safo-broker-egress-refresh.timer", "OnUnitActiveSec") == ["10s"]
    # the first run is at activation (enable, restart, boot), not a delay later
    assert values("safo-broker-egress-refresh.timer", "OnActiveSec") == ["1s"]
    assert values("safo-broker-egress-refresh.timer", "OnBootSec") == []
    assert values("safo-broker-egress-refresh.service", "ExecStart") == ["/usr/local/sbin/safo-broker-egress tick"]


def test_the_comments_say_exactly_what_the_address_family_line_does_and_does_not_do() -> None:
    """RestrictAddressFamilies restricts the socket() call only (man systemd.exec): socketpair() and io_uring are not
    covered, so no text may claim that Unix sockets are impossible."""
    comments = " ".join(x for x in read("safo-broker.service").splitlines() if x.startswith("#"))
    assert "at all" not in comments
    assert "socket()" in comments and "socketpair()" in comments and "io_uring" in comments
    doc = (UNIT_DIR.parents[1] / "docs" / "gemini-broker.md").read_text()
    section = doc[doc.index("**Egress control for the service user.**") : doc.index("**Unit policy.**")]
    assert "no Unix\nsockets at all" not in section and "no Unix sockets at all" not in section
    assert "socketpair()" in section and "io_uring" in section
    test_source = Path(__file__).read_text()
    assert "cannot create or connect Unix sockets" not in test_source.split("def test_the_comments_say_exactly")[0]
