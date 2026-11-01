# SPDX-License-Identifier: Apache-2.0
"""The egress control for the broker's service user: validator, refresher, ruleset, hosts view.

Nothing here touches a firewall. The nft runner is a fake; the ruleset is only syntax-checked with `nft -c` inside a
throwaway user and network namespace (no root, no change to this machine), and that test skips with a reason when the
tools are missing.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

import safo_broker_egress as egress
from safo_broker_egress import EgressError

REPO = Path(__file__).resolve().parent.parent
UID = os.getuid()
TEMPLATE = REPO / "packaging" / "nftables" / "safo-broker.nft"
HOST = "api.vendor.example.invalid"
GOOD = ["142.250.80.10", "142.250.80.11"]


# ---- the address validator over hostile input -----------------------------------------------------------------------


@pytest.mark.parametrize("addr", ["142.250.80.10", "8.8.8.8", "1.1.1.1", "93.184.216.34"])
def test_public_ipv4_addresses_are_accepted(addr: str) -> None:
    assert egress.validate_address(addr) == addr


@pytest.mark.parametrize(
    "addr",
    [
        "10.0.0.1",
        "172.16.5.4",
        "192.168.1.1",  # private
        "127.0.0.1",
        "127.255.255.254",  # loopback
        "169.254.169.254",
        "169.254.0.1",  # link-local
        "224.0.0.1",
        "239.255.255.250",  # multicast
        "0.0.0.0",  # noqa: S104 - a hostile input to the validator, nothing binds to it
        "255.255.255.255",
        "240.0.0.1",  # unspecified, broadcast, reserved
        "100.64.0.1",  # carrier-grade NAT
        "192.0.2.1",
        "198.51.100.7",
        "203.0.113.9",  # documentation
        "198.18.0.1",  # benchmarking
        "::1",
        "2001:4860:4860::8888",
        "::ffff:8.8.8.8",  # not IPv4
        "",
        " ",
        "8.8.8.8 ",
        " 8.8.8.8",
        "8.8.8.8\n",
        "8.8.8.8\n1.1.1.1",
        "8.8.8.8, 1.1.1.1",
        "8.8.8.8; flush ruleset",
        "8.8.8.8/32",
        "8.8.8.0/24",
        "8.8.8",
        "8.8.8.8.8",
        "08.8.8.8",
        "010.1.1.1",
        "0x8.8.8.8",
        "2130706433",
        "8.8.8.256",
        "8.8.8.-1",
        "8.8.8.8\x00",
        "dns.google",
        "{ 8.8.8.8 }",
        "8.8.8.8 }",
        "٨.٨.٨.٨",
    ],
)
def test_everything_else_is_refused(addr: str) -> None:
    with pytest.raises(EgressError):
        egress.validate_address(addr)


def test_non_string_answers_are_refused() -> None:
    for bad in (None, 5, b"8.8.8.8", ("8.8.8.8",), 8.8):
        with pytest.raises(EgressError):
            egress.validate_address(bad)


def test_the_answer_set_is_deduplicated_sorted_and_bounded() -> None:
    assert egress.validate_answers(["142.250.80.11", "142.250.80.10", "142.250.80.10"]) == GOOD
    with pytest.raises(EgressError, match="no addresses"):
        egress.validate_answers([])
    many = [f"142.250.80.{i}" for i in range(1, egress.MAX_ADDRESSES + 2)]
    with pytest.raises(EgressError, match="implausible"):
        egress.validate_answers(many)
    egress.validate_answers(many[: egress.MAX_ADDRESSES])


def test_one_bad_answer_refuses_the_whole_set() -> None:
    with pytest.raises(EgressError):
        egress.validate_answers(["142.250.80.10", "10.0.0.1"])


@pytest.mark.parametrize("name", ["api.vendor.example.invalid", "a.b", "x-y.z0.example"])
def test_plausible_host_names(name: str) -> None:
    assert egress.valid_host(name)


@pytest.mark.parametrize(
    "name",
    [
        "",
        "localhost",
        "-a.b",
        "a..b",
        ".a.b",
        "a.b.",
        "a b.c",
        "a.b;x",
        "a.b\n",
        "A.B",
        "a_b.c",
        "a.b" + "x" * 300,
        "http://a.b",
        "1.2.3.4",
        "a.b/c",
    ],
)
def test_implausible_host_names_are_refused(name: str) -> None:
    assert not egress.valid_host(name)


# ---- the root-owned config ------------------------------------------------------------------------------------------


def make_conf(tmp_path: Path, text: str) -> tuple[Path, Path]:
    base = tmp_path / "etc"
    base.mkdir(parents=True)
    base.chmod(0o755)
    conf = base / "broker-egress.conf"
    conf.write_text(text)
    conf.chmod(0o644)
    return conf, tmp_path


def test_the_config_names_the_host_and_a_missing_mode_means_drop(tmp_path: Path) -> None:
    conf, anchor = make_conf(tmp_path, f"# the vendor host\nVENDOR_HOST={HOST}\n")
    cfg = egress.read_config(conf, uid=os.getuid(), anchor=anchor)
    assert (cfg.host, cfg.mode) == (HOST, "drop")  # fail closed: only an explicit MODE=observe logs and accepts
    conf.write_text(f"VENDOR_HOST={HOST}\nMODE=drop\n")
    assert egress.read_config(conf, uid=os.getuid(), anchor=anchor).mode == "drop"


@pytest.mark.parametrize(
    "text",
    [
        "",
        "MODE=observe\n",
        "VENDOR_HOST=\n",
        "VENDOR_HOST=not a host\n",
        f"VENDOR_HOST={HOST}\nMODE=maybe\n",
        f"VENDOR_HOST={HOST}\nOTHER=1\n",
        f"VENDOR_HOST={HOST}\nVENDOR_HOST={HOST}\n",
        f"VENDOR_HOST = {HOST}\n",
    ],
)
def test_a_bad_config_refuses(tmp_path: Path, text: str) -> None:
    conf, anchor = make_conf(tmp_path, text)
    with pytest.raises(EgressError):
        egress.read_config(conf, uid=os.getuid(), anchor=anchor)


def test_a_config_that_others_can_write_or_that_is_not_ours_refuses(tmp_path: Path) -> None:
    conf, anchor = make_conf(tmp_path / "a", f"VENDOR_HOST={HOST}\n")
    conf.chmod(0o664)
    with pytest.raises(EgressError, match="writable"):
        egress.read_config(conf, uid=os.getuid(), anchor=anchor)
    conf, anchor = make_conf(tmp_path / "b", f"VENDOR_HOST={HOST}\n")
    with pytest.raises(EgressError, match="not owned"):
        egress.read_config(conf, uid=os.getuid() + 1, anchor=anchor)
    conf, anchor = make_conf(tmp_path / "c", f"VENDOR_HOST={HOST}\n")
    link = conf.parent / "link"
    link.symlink_to(conf)
    with pytest.raises(EgressError, match="symlink"):
        egress.read_config(link, uid=os.getuid(), anchor=anchor)


# ---- the ruleset ----------------------------------------------------------------------------------------------------


def test_the_template_has_exactly_the_two_placeholders() -> None:
    text = TEMPLATE.read_text()
    assert text.count("@SERVICE_UID@") == 1
    assert text.count("@FINAL_RULE@") == 1
    assert "skuid" in text
    assert "tcp dport 443" in text
    assert "@vendor_v4" in text


def test_the_reference_file_and_the_constant_root_runs_render_identically() -> None:
    for mode in egress.MODES:
        assert egress.render_rules(TEMPLATE.read_text(), uid=1234, mode=mode) == egress.render_rules(
            egress.RULES_TEMPLATE, uid=1234, mode=mode
        )


def test_observe_mode_logs_then_accepts_and_drop_mode_logs_then_drops() -> None:
    template = TEMPLATE.read_text()
    observe = egress.render_rules(template, uid=1234, mode="observe")
    drop = egress.render_rules(template, uid=1234, mode="drop")
    assert "@SERVICE_UID@" not in observe + drop
    assert "@FINAL_RULE@" not in observe + drop
    assert "meta skuid != 1234 return" in observe
    for text, prefix, action in ((observe, "observe", "accept"), (drop, "drop", "drop")):
        tail = [x.strip() for x in text.splitlines()][-4:-2]  # the two final rules, before the closing braces
        assert tail[0] == f'limit rate 10/minute burst 10 packets log prefix "safo-broker-egress-{prefix} "', tail
        assert tail[1] == f"counter {action}", tail
    # the log is rate limited, the verdict is not: a flood cannot fill the log and still gets the verdict
    assert sum("log prefix" in x for x in observe.splitlines()) == 1
    # the only difference between the two modes is the final pair of rules
    diff = [(a, b) for a, b in zip(observe.splitlines(), drop.splitlines(), strict=True) if a != b]
    assert len(diff) == 2


def test_the_ruleset_allows_only_tcp_443_to_the_set_and_gives_the_uid_no_dns() -> None:
    rules = egress.render_rules(TEMPLATE.read_text(), uid=1234, mode="drop")
    accepts = [
        x.strip() for x in rules.splitlines() if x.strip().endswith(" accept") and not x.strip().startswith("type ")
    ]
    # no established/related shortcut: a connection opened while the table was missing must not outlive the rebuild
    assert accepts == ["ip daddr @vendor_v4 tcp dport 443 counter accept"]
    assert "ct state" not in rules
    assert "dport 53" not in rules
    assert "ip6" not in rules  # IPv6 is not allowed, so the final rule drops it
    assert "table inet" in rules  # one table covers both families


@pytest.mark.parametrize("bad_uid", [-1, "0", "0; flush ruleset", None, True, 2**40])
def test_the_uid_must_be_a_plain_small_integer(bad_uid: object) -> None:
    with pytest.raises(EgressError):
        egress.render_rules(TEMPLATE.read_text(), uid=bad_uid, mode="drop")


def test_an_unknown_mode_refuses() -> None:
    with pytest.raises(EgressError):
        egress.render_rules(TEMPLATE.read_text(), uid=1, mode="warn")


UNSHARE = shutil.which("unshare")
NFT = shutil.which("nft")


def userns_ok() -> bool:
    if not UNSHARE:
        return False
    done = subprocess.run(  # noqa: S603 - fixed argv, harmless probe
        [UNSHARE, "-Urn", "true"], capture_output=True, stdin=subprocess.DEVNULL, timeout=30, check=False
    )
    return done.returncode == 0


def nft_check(text: str) -> subprocess.CompletedProcess[str]:
    assert UNSHARE and NFT
    return subprocess.run(  # noqa: S603 - fixed argv: syntax check only, inside a private user and network namespace
        [UNSHARE, "-Urn", NFT, "-c", "-f", "-"],
        input=text,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


@pytest.mark.skipif(
    not (NFT and UNSHARE), reason="nft or unshare is not installed here; the ruleset syntax is not checked"
)
def test_nft_accepts_both_rendered_rulesets_and_rejects_a_broken_one() -> None:
    if not userns_ok():
        pytest.skip("unprivileged user namespaces are unavailable here; the ruleset syntax is not checked")
    for mode in ("observe", "drop"):
        done = nft_check(egress.render_rules(TEMPLATE.read_text(), uid=1234, mode=mode))
        assert done.returncode == 0, done.stderr
    broken = egress.render_rules(TEMPLATE.read_text(), uid=1234, mode="drop").replace("tcp dport 443", "tcp dprt 443")
    assert nft_check(broken).returncode != 0
    rules = egress.render_rules(egress.RULES_TEMPLATE, uid=1234, mode="drop")
    # the whole refresh transaction parses: the table is rebuilt and the set is filled in one script
    done = nft_check(egress.refresh_script(rules, GOOD))
    assert done.returncode == 0, done.stderr


# ---- the atomic set swap --------------------------------------------------------------------------------------------


def test_the_refresh_rebuilds_the_whole_table_with_the_set_in_one_transaction() -> None:
    rules = egress.render_rules(egress.RULES_TEMPLATE, uid=1234, mode="observe")
    script = egress.refresh_script(rules, GOOD)
    lines = script.splitlines()
    assert lines[:2] == ["table inet safo_broker_egress", "delete table inet safo_broker_egress"]
    assert lines[-1] == "add element inet safo_broker_egress vendor_v4 { 142.250.80.10, 142.250.80.11 }"
    assert script.index("delete table") < script.index("hook output") < script.index("add element")


def test_the_refresh_script_refuses_anything_that_is_not_a_validated_address() -> None:
    rules = egress.render_rules(egress.RULES_TEMPLATE, uid=1234, mode="drop")
    with pytest.raises(EgressError):
        egress.refresh_script(rules, ["8.8.8.8", "1.1.1.1 }; flush ruleset; {"])
    with pytest.raises(EgressError):
        egress.refresh_script(rules, [])


# ---- the hosts view -------------------------------------------------------------------------------------------------


def test_the_hosts_content_is_fixed_size_and_names_only_validated_addresses() -> None:
    data = egress.hosts_content(HOST, GOOD)
    assert len(data) == egress.HOSTS_SIZE
    text = data.decode("ascii")
    lines = [x for x in text.splitlines() if x and not x.startswith("#")]
    assert lines == ["127.0.0.1 localhost", f"142.250.80.10 {HOST}", f"142.250.80.11 {HOST}"]
    assert text.endswith("\n")
    assert "::" not in text


def test_the_hosts_content_for_an_empty_set_has_only_localhost() -> None:
    text = egress.hosts_content(HOST, []).decode("ascii")
    assert [x for x in text.splitlines() if x and not x.startswith("#")] == ["127.0.0.1 localhost"]


def test_the_hosts_file_is_written_in_place_with_a_group_readable_mode(tmp_path: Path) -> None:
    path = tmp_path / "hosts"
    egress.write_hosts(path, egress.hosts_content(HOST, GOOD), uid=UID, gid=os.getgid())
    inode = path.stat().st_ino
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert path.stat().st_size == egress.HOSTS_SIZE
    egress.write_hosts(path, egress.hosts_content(HOST, ["142.250.80.99"]), uid=UID, gid=os.getgid())
    # a bind mount of a single file is pinned to the inode, so the update must not replace the file
    assert path.stat().st_ino == inode
    assert "142.250.80.99" in path.read_text()
    assert "142.250.80.10" not in path.read_text()
    assert path.stat().st_size == egress.HOSTS_SIZE


def test_the_hosts_writer_refuses_a_file_owned_by_someone_else_and_takes_ownership_of_a_new_one(tmp_path: Path) -> None:
    path = tmp_path / "hosts"
    with pytest.raises(EgressError, match="not owned"):
        egress.write_hosts(path, egress.hosts_content(HOST, GOOD), uid=UID + 1, gid=os.getgid())
    path = tmp_path / "other"
    path.write_text("x")
    with pytest.raises(EgressError, match="not owned"):
        egress.write_hosts(path, egress.hosts_content(HOST, GOOD), uid=UID + 1, gid=os.getgid())
    assert path.read_text() == "x"


def test_a_short_write_is_continued_and_a_zero_write_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = os.pwrite

    def short(fd: int, data: bytes, offset: int) -> int:
        return real(fd, data[:1000], offset)

    monkeypatch.setattr(os, "pwrite", short)
    path = tmp_path / "hosts"
    data = egress.hosts_content(HOST, GOOD)
    egress.write_hosts(path, data, uid=UID, gid=os.getgid())
    assert path.read_bytes() == data

    monkeypatch.setattr(os, "pwrite", lambda fd, data, offset: 0)
    with pytest.raises(EgressError, match="completely"):
        egress.write_hosts(tmp_path / "hosts2", data, uid=UID, gid=os.getgid())


def test_the_hosts_writer_refuses_a_symlink_and_wrong_sized_data(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_text("x")
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(EgressError):
        egress.write_hosts(link, egress.hosts_content(HOST, GOOD), uid=UID, gid=os.getgid())
    assert real.read_text() == "x"
    with pytest.raises(EgressError):
        egress.write_hosts(tmp_path / "h", b"short", uid=UID, gid=os.getgid())


# ---- the refresher: failure modes keep the previous set ------------------------------------------------------------


class Fake:
    """A fake nft runner and resolver that record what the refresher did."""

    def __init__(self, answers: Sequence[object] | Exception) -> None:
        self.answers = answers
        self.scripts: list[str] = []
        self.nft_fails = False

    def resolver(self, host: str) -> list[object]:
        assert host == HOST
        if isinstance(self.answers, Exception):
            raise self.answers
        return list(self.answers)

    def nft(self, script: str) -> None:
        if self.nft_fails:
            msg = "nft failed"
            raise EgressError(msg)
        self.scripts.append(script)


def setup(tmp_path: Path, answers: Sequence[object] | Exception) -> tuple[Fake, Path, egress.Config]:
    hosts = tmp_path / "egress" / "hosts"
    hosts.parent.mkdir()
    fake = Fake(answers)
    cfg = egress.Config(host=HOST, mode="observe")
    egress.write_hosts(hosts, egress.hosts_content(HOST, ["142.250.80.1"]), uid=UID, gid=os.getgid())
    return fake, hosts, cfg


def run_refresh(fake: Fake, hosts: Path, cfg: egress.Config) -> list[str]:
    return egress.refresh(
        cfg, resolver=fake.resolver, nft=fake.nft, hosts_path=hosts, uid=UID, service_uid=1234, gid=os.getgid()
    )


def test_a_good_answer_swaps_the_set_and_the_hosts_view(tmp_path: Path) -> None:
    fake, hosts, cfg = setup(tmp_path, GOOD)
    assert run_refresh(fake, hosts, cfg) == GOOD
    assert len(fake.scripts) == 1  # one transaction
    assert "delete table" in fake.scripts[0]
    assert "add element" in fake.scripts[0]
    assert "meta skuid != 1234 return" in fake.scripts[0]
    assert "142.250.80.11" in hosts.read_text()


@pytest.mark.parametrize(
    "answers",
    [
        [],
        ["10.0.0.5"],
        ["142.250.80.10", "192.168.0.1"],
        ["127.0.0.1"],
        ["169.254.169.254"],
        ["224.0.0.251"],
        ["::1"],
        ["8.8.8.8; flush ruleset"],
        [None],
        [f"142.250.80.{i}" for i in range(1, 40)],
        OSError("resolver error"),
        TimeoutError("resolver timed out"),
    ],
)
def test_a_bad_answer_or_resolver_error_keeps_the_previous_set_and_hosts(tmp_path: Path, answers: object) -> None:
    fake, hosts, cfg = setup(tmp_path, answers)  # type: ignore[arg-type]
    before = hosts.read_bytes()
    with pytest.raises(EgressError):
        run_refresh(fake, hosts, cfg)
    assert fake.scripts == []  # the set was never touched
    assert hosts.read_bytes() == before


def test_an_nft_failure_keeps_the_previous_hosts_view(tmp_path: Path) -> None:
    fake, hosts, cfg = setup(tmp_path, GOOD)
    fake.nft_fails = True
    before = hosts.read_bytes()
    with pytest.raises(EgressError):
        run_refresh(fake, hosts, cfg)
    assert hosts.read_bytes() == before


def test_the_default_resolver_asks_for_ipv4_only_and_wraps_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    seen: dict[str, object] = {}

    def fake_getaddrinfo(
        host: str, port: object, *, family: int, type: int
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        seen.update(host=host, family=family)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("142.250.80.10", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert egress.default_resolver(HOST) == ["142.250.80.10"]
    assert seen == {"host": HOST, "family": socket.AF_INET}

    def boom(*a: object, **k: object) -> None:
        raise socket.gaierror("no")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(EgressError, match="resolver"):
        egress.default_resolver(HOST)


# ---- load, unload, and the command line --------------------------------------------------------------------------


def test_load_applies_the_rendered_rules_and_creates_the_hosts_file(tmp_path: Path) -> None:
    fake = Fake(GOOD)
    hosts = tmp_path / "hosts"
    egress.load(
        egress.Config(host=HOST, mode="observe"),
        service_uid=1234,
        nft=fake.nft,
        hosts_path=hosts,
        uid=UID,
        gid=os.getgid(),
    )
    assert len(fake.scripts) == 1
    assert "meta skuid != 1234 return" in fake.scripts[0]
    assert "observe" in fake.scripts[0]
    assert hosts.stat().st_size == egress.HOSTS_SIZE
    assert [x for x in hosts.read_text().splitlines() if x and not x.startswith("#")] == ["127.0.0.1 localhost"]
    # loading again never empties a view the refresher has filled
    egress.write_hosts(hosts, egress.hosts_content(HOST, GOOD), uid=UID, gid=os.getgid())
    egress.load(
        egress.Config(host=HOST, mode="drop"),
        service_uid=1234,
        nft=fake.nft,
        hosts_path=hosts,
        uid=UID,
        gid=os.getgid(),
    )
    assert "142.250.80.10" in hosts.read_text()


def test_unload_deletes_only_its_own_table_and_is_idempotent() -> None:
    fake = Fake([])
    egress.unload(nft=fake.nft)
    assert fake.scripts == ["add table inet safo_broker_egress\ndelete table inet safo_broker_egress\n"]


def test_the_default_nft_runner_uses_a_fixed_binary_and_a_clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
        calls.append((argv, kw))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    egress.run_nft("flush set inet safo_broker_egress vendor_v4\n")
    argv, kw = calls[0]
    assert argv == [egress.NFT, "-f", "-"]
    assert egress.NFT.startswith("/")
    assert kw["input"] == "flush set inet safo_broker_egress vendor_v4\n"
    assert kw["env"] == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}

    def failing(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 1, "", "Error: syntax")

    monkeypatch.setattr(subprocess, "run", failing)
    with pytest.raises(EgressError, match="nft"):
        egress.run_nft("x")


def test_main_refuses_unknown_commands_and_reports_errors(capsys: pytest.CaptureFixture[str]) -> None:
    assert egress.main([]) == 2
    assert egress.main(["frobnicate"]) == 2
    assert egress.main(["refresh", "--extra"]) == 2
    capsys.readouterr()


def test_main_render_prints_the_ruleset_for_review_without_root(capsys: pytest.CaptureFixture[str]) -> None:
    assert egress.main(["render", "--uid", "1234", "--mode", "observe"]) == 0
    out = capsys.readouterr().out
    assert "meta skuid != 1234 return" in out
    assert egress.main(["render", "--uid", "1234", "--mode", "nope"]) == 1


def test_the_module_cannot_run_anything_but_the_fixed_nft_binary() -> None:
    source = Path(egress.__file__).read_text()
    assert source.count("subprocess.run(") == 1
    for banned in ("shell" + "=True", "os." + "system", "os." + "popen", "eval" + "(", "exec" + "("):
        assert banned not in source


def test_the_helper_is_standalone_and_never_imports_the_release() -> None:
    source = Path(egress.__file__).read_text()
    assert "from safo" not in source
    assert "import safo\n" not in source
    assert source.startswith("#!/usr/bin/python3 -I\n")


def test_a_refresh_rebuilds_a_table_that_was_removed_from_outside(tmp_path: Path) -> None:
    """The transaction starts by adding and deleting the table, so a missing table is created again."""
    fake, hosts, cfg = setup(tmp_path, GOOD)
    run_refresh(fake, hosts, cfg)
    assert fake.scripts[0].startswith("table inet safo_broker_egress\ndelete table inet safo_broker_egress\n")


def test_a_hosts_write_failure_puts_the_previous_set_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The set and the hosts view change together or not at all: if the view cannot be written, the set is restored."""
    fake, hosts, cfg = setup(tmp_path, GOOD)
    before = hosts.read_bytes()

    def boom(*a: object, **k: object) -> None:
        msg = "disk full"
        raise EgressError(msg)

    monkeypatch.setattr(egress, "write_hosts", boom)
    with pytest.raises(EgressError, match="disk full"):
        run_refresh(fake, hosts, cfg)
    assert len(fake.scripts) == 2  # the new set, then the previous one
    assert "142.250.80.10" in fake.scripts[0]
    assert fake.scripts[1].rstrip().endswith("{ 142.250.80.1 }")  # the address the previous view named
    assert "142.250.80.10" not in fake.scripts[1]
    assert hosts.read_bytes() == before


def test_a_failed_refresh_with_no_previous_addresses_leaves_an_empty_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake, hosts, cfg = setup(tmp_path, GOOD)
    egress.write_hosts(hosts, egress.hosts_content(HOST, []), uid=UID, gid=os.getgid())

    def boom(*a: object, **k: object) -> None:
        msg = "disk full"
        raise EgressError(msg)

    monkeypatch.setattr(egress, "write_hosts", boom)
    with pytest.raises(EgressError):
        run_refresh(fake, hosts, cfg)
    assert "add element" not in fake.scripts[1]
    assert "delete table" in fake.scripts[1]


def test_the_addresses_a_hosts_view_names_are_read_back_for_the_restore() -> None:
    data = egress.hosts_content(HOST, GOOD)
    assert egress.addresses_in_hosts(data, HOST) == GOOD
    assert egress.addresses_in_hosts(egress.hosts_content(HOST, []), HOST) == []
    assert (
        egress.addresses_in_hosts(b"garbage\n10.0.0.1 " + HOST.encode() + b"\n", HOST) == []
    )  # nothing invalid is trusted


# ---- persistence: a removal or change from outside is noticed and undone -------------------------------------------

SUID = 1234


def listing(*, chain: list[str] | None = None, addrs: Sequence[str] = GOOD, extra: str = "", mode: str = "drop") -> str:
    """The text `nft list table` prints for the reviewed table (counters and expiry times vary and are ignored)."""
    rules = chain if chain is not None else egress.expected_chain(SUID, mode)
    rules = [
        r.replace("counter accept", "counter packets 3 bytes 180 accept").replace(
            "counter drop", "counter packets 0 bytes 0 drop"
        )
        for r in rules
    ]
    elements = ""
    if addrs:
        elements = "\t\telements = { " + ",\n\t\t\t     ".join(f"{a} expires 59m59s987ms" for a in addrs) + " }\n"
    body = "\n".join(f"\t\t{r}" for r in rules)
    return (
        f"table inet safo_broker_egress {{\n\tset vendor_v4 {{\n\t\ttype ipv4_addr\n\t\ttimeout 1h\n{elements}\t}}\n\n"
        f"\tchain out {{\n{body}\n\t}}\n{extra}}}\n"
    )


def problem(text: str | None, *, mode: str = "drop", addrs: Sequence[str] = GOOD) -> str | None:
    return egress.live_problem(text, service_uid=SUID, mode=mode, addresses=addrs)


@pytest.mark.parametrize("mode", ["observe", "drop"])
def test_the_reviewed_table_is_not_a_problem(mode: str) -> None:
    assert problem(listing(mode=mode), mode=mode) is None
    assert problem(listing(addrs=[], mode=mode), mode=mode, addrs=[]) is None


def test_a_missing_table_is_a_problem() -> None:
    assert problem(None) is not None


def test_the_check_bites_on_every_kind_of_change() -> None:
    good = egress.expected_chain(SUID, "drop")
    changed = {
        "an extra early accept": listing(chain=[good[0], "accept", *good[1:]]),
        "a rule removed": listing(chain=good[:3] + good[4:]),
        "the uid exception widened": listing(chain=[good[0], "meta skuid != 0 return", *good[2:]]),
        "the final verdict flipped": listing(chain=[*good[:4], "counter accept"]),
        "the chain emptied": listing(chain=[good[0]]),
        "the hook policy changed": listing(chain=["type filter hook output priority filter; policy drop;", *good[1:]]),
        "the set emptied": listing(addrs=[]),
        "an address added": listing(addrs=[*GOOD, "8.8.8.8"]),
        "another chain added": listing(extra="\n\tchain other {\n\t\taccept\n\t}\n"),
        "another set added": listing(extra="\n\tset more {\n\t\ttype ipv4_addr\n\t}\n"),
    }
    for what, text in changed.items():
        assert problem(text) is not None, what
    assert problem(listing(mode="observe"), mode="drop") is not None  # the mode in the config is the one that counts
    assert problem("garbage") is not None
    assert problem("") is not None


class Lab:
    """A fake `nft list` and `nft -f` pair for the persistence tests."""

    def __init__(self, live: str | None) -> None:
        self.live = live
        self.scripts: list[str] = []

    def lister(self) -> str | None:
        return self.live

    def nft(self, script: str) -> None:
        self.scripts.append(script)


def test_ensure_leaves_a_good_table_alone(tmp_path: Path) -> None:
    _fake, hosts, cfg = setup(tmp_path, GOOD)
    egress.write_hosts(hosts, egress.hosts_content(HOST, GOOD), uid=UID, gid=os.getgid())
    lab = Lab(listing(mode="observe"))
    assert egress.ensure(cfg, lister=lab.lister, nft=lab.nft, hosts_path=hosts, service_uid=SUID) is None
    assert lab.scripts == []


def test_ensure_rebuilds_a_removed_table_from_the_hosts_view_without_resolving(tmp_path: Path) -> None:
    _fake, hosts, cfg = setup(tmp_path, GOOD)
    egress.write_hosts(hosts, egress.hosts_content(HOST, GOOD), uid=UID, gid=os.getgid())
    lab = Lab(None)
    assert egress.ensure(cfg, lister=lab.lister, nft=lab.nft, hosts_path=hosts, service_uid=SUID)
    assert len(lab.scripts) == 1
    assert lab.scripts[0].startswith("table inet safo_broker_egress\ndelete table inet safo_broker_egress\n")
    assert "vendor_v4 { 142.250.80.10 timeout " in lab.scripts[0]
    assert ", 142.250.80.11 timeout " in lab.scripts[0]


def test_ensure_rebuilds_a_tampered_table_and_an_unreadable_view_gives_an_empty_set(tmp_path: Path) -> None:
    _fake, hosts, cfg = setup(tmp_path, GOOD)
    hosts.unlink()
    lab = Lab(listing(chain=["accept"], mode="observe"))
    assert egress.ensure(cfg, lister=lab.lister, nft=lab.nft, hosts_path=hosts, service_uid=SUID)
    assert "add element" not in lab.scripts[0]
    assert "meta skuid != 1234 return" in lab.scripts[0]


def test_ensure_does_not_swallow_an_nft_failure(tmp_path: Path) -> None:
    _fake, hosts, cfg = setup(tmp_path, GOOD)

    def refuse(script: str) -> None:
        msg = "nft refused"
        raise EgressError(msg)

    with pytest.raises(EgressError, match="nft refused"):
        egress.ensure(cfg, lister=lambda: None, nft=refuse, hosts_path=hosts, service_uid=SUID)


def test_the_lock_is_exclusive_and_refuses_a_symlink(tmp_path: Path) -> None:
    lock = tmp_path / "lock"
    with egress.locked(lock):
        assert lock.exists()
        assert stat.S_IMODE(lock.stat().st_mode) == 0o600
    link = tmp_path / "link"
    link.symlink_to(lock)
    with pytest.raises(EgressError, match="lock"), egress.locked(link):
        pytest.fail("a symlink must not be opened")


def test_main_check_and_refresh_put_the_table_back_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A removed table is restored even when the lookup then fails; `check` never resolves anything."""
    _fake, hosts, _cfg = setup(tmp_path, GOOD)
    conf = tmp_path / "broker-egress.conf"
    conf.write_text(f"VENDOR_HOST={HOST}\nMODE=observe\n")
    lab = Lab(None)
    asked: list[str] = []

    def resolver(host: str) -> list[object]:
        asked.append(host)
        msg = "the resolver failed"
        raise EgressError(msg)

    monkeypatch.setattr(egress, "service_ids", lambda: (SUID, os.getgid()))
    monkeypatch.setattr(egress, "read_config", lambda path: egress.Config(host=HOST, mode="observe"))
    monkeypatch.setattr(egress, "HOSTS", hosts)
    monkeypatch.setattr(egress, "LOCK", tmp_path / "lock")
    monkeypatch.setattr(egress, "list_table", lab.lister)
    monkeypatch.setattr(egress, "run_nft", lab.nft)
    monkeypatch.setattr(egress, "default_resolver", resolver)
    assert egress.main(["check"]) == 0
    assert asked == [] and len(lab.scripts) == 1
    assert egress.main(["refresh"]) == 1  # the lookup fails ...
    assert asked == [HOST] and len(lab.scripts) == 3  # ... the table was put back before it and again after it
    assert "put back" in capsys.readouterr().err


def test_the_default_lister_reads_only_our_table_with_a_fixed_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
        seen["argv"], seen["env"] = argv, kw["env"]
        return subprocess.CompletedProcess(argv, 1, "", "no such table")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert egress.list_table() is None
    assert seen["argv"] == ["/usr/sbin/nft", "list", "table", "inet", "safo_broker_egress"]
    assert seen["env"] == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}

    def failing(*a: object, **k: object) -> None:
        raise OSError

    monkeypatch.setattr(subprocess, "run", failing)
    with pytest.raises(EgressError, match="nft"):
        egress.list_table()


@pytest.mark.skipif(not (NFT and UNSHARE), reason="nft or unshare is not installed here; real nft output not compared")
def test_real_nft_output_matches_the_check_and_every_outside_change_is_seen(tmp_path: Path) -> None:
    """Inside a throwaway user and network namespace (no root, nothing on this machine changes): load the real rules,
    read them back with the real nft, and make outside changes."""
    if not userns_ok():
        pytest.skip("unprivileged user namespaces are unavailable here; real nft output not compared")
    assert UNSHARE
    results: dict[str, str] = {}
    for mode in ("observe", "drop"):
        rules = egress.render_rules(egress.RULES_TEMPLATE, uid=SUID, mode=mode)
        script = egress.refresh_script(rules, GOOD)
        steps = {
            "good": "true",
            "emptied": "nft flush set inet safo_broker_egress vendor_v4",
            "inserted": "nft insert rule inet safo_broker_egress out accept",
            "flushed": "nft flush chain inet safo_broker_egress out",
            "added": "nft add element inet safo_broker_egress vendor_v4 '{ 8.8.8.8 }'",
            "deleted": "nft delete table inet safo_broker_egress",
        }
        for name, cmd in steps.items():
            sh = f"nft -f {tmp_path}/rules && {cmd}; nft list table inet safo_broker_egress 2>/dev/null"
            (tmp_path / "rules").write_text(script)
            done = subprocess.run(  # noqa: S603 - fixed argv inside a private user and network namespace
                [UNSHARE, "-Urn", "sh", "-c", sh], capture_output=True, text=True, timeout=60, check=False
            )
            results[f"{mode}-{name}"] = done.stdout
        assert problem(results[f"{mode}-good"], mode=mode) is None, results[f"{mode}-good"]
        for name in ("emptied", "inserted", "flushed", "added"):
            assert problem(results[f"{mode}-{name}"], mode=mode) is not None, name
        assert results[f"{mode}-deleted"] == ""
        # persistence: for every change, ensure() sees the real listing (a deleted table is None), sends a rebuild,
        # and that rebuild, run by the real nft in a fresh namespace, gives back exactly the reviewed table
        hosts = tmp_path / f"hosts-{mode}"
        egress.write_hosts(hosts, egress.hosts_content(HOST, GOOD), uid=UID, gid=os.getgid())
        cfg = egress.Config(host=HOST, mode=mode)
        for name in ("emptied", "inserted", "flushed", "added", "deleted"):
            live = results[f"{mode}-{name}"] or None
            lab = Lab(live)
            why = egress.ensure(cfg, lister=lab.lister, nft=lab.nft, hosts_path=hosts, service_uid=SUID)
            assert why and len(lab.scripts) == 1, name
            (tmp_path / "fix").write_text(lab.scripts[0])
            sh = f"nft -f {tmp_path}/fix && nft list table inet safo_broker_egress"
            done = subprocess.run(  # noqa: S603 - fixed argv inside a private user and network namespace
                [UNSHARE, "-Urn", "sh", "-c", sh], capture_output=True, text=True, timeout=60, check=False
            )
            assert problem(done.stdout, mode=mode) is None, (name, done.stderr)
        quiet = Lab(results[f"{mode}-good"])
        assert egress.ensure(cfg, lister=quiet.lister, nft=quiet.nft, hosts_path=hosts, service_uid=SUID) is None
        assert quiet.scripts == []


def test_a_fresh_hosts_view_is_not_resolved_again_but_an_old_missing_or_future_one_is(tmp_path: Path) -> None:
    hosts = tmp_path / "hosts"
    assert egress.view_is_fresh(hosts, now=1000.0) is False  # missing
    hosts.write_bytes(b"x")
    os.utime(hosts, (900.0, 900.0))
    assert egress.view_is_fresh(hosts, now=1000.0) is False  # 100 s old
    os.utime(hosts, (1000.0 - egress.REFRESH_AFTER + 1, 1000.0 - egress.REFRESH_AFTER + 1))
    assert egress.view_is_fresh(hosts, now=1000.0) is True
    os.utime(hosts, (1000.0 - egress.REFRESH_AFTER - 1, 1000.0 - egress.REFRESH_AFTER - 1))
    assert egress.view_is_fresh(hosts, now=1000.0) is False
    os.utime(hosts, (2000.0, 2000.0))
    assert egress.view_is_fresh(hosts, now=1000.0) is False  # dated in the future: do not trust it


def test_main_tick_checks_every_time_but_resolves_only_when_the_view_is_old(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake, hosts, _cfg = setup(tmp_path, GOOD)
    lab = Lab(None)
    asked: list[str] = []

    def resolver(host: str) -> list[object]:
        asked.append(host)
        return list(GOOD)

    monkeypatch.setattr(egress, "service_ids", lambda: (SUID, os.getgid()))
    monkeypatch.setattr(egress, "read_config", lambda path: egress.Config(host=HOST, mode="observe"))
    monkeypatch.setattr(egress, "HOSTS", hosts)
    monkeypatch.setattr(egress, "LOCK", tmp_path / "lock")
    monkeypatch.setattr(egress, "list_table", lab.lister)
    monkeypatch.setattr(egress, "run_nft", lab.nft)
    monkeypatch.setattr(egress, "default_resolver", resolver)

    def fake_refresh(cfg: egress.Config, *, resolver: egress.Resolver, **kw: object) -> list[str]:
        return egress.validate_answers(resolver(cfg.host))

    monkeypatch.setattr(egress, "refresh", fake_refresh)  # writing the view as root is covered by the refresh tests
    assert egress.main(["tick"]) == 0  # the view was just written: put the table back, do not resolve
    assert asked == [] and len(lab.scripts) == 1
    os.utime(hosts, (1.0, 1.0))
    assert egress.main(["tick"]) == 0  # an old view: put the table back and resolve
    assert (
        asked == [HOST] and len(lab.scripts) == 3
    )  # before and after the lookup (the aged view gets no addresses back)


def test_an_aged_view_is_not_put_back_and_a_young_one_keeps_only_its_remaining_time(tmp_path: Path) -> None:
    """Restoring must not extend an address past the lifetime the set would have given it."""
    _fake, hosts, cfg = setup(tmp_path, GOOD)
    egress.write_hosts(hosts, egress.hosts_content(HOST, GOOD), uid=UID, gid=os.getgid())
    os.utime(hosts, (10_000.0, 10_000.0))
    old = Lab(None)
    now = 10_000.0 + egress.SET_LIFETIME
    assert egress.ensure(cfg, lister=old.lister, nft=old.nft, hosts_path=hosts, service_uid=SUID, now=now)
    assert "add element" not in old.scripts[0]  # past its lifetime: an empty set
    young = Lab(None)
    assert egress.ensure(cfg, lister=young.lister, nft=young.nft, hosts_path=hosts, service_uid=SUID, now=10_600.0)
    assert "142.250.80.10 timeout 3000s, 142.250.80.11 timeout 3000s" in young.scripts[0]
    future = Lab(None)
    assert egress.ensure(cfg, lister=future.lister, nft=future.nft, hosts_path=hosts, service_uid=SUID, now=9_000.0)
    assert "add element" not in future.scripts[0]  # dated in the future: not trusted
    # an expired set that is already empty is a good table, so nothing is rewritten every ten seconds
    quiet = Lab(listing(addrs=[], mode="observe"))
    assert egress.ensure(cfg, lister=quiet.lister, nft=quiet.nft, hosts_path=hosts, service_uid=SUID, now=now) is None
    assert quiet.scripts == []


def test_a_table_removed_while_the_lookup_runs_is_put_back_in_the_same_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check runs after the lookup attempt too, whether the lookup failed, was refused or succeeded."""
    for outcome in ("fails", "returns-bad-address", "succeeds"):
        (tmp_path / outcome).mkdir()
        _fake, hosts, _cfg = setup(tmp_path / outcome, GOOD)
        os.utime(hosts, (1.0, 1.0))  # an old view: the lookup will run
        lab = Lab(listing(addrs=[], mode="observe"))

        def resolver(host: str, lab: Lab = lab, outcome: str = outcome) -> list[object]:
            lab.live = None  # something else removes the table while the lookup is running
            if outcome == "fails":
                msg = "the resolver failed"
                raise EgressError(msg)
            return ["10.0.0.1"] if outcome == "returns-bad-address" else list(GOOD)

        def fake_refresh(cfg: egress.Config, *, resolver: egress.Resolver, **kw: object) -> list[str]:
            return egress.validate_answers(resolver(cfg.host))

        monkeypatch.setattr(egress, "service_ids", lambda: (SUID, os.getgid()))
        monkeypatch.setattr(egress, "read_config", lambda path: egress.Config(host=HOST, mode="observe"))
        monkeypatch.setattr(egress, "HOSTS", hosts)
        monkeypatch.setattr(egress, "LOCK", tmp_path / "lock")
        monkeypatch.setattr(egress, "list_table", lab.lister)
        monkeypatch.setattr(egress, "run_nft", lab.nft)
        monkeypatch.setattr(egress, "default_resolver", resolver)
        monkeypatch.setattr(egress, "refresh", fake_refresh)
        code = egress.main(["tick"])
        assert code == (0 if outcome == "succeeds" else 1), outcome
        assert len(lab.scripts) == 1, outcome  # the table is back before the run ends (the view is old: no addresses)
        assert "meta skuid != 1234 return" in lab.scripts[0], outcome
