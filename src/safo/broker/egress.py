# SPDX-License-Identifier: Apache-2.0
"""Egress control for the broker's service user (docs/gemini-broker.md, "Install (phase 5 status)").

Root runs this from the release, from three systemd units: `load` installs the nftables ruleset and an empty hosts view,
`refresh` (a timer, every five minutes) resolves the vendor host from the root-owned config, validates every address,
swaps the nft set in one transaction and rewrites the hosts view the broker's unit bind-mounts over /etc/hosts, and
`unload` removes the table. The service user may then open new connections only to port 443 of those addresses, and
needs no DNS, because the hosts view already names them.

Fail closed in the useful direction: on an empty answer, an implausible answer, any address that is not a public IPv4
address, or a resolver or nft error, nothing is changed and the previous set and hosts view stay. The vendor host
name is read from /etc/safo/broker-egress.conf and is not in any unit or command line. Standard library plus the
single output path; the only program it runs is nft, by absolute path, with a fixed argument list.
"""

from __future__ import annotations

import grp
import ipaddress
import os
import pwd
import re
import socket
import stat
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from safo import output
from safo.broker.floor import entry_problem

NFT = "/usr/sbin/nft"
CONF = Path("/etc/safo/broker-egress.conf")
HOSTS = Path("/etc/safo/egress/hosts")
SERVICE_USER = "safo-broker"
TABLE = "safo_broker_egress"
SET = "vendor_v4"
MAX_ADDRESSES = 16
HOSTS_SIZE = 4096
MODES = ("observe", "drop")
FINAL_RULES = {
    "observe": 'counter log prefix "safo-broker-egress-observe " accept',
    "drop": 'counter log prefix "safo-broker-egress-drop " drop',
}
ADDRESS = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}")
HOST = re.compile(r"(?=.{3,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]*[a-z0-9])?")
CONF_LINE = re.compile(r"([A-Z_]+)=(.*)")


class EgressError(Exception):
    """A refusal or a failure. Nothing was changed when this is raised before the apply step."""


@dataclass(frozen=True)
class Config:
    host: str
    mode: str


Nft = Callable[[str], None]
Resolver = Callable[[str], Sequence[object]]


# ---- validation -----------------------------------------------------------------------------------------------------


def valid_host(name: object) -> bool:
    return isinstance(name, str) and HOST.fullmatch(name) is not None and not re.fullmatch(r"[0-9.]+", name)


def validate_address(text: object) -> str:
    """Return `text` if it is a public IPv4 address in plain dotted-quad form, else raise. Nothing about the text is
    repaired: no whitespace, no leading zeros, no ranges, no other families."""
    if type(text) is not str or not ADDRESS.fullmatch(text) or not text.isascii():
        msg = "an answer is not a plain IPv4 address"
        raise EgressError(msg)
    if any(str(int(octet)) != octet for octet in text.split(".")):
        msg = "an answer has leading zeros or a value out of range"
        raise EgressError(msg)
    try:
        addr = ipaddress.IPv4Address(text)
    except ValueError:
        msg = "an answer is not an IPv4 address"
        raise EgressError(msg) from None
    if (
        not addr.is_global
        or addr.is_multicast
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_private
        or addr.is_reserved
        or addr.is_unspecified
    ):
        msg = "an answer is not a public IPv4 address"
        raise EgressError(msg)
    return text


def validate_answers(raw: Sequence[object]) -> list[str]:
    """Validate every answer; refuse the whole set on one bad one, an empty set or an implausibly large one."""
    found = sorted({validate_address(x) for x in raw}, key=lambda a: int(ipaddress.IPv4Address(a)))
    if not found:
        msg = "the resolver gave no addresses"
        raise EgressError(msg)
    if len(found) > MAX_ADDRESSES:
        msg = f"the resolver gave an implausible number of addresses ({len(found)})"
        raise EgressError(msg)
    return found


def read_config(path: Path, *, uid: int = 0, anchor: Path = Path("/")) -> Config:
    problem = entry_problem(path, uid, want_dir=False)
    parent = path.parent
    while problem is None:
        problem = entry_problem(parent, uid, want_dir=True)
        if parent == anchor or parent == parent.parent:
            break
        parent = parent.parent
    if problem:
        msg = f"the egress config is unusable: {problem}"
        raise EgressError(msg)
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = CONF_LINE.fullmatch(line)
        if not m or m[1] not in ("VENDOR_HOST", "MODE") or m[1] in values:
            msg = "the egress config has a line that is not VENDOR_HOST=... or MODE=..., or repeats one"
            raise EgressError(msg)
        values[m[1]] = m[2]
    host = values.get("VENDOR_HOST", "")
    mode = values.get("MODE", "observe")
    if not valid_host(host):
        msg = "the egress config has no plausible VENDOR_HOST"
        raise EgressError(msg)
    if mode not in MODES:
        msg = f"the egress config MODE must be one of {', '.join(MODES)}"
        raise EgressError(msg)
    return Config(host=host, mode=mode)


# ---- the ruleset, the set swap and the hosts view -------------------------------------------------------------


def render_rules(template: str, *, uid: object, mode: str) -> str:
    if type(uid) is not int or not 0 <= uid < 2**31:
        msg = "the service uid must be a small non-negative integer"
        raise EgressError(msg)
    if mode not in MODES:
        msg = f"mode must be one of {', '.join(MODES)}"
        raise EgressError(msg)
    for token in ("@SERVICE_UID@", "@FINAL_RULE@"):
        if template.count(token) != 1:
            msg = f"the ruleset template must contain {token} exactly once"
            raise EgressError(msg)
    text = template.replace("@SERVICE_UID@", str(uid)).replace("@FINAL_RULE@", FINAL_RULES[mode])
    return "".join(x + "\n" for x in text.splitlines() if not x.lstrip().startswith("#"))


def set_script(addresses: Sequence[str]) -> str:
    """One nft transaction: empty the set and fill it, so the set is never half-updated."""
    if not addresses:
        msg = "no addresses to put in the set"
        raise EgressError(msg)
    checked = [validate_address(a) for a in addresses]
    return f"flush set inet {TABLE} {SET}\nadd element inet {TABLE} {SET} {{ {', '.join(checked)} }}\n"


def hosts_content(host: str, addresses: Sequence[str]) -> bytes:
    """The hosts view: localhost and the validated vendor addresses, padded with a comment to a fixed size so an
    in-place rewrite never changes the file's length."""
    if not valid_host(host):
        msg = "not a plausible host name"
        raise EgressError(msg)
    lines = ["127.0.0.1 localhost", *(f"{validate_address(a)} {host}" for a in addresses)]
    base = "\n".join(lines) + "\n"
    remaining = HOSTS_SIZE - len(base)
    if remaining < 2:
        msg = "the hosts view would be too large"
        raise EgressError(msg)
    return (base + "#" + "x" * (remaining - 2) + "\n").encode("ascii")


def write_hosts(path: Path, data: bytes, *, gid: int) -> None:
    """Rewrite the hosts view in place. The unit bind-mounts this one file, and a bind mount of a file follows the
    inode, so the file must never be replaced by a rename. Group-readable by the service group, nothing else."""
    if len(data) != HOSTS_SIZE:
        msg = "the hosts view has the wrong size"
        raise EgressError(msg)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o640)
    except OSError as exc:
        msg = f"cannot open the hosts view: {type(exc).__name__}"
        raise EgressError(msg) from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            msg = "the hosts view is not a plain file"
            raise EgressError(msg)
        os.fchown(fd, -1, gid)
        os.fchmod(fd, 0o640)
        os.pwrite(fd, data, 0)
        if st.st_size != HOSTS_SIZE:
            os.ftruncate(fd, HOSTS_SIZE)
        os.fsync(fd)
    except OSError as exc:
        msg = f"cannot write the hosts view: {type(exc).__name__}"
        raise EgressError(msg) from None
    finally:
        os.close(fd)


# ---- the actions ----------------------------------------------------------------------------------------------------


def run_nft(script: str) -> None:
    try:
        done = subprocess.run(  # noqa: S603 - absolute nft, fixed argument list, the script on stdin, scrubbed environment
            [NFT, "-f", "-"],
            input=script,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        msg = f"nft could not run: {type(exc).__name__}"
        raise EgressError(msg) from None
    if done.returncode != 0:
        lines = done.stderr.strip().splitlines()
        msg = f"nft refused the script: {lines[0][:120] if lines else 'no message'}"
        raise EgressError(msg)


def default_resolver(host: str) -> list[object]:
    try:
        infos = socket.getaddrinfo(host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except OSError:
        msg = "the resolver failed"
        raise EgressError(msg) from None
    return [info[4][0] for info in infos]


def refresh(config: Config, *, resolver: Resolver, nft: Nft, hosts_path: Path, gid: int) -> list[str]:
    """Resolve, validate, then swap the set and rewrite the hosts view. Any failure before the swap changes nothing."""
    try:
        raw = resolver(config.host)
    except EgressError:
        raise
    except (OSError, TimeoutError, ValueError):
        msg = "the resolver failed"
        raise EgressError(msg) from None
    addresses = validate_answers(raw)
    data = hosts_content(config.host, addresses)
    nft(set_script(addresses))
    write_hosts(hosts_path, data, gid=gid)
    return addresses


def load(config: Config, template_path: Path, *, uid: int, nft: Nft, hosts_path: Path, gid: int) -> None:
    nft(render_rules(template_path.read_text(), uid=uid, mode=config.mode))
    if not os.path.lexists(hosts_path):
        write_hosts(hosts_path, hosts_content(config.host, []), gid=gid)


def unload(*, nft: Nft) -> None:
    nft(f"add table inet {TABLE}\ndelete table inet {TABLE}\n")


# ---- command line ---------------------------------------------------------------------------------------------------


def parse_options(argv: Sequence[str], allowed: Sequence[str]) -> dict[str, str] | None:
    if len(argv) % 2:
        return None
    options: dict[str, str] = {}
    for key, value in zip(argv[::2], argv[1::2], strict=True):
        if key not in allowed or key in options:
            return None
        options[key] = value
    return options


def service_ids() -> tuple[int, int]:
    try:
        return pwd.getpwnam(SERVICE_USER).pw_uid, grp.getgrnam(SERVICE_USER).gr_gid
    except KeyError:
        msg = f"the user and group {SERVICE_USER} must exist"
        raise EgressError(msg) from None


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    command = args[0] if args else ""
    rest = args[1:]
    try:
        if command == "render":
            options = parse_options(rest, ("--rules", "--uid", "--mode"))
            if options is None or set(options) != {"--rules", "--uid", "--mode"}:
                output.write(sys.stderr, "usage: render --rules FILE --uid N --mode observe|drop")
                return 2
            text = render_rules(Path(options["--rules"]).read_text(), uid=int(options["--uid"]), mode=options["--mode"])
            for line in text.splitlines():
                output.write(sys.stdout, line)
            return 0
        if command == "load":
            options = parse_options(rest, ("--rules",))
            if options is None or set(options) != {"--rules"}:
                output.write(sys.stderr, "usage: load --rules FILE")
                return 2
            uid, gid = service_ids()
            load(read_config(CONF), Path(options["--rules"]), uid=uid, nft=run_nft, hosts_path=HOSTS, gid=gid)
            return 0
        if command == "refresh" and not rest:
            _uid, gid = service_ids()
            found = refresh(read_config(CONF), resolver=default_resolver, nft=run_nft, hosts_path=HOSTS, gid=gid)
            output.write(sys.stderr, f"egress set refreshed: {len(found)} addresses")
            return 0
        if command == "unload" and not rest:
            unload(nft=run_nft)
            return 0
    except (EgressError, ValueError, OSError) as exc:
        output.write(sys.stderr, f"egress: {exc}")
        return 1
    output.write(sys.stderr, "usage: safo.broker.egress load --rules FILE | refresh | unload | render ...")
    return 2


if __name__ == "__main__":
    sys.exit(main())
