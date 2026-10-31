#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""safo-broker-egress: the root helper for the broker's egress control (docs/gemini-broker.md, "Install (phase 5
status)").

Installed once by root from a reviewed copy to /usr/local/sbin, like the installer, and NOT run from the release tree:
the egress units call this file, so a new release cannot change what root does with CAP_NET_ADMIN. The ruleset is a
constant in this file (packaging/nftables/safo-broker.nft is the reviewed reference copy and a test keeps them equal).
The only inputs are the numeric uid of the service user, the mode (observe or drop) and the vendor host, read from the
root-owned /etc/safo/broker-egress.conf, which no unit or command line names.

Commands: `load` installs the ruleset and an empty hosts view. `refresh` (a timer, every five minutes) resolves the
vendor host, validates every address, and re-applies the whole table with the new set in ONE nft transaction (so a table
that was removed or replaced from outside is rebuilt, and the set is never half-updated), then rewrites the hosts view
the broker unit bind-mounts over /etc/hosts. `unload` removes the table. `render` prints the ruleset for review.

On an empty answer, an implausible answer, any address that is not a public IPv4 address, or a resolver error, nothing
is changed. Standard library only; the only program it runs is nft, by absolute path, with a fixed argument list.
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
from typing import TextIO

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
# The service user may open new TCP connections to port 443 of the addresses in the set and nothing else: no DNS (the
# hosts view names the vendor), no IPv6 (the set is IPv4 only, so the final rule catches it), no loopback, no other
# port, and no established/related shortcut (every packet is judged by the destination rule, so a connection opened
# while the table was missing does not survive its rebuild). Other users are not matched. Vendor traffic is accepted
# before the logging rule, so it never appears in the log.
RULES_TEMPLATE = """table inet safo_broker_egress
delete table inet safo_broker_egress
table inet safo_broker_egress {
	set vendor_v4 {
		type ipv4_addr
		flags timeout
		timeout 1h
	}
	chain out {
		type filter hook output priority filter; policy accept;
		meta skuid != @SERVICE_UID@ return
		ip daddr @vendor_v4 tcp dport 443 counter accept
		@FINAL_RULE@
	}
}
"""
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


def say(stream: TextIO, text: str) -> None:
    """One printable line: control characters are replaced, so nothing in an error can start a second line."""
    clean = "".join(c if " " <= c <= "~" else "?" for c in text)
    print(clean, file=stream)


# ---- trusted files ---------------------------------------------------------------------------------------------------


def entry_problem(path: Path, uid: int, *, want_dir: bool) -> str | None:
    try:
        st = os.lstat(path)
    except OSError:
        return f"{path} is missing"
    if stat.S_ISLNK(st.st_mode):
        return f"{path} is a symlink"
    if not (stat.S_ISDIR(st.st_mode) if want_dir else stat.S_ISREG(st.st_mode)):
        return f"{path} is not a regular {'directory' if want_dir else 'file'}"
    if st.st_uid != uid:
        return f"{path} is not owned by the trusted user"
    if st.st_mode & 0o022:
        return f"{path} is writable by its group or others"
    return None


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


# ---- the ruleset, the refresh transaction and the hosts view -------------------------------------------------------


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


def refresh_script(rules: str, addresses: Sequence[str]) -> str:
    """The whole table, rebuilt with the new set, as one nft transaction: it replaces a table that is missing or was
    changed from outside, and the set is never half-updated."""
    if not addresses:
        msg = "no addresses to put in the set"
        raise EgressError(msg)
    checked = [validate_address(a) for a in addresses]
    return f"{rules}add element inet {TABLE} {SET} {{ {', '.join(checked)} }}\n"


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


def write_hosts(path: Path, data: bytes, *, uid: int, gid: int) -> None:
    """Rewrite the hosts view in place. The unit bind-mounts this one file, and a bind mount of a file follows the
    inode, so the file must never be replaced by a rename. The file must already be ours (or new); it ends up owned by
    `uid`, group `gid`, mode 0640, so the service group can read it and nobody else."""
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
        if st.st_uid != uid:
            msg = "the hosts view is not owned by the trusted user"
            raise EgressError(msg)
        os.fchown(fd, uid, gid)
        os.fchmod(fd, 0o640)
        done = 0
        while done < len(data):  # a short write is continued, not accepted
            written = os.pwrite(fd, data[done:], done)
            if written <= 0:
                msg = "the hosts view could not be written completely"
                raise EgressError(msg)
            done += written
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


def refresh(
    config: Config, *, resolver: Resolver, nft: Nft, hosts_path: Path, uid: int, service_uid: int, gid: int
) -> list[str]:
    """Resolve, validate, rebuild the table with the new set in one transaction, then rewrite the hosts view. Any
    failure before the transaction changes nothing."""
    try:
        raw = resolver(config.host)
    except EgressError:
        raise
    except (OSError, TimeoutError, ValueError):
        msg = "the resolver failed"
        raise EgressError(msg) from None
    addresses = validate_answers(raw)
    data = hosts_content(config.host, addresses)
    rules = render_rules(RULES_TEMPLATE, uid=service_uid, mode=config.mode)
    nft(refresh_script(rules, addresses))
    write_hosts(hosts_path, data, uid=uid, gid=gid)
    return addresses


def load(config: Config, *, service_uid: int, nft: Nft, hosts_path: Path, uid: int, gid: int) -> None:
    nft(render_rules(RULES_TEMPLATE, uid=service_uid, mode=config.mode))
    if not os.path.lexists(hosts_path):
        write_hosts(hosts_path, hosts_content(config.host, []), uid=uid, gid=gid)


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
            options = parse_options(rest, ("--uid", "--mode"))
            if options is None or set(options) != {"--uid", "--mode"}:
                say(sys.stderr, "usage: render --uid N --mode observe|drop")
                return 2
            text = render_rules(RULES_TEMPLATE, uid=int(options["--uid"]), mode=options["--mode"])
            for line in text.splitlines():
                say(sys.stdout, line)
            return 0
        if command in ("load", "refresh") and not rest:
            service_uid, gid = service_ids()
            config = read_config(CONF)
            if command == "load":
                load(config, service_uid=service_uid, nft=run_nft, hosts_path=HOSTS, uid=0, gid=gid)
                return 0
            found = refresh(
                config,
                resolver=default_resolver,
                nft=run_nft,
                hosts_path=HOSTS,
                uid=0,
                service_uid=service_uid,
                gid=gid,
            )
            say(sys.stderr, f"egress set refreshed: {len(found)} addresses")
            return 0
        if command == "unload" and not rest:
            unload(nft=run_nft)
            return 0
    except (EgressError, ValueError, OSError) as exc:
        say(sys.stderr, f"egress: {exc}")
        return 1
    say(sys.stderr, "usage: safo-broker-egress load | refresh | unload | render --uid N --mode M")
    return 2


if __name__ == "__main__":
    sys.exit(main())
