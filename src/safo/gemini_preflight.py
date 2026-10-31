# SPDX-License-Identifier: Apache-2.0
"""A read-only preflight for the maintainer-side setup of the paid Gemini broker (#263).

It answers one question before the first dry run: is this machine ready for hardware-key approvals? It reads; it never
writes, creates, signs, enrolls or deletes anything, makes no network or vendor call, and opens no private key. Its
only commands are the four read-only queries in `READ_ONLY_COMMANDS`, run without a shell through an injected runner.

Run it with `--enabling` just before the enable switch is created: it then FAILS while the egress control is in
observe mode (it logs and accepts), unless the maintainer also passes `--ack-observe-mode` (see the runbook). The same
check applies whenever the switch file already exists.

It prints one line per check, `PASS`, `WARN` or `FAIL`, then a summary, and returns an exit code: 0 when nothing
failed (1 when anything failed, or anything warned with `strict`). Output carries names, counts, modes, owners and line
numbers only: never a key line, a key type's key material, or file content.

This module is standalone. It is not wired into `safo gemini`, so it does not touch the broker phases that are still in
review; wiring it is a small follow-up once they are merged.
"""

from __future__ import annotations

import os
import pwd
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from safo import output

NAMESPACE = "safo-gemini-approval"
SK_TYPES = ("sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
READ_ONLY_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("ssh", "-Q", "key"),
    ("ldconfig", "-p"),
    ("fido2-token", "-L"),
    ("ssh-add", "-L"),
)
_TOKEN = re.compile(r'(?:[^\s"]|"[^"]*")+')
_FLAGS = {"--strict", "--enabling", "--ack-observe-mode"}
_RUN_SECONDS = 10
_MAX_FILE_BYTES = 65_536


@dataclass(frozen=True)
class RunResult:
    returncode: int
    stdout: str


Runner = Callable[[Sequence[str]], RunResult]
UserLookup = Callable[[str], int | None]


@dataclass(frozen=True)
class Check:
    name: str
    status: str  # "pass" | "warn" | "fail"
    detail: str


@dataclass(frozen=True)
class Locations:
    allowed_signers: Path = Path("/etc/safo/gemini-allowed-signers")
    switch: Path = Path("/etc/safo/gemini-paid-enabled")
    egress_conf: Path = Path("/etc/safo/broker-egress.conf")
    state_dir: Path = Path("/var/lib/safo-broker")
    udev_dirs: tuple[Path, ...] = (Path("/etc/udev/rules.d"), Path("/usr/lib/udev/rules.d"), Path("/lib/udev/rules.d"))
    sk_helper_dirs: tuple[Path, ...] = (Path("/usr/lib/openssh"), Path("/usr/libexec/openssh"), Path("/usr/libexec"))
    service_user: str = "safo-broker"
    trust_uid: int = 0  # the owner the trust files must have: root. Only a test passes another.
    vendor_id: str = "1050"  # USB vendor id of the key class whose udev rule is looked for (Yubico)
    namespace: str = NAMESPACE


def default_runner(argv: Sequence[str]) -> RunResult:
    """Run one fixed argv: no shell, closed stdin, bounded time, small environment. OSError if the command is absent."""
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin", "LC_ALL": "C"}
    done = subprocess.run(  # noqa: S603 - fixed read-only argv from READ_ONLY_COMMANDS, no shell, stdin closed, bounded time
        list(argv),
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=_RUN_SECONDS,
        check=False,
        env=env,
    )
    return RunResult(done.returncode, done.stdout)


def default_lookup(name: str) -> int | None:
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        return None


def _ask(runner: Runner, argv: tuple[str, ...]) -> RunResult | None:
    try:
        return runner(argv)
    except (OSError, subprocess.TimeoutExpired):
        return None


def check_ssh_sk_support(loc: Locations, runner: Runner) -> Check:
    name = "ssh-sk-support"
    result = _ask(runner, ("ssh", "-Q", "key"))
    if result is None or result.returncode != 0:
        return Check(name, "fail", "could not run `ssh -Q key`")
    listed = {line.strip() for line in result.stdout.splitlines()}
    missing = [t for t in SK_TYPES if t not in listed]
    if missing:
        return Check(name, "fail", "ssh does not list the key type(s): " + ", ".join(missing))
    if not any((d / "ssh-sk-helper").is_file() for d in loc.sk_helper_dirs):
        return Check(
            name, "fail", "key types are listed but ssh-sk-helper was not found (OpenSSH built without FIDO support?)"
        )
    return Check(name, "pass", "ssh lists ed25519-sk and ecdsa-sk and ssh-sk-helper is installed")


def check_libfido2(runner: Runner) -> Check:
    result = _ask(runner, ("ldconfig", "-p"))
    if result is None or result.returncode != 0:
        return Check("libfido2", "warn", "could not run `ldconfig -p`; confirm the libfido2 package by hand")
    if "libfido2.so" in result.stdout:
        return Check("libfido2", "pass", "libfido2 is in the linker cache")
    return Check("libfido2", "fail", "libfido2 is not in the linker cache (install the libfido2 package)")


def check_udev_rule(loc: Locations) -> Check:
    name = "udev-rule"
    found: list[str] = []
    for directory in loc.udev_dirs:
        try:
            files = sorted(directory.glob("*.rules"))
        except OSError:
            continue
        for rule in files:
            try:
                if rule.stat().st_size > _MAX_FILE_BYTES * 8:
                    continue
                text = rule.read_text(errors="replace")
            except OSError:
                continue
            for line in text.splitlines():
                if line.lstrip().startswith("#"):
                    continue
                if "hidraw" in line and f'"{loc.vendor_id}"' in line and ("uaccess" in line or "plugdev" in line):
                    found.append(rule.name)
                    break
    if found:
        return Check(
            name, "pass", f"a hidraw rule for vendor {loc.vendor_id} is present in: " + ", ".join(sorted(set(found)))
        )
    return Check(
        name,
        "warn",
        f"no hidraw rule with uaccess or plugdev for vendor {loc.vendor_id} was found; "
        "the key may be unreadable without root (see docs/gemini-enrollment.md)",
    )


def check_hardware_key(runner: Runner) -> Check:
    name = "hardware-key"
    token = _ask(runner, ("fido2-token", "-L"))
    devices = 0
    if token is not None and token.returncode == 0:
        devices = sum(1 for line in token.stdout.splitlines() if line.startswith("/dev/") or "vendor=" in line)
    agent = _ask(runner, ("ssh-add", "-L"))
    agent_keys = 0
    if agent is not None and agent.returncode == 0:
        agent_keys = sum(1 for line in agent.stdout.splitlines() if line.split(" ", 1)[0] in SK_TYPES)
    if devices or agent_keys:
        return Check(
            name, "pass", f"{devices} authenticator(s) visible to fido2-token, {agent_keys} sk key(s) in the agent"
        )
    if token is None and agent is None:
        return Check(
            name, "warn", "neither fido2-token nor ssh-add could be run; plug in the key and install fido2-tools"
        )
    return Check(name, "warn", "no hardware key is visible: plug it in (and load it with ssh-add if you use the agent)")


def _parent_problem(path: Path, trust_uid: int) -> str | None:
    try:
        st = path.parent.lstat()
    except OSError:
        return "its directory cannot be read"
    if not stat.S_ISDIR(st.st_mode):
        return "its parent is not a directory"
    if st.st_uid != trust_uid:
        return "its directory has the wrong owner"
    if st.st_mode & 0o022:
        return "its directory is writable by group or others"
    return None


def _file_problem(path: Path, trust_uid: int) -> tuple[os.stat_result | None, str | None]:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None, "absent"
    except OSError:
        return None, "cannot be read"
    if stat.S_ISLNK(st.st_mode):
        return st, "is a symbolic link"
    if not stat.S_ISREG(st.st_mode):
        return st, "is not a regular file"
    if st.st_uid != trust_uid:
        return st, f"has the wrong owner (uid {st.st_uid}, expected {trust_uid})"
    if stat.S_IMODE(st.st_mode) != 0o644:
        return st, f"has mode {stat.S_IMODE(st.st_mode):04o}, expected 0644"
    return st, None


def _line_namespace_problem(line: str, namespace: str) -> bool:
    """True when the line is NOT bound to exactly the namespace. The line is never returned or printed."""
    tokens = _TOKEN.findall(line)
    if len(tokens) < 3:
        return True
    options = tokens[1] if tokens[1] not in SK_TYPES and not tokens[1].startswith(("ssh-", "ecdsa-", "sk-")) else ""
    for option in re.split(r",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", options):
        key, _, value = option.partition("=")
        if key.lower() == "namespaces" and value.strip('"') == namespace:
            return False
    return True


def check_allowed_signers(loc: Locations) -> Check:
    name = "allowed-signers"
    path = loc.allowed_signers
    st, problem = _file_problem(path, loc.trust_uid)
    if problem == "absent":
        return Check(name, "fail", "the file does not exist (step d of docs/gemini-enrollment.md)")
    if problem:
        return Check(name, "fail", f"the file {problem}")
    if st is None:
        return Check(name, "fail", "the file cannot be inspected")
    parent = _parent_problem(path, loc.trust_uid)
    if parent:
        return Check(name, "fail", f"the file is fine but {parent}")
    if st.st_size > _MAX_FILE_BYTES:
        return Check(name, "fail", f"the file is larger than {_MAX_FILE_BYTES} bytes")
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return Check(name, "fail", "the file cannot be read")
    keys = 0
    bad: list[int] = []
    secret_lines: list[int] = []
    for number, line in enumerate(text.splitlines(), 1):
        if "PRIVATE KEY" in line:
            secret_lines.append(number)
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        keys += 1
        if _line_namespace_problem(stripped, loc.namespace):
            bad.append(number)
    if secret_lines:
        return Check(
            name,
            "fail",
            "private key text at line " + ", ".join(map(str, secret_lines)) + " (content not shown): remove it now",
        )
    if keys == 0:
        return Check(name, "fail", "the file has no key lines, so nothing can approve")
    if bad:
        return Check(
            name, "fail", f'line {", ".join(map(str, bad))} lack(s) namespaces="{loc.namespace}" (content not shown)'
        )
    return Check(name, "pass", f'{keys} key line(s), each bound to namespaces="{loc.namespace}"; root-owned, mode 0644')


def check_switch(loc: Locations) -> Check:
    name = "switch"
    try:
        st = loc.switch.lstat()
    except FileNotFoundError:
        return Check(name, "pass", "absent: paid use is off (the safe state until the dry run has passed)")
    except OSError:
        return Check(name, "fail", "the switch path cannot be inspected")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return Check(name, "fail", "present but not a regular file; the broker treats it as disabled")
    if st.st_uid != loc.trust_uid or stat.S_IMODE(st.st_mode) != 0o644:
        return Check(
            name,
            "fail",
            f"present with owner uid {st.st_uid} and mode {stat.S_IMODE(st.st_mode):04o}; expected root and 0644",
        )
    return Check(
        name, "warn", "present (content not read): paid use is switched on if the file says so; remove it to switch off"
    )


_CONF_LINE = re.compile(r"([A-Z_]+)=(.*)")


def _egress_mode(loc: Locations) -> tuple[str | None, str]:
    """(mode, problem): the mode word from the root-owned egress config, read like the helper reads it (a missing MODE
    line means drop). Nothing but the mode word is ever returned: not the vendor host, not the file."""
    _st, problem = _file_problem(loc.egress_conf, loc.trust_uid)
    if problem == "absent":
        return None, "the egress config does not exist (the egress steps of the runbook are not done)"
    if problem:
        return None, f"the egress config {problem}"
    parent = _parent_problem(loc.egress_conf, loc.trust_uid)
    if parent:
        return None, f"the egress config is fine but {parent}"
    try:
        text = loc.egress_conf.read_text(errors="replace")
    except OSError:
        return None, "the egress config cannot be read"
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _CONF_LINE.fullmatch(line)
        if not m or m[1] not in ("VENDOR_HOST", "MODE") or m[1] in values:
            return None, "the egress config has a line that is not VENDOR_HOST=... or MODE=..., or repeats one"
        values[m[1]] = m[2]
    mode = values.get("MODE", "drop")
    if mode not in ("observe", "drop"):
        return None, "the egress config MODE is neither observe nor drop"
    return mode, ""


def check_egress_mode(loc: Locations, *, enabling: bool, ack_observe: bool) -> Check:
    """Paid use may not be enabled while the egress control only logs and accepts. `enabling` is true when the
    maintainer is about to create the switch (`--enabling`) or the switch file already exists. The acknowledgement turns
    the one failure (observe mode) into a warning; it never excuses a missing or unusable config."""
    name = "egress-mode"
    enabled = enabling or os.path.lexists(loc.switch)
    mode, problem = _egress_mode(loc)
    if mode is None:
        return Check(name, "fail" if enabled else "warn", problem)
    if mode == "drop":
        return Check(name, "pass", "drop: connections from the service user outside the allowed set are dropped")
    if not enabled:
        return Check(
            name,
            "warn",
            "observe: the egress control logs and accepts. Fine while paid use is off; switch to drop before paid use, "
            "or at the latest after the first clean real call",
        )
    if ack_observe:
        return Check(
            name,
            "warn",
            "observe, acknowledged with --ack-observe-mode: the minimum evidence is an empty observe log through a "
            "full dry run; switch to drop after the first clean real call at the latest",
        )
    return Check(
        name,
        "fail",
        "paid use is being enabled while the egress control is in observe mode (it logs and accepts, so a code "
        "execution bug in the broker could send the key anywhere). Set MODE=drop, or pass --ack-observe-mode after an "
        "empty observe log through a full dry run",
    )


def check_service_user(loc: Locations, lookup: UserLookup) -> Check:
    uid = lookup(loc.service_user)
    if uid is None:
        return Check(
            "service-user",
            "fail",
            f"user {loc.service_user} does not exist (step 2 of the root setup in docs/gemini-broker.md)",
        )
    return Check("service-user", "pass", f"user {loc.service_user} exists (uid {uid})")


def check_state_dir(loc: Locations, lookup: UserLookup) -> Check:
    name = "state-dir"
    try:
        st = loc.state_dir.lstat()
    except FileNotFoundError:
        return Check(name, "warn", "absent: systemd creates it at the first start of the service (StateDirectory=)")
    except OSError:
        return Check(name, "fail", "the state directory cannot be inspected")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return Check(name, "fail", "the state path is not a real directory")
    problems: list[str] = []
    uid = lookup(loc.service_user)
    if stat.S_IMODE(st.st_mode) != 0o700:
        problems.append(f"directory mode {stat.S_IMODE(st.st_mode):04o}, expected 0700")
    if uid is not None and st.st_uid != uid:
        problems.append(f"directory owner uid {st.st_uid}, expected {uid}")
    count = 0
    try:
        entries = sorted(loc.state_dir.rglob("*"))
    except OSError:
        entries = []
        problems.append("the directory cannot be listed")
    for entry in entries:
        rel = entry.relative_to(loc.state_dir)
        try:
            est = entry.lstat()
        except OSError:
            problems.append(f"{rel} cannot be inspected")
            continue
        count += 1
        mode = stat.S_IMODE(est.st_mode)
        if stat.S_ISLNK(est.st_mode):
            problems.append(f"{rel} is a symbolic link")
        elif stat.S_ISDIR(est.st_mode):
            if mode & 0o077:
                problems.append(f"{rel} is a directory with mode {mode:04o}, expected no group or other access")
        elif mode != 0o600:
            problems.append(f"{rel} has mode {mode:04o}, expected 0600")
        if uid is not None and est.st_uid != uid:
            problems.append(f"{rel} has owner uid {est.st_uid}, expected {uid}")
    if problems:
        shown = "; ".join(problems[:6]) + (f"; and {len(problems) - 6} more" if len(problems) > 6 else "")
        return Check(name, "fail", shown)
    return Check(
        name, "pass", f"mode 0700, owned by {loc.service_user}, {count} entr{'y' if count == 1 else 'ies'} correct"
    )


def run_preflight(
    loc: Locations, runner: Runner, lookup: UserLookup, *, enabling: bool = False, ack_observe: bool = False
) -> list[Check]:
    return [
        check_ssh_sk_support(loc, runner),
        check_libfido2(runner),
        check_udev_rule(loc),
        check_hardware_key(runner),
        check_allowed_signers(loc),
        check_switch(loc),
        check_egress_mode(loc, enabling=enabling, ack_observe=ack_observe),
        check_service_user(loc, lookup),
        check_state_dir(loc, lookup),
    ]


def render(checks: Sequence[Check]) -> str:
    # names found on disk (state directory entries) can hold control characters: the shared escaper handles them
    return "\n".join(output.line(f"{c.status.upper()} {c.name}: {c.detail}") for c in checks)


def exit_code(checks: Sequence[Check], *, strict: bool = False) -> int:
    if any(c.status == "fail" for c in checks):
        return 1
    if strict and any(c.status == "warn" for c in checks):
        return 1
    return 0


def main_with(
    loc: Locations,
    runner: Runner,
    lookup: UserLookup,
    *,
    out: TextIO,
    strict: bool = False,
    enabling: bool = False,
    ack_observe: bool = False,
) -> int:
    checks = run_preflight(loc, runner, lookup, enabling=enabling, ack_observe=ack_observe)
    out.write(render(checks) + "\n")
    counts = {s: sum(1 for c in checks if c.status == s) for s in ("pass", "warn", "fail")}
    code = exit_code(checks, strict=strict)
    out.write(f"summary: {counts['pass']} pass, {counts['warn']} warn, {counts['fail']} fail; exit {code}\n")
    return code


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if any(a not in _FLAGS for a in args):
        output.write(sys.stderr, "usage: python -m safo.gemini_preflight [--strict] [--enabling] [--ack-observe-mode]")
        return 2
    return main_with(
        Locations(),
        default_runner,
        default_lookup,
        out=sys.stdout,
        strict="--strict" in args,
        enabling="--enabling" in args,
        ack_observe="--ack-observe-mode" in args,
    )


if __name__ == "__main__":
    raise SystemExit(main())
