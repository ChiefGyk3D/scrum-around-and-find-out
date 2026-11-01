#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""safo-broker-install: the root-run installer for the paid broker (docs/gemini-broker.md, "Install and update chain").

Standard library only, so root can copy this one file to /usr/local/sbin and run it before anything else is installed.

What it does, and refuses to skip, for `install VERSION`:

1. Fetches the source itself into a root-owned work directory (a shallow fetch of one tag). There is no option and no
   environment variable that names a repository, a folder or a download: the caller cannot supply a source.
2. Verifies the signed *annotated tag object* against the root-owned release signers file with git and ssh-keygen. A
   lightweight tag, an unsigned tag, a signature that is not an SSH signature, a tag object stored under another name
   and a key that is not listed are all refused. Only the commit that tag points at is used afterward, read from
   git objects (no checkout, no filters, no symlinks).
3. Takes the version from the signed tag and cross-checks it with the package's `__version__` read as text.
4. Refuses a version below the root-owned floor, a version below the highest ever installed (unless root passes
   `--allow-downgrade VERSION`), and the same version (unless `--reinstall`).
5. Prints the review (versions, signer, commit, build-control diffs, every dependency change) and waits for root to type
   the version. Without `--apply` it stops there: dry-run is the default.
6. Installs from wheels only: the hash-locked lock is parsed strictly, `pip download --only-binary=:all:
   --require-hashes --no-deps --isolated` fetches into a temporary directory, every file is checked against the lock,
   and a wheel with a `.pth` file, scripts, console entry points, a link or an unsafe member path is refused. No build
   backend and no project code runs as root.
7. Builds the release in a staging directory, verifies a manifest, the unit files (systemd-analyze) and a self-test as
   the service user, makes it read-only, renames it into `releases/`, and activates it with an atomic symlink swap (a
   temporary link renamed over `current`). The previous release stays for `rollback`. A failure after activation swaps
   back and restores the units. The monotonic version file is written only after the new release started and answered.

It never reads, writes or lists the broker's state directory. It never runs the setup runbook: `plan` only prints it.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import difflib
import errno
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import venv
import zipfile
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_URL = "https://github.com/ChiefGyk3D/scrum-around-and-find-out.git"  # a constant: no option or variable changes it
GIT = "/usr/bin/git"
SSH_KEYGEN = "/usr/bin/ssh-keygen"
SYSTEMCTL = "/usr/bin/systemctl"
SYSTEMD_ANALYZE = "/usr/bin/systemd-analyze"
SYSTEMD_RUN = "/usr/bin/systemd-run"
SERVICE_USER = "safo-broker"
UNIT_NAMES = (
    "safo-broker.service",
    "safo-broker.socket",
    "safo-broker-egress.service",
    "safo-broker-egress-refresh.service",
    "safo-broker-egress-refresh.timer",
)
EGRESS_RULES_REL = "packaging/nftables/safo-broker.nft"
EGRESS_HELPER = "/usr/local/sbin/safo-broker-egress"
# The staged tree is tried in a transient systemd sandbox: the service user, no network, private IPC and /tmp, a
# read-only file system, and empty in-memory directories where the live state and the root-owned config would be. It
# can see and change nothing the running broker owns.
STATE_DIR = "/var/lib/safo-broker"
CONFIG_DIR = "/etc/safo"
RUN_DIR = "/run"  # an empty in-memory directory: every host runtime socket is gone
# the live unit's inaccessible set, plus every place a service credential can sit
SELF_TEST_HIDDEN = (
    "-/run/systemd/resolve",
    "-/run/dbus",
    "-/run/nscd",
    "-/run/avahi-daemon",
    "-/run/systemd/private",
    "-/run/credentials",
    "-/run/credstore",
    "-/run/credstore.encrypted",
    "-/etc/credstore",
    "-/etc/credstore.encrypted",
)
SELF_TEST_PROPERTIES = (
    "DynamicUser=yes",  # a uid of its own, never the live broker's
    "PrivateNetwork=yes",
    "PrivatePIDs=yes",  # refused by a systemd without it, which fails the self-test closed
    "PrivateIPC=yes",
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "ProtectProc=invisible",
    "ProcSubset=pid",
    "ProtectHostname=yes",
    "NoNewPrivileges=yes",
    "CapabilityBoundingSet=",
    "RestrictAddressFamilies=none",  # no socket of any family: host Unix sockets cannot be reached
    "RestrictNamespaces=yes",
    "LockPersonality=yes",
    "MemoryDenyWriteExecute=yes",
    "SystemCallArchitectures=native",
    "SystemCallFilter=@system-service",
    "SystemCallFilter=~@privileged @resources",
    "SystemCallFilter=~recvmsg recvmmsg",
    "SystemCallErrorNumber=EPERM",
    "InaccessiblePaths=" + " ".join(SELF_TEST_HIDDEN),
    "MemoryMax=1G",
    "RuntimeMaxSec=120",
    f"TemporaryFileSystem={STATE_DIR}:mode=0700 {CONFIG_DIR}:mode=0755 {RUN_DIR}:mode=0755",
)
NSSWITCH_REL = "packaging/etc/nsswitch.conf"
EGRESS_RESTART = ["try-restart", "safo-broker-egress.service", "safo-broker-egress-refresh.timer"]
# Exposure budget per unit (systemd-analyze security, offline): a rise past it means a hardening line was lost.
EXPOSURE_BUDGET = {
    "safo-broker.service": 2.0,
    "safo-broker-egress.service": 3.0,
    "safo-broker-egress-refresh.service": 3.0,
}
# Checks systemd must resolve as set for the broker service, whatever the file text says.
RESOLVED_MUST_BE_SET = (
    "NoNewPrivileges=",
    "PrivateTmp=",
    "PrivateDevices=",
    "PrivateMounts=",
    "ProtectSystem=",
    "ProtectHome=",
    "ProtectKernelTunables=",
    "ProtectKernelModules=",
    "ProtectKernelLogs=",
    "ProtectControlGroups=",
    "ProtectClock=",
    "ProtectHostname=",
    "ProtectProc=",
    "ProcSubset=",
    "MemoryDenyWriteExecute=",
    "LockPersonality=",
    "RestrictSUIDSGID=",
    "RestrictRealtime=",
    "RestrictNamespaces=~user",
    "SystemCallArchitectures=",
    "RemoveIPC=",
    "KeyringMode=",
    "UMask=",
    "AmbientCapabilities=",
    "CapabilityBoundingSet=~CAP_SYS_ADMIN",
    "CapabilityBoundingSet=~CAP_NET_ADMIN",
    "RestrictAddressFamilies=~AF_PACKET",
    "RestrictAddressFamilies=~AF_NETLINK",
)

UNIT_EXEC_PREFIX = "/opt/safo-broker/current"
RELEASE_INTERPRETER = f"{UNIT_EXEC_PREFIX}/venv/bin/python"  # the only interpreter a release has: stage/venv/bin/python
SK_KEY_TYPES = ("sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")  # hardware keys only, by default
LOCK_REL = "packaging/broker-requirements.txt"
TREE_PATHS = ("src/safo", "packaging", "pyproject.toml")
BUILD_CONTROL = ("pyproject.toml", "packaging")
MAX_BLOB = 16 * 1024 * 1024
MAX_WHEEL_BYTES = 256 * 1024 * 1024
MAX_WHEEL_MEMBERS = 20000
KEEP_OTHERS = 2  # besides the current release, the newest two others are kept (the previous one is always kept)

FAULT_POINTS = (
    "before_build",
    "after_build",
    "before_swap",
    "after_previous_link",
    "after_tmp_link",
    "after_swap",
    "units_tmp_written",
    "after_units",
    "after_restart",
    "after_health",
    "after_version_write",
)

# The interpreter links `venv` makes: python, python3, python3.14, a trailing t on free-threaded builds and, from 3.14,
# a link named with the Greek pi letter (U+1D70B).
INTERPRETER_LINK = re.compile("(?:python|\U0001d70bthon)[0-9.]*t?")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
RELEASE_RE = re.compile(r"([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.r([0-9]+))?")
TAG_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
LINK_RE = re.compile(r"releases/([0-9]+\.[0-9]+\.[0-9]+(?:\.r[0-9]+)?)")
REQ_RE = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)((?:\s+--hash=sha256:[0-9a-f]{64})*)")
INDEX_RE = re.compile(r"--index-url\s+(https://[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[A-Za-z0-9._~%/-]*)?)")
WHEEL_RE = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9_.]*)-(?P<ver>[A-Za-z0-9_.+!]+)(?:-(?P<build>[0-9][A-Za-z0-9_.]*))?"
    r"-(?P<py>[A-Za-z0-9_.]+)-(?P<abi>[A-Za-z0-9_.]+)-(?P<plat>[A-Za-z0-9_.]+)\.whl"
)
VERSION_LINE_RE = re.compile(r'^__version__\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', re.MULTILINE)
GOOD_RE = re.compile(r'Good "git" signature for (\S+) with (\S+) key (SHA256:\S+)')


class InstallError(Exception):
    """A refusal or a failure. The message is safe to print."""


# ---- layout and hooks -----------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Layout:
    """Where everything lives. The real values are the defaults; tests point it at a temporary tree."""

    opt_dir: Path = Path("/opt/safo-broker")
    signers: Path = Path("/etc/safo/broker-release-signers")
    floor_file: Path = Path("/etc/safo/broker-min-version")
    version_file: Path = Path("/var/lib/safo-broker-install/version")
    work_dir: Path = Path("/var/lib/safo-broker-install/work")
    log_file: Path = Path("/var/lib/safo-broker-install/install.log")
    unit_dir: Path = Path("/etc/systemd/system")
    anchor: Path = Path("/")  # parent checks stop here (inclusive)
    uid: int = 0
    key_types: tuple[str, ...] = SK_KEY_TYPES  # key types a release signer may have; root can change it explicitly
    check_python: bool = True  # the interpreter the release venv links to must be a trusted one
    egress_helper: Path = Path("/usr/local/sbin/safo-broker-egress")  # installed once by root; the egress units run it


@dataclass(frozen=True)
class Hooks:
    fetch: Callable[[str, Path], None]
    download: Callable[[Path, Path], None]
    systemctl: Callable[[Sequence[str]], int]
    verify_units: Callable[[Path, Path], None]
    self_test: Callable[[Path], None]
    health: Callable[[], str]
    fault: Callable[[str], None]
    confirm: Callable[[str], str]


@dataclass(frozen=True)
class Report:
    version: str
    commit: str
    signer: str
    applied: bool
    review: str
    release_dir: Path | None = None


@dataclass(frozen=True)
class TagInfo:
    commit: str
    signer: str


@dataclass(frozen=True)
class Lock:
    index_url: str | None
    requirements: dict[str, tuple[str, frozenset[str]]] = field(default_factory=dict)


def _run(
    argv: Sequence[str], *, env: dict[str, str], cwd: Path | None = None, timeout: int = 300
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - absolute program paths, fixed argument lists, scrubbed environment, no shell
        list(argv),
        env=env,
        cwd=cwd,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
    )


def _run_bytes(argv: Sequence[str], *, env: dict[str, str], timeout: int = 120) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - absolute program paths, fixed argument lists, scrubbed environment, no shell
        list(argv),
        env=env,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
    )


def _clean_env(home: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(home),
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _git_env(home: Path, protocol: str) -> dict[str, str]:
    env = _clean_env(home)
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": protocol,
            "GNUPGHOME": str(home / "gnupg"),
        }
    )
    return env


# ---- versions and trusted files -------------------------------------------------------------------------------------


def parse_version(text: str) -> tuple[int, int, int]:
    if not VERSION_RE.fullmatch(text):
        msg = f"version {text!r} is not three dotted numbers (for example 1.2.3)"
        raise InstallError(msg)
    a, b, c = (int(x) for x in text.split("."))
    return (a, b, c)


def fmt(version: tuple[int, int, int]) -> str:
    return ".".join(str(x) for x in version)


def release_key(name: str) -> tuple[int, int, int, int]:
    m = RELEASE_RE.fullmatch(name)
    if not m:
        msg = f"{name!r} is not a release name"
        raise InstallError(msg)
    return (int(m[1]), int(m[2]), int(m[3]), int(m[4] or 0))


def _check_entry(path: Path, layout: Layout, what: str, *, want_dir: bool) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        msg = f"{what} {path} is missing"
        raise InstallError(msg) from None
    if stat.S_ISLNK(st.st_mode):
        msg = f"{what} {path} is a symlink"
        raise InstallError(msg)
    if not (stat.S_ISDIR(st.st_mode) if want_dir else stat.S_ISREG(st.st_mode)):
        msg = f"{what} {path} is not a regular {'directory' if want_dir else 'file'}"
        raise InstallError(msg)
    if st.st_uid != layout.uid:
        msg = f"{what} {path} is not owned by the trusted user (uid {layout.uid})"
        raise InstallError(msg)
    if st.st_mode & 0o022:
        msg = f"{what} {path} is writable by its group or others"
        raise InstallError(msg)


def check_trusted(path: Path, layout: Layout, what: str, *, want_dir: bool = False) -> None:
    """The entry and every parent up to the anchor: no symlink, owned by the trusted user, not group/world writable."""
    _check_entry(path, layout, what, want_dir=want_dir)
    parent = path.parent
    while True:
        _check_entry(parent, layout, f"directory of {what}", want_dir=True)
        if parent == layout.anchor or parent == parent.parent:
            break
        parent = parent.parent


def read_floor(layout: Layout) -> tuple[int, int, int]:
    try:
        check_trusted(layout.floor_file, layout, "version floor file")
        return parse_version(layout.floor_file.read_text().strip())
    except (InstallError, OSError) as exc:
        msg = f"the version floor file is unusable ({exc}); install refuses without it"
        raise InstallError(msg) from None


def _live_install(layout: Layout) -> bool:
    if os.path.lexists(layout.opt_dir / "current"):
        return True
    releases = layout.opt_dir / "releases"
    return releases.is_dir() and any(RELEASE_RE.fullmatch(p.name) for p in releases.iterdir())


def read_highest(layout: Layout) -> tuple[int, int, int] | None:
    if not os.path.lexists(layout.version_file):
        if _live_install(layout):
            msg = "the version file is missing but a release is installed; root must restore it before another install"
            raise InstallError(msg)
        return None
    try:
        check_trusted(layout.version_file, layout, "version file")
        return parse_version(layout.version_file.read_text().strip())
    except (InstallError, OSError) as exc:
        msg = f"the version file is unusable ({exc})"
        raise InstallError(msg) from None


def write_atomic(path: Path, data: bytes, mode: int) -> None:
    tmp = path.parent / f".{path.name}.tmp.{os.getpid()}"
    with contextlib.suppress(FileNotFoundError):
        tmp.unlink()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, data)
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def log_line(layout: Layout, message: str) -> None:
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {message}\n"
    print(f"safo-broker-install: {message}", file=sys.stderr)
    fd = os.open(layout.log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, line.encode())
    finally:
        os.close(fd)


# ---- the tag ----------------------------------------------------------------------------------------------------


def default_fetch(url: str = REPO_URL) -> Callable[[str, Path], None]:
    """Return a fetcher: one shallow fetch of one tag into a fresh repository. The URL is fixed by the caller of this
    function (the module's constant, or a test's file URL); the command line cannot change it."""
    scheme = url.split(":", 1)[0]
    if scheme not in ("https", "file"):
        msg = "the source must be an https or file URL"
        raise InstallError(msg)

    def fetch(tag: str, dest: Path) -> None:
        if not TAG_RE.fullmatch(tag):
            msg = f"tag {tag!r} is not of the form vX.Y.Z"
            raise InstallError(msg)
        env = _git_env(dest.parent, scheme)
        init = [GIT, "init", "-q", str(dest)]
        pull = [GIT, "-C", str(dest), "fetch", "-q", "--depth", "1", "--no-tags", "--no-recurse-submodules"]
        pull += [url, f"refs/tags/{tag}:refs/tags/{tag}"]
        for argv in (init, pull):
            done = _run(argv, env=env, timeout=300)
            if done.returncode != 0:
                lines = done.stderr.strip().splitlines()
                msg = f"could not fetch tag {tag}: {lines[-1] if lines else 'git failed'}"
                raise InstallError(msg)

    return fetch


def parse_tag_object(raw: str, tag: str) -> str:
    """Check a raw tag object (`git cat-file tag`) and return the commit it points at."""
    head, _, body = raw.partition("\n\n")
    fields: dict[str, str] = {}
    for line in head.splitlines():
        key, _, value = line.partition(" ")
        fields.setdefault(key, value)
    if "-----BEGIN SSH SIGNATURE-----" not in body or "-----BEGIN PGP" in raw:
        msg = "the tag has no SSH signature block (an unsigned or non-SSH signed tag is refused)"
        raise InstallError(msg)
    if fields.get("type") != "commit" or not re.fullmatch(r"[0-9a-f]{40}", fields.get("object", "")):
        msg = "the tag does not point at a commit"
        raise InstallError(msg)
    if fields.get("tag") != tag:
        named = fields.get("tag")
        msg = f"the tag object names {named!r}, not {tag!r}; a signed object replayed under another name is refused"
        raise InstallError(msg)
    return fields["object"]


def verify_tag(repo: Path, tag: str, layout: Layout, home: Path) -> TagInfo:
    env = _git_env(home, "file")
    ref = f"refs/tags/{tag}"
    kind = _run([GIT, "-C", str(repo), "cat-file", "-t", ref], env=env)
    if kind.returncode != 0 or kind.stdout.strip() != "tag":
        msg = f"{tag} is not an annotated tag object (a lightweight tag is refused)"
        raise InstallError(msg)
    raw = _run([GIT, "-C", str(repo), "cat-file", "tag", ref], env=env)
    if raw.returncode != 0:
        msg = f"could not read the tag object for {tag}"
        raise InstallError(msg)
    commit = parse_tag_object(raw.stdout, tag)
    verify = [
        GIT,
        "-c",
        "gpg.format=ssh",
        "-c",
        f"gpg.ssh.allowedSignersFile={layout.signers}",
        "-c",
        f"gpg.ssh.program={SSH_KEYGEN}",
        "-C",
        str(repo),
        "verify-tag",
        ref,
    ]
    done = _run(verify, env=env)
    good = GOOD_RE.search(done.stdout + "\n" + done.stderr)
    if done.returncode != 0 or not good:
        msg = f"the signature on {tag} did not verify against the release signers file"
        raise InstallError(msg)
    check_reported_key_type(good[2], layout.key_types)
    return TagInfo(commit=commit, signer=f"{good[1]} {good[2]} {good[3]}")


def extract_tree(repo: Path, commit: str, dest: Path, home: Path) -> dict[str, bytes]:
    """Read the wanted paths of `commit` straight from git objects. Symlinks and submodules are refused."""
    env = _git_env(home, "file")
    listing = _run_bytes([GIT, "-C", str(repo), "ls-tree", "-r", "-z", commit, "--", *TREE_PATHS], env=env)
    if listing.returncode != 0:
        msg = "could not list the release tree"
        raise InstallError(msg)
    files: dict[str, bytes] = {}
    for entry in listing.stdout.split(b"\0"):
        if not entry:
            continue
        meta, _, raw_path = entry.partition(b"\t")
        mode, kind, oid = meta.decode().split(" ")
        path = raw_path.decode()
        parts = path.split("/")
        if mode == "120000":
            msg = f"the release tree has a symlink at {path}; refused"
            raise InstallError(msg)
        if kind != "blob" or mode not in ("100644", "100755"):
            msg = f"the release tree has an unsupported entry at {path} (mode {mode}, {kind})"
            raise InstallError(msg)
        if any(p in ("", ".", "..", ".git") for p in parts) or "\\" in path or path.startswith("/"):
            msg = f"the release tree has an unsafe path {path!r}"
            raise InstallError(msg)
        blob = _run_bytes([GIT, "-C", str(repo), "cat-file", "blob", oid], env=env)
        if blob.returncode != 0 or len(blob.stdout) > MAX_BLOB:
            msg = f"could not read {path} from the release tree"
            raise InstallError(msg)
        files[path] = blob.stdout
        target = dest / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob.stdout)
    for need in (
        "src/safo/__init__.py",
        LOCK_REL,
        "pyproject.toml",
        EGRESS_RULES_REL,
        *(f"packaging/systemd/{u}" for u in UNIT_NAMES),
    ):
        if need not in files:
            msg = f"the release tree has no {need}"
            raise InstallError(msg)
    return files


# ---- the lock and the wheels -----------------------------------------------------------------------------------


# The hardening that every release must keep, whatever the release says. tests/test_broker_install_gates.py pins this
# table to the one the unit tests use, so a change to the shipped units must change both.
UNIT_POLICY: dict[str, tuple[tuple[str, str, str], ...]] = {
    "safo-broker.service": (
        ("Unit", "Requires", "safo-broker.socket"),
        ("Unit", "BindsTo", "safo-broker-egress.service"),
        ("Unit", "After", "network-online.target safo-broker.socket safo-broker-egress.service"),
        ("Unit", "StartLimitIntervalSec", "60"),
        ("Unit", "StartLimitBurst", "5"),
        ("Service", "Type", "simple"),
        ("Service", "User", "safo-broker"),
        ("Service", "Group", "safo-broker"),
        ("Service", "ExecStartPre", f"{RELEASE_INTERPRETER} -I -m safo.broker.floor"),
        ("Service", "ExecStart", f"{RELEASE_INTERPRETER} -I -m safo.broker"),
        ("Service", "LoadCredentialEncrypted", "paid-key:/etc/safo/broker/paid-key"),
        ("Service", "StateDirectory", "safo-broker"),
        ("Service", "StateDirectoryMode", "0700"),
        ("Service", "ReadWritePaths", "/var/lib/safo-broker"),
        ("Service", "ReadOnlyPaths", "/etc/safo /opt/safo-broker"),
        ("Service", "BindReadOnlyPaths", "/etc/safo/egress/hosts:/etc/hosts"),
        (
            "Service",
            "BindReadOnlyPaths",
            "/opt/safo-broker/current/meta/packaging/etc/nsswitch.conf:/etc/nsswitch.conf",
        ),
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
        ("Service", "RestrictAddressFamilies", "AF_INET"),
        ("Service", "RestrictNamespaces", "yes"),
        ("Service", "RestrictRealtime", "yes"),
        ("Service", "RestrictSUIDSGID", "yes"),
        ("Service", "LockPersonality", "yes"),
        ("Service", "MemoryDenyWriteExecute", "yes"),
        ("Service", "SystemCallArchitectures", "native"),
        ("Service", "SystemCallFilter", "@system-service"),
        ("Service", "SystemCallFilter", "~@privileged @resources"),
        ("Service", "SystemCallFilter", "~recvmsg recvmmsg"),
        ("Service", "SystemCallErrorNumber", "EPERM"),
        ("Service", "DevicePolicy", "closed"),
        ("Service", "KeyringMode", "private"),
        ("Service", "RemoveIPC", "yes"),
        ("Service", "LimitCORE", "0"),
        ("Service", "LimitNOFILE", "64"),
        ("Service", "TasksMax", "32"),
        ("Service", "MemoryMax", "512M"),
        ("Service", "TimeoutStartSec", "30s"),
        ("Service", "TimeoutStopSec", "360s"),
        ("Service", "Restart", "on-failure"),
        ("Service", "RestartSec", "2s"),
    ),
    "safo-broker.socket": (
        ("Socket", "ListenStream", "/run/safo-broker.sock"),
        ("Socket", "SocketUser", "root"),
        ("Socket", "SocketGroup", "safo-broker-clients"),
        ("Socket", "SocketMode", "0660"),
        ("Socket", "Accept", "no"),
        ("Socket", "Backlog", "16"),
        ("Install", "WantedBy", "sockets.target"),
    ),
    "safo-broker-egress.service": (
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
    ),
    "safo-broker-egress-refresh.service": (
        ("Unit", "Requires", "safo-broker-egress.service"),
        ("Unit", "After", "safo-broker-egress.service network-online.target"),
        ("Service", "Type", "oneshot"),
        ("Service", "ExecStart", "/usr/local/sbin/safo-broker-egress tick"),
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
    ),
    "safo-broker-egress-refresh.timer": (
        ("Timer", "OnActiveSec", "1s"),
        ("Timer", "OnUnitActiveSec", "10s"),
        ("Timer", "AccuracySec", "1s"),
        ("Timer", "Unit", "safo-broker-egress-refresh.service"),
        ("Install", "WantedBy", "timers.target"),
    ),
}

# Keys a release may add without their being pinned: they describe or order the unit and grant nothing.
HARMLESS_KEYS = (
    ("Unit", "Description"),
    ("Unit", "Documentation"),
)
UNIT_SECTIONS = {
    "safo-broker.service": ("Unit", "Service"),
    "safo-broker.socket": ("Unit", "Socket", "Install"),
    "safo-broker-egress.service": ("Unit", "Service", "Install"),
    "safo-broker-egress-refresh.service": ("Unit", "Service"),
    "safo-broker-egress-refresh.timer": ("Unit", "Timer", "Install"),
}
KEY_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*")


def parse_unit_text(name: str, raw: str | bytes) -> list[tuple[str, str, str]]:
    """Read a unit file the one way every reader agrees on: printable ASCII and newlines only (so no carriage return,
    NUL, vertical tab, form feed, unicode separator or byte-order mark can make two readers split lines differently), no
    backslash at all (so no continuation and no escape), newline-only line splitting, known section names, each section
    once, and every other line a `Key=value` setting."""
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            msg = f"unit policy: {name} is not valid UTF-8"
            raise InstallError(msg) from None
    else:
        text = raw
    for ch in text:
        if ch not in "\n\t" and not (" " <= ch <= "~" and ch != "\\"):
            msg = f"unit policy: {name} has a disallowed character (U+{ord(ch):04X}); ASCII, tab and newline only"
            raise InstallError(msg)
    triples: list[tuple[str, str, str]] = []
    section = ""
    seen: list[str] = []
    for line in text.split("\n"):
        stripped = line.strip(" \t")
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("["):
            if not stripped.endswith("]") or stripped[1:-1] not in UNIT_SECTIONS[name] or stripped[1:-1] in seen:
                msg = f"unit policy: {name} has an unknown, repeated or malformed section header {stripped[:40]!r}"
                raise InstallError(msg)
            section = stripped[1:-1]
            seen.append(section)
            continue
        key, sep, value = stripped.partition("=")
        key = key.strip(" \t")
        if not sep or not section or not KEY_RE.fullmatch(key):
            msg = f"unit policy: {name} has a line that is not a setting inside a section: {stripped[:40]!r}"
            raise InstallError(msg)
        triples.append((section, key, value.strip(" \t")))
    return triples


def enforce_unit_policy(units: dict[str, str] | dict[str, bytes] | dict[str, str | bytes]) -> None:
    """Refuse a release whose units are not exactly the policy: every (section, key) must be pinned in UNIT_POLICY or be
    in HARMLESS_KEYS (an allowlist, so an unknown key is refused), and every pinned key must carry exactly the pinned
    values in order, so a later assignment, an empty reset or a repeat cannot override."""
    for name in UNIT_NAMES:
        if name not in units:
            msg = f"unit policy: {name} is missing from the release"
            raise InstallError(msg)
        triples = parse_unit_text(name, units[name])
        wanted: dict[tuple[str, str], list[str]] = {}
        for section, key, value in UNIT_POLICY[name]:
            wanted.setdefault((section, key), []).append(value)
        for section, key, _value in triples:
            if (section, key) not in wanted and (section, key) not in HARMLESS_KEYS:
                msg = f"unit policy: {name} [{section}] {key} is not in the allowed set"
                raise InstallError(msg)
        for (section, key), values in wanted.items():
            actual = [v for s_, k, v in triples if s_ == section and k == key]
            if actual != values:
                msg = f"unit policy: {name} [{section}] {key} must be exactly {values!r}, the release has {actual!r}"
                raise InstallError(msg)


SIGNER_PRINCIPAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]*")  # one plain name: no list, wildcard or negation
SIGNER_OPTIONS = 'namespaces="git"'  # the only option a release signer line may carry, written exactly so
SIGNER_BODY_RE = re.compile(r"[A-Za-z0-9+/]+={0,2}")
# What ssh-keygen prints for the key type of a verified signature. A certificate prints a name ending in -CERT, which is
# never in this table, so a signature made through a certificate authority cannot pass.
REPORTED_KEY_TYPE = {
    "sk-ssh-ed25519@openssh.com": "ED25519-SK",
    "sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA-SK",
    "ssh-ed25519": "ED25519",
    "ecdsa-sha2-nistp256": "ECDSA",
    "ssh-rsa": "RSA",
}


def _signer_line_problem(line: str, allowed: Sequence[str]) -> str | None:
    """Why a signers line is not exactly `PRINCIPAL namespaces="git" KEYTYPE BASE64 [comment]` with an allowed plain key
    type, or None. Anything else (cert-authority, another or extra option, a principal list or pattern, a certificate
    type) is refused rather than interpreted, because OpenSSH reads those as wider trust."""
    tokens = line.split(None, 4)
    if len(tokens) < 4:
        return "a line is not principal, options, key type and key"
    principal, options, key_type, body = tokens[:4]
    if not SIGNER_PRINCIPAL_RE.fullmatch(principal):
        return "a principal is not one plain name"
    if options != SIGNER_OPTIONS:
        return f"the only allowed option is exactly {SIGNER_OPTIONS}"
    if key_type not in allowed:
        return "a key type is not allowed"
    if not SIGNER_BODY_RE.fullmatch(body):
        return "a key is not base64"
    return None


def check_signer_key_types(path: Path, allowed: Sequence[str]) -> None:
    """Every line of the release signers file must be an exact key line of an allowed type (hardware keys by default):
    one plain principal, exactly the git namespace restriction, no cert-authority and no other option."""
    found = 0
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        problem = _signer_line_problem(line, allowed)
        if problem:
            msg = (
                f"the release signers file has a line that is not an exact key line of a hardware key type "
                f"({', '.join(allowed)}; {problem}); root can name other types with --release-key-type"
            )
            raise InstallError(msg)
        found += 1
    if not found:
        msg = "the release signers file has no keys"
        raise InstallError(msg)


def check_reported_key_type(reported: str, allowed: Sequence[str]) -> None:
    """The key type ssh-keygen reports for a verified signature must be a plain allowed type, never a certificate."""
    if reported.endswith("-CERT") or "CERT" in reported:
        msg = f"the signature verified through a certificate ({reported}), which is refused"
        raise InstallError(msg)
    if reported not in {REPORTED_KEY_TYPE[t] for t in allowed if t in REPORTED_KEY_TYPE}:
        msg = f"the signature verified with a key type that is not an allowed one ({reported})"
        raise InstallError(msg)


def check_interpreter(path: Path | str, *, uid: int, anchor: Path = Path("/")) -> None:
    """The interpreter the service will run must resolve to a root-owned file in a closed path."""
    resolved = Path(os.path.realpath(path))
    try:
        check_trusted(resolved, Layout(uid=uid, anchor=anchor), "interpreter")
    except InstallError as exc:
        msg = f"the interpreter {resolved} is not trustworthy: {exc}"
        raise InstallError(msg) from None


def check_venv_interpreter(expected: Path | str, venv_python: Path | str) -> None:
    if os.path.realpath(expected) != os.path.realpath(venv_python):
        found = os.path.realpath(venv_python)
        msg = f"the release venv links to the interpreter {found}, not {os.path.realpath(expected)}"
        raise InstallError(msg)


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_lock(text: str) -> Lock:
    index: str | None = None
    reqs: dict[str, tuple[str, frozenset[str]]] = {}
    for raw in re.sub(r"\\\r?\n", " ", text).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--index-url"):
            m = INDEX_RE.fullmatch(line)
            if not m or index is not None:
                msg = f"the lock has an unusable index line: {line[:80]!r}"
                raise InstallError(msg)
            index = m[1]
            continue
        m = REQ_RE.fullmatch(line)
        if not m:
            msg = f"the lock has an unsupported line (only name==version with hashes, one https index): {line[:80]!r}"
            raise InstallError(msg)
        hashes = frozenset(re.findall(r"--hash=sha256:([0-9a-f]{64})", m[3]))
        if not hashes:
            msg = f"the lock requirement {m[1]!r} has no hash (every line needs --hash=sha256:...)"
            raise InstallError(msg)
        key = normalize(m[1])
        if key in reqs:
            msg = f"the lock lists {m[1]!r} twice"
            raise InstallError(msg)
        reqs[key] = (m[2], hashes)
    if not reqs:
        msg = "the lock lists no requirements"
        raise InstallError(msg)
    return Lock(index_url=index, requirements=reqs)


def render_lock(lock: Lock, *, with_index: bool) -> str:
    lines = [f"--index-url {lock.index_url}"] if with_index and lock.index_url else []
    for name, (version, hashes) in sorted(lock.requirements.items()):
        lines.append(" ".join([f"{name}=={version}", *(f"--hash=sha256:{h}" for h in sorted(hashes))]))
    return "\n".join(lines) + "\n"


def check_wheel_name(name: str) -> tuple[str, str]:
    m = WHEEL_RE.fullmatch(name)
    if not m:
        msg = f"{name!r} is not an acceptable wheel filename (wheels only)"
        raise InstallError(msg)
    return normalize(m["name"]), m["ver"]


def pip_download_argv(python: str, lock: Path, dest: Path, extra: Sequence[str] = ()) -> list[str]:
    return [
        python,
        "-I",
        "-m",
        "pip",
        "--isolated",
        "download",
        "--only-binary=:all:",
        "--require-hashes",
        "--no-deps",
        "--no-cache-dir",
        "--disable-pip-version-check",
        "-d",
        str(dest),
        "-r",
        str(lock),
        *extra,
    ]


def pip_install_argv(python: str, venv_python: Path, lock: Path, find_links: Path) -> list[str]:
    return [
        python,
        "-I",
        "-m",
        "pip",
        "--isolated",
        "--python",
        str(venv_python),
        "install",
        "--only-binary=:all:",
        "--require-hashes",
        "--no-deps",
        "--no-index",
        "--find-links",
        str(find_links),
        "--no-compile",
        "--no-cache-dir",
        "--disable-pip-version-check",
        "-r",
        str(lock),
    ]


def default_download(extra: Sequence[str] = ()) -> Callable[[Path, Path], None]:
    def download(lock: Path, dest: Path) -> None:
        done = _run(pip_download_argv(sys.executable, lock, dest, extra), env=_clean_env(dest.parent), timeout=900)
        if done.returncode != 0:
            tail = " | ".join(done.stderr.strip().splitlines()[-3:])
            msg = f"pip download refused or failed: {tail}"
            raise InstallError(msg)

    return download


def inspect_wheel(path: Path) -> None:
    try:
        z = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        msg = f"{path.name} is not a readable wheel archive"
        raise InstallError(msg) from None
    with z:
        infos = z.infolist()
        if len(infos) > MAX_WHEEL_MEMBERS or sum(i.file_size for i in infos) > MAX_WHEEL_BYTES:
            msg = f"{path.name} is too large or has too many members"
            raise InstallError(msg)
        for info in infos:
            name = info.filename
            parts = name.split("/")
            if name.startswith("/") or "\\" in name or ".." in parts or "\0" in name or name[1:2] == ":":
                msg = f"{path.name} has an unsafe member path (traversal): {name!r}"
                raise InstallError(msg)
            if stat.S_ISLNK(info.external_attr >> 16):
                msg = f"{path.name} contains a symlink member: {name!r}"
                raise InstallError(msg)
            if name.endswith(".pth"):
                msg = f"{path.name} contains a .pth file ({name}), which runs code at interpreter start"
                raise InstallError(msg)
            data_part = name.split(".data/", 1)
            if len(data_part) == 2 and data_part[1].split("/", 1)[0] not in ("purelib", "platlib"):
                msg = f"{path.name} installs scripts, headers or data outside site-packages ({name})"
                raise InstallError(msg)
            if name.endswith(".dist-info/entry_points.txt"):
                body = z.read(info).decode("utf-8", "replace")
                if re.search(r"^\[(console_scripts|gui_scripts)\]", body, re.MULTILINE):
                    msg = f"{path.name} declares console or gui entry points"
                    raise InstallError(msg)


def validate_wheels(download_dir: Path, lock: Lock) -> dict[str, Path]:
    seen: dict[str, Path] = {}
    for entry in sorted(download_dir.iterdir()):
        st = os.lstat(entry)
        if not stat.S_ISREG(st.st_mode):
            msg = f"{entry.name} is not a regular wheel file"
            raise InstallError(msg)
        name, version = check_wheel_name(entry.name)
        if name not in lock.requirements:
            msg = f"wheel {entry.name} is not in the lock"
            raise InstallError(msg)
        locked_version, hashes = lock.requirements[name]
        if version != locked_version:
            msg = f"wheel {entry.name} is version {version}, the lock says {locked_version}"
            raise InstallError(msg)
        digest = hashlib.sha256(entry.read_bytes()).hexdigest()
        if digest not in hashes:
            msg = f"the hash of {entry.name} does not match the lock"
            raise InstallError(msg)
        if name in seen:
            msg = f"more than one wheel for {name}"
            raise InstallError(msg)
        inspect_wheel(entry)
        seen[name] = entry
    for name in lock.requirements:
        if name not in seen:
            msg = f"no wheel was downloaded for {name}"
            raise InstallError(msg)
    return seen


# ---- manifest, ownership walk, read-only ---------------------------------------------------------------------------


def _walk(root: Path) -> Iterator[tuple[str, Path]]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            p = Path(dirpath) / name
            yield str(p.relative_to(root)), p


def write_manifest(release: Path) -> None:
    lines = []
    for rel, p in _walk(release):
        if rel == "MANIFEST.sha256":
            continue
        if p.is_symlink():
            lines.append(f"link\t{os.readlink(p)}\t{rel}")
        elif p.is_file():
            lines.append(f"file\t{hashlib.sha256(p.read_bytes()).hexdigest()}\t{rel}")
    (release / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")


def verify_manifest(release: Path) -> list[str]:
    """Return a list of problems (empty when the tree matches its manifest exactly)."""
    try:
        wanted = [line.split("\t") for line in (release / "MANIFEST.sha256").read_text().splitlines() if line]
    except OSError:
        return ["missing: MANIFEST.sha256"]
    problems: list[str] = []
    expect = {rel: (kind, value) for kind, value, rel in wanted}
    actual: set[str] = set()
    for rel, p in _walk(release):
        if rel == "MANIFEST.sha256":
            continue
        if p.is_symlink():
            actual.add(rel)
            if expect.get(rel) != ("link", os.readlink(p)):
                problems.append(f"modified: {rel}")
        elif p.is_file():
            actual.add(rel)
            if expect.get(rel) != ("file", hashlib.sha256(p.read_bytes()).hexdigest()):
                problems.append(f"modified: {rel}")
    problems += [f"unexpected: {r}" for r in sorted(actual - expect.keys())]
    problems += [f"missing: {r}" for r in sorted(expect.keys() - actual)]
    return sorted(set(problems))


def check_venv_bin(bin_dir: Path) -> None:
    """Nothing but what `venv` itself creates may sit in bin/, and the interpreter names must still be links."""
    for entry in bin_dir.iterdir():
        name = entry.name
        if INTERPRETER_LINK.fullmatch(name):
            if not entry.is_symlink():
                msg = f"venv/bin/{name} is not a symlink after the install; refused"
                raise InstallError(msg)
        elif name not in ("activate", "activate.csh", "activate.fish", "Activate.ps1"):
            msg = f"venv/bin/{name} was not created by venv; refused"
            raise InstallError(msg)


def check_links(release: Path) -> None:
    """The only links in a staged tree are the ones `venv` makes. Run before anything is chmod-ed."""
    for rel, p in _walk(release):
        if p.is_symlink() and not (
            rel == "venv/lib64"
            or (rel.startswith("venv/bin/") and INTERPRETER_LINK.fullmatch(rel.removeprefix("venv/bin/")))
        ):
            msg = f"staged tree has an unexpected symlink at {rel}"
            raise InstallError(msg)


def normalize_modes(release: Path) -> None:
    """Clear group/other write and the setuid/setgid/sticky bits on every real file and directory. The result must not
    depend on the caller's umask or on the modes of files the environment builder copied. Links are never followed."""
    for _rel, p in _walk(release):
        st = os.lstat(p)
        if stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode):
            os.chmod(p, stat.S_IMODE(st.st_mode) & ~0o7022, follow_symlinks=False)
    os.chmod(release, stat.S_IMODE(os.lstat(release).st_mode) & ~0o7022)


def check_tree_owner(release: Path, layout: Layout) -> None:
    for rel, p in _walk(release):
        st = os.lstat(p)
        if st.st_uid != layout.uid:
            msg = f"staged file {rel} is not owned by the trusted user"
            raise InstallError(msg)
        if stat.S_ISLNK(st.st_mode):
            continue  # check_links has already limited which links may exist
        if st.st_mode & 0o022:
            msg = f"staged file {rel} is writable by its group or others"
            raise InstallError(msg)


def make_read_only(release: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(release, topdown=False, followlinks=False):
        for name in filenames:
            p = Path(dirpath) / name
            if not p.is_symlink():
                p.chmod(p.stat().st_mode & ~0o222)
        for name in dirnames:
            p = Path(dirpath) / name
            if not p.is_symlink():
                p.chmod(0o555)
    release.chmod(0o555)


def remove_tree(path: Path) -> None:
    if not os.path.lexists(path):
        return
    if path.is_symlink():
        path.unlink()
        return
    for dirpath, dirnames, _ in os.walk(path, followlinks=False):
        Path(dirpath).chmod(0o755)
        dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
    shutil.rmtree(path)


# ---- units, self-test, health -----------------------------------------------------------------------------------


def default_verify_units(unit_dir: Path, release: Path) -> None:
    """Ask systemd itself, without starting anything: `verify` on the staged copies must print nothing about unknown or
    ignored settings, the broker service must resolve every hardening check in RESOLVED_MUST_BE_SET as set, and each
    unit's offline exposure score must stay within its budget."""
    if not os.access(SYSTEMD_ANALYZE, os.X_OK):
        msg = "systemd-analyze is not available, so the staged units cannot be verified; refused"
        raise InstallError(msg)
    with tempfile.TemporaryDirectory(prefix="units-") as tmp:
        paths = []
        for name in UNIT_NAMES:
            text = (unit_dir / name).read_text().replace(UNIT_EXEC_PREFIX, str(release))
            text = text.replace(EGRESS_HELPER, str(release / "venv" / "bin" / "python"))  # a stand-in that exists
            target = Path(tmp) / name
            target.write_text(text)
            paths.append(str(target))
        env = _clean_env(Path(tmp))
        done = _run([SYSTEMD_ANALYZE, "verify", "--man=no", *paths], env=env, timeout=120)
        noise = done.stderr + done.stdout
        if done.returncode != 0 or re.search(
            r"Unknown|Ignoring|Invalid|Failed to parse|Missing|outside of section|deprecated", noise
        ):
            msg = f"systemd-analyze verify failed: {' | '.join(noise.strip().splitlines()[-3:])}"
            raise InstallError(msg)
        for name, budget in EXPOSURE_BUDGET.items():
            path = str(Path(tmp) / name)
            score = _run([SYSTEMD_ANALYZE, "security", "--offline=true", "--no-pager", path], env=env, timeout=120)
            m = re.search(r"Overall exposure level for \S+: ([0-9.]+)", score.stdout)
            if score.returncode != 0 or not m or float(m[1]) > budget:
                level = m[1] if m else "unknown"
                msg = f"systemd resolves {name} to an exposure level of {level}, over its budget {budget}; refused"
                raise InstallError(msg)
        resolved = _run(
            [
                SYSTEMD_ANALYZE,
                "security",
                "--offline=true",
                "--no-pager",
                "--json=short",
                str(Path(tmp) / "safo-broker.service"),
            ],
            env=env,
            timeout=120,
        )
        try:
            checks = {c["name"]: bool(c["set"]) for c in json.loads(resolved.stdout)}
        except (ValueError, KeyError, TypeError):
            msg = "systemd-analyze security gave no readable result for the broker service; refused"
            raise InstallError(msg) from None
        missing = [n for n in RESOLVED_MUST_BE_SET if not checks.get(n)]
        if missing:
            msg = f"systemd does not resolve these checks as set for the broker service: {', '.join(missing)}; refused"
            raise InstallError(msg)


def sandboxed(argv: list[str]) -> list[str]:
    """Wrap a command in the transient sandbox. The state directory it is told about is the empty in-memory one."""
    wrap = [SYSTEMD_RUN, "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec"]
    for prop in SELF_TEST_PROPERTIES:
        wrap += ["-p", prop]
    wrap += ["-E", f"STATE_DIRECTORY={STATE_DIR}", "-E", "PYTHONDONTWRITEBYTECODE=1", "-E", "PATH=/usr/bin:/bin"]
    return [*wrap, "--working-directory=/", "--", *argv]


def self_test_argv(python: Path, modules: Sequence[str], *, as_service_user: bool) -> list[str]:
    """The import check. As root it runs in the sandbox, so import-time code in the release or its dependencies can
    neither read root's or the broker's files nor reach the network."""
    argv = [str(python), "-I", "-c", "import " + ", ".join(modules)]
    return sandboxed(argv) if as_service_user else argv


def broker_modules(release: Path) -> list[str]:
    """The broker package and every module in it (except the entry point), found in the staged tree."""
    package = _site_packages(release) / "safo" / "broker"
    names = ["safo.broker"]
    names += [f"safo.broker.{p.stem}" for p in sorted(package.glob("*.py")) if p.stem not in ("__init__", "__main__")]
    return sorted(names)


def entry_self_test_argv(python: Path, *, as_service_user: bool) -> list[str]:
    argv = [str(python), "-I", "-m", "safo.broker", "--self-test"]
    return sandboxed(argv) if as_service_user else argv


def default_self_test(
    modules: Sequence[str] = ("yaml",),
    *,
    use_runuser: bool | None = None,
    run: Callable[..., subprocess.CompletedProcess[str]] = _run,
    wrap: Callable[[list[str]], list[str]] | None = None,
) -> Callable[[Path], None]:
    """Import every broker module and every extra module, then run the real entry point in its self-test mode, both in
    the transient sandbox. Staged code is never run outside a sandbox: without root there is none, so the self-test
    refuses unless the caller names a `wrap` (a test seam; the installer itself never passes one)."""

    def self_test(release: Path) -> None:
        python = release / "venv" / "bin" / "python"
        root = use_runuser if use_runuser is not None else os.geteuid() == 0
        confine = wrap
        if confine is None:
            if not root:
                msg = "refusing to run the staged tree without the sandbox, which needs root"
                raise InstallError(msg)
            confine = sandboxed
        with tempfile.TemporaryDirectory(prefix="safo-selftest-") as empty_state:
            env = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "STATE_DIRECTORY": empty_state}
            for argv in (
                self_test_argv(python, [*broker_modules(release), *modules], as_service_user=False),
                entry_self_test_argv(python, as_service_user=False),
            ):
                done = run(confine(argv), env=env, cwd=Path("/"), timeout=120)
                if done.returncode != 0:
                    tail = " | ".join(done.stderr.strip().splitlines()[-2:])
                    msg = f"the staged tree failed its self-test: {tail}"
                    raise InstallError(msg)

    return self_test


def default_systemctl(args: Sequence[str]) -> int:
    return _run([SYSTEMCTL, *args], env={"PATH": "/usr/bin:/bin"}, timeout=180).returncode


def default_health(systemctl: Callable[[Sequence[str]], int]) -> Callable[[], str]:
    """Until the socket server lands (phase 3) the check is that systemd reports the socket active. A socket that is not
    enabled yet (a first install, before the runbook enables it) is reported as skipped, which is not a pass."""

    def health() -> str:
        if systemctl(["is-enabled", "--quiet", "safo-broker.socket"]) != 0:
            return "socket not enabled yet; the post-start check was skipped (not a pass)"
        if systemctl(["is-active", "--quiet", "safo-broker.socket"]) != 0:
            msg = "safo-broker.socket is not active after the restart"
            raise RuntimeError(msg)
        return "socket active"

    return health


def _ask(prompt: str) -> str:
    return input(prompt + " ")


def make_hooks(
    *,
    fetch: Callable[[str, Path], None] | None = None,
    download: Callable[[Path, Path], None] | None = None,
    systemctl: Callable[[Sequence[str]], int] | None = None,
    verify_units: Callable[[Path, Path], None] | None = None,
    self_test: Callable[[Path], None] | None = None,
    health: Callable[[], str] | None = None,
    fault: Callable[[str], None] | None = None,
    confirm: Callable[[str], str] | None = None,
) -> Hooks:
    ctl = systemctl or default_systemctl
    return Hooks(
        fetch=fetch or default_fetch(),
        download=download or default_download(),
        systemctl=ctl,
        verify_units=verify_units or default_verify_units,
        self_test=self_test or default_self_test(),
        health=health or default_health(ctl),
        fault=fault or (lambda point: None),
        confirm=confirm or _ask,
    )


# ---- links, releases and units on disk ------------------------------------------------------------------------


def open_opt(layout: Layout) -> int:
    check_trusted(layout.opt_dir, layout, "install directory", want_dir=True)
    check_trusted(layout.opt_dir / "releases", layout, "releases directory", want_dir=True)
    return os.open(layout.opt_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def read_link(fd: int, name: str) -> str | None:
    try:
        return os.readlink(name, dir_fd=fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.EINVAL:
            msg = f"{name} is not a symlink; refused"
            raise InstallError(msg) from None
        raise


def link_release(target: str | None, what: str) -> str | None:
    if target is None:
        return None
    m = LINK_RE.fullmatch(target)
    if not m:
        msg = f"the {what} link points somewhere unexpected ({target!r}); refused"
        raise InstallError(msg)
    return m[1]


def set_link(fd: int, name: str, target: str, fault: Callable[[str], None] | None = None, point: str = "") -> None:
    """Atomically point `name` at `target`: a temporary link in the same directory, renamed over `name`."""
    tmp = f".{name}.tmp.{os.getpid()}"
    with contextlib.suppress(FileNotFoundError):
        os.unlink(tmp, dir_fd=fd)
    os.symlink(target, tmp, dir_fd=fd)
    if fault and point:
        fault(point)
    os.replace(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
    os.fsync(fd)


def drop_link(fd: int, name: str) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.unlink(name, dir_fd=fd)
    os.fsync(fd)


def clean_stale(layout: Layout) -> None:
    for p in layout.opt_dir.iterdir():
        if re.fullmatch(r"\.(current|previous)\.tmp\.[0-9]+", p.name):
            p.unlink()
    for p in (layout.opt_dir / "releases").iterdir():
        if p.name.startswith(".stage-"):
            remove_tree(p)
    for p in layout.unit_dir.iterdir():
        if re.fullmatch(r"\.safo-broker\.(service|socket)\.tmp\.[0-9]+", p.name):
            p.unlink()


def installed_releases(layout: Layout) -> list[str]:
    root = layout.opt_dir / "releases"
    names = [p.name for p in root.iterdir() if RELEASE_RE.fullmatch(p.name) and p.is_dir() and not p.is_symlink()]
    return sorted(names, key=release_key)


def choose_name(layout: Layout, version: str, current: str | None, previous: str | None) -> str:
    releases = layout.opt_dir / "releases"
    if not os.path.lexists(releases / version):
        return version
    if version not in (current, previous):
        remove_tree(releases / version)  # left over from an interrupted install, never active
        return version
    n = 1
    while os.path.lexists(releases / f"{version}.r{n}"):
        if f"{version}.r{n}" not in (current, previous):
            remove_tree(releases / f"{version}.r{n}")
            break
        n += 1
    return f"{version}.r{n}"


def read_units(path: Path) -> dict[str, bytes | None]:
    out: dict[str, bytes | None] = {}
    for name in UNIT_NAMES:
        p = path / name
        out[name] = p.read_bytes() if p.is_file() and not p.is_symlink() else None
    return out


def write_units(layout: Layout, units: dict[str, bytes | None], hooks: Hooks | None = None) -> None:
    """Replace the unit files: every new file is written under a temporary name first, then renamed into place."""
    check_trusted(layout.unit_dir, layout, "unit directory", want_dir=True)
    temps = []
    for name, data in units.items():
        if data is None:
            continue
        tmp = layout.unit_dir / f".{name}.tmp.{os.getpid()}"
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            os.write(fd, data)
            os.fchmod(fd, 0o644)
            os.fsync(fd)
        finally:
            os.close(fd)
        temps.append((tmp, layout.unit_dir / name))
    if hooks:
        hooks.fault("units_tmp_written")
    for tmp, final in temps:
        os.replace(tmp, final)
    for name, data in units.items():
        if data is None:
            with contextlib.suppress(FileNotFoundError):
                (layout.unit_dir / name).unlink()


def reload_and_restart(hooks: Hooks) -> str:
    if hooks.systemctl(["daemon-reload"]) != 0:
        msg = "systemctl daemon-reload failed"
        raise RuntimeError(msg)
    if hooks.systemctl(EGRESS_RESTART) != 0:
        msg = "systemctl try-restart of the egress units failed"
        raise RuntimeError(msg)
    if hooks.systemctl(["try-restart", "safo-broker.socket", "safo-broker.service"]) != 0:
        msg = "systemctl try-restart failed"
        raise RuntimeError(msg)
    hooks.fault("after_restart")
    detail = hooks.health()
    hooks.fault("after_health")
    return detail


def prune(layout: Layout, current: str, previous: str | None) -> None:
    names = installed_releases(layout)
    keep = {current}
    if previous:
        keep.add(previous)
    others = [n for n in reversed(names) if n != current]
    keep.update(others[:KEEP_OTHERS])
    for name in names:
        if name not in keep:
            remove_tree(layout.opt_dir / "releases" / name)


# ---- review ---------------------------------------------------------------------------------------------------------


def _site_packages(release: Path) -> Path:
    found = sorted((release / "venv").glob("lib/python*/site-packages"))
    if len(found) != 1:
        msg = "the staged venv does not have exactly one site-packages directory"
        raise InstallError(msg)
    return found[0]


def _udiff(old: str, new: str, name: str) -> list[str]:
    return list(
        difflib.unified_diff(old.splitlines(), new.splitlines(), f"installed/{name}", f"new/{name}", lineterm="")
    )


def build_review(
    layout: Layout,
    *,
    version: str,
    commit: str,
    tag: TagInfo,
    lock: Lock,
    wheels: dict[str, Path],
    files: dict[str, bytes],
    current: str | None,
    apply: bool,
) -> str:
    lines = [f"Broker install review ({'APPLY' if apply else 'DRY RUN: nothing will be changed'})", ""]
    old_dir = layout.opt_dir / "releases" / current if current else None
    old_commit = (old_dir / "COMMIT").read_text().strip() if old_dir and (old_dir / "COMMIT").is_file() else "none"
    lines += [
        f"installed: {current or 'none'} (commit {old_commit})",
        f"new:       {version} (commit {commit})",
        f"tag signer: {tag.signer}",
        f"index:     {lock.index_url or 'none named in the lock'}",
        "",
        "Dependencies (exact wheel, hash):",
    ]
    old_lock: Lock | None = None
    if old_dir and (old_dir / "meta" / LOCK_REL).is_file():
        with contextlib.suppress(InstallError):
            old_lock = parse_lock((old_dir / "meta" / LOCK_REL).read_text())
    old_reqs = old_lock.requirements if old_lock else {}
    for name, (ver, _hashes) in sorted(lock.requirements.items()):
        wheel = wheels[name]
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        if name not in old_reqs:
            lines.append(f"  +{name}=={ver}  {wheel.name}  sha256:{digest}")
        elif old_reqs[name][0] != ver:
            lines.append(f"  ~{name}: {old_reqs[name][0]} -> {ver}  {wheel.name}  sha256:{digest}")
        else:
            lines.append(f"   {name}=={ver}  {wheel.name}  sha256:{digest}")
    lines += [f"  -{n}=={v[0]}" for n, v in sorted(old_reqs.items()) if n not in lock.requirements]
    lines += ["", "Build-control files changed since the installed release:"]
    changed = 0
    for rel in sorted(files):
        if not (rel in BUILD_CONTROL or rel.startswith("packaging/")):
            continue
        old_file = old_dir / "meta" / rel if old_dir else None
        old_text = old_file.read_text() if old_file and old_file.is_file() else None
        new_text = files[rel].decode("utf-8", "replace")
        if old_text == new_text:
            continue
        changed += 1
        lines.append(f"  {rel} ({'new' if old_text is None else 'changed'})")
        lines += [f"    {d}" for d in _udiff(old_text or "", new_text, rel)]
    if old_dir and (old_dir / "meta").is_dir():
        for p in sorted((old_dir / "meta").rglob("*")):
            rel = str(p.relative_to(old_dir / "meta"))
            if p.is_file() and rel not in files:
                changed += 1
                lines.append(f"  {rel} (removed)")
    if not changed:
        lines.append("  none")
    lines += ["", "Broker source changes:"]
    old_site = _site_packages(old_dir) if old_dir and (old_dir / "venv").is_dir() else None
    shown = 0
    for rel in sorted(files):
        if not rel.startswith("src/safo/"):
            continue
        sub = rel.removeprefix("src/")
        old_file = old_site / sub if old_site else None
        old_text = old_file.read_text(errors="replace") if old_file and old_file.is_file() else None
        new_text = files[rel].decode("utf-8", "replace")
        if old_text == new_text:
            continue
        shown += 1
        lines.append(f"  {sub} ({'new' if old_text is None else 'changed'})")
        lines += [f"    {d}" for d in _udiff(old_text or "", new_text, sub)]
    if not shown:
        lines.append("  none")
    return "\n".join(lines) + "\n"


# ---- building -------------------------------------------------------------------------------------------------


def build_release(*args: Any, **kwargs: Any) -> None:
    """Build under an explicit umask, so the release never depends on the caller's (the children inherit it)."""
    old = os.umask(0o022)
    try:
        _build_release(*args, **kwargs)
    finally:
        os.umask(old)


def _build_release(
    layout: Layout,
    hooks: Hooks,
    stage: Path,
    *,
    files: dict[str, bytes],
    lock: Lock,
    download_dir: Path,
    commit: str,
    version: str,
    home: Path,
) -> None:
    stage.mkdir(mode=0o755)
    venv.EnvBuilder(with_pip=False, symlinks=True, clear=False, system_site_packages=False).create(stage / "venv")
    if layout.check_python:
        check_venv_interpreter(sys.executable, stage / "venv" / "bin" / "python")
    site = _site_packages(stage)
    install_lock = home / "install-lock.txt"
    install_lock.write_text(render_lock(lock, with_index=False))
    argv = pip_install_argv(sys.executable, stage / "venv" / "bin" / "python", install_lock, download_dir)
    done = _run(argv, env=_clean_env(home), timeout=900)
    if done.returncode != 0:
        msg = f"pip install failed: {' | '.join(done.stderr.strip().splitlines()[-3:])}"
        raise InstallError(msg)
    check_venv_bin(stage / "venv" / "bin")
    if list(site.rglob("*.pth")):
        msg = "the installed environment contains a .pth file; refused"
        raise InstallError(msg)
    if (site / "safo").exists():
        msg = "a locked wheel installs a package named safo, which would overlap the broker's own code; refused"
        raise InstallError(msg)
    for rel, data in files.items():
        if rel.startswith("src/safo/"):
            target = site / rel.removeprefix("src/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o644)
    (stage / "units").mkdir()
    for name in UNIT_NAMES:
        (stage / "units" / name).write_bytes(files[f"packaging/systemd/{name}"])
    for rel, data in files.items():
        if rel in BUILD_CONTROL or rel.startswith("packaging/"):
            target = stage / "meta" / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    (stage / "COMMIT").write_text(commit + "\n")
    (stage / "VERSION").write_text(version + "\n")
    # every installed broker file must equal the verified commit's blob, and nothing extra may sit in the package
    installed = {str(p.relative_to(site)): p for p in (site / "safo").rglob("*") if p.is_file()}
    wanted = {rel.removeprefix("src/"): data for rel, data in files.items() if rel.startswith("src/safo/")}
    if set(installed) != set(wanted) or any(installed[k].read_bytes() != wanted[k] for k in wanted):
        msg = "the installed broker source does not match the verified commit"
        raise InstallError(msg)
    check_links(stage)
    normalize_modes(stage)
    write_manifest(stage)
    check_tree_owner(stage, layout)
    if verify_manifest(stage):
        msg = "the staged tree does not match its manifest"
        raise InstallError(msg)
    hooks.verify_units(stage / "units", stage)
    hooks.self_test(stage)
    make_read_only(stage)


# ---- install ----------------------------------------------------------------------------------------------------


@contextlib.contextmanager
def single_instance(layout: Layout) -> Iterator[None]:
    path = layout.version_file.parent / "install.lock"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            msg = "another install or rollback is running"
            raise InstallError(msg) from None
        yield
    finally:
        os.close(fd)


def check_policy(
    version: str, layout: Layout, reinstall: bool, allow_downgrade: str | None
) -> tuple[tuple[int, int, int] | None, bool]:
    """Read the floor and the highest-installed record now and decide. Returns (highest, is_a_downgrade)."""
    ver = parse_version(version)
    floor = read_floor(layout)
    highest = read_highest(layout)
    if ver < floor:
        msg = f"version {version} is below the floor {fmt(floor)}; refused (the floor cannot be passed with a flag)"
        raise InstallError(msg)
    downgrade = False
    if highest is not None:
        if ver < highest:
            if allow_downgrade != version:
                msg = (
                    f"version {version} is lower than the highest installed {fmt(highest)}; refused "
                    f"(root can pass --allow-downgrade {version})"
                )
                raise InstallError(msg)
            downgrade = True
        elif ver == highest and not reinstall:
            msg = f"version {version} is the same as the highest installed; pass --reinstall to install it again"
            raise InstallError(msg)
    return highest, downgrade


def prepare_state(layout: Layout, *, need_work: bool = True) -> None:
    """The installer's own directories must be root-owned and closed before anything is written there."""
    check_trusted(layout.version_file.parent, layout, "installer state directory", want_dir=True)
    if need_work:
        layout.work_dir.mkdir(mode=0o700, exist_ok=True)
        check_trusted(layout.work_dir, layout, "work directory", want_dir=True)
    if os.path.lexists(layout.log_file):
        check_trusted(layout.log_file, layout, "install log")


def install(
    version: str,
    layout: Layout,
    hooks: Hooks,
    *,
    apply: bool = False,
    reinstall: bool = False,
    allow_downgrade: str | None = None,
    out: Callable[[str], None] = print,
) -> Report:
    parse_version(version)
    if not apply:
        return _install(version, layout, hooks, False, reinstall, allow_downgrade, out)
    # the lock comes first: the policy files are read, re-read and acted on while no other install can run
    prepare_state(layout)
    with single_instance(layout):
        return _install(version, layout, hooks, True, reinstall, allow_downgrade, out)


def _install(
    version: str,
    layout: Layout,
    hooks: Hooks,
    apply: bool,
    reinstall: bool,
    allow_downgrade: str | None,
    out: Callable[[str], None],
) -> Report:
    tag = f"v{version}"
    check_trusted(layout.signers, layout, "release signers file")
    check_signer_key_types(layout.signers, layout.key_types)
    check_trusted(layout.opt_dir, layout, "install directory", want_dir=True)
    check_policy(version, layout, reinstall, allow_downgrade)
    work = Path(tempfile.mkdtemp(prefix="install-", dir=layout.work_dir if apply else None))
    try:
        hooks.fetch(tag, work / "repo")
        info = verify_tag(work / "repo", tag, layout, work)
        files = extract_tree(work / "repo", info.commit, work / "tree", work)
        m = VERSION_LINE_RE.search(files["src/safo/__init__.py"].decode("utf-8", "replace"))
        if not m or m[1] != version:
            msg = (
                f"the signed tag says {version} but the package's __version__ is {m[1] if m else 'unreadable'}; refused"
            )
            raise InstallError(msg)
        enforce_unit_policy({n: files[f"packaging/systemd/{n}"] for n in UNIT_NAMES})
        lock = parse_lock(files[LOCK_REL].decode("utf-8", "replace"))
        download_dir = work / "wheels"
        download_dir.mkdir(mode=0o700)
        lock_path = work / "download-lock.txt"
        lock_path.write_text(render_lock(lock, with_index=True))
        hooks.download(lock_path, download_dir)
        wheels = validate_wheels(download_dir, lock)
        current = None
        if (layout.opt_dir / "releases").is_dir():
            fd = open_opt(layout)
            try:
                current = link_release(read_link(fd, "current"), "current")
            finally:
                os.close(fd)
        review = build_review(
            layout,
            version=version,
            commit=info.commit,
            tag=info,
            lock=lock,
            wheels=wheels,
            files=files,
            current=current,
            apply=apply,
        )
        out(review)
        if not apply:
            return Report(version, info.commit, info.signer, False, review)
        if hooks.confirm(f"Type the version to continue: {version}").strip() != version:
            msg = "not confirmed: the typed version did not match; nothing was changed"
            raise InstallError(msg)
        release_dir = activate(
            layout,
            hooks,
            version=version,
            commit=info.commit,
            signer=info.signer,
            files=files,
            lock=lock,
            download_dir=download_dir,
            work=work,
            reinstall=reinstall,
            allow_downgrade=allow_downgrade,
            out=out,
        )
        return Report(version, info.commit, info.signer, True, review, release_dir)
    except subprocess.TimeoutExpired:
        msg = "a command timed out"
        raise InstallError(msg) from None
    finally:
        shutil.rmtree(work, ignore_errors=True)


def activate(
    layout: Layout,
    hooks: Hooks,
    *,
    version: str,
    commit: str,
    signer: str,
    files: dict[str, bytes],
    lock: Lock,
    download_dir: Path,
    work: Path,
    reinstall: bool,
    allow_downgrade: str | None,
    out: Callable[[str], None],
) -> Path:
    if layout.check_python:
        check_interpreter(sys.executable, uid=layout.uid, anchor=layout.anchor)
    check_trusted(layout.egress_helper, layout, "egress helper")
    if not os.access(layout.egress_helper, os.X_OK):
        msg = f"the egress helper {layout.egress_helper} is not executable; install it first (see the runbook)"
        raise InstallError(msg)
    fd = open_opt(layout)
    try:
        clean_stale(layout)
        old_target = read_link(fd, "current")
        old_prev_target = read_link(fd, "previous")
        current = link_release(old_target, "current")
        previous = link_release(old_prev_target, "previous")
        name = choose_name(layout, version, current, previous)
        releases = layout.opt_dir / "releases"
        stage = releases / f".stage-{os.getpid()}"
        final = releases / name
        old_units = read_units(layout.unit_dir)
        hooks.fault("before_build")
        try:
            build_release(
                layout,
                hooks,
                stage,
                files=files,
                lock=lock,
                download_dir=download_dir,
                commit=commit,
                version=version,
                home=work,
            )
            # the policy files are read again now, under the lock, after the human review and the build
            highest, downgrade = check_policy(version, layout, reinstall, allow_downgrade)
            os.rename(stage, final)
            hooks.fault("after_build")
        except Exception as exc:
            remove_tree(stage)
            remove_tree(final)
            if isinstance(exc, InstallError):
                raise
            msg = f"the build failed: {type(exc).__name__}"
            raise InstallError(msg) from None
        step = "swap"
        new_highest = max(highest, parse_version(version)) if highest else parse_version(version)
        try:
            hooks.fault("before_swap")
            if old_target:
                set_link(fd, "previous", old_target)
                hooks.fault("after_previous_link")
            set_link(fd, "current", f"releases/{name}", hooks.fault, "after_tmp_link")
            hooks.fault("after_swap")
            step = "units"
            write_units(layout, read_units(final / "units"), hooks)
            hooks.fault("after_units")
            step = "restart"
            detail = reload_and_restart(hooks)
            step = "version file"
            write_atomic(layout.version_file, (fmt(new_highest) + "\n").encode(), 0o600)
            hooks.fault("after_version_write")
        except Exception as exc:
            note = restore(layout, hooks, fd, old_target, old_prev_target, old_units, final)
            log_line(layout, f"install {version} failed at {step} ({type(exc).__name__}); rolled back{note}")
            msg = f"install of {version} failed at {step}: {exc}; rolled back to {current or 'nothing'}{note}"
            raise InstallError(msg) from None
        downgrade_note = " downgrade" if downgrade else ""
        log_line(
            layout,
            f"install {version} commit={commit} signer={signer} from={current or 'none'}{downgrade_note} ({detail})",
        )
        if downgrade:
            log_line(layout, f"downgrade to {version} allowed by root; highest stays {fmt(new_highest)}")
        prune(layout, name, link_release(read_link(fd, "previous"), "previous"))
        out(f"installed {version}; active release is {name} ({detail})")
        return final
    finally:
        os.close(fd)


RETIRE_ORDER = (
    "safo-broker-egress-refresh.timer",
    "safo-broker-egress-refresh.service",
    "safo-broker-egress.service",
)


def stop_retired_units(hooks: Hooks, before: dict[str, bytes | None], after: dict[str, bytes | None]) -> list[str]:
    """Stop the units that exist now but will not exist after the change, while their files are still there (a unit
    whose file is gone keeps running and can no longer be stopped by name). Dependents first. Returns the failures."""
    failed = []
    for name in RETIRE_ORDER:
        if before.get(name) is not None and after.get(name) is None and hooks.systemctl(["stop", name]) != 0:
            failed.append(name)
    return failed


def restore(
    layout: Layout,
    hooks: Hooks,
    fd: int,
    old_target: str | None,
    old_prev_target: str | None,
    old_units: dict[str, bytes | None],
    new_release: Path | None,
) -> str:
    """Put the links and the units back. Returns a note for the message when something could not be restored."""
    problems = []
    try:
        if old_target:
            set_link(fd, "current", old_target)
        else:
            drop_link(fd, "current")
        if old_prev_target:
            set_link(fd, "previous", old_prev_target)
        else:
            drop_link(fd, "previous")
        stuck = stop_retired_units(hooks, read_units(layout.unit_dir), old_units)
        if stuck:
            problems.append(f"could not stop {', '.join(stuck)}; stop them by hand")
        write_units(layout, old_units)
        reloaded = hooks.systemctl(["daemon-reload"]) == 0
        egress_ok = hooks.systemctl(EGRESS_RESTART) == 0
        restarted = hooks.systemctl(["try-restart", "safo-broker.socket", "safo-broker.service"]) == 0
        if not (reloaded and egress_ok and restarted):
            problems.append("systemctl could not reload or restart after the rollback")
    except Exception as exc:
        problems.append(f"restore error {type(exc).__name__}")
    if new_release is not None:
        with contextlib.suppress(Exception):
            remove_tree(new_release)
    return f" ({'; '.join(problems)})" if problems else ""


def rollback(layout: Layout, hooks: Hooks, *, to: str | None = None, out: Callable[[str], None] = print) -> str:
    check_trusted(layout.opt_dir, layout, "install directory", want_dir=True)
    floor = read_floor(layout)
    prepare_state(layout, need_work=False)
    with single_instance(layout):
        fd = open_opt(layout)
        try:
            clean_stale(layout)
            old_target = read_link(fd, "current")
            old_prev_target = read_link(fd, "previous")
            current = link_release(old_target, "current")
            name: str
            if current is None:
                msg = "there is no current release to roll back from"
                raise InstallError(msg)
            if to is not None:
                if not RELEASE_RE.fullmatch(to):
                    msg = f"{to!r} is not a release version"
                    raise InstallError(msg)
                name = to
            else:
                found = link_release(old_prev_target, "previous")
                if found is None:
                    msg = "there is no previous release to roll back to"
                    raise InstallError(msg)
                name = found
            target_dir = layout.opt_dir / "releases" / name
            if not target_dir.is_dir() or target_dir.is_symlink():
                msg = f"there is no installed release {name}"
                raise InstallError(msg)
            if name == current:
                msg = f"release {name} is already the current one"
                raise InstallError(msg)
            if release_key(name)[:3] < floor:
                msg = f"release {name} is below the floor {fmt(floor)}; refused"
                raise InstallError(msg)
            problems = verify_manifest(target_dir)
            if problems or not (target_dir / "venv" / "bin" / "python").exists():
                why = "; ".join(problems[:3]) or "no interpreter"
                msg = f"release {name} does not match its manifest ({why}); refused"
                raise InstallError(msg)
            old_units = read_units(layout.unit_dir)
            try:
                set_link(fd, "current", f"releases/{name}")
                set_link(fd, "previous", old_target or f"releases/{current}")
                target_units = read_units(target_dir / "units")
                stuck = stop_retired_units(hooks, old_units, target_units)
                if stuck:
                    msg = f"could not stop {', '.join(stuck)} before rolling back past them"
                    raise RuntimeError(msg)
                write_units(layout, target_units)
                detail = reload_and_restart(hooks)
            except Exception as exc:
                note = restore(layout, hooks, fd, old_target, old_prev_target, old_units, None)
                msg = f"rollback to {name} failed ({type(exc).__name__}); restored the previous state{note}"
                raise InstallError(msg) from None
            log_line(layout, f"rollback {current} -> {name} ({detail})")
            out(f"rolled back from {current} to {name} ({detail})")
            return name
        finally:
            os.close(fd)


# ---- command line -------------------------------------------------------------------------------------------------


def cmd_plan(maintainer: str, out: Callable[[str], None]) -> int:
    try:
        from safo.broker import runbook  # not part of the single-file copy: the plan is printed from a checkout
    except ImportError:
        print("refused: `plan` needs the safo package; run it from the reviewed checkout", file=sys.stderr)
        return 1
    try:
        out(runbook.render(maintainer=maintainer))
    except ValueError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safo-broker-install", description="Install the paid Gemini broker from a signed tag."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p_plan = sub.add_parser("plan", help="print the one-time root setup runbook (never executes it)")
    p_plan.add_argument("--maintainer", default="MAINTAINER_LOGIN")
    p_inst = sub.add_parser("install", help="verify and install a signed release (dry run unless --apply)")
    p_inst.add_argument("version")
    p_inst.add_argument("--apply", action="store_true")
    p_inst.add_argument("--reinstall", action="store_true")
    p_inst.add_argument("--allow-downgrade", metavar="VERSION")
    p_inst.add_argument(
        "--release-key-type",
        action="append",
        metavar="TYPE",
        help="key type a release signer may have (repeatable); the default is hardware keys only",
    )
    p_roll = sub.add_parser("rollback", help="activate the previous (or a named) installed release")
    p_roll.add_argument("--to", metavar="VERSION")
    return parser


def main(argv: Sequence[str] | None = None, *, layout: Layout | None = None, hooks: Hooks | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    layout = layout or Layout()
    if args.command == "install" and args.release_key_type:
        layout = dataclasses.replace(layout, key_types=tuple(args.release_key_type))
    if args.command == "plan":
        return cmd_plan(args.maintainer, print)
    if (args.command == "rollback" or args.apply) and os.geteuid() != layout.uid:
        parser.error("this needs root (a dry run does not)")
    hooks = hooks or make_hooks()
    try:
        if args.command == "install":
            install(
                args.version,
                layout,
                hooks,
                apply=args.apply,
                reinstall=args.reinstall,
                allow_downgrade=args.allow_downgrade,
            )
        else:
            rollback(layout, hooks, to=args.to)
    except InstallError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return 0


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run()
