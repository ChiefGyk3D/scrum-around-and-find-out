# SPDX-License-Identifier: Apache-2.0
"""Read-only checks for the root-door items of `check-install` (issue #293; docs/gemini-broker.md, "The root-door
precondition").

The whole broker design assumes the maintainer's account has no way to become root. Each check here looks for one kind
of door and returns ONE finding: `pass`, `warn` or `fail`, with one plain sentence.

* **Read-only.** Files are opened read-only without following a final symbolic link; directories are listed with
  `scandir`; metadata comes from `lstat`. No program is run (neither the sudo listing command nor the package manager), no privilege is requested, and
  nothing is written. The command is root-only for reasons of its own (it reads root-owned files); these checks need
  nothing a root-owned read does not already give them, and a path that cannot be read is a **fail**, never a pass.
* **Fail closed.** A missing file that must exist, a file with the wrong owner, one that others can write, a symbolic
  link where a file belongs, a path that cannot be read, a malformed line and a scan that hits its entry limit are all
  `fail`. A path that may legitimately be absent (the polkit directories, the preload file) passes when it is absent.
* **A clean report is "no door found by these checks", never "no door".** Access control lists, attributes other than
  file capabilities, a privileged socket the account can reach, a flaw in a package-owned program and anything that
  changes after the run are not seen.

What each check does and does not see is written next to it. The default paths are the Debian family's; every path is a
field of `DoorPaths` so a test can point the checks at a temporary tree.
"""

from __future__ import annotations

import dataclasses
import errno
import os
import re
import stat
from collections.abc import Iterator, Sequence
from pathlib import Path

from safo import output

MAX_FILE = 4_000_000  # bytes read from any one file; a bigger file is a fail
BAD_GROUPS = ("root", "sudo", "wheel", "admin", "docker", "lxd", "lxc", "libvirt", "disk", "shadow")
UNIT_KEYS = ("ExecStart", "ExecCondition", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload")
HOME_KEYS = ("EnvironmentFile", "WorkingDirectory")
CRON_VAR = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*=")
EXAMPLES = 3


@dataclasses.dataclass(frozen=True)
class Finding:
    """One check's answer: pass, warn or fail, and one plain sentence."""

    name: str
    status: str
    text: str

    def line(self) -> str:
        return f"{self.status}: {self.name}: {self.text}"


@dataclasses.dataclass(frozen=True)
class DoorPaths:
    """Where everything is. Fixed in code; tests inject their own."""

    passwd: Path = Path("/etc/passwd")
    group: Path = Path("/etc/group")
    sudoers: Path = Path("/etc/sudoers")
    sudoers_d: Path = Path("/etc/sudoers.d")
    polkit_dirs: tuple[Path, ...] = (
        Path("/etc/polkit-1/rules.d"),
        Path("/usr/share/polkit-1/rules.d"),
        Path("/etc/polkit-1/localauthority"),
        Path("/var/lib/polkit-1/localauthority"),
    )
    # root-run places the account must not be able to write (the broker's own folders are added by the caller)
    writable_roots: tuple[Path, ...] = (
        Path("/etc"),
        Path("/usr/local"),
        Path("/opt"),
        Path("/usr/lib/systemd/system"),
        Path("/usr/share/polkit-1"),
        Path("/var/spool/cron"),
        Path("/var/spool/at"),
    )
    unit_dirs: tuple[Path, ...] = (Path("/etc/systemd/system"), Path("/usr/lib/systemd/system"))
    cron_files: tuple[Path, ...] = (Path("/etc/crontab"),)
    cron_dirs: tuple[Path, ...] = (Path("/etc/cron.d"),)
    ld_preload: Path = Path("/etc/ld.so.preload")
    setuid_roots: tuple[Path, ...] = (
        Path("/usr"),
        Path("/opt"),
        Path("/bin"),
        Path("/sbin"),
        Path("/lib"),
        Path("/lib32"),
        Path("/lib64"),
        Path("/libx32"),
    )
    dpkg_info: Path = Path("/var/lib/dpkg/info")
    # (old, new) prefixes: a merged-/usr system lists some files under /bin that the scan finds under /usr/bin
    merged_dirs: tuple[tuple[str, str], ...] = (
        ("/bin", "/usr/bin"),
        ("/sbin", "/usr/sbin"),
        ("/lib", "/usr/lib"),
        ("/lib32", "/usr/lib32"),
        ("/lib64", "/usr/lib64"),
        ("/libx32", "/usr/libx32"),
    )
    # relative to the account's home. Inferred from how the secret store's command-line tool is documented to keep its
    # local settings; not read from a vendor page by this agent (docs/gemini-broker.md says so too).
    credential_paths: tuple[str, ...] = (".doppler", ".config/doppler")
    max_entries: int = 3_000_000  # per scan; past it the scan fails closed


class _Problem(Exception):
    """A path that cannot be trusted or read. The message is a fixed sentence fragment."""


def _show(path: object) -> str:
    return output.inner(str(path))


def _sentence(head: str, items: Sequence[str], tail: str = "") -> str:
    shown = ", ".join(items[:EXAMPLES])
    more = f" and {len(items) - EXAMPLES} more" if len(items) > EXAMPLES else ""
    return f"{head} {shown}{more}{tail}"


# -- reading --------------------------------------------------------------------------------------------------------


def _lstat(path: Path | str, what: str) -> os.stat_result:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        raise _Problem(f"{what} cannot be read (it is missing)") from None
    except OSError:
        raise _Problem(f"{what} cannot be read (it cannot be examined)") from None


def _read(path: Path, what: str, trust: int | None) -> bytes:
    """The file's bytes. With `trust` set the file must be owned by that uid and closed to group and others."""
    info = _lstat(path, what)
    if stat.S_ISLNK(info.st_mode):
        raise _Problem(f"{what} cannot be read (it is a symbolic link)")
    if not stat.S_ISREG(info.st_mode):
        raise _Problem(f"{what} cannot be read (it is not a regular file)")
    if trust is not None and info.st_uid != trust:
        raise _Problem(f"{what} cannot be read (it is not owned by root)")
    if trust is not None and info.st_mode & 0o022:
        raise _Problem(f"{what} cannot be read (it is writable by its group or by others)")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise _Problem(f"{what} cannot be read (it cannot be opened)") from None
    try:
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino) != (info.st_dev, info.st_ino) or not stat.S_ISREG(after.st_mode):
            raise _Problem(f"{what} cannot be read (it changed while it was opened)")
        data = os.read(fd, MAX_FILE + 1)
    except OSError:
        raise _Problem(f"{what} cannot be read (the read failed)") from None
    finally:
        os.close(fd)
    if len(data) > MAX_FILE:
        raise _Problem(f"{what} cannot be read (it is larger than {MAX_FILE} bytes)")
    return data


def _text(path: Path, what: str, trust: int | None) -> str:
    return _read(path, what, trust).decode("utf-8", "replace")


def _folder_state(path: Path, what: str) -> bool:
    """True when the folder exists and is a real directory; False when it is absent. A link or a file is a problem."""
    try:
        info = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        raise _Problem(f"{what} cannot be read (it cannot be examined)") from None
    if stat.S_ISLNK(info.st_mode):
        raise _Problem(f"{what} cannot be read (it is a symbolic link)")
    if not stat.S_ISDIR(info.st_mode):
        raise _Problem(f"{what} cannot be read (it is not a directory)")
    return True


class _Scan:
    """A bounded, read-only walk that never follows a symbolic link and records what it could not read."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.count = 0
        self.problems: list[str] = []
        self.limited = False

    def walk(self, root: Path) -> Iterator[tuple[str, os.stat_result]]:
        stack = [str(root)]
        while stack:
            folder = stack.pop()
            try:
                with os.scandir(folder) as handle:
                    entries = list(handle)
            except OSError:
                self.problems.append(f"{_show(folder)} cannot be read")
                continue
            for entry in entries:
                self.count += 1
                if self.count > self.limit:
                    self.limited = True
                    return
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    self.problems.append(f"{_show(entry.path)} cannot be examined")
                    continue
                yield entry.path, info
                if stat.S_ISDIR(info.st_mode):
                    stack.append(entry.path)

    def failure(self, what: str) -> str | None:
        if self.limited:
            return f"{what} stopped at the limit of {self.limit} entries, so it was not completed"
        if self.problems:
            return _sentence(f"{what} could not read", self.problems)
        return None


# -- who the maintainer is ------------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _Who:
    login: str
    uid: int
    gid: int
    home: str
    group_names: frozenset[str]
    gids: frozenset[int]

    def can_write(self, info: os.stat_result) -> bool:
        mode = info.st_mode
        if info.st_uid == self.uid and mode & 0o200:
            return True
        if info.st_gid in self.gids and mode & 0o020:
            return True
        return bool(mode & 0o002)


def _load_who(door: DoorPaths, trust: int, uid: int) -> _Who:
    account = None
    for number, raw in enumerate(_text(door.passwd, "the account database", trust).splitlines(), 1):
        if not raw.strip() or raw.startswith("#"):
            continue
        parts = raw.split(":")
        if len(parts) != 7 or not parts[2].isdigit() or not parts[3].isdigit():
            raise _Problem(f"the account database cannot be read (line {number} is malformed)")
        if int(parts[2]) == uid and account is None:
            account = parts
    if account is None:
        raise _Problem(f"the account database cannot be read (user id {uid} is not in it)")
    login, gid, home = account[0], int(account[3]), account[5]
    names = set[str]()
    gids = {gid}
    for number, raw in enumerate(_text(door.group, "the group database", trust).splitlines(), 1):
        if not raw.strip() or raw.startswith("#"):
            continue
        parts = raw.split(":")
        if len(parts) != 4 or not parts[2].isdigit():
            raise _Problem(f"the group database cannot be read (line {number} is malformed)")
        members = [m for m in parts[3].split(",") if m]
        if int(parts[2]) == gid or login in members:
            names.add(parts[0])
            gids.add(int(parts[2]))
    return _Who(login, uid, gid, home, frozenset(names), frozenset(gids))


# -- the checks -----------------------------------------------------------------------------------------------------


def _check_groups(who: _Who) -> Finding:
    if who.uid == 0 or who.gid == 0:
        return Finding("groups", "fail", f"the account {_show(who.login)} is root itself or has root as its primary group")
    bad = sorted(name for name in who.group_names if name in BAD_GROUPS)
    if bad:
        return Finding("groups", "fail", f"the account is in root-equivalent groups: {', '.join(bad)}")
    return Finding("groups", "pass", "the account is in none of the root-equivalent groups on the list")


_INCLUDE = re.compile(r"[#@]include(dir)?\s+(\S+)")
_SKIP_SUDO = ("Defaults", "Host_Alias", "Cmnd_Alias", "Cmd_Alias", "Runas_Alias")


def _logical_lines(text: str) -> list[str]:
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        if raw.endswith("\\"):
            pending += raw[:-1] + " "
            continue
        lines.append((pending + raw).strip())
        pending = ""
    if pending.strip():
        lines.append(pending.strip())
    return lines


def _members(text: str) -> list[str]:
    return [m for m in re.split(r"[,\s]+", text) if m and not m.startswith("!")]


def _check_sudo(door: DoorPaths, trust: int, who: _Who) -> Finding:
    sources: list[tuple[str, list[str]]] = []
    problems: list[str] = []
    try:
        sources.append(("the sudoers file", _logical_lines(_text(door.sudoers, "the sudoers file", trust))))
        if _folder_state(door.sudoers_d, "the sudoers directory"):
            info = os.lstat(door.sudoers_d)
            if info.st_uid != trust or info.st_mode & 0o022:
                raise _Problem("the sudoers directory cannot be read (it is not owned by root or others can write it)")
            for name in sorted(os.listdir(door.sudoers_d)):
                if "." in name or name.endswith("~"):  # sudo does not read these
                    continue
                sources.append((name, _logical_lines(_text(door.sudoers_d / name, f"sudoers file {_show(name)}", trust))))
    except _Problem as problem:
        return Finding("sudo", "fail", str(problem))
    except OSError:
        return Finding("sudo", "fail", "the sudoers directory cannot be read (it cannot be listed)")
    rules: list[tuple[str, str]] = []
    aliases: dict[str, list[str]] = {}
    for source, lines in sources:
        for line in lines:
            include = _INCLUDE.match(line)
            if include:
                if include.group(1) and Path(include.group(2)) == door.sudoers_d:
                    continue
                problems.append(f"{source} includes {_show(include.group(2))}, which this check does not read")
                continue
            if not line or line.startswith("#"):
                continue
            first = line.split(None, 1)[0]
            if first.startswith(_SKIP_SUDO):
                continue
            if first == "User_Alias":
                for part in line[len("User_Alias") :].split(":"):
                    name, _, members = part.partition("=")
                    aliases.setdefault(name.strip(), []).extend(_members(members))
                continue
            head = line.partition("=")[0].split()
            if len(head) >= 2:
                rules.append((source, " ".join(head[:-1])))
    matched: set[str] = set()

    def applies(member: str) -> bool:
        if member in ("ALL", who.login, f"#{who.uid}") or member in matched:
            return True
        if member.startswith("%#"):
            return member[2:].isdigit() and int(member[2:]) in who.gids
        return member.startswith("%") and member[1:] in who.group_names

    changed = True
    while changed:
        changed = False
        for name, members in aliases.items():
            if name not in matched and any(applies(m) for m in members):
                matched.add(name)
                changed = True
    hits = sorted({source for source, users in rules if any(applies(m) for m in _members(users))})
    if problems:
        return Finding("sudo", "fail", problems[0])
    if hits:
        return Finding("sudo", "fail", _sentence("a sudoers rule applies to the account or one of its groups, in", hits))
    return Finding("sudo", "pass", "no sudoers rule names the account, one of its groups or ALL")


_YES = re.compile(r"polkit\.Result\.YES|Result(?:Any|Inactive|Active)\s*=\s*yes", re.IGNORECASE)


def _check_polkit(door: DoorPaths, who: _Who) -> Finding:
    scan = _Scan(door.max_entries)
    hits: list[str] = []
    others: list[str] = []
    try:
        for folder in door.polkit_dirs:
            if not _folder_state(folder, f"polkit folder {_show(folder)}"):
                continue
            for path, info in scan.walk(folder):
                if not path.endswith((".rules", ".pkla")):
                    continue
                if stat.S_ISLNK(info.st_mode):
                    raise _Problem(f"polkit file {_show(path)} cannot be read (it is a symbolic link)")
                if not stat.S_ISREG(info.st_mode):
                    continue
                text = _text(Path(path), f"polkit file {_show(path)}", None)
                if not _YES.search(text):
                    continue
                names = [who.login, *sorted(who.group_names)]
                quoted = any(re.search(r"[\"']" + re.escape(n) + r"[\"']", text) for n in names)
                pkla = any(
                    re.search(r"unix-(?:user|group):" + re.escape(n) + r"(?![\w.-])", text) for n in names
                ) or re.search(r"unix-(?:user|group):\*", text)
                (hits if quoted or pkla else others).append(_show(path))
    except _Problem as problem:
        return Finding("polkit", "fail", str(problem))
    failure = scan.failure("the polkit scan")
    if failure:
        return Finding("polkit", "fail", failure)
    if hits:
        return Finding("polkit", "fail", _sentence("polkit grants the account or one of its groups an action without a password in", hits))
    if others:
        return Finding("polkit", "warn", _sentence("polkit grants an action without a password in", others, "; check that it is not for the account"))
    return Finding("polkit", "pass", "no polkit rule grants the account or its groups an action without a password")


def _check_writable(door: DoorPaths, who: _Who, extra: Sequence[Path]) -> Finding:
    scan = _Scan(door.max_entries)
    hits: list[str] = []
    try:
        for root in (*door.writable_roots, *extra):
            if not _folder_state(root, f"root-run folder {_show(root)}"):
                continue
            if who.can_write(os.lstat(root)):
                hits.append(_show(root))
            for path, info in scan.walk(root):
                if not stat.S_ISLNK(info.st_mode) and who.can_write(info):
                    hits.append(_show(path))
    except _Problem as problem:
        return Finding("writable", "fail", str(problem))
    failure = scan.failure("the scan of root-run folders")
    if failure:
        return Finding("writable", "fail", failure)
    if hits:
        return Finding("writable", "fail", _sentence(f"the account can write {len(hits)} paths under root-run folders, for example", hits))
    return Finding("writable", "pass", "the account can write nothing under the root-run folders that were scanned")


def _chain_writable(path: str, who: _Who, cache: dict[str, os.stat_result | None]) -> str | None:
    """The first component of `path` (a path, or a folder above it) that the account can write; None when none."""
    for candidate in (path, os.path.realpath(path)):
        parts = Path(candidate).parts
        for index in range(1, len(parts) + 1):
            prefix = str(Path(*parts[:index]))
            if prefix not in cache:
                try:
                    cache[prefix] = os.lstat(prefix)
                except FileNotFoundError:
                    cache[prefix] = None
            info = cache[prefix]
            if info is None:
                break
            if stat.S_ISLNK(info.st_mode):
                continue
            sticky_foreign = stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX and info.st_uid != who.uid
            if who.can_write(info) and not sticky_foreign:  # a sticky folder lets the account add, not replace
                return prefix
    return None


def _under(path: str, home: str) -> bool:
    return bool(home) and (path == home or path.startswith(home.rstrip("/") + "/"))


def _unit_hits(text: str, who: _Who, cache: dict[str, os.stat_result | None]) -> str | None:
    user = ""
    entries: list[tuple[str, str]] = []
    for line in _logical_lines(text):
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key == "User":
            user = value
        elif key in UNIT_KEYS or key in HOME_KEYS:
            entries.append((key, value))
    if user not in ("", "root", "0"):
        return None
    for key, value in entries:
        first = value.lstrip("@-:+!").split(None, 1)[0] if value.lstrip("@-:+!") else ""
        if key in HOME_KEYS:
            first = value.lstrip("-").split(None, 1)[0] if value.lstrip("-") else ""
        if not first.startswith("/"):
            continue
        if _under(first, who.home):
            return f"reads or runs {_show(first)} from the account's home"
        writable = _chain_writable(first, who, cache)
        if writable is not None:
            return f"runs {_show(first)}, which the account can replace through {_show(writable)}"
    return None


def _cron_hit(text: str, who: _Who, cache: dict[str, os.stat_result | None]) -> str | None:
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or CRON_VAR.match(line):
            continue
        fields = line.split(None, 2 if line.startswith("@") else 6)
        index = 1 if line.startswith("@") else 5
        if len(fields) <= index + 1 or fields[index] != "root":
            continue
        command = fields[index + 1].split(None, 1)[0]
        if _under(command, who.home):
            return f"runs {_show(command)} from the account's home as root"
        if command.startswith("/"):
            writable = _chain_writable(command, who, cache)
            if writable is not None:
                return f"runs {_show(command)} as root, which the account can replace through {_show(writable)}"
    return None


def _check_jobs(door: DoorPaths, who: _Who) -> Finding:
    cache: dict[str, os.stat_result | None] = {}
    hits: list[str] = []
    try:
        for folder in door.unit_dirs:
            if not _folder_state(folder, f"unit folder {_show(folder)}"):
                continue
            for name in sorted(os.listdir(folder)):
                path = folder / name
                if not name.endswith(".service") or stat.S_ISLNK(_lstat(path, f"unit {_show(name)}").st_mode):
                    continue
                found = _unit_hits(_text(path, f"unit {_show(name)}", None), who, cache)
                if found:
                    hits.append(f"unit {_show(name)} {found}")
        files = list(door.cron_files)
        for folder in door.cron_dirs:
            if _folder_state(folder, f"cron folder {_show(folder)}"):
                files.extend(folder / n for n in sorted(os.listdir(folder)))
        for path in files:
            try:
                info = os.lstat(path)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                continue
            found = _cron_hit(_text(path, f"cron file {_show(path.name)}", None), who, cache)
            if found:
                hits.append(f"cron file {_show(path.name)} {found}")
    except _Problem as problem:
        return Finding("jobs", "fail", str(problem))
    except OSError:
        return Finding("jobs", "fail", "a unit or cron folder cannot be read (it cannot be listed)")
    if hits:
        return Finding("jobs", "fail", _sentence("a root-run job is open to the account:", hits))
    return Finding(
        "jobs",
        "pass",
        "no root-run unit or cron job runs a file the account can replace or reads from its home (first word of each command only)",
    )


def _check_preload(door: DoorPaths, trust: int) -> Finding:
    try:
        text = _text(door.ld_preload, "the preload file", trust)
    except _Problem as problem:
        if "(it is missing)" in str(problem):
            return Finding("preload", "pass", "there is no dynamic linker preload file")
        return Finding("preload", "fail", str(problem))
    if any(x.strip() and not x.lstrip().startswith("#") for x in text.splitlines()):
        return Finding("preload", "warn", "the preload file lists libraries that load into every program; check each is yours")
    return Finding("preload", "pass", "the preload file is root-owned, closed to others and empty")


def _has_capability(path: str) -> bool:
    """True when the file carries file capabilities. Read-only (`getxattr`); an unreadable answer is an OSError."""
    try:
        os.getxattr(path, "security.capability", follow_symlinks=False)
    except OSError as err:
        if err.errno in (errno.ENODATA, errno.ENOTSUP):
            return False
        raise
    return True


def _packages(door: DoorPaths) -> set[str]:
    owned: set[str] = set()
    if not _folder_state(door.dpkg_info, "the package database"):
        raise _Problem("the package database cannot be read (it is missing)")
    for name in sorted(os.listdir(door.dpkg_info)):
        if not name.endswith(".list"):
            continue
        for line in _text(door.dpkg_info / name, "a package file list", None).splitlines():
            owned.add(_merge(door, line.strip()))
    if not owned:
        raise _Problem("the package database cannot be read (it lists no files)")
    return owned


def _merge(door: DoorPaths, path: str) -> str:
    for old, new in door.merged_dirs:
        if path == old or path.startswith(old + "/"):
            return new + path[len(old) :]
    return path


def _check_suid(door: DoorPaths, who: _Who) -> Finding:
    scan = _Scan(door.max_entries)
    marked: list[tuple[str, os.stat_result]] = []
    capped: list[tuple[str, os.stat_result]] = []
    try:
        roots = [r for r in door.setuid_roots]
        real = {r: os.path.realpath(r) for r in roots}
        for root in roots:
            try:
                info = os.lstat(root)
            except (FileNotFoundError, NotADirectoryError):
                continue
            except OSError:
                raise _Problem(f"scan folder {_show(root)} cannot be read (it cannot be examined)") from None
            if stat.S_ISLNK(info.st_mode):
                inside = any(
                    other != root and not os.path.islink(other) and (real[root] + "/").startswith(real[other] + "/")
                    for other in roots
                )
                if not inside:
                    raise _Problem(f"scan folder {_show(root)} is a symbolic link that leads outside the other scan folders")
                continue
            if not stat.S_ISDIR(info.st_mode):
                raise _Problem(f"scan folder {_show(root)} is not a directory")
            for path, entry in scan.walk(root):
                if not stat.S_ISREG(entry.st_mode):
                    continue
                if entry.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    marked.append((path, entry))
                elif entry.st_mode & 0o111:
                    try:
                        if _has_capability(path):
                            capped.append((path, entry))
                    except OSError:
                        scan.problems.append(f"the capabilities of {_show(path)} cannot be read")
    except _Problem as problem:
        return Finding("setuid", "fail", str(problem))
    failure = scan.failure("the setuid scan")
    if failure:
        return Finding("setuid", "fail", failure)
    owned: set[str] = set()
    if marked or capped:
        try:
            owned = _packages(door)
        except _Problem as problem:
            return Finding("setuid", "fail", f"setuid, setgid or capability files exist and {problem}")
    bad = [_show(p) for p, i in marked + capped if who.can_write(i)]
    if bad:
        return Finding("setuid", "fail", _sentence("the account can write setuid, setgid or capability files:", bad))
    unowned = [_show(p) for p, _ in marked if _merge(door, p) not in owned]
    if unowned:
        return Finding("setuid", "fail", _sentence("setuid or setgid files that no package owns:", unowned))
    loose = [_show(p) for p, _ in capped if _merge(door, p) not in owned]
    if loose:
        return Finding("setuid", "warn", _sentence("files with capabilities that no package owns:", loose))
    return Finding("setuid", "pass", f"{len(marked)} setuid or setgid files were found, all owned by a package and closed to the account")


def _check_credential(door: DoorPaths, who: _Who) -> Finding:
    if not who.home.startswith("/") or who.home == "/":
        return Finding("credential", "fail", "the account database records no usable home folder, so the old credential was not looked for")
    found: list[str] = []
    for rel in door.credential_paths:
        path = Path(who.home) / rel
        try:
            os.lstat(path)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            return Finding("credential", "fail", f"{_show(path)} cannot be examined, so the old credential was not looked for")
        found.append(_show(path))
    if found:
        return Finding(
            "credential",
            "warn",
            _sentence("an old secret-store credential or setting is still on disk at", found, "; revoke it at the vendor, then delete it"),
        )
    return Finding("credential", "pass", "no old secret-store credential was found in the account's home")


_NEEDS_WHO = ("sudo", "groups", "polkit", "writable", "jobs", "setuid", "credential")


def check_doors(
    door: DoorPaths,
    trust_uid: int,
    maintainer_uid: int | None,
    extra_roots: Sequence[Path] = (),
) -> list[Finding]:
    """One finding per check, in a fixed order. Never raises for a path problem: that is a fail."""
    who: _Who | None = None
    unknown = ""
    if maintainer_uid is None:
        unknown = "the maintainer account is unknown (run through sudo so SUDO_UID is set), so this was not judged"
        state = "warn"
    else:
        state = "fail"
        try:
            who = _load_who(door, trust_uid, maintainer_uid)
        except _Problem as problem:
            unknown = str(problem)
    results: list[Finding] = []
    for name in _NEEDS_WHO:
        if who is None:
            results.append(Finding(name, state, unknown))
        elif name == "sudo":
            results.append(_check_sudo(door, trust_uid, who))
        elif name == "groups":
            results.append(_check_groups(who))
        elif name == "polkit":
            results.append(_check_polkit(door, who))
        elif name == "writable":
            results.append(_check_writable(door, who, extra_roots))
        elif name == "jobs":
            results.append(_check_jobs(door, who))
        elif name == "setuid":
            results.append(_check_suid(door, who))
        else:
            results.append(_check_credential(door, who))
    results.append(_check_preload(door, trust_uid))
    return results
