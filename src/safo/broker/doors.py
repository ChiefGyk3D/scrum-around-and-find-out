# SPDX-License-Identifier: Apache-2.0
"""Read-only checks for the root-door items of `check-install` (issue #293; docs/gemini-broker.md, "The root-door
precondition").

The whole broker design assumes the maintainer's account has no way to become root. Each check here looks for one kind
of door and returns ONE finding: `pass`, `warn` or `fail`, with one plain sentence.

* **Read-only.** Files are opened read-only without following a final symbolic link; directories are listed through a
  descriptor opened without moving the access time where the kernel allows it (otherwise listing may update it);
  metadata comes from `lstat`. No program is run (neither the sudo listing command nor the package
  manager), no privilege is requested, and
  nothing is modified, except that where the kernel refuses to leave access times alone, reading or listing can update
  them. The command is root-only for reasons of its own (it reads root-owned files); these checks need
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
import shlex
import stat
from collections.abc import Iterator, Sequence
from pathlib import Path

from safo import output

MAX_FILE = 4_000_000  # bytes read from any one file; a bigger file is a fail
BAD_GROUPS = ("root", "sudo", "wheel", "admin", "docker", "lxd", "lxc", "libvirt", "disk", "shadow")
STDIN_KEYS = ("StandardInput", "StandardInputText", "StandardInputData")
UNIT_KEYS = (
    "ExecStart",
    "ExecCondition",
    "ExecStartPre",
    "ExecStartPost",
    "ExecStop",
    "ExecStopPre",
    "ExecStopPost",
    "ExecReload",
    "ExecStartChown",
)
HANDLED_UNITS = {"service": "Service", "socket": "Socket"}  # unit type -> the section that holds its commands
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
        label = "nothing found" if self.status == "pass" else self.status  # a clean result is not proof
        return f"{label}: {self.name}: {self.text}"


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
        Path("/var/lib/polkit-1"),
        Path("/run/systemd/system"),
        Path("/run/systemd/transient"),
        Path("/run/systemd/generator"),
        Path("/run/systemd/generator.early"),
        Path("/run/systemd/generator.late"),
        Path("/run/systemd/system.control"),
        Path("/run/systemd/system.attached"),
        Path("/etc/systemd/system.control"),
        Path("/etc/systemd/system.attached"),
        Path("/usr/lib/systemd/system-generators"),
        Path("/usr/local/lib/systemd/system-generators"),
        Path("/run/systemd/system-generators"),
        Path("/usr/lib/systemd/system-environment-generators"),
    )
    # in systemd's search order, highest priority first
    unit_dirs: tuple[Path, ...] = (
        Path("/etc/systemd/system.control"),
        Path("/run/systemd/system.control"),
        Path("/run/systemd/transient"),
        Path("/run/systemd/generator.early"),
        Path("/etc/systemd/system"),
        Path("/etc/systemd/system.attached"),
        Path("/run/systemd/system"),
        Path("/run/systemd/system.attached"),
        Path("/run/systemd/generator"),
        Path("/usr/local/lib/systemd/system"),
        Path("/usr/lib/systemd/system"),
        Path("/run/systemd/generator.late"),
    )
    cron_files: tuple[Path, ...] = (Path("/etc/crontab"),)
    cron_dirs: tuple[Path, ...] = (Path("/etc/cron.d"),)
    ld_preload: Path = Path("/etc/ld.so.preload")
    polkit_action_dirs: tuple[Path, ...] = (Path("/usr/share/polkit-1/actions"), Path("/etc/polkit-1/actions"))
    nsswitch: Path = Path("/etc/nsswitch.conf")
    # systemd's user and group record folders (JSON user records, homed users): any record there is an account or group
    # this check does not read, so a record fails closed; a folder that is absent is fine
    userdb_dirs: tuple[Path, ...] = (Path("/etc/userdb"), Path("/run/userdb"), Path("/run/systemd/userdb"))
    # path components at or below this folder are judged for "can the account replace this"; "/" judges them all
    # (a test points it at its temporary tree, whose parents are not the machine's)
    chain_floor: Path = Path("/")
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
    # the root-owned system trees: nothing in them may be writable by the account, whatever consumes it
    system_trees: tuple[Path, ...] = (
        Path("/usr"),
        Path("/etc"),
        Path("/opt"),
        Path("/lib"),
        Path("/lib32"),
        Path("/lib64"),
        Path("/libx32"),
        Path("/boot"),
        Path("/sbin"),
        Path("/bin"),
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
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        try:  # reading must not even move the access time; the kernel allows this to the owner and to root
            fd = os.open(path, flags | getattr(os, "O_NOATIME", 0))
        except PermissionError:
            fd = os.open(path, flags)
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


def _listdir(path: Path | str) -> list[str]:
    """Names in a folder, listed through a descriptor opened with O_NOATIME where the kernel allows it (the owner and
    root), so listing does not move the folder's access time; otherwise a plain listing, which may."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    try:
        fd = os.open(path, flags | getattr(os, "O_NOATIME", 0))
    except PermissionError:
        fd = os.open(path, flags)
    try:
        return os.listdir(fd)
    finally:
        os.close(fd)


class _Scan:
    """A bounded, read-only walk that never follows a symbolic link and records what it could not read."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.count = 0
        self.problems: list[str] = []
        self.boundaries: list[str] = []
        self.limited = False

    def walk(self, root: Path) -> Iterator[tuple[str, os.stat_result]]:
        try:
            root_device = os.lstat(root).st_dev
        except OSError:
            self.problems.append(f"{_show(root)} cannot be examined")
            return
        stack = [(str(root), root_device)]
        while stack:
            folder, device = stack.pop()
            try:
                names = _listdir(folder)
            except OSError:
                self.problems.append(f"{_show(folder)} cannot be read")
                continue
            for name in names:
                self.count += 1
                if self.count > self.limit:
                    self.limited = True
                    return
                entry_path = os.path.join(folder, name)
                try:
                    info = os.lstat(entry_path)
                except OSError:
                    self.problems.append(f"{_show(entry_path)} cannot be examined")
                    continue
                yield entry_path, info
                if stat.S_ISDIR(info.st_mode):
                    if info.st_dev != device:  # another filesystem (an automount point is one): never listed
                        self.boundaries.append(_show(entry_path))
                    else:
                        stack.append((entry_path, device))

    def failure(self, what: str) -> str | None:
        if self.limited:
            return f"{what} stopped at the limit of {self.limit} entries, so it was not completed"
        if self.problems:
            return _sentence(f"{what} could not read", self.problems)
        if self.boundaries:
            return _sentence(f"{what} reached a mount point it does not enter, at", self.boundaries, f"; {HUMAN}")
        return None


# -- who the maintainer is ------------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _Who:
    login: str  # the first login for the uid, for messages
    uid: int
    gid: int
    home: str  # the first home
    group_names: frozenset[str]
    gids: frozenset[int]
    logins: frozenset[str] = frozenset()  # every login that maps to the uid
    homes: tuple[str, ...] = ()
    root_names: frozenset[str] = frozenset()  # every name the account database maps to uid 0
    known_names: frozenset[str] = frozenset()  # every name in the account database

    def classify(self, user: str) -> str:
        """root, other or unknown for a user as written in a unit or crontab: a name is looked up in the account
        database (every name that maps to uid 0 is root), a number is a uid, anything else cannot be placed."""
        user = user.strip()
        if re.fullmatch(r"\+?[0-9]+", user):
            return "root" if int(user) == 0 else "other"
        if user in self.root_names or user == "root":
            return "root"
        return "other" if user in self.known_names else "unknown"

    def can_write(self, info: os.stat_result) -> bool:
        mode = info.st_mode
        if info.st_uid == self.uid:  # the owner can change the mode, so the mode bits do not matter
            return True
        if info.st_gid in self.gids and mode & 0o020:
            return True
        return bool(mode & 0o002)


_PLAIN_SOURCES = ("files", "compat")  # "systemd" is not plain: its records are read through the userdb folders
_IDENTITY_DATABASES = ("passwd", "group", "shadow", "gshadow", "initgroups")


def _check_nsswitch(door: DoorPaths, trust: int) -> None:
    """Fail closed when accounts or groups can come from a source this check does not read (ldap, sss, nis...)."""
    seen = set[str]()
    for raw in _text(door.nsswitch, "the name service switch file", trust).splitlines():
        line = raw.split("#", 1)[0].strip()
        database, _, rest = line.partition(":")
        if database.strip() not in _IDENTITY_DATABASES:
            continue
        seen.add(database.strip())
        sources = [t for t in re.sub(r"\[[^\]]*\]", " ", rest).split() if t]
        odd = [t for t in sources if t not in _PLAIN_SOURCES]
        if odd or not sources:
            raise _Problem(
                f"the {database.strip()} database can come from a source other than local files "
                f"({_show(' '.join(odd) or 'none named')}), which this check does not read"
            )
    if not {"passwd", "group"} <= seen:
        raise _Problem("the name service switch file cannot be read (it does not name the passwd and group databases)")
    for folder in door.userdb_dirs:
        if _folder_state(folder, f"user record folder {_show(folder)}"):
            try:
                names = _listdir(folder)
            except OSError:
                raise _Problem(f"user record folder {_show(folder)} cannot be read (it cannot be listed)") from None
            if names:
                raise _Problem(
                    f"user record folder {_show(folder)} holds records for users or groups, "
                    "which this check does not read"
                )


def _load_who(door: DoorPaths, trust: int, uid: int) -> _Who:
    _check_nsswitch(door, trust)
    accounts: list[list[str]] = []
    every: list[list[str]] = []
    for number, raw in enumerate(_text(door.passwd, "the account database", trust).splitlines(), 1):
        if not raw.strip() or raw.startswith("#"):
            continue
        parts = raw.split(":")
        if len(parts) != 7 or not parts[2].isdigit() or not parts[3].isdigit():
            raise _Problem(f"the account database cannot be read (line {number} is malformed)")
        every.append(parts)
        if int(parts[2]) == uid:
            accounts.append(parts)
    if not accounts:
        raise _Problem(f"the account database cannot be read (user id {uid} is not in it)")
    login, gid, home = accounts[0][0], int(accounts[0][3]), accounts[0][5]
    logins = frozenset(a[0] for a in accounts)
    homes = tuple(dict.fromkeys(a[5] for a in accounts))
    primary = {int(a[3]) for a in accounts}
    names = set[str]()
    gids = set(primary)
    for number, raw in enumerate(_text(door.group, "the group database", trust).splitlines(), 1):
        if not raw.strip() or raw.startswith("#"):
            continue
        parts = raw.split(":")
        if len(parts) != 4 or not parts[2].isdigit():
            raise _Problem(f"the group database cannot be read (line {number} is malformed)")
        members = [m for m in parts[3].split(",") if m]
        if int(parts[2]) in primary or logins & set(members):
            names.add(parts[0])
            gids.add(int(parts[2]))
    root_names = frozenset(a[0] for a in every if int(a[2]) == 0)
    known = frozenset(a[0] for a in every)
    return _Who(login, uid, gid, home, frozenset(names), frozenset(gids), logins, homes, root_names, known)


# -- the checks -----------------------------------------------------------------------------------------------------


def _check_groups(who: _Who) -> Finding:
    if who.uid == 0 or who.gid == 0:
        return Finding(
            "groups", "fail", f"the account {_show(who.login)} is root itself or has root as its primary group"
        )
    bad = sorted(name for name in who.group_names if name in BAD_GROUPS)
    if bad:
        return Finding("groups", "fail", f"the account is in root-equivalent groups: {', '.join(bad)}")
    return Finding("groups", "pass", "the account is in none of the root-equivalent groups on the list")


_INCLUDE = re.compile(r"[#@]include(dir)?\s+(\S+)")
_NUMERIC_RULE = re.compile(r"#[0-9]+[\s,]")  # "#1000 ALL=..." is a rule for a user id, not a comment
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


def _check_sudoers_source(door: DoorPaths, trust: int) -> None:
    """Fail closed when the sudoers rules can come from a source other than local files (sss, ldap...)."""
    for raw in _text(door.nsswitch, "the name service switch file", trust).splitlines():
        database, _, rest = raw.split("#", 1)[0].partition(":")
        if database.strip() != "sudoers":
            continue
        sources = [t for t in re.sub(r"\[[^\]]*\]", " ", rest).split() if t]
        if sources != ["files"]:
            raise _Problem(
                "sudo rules can come from a source other than local files "
                f"({_show(' '.join(sources) or 'none named')}), which this check does not read"
            )


def _check_sudo(door: DoorPaths, trust: int, who: _Who) -> Finding:
    sources: list[tuple[str, list[str]]] = []
    problems: list[str] = []
    try:
        _check_sudoers_source(door, trust)
        sources.append(("the sudoers file", _logical_lines(_text(door.sudoers, "the sudoers file", trust))))
        if _folder_state(door.sudoers_d, "the sudoers directory"):
            info = os.lstat(door.sudoers_d)
            if info.st_uid != trust or info.st_mode & 0o022:
                raise _Problem("the sudoers directory cannot be read (it is not owned by root or others can write it)")
            for name in sorted(_listdir(door.sudoers_d)):
                if "." in name or name.endswith("~"):  # sudo does not read these
                    continue
                sources.append(
                    (name, _logical_lines(_text(door.sudoers_d / name, f"sudoers file {_show(name)}", trust)))
                )
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
            if not line or (line.startswith("#") and not _NUMERIC_RULE.match(line)):
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
                users = " ".join(head[:-1])
                if any(m.startswith("+") for m in re.split(r"[,\s]+", users)):
                    problems.append(f"{source} uses a netgroup, which this check does not read")
                rules.append((source, users))
    matched: set[str] = set()

    def applies(member: str) -> bool:
        if member == "ALL" or member in who.logins or member == f"#{who.uid}" or member in matched:
            return True
        if member.startswith("%#"):
            return member[2:].isdigit() and int(member[2:]) in who.gids
        return member.startswith("%") and member[1:] in who.group_names

    changed = True
    while changed:
        changed = False
        for name, listed in aliases.items():
            if name not in matched and any(applies(m) for m in listed):
                matched.add(name)
                changed = True
    hits = sorted({source for source, users in rules if any(applies(m) for m in _members(users))})
    if problems:
        return Finding("sudo", "fail", problems[0])
    if hits:
        return Finding(
            "sudo", "fail", _sentence("a sudoers rule applies to the account or one of its groups, in", hits)
        )
    return Finding("sudo", "pass", "no sudoers rule names the account, one of its groups or ALL")


_ALLOW = re.compile(r"<allow_(any|inactive|active)\s*>(.*?)</allow_\1\s*>", re.DOTALL)
_AUTH_VALUES = frozenset({"no", "auth_self", "auth_admin", "auth_self_keep", "auth_admin_keep"})


def _policy_verdict(text: str) -> str:
    """grant (a default that needs no authentication), human (a default or markup this check cannot read) or none."""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    if "<![CDATA[" in text or "<!ENTITY" in text:
        return "human"
    found = _ALLOW.findall(text)
    if text.count("<allow_") != len(found):
        return "human"
    values = [value.strip().lower() for _, value in found]
    if "yes" in values:
        return "grant"
    return "human" if any(v not in _AUTH_VALUES for v in values) else "none"


_PKLA_YES = re.compile(r"Result(?:Any|Inactive|Active)\s*=\s*yes", re.IGNORECASE)
# The ONLY shape of rules file this check can judge. The whole file must be one or more
#     polkit.addRule(function(action, subject) { if (TERM && TERM ...) { return RESULT; } ... });
# where a TERM is `subject.user == "x"`, `subject.isInGroup("x")` or `action.id == "x"` (literals are word characters,
# dots and dashes), the body of each `if` is one return of a known result and nothing else. Every other nonempty rules
# file (comments, else, ternaries, `||`, `!`, other comparisons, other ways to write a result, extra statements,
# any other shape) cannot be judged, and is a door a human has to look at.
_Q = r"""(?:"[\w.-]+"|'[\w.-]+')"""
_TERM = rf"(?:subject\.user[ \t]*===?[ \t]*{_Q}|subject\.isInGroup\([ \t]*{_Q}[ \t]*\)|action\.id[ \t]*===?[ \t]*{_Q})"
_RET = r"""return[ \t]+(?:polkit\.Result\.([A-Z_]+)|"([a-z_]+)"|'([a-z_]+)')[ \t]*;"""
_STMT = rf"if[ \t]*\([ \t]*{_TERM}(?:[ \t]*&&[ \t]*{_TERM})*[ \t]*\)\s*(?:\{{\s*{_RET}\s*\}}|{_RET})"
_RULE = rf"polkit\.addRule\(\s*function\s*\(\s*action\s*,\s*subject\s*\)\s*\{{\s*(?:{_STMT}\s*)+\}}\s*\)\s*;"
_RULES_FILE = re.compile(rf"\s*(?:{_RULE}\s*)+")
_STATEMENT = re.compile(_STMT)
_SUBJECT_TERM = re.compile(rf"subject\.user[ \t]*===?[ \t]*({_Q})|subject\.isInGroup\([ \t]*({_Q})[ \t]*\)")
_RESULTS = frozenset(
    {"YES", "NO", "AUTH_SELF", "AUTH_ADMIN", "AUTH_SELF_KEEP", "AUTH_ADMIN_KEEP", "NOT_HANDLED"}
    | {"yes", "no", "auth_self", "auth_admin", "auth_self_keep", "auth_admin_keep", "not_handled"}
)
MAX_RULES_FILE = 100_000


def _classify_rules(text: str, who: _Who) -> str:
    """none (no grant), warn (a grant for other principals only), hit (a grant for the account or its groups) or human
    (a shape this check cannot judge). An empty file is none; every other file must parse completely."""
    if not text.strip():
        return "none"
    names = [*sorted(who.logins), *sorted(who.group_names)]
    quoted = any(re.search(r"[\"']" + re.escape(n) + r"[\"']", text) for n in names)
    if len(text) > MAX_RULES_FILE or _RULES_FILE.fullmatch(text) is None:
        return "hit" if quoted else "human"
    grants = False
    for statement in _STATEMENT.finditer(text):
        value = next((g for g in statement.groups() if g), "")
        if value not in _RESULTS:
            return "human"
        if value.lower() != "yes":
            continue
        grants = True
        tests = [(m.group(1) or m.group(2))[1:-1] for m in _SUBJECT_TERM.finditer(statement.group())]
        if any(t in who.logins or t in who.group_names for t in tests):
            return "hit"
        if not tests:  # only `action.id` tests: the grant is for everyone
            return "human"
    return "warn" if grants else "none"


def _check_polkit(door: DoorPaths, who: _Who) -> Finding:
    scan = _Scan(door.max_entries)
    cache: dict[str, os.stat_result | None] = {}
    hits: list[str] = []
    others: list[str] = []
    human: list[str] = []
    defaults: list[str] = []
    open_to_account: list[str] = []
    try:
        for folder in (*door.polkit_dirs, *door.polkit_action_dirs):
            if not _folder_state(folder, f"polkit folder {_show(folder)}"):
                continue
            reach = _chain_writable(str(folder), who, cache, str(door.chain_floor))
            if reach is not None:
                open_to_account.append(_show(reach))
            for path, info in scan.walk(folder):
                if not stat.S_ISLNK(info.st_mode) and who.can_write(info):
                    open_to_account.append(_show(path))
                if not path.endswith((".rules", ".pkla", ".policy")):
                    continue
                if stat.S_ISLNK(info.st_mode):
                    raise _Problem(f"polkit file {_show(path)} cannot be read (it is a symbolic link)")
                if not stat.S_ISREG(info.st_mode):
                    continue
                text = _text(Path(path), f"polkit file {_show(path)}", None)
                if path.endswith(".policy"):
                    verdict = _policy_verdict(text)
                    {"grant": defaults, "human": human}.get(verdict, []).append(_show(path))
                    continue
                if path.endswith(".rules"):
                    verdict = _classify_rules(text, who)
                    {"hit": hits, "human": human, "warn": others}.get(verdict, []).append(_show(path))
                    continue
                if not _PKLA_YES.search(text):
                    continue
                names = [*sorted(who.logins), *sorted(who.group_names)]
                named = any(
                    re.search(r"unix-(?:user|group):" + re.escape(n) + r"(?![\w.-])", text) for n in names
                ) or re.search(r"unix-(?:user|group):\*", text)
                (hits if named else others).append(_show(path))
    except _Problem as problem:
        return Finding("polkit", "fail", str(problem))
    failure = scan.failure("the polkit scan")
    if failure:
        return Finding("polkit", "fail", failure)
    if open_to_account:
        return Finding("polkit", "fail", _sentence("the account can write polkit storage:", open_to_account))
    if hits:
        return Finding(
            "polkit",
            "fail",
            _sentence("polkit grants the account or one of its groups an action without a password in", hits),
        )
    if defaults:
        return Finding(
            "polkit",
            "fail",
            _sentence(
                "a polkit action policy default grants an active user an action without authentication in", defaults
            ),
        )
    if human:
        return Finding(
            "polkit",
            "fail",
            _sentence(
                "polkit file",
                human,
                " is in a shape this check cannot judge; a human needs to look",
            ),
        )
    if others:
        return Finding(
            "polkit",
            "warn",
            _sentence(
                "polkit grants an action without a password in", others, "; check that it is not for the account"
            ),
        )
    return Finding("polkit", "pass", "no polkit rule grants the account or its groups an action without a password")


def _check_writable(door: DoorPaths, who: _Who, extra: Sequence[Path]) -> Finding:
    scan = _Scan(door.max_entries)
    hits: list[str] = []
    try:
        for root in (*door.writable_roots, *extra):
            if not _folder_state(root, f"root-run folder {_show(root)}"):
                continue
            above = _chain_writable(str(root), who, {}, str(door.chain_floor))
            if above is not None:
                hits.append(_show(above))
            elif who.can_write(os.lstat(root)):
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
        return Finding(
            "writable",
            "fail",
            _sentence(f"the account can write {len(hits)} paths under root-run folders, for example", hits),
        )
    return Finding("writable", "pass", "the account can write nothing under the root-run folders that were scanned")


def _check_trees(door: DoorPaths, who: _Who) -> Finding:
    """The invariant behind the named checks: walk the system trees (bounded, never across a device, never following a
    link) and report any entry the account can write, and any link inside whose target the account can reach."""
    hits: list[str] = []
    human: list[str] = []
    cache: dict[str, os.stat_result | None] = {}
    floor = str(door.chain_floor)
    failures: list[str] = []
    try:
        roots = list(door.system_trees)
        real = {r: os.path.realpath(r) for r in roots}
        inside_trees = tuple(r.rstrip("/") + "/" for r in real.values())
        for root in roots:
            try:
                info = os.lstat(root)
            except (FileNotFoundError, NotADirectoryError):
                continue
            except OSError:
                raise _Problem(f"system tree {_show(root)} cannot be read (it cannot be examined)") from None
            if stat.S_ISLNK(info.st_mode):
                inside = any(
                    other != root and not os.path.islink(other) and (real[root] + "/").startswith(real[other] + "/")
                    for other in roots
                )
                if not inside:
                    raise _Problem(f"system tree {_show(root)} is a link that leads outside the other trees; {HUMAN}")
                continue
            if not stat.S_ISDIR(info.st_mode):
                raise _Problem(f"system tree {_show(root)} is not a directory")
            above = _chain_writable(str(root), who, cache, floor)
            if above is not None:
                hits.append(_show(above))
            scan = _Scan(door.max_entries)
            for path, entry in scan.walk(root):
                if stat.S_ISLNK(entry.st_mode):
                    found, final = _follow_links(Path(path), who, cache, floor, dangling_ok=True)
                    if found:
                        (human if HUMAN in found else hits).append(f"{_show(path)} {found}")
                        continue
                    try:
                        reach = os.stat(final)
                    except FileNotFoundError:
                        continue
                    except OSError:
                        human.append(f"{_show(path)} has a link target that cannot be examined; {HUMAN}")
                        continue
                    target = os.path.realpath(final)
                    if who.can_write(reach):
                        hits.append(f"{_show(path)} (a link to {_show(target)})")
                    elif stat.S_ISDIR(reach.st_mode) and not (target + "/").startswith(inside_trees):
                        human.append(f"{_show(path)} leads to a folder outside the walked trees; {HUMAN}")
                elif who.can_write(entry):
                    hits.append(_show(path))
            failure = scan.failure(f"the scan of {_show(root)}")
            if failure:
                failures.append(failure)
    except _Problem as problem:
        return Finding("trees", "fail", str(problem))
    if failures:
        return Finding("trees", "fail", f"{failures[0]}; {HUMAN}")
    if hits:
        return Finding(
            "trees",
            "fail",
            _sentence(f"the account can write or redirect {len(hits)} entries in the system trees, for example", hits),
        )
    if human:
        return Finding("trees", "fail", _sentence("links in the system trees that this check cannot judge:", human))
    return Finding("trees", "pass", "the account can write nothing in the system trees that were walked")


def _chain_writable(path: str, who: _Who, cache: dict[str, os.stat_result | None], floor: str = "/") -> str | None:
    """The first component of `path` (a path, or a folder above it) that the account can write; None when none.

    A component that does not exist yet counts through its nearest existing parent: if the account can create entries
    there, it can create the missing one. A sticky world-writable folder counts too: it stops the account replacing
    another user's file in it, but a root job that runs from there is still the account's to plant."""
    for candidate in (path, os.path.realpath(path)):
        parts = Path(candidate).parts
        for index in range(1, len(parts) + 1):
            prefix = str(Path(*parts[:index]))
            if floor != "/" and prefix != floor and not prefix.startswith(floor.rstrip("/") + "/"):
                continue
            if prefix not in cache:
                try:
                    cache[prefix] = os.lstat(prefix)
                except FileNotFoundError:
                    cache[prefix] = None
                except OSError:
                    raise _Problem(f"{_show(prefix)} cannot be examined; {HUMAN}") from None
            info = cache[prefix]
            if info is None:
                break
            if stat.S_ISLNK(info.st_mode):
                continue
            if who.can_write(info):
                return prefix
    return None


def _under(path: str, home: str) -> bool:
    return bool(home) and (path == home or path.startswith(home.rstrip("/") + "/"))


def _in_home(path: str, who: _Who) -> bool:
    return any(_under(path, h) for h in who.homes)


INTERPRETERS = frozenset(
    {
        "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "ash", "busybox",
        "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "lua", "tclsh", "awk", "gawk",
        "env", "nice", "ionice", "timeout", "nohup", "setsid", "flock", "stdbuf", "xargs", "sudo", "su", "chroot",
        "run-parts", "systemd-run", "unshare", "nsenter", "script", "watch", "time", "strace", "taskset",
    }
)  # fmt: skip
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_CODE_OPTION = re.compile(r"-[A-Za-z]*[ceEmrx][A-Za-z]*|--(?:command|eval|exec|execute|expression)\b.*")
_SHELL_SYNTAX = re.compile(r"[;|&`$()<>\\%\n*?\[\]{}~!#]")  # also glob, brace, tilde, history and comment characters
# the only options on an interpreter or wrapper that are known to take no value and run no code
PYTHON_FLAGS = frozenset({"-I", "-u", "-B", "-s", "-S", "-O", "-OO", "-q", "--"})  # python -s is "no user site"
WRAPPER_FLAGS = frozenset({"-i", "--"})
NO_FLAGS = frozenset({"--"})  # shells and every other interpreter: no option is known to be harmless (-s reads stdin)
# wrappers with no positional arguments of their own: the first positional is the program they run. Every other wrapper
# (flock has a lock file, timeout a duration, xargs and ionice take values) is handled as an interpreter: each of its
# arguments must be a known-harmless flag or an absolute path to an existing regular file, else a human looks.
WRAPPERS = frozenset({"env", "nice", "nohup", "setsid", "time"})


def _safe_flags(base: str) -> frozenset[str]:
    if base == "python" or base in ("python2", "python3"):
        return PYTHON_FLAGS
    return NO_FLAGS


# these take their program text first, so a command line for them cannot be followed
TEXT_FIRST = frozenset({"awk", "gawk", "mawk", "nawk", "sed"})
HUMAN = "a human needs to look"


def _command_hit(argv: list[str], who: _Who, cache: dict[str, os.stat_result | None], floor: str) -> str | None:
    """A root job's command line. The program must be an absolute path out of the account's reach. An interpreter, shell
    or wrapper is followed: every absolute path among its arguments must be out of reach too, and a command line that
    runs code from a string, from a relative name or from nothing cannot be judged, so it is reported for a human."""
    if not argv:
        return None
    first = argv[0]
    if not first.startswith("/"):
        return f"runs {_show(first)}, which is not an absolute path; {HUMAN}"
    candidates = [first]
    folders: list[str] = []  # candidates that may be a folder rather than a file
    base = re.sub(r"[0-9.]+$", "", os.path.basename(first))
    if base in TEXT_FIRST:
        return f"runs {_show(first)}, which takes its program text from the command line; {HUMAN}"
    if base in WRAPPERS:
        # a wrapper's own flags are valid only before the program it runs; from there the nested program's own rules
        # apply to the rest of the line
        for index, arg in enumerate(argv[1:], 1):
            if _CODE_OPTION.fullmatch(arg) and arg not in WRAPPER_FLAGS:
                return f"runs {_show(first)} with code on its command line; {HUMAN}"
            if arg.startswith("-"):
                if arg in WRAPPER_FLAGS:
                    continue
                return f"runs {_show(first)} with the option {_show(arg)}, which is not known to be harmless; {HUMAN}"
            if _SHELL_SYNTAX.search(arg):
                return f"runs {_show(first)} with {_show(arg)}, which uses shell syntax; {HUMAN}"
            if _ASSIGN.match(arg):
                value = arg.partition("=")[2]
                if value.startswith("/"):
                    candidates.append(value)
                continue
            own = _candidates_hit(candidates, who, cache, floor)
            if own:
                return own
            try:
                runnable = stat.S_ISREG(os.stat(arg).st_mode) and os.stat(arg).st_mode & 0o111
            except OSError:
                runnable = 0
            if arg.startswith("/") and not runnable:
                return f"runs {_show(arg)}, which is not an existing executable file; {HUMAN}"
            return _command_hit(argv[index:], who, cache, floor)
        return f"runs {_show(first)} without a command; {HUMAN}"
    if base in INTERPRETERS:
        found_script = False
        for arg in argv[1:]:
            if _CODE_OPTION.fullmatch(arg):
                return f"runs {_show(first)} with code on its command line; {HUMAN}"
            if arg.startswith("-"):
                if arg in _safe_flags(base):
                    continue
                return f"runs {_show(first)} with the option {_show(arg)}, which is not known to be harmless; {HUMAN}"
            if _SHELL_SYNTAX.search(arg):
                return f"runs {_show(first)} with {_show(arg)}, which uses shell syntax; {HUMAN}"
            if _ASSIGN.match(arg):
                value = arg.partition("=")[2]
                if value.startswith("/"):
                    candidates.append(value)
                continue
            if not arg.startswith("/"):
                return f"runs {_show(first)} with {_show(arg)}, which is not an absolute path; {HUMAN}"
            found_script = True
            candidates.append(arg)
        if not found_script:
            return f"runs {_show(first)} without a script path; {HUMAN}"
    else:  # a program this check does not know may load code from any argument: look at every one
        for arg in argv[1:]:
            if _SHELL_SYNTAX.search(arg):
                return f"runs {_show(first)} with {_show(arg)}, which uses shell syntax; {HUMAN}"
            if arg.startswith("-"):
                attached = re.fullmatch(r"-[A-Za-z]+(/.*)", arg)
                value = attached.group(1) if attached else arg.partition("=")[2]
                if value.startswith("/"):
                    candidates.append(value)
                    folders.append(value)
                elif "/" in value:
                    return f"runs {_show(first)} with {_show(arg)}, which names a relative path; {HUMAN}"
            elif arg.startswith("/"):
                candidates.append(arg)
                folders.append(arg)
            elif not arg.isdigit():
                return f"runs {_show(first)} with {_show(arg)}, which this check cannot place; {HUMAN}"
    return _candidates_hit(candidates, who, cache, floor, folders)


def _candidates_hit(
    candidates: list[str],
    who: _Who,
    cache: dict[str, os.stat_result | None],
    floor: str,
    folders: Sequence[str] = (),
) -> str | None:
    for candidate in candidates:
        if _in_home(candidate, who):
            return f"reads or runs {_show(candidate)} from the account's home"
        writable = _chain_writable(candidate, who, cache, floor)
        if writable is not None:
            return f"runs {_show(candidate)}, which the account can replace through {_show(writable)}"
    for candidate in candidates:  # a path that is not there is never treated as safe
        try:
            mode = os.stat(candidate).st_mode
            regular = stat.S_ISREG(mode) or (stat.S_ISDIR(mode) and candidate in folders)
        except OSError:
            regular = False
        if not regular:
            return f"names {_show(candidate)}, which is not an existing regular file; {HUMAN}"
    for candidate in folders:
        if os.path.isdir(candidate):
            hit = _folder_contents_hit(candidate, who, cache, floor)
            if hit:
                return hit
    return None


FOLDER_ENTRY_LIMIT = 20_000


def _folder_contents_hit(folder: str, who: _Who, cache: dict[str, os.stat_result | None], floor: str) -> str | None:
    """A folder named on a command line: nothing in it may be writable by the account, no link in it may lead somewhere
    the account can reach, and the walk must finish, else a human looks."""
    scan = _Scan(FOLDER_ENTRY_LIMIT)
    for path, info in scan.walk(Path(folder)):
        if stat.S_ISLNK(info.st_mode):
            real = os.path.realpath(path)
            if not os.path.exists(real):
                return f"{_show(folder)} holds a link, {_show(path)}, that does not resolve; {HUMAN}"
            if os.path.isdir(real):
                return f"{_show(folder)} holds a link, {_show(path)}, to a folder; {HUMAN}"
            if _in_home(real, who) or _chain_writable(real, who, cache, floor) is not None:
                return f"{_show(folder)} holds a link, {_show(path)}, that leads where the account can reach"
        elif who.can_write(info):
            return f"{_show(folder)} holds {_show(path)}, which the account can write"
    failure = scan.failure(f"the scan of {_show(folder)}")
    return f"{failure}; {HUMAN}" if failure else None


def _split_command(text: str) -> list[str] | None:
    try:
        return shlex.split(text)
    except ValueError:
        return None


SINGLE_KEYS = frozenset({"StandardInput", "StandardInputText", "StandardInputData", "WorkingDirectory"})
EXEC_PREFIXES = "-:+!@"


def _unquote(value: str) -> str:
    """A value as systemd reads a plain scalar: surrounding white space and one pair of matching quotes removed."""
    value = value.strip()
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        value = value[1:-1].strip()
    return value


def _assignments(text: str, section: str) -> list[tuple[str, str]]:
    """The assignments of one section, in order. Anything outside that section is ignored, as systemd ignores it."""
    found: list[tuple[str, str]] = []
    current = ""
    for line in _logical_lines(text):
        if line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            continue
        if current != section:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key in UNIT_KEYS:
            found.append((key, value))  # command lines keep their quoting: the command parser reads it
        elif key in ("User", "PermissionsStartOnly") or key in HOME_KEYS or key in STDIN_KEYS:
            found.append((key, _unquote(value)))
    return found


def _unit_hits(
    assignments: list[tuple[str, str]],
    who: _Who,
    cache: dict[str, os.stat_result | None],
    floor: str,
    socket: bool = False,
) -> str | None:
    """The merged unit: the base file and its drop-ins in order, the last assignment winning for a single-value key,
    an empty assignment clearing a list, and every other assignment adding to it. A command runs as root when the unit
    does (a socket unit's commands always do), when it carries the plus or bang prefix, or, with PermissionsStartOnly,
    when it is not the main command. Files the manager reads (environment, working folder, input) count whoever the
    user is."""
    user = ""
    start_only = False
    merged: dict[str, list[str]] = {}
    for key, value in assignments:
        if key == "User":
            user = value
        elif key == "PermissionsStartOnly":
            start_only = value.lower() not in ("false", "no", "0", "off", "")
        elif key in SINGLE_KEYS:
            merged[key] = [value] if value else []
        elif not value:
            merged[key] = []
        else:
            merged.setdefault(key, []).append(value)
    kind = "root" if socket or user == "" or re.search(r"[%$\"'\\]", user) else who.classify(user)
    if kind == "unknown":
        return f"runs as {_show(user)}, which the account database does not know; {HUMAN}"
    root_unit = kind == "root"
    for key, values in merged.items():
        for value in values:
            if key in UNIT_KEYS:
                prefix = value[: len(value) - len(value.lstrip(EXEC_PREFIXES))]
                if not (root_unit or "+" in prefix or "!" in prefix or (start_only and key != "ExecStart")):
                    continue
            hit = _entry_hit(key, value, who, cache, floor)
            if hit:
                return hit
    return None


def _entry_hit(key: str, value: str, who: _Who, cache: dict[str, os.stat_result | None], floor: str) -> str | None:
    if key in STDIN_KEYS:
        if key == "StandardInput" and value in ("", "null"):
            return None
        if key == "StandardInput" and value.startswith("file:") and value[5:].startswith("/"):
            return _candidates_hit([value[5:]], who, cache, floor)
        return f"feeds {_show(key)} to a root job ({_show(value[:40])}); {HUMAN}"
    if key in HOME_KEYS:
        first = value.lstrip("-").split(None, 1)[0] if value.lstrip("-") else ""
        if not first.startswith("/"):
            return None
        if _in_home(first, who):
            return f"reads or runs {_show(first)} from the account's home"
        writable = _chain_writable(first, who, cache, floor)
        if writable is not None:
            return f"runs {_show(first)}, which the account can replace through {_show(writable)}"
        return None
    body = value.lstrip("-:+!")
    if not body:
        return None
    argv = None if body.startswith("@") else _split_command(body)
    if argv is None or ";" in argv:
        return f"has a command line this check cannot read ({_show(body.split(None, 1)[0])}); {HUMAN}"
    return _command_hit(argv, who, cache, floor)


def _fragment(
    path: Path, name: str, section: str, who: _Who, cache: dict[str, os.stat_result | None], floor: str
) -> tuple[list[tuple[str, str]], str | None]:
    """The assignments of a unit file or drop-in, or a finding. A link is resolved: its target (and every folder on the
    way) must be out of the account's reach, else the link is a finding; one that does not resolve fails closed. A link
    to /dev/null is a masked unit and has no assignments."""
    real = str(path)
    info = _lstat(path, f"unit {_show(name)}")
    if stat.S_ISLNK(info.st_mode):
        hit, _ = _follow_links(path, who, cache, floor)
        if hit:
            return [], hit
        real = os.path.realpath(path)
        if real == os.devnull:
            return [], None
        try:
            target = os.stat(real)
        except OSError:
            raise _Problem(f"unit {_show(name)} cannot be read (its link does not resolve)") from None
        if not stat.S_ISREG(target.st_mode):
            raise _Problem(f"unit {_show(name)} cannot be read (its link does not lead to a regular file)")
    elif not stat.S_ISREG(info.st_mode):
        raise _Problem(f"unit {_show(name)} cannot be read (it is not a regular file)")
    return _assignments(_text(Path(real), f"unit {_show(name)}", None), section), None


def _applies(unit: str, dropin: str) -> bool:
    """Whether the drop-in folder `dropin` (its name without .d) belongs to `unit`, as systemd matches them: the unit's
    own folder, the one for its whole type, and the ones for each leading part of its name up to a dash."""
    kind = unit.rsplit(".", 1)[-1]
    if dropin in (unit, kind):
        return True
    suffix = "-." + kind
    return dropin.endswith(suffix) and unit.startswith(dropin[: -len("." + kind)])


_INSTANCE = re.compile(r"(.+)@(.+)\.([A-Za-z]+)")


def _unit_findings(
    door: DoorPaths, who: _Who, cache: dict[str, os.stat_result | None], floor: str
) -> tuple[list[str], list[str]]:
    bases: dict[str, list[Path]] = {}
    dropdirs: list[tuple[str, Path]] = []
    unhandled: list[str] = []
    for folder in door.unit_dirs:
        if not _folder_state(folder, f"unit folder {_show(folder)}"):
            continue
        for name in sorted(_listdir(folder)):
            path = folder / name
            if name.endswith(".d"):
                label = name[:-2]
                if not _folder_state(path, f"drop-in folder {_show(name)}"):
                    continue
                if label.rsplit(".", 1)[-1] in HANDLED_UNITS:
                    dropdirs.append((label, path))
                else:
                    unhandled.append(_show(name))
            elif "." in name and name.rsplit(".", 1)[-1] in HANDLED_UNITS:
                bases.setdefault(name, []).append(path)
    units = set(bases)
    for label, _ in dropdirs:
        if "." in label and not label.endswith("-." + label.rsplit(".", 1)[-1]):
            units.add(label)
    hits: list[str] = []
    for unit in sorted(units):
        kind = unit.rsplit(".", 1)[-1]
        instance = _INSTANCE.fullmatch(unit)
        template = f"{instance.group(1)}@.{instance.group(3)}" if instance else None
        names = [unit] + ([template] if template else [])
        confs: list[tuple[str, Path]] = []
        shadowed: list[str] = []
        seen: set[str] = set()
        for dname, dpath in dropdirs:  # in folder priority order: the first file of a name is the effective one
            if any(_applies(n, dname) for n in names):
                for conf in sorted(_listdir(dpath)):
                    if not conf.endswith(".conf"):
                        continue
                    if conf in seen:
                        shadowed.append(f"{conf} in {dname}.d")  # reported, never merged into the effective unit
                    else:
                        seen.add(conf)
                        confs.append((conf, dpath / conf))
        confs.sort(key=lambda item: item[0])  # systemd reads them in file name order, whatever the folder
        base_files: list[Path | None] = [*bases.get(unit, [])] or ([*bases.get(template or "", [])] or [None])
        if instance and base_files == [None]:
            raise _Problem(f"unit {_show(unit)} is a template instance and its template base file is missing")
        label = f"unit {_show(unit)}" + (f" with drop-ins {_show(', '.join(c for c, _ in confs))}" if confs else "")
        for base in base_files:
            assignments: list[tuple[str, str]] = []
            found: str | None = None
            for fname, fpath in ([(unit, base)] if base else []) + confs:
                part, found = _fragment(fpath, fname, HANDLED_UNITS[kind], who, cache, floor)
                if found:
                    break
                assignments.extend(part)
            found = found or _unit_hits(assignments, who, cache, floor, socket=kind == "socket")
            if found:
                hits.append(f"{label} {found}")
        if shadowed:
            hits.append(
                f"{label} has drop-ins that a higher-priority file of the same name shadows "
                f"({_show(', '.join(shadowed))}); {HUMAN}"
            )
    return hits, unhandled


def _cron_hit(text: str, who: _Who, cache: dict[str, os.stat_result | None], floor: str) -> str | None:
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or CRON_VAR.match(line):
            continue
        fields = line.split(None, 2 if line.startswith("@") else 6)
        index = 1 if line.startswith("@") else 5
        if len(fields) <= index + 1:
            continue
        kind = who.classify(fields[index])
        if kind == "unknown":
            return f"has a job for {_show(fields[index])}, which the account database does not know; {HUMAN}"
        if kind != "root":
            continue
        command = fields[index + 1]
        argv = None if _SHELL_SYNTAX.search(command) else _split_command(command)
        if argv is None:
            return f"runs a command line this check cannot read ({_show(command.split(None, 1)[0])}); {HUMAN}"
        hit = _command_hit(argv, who, cache, floor)
        if hit:
            return hit
    return None


MAX_LINK_HOPS = 4


def _follow_links(
    path: Path, who: _Who, cache: dict[str, os.stat_result | None], floor: str, dangling_ok: bool = False
) -> tuple[str | None, str]:
    """Follow a chain of symbolic links one hop at a time. Every hop (and the folders above it) must be out of the
    account's reach and out of its home; a chain longer than a few hops, a loop or a link that does not resolve goes
    to a human. Returns (a finding or None, the final path)."""
    current = str(path)
    seen: set[str] = set()
    for _ in range(MAX_LINK_HOPS + 1):
        if current == os.devnull:  # a masked unit
            return None, current
        if _in_home(current, who) or _in_home(os.path.realpath(current), who):
            return f"is, or links through, {_show(current)}, under the account's home", current
        writable = _chain_writable(current, who, cache, floor)
        if writable is not None:
            return f"links through {_show(current)}, which the account can replace through {_show(writable)}", current
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if dangling_ok:  # the target is not there, but the checks above ran on where it would be
                return None, current
            return f"has a link that does not resolve ({_show(current)}); {HUMAN}", current
        except OSError:
            return f"has a link that cannot be examined ({_show(current)}); {HUMAN}", current
        if not stat.S_ISLNK(info.st_mode):
            return None, current
        if current in seen:
            return f"has a link loop at {_show(current)}; {HUMAN}", current
        seen.add(current)
        try:
            target = os.readlink(current)
        except OSError:
            return f"has a link that cannot be read ({_show(current)}); {HUMAN}", current
        folder = os.path.realpath(os.path.dirname(current))
        # no lexical clean-up: a ".." after a link means something else to the kernel, so the path is kept as written
        # and every check below resolves it the way the kernel does (the folder checks use real paths)
        current = target if target.startswith("/") else os.path.join(folder, target)
    return f"has a chain of more than {MAX_LINK_HOPS} links; {HUMAN}", current


def _cron_file_hit(
    path: Path, info: os.stat_result, who: _Who, cache: dict[str, os.stat_result | None], floor: str
) -> str | None:
    """A cron file. cron follows a link, so a link is resolved: its target and every folder on the way must be out of
    the account's reach, and a link that does not lead to a regular file goes to a human."""
    real = path
    if stat.S_ISLNK(info.st_mode):
        hit, final = _follow_links(path, who, cache, floor)
        if hit:
            return hit
        try:
            regular = stat.S_ISREG(os.stat(final).st_mode)
        except OSError:
            regular = False
        if not regular:
            return f"is a link that does not lead to a regular file; {HUMAN}"
        real = Path(os.path.realpath(path))
    elif not stat.S_ISREG(info.st_mode):
        return None
    return _cron_hit(_text(real, f"cron file {_show(path.name)}", None), who, cache, floor)


def _check_jobs(door: DoorPaths, who: _Who) -> Finding:
    cache: dict[str, os.stat_result | None] = {}
    hits: list[str] = []
    unhandled: list[str] = []
    floor = str(door.chain_floor)
    try:
        unit_hits, unhandled = _unit_findings(door, who, cache, floor)
        hits.extend(unit_hits)
        files = list(door.cron_files)
        for folder in door.cron_dirs:
            if _folder_state(folder, f"cron folder {_show(folder)}"):
                files.extend(folder / n for n in sorted(_listdir(folder)))
        for path in files:
            try:
                info = os.lstat(path)
            except FileNotFoundError:
                continue
            found = _cron_file_hit(path, info, who, cache, floor)
            if found:
                hits.append(f"cron file {_show(path.name)} {found}")
    except _Problem as problem:
        return Finding("jobs", "fail", str(problem))
    except OSError:
        return Finding("jobs", "fail", "a unit or cron folder cannot be read (it cannot be listed)")
    if hits:
        return Finding("jobs", "fail", _sentence("a root-run job is open to the account:", hits))
    if unhandled:
        return Finding(
            "jobs",
            "warn",
            _sentence("drop-in folders exist for unit types this check does not read:", unhandled),
        )
    return Finding(
        "jobs",
        "pass",
        "no root-run unit or cron job runs a file the account can replace or reads from its home",
    )


def _check_preload(door: DoorPaths, trust: int) -> Finding:
    try:
        text = _text(door.ld_preload, "the preload file", trust)
    except _Problem as problem:
        if "(it is missing)" in str(problem):
            return Finding("preload", "pass", "there is no dynamic linker preload file")
        return Finding("preload", "fail", str(problem))
    if any(x.strip() and not x.lstrip().startswith("#") for x in text.splitlines()):
        return Finding(
            "preload", "warn", "the preload file lists libraries that load into every program; check each is yours"
        )
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


def _packages(door: DoorPaths, trust: int, who: _Who) -> set[str]:
    """The files the packages own. The database is evidence only if the account cannot have written it: the folder and
    every list must be owned by root and closed, and the account must not be able to write any folder above it."""
    owned: set[str] = set()
    if not _folder_state(door.dpkg_info, "the package database"):
        raise _Problem("the package database cannot be read (it is missing)")
    info = _lstat(door.dpkg_info, "the package database")
    if info.st_uid != trust or info.st_mode & 0o022:
        raise _Problem("the package database cannot be trusted (its folder is not owned by root or is open to others)")
    reach = _chain_writable(str(door.dpkg_info), who, {}, str(door.chain_floor))
    if reach is not None:
        raise _Problem(f"the package database cannot be trusted (the account can write {_show(reach)})")
    for name in sorted(_listdir(door.dpkg_info)):
        if not name.endswith(".list"):
            continue
        for line in _text(door.dpkg_info / name, "a package file list", trust).splitlines():
            owned.add(_merge(door, line.strip()))
    if not owned:
        raise _Problem("the package database cannot be read (it lists no files)")
    return owned


def _merge(door: DoorPaths, path: str) -> str:
    for old, new in door.merged_dirs:
        if path == old or path.startswith(old + "/"):
            return new + path[len(old) :]
    return path


def _check_suid(door: DoorPaths, who: _Who, trust: int) -> Finding:
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
                    raise _Problem(
                        f"scan folder {_show(root)} is a symbolic link that leads outside the other scan folders"
                    )
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
            owned = _packages(door, trust, who)
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
    return Finding(
        "setuid",
        "pass",
        f"{len(marked)} setuid or setgid files were found, all owned by a package and closed to the account",
    )


def _check_credential(door: DoorPaths, who: _Who) -> Finding:
    if any(not h.startswith("/") or h == "/" for h in who.homes):
        return Finding(
            "credential",
            "fail",
            "the account database records no usable home folder, so the old credential was not looked for",
        )
    found: list[str] = []
    for rel, home in ((r, h) for h in who.homes for r in door.credential_paths):
        path = Path(home) / rel
        try:
            os.lstat(path)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            return Finding(
                "credential", "fail", f"{_show(path)} cannot be examined, so the old credential was not looked for"
            )
        found.append(_show(path))
    if found:
        return Finding(
            "credential",
            "warn",
            _sentence(
                "an old secret-store credential or setting is still on disk at",
                found,
                "; revoke it at the vendor, then delete it",
            ),
        )
    return Finding("credential", "pass", "no old secret-store credential was found in the account's home")


_NEEDS_WHO = ("sudo", "groups", "polkit", "writable", "jobs", "setuid", "credential", "trees")


def check_doors(
    door: DoorPaths,
    trust_uid: int,
    maintainer_uid: int | None,
    extra_roots: Sequence[Path] = (),
    claimed_login: str | None = None,
) -> list[Finding]:
    """One finding per check, in a fixed order. Never raises for a path problem: that is a fail. An account that is not
    known is a fail, never a warning: with `claimed_login` set (sudo's own user name) it must be one of the logins of
    the uid, so a user id alone, set by hand, does not select the account that gets judged."""
    who: _Who | None = None
    unknown = ""
    state = "fail"
    if maintainer_uid is None:
        unknown = "the maintainer account is unknown (run through sudo so SUDO_UID is set), so nothing was judged"
    else:
        try:
            who = _load_who(door, trust_uid, maintainer_uid)
        except _Problem as problem:
            unknown = str(problem)
        if who is not None and claimed_login is not None and claimed_login not in who.logins:
            who = None
            unknown = "the user name sudo reports does not belong to the user id it reports, so nothing was judged"
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
            results.append(_check_suid(door, who, trust_uid))
        elif name == "trees":
            results.append(_check_trees(door, who))
        else:
            results.append(_check_credential(door, who))
    results.append(_check_preload(door, trust_uid))
    return results
