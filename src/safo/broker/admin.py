# SPDX-License-Identifier: Apache-2.0
"""The root-only administration command for the paid Gemini broker (docs/gemini-broker.md, "Administration").

    python -I -m safo.broker.admin status | usage | check-install | clear | reconcile

How root gets at the ledger without weakening the rule the service relies on. The ledger refuses any file that does
not belong to the effective uid, and the state directory belongs to the service user, so root cannot open it as
root. Two ways round that were weighed:

* give the ledger a read-write admin mode that accepts euid 0 and chowns files back: rejected, because it widens the
  owner rule the service depends on, and a file root creates (a new marker, the head or height record) would be owned by
  root and refused by the service on its next start;
* run as root only long enough to read what only root can read, then drop to the service user (`drop_privilege`) and
  use the ledger exactly as the service does: CHOSEN. Nothing in the ledger changes, every file root writes belongs to
  the service user, and the same lock is taken.

The drop is explicit and checked: the working directory is moved to `/`, the umask is set to 077, the supplementary
groups are emptied, then the group and then the user are set, the three ids of each kind are read back, and the process
proves it cannot return to root. Any failure stops the command before the ledger is opened. Reading the root-owned files
(`status` and `check-install`) happens BEFORE the drop. Nothing is read from standard input: a confirmation is a typed
argument. All output goes through `safo.output`.

Run it ONLY as `python -I -m safo.broker.admin ...` with the root-owned interpreter by its full path. `-I` (isolated)
keeps the current directory, the user site and every PYTHON environment variable out of the module search path, so
nothing the operator's shell can reach is imported while the process is root. The module refuses to start otherwise
(`sys.flags.isolated`), and checks that before it imports anything outside the standard library. The interpreter's own
start-up and the `safo` and `safo.broker` package files are imported before this check can run: they come from the
installed, root-owned release, which is why the check is a second line and not the only one.

`now` and the identity operations are parameters, so tests need no clock and no root.
"""

from __future__ import annotations

import os
import sys

if __name__ == "__main__" and not sys.flags.isolated:  # before any import outside the standard library
    os.write(2, b"safo-broker-admin: refusing to run; start it as: python -I -m safo.broker.admin ...\n")
    raise SystemExit(2)

import argparse
import dataclasses
import datetime as dt
import pwd
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn, TextIO

from safo import gemini, geminisign, output
from safo.broker.errors import BrokerError, LedgerError
from safo.broker.ledger import AdminWho, CallLedger, CallRecord, LedgerView
from safo.broker.money import MoneyError, format_usd, parse_usd
from safo.broker.policy import MONTH_CAP_MICRO
from safo.broker.records import MONTH, SCHEMA_VERSION, UID_MAX
from safo.errors import SafoError

SERVICE_USER = "safo-broker"
VERSION = re.compile(r"[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}")
SUDO_UID = re.compile(r"[0-9]{1,10}")
USAGE = (
    "usage: python -I -m safo.broker.admin status\n"
    "       python -I -m safo.broker.admin usage [--month YYYY-MM]\n"
    "       python -I -m safo.broker.admin check-install\n"
    "       python -I -m safo.broker.admin clear MODEL --confirm CALL_ID [--confirm CALL_ID ...]"
    " [--actual CALL_ID=USD ... --reason TEXT]\n"
    "       python -I -m safo.broker.admin reconcile [--month YYYY-MM] [--billing-usd USD --reason TEXT]"
)


class AdminError(BrokerError):
    """The command was refused or could not run. The message is a fixed sentence."""

    exit_code = 2


class UsageError(AdminError):
    """The arguments were not understood; the usage lines follow the message."""


# -- paths and identity --------------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Paths:
    """Where everything is. Fixed in code: no flag and no environment variable moves them (tests inject their own)."""

    state_dir: Path = Path("/var/lib/safo-broker")
    switch: Path = Path("/etc/safo/gemini-paid-enabled")
    min_version: Path = Path("/etc/safo/broker-min-version")
    install_version: Path = Path("/var/lib/safo-broker-install/version")
    release_link: Path = Path("/opt/safo-broker/current")
    trust_uid: int = 0  # who must own the root files above


@dataclasses.dataclass(frozen=True)
class PrivOps:
    """The process-identity operations, as a seam so a test can record them and needs no root."""

    geteuid: Callable[[], int]
    getuid: Callable[[], int]
    getpwnam: Callable[[str], Any]
    setgroups: Callable[[list[int]], None]
    setgid: Callable[[int], None]
    setuid: Callable[[int], None]
    getresuid: Callable[[], tuple[int, int, int]]
    getresgid: Callable[[], tuple[int, int, int]]
    getgroups: Callable[[], list[int]]
    umask: Callable[[int], int]
    chdir: Callable[[str], None]


REAL_OPS = PrivOps(
    geteuid=os.geteuid,
    getuid=os.getuid,
    getpwnam=pwd.getpwnam,
    setgroups=os.setgroups,
    setgid=os.setgid,
    setuid=os.setuid,
    getresuid=os.getresuid,
    getresgid=os.getresgid,
    getgroups=os.getgroups,
    umask=os.umask,
    chdir=os.chdir,
)


def drop_privilege(user: str, ops: PrivOps) -> None:
    """Become `user` for good: groups emptied, then group, then user; read back; prove root cannot be regained. Raises
    AdminError (and leaves nothing opened) if any step fails or does not hold."""
    try:
        entry = ops.getpwnam(user)
    except KeyError:
        raise AdminError("the service user does not exist on this machine") from None
    uid, gid = entry.pw_uid, entry.pw_gid
    if uid == 0 or gid == 0:
        raise AdminError("the service user must not be root or in root's group")
    try:
        ops.chdir("/")
        ops.umask(0o077)
        ops.setgroups([])
        ops.setgid(gid)
        ops.setuid(uid)
    except OSError:
        raise AdminError("the privilege drop failed; nothing was opened") from None
    if ops.getresuid() != (uid, uid, uid) or ops.getresgid() != (gid, gid, gid) or ops.getgroups() != []:
        raise AdminError("the privilege drop did not take hold; nothing was opened")
    try:
        ops.setuid(0)
    except OSError:
        return
    raise AdminError("the privilege drop can be undone; nothing was opened")


def sudo_uid(env: Mapping[str, str]) -> int:
    """The uid sudo says the command came from, else -1."""
    text = env.get("SUDO_UID", "")
    if SUDO_UID.fullmatch(text) is None or int(text) > UID_MAX:
        return -1
    return int(text)


# -- what only root can read ---------------------------------------------------------------------------------------


def _version(text: bytes) -> tuple[int, int, int] | None:
    try:
        line = text.decode("ascii").strip()
    except UnicodeError:
        return None
    if VERSION.fullmatch(line) is None:
        return None
    a, b, c = line.split(".")
    return (int(a), int(b), int(c))


def _show(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


@dataclasses.dataclass(frozen=True)
class RootFacts:
    switch_enabled: bool
    min_version: tuple[int, int, int] | None


def read_root_facts(paths: Paths) -> RootFacts:
    """The enable switch and the floor, read as root before the drop."""
    try:
        data = geminisign.read_trust_file(paths.switch, paths.trust_uid, "paid-use switch")
        lines = [x.strip() for x in data.decode("utf-8", "replace").splitlines() if x.strip() and not x.startswith("#")]
        enabled = lines == ["enabled"]
    except gemini.RefusedError:
        enabled = False
    try:
        floor = _version(geminisign.read_trust_file(paths.min_version, paths.trust_uid, "broker floor"))
    except gemini.RefusedError:
        floor = None
    return RootFacts(enabled, floor)


def _read_version(path: Path, uid: int, what: str) -> tuple[tuple[int, int, int] | None, str]:
    try:
        data = geminisign.read_trust_file(path, uid, what)
    except gemini.RefusedError:
        return None, f"{what} cannot be read (missing, not owned by root, writable, or under a writable folder)"
    version = _version(data)
    if version is None:
        return None, f"{what} is not a version (three dotted numbers)"
    return version, ""


def check_install(paths: Paths) -> tuple[list[str], list[str]]:
    """(facts, failures): whether the release link, the monotonic version record and the floor agree. Read-only."""
    facts: list[str] = []
    fails: list[str] = []
    notes: list[str] = []
    current: tuple[int, int, int] | None = None
    link = paths.release_link
    releases = Path(os.path.normpath(link.parent / "releases"))
    try:
        info = os.lstat(link)
    except OSError:
        info = None
        fails.append("the release link is missing")
    if info is not None and not stat.S_ISLNK(info.st_mode):
        fails.append("the release link is not a symbolic link")
    elif info is not None:
        target = Path(os.path.normpath(link.parent / os.readlink(link)))
        if target.parent != releases:
            fails.append("the release link points outside the releases folder")
        elif VERSION.fullmatch(target.name) is None:
            fails.append("the release folder name is not a version")
        else:
            try:
                folder = os.lstat(target)
            except OSError:
                fails.append("the release folder does not exist")
            else:
                if not stat.S_ISDIR(folder.st_mode) or folder.st_uid != paths.trust_uid or folder.st_mode & 0o022:
                    fails.append("the release folder is not a folder owned by root and closed to group and others")
                else:
                    current = _version(target.name.encode())
    recorded, why = _read_version(paths.install_version, paths.trust_uid, "recorded version")
    if why:
        fails.append(why)
    floor, why = _read_version(paths.min_version, paths.trust_uid, "floor")
    if why:
        fails.append(why)
    for label, value in (("release", current), ("recorded", recorded), ("floor", floor)):
        if value is not None:
            facts.append(f"{label}: {_show(value)}")
    if current is not None and floor is not None and current < floor:
        fails.append("the release is below the floor, so the broker refuses to start")
    if floor is not None and recorded is not None and floor > recorded:
        fails.append("the floor is above the record of the highest installed version")
    if current is not None and recorded is not None and current > recorded:
        fails.append("the release is newer than the record, so the monotonic record was not kept")
    if current is not None and recorded is not None and current < recorded:
        notes.append("the release is below the highest version ever installed (a rollback or an allowed downgrade)")
    lines = facts + [f"fail: {text}" for text in fails] + [f"note: {text}" for text in notes]
    if not fails:
        lines.append("ok: the release link, the record and the floor agree")
    return lines, fails


# -- the ledger commands -------------------------------------------------------------------------------------------


def _month_key(now: dt.datetime) -> str:
    return now.astimezone(dt.UTC).strftime("%Y-%m")


def _record_lines(rec: CallRecord) -> list[str]:
    lines = [
        f"call: {rec.call_id}",
        f"model: {rec.model}",
        f"job: {rec.job}",
        f"kind: {'breach' if rec.breach else 'ambiguous'}",
        f"started: {gemini.stamp(rec.started)}",
        f"reserved_usd: {format_usd(rec.reserved_micro)}",
        f"state: {rec.state.value}",
        f"counted_usd: {format_usd(rec.counted_micro)}",
    ]
    if rec.actual_micro is not None:
        lines.append(f"recorded_actual_usd: {format_usd(rec.actual_micro)}")
    return lines


def _status(ledger: CallLedger, facts: RootFacts, now: dt.datetime) -> list[str]:
    view = ledger.view()
    floor = ledger.floor()
    key = _month_key(now)
    opened = view.open_calls()
    lines = [
        f"month: {key}",
        f"spent_usd: {format_usd(view.month_total(key))}",
        f"ceiling_usd: {format_usd(MONTH_CAP_MICRO)} (built in; a configuration may lower it)",
        "open_calls: " + (f"{len(opened)} ({', '.join(c.call_id for c in opened)})" if opened else "0"),
    ]
    if view.suspended:
        lines += [f"suspended: {model} ({', '.join(ids)})" for model, ids in sorted(view.suspended.items())]
    else:
        lines.append("suspended: none")
    lines += [
        f"switch: {'enabled' if facts.switch_enabled else 'disabled'}",
        f"schema_version: {SCHEMA_VERSION}",
        f"schema_floor: {floor if floor is not None else 'none'}",
        f"min_version: {_show(facts.min_version) if facts.min_version else 'unreadable'}",
        f"ledger_rows: {view.rows}",
    ]
    return lines


def _usage(view: LedgerView, key: str) -> list[str]:
    jobs: dict[str, tuple[int, int]] = {}
    for rec in view.calls.values():
        if rec.month == key:
            count, spent = jobs.get(rec.job, (0, 0))
            jobs[rec.job] = (count + 1, spent + rec.counted_micro)
    lines = [f"month: {key}", "job calls spent_usd"]
    lines += [f"{job} {count} {format_usd(spent)}" for job, (count, spent) in sorted(jobs.items())]
    lines.append(f"adjustments_usd: {format_usd(view.adjusted.get(key, 0))}")
    lines.append(f"total_usd: {format_usd(view.month_total(key))}")
    return lines


def _actuals(items: Sequence[str]) -> dict[str, int]:
    found: dict[str, int] = {}
    for item in items:
        call_id, sep, amount = item.partition("=")
        if not sep or not call_id or call_id in found:
            raise AdminError("an actual is CALL_ID=USD, once per call")
        try:
            found[call_id] = parse_usd(amount)
        except MoneyError:
            raise AdminError("an actual is a plain amount in dollars with up to six decimals") from None
    return found


def _clear(
    ledger: CallLedger, args: argparse.Namespace, who: AdminWho, now: dt.datetime, out: TextIO, err: TextIO
) -> int:
    view = ledger.view()
    ids = view.suspended.get(args.model)
    if not ids:
        raise AdminError("this model is not suspended")
    for call_id in ids:
        for line in _record_lines(view.calls[call_id]):
            output.write(out, line)
        output.write(out, "")
    if not args.confirm:
        output.write(err, "not cleared: repeat every call id above with --confirm CALL_ID to clear the suspension")
        return 2
    done = ledger.admin_clear(args.model, args.confirm, _actuals(args.actual), args.reason, who, now)
    output.write(out, f"cleared: {done.model}")
    for call_id, before, after in done.calls:
        output.write(out, f"settled: {call_id} counted_usd {format_usd(before)} -> {format_usd(after)}")
    return 0


def _reconcile(ledger: CallLedger, args: argparse.Namespace, who: AdminWho, now: dt.datetime, out: TextIO) -> int:
    billing = None
    if args.billing_usd is not None:
        try:
            billing = parse_usd(args.billing_usd)
        except MoneyError:
            raise AdminError("the billing figure is a plain amount in dollars with up to six decimals") from None
    month = args.month or _month_key(now)
    if MONTH.fullmatch(month) is None:
        raise AdminError("a month is written YYYY-MM")
    if billing is not None and not args.reason:
        raise AdminError("entering a billing figure needs --reason")
    try:
        found = ledger.audit(now)
    except LedgerError as err:
        output.write(out, f"mismatch: the ledger or the used folder cannot be trusted: {err}")
        return 1
    added = ledger.admin_adjust(month, billing, args.reason, who, now) if billing is not None else None
    output.write(out, f"month: {month}")
    output.write(out, f"mismatches: {len(found)}")
    for text in found:
        output.write(out, f"mismatch: {text}")
    if added is not None:
        output.write(out, f"adjusted_usd: {format_usd(added)}")
    output.write(out, f"spent_usd: {format_usd(ledger.view().month_total(month))}")
    return 1 if found else 0


# -- the command ---------------------------------------------------------------------------------------------------


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise UsageError("the arguments were not understood")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="python -m safo.broker.admin", add_help=False, allow_abbrev=False)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    sub.add_parser("check-install")
    usage = sub.add_parser("usage")
    usage.add_argument("--month")
    clear = sub.add_parser("clear")
    clear.add_argument("model")
    clear.add_argument("--confirm", action="append", default=[])
    clear.add_argument("--actual", action="append", default=[])
    clear.add_argument("--reason", default="")
    rec = sub.add_parser("reconcile")
    rec.add_argument("--month")
    rec.add_argument("--billing-usd")
    rec.add_argument("--reason", default="")
    return parser


def run(
    argv: Sequence[str],
    *,
    ops: PrivOps = REAL_OPS,
    paths: Paths | None = None,
    env: Mapping[str, str] | None = None,
    now: dt.datetime,
    out: TextIO,
    err: TextIO,
) -> int:
    """Run one command; returns the exit code (0 done, 1 a finding to act on, 2 refused or could not run)."""
    try:
        return _run(argv, ops, paths or Paths(), os.environ if env is None else env, now, out, err)
    except SafoError as problem:
        output.write(err, f"safo-broker-admin: {problem}")
        if isinstance(problem, UsageError):
            for line in USAGE.splitlines():
                output.write(err, line)
        return 2


def _run(
    argv: Sequence[str],
    ops: PrivOps,
    paths: Paths,
    env: Mapping[str, str],
    now: dt.datetime,
    out: TextIO,
    err: TextIO,
) -> int:
    args = _parser().parse_args(list(argv))
    if ops.geteuid() != 0:
        raise AdminError("the broker administration command runs as root only")
    who = AdminWho(ops.getuid(), sudo_uid(env))
    if args.cmd == "check-install":
        lines, fails = check_install(paths)
        for line in lines:
            output.write(out, line)
        return 1 if fails else 0
    facts = read_root_facts(paths) if args.cmd == "status" else RootFacts(False, None)
    if args.cmd == "usage" and args.month is not None and MONTH.fullmatch(args.month) is None:
        raise AdminError("a month is written YYYY-MM")
    drop_privilege(SERVICE_USER, ops)
    if not os.path.lexists(paths.state_dir):
        raise AdminError("the broker state directory does not exist; nothing was created")
    ledger = CallLedger(paths.state_dir)
    if args.cmd == "status":
        for line in _status(ledger, facts, now):
            output.write(out, line)
        return 0
    if args.cmd == "usage":
        for line in _usage(ledger.view(), args.month or _month_key(now)):
            output.write(out, line)
        return 0
    if args.cmd == "clear":
        return _clear(ledger, args, who, now, out, err)
    return _reconcile(ledger, args, who, now, out)


def main(argv: Sequence[str] | None = None) -> int:
    if not sys.flags.isolated:
        output.write(sys.stderr, "safo-broker-admin: refusing to run; start it as: python -I -m safo.broker.admin ...")
        return 2
    return run(
        sys.argv[1:] if argv is None else argv,
        now=dt.datetime.now(dt.UTC),
        out=sys.stdout,
        err=sys.stderr,
    )


if __name__ == "__main__":
    raise SystemExit(main())
