# SPDX-License-Identifier: Apache-2.0
"""safo-file: the idea gate and the cross-project line (issue #443), a wrapper in the style of `safo file` (#348).

A tool, not a guard, and ADVISORY by design for same-repo filing: nothing forces an agent to run `check` first, and a
same-repo `issue` works without it (owner decision: the gate is for new ideas and cross-repo filing). Routing a direct
`gh issue create` here is a follow-up in the frozen guard's territory, not in this module. It never touches the
dispatch guard, the hooks, `~/.config/safo` (it only READS agents.yaml through the normal loader) or settings.json. It
creates no repository, epic or card, ever.

    safo-file check IDEA --working-repo o/r [--answer ANSWER] [--owner-ok] [--timebox 30m] [--parking o/r#N]
    safo-file issue --repo o/r --working-repo o/r --title T --body B [--allow-other-owner]
    safo-file report [--working-repo o/r]

`check` matches the idea against `hooks.tracking_repos`, `gh repo list` and a pluggable memory search
(`$SAFO_MEMORY_SEARCH`: a command that is run as `<command> -- <idea>`; each output line is one hit), prints the top
hits, and requires exactly one ANSWER: `extends:<repo>`, `new-project` (needs `--owner-ok`) or `tangent` (prints one
parking-lot body with a time box; with `--parking` it posts that body as a comment on that one issue).

`issue` files one issue through `gh` (the body goes over stdin, never argv). Filing in a repo other than the working
repo needs a `cross-project: <reason>` line in the body. Every filing is appended to a ledger; `report` counts, in
code, those whose repo differs.

ENFORCED here: `issue` in another repo needs a non-empty `cross-project: <reason>` line (outside a code fence) and
`--allow-other-owner` when the owner differs; the ledger is opened and checked before the issue is created; `check`
needs exactly one answer; `new-project` needs `--owner-ok`. NOT enforced: that `check` ran, that the reason is true
(the line is a reminder, not an adversary-proof control), and anything an agent does by calling `gh` directly.
See docs/file.md.

Exit codes: 0 done, 1 refused (a rule), 2 a bad command line or an error, 3 an answer is still needed.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import os
import re
import select
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from safo import output
from safo.credentials import AMBIENT_GH_VARIABLES, find_gh
from safo.errors import SafoError
from safo.trust import read_trusted_regular_file

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_ERROR = 2
EXIT_NEEDS_ANSWER = 3

TOP = 5
CALL_TIMEOUT = 60
MEMORY_TIMEOUT = 10
MEMORY_CAP = 65_536  # bytes read from the memory command, never more
LEDGER_LIMIT = 8 * 1024 * 1024
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}")
PARKING = re.compile(r"([A-Za-z0-9][A-Za-z0-9-]{0,38}/(?!\.{1,2}#)[A-Za-z0-9._-]{1,100})#([1-9][0-9]{0,8})")
TIMEBOX = re.compile(r"[1-9][0-9]{0,2}[mh]")
CROSS = re.compile(r"^cross-project:[ \t]*(\S.*)$", re.MULTILINE)
FENCE = re.compile(r"^ {0,3}(```|~~~)")
WORD = re.compile(r"[a-z0-9]{3,}")
ANSWERS = "extends:<repo>, new-project, tangent"


@dataclass
class Deps:
    """Everything that leaves the process. Tests pass fakes; `real_deps` builds the live ones."""

    tracking: Callable[[], Sequence[str]]
    gh_repos: Callable[[], Sequence[tuple[str, str]]]  # (owner/name, description)
    memory: Callable[[str], Sequence[str]]
    create_issue: Callable[[str, str, str], str]  # repo, title, body -> url
    comment: Callable[[str, int, str], None]  # repo, issue number, body
    ledger: Path


def words(text: str) -> set[str]:
    return set(WORD.findall(text.lower()))


def top_hits(idea: str, candidates: Sequence[tuple[str, str]]) -> list[tuple[int, str, str]]:
    """Candidates sharing at least one word with the idea, best first. Counting is code, never a model."""
    want = words(idea)
    scored = [(len(want & words(f"{name} {desc}")), name, desc) for name, desc in candidates]
    return sorted((s for s in scored if s[0] > 0), key=lambda s: (-s[0], s[1]))[:TOP]


def parse_answer(answer: str, known: set[str]) -> tuple[str, str]:
    if answer in ("new-project", "tangent"):
        return answer, ""
    if answer.startswith("extends:"):
        repo = answer[len("extends:") :]
        if not REPO.fullmatch(repo):
            raise SafoError(f"extends needs a repository as owner/name, got {repo!r}")
        if repo not in known:
            raise SafoError(f"{repo} is not in tracking_repos, the working repo or `gh repo list`; use new-project")
        return "extends", repo
    raise SafoError(f"the answer must be exactly one of: {ANSWERS}")


def tangent_body(idea: str, timebox: str, working: str, now: dt.datetime) -> str:
    return (
        f"Parking lot ({now.date().isoformat()}, from {working})\n\n"
        f"Idea: {idea}\n"
        f"Time box: {timebox}. Past it, the idea is dropped or filed as a new project with the owner's OK.\n"
        "No repository, epic or card is created for a tangent.\n"
    )


def check(args: argparse.Namespace, deps: Deps, out: TextIO, err: TextIO, now: dt.datetime) -> int:
    tracking = list(deps.tracking())
    repos = list(deps.gh_repos())
    known = set(tracking) | {name for name, _ in repos} | {args.working_repo}
    output.write(out, f"idea: {args.idea}")
    output.write(out, "tracking_repos hits:")
    _show(out, top_hits(args.idea, [(r, "") for r in tracking]))
    output.write(out, "gh repo list hits:")
    _show(out, top_hits(args.idea, repos))
    output.write(out, "memory hits:")
    mem = [line for line in deps.memory(args.idea) if line.strip()][:TOP]
    for line in mem:
        output.write(out, f"  - {line}")
    if not mem:
        output.write(out, "  (none)")
    if not args.answer:
        output.write(out, f"answer with exactly one of: {ANSWERS}")
        return EXIT_NEEDS_ANSWER
    if len(args.answer) != 1:
        raise SafoError(f"exactly one answer is required, got {len(args.answer)}")
    kind, repo = parse_answer(args.answer[0], known)
    if kind == "extends":
        output.write(out, f"extends {repo}: file under that project; nothing is created here")
    elif kind == "new-project":
        if not args.owner_ok:
            output.write(err, "refused: a new project needs the owner's explicit OK (--owner-ok)")
            return EXIT_REFUSED
        output.write(out, "new-project: owner OK recorded; create the repo, epic and card by the normal process")
    else:
        body = tangent_body(args.idea, args.timebox, args.working_repo, now)
        output.write(out, "tangent: parking-lot body (no repo, epic or card):")
        for text in body.splitlines():  # shown escaped; the raw text goes only to GitHub
            output.write(out, text)
        if args.parking:
            m = PARKING.fullmatch(args.parking)
            if not m:
                raise SafoError("--parking must be owner/repo#N")
            deps.comment(m.group(1), int(m.group(2)), body)
            output.write(out, f"posted to {args.parking}")
    return EXIT_OK


def _show(out: TextIO, hits: Sequence[tuple[int, str, str]]) -> None:
    for score, name, desc in hits:
        output.write(out, f"  - {name} (match {score}){': ' + desc if desc else ''}")
    if not hits:
        output.write(out, "  (none)")


def outside_fences(body: str) -> str:
    """The body without fenced code blocks (an unclosed fence runs to the end), so a quoted line cannot count."""
    kept: list[str] = []
    fence = ""
    for text in body.splitlines():
        m = FENCE.match(text)
        if m and not fence:
            fence = m.group(1)
        elif m and m.group(1) == fence:
            fence = ""
        elif not fence:
            kept.append(text)
    return "\n".join(kept)


def open_ledger(path: Path) -> int:
    """A descriptor to append to, opened without following a link and judged regular; before any issue exists."""
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, flags, 0o600)
    except OSError as problem:
        raise SafoError(f"the ledger cannot be opened for appending ({problem.strerror}); nothing was filed") from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise SafoError("the ledger is not a regular file; nothing was filed")
    return fd


def file_issue(args: argparse.Namespace, deps: Deps, out: TextIO, err: TextIO, now: dt.datetime) -> int:
    for name in (args.repo, args.working_repo):
        if not REPO.fullmatch(name):
            raise SafoError(f"expected owner/name, got {name!r}")
    cross = args.repo != args.working_repo
    other_owner = args.repo.split("/")[0].lower() != args.working_repo.split("/")[0].lower()
    if cross and other_owner and not args.allow_other_owner:
        output.write(err, f"refused: {args.repo} has another owner than {args.working_repo}; pass --allow-other-owner")
        return EXIT_REFUSED
    if cross and not CROSS.search(outside_fences(args.body)):
        output.write(
            err,
            f"refused: {args.repo} is not the working repo {args.working_repo}; "
            "the body needs a `cross-project: <reason>` line",
        )
        return EXIT_REFUSED
    fd = open_ledger(deps.ledger)
    try:
        url = deps.create_issue(args.repo, args.title, args.body)
        entry = {"ts": now.isoformat(), "repo": args.repo, "working_repo": args.working_repo, "url": url}
        try:
            os.write(fd, (json.dumps(entry) + "\n").encode())
        except OSError:
            output.write(err, f"safo-file: the issue was filed ({url}) but the ledger write failed")
            return EXIT_ERROR
    finally:
        os.close(fd)
    output.write(out, url)
    return EXIT_OK


def count_mismatches(ledger: Path, working: str | None) -> tuple[int, int, int]:
    """(issues whose repo differs from the working repo, all issues, corrupt lines skipped), optionally for one
    working repo. A missing ledger is zero; an unreadable, linked, non-regular or oversize one is a SafoError."""
    if not ledger.is_symlink() and not ledger.exists():
        return 0, 0, 0
    text = read_trusted_regular_file(ledger, LEDGER_LIMIT).decode("utf-8", "replace")
    total = differ = corrupt = 0
    for raw in text.splitlines():
        if not raw.strip():
            continue
        try:
            e = json.loads(raw)
        except ValueError:
            e = None
        if not isinstance(e, dict) or not isinstance(e.get("repo"), str) or not isinstance(e.get("working_repo"), str):
            corrupt += 1
            continue
        if working and e["working_repo"] != working:
            continue
        total += 1
        differ += e["repo"] != e["working_repo"]
    return differ, total, corrupt


def report(args: argparse.Namespace, deps: Deps, out: TextIO, err: TextIO) -> int:
    differ, total, corrupt = count_mismatches(deps.ledger, args.working_repo)
    if corrupt:
        output.write(err, f"safo-file: skipped {corrupt} corrupt ledger line(s)")
    output.write(out, f"cross-project issues: {differ} of {total}")
    return EXIT_OK


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="safo-file", description="idea gate and cross-project line for filing work")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="match an idea and require one answer")
    c.add_argument("idea")
    c.add_argument("--working-repo", required=True)
    c.add_argument("--answer", action="append", default=[], help=ANSWERS)
    c.add_argument("--owner-ok", action="store_true", help="the owner's explicit OK for a new project")
    c.add_argument("--timebox", default="30m", help="tangent time box, like 30m or 2h")
    c.add_argument("--parking", default="", help="the one parking-lot issue, owner/repo#N, to post a tangent to")
    i = sub.add_parser("issue", help="file one issue; another repo needs a cross-project line")
    i.add_argument("--repo", required=True)
    i.add_argument("--working-repo", required=True)
    i.add_argument("--title", required=True)
    i.add_argument("--body", required=True)
    i.add_argument("--allow-other-owner", action="store_true", help="allow a repo owned by someone else")
    r = sub.add_parser("report", help="count issues whose repo differs from the working repo")
    r.add_argument("--working-repo", default=None)
    for s in (c, i, r):
        s.add_argument("--ledger", default="", help="filing ledger (default: ~/.local/state/safo/file-ledger.jsonl)")
    return p


def _scrubbed(env: Mapping[str, str]) -> dict[str, str]:
    return {k: v for k, v in env.items() if k not in AMBIENT_GH_VARIABLES}


def _gh(
    env: Mapping[str, str], run: Callable[..., subprocess.CompletedProcess[str]], *argv: str, body: str = ""
) -> str:
    """One gh call: a fixed argument list, the body (if any) on stdin, no ambient token, bounded."""
    path = find_gh(env)
    if path is None:
        raise SafoError("gh must be on PATH")
    try:
        done = run(
            [path, *argv],
            input=body or None,
            stdin=None if body else subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=CALL_TIMEOUT,
            check=False,
            env=_scrubbed(env),
        )
    except subprocess.TimeoutExpired:
        raise SafoError(f"gh {argv[0]} {argv[1]} timed out") from None
    except (OSError, UnicodeError) as problem:
        raise SafoError(f"gh {argv[0]} {argv[1]} could not run: {type(problem).__name__}") from None
    if done.returncode != 0:
        raise SafoError(f"gh {argv[0]} {argv[1]} failed: {done.stderr.strip()[:200]}")
    return done.stdout


def run_memory(env: Mapping[str, str], idea: str) -> list[str]:
    """The pluggable memory search: `$SAFO_MEMORY_SEARCH -- <idea>`. At most MEMORY_CAP bytes are read, for at most
    MEMORY_TIMEOUT seconds; the child's whole process group is killed afterwards."""
    raw = env.get("SAFO_MEMORY_SEARCH")
    if raw is None or raw == "":
        return []
    try:
        cmd = shlex.split(raw)
    except ValueError:
        raise SafoError("SAFO_MEMORY_SEARCH cannot be parsed") from None
    if not cmd:
        raise SafoError("SAFO_MEMORY_SEARCH is blank")
    exe = cmd[0] if "/" in cmd[0] else shutil.which(cmd[0], path=env.get("PATH", ""))
    if not exe or not os.path.isfile(exe) or not os.access(exe, os.X_OK):
        raise SafoError("SAFO_MEMORY_SEARCH does not name an executable file")
    try:
        proc = subprocess.Popen(  # noqa: S603 - a fixed argument list, no shell; the idea follows `--`
            [exe, *cmd[1:], "--", idea],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_scrubbed(env),
            start_new_session=True,
        )
    except OSError as problem:
        raise SafoError(f"the memory command could not start: {problem.strerror}") from None
    if proc.stdout is None:
        raise SafoError("the memory command has no output pipe")
    data = b""
    capped = timed_out = False
    deadline = time.monotonic() + MEMORY_TIMEOUT
    try:
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                timed_out = True
                break
            if not select.select([proc.stdout], [], [], left)[0]:
                continue
            chunk = os.read(proc.stdout.fileno(), MEMORY_CAP + 1 - len(data))
            if not chunk:
                break
            data += chunk
            if len(data) > MEMORY_CAP:
                capped = True
                break
    finally:
        with contextlib.suppress(OSError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.stdout.close()
        proc.wait()
    if timed_out:
        raise SafoError("the memory command timed out")
    if not capped and proc.returncode not in (0, -signal.SIGKILL):
        raise SafoError("the memory command failed")
    return data[:MEMORY_CAP].decode("utf-8", "replace").splitlines()


def real_deps(args: argparse.Namespace, env: Mapping[str, str], now: dt.datetime) -> Deps:
    from safo.context import LocalContext
    from safo.localfiles import load_agents_for

    run = subprocess.run
    working = getattr(args, "working_repo", None) or ""
    owner = working.split("/")[0] if "/" in working else ""
    home = Path(env.get("HOME", str(Path.home())))
    ledger = Path(args.ledger) if args.ledger else home / ".local" / "state" / "safo" / "file-ledger.jsonl"

    def tracking() -> Sequence[str]:
        ns = argparse.Namespace(agents="", agents_local="")
        ctx = LocalContext(sys.stdout, env, now)
        return load_agents_for(ctx, ns).hooks.tracking_repos

    def gh_repos() -> list[tuple[str, str]]:
        if not owner:
            return []
        raw = _gh(env, run, "repo", "list", owner, "--limit", "200", "--json", "nameWithOwner,description")
        try:
            return [(x["nameWithOwner"], x.get("description") or "") for x in json.loads(raw)]
        except (ValueError, KeyError, TypeError, AttributeError):
            raise SafoError("gh repo list answered something unreadable") from None

    def create(repo: str, title: str, body: str) -> str:
        return _gh(env, run, "issue", "create", "--repo", repo, "--title", title, "--body-file", "-", body=body).strip()

    def comment(repo: str, number: int, body: str) -> None:
        _gh(env, run, "issue", "comment", str(number), "--repo", repo, "--body-file", "-", body=body)

    return Deps(tracking, gh_repos, lambda idea: run_memory(env, idea), create, comment, ledger)


def main(
    argv: Sequence[str] | None = None,
    *,
    deps: Deps | None = None,
    env: Mapping[str, str] | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
    now: dt.datetime | None = None,
) -> int:
    out, err = out or sys.stdout, err or sys.stderr
    env = os.environ if env is None else env
    now = now or dt.datetime.now(dt.UTC)
    try:
        args = parser().parse_args(argv)
        if args.cmd == "check" and not (TIMEBOX.fullmatch(args.timebox) and REPO.fullmatch(args.working_repo)):
            raise SafoError("--timebox must look like 30m or 2h, and --working-repo must be owner/name")
        if deps is None:
            deps = real_deps(args, env, now)
        elif getattr(args, "ledger", ""):
            deps.ledger = Path(args.ledger)
        if args.cmd == "check":
            return check(args, deps, out, err, now)
        if args.cmd == "issue":
            return file_issue(args, deps, out, err, now)
        return report(args, deps, out, err)
    except SafoError as problem:
        output.write(err, f"safo-file: {problem}")
        return EXIT_ERROR


def entry() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entry()
