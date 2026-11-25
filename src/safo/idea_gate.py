# SPDX-License-Identifier: Apache-2.0
"""safo-file: the idea gate and the cross-project line (issue #443), a wrapper in the style of `safo file` (#348).

A tool, not a guard: it never touches the dispatch guard, the hooks, `~/.config/safo` (it only READS agents.yaml
through the normal loader) or settings.json. It creates no repository, epic or card, ever.

    safo-file check IDEA --working-repo o/r [--answer ANSWER] [--owner-ok] [--timebox 30m] [--parking o/r#N]
    safo-file issue --repo o/r --working-repo o/r --title T --body B
    safo-file report [--working-repo o/r]

`check` matches the idea against `hooks.tracking_repos`, `gh repo list` and a pluggable memory search
(`$SAFO_MEMORY_SEARCH`: a command; the idea is its last argument; each output line is one hit), prints the top hits,
and requires exactly one ANSWER: `extends:<repo>`, `new-project` (needs `--owner-ok`) or `tangent` (prints one
parking-lot body with a time box; with `--parking` it posts that body as a comment on that one issue).

`issue` files one issue through `gh`. Filing in a repo other than the working repo needs a `cross-project: <reason>`
line in the body. Every filing is appended to a ledger; `report` counts, in code, those whose repo differs.

Exit codes: 0 done, 1 refused (a rule), 2 a bad command line or an error, 3 an answer is still needed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shlex
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from safo import output
from safo.credentials import find_gh
from safo.errors import SafoError

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_ERROR = 2
EXIT_NEEDS_ANSWER = 3

TOP = 5
CALL_TIMEOUT = 60
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}")
PARKING = re.compile(r"([A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100})#([1-9][0-9]{0,8})")
TIMEBOX = re.compile(r"[1-9][0-9]{0,2}[mh]")
CROSS = re.compile(r"^cross-project:[ \t]*(\S.*)$", re.MULTILINE)
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
        out.write(body)
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


def file_issue(args: argparse.Namespace, deps: Deps, out: TextIO, err: TextIO, now: dt.datetime) -> int:
    for name in (args.repo, args.working_repo):
        if not REPO.fullmatch(name):
            raise SafoError(f"expected owner/name, got {name!r}")
    cross = args.repo != args.working_repo
    reason = CROSS.search(args.body)
    if cross and not reason:
        output.write(
            err,
            f"refused: {args.repo} is not the working repo {args.working_repo}; "
            "the body needs a `cross-project: <reason>` line",
        )
        return EXIT_REFUSED
    url = deps.create_issue(args.repo, args.title, args.body)
    entry = {"ts": now.isoformat(), "repo": args.repo, "working_repo": args.working_repo, "url": url}
    deps.ledger.parent.mkdir(parents=True, exist_ok=True)
    with deps.ledger.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    output.write(out, url)
    return EXIT_OK


def count_mismatches(ledger: Path, working: str | None) -> tuple[int, int]:
    """(issues whose repo differs from the working repo, all issues), optionally for one working repo."""
    total = differ = 0
    if not ledger.exists():
        return 0, 0
    for raw in ledger.read_text(encoding="utf-8").splitlines():
        try:
            e = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(e, dict) or (working and e.get("working_repo") != working):
            continue
        total += 1
        differ += e.get("repo") != e.get("working_repo")
    return differ, total


def report(args: argparse.Namespace, deps: Deps, out: TextIO) -> int:
    differ, total = count_mismatches(deps.ledger, args.working_repo)
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
    r = sub.add_parser("report", help="count issues whose repo differs from the working repo")
    r.add_argument("--working-repo", default=None)
    for s in (c, i, r):
        s.add_argument("--ledger", default="", help="filing ledger (default: ~/.local/state/safo/file-ledger.jsonl)")
    return p


def _gh(env: Mapping[str, str], run: Callable[..., subprocess.CompletedProcess[str]], *argv: str) -> str:
    path = find_gh(env)
    if path is None:
        raise SafoError("gh must be on PATH")
    done = run([path, *argv], capture_output=True, text=True, timeout=CALL_TIMEOUT, check=False, env=dict(env))
    if done.returncode != 0:
        raise SafoError(f"gh {argv[0]} {argv[1]} failed: {done.stderr.strip()[:200]}")
    return done.stdout


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
        return [(x["nameWithOwner"], x.get("description") or "") for x in json.loads(raw)]

    def memory(idea: str) -> list[str]:
        cmd = env.get("SAFO_MEMORY_SEARCH", "")
        if not cmd:
            return []
        done = run([*shlex.split(cmd), idea], capture_output=True, text=True, timeout=CALL_TIMEOUT, check=False)
        return done.stdout.splitlines() if done.returncode == 0 else []

    def create(repo: str, title: str, body: str) -> str:
        return _gh(env, run, "issue", "create", "--repo", repo, "--title", title, "--body", body).strip()

    def comment(repo: str, number: int, body: str) -> None:
        _gh(env, run, "issue", "comment", str(number), "--repo", repo, "--body", body)

    return Deps(tracking, gh_repos, memory, create, comment, ledger)


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
        return report(args, deps, out)
    except SafoError as problem:
        output.write(err, f"safo-file: {problem}")
        return EXIT_ERROR


def entry() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entry()
