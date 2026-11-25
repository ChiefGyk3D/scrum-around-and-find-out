# SPDX-License-Identifier: Apache-2.0
"""safo-file: the idea gate and the cross-project line (issue #443), a wrapper in the style of `safo file` (#348).

A tool, not a guard, and ADVISORY by design for same-repo filing: nothing forces an agent to run `check` first, and a
same-repo `issue` works without it (owner decision: the gate is for new ideas and cross-repo filing). Routing a direct
`gh issue create` here is a follow-up in the frozen guard's territory, not in this module. It never touches the
dispatch guard, the hooks, `~/.config/safo` (it only READS the one file `~/.config/safo/agents.yaml`, through the
shared loader, with no override and no environment redirect) or settings.json. It creates no repository, epic or
card, ever.

    safo-file check IDEA --working-repo o/r [--answer ANSWER] [--owner-ok] [--timebox 30m]
                     [--parking o/r#N | --parking-number N]
    safo-file issue --repo o/r --working-repo o/r --title T --body B [--allow-other-owner]
                    [--class NAME] [--allow-public]
    safo-file route DESCRIPTION --working-repo o/r [--class NAME]
    safo-file report [--working-repo o/r]

`check` matches the idea against `hooks.tracking_repos`, `gh repo list` and a pluggable memory search
(`$SAFO_MEMORY_SEARCH`: a command that is run as `<command> -- <idea>`; each output line is one hit), prints the top
hits, and requires exactly one ANSWER: `extends:<repo>`, `new-project` (needs `--owner-ok`) or `tangent` (prints one
parking-lot body with a time box; with `--parking` it posts that body as a comment on that one issue).

`issue` files one issue through `gh` (the body goes over stdin, never argv). Filing in a repo other than the working
repo needs a `cross-project: <reason>` line in the body. The ledger gets a `pending` record BEFORE the issue is created
and a `committed` record (with the URL) after; `report` counts, in code, the committed filings whose repo differs and
names the pending ones that never committed.

`route` prints the destination repo for a piece of work and why (the routing table of issue #455, in
`safo.idea_gate_routes`; matching is by keyword and path hint, never a model) and records the decision in the ledger
as a `routed` record. Exit 3 means the class could not be decided and the destination is only the default. `issue`
refuses a private-workflow class (homelab, ai-tooling, research, tangent, or any class the routes file marks private)
in a public repo unless `--allow-public` and a `public-ok: <reason>` body line are both given; whether the repo is
public comes from `gh api` and a failed lookup refuses (exit 2).

ENFORCED here: `issue` in another repo needs a non-empty `cross-project: <reason>` line (outside a code fence) and
`--allow-other-owner` when the owner differs; the ledger is opened and checked before the issue is created; `check`
needs exactly one answer; `new-project` needs `--owner-ok`; `gh` and the memory command run only from a trusted
absolute path, with an allowlisted environment, bounded output and a time limit (idea_gate_io.py). NOT enforced: that
`check` ran, that the reason is true (the line is a reminder, not an adversary-proof control), and anything an agent
does by calling `gh` directly. See docs/file.md.

Exit codes: 0 done, 1 refused (a rule), 2 a bad command line or an error, 3 an answer is still needed.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import os
import re
import secrets
import shlex
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from safo import bounded, output
from safo import idea_gate_io as gio
from safo import idea_gate_routes as routes
from safo.agentsfile import load_agents_merged
from safo.credentials import find_gh
from safo.errors import SafoError
from safo.idea_gate_routes import is_repo
from safo.localfiles import refuse_workspace
from safo.trust import read_trusted_regular_file

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_ERROR = 2
EXIT_NEEDS_ANSWER = 3

TOP = 5
CALL_TIMEOUT = 60
MEMORY_TIMEOUT = 10
MEMORY_CAP = 65_536  # bytes read from the memory command, never more
GH_OUT_CAP = 1_048_576
GH_ERR_CAP = 65_536
URL_SHOWN = 2_000  # characters of a returned URL that are shown and recorded
LEDGER_LIMIT = 8 * 1024 * 1024
NUMBER = re.compile(r"[1-9][0-9]{0,8}")
TIMEBOX = re.compile(r"[1-9][0-9]{0,2}[mh]")
CROSS = re.compile(r"^cross-project:[ \t]*(\S.*)$", re.MULTILINE)
PUBLIC_OK = re.compile(r"^public-ok:[ \t]*(\S.*)$", re.MULTILINE)
PLACEHOLDER_WORDS = frozenset({"todo", "tbd", "none", "na", "n", "a", "ok", "yes", "no", "test", "tests", "x"})
REASON_MIN = 12
OVERRIDE_HELP = "pass --allow-public and put a `public-ok: <reason>` line in the body"
REASON_HELP = (
    f"the public-ok reason must be at least {REASON_MIN} characters with at least two different words that are not "
    "placeholders (TODO, TBD, none, n/a, ok, yes, test)"
)
DESCRIPTION_LIMIT = 2_000
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
WORD = re.compile(r"[a-z0-9]{3,}")
ANSWERS = "extends:<repo>, new-project, tangent"

write_fd = os.write  # the ledger's write call; a test replaces it to make a short or a failing write


def same_repo(a: str, b: str) -> bool:
    return a.lower() == b.lower()


@dataclass
class Deps:
    """Everything that leaves the process. Tests pass fakes; `real_deps` builds the live ones."""

    tracking: Callable[[], Sequence[str]]
    gh_repos: Callable[[], Sequence[tuple[str, str]]]  # (owner/name, description)
    memory: Callable[[str], Sequence[str]]
    create_issue: Callable[[str, str, str], str]  # repo, title, body -> url
    comment: Callable[[str, int, str], None]  # repo, issue number, body
    ledger: Path
    routes: Callable[[], routes.RouteTable] = routes.default_table
    is_public: Callable[[str], bool] | None = None  # True when the repo is public; raises SafoError on any doubt


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
        if not is_repo(repo):
            raise SafoError(f"extends needs a repository as owner/name, got {repo!r}")
        if repo.lower() not in {k.lower() for k in known}:
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
        parking = args.parking
        if args.parking_number:
            if parking:
                raise SafoError("give --parking or --parking-number, not both")
            if not NUMBER.fullmatch(args.parking_number):
                raise SafoError("--parking-number must be an issue number")
            parking = f"{deps.routes().fallback.repo}#{args.parking_number}"
        if parking:
            target, _, number = parking.rpartition("#")
            if not (is_repo(target) and NUMBER.fullmatch(number)):
                raise SafoError("--parking must be owner/repo#N")
            deps.comment(target, int(number), body)
            output.write(out, f"posted to {parking}")
        else:
            output.write(
                out, f"parking-lot repo: {deps.routes().fallback.repo} (pass --parking-number N to post to that issue)"
            )
    return EXIT_OK


def _show(out: TextIO, hits: Sequence[tuple[int, str, str]]) -> None:
    for score, name, desc in hits:
        output.write(out, f"  - {name} (match {score}){': ' + desc if desc else ''}")
    if not hits:
        output.write(out, "  (none)")


def outside_fences(body: str) -> str:
    """The body without fenced code blocks, so a quoted line cannot count. A fence is closed only by the same
    character, at least as long as the opener, with nothing after it; an unclosed fence runs to the end."""
    kept: list[str] = []
    char, length = "", 0
    for text in body.splitlines():
        m = FENCE.match(text)
        if char:
            if m and m.group(1)[0] == char and len(m.group(1)) >= length and not m.group(2).strip():
                char = ""
            continue
        if m and not (m.group(1)[0] == "`" and "`" in m.group(2)):  # a backtick fence's info text has no backtick
            char, length = m.group(1)[0], len(m.group(1))
            continue
        kept.append(text)
    return "\n".join(kept)


def record(state: str, rid: str, args: argparse.Namespace, now: dt.datetime, **extra: str) -> bytes:
    entry = {"state": state, "id": rid, "ts": now.isoformat(), "repo": args.repo, "working_repo": args.working_repo}
    return (json.dumps({**entry, **extra}) + "\n").encode()


def public_ok_reason(body: str) -> tuple[bool, str]:
    """(a valid reason line is present, why not). The line is `public-ok: <reason>` outside a code fence; the first
    valid one counts. A reason is real when it has REASON_MIN characters and two different words that are not
    placeholders."""
    reasons = [m.group(1).strip() for m in PUBLIC_OK.finditer(outside_fences(body))]
    if not reasons:
        return False, ""
    for reason in reasons:
        words = set(re.findall(r"[^\W\d_]+", reason.casefold())) - PLACEHOLDER_WORDS
        if len(reason) >= REASON_MIN and len(words) >= 2 and len(set(reason.replace(" ", ""))) >= 3:
            return True, ""
    return False, REASON_HELP


def routed_record(
    rid: str, now: dt.datetime, repo: str, working: str, cls: str, how: str, matched: Sequence[str],
    decided: bool, **extra: str,
) -> bytes:  # fmt: skip
    """The ledger record of one routing decision (its own record type, `routed`). The description is never stored."""
    entry = {
        "state": "routed", "id": rid, "ts": now.isoformat(), "repo": repo, "working_repo": working,
        "class": cls, "how": how, "matched": list(matched[: routes.MATCHED_SHOWN]), "decided": decided,
    }  # fmt: skip
    return (json.dumps({**entry, **extra}) + "\n").encode()


def append(fd: int, data: bytes, what: str) -> None:
    try:
        gio.write_all(fd, data, write_fd)
    except OSError as problem:
        raise SafoError(f"the ledger cannot be written ({problem}); {what}") from None


def route_cmd(args: argparse.Namespace, deps: Deps, out: TextIO, now: dt.datetime) -> int:
    d = routes.decide(deps.routes(), args.description, args.route_class, args.working_repo, deps.tracking)
    fd = gio.open_ledger(deps.ledger)
    try:
        record_bytes = routed_record(
            secrets.token_hex(8), now, d.repo, args.working_repo, d.cls.name, d.how, d.matched, d.decided
        )
        append(fd, record_bytes, "the decision was not recorded")
    finally:
        os.close(fd)
    output.write(out, f"destination: {d.repo}" + ("" if d.decided else " (default only)"))
    output.write(out, f"class: {d.cls.name}" + ("" if d.decided else " (not decided)"))
    output.write(out, f"reason: {d.reason}")
    return EXIT_OK if d.decided else EXIT_NEEDS_ANSWER


def issue_verdict(args: argparse.Namespace, deps: Deps) -> tuple[str, str, tuple[str, ...], str]:
    """(class name, how it was decided, what matched, why a PUBLIC target would be refused or "" when it would not).
    A public target takes work only when no private class matches the whole text, the text is small enough to scan,
    and the work is positively product: `--class product`, or the target is the working repo."""
    table = deps.routes()
    explicit = routes.find_class(table, args.route_class) if args.route_class else None
    text = f"{args.title}\n{args.body}"
    if len(text) > routes.TEXT_LIMIT:
        return (explicit.name if explicit else "unclassified"), "unclassified", (), "the text is too large to classify"
    private = [(c, m) for c, m in routes.matching(table, text) if c.private]
    if explicit is not None and explicit.private:
        return explicit.name, "explicit", (), f"{explicit.name} is a private-workflow class"
    if private:
        names = ", ".join(c.name for c, _ in private)
        terms = tuple(t for _, m in private for t in m)
        return private[0][0].name, "matched", terms, f"private-workflow wording matched ({names})"
    if (explicit is not None) or same_repo(args.repo, args.working_repo):
        return routes.PRODUCT, "explicit" if explicit else "working-repo", (), ""
    return (
        "unclassified",
        "unclassified",
        (),
        "the work is not positively product (use --class product or the working repo)",
    )


def file_issue(args: argparse.Namespace, deps: Deps, out: TextIO, err: TextIO, now: dt.datetime) -> int:
    for name in (args.repo, args.working_repo):
        if not is_repo(name):
            raise SafoError(f"expected owner/name, got {name!r}")
    cross = not same_repo(args.repo, args.working_repo)
    other_owner = not same_repo(args.repo.split("/")[0], args.working_repo.split("/")[0])
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
    verdict = issue_verdict(args, deps)
    fd = gio.open_ledger(deps.ledger)
    rid = secrets.token_hex(8)
    try:
        if deps.is_public is None:
            raise SafoError(f"cannot tell whether {args.repo} is public; nothing was filed")
        cls, how, matched, why = verdict
        reason_ok, reason_problem = public_ok_reason(args.body) if args.allow_public else (False, "")
        outcome = "private-repo"
        if deps.is_public(args.repo):  # a live lookup for every filing; any doubt raises and nothing is filed
            outcome = "public-product" if not why else ("override" if reason_ok else "refused")
        if outcome != "private-repo":  # the decisions that matter are the ones about a public target
            routed = routed_record(rid, now, args.repo, args.working_repo, cls, how, matched, True, outcome=outcome)
            append(fd, routed, "nothing was filed")
        if outcome == "refused":
            output.write(err, f"refused: {args.repo} is public and {why}; {reason_problem or OVERRIDE_HELP}")
            return EXIT_REFUSED
        try:
            gio.write_all(fd, record("pending", rid, args, now), write_fd)
        except OSError as problem:
            raise SafoError(f"the ledger cannot be written ({problem}); nothing was filed") from None
        # The lookup and the create are adjacent, so the window in which the repo can turn public is as small as it
        # can be made; it cannot be closed (docs/file.md). A repo that is public now needs the same decision again.
        public_now = deps.is_public(args.repo)
        if public_now and why and outcome != "override":
            output.write(
                err, f"refused: {args.repo} became public just before filing; {reason_problem or OVERRIDE_HELP}"
            )
            return EXIT_REFUSED
        url = deps.create_issue(args.repo, args.title, args.body)[:URL_SHOWN]
        try:
            gio.write_all(fd, record("committed", rid, args, now, url=url), write_fd)
        except OSError as problem:
            output.write(err, f"safo-file: the issue was created but not recorded in the ledger ({problem}): {url}")
            return EXIT_ERROR
        if why and not public_now:  # private-workflow work: look once more, right after the create
            try:
                exposed = deps.is_public(args.repo)
            except SafoError:
                output.write(err, f"safo-file: the issue was created ({url}) but its visibility could not be checked")
                return EXIT_ERROR
            if exposed:
                output.write(err, f"safo-file: EXPOSED: {args.repo} became public while this issue was filed: {url}")
                with contextlib.suppress(SafoError):  # the error line is out; the record is best effort
                    exposure = routed_record(
                        rid, now, args.repo, args.working_repo, cls, how, matched, True, outcome="exposed"
                    )
                    append(fd, exposure, "the exposure was not recorded")
                return EXIT_ERROR
    finally:
        os.close(fd)
    output.write(out, url)
    return EXIT_OK


def count_mismatches(ledger: Path, working: str | None) -> tuple[int, int, int, int]:
    """(committed issues whose repo differs from the working repo, all committed issues, corrupt lines skipped,
    pending records that never committed), optionally for one working repo. A missing ledger is zero; an unreadable,
    linked, non-regular or oversize one is a SafoError."""
    if not ledger.is_symlink() and not ledger.exists():
        return 0, 0, 0, 0
    text = read_trusted_regular_file(ledger, LEDGER_LIMIT).decode("utf-8", "replace")
    total = differ = corrupt = 0
    pending: set[str] = set()
    committed: set[str] = set()
    for raw in text.splitlines():
        if not raw.strip():
            continue
        try:
            e = bounded.loads(raw)
        except (ValueError, RecursionError):
            e = None
        ok = (
            isinstance(e, dict)
            and e.get("state") in ("pending", "committed", "routed")
            and isinstance(e.get("id"), str)
            and isinstance(e.get("repo"), str)
            and isinstance(e.get("working_repo"), str)
        )
        if not ok:
            corrupt += 1
            continue
        if working and not same_repo(e["working_repo"], working):
            continue
        if e["state"] == "routed":
            continue  # a routing decision, not a filing
        if e["state"] == "pending":
            pending.add(e["id"])
            continue
        committed.add(e["id"])
        total += 1
        differ += not same_repo(e["repo"], e["working_repo"])
    return differ, total, corrupt, len(pending - committed)


def report(args: argparse.Namespace, deps: Deps, out: TextIO, err: TextIO) -> int:
    differ, total, corrupt, pending = count_mismatches(deps.ledger, args.working_repo)
    if corrupt:
        output.write(err, f"safo-file: skipped {corrupt} corrupt ledger line(s)")
    if pending:
        output.write(err, f"safo-file: {pending} pending ledger record(s) never committed (an issue may exist)")
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
    c.add_argument("--parking-number", default="", help="that issue's number in the table's tangent repo (workbench)")
    i = sub.add_parser("issue", help="file one issue; another repo needs a cross-project line")
    i.add_argument("--repo", required=True)
    i.add_argument("--working-repo", required=True)
    i.add_argument("--title", required=True)
    i.add_argument("--body", required=True)
    i.add_argument("--allow-other-owner", action="store_true", help="allow a repo owned by someone else")
    i.add_argument("--class", dest="route_class", default="", help="the work's class (default: matched from the text)")
    i.add_argument("--allow-public", action="store_true", help="allow private-workflow work in a public repo")
    t = sub.add_parser("route", help="print the destination repo for a piece of work and why")
    t.add_argument("description")
    t.add_argument("--working-repo", required=True)
    t.add_argument("--class", dest="route_class", default="", help="decide the class yourself")
    r = sub.add_parser("report", help="count issues whose repo differs from the working repo")
    r.add_argument("--working-repo", default=None)
    for s in (c, i, r, t):
        s.add_argument("--ledger", default="", help="filing ledger (default: ~/.local/state/safo/file-ledger.jsonl)")
    return p


def _text(data: bytes) -> str:
    return data.decode("utf-8", "replace")


def _gh(env: Mapping[str, str], *argv: str, body: str = "") -> str:
    """One gh call: a trusted absolute executable, an allowlisted environment, the body (if any) on stdin, bounded
    output and time, the whole process group gone afterwards."""
    cenv = gio.child_env(env, "gh")
    found = find_gh(gio.lookup_env(env))
    if found is None:
        raise gio.explain_missing("gh", env, "gh")
    path = gio.trusted_executable(found, "gh")
    ran = gio.run_bounded(
        [path, *argv], env=cenv, stdin_text=body, out_cap=GH_OUT_CAP, err_cap=GH_ERR_CAP, timeout=CALL_TIMEOUT
    )
    what = f"gh {argv[0]} {argv[1]}"
    if ran.timed_out:
        raise SafoError(f"{what} timed out")
    if ran.out_capped or ran.err_capped:
        raise SafoError(f"{what} wrote more output than the limit")
    if ran.rc != 0:
        raise SafoError(f"{what} failed: {_text(ran.err).strip()[:200]}")
    return _text(ran.out)


def run_memory(env: Mapping[str, str], idea: str) -> list[str]:
    """The pluggable memory search: `$SAFO_MEMORY_SEARCH -- <idea>`, from a trusted absolute path, with an allowlisted
    environment; at most MEMORY_CAP bytes read, for at most MEMORY_TIMEOUT seconds."""
    raw = env.get("SAFO_MEMORY_SEARCH")
    if raw is None or raw == "":
        return []
    try:
        cmd = shlex.split(raw)
    except ValueError:
        raise SafoError("SAFO_MEMORY_SEARCH cannot be parsed") from None
    if not cmd:
        raise SafoError("SAFO_MEMORY_SEARCH is blank")
    exe = gio.resolve_command(cmd[0], env, "the SAFO_MEMORY_SEARCH command")
    ran = gio.run_bounded(
        [exe, *cmd[1:], "--", idea],
        env=gio.child_env(env, "memory"),
        out_cap=MEMORY_CAP,
        err_cap=0,
        timeout=MEMORY_TIMEOUT,
    )
    if ran.timed_out:
        raise SafoError("the memory command timed out")
    if not ran.out_capped and ran.rc != 0:
        raise SafoError("the memory command failed")
    return _text(ran.out).splitlines()


def real_deps(args: argparse.Namespace, env: Mapping[str, str], now: dt.datetime) -> Deps:
    working = getattr(args, "working_repo", None) or ""
    owner = working.split("/")[0] if "/" in working else ""
    home = Path(env.get("HOME", str(Path.home())))
    ledger = Path(args.ledger) if args.ledger else home / ".local" / "state" / "safo" / "file-ledger.jsonl"

    def tracking() -> Sequence[str]:
        # the one fixed file: no $SAFO_AGENTS, no local override, no merge
        path = refuse_workspace(home / ".config" / "safo" / "agents.yaml", env, "the agents file", explicit=False)
        return list(dict.fromkeys(load_agents_merged(path, None).hooks.tracking_repos))

    def gh_repos() -> list[tuple[str, str]]:
        if not owner:
            return []
        raw = _gh(env, "repo", "list", owner, "--limit", "200", "--json", "nameWithOwner,description")
        try:
            return [(x["nameWithOwner"], x.get("description") or "") for x in bounded.loads(raw)]
        except (ValueError, RecursionError, KeyError, TypeError, AttributeError):
            raise SafoError("gh repo list answered something unreadable") from None

    def create(repo: str, title: str, body: str) -> str:
        done = _gh(env, "issue", "create", "--repo", repo, "--title", title, "--body-file", "-", body=body)
        lines = [x for x in done.splitlines() if x.strip()]
        return lines[-1].strip() if lines else ""

    def comment(repo: str, number: int, body: str) -> None:
        _gh(env, "issue", "comment", str(number), "--repo", repo, "--body-file", "-", body=body)

    def fetch_public(repo: str) -> bool:  # live, once per filing; there is no cache
        raw = _gh(env, "api", f"repos/{repo}", "--jq", ".private").strip()
        if raw not in ("true", "false"):
            raise SafoError(f"gh api answered something unreadable about {repo}; refusing")
        return raw == "false"

    return Deps(
        tracking,
        gh_repos,
        lambda idea: run_memory(env, idea),
        create,
        comment,
        ledger,
        routes=lambda: routes.load_table(str(home)),
        is_public=fetch_public,
    )


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
        if args.cmd == "check" and not (TIMEBOX.fullmatch(args.timebox) and is_repo(args.working_repo)):
            raise SafoError("--timebox must look like 30m or 2h, and --working-repo must be owner/name")
        if args.cmd == "route" and not is_repo(args.working_repo):
            raise SafoError("--working-repo must be owner/name")
        if args.cmd == "route" and len(args.description) > DESCRIPTION_LIMIT:
            raise SafoError(f"the description is longer than {DESCRIPTION_LIMIT} characters")
        if deps is None:
            deps = real_deps(args, env, now)
        elif getattr(args, "ledger", ""):
            deps.ledger = Path(args.ledger)
        if args.cmd == "check":
            return check(args, deps, out, err, now)
        if args.cmd == "issue":
            return file_issue(args, deps, out, err, now)
        if args.cmd == "route":
            return route_cmd(args, deps, out, now)
        return report(args, deps, out, err)
    except SafoError as problem:
        output.write(err, f"safo-file: {problem}")
        return EXIT_ERROR


def entry() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entry()
