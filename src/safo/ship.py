# SPDX-License-Identifier: Apache-2.0
"""safo-ship: the one tested merge watcher (issue #85). Wait for CI on an exact commit, then merge that commit.

A tool, not a guard: it reads and merges pull requests through `gh`, nothing more. It never touches the hooks, the
guard, or any settings file.

For each pull request, in order:

2. Wait, bounded (`--timeout`, `--max-polls`), until the check rollup is COMPLETE and every required check is
   present and succeeded on that commit. The required checks are `CI green` plus every context the base branch lists.
   succeeded on that commit. The required checks are `CI green` plus every context the base branch's protection lists.
   An empty rollup, a missing required check, or any run still queued or in progress is PENDING, never done.
3. A cancelled job is re-run once. A job whose only failed step is the approved egress canary (EX-0001) is re-run, at
   most twice per run. Any other failure is real and is never re-run.
4. Optionally (`--wait-for-review SECONDS`) wait, bounded, for the automated reviewer's review of the pinned head, then
   require 0 unresolved review threads; otherwise stop and list each (author, file:line, first 600 characters).
5. Merge with `--match-head-commit <pinned sha>`, retry once on "Base branch was modified", then read the state back.

`--open-pr` first pushes the branch (never forced), opens the pull request from `--title` and `--issue`, and pins the
pushed commit, then does the above.

Exit codes (several pull requests: the highest code wins):
    0 merged (or already merged)       4 head moved (the new head is printed)
    1 CI failed (a real failure)       5 timed out while still pending
    3 unresolved review threads        6 merge refused, or the read-back did not say MERGED
    7 an error: gh missing or failing, push or open failed, unreadable protection
    (argparse's 2 is a usage error)
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, TextIO

from safo import bounded, output
from safo.credentials import find_executable, find_gh

EXIT_MERGED = 0
EXIT_CI_FAILED = 1
EXIT_THREADS = 3
EXIT_HEAD_MOVED = 4
EXIT_TIMEOUT = 5
EXIT_MERGE_REFUSED = 6
EXIT_ERROR = 7

GATE = "CI green"
CANARY = "EX-0001"
CANCEL_RERUNS = 1  # per run
CANARY_RERUNS = 2  # per run
STALE_GRACE_POLLS = 3  # polls a just-re-run failure may still show before it counts again
CALL_TIMEOUT = 60
OK_REQUIRED = {"SUCCESS", "NEUTRAL", "SKIPPED"}
FAILING = {"FAILURE", "TIMED_OUT", "ACTION_REQUIRED", "STARTUP_FAILURE", "STALE", "ERROR"}
SHA = re.compile(r"[0-9a-f]{40}")
SLUG = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
BODY_LIMIT = 600  # characters of a review comment printed per thread; never more
MAX_WAIT_FOR_REVIEW = 900
REVIEWER_LOGINS = ("copilot-pull-request-reviewer", "copilot")  # the automated reviewer, compared without case
RUN_URL = re.compile(r"/actions/runs/(\d+)(?:/job/(\d+))?")

Run = Callable[..., Any]
Sleep = Callable[[float], None]
Clock = Callable[[], float]


class ShipError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Check:
    name: str
    names: frozenset[str]  # every spelling a required context may use for it
    done: bool
    outcome: str  # upper-case conclusion or state; "" while running
    run_id: str = ""
    job_id: str = ""
    url: str = ""


def clean(text: str, limit: int) -> tuple[str, bool]:
    """(`text` as one line without control or format characters, cut to `limit` characters; whether it was cut)."""
    kept = []
    for char in text:
        if char.isspace():
            kept.append(" ")
        elif unicodedata.category(char)[0] != "C":
            kept.append(char)
    flat = " ".join("".join(kept).split())
    return flat[:limit], len(flat) > limit


@dataclass(frozen=True)
class Thread:
    where: str  # path:line
    author: str
    url: str
    body: str  # already cleaned and cut to BODY_LIMIT
    cut: bool

    def lines(self) -> list[str]:
        shown = f"{self.body} [truncated]" if self.cut else self.body
        return [f"  {self.where} {self.url}".rstrip(), f'    {self.author or "?"}: "{shown}"']


@dataclass
class Result:
    code: int
    word: str
    detail: str = ""
    extra: list[str] = field(default_factory=list)


@dataclass
class Gh:
    """`gh` and `git` as fixed argument lists, no shell, stdin closed, output captured."""

    gh: str
    git: str
    env: Mapping[str, str]
    run: Run = subprocess.run
    cwd: str | None = None

    def _call(self, argv: list[str]) -> tuple[int, str, str]:
        try:
            done = self.run(
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=CALL_TIMEOUT,
                env=dict(self.env),
                cwd=self.cwd,
            )
        except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError) as error:
            return 127, "", f"{type(error).__name__}"
        return int(done.returncode), str(done.stdout or ""), str(done.stderr or "")

    def gh_call(self, *args: str) -> tuple[int, str, str]:
        return self._call([self.gh, *args])

    def git_call(self, *args: str) -> tuple[int, str, str]:
        return self._call([self.git, *args])

    def json(self, *args: str) -> Any:
        code, out, err = self.gh_call(*args)
        if code != 0:
            raise ShipError(EXIT_ERROR, f"gh {args[0]} {args[1] if len(args) > 1 else ''} failed: {err.strip()[:200]}")
        try:
            return bounded.loads(out)
        except ValueError as error:
            raise ShipError(EXIT_ERROR, f"gh {args[0]} gave unreadable JSON") from error


def parse_checks(rollup: Any) -> list[Check]:
    checks: list[Check] = []
    for item in rollup if isinstance(rollup, list) else []:
        if not isinstance(item, dict):
            continue
        if "context" in item and "name" not in item:  # a commit status
            state = str(item.get("state") or "").upper()
            name = str(item.get("context") or "")
            checks.append(Check(name, frozenset({name}), state not in {"PENDING", "EXPECTED", ""}, state))
            continue
        name = str(item.get("name") or "")
        workflow = str(item.get("workflowName") or "")
        status = str(item.get("status") or "").upper()
        url = str(item.get("detailsUrl") or "")
        found = RUN_URL.search(url)
        names = {name} | ({f"{workflow} / {name}"} if workflow else set())
        done = status == "COMPLETED"
        checks.append(
            Check(
                name,
                frozenset(names),
                done,
                str(item.get("conclusion") or "").upper() if done else "",
                found.group(1) if found else "",
                (found.group(2) or "") if found else "",
                url,
            )
        )
    return checks


def matches(check: Check, context: str) -> bool:
    if context in check.names:
        return True
    # only a bare name ("CI green") may be the tail of a "workflow / job" spelling; a qualified context is exact
    return " / " not in context and any(n.endswith(f" / {context}") for n in check.names)


@dataclass
class Verdict:
    state: str  # "pending" | "green" | "failed"
    why: str = ""
    failing: list[Check] = field(default_factory=list)


def judge(checks: list[Check], required: Sequence[str]) -> Verdict:
    """Pending unless the rollup is non-empty, complete, and carries every required check."""
    if not checks:
        return Verdict("pending", "no checks registered on this commit yet")
    running = [c.name for c in checks if not c.done]
    if running:
        return Verdict("pending", f"{len(running)} of {len(checks)} checks not complete ({', '.join(running[:3])})")
    absent = [r for r in required if not any(matches(c, r) for c in checks)]
    if absent:
        return Verdict("pending", f"required check not present yet: {', '.join(absent)}")
    bad = [c for c in checks if c.outcome in FAILING or c.outcome == "CANCELLED"]
    for ctx in required:
        for c in (x for x in checks if matches(x, ctx)):
            ok = c.outcome == "SUCCESS" if ctx == GATE else c.outcome in OK_REQUIRED
            if not ok and c not in bad:
                bad.append(c)
    if bad:
        return Verdict("failed", ", ".join(f"{c.name}={c.outcome or '?'}" for c in bad), bad)
    return Verdict("green")


def protection_contexts(data: Any) -> list[str]:
    """Every required context in a required_status_checks answer; any other shape is unreadable (fail closed)."""
    contexts = data.get("contexts") if isinstance(data, dict) else None
    checks = data.get("checks") if isinstance(data, dict) else None
    if (
        not isinstance(contexts, list)
        or not isinstance(checks, list)
        or not all(isinstance(c, str) and c for c in contexts)
        or not all(isinstance(c, dict) and isinstance(c.get("context"), str) and c["context"] for c in checks)
    ):
        raise ShipError(EXIT_ERROR, "unreadable required-checks answer")
    return [*contexts, *(c["context"] for c in checks)]


class Watcher:
    def __init__(
        self,
        gh: Gh,
        out: TextIO,
        *,
        timeout: float,
        interval: float,
        max_polls: int,
        method: str,
        delete_branch: bool,
        sleep: Sleep = time.sleep,
        clock: Clock = time.monotonic,
        wait_for_review: float = 0.0,
    ):
        self.wait_for_review = wait_for_review
        self.gh, self.out = gh, out
        self.timeout, self.interval, self.max_polls = timeout, interval, max_polls
        self.method, self.delete_branch = method, delete_branch
        self.sleep, self.clock = sleep, clock

    def say(self, line: str) -> None:
        output.write(self.out, line)

    # reads

    def view(self, repo: str, number: int) -> dict[str, Any]:
        data = self.gh.json(
            "pr",
            "view",
            str(number),
            "-R",
            repo,
            "--json",
            "state,headRefOid,baseRefName,statusCheckRollup,url",
        )
        if not isinstance(data, dict) or not SHA.fullmatch(str(data.get("headRefOid") or "")):
            raise ShipError(EXIT_ERROR, f"PR #{number}: no head commit in the answer")
        return data

    def required(self, repo: str, base: str) -> list[str]:
        code, out, err = self.gh.gh_call("api", f"repos/{repo}/branches/{base}/protection/required_status_checks")
        names = [GATE]
        if code != 0:
            if "404" in err or "Not Found" in err or "not protected" in err.lower():
                return names
            raise ShipError(EXIT_ERROR, f"cannot read the required checks of {base}: {err.strip()[:200]}")
        try:
            data = bounded.loads(out)
        except ValueError as error:
            raise ShipError(EXIT_ERROR, "unreadable required-checks answer") from error
        found = protection_contexts(data)
        for context in found:
            if context not in names:
                names.append(context)
        return names

    def threads(self, repo: str, number: int) -> list[Thread]:
        owner, name = repo.split("/", 1)
        query = (
            "query($owner:String!,$name:String!,$number:Int!,$cursor:String){repository(owner:$owner,name:$name)"
            "{pullRequest(number:$number){reviewThreads(first:100,after:$cursor){pageInfo{hasNextPage endCursor}"
            "nodes{isResolved path line comments(first:1){nodes{author{login} url body}}}}}}}"
        )
        unresolved: list[Thread] = []
        cursor = ""
        for _ in range(20):
            args = ["api", "graphql", "-f", f"query={query}", "-f", f"owner={owner}", "-f", f"name={name}"]
            args += ["-F", f"number={number}"] + (["-f", f"cursor={cursor}"] if cursor else [])
            data = self.gh.json(*args)
            try:
                block = data["data"]["repository"]["pullRequest"]["reviewThreads"]
                nodes = block["nodes"]
                more = bool(block["pageInfo"]["hasNextPage"])
                cursor = str(block["pageInfo"]["endCursor"] or "")
            except (KeyError, TypeError) as error:
                raise ShipError(EXIT_ERROR, "unreadable review-thread answer") from error
            for node in nodes:
                if isinstance(node, dict) and not node.get("isResolved"):
                    first = ((node.get("comments") or {}).get("nodes") or [{}])[0] or {}
                    where = clean(f"{node.get('path') or '?'}:{node.get('line') or '?'}", 300)[0]
                    author = clean(str((first.get("author") or {}).get("login") or ""), 100)[0]
                    body, cut = clean(str(first.get("body") or ""), BODY_LIMIT)
                    unresolved.append(Thread(where, author, clean(str(first.get("url") or ""), 300)[0], body, cut))
            if not more:
                return unresolved
        raise ShipError(EXIT_ERROR, "more than 2000 review threads: not read in full")

    def reviewed(self, repo: str, number: int, pin: str) -> bool:
        """True when the automated reviewer has a review on exactly the pinned commit (a read; REST)."""
        code, out, err = self.gh.gh_call(
            "api",
            f"repos/{repo}/pulls/{number}/reviews?per_page=100",
            "--paginate",
            "--jq",
            ".[] | {login: .user.login, commit: .commit_id}",
        )
        if code != 0:
            raise ShipError(EXIT_ERROR, f"cannot read the reviews of #{number}: {err.strip()[:200]}")
        for raw in out.splitlines():
            if not raw.strip():
                continue
            try:
                item = bounded.loads(raw)
                login, commit = str(item["login"] or "").lower(), str(item["commit"] or "")
            except (ValueError, KeyError, TypeError):
                raise ShipError(EXIT_ERROR, "unreadable reviews answer") from None
            if commit == pin and login.removesuffix("[bot]") in REVIEWER_LOGINS:
                return True
        return False

    def await_review(self, repo: str, number: int, pin: str, deadline: float) -> Result | None:
        """Wait for the automated reviewer's review of the pinned head, bounded by `--wait-for-review`, by `--timeout`
        (as `deadline`) and by `--max-polls`. It goes on either way, with a notice when none came; a moved head
        ends it."""
        if self.wait_for_review <= 0:
            return None
        end = min(deadline, self.clock() + self.wait_for_review)
        for poll in range(1, self.max_polls + 1):
            if end - self.clock() <= 0:  # no gh call is started after the deadline
                break
            head = str(self.view(repo, number)["headRefOid"])
            if head != pin:
                return Result(EXIT_HEAD_MOVED, "HEAD-MOVED", f"pinned {pin[:12]}, head is now {head}")
            if end - self.clock() <= 0:  # the head read used the rest of the time
                break
            if self.reviewed(repo, number, pin):
                return None
            left = end - self.clock()
            if left <= 0 or poll == self.max_polls:
                break
            self.sleep(min(self.interval, left))
        self.say(f"NOTICE no review by the automated reviewer on {pin[:12]} arrived within the wait; checking threads")
        return None

    # CI

    def canary_jobs(self, repo: str, run_id: str) -> dict[str, bool]:
        """{job id: True when every failed step of that job is the EX-0001 canary, and at least one failed}."""
        data = self.gh.json("run", "view", run_id, "-R", repo, "--json", "jobs")
        jobs: dict[str, bool] = {}
        for job in (data.get("jobs") or []) if isinstance(data, dict) else []:
            failed = [s for s in job.get("steps") or [] if str(s.get("conclusion") or "").lower() == "failure"]
            jobs[str(job.get("databaseId"))] = bool(failed) and all(CANARY in str(s.get("name")) for s in failed)
        return jobs

    def classify(self, repo: str, check: Check) -> str:
        """'cancelled', 'canary' or 'real' for one failed check."""
        if not check.run_id or not check.job_id:
            return "real"  # cannot name the job, so cannot prove it is safe to re-run
        if check.outcome == "CANCELLED":
            return "cancelled"
        if check.outcome != "FAILURE":
            return "real"
        return "canary" if self.canary_jobs(repo, check.run_id).get(check.job_id) else "real"

    def wait_ci(self, repo: str, number: int, pin: str) -> Result | None:
        """None when CI is green on `pin`; otherwise the Result that ends this PR."""
        start = self.clock()
        base = ""
        required: list[str] = []
        cancels: dict[str, int] = {}
        canaries: dict[str, int] = {}
        grace: dict[tuple[str, str], int] = {}
        last = ""
        for poll in range(1, self.max_polls + 1):
            data = self.view(repo, number)
            head = str(data["headRefOid"])
            if head != pin:
                return Result(EXIT_HEAD_MOVED, "HEAD-MOVED", f"pinned {pin[:12]}, head is now {head}")
            if data.get("state") == "MERGED":
                return Result(EXIT_MERGED, "MERGED", "already merged")
            if data.get("state") != "OPEN":
                return Result(EXIT_MERGE_REFUSED, "MERGE-REFUSED", f"pull request is {data.get('state')}")
            if not required:
                base = str(data.get("baseRefName") or "")
                required = self.required(repo, base)
            checks = parse_checks(data.get("statusCheckRollup"))
            verdict = judge(checks, required)
            if verdict.state == "green":
                return None
            if verdict.state == "failed":
                held = [c for c in verdict.failing if grace.get((c.name, c.url), 0) > 0]
                for c in held:
                    grace[(c.name, c.url)] -= 1
                if held:
                    last = f"waiting for the re-run of {', '.join(c.name for c in held)} to register"
                else:
                    ended = self.handle_failure(repo, verdict, cancels, canaries, grace)
                    if ended is not None:
                        return ended
                    last = "re-ran a job; waiting"
            else:
                last = verdict.why
            if poll == self.max_polls or self.clock() - start >= self.timeout:
                break
            self.sleep(self.interval)
        return Result(EXIT_TIMEOUT, "TIMEOUT", f"still pending after the wait: {last}")

    def handle_failure(
        self,
        repo: str,
        verdict: Verdict,
        cancels: dict[str, int],
        canaries: dict[str, int],
        grace: dict[tuple[str, str], int],
    ) -> Result | None:
        kinds = [(c, self.classify(repo, c)) for c in verdict.failing]
        # The gate fails or is skipped BECAUSE a job it needs was cancelled or hit the canary: re-running that job
        # re-runs the gate with it. Only the gate of the same run is excused, and only beside such a job.
        rerunnable = {c.run_id for c, kind in kinds if kind != "real"}
        excused = [c for c, k in kinds if k == "real" and matches(c, GATE) and c.run_id in rerunnable]
        kinds = [(c, k) for c, k in kinds if c not in excused]
        real = [c for c, kind in kinds if kind == "real"]
        if real:
            return Result(EXIT_CI_FAILED, "CI-FAILED", ", ".join(f"{c.name}={c.outcome or '?'}" for c in real))
        for c, kind in kinds:
            table = cancels if kind == "cancelled" else canaries
            cap = CANCEL_RERUNS if kind == "cancelled" else CANARY_RERUNS
            if table.get(c.run_id, 0) >= cap:
                return Result(EXIT_CI_FAILED, "CI-FAILED", f"{c.name}={c.outcome} again after {cap} re-run(s) ({kind})")
        for c, kind in kinds:
            table = cancels if kind == "cancelled" else canaries
            code, _out, err = self.gh.gh_call("run", "rerun", c.run_id, "-R", repo, "--job", c.job_id)
            if code != 0:
                return Result(EXIT_ERROR, "ERROR", f"re-run of {c.name} failed: {err.strip()[:200]}")
            table[c.run_id] = table.get(c.run_id, 0) + 1
            grace[(c.name, c.url)] = STALE_GRACE_POLLS
            self.say(f"  re-ran {c.name} ({kind}, run {c.run_id})")
        for c in excused:
            grace[(c.name, c.url)] = STALE_GRACE_POLLS
        return None

    # merge

    def merge(self, repo: str, number: int, pin: str) -> Result:
        flag = {"squash": "--squash", "merge": "--merge", "rebase": "--rebase"}[self.method]
        argv = ["pr", "merge", str(number), "-R", repo, flag, "--match-head-commit", pin]
        if self.delete_branch:
            argv.append("--delete-branch")
        for attempt in (1, 2):
            code, _out, err = self.gh.gh_call(*argv)
            if code == 0:
                break
            if attempt == 1 and "base branch was modified" in err.lower():
                self.sleep(self.interval)
                moved = self.view(repo, number)
                if str(moved["headRefOid"]) != pin:
                    return Result(
                        EXIT_HEAD_MOVED, "HEAD-MOVED", f"pinned {pin[:12]}, head is now {moved['headRefOid']}"
                    )
                continue
            return self.refused(repo, number, pin, err)
        state = self.view(repo, number).get("state")
        if state != "MERGED":
            return Result(EXIT_MERGE_REFUSED, "MERGE-REFUSED", f"merge accepted but the read-back says {state}")
        return Result(EXIT_MERGED, "MERGED", f"head={pin[:12]}")

    def refused(self, repo: str, number: int, pin: str, err: str) -> Result:
        """A merge gh refused: a head that moved since the pin is HEAD-MOVED with the new sha, else a plain refusal."""
        try:
            head = str(self.view(repo, number)["headRefOid"])
        except ShipError:
            head = pin
        if head != pin:
            return Result(EXIT_HEAD_MOVED, "HEAD-MOVED", f"pinned {pin[:12]}, head is now {head}")
        return Result(
            EXIT_MERGE_REFUSED, "MERGE-REFUSED", err.strip().splitlines()[0][:200] if err.strip() else "gh refused"
        )

    def one(self, repo: str, number: int, expect: str = "") -> Result:
        try:
            started = self.clock()
            pin = expect or str(self.view(repo, number)["headRefOid"])
            ended = self.wait_ci(repo, number, pin)
            if ended is not None:
                return ended
            ended = self.await_review(repo, number, pin, started + self.timeout)
            if ended is not None:
                return ended
            open_threads = self.threads(repo, number)
            if open_threads:
                return Result(
                    EXIT_THREADS,
                    "THREADS",
                    f"{len(open_threads)} unresolved review thread(s)",
                    [line for t in open_threads for line in t.lines()],
                )
            return self.merge(repo, number, pin)
        except ShipError as error:
            return Result(error.code, "ERROR", str(error))


def open_pr(gh: Gh, repo: str, branch: str, base: str, title: str, issue: str) -> tuple[int, str]:
    """Push `branch` (no force), open the PR unless one is open for it, and return (number, pushed commit)."""
    if branch in {"main", "master", base}:
        raise ShipError(EXIT_ERROR, f"refusing to ship from {branch}")
    code, sha, err = gh.git_call("rev-parse", branch)
    sha = sha.strip()
    if code != 0 or not SHA.fullmatch(sha):
        raise ShipError(EXIT_ERROR, f"cannot read branch {branch}: {err.strip()[:200]}")
    code, _o, err = gh.git_call("push", "-u", "origin", branch)
    if code != 0:
        raise ShipError(EXIT_ERROR, f"push failed: {err.strip()[:200]}")
    existing = gh.json("pr", "list", "-R", repo, "--head", branch, "--state", "open", "--json", "number")
    if isinstance(existing, list) and existing:
        return int(existing[0]["number"]), sha
    body = f"Closes {issue}"
    code, out, err = gh.gh_call(
        "pr", "create", "-R", repo, "--head", branch, "--base", base, "--title", title, "--body", body
    )
    found = re.search(r"/pull/(\d+)\s*$", out.strip())
    if code != 0 or not found:
        raise ShipError(EXIT_ERROR, f"opening the pull request failed: {err.strip()[:200]}")
    return int(found.group(1)), sha


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="safo-ship", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("pr", nargs="*", type=int, help="pull request number(s), merged in the order given")
    p.add_argument("--repo", default="", help="owner/name (default: the repository of the working directory)")
    p.add_argument("--expect-head", default="", help="pin this 40-hex commit instead of the first head read (one PR)")
    p.add_argument("--timeout", type=float, default=1800.0, help="seconds to wait per PR, at most 7200 (default 1800)")
    p.add_argument("--interval", type=float, default=20.0, help="seconds between polls, 1 to 300 (default 20)")
    p.add_argument("--max-polls", type=int, default=120, help="poll cap per PR, at most 1000 (default 120)")
    p.add_argument("--method", choices=("squash", "merge", "rebase"), default="squash")
    p.add_argument(
        "--wait-for-review",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="after CI is green, wait up to this long (0 to 900, default 0; within --timeout and --max-polls) for the "
        "automated reviewer's review of the pinned head before the thread check; then go on either way",
    )
    p.add_argument("--delete-branch", action="store_true")
    p.add_argument(
        "--open-pr", action="store_true", help="push the branch and open the PR first (needs --title, --issue)"
    )
    p.add_argument("--title", default="")
    p.add_argument("--issue", default="", help="N or owner/repo#N; the PR body says Closes <it>")
    p.add_argument("--branch", default="", help="branch to ship (default: the current branch)")
    p.add_argument("--base", default="main")
    p.add_argument("--workdir", default=None, help="git working directory for --open-pr (default: here)")
    return p


def validate(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.repo and not SLUG.fullmatch(args.repo):
        parser.error("--repo must be owner/name")
    if not 1 <= args.interval <= 300:
        parser.error("--interval must be 1 to 300")
    if not 1 <= args.timeout <= 7200:
        parser.error("--timeout must be 1 to 7200")
    if not 1 <= args.max_polls <= 1000:
        parser.error("--max-polls must be 1 to 1000")
    if not 0 <= args.wait_for_review <= MAX_WAIT_FOR_REVIEW:
        parser.error(f"--wait-for-review must be 0 to {MAX_WAIT_FOR_REVIEW}")
    if args.expect_head and (not SHA.fullmatch(args.expect_head) or len(args.pr) > 1 or args.open_pr):
        parser.error("--expect-head is one 40-hex commit for one existing PR")
    if args.branch and not BRANCH.fullmatch(args.branch):
        parser.error("--branch is not a plain branch name")
    if args.open_pr:
        if args.pr or not args.title.strip() or not re.fullmatch(r"(?:[\w.-]+/[\w.-]+)?#?\d+", args.issue.strip()):
            parser.error("--open-pr takes no PR number and needs --title and --issue (N or owner/repo#N)")
    elif not args.pr:
        parser.error("give a pull request number, or --open-pr")


def resolve_workdir(path: str | None) -> str:
    """The absolute real path (symlinks resolved) of --workdir, or of the current directory."""
    return os.path.realpath(path or os.getcwd())


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
    run: Run = subprocess.run,
    sleep: Sleep = time.sleep,
    clock: Clock = time.monotonic,
) -> int:
    env = os.environ if env is None else env
    out = out or sys.stdout
    err = err or sys.stderr
    parser = build_parser()
    args = parser.parse_args(argv)
    validate(args, parser)
    workdir = resolve_workdir(args.workdir)  # the trust root: no gh or git from inside it is ever chosen
    gh_path, git_path = find_gh(env, workdir), find_executable("git", env, workdir)
    if gh_path is None or git_path is None:
        output.write(err, "error: gh and git must be on PATH")
        return EXIT_ERROR
    gh = Gh(gh_path, git_path, env, run, workdir)
    watcher = Watcher(
        gh,
        out,
        timeout=args.timeout,
        interval=args.interval,
        max_polls=args.max_polls,
        method=args.method,
        delete_branch=args.delete_branch,
        sleep=sleep,
        clock=clock,
        wait_for_review=args.wait_for_review,
    )
    results: list[tuple[str, Result]] = []
    try:
        repo = args.repo or str(gh.json("repo", "view", "--json", "nameWithOwner")["nameWithOwner"])
        if not SLUG.fullmatch(repo):
            raise ShipError(EXIT_ERROR, "gh gave an unreadable repository name")
        if args.open_pr:
            branch = args.branch or gh.git_call("rev-parse", "--abbrev-ref", "HEAD")[1].strip()
            issue = args.issue.strip()
            issue = issue if "#" in issue and "/" in issue else f"#{issue.lstrip('#')}"
            number, sha = open_pr(gh, repo, branch, args.base, args.title.strip(), issue)
            targets = [(number, sha)]
        else:
            targets = [(n, args.expect_head) for n in args.pr]
    except ShipError as error:
        output.write(out, f"ERROR {error}")
        return error.code
    for number, expect in targets:
        result = watcher.one(repo, number, expect)
        results.append((f"{repo}#{number}", result))
        output.write(out, f"{result.word} {repo}#{number} {result.detail}".rstrip())
        for line in result.extra:
            output.write(out, line)
    return max((r.code for _n, r in results), default=EXIT_ERROR)


def wait_ci_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="safo-wait-ci",
        description="Wait for CI on one pull request or commit and print one result line. Read-only: it never merges. "
        "Exit codes as safo-ship (0 green, 1 CI failed, 4 head moved, 5 timed out, 7 error).",
    )
    p.add_argument("repo", help="owner/name")
    p.add_argument("target", help="a pull request number, or a 40-hex commit sha (pinned)")
    p.add_argument("--timeout", type=float, default=1800.0)
    p.add_argument("--interval", type=float, default=20.0)
    p.add_argument("--max-polls", type=int, default=120)
    p.add_argument("--workdir", default=None)
    return p


def wait_ci_main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
    run: Run = subprocess.run,
    sleep: Sleep = time.sleep,
    clock: Clock = time.monotonic,
) -> int:
    """`safo-wait-ci <owner/repo> <pr|sha>`: the safo-ship engine, stopping before the merge."""
    env = os.environ if env is None else env
    out = out or sys.stdout
    err = err or sys.stderr
    parser = wait_ci_parser()
    args = parser.parse_args(argv)
    if not SLUG.fullmatch(args.repo):
        parser.error("repo must be owner/name")
    if not (args.target.isdigit() or SHA.fullmatch(args.target)):
        parser.error("target must be a pull request number or a 40-hex commit sha")
    if not 1 <= args.interval <= 300 or not 1 <= args.timeout <= 7200 or not 1 <= args.max_polls <= 1000:
        parser.error("--interval is 1 to 300, --timeout 1 to 7200, --max-polls 1 to 1000")
    workdir = resolve_workdir(args.workdir)
    gh_path, git_path = find_gh(env, workdir), find_executable("git", env, workdir)
    if gh_path is None or git_path is None:
        output.write(err, "error: gh and git must be on PATH")
        return EXIT_ERROR
    gh = Gh(gh_path, git_path, env, run, workdir)
    watcher = Watcher(
        gh,
        out,
        timeout=args.timeout,
        interval=args.interval,
        max_polls=args.max_polls,
        method="squash",
        delete_branch=False,
        sleep=sleep,
        clock=clock,
    )
    try:
        if args.target.isdigit():
            number, pin = int(args.target), ""
        else:
            pin = args.target
            pulls = gh.json("api", f"repos/{args.repo}/commits/{pin}/pulls")
            open_ones = (
                [
                    p
                    for p in pulls
                    if isinstance(p, dict) and p.get("state") == "open" and (p.get("head") or {}).get("sha") == pin
                ]
                if isinstance(pulls, list)
                else []
            )
            if len(open_ones) != 1 or not isinstance(open_ones[0].get("number"), int):
                raise ShipError(EXIT_ERROR, f"{pin[:12]} is not the head of exactly one open pull request")
            number = open_ones[0]["number"]
        pin = pin or str(watcher.view(args.repo, number)["headRefOid"])
        ended = watcher.wait_ci(args.repo, number, pin)
    except ShipError as error:
        ended = Result(error.code, "ERROR", str(error))
        number = int(args.target) if args.target.isdigit() else 0
    if ended is None:
        ended = Result(EXIT_MERGED, "GREEN", f"head={pin[:12]}")
    output.write(out, f"{ended.word} {args.repo}#{number} {ended.detail}".rstrip())
    return ended.code


def run_wait_ci() -> None:
    raise SystemExit(wait_ci_main())


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
