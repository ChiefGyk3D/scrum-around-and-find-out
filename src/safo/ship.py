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
   `--queue` (issue #586): the pull requests are taken one at a time, and the queue stops at the first one that does
   not merge (later ones print SKIPPED and are never read). A head the API shows late (`--pin N=SHA`) is re-read for
   up to HEAD_LAG_POLLS polls before HEAD-MOVED. A branch that is BEHIND gets update-branch once (guarded with
   expected_head_sha), then the new head is pinned and CI is waited for again. A conflict is CONFLICT (8).
5. Merge with `--match-head-commit <pinned sha>`, retry once on "Base branch was modified", then read the state back.

`--open-pr` first pushes the branch (never forced), opens the pull request from `--title` and `--issue`, and pins the
pushed commit, then does the above.

Exit codes (several pull requests: the highest code wins):
    0 merged (or already merged)       4 head moved (the new head is printed)
    1 CI failed (a real failure)       5 timed out while still pending
    3 unresolved review threads        6 merge refused, or the read-back did not say MERGED
    7 an error: gh missing or failing, push or open failed, unreadable protection
    8 conflict (queue mode only)       9 branch protection refused the merge (queue mode only)
   10 NEEDS-HUMAN: the pull request changes a workflow file (never merged automatically)
    (argparse's 2 is a usage error)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, TextIO
from urllib.parse import quote

import yaml

from safo import bounded, output, shipscan
from safo.credentials import find_executable, find_gh

EXIT_MERGED = 0
EXIT_CI_FAILED = 1
EXIT_THREADS = 3
EXIT_HEAD_MOVED = 4
EXIT_TIMEOUT = 5
EXIT_MERGE_REFUSED = 6
EXIT_ERROR = 7
EXIT_CONFLICT = 8  # queue mode: the pull request conflicts with its base; an agent must resolve it
EXIT_PROTECTED = 9  # queue mode: branch protection refused the merge
EXIT_NEEDS_HUMAN = 10  # the pull request changes a workflow file: never merged automatically
GITHUB_DIR = ".github/"  # any change under it needs a human: local actions and reusable workflows live here
GATE_RUN_EVENTS = ("pull_request", "push")  # events a trusted gate run may come from
USES_TOKEN = re.compile(r"(?<![\w-])uses(?![\w-])")  # the simple second scan: every word `uses`, comments left out
COMMENT = re.compile(r"(?:^|[ \t])#.*$", re.MULTILINE)
MAX_WORKFLOW_BYTES = 262144  # a workflow file larger than this is not read
MAX_FILES = 20  # workflow, action and script files read for one gate
MAX_EXEC_FILES = 40  # repository files a gate runs that are compared
MAX_SCRIPT_BYTES = 65536  # a script larger than this is not read
RECOVERY_SECONDS = 30.0  # the read that settles what a merge call did may run this long past the deadline
TOO_MANY = "too many references or nesting too deep to verify"
PINNED_REF = re.compile(r"[^@\s]+@[0-9a-f]{40}")
DOCKER_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
MAX_REFS = 50  # `uses:` lines read per workflow file
MAX_DEPTH = 3  # local workflows followed
COMPARE_CAP = 300  # the compare API lists at most 300 files: that many or more cannot prove "no workflow changed"

GATE = "CI green"
CANARY = "EX-0001"
CANCEL_RERUNS = 1  # per run
CANARY_RERUNS = 2  # per run
STALE_GRACE_POLLS = 3  # polls a just-re-run failure may still show before it counts again
CALL_TIMEOUT = 60
GATE_APP_ID = 15368  # the GitHub Actions app: the default source of the `CI green` check run
MAX_TOTAL_TIMEOUT = 28800
HEAD_LAG_POLLS = 6  # queue mode: reads of the head, at --interval, while the API still shows an older commit
UPDATE_WAIT_POLLS = 10  # queue mode: reads after update-branch, at --interval, for the head to change
PROTECTED_WORDS = ("policy", "protect", "required status", "required review", "not mergeable", "blocked")
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


class BinaryFileError(Exception):
    """A file that is not text: read_text raises it, the caller turns it into a human stop."""


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
    retry: bool = False  # the base branch moved: the whole verification starts again (once), nothing was merged


@dataclass(frozen=True)
class PrCtx:
    """The pull request a gate run must belong to."""

    number: int
    base: str
    head_branch: str


@dataclass
class Gh:
    """`gh` and `git` as fixed argument lists, no shell, stdin closed, output captured."""

    gh: str
    git: str
    env: Mapping[str, str]
    run: Run = subprocess.run
    cwd: str | None = None
    clock: Clock = time.monotonic
    limit: float | None = None  # absolute clock time the whole run must end by; caps each call's time

    def _call(self, argv: list[str]) -> tuple[int, str, str]:
        wait = float(CALL_TIMEOUT)
        if self.limit is not None:
            left = self.limit - self.clock()
            if left <= 0:  # no process is started after the deadline
                raise ShipError(EXIT_TIMEOUT, "the time ran out before this call")
            wait = min(wait, left)
        try:
            done = self.run(
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=wait,
                env=dict(self.env),
                cwd=self.cwd,
            )
        except subprocess.TimeoutExpired:
            name = " ".join([os.path.basename(argv[0]), *argv[1:3]])
            raise ShipError(EXIT_TIMEOUT, f"{clean(name, 200)[0]} timed out after {wait:.0f}s") from None
        except (OSError, UnicodeDecodeError) as error:
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


def protection_apps(data: Any) -> dict[str, int]:
    """{context: app_id} for every required check that branch protection pins to one GitHub App."""
    found: dict[str, int] = {}
    for item in data.get("checks", []) if isinstance(data, dict) else []:
        app = item.get("app_id") if isinstance(item, dict) else None
        if isinstance(app, int) and not isinstance(app, bool) and app > 0:
            found[str(item["context"])] = app
    return found


SAFE_PATH = re.compile(r"[A-Za-z0-9._/-]+")
MAX_PATH = 200


def safe_repo_path(path: str) -> bool:
    """A repository path made only of [A-Za-z0-9._/-] with no empty, `.` or `..` segment, and not very long."""
    return (
        0 < len(path) <= MAX_PATH
        and SAFE_PATH.fullmatch(path) is not None
        and all(part not in ("", ".", "..") for part in path.split("/"))
    )


def ref_part(ref: str) -> str:
    """A branch name as URL path segments: each part percent-quoted (so `#`, `%`, `?`, spaces and non-ASCII cannot end
    or change the path), the slashes of a name like `release/1.x` kept as separators."""
    return "/".join(quote(part, safe="") for part in ref.split("/"))


def contents_args(repo: str, path: str, ref: str) -> list[str]:
    """The `gh api` arguments for the contents of `path` at `ref`: every path segment percent-quoted, and the ref sent
    as a query field (`-X GET -f ref=...`), never glued into the URL, so no text of either can add a parameter."""
    quoted = "/".join(quote(part, safe="") for part in path.split("/"))
    return ["api", "-X", "GET", f"repos/{repo}/contents/{quoted}", "-f", f"ref={ref}"]


UNIX_LABEL = re.compile(r"(ubuntu|macos)-[A-Za-z0-9._-]+")


def _run_steps(steps: list[Any], defaults: Mapping[str, Any], unix: bool) -> tuple[list[str], str]:
    """The `run:` texts of a list of steps, or why a step cannot be read. A step runs from the repository root in bash
    or sh: its shell is its own or the default, and an unset shell counts as bash only on a literal ubuntu or macos
    runner label (on Windows it would be pwsh, on anything else it is unknown). Another working directory, shell or
    shape is a problem, not a guess."""
    out: list[str] = []
    for step in steps:
        if "run" not in step:
            continue
        text = step["run"]
        shell = step["shell"] if "shell" in step else defaults.get("shell")
        wd = step["working-directory"] if "working-directory" in step else defaults.get("working-directory")
        if not isinstance(text, str):
            return [], "a run step that is not text"
        if shell is None and not unix:
            return [], "a run step whose shell is not known (no shell set and no ubuntu or macos runner label)"
        if shell not in (None, "bash", "sh"):
            return [], "a run step with a shell other than bash or sh"
        if wd not in (None, "", "."):
            return [], "a run step with a working directory other than the repository root"
        out.append(text)
    return out, ""


def _run_defaults(section: Mapping[str, Any]) -> dict[str, Any] | None:
    """`defaults.run` of a workflow or job as a dict (empty when absent); None for an odd shape."""
    holder = section.get("defaults")
    if holder is None:
        return {}
    if not isinstance(holder, dict):
        return None
    run = holder.get("run")
    if run is None:
        return {}
    return dict(run) if isinstance(run, dict) else None


def workflow_refs(text: str, action: bool = False) -> tuple[list[str], list[str], str]:
    """(the `uses:` references, the `run:` texts, "") of a workflow (jobs.*) or a composite action (runs.steps), or
    ([], [], why the file cannot be trusted).

    Fail closed, never open: a file that is too large, does not parse, uses an anchor or alias, has a shape other than
    mappings and lists where `jobs`, a job or `steps` should be, or has more than MAX_REFS references is refused; and
    every word `uses` outside a comment, found by a second plain scan, must be one of the parsed references (so one in
    a block scalar, a flow mapping, an odd place, or a duplicate key that the parser overwrote is refused). A comment
    that merely says "uses" therefore also stops it: a human reads that file."""
    bad = "cannot be verified (too large, unparsable or an unexpected shape)"
    if len(text.encode("utf-8", "replace")) > MAX_WORKFLOW_BYTES:
        return [], [], bad
    try:
        if any(isinstance(e, yaml.AliasEvent) or getattr(e, "anchor", None) for e in yaml.parse(text)):
            return [], [], bad
        data = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError, ValueError):
        return [], [], bad
    if not isinstance(data, dict):
        return [], [], bad
    units: list[dict[str, Any]] = []  # jobs, or the one composite action
    defaults: list[dict[str, Any]] = []
    unix: list[bool] = []
    if action:
        section = data.get("runs")
        if section is not None and not isinstance(section, dict):
            return [], [], bad
        if isinstance(section, dict) and section.get("using") == "composite":
            units.append(section)
            defaults.append({})
            unix.append(False)  # a composite step names its shell
        elif isinstance(section, dict) and isinstance(section.get("image"), str):
            units.append({"uses": section["image"]} if section["image"].startswith("docker://") else {})
            defaults.append({})
            unix.append(False)
    else:
        jobs = data.get("jobs")
        if jobs is None:
            jobs = {}
        if not isinstance(jobs, dict):
            return [], [], bad
        top = _run_defaults(data)
        if top is None:
            return [], [], bad
        for job in jobs.values():
            if not isinstance(job, dict):
                return [], [], bad
            own = _run_defaults(job)
            if own is None:
                return [], [], bad
            units.append(job)
            defaults.append({**top, **own})  # a job's own default wins, key by key
            label = job.get("runs-on")
            unix.append(isinstance(label, str) and UNIX_LABEL.fullmatch(label) is not None)
    refs: list[str] = []
    runs: list[str] = []
    for unit, default, is_unix in zip(units, defaults, unix, strict=True):
        found: list[Any] = [unit["uses"]] if "uses" in unit else []
        steps = unit.get("steps")
        if steps is not None and not isinstance(steps, list):
            return [], [], bad
        for step in steps or []:
            if not isinstance(step, dict):
                return [], [], bad
            if "uses" in step:
                found.append(step["uses"])
        if not all(isinstance(ref, str) and ref.strip() for ref in found):
            return [], [], bad
        refs += [ref.strip() for ref in found]
        texts, problem = _run_steps(steps or [], default, is_unix)
        if problem:
            return [], [], problem
        runs += texts
    if len(refs) > MAX_REFS:
        return [], [], TOO_MANY
    if len(USES_TOKEN.findall(COMMENT.sub("", text))) != len(refs):
        return [], [], "has a `uses` the parse did not account for; " + bad
    return refs, runs, ""


def name_ok(context: str, name: str) -> bool:
    """A check run `name` satisfies a required `context`: exactly, or a bare context as the tail of `workflow / job`."""
    return context == name or (" / " not in context and name.endswith(f" / {context}"))


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
        queue: bool = False,
        gate_app: int = GATE_APP_ID,
        total_deadline: float | None = None,
        gate_workflow: str = "",
        protect_paths: Sequence[str] = (),
        best_effort_threads: bool = False,
        gate_commands: Sequence[str] = (),
    ):
        self.gate_commands = tuple(gate_commands)
        self.protect_paths = tuple(protect_paths)
        self.best_effort_threads = best_effort_threads
        self.tip0 = ""  # the base tip every check of this attempt was read against
        self.pin = ""
        self.chain: tuple[list[str], dict[str, int], str, PrCtx] | None = None
        self.gate_app, self.total_deadline = gate_app, total_deadline
        self.gate_workflow = gate_workflow
        self.last_base = ""
        self.deadline: float | None = None
        self.noticed = False
        self.queue = queue
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
            "state,headRefOid,headRefName,baseRefName,statusCheckRollup,url,mergeable,mergeStateStatus",
        )
        if not isinstance(data, dict) or not SHA.fullmatch(str(data.get("headRefOid") or "")):
            raise ShipError(EXIT_ERROR, f"PR #{number}: no head commit in the answer")
        return data

    def required(self, repo: str, base: str) -> tuple[list[str], dict[str, int]]:
        # -i puts the HTTP status line on stdout, so a missing protection is told by status, never by stderr text
        code, out, _err = self.gh.gh_call(
            "api", "-i", f"repos/{repo}/branches/{ref_part(base)}/protection/required_status_checks"
        )
        names = [GATE]
        head, _sep, body = out.replace("\r\n", "\n").partition("\n\n")
        found = re.match(r"HTTP/\S+ (\d{3})", head)
        status = int(found.group(1)) if found else 0
        if status == 404:
            return names, {}
        if code != 0 or not 200 <= status < 300:
            raise ShipError(EXIT_ERROR, f"cannot read the required checks of {base}: HTTP status {status or 'unknown'}")
        try:
            data = bounded.loads(body)
        except ValueError as error:
            raise ShipError(EXIT_ERROR, "unreadable required-checks answer") from error
        found_contexts = protection_contexts(data)
        for context in found_contexts:
            if context not in names:
                names.append(context)
        return names, protection_apps(data)

    def gate_path(self, repo: str, base: str) -> str:
        """The workflow file that must have produced `CI green`: --gate-workflow, else the one `ci.yml` (or `ci.yaml`)
        that the base branch holds. Anything else is an error: the gate's identity is never guessed."""
        if self.gate_workflow:
            return self.gate_workflow
        code, out, err = self.gh.gh_call(*contents_args(repo, ".github/workflows", base), "--jq", ".[].path")
        if code != 0:
            raise ShipError(EXIT_ERROR, f"cannot list the workflows of {base}: {err.strip()[:200]}")
        found = [p for p in out.split() if p in (".github/workflows/ci.yml", ".github/workflows/ci.yaml")]
        if len(found) != 1:
            raise ShipError(EXIT_ERROR, "cannot tell which workflow file is the gate: pass --gate-workflow PATH")
        return found[0]

    def gate_run(
        self,
        repo: str,
        pin: str,
        check: dict[str, Any],
        gate_path: str,
        ctx: PrCtx,
        cache: dict[str, tuple[bool, bool]],
    ) -> tuple[bool, bool]:
        """(is it a run of the gate workflow for THIS pull request on `pin`, did that run succeed). Identity: the gate
        file as `path`, exactly `pin` as head_sha, this repository, and either a pull_request run listing this PR with
        this base, or a push run on this PR's head branch. Any doubt (no run id, unreadable answer) is (False, False).
        Success is kept apart so that a failed run of the gate is a failure and is never ignored."""
        found = RUN_URL.search(str(check.get("details_url") or ""))
        if not found:
            return False, False
        run_id = found.group(1)
        if run_id not in cache:
            code, out, _err = self.gh.gh_call("api", f"repos/{repo}/actions/runs/{run_id}")
            try:
                run = bounded.loads(out) if code == 0 else None
            except ValueError:
                run = None
            cache[run_id] = self.judge_run(run, repo, pin, gate_path, ctx)
        return cache[run_id]

    @staticmethod
    def judge_run(run: Any, repo: str, pin: str, gate_path: str, ctx: PrCtx) -> tuple[bool, bool]:
        if not isinstance(run, dict):
            return False, False
        repo_name = (
            str((run.get("repository") or {}).get("full_name") or "") if isinstance(run.get("repository"), dict) else ""
        )
        event = run.get("event")
        listed = run.get("pull_requests")
        bound = (
            event == "pull_request"
            and isinstance(listed, list)
            and any(
                isinstance(pr, dict)
                and pr.get("number") == ctx.number
                and isinstance(pr.get("base"), dict)
                and pr["base"].get("ref") == ctx.base
                for pr in listed
            )
        ) or (event == "push" and bool(ctx.head_branch) and run.get("head_branch") == ctx.head_branch)
        identity = (
            str(run.get("path") or "").split("@")[0] == gate_path
            and run.get("head_sha") == pin
            and repo_name.lower() == repo.lower()
            and event in GATE_RUN_EVENTS
            and bound
        )
        return identity, identity and str(run.get("status")) == "completed" and str(run.get("conclusion")) == "success"

    def blob(self, repo: str, path: str, ref: str) -> str:
        code, out, err = self.gh.gh_call(*contents_args(repo, path, ref), "--jq", '[.path, .sha] | join("|")')
        got, _bar, sha = out.strip().partition("|")
        if code != 0 or not sha:
            raise ShipError(EXIT_ERROR, f"cannot read {clean(path, 200)[0]} at {ref[:12]}: {err.strip()[:200]}")
        if got != path:  # the answer is about some other path than the one asked for
            raise ShipError(EXIT_ERROR, f"the contents answer is not about {clean(path, 200)[0]}")
        return sha

    def base_moved(self, repo: str, number: int, pin: str, base: str) -> Result | None:
        """Re-read the pull request: a stop when its base is no longer the one the checks were read for, or its head
        is no longer the pin. The required checks, the gate file and the compare all depend on the base."""
        data = self.view(repo, number)
        now = str(data.get("baseRefName") or "")
        if now != base:
            return Result(
                EXIT_MERGE_REFUSED, "MERGE-REFUSED", f"the base branch changed from {base} to {now} after the checks"
            )
        if str(data["headRefOid"]) != pin:
            return Result(EXIT_HEAD_MOVED, "HEAD-MOVED", f"pinned {pin[:12]}, head is now {data['headRefOid']}")
        tip = self.base_tip(repo, base)
        if tip != self.tip0:  # every check was read against another tip: they all have to be read again
            return Result(
                EXIT_MERGE_REFUSED,
                "MERGE-REFUSED",
                f"the base branch tip moved from {self.tip0[:12]} to {tip[:12]} after the checks",
                retry=True,
            )
        return None

    def regate(self, repo: str, pin: str) -> Result | None:
        """The gate again, right before the merge: a rerun or a new failed run after it was verified is a stop."""
        if self.chain is None:
            raise ShipError(EXIT_ERROR, "no gate was verified for this pull request")
        required, apps, gate_path, ctx = self.chain
        why = self.verify_sources(repo, pin, required, apps, gate_path, ctx)
        if why:
            return Result(EXIT_CI_FAILED, "CI-FAILED", f"the gate changed after it was verified: {why}")
        return None

    def workflow_stop(self, repo: str, pin: str, base: str) -> Result | None:
        """NEEDS-HUMAN when the pull request touches anything under `.github/`, the gate's file or a protected path (or
        the list is too long to prove it does not), or when the gate file differs between `base` and `pin`: a change
        to the gate or to what it runs can make its own CI green, so it is never merged automatically."""
        gate = self.gate_path(repo, base)
        code, out, err = self.gh.gh_call(
            "api",
            f"repos/{repo}/compare/{ref_part(base)}...{ref_part(pin)}?per_page=100",
            "--paginate",
            "--jq",
            ".files[] | .filename, (.previous_filename // empty)",
        )
        if code != 0:
            raise ShipError(EXIT_ERROR, f"cannot list the changed files: {err.strip()[:200]}")
        files = [line for line in out.splitlines() if line.strip()]
        protect = [p.rstrip("/") for p in self.protect_paths]
        hit = next(
            (
                f
                for f in files
                if f.startswith(GITHUB_DIR) or f == gate or any(f == p or f.startswith(p + "/") for p in protect)
            ),
            None,
        )
        if hit is not None:
            return Result(
                EXIT_NEEDS_HUMAN, "NEEDS-HUMAN", f"changes {clean(hit, 200)[0]}; a protected path is merged by a human"
            )
        if self.blob(repo, gate, base) != self.blob(repo, gate, pin):
            return Result(EXIT_NEEDS_HUMAN, "NEEDS-HUMAN", f"{gate} differs between {base} and the pinned head")
        if len(files) >= COMPARE_CAP:
            return Result(
                EXIT_NEEDS_HUMAN,
                "NEEDS-HUMAN",
                f"{COMPARE_CAP} or more changed files: cannot prove no workflow changed",
            )
        return self.gate_refs(repo, gate, base, pin)

    def local_state(self, repo: str, path: str, ref: str) -> str | None:
        """The content sha of a file, or of a directory listing, at `ref`. None only for a structurally valid HTTP 404
        (the status line); every other failure, an empty or malformed answer, or an answer about another path is an
        error, never "absent"."""
        code, out, err = self.gh.gh_call("api", "-i", *contents_args(repo, path, ref)[1:])
        head, _sep, body = out.replace("\r\n", "\n").partition("\n\n")
        found = re.match(r"HTTP/\S+ (\d{3})", head)
        status = int(found.group(1)) if found else 0
        where = f"{clean(path, 200)[0]} at {ref[:12]}"
        if status == 404:
            return None
        if code != 0 or not 200 <= status < 300:
            raise ShipError(EXIT_ERROR, f"cannot read {where}: HTTP status {status or 'unknown'} {err.strip()[:100]}")
        try:
            data = bounded.loads(body)
            if isinstance(data, dict):
                ok = data["path"] == path
                state: Any = {"file": data["path"], "sha": data["sha"]}
            elif isinstance(data, list) and data:
                ok = all(isinstance(i, dict) and str(i["path"]).rsplit("/", 1)[0] == path for i in data)
                state = {"dir": [{"p": i["path"], "s": i["sha"]} for i in data]}
            else:
                raise ValueError("empty")
        except (ValueError, KeyError, TypeError):
            raise ShipError(EXIT_ERROR, f"unreadable contents answer for {where}") from None
        if not ok:  # the answer is about some other path than the one asked for
            raise ShipError(EXIT_ERROR, f"the contents answer is not about {clean(path, 200)[0]}")
        return json.dumps(state, sort_keys=True, separators=(",", ":"))

    def read_text(self, repo: str, path: str, ref: str) -> str | None:
        """The raw text of a file at `ref`; None only for a clear HTTP 404 (read from the status line, never from text);
        any other failure is an error."""
        code, out, err = self.gh.gh_call(
            "api", "-i", *contents_args(repo, path, ref)[1:], "-H", "Accept: application/vnd.github.raw"
        )
        if err.strip() == "UnicodeDecodeError":
            raise BinaryFileError
        head, _sep, body = out.replace("\r\n", "\n").partition("\n\n")
        found = re.match(r"HTTP/\S+ (\d{3})", head)
        status = int(found.group(1)) if found else 0
        if status == 404:
            return None
        if code != 0 or not 200 <= status < 300:
            raise ShipError(
                EXIT_ERROR,
                f"cannot read {clean(path, 200)[0]} at {ref[:12]}: HTTP status {status or 'unknown'}"
                f" {err.strip()[:100]}",
            )
        return body

    def gate_refs(self, repo: str, gate: str, base: str, pin: str) -> Result | None:
        """NEEDS-HUMAN unless everything the gate workflow executes is the same on `base` and `pin`, or pinned:
        - every `uses:` (of the workflow, of each local workflow and of each local composite action, followed) is a
          remote reference pinned by a 40-hex commit (a docker one by digest) or a local path identical on both;
        - every `run:` text (of those files) is in the strict grammar of safo.shipscan, and every repository file it
          executes is identical on both. A line outside the grammar is itself a stop.
        Files that a script reads, Makefile targets, configuration, installed dependencies and what a program imports
        stay outside it; --protect-path and rulesets with required workflows are the other controls."""
        seen: set[tuple[str, str, str]] = set()
        compared: set[str] = set()
        queue: list[tuple[str, int, str, str]] = [(gate, 0, "workflow", "")]
        while queue:
            path, depth, kind, cwd = queue.pop(0)
            if (kind, path, cwd) in seen:
                continue
            if len(seen) >= MAX_FILES:
                return Result(EXIT_NEEDS_HUMAN, "NEEDS-HUMAN", TOO_MANY)
            seen.add((kind, path, cwd))
            where = clean(path, 200)[0]
            units: list[tuple[str, str]]
            if kind == "script":
                try:
                    text = self.read_text(repo, path, pin)
                except BinaryFileError:
                    return Result(EXIT_NEEDS_HUMAN, "NEEDS-HUMAN", f"{where}: a file that is not text")
                if text is None:
                    raise ShipError(EXIT_ERROR, f"cannot read {where}: not found at the pinned head")
                if len(text.encode("utf-8", "replace")) > MAX_SCRIPT_BYTES or chr(0) in text:
                    return Result(EXIT_NEEDS_HUMAN, "NEEDS-HUMAN", f"{where}: a binary or oversized file")
                why = shipscan.shebang_problem(text)
                if why:
                    return Result(EXIT_NEEDS_HUMAN, "NEEDS-HUMAN", f"{where}: {clean(why, 200)[0]}")
                refs: list[str] = []
                units = [(text, cwd)]  # a script is held to the same grammar, from the directory it was run from
            else:
                if kind == "action":
                    text = self.read_text(repo, f"{path}/action.yml", pin)
                    if text is None:
                        text = self.read_text(repo, f"{path}/action.yaml", pin)
                    if text is None:
                        return Result(EXIT_NEEDS_HUMAN, "NEEDS-HUMAN", f"{where}: a local action without action.yml")
                else:
                    text = self.read_text(repo, path, pin)
                    if text is None:
                        raise ShipError(EXIT_ERROR, f"cannot read {where}: not found at the pinned head")
                refs, runs, problem = workflow_refs(text, action=kind == "action")
                if problem:
                    return Result(EXIT_NEEDS_HUMAN, "NEEDS-HUMAN", f"{where}: {problem}")
                units = [(run_text, "") for run_text in runs]
            for run_text, run_cwd in units:
                facts = shipscan.analyze(run_text, commands=self.gate_commands, cwd=run_cwd)
                if facts.problem:
                    return Result(
                        EXIT_NEEDS_HUMAN,
                        "NEEDS-HUMAN",
                        f"{where}: not in the allowed grammar: {clean(facts.problem, 200)[0]}",
                    )
                for file, from_dir in facts.runs:
                    if file not in compared:
                        if len(compared) >= MAX_EXEC_FILES:
                            return Result(EXIT_NEEDS_HUMAN, "NEEDS-HUMAN", TOO_MANY)
                        compared.add(file)
                        if not safe_repo_path(file):
                            return Result(EXIT_NEEDS_HUMAN, "NEEDS-HUMAN", f"{where}: an unusual path in a run step")
                        before, after = self.local_state(repo, file, base), self.local_state(repo, file, pin)
                        if before is None or after is None:
                            # no generated-file support: a path the gate runs that is not in the repository at both
                            # refs cannot be read, so a human decides
                            return Result(
                                EXIT_NEEDS_HUMAN,
                                "NEEDS-HUMAN",
                                f"{clean(file, 200)[0]} (run by {where}) is absent at "
                                f"{clean(base, 80)[0] if before is None else 'the pin'}",
                            )
                        if before != after:
                            return Result(
                                EXIT_NEEDS_HUMAN,
                                "NEEDS-HUMAN",
                                f"{clean(file, 200)[0]} (run by {where}) differs between {base} and the pin",
                            )
                    # what a script runs is held to the same rules, down to MAX_DEPTH levels
                    if depth + 1 > MAX_DEPTH:
                        return Result(EXIT_NEEDS_HUMAN, "NEEDS-HUMAN", TOO_MANY)
                    queue.append((file, depth + 1, "script", from_dir))
            for ref in refs:
                if ref.startswith("./"):
                    local = ref[2:].rstrip("/")
                    if not safe_repo_path(local):
                        return Result(
                            EXIT_NEEDS_HUMAN, "NEEDS-HUMAN", "local workflow reference has unsupported characters"
                        )
                    before, after = self.local_state(repo, local, base), self.local_state(repo, local, pin)
                    if before is None and after is None:
                        raise ShipError(EXIT_ERROR, f"cannot read {clean(ref, 200)[0]}")
                    if before != after:
                        return Result(
                            EXIT_NEEDS_HUMAN, "NEEDS-HUMAN", f"{clean(ref, 200)[0]} differs between {base} and the pin"
                        )
                    if depth >= MAX_DEPTH:
                        return Result(EXIT_NEEDS_HUMAN, "NEEDS-HUMAN", TOO_MANY)
                    queue.append((local, depth + 1, "workflow" if local.endswith((".yml", ".yaml")) else "action", ""))
                elif ref.startswith("docker://"):
                    if not DOCKER_DIGEST.search(ref):
                        return Result(
                            EXIT_NEEDS_HUMAN, "NEEDS-HUMAN", f"unpinned reference {clean(ref, 200)[0]} (needs a digest)"
                        )
                elif not PINNED_REF.fullmatch(ref):
                    return Result(
                        EXIT_NEEDS_HUMAN, "NEEDS-HUMAN", f"unpinned reference {clean(ref, 200)[0]} (needs a 40-hex sha)"
                    )
        return None

    def check_runs(self, repo: str, sha: str) -> list[dict[str, Any]]:
        """Every check run of `sha` (all pages) with the id of the GitHub App that made it."""
        code, out, err = self.gh.gh_call(
            "api",
            f"repos/{repo}/commits/{sha}/check-runs?per_page=100",
            "--paginate",
            "--jq",
            ".check_runs[] | {name: .name, status: .status, conclusion: .conclusion, app_id: .app.id,"
            " details_url: .details_url}",
        )
        if code != 0:
            raise ShipError(EXIT_ERROR, f"cannot read the check runs of {sha[:12]}: {err.strip()[:200]}")
        runs: list[dict[str, Any]] = []
        for raw in out.splitlines():
            if raw.strip():
                try:
                    item = bounded.loads(raw)
                except ValueError:
                    raise ShipError(EXIT_ERROR, "unreadable check-runs answer") from None
                if not isinstance(item, dict):
                    raise ShipError(EXIT_ERROR, "unreadable check-runs answer")
                runs.append(item)
        return runs

    def verify_sources(
        self, repo: str, pin: str, required: Sequence[str], apps: Mapping[str, int], gate_path: str, ctx: PrCtx
    ) -> str:
        """ "" when every app-pinned required check (the gate always) is a successful check run of the pinned app on
        `pin`, else why not. A commit status, or a check run of another app, never counts for such a check. For the
        gate the run must also be a trusted run of `gate_path` (see trusted_run); impostor jobs are ignored."""
        need = {c: apps[c] for c in required if c in apps}
        if GATE in required and GATE not in need:
            need[GATE] = self.gate_app
        if not need:
            return ""
        runs = self.check_runs(repo, pin)
        cache: dict[str, tuple[bool, bool]] = {}
        for context, app in need.items():
            mine = [r for r in runs if r.get("app_id") == app and name_ok(context, str(r.get("name") or ""))]
            runs_ok = True
            if context == GATE:
                judged = [(r, self.gate_run(repo, pin, r, gate_path, ctx, cache)) for r in mine]
                mine = [r for r, (identity, _success) in judged if identity]
                runs_ok = all(success for _r, (identity, success) in judged if identity)  # a failed gate run counts
            good = OK_REQUIRED if context != GATE else {"SUCCESS"}
            if (
                not mine
                or not runs_ok
                or not all(
                    str(r.get("status")).upper() == "COMPLETED" and str(r.get("conclusion") or "").upper() in good
                    for r in mine
                )
            ):
                return f"no successful check run of {context} from app {app} on {pin[:12]} yet"
        return ""

    @staticmethod
    def thread_of(node: dict[str, Any]) -> Thread:
        comments = node.get("comments")
        if comments is not None and not isinstance(comments, dict):
            raise TypeError("comments is not an object")
        comments = comments or {}
        first = (comments.get("nodes") or [{}])[0] or {}
        where = clean(f"{node.get('path') or '?'}:{node.get('line') or '?'}", 300)[0]
        author = clean(str((first.get("author") or {}).get("login") or ""), 100)[0]
        body, cut = clean(str(first.get("body") or ""), BODY_LIMIT)
        return Thread(where, author, clean(str(first.get("url") or ""), 300)[0], body, cut)

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
            if not isinstance(nodes, list):
                raise ShipError(EXIT_ERROR, "unreadable review-thread answer")
            for node in nodes:
                if isinstance(node, dict) and not node.get("isResolved"):
                    try:
                        unresolved.append(self.thread_of(node))
                    except (AttributeError, TypeError, IndexError) as error:
                        raise ShipError(EXIT_ERROR, "unreadable review-thread answer") from error
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

    def wait_ci(self, repo: str, number: int, pin: str, deadline: float | None = None) -> Result | None:
        """None when CI is green on `pin`; otherwise the Result that ends this PR."""
        start = self.clock()
        base = ""
        required: list[str] = []
        apps: dict[str, int] = {}
        gate_path = ""
        ctx = PrCtx(number, "", "")
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
                self.last_base = base
                required, apps = self.required(repo, base)  # per call: nothing carries over from another PR
                gate_path = self.gate_path(repo, base)
                ctx = PrCtx(number, base, str(data.get("headRefName") or ""))
                self.chain = (required, apps, gate_path, ctx)
                if not self.tip0:  # the base tip is pinned before any check is judged
                    self.tip0 = self.base_tip(repo, base)
            checks = parse_checks(data.get("statusCheckRollup"))
            verdict = judge(checks, required)
            if verdict.state == "green":
                why = self.verify_sources(repo, pin, required, apps, gate_path, ctx)
                if not why:
                    return None
                last = why
            elif verdict.state == "failed":
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
            if (
                poll == self.max_polls
                or self.clock() - start >= self.timeout
                or (deadline is not None and self.clock() >= deadline)
            ):
                break
            if deadline is not None and deadline - self.clock() <= 0:
                break
            self.sleep(self.interval if deadline is None else min(self.interval, deadline - self.clock()))
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
        """One merge call, never retried here: when the base moved ("Base branch was modified") the caller starts the
        whole verification again. Every call stays under the per-PR deadline; only the read that settles what a merge
        call did gets a small separate allowance (RECOVERY_SECONDS), and no second merge call starts after it."""
        flag = {"squash": "--squash", "merge": "--merge", "rebase": "--rebase"}[self.method]
        argv = ["pr", "merge", str(number), "-R", repo, flag, "--match-head-commit", pin]
        if self.delete_branch:
            argv.append("--delete-branch")
        try:
            code, _out, err = self.gh.gh_call(*argv)
        except ShipError as error:
            if error.code == EXIT_TIMEOUT and "timed out" in str(error):  # the call ran and was cut off
                self.recovery_window()
                try:
                    if self.view(repo, number).get("state") == "MERGED":
                        return Result(
                            EXIT_MERGED, "MERGED", f"head={pin[:12]} (the merge call timed out, read-back says so)"
                        )
                except ShipError:
                    pass
                raise ShipError(
                    EXIT_TIMEOUT, f"{error}; the merge may have been applied: read the pull request"
                ) from None
            raise
        if code == 0:
            self.recovery_window()
            state = self.view(repo, number).get("state")
            if state != "MERGED":
                return Result(EXIT_MERGE_REFUSED, "MERGE-REFUSED", f"merge accepted but the read-back says {state}")
            return Result(EXIT_MERGED, "MERGED", f"head={pin[:12]}")
        if "base branch was modified" in err.lower():
            moved = self.view(repo, number)
            if str(moved["headRefOid"]) != pin:
                return Result(EXIT_HEAD_MOVED, "HEAD-MOVED", f"pinned {pin[:12]}, head is now {moved['headRefOid']}")
            return Result(EXIT_MERGE_REFUSED, "MERGE-REFUSED", "Base branch was modified", retry=True)
        return self.refused(repo, number, pin, err)

    def recovery_window(self) -> None:
        """After a merge call ran, the read that settles its outcome may use RECOVERY_SECONDS beyond the deadline."""
        if self.gh.limit is not None:
            self.gh.limit = max(self.gh.limit, self.clock() + RECOVERY_SECONDS)

    def refused(self, repo: str, number: int, pin: str, err: str) -> Result:
        """A merge gh refused: a head that moved since the pin is HEAD-MOVED with the new sha, else a plain refusal."""
        try:
            data = self.view(repo, number)
            head = str(data["headRefOid"])
        except ShipError:
            data, head = {}, pin
        if head != pin:
            return Result(EXIT_HEAD_MOVED, "HEAD-MOVED", f"pinned {pin[:12]}, head is now {head}")
        reason = err.strip().splitlines()[0][:200] if err.strip() else "gh refused"
        if self.queue:
            # Structured state wins unconditionally; the error text is read only when the state says nothing (missing
            # or UNKNOWN), because a clean state with a hostile or buggy message must not name a stop it cannot prove.
            state, mergeable = data.get("mergeStateStatus"), data.get("mergeable")
            if state in (None, "", "UNKNOWN") and mergeable in (None, "", "UNKNOWN"):
                if "conflict" in reason.lower():
                    return Result(EXIT_CONFLICT, "CONFLICT", reason)
                if any(word in reason.lower() for word in PROTECTED_WORDS):
                    return Result(EXIT_PROTECTED, "PROTECTED", reason)
            else:
                if (stop := self.conflicting(data)) is not None:
                    return Result(stop.code, stop.word, reason)
                if state == "BLOCKED":
                    return Result(EXIT_PROTECTED, "PROTECTED", reason)
        return Result(EXIT_MERGE_REFUSED, "MERGE-REFUSED", reason)

    # queue mode

    def pinned_view(self, repo: str, number: int, expect: str, deadline: float) -> dict[str, Any] | Result:
        """The view whose head is `expect`; an older head is re-read (bounded by polls and `deadline`) in case the
        API lags the push."""
        data = self.view(repo, number)
        for _ in range(HEAD_LAG_POLLS):
            if str(data["headRefOid"]) == expect:
                return data
            left = deadline - self.clock()
            if left <= 0:
                break
            self.sleep(min(self.interval, left))
            if deadline - self.clock() <= 0:
                break
            data = self.view(repo, number)
        if str(data["headRefOid"]) == expect:
            return data
        return Result(EXIT_HEAD_MOVED, "HEAD-MOVED", f"pinned {expect[:12]}, head is now {data['headRefOid']}")

    @staticmethod
    def conflicting(data: dict[str, Any]) -> Result | None:
        if data.get("mergeable") == "CONFLICTING" or data.get("mergeStateStatus") == "DIRTY":
            return Result(EXIT_CONFLICT, "CONFLICT", "conflicts with the base branch; needs an agent")
        return None

    def base_tip(self, repo: str, base: str) -> str:
        data = self.gh.json("api", f"repos/{repo}/git/ref/heads/{ref_part(base)}")
        tip = str(((data.get("object") or {}) if isinstance(data, dict) else {}).get("sha") or "")
        if not SHA.fullmatch(tip):
            raise ShipError(EXIT_ERROR, f"cannot read the tip of {clean(base, 100)[0]}")
        if data.get("ref") != f"refs/heads/{base}":  # the answer must be about the branch that was asked for
            raise ShipError(EXIT_ERROR, f"the ref answer is not about {clean(base, 100)[0]}")
        return tip

    def is_update_commit(self, repo: str, head: str, pin: str, tip: str) -> bool:
        """True only for the merge commit GitHub itself made from `pin` and the base `tip`: exactly those two parents,
        in that order, and a signature GitHub verified for its web-flow committer. A branch writer cannot fake that."""
        data = self.gh.json("api", f"repos/{repo}/commits/{head}")
        try:
            parents = [str(p["sha"]) for p in data["parents"]]
            committer = str((data.get("committer") or {}).get("login") or "")
            verified = (data.get("commit") or {}).get("verification", {}).get("verified") is True
        except (KeyError, TypeError, AttributeError) as error:
            raise ShipError(EXIT_ERROR, "unreadable commit answer") from error
        return parents == [pin, tip] and committer == "web-flow" and verified

    def update_branch(self, repo: str, number: int, pin: str, base: str, deadline: float) -> str | Result:
        """Ask GitHub to merge the base into the branch (once), then return the new head to pin."""
        tip = self.base_tip(repo, base)  # read just before, so the update commit's second parent can be checked
        code, _out, err = self.gh.gh_call(
            "api", f"repos/{repo}/pulls/{number}/update-branch", "-X", "PUT", "-f", f"expected_head_sha={pin}"
        )
        if code != 0:
            if "conflict" in err.lower():
                return Result(EXIT_CONFLICT, "CONFLICT", "update-branch hit a conflict; needs an agent")
            return Result(EXIT_ERROR, "ERROR", f"update-branch failed: {err.strip()[:200]}")
        for poll in range(1, UPDATE_WAIT_POLLS + 1):
            data = self.view(repo, number)
            head = str(data["headRefOid"])
            if head != pin:
                if not self.is_update_commit(repo, head, pin, tip):  # never re-pin to a commit GitHub did not make
                    return Result(EXIT_HEAD_MOVED, "HEAD-MOVED", f"pinned {pin[:12]}, head is now {head}")
                self.say(f"  updated the branch: pinned {pin[:12]} -> {head[:12]}")
                return head
            if poll < UPDATE_WAIT_POLLS and self.clock() < deadline:
                self.sleep(min(self.interval, max(deadline - self.clock(), 0.0)))
            else:
                break
        return Result(EXIT_TIMEOUT, "TIMEOUT", f"update-branch accepted but the head stayed {pin[:12]}")

    def queued_attempt(self, repo: str, number: int, expect: str, deadline: float) -> Result:
        first = self.pinned_view(repo, number, expect, deadline) if expect else self.view(repo, number)
        if isinstance(first, Result):
            return first
        pin = self.pin = str(first["headRefOid"])
        updated = False
        data = first
        while True:
            if (stop := self.conflicting(data)) is not None:
                return stop
            if data.get("mergeStateStatus") == "BEHIND" and not updated and data.get("state") == "OPEN":
                updated = True
                new = self.update_branch(repo, number, pin, str(data.get("baseRefName") or ""), deadline)
                if isinstance(new, Result):
                    return new
                pin = self.pin = new
            ended = self.wait_ci(repo, number, pin, deadline)
            if ended is not None:
                return ended
            data = self.view(repo, number)
            if str(data["headRefOid"]) != pin:
                return Result(EXIT_HEAD_MOVED, "HEAD-MOVED", f"pinned {pin[:12]}, head is now {data['headRefOid']}")
            if (stop := self.conflicting(data)) is not None:
                return stop
            if data.get("mergeStateStatus") == "BEHIND":
                if updated:
                    return Result(EXIT_MERGE_REFUSED, "MERGE-REFUSED", "still behind the base after one update-branch")
                continue  # the loop head updates once and waits for CI on the new head
            break
        return self.finish(repo, number, pin, deadline)

    def plain_attempt(self, repo: str, number: int, expect: str, deadline: float) -> Result:
        pin = self.pin = expect or str(self.view(repo, number)["headRefOid"])
        ended = self.wait_ci(repo, number, pin, deadline)
        if ended is not None:
            return ended
        return self.finish(repo, number, pin, deadline)

    def finish(self, repo: str, number: int, pin: str, deadline: float) -> Result:
        """Everything after CI is green, then the merge. A Result with `retry` set means the base moved and nothing was
        merged: the caller verifies the whole chain again, against the new base."""
        ended = self.await_review(repo, number, pin, deadline)
        if ended is not None:
            return ended
        base = self.last_base
        stop = self.base_moved(repo, number, pin, base) or self.workflow_stop(repo, pin, base)
        if stop is not None:
            return stop
        open_threads = self.threads(repo, number)
        if open_threads:
            return Result(
                EXIT_THREADS,
                "THREADS",
                f"{len(open_threads)} unresolved review thread(s)",
                [line for t in open_threads for line in t.lines()],
            )
        # as close to the merge as possible, and every time: nothing is remembered from an earlier pull request
        stop = (
            self.require_conversation(repo, base) or self.regate(repo, pin) or self.base_moved(repo, number, pin, base)
        )
        if stop is not None:
            return stop
        return self.merge(repo, number, pin)

    def run_chain(
        self, repo: str, number: int, expect: str, attempt: Callable[[str, int, str, float], Result]
    ) -> Result:
        """Run the verification chain under one per-PR deadline. When the base moved (retry), the chain runs again from
        the start, once, on the same head; never a second merge call inside one pass."""
        try:
            deadline = self.clock() + self.timeout
            if self.total_deadline is not None:
                deadline = min(deadline, self.total_deadline)
            self.deadline, self.gh.limit = deadline, deadline  # every gh call is capped by what is left of this PR
            for round_ in (1, 2):
                self.tip0, self.chain, self.last_base = "", None, ""
                result = attempt(repo, number, expect, deadline)
                if not result.retry:
                    return result
                expect = self.pin
                left = deadline - self.clock()
                if round_ == 2 or left <= 0:
                    return Result(
                        EXIT_MERGE_REFUSED,
                        "MERGE-REFUSED",
                        f"{result.detail}; the base moved again: nothing was merged",
                    )
                self.sleep(min(self.interval, left))
            raise ShipError(EXIT_ERROR, "unreachable")
        except ShipError as error:
            return Result(error.code, "TIMEOUT" if error.code == EXIT_TIMEOUT else "ERROR", str(error))
        finally:
            self.deadline, self.gh.limit = None, None

    def one_queued(self, repo: str, number: int, expect: str = "") -> Result:
        return self.run_chain(repo, number, expect, lambda r, n, e, d: self.queued_attempt(r, n, e, d))

    def require_conversation(self, repo: str, base: str) -> Result | None:
        """A stop (exit 9) unless branch protection of `base` requires conversation resolution, read structurally; an
        unreadable or oddly shaped answer is a refusal too. Only GitHub can make the thread check atomic with the
        merge. `--best-effort-threads` keeps the old behavior with a NOTICE that names the race."""
        if self.best_effort_threads:
            if not self.noticed:
                self.noticed = True
                self.say(
                    "NOTICE --best-effort-threads: the thread check is best-effort; a thread opened between its read "
                    f"and the merge call on {base} is not stopped"
                )
            return None
        code, out, _err = self.gh.gh_call("api", f"repos/{repo}/branches/{ref_part(base)}/protection")
        try:
            data = bounded.loads(out) if code == 0 else None
            section = data.get("required_conversation_resolution") if isinstance(data, dict) else None
            enabled = isinstance(section, dict) and section.get("enabled") is True
            about = data.get("url") if isinstance(data, dict) else None  # when it names a branch it must be this one
            if isinstance(about, str) and f"/branches/{ref_part(base)}/protection" not in about:
                enabled = False
        except ValueError:
            enabled = False
        if not enabled:
            return Result(
                EXIT_PROTECTED,
                "PROTECTED",
                "conversation resolution is not required by branch protection; thread check would be best-effort",
            )
        return None

    def one(self, repo: str, number: int, expect: str = "") -> Result:
        if self.queue:
            return self.one_queued(repo, number, expect)
        return self.run_chain(repo, number, expect, lambda r, n, e, d: self.plain_attempt(r, n, e, d))


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
    p.add_argument(
        "--total-timeout",
        type=float,
        default=7200.0,
        help="queue only: seconds for the whole run, 1 to 28800 (default 7200); later PRs print SKIPPED",
    )
    p.add_argument(
        "--gate-workflow",
        default="",
        metavar="PATH",
        help="workflow file that must have produced `CI green` (default: the base branch's one ci.yml or ci.yaml)",
    )
    p.add_argument("--gate-app-id", type=int, default=GATE_APP_ID, help="GitHub App id that must own `CI green`")
    p.add_argument(
        "--gate-command",
        action="append",
        default=[],
        metavar="NAME",
        help="repeatable: an exact command name (such as make or pytest) the gate's run steps may use; it is NOT "
        "followed to any file, so protect its inputs with --protect-path",
    )
    p.add_argument(
        "--best-effort-threads",
        action="store_true",
        help="merge even when branch protection does not require conversation resolution (a thread opened between "
        "the thread read and the merge is then not stopped; a NOTICE says so)",
    )
    p.add_argument(
        "--protect-path",
        action="append",
        default=[],
        metavar="PATH",
        help="repeatable: a file or directory whose change always needs a human (exit 10), as is anything in .github/",
    )
    p.add_argument("--delete-branch", action="store_true")
    p.add_argument(
        "--queue",
        action="store_true",
        help="take the pull requests one at a time and stop at the first that does not merge; retry a lagging head, "
        "update-branch once when behind, name each stop (exit 8 conflict, 9 protection refusal)",
    )
    p.add_argument(
        "--pin", action="append", default=[], metavar="N=SHA", help="queue only: pin this 40-hex head for PR N"
    )
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
    if not 1 <= args.total_timeout <= MAX_TOTAL_TIMEOUT:
        parser.error(f"--total-timeout must be 1 to {MAX_TOTAL_TIMEOUT}")
    if args.gate_workflow and not re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", args.gate_workflow):
        parser.error("--gate-workflow is a path like .github/workflows/ci.yml")
    if args.gate_command and not args.protect_path:
        parser.error("--gate-command needs at least one --protect-path: nothing follows a listed command to its inputs")
    for name in args.gate_command:
        if not shipscan.valid_command_name(name):
            parser.error("--gate-command is one plain command name (no path, no option, no interpreter)")
    for path in args.protect_path:
        parts = path.rstrip("/").split("/")
        if not path or path.startswith("/") or "\\" in path or ".." in parts or "" in parts or len(path) > 300:
            parser.error("--protect-path is a relative path inside the repository, without .. or empty parts")
        if any(unicodedata.category(c)[0] == "C" for c in path):
            parser.error("--protect-path has a control character")
    if args.gate_app_id < 1:
        parser.error("--gate-app-id must be a positive App id")
    if any(n < 1 for n in args.pr):
        parser.error("pull request numbers are positive")
    if not 0 <= args.wait_for_review <= MAX_WAIT_FOR_REVIEW:
        parser.error(f"--wait-for-review must be 0 to {MAX_WAIT_FOR_REVIEW}")
    pins: dict[int, str] = {}
    for item in args.pin:
        number, _eq, sha = item.partition("=")
        if not number.isdigit() or int(number) not in args.pr or not SHA.fullmatch(sha):
            parser.error("--pin is N=<40-hex commit> for a pull request N named in the queue")
        pins[int(number)] = sha
    if (args.queue or args.pin) and (not args.queue or args.open_pr or args.expect_head):
        parser.error("--queue takes pull request numbers (and --pin); --pin needs --queue; no --open-pr, --expect-head")
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
    gh = Gh(gh_path, git_path, env, run, workdir, clock)
    total_deadline = clock() + args.total_timeout if args.queue else None
    gh.limit = total_deadline
    watcher = Watcher(
        gh,
        out,
        total_deadline=total_deadline,
        gate_app=args.gate_app_id,
        gate_workflow=args.gate_workflow,
        protect_paths=args.protect_path,
        best_effort_threads=args.best_effort_threads,
        gate_commands=args.gate_command,
        timeout=args.timeout,
        interval=args.interval,
        max_polls=args.max_polls,
        method=args.method,
        delete_branch=args.delete_branch,
        sleep=sleep,
        clock=clock,
        wait_for_review=args.wait_for_review,
        queue=args.queue,
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
            pins = dict(item.split("=", 1) for item in args.pin)
            targets = [(n, pins.get(str(n), args.expect_head)) for n in args.pr]
    except ShipError as error:
        output.write(out, f"ERROR {error}")
        return error.code
    stopped: int | None = None
    for number, expect in targets:
        if stopped is not None:
            output.write(out, f"SKIPPED {repo}#{number} queue stopped at #{stopped}")
            continue
        result = watcher.one(repo, number, expect)
        if args.queue and result.code != EXIT_MERGED:
            stopped = number
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
    p.add_argument("--gate-workflow", default="", metavar="PATH", help="as safo-ship")
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
        gate_workflow=args.gate_workflow,
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
