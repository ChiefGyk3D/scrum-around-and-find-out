# SPDX-License-Identifier: Apache-2.0
"""`safo protection --all`: the default branch of every tracked repository against the standard (#541).

Read-only: GET requests through `protection.Rest` (no other verb exists there), one repository at a time, one request
after another. The reads of the protection itself (the classic rule and the active rulesets) are the ones
`safo protection --repo` makes; this module adds only the standard's other rows:

- `CI green` is required (any source; `--require-app-id` also pins it) and so is every security check the repository's
  workflows declare: a job of a workflow that runs on pull requests whose name or id says security (`SECURITY_JOB`);
  a job that never runs on a pull request cannot be required, so it is not demanded;
- a pull request is required, and force pushes and deleting the branch are off;
- reported, never a failure: whether administrators are included, and whether conversation resolution is required.

A repository whose protection cannot be read in full is UNKNOWN (exit 2), never a pass. Exit 1 on any MISSING or DRIFT
item, 2 on any UNKNOWN, else 0. `rules.gate_exempt_repos` are listed and not read. Unlike `--repo` this reads once, not
twice: it is a drift audit across many repositories, not the proof of one.
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from typing import Any

import yaml

from safo.errors import EXIT_DRIFT, EXIT_OK, EXIT_UNKNOWN, SafoError
from safo.protection import (
    BRANCH,
    CannotTell,
    Rest,
    Source,
    _obj,
    _repo_path,
    _str,
    ci_condition,
    read_repo,
    read_sources,
)
from safo.schema import Board

SECURITY_JOB = re.compile(r"security|codeql|semgrep|gitleaks|trivy|zizmor|dependency[ _-]?review|sast", re.IGNORECASE)
MAX_WORKFLOWS = 100
MAX_WORKFLOW_BYTES = 256 * 1024
PULL_TRIGGERS = ("pull_request", "pull_request_target")


def _runs_on_pulls(doc: dict[Any, Any]) -> bool:
    trigger = doc.get("on", doc.get(True))  # YAML 1.1 reads a bare `on` key as true
    if isinstance(trigger, str):
        return trigger in PULL_TRIGGERS
    if isinstance(trigger, list):
        return any(t in PULL_TRIGGERS for t in trigger)
    return isinstance(trigger, dict) and any(t in trigger for t in PULL_TRIGGERS)


def security_jobs(text: str) -> list[str]:
    """The names of the security jobs one workflow file declares, [] when it does not run on pull requests."""
    try:
        doc = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError):
        raise CannotTell("cannot tell: a workflow file is not valid YAML") from None
    if not isinstance(doc, dict) or not _runs_on_pulls(doc) or not isinstance(doc.get("jobs"), dict):
        return []
    found: list[str] = []
    for job_id, job in doc["jobs"].items():
        label = job.get("name") if isinstance(job, dict) and isinstance(job.get("name"), str) else job_id
        if isinstance(label, str) and (SECURITY_JOB.search(label) or SECURITY_JOB.search(str(job_id))):
            found.append(label)
    return found


def declared_security(rest: Rest, base: str, branch: str) -> list[str]:
    ref = urllib.parse.quote(branch, safe="/")
    status, listing, _ = rest.get(f"{base}/contents/.github/workflows?ref={ref}", "the workflow directory")
    if status == 404:
        return []
    if not isinstance(listing, list) or len(listing) > MAX_WORKFLOWS:
        raise CannotTell("cannot tell: the workflow directory is not a list this check will read")
    names: list[str] = []
    for entry in listing:
        item = _obj(entry, "a workflow entry")
        name, kind = _str(item, "name", "a workflow entry"), _str(item, "type", "a workflow entry")
        if kind != "file" or not name.endswith((".yml", ".yaml")) or "/" in name or name.startswith("."):
            continue
        status, body, _ = rest.get(
            f"{base}/contents/.github/workflows/{urllib.parse.quote(name)}?ref={ref}", "a workflow"
        )
        file = _obj(body, "a workflow answer")
        if status != 200 or file.get("encoding") != "base64":
            raise CannotTell("cannot tell: a workflow file could not be read")
        try:
            raw = base64.b64decode("".join(_str(file, "content", "a workflow").split()), validate=True)
            if len(raw) > MAX_WORKFLOW_BYTES:
                raise CannotTell("cannot tell: a workflow file is larger than this check reads")
            names.extend(security_jobs(raw.decode()))
        except (binascii.Error, ValueError):
            raise CannotTell("cannot tell: a workflow file cannot be decoded") from None
    return list(dict.fromkeys(names))


def satisfied(job: str, contexts: tuple[str, ...]) -> bool:
    """A required context names the job itself or, for a reusable workflow, `job / inner` or `outer / job`."""
    return any(c == job or c.startswith(job + " / ") or c.endswith(" / " + job) for c in contexts)


def judge(sources: list[Source], declared: list[str], require_app: int | None = None) -> tuple[list[str], list[str]]:
    """(the MISSING and DRIFT items, the reported states). Pure."""
    if not sources:
        return ["MISSING protection (no classic rule and no active ruleset applies)"], []
    items: list[str] = []
    if not ci_condition(sources, require_app).ok:
        items.append(
            "MISSING ci-green (the `CI green` check is not required"
            + (f" and pinned to app {require_app}" if require_app else "")
            + ")"
        )
    if not any(s.pr_required for s in sources):
        items.append("MISSING pull-request (a pull request is not required)")
    if not any(s.force_push_off for s in sources):
        items.append("DRIFT force-push (force pushes are allowed)")
    if not any(s.deletion_off for s in sources):
        items.append("DRIFT deletion (deleting the branch is allowed)")
    contexts = tuple(c for s in sources for c in s.contexts)
    items += [f"MISSING security-check {job}" for job in declared if not satisfied(job, contexts)]
    admins = "enforced" if all(s.admins_included for s in sources) else "can bypass"
    talk = "required" if any(s.conversation for s in sources) else "off"
    return items, [f"admins: {admins}", f"conversation resolution: {talk}"]


def audit(rest: Rest, board: Board, require_app: int | None = None) -> tuple[list[str], int]:
    """One line per tracked repository and a final count, with the exit code."""
    exempt = {x.lower() for x in board.rules.gate_exempt_repos}
    lines: list[str] = []
    read = drifted = unknown = 0
    for repo in board.repositories:
        name = repo.full_name
        if name.lower() in exempt:
            lines.append(f"EXEMPT {name}: listed in rules.gate_exempt_repos, not read")
            continue
        read += 1
        try:
            base = _repo_path(name)
            branch = read_repo(rest, base, name).default_branch
            if not BRANCH.fullmatch(branch):
                raise CannotTell("cannot tell: the default branch name is not one this check will put in a request")
            classic, rulesets, _ = read_sources(rest, base, branch, "")
            sources = ([classic] if classic else []) + [s for _, s in rulesets]
            items, states = judge(sources, declared_security(rest, base, branch), require_app)
        except CannotTell as err:
            unknown += 1
            lines.append(f"UNKNOWN {name}: {err}")
            continue
        except SafoError as err:
            unknown += 1
            lines.append(f"UNKNOWN {name}: {err}")
            continue
        if items:
            drifted += 1
            lines.append(f"{name}: " + "; ".join(items) + (f" [{', '.join(states)}]" if states else ""))
        else:
            lines.append(f"OK {name} [{', '.join(states)}]")
    tail = f"protection: {read} repositories read, {drifted} with drift" + (f", {unknown} unknown" if unknown else "")
    lines.append(tail)
    return lines, EXIT_UNKNOWN if unknown else (EXIT_DRIFT if drifted else EXIT_OK)
