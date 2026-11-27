# SPDX-License-Identifier: Apache-2.0
"""safo-protect-threads: turn on "require conversation resolution before merging" on a repository's default branch and
change nothing else (issue #541).

The REST call that edits branch protection (`PUT .../protection`) replaces the whole configuration, and what GET shows
cannot be turned back into a PUT body without loss (user, team and app objects, per-check apps, the separate signature
endpoint). So this tool uses the GraphQL mutation `updateBranchProtectionRule`, which changes only the fields it is
given, and passes exactly one: `requiresConversationResolution`.

    safo-protect-threads OWNER/NAME                              dry run: reads and prints the change, writes nothing
    safo-protect-threads OWNER/NAME --apply --backup-dir DIR     performs the mutation, then reads back and verifies

Before `--apply` writes anything the whole rule is saved to a new file (mode 0600) in DIR. After it, the rule is read
again and every field must equal what was read before, except the flag, which must be true; if not, the exact rollback
(the same mutation with false, and the saved file) is printed and the exit code is 6.

Refused with exit 3, changing nothing: a ruleset applies to the default branch (a different API; not guessed at), no
rule or more than one rule covers the default branch, more rules than one page holds, or the rule cannot be read in
full. No token is read or printed: `gh` holds the credential. Separate entry point, so the guard's
`TOP_LEVEL_COMMANDS` stays as it is.

Exit codes: 0 done (or already on); 2 usage; 3 refused; 4 a read failed; 5 the write failed and nothing changed;
6 the write was made but the read-back does not match (rollback printed).
"""

from __future__ import annotations

import argparse
import datetime as dt
import difflib
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

from safo import bounded, output
from safo.credentials import find_gh

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_REFUSED = 3
EXIT_READ = 4
EXIT_WRITE = 5
EXIT_VERIFY = 6

CALL_TIMEOUT = 60
FLAG = "requiresConversationResolution"
SLUG = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
BRANCH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/+@=-]{0,254}")
RULE_ID = re.compile(r"[A-Za-z0-9_=-]{1,200}")

BOOLS = (
    "allowsDeletions",
    "allowsForcePushes",
    "blocksCreations",
    "dismissesStaleReviews",
    "isAdminEnforced",
    "lockAllowsFetchAndMerge",
    "lockBranch",
    "requireLastPushApproval",
    "requiresApprovingReviews",
    "requiresCodeOwnerReviews",
    "requiresCommitSignatures",
    FLAG,
    "requiresDeployments",
    "requiresLinearHistory",
    "requiresStatusChecks",
    "requiresStrictStatusChecks",
    "restrictsPushes",
    "restrictsReviewDismissals",
)
STRING_LISTS = ("requiredDeploymentEnvironments", "requiredStatusCheckContexts")
COUNTS = ("pushAllowances", "bypassPullRequestAllowances", "bypassForcePushAllowances", "reviewDismissalAllowances")

QUERY = (
    "query($o:String!,$n:String!,$q:String!){repository(owner:$o,name:$n){defaultBranchRef{name} "
    "branchProtectionRules(first:100){pageInfo{hasNextPage} nodes{id pattern "
    + " ".join(BOOLS)
    + " requiredApprovingReviewCount "
    + " ".join(STRING_LISTS)
    + " requiredStatusChecks{context app{databaseId}} "
    + " ".join(
        f"{c}(first:100){{totalCount pageInfo{{hasNextPage}} nodes{{actor{{__typename ... on Node{{id}}}}}}}}"
        for c in COUNTS
    )
    + " matchingRefs(first:100,query:$q){nodes{name}}}}}}"
)
MUTATION = (
    "mutation($id:ID!){updateBranchProtectionRule(input:{branchProtectionRuleId:$id,"
    + FLAG
    + ":%s}){branchProtectionRule{"
    + FLAG
    + "}}}"
)

Run = Callable[..., Any]


class ProtectError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class Gh:
    gh: str
    env: Mapping[str, str]
    run: Run = subprocess.run

    def call(self, *args: str) -> tuple[int, str]:
        try:
            done = self.run(
                [self.gh, *args],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=CALL_TIMEOUT,
                env=dict(self.env),
            )
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return 127, ""
        return int(done.returncode), str(done.stdout or "")

    def json(self, what: str, *args: str) -> Any:
        rc, out = self.call(*args)
        if rc != 0:
            raise ProtectError(EXIT_READ, f"{what} failed (exit {rc})")  # stderr can echo request text: not shown
        try:
            return bounded.loads(out)
        except ValueError as error:
            raise ProtectError(EXIT_READ, f"{what} gave unreadable JSON") from error

    def graphql(self, what: str, query: str, **variables: str) -> Any:
        args = ["api", "graphql", "-f", f"query={query}"]
        for key, value in variables.items():
            args += ["-f", f"{key}={value}"]
        doc = self.json(what, *args)
        if not isinstance(doc, dict) or doc.get("errors") or not isinstance(doc.get("data"), dict):
            raise ProtectError(EXIT_READ, f"{what} was refused or unreadable")
        return doc["data"]


# -- reading ---------------------------------------------------------------------------------------------------------


def _actors(node: Any, where: str) -> list[str]:
    """The allowed actors of one allowance list as sorted `Type:id` text. A list longer than the page, one whose count
    does not match what was read, or an actor without an id is refused, so the read-back compares who, not how many."""
    total = node.get("totalCount") if isinstance(node, dict) else None
    page = node.get("pageInfo") if isinstance(node, dict) else None
    nodes = node.get("nodes") if isinstance(node, dict) else None
    if (
        not isinstance(total, int)
        or isinstance(total, bool)
        or not isinstance(page, dict)
        or page.get("hasNextPage") is not False
        or not isinstance(nodes, list)
        or len(nodes) != total
    ):
        raise ProtectError(
            EXIT_REFUSED, f"{where} is not readable in full (more than one page, or a count that does not match)"
        )
    actors = []
    for item in nodes:
        actor = item.get("actor") if isinstance(item, dict) else None
        kind = actor.get("__typename") if isinstance(actor, dict) else None
        ident = actor.get("id") if isinstance(actor, dict) else None
        if not isinstance(kind, str) or not isinstance(ident, str) or not kind or not ident:
            raise ProtectError(EXIT_REFUSED, f"{where} has an actor that cannot be identified")
        actors.append(f"{kind}:{ident}")
    return sorted(actors)


def snapshot(rule: Any) -> dict[str, Any]:
    """The fields of the rule this tool compares, strictly typed; a missing or mistyped field refuses."""
    if not isinstance(rule, dict):
        raise ProtectError(EXIT_REFUSED, "the protection rule is not readable")
    snap: dict[str, Any] = {}
    for key in ("id", "pattern"):
        if not isinstance(rule.get(key), str) or not rule[key]:
            raise ProtectError(EXIT_REFUSED, f"the rule's {key} is not readable")
        snap[key] = rule[key]
    if not RULE_ID.fullmatch(snap["id"]):
        raise ProtectError(EXIT_REFUSED, "the rule's id has an unexpected shape")
    for key in BOOLS:
        if not isinstance(rule.get(key), bool):
            raise ProtectError(EXIT_REFUSED, f"the rule's {key} is not readable")
        snap[key] = rule[key]
    count = rule.get("requiredApprovingReviewCount")
    if count is not None and (not isinstance(count, int) or isinstance(count, bool)):
        raise ProtectError(EXIT_REFUSED, "the rule's requiredApprovingReviewCount is not readable")
    snap["requiredApprovingReviewCount"] = count
    for key in STRING_LISTS:
        values = rule.get(key)
        if values is None:
            values = []
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise ProtectError(EXIT_REFUSED, f"the rule's {key} is not readable")
        snap[key] = sorted(values)
    checks = rule.get("requiredStatusChecks")
    if checks is None:
        checks = []
    if not isinstance(checks, list):
        raise ProtectError(EXIT_REFUSED, "the rule's requiredStatusChecks is not readable")
    pairs = []
    for check in checks:
        app = check.get("app") if isinstance(check, dict) else None
        app_id = app.get("databaseId") if isinstance(app, dict) else None
        if (
            not isinstance(check, dict)
            or not isinstance(check.get("context"), str)
            or (app is not None and (not isinstance(app_id, int) or isinstance(app_id, bool)))
        ):
            raise ProtectError(EXIT_REFUSED, "the rule's requiredStatusChecks is not readable")
        pairs.append([check["context"], app_id])
    snap["requiredStatusChecks"] = sorted(pairs, key=lambda p: (p[0], p[1] if p[1] is not None else -1))
    for key in COUNTS:
        snap[key] = _actors(rule.get(key), f"the rule's {key}")
    return snap


def covering(data: Any, branch: str) -> tuple[dict[str, Any], int]:
    """The one rule that covers `branch`, as a snapshot. Several, or none, is a refusal."""
    repo = data.get("repository") if isinstance(data, dict) else None
    rules = repo.get("branchProtectionRules") if isinstance(repo, dict) else None
    if (
        not isinstance(rules, dict)
        or not isinstance(rules.get("nodes"), list)
        or not isinstance(rules.get("pageInfo"), dict)
    ):
        raise ProtectError(EXIT_READ, "the rule list is unreadable")
    if rules["pageInfo"].get("hasNextPage") is not False:
        raise ProtectError(EXIT_REFUSED, "the repository has more protection rules than one page; not guessing")
    hits = []
    for rule in rules["nodes"]:
        refs = rule.get("matchingRefs") if isinstance(rule, dict) else None
        nodes = refs.get("nodes") if isinstance(refs, dict) else None
        if not isinstance(nodes, list):
            raise ProtectError(EXIT_READ, "the rule's matching branches are unreadable")
        if any(isinstance(n, dict) and n.get("name") == branch for n in nodes):
            hits.append(rule)
    if not hits:
        raise ProtectError(EXIT_REFUSED, "no branch protection rule covers the default branch (nothing to change)")
    if len(hits) > 1:
        raise ProtectError(EXIT_REFUSED, f"{len(hits)} protection rules cover the default branch; refusing to pick one")
    return snapshot(hits[0]), len(rules["nodes"])


def read_rule(gh: Gh, owner: str, name: str) -> tuple[dict[str, Any], str]:
    data = gh.graphql("the protection read", QUERY, o=owner, n=name, q="")
    branch = (((data.get("repository") or {}).get("defaultBranchRef")) or {}).get("name")
    if not isinstance(branch, str) or not BRANCH.fullmatch(branch):
        raise ProtectError(EXIT_READ, "the default branch name is unreadable")
    data = gh.graphql("the protection read", QUERY, o=owner, n=name, q=branch)  # the ref filter needs the name
    snap, _ = covering(data, branch)
    return snap, branch


def rulesets_apply(gh: Gh, repo: str, branch: str) -> bool:
    rules = gh.json("the ruleset read", "api", f"repos/{repo}/rules/branches/{branch}")
    if not isinstance(rules, list):
        raise ProtectError(EXIT_READ, "the ruleset read gave an unexpected shape")
    return bool(rules)


# -- output ----------------------------------------------------------------------------------------------------------


def _pretty(snap: Mapping[str, Any]) -> list[str]:
    return json.dumps(snap, indent=2, sort_keys=True).splitlines()


def diff_lines(old: Mapping[str, Any], new: Mapping[str, Any]) -> list[str]:
    return list(difflib.unified_diff(_pretty(old), _pretty(new), "current", "after", lineterm="", n=1))


def save_backup(directory: Path, repo: str, branch: str, old: Mapping[str, Any], stamp: str) -> Path:
    if directory.is_symlink() or not directory.is_dir():
        raise ProtectError(EXIT_USAGE, "--backup-dir must be an existing directory (not a symbolic link)")
    name = f"protection-{repo.replace('/', '-')}-{branch.replace('/', '_')}-{stamp}.json"
    path = directory / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(old, indent=2, sort_keys=True) + "\n")
    return path


def mutate(gh: Gh, rule_id: str, value: bool) -> int:
    rc, _ = gh.call("api", "graphql", "-f", "query=" + MUTATION % ("true" if value else "false"), "-f", f"id={rule_id}")
    return rc


def rollback_text(rule_id: str, backup: Path) -> list[str]:
    return [
        f"rollback: the same mutation with false (the full rule as it was is in {backup}):",
        "gh api graphql -f 'query=" + MUTATION % "false" + f"' -f id={rule_id}",
    ]


def run_tool(gh: Gh, repo: str, apply: bool, backup_dir: Path | None, now: Callable[[], str], out: TextIO) -> int:
    owner, name = repo.split("/")
    old, branch = read_rule(gh, owner, name)
    if rulesets_apply(gh, repo, branch):
        raise ProtectError(EXIT_REFUSED, f"a ruleset applies to {branch}: rulesets use a different API; not guessing")
    if old[FLAG]:
        output.write(out, f"{repo} {branch}: {FLAG} is already true; nothing to do")
        return EXIT_OK
    new = {**old, FLAG: True}
    output.write(out, f"{repo} {branch}: rule {old['pattern']!r}, {len(old['requiredStatusChecks'])} required check(s)")
    if old["pattern"] != branch:
        output.write(
            out, f"NOTE: the rule's pattern is {old['pattern']!r}; the change applies to everything it matches"
        )
    for line in diff_lines(old, new):
        output.write(out, line)
    if not apply:
        output.write(out, "dry run: nothing was written; add --apply --backup-dir DIR to make this change")
        return EXIT_OK
    if backup_dir is None:
        raise ProtectError(EXIT_USAGE, "--apply needs --backup-dir")
    backup = save_backup(backup_dir, repo, branch, old, now())
    output.write(out, f"saved the current rule to {backup} (mode 0600)")
    rc = mutate(gh, old["id"], True)
    try:
        after, _ = read_rule(gh, owner, name)
    except ProtectError:
        after = None
    if after == old and rc != 0:
        raise ProtectError(EXIT_WRITE, "the write failed and nothing changed")
    if after == new:
        output.write(out, f"applied and verified: {FLAG} is true and every other field equals what was read before")
        return EXIT_OK
    for line in rollback_text(old["id"], backup):
        output.write(out, line)
    output.write(out, "rollback body (the rule as it was): " + json.dumps(old, sort_keys=True))
    if after is None:
        raise ProtectError(EXIT_VERIFY, "the write was sent but the rule could not be read back")
    changed = sorted(k for k in new if after.get(k) != new[k])
    raise ProtectError(EXIT_VERIFY, "read-back differs from the expected rule in: " + ", ".join(changed or ["(shape)"]))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="safo-protect-threads", description=__doc__.split("\n\n")[0])
    parser.add_argument("repo", help="OWNER/NAME")
    parser.add_argument("--apply", action="store_true", help="perform the change (default is a dry run)")
    parser.add_argument("--backup-dir", type=Path, help="existing directory for the saved rule (required with --apply)")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
    run: Run = subprocess.run,
    now: Callable[[], str] = lambda: dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ"),
) -> int:
    env = os.environ if env is None else env
    out, err = out or sys.stdout, err or sys.stderr
    args = build_parser().parse_args(argv)
    if not SLUG.fullmatch(args.repo) or ".." in args.repo or args.repo.startswith("."):
        output.write(err, "error: need OWNER/NAME")
        return EXIT_USAGE
    if args.apply:
        directory = args.backup_dir
        if directory is None or directory.is_symlink() or not directory.is_dir():
            output.write(err, "error: --apply needs --backup-dir DIR, an existing directory (not a symbolic link)")
            return EXIT_USAGE
    gh_path = find_gh(env, os.getcwd())
    if gh_path is None:
        output.write(err, "error: gh must be on PATH")
        return EXIT_READ
    try:
        return run_tool(Gh(gh_path, env, run), args.repo, args.apply, args.backup_dir, now, out)
    except ProtectError as error:
        output.write(err, f"error: {error}")
        return error.code
    except OSError:
        output.write(err, "error: the backup file could not be written; nothing was changed")
        return EXIT_USAGE


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
