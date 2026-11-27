# SPDX-License-Identifier: Apache-2.0
"""safo-threads: list the open review threads of a pull request, then reply to and resolve them from a file.

`list REPO PR` prints the unresolved review threads (outdated ones marked `[outdated]`) grouped by file, one line
each, with the first comment's id, author and the first 200 characters of its body. `apply REPO PR FILE` reads a
strict JSON list of dispositions `[{"comment_id": 1, "action": "reply|reply_resolve|skip", "body": "..."}]` and
carries them out: a reply is
one REST POST, a resolve is one GraphQL `resolveReviewThread` mutation for that thread.

Every disposition is checked against the live thread list and the file's own rules before the first write, so a bad
file writes nothing. After that the writes run one at a time and stop at the first failure (a reply is never retried:
a POST whose outcome is unknown could double-post). A thread is resolved only after its reply was accepted. No token is
read or printed: `gh` holds the credential. Separate entry point (not a `safo` subcommand) so that the guard's
`TOP_LEVEL_COMMANDS` stays as it is.

Exit codes: 0 done; 2 usage; 3 the dispositions file is refused (nothing was written); 4 a read from GitHub failed
(nothing was written); 5 a write failed (earlier writes in the run stand and are printed).
"""

from __future__ import annotations

import argparse
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
EXIT_FILE = 3
EXIT_READ = 4
EXIT_WRITE = 5

CALL_TIMEOUT = 60
PAGE = 50
MAX_PAGES = 20  # 1000 threads; more is refused, not silently cut
SHOW = 200
MAX_BODY = 2000
MAX_ITEMS = 200
FILE_LIMIT = 262_144
ACTIONS = ("reply", "reply_resolve", "skip")
SLUG = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
THREAD_ID = re.compile(r"[A-Za-z0-9_=-]{1,200}")

Run = Callable[..., Any]

QUERY = (
    "query($owner:String!,$name:String!,$number:Int!,$cursor:String){repository(owner:$owner,name:$name)"
    "{pullRequest(number:$number){reviewThreads(first:50,after:$cursor){pageInfo{hasNextPage endCursor}"
    "nodes{id isResolved isOutdated path line comments(first:1){nodes{databaseId author{login} body}}}}}}}"
)
MUTATION = "mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{isResolved}}}"


class ThreadsError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Thread:
    thread_id: str
    comment_id: int
    path: str
    line: str
    author: str
    body: str
    outdated: bool = False


@dataclass(frozen=True)
class Disposition:
    comment_id: int
    action: str
    body: str


def flat(text: str, limit: int) -> str:
    """One line: every whitespace run is one space, cut to `limit`. Control characters are escaped on output."""
    return " ".join(("".join(" " if c.isspace() else c for c in text)).split())[:limit]


@dataclass
class Gh:
    gh: str
    env: Mapping[str, str]
    run: Run = subprocess.run
    cwd: str | None = None

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
                cwd=self.cwd,
            )
        except (OSError, ValueError, subprocess.TimeoutExpired):  # ValueError: a NUL or lone surrogate in argv
            return 127, ""
        return int(done.returncode), str(done.stdout or "")

    def json(self, code: int, *args: str) -> Any:
        rc, out = self.call(*args)
        if rc != 0:
            raise ThreadsError(code, f"gh {args[0]} failed (exit {rc})")  # gh's stderr can echo request text: not shown
        try:
            return bounded.loads(out)
        except ValueError as error:
            raise ThreadsError(code, f"gh {args[0]} gave unreadable JSON") from error


def fetch_threads(gh: Gh, repo: str, number: int) -> list[Thread]:
    """Unresolved threads of the PR, outdated ones included (the merge watcher counts them).

    The answer is checked field by field and a bad shape is exit 4."""
    owner, name = repo.split("/", 1)
    found: list[Thread] = []
    cursor = ""
    for _ in range(MAX_PAGES):
        args = ["api", "graphql", "-f", f"query={QUERY}", "-f", f"owner={owner}", "-f", f"name={name}"]
        args += ["-F", f"number={number}"] + (["-f", f"cursor={cursor}"] if cursor else [])
        data = gh.json(EXIT_READ, *args)
        try:
            if data.get("errors"):
                raise ThreadsError(EXIT_READ, "GitHub answered with errors")
            block = data["data"]["repository"]["pullRequest"]["reviewThreads"]
            nodes = block["nodes"]
            more = block["pageInfo"]["hasNextPage"]
            if not isinstance(more, bool):
                raise ValueError("hasNextPage")
            cursor = str(block["pageInfo"]["endCursor"] or "")
            for node in nodes:
                if node["isResolved"]:
                    continue
                first = node["comments"]["nodes"][0]
                comment_id, thread_id = first["databaseId"], node["id"]
                if isinstance(comment_id, bool) or not isinstance(comment_id, int) or comment_id < 1:
                    raise ValueError("comment id")
                if not isinstance(thread_id, str) or not THREAD_ID.fullmatch(thread_id):
                    raise ValueError("thread id")
                found.append(
                    Thread(
                        thread_id,
                        comment_id,
                        str(node.get("path") or "?"),
                        str(node.get("line") or "?"),
                        str((first.get("author") or {}).get("login") or "?"),
                        str(first.get("body") or ""),
                        node["isOutdated"] is True,
                    )
                )
        except ThreadsError:
            raise
        except (KeyError, TypeError, IndexError, AttributeError, ValueError) as error:
            raise ThreadsError(EXIT_READ, "unreadable review-thread answer") from error
        if not more:
            return found
        if not cursor:
            raise ThreadsError(EXIT_READ, "unreadable review-thread answer")
    raise ThreadsError(EXIT_READ, f"more than {PAGE * MAX_PAGES} review threads: not read in full")


def parse_dispositions(path: Path) -> list[Disposition]:
    try:
        raw = bounded.read_bounded(path, FILE_LIMIT + 1)
    except OSError as error:
        raise ThreadsError(EXIT_FILE, f"cannot read the dispositions file ({type(error).__name__})") from error
    if len(raw) > FILE_LIMIT:
        raise ThreadsError(EXIT_FILE, "dispositions file is too large")
    try:
        data = bounded.loads(raw, FILE_LIMIT)
    except ValueError as error:  # includes duplicate keys, depth, size, bad UTF-8; the message names no value
        raise ThreadsError(EXIT_FILE, f"dispositions file is not valid JSON: {type(error).__name__}") from error
    if not isinstance(data, list) or not data:
        raise ThreadsError(EXIT_FILE, "dispositions must be a non-empty JSON list")
    if len(data) > MAX_ITEMS:
        raise ThreadsError(EXIT_FILE, f"more than {MAX_ITEMS} dispositions")
    items: list[Disposition] = []
    seen: set[int] = set()
    for index, row in enumerate(data, 1):
        where = f"disposition {index}"
        if not isinstance(row, dict):
            raise ThreadsError(EXIT_FILE, f"{where} is not an object")
        extra = set(row) - {"comment_id", "action", "body"}
        if extra or "comment_id" not in row or "action" not in row:
            raise ThreadsError(EXIT_FILE, f"{where} needs comment_id and action (and body), nothing else")
        cid, action, body = row["comment_id"], row["action"], row.get("body", "")
        if isinstance(cid, bool) or not isinstance(cid, int) or cid < 1:
            raise ThreadsError(EXIT_FILE, f"{where} has a comment_id that is not a positive integer")
        if action not in ACTIONS:
            raise ThreadsError(EXIT_FILE, f"{where} has an action that is not one of {', '.join(ACTIONS)}")
        if not isinstance(body, str):
            raise ThreadsError(EXIT_FILE, f"{where} has a body that is not text")
        if action == "skip" and "body" in row:
            raise ThreadsError(EXIT_FILE, f"{where} is a skip and must not carry a body")
        if chr(0) in body:
            raise ThreadsError(EXIT_FILE, f"{where} has a body with a NUL character")
        try:
            body.encode("utf-8")  # a lone surrogate cannot be passed to gh
        except UnicodeEncodeError as error:
            raise ThreadsError(EXIT_FILE, f"{where} has a body that is not valid text") from error
        if action != "skip":
            if not body.strip():
                raise ThreadsError(EXIT_FILE, f"{where} has an empty body")
            if len(body) > MAX_BODY:
                raise ThreadsError(EXIT_FILE, f"{where} has a body over {MAX_BODY} characters")
        if cid in seen:
            raise ThreadsError(EXIT_FILE, f"{where} repeats comment_id {cid}")
        seen.add(cid)
        items.append(Disposition(cid, action, body))
    return items


def list_cmd(gh: Gh, repo: str, number: int, out: TextIO) -> int:
    threads = fetch_threads(gh, repo, number)
    if not threads:
        output.write(out, f"no unresolved threads on {repo}#{number}")
        return EXIT_OK
    by_file: dict[str, list[Thread]] = {}
    for thread in threads:
        by_file.setdefault(thread.path, []).append(thread)
    for path in sorted(by_file):
        output.write(out, flat(path, 300))
        for t in by_file[path]:
            mark = "[outdated] " if t.outdated else ""
            where = f"{flat(t.path, 100)}:{flat(t.line, 10)}"
            output.write(out, f"  {t.comment_id} {where} {mark}{flat(t.author, 60)}: {flat(t.body, SHOW)}")
    output.write(out, f"{len(threads)} unresolved thread(s) on {repo}#{number}")
    return EXIT_OK


def apply_cmd(gh: Gh, repo: str, number: int, path: Path, out: TextIO) -> int:
    items = parse_dispositions(path)
    known = {t.comment_id: t for t in fetch_threads(gh, repo, number)}
    for item in items:
        if item.comment_id not in known:
            raise ThreadsError(
                EXIT_FILE, f"comment_id {item.comment_id} is not an unresolved thread of {repo}#{number}"
            )
    done = 0
    for item in items:
        if item.action == "skip":
            output.write(out, f"skip {item.comment_id}")
            continue
        code, _out = gh.call(
            "api",
            "-X",
            "POST",
            f"repos/{repo}/pulls/{number}/comments/{item.comment_id}/replies",
            "-f",
            f"body={item.body}",
        )
        if code != 0:
            output.write(out, f"{done} of {len(items)} done before this failure")
            raise ThreadsError(EXIT_WRITE, f"reply to {item.comment_id} failed (exit {code}); not retried")
        output.write(out, f"replied {item.comment_id}")
        if item.action == "reply_resolve":
            answer = None
            try:
                answer = gh.json(
                    EXIT_WRITE,
                    "api",
                    "graphql",
                    "-f",
                    f"query={MUTATION}",
                    "-f",
                    f"id={known[item.comment_id].thread_id}",
                )
                resolved = answer["data"]["resolveReviewThread"]["thread"]["isResolved"] is True and not answer.get(
                    "errors"
                )
            except ThreadsError:
                resolved = False
            except (KeyError, TypeError, AttributeError):
                resolved = False
            if not resolved:
                raise ThreadsError(EXIT_WRITE, f"reply to {item.comment_id} posted, but the thread was not resolved")
            output.write(out, f"resolved {item.comment_id}")
        done += 1
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="safo-threads", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name, text in (("list", "show unresolved review threads"), ("apply", "reply and resolve from a file")):
        p = sub.add_parser(name, help=text)
        p.add_argument("repo", help="OWNER/NAME")
        p.add_argument("pr", type=int, help="pull request number")
        if name == "apply":
            p.add_argument("file", type=Path, help="JSON file of dispositions")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
    run: Run = subprocess.run,
) -> int:
    env = os.environ if env is None else env
    out, err = out or sys.stdout, err or sys.stderr
    parser = build_parser()
    args = parser.parse_args(argv)
    if not SLUG.fullmatch(args.repo) or ".." in args.repo or args.repo.startswith(".") or args.pr < 1:
        output.write(err, "error: need OWNER/NAME and a positive pull request number")
        return EXIT_USAGE
    gh_path = find_gh(env, os.getcwd())
    if gh_path is None:
        output.write(err, "error: gh must be on PATH")
        return EXIT_READ
    gh = Gh(gh_path, env, run)
    try:
        if args.command == "list":
            return list_cmd(gh, args.repo, args.pr, out)
        return apply_cmd(gh, args.repo, args.pr, args.file, out)
    except ThreadsError as error:
        output.write(err, f"error: {error}")
        return error.code


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
