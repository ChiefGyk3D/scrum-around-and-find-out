# SPDX-License-Identifier: Apache-2.0
"""protection: read the default branch's protection back from GitHub and say which required condition does not hold.

Read-only (GET requests, read access). Exit 0 when every condition holds, 1 when any does not, 2 when it cannot tell.
Spec 8.5 row R2(a); the maintainer applies the protection, this only reads it.
"""

from __future__ import annotations

import argparse
import contextlib
import re

from safo import credentials
from safo.context import LocalContext
from safo.errors import EXIT_DRIFT, EXIT_INTERRUPTED, EXIT_OK, EXIT_UNKNOWN, ConfigError, SafoError
from safo.modes import LocalMode, register_local
from safo.protection import API_URL, CannotTell, Rest, check


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", required=True, help="owner/name of the repository to read")
    parser.add_argument("--agent-login", default="", help="the agent account; named if it may bypass the rule")
    parser.add_argument(
        "--require-app-id",
        default="",
        help="fail ci-green unless every `CI green` check is pinned to this app id (GitHub Actions is 15368)",
    )
    parser.add_argument("--api-url", default=API_URL, help="the REST API (https; plain http for loopback only)")



def emit(ctx: LocalContext, lines: list[str], code: int) -> int:
    """Write the report; the decision `code` was computed before any output and does not depend on it.

    If the output cannot be written (a closed pipe), a failure (1) or an unknown (2) stays as it was, and a pass (0)
    becomes 2: a pass that nobody could read is not reported as one.
    """
    try:
        for line in lines:
            ctx.say(line)
    except Exception:  # a closed pipe, a closed stream, or whatever a reporting backend raises: the decision stands
        return code or EXIT_UNKNOWN
    return code


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    """The one boundary: only a deliberate SafoError (a usage or credential problem, handled by the command line) and
    the three documented codes ever leave this function. An interrupt is 130; anything else, an unexpected exception or
    any SystemExit (even `SystemExit(0)`) or GeneratorExit from a dependency, is 2 with only the class name reported, so
    1 stays the code of a decision that was computed and 0 the code of a pass."""
    try:
        return _run(ctx, args)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except SafoError:
        raise
    except BaseException as err:
        with contextlib.suppress(BaseException):  # reporting the failure must not change the code
            ctx.say(f"UNKNOWN cannot tell: internal error ({type(err).__name__})")
        return EXIT_UNKNOWN


def _run(ctx: LocalContext, args: argparse.Namespace) -> int:
    if args.agent_login and not credentials.LOGIN.fullmatch(args.agent_login):
        raise ConfigError("agent-login is not a GitHub login")
    if args.require_app_id and not re.fullmatch(r"[1-9][0-9]{0,15}", args.require_app_id):
        raise ConfigError("require-app-id must be a positive app id")
    creds = credentials.from_env(ctx.env) or credentials.from_gh(ctx.env, ctx.env.get("SAFO_GH_USER", "").strip())
    if creds is None:
        raise credentials.NoTokenError(
            "no token: set SAFO_TOKEN, or log in with `gh auth login` (read access is enough)"
        )
    if creds.kind == credentials.GH and args.api_url != API_URL:
        raise ConfigError(f"a gh token is only sent to {API_URL}; --api-url cannot redirect it")
    try:
        branch, found, conditions = check(
            Rest(creds.token, args.api_url),
            args.repo,
            args.agent_login,
            int(args.require_app_id) if args.require_app_id else None,
        )
    except CannotTell as err:
        return emit(ctx, [f"UNKNOWN {err}"], EXIT_UNKNOWN)
    failed = [c for c in conditions if not c.ok]
    code = EXIT_DRIFT if failed else EXIT_OK
    lines = [f"default branch: {branch}; protection found: {found if found else 'none (not protected)'}"]
    for c in conditions:
        shown = f" (matched: {c.matched})" if c.matched else (f" ({c.note})" if c.note and not c.ok else "")
        lines.append(f"{'PASS' if c.ok else 'FAIL'} {c.id}: {c.text}{shown}")
        if c.warn:
            lines.append(f"NOTE {c.id}: {c.warn}")  # never changes the exit code on its own
    lines.append(
        f"protection: all {len(conditions)} conditions hold"
        if not failed
        else f"protection: {len(failed)} of {len(conditions)} conditions do not hold"
    )
    return emit(ctx, lines, code)


register_local(
    LocalMode(
        "protection", "read the default branch's protection back (GET only); exit 2 when unreadable", add_arguments, run
    )
)
