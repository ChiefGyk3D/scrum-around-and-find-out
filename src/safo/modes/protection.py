# SPDX-License-Identifier: Apache-2.0
"""protection: read the default branch's protection back from GitHub and say which required condition does not hold.

Read-only (GET requests, read access). Exit 0 when every condition holds, 1 when any does not, 2 when it cannot tell.
Spec 8.5 row R2(a); the maintainer applies the protection, this only reads it.
"""

from __future__ import annotations

import argparse

from safo import credentials
from safo.context import LocalContext
from safo.errors import EXIT_DRIFT, EXIT_OK, EXIT_UNKNOWN, ConfigError
from safo.modes import LocalMode, register_local
from safo.protection import API_URL, CannotTell, Rest, check


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", required=True, help="owner/name of the repository to read")
    parser.add_argument("--agent-login", default="", help="the agent account; named if it may bypass the rule")
    parser.add_argument("--api-url", default=API_URL, help="the REST API (https; plain http for loopback only)")


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    if args.agent_login and not credentials.LOGIN.fullmatch(args.agent_login):
        raise ConfigError("agent-login is not a GitHub login")
    creds = credentials.from_env(ctx.env) or credentials.from_gh(ctx.env, ctx.env.get("SAFO_GH_USER", "").strip())
    if creds is None:
        raise credentials.NoTokenError(
            "no token: set SAFO_TOKEN, or log in with `gh auth login` (read access is enough)"
        )
    if creds.kind == credentials.GH and args.api_url != API_URL:
        raise ConfigError(f"a gh token is only sent to {API_URL}; --api-url cannot redirect it")
    try:
        branch, found, conditions = check(Rest(creds.token, args.api_url), args.repo, args.agent_login)
    except CannotTell as err:
        ctx.say(f"UNKNOWN {err}")
        return EXIT_UNKNOWN
    ctx.say(f"default branch: {branch}; protection found: {found if found else 'none (not protected)'}")
    for c in conditions:
        ctx.say(f"{'PASS' if c.ok else 'FAIL'} {c.id}: {c.text}" + (f" ({c.note})" if c.note and not c.ok else ""))
    failed = [c for c in conditions if not c.ok]
    ctx.say(
        f"protection: all {len(conditions)} conditions hold"
        if not failed
        else f"protection: {len(failed)} of {len(conditions)} conditions do not hold"
    )
    return EXIT_DRIFT if failed else EXIT_OK


register_local(
    LocalMode(
        "protection", "read the default branch's protection back (GET only); exit 2 when unreadable", add_arguments, run
    )
)
