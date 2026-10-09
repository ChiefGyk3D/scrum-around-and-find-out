# SPDX-License-Identifier: MIT
"""Copilot coding agent: sessions this month from `gh agent-task list`; premium requests only if billing can be read.

Exact premium-request use comes from the billing endpoint, which needs a token that may read it. That read is opt-in
(`safo usage --billing`), uses whatever `gh` already holds, never asks for a broader scope, and anything but a clean
answer is reported as unknown rather than guessed.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from safo.bounded import loads, number
from safo.bounded import month as valid_month

LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
DATE = re.compile(r"(?<!\d)(\d{4}-\d{2})-\d{2}(?!\d)")


@dataclass(frozen=True)
class CopilotUsage:
    available: bool  # gh is present, recent enough, and the account has the agent
    sessions: int | None  # this month's sessions; None when gh could not list them
    sessions_exact: bool  # False when the listing carried no dates, so sessions counts everything listed
    premium_requests: float | None
    allowance: int | None
    monthly_percent: float | None


def _gh(run: Callable[..., Any], gh: str, *args: str) -> str | None:
    try:
        done = run([gh, *args], stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False, timeout=30)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        return None  # absent, hung or unreadable: unknown, never a guess
    return str(done.stdout) if done.returncode == 0 and isinstance(done.stdout, str) else None


def read_copilot_usage(
    run: Callable[..., Any],
    which: Callable[[str], str | None],
    month: str,
    *,
    billing: bool,
    allowance: int | None,
) -> CopilotUsage:
    valid_month(month)
    gh = which("gh")
    if gh is None:
        return CopilotUsage(False, None, False, None, allowance, None)
    listing = _gh(run, gh, "agent-task", "list", "-L", "200")
    sessions: int | None = None
    exact = False
    if listing is not None:
        lines = [x for x in listing.splitlines() if x.strip()]
        dated = [m[1] for x in lines if (m := DATE.search(x))]
        exact = bool(dated)
        sessions = sum(1 for d in dated if d == month) if exact else len(lines)
    requests: float | None = None
    if billing:
        login = _gh(run, gh, "api", "user", "--jq", ".login")
        year, _, mon = month.partition("-")
        if login and LOGIN.fullmatch(login.strip()):
            body = _gh(
                run,
                gh,
                "api",
                f"/users/{login.strip()}/settings/billing/premium_request/usage?year={year}&month={int(mon)}",
            )
            requests = _premium_requests(body)
    percent = None  # premium requests and AI credits are different units; no assumed conversion
    return CopilotUsage(True, sessions, exact, requests, allowance, percent)


def _premium_requests(body: str | None) -> float | None:
    if not body:
        return None
    try:
        items = loads(body).get("usageItems")
    except (ValueError, AttributeError):
        return None
    if not isinstance(items, list):
        return None
    total = 0.0
    matched = False
    for item in items:
        if not isinstance(item, dict):
            return None
        if (item.get("product"), item.get("sku"), item.get("unitType")) != (
            "GitHub Copilot",
            "Copilot premium requests",
            "premium_requests",
        ):
            continue
        quantity = number(item.get("grossQuantity"))
        if quantity is None:
            return None
        total += quantity
        matched = True
    return total if matched else None


def cached_percent(path: Any, month: str, allowance: int | None) -> float | None:
    from safo.bounded import read_json

    try:
        row = read_json(path)
        if (
            not isinstance(row, dict)
            or row.get("product") != "GitHub Copilot"
            or row.get("sku") != "Copilot AI credits"
            or row.get("unit") != "ai_credits"
            or row.get("month") != valid_month(month)
        ):
            return None
        used = number(row.get("used"))
        return round(100 * used / allowance, 1) if used is not None and allowance and allowance > 0 else None
    except (OSError, ValueError, UnicodeError):
        return None
