# SPDX-License-Identifier: Apache-2.0
"""What the dispatch guard reads in a brief about Gemini (#200).

This is a speed bump against an honest or prompt-injected model writing a brief, not a sandbox: whoever can run
shell commands can reach the wrapper directly, and the wrapper (`safo.gemini`) is where the gates really are. The guard
therefore fails closed. After joining line continuations and removing quotes and backslashes, a brief counts as naming a
Gemini step when it has a declaration line (also as a list item), when `safo` and `gemini` appear within a short window
of each other, when `safo` sits beside a shell expansion and an action word, when it decodes base64 to a shell, when it
writes the vendor host (any case) or the Google genai SDK, or when it names the paid secret-store config. Every such
step must be proven complete and allowed by the strict parser; a step that cannot be is blocked, and a false positive is
a block, not a leak. Raw SDK use outside a brief is out of this guard's reach.

* every step needs the line `gemini-material: public`, and no secret-shaped string or private term anywhere in the
  brief: the free tier may train on prompts and be read by people;
* a paid step (`paid` or `--paid`, or the paid secret-store config named anywhere in the brief) needs a cap of at most
  2 USD and the id of an approval record that is live now.

Nothing here repeats any text of the brief in a reason. Every failure to check is a failure to pass: a check that
raises, or that does not exist, blocks.
"""

from __future__ import annotations

import bisect
import re
import shlex
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path

from safo.bounded import read_bounded
from safo.gemini import JOB_CAP, RECORD_ID, VENDOR_HOST, has_secret_shape
from safo.guardlog import config_dir
from safo.modes.gemini import BriefParseError, brief_namespace

GEMINI_PAID = "gemini-paid"
GEMINI_MATERIAL = "gemini-material"
GEMINI_RULES = (GEMINI_PAID, GEMINI_MATERIAL)

DECLARATION = re.compile(r"^\s*(?:[-*+]\s+|\d{1,3}[.)]\s+)?(?:#+\s*)?gemini(?:-step)?\s*:(?P<rest>.*)$", re.IGNORECASE)
MATERIAL = re.compile(r"^\s*(?:[-*+]\s+|\d{1,3}[.)]\s+)?gemini-material\s*:\s*(?P<value>.*?)\s*$", re.IGNORECASE)
PAID_CONFIG = re.compile(r"\bprd_paid\b")
SDK = re.compile(
    r"google[.\s-]*genai|google\s+import\s+[\w ,]{0,40}genai|google-generativeai|generativelanguage|genai\.client"
)
BASE64_SHELL = re.compile(r"base64\s+(?:-d\b|-D\b|--decode\b)")
OPERATORS = re.compile(r"[;&|<>()\n]")
ACTION_WORDS = ("ask", "approve", "--paid", "--cap", "--approval", "--model", "--material")
MARKERS = ("safo", "gemini", "generativelanguage", "genai", "prd_paid", "base64")
WINDOW = 240  # characters between `safo` and `gemini` for them to count as one command
LINE_CAP = 4000  # a line longer than this that mentions anything above is blocked unread
MAX_CANDIDATES = 50  # commands examined per brief; more than this is blocked
TERMS_CAP = 200
TERMS_FILE_BYTES = 65_536

ApprovalCheck = Callable[[str], str | None]


@dataclass(frozen=True)
class Step:
    """One Gemini step a brief names. `unreadable` means it could not be read, so it is treated as paid."""

    paid: bool = False
    cap: str | None = None
    approval: str | None = None
    unreadable: bool = False


def _tokens(rest: str) -> list[str] | None:
    try:
        return shlex.split(rest)
    except ValueError:
        return None


def _option(tokens: list[str], name: str) -> str | None:
    """`name=V`, `--name=V` or `--name V`, for the declaration lines only (a command goes through the real parser)."""
    for i, token in enumerate(tokens):
        for prefix in (f"{name}=", f"--{name}="):
            if token.lower().startswith(prefix):
                return token[len(prefix) :]
        if token.lower() == f"--{name}" and i + 1 < len(tokens):
            return tokens[i + 1]
    return None


def _declared(rest: str) -> Step:
    tokens = _tokens(rest)
    if tokens is None:
        return Step(unreadable=True)
    paid = "paid" in (x.lower() for x in tokens) or "--paid" in tokens or _option(tokens, "tier") == "paid"
    return Step(paid, _option(tokens, "cap"), _option(tokens, "approval"))


_PARSE_CACHE: dict[str, Step | None] = {}


def _command_tail_step(tail: str) -> Step | None:
    """One command's arguments (up to the first shell operator), read with the parser the CLI itself uses."""
    cut = OPERATORS.split(tail, 1)[0]
    key = cut.strip()
    if key in _PARSE_CACHE:
        return _PARSE_CACHE[key]
    try:
        ns = brief_namespace(key.split())
    except BriefParseError:
        step: Step | None = Step(unreadable=True)
    else:
        if ns.action == "quota":
            step = None  # not a step: it prints the quota line and sends nothing
        else:
            step = Step(bool(ns.paid) or ns.action == "approve", ns.cap or ns.max_usd or None, ns.approval or None)
    if len(_PARSE_CACHE) < 256:
        _PARSE_CACHE[key] = step
    return step


def _cap_problem(value: str | None) -> str | None:
    if value is None:
        return "a paid step states its cap (cap=USD) and the cap is at most 2 USD"
    try:
        cap = Decimal(value)
    except InvalidOperation:
        return "the cap of a paid step is not a number"
    if not cap.is_finite() or cap <= 0 or cap > JOB_CAP:
        return "the cap of a paid step is above 0 and at most 2 USD"
    return None


def _paid_problem(step: Step, check: ApprovalCheck | None) -> str | None:
    if step.unreadable:
        return (
            "a Gemini step could not be read exactly as the CLI would read it, so it is treated as paid and unapproved"
        )
    problem = _cap_problem(step.cap)
    if problem:
        return problem
    record = step.approval
    if not record or not RECORD_ID.fullmatch(record):
        return "a paid Gemini step needs a live approval record (approval=ID from `safo gemini approve`)"
    if check is None:
        return "a paid Gemini step needs a live approval record, and none can be checked here"
    try:
        why = check(record)
    except Exception:
        return "the approval record could not be checked, so the paid step is blocked"
    return f"the approval record is not usable: {why}" if why else None


_FAIL_CLOSED = [
    (GEMINI_PAID, "the brief could not be checked in time or in full, so any Gemini step in it is blocked"),
    (GEMINI_MATERIAL, "the brief could not be checked in time or in full, so any Gemini step in it is blocked"),
]


def findings(
    prompt: str,
    check: ApprovalCheck | None = None,
    terms: tuple[re.Pattern[str], ...] = (),
    deadline: float | None = None,
) -> list[tuple[str, str]]:
    """(rule, reason) for each Gemini rule the brief breaks, at most one entry per rule. Fails closed on a timeout."""
    lowered = prompt.lower()
    if not any(m in lowered for m in MARKERS):
        return []  # nothing in the brief can name Gemini, so there is nothing to time out on
    try:
        return _findings(prompt, check, terms, deadline)
    except TimeoutError:
        return list(_FAIL_CLOSED)


def _scan_line(line: str, steps: list[Step], flags: set[str], materials: list[str], budget: list[int]) -> None:
    clean = line.replace("'", "").replace('"', "").replace("`", "").replace("\\", "")
    low = clean.lower()
    if len(low) != len(clean):
        steps.append(Step(unreadable=True))  # a character whose lower case is a different length: do not guess
        return
    found = MATERIAL.match(clean)
    if found:
        materials.append(found.group("value").lower())
        return
    declared = DECLARATION.match(clean)
    if declared:
        steps.append(_declared(declared.group("rest")))
    if PAID_CONFIG.search(low):
        flags.add("paid")
    if VENDOR_HOST in low or SDK.search(low):
        flags.add("vendor")
    if BASE64_SHELL.search(low):
        steps.append(Step(unreadable=True))
    safos: list[int] = []
    at = low.find("safo")
    while at != -1:
        safos.append(at)
        at = low.find("safo", at + 4)
    if not safos or budget[0] <= 0:
        if safos and budget[0] <= 0:
            steps.append(Step(unreadable=True))
        return
    seen_gemini = False
    at = low.find("gemini")
    while at != -1:
        if safos[bisect.bisect_left(safos, at - WINDOW) : bisect.bisect_left(safos, at)]:
            seen_gemini = True
            budget[0] -= 1
            if budget[0] < 0:
                steps.append(Step(unreadable=True))
                return
            found_step = _command_tail_step(clean[at + 6 : at + 6 + LINE_CAP])
            if found_step is not None:
                steps.append(found_step)
        at = low.find("gemini", at + 6)
    if seen_gemini:
        return
    for s in safos:  # `safo` beside a shell expansion and an action word: a command built at run time
        near = low[s : s + WINDOW]
        if "$" in near and any(w in near for w in ACTION_WORDS):
            steps.append(Step(unreadable=True))
            return


def _findings(
    prompt: str, check: ApprovalCheck | None, terms: tuple[re.Pattern[str], ...], deadline: float | None
) -> list[tuple[str, str]]:
    def tick() -> None:
        if deadline is not None and time.monotonic() > deadline:
            raise TimeoutError("the Gemini check ran out of time")

    tick()
    joined = prompt.replace("\\\r\n", "").replace("\\\n", "")
    steps: list[Step] = []
    flags: set[str] = set()
    materials: list[str] = []
    budget = [MAX_CANDIDATES]
    for line in joined.splitlines():
        tick()
        if len(line) > LINE_CAP:
            if any(m in line.lower() for m in MARKERS):
                steps.append(Step(unreadable=True))
                if "generativelanguage" in line.lower() or "genai" in line.lower():
                    flags.add("vendor")
            continue
        _scan_line(line, steps, flags, materials, budget)
    if "vendor" in flags:
        steps.append(Step(unreadable=True))
    if "paid" in flags and not any(t.paid or t.unreadable for t in steps):
        steps.append(Step(paid=True))  # the paid key is named, so the step is paid, and it states no cap or record
    if not steps:
        return []
    tick()
    reasons: dict[str, list[str]] = {}

    def add(rule: str, why: str) -> None:
        reasons.setdefault(rule, []).append(why)

    if "vendor" in flags:
        add(GEMINI_MATERIAL, "call Gemini only through `safo gemini`, never the vendor API or its SDK directly")
    if not materials or any(m != "public" for m in materials):
        add(
            GEMINI_MATERIAL,
            "a Gemini step states `gemini-material: public`; private or sensitive material never goes to it",
        )
    if has_secret_shape(prompt):
        add(
            GEMINI_MATERIAL, "the brief holds something shaped like a secret or a private key; it must not go to Gemini"
        )
    if any(t.search(prompt) for t in terms):
        add(GEMINI_MATERIAL, "the brief matches one of the maintainer's private terms; it must not go to Gemini")
    for step in steps:
        tick()
        if step.paid or step.unreadable:
            problem = _paid_problem(step, check)
            if problem:
                add(GEMINI_PAID, problem)
    return [(rule, "; ".join(dict.fromkeys(why))) for rule, why in reasons.items()]


def load_terms(env: Mapping[str, str]) -> tuple[re.Pattern[str], ...]:
    """The maintainer's private terms, one regular expression per line, from $SAFO_PRIVACY_EXTRA_FILE or the config
    directory's privacy-terms.txt. Read, never written, never repeated. A file that cannot be read adds none."""
    given = env.get("SAFO_PRIVACY_EXTRA_FILE", "")
    folder = config_dir(env)
    path = given if given else (str(folder / "privacy-terms.txt") if folder else "")
    if not path:
        return ()
    try:
        text = read_bounded(Path(path), TERMS_FILE_BYTES).decode("utf-8")
    except (OSError, UnicodeError):
        return ()
    compiled: list[re.Pattern[str]] = []
    for line in text.splitlines()[:TERMS_CAP]:
        line = line.strip()
        if not line or line.startswith("#") or len(line) > 200:
            continue
        try:
            compiled.append(re.compile(line, re.IGNORECASE))
        except re.error:
            continue
    return tuple(compiled)
