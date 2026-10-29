# SPDX-License-Identifier: Apache-2.0
"""What the dispatch guard reads in a brief about Gemini (#200).

A brief names a Gemini step in one of three ways: a declaration line (`gemini: free ...` or `gemini: paid cap=1.50
approval=ID`), a `safo gemini ask|approve` command, or the raw vendor host. Free-text mentions of the word are not a
step: the guard is a speed bump, and the wrapper (`safo.gemini`) is where the gates really are.

* every step needs the line `gemini-material: public`, and no secret-shaped string or private term anywhere in the
  brief: the free tier may train on prompts and be read by people;
* a paid step (`paid` or `--paid`, or the paid secret-store config named anywhere in the brief) needs a cap of at most
  2 USD and the id of an approval record that is live now.

Nothing here repeats any text of the brief in a reason. Every failure to check is a failure to pass: a check that
raises, or that does not exist, blocks.
"""

from __future__ import annotations

import os
import re
import shlex
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

DECLARATION = re.compile(r"^\s*gemini(?:-step)?\s*:(?P<rest>.*)$", re.IGNORECASE)
COMMAND = re.compile(r"\bsafo\b.*\bgemini\b")
MATERIAL = re.compile(r"^\s*gemini-material\s*:\s*(?P<value>.*?)\s*$", re.IGNORECASE)
PAID_CONFIG = re.compile(r"\bprd_paid\b")
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


def _segments(line: str) -> list[list[str]] | None:
    """The line's simple commands (split at shell operators), or None when it cannot be tokenized."""
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return None
    segments: list[list[str]] = [[]]
    for token in tokens:
        if all(c in lexer.punctuation_chars for c in token):
            segments.append([])
        else:
            segments[-1].append(token)
    return segments


def _command_steps(line: str) -> list[Step]:
    """Each `safo ... gemini ...` command on the line, read with the parser the CLI itself uses (no abbreviations,
    the same options), so the guard and the CLI cannot disagree about a spelling."""
    segments = _segments(line)
    if segments is None:
        return [Step(unreadable=True)]
    steps: list[Step] = []
    for words in segments:
        names = [os.path.basename(w) for w in words]
        if "safo" not in names:
            continue
        start = names.index("safo")
        if "gemini" not in names[start + 1 :]:
            continue
        tail = words[names.index("gemini", start + 1) + 1 :]
        try:
            ns = brief_namespace(tail)
        except BriefParseError:
            steps.append(Step(unreadable=True))
            continue
        if ns.action == "quota":
            continue
        steps.append(Step(bool(ns.paid) or ns.action == "approve", ns.cap or ns.max_usd or None, ns.approval or None))
    return steps


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


def findings(
    prompt: str, check: ApprovalCheck | None = None, terms: tuple[re.Pattern[str], ...] = ()
) -> list[tuple[str, str]]:
    """(rule, reason) for each Gemini rule the brief breaks, at most one entry per rule."""
    steps: list[Step] = []
    materials: list[str] = []
    for line in prompt.splitlines():
        found = MATERIAL.match(line)
        if found:
            materials.append(found.group("value").lower())
            continue
        found = DECLARATION.match(line)
        if found:
            steps.append(_declared(found.group("rest")))
        elif COMMAND.search(line):
            steps.extend(_command_steps(line))
    if VENDOR_HOST in prompt and not steps:
        steps.append(Step())  # raw use of the API is a step too, and bypasses every gate the wrapper has
    if not steps:
        return []
    reasons: dict[str, list[str]] = {}

    def add(rule: str, why: str) -> None:
        reasons.setdefault(rule, []).append(why)

    if VENDOR_HOST in prompt:
        add(GEMINI_MATERIAL, "call Gemini only through `safo gemini`, never the vendor API directly")
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
    paid_steps = [t for t in steps if t.paid or t.unreadable]
    if PAID_CONFIG.search(prompt) and not paid_steps:
        paid_steps.append(Step(paid=True))  # the paid key is named, so the step is paid, and it states no cap or record
    for step in paid_steps:
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
