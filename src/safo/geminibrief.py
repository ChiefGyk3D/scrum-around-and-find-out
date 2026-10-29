# SPDX-License-Identifier: Apache-2.0
"""What the dispatch guard reads in a brief about Gemini (#200).

This is a speed bump against an honest or prompt-injected model writing a brief, not a sandbox: whoever can run shell
commands can reach the wrapper directly, and the wrapper (`safo.gemini`) is where the gates really are. The guard fails
closed, but only on things that look like a command. After NFKC normalization, joining line continuations and removing
quotes and backslashes, a brief names a Gemini step when it has

* a declaration line in the exact grammar: `gemini: free` or `gemini: paid cap=USD approval=ID` (also as a list item),
  with nothing after the tier but `key=value` pairs;
* a command: a `safo` token, then within a few tokens a `gemini` token, then an action word (`ask`, `approve`,
  `quota`). It is cut at `; | & )`, read with the parser the CLI itself uses (a redirection inside it is unreadable),
  and a path such as `src/safo/gemini.py` or a model id such as `gemini-3.6-flash` is never a command start;
* a `gemini` or `safo` token beside a shell expansion, glob, brace, backtick or `%` and an `ask` or `approve` word, so
  a command built at run time cannot hide its name;
* a decode-to-shell form (base64, openssl, xxd, rev, printf escapes piped to a shell), the vendor host in any case, the
  Google genai SDK, or the name of the paid secret-store config.

Every step must be proven complete (cap, approval, `gemini-material: public`) or the brief is blocked, and a block names
the line, the reason and the fix. A false positive is a block, not a leak. Raw SDK use outside a brief is out of this
guard's reach. Nothing here repeats any text of the brief in a reason.
"""

from __future__ import annotations

import bisect
import dataclasses
import re
import shlex
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from safo.gemini import JOB_CAP, RECORD_ID, VENDOR_HOST, has_secret_shape, private_term_hit
from safo.modes.gemini import BriefParseError, brief_namespace

GEMINI_PAID = "gemini-paid"
GEMINI_MATERIAL = "gemini-material"
GEMINI_RULES = (GEMINI_PAID, GEMINI_MATERIAL)

DECLARATION = re.compile(r"^\s*(?:[-*+]\s+|\d{1,3}[.)]\s+)?(?:#+\s*)?gemini(?:-step)?\s*:(?P<rest>.*)$", re.IGNORECASE)
MATERIAL = re.compile(r"^\s*(?:[-*+]\s+|\d{1,3}[.)]\s+)?gemini-material\s*:\s*(?P<value>.*?)\s*$", re.IGNORECASE)
MARKDOWN_LINK = re.compile(r"\[[^\]\s]{0,200}\]\([^)\s]{0,300}\)")
MARKDOWN_CODE = re.compile(r"`(safo\b[^`]*)`")
PAID_CONFIG = re.compile(r"\bprd_paid\b")
SDK = re.compile(
    r"google[.\s-]*genai|google\s+import\s+[\w ,]{0,40}genai|google-generativeai|generativelanguage|genai\.client"
)
SINK = r"(?:\|\s*(?:sh|bash|zsh|dash|ksh)\b|\b(?:eval|exec|source)\b|\$\()"
DECODE = re.compile(
    r"(?:base64\s+(?:-d\b|-D\b|--decode\b)|openssl\s+[^|]{0,40}-d\b|xxd\s+-r|\brev\b|printf\s+[^|]{0,80}\\x)"
)
SINK_RE = re.compile(SINK)
SHELL_WILD = frozenset("$*?[]{}`%")
RISKY_ACTIONS = ("ask", "approve")
ACTIONS = ("ask", "approve", "quota")
# a path or file name about the feature, for example src/safo/gemini.py or tests/test_gemini*.py
# inline code in prose that wraps a known word, an option or a file name; any other word in backticks runs as a command
MARKDOWN_WORD = re.compile(
    r"^`(?:ask|approve|quota|gemini|safo|--[a-z-]{1,30}|[\w.-]{0,60}[./][\w./-]{0,100})`[.,:;)]*$"
)
PATHLIKE = re.compile(r"^[\w./-]*gemini[\w./*-]*$", re.IGNORECASE)
MARKERS = (
    "safo",
    "gemini",
    "generativelanguage",
    "genai",
    "prd_paid",
    "base64",
    "xxd",
    "openssl",
    "| rev",
    "|rev",
    "printf",
)
TOKEN_WINDOW = 12  # tokens between `safo` and `gemini` for them to count as one command
LINE_CAP = 4000  # a line longer than this that mentions anything above is blocked unread
MAX_CANDIDATES = 50  # commands examined per brief; more than this is blocked
FIX = (
    "reword the mention (keep `safo`, `gemini` and ask/approve out of one line), or write the step as one plain "
    "`safo gemini ask --model M ...` command, or as a `gemini: free` or `gemini: paid cap=USD approval=ID` line"
)

ApprovalCheck = Callable[[str], str | None]


@dataclass(frozen=True)
class Step:
    """One Gemini step a brief names. `unreadable` means it could not be read, so it is treated as paid."""

    paid: bool = False
    cap: str | None = None
    approval: str | None = None
    unreadable: bool = False
    line: int = 0
    why: str = ""


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


KEYVALUE = re.compile(r"^[A-Za-z_-]{1,20}=\S{0,200}$")


def _declared(rest: str, line: int) -> Step | None:
    """A declaration line in the exact grammar: a tier (`free` or `paid`) and then only key=value pairs. Anything else
    after `gemini:` is prose (a heading, a sentence) and is not a step."""
    tokens = _tokens(rest)
    if tokens is None:
        return Step(unreadable=True, line=line, why="the declaration has an unbalanced quote")
    if not tokens or tokens[0].lower().startswith("tier="):
        tier = tokens[0].lower().removeprefix("tier=") if tokens else ""
        pairs = tokens[1:]
    else:
        tier, pairs = tokens[0].lower(), tokens[1:]
    if tier not in ("free", "paid") or not all(KEYVALUE.match(t) for t in pairs):
        return None
    return Step(tier == "paid", _option(tokens, "cap"), _option(tokens, "approval"), line=line)


_PARSE_CACHE: dict[str, Step | None] = {}


def _command_step(span: list[str], line: int) -> Step | None:
    """One command's arguments, read with the parser the CLI itself uses. A redirection or an expansion inside the
    command is unreadable: the shell would act on it before the parser ever sees it."""
    text = " ".join(span)
    if "<" in text or ">" in text:
        return Step(unreadable=True, line=line, why="the command has a redirection, which can hide an option")
    if any(c in text for c in SHELL_WILD):
        return Step(unreadable=True, line=line, why="the command has a shell expansion, glob, brace or backtick")
    if text in _PARSE_CACHE:
        cached = _PARSE_CACHE[text]
        return None if cached is None else dataclasses.replace(cached, line=line)
    try:
        ns = brief_namespace(span)
    except BriefParseError:
        step: Step | None = Step(
            unreadable=True,
            line=line,
            why="the command is not one the CLI accepts (an unknown or shortened option, a missing value)",
        )
    else:
        if ns.action == "quota":
            step = None  # not a step: it prints the quota line and sends nothing
        else:
            step = Step(
                bool(ns.paid) or ns.action == "approve", ns.cap or ns.max_usd or None, ns.approval or None, line=line
            )
    if len(_PARSE_CACHE) < 256:
        _PARSE_CACHE[text] = step
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
    where = f"line {step.line}: " if step.line else ""
    if step.unreadable:
        return (
            f"{where}{step.why or 'this Gemini step could not be read exactly as the CLI reads it'}, so it is treated "
            f"as paid and unapproved; {FIX}"
        )
    problem = _cap_problem(step.cap)
    if problem:
        return f"{where}{problem}"
    record = step.approval
    if not record or not RECORD_ID.fullmatch(record):
        return f"{where}a paid Gemini step needs a live approval record (approval=ID from `safo gemini approve`)"
    if check is None:
        return f"{where}a paid Gemini step needs a live approval record, and none can be checked here"
    try:
        why = check(record)
    except Exception:
        return f"{where}the approval record could not be checked, so the paid step is blocked"
    return f"{where}the approval record is not usable: {why}" if why else None


_FAIL_CLOSED = [
    (GEMINI_PAID, "the brief could not be checked in time or in full, so any Gemini step in it is blocked"),
    (GEMINI_MATERIAL, "the brief could not be checked in time or in full, so any Gemini step in it is blocked"),
]

TermsSource = tuple[re.Pattern[str], ...] | Callable[[], tuple[re.Pattern[str], ...]]


def findings(
    prompt: str,
    check: ApprovalCheck | None = None,
    terms: TermsSource = (),
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


def _core(token: str) -> str:
    return token.strip("()${};|&,:'\"`").lower()


def _is_safo(token: str) -> bool:
    base = _core(token).rsplit("/", 1)[-1]
    return base == "safo" or base.startswith("safo.")


def _span(tokens: list[str], start: int) -> list[str]:
    """The arguments of a command: up to the first shell operator (`; | & )`), which may sit inside a token."""
    span: list[str] = []
    for token in tokens[start:]:
        cut = min((i for i in (token.find(c) for c in ";|&)") if i != -1), default=-1)
        if cut == -1:
            span.append(token)
            continue
        if cut > 0:
            span.append(token[:cut])
        break
    return span


def _scan_line(
    number: int, line: str, steps: list[Step], flags: dict[str, int], materials: list[str], budget: list[int]
) -> None:
    norm = unicodedata.normalize("NFKC", line)
    # markdown inline code around a whole command: `safo gemini quota ...` is the command, not a shell substitution
    norm = MARKDOWN_CODE.sub(r" \1 ; ", MARKDOWN_LINK.sub(" ", norm))
    raw_tokens = norm.split()
    clean = norm.replace("'", "").replace('"', "").replace("\\", "")
    low = clean.lower()
    found = MATERIAL.match(clean)
    if found:
        materials.append(found.group("value").lower())
        return
    declared = DECLARATION.match(clean)
    if declared:
        step = _declared(declared.group("rest"), number)
        if step is not None:
            steps.append(step)
    if PAID_CONFIG.search(low):
        flags.setdefault("paid", number)
    if VENDOR_HOST in low or SDK.search(low):
        flags.setdefault("vendor", number)
    if DECODE.search(norm.lower()) and SINK_RE.search(norm.lower()):
        steps.append(Step(unreadable=True, line=number, why="the line decodes text and hands it to a shell"))
    tokens = clean.split()
    safos = [i for i, t in enumerate(tokens) if _is_safo(t)]
    geminis = [i for i, t in enumerate(tokens) if _core(t) == "gemini"]
    if not safos and not geminis:
        return
    commands = 0
    for g in geminis:
        if not safos[bisect.bisect_left(safos, g - TOKEN_WINDOW) : bisect.bisect_left(safos, g)]:
            continue
        span = _span(tokens, g + 1)
        if not any(w.lower() in ACTIONS for w in span):
            continue  # `safo gemini` in a sentence, with no action word: prose
        commands += 1
        budget[0] -= 1
        if budget[0] < 0:
            steps.append(Step(unreadable=True, line=number, why="the brief has more than 50 Gemini commands"))
            return
        found_step = _command_step(span, number)
        if found_step is not None:
            steps.append(found_step)
    if commands:
        return
    # no plain command: a name or a command built at run time (an expansion, a glob, printf) beside an action word
    risky = any(_core(t) in RISKY_ACTIONS for t in tokens)
    anchors = sorted(safos + geminis)
    wild_near = False
    for i, t in enumerate(raw_tokens):
        if any(c in t for c in SHELL_WILD) and not (PATHLIKE.match(t) or MARKDOWN_WORD.match(t)):
            near = bisect.bisect_left(anchors, i - TOKEN_WINDOW)
            if near < len(anchors) and anchors[near] <= i + TOKEN_WINDOW:
                wild_near = True
                break
    if risky and wild_near:
        steps.append(
            Step(
                unreadable=True, line=number, why="the line builds a Gemini command at run time (an expansion or glob)"
            )
        )


def _findings(
    prompt: str, check: ApprovalCheck | None, terms: TermsSource, deadline: float | None
) -> list[tuple[str, str]]:
    def tick() -> None:
        if deadline is not None and time.monotonic() > deadline:
            raise TimeoutError("the Gemini check ran out of time")

    tick()
    joined = prompt.replace("\\\r\n", "").replace("\\\n", "")
    steps: list[Step] = []
    flags: dict[str, int] = {}
    materials: list[str] = []
    budget = [MAX_CANDIDATES]
    for number, line in enumerate(joined.splitlines(), 1):
        tick()
        if len(line) > LINE_CAP:
            if any(m in line.lower() for m in MARKERS):
                steps.append(
                    Step(
                        unreadable=True,
                        line=number,
                        why=f"the line is longer than {LINE_CAP} characters and mentions Gemini, so it was not read; "
                        "put it on a shorter line",
                    )
                )
                if "generativelanguage" in line.lower() or "genai" in line.lower():
                    flags.setdefault("vendor", number)
            continue
        _scan_line(number, line, steps, flags, materials, budget)
    if "vendor" in flags:
        steps.append(
            Step(
                unreadable=True,
                line=flags["vendor"],
                why="the vendor API or its SDK is named, which bypasses the gates",
            )
        )
    if "paid" in flags and not any(t.paid or t.unreadable for t in steps):
        steps.append(
            Step(
                paid=True,
                line=flags["paid"],
                why="the paid secret-store config is named",
            )
        )
    if not steps:
        return []
    tick()
    reasons: dict[str, list[str]] = {}

    def add(rule: str, why: str) -> None:
        reasons.setdefault(rule, []).append(why)

    if "vendor" in flags:
        add(
            GEMINI_MATERIAL,
            f"line {flags['vendor']}: call Gemini only through `safo gemini`, never the vendor API or its SDK directly",
        )
    if not materials or any(m != "public" for m in materials):
        add(
            GEMINI_MATERIAL,
            "a Gemini step needs the line `gemini-material: public` (private or sensitive material never goes to it); "
            "add it, or remove the Gemini step",
        )
    if has_secret_shape(prompt):
        add(
            GEMINI_MATERIAL,
            "the brief holds something shaped like a secret or a private key; remove it before any Gemini step",
        )
    if terms:
        tick()
        try:
            loaded = terms() if callable(terms) else terms
        except Exception as err:  # the loader's message names no brief text; any failure blocks
            add(GEMINI_MATERIAL, f"the private terms could not be loaded ({err}); fix the terms file")
            loaded = ()
        if loaded and private_term_hit(loaded, joined, tick):
            add(
                GEMINI_MATERIAL,
                "the brief matches one of the maintainer's private terms; remove it before any Gemini step",
            )
    for step in steps[: MAX_CANDIDATES + 5]:
        tick()
        if step.paid or step.unreadable:
            problem = _paid_problem(step, check)
            if problem:
                add(GEMINI_PAID, problem)
    return [(rule, "; ".join(dict.fromkeys(why[:6]))) for rule, why in reasons.items()]
