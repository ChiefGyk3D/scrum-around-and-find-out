# SPDX-License-Identifier: Apache-2.0
"""What the dispatch guard reads in a brief about Gemini (#200).

This is a speed bump against an honest or prompt-injected model writing a brief, not a sandbox: whoever can run shell
commands can reach the wrapper directly, and the wrapper (`safo.gemini`) is where the gates really are. The guard's
claim is narrow. After folding the text (invisible and combining characters removed, look-alike letters mapped),
replacing markdown links by their text and joining line continuations, a brief names a Gemini step when it has

* a declaration line in the exact grammar: `gemini: free` or `gemini: paid cap=USD approval=ID` (also as a list item),
  with nothing after the tier but `key=value` pairs;
* a literal `safo gemini <action>` command (a `safo` word, within a few shell words a `gemini` word, then `ask`,
  `approve` or `quota`), also inside a quoted string. Quotes are respected, the arguments end at an unquoted operator,
  redirections are skipped as the shell skips them, an operator or expansion character inside an argument is
  unreadable, and the arguments are read with the parser the CLI itself uses;
* the named forms: `safo` or `gemini` beside a shell expansion, glob, brace, backtick or `%` and an ask/approve word;
  a line that runs `safo` through `$`, a function, `xargs`, `eval` or `-c` when the brief names `gemini` and an action;
  a decode-to-shell pipe; the vendor host in any case; the Google genai SDK; the paid secret-store config name.

A way of building a command that is not on that list is not seen. Every step must be proven complete (cap, approval,
`gemini-material: public` when it sends anything) or the brief is blocked, and a block names the line, the reason and
the fix. A false positive is a block, not a leak. Raw SDK use outside a brief is out of this guard's reach, and above
1 MiB the whole hook fails open. Nothing here repeats any text of the brief in a reason.
"""

from __future__ import annotations

import bisect
import dataclasses
import re
import shlex
import time
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import NamedTuple

from safo.gemini import (
    JOB_CAP,
    RECORD_ID,
    VENDOR_HOST,
    TermsCheckError,
    fold,
    has_secret_shape,
    private_term_hit,
)
from safo.modes.gemini import BriefParseError, brief_namespace

GEMINI_PAID = "gemini-paid"
GEMINI_MATERIAL = "gemini-material"
GEMINI_RULES = (GEMINI_PAID, GEMINI_MATERIAL)

DECLARATION = re.compile(r"^\s*(?:[-*+]\s+|\d{1,3}[.)]\s+)?(?:#+\s*)?gemini(?:-step)?\s*:(?P<rest>.*)$", re.IGNORECASE)
MATERIAL = re.compile(r"^\s*(?:[-*+]\s+|\d{1,3}[.)]\s+)?gemini-material\s*:\s*(?P<value>.*?)\s*$", re.IGNORECASE)
MARKDOWN_LINK = re.compile(r"\[([^\]]{0,200})\]\([^)\s]{0,300}\)")
MARKDOWN_CODE = re.compile(r"`(safo\b[^`]*)`")
PAID_CONFIG = re.compile(r"\bprd_paid\b")
SDK = re.compile(
    r"google[.\s-]*genai|google\s+import\s+[\w ,]{0,40}genai|google-generativeai|generativeai|generativelanguage"
    r"|genai\.client"
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
PATHLIKE = re.compile(r"^[\w./-]*gemini[\w./-]*$", re.IGNORECASE)
VENDOR_RE = re.compile(re.escape(VENDOR_HOST))
# Every detector pattern, so the cheap prefilter below can never miss what a detector would catch. A new detector regex
# must be added here (a test fails otherwise); the second field names it.
PREFILTER = (
    ("safo", re.compile("safo")),
    ("gemini", re.compile("gemini")),
    ("paid config", PAID_CONFIG),
    ("vendor host", VENDOR_RE),
    ("sdk", SDK),
    ("decode", DECODE),
)
TOKEN_WINDOW = 12  # tokens between `safo` and `gemini` for them to count as one command
LINE_CAP = 4000  # a line longer than this that mentions anything above is blocked unread
MAX_CANDIDATES = 50  # commands examined per brief; more than this is blocked
TERMS_SECONDS_DEFAULT = 5.0  # the most the private-terms search is given
TERMS_MIN_SECONDS = 0.5  # the least the private-terms search is given when the deadline is close
OPCHARS = frozenset(";|&()<>")
RUNTIME_FORMS = re.compile(r"\$|\bxargs\b|\beval\b|(?<![\w-])-c\b|\bfunction\b|\(\)")
WILD_NAMES = {
    "$": "a shell expansion",
    "*": "a glob",
    "?": "a glob",
    "[": "a glob or bracket",
    "]": "a glob or bracket",
    "{": "a brace expansion",
    "}": "a brace expansion",
    "`": "a command substitution",
    "%": "a format string",
}
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
    sends: bool = True  # False for a mention that sends nothing (an approve or quota command with no prompt file)


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
    if not relevant(prompt):
        return []  # nothing in the brief can name Gemini, so there is nothing to time out on
    try:
        return _findings(prompt, check, terms, deadline)
    except TimeoutError:
        return list(_FAIL_CLOSED)


def _join(text: str) -> str:
    return text.replace("\\\r\n", "").replace("\\\n", "")


def _views(line: str) -> tuple[str, str, str]:
    """The ONE normalization of a line, used by the scan and by the prefilter alike: folded (NFKD, invisible and
    combining characters removed, NFKC, look-alike letters mapped), markdown links replaced by their text, inline code
    around a `safo` command cut with a terminator, then (`norm`) that text with its quotes and backslashes, (`clean`)
    the text with quotes and backslashes removed, and (`low`) that in lower case."""
    norm = fold(line)
    # markdown inline code around a whole command: `safo gemini quota ...` is the command, not a shell substitution
    norm = MARKDOWN_CODE.sub(r" \1 ; ", MARKDOWN_LINK.sub(r"\1", norm))
    clean = norm.replace("'", "").replace('"', "").replace("\\", "")
    return norm, clean, clean.lower()


def normalized(text: str) -> str:
    """The text the detectors see, line by line, joined back (quotes and backslashes removed, lower case)."""
    return "\n".join(_views(line)[2] for line in _join(text).splitlines())


def relevant(text: str) -> bool:
    """False only when no detector could possibly fire. It runs the detector patterns over the very views `_scan_line`
    builds: the decode detector reads the text with its backslashes, every other one the cleaned lower case text."""
    for line in _join(text).splitlines():
        norm, _, low = _views(line)
        raw = norm.lower()
        if any(p.search(raw if name == "decode" else low) for name, p in PREFILTER):
            return True
    return False


class Tok(NamedTuple):
    value: str
    quoted: bool
    op: bool


def _lex(text: str) -> list[Tok] | None:
    """Shell-like words with quotes noted, not interpreted: an unquoted operator run is its own token, a quoted one
    stays inside a word (which is how a quoted `;` is told from a real one). None on an unterminated quote."""
    lexer = shlex.shlex(text, posix=False, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    tokens: list[Tok] = []
    try:
        for raw in lexer:
            if all(c in OPCHARS for c in raw):
                tokens.append(Tok(raw, False, True))
            else:
                tokens.append(
                    Tok(raw.replace("'", "").replace('"', "").replace("\\", ""), "'" in raw or '"' in raw, False)
                )
    except ValueError:
        return None
    return tokens


def _core(token: str) -> str:
    return token.strip("()${};|&,:'\"`?!.").lower()


def _is_safo(token: str) -> bool:
    base = _core(token).rsplit("/", 1)[-1]
    return base == "safo" or base.startswith("safo.")


_PARSE_CACHE: dict[str, Step | None] = {}
_ARGPARSE_WORDS = (
    ("unrecognized arguments", "an option or argument the CLI does not know (abbreviations are refused too)"),
    ("required", "a missing action or required option"),
    ("expected one argument", "an option with no value"),
    ("invalid choice", "an action that is not ask, approve or quota"),
    ("invalid", "a value the CLI rejects"),
)


def _command_step(span: list[str], line: int, problems: tuple[str, ...] = ()) -> Step | None:
    """One command's arguments, read with the parser the CLI itself uses. An operator character inside an argument or
    a shell expansion is unreadable: the shell acts on it before the parser sees it."""
    if problems:
        return Step(unreadable=True, line=line, why="the command has " + "; ".join(problems))
    text = " ".join(span)
    for char in OPCHARS:
        if char in text:
            return Step(
                unreadable=True,
                line=line,
                why=f"the command has {char!r} inside an argument (a quoted operator or redirection)",
            )
    for char, name in WILD_NAMES.items():
        if char in text:
            return Step(
                unreadable=True, line=line, why=f"the command has {char!r} ({name}), which the shell expands first"
            )
    if text in _PARSE_CACHE:
        cached = _PARSE_CACHE[text]
        return None if cached is None else dataclasses.replace(cached, line=line)
    try:
        ns = brief_namespace(span)
    except BriefParseError as err:
        reason = next((phrase for key, phrase in _ARGPARSE_WORDS if key in str(err)), "a form the CLI does not accept")
        step: Step | None = Step(
            unreadable=True,
            line=line,
            why=f"the command has {reason} (an unknown or shortened option, a missing value)",
        )
    else:
        if ns.action == "quota":
            step = None  # not a step: it prints the quota line and sends nothing
        else:
            step = Step(
                bool(ns.paid) or ns.action == "approve",
                ns.cap or ns.max_usd or None,
                ns.approval or None,
                line=line,
                sends=ns.action == "ask" or bool(ns.prompt_file),
            )
    if len(_PARSE_CACHE) < 256:
        _PARSE_CACHE[text] = step
    return step


def _commands(text: str, number: int, steps: list[Step], budget: list[int], depth: int = 0) -> bool:
    """Find `safo ... gemini ... <action>` commands in a line, also inside a quoted shell string (`bash -c '...'`).
    True when at least one command was found."""
    tokens = _lex(text)
    if tokens is None:
        low = text.lower()
        if "safo" in low and "gemini" in low:
            steps.append(Step(unreadable=True, line=number, why="the line has an unbalanced quote"))
            return True
        return False
    found = False
    for t in tokens:
        if t.quoted and " " in t.value and "safo" in t.value.lower() and depth < 3:
            found = _commands(t.value, number, steps, budget, depth + 1) or found
    safos = [i for i, t in enumerate(tokens) if not t.op and _is_safo(t.value)]
    for g, t in enumerate(tokens):
        if t.op or _core(t.value) != "gemini":
            continue
        if not safos[bisect.bisect_left(safos, g - TOKEN_WINDOW) : bisect.bisect_left(safos, g)]:
            continue
        span: list[str] = []
        problems: list[str] = []
        i = g + 1
        while i < len(tokens):
            nxt = tokens[i]
            if nxt.op:
                if "<" in nxt.value or ">" in nxt.value:  # a redirection: the shell skips it and its operand
                    if span and span[-1] in ("0", "1", "2"):
                        span.pop()
                    i += 2 if i + 1 < len(tokens) and not tokens[i + 1].op else 1
                    continue
                break
            for char in OPCHARS:
                if char in nxt.value:
                    problems.append(f"{char!r} inside quotes")
            span.append(nxt.value.rstrip("?!.,") or nxt.value)
            i += 1
        if not any(w.lower() in ACTIONS for w in span):
            continue  # `safo gemini` in a sentence, with no action word: prose
        found = True
        budget[0] -= 1
        if budget[0] < 0:
            steps.append(Step(unreadable=True, line=number, why="the brief has more than 50 Gemini commands"))
            return True
        step = _command_step(span, number, tuple(dict.fromkeys(problems)))
        if step is not None:
            steps.append(step)
    return found


def _scan_line(
    number: int,
    line: str,
    steps: list[Step],
    flags: dict[str, int],
    materials: list[str],
    budget: list[int],
    runtime_scan: bool,
) -> None:
    norm, clean, low = _views(line)
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
    if runtime_scan and "safo" in low and RUNTIME_FORMS.search(low):
        steps.append(
            Step(
                unreadable=True,
                line=number,
                why="the line runs safo through a variable, function, xargs, eval or -c while the brief names "
                "Gemini and an action, so the command cannot be read",
            )
        )
    if "safo" not in low and "gemini" not in low:
        return
    if _commands(norm, number, steps, budget):
        return
    # no plain command: a name or a command built at run time (an expansion, a glob, printf) beside an action word
    tokens = _lex(norm) or []
    values: list[str] = []
    for t in tokens:
        if t.op:
            continue
        # a quoted string that holds a command (`printf 'safo gem%s ask'`) is read word by word
        values.extend(t.value.split() if t.quoted and " " in t.value else [t.value])
    risky = any(_core(v) in RISKY_ACTIONS for v in values)
    anchors = [i for i, v in enumerate(values) if _is_safo(v) or _core(v) == "gemini"]
    wild_near = False
    for i, v in enumerate(values):
        if any(c in v for c in SHELL_WILD) and not (PATHLIKE.match(v) or MARKDOWN_WORD.match(v)):
            near = bisect.bisect_left(anchors, i - TOKEN_WINDOW)
            if near < len(anchors) and anchors[near] <= i + TOKEN_WINDOW:
                wild_near = True
                break
    if risky and wild_near:
        steps.append(
            Step(
                unreadable=True,
                line=number,
                why="the line builds a Gemini command at run time (a shell expansion, glob or format string)",
            )
        )


def _findings(
    prompt: str, check: ApprovalCheck | None, terms: TermsSource, deadline: float | None
) -> list[tuple[str, str]]:
    def tick() -> None:
        if deadline is not None and time.monotonic() > deadline:
            raise TimeoutError("the Gemini check ran out of time")

    tick()
    joined = _join(prompt)
    lines = joined.splitlines()
    whole = "\n".join(_views(line)[2] for line in lines)
    runtime_scan = bool(re.search(r"\bgemini\b", whole)) and bool(
        re.search(r"(?<![\w-])(?:ask|approve)\b|--paid", whole)
    )
    steps: list[Step] = []
    flags: dict[str, int] = {}
    materials: list[str] = []
    budget = [MAX_CANDIDATES]
    for number, line in enumerate(lines, 1):
        tick()
        if len(line) > LINE_CAP:
            if relevant(line):
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
        _scan_line(number, line, steps, flags, materials, budget, runtime_scan)
    if "vendor" in flags:
        steps.append(
            Step(
                unreadable=True,
                line=flags["vendor"],
                why="the vendor API or its SDK is named, which bypasses the gates",
            )
        )
    if "paid" in flags and not any(t.paid or t.unreadable for t in steps):
        steps.append(Step(paid=True, line=flags["paid"], why="the paid secret-store config is named"))
    if not steps:
        return []
    tick()
    reasons: dict[str, list[str]] = {}

    def add(rule: str, why: str) -> None:
        reasons.setdefault(rule, []).append(why)

    sends = any(step.sends or step.unreadable for step in steps)
    if "vendor" in flags:
        add(
            GEMINI_MATERIAL,
            f"line {flags['vendor']}: call Gemini only through `safo gemini`, never the vendor API or its SDK directly",
        )
    if sends:
        if not materials or any(m != "public" for m in materials):
            add(
                GEMINI_MATERIAL,
                "a Gemini step needs the line `gemini-material: public` (private or sensitive material never goes to "
                "it); add it, or remove the Gemini step",
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
            if loaded:
                left = (deadline - time.monotonic()) if deadline is not None else TERMS_SECONDS_DEFAULT
                limit = min(max(left - 0.2, TERMS_MIN_SECONDS), TERMS_SECONDS_DEFAULT)
                try:
                    if private_term_hit(loaded, [joined, whole], limit):
                        add(
                            GEMINI_MATERIAL,
                            "the brief matches one of the maintainer's private terms; remove it before any Gemini step",
                        )
                except TermsCheckError as err:
                    add(GEMINI_MATERIAL, str(err))
    for step in steps[: MAX_CANDIDATES + 5]:
        tick()
        if step.paid or step.unreadable:
            problem = _paid_problem(step, check)
            if problem:
                add(GEMINI_PAID, problem)
    return [(rule, "; ".join(dict.fromkeys(why[:6]))) for rule, why in reasons.items()]
