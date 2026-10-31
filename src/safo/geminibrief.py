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
the fix. A false positive is a block, not a leak. Raw SDK use outside a brief is out of this guard's reach.
Nothing here repeats any text of the brief in a reason.
"""

from __future__ import annotations

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

GEMINI_PAID = "gemini-paid"
GEMINI_MATERIAL = "gemini-material"
GEMINI_RULES = (GEMINI_PAID, GEMINI_MATERIAL)
# the phrase classes a paid-use denial names; fixed text, so a denial never repeats a word of the brief
MATCH_COMMAND = "a `safo gemini` command"
MATCH_DECLARATION = "a `gemini:` declaration"
MATCH_CONFIG = "the paid config name"

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
    r"(?:base64\s+(?:-d\b|-D\b|--decode\b)|openssl\s+[^|]{0,40}-d\b|xxd\s+-r|(?<![\w=-])rev(?![\w=-])|printf\s+[^|]{0,80}\\x)"
)
SINK_RE = re.compile(SINK)
SHELL_WILD = frozenset("$*?[]{}`%")
RISKY_ACTIONS = ("ask", "approve", "paid", "paid-dryrun")  # the broker entries are paid action words (#287)
ACTIONS = ("ask", "approve", "quota", "paid", "paid-dryrun")  # paid and paid-dryrun: the broker entries (#287)
# inline code in prose that wraps a known word, an option or a file name; any other word in backticks runs as a command
MARKDOWN_WORD = re.compile(
    r"^`(?:ask|approve|quota|paid|paid-dryrun|gemini|safo|--[a-z-]{1,30}|[\w.-]{0,60}[./][\w./-]{0,100})`[.,:;)]*$"
)
VENDOR_RE = re.compile(re.escape(VENDOR_HOST))
# The bare word `paid` is also ordinary English ("the paid tier"), unlike `ask` and `approve` in this grammar. A line
# that is prose (no run-time construct on it, or a markdown table row) has the bare word neutralized before any scan;
# every other line keeps it, so `echo paid | xargs safo gemini`, `A=paid`, `eval` of a string and `safo gemini paid`
# stay read.
# `paid-dryrun`, `--paid` and the broker options are never neutralized.
_BARE_PAID = re.compile(r"(?<![\w-])paid(?![\w-])")
_RUNTIME_SIGNAL = re.compile(
    r"\bxargs\b|\beval\b|(?<![\w-])-c\b|\s\|\s|\$|=\s*[\"']?paid(?![\w-])|\bgemini\s+paid\b|\bfor\b.*\bin\b"
)
# Every detector pattern, so the cheap prefilter below can never miss what a detector would catch. A new detector regex
# must be added here (a test fails otherwise); the second field names it.
# words built with escapes, printf -v, ANSI-C quoting: a brief that has them is read even without a Gemini word
CONCEAL = re.compile(r"\$'[^']*\\|printf\s+-v\b|\\x[0-9a-fA-F]{2}|\\[0-7]{3}|\\u[0-9a-fA-F]{4}")
PREFILTER = (
    ("safo", re.compile("safo")),
    ("gemini", re.compile("gemini")),
    ("paid config", PAID_CONFIG),
    ("vendor host", VENDOR_RE),
    ("sdk", SDK),
    ("decode", DECODE),
    ("conceal", CONCEAL),
)
LINE_CAP = 4000  # a line longer than this that mentions anything above is blocked unread
MAX_CANDIDATES = 50  # commands examined per brief; more than this is blocked
TERMS_SECONDS_DEFAULT = 5.0  # the most the private-terms search is given
TERMS_MIN_SECONDS = 0.5  # the least the private-terms search is given when the deadline is close
OPCHARS = frozenset(";|&()<>")
RUNTIME_FORMS = re.compile(r"\$|\bxargs\b|\beval\b|\balias\b|(?<![\w-])-c\b|\bfunction\b|\(\)")
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
    matched: str = ""  # the CLASS of phrase that made this a step (never brief text), shown in the denial


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
    return Step(
        tier == "paid",
        _option(tokens, "cap"),
        _option(tokens, "approval"),
        line=line,
        matched=MATCH_DECLARATION,
    )


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
    disabled = getattr(check, "disabled", None)
    if isinstance(disabled, str):
        found = "; ".join(x for x in (step.why, step.matched) if x)
        return f"{where}{disabled} [rule gemini-paid, matched: {found}]" if found else f"{where}{disabled}"
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


def _neutral_prose(line: str) -> str:
    """A prose line has the bare word `paid` replaced (see `_BARE_PAID`); a line with a run-time construct, or that is
    not a markdown table row but holds the Gemini command group before the word, is returned unchanged."""
    if _BARE_PAID.search(line) is None or (_RUNTIME_SIGNAL.search(line) and not line.lstrip().startswith("|")):
        return line
    return _BARE_PAID.sub("p-id", line)


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


def _strip(text: str) -> str:
    return text.replace("'", "").replace('"', "").replace("\\", "")


def _views(line: str) -> tuple[str, str, str, str, str]:
    """The ONE normalization of a line, used by the scan and by the prefilter alike. The line is folded (NFKD, invisible
    and combining characters removed, NFKC, look-alike letters mapped); markdown links become their text and inline code
    around a `safo` command gets a terminator. Returns, in order: `norm` (that text, quotes and backslashes kept),
    `clean` (quotes and backslashes removed), `low` (clean in lower case), and two views of the folded line BEFORE the
    link rewrite, `pre_low` (clean, lower case) and `pre_raw` (lower case with its backslashes), so a vendor host or
    an SDK name that sits only in a link target is still seen."""
    folded = fold(line)
    # markdown inline code around a whole command: `safo gemini quota ...` is the command, not a shell substitution
    norm = MARKDOWN_CODE.sub(r" \1 ; ", MARKDOWN_LINK.sub(r"\1", folded))
    clean = _strip(norm)
    return norm, clean, clean.lower(), _strip(folded).lower(), folded.lower()


def normalized(text: str) -> str:
    """The text the detectors see, line by line, joined back (quotes and backslashes removed, lower case)."""
    return "\n".join(_views(line)[2] for line in _join(text).splitlines())


def relevant(text: str) -> bool:
    """False only when no detector could possibly fire. It runs the detector patterns over the very views `_scan_line`
    builds, link targets included: the decode detector reads the text with its backslashes, every other one the cleaned
    lower case text. Words built with escapes (ANSI-C quoting, `printf -v`, hex or octal escapes) make a brief relevant
    on their own, since the words and the options may both be what the escapes hide."""
    concealed = False
    for line in _join(text).splitlines():
        norm, _, low, pre_low, pre_raw = _views(line)
        raw = norm.lower()
        if _risk_line(norm, low):
            return True
        for name, pattern in PREFILTER:
            if name == "conceal":
                concealed = concealed or bool(pattern.search(raw) or pattern.search(pre_raw))
            elif name == "decode":
                if pattern.search(raw) or pattern.search(pre_raw):
                    return True
            elif pattern.search(low) or pattern.search(pre_low):
                return True
    return concealed


class Tok(NamedTuple):
    value: str
    quoted: bool  # the word held a quote
    op: bool
    mixed: bool  # a quote or backslash anywhere but the two outer edges of the word
    start: int
    end: int


def _lex(text: str) -> list[Tok] | None:
    """Words the way bash cuts them, for the subset the guard reads: unquoted whitespace ends a word, an unquoted run of
    `; | & ( ) < >` is an operator token, single quotes are literal, double quotes honor a backslash before `$ ` " \\`,
    and a backslash outside quotes escapes one character. Each word notes whether it held a quote and whether the quote
    or backslash was anywhere but its outer edges. None on an unterminated quote."""
    tokens: list[Tok] = []
    n = len(text)
    i = 0
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if c in OPCHARS:
            j = i
            while j < n and text[j] in OPCHARS:
                j += 1
            tokens.append(Tok(text[i:j], False, True, False, i, j))
            i = j
            continue
        start = i
        buf: list[str] = []
        quoted = escaped = False
        segments = 0
        while i < n and not text[i].isspace() and text[i] not in OPCHARS:
            c = text[i]
            if c == "'":
                end = text.find("'", i + 1)
                if end == -1:
                    return None
                buf.append(text[i + 1 : end])
                quoted = True
                segments += 1
                i = end + 1
            elif c == '"':
                j = i + 1
                chunk: list[str] = []
                while True:
                    if j >= n:
                        return None
                    d = text[j]
                    if d == "\\" and j + 1 < n and text[j + 1] in '$`"\\':
                        chunk.append(text[j + 1])
                        j += 2
                    elif d == '"':
                        break
                    else:
                        chunk.append(d)
                        j += 1
                buf.append("".join(chunk))
                quoted = True
                segments += 1
                i = j + 1
            elif c == "\\":
                escaped = True
                if i + 1 < n:
                    buf.append(text[i + 1])
                i += 2
            else:
                buf.append(c)
                i += 1
        whole_quote = quoted and segments == 1 and not escaped and text[start] in "'\"" and text[i - 1] == text[start]
        mixed = escaped or (quoted and not whole_quote)
        tokens.append(Tok("".join(buf), quoted or escaped, False, mixed, start, i))
    return tokens


def _breaks(operator: str) -> bool:
    """An operator that ends a simple command: `;`, `|` or `&` (also in `&&` and `||`). Parentheses and redirections
    do not, so `$(which safo) gemini ask` and `safo > out gemini ask` stay one command."""
    return any(c in operator for c in ";|&")


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
    text = " ".join(span)
    shown = MATCH_COMMAND
    if problems:
        return Step(unreadable=True, line=line, why="the command has " + "; ".join(problems), matched=shown)
    for char in OPCHARS:
        if char in text:
            return Step(
                unreadable=True,
                line=line,
                why=f"the command has {char!r} inside an argument (a quoted operator or redirection)",
                matched=shown,
            )
    for char, name in WILD_NAMES.items():
        if char in text:
            return Step(
                unreadable=True,
                line=line,
                why=f"the command has {char!r} ({name}), which the shell expands first",
                matched=shown,
            )
    if text in _PARSE_CACHE:
        cached = _PARSE_CACHE[text]
        return None if cached is None else dataclasses.replace(cached, line=line)
    # deferred: the Gemini mode builds argparse, which the guard's entry point must not load at import
    from safo.modes.gemini import PAID_ACTIONS, BriefParseError, brief_namespace

    try:
        ns = brief_namespace(span)
    except BriefParseError as err:
        reason = next((phrase for key, phrase in _ARGPARSE_WORDS if key in str(err)), "a form the CLI does not accept")
        step: Step | None = Step(
            unreadable=True,
            line=line,
            why=f"the command has {reason} (an unknown or shortened option, a missing value)",
            matched=shown,
        )
    else:
        if ns.action == "quota":
            step = None  # not a step: it prints the quota line and sends nothing
        else:
            step = Step(
                bool(ns.paid) or ns.action in ("approve", *PAID_ACTIONS),
                ns.cap or ns.max_usd or None,
                ns.approval or None,
                line=line,
                sends=ns.action == "ask" or bool(ns.prompt_file),
                matched=shown,
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
    # `gemini` after a `safo` in the same simple command, however many flags sit between them; a redirection does not
    # end the command, an unquoted `; | & ( )` does
    last_safo = -1
    last_stop = -1
    mixed_since_safo = False
    for g, t in enumerate(tokens):
        if t.op:
            if _breaks(t.value):
                last_stop = g
            continue
        if _is_safo(t.value):
            last_safo = g
            mixed_since_safo = t.mixed
            continue
        mixed_since_safo = mixed_since_safo or t.mixed
        if _core(t.value) != "gemini" or last_safo < 0 or last_safo < last_stop:
            continue
        span: list[str] = []
        problems: list[str] = []
        if mixed_since_safo:
            problems.append("a word with a quote or backslash in the middle of it")
        i = g + 1
        word_end = -1
        while i < len(tokens):
            nxt = tokens[i]
            if nxt.op:
                if "<" in nxt.value or ">" in nxt.value:  # a redirection: the shell skips it and its operand
                    if span and span[-1] in ("0", "1", "2") and word_end == nxt.start:
                        span.pop()
                    i += 2 if i + 1 < len(tokens) and not tokens[i + 1].op else 1
                    continue
                prev = tokens[i - 1]
                if (not prev.op and prev.quoted and prev.end == nxt.start) or (
                    i + 1 < len(tokens) and tokens[i + 1].quoted and tokens[i + 1].start == nxt.end
                ):
                    problems.append("an operator touching a quoted word")
                if i + 1 < len(tokens) and not tokens[i + 1].op and tokens[i + 1].value.startswith("--"):
                    problems.append("an option-like word after the command ends, so the cut may be wrong")
                break
            if nxt.mixed:
                problems.append("a word with a quote or backslash in the middle of it")
            for char in OPCHARS:
                if char in nxt.value:
                    problems.append(f"{char!r} inside quotes")
            span.append(nxt.value.rstrip("?!.,") or nxt.value)
            word_end = nxt.end
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
    norm, clean, low, pre_low, pre_raw = _views(line)
    found = MATERIAL.match(clean)
    if found:
        materials.append(found.group("value").lower())
        return
    declared = DECLARATION.match(clean)
    if declared:
        step = _declared(declared.group("rest"), number)
        if step is not None:
            steps.append(step)
    if PAID_CONFIG.search(low) or PAID_CONFIG.search(pre_low):
        flags.setdefault("paid", number)
    if VENDOR_HOST in low or VENDOR_HOST in pre_low or SDK.search(low) or SDK.search(pre_low):
        flags.setdefault("vendor", number)
    if (DECODE.search(norm.lower()) and SINK_RE.search(norm.lower())) or (
        DECODE.search(pre_raw) and SINK_RE.search(pre_raw)
    ):
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
    segments: list[int] = []
    segment = 0
    for t in tokens:
        if t.op:
            if _breaks(t.value):
                segment += 1
            continue
        # a quoted string that holds a command (`printf 'safo gem%s ask'`) is read word by word
        for word in t.value.split() if t.quoted and " " in t.value else [t.value]:
            values.append(word)
            segments.append(segment)
    risky = any(_core(v) in RISKY_ACTIONS for v in values)
    anchored = {segments[i] for i, v in enumerate(values) if _is_safo(v) or _core(v) == "gemini"}
    wild_near = any(
        any(c in v for c in SHELL_WILD) and not MARKDOWN_WORD.match(v) and segments[i] in anchored
        for i, v in enumerate(values)
    )
    if risky and wild_near:
        steps.append(
            Step(
                unreadable=True,
                line=number,
                why="the line builds a Gemini command at run time (a shell expansion, glob or format string)",
            )
        )


# Brief-wide reading of a command that is built over several lines. No shell semantics are modeled and no value is
# resolved: the guard only asks where variables, escapes and substitutions FLOW.
#
# * A FLOW construct makes the brief unreadable when it names the Gemini surface (safo, gemini, the vendor host, an SDK,
#   the paid config, or words built with escapes): a variable assigned anywhere in the brief (NAME=value, a prefix
#   assignment, export/declare/readonly/local, an array, printf -v, a for or read variable) that is referenced at a
#   command position, or as an argument of a line that carries a Gemini option or action; an ANSI-C word or an escape on
#   such a line, or an ANSI-C word at a command position. A "weak" flow (an expansion nothing in the brief assigned)
#   needs safo, gemini and an action all named. A command made only of literal words, with no variable, stays readable.
# * A STANDALONE construct (an array, a function, eval, xargs, a shell -c, an assignment from an expansion) makes the
#   brief unreadable only beside a paid or approve step. A shell comment is not code: it is cut off, quote-aware, before
#   anything else is looked at.
_FUNCTION = re.compile(r"(?<![\w$.\-/])[A-Za-z_]\w*\s*\(\)|(?<![\w-])function\s+[A-Za-z_]\w*")
_ASSIGNED = re.compile(r"(?<![\w$.\-/])([A-Za-z_][A-Za-z0-9_]*)\+?=")
_PRINTF_NAME = re.compile(r"(?<![\w$.\-/])printf\s+-v\s+([A-Za-z_]\w*)")
_LOOP_NAME = re.compile(r"(?<![\w-])for\s+([A-Za-z_]\w*)\s+in\b")
_READ_NAME = re.compile(r"(?<![\w-])read\s+(?:-\w+\s+)*([A-Za-z_]\w*)")
_REFERENCE = re.compile(r"\$\{?[!#]?([A-Za-z_][A-Za-z0-9_]*)")
_ANSI_ESCAPE = re.compile(r"\$'[^']*\\[^']*'")
_RISK_TOKEN = re.compile(
    r"--paid|--approval|--cap(?![\w-])|--max-usd|--job(?![\w-])|(?<![\w-])(?:ask|approve|paid-dryrun|paid)(?![\w-])"
)
_PAID_TOKEN = re.compile(r"--paid|(?<![\w-])(?:approve|paid-dryrun|paid)(?![\w-])")
_GEMINI_WORD = re.compile(r"\b(?:safo|gemini)\b|--paid|--approval|--cap(?![\w-])")
_SHELL_C = re.compile(
    r"(?<![\w-])(?:bash|sh|zsh|dash|ksh|csh|tcsh|fish|pwsh|python[\d.]*|perl|ruby|node|php|lua)\b(?:\s+-{1,2}[\w-]+)*"
    r"\s+-\w*c\b"
)
_STANDALONE = (
    ("eval", re.compile(r"(?<![\w-])eval\b")),
    ("xargs", re.compile(r"(?<![\w-])xargs\b")),
    ("a shell or interpreter -c", _SHELL_C),
)
MAX_VARIABLES = 2000  # assigned names tracked in one brief; more is unreadable

Construct = tuple[str, int, str]  # (what, line number, kind: flow, weak, standalone or always)


def _strip_comment(text: str) -> str:
    """The text without a shell comment, cut the way bash cuts: a `#` that starts a word (at the start, or after an
    ASCII space, tab, newline or one of `; & | ( ) < >`), outside single quotes, double quotes and `$'...'` words
    (inside which a backslash escapes the next character, a quote included). It fails closed: when the comment text
    holds `$`, a backtick, `;`, `|` or `&`, or the text before it holds `$'` or a non-ASCII space (an ordinary word
    character to bash), the whole line is returned, so nothing bash may still run is hidden."""
    mode = ""
    i = 0
    while i < len(text):
        c = text[i]
        if mode == "'":
            if c == "'":
                mode = ""
        elif mode in ('"', "$'"):
            if c == "\\":
                i += 2
                continue
            if c == mode[-1]:
                mode = ""
        elif c == "\\":
            i += 2
            continue
        elif c == "'":
            mode = "'"
        elif c == '"':
            mode = '"'
        elif c == "$" and text[i + 1 : i + 2] == "'":
            mode = "$'"
            i += 2
            continue
        elif c == "#" and (i == 0 or text[i - 1] in " \t\n;&|()<>"):
            head, tail = text[:i], text[i:]
            if any(ch in tail for ch in "$`;|&") or "$'" in head or any(ord(ch) > 127 and ch.isspace() for ch in head):
                return text
            return head
        i += 1
    return text


_ASSIGNMENT_WORD = re.compile(r"[A-Za-z_]\w*\+?=")
_PREFIX_WORDS = frozenset(
    {"env", "command", "exec", "nohup", "time", "sudo", "builtin", "eval", "xargs", "do", "then", "else", "elif", "if"}
    | {"while", "until", "!", "{"}
)
_DOLLAR = re.compile(
    r"\$[\w{(@*#?!\\-]"
)  # a shell expansion ($A, ${A}, $(cmd), $1, $@, $'..'), not a price or a bare sign
_BACKTICK_CMD = re.compile(
    r"`\s*(?:echo|printf|cat|base64|xxd|rev|tr|sed|awk|cut|head|tail|printenv|which|env|command|type|basename|dirname"
    r"|readlink|date|git|jq|python[\d.]*|perl|ruby|node|bash|sh)\b[^`]*`"
)  # a command substitution in backticks; markdown code spans (`quota`, `approve <job>`) are not one


_COMMAND_START = re.compile(r"(?:\s*(?:[A-Za-z_]\w*\+?=\S*|env|command|exec|nohup|time|sudo|eval|xargs)\s+)*\s*")


def _backtick_command(text: str) -> bool:
    """A backtick command substitution where a command word (or an assignment value) would stand: at the start of a
    command or after `;`, `&`, `|`, `(`, `=`. In prose a code span such as `printf -v` has text before it."""
    for m in _BACKTICK_CMD.finditer(text):
        before = text[: m.start()]
        if before.rstrip().endswith((";", "&", "|", "(", "=")) or _COMMAND_START.fullmatch(before):
            return True
    return False


def _expands(text: str) -> bool:
    """True when the text holds a shell expansion, or a backtick substitution where a command or a value would stand."""
    return bool(_DOLLAR.search(text) or _backtick_command(text))


def _expansion_at_command(text: str) -> bool:
    """True when a command word (the first word of a command, after an operator, or after env/command/exec...) holds a
    shell expansion, an ANSI-C word or a command substitution, so what runs is not what is written. A line the lexer
    cannot read that holds one is unreadable, so True as well. A shell comment is not code."""
    text = _strip_comment(text)
    tokens = _lex(text)
    if tokens is None:
        return _expands(text)
    if _backtick_command(text):
        return True
    at_start = True
    for t in tokens:
        if t.op:
            at_start = _breaks(t.value)
            continue
        if at_start and _ASSIGNMENT_WORD.match(t.value):
            continue  # NAME=value before the command word: the value is judged as an assignment, not as the command
        if at_start and _DOLLAR.search(t.value):
            return True
        at_start = at_start and t.value in _PREFIX_WORDS
    return False


_GEMINI_OPTION = re.compile(r"--paid|--approval|--cap(?![\w-])|--max-usd|--job(?![\w-])")
_RISK_OPTION = re.compile(
    r"(?<![\w-])--paid(?![\w-])|(?<![\w-])--approval(?![\w-])|(?<![\w-])--cap(?![\w-])|(?<![\w-])approve(?![\w-])"
)  # exact tokens: --cap-add is not one, and approve is a word of its own


_RISK_FLAG = re.compile(
    r"(?<![\w-])--paid(?![\w-])|(?<![\w-])--approval(?![\w-])|(?<![\w-])--cap(?![\w-])|(?<![\w-])approve(?=\s+-)"
)  # the flags that are unambiguous in prose: `approve` counts only when an option follows it
_BRACE_FRAGMENTS = ("--", "appro", "cap", "paid")


def _brace_list(word: str) -> bool:
    """Whether the word holds a brace expansion bash would perform (`{a,b}` or `{x..y}`, nested too). A `${...}` is a
    frame of its own, so a comma inside it never makes the braces around it a list and its `}` never closes one. One
    pass over the text, no string built; more than 64 levels deep counts as a brace expansion."""
    frames: list[int] = []  # 0: a ${...}, 1: a list so far, 2: a list that has a separator
    i = 0
    while i < len(word):
        c = word[i]
        if c == "\\":
            i += 2
            continue
        if c == "{":
            if len(frames) >= 64:
                return True
            frames.append(0 if i > 0 and word[i - 1] == "$" else 1)
        elif c == "}" and frames:
            if frames.pop() == 2:
                return True
        elif frames and frames[-1] and (c == "," or (c == "." and word[i + 1 : i + 2] == ".")):
            frames[-1] = 2
        i += 1
    return False


def _has_brace_word(norm: str) -> bool:
    """A word on the line that bash may brace-expand: an unquoted brace list, or any word holding a brace that is only
    partly quoted. A word that is one quoted string is not expanded by the shell."""
    tokens = _lex(_strip_comment(norm))
    if tokens is None:
        return "{" in norm and _brace_list(norm)
    return any(
        not t.op
        and "{" in t.value
        and not (t.quoted and not t.mixed)  # a word that is one quoted string is not brace-expanded
        and (t.mixed or _brace_list(t.value))  # a partly quoted word still may be: any brace in it counts
        for t in tokens
    )


def _brace_word_risk(low: str) -> bool:
    """For text with no lines (an oversized event): a brace expansion in a word that holds `--`, `appro`, `cap` or
    `paid`, so a risk token could be spelled by it. A word longer than LINE_CAP that holds a brace counts."""
    return any(
        "{" in word and any(f in word for f in _BRACE_FRAGMENTS) and (len(word) > LINE_CAP or _brace_list(word))
        for word in low.split()
    )


def _expansion_past_first_word(norm: str) -> bool:
    """Any expansion after the first word of a command (NAME=value words before it are skipped): a wrapper such as
    `env -u X $BIN ...` hides the real command behind options, so no wrapper is named and none is tracked."""
    text = _strip_comment(norm)
    if _backtick_command(text):
        return True
    tokens = _lex(text)
    if tokens is None:
        return _expands(text)
    seen_command = False
    for t in tokens:
        if t.op:
            seen_command = seen_command and not _breaks(t.value)
        elif not seen_command:
            seen_command = not _ASSIGNMENT_WORD.match(t.value)
        elif _DOLLAR.search(t.value):
            return True
    return False


def _risk_line(norm: str, low: str) -> bool:
    """A Gemini-risk token on a line whose command is made by an expansion: no Gemini word needs to be on the page.
    Nothing is enumerated or built: a brace expansion on the line may spell a token, so it counts as one; an expansion
    anywhere after the first word counts when the line carries an unambiguous flag; a line longer than LINE_CAP is
    judged by the same marks without being read further."""
    if len(norm) > LINE_CAP:
        return ("$" in norm or "`" in norm) and bool(_RISK_OPTION.search(low) or "{" in norm)
    if not _expands(norm):
        return False
    word = bool(_RISK_OPTION.search(low))
    brace = _has_brace_word(norm)
    if (word or brace) and _expansion_at_command(norm):
        return True
    if (_RISK_FLAG.search(low) or brace) and _expansion_past_first_word(norm):
        return True
    return word and bool(_SHELL_C.search(low) and _DOLLAR.search(norm))


def _gemini_expansion(text: str, low: str, names: set[str]) -> bool:
    """A command segment that holds the word `gemini` (or the vendor host, an SDK or the paid config) and, in that same
    segment, a variable the brief assigns or any other expansion. A segment ends at `; | & ( ) < >`, so an expansion in
    another command is not counted, however near. When the lexer cannot read the line, the whole line is the segment."""
    marker = bool(PAID_CONFIG.search(low) or VENDOR_HOST in low or SDK.search(low))
    tokens = _lex(text)
    if tokens is None:
        return (marker or bool(re.search(r"(?<![\w/.-])gemini(?![\w/.-])", low))) and (
            _expands(text) or any(m.group(1) in names for m in _REFERENCE.finditer(text))
        )
    segments: dict[int, list[Tok]] = {}
    segment = 0
    for t in tokens:
        if t.op:
            if _breaks(t.value):
                segment += 1
            continue
        segments.setdefault(segment, []).append(t)
    for words in segments.values():
        if not (marker or any(_core(t.value) == "gemini" for t in words)):
            continue
        for t in words:
            if _DOLLAR.search(t.value) or any(m.group(1) in names for m in _REFERENCE.finditer(t.value)):
                return True
    return marker and _expands(text)


def _flows(lines: list[str], tick: Callable[[], None]) -> list[Construct]:
    """The constructs that hide where a command comes from. Time is checked once per line; nothing is expanded."""
    found: list[Construct] = []
    stripped: list[str] = []
    names: set[str] = set()
    for line in lines:
        tick()
        text = _strip_comment(line)
        stripped.append(text)
        for pattern in (_ASSIGNED, _PRINTF_NAME, _LOOP_NAME, _READ_NAME):
            names.update(m.group(1) for m in pattern.finditer(text))
    if len(names) > MAX_VARIABLES:
        return [("more variables than can be followed", 1, "always")]
    for number, text in enumerate(stripped, 1):
        if not text.strip():
            continue
        views = _views(text)
        low = views[2]
        value = [m.group(1) for m in _REFERENCE.finditer(text)]
        refers = any(name in names for name in value)
        gemini_line = bool(_RISK_TOKEN.search(low))
        if _FUNCTION.search(low):
            found.append(("a function", number, "standalone"))
        for label, pattern in _STANDALONE:
            if pattern.search(low):
                found.append((label, number, "standalone"))
        for m in _ASSIGNED.finditer(text):
            rest = text[m.end() : m.end() + 2]
            if rest.startswith("(") and not rest.startswith("(("):
                found.append(("an array", number, "standalone"))
            elif _expands(text[m.end() :].split(None, 1)[0] if text[m.end() :].strip() else ""):
                found.append(("an assignment from an expansion", number, "standalone"))
        at_command = _expansion_at_command(views[0])
        if _risk_line(views[0], low):
            found.append(
                ("a Gemini option or action on a line whose command is built by an expansion", number, "always")
            )
        concealed = bool(CONCEAL.search(text.lower()))
        expands = _expands(text)
        option = bool(_GEMINI_OPTION.search(low))
        # independent checks: every one that holds is recorded, and the brief-wide gating picks what counts
        if at_command and (refers or concealed):
            found.append(("a variable or escape sequence that is the command", number, "flow"))
        if at_command:
            found.append(("an expansion that is the command", number, "weak"))
        if _gemini_expansion(text, low, names):
            found.append(("a variable or expansion on a line that names Gemini", number, "flow"))
        if refers and gemini_line:
            found.append(("a variable in a Gemini command line", number, "flow"))
        if expands and option:
            found.append(("an expansion in a Gemini command line", number, "weak"))
        if concealed and (gemini_line or option or _GEMINI_WORD.search(low)):
            found.append(("an escape sequence on a Gemini line", number, "flow"))
    return found


def _findings(
    prompt: str, check: ApprovalCheck | None, terms: TermsSource, deadline: float | None
) -> list[tuple[str, str]]:
    def tick() -> None:
        if deadline is not None and time.monotonic() > deadline:
            raise TimeoutError("the Gemini check ran out of time")

    tick()
    joined = _join(prompt)
    lines = [_neutral_prose(line) for line in joined.splitlines()]
    whole = "\n".join(_views(line)[2] for line in lines)
    runtime_scan = bool(re.search(r"\bgemini\b", whole)) and bool(
        re.search(r"(?<![\w-])(?:ask|approve|paid-dryrun|paid)(?![\w-])|--paid", whole)
    )
    steps: list[Step] = []
    flags: dict[str, int] = {}
    materials: list[str] = []
    budget = [MAX_CANDIDATES]
    constructs = _flows(lines, tick)
    named = bool(re.search(r"\bsafo\b", whole) and re.search(r"\bgemini\b", whole))
    surface = bool(
        re.search(r"\b(?:safo|gemini)\b", whole)
        or PAID_CONFIG.search(whole)
        or VENDOR_HOST in whole
        or SDK.search(whole)
        or CONCEAL.search(joined.lower())
    )
    weak_on = named
    standalone_on = named and bool(_PAID_TOKEN.search(whole))
    for name, number, kind in constructs:
        if (
            kind == "always"
            or (kind == "flow" and surface)
            or (kind == "weak" and weak_on)
            or (kind == "standalone" and standalone_on)
        ):
            steps.append(
                Step(
                    unreadable=True,
                    line=number,
                    why=f"the brief uses {name}, so it cannot be read as one command; a Gemini command built from "
                    "variables, escapes or substitutions is blocked by design: write one plain "
                    "`safo gemini ask --model M ...` command",
                )
            )
            break
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
        steps.append(
            Step(paid=True, line=flags["paid"], why="the paid secret-store config is named", matched=MATCH_CONFIG)
        )
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


# -- shell commands (#209) ---------------------------------------------------------------------------------------------
# A cheap, fail-closed check on one Bash command. It names no value and resolves nothing: it looks for the vendor API
# host, its SDK, the key variable name and the secret-store project and config names (all shown in docs/gemini-keys.md
# and examples/gemini.example.yaml), and for words built from escapes or an expansion beside a network or secret tool.
# The wrapper `safo gemini ...` holds the real gates. There is no exemption: a command that names them is denied
# whatever it is called or runs from. The classes are fixed text: a denial never repeats a word of the command.
SHELL_VENDOR = "the vendor API host or SDK"
SHELL_KEY = "the key variable name"
SHELL_STORE = "the secret-store project or config name"
SHELL_BUILT = "a word built from escapes beside a network or secret tool"
SHELL_TOOL = "a secret tool run with a shell expansion"
SHELL_UNVERIFIED = "a command that could not be checked in time"
SHELL_CAP = 64 * 1024  # a command longer than this is denied unread: no normalization runs on it
_SHELL_KEY = re.compile(r"gemini[\W_]*api[\W_]*key")
_SHELL_PROJECT = re.compile(r"(?<![\w-])image-gen(?![\w-])")
_SHELL_CONFIG = re.compile(r"(?<![\w-])prd(?![\w-])")
_SECRET_TOOL = re.compile(r"(?<![\w.-])doppler(?![\w-])")
_NETWORK_TOOL = re.compile(
    r"(?<![\w.-])(?:curl|wget|nc|ncat|socat|openssl|ssh|telnet|python[\d.]*|node|nodejs|perl|ruby|php|go|deno|bun"
    r"|httpie|http|https|aria2c|lwp-request|powershell|pwsh)(?![\w-])"
)


def shell_command_class(command: str, deadline: float | None = None) -> str | None:
    """The fixed phrase class of what makes one Bash command a direct route to the vendor API or its key, or None when
    it is fine. Fails closed: past the deadline it answers SHELL_UNVERIFIED."""

    def tick() -> None:
        if deadline is not None and time.monotonic() > deadline:
            raise TimeoutError("the shell check ran out of time")

    if len(command) > SHELL_CAP:
        return SHELL_UNVERIFIED  # before any normalization: the cost of the check never depends on a hostile length
    try:
        tick()
        lines = _join(command).splitlines() or [command]
        found: str | None = None
        secret_tool = network = False
        for line in lines:
            tick()
            _, _, low, pre_low, _pre_raw = _views(line)
            for view in (low, pre_low):
                if VENDOR_RE.search(view) or SDK.search(view):
                    found = found or SHELL_VENDOR
                if _SHELL_KEY.search(view):
                    found = found or SHELL_KEY
                if PAID_CONFIG.search(view) or _SHELL_PROJECT.search(view):
                    found = found or SHELL_STORE
                secret_tool = secret_tool or bool(_SECRET_TOOL.search(view))
                network = network or bool(_NETWORK_TOOL.search(view))
            if secret_tool and any(_SHELL_CONFIG.search(v) for v in (low, pre_low)):
                found = found or SHELL_STORE
        tick()
        built = bool(CONCEAL.search(command.lower()) or CONCEAL.search(_join(command).lower()))
        if found is None and built and (network or secret_tool):
            found = SHELL_BUILT
        if found is None and secret_tool and (_DOLLAR.search(command) or "`" in command):
            found = SHELL_TOOL
        if found is None:
            return None
        return found
    except TimeoutError:
        return SHELL_UNVERIFIED
