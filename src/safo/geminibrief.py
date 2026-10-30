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
    r"(?:base64\s+(?:-d\b|-D\b|--decode\b)|openssl\s+[^|]{0,40}-d\b|xxd\s+-r|(?<![\w=-])rev(?![\w=-])|printf\s+[^|]{0,80}\\x)"
)
SINK_RE = re.compile(SINK)
SHELL_WILD = frozenset("$*?[]{}`%")
RISKY_ACTIONS = ("ask", "approve")
ACTIONS = ("ask", "approve", "quota")
# inline code in prose that wraps a known word, an option or a file name; any other word in backticks runs as a command
MARKDOWN_WORD = re.compile(
    r"^`(?:ask|approve|quota|gemini|safo|--[a-z-]{1,30}|[\w.-]{0,60}[./][\w./-]{0,100})`[.,:;)]*$"
)
VENDOR_RE = re.compile(re.escape(VENDOR_HOST))
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
    disabled = getattr(check, "disabled", None)
    if isinstance(disabled, str):
        return f"{where}{disabled}"
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
    when it also carries a Gemini option or action, since the words themselves may be what the escapes hide."""
    concealed = risky = False
    for line in _join(text).splitlines():
        norm, _, low, pre_low, pre_raw = _views(line)
        raw = norm.lower()
        for name, pattern in PREFILTER:
            if name == "conceal":
                concealed = concealed or bool(pattern.search(raw) or pattern.search(pre_raw))
            elif name == "decode":
                if pattern.search(raw) or pattern.search(pre_raw):
                    return True
            elif pattern.search(low) or pattern.search(pre_low):
                return True
        risky = risky or bool(_RISK_TOKEN.search(low))
    return concealed and risky


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
                    problems.append(f"an operator ({nxt.value!r}) touching a quoted word")
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


# Brief-wide reading of a command that is built over several lines.
#
# * Plain NAME=value assignments, plain ANSI-C words ($'\x73afo') and `printf -v NAME 'literal'` are resolved and the
#   values expanded into what follows, so a command built that way is read as the literal command it is.
# * What cannot be resolved is a "construct". A FLOW construct is a value that still reaches a command position (an
#   expansion or substitution that is left, an escape or printf that cannot be resolved): it makes the brief unreadable
#   when the brief names a Gemini command or builds words with escapes. A STANDALONE construct (an array, a function,
#   eval, xargs, a shell -c, an assignment from an expansion) makes the brief unreadable only beside a paid or approve
#   step. A resource construct (a line or the total growing past a limit) always does.
_ASSIGN = re.compile(r"(?<![\w$.\-/])([A-Za-z_][A-Za-z0-9_]*)(\+?)=(\"[^\"]*\"|'[^']*'|\(|[^\s;&|<>]*)")
_VAR_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_FUNCTION = re.compile(r"(?<![\w$.\-/])[A-Za-z_]\w*\s*\(\)|(?<![\w-])function\s+[A-Za-z_]\w*")
_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'", re.S)
_PRINTF_V = re.compile(
    r"(?<![\w$.\-/])printf\s+-v\s+([A-Za-z_]\w*)\s+('(?:[^'\\]|\\.)*'|\"(?:[^\"$`\\]|\\.)*\"|[^\s;&|<>$`\"']+)"
)
_ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[0-7]{1,3}|.)", re.S)
_SIMPLE_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "e": "\x1b",
    "E": "\x1b",
}
_PLAIN_VALUE = re.compile(r"[\w@%+=:,./-]+")
_RISK_TOKEN = re.compile(r"--paid|--approval|--cap\b|(?<![\w-])(?:ask|approve)\b")
_PAID_TOKEN = re.compile(r"--paid|(?<![\w-])approve\b")
_GEMINI_WORD = re.compile(r"\b(?:safo|gemini)\b|--paid|--approval|--cap\b")
_SHELL_C = re.compile(
    r"(?<![\w-])(?:bash|sh|zsh|dash|ksh|csh|tcsh|fish|pwsh|python[\d.]*|perl|ruby|node|php|lua)\b(?:\s+-{1,2}[\w-]+)*"
    r"\s+-\w*c\b"
)
_STANDALONE = (
    ("eval", re.compile(r"(?<![\w-])eval\b")),
    ("xargs", re.compile(r"(?<![\w-])xargs\b")),
    ("a shell or interpreter -c", _SHELL_C),
)
TOTAL_EXPANDED_CAP = 200_000  # characters of expanded lines in one brief

Construct = tuple[str, int, str]  # (what, line number, kind: flow, standalone or always)


class _Grew(Exception):
    """An expansion grew past a limit."""


def _unescape(body: str) -> str | None:
    def one(m: re.Match[str]) -> str:
        g = m.group(1)
        if g[0] == "x":
            return chr(int(g[1:], 16))
        if g[0] in "uU":
            return chr(int(g[1:], 16))
        if g[0] in "01234567":
            return chr(int(g, 8) & 0xFF)
        return _SIMPLE_ESCAPES.get(g, g if g in "\\'\"?" else "\\" + g)

    try:
        return _ESCAPE.sub(one, body)
    except (ValueError, OverflowError):
        return None


def _as_word(value: str) -> str | None:
    """A resolved value as shell text: itself when plain, single-quoted when it only holds printable text, else None."""
    if value and _PLAIN_VALUE.fullmatch(value):
        return value
    if value and all(c.isprintable() and c not in "'\\$`" for c in value):
        return "'" + value + "'"
    return None


def _ansi_c(text: str) -> tuple[str, bool]:
    """ANSI-C words resolved where plain. The flag is True when one could not be."""
    bad = False

    def one(m: re.Match[str]) -> str:
        nonlocal bad
        word = _as_word(_unescape(m.group(1)) or "")
        if word is None:
            bad = True
            return m.group(0)
        return word

    return _ANSI_C.sub(one, text), bad


def _strip_comment(text: str) -> str:
    """The text without a shell comment: a `#` that starts a word and is not inside quotes."""
    quote = ""
    for i, c in enumerate(text):
        if quote:
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c == "\\":
            continue
        elif c == "#" and (i == 0 or text[i - 1].isspace()):
            return text[:i]
    return text


_ASSIGNMENT_WORD = re.compile(r"[A-Za-z_]\w*\+?=")
_PREFIX_WORDS = frozenset({"env", "command", "exec", "nohup", "time", "sudo", "builtin", "eval", "xargs"})


_DOLLAR = re.compile(r"\$[\w{(@*#?!-]")  # a shell expansion ($A, ${A}, $(cmd), $1, $@), not a price or a bare sign
_BACKTICK_CMD = re.compile(
    r"`\s*(?:echo|printf|cat|base64|xxd|rev|tr|sed|awk|cut|head|tail|printenv|which|env|command|type|basename|dirname"
    r"|readlink|date|git|jq|python[\d.]*|perl|ruby|node|bash|sh)\b[^`]*`"
)  # a command substitution in backticks; markdown code spans (`quota`, `approve <job>`) are not one


def _expands(text: str) -> bool:
    """True when the text holds a shell expansion or a backtick command substitution."""
    return bool(_DOLLAR.search(text) or _BACKTICK_CMD.search(text))


def _expansion_at_command(text: str) -> bool:
    """True when a command word (the first word of a command, after an operator, or after env/command/exec...) still
    holds a shell expansion or a command substitution, so what runs is not what is written. A line the lexer cannot
    read that holds one is unreadable, so True as well. A shell comment is not code."""
    text = _strip_comment(text)
    tokens = _lex(text)
    if tokens is None:
        return _expands(text)
    if _BACKTICK_CMD.search(text):
        return True
    at_start = True
    for t in tokens:
        if t.op:
            at_start = _breaks(t.value)
            continue
        if at_start and _ASSIGNMENT_WORD.match(t.value) and not t.quoted:
            continue  # NAME=value before the command word: the value is judged as an assignment, not as the command
        if at_start and _DOLLAR.search(t.value):
            return True
        at_start = at_start and t.value in _PREFIX_WORDS
    return False


def _expansion_anywhere(text: str) -> bool:
    return _expands(_strip_comment(text))


def _resolve(lines: list[str], tick: Callable[[], None]) -> tuple[list[str], list[Construct]]:
    """(the lines with the resolvable values expanded into what follows them, the constructs that could not be
    resolved). Time is checked per line and per expansion; a line may not grow past LINE_CAP, nor the brief past
    TOTAL_EXPANDED_CAP: either records a construct and stops expanding."""
    known: dict[str, str | None] = {}
    found: list[Construct] = []
    out: list[str] = []
    total = 0
    for number, line in enumerate(lines, 1):
        tick()
        if total > TOTAL_EXPANDED_CAP:
            found.append(("expansions that grow past the limit for a brief", number, "always"))
            out.extend(lines[number - 1 :])
            break
        size = [len(line)]

        def expand(text: str, size: list[int] = size) -> str:
            def one(ref: re.Match[str]) -> str:
                tick()
                value = known.get(ref.group(1) or ref.group(2))
                if value is None:
                    return ref.group(0)
                size[0] += len(value) - len(ref.group(0))
                if size[0] > LINE_CAP:
                    raise _Grew
                return value

            return _VAR_REF.sub(one, text)

        try:
            work, bad = _ansi_c(line)
            if bad:
                found.append(("an escape sequence that cannot be resolved", number, "flow"))
            text, at = "", 0
            low = _views(work)[2]
            # printf -v NAME 'literal' is an assignment
            for pm in _PRINTF_V.finditer(work):
                raw = pm.group(2)
                inner = raw[1:-1] if raw[:1] in "'\"" and raw[-1:] == raw[:1] and len(raw) >= 2 else raw
                if "%" in inner.replace("%%", ""):
                    found.append(("printf -v with a conversion", number, "flow"))
                    known[pm.group(1)] = None
                else:
                    value = _unescape(inner.replace("%%", "%"))
                    known[pm.group(1)] = value if value is not None and "\x00" not in value else None
                    if known[pm.group(1)] is None:
                        found.append(("printf -v with a value that cannot be resolved", number, "flow"))
            for m in _ASSIGN.finditer(work):
                text += expand(work[at : m.start()]) + work[m.start() : m.end()]
                at = m.end()
                name, plus, value = m.group(1), m.group(2), m.group(3)
                if value == "(":
                    found.append(("an array", number, "standalone"))
                    known[name] = None
                elif "$" in value or "`" in value or "\\" in value:
                    found.append(("an assignment from an expansion", number, "standalone"))
                    known[name] = None
                else:
                    quoted = len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]
                    plain = value[1:-1] if quoted else value
                    before = known.get(name)
                    known[name] = before + plain if plus and before is not None else plain
            text += expand(work[at:])
        except _Grew:
            found.append(("a line that grows past the line limit when its variables are expanded", number, "always"))
            out.append(line)
            total += len(line)
            continue
        out.append(text)
        total += len(text)
        if _FUNCTION.search(low):
            found.append(("a function", number, "standalone"))
        for label, pattern in _STANDALONE:
            if pattern.search(low):
                found.append((label, number, "standalone"))
        if ("$" in text or "`" in text) and _expansion_at_command(_views(text)[0]):
            found.append(("an expansion that cannot be resolved", number, "flow"))
        elif (
            ("$" in text or "`" in text)
            and _GEMINI_WORD.search(_views(text)[2])
            and _expansion_anywhere(_views(text)[0])
        ):
            found.append(("an expansion that cannot be resolved in a Gemini command line", number, "flow"))
    return out, found


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
    expanded, constructs = _resolve(lines, tick)
    whole2 = "\n".join(_views(line)[2] for line in expanded)
    named = bool(re.search(r"\bsafo\b", whole2) and re.search(r"\bgemini\b", whole2))
    flow_on = (named and bool(_RISK_TOKEN.search(whole2))) or (
        bool(CONCEAL.search(joined.lower())) and bool(_GEMINI_WORD.search(whole2) or _RISK_TOKEN.search(whole2))
    )
    standalone_on = named and bool(_PAID_TOKEN.search(whole2))
    for name, number, kind in constructs:
        if kind == "always" or (kind == "flow" and flow_on) or (kind == "standalone" and standalone_on):
            steps.append(
                Step(
                    unreadable=True,
                    line=number,
                    why=f"the brief uses {name} to build or hide a command, so it cannot be read as one command; "
                    "write one plain `safo gemini ask --model M ...` command",
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
        if expanded[number - 1] != line:  # `_resolve` keeps every expanded line within LINE_CAP, or records why not
            _scan_line(number, expanded[number - 1], steps, flags, materials, budget, runtime_scan)
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
