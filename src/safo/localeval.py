# SPDX-License-Identifier: Apache-2.0
"""safo-eval: score the local LLM against synthetic work items with ground truth, and derive a routing table (#484).

    safo-eval run --models qwen3.5:4b,gemma4:12b --tasks all --repeats 3 --out DIR [--calibrate N]
    safo-eval report --runs DIR/runs.jsonl --out DIR [--rescore]
    safo-eval calibrate --runs DIR/runs.jsonl --n 35 --out DIR       # writes DIR/calibration.json to fill in
    safo-eval calibrate --ingest DIR/calibration.json --out DIR      # reads the verdicts, writes the agreement file

Scoring is code only (fact recall, forbidden hits, format, length); no model ever grades a model. Calls go through
`llm-local`, one at a time, stdin always /dev/null. Exit 75 (queue busy) is retried with backoff and then recorded as
busy, never as an error. Any other failure is recorded and counted, never hidden.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import re
import stat
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

from safo import bounded, output

TASKS: tuple[str, ...] = (
    "issue-draft",
    "issue-triage",
    "ci-log-digest",
    "pr-summary",
    "commit-message",
    "first-pass-review-comment",
    "doc-skeleton",
)

INSTRUCTIONS: dict[str, str] = {
    "issue-draft": "Draft a GitHub issue from the notes below. Output a title line, then the body. "
    "Use only facts in the notes.",
    "issue-triage": "Triage the issue below. Choose exactly one label and one epic from the lists it gives. "
    'Reply as JSON {"label": "...", "epic": "..."} and nothing else.',
    "ci-log-digest": "Summarize the CI log below in at most six lines for a person who will not read it: what failed, "
    "where, and the likely cause. Copy numbers and names exactly. Do not invent any.",
    "pr-summary": "Write a pull request summary for the diff or notes below: a one-line title, then short bullets. "
    "Use only what is in the input.",
    "commit-message": "Write one git commit message for the change below: a subject line of at most 72 characters in "
    "the form type: subject (type is feat, fix, docs, refactor, test or chore), a blank line, then a short body. "
    "Use fix: only for a bug fix, feat: only for a new user-visible capability, docs: only for documentation, "
    "chore: for dependency bumps and tooling, refactor: for restructuring with no behavior change.",
    "first-pass-review-comment": "Review the small diff below. Find the single planted defect and write one review "
    "comment that names the defect and the line or function it is in.",
    "doc-skeleton": "Write a Markdown documentation skeleton for the topic below: a title, then one heading per "
    "section asked for, each with a one-line placeholder. Use the section names given.",
}

PASS_RECALL = 0.8
LOCAL_MIN = 0.9  # best model pass rate at or above this: local only
CHECK_MIN = 0.6  # at or above this but below LOCAL_MIN: local draft, Claude checks
CAL_SAMPLE_DEFAULT = 35  # passing outputs sampled per (task, model) cell for human or reviewer verdicts
CAL_MIN_VERDICTS = 35  # fewer verdicts than this and the cell is not calibrated
CAL_MIN_LOWER = 0.9  # lower bound of the ok share needed for local-only
# two-sided 95 percent, the same as the pass-rate gate: 35 of 35 ok gives about 0.901, 34 of 35 does not
CAL_Z = 1.96
CAL_FORMAT = "safo-eval-calibration-1"
CAL_MAX_BYTES = 50_000_000
CAL_MAX_N = 100_000  # an n above this in a calibration file is not a sample size
MODEL_TIER = {"qwen3.5:4b": "local-qwen", "gemma4:12b": "local-gemma"}
DEFAULT_CALL_LOG = Path.home() / ".local/share/llm-local/calls.jsonl"
BUSY_EXIT = 75
COPY_CAP_DEFAULT = 0.5  # share of the output that may be copied from the input (lines or 8-word shingles)
COPY_CAP: dict[str, float] = {"issue-triage": 1.0}  # JSON answers restate labels from the input by design
FACTS_ONLY_MIN = 0.3  # at least this share of the tokens must be words that are not fact tokens
FACTS_ONLY_EXEMPT = frozenset({"issue-triage"})
SHINGLE = 8
MIN_BUCKET_RUNS = 10
BUCKET_HOURS = 4
FIXTURES_DEFAULT = Path(__file__).resolve().parents[2] / "eval" / "fixtures"


class EvalError(Exception):
    """A usage or fixture problem; the message is shown and the exit code is 2."""


@dataclass(frozen=True)
class Fact:
    text: str
    variants: tuple[str, ...] = ()


@dataclass(frozen=True)
class Fixture:
    id: str
    task: str
    input: str
    facts: tuple[Fact, ...]
    forbidden: tuple[str, ...]
    max_chars: int
    required_format: str  # any | json | json-object | regex:<pattern>
    wrong: tuple[str, ...] = ()  # known-wrong outputs: a guard test asserts none of them passes
    sections: tuple[str, ...] = ()  # doc-skeleton: the facts that must be headings (default: every fact)
    correct_alts: tuple[str, ...] = ()  # valid alternative outputs: a guard test asserts every one passes


@dataclass
class Score:
    recall: float
    facts_missed: list[str]
    forbidden_hits: list[str]
    format_ok: bool
    length_ok: bool
    passed: bool = field(default=False)
    fenced: bool = False  # one outer code fence was stripped before the json check
    structure_ok: bool = True
    copy_ratio: float = 0.0
    facts_only: bool = False
    reasons: list[str] = field(default_factory=list)  # why a run failed: recall forbidden format length structure copy


def load_fixture(path: Path) -> Fixture:
    try:
        raw = bounded.loads(path.read_text(encoding="utf-8"))
        facts = tuple(
            Fact(f, ()) if isinstance(f, str) else Fact(str(f["text"]), tuple(str(v) for v in f.get("variants", [])))
            for f in raw["facts"]
        )
        fixture = Fixture(
            id=f"{path.parent.name}/{path.stem}",
            task=str(raw["task"]),
            input=str(raw["input"]),
            facts=facts,
            forbidden=tuple(str(x) for x in raw.get("forbidden", [])),
            max_chars=int(raw["max_chars"]),
            required_format=str(raw.get("required_format", "any")),
            wrong=tuple(str(x) for x in raw.get("wrong", [])),
            sections=tuple(str(x) for x in raw.get("sections", [])),
            correct_alts=tuple(str(x) for x in raw.get("correct_alts", [])),
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise EvalError(f"bad fixture {path.name}: {exc}") from exc
    if fixture.task not in TASKS:
        raise EvalError(f"bad fixture {path.name}: unknown task {fixture.task!r}")
    if not fixture.facts:
        raise EvalError(f"bad fixture {path.name}: no facts")
    for pattern in (*fixture.forbidden, *(v for f in facts for v in f.variants)):
        try:
            re.compile(pattern)
        except re.error as exc:
            raise EvalError(f"bad fixture {path.name}: bad regex {pattern!r}: {exc}") from exc
    return fixture


def load_fixtures(root: Path, tasks: Sequence[str] | None = None) -> list[Fixture]:
    fixtures = [load_fixture(p) for p in sorted(root.glob("*/*.json"))]
    if tasks is not None:
        fixtures = [f for f in fixtures if f.task in tasks]
    if not fixtures:
        raise EvalError(f"no fixtures found under {root}")
    return fixtures


def _fact_spans(fact: Fact, output: str) -> list[tuple[int, int]]:
    """Every place the fact matches. The fact text counts on word boundaries (60 is not in 600, Install is not in
    Uninstall); a text of two characters or fewer is also case-sensitive (Z is not in zebra, Id is not id). Variants
    are regexes written by the fixture."""
    text = fact.text
    pattern = (r"(?<!\w)" if text[:1].isalnum() or text[:1] == "_" else "") + re.escape(text)
    pattern += r"(?!\w)" if text[-1:].isalnum() or text[-1:] == "_" else ""
    flags = 0 if len(text) <= 2 else re.IGNORECASE
    spans = [m.span() for m in re.finditer(pattern, output, flags)]
    for v in fact.variants:
        spans += [m.span() for m in re.finditer(v, output, re.IGNORECASE)]
    return spans


def _fact_matches(fact: Fact, output: str) -> bool:
    return bool(_fact_spans(fact, output))


_FENCE = re.compile(r"\A\s*```[\w+.-]*[ \t]*\n(?P<body>.*?)\n[ \t]*```\s*\Z", re.DOTALL)


def strip_one_fence(output: str) -> tuple[str, bool]:
    """Remove exactly one outer markdown code fence; only whitespace may sit outside it.

    Text before or after the fence, an unclosed fence, or a second fence inside leaves the output unchanged.
    """
    m = _FENCE.match(output)
    if m is None:
        return output, False
    body = m.group("body")
    if any(line.lstrip().startswith("```") for line in body.splitlines()):
        return output, False
    return body, True


def _format_ok(spec: str, output: str) -> tuple[bool, bool]:
    """Returns (format ok, whether an outer fence was stripped to get there)."""
    if spec == "any":
        return True, False
    if spec in ("json", "json-object"):
        body, fenced = strip_one_fence(output)
        try:
            data = bounded.loads(body.strip())
        except ValueError:
            return False, fenced
        return (isinstance(data, dict) if spec == "json-object" else True), fenced
    if spec.startswith("regex:"):
        return re.search(spec[len("regex:") :], output, re.DOTALL) is not None, False
    raise EvalError(f"unknown required_format {spec!r}")


_BULLET = re.compile(r"^\s*(?:[-*+•]|\d+[.)])\s+")
_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(?P<text>.*?)\s*#*\s*$")
_WORD = re.compile(r"[a-z0-9_]+")
_SENTENCE = re.compile(r"(?<=[.!?])\s+")


def _norm(line: str) -> str:
    return " ".join(_BULLET.sub("", line).lower().split())


def _nonblank(output: str) -> list[str]:
    return [ln for ln in output.splitlines() if ln.strip()]


def _words(text: str) -> list[str]:
    return _WORD.findall(text.lower())


def copy_ratio(source: str, output: str) -> float:
    """Share of the output copied from the input: the larger of (a) the share of output lines of 4 or more words that
    appear verbatim in the input and (b) the share of the output's 8-word shingles that are also input shingles."""
    flat = _norm(source)
    lines = [_norm(ln) for ln in _nonblank(output)]
    lines = [ln for ln in lines if len(ln.split()) >= 4]
    by_line = sum(1 for ln in lines if ln in flat) / len(lines) if lines else 0.0
    out_w, in_w = _words(output), _words(source)
    out_sh = [tuple(out_w[i : i + SHINGLE]) for i in range(len(out_w) - SHINGLE + 1)]
    in_sh = {tuple(in_w[i : i + SHINGLE]) for i in range(len(in_w) - SHINGLE + 1)}
    by_shingle = sum(1 for sh in out_sh if sh in in_sh) / len(out_sh) if out_sh else 0.0
    return max(by_line, by_shingle)


def facts_only(fixture: Fixture, output: str) -> bool:
    """True when the output is little more than the facts strung together: fewer than 30 percent of its tokens are
    words that are not fact tokens (the connecting words a real answer needs)."""
    fact_tokens = {t for f in fixture.facts for t in _words(f.text)}
    tokens = _words(output)
    if not tokens:
        return True
    return sum(1 for t in tokens if t not in fact_tokens) / len(tokens) < FACTS_ONLY_MIN


STOPWORDS = frozenset(
    {
        *("a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "have", "in", "is", "it", "its"),
        *("of", "on", "or", "that", "the", "this", "to", "was", "were", "with", "not", "but", "if", "so", "then"),
        *("than", "there", "these", "those", "which", "who", "will", "would", "can", "could", "should", "may"),
        *("might", "do", "does", "did", "into", "out", "up"),
    }
)
CI_MIN_NOVEL = 8  # ci-log-digest: content words that are neither fact words nor words of the input
REVIEW_MIN_WORDS = 8  # first-pass-review-comment: words outside the facts (the function name is fact one)
NEAR_CHARS = 80  # a causal or locator phrase must sit within this many characters of a fact
# a digest must say why or where: one of these words or phrases, near a fact
CAUSAL = re.compile(
    r"\b(?:because|caused|cause|due to|failed at|failed in|in step|at line|after|when|since|root cause|during|while)\b",
    re.IGNORECASE,
)
# a review comment states the defect in a full sentence: one of these verbs or auxiliaries in it
DEFECT_VERB = re.compile(
    r"\b(?:is|are|was|were|will|can|could|may|might|does|do|did|never|should|must|has|have|had|isn't|doesn't|don't|"
    r"won't|can't|leaks?|leaked|leaving|left|overwrites?|overwrote|skips?|skipped|ignores?|ignored|returns?|returned|"
    r"raises?|raised|mutates?|mutated|shares?|shared|concatenat(?:es|ed|ing)|drops?|dropped|omits?|omitted|misses?|"
    r"missed|excludes?|excluded|uses?|used|opens?|opened|closes?|closed|fails?|failed|evaluat(?:es|ed)|"
    r"accumulat(?:es|ed)|persists?|persisted|allows?|allowed|builds?|built|compar(?:es|ed)|treats?|treated|reads?|"
    r"writes?|wrote|appends?|appended|lacks?|breaks?|broke|splic(?:es|ed|ing)|inserts?|inserted|interpolat(?:es|ed)|"
    r"removes?|removed|loses?|lost|replac(?:es|ed)|reus(?:es|ed)|forgets?|forgot|passes|passed|accepts?|trusts?|"
    r"exposes?|exposed|divid(?:es|ed)|makes?|made|multipl(?:ies|ied)|subtracts?|subtracted|applies|applied|"
    r"computes?|computed|calculat(?:es|ed)|produces?|produced|gives?|gave|takes?|took)\b",
    re.IGNORECASE,
)


# a review comment that names the defect only to deny it ("so there is no SQL injection risk", "the boundary is
# correct") is wrong. Two checks, per sentence, only in a sentence that holds a defect fact:
# (1) a denial phrase anywhere in the sentence ("not possible", "cannot happen", "impossible", "no risk", ...);
# (2) a marker within NEG_WINDOW words of the fact, unless the marker is itself negated ("not safe") or the sentence
#     says the defect is present (a defect cue such as "remains", "still", "leaks", "no escaping", "no guarantee").
# not, never and without are left out of the markers on purpose: "never closes the file" states the defect. So does
# "no longer". The lists are words, not understanding (docs/local-eval.md).
NEGATION_MARKERS = ("no", "correct", "correctly", "safe", "fine", "ok", "harmless")
NEG_WINDOW = 3
DENIAL_PHRASES = re.compile(
    r"\b(?:not possible|cannot happen|can not happen|impossible|no risk|no issue|no problem|not an issue)\b",
    re.IGNORECASE,
)
DEFECT_CUES = re.compile(
    r"\b(?:possible|remains?|still|leaks?|leaked|vulnerable|exploitable|no escaping|no guarantee)\b", re.IGNORECASE
)
_TOKEN = re.compile(r"[A-Za-z0-9_']+")
_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+|\n")


def denies_defect(defect: Sequence[Fact], output: str) -> bool:
    for sentence in _SENT_SPLIT.split(output):
        toks = [(m.group().lower(), m.start(), m.end()) for m in _TOKEN.finditer(sentence)]
        stated = DEFECT_CUES.search(sentence) is not None
        for fact in defect:
            spans = _fact_spans(fact, sentence)
            if spans and DENIAL_PHRASES.search(sentence):
                return True
            for fs, fe in spans:
                inside = [i for i, (_, s, e) in enumerate(toks) if s < fe and e > fs]
                if not inside or stated:
                    continue
                lo, hi = inside[0], inside[-1]
                for i in [*range(max(0, lo - NEG_WINDOW), lo), *range(hi + 1, min(len(toks), hi + 1 + NEG_WINDOW))]:
                    longer = i + 1 < len(toks) and toks[i + 1][0] == "longer"  # "no longer divides" states the defect
                    negated = i > 0 and toks[i - 1][0] == "not"  # "not safe" says the opposite of safe
                    if toks[i][0] in NEGATION_MARKERS and not (toks[i][0] == "no" and longer) and not negated:
                        return True
    return False


def _all_fact_spans(fixture: Fixture, output: str) -> list[tuple[int, int]]:
    return [sp for f in fixture.facts for sp in _fact_spans(f, output)]


def _fact_tokens(fixture: Fixture) -> set[str]:
    return {t for f in fixture.facts for t in _words(f.text)}


def outside_words(fixture: Fixture, output: str) -> list[str]:
    """The words of the output that are not words of a fact text (the function name is fact one)."""
    tokens = _fact_tokens(fixture)
    return [w for w in _words(output) if w not in tokens]


def novel_words(fixture: Fixture, output: str) -> set[str]:
    """Content words of the output that are not fact words and not words of the input: what the model added."""
    known = set(_words(fixture.input)) | STOPWORDS
    return {w for w in outside_words(fixture, output) if len(w) >= 3 and w not in known}


def causal_near_fact(fixture: Fixture, output: str) -> bool:
    spans = _all_fact_spans(fixture, output)
    return any(
        max(0, fs - cb, ca - fe) <= NEAR_CHARS
        for ca, cb in (m.span() for m in CAUSAL.finditer(output))
        for fs, fe in spans
    )


def _title_ok(line: str) -> bool:
    title = re.sub(r"^[#*\s]+", "", line).strip()
    title = re.sub(r"^title:\s*", "", title, flags=re.IGNORECASE).rstrip("* ").strip()
    return 0 < len(title) <= 80


def _structure_ok(fixture: Fixture, output: str) -> bool:
    """Per-task required shape: whatever INSTRUCTIONS asks for that code can check."""
    task = fixture.task
    lines = _nonblank(output)
    if task == "issue-draft":  # a title of at most 80 characters, then at least two bullets or sentences
        units = sum(
            1 if _BULLET.match(ln) else len([x for x in _SENTENCE.split(ln) if len(x.split()) >= 3]) for ln in lines[1:]
        )
        return len(lines) >= 2 and _title_ok(lines[0]) and units >= 2
    if task == "pr-summary":  # one summary paragraph, then at least two bullets
        raw = output.strip("\n").splitlines()
        first = next((i for i, ln in enumerate(raw) if _BULLET.match(ln)), None)
        if first is None or sum(1 for ln in raw if _BULLET.match(ln)) < 2:
            return False
        head = "\n".join(raw[:first]).strip().splitlines()  # a blank line before the bullets is normal
        return bool(head) and all(ln.strip() for ln in head)
    if task == "ci-log-digest":  # at most six lines, and no log line copied
        flat = _norm(fixture.input)
        quoted = any(len(_norm(ln).split()) >= 4 and _norm(ln) in flat for ln in lines)
        return (
            len(lines) <= 6
            and not quoted
            and len(novel_words(fixture, output)) >= CI_MIN_NOVEL
            and causal_near_fact(fixture, output)
        )
    if task == "first-pass-review-comment":  # at most 3 lines; a full sentence names the function and the defect
        if len(lines) > 3 or len(outside_words(fixture, output)) < REVIEW_MIN_WORDS:
            return False
        subject, defect = fixture.facts[0], fixture.facts[1:]
        sentences = [x for x in re.split(r"(?<=[.!?])\s+|\n", output) if len(x.split()) >= 5]

        # the function and the defect class must sit in one sentence, or in two sentences next to each other
        # and the sentence that states the defect carries a verb, so it is a statement and not a label
        def stated(x: str) -> bool:
            return DEFECT_VERB.search(x) is not None and any(_fact_matches(d, x) for d in defect)

        return not denies_defect(defect, output) and any(
            _fact_matches(subject, " ".join(sentences[i : i + 2])) and any(stated(x) for x in sentences[i : i + 2])
            for i in range(len(sentences))
        )
    if task == "doc-skeleton":  # a title heading, then each named section as a heading with a placeholder line
        heads = [_HEADING.match(ln) for ln in lines]
        names = {x.lower() for x in (fixture.sections or tuple(f.text for f in fixture.facts))}

        def clean(m: re.Match[str]) -> str:
            return re.sub(r"^\d+[.)]\s*", "", m.group("text")).rstrip(":. ").lower()

        first_head = heads[0] if heads else None
        if first_head is None or clean(first_head) in names:
            return False
        for name in names:
            idx = next((i for i, m in enumerate(heads) if m is not None and clean(m) == name), None)
            if idx is None or idx + 1 >= len(lines) or heads[idx + 1] is not None:
                return False
        return True
    return True


def score_output(fixture: Fixture, output: str) -> Score:
    missed = [f.text for f in fixture.facts if not _fact_matches(f, output)]
    recall = 1.0 - len(missed) / len(fixture.facts)
    hits = [p for p in fixture.forbidden if re.search(p, output, re.IGNORECASE)]
    fmt, fenced = _format_ok(fixture.required_format, output)
    length = len(output) <= fixture.max_chars
    structure = _structure_ok(fixture, output)
    ratio = copy_ratio(fixture.input, output)
    copied = ratio > COPY_CAP.get(fixture.task, COPY_CAP_DEFAULT)
    bare = fixture.task not in FACTS_ONLY_EXEMPT and facts_only(fixture, output)
    reasons = [
        name
        for name, bad in (
            ("recall", recall < PASS_RECALL),
            ("forbidden", bool(hits)),
            ("format", not fmt),
            ("length", not length),
            ("structure", not structure),
            ("copy", copied),
            ("facts-only", bare),
        )
        if bad
    ]
    return Score(recall, missed, hits, fmt, length, not reasons, fenced, structure, ratio, bare, reasons)


def score_dict(sc: Score) -> dict[str, Any]:
    return {
        "recall": sc.recall,
        "facts_missed": sc.facts_missed,
        "forbidden_hits": sc.forbidden_hits,
        "format_ok": sc.format_ok,
        "length_ok": sc.length_ok,
        "passed": sc.passed,
        "fenced": sc.fenced,
        "structure_ok": sc.structure_ok,
        "copy_ratio": round(sc.copy_ratio, 3),
        "facts_only": sc.facts_only,
        "reasons": sc.reasons,
    }


def build_prompt(fixture: Fixture) -> str:
    return (
        f"{INSTRUCTIONS[fixture.task]}\nKeep the answer under {fixture.max_chars} characters.\n\n"
        f"---\n{fixture.input}\n---"
    )


def _run_cmd(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv list, no shell
        list(argv), stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout, check=False
    )


def _call_stats(call_log: Path, call_id: str) -> tuple[int | None, float | None]:
    try:
        lines = call_log.read_text(encoding="utf-8").splitlines()[-400:]
    except OSError:
        return None, None
    for line in reversed(lines):
        try:
            rec = bounded.loads(line)
        except ValueError:
            continue
        if rec.get("id") == call_id:
            tokens, secs = rec.get("eval_tokens"), rec.get("seconds")
            return (tokens if isinstance(tokens, int) else None, secs if isinstance(secs, int | float) else None)
    return None, None


def run_one(
    fixture: Fixture,
    model: str,
    *,
    wait: int = 120,
    timeout: float = 300.0,
    retries: int = 4,
    backoff: float = 2.0,
    call_log: Path = DEFAULT_CALL_LOG,
    sleep: Callable[[float], None] = time.sleep,
    exe: str = "llm-local",
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, Any]:
    """One bounded llm-local call. Returns a run record with status ok|busy|failed."""
    argv = [exe, "--task", f"eval-{fixture.task}", "--model", model, "--wait", str(wait), "--envelope"]
    argv.append(build_prompt(fixture))
    record: dict[str, Any] = {"fixture": fixture.id, "task": fixture.task, "model": model, "status": "failed"}
    started_at = clock()
    record["ts"] = started_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    record["hour_utc"] = started_at.hour
    started = time.monotonic()
    attempts = 0
    busy_seen = 0
    while True:
        attempts += 1
        try:
            proc = _run_cmd(argv, timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"[:300]
            break
        if proc.returncode == BUSY_EXIT:
            busy_seen += 1
            if attempts > retries:
                record["status"] = "busy"
                break
            sleep(backoff * 2 ** (attempts - 1))
            continue
        if proc.returncode != 0:
            record["error"] = f"exit {proc.returncode}: {proc.stderr.strip()[-300:]}"
            break
        try:
            env = bounded.loads(proc.stdout)
            response = str(env["response"])
        except (ValueError, KeyError, TypeError):
            record["error"] = "unparseable envelope from llm-local"
            break
        record["status"] = "ok"
        record["output"] = response
        record["call_id"] = str(env.get("call_id", ""))
        record["eval_tokens"], record["call_seconds"] = _call_stats(call_log, record["call_id"])
        score = score_output(fixture, response)
        record["score"] = score_dict(score)
        break
    record["attempts"] = attempts
    record["busy_retries"] = busy_seen
    record["latency_s"] = round(time.monotonic() - started, 3)
    return record


def _private_dir(path: Path) -> None:
    """Create a missing directory (and missing parents) with mode 0700; never through a symlink. An existing
    directory is left as it is: the files in it are private either way."""
    if path.is_symlink():
        raise EvalError(f"refusing to use a symlink as an output directory: {path}")
    if path.is_dir():
        return
    if path.exists():
        raise EvalError(f"output path is not a directory: {path}")
    _private_dir(path.parent)
    try:
        os.mkdir(path, 0o700)
        os.chmod(
            path, stat.S_IRWXU
        )  # 0700, owner only; the umask may have narrowed the mode, never widened it; make it exact
    except OSError as exc:
        raise EvalError(f"cannot create {path}: {exc.strerror}") from exc


def _open_private(path: Path) -> IO[str]:
    """Open a result file for writing with mode 0600, truncating, never following a symlink; an existing file is
    chmodded to 0600 too."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise EvalError(f"cannot write {path}: {exc.strerror}") from exc
    try:
        os.fchmod(fd, 0o600)
        return os.fdopen(fd, "w", encoding="utf-8")
    except OSError as exc:
        os.close(fd)
        raise EvalError(f"cannot write {path}: {exc.strerror}") from exc


def _write_private(path: Path, text: str) -> None:
    with _open_private(path) as fh:
        fh.write(text)


def wilson(passed: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95 percent Wilson score interval for a pass rate; (0, 1) when there are no scored runs."""
    if n <= 0:
        return 0.0, 1.0
    p = passed / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def summarize(runs: Sequence[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in runs:
        groups[(r["task"], r["model"])].append(r)
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for key, rs in groups.items():
        ok = [r for r in rs if r["status"] == "ok"]
        failed = sum(1 for r in rs if r["status"] == "failed")
        passed = sum(1 for r in ok if r["score"]["passed"])
        denom = len(ok) + failed  # busy is not an error and not a verdict
        ci_low, ci_high = wilson(passed, denom)
        fenced = sum(1 for r in ok if r["score"].get("fenced"))
        rates = [r["eval_tokens"] / r["call_seconds"] for r in ok if r.get("eval_tokens") and r.get("call_seconds")]
        out[key] = {
            "runs": len(rs),
            "scored": denom,
            "pass_rate": passed / denom if denom else None,
            "ci_low": ci_low,
            "ci_high": ci_high,
            "fenced_share": fenced / len(ok) if ok else None,
            "mean_recall": statistics.fmean(r["score"]["recall"] for r in ok) if ok else None,
            "median_latency": statistics.median(r["latency_s"] for r in ok) if ok else None,
            "tok_per_s": statistics.median(rates) if rates else None,
            "busy": sum(1 for r in rs if r["status"] == "busy"),
            "failed": failed,
            "forbidden_runs": sum(1 for r in ok if r["score"]["forbidden_hits"]),
        }
    return out


def agreement(ok: int, wrong: int, sampled: int | None = None) -> dict[str, Any]:
    """Agreement of the verdicts for one cell: the ok share with its two-sided 95 percent Wilson interval. sampled is
    how many entries the drawn sample holds for the cell (every one of them must be judged); None means the verdicts
    are all there is."""
    n = ok + wrong
    lo, hi = wilson(ok, n, CAL_Z)
    return {
        "verdicts": n,
        "sampled": n if sampled is None else sampled,
        "ok": ok,
        "wrong": wrong,
        "ok_share": ok / n if n else None,
        "ci_low": lo,
        "ci_high": hi,
    }


def _all_judged(cell: dict[str, Any]) -> bool:
    return bool(cell["verdicts"] >= cell.get("sampled", cell["verdicts"]))


def cal_status(cell: dict[str, Any] | None) -> str:
    """none: no verdict yet; partial: fewer than CAL_MIN_VERDICTS, or not every sampled entry of the cell judged;
    failed: all judged, enough verdicts, but the ok share's lower bound is under CAL_MIN_LOWER; done: all judged,
    enough verdicts and the bound clears it."""
    n = cell["verdicts"] if cell else 0
    if cell is None or n == 0:
        return "none"
    if n < CAL_MIN_VERDICTS or not _all_judged(cell):
        return "partial"
    return "done" if cell["ci_low"] >= CAL_MIN_LOWER else "failed"


def cal_label(cell: dict[str, Any] | None) -> str:
    status = cal_status(cell)
    if cell is not None and status == "partial":
        return f"partial ({cell['verdicts']} of {cell.get('sampled', cell['verdicts'])} judged)"
    return status


def calibration_ok(cell: dict[str, Any] | None) -> bool:
    return cell is not None and cal_status(cell) == "done"


def tier_for(
    task_stats: dict[str, dict[str, Any]], calibration: dict[str, dict[str, Any]] | None = None
) -> tuple[str, str]:
    """task_stats maps model -> summary, calibration maps model -> agreement for this task. Returns (tier, reason).
    The pass-rate thresholds apply to the Wilson lower bound; local-only also needs a calibrated cell, so a
    cell that passes the scorer but was never checked by a person can be at best local-then-claude-check."""
    cal = calibration or {}
    rated = {m: s["ci_low"] for m, s in task_stats.items() if s["pass_rate"] is not None}
    if not rated:
        return "claude", "no scored runs"

    def pick(models: list[str]) -> str:  # highest lower bound wins; a tie goes to the smaller model (qwen)
        return max(sorted(models, key=lambda m: (MODEL_TIER.get(m) != "local-qwen", m)), key=lambda m: rated[m])

    def shown(m: str) -> str:
        return f"{m} lower bound {rated[m]:.2f} (pass rate {task_stats[m]['pass_rate']:.2f})"

    qualified = [m for m in rated if rated[m] >= LOCAL_MIN and calibration_ok(cal.get(m))]
    if qualified:
        best = pick(qualified)
        return MODEL_TIER.get(best, f"local-{best}"), f"{shown(best)} >= {LOCAL_MIN}, calibrated"
    best = pick(list(rated))
    rate = rated[best]
    if rate >= LOCAL_MIN:
        cell = cal.get(best)
        if cell is not None and cal_status(cell) == "failed":
            why = f"calibration failed: ok lower bound {cell['ci_low']:.2f} < {CAL_MIN_LOWER}"
        else:
            need = f"needs {CAL_MIN_VERDICTS}+ verdicts and ok lower bound >= {CAL_MIN_LOWER}"
            why = f"calibration {cal_status(cell)}: {need}"
        return "local-then-claude-check", f"{shown(best)} >= {LOCAL_MIN} but {why}"
    if rate >= CHECK_MIN:
        return "local-then-claude-check", f"{shown(best)} in [{CHECK_MIN}, {LOCAL_MIN})"
    return "claude", f"{shown(best)} < {CHECK_MIN}"


def _fmt(value: float | None, spec: str = ".2f") -> str:
    return "n/a" if value is None else format(value, spec)


def hour_of(run: dict[str, Any]) -> int | None:
    """UTC hour a run started in: from hour_utc, else from ts; None for rows recorded before timestamps existed."""
    hour = run.get("hour_utc")
    if isinstance(hour, int) and not isinstance(hour, bool) and 0 <= hour <= 23:  # True is not hour 1
        return hour
    ts = run.get("ts")
    if isinstance(ts, str):
        try:
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").hour
        except ValueError:
            return None
    return None


def _bucket(hour: int | None) -> str:
    if hour is None:
        return "unknown"
    lo = hour // BUCKET_HOURS * BUCKET_HOURS
    return f"{lo:02d}-{lo + BUCKET_HOURS:02d} UTC"


def render_time_buckets(runs: Sequence[dict[str, Any]]) -> list[str]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in runs:
        groups[(r["model"], _bucket(hour_of(r)))].append(r)
    lines = [
        "",
        "## TIME OF DAY (UTC, 4-hour buckets)",
        "",
        f"Per model, all tasks together. A bucket with fewer than {MIN_BUCKET_RUNS} scored runs says too few and "
        "shows no rate: no conclusion about when the server performs best may be drawn from it. Busy retries is the "
        "number of exit-75 answers from llm-local seen in the bucket (queue evidence); rows recorded before "
        "timestamps existed sit in unknown.",
        "",
        "| model | bucket | n | pass rate | median latency s | busy retries |",
        "|---|---|---|---|---|---|",
    ]
    for model, label in sorted(groups, key=lambda k: (k[0], k[1] == "unknown", k[1])):
        rs = groups[(model, label)]
        ok = [r for r in rs if r["status"] == "ok"]
        scored = len(ok) + sum(1 for r in rs if r["status"] == "failed")
        retries = sum(int(r.get("busy_retries", 0)) for r in rs)
        if scored < MIN_BUCKET_RUNS:
            rate, lat = "too few", "too few"
        else:
            rate = _fmt(sum(1 for r in ok if r["score"]["passed"]) / scored)
            lat = _fmt(statistics.median(r["latency_s"] for r in ok), ".1f") if ok else "n/a"
        lines.append(f"| {model} | {label} | {scored} | {rate} | {lat} | {retries} |")
    return lines


def render_report(
    runs: Sequence[dict[str, Any]],
    calibration: dict[tuple[str, str], dict[str, Any]] | None = None,
    calibration_note: str | None = None,
) -> str:
    cals = calibration or {}
    stats = summarize(runs)
    tasks = [t for t in TASKS if any(k[0] == t for k in stats)]
    models = sorted({k[1] for k in stats})
    lines = ["# Local LLM evaluation", "", f"Runs: {len(runs)}. Scoring is code only (see docs/local-eval.md).", ""]
    lines += [
        "| task | model | runs | pass rate | 95% CI | mean recall | fenced | median latency s | tok/s | forbidden "
        "| busy | failed |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for t in tasks:
        for m in models:
            s = stats.get((t, m))
            if s:
                lines.append(
                    f"| {t} | {m} | {s['runs']} | {_fmt(s['pass_rate'])} | "
                    f"[{_fmt(s['ci_low'])}, {_fmt(s['ci_high'])}] | {_fmt(s['mean_recall'])} | "
                    f"{_fmt(s['fenced_share'])} | {_fmt(s['median_latency'], '.1f')} | "
                    f"{_fmt(s['tok_per_s'], '.0f')} | {s['forbidden_runs']} | "
                    f"{s['busy']} | {s['failed']} |"
                )
    lines += [
        "",
        "## ROUTING TABLE",
        "",
        "Rule, applied by code: take the best model for the task by the lower bound of the 95% Wilson interval of its "
        "pass rate (failed runs count as not passed, busy runs are left out), so a cell with few runs cannot qualify "
        "on luck. A fenced share above 0 means the model wrapped its JSON in a code fence: a downstream consumer must "
        f"strip one outer fence too. A run passes when recall >= {PASS_RECALL}, no forbidden string appears, the "
        "format is valid and the length bound holds.",
        f"- lower bound >= {LOCAL_MIN} and calibrated (at least {CAL_MIN_VERDICTS} verdicts, ok-share lower bound >= "
        f"{CAL_MIN_LOWER}): local only (local-qwen or local-gemma, whichever scored higher; ties go to qwen)",
        f"- lower bound >= {LOCAL_MIN} but not calibrated: local-then-claude-check",
        f"- {CHECK_MIN} <= lower bound < {LOCAL_MIN}: local-then-claude-check",
        f"- lower bound < {CHECK_MIN}, or no scored runs: claude",
        "",
        "| task | tier | why |",
        "|---|---|---|",
    ]
    for t in tasks:
        tier, why = tier_for(
            {m: s for (tt, m), s in stats.items() if tt == t}, {m: c for (tt, m), c in cals.items() if tt == t}
        )
        lines.append(f"| {t} | {tier} | {why} |")
    lines += [
        "",
        "## CALIBRATION",
        "",
        f"Per cell: none (no verdict), partial (under {CAL_MIN_VERDICTS} verdicts, or not every sampled entry of the "
        f"cell judged: k of n), failed (all judged, {CAL_MIN_VERDICTS} or more, but "
        f"the ok lower bound is under {CAL_MIN_LOWER}), done (all judged, {CAL_MIN_VERDICTS} or more and the bound "
        "clears it). "
        "Verdicts are human or reviewer ok/wrong calls on passing outputs; the ok share's lower bound is the two-sided "
        "95% Wilson bound. A pass means the facts are present and the shape is right, "
        "not that the answer is meaningful.",
        "",
        *(
            [f"**CALIBRATION IGNORED: {calibration_note}. No cell counts as calibrated.**", ""]
            if calibration_note
            else []
        ),
        "| task | model | status | verdicts | ok share | ok lower bound |",
        "|---|---|---|---|---|---|",
    ]
    for t in tasks:
        for m in models:
            if (t, m) in stats:
                c = cals.get((t, m))
                lines.append(
                    f"| {t} | {m} | {cal_label(c)} | {c['verdicts'] if c else 0} | "
                    f"{_fmt(c['ok_share'] if c else None)} | {_fmt(c['ci_low'] if c else None)} |"
                )
    lines += render_time_buckets(runs)
    return "\n".join(lines) + "\n"


def calibration_sample(runs: Sequence[dict[str, Any]], n: int, seed: int | None = None) -> str:
    ok = [r for r in runs if r["status"] == "ok"]
    picked = random.Random(seed).sample(ok, min(n, len(ok)))  # noqa: S311 - audit sampling, not security
    parts = ["# Calibration sample", "", "Check each verdict by hand against the output and the fixture facts.", ""]
    for i, r in enumerate(picked, 1):
        sc = r["score"]
        parts += [
            f"## {i}. {r['fixture']} ({r['model']})",
            f"Scored: passed={sc['passed']} recall={sc['recall']:.2f} missed={sc['facts_missed']} "
            f"forbidden={sc['forbidden_hits']} format_ok={sc['format_ok']} length_ok={sc['length_ok']}",
            "",
            "```text",
            r["output"].replace("```", "'''"),
            "```",
            "",
        ]
    return "\n".join(parts)


def output_sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def run_id(index: int, run: dict[str, Any]) -> str:
    """A stable id for one run record: its position in the runs file, its timestamp when it has one, its task and
    model, and the hash of its output. The same run has the same id in every draw; a counter would not."""
    raw = json.dumps([index, run.get("ts"), run.get("task"), run.get("model"), output_sha(str(run.get("output", "")))])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def calibration_file(runs: Sequence[dict[str, Any]], n: int, seed: int = 0, runs_sha: str = "") -> dict[str, Any]:
    """The file a person or reviewer fills in: up to n PASSING outputs per (task, model) cell (all of them when
    fewer pass), each with an id derived from the run, the hash of its output and an empty verdict (ok or wrong).
    runs_sha256 is the sha256 of the runs file sampled from; ingest recomputes this same sample from the runs."""
    cells: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    for i, r in enumerate(runs):
        if r["status"] == "ok" and r["score"]["passed"]:
            cells[(r["task"], r["model"])].append((i, r))
    rng = random.Random(seed)  # noqa: S311 - audit sampling, not security
    entries: list[dict[str, Any]] = []
    for task, model in sorted(cells):
        for i, r in rng.sample(cells[(task, model)], min(n, len(cells[(task, model)]))):
            entries.append(
                {
                    "id": run_id(i, r),
                    "task": task,
                    "model": model,
                    "fixture": r["fixture"],
                    "output": r["output"],
                    "output_sha256": output_sha(r["output"]),
                    "verdict": "",
                }
            )
    note = "Set verdict to exactly ok or wrong for each entry you judged; leave the rest empty."
    return {
        "format": CAL_FORMAT,
        "runs_sha256": runs_sha,
        "n": n,
        "seed": seed,
        "instructions": note,
        "entries": entries,
    }


def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


@dataclass
class Ingested:
    """The judged entries of one sample, merged over ingests: id -> (task, model, verdict), the agreement per cell
    (with the number of sampled entries of the cell), the sample's n and seed and the log of replaced verdicts."""

    cells: dict[tuple[str, str], dict[str, Any]]
    verdicts: dict[str, tuple[str, str, str]]
    n: int
    seed: int
    replaced: list[dict[str, str]] = field(default_factory=list)


def _cells_of(
    expected: dict[str, dict[str, Any]], verdicts: dict[str, tuple[str, str, str]]
) -> dict[tuple[str, str], dict[str, Any]]:
    sampled: dict[tuple[str, str], int] = defaultdict(int)
    for e in expected.values():
        sampled[(e["task"], e["model"])] += 1
    counts: dict[tuple[str, str], list[int]] = {k: [0, 0] for k in sampled}
    for task, model, verdict in verdicts.values():
        if (task, model) not in counts:
            raise EvalError("a stored verdict belongs to no sampled cell")
        counts[(task, model)][0 if verdict == "ok" else 1] += 1
    return {k: agreement(v[0], v[1], sampled[k]) for k, v in sorted(counts.items())}


def ingest_full(
    doc: Any,
    runs: Sequence[dict[str, Any]],
    runs_sha: str,
    prior: Ingested | None = None,
    replace: bool = False,
) -> Ingested:
    """Agreement per (task, model) cell from a filled calibration file, bound to the runs it was sampled from. The
    file must name the sha256 of this runs file; the sample is drawn again from the runs with the stored n and seed,
    and every entry must be one of its ids with the same task, model and output hash, else the whole file is
    rejected (the error names a count, never output text). Only the verdicts ok and wrong count; an empty verdict
    is not yet judged; any other value, a duplicate id or an unknown task is an error. A file may omit sampled
    entries: the cell then reads partial (judged k of n) until every sampled entry of it has a verdict. With prior (the
    stored agreement of an earlier ingest of the same sample) the verdicts are merged; a different verdict for an
    id already judged is an error unless replace is set, and each replacement is logged."""
    if not isinstance(doc, dict) or doc.get("format") != CAL_FORMAT or not isinstance(doc.get("entries"), list):
        raise EvalError("not a safo-eval calibration file")
    if doc.get("runs_sha256") != runs_sha:
        raise EvalError("the runs file is not the one this calibration file was sampled from (sha256 differs)")
    n, seed = doc.get("n"), doc.get("seed")
    if not isinstance(n, int) or isinstance(n, bool) or not isinstance(seed, int) or isinstance(seed, bool):
        raise EvalError("calibration file has no valid n and seed")
    if not 1 <= n <= CAL_MAX_N:
        raise EvalError("calibration file has no valid n and seed")
    if prior is not None and (prior.n, prior.seed) != (n, seed):
        raise EvalError(
            "this file is another sample (n or seed differ) than the stored verdicts: start a new directory"
        )
    expected = {e["id"]: e for e in calibration_file(runs, n, seed, runs_sha)["entries"]}
    new: dict[str, tuple[str, str, str]] = {}
    seen: set[str] = set()
    foreign = 0
    for e in doc["entries"]:
        if not isinstance(e, dict):
            raise EvalError("bad calibration entry")
        eid, task, model, verdict = e.get("id"), e.get("task"), e.get("model"), e.get("verdict")
        if not isinstance(eid, str) or not eid or eid in seen:
            raise EvalError("missing or duplicate calibration id")
        seen.add(eid)
        if task not in TASKS or not isinstance(model, str) or not model:
            raise EvalError("bad task or model in a calibration entry")
        if not isinstance(verdict, str) or verdict not in ("", "ok", "wrong"):
            raise EvalError("a calibration verdict must be exactly ok or wrong")
        want = expected.get(eid)
        if want is None:
            foreign += 1  # an id that was never sampled from these runs
            continue
        out = e.get("output")
        same_output = (
            e.get("output_sha256") == want["output_sha256"]
            and isinstance(out, str)
            and output_sha(out) == want["output_sha256"]
        )
        if (task, model) != (want["task"], want["model"]) or not same_output:
            foreign += 1  # a real id with another cell or another output
            continue
        if verdict:
            new[eid] = (task, model, verdict)
    if foreign:
        raise EvalError(
            f"{foreign} of {len(doc['entries'])} calibration entries are not in the sample drawn from this runs file "
            "(id, task, model or output hash differ); the whole file is rejected"
        )
    merged = dict(prior.verdicts) if prior else {}
    replaced = list(prior.replaced) if prior else []
    changed = sorted(i for i, v in new.items() if i in merged and merged[i][2] != v[2])
    if changed and not replace:
        raise EvalError(
            f"{len(changed)} verdicts differ from the ones already stored; pass --replace to change a judged verdict"
        )
    for i in changed:
        replaced.append({"id": i, "from": merged[i][2], "to": new[i][2]})
    merged.update(new)
    return Ingested(_cells_of(expected, merged), merged, n, seed, replaced)


def ingest_verdicts(doc: Any, runs: Sequence[dict[str, Any]], runs_sha: str) -> dict[tuple[str, str], dict[str, Any]]:
    return ingest_full(doc, runs, runs_sha).cells


class CalibrationMismatch(EvalError):
    """An agreement file that does not belong to these runs or was edited: not calibrated, said loudly."""


def _integrity(
    cells: Sequence[tuple[str, str, int, int, int]],
    runs_sha: str,
    verdicts: Sequence[tuple[str, str, str, str]],
    replaced: Sequence[dict[str, str]],
    sample_ref: tuple[int, int],
) -> str:
    """sha256 over the counts, the runs hash, the sample (n, seed), the sorted judged entries and the replacement
    log. No key: it catches a slipped or a careless edit and an agent that writes counts without the sample; the
    owner can always recompute it (docs/local-eval.md)."""
    raw = json.dumps(
        {
            "runs": runs_sha,
            "sample": list(sample_ref),
            "cells": sorted(cells),
            "verdicts": sorted(verdicts),
            "replaced": [[r["id"], r["from"], r["to"]] for r in replaced],
        },
        separators=(",", ":"),
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _cell_tuples(cells: dict[tuple[str, str], dict[str, Any]]) -> list[tuple[str, str, int, int, int]]:
    return [(t, m, c["ok"], c["wrong"], c["sampled"]) for (t, m), c in cells.items()]


def agreement_doc(ing: Ingested, runs_sha: str) -> dict[str, Any]:
    rows = [(i, t, m, v) for i, (t, m, v) in ing.verdicts.items()]
    return {
        "format": CAL_FORMAT + "-agreement",
        "runs_sha256": runs_sha,
        "n": ing.n,
        "seed": ing.seed,
        "cells": [{"task": t, "model": m, **c} for (t, m), c in sorted(ing.cells.items())],
        "verdicts": [{"id": i, "task": t, "model": m, "verdict": v} for i, t, m, v in sorted(rows)],
        "replaced": ing.replaced,
        "integrity": _integrity(_cell_tuples(ing.cells), runs_sha, rows, ing.replaced, (ing.n, ing.seed)),
    }


def load_ingested(doc: Any, runs_sha: str) -> Ingested:
    """Read an agreement file back for this runs file. Only the judged entries are trusted (the counts must match
    them), and only when the file names this runs file and its integrity field matches; else CalibrationMismatch
    (not calibrated)."""
    if not isinstance(doc, dict) or doc.get("format") != CAL_FORMAT + "-agreement":
        raise EvalError("not a safo-eval calibration agreement file")
    if not isinstance(doc.get("cells"), list) or not isinstance(doc.get("verdicts"), list):
        raise EvalError("not a safo-eval calibration agreement file")
    n_raw, seed_raw = doc.get("n"), doc.get("seed")
    if (
        not isinstance(n_raw, int)
        or isinstance(n_raw, bool)
        or not isinstance(seed_raw, int)
        or isinstance(seed_raw, bool)
    ):
        raise EvalError("not a safo-eval calibration agreement file")
    n, seed = n_raw, seed_raw
    cells: dict[tuple[str, str], dict[str, Any]] = {}
    for c in doc["cells"]:
        try:
            ok, wrong, sampled, task, model = c["ok"], c["wrong"], c["sampled"], c["task"], c["model"]
        except (KeyError, TypeError) as exc:
            raise EvalError("bad agreement cell") from exc
        counts_ok = all(_is_int(x) and x >= 0 for x in (ok, wrong, sampled))
        if not counts_ok or task not in TASKS or not isinstance(model, str):
            raise EvalError("bad agreement cell")
        cells[(task, model)] = agreement(ok, wrong, sampled)
    verdicts: dict[str, tuple[str, str, str]] = {}
    for v in doc["verdicts"]:
        try:
            vid, task, model, verdict = v["id"], v["task"], v["model"], v["verdict"]
        except (KeyError, TypeError) as exc:
            raise EvalError("bad agreement verdict") from exc
        if (
            not isinstance(vid, str)
            or task not in TASKS
            or not isinstance(model, str)
            or verdict not in ("ok", "wrong")
        ):
            raise EvalError("bad agreement verdict")
        verdicts[vid] = (task, model, verdict)
    replaced = doc.get("replaced")
    if not isinstance(replaced, list) or not all(
        isinstance(r, dict) and all(isinstance(r.get(k), str) for k in ("id", "from", "to")) for r in replaced
    ):
        raise EvalError("bad agreement replacement log")
    if doc.get("runs_sha256") != runs_sha:
        raise CalibrationMismatch("the agreement file was made from a different runs file (sha256 differs)")
    rows = [(i, t, m, v) for i, (t, m, v) in verdicts.items()]
    recount = _cells_of_counts(verdicts)
    counts_match = len(verdicts) == len(doc["verdicts"]) and all(
        recount.get(k, (0, 0)) == (c["ok"], c["wrong"]) for k, c in cells.items()
    )
    if not counts_match or sum(a + b for a, b in recount.values()) != sum(c["verdicts"] for c in cells.values()):
        raise CalibrationMismatch("the agreement file's integrity field does not match its counts and ids (edited?)")
    if _integrity(_cell_tuples(cells), runs_sha, rows, replaced, (n, seed)) != doc.get("integrity"):
        raise CalibrationMismatch("the agreement file's integrity field does not match its counts and ids (edited?)")
    return Ingested(cells, verdicts, n, seed, [dict(r) for r in replaced])


def _cells_of_counts(verdicts: dict[str, tuple[str, str, str]]) -> dict[tuple[str, str], tuple[int, int]]:
    out: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
    for task, model, verdict in verdicts.values():
        out[(task, model)][0 if verdict == "ok" else 1] += 1
    return {k: (v[0], v[1]) for k, v in out.items()}


def load_agreement(doc: Any, runs_sha: str) -> dict[tuple[str, str], dict[str, Any]]:
    return load_ingested(doc, runs_sha).cells


def _read_private(path: Path, uid: int | None = None) -> str:
    """Read a verdict or agreement file: a regular file we own, readable by the owner only, never through a symlink.
    uid is the expected owner (the current user when None); a test passes another one."""
    owner = os.getuid() if uid is None else uid
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise EvalError(f"cannot read {path}: {exc.strerror}") from exc
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != owner or st.st_mode & 0o077:
            raise EvalError(f"refusing {path}: must be a regular file owned by you with mode 0600 or 0400")
        data = fh.read(CAL_MAX_BYTES + 1)
    if len(data) > CAL_MAX_BYTES:
        raise EvalError(f"{path} is too large")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvalError(f"{path} is not UTF-8") from exc


def _read_json_private(path: Path) -> Any:
    try:
        return bounded.loads(_read_private(path))
    except ValueError as exc:
        raise EvalError(f"{path} is not valid JSON") from exc


def _read_runs_hashed(path: Path) -> tuple[list[dict[str, Any]], str]:
    """The runs and the sha256 of the file's bytes: the calibration is bound to that hash."""
    try:
        raw = path.read_bytes()
        runs = [bounded.loads(ln) for ln in raw.decode("utf-8").splitlines() if ln.strip()]
    except (OSError, ValueError) as exc:
        raise EvalError(f"cannot read runs {path}: {exc}") from exc
    return runs, hashlib.sha256(raw).hexdigest()


def _read_runs(path: Path) -> list[dict[str, Any]]:
    return _read_runs_hashed(path)[0]


def rescore(runs: Sequence[dict[str, Any]], fixtures: Sequence[Fixture]) -> list[dict[str, Any]]:
    """Recompute the score of every ok run from its stored output. No model call."""
    by_id = {f.id: f for f in fixtures}
    out: list[dict[str, Any]] = []
    for r in runs:
        new = dict(r)
        if r["status"] == "ok":
            fx = by_id.get(r["fixture"])
            if fx is None:
                raise EvalError(f"no fixture for {r['fixture']}")
            sc = score_output(fx, r["output"])
            new["score"] = score_dict(sc)
        out.append(new)
    return out


def run_all(
    fixtures: Sequence[Fixture], models: Sequence[str], repeats: int, runs_path: Path, **kw: Any
) -> list[dict[str, Any]]:
    """Strictly one call at a time. Each record is appended to the JSONL as it finishes."""
    runs: list[dict[str, Any]] = []
    _private_dir(runs_path.parent)
    with _open_private(runs_path) as fh:
        for rep in range(1, repeats + 1):
            for model in models:
                for fx in fixtures:
                    rec = run_one(fx, model, **kw)
                    rec["repeat"] = rep
                    runs.append(rec)
                    fh.write(json.dumps(rec) + "\n")
                    fh.flush()
    return runs


def entry(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="safo-eval", description="Evaluate the local LLM and derive a routing table.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--models", required=True)
    r.add_argument("--tasks", default="all")
    r.add_argument("--repeats", type=int, default=3)
    r.add_argument("--out", required=True, type=Path)
    r.add_argument("--fixtures", type=Path, default=FIXTURES_DEFAULT)
    r.add_argument("--calibrate", type=int, default=0)
    r.add_argument("--wait", type=int, default=120)
    rp = sub.add_parser("report")
    rp.add_argument("--runs", required=True, type=Path)
    rp.add_argument("--out", required=True, type=Path)
    rp.add_argument("--rescore", action="store_true", help="re-score stored outputs; writes report-rescored.md")
    rp.add_argument("--fixtures", type=Path, default=FIXTURES_DEFAULT)
    rp.add_argument(
        "--calibration",
        type=Path,
        help="calibration-agreement.json from `calibrate --ingest`; only counts when --runs is the sampled file",
    )
    c = sub.add_parser("calibrate", help="sample passing outputs to check by hand, or ingest the verdicts")
    c.add_argument("--runs", type=Path, help="runs JSONL to sample passing outputs from (also needed with --ingest)")
    c.add_argument("--n", type=int, default=CAL_SAMPLE_DEFAULT, help="outputs per (task, model) cell")
    c.add_argument("--seed", type=int, default=0)
    c.add_argument("--ingest", type=Path, help="a filled calibration.json: store the agreement per cell")
    c.add_argument(
        "--replace", action="store_true", help="with --ingest: allow a different verdict for an id already judged"
    )
    c.add_argument("--out", required=True, type=Path, help="output directory")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "run":
            tasks = None if args.tasks == "all" else [t.strip() for t in args.tasks.split(",")]
            bad = [t for t in tasks or [] if t not in TASKS]
            if bad or args.repeats < 1:
                raise EvalError(f"unknown task {bad} or repeats < 1")
            fixtures = load_fixtures(args.fixtures, tasks)
            models = [m.strip() for m in args.models.split(",") if m.strip()]
            _private_dir(args.out)
            runs = run_all(fixtures, models, args.repeats, args.out / "runs.jsonl", wait=args.wait)
            _write_private(args.out / "report.md", render_report(runs))
            if args.calibrate:
                _write_private(args.out / "calibration.md", calibration_sample(runs, args.calibrate))
            output.write(sys.stdout, f"{len(runs)} runs; report at {args.out / 'report.md'}")
        elif args.cmd == "report":
            _private_dir(args.out)
            runs, runs_sha = _read_runs_hashed(args.runs)
            cals, note = None, None
            if args.calibration:
                try:
                    cals = load_agreement(_read_json_private(args.calibration), runs_sha)
                except CalibrationMismatch as exc:
                    note = str(exc)
                    output.write(sys.stderr, f"safo-eval: WARNING: calibration ignored, no cell is calibrated: {note}")
            if args.rescore:
                runs = rescore(runs, load_fixtures(args.fixtures))
                _write_private(args.out / "runs-rescored.jsonl", "".join(json.dumps(r) + "\n" for r in runs))
                _write_private(args.out / "report-rescored.md", render_report(runs, cals, note))
            else:
                _write_private(args.out / "report.md", render_report(runs, cals, note))
        elif args.ingest:
            if args.runs is None:
                raise EvalError("calibrate --ingest needs --runs: the verdicts are checked against the sampled runs")
            runs, runs_sha = _read_runs_hashed(args.runs)
            filled = _read_json_private(args.ingest)
            stored = args.out / "calibration-agreement.json"
            prior = None
            if stored.exists():
                try:
                    prior = load_ingested(_read_json_private(stored), runs_sha)
                except CalibrationMismatch as exc:
                    if "integrity" in str(exc):
                        raise
                    output.write(
                        sys.stderr, f"safo-eval: stored verdicts are for another runs file and are void: {exc}"
                    )
            ing = ingest_full(filled, runs, runs_sha, prior=prior, replace=args.replace)
            _private_dir(args.out)
            _write_private(stored, json.dumps(agreement_doc(ing, runs_sha), indent=1) + "\n")
        else:
            if args.runs is None or args.n < 1:
                raise EvalError("calibrate needs --runs and --n >= 1, or --ingest")
            runs, runs_sha = _read_runs_hashed(args.runs)
            doc = calibration_file(runs, args.n, args.seed, runs_sha)
            _private_dir(args.out)
            _write_private(args.out / "calibration.json", json.dumps(doc, indent=1) + "\n")
    except EvalError as exc:
        output.write(sys.stderr, f"safo-eval: {exc}")
        return 2
    return 0


def run() -> None:
    sys.exit(entry())


if __name__ == "__main__":
    run()
