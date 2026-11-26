# SPDX-License-Identifier: Apache-2.0
"""safo-eval: score the local LLM against synthetic work items with ground truth, and derive a routing table (#484).

    safo-eval run --models qwen3.5:4b,gemma4:12b --tasks all --repeats 3 --out DIR [--calibrate N]
    safo-eval report --runs DIR/runs.jsonl --out DIR [--rescore]
    safo-eval calibrate --runs DIR/runs.jsonl --n 10 --out FILE

Scoring is code only (fact recall, forbidden hits, format, length); no model ever grades a model. Calls go through
`llm-local`, one at a time, stdin always /dev/null. Exit 75 (queue busy) is retried with backoff and then recorded as
busy, never as an error. Any other failure is recorded and counted, never hidden.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import re
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
    "the form type: subject (type is feat, fix, docs, refactor, test or chore), a blank line, then a short body.",
    "first-pass-review-comment": "Review the small diff below. Find the single planted defect and write one review "
    "comment that names the defect and the line or function it is in.",
    "doc-skeleton": "Write a Markdown documentation skeleton for the topic below: a title, then one heading per "
    "section asked for, each with a one-line placeholder. Use the section names given.",
}

PASS_RECALL = 0.8
LOCAL_MIN = 0.9  # best model pass rate at or above this: local only
CHECK_MIN = 0.6  # at or above this but below LOCAL_MIN: local draft, Claude checks
MODEL_TIER = {"qwen3.5:4b": "local-qwen", "gemma4:12b": "local-gemma"}
DEFAULT_CALL_LOG = Path.home() / ".local/share/llm-local/calls.jsonl"
BUSY_EXIT = 75
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


@dataclass
class Score:
    recall: float
    facts_missed: list[str]
    forbidden_hits: list[str]
    format_ok: bool
    length_ok: bool
    passed: bool = field(default=False)
    fenced: bool = False  # one outer code fence was stripped before the json check


def load_fixture(path: Path) -> Fixture:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
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


def _fact_matches(fact: Fact, output: str) -> bool:
    if fact.text.lower() in output.lower():
        return True
    return any(re.search(v, output, re.IGNORECASE) for v in fact.variants)


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
            data = json.loads(body.strip())
        except ValueError:
            return False, fenced
        return (isinstance(data, dict) if spec == "json-object" else True), fenced
    if spec.startswith("regex:"):
        return re.search(spec[len("regex:") :], output, re.DOTALL) is not None, False
    raise EvalError(f"unknown required_format {spec!r}")


def score_output(fixture: Fixture, output: str) -> Score:
    missed = [f.text for f in fixture.facts if not _fact_matches(f, output)]
    recall = 1.0 - len(missed) / len(fixture.facts)
    hits = [p for p in fixture.forbidden if re.search(p, output, re.IGNORECASE)]
    fmt, fenced = _format_ok(fixture.required_format, output)
    length = len(output) <= fixture.max_chars
    passed = recall >= PASS_RECALL and not hits and fmt and length
    return Score(recall, missed, hits, fmt, length, passed, fenced)


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
            rec = json.loads(line)
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
) -> dict[str, Any]:
    """One bounded llm-local call. Returns a run record with status ok|busy|failed."""
    argv = [exe, "--task", f"eval-{fixture.task}", "--model", model, "--wait", str(wait), "--envelope"]
    argv.append(build_prompt(fixture))
    record: dict[str, Any] = {"fixture": fixture.id, "task": fixture.task, "model": model, "status": "failed"}
    started = time.monotonic()
    attempts = 0
    while True:
        attempts += 1
        try:
            proc = _run_cmd(argv, timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"[:300]
            break
        if proc.returncode == BUSY_EXIT:
            if attempts > retries:
                record["status"] = "busy"
                break
            sleep(backoff * 2 ** (attempts - 1))
            continue
        if proc.returncode != 0:
            record["error"] = f"exit {proc.returncode}: {proc.stderr.strip()[-300:]}"
            break
        try:
            env = json.loads(proc.stdout)
            response = str(env["response"])
        except (ValueError, KeyError, TypeError):
            record["error"] = "unparseable envelope from llm-local"
            break
        record["status"] = "ok"
        record["output"] = response
        record["call_id"] = str(env.get("call_id", ""))
        record["eval_tokens"], record["call_seconds"] = _call_stats(call_log, record["call_id"])
        score = score_output(fixture, response)
        record["score"] = {
            "recall": score.recall,
            "facts_missed": score.facts_missed,
            "forbidden_hits": score.forbidden_hits,
            "format_ok": score.format_ok,
            "length_ok": score.length_ok,
            "passed": score.passed,
            "fenced": score.fenced,
        }
        break
    record["attempts"] = attempts
    record["latency_s"] = round(time.monotonic() - started, 3)
    return record


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


def tier_for(task_stats: dict[str, dict[str, Any]]) -> tuple[str, str]:
    """task_stats maps model -> summary. Returns (tier, reason); thresholds apply to the Wilson lower bound."""
    rated = {m: s["ci_low"] for m, s in task_stats.items() if s["pass_rate"] is not None}
    if not rated:
        return "claude", "no scored runs"
    # highest pass rate wins; a tie goes to the smaller model (qwen) by sort order
    best = max(sorted(rated, key=lambda m: (MODEL_TIER.get(m) != "local-qwen", m)), key=lambda m: rated[m])
    rate = rated[best]
    shown = f"{best} lower bound {rate:.2f} (pass rate {task_stats[best]['pass_rate']:.2f})"
    if rate >= LOCAL_MIN:
        return MODEL_TIER.get(best, f"local-{best}"), f"{shown} >= {LOCAL_MIN}"
    if rate >= CHECK_MIN:
        return "local-then-claude-check", f"{shown} in [{CHECK_MIN}, {LOCAL_MIN})"
    return "claude", f"{shown} < {CHECK_MIN}"


def _fmt(value: float | None, spec: str = ".2f") -> str:
    return "n/a" if value is None else format(value, spec)


def render_report(runs: Sequence[dict[str, Any]]) -> str:
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
        f"- lower bound >= {LOCAL_MIN}: local only (local-qwen or local-gemma, whichever scored higher; ties go to "
        "qwen)",
        f"- {CHECK_MIN} <= lower bound < {LOCAL_MIN}: local-then-claude-check",
        f"- lower bound < {CHECK_MIN}, or no scored runs: claude",
        "",
        "| task | tier | why |",
        "|---|---|---|",
    ]
    for t in tasks:
        tier, why = tier_for({m: s for (tt, m), s in stats.items() if tt == t})
        lines.append(f"| {t} | {tier} | {why} |")
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


def _read_runs(path: Path) -> list[dict[str, Any]]:
    try:
        return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except (OSError, ValueError) as exc:
        raise EvalError(f"cannot read runs {path}: {exc}") from exc


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
            new["score"] = {
                "recall": sc.recall,
                "facts_missed": sc.facts_missed,
                "forbidden_hits": sc.forbidden_hits,
                "format_ok": sc.format_ok,
                "length_ok": sc.length_ok,
                "passed": sc.passed,
                "fenced": sc.fenced,
            }
        out.append(new)
    return out


def run_all(
    fixtures: Sequence[Fixture], models: Sequence[str], repeats: int, runs_path: Path, **kw: Any
) -> list[dict[str, Any]]:
    """Strictly one call at a time. Each record is appended to the JSONL as it finishes."""
    runs: list[dict[str, Any]] = []
    runs_path.parent.mkdir(parents=True, exist_ok=True)
    with runs_path.open("w", encoding="utf-8") as fh:
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
    c = sub.add_parser("calibrate")
    c.add_argument("--runs", required=True, type=Path)
    c.add_argument("--n", required=True, type=int)
    c.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "run":
            tasks = None if args.tasks == "all" else [t.strip() for t in args.tasks.split(",")]
            bad = [t for t in tasks or [] if t not in TASKS]
            if bad or args.repeats < 1:
                raise EvalError(f"unknown task {bad} or repeats < 1")
            fixtures = load_fixtures(args.fixtures, tasks)
            models = [m.strip() for m in args.models.split(",") if m.strip()]
            args.out.mkdir(parents=True, exist_ok=True)
            runs = run_all(fixtures, models, args.repeats, args.out / "runs.jsonl", wait=args.wait)
            (args.out / "report.md").write_text(render_report(runs), encoding="utf-8")
            if args.calibrate:
                (args.out / "calibration.md").write_text(calibration_sample(runs, args.calibrate), encoding="utf-8")
            print(f"{len(runs)} runs; report at {args.out / 'report.md'}")
        elif args.cmd == "report":
            args.out.mkdir(parents=True, exist_ok=True)
            runs = _read_runs(args.runs)
            if args.rescore:
                runs = rescore(runs, load_fixtures(args.fixtures))
                (args.out / "runs-rescored.jsonl").write_text(
                    "".join(json.dumps(r) + "\n" for r in runs), encoding="utf-8"
                )
                (args.out / "report-rescored.md").write_text(render_report(runs), encoding="utf-8")
            else:
                (args.out / "report.md").write_text(render_report(runs), encoding="utf-8")
        else:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(calibration_sample(_read_runs(args.runs), args.n), encoding="utf-8")
    except EvalError as exc:
        print(f"safo-eval: {exc}", file=sys.stderr)
        return 2
    return 0


def run() -> None:
    sys.exit(entry())


if __name__ == "__main__":
    run()
