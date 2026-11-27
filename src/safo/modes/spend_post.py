# SPDX-License-Identifier: Apache-2.0
"""spend-post: run the weekly spend report and post a short summary to a PRIVATE issue (#538).

The body holds counts, weighted totals and the change since the stored baseline, from fixed labels and numbers only:
no path, user name, host name, title or transcript text. Before anything is posted the target repo must answer
`true` to `gh api repos/OWNER/REPO --jq .private`; any other answer, or a failed lookup, refuses the run (fail closed).
The comment is posted once and never replayed: a failure is reported and the next weekly run starts clean. Nothing here
schedules itself; docs/spend-report.md shows a timer and a cron line for the operator to install.
"""

from __future__ import annotations

import argparse
import re
import socket
import subprocess

from safo.context import LocalContext
from safo.errors import EXIT_OK, ConfigError
from safo.modes import LocalMode, register_local, spend

REPO_SHAPE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}")
ISSUE_SHAPE = re.compile(r"[1-9][0-9]{0,8}")
GH_SECONDS = 60
HEADLINE = (
    ("claude.weighted_total", "Claude weighted total"),
    ("claude.pool.lead.weighted", "lead"),
    ("claude.pool.implementer.weighted", "implementer agents"),
    ("claude.pool.general-purpose.weighted", "general-purpose agents"),
    ("claude.pool.reviewer.weighted", "reviewer agents"),
    ("claude.pool.other.weighted", "other agents"),
    ("claude.lead_turns.weighted_per_turn", "weighted per lead turn"),
    ("claude.per_merged_pr.weighted_per_pr", "weighted per merged PR"),
    ("codex.weighted", "Codex weighted (counted apart)"),
)


def summary(g: spend.Gathered) -> str:
    """The posted text. Built from numbers and the labels above only."""
    r = g.report
    out = [f"# Weekly spend summary, {r['week']}", ""]
    out.append(
        "Measured: token counts, session and file counts. Weighted tokens apply inferred price ratios "
        f"(input x{spend.WEIGHT_INPUT:g}, output x{spend.WEIGHT_OUTPUT:g}, cache read x{spend.WEIGHT_CACHE_READ:g}, "
        f"cache write x{spend.WEIGHT_CACHE_WRITE:g}); they rank patterns and are not dollars."
    )
    c = r.get("claude")
    if c:
        out += ["", "## Counts (measured)", ""]
        out.append(f"- Claude files: {c['lead_files']} lead, {c['agent_files']} agent")
        out.append(f"- Lead turns: {c['lead_turns']['turns']}")
        pr = r.get("per_merged_pr", {})
        if pr.get("given"):
            out.append(f"- Merged PRs: {pr['merged_prs']}")
        out += ["", "## Weighted totals", ""]
        out.append(f"- Claude total: {spend.num(c['weighted_total'])}")
        for name, cell in c["pools"].items():
            out.append(f"- {name}: {spend.num(cell['weighted'])} ({spend.pct(cell['share'])})")
        out.append(
            f"- Agent first-turn instruction and skill share (estimate, {spend.CHARS_PER_TOKEN:g} chars per token): "
            f"{spend.pct(c['agent_first_turn']['median_instruction_and_skill_share'])}"
        )
    x = r.get("codex")
    if x:
        out.append(f"- Codex sessions: {x['sessions']}, weighted {spend.num(x['weighted'])} (counted apart)")
    loc = r.get("local", {}).get("llm_local")
    if loc and "calls" in loc:
        out.append(f"- Real llm-local calls: {loc['calls']}")
    out += ["", "## Change since the stored baseline", ""]
    if g.base is None:
        out.append("- No baseline stored yet; this run starts it." if g.baseline_path else "- No baseline was given.")
    else:
        for key, label in HEADLINE:
            if key in g.now:
                out.append(f"- {label}: {_change(g.now[key], g.base.get(key))}")
    return "\n".join(out) + "\n"


def _change(value: float, was: float | None) -> str:
    if was is None:
        return f"{value:g} (not in the baseline)"
    delta = value - was
    rel = f", {delta / was * 100:+.1f}%" if was else ""
    return f"{value:g} (baseline {was:g}, change {delta:+g}{rel})"


def leak_terms(ctx: LocalContext) -> list[str]:
    terms = {str(ctx.home), ctx.home.name, ctx.env.get("USER", ""), ctx.env.get("LOGNAME", ""), socket.gethostname()}
    return [t.lower() for t in terms if len(t) >= 3]


def refuse_leaks(ctx: LocalContext, body: str) -> None:
    low = body.lower()
    if any(t in low for t in leak_terms(ctx)) or not all(c == "\n" or 32 <= ord(c) < 127 for c in body):
        raise ConfigError(
            "the summary would carry a path, a user or host name or a non-ASCII character; nothing posted"
        )


def gh_call(ctx: LocalContext, gh: str, argv: list[str], what: str, stdin: str | None = None) -> str:
    try:
        done = ctx.run(
            [gh, *argv], capture_output=True, text=True, timeout=GH_SECONDS, check=False, input=stdin, env=dict(ctx.env)
        )
    except (OSError, subprocess.SubprocessError):
        raise ConfigError(f"gh could not be run for {what}") from None
    if done.returncode != 0:
        raise ConfigError(f"gh failed for {what}")
    return str(done.stdout)


def require_private(ctx: LocalContext, gh: str, repo: str) -> None:
    answer = gh_call(ctx, gh, ["api", f"repos/{repo}", "--jq", ".private"], "the visibility check")
    if answer.strip() != "true" or answer.count("\n") > 1:
        raise ConfigError("the target repo is not confirmed private; refusing to post a spend summary there")


def run(ctx: LocalContext, args: argparse.Namespace) -> int:
    if not REPO_SHAPE.fullmatch(args.repo or "") or ".." in args.repo:
        raise ConfigError("--repo must be OWNER/REPO")
    if not ISSUE_SHAPE.fullmatch(args.issue or ""):
        raise ConfigError("--issue must be a positive issue number")
    gh = ctx.which("gh")
    if not gh:
        raise ConfigError("gh was not found on PATH")
    require_private(ctx, gh, args.repo)
    g = spend.gather(ctx, args)
    body = summary(g)
    refuse_leaks(ctx, body)
    if args.dry_run:
        for line in body.splitlines():
            ctx.say(line)
        return EXIT_OK
    gh_call(ctx, gh, ["issue", "comment", args.issue, "--repo", args.repo, "--body-file", "-"], "the comment", body)
    ctx.say(f"posted the {g.report['week']} spend summary to {args.repo}#{args.issue}")
    if spend.write_baseline(g):
        ctx.say("Baseline written; later runs print the change since it.")
    return EXIT_OK


def add_arguments(parser: argparse.ArgumentParser) -> None:
    spend.add_input_arguments(parser)
    parser.set_defaults(json="")  # the posted summary is the output; no report file is written here
    parser.add_argument("--repo", default="", help="OWNER/REPO of a PRIVATE repo (checked live; public is refused)")
    parser.add_argument("--issue", default="", help="the issue number to comment on")
    parser.add_argument("--dry-run", action="store_true", help="print the summary; post nothing and write no baseline")


register_local(
    LocalMode(
        "spend-post",
        "post the weekly spend summary to a private issue (local; refuses a public repo)",
        add_arguments,
        run,
    )
)
