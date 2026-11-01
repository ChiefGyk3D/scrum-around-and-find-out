# SPDX-License-Identifier: Apache-2.0
"""The dispatch guard's Gemini rules (#200): a paid step needs a live approval record and a cap of at most 2.50 USD, and
nothing private goes to the free tier. These rules deny in every guard mode, warn included: the maintainer's rule is
that no record means the guard blocks, not warns.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from agentsdata import agents_with
from geminidata import MODEL, NOW, hard_timeout, pathological
from hooksdata import agents_file, dispatch, hooks, read_log, set_mode
from safo.gemini import Locations
from safo.geminibrief import GEMINI_MATERIAL, GEMINI_PAID, findings
from safo.hooks import RULES, Verdict, check_dispatch, decide

OK = "id-0123456789ab"


def accepts(known: str = OK) -> Callable[[str], str | None]:
    return lambda record: None if record == known else "no such approval record"


def rules(
    prompt: str, check: Callable[[str], str | None] | None = None, terms: tuple[re.Pattern[str], ...] = ()
) -> list[str]:
    return [rule for rule, _ in findings(prompt, check, terms)]


PUBLIC = "gemini-material: public\n"


def test_a_brief_that_names_no_gemini_step_is_untouched() -> None:
    assert rules("Research the CVE. Ask Gemini nothing. paid and image words in prose are not a step.") == []


def test_a_free_step_needs_the_public_material_line() -> None:
    assert rules("gemini: free model=gemini-3.6-flash\n") == [GEMINI_MATERIAL]
    assert rules("gemini: free model=gemini-3.6-flash\n" + PUBLIC) == []


@pytest.mark.parametrize("word", ["private", "sensitive", "internal", ""])
def test_anything_but_public_is_blocked_from_the_free_tier(word: str) -> None:
    assert rules(f"gemini: free\ngemini-material: {word}\n") == [GEMINI_MATERIAL]


def test_a_secret_shape_in_the_brief_blocks_a_gemini_step() -> None:
    for secret in ("AIza" + "B" * 35, "ghp_" + "c" * 36, "-----BEGIN OPENSSH PRIVATE KEY-----", "AKIA" + "D" * 16):
        assert rules(f"gemini: free\n{PUBLIC}context: {secret}\n") == [GEMINI_MATERIAL]


def test_the_makers_private_terms_block_a_gemini_step_without_being_named() -> None:
    terms = (re.compile(r"acme-internal", re.IGNORECASE),)
    found = findings(f"gemini: free\n{PUBLIC}about ACME-Internal tooling\n", None, terms)
    assert [r for r, _ in found] == [GEMINI_MATERIAL]
    assert "acme" not in " ".join(text for _, text in found).lower(), "the matched text is never repeated"


def test_a_paid_step_without_a_record_is_blocked() -> None:
    assert GEMINI_PAID in rules(f"gemini: paid cap=1.50\n{PUBLIC}")
    assert GEMINI_PAID in rules(f"gemini: paid cap=1.50 approval=missing-record-1\n{PUBLIC}", accepts())


def test_a_paid_step_with_a_live_record_and_a_cap_passes() -> None:
    assert rules(f"gemini: paid model={MODEL} cap=1.50 approval={OK}\n{PUBLIC}", accepts()) == []


@pytest.mark.parametrize("cap", ["2.51", "10", "0", "-1", "abc", "nan", "inf", "1e9"])
def test_a_cap_over_the_job_cap_or_unreadable_is_blocked(cap: str) -> None:
    assert GEMINI_PAID in rules(f"gemini: paid cap={cap} approval={OK}\n{PUBLIC}", accepts())


def test_a_cap_of_exactly_the_job_cap_passes() -> None:
    assert rules(f"gemini: paid cap=2.50 approval={OK}\n{PUBLIC}", accepts()) == []


def test_a_paid_step_with_no_cap_is_blocked() -> None:
    assert GEMINI_PAID in rules(f"gemini: paid approval={OK}\n{PUBLIC}", accepts())


def test_the_command_form_is_read_too() -> None:
    cmd = "safo gemini ask --paid --model m --cap 1.5 --approval " + OK
    assert rules(f"run: {cmd}\n{PUBLIC}", accepts()) == []
    assert GEMINI_PAID in rules(f"run: safo gemini ask --paid --model m\n{PUBLIC}", accepts())
    assert GEMINI_PAID in rules(f"run: safo gemini ask --paid --cap 3 --approval {OK}\n{PUBLIC}", accepts())


def test_the_paid_secret_store_config_counts_as_a_paid_step() -> None:
    assert GEMINI_PAID in rules(f"gemini: free\nuse the key in prd_paid\n{PUBLIC}", accepts())


def test_a_record_check_that_fails_blocks_instead_of_allowing() -> None:
    def broken(record: str) -> str | None:
        raise OSError("disk")

    assert GEMINI_PAID in rules(f"gemini: paid cap=1 approval={OK}\n{PUBLIC}", broken)
    assert GEMINI_PAID in rules(f"gemini: paid cap=1 approval={OK}\n{PUBLIC}", None), "no checker means no record"


def test_quotes_are_removed_before_a_declaration_is_read() -> None:
    assert rules(f'gemini: paid cap="1 approval={OK}\n{PUBLIC}', accepts()) == []
    assert GEMINI_PAID in rules(f'gemini: paid cap="3 approval={OK}\n{PUBLIC}', accepts())


def test_the_rule_names_are_registered() -> None:
    assert GEMINI_PAID in RULES and GEMINI_MATERIAL in RULES


def test_check_dispatch_carries_the_gemini_rules() -> None:
    doc = agents_with()
    brief = {"model": "sonnet", "prompt": "issue: TEST-1\ngemini: paid cap=1\n" + PUBLIC}
    verdict = check_dispatch(doc, brief, False, None)
    assert GEMINI_PAID in verdict.rules
    clean = check_dispatch(doc, {"model": "sonnet", "prompt": "issue: TEST-1\nplain work"}, False, None)
    assert GEMINI_PAID not in clean.rules and GEMINI_MATERIAL not in clean.rules


@pytest.mark.parametrize("mode", ["warn", "block"])
def test_a_gemini_violation_denies_even_in_warn_mode(mode: str) -> None:
    verdict = Verdict((GEMINI_PAID,), ("x",), "sonnet", False, False)
    assert decide(verdict, mode) == "deny"
    assert decide(Verdict(("no-model",), ("x",), "", False, False), "warn") == "warn", "other rules keep their mode"


# -- end to end through the hook ----------------------------------------------------------------------------------


def test_the_hook_denies_a_paid_brief_with_no_record_in_warn_mode(_private_home: Path, tmp_path: Path) -> None:
    agents = agents_file(tmp_path / "agents.yaml")
    set_mode(_private_home, "warn")
    brief = f"gemini: paid model={MODEL} cap=1.50 approval={OK}\n{PUBLIC}"
    code, out, _ = hooks("guard", "--agents", str(agents), home=_private_home, stdin=dispatch(prompt=brief))
    assert code == 0
    data = json.loads(out)
    assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "only through the broker" in data["hookSpecificOutput"]["permissionDecisionReason"]
    row = read_log(_private_home)[-1]
    assert row["decision"] == "deny" and GEMINI_PAID in row["rules"]
    assert brief not in json.dumps(row), "the log never holds the brief"


def test_the_hook_denies_a_paid_brief_whatever_record_it_names(
    _private_home: Path, tmp_path: Path, gemini_locations: Locations
) -> None:
    """The in-process approval records are gone (#287): no id, however well formed, makes a paid step pass the hook."""
    agents = agents_file(tmp_path / "agents.yaml")
    _config_with_terms(gemini_locations, tmp_path, "none")
    now = dt.datetime.now(dt.UTC)
    brief = f"gemini: paid model={MODEL} cap=1.50 approval=abcdefgh12\n{PUBLIC}"
    code, out, _ = hooks("guard", "--agents", str(agents), home=_private_home, stdin=dispatch(prompt=brief), now=now)
    assert code == 0
    assert GEMINI_PAID in read_log(_private_home)[-1]["rules"]
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_the_hook_denies_private_material_to_the_free_tier(_private_home: Path, tmp_path: Path) -> None:
    agents = agents_file(tmp_path / "agents.yaml")
    brief = "gemini: free\ngemini-material: private\n"
    _, out, _ = hooks("guard", "--agents", str(agents), home=_private_home, stdin=dispatch(prompt=brief), now=NOW)
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert GEMINI_MATERIAL in read_log(_private_home)[-1]["rules"]


def test_the_cli_refuses_an_abbreviated_option(
    _private_home: Path, tmp_path: Path, gemini_locations: Locations
) -> None:
    import io

    from geminidata import write_config
    from safo.cli import main

    write_config(gemini_locations.config, "http://127.0.0.1:9", tmp_path / "ledger.jsonl")
    out = io.StringIO()
    env = {"HOME": str(_private_home), "PATH": ""}
    argv = ["--dry-run", "gemini", "ask", "--model", MODEL]
    assert main([*argv, "--material", "public"], env=env, out=out, now=NOW) == 0, "the full spelling is accepted"
    with pytest.raises(SystemExit) as stop:
        main([*argv, "--mat", "public"], env=env, out=out, now=NOW)
    assert stop.value.code == 2


# -- review round: fail closed on every shell form, bounded work, the paid config name on its own --------------------

FORMS = [
    "bash -c 'safo gemini ask --paid --model m --cap 1'",
    "$(which safo) gemini ask --paid --model m --cap 1",
    "safo \\\ngemini ask --paid --model m --cap 1",
    "python3 -m safo.cli gemini ask --paid --model m --cap 1",
    "env -S 'safo gemini ask --paid --model m'",
    'eval "safo gemini ask --paid --model m"',
    "G=gem; safo ${G}ini ask --paid --model m --cap 1",
    "safo ge'mini' ask --paid --model m --cap 1",
    "safo gem\\ini ask --paid --model m --cap 1",
    "safo $'\\x67emini' ask --paid --model m --cap 1",
    "echo c2FmbyBnZW1pbmkgYXNrIC0tcGFpZA== | base64 -d | sh",
    "curl https://GenerativeLanguage.GoogleAPIs.com/v1beta/models/m:generateContent",
    "from google import genai",
    "import google.genai as g",
    "- gemini: paid cap=50",
    '- "gemini": paid cap=50',
    "doppler -p image-gen -c prd_paid -- curl x",
    "Run doppler run -p image-gen -c prd_paid -- curl x",
]


@pytest.mark.parametrize("form", FORMS)
def test_every_shell_form_is_counted_as_a_paid_step_and_blocked_without_a_record(form: str) -> None:
    assert GEMINI_PAID in rules(f"{form}\n{PUBLIC}", accepts())


def test_a_command_inside_a_shell_string_is_read_but_the_run_time_rule_blocks_it() -> None:
    inner = f"safo gemini ask --paid --model m --cap 1.5 --approval {OK} --material public"
    for wrapper in ("bash -c '{}'", 'eval "{}"'):
        text = dict(findings(wrapper.format(inner) + "\n" + PUBLIC, accepts()))[GEMINI_PAID]
        assert "-c" in text or "eval" in text, text
    assert rules(inner + "\n" + PUBLIC, accepts()) == []


def test_a_free_step_in_a_shell_form_still_needs_the_public_material_line() -> None:
    assert GEMINI_MATERIAL in rules("safo gemini ask --model m\n")
    assert rules("safo gemini ask --model m\n" + PUBLIC) == []
    assert GEMINI_PAID in rules("bash -c 'safo gemini ask --model m'\n" + PUBLIC), "the -c form is read as unreadable"


def test_the_paid_config_name_is_checked_on_its_own() -> None:
    assert GEMINI_PAID in rules("use doppler -p image-gen -c prd_paid for it", accepts())
    assert rules("no paid config named here, just prose about prd", accepts()) == []


def test_a_list_item_material_line_counts() -> None:
    assert rules("- gemini: free\n- gemini-material: public\n") == []


def _grows_linearly(work: Callable[[int], object], small: int = 2000, big: int = 16_000) -> bool:
    """Compare an 8x larger input to a small one on the same machine, so a slow or busy runner (or a tracing coverage
    run on Python 3.11 and 3.12) cannot fail it, which a fixed seconds bound did: linear work costs about 8x, quadratic
    about 64x."""
    import time

    timings = []
    for size in (small, big):
        started = time.monotonic()
        work(size)
        timings.append(time.monotonic() - started)
    return timings[1] < 24 * timings[0] + 0.25


def _quadratic_briefs(size: int) -> None:
    for brief in ("safo " * size, "safo gemini ask --paid\n" * (size * 3 // 8), "safo " * size + "gemini"):
        found = findings(brief + "\n" + PUBLIC, accepts())
        assert [r for r, _ in found if r == GEMINI_PAID], "blocked"


def test_a_quadratic_brief_is_blocked_fast() -> None:
    assert _grows_linearly(_quadratic_briefs)


def test_the_linear_time_guard_bites_on_quadratic_work() -> None:
    assert not _grows_linearly(lambda size: sum(1 for _ in range(size * size // 8)))


def test_a_past_deadline_fails_closed() -> None:
    import time

    found = findings(f"gemini: free\n{PUBLIC}", accepts(), (), time.monotonic() - 1)
    assert {r for r, _ in found} == {GEMINI_PAID, GEMINI_MATERIAL}


def test_check_dispatch_fails_closed_when_the_check_crashes(monkeypatch: pytest.MonkeyPatch) -> None:
    import safo.hooks as h

    def boom(*a: object, **k: object) -> list[tuple[str, str]]:
        raise RuntimeError("x")

    monkeypatch.setattr(h, "findings", boom)
    verdict = check_dispatch(agents_with(), {"model": "sonnet", "prompt": "issue: TEST-1\nnothing here"}, False, None)
    assert GEMINI_PAID in verdict.rules and GEMINI_MATERIAL in verdict.rules


def test_the_hook_passes_its_deadline_to_the_check(_private_home: Path, tmp_path: Path) -> None:
    agents = agents_file(tmp_path / "agents.yaml")
    brief = "gemini: free\n" + PUBLIC + ("safo gemini ask --paid\n" * 3000)
    _, out, _ = hooks("guard", "--agents", str(agents), home=_private_home, stdin=dispatch(prompt=brief))
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_safo_and_gemini_far_apart_are_not_one_command() -> None:
    assert rules("safo status;" + " word" * 30 + " and then gemini ask --paid\n", accepts()) == [], (
        "an operator between"
    )
    assert GEMINI_PAID in rules("safo status" + " word" * 3 + " gemini ask --paid\n", accepts())
    assert GEMINI_PAID in rules("safo status" + " word" * 30 + " gemini ask --paid\n", accepts()), "no distance cap"


def test_a_brief_with_no_gemini_marker_is_untouched_by_a_past_deadline() -> None:
    import time

    assert findings("issue: TEST-1\nrename a variable\n", accepts(), (), time.monotonic() - 1) == []


# -- second review round -------------------------------------------------------------------------------------------

EXAMPLE_MODELS = sorted(
    yaml.safe_load((Path(__file__).parent.parent / "examples" / "gemini.example.yaml").read_text())["free"]
)


@pytest.mark.parametrize("model", EXAMPLE_MODELS)
def test_a_real_model_id_is_an_argument_not_a_new_command(model: str) -> None:
    assert len(EXAMPLE_MODELS) >= 3
    quota = f"safo gemini quota --model {model}"
    free = f"safo gemini ask --model {model} --material public --prompt-file p.txt"
    paid = f"safo gemini ask --model {model} --paid --job j --cap 1.5 --approval {OK} --material public"
    assert rules(quota + "\n", accepts()) == []
    assert rules(free + "\n" + PUBLIC, accepts()) == []
    assert rules(paid + "\n" + PUBLIC, accepts()) == []
    assert GEMINI_PAID in rules(paid.replace(f"--approval {OK}", "") + "\n" + PUBLIC, accepts())


def test_the_example_models_are_the_ones_the_cli_parser_accepts() -> None:
    from safo.modes.gemini import brief_namespace

    for model in EXAMPLE_MODELS:
        assert brief_namespace(["ask", "--model", model]).model == model


REDIRECTS = [
    "safo gemini ask --model m > out --paid --job j",
    "safo gemini ask --model m < in --paid --job j",
    "safo gemini ask --model m 2>/dev/null --paid --job j",
    "safo gemini ask >out --model m --paid",
    "safo gemini ask --model m >> out --paid --job j",
    "safo gemini ask --model m 2>&1 --paid",
]


@pytest.mark.parametrize("line", REDIRECTS)
def test_a_redirection_inside_a_gemini_command_cannot_hide_an_option(line: str) -> None:
    assert GEMINI_PAID in rules(f"{line}\n{PUBLIC}", accepts())


def test_the_guard_never_reads_a_command_as_freer_than_bash_runs_it(tmp_path: Path) -> None:
    import subprocess

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    record = tmp_path / "argv.txt"
    stub = bin_dir / "safo"
    stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$RECORD"\n')
    stub.chmod(0o755)
    (tmp_path / "in").write_text("")
    lines = [
        *REDIRECTS,
        "safo --dry-run gemini ask --paid --model m",
        "safo gemini ask --model m --paid;",
        "(safo gemini ask --model m --paid)",
        "safo gemini ask --model m --paid && echo done",
        "safo gemini ask --model m --paid | cat",
        "safo gemini ask --model gemini-3.6-flash --paid --job j",
        "safo gemini ask --model m --job j",
        "safo gemini quota --model m",
    ]
    paid_seen = 0
    for line in lines:
        record.unlink(missing_ok=True)
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "RECORD": str(record)}
        subprocess.run(["bash", "-c", line], cwd=tmp_path, env=env, check=False, capture_output=True)  # noqa: S603, S607 - a fixed test command
        assert record.exists(), line
        paid = "--paid" in record.read_text().split()
        paid_seen += paid
        if paid:
            assert GEMINI_PAID in rules(f"{line}\n{PUBLIC}"), line
    assert paid_seen >= 10


HIDDEN = [
    "safo" + " " * 300 + "gemini ask --paid --model m",
    "safo --board " + "x" * 400 + " gemini ask --paid --model m",
    "/usr/bin/s?fo gemini ask --paid --model m",
    "sa[f]o gemini ask --paid --model m",
    "$(command -v s?fo) gemini ask --paid --model m",
    "X=sa; $X''fo gemini ask --paid --model m",
    "eval $(printf '\\x73afo') gemini ask --paid --model m",
    "\uff53\uff41\uff46\uff4f gemini ask --paid --model m",
    "printf 'safo gem%s ask --paid' ini | sh",
    "echo 7361666f2067656d696e69206173 | xxd -r -p | sh",
    "echo c2FmbyBnZW1pbmk= | openssl enc -base64 -d | bash",
    "echo inimeg ofas | rev | sh",
    "/usr/bin/s*o gemini ask --paid --model m",
]


@pytest.mark.parametrize("form", HIDDEN)
def test_a_command_whose_safo_is_hidden_or_far_away_is_still_a_gemini_step(form: str) -> None:
    assert GEMINI_PAID in rules(f"{form}\n{PUBLIC}", accepts())


PROSE = [
    "Edit src/safo/gemini.py and tests/test_gemini*.py to add the check.",
    "## Gemini: the free-only provider for public material",
    "Gemini: free tier only, public material only.",
    "The safo gemini wrapper keeps a ledger.",
    "See tests/test_gemini_guard.py and src/safo/modes/gemini.py for the code.",
    "Gemini is a research provider; ask the maintainer before using it.",
    "Run `safo gemini quota --model gemini-3.6-flash` to see the line.",
]


@pytest.mark.parametrize("text", PROSE)
def test_prose_and_paths_about_the_feature_are_not_steps(text: str) -> None:
    assert rules(text + "\n", accepts()) == []


def test_the_prose_exemptions_do_not_open_a_bypass() -> None:
    assert GEMINI_PAID in rules("/usr/bin/safo gemini ask --paid --model m\n", accepts())
    assert GEMINI_PAID in rules("src/safo/gemini.py then safo gemini ask --paid --model m\n", accepts())
    assert GEMINI_PAID in rules("/usr/bin/s*o gemini ask --paid\n", accepts())
    assert GEMINI_PAID in rules("gemini: paid cap=50\n", accepts())
    assert GEMINI_MATERIAL in rules("gemini: free model=m\n", accepts())


def test_every_block_says_the_line_the_reason_and_how_to_fix_it() -> None:
    found = dict(findings("fine line\nsafo gemini ask --paid --mod m\n" + PUBLIC, accepts()))
    text = found[GEMINI_PAID]
    assert "line 2" in text and "safo gemini ask" in text and "gemini: paid" in text
    material = dict(findings("fine line\ngemini: free\n", accepts()))[GEMINI_MATERIAL]
    assert "gemini-material: public" in material
    long_line = dict(findings("ok\n" + "safo " * 2000 + "\n" + PUBLIC, accepts()))[GEMINI_PAID]
    assert "line 2" in long_line and "shorter" in long_line


def test_the_guard_over_the_repos_own_docs_has_a_small_false_positive_ceiling() -> None:
    """Every paragraph of the docs and README that mentions Gemini. A block is legitimate when the paragraph really
    holds a command, a declaration, the paid config name, the vendor host or an SDK or decode form; any other block is a
    false positive. The ceiling is set where it was measured (zero) so a new false positive shows up."""
    root = Path(__file__).parent.parent
    paragraphs = [
        p
        for f in [root / "README.md", *sorted((root / "docs").glob("*.md"))]
        for p in re.split(r"\n\s*\n", f.read_text(encoding="utf-8"))
        if "gemini" in p.lower()
    ]
    legit = re.compile(
        r"safo gemini (?:ask|approve|paid)|gemini: ?(?:free|paid)|prd_paid|generativelanguage|genai|base64|xxd|openssl",
        re.IGNORECASE,
    )
    assert len(paragraphs) >= 20, "something was collected"
    blocked = [p for p in paragraphs if findings(p, accepts())]
    false_positives = [p for p in blocked if not legit.search(p)]
    assert len(blocked) >= 3, "the guard still bites on real commands in the docs"
    assert len(false_positives) <= FALSE_POSITIVE_CEILING, [p[:80] for p in false_positives]


FALSE_POSITIVE_CEILING = 0


def test_more_than_fifty_commands_fail_closed_on_their_own() -> None:
    line = "safo gemini ask --model m --material public\n"
    assert rules(line * 10 + PUBLIC, accepts()) == []
    assert GEMINI_PAID in rules(line * 60 + PUBLIC, accepts())


# -- one loader for the private terms, safe to run and failing closed ----------------------------------------------


def _config_with_terms(locations: Locations, tmp_path: Path, setting: str) -> None:
    from geminidata import write_config

    write_config(locations.config, "http://127.0.0.1:9", tmp_path / "ledger.jsonl", private_terms=setting)


def denied(data: dict[str, Any]) -> bool:
    return bool(data) and data.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


def _guard(home: Path, tmp_path: Path, brief: str, env: dict[str, str] | None = None) -> dict[str, Any]:
    agents = agents_file(tmp_path / "agents.yaml")
    _, out, _ = hooks("guard", "--agents", str(agents), home=home, stdin=dispatch(prompt=brief), env=env)
    return json.loads(out) if out else {}


def test_the_guard_and_the_wrapper_share_one_terms_loader() -> None:
    import safo.geminibrief as brief

    assert not hasattr(brief, "load_terms")


@hard_timeout(30)
def test_the_guard_denies_a_brief_that_matches_the_private_terms(
    _private_home: Path, tmp_path: Path, gemini_locations: Locations
) -> None:
    _config_with_terms(gemini_locations, tmp_path, "default")
    gemini_locations.terms.write_text("acme-internal\n")
    data = _guard(_private_home, tmp_path, f"gemini: free\n{PUBLIC}about acme-internal things\n")
    assert denied(data)
    assert "acme" not in json.dumps(data).lower()


def test_the_guard_ignores_the_privacy_variable_and_reads_the_fixed_file(
    _private_home: Path, tmp_path: Path, gemini_locations: Locations
) -> None:
    _config_with_terms(gemini_locations, tmp_path, "default")
    gemini_locations.terms.write_text("zzz-never-here\n")
    other = tmp_path / "other-terms.txt"
    other.write_text("acme-internal\n")
    env = {"SAFO_PRIVACY_EXTRA_FILE": str(other), "XDG_CONFIG_HOME": str(tmp_path)}
    data = _guard(_private_home, tmp_path, f"gemini: free\n{PUBLIC}about acme-internal things\n", env)
    assert data == {} or "permissionDecision" not in json.dumps(data), "the variable is not honored"


@pytest.mark.parametrize(
    "bad",
    [
        "(unclosed\n",
        pathological("nested_y") + "\n",
        pathological("alternation_y") + "\n",
        ".*secret\n",
        "x" * 300 + "\n",
        "(a)\\1\n",
    ],
)
@hard_timeout(30)
def test_a_bad_or_dangerous_terms_file_makes_the_guard_deny_quickly(
    _private_home: Path, tmp_path: Path, gemini_locations: Locations, bad: str
) -> None:
    import time

    _config_with_terms(gemini_locations, tmp_path, "default")
    gemini_locations.terms.write_text("fine-term\n" + bad)
    started = time.monotonic()
    data = _guard(_private_home, tmp_path, f"gemini: free\n{PUBLIC}" + "a" * 200 + "\n")
    assert time.monotonic() - started < 3
    assert denied(data)


def test_the_guard_denies_when_the_terms_file_is_missing_and_not_opted_out(
    _private_home: Path, tmp_path: Path, gemini_locations: Locations
) -> None:
    _config_with_terms(gemini_locations, tmp_path, "default")
    data = _guard(_private_home, tmp_path, f"gemini: free\n{PUBLIC}")
    assert denied(data)
    _config_with_terms(gemini_locations, tmp_path, "none")
    assert not denied(_guard(_private_home, tmp_path, f"gemini: free\n{PUBLIC}"))


def test_a_brief_with_no_gemini_step_never_reads_the_terms(
    _private_home: Path, tmp_path: Path, gemini_locations: Locations
) -> None:
    assert not gemini_locations.config.exists() and not gemini_locations.terms.exists()
    assert not denied(_guard(_private_home, tmp_path, "rename a variable\n"))


def test_the_markdown_and_link_exemptions_do_not_hide_a_command() -> None:
    assert GEMINI_PAID in rules("`safo gemini ask --paid --model m`\n", accepts())
    assert GEMINI_PAID in rules("[x](y) /usr/bin/s?fo gemini ask --paid --model m\n", accepts())
    assert GEMINI_PAID in rules("safo gemini ask --model m `cmd`\n", accepts())
    assert GEMINI_PAID in rules("`runner` $(command -v s?fo) gemini ask --model m\n", accepts())
    assert rules("Use `safo gemini quota --model gemini-3.6-flash` and read [the page](gemini.md).\n", accepts()) == []


def test_a_redirection_or_expansion_in_an_argument_the_parser_would_accept_is_still_unreadable() -> None:
    from safo.geminibrief import _command_step

    for value in ("a>b", "$X", "`x`", "a*b"):
        step = _command_step(["ask", "--model", value], 7)
        assert step is not None and step.unreadable and step.line == 7, value
    plain = _command_step(["ask", "--model", "gemini-3.6-flash"], 7)
    assert plain is not None and not plain.unreadable and not plain.paid


def test_a_wild_character_far_from_any_gemini_or_safo_token_is_not_a_command() -> None:
    far = "use gemini and then ask; " + "word " * 30 + "$HOME is where it lives"
    assert rules(far + "\n", accepts()) == []
    near = "use gemini and then ask $HOME is where it lives"
    assert GEMINI_PAID in rules(near + "\n", accepts())


# -- the prefilter is derived from the detectors -----------------------------------------------------------------------


def test_the_sdk_spelled_generativeai_is_a_gemini_step() -> None:
    for text in ("import generativeai\n", "pip install google-generativeai\n", "from google import generativeai\n"):
        assert GEMINI_PAID in rules(text + PUBLIC, accepts()), text


PREFILTER_TRIGGERS = {
    "safo": "run safo status",
    "gemini": "ask gemini",
    "paid config": "doppler -c prd_paid",
    "vendor host": "curl https://generativelanguage.googleapis.com/x",
    "sdk": "import generativeai",
    "decode": "printf '\\x41' | sh",
    "conceal": "$'\\x73afo' ask --paid",
    "broker module": "python3 -m safo.broker.client",
}


def test_every_detector_trigger_passes_the_prefilter() -> None:
    from safo import geminibrief as gb

    assert set(PREFILTER_TRIGGERS) == {name for name, _ in gb.PREFILTER}, "a trigger string for every detector"
    for name, pattern in gb.PREFILTER:
        sample = PREFILTER_TRIGGERS[name]
        assert pattern.search(gb.normalized(sample)) or pattern.search(sample.lower()), name
        assert gb.relevant(sample), name
    assert not gb.relevant("rename a variable and review the diff\n")


def test_no_detector_pattern_is_missing_from_the_prefilter() -> None:
    """Every compiled pattern in the module is either a prefilter entry or named here as not a detector, so a new
    detector regex cannot be added without a prefilter entry (or a deliberate line in this list)."""
    from safo import geminibrief as gb

    not_detectors = {
        "DECLARATION", "MATERIAL", "KEYVALUE", "MARKDOWN_LINK", "MARKDOWN_CODE", "MARKDOWN_WORD", "PATHLIKE", "SINK_RE",
        "RUNTIME_FORMS",  # gated by the safo detector, which the prefilter already covers
        # the cross-line reader: run only on a brief the prefilter already passed, and acts only with safo and gemini
        "_ASSIGNED", "_PRINTF_NAME", "_LOOP_NAME", "_READ_NAME", "_REFERENCE", "_ANSI_ESCAPE", "_FUNCTION",
        "_RISK_TOKEN", "_PAID_TOKEN", "_GEMINI_WORD", "_SHELL_C", "_ASSIGNMENT_WORD", "_DOLLAR", "_BACKTICK_CMD",
        "_COMMAND_START", "_GEMINI_OPTION", "_RISK_OPTION", "_RISK_FLAG",
        "RECORD_ID",
        # the Bash command check (#209) is its own scan of a shell command, not a brief detector
        "_SHELL_KEY", "_SHELL_PROJECT", "_SHELL_CONFIG", "_SECRET_TOOL", "_NETWORK_TOOL",
        # the broker client module reader (#299): gated by the "broker module" prefilter word or a risk line
        "_BM_ENTRY", "_BM_SCRIPT", "_BM_LOCAL", "_BM_IMPORT", "_BM_CODE", "_BM_DOTTED", "_BM_PATH", "_BM_RUNTIME",
        "_BM_FEED", "_BM_MFLAG", "_BM_OPTION", "_BM_PY_RE", "_BM_ANY_M", "_BM_DYNAMIC",
    }  # fmt: skip
    in_prefilter = {id(p) for _, p in gb.PREFILTER}
    compiled = {n: v for n, v in vars(gb).items() if isinstance(v, re.Pattern)}
    assert len(compiled) >= 10, "something was collected"
    missing = [n for n, v in compiled.items() if id(v) not in in_prefilter and n not in not_detectors]
    assert missing == []


def test_a_prefilter_miss_would_be_caught() -> None:
    from safo import geminibrief as gb

    assert gb.relevant("see the generativeai package") and not gb.relevant("nothing about it")


def test_a_decode_form_that_needs_its_backslash_passes_the_prefilter_and_is_blocked() -> None:
    brief = "printf '\\x73\\x61' | sh\n"
    assert GEMINI_PAID in rules(brief + PUBLIC, accepts())


# -- the prefilter and the scan share one normalization -------------------------------------------------------------


def fullwidth(text: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in text)


def split_quote(text: str) -> str:
    return text[:2] + "'" + text[2:4] + "'" + text[4:]


def split_backslash(text: str) -> str:
    return text[:3] + "\\" + text[3:]


def split_continuation(text: str) -> str:
    return text[:4] + "\\\n" + text[4:]


TRANSFORMS: dict[str, Callable[[str], str]] = {
    "none": lambda t: t,
    "fullwidth": fullwidth,
    "quote split": split_quote,
    "backslash split": split_backslash,
    "continuation": split_continuation,
    "markdown code": lambda t: f"`{t}`",
    "markdown link": lambda t: f"see [a](b) then {t}",
    "link between words": lambda t: t.replace(" ", " [a](b) "),
    "code between words": lambda t: t.replace(" ", " `safo x` "),
}
STEP_TRIGGERS = [
    "gemini: paid cap=50",
    "safo gemini ask --paid --model m",
    "doppler -c prd_paid -- x",
    "curl https://generativelanguage.googleapis.com/x",
    "import generativeai",
    "echo x | base64 -d | sh",
    "printf '\\x41' | sh",
]


def test_the_prefilter_is_never_narrower_than_the_full_scan() -> None:
    """Whatever a transform does to a trigger, if the full scan (without the prefilter) flags it, the prefilter says
    relevant. Removing a transform from the shared helper makes a flagged case irrelevant and this test red."""
    from safo import geminibrief as gb

    flagged_by: dict[str, int] = dict.fromkeys(TRANSFORMS, 0)
    for name, transform in TRANSFORMS.items():
        for trigger in STEP_TRIGGERS:
            text = transform(trigger) + "\n"  # no public-material line: it names Gemini and would mask a miss
            if gb._findings(text, accepts(), (), None):
                flagged_by[name] += 1
                assert gb.relevant(text), (name, trigger)
                assert gb.findings(text, accepts()), (name, trigger)
    assert all(count >= 3 for count in flagged_by.values()), flagged_by


@pytest.mark.parametrize("name", ["fullwidth", "quote split", "backslash split", "continuation"])
def test_a_trigger_that_exists_only_after_a_transform_is_found(name: str) -> None:
    text = TRANSFORMS[name]("gemini: paid cap=50") + "\n"
    assert GEMINI_PAID in rules(text, accepts()), name


def test_a_pattern_that_matches_only_after_a_markdown_link_is_removed_is_found() -> None:
    from safo import geminibrief as gb

    for text in ("from google import [a](b) genai\n", "from google import [a](b) [c](d) generativeai\n"):
        assert gb._findings(text + PUBLIC, accepts(), (), None), text
        assert gb.relevant(text), text
        assert GEMINI_PAID in rules(text + PUBLIC, accepts()), text


# -- third review round ---------------------------------------------------------------------------------------------


@hard_timeout(30)
def test_each_term_sees_a_bounded_chunk_of_text() -> None:
    from typing import cast

    from safo.termsearch import TERMS_CHUNK, hit

    seen: list[int] = []

    class Spy:
        def search(self, text: str, pos: int = 0, endpos: int | None = None) -> None:
            seen.append((len(text) if endpos is None else endpos) - pos)

    assert not hit(cast("tuple[re.Pattern[str], ...]", (Spy(),)), ["x" * 20_000])
    assert seen and max(seen) <= TERMS_CHUNK and len(seen) >= 5


SLOW = [
    "(a?){26}a{26}",
    "[a-z]{0,99}[a-z]{0,99}[a-z]{0,99}[a-z]{0,99}[a-z]{0,99}!",
    ".{0,99}.{0,99}.{0,99}z",
    "(ab?){2}",
]


@pytest.mark.parametrize("term", SLOW)
@hard_timeout(30)
def test_slow_term_shapes_are_refused_at_load_with_the_line_number(term: str, tmp_path: Path) -> None:
    from safo.gemini import load_private_terms

    path = tmp_path / "t.txt"
    path.write_text(f"fine\n{term}\n")
    with pytest.raises(Exception, match=r"line 2"):
        load_private_terms(str(path))


@hard_timeout(30)
def test_a_plausible_term_loads_and_runs_fast(tmp_path: Path) -> None:
    import time

    from safo.gemini import load_private_terms, private_term_hit

    path = tmp_path / "t.txt"
    path.write_text("foo.{0,50}bar.{0,50}baz\nacme-internal\n")
    terms = load_private_terms(str(path))
    started = time.monotonic()
    assert private_term_hit(terms, ["x foo 12 bar 34 baz y" + "z" * 20_000], 5.0)
    assert not private_term_hit(terms, ["nothing here " * 2000], 5.0)
    assert time.monotonic() - started < 3


@hard_timeout(30)
def test_one_search_cannot_pass_the_deadline() -> None:
    import re
    import time

    from safo.gemini import RefusedError, private_term_hit

    evil = re.compile(pathological("nested"))  # built here, past the loader, to prove the worker is killable
    started = time.monotonic()
    with pytest.raises(RefusedError, match="private terms"):
        private_term_hit((evil,), ["a" * 40 + "!"], 1.0)
    assert time.monotonic() - started < 4


@hard_timeout(30)
def test_the_guard_denies_a_term_check_that_runs_out_of_time(monkeypatch: pytest.MonkeyPatch) -> None:
    import re
    import time

    monkeypatch.setattr("safo.geminibrief.TERMS_MIN_SECONDS", 0.5)
    started = time.monotonic()
    found = findings(
        "gemini: free\n" + PUBLIC + "a" * 40 + "!\n",
        accepts(),
        (re.compile(pathological("nested")),),
        time.monotonic() + 1.5,
    )
    assert time.monotonic() - started < 5
    assert GEMINI_MATERIAL in {r for r, _ in found}


@pytest.mark.parametrize("term", ["x{0,5}", "^", "(?:)", r"\b", "a?"])
@hard_timeout(30)
def test_a_term_that_can_match_nothing_is_refused_with_the_line_number(term: str, tmp_path: Path) -> None:
    from safo.gemini import load_private_terms

    path = tmp_path / "t.txt"
    path.write_text(f"fine\n{term}\n")
    with pytest.raises(Exception, match=r"line 2"):
        load_private_terms(str(path))


QUOTING = [
    'safo gemini ask --model m --material "a;b" --paid',
    "safo gemini ask --model m --material 'a|b' --paid",
    'safo --board "a b c d e f g h i j k l" gemini ask --paid --model m',
    "safo gemini ask '>' --paid --model m",
]


@pytest.mark.parametrize("line", QUOTING)
def test_quoting_cannot_hide_an_option_or_stretch_the_window(line: str) -> None:
    assert GEMINI_PAID in rules(f"{line}\n{PUBLIC}", accepts()), line


def test_a_quoted_operator_is_named_in_the_message() -> None:
    text = dict(findings('safo gemini ask --model m --material "a;b"\n' + PUBLIC, accepts()))[GEMINI_PAID]
    assert "';'" in text and "quote" in text


LINKS = [
    "[safo](x) gemini ask --paid --model m",
    "safo [gemini](x) ask --paid --model m",
    "safo gemini [ask](x) --model m [--paid](x)",
]


@pytest.mark.parametrize("line", LINKS)
def test_a_link_is_replaced_by_its_text_not_deleted(line: str) -> None:
    assert GEMINI_PAID in rules(f"{line}\n{PUBLIC}", accepts()), line


LOOKALIKES = [
    "sa\u200bfo gemini ask --paid --model m",
    "safo ge\u0301mini ask --paid --model m",
    "safo gem\U000e0067ini ask --paid --model m",
    "sa\x00fo gemini ask --paid --model m",
    "safo gemini\ufe0f ask --paid --model m",
    "\u0455afo gemini ask --paid --model m",
    "safo gem\u0456ni ask --paid --model m",
    "safo gemini \u0430sk --paid --model m",
    "safo gemini ask --pa\u0456d --model m",
    "safo gemini approve\u200d --model m",
]


@pytest.mark.parametrize("line", LOOKALIKES)
def test_invisible_and_lookalike_characters_do_not_hide_a_command(line: str) -> None:
    assert GEMINI_PAID in rules(f"{line}\n{PUBLIC}", accepts()), repr(line)


def test_private_terms_are_matched_on_the_folded_text_too() -> None:
    import re

    terms = (re.compile("acme-internal", re.IGNORECASE),)
    for disguised in ("\u0430cme-internal", "ac\u200bme-internal", "ACME\uff0dinternal"):
        found = findings(f"gemini: free\n{PUBLIC}{disguised}\n", accepts(), terms)
        assert GEMINI_MATERIAL in {r for r, _ in found}, repr(disguised)


def test_the_wrapper_folds_the_prompt_before_the_private_terms(tmp_path: Path) -> None:
    from safo.gemini import fold

    assert fold("\u0430cme\u200b-internal") == "acme-internal"


RUNTIME = [
    'CMD="gemini ask"\nsafo $CMD --paid --model m',
    "G=gemini\nA=ask\nsafo $G $A --paid",
    "safo ${x:-gemini} ask --paid",
    'run() { safo "$@"; }\nrun gemini ask --paid',
    "echo 'gemini ask --paid' | xargs safo",
    'python3 -c \'from safo.cli import main; main(["gemini","ask","--paid"])\'',
    "eval safo gemini ask --paid",
]


@pytest.mark.parametrize("brief", RUNTIME)
def test_named_run_time_forms_across_lines_are_unreadable(brief: str) -> None:
    assert GEMINI_PAID in rules(f"{brief}\n{PUBLIC}", accepts()), brief


def test_the_run_time_rule_needs_gemini_and_an_action_in_the_brief() -> None:
    assert rules("safo audit -c board.yaml and eval $X\n", accepts()) == []


def test_trailing_punctuation_is_not_part_of_a_word() -> None:
    from safo.geminibrief import _core

    assert _core("gemini?") == "gemini" and _core("safo.") == "safo" and _core("ask!") == "ask"
    assert rules("Is it gemini? Try safo gemini quota --model m?\n", accepts()) == []


def test_a_quota_or_approve_mention_needs_no_public_material_line() -> None:
    assert GEMINI_MATERIAL not in rules("safo gemini approve --model m --max-usd 1\n", accepts())
    assert rules("safo gemini quota --model m\n", accepts()) == []
    assert GEMINI_MATERIAL in rules("safo gemini ask --model m\n", accepts())


def test_a_redirect_outside_or_after_the_command_is_not_a_problem() -> None:
    ok = "safo gemini ask --model m --material public"
    assert rules(f"{ok} 2>&1\n{PUBLIC}", accepts()) == []
    assert rules(f"{ok} > out.txt\n{PUBLIC}", accepts()) == []
    assert rules(f"{ok} && echo done > log\n{PUBLIC}", accepts()) == []
    assert GEMINI_PAID in rules("safo gemini ask --model m > out --paid\n" + PUBLIC, accepts())


def test_a_star_in_a_gemini_word_is_not_a_path() -> None:
    assert GEMINI_PAID in rules("safo gemini* ask --paid --model m\n" + PUBLIC, accepts())


def test_an_unreadable_step_says_which_form_made_it_so() -> None:
    cases = {
        "safo gemini ask --model $M --paid\n": "'$'",
        "safo gemini ask --pai --model m\n": "option",
        "safo gemini ask 'x\n": "quote",
    }
    for text, word in cases.items():
        why = dict(findings(text + PUBLIC, accepts()))[GEMINI_PAID]
        assert word in why, (text, why)


# (brief, blocked): realistic briefs, with the expected outcome stated for each
FIXTURE = [
    ("Summarize the changelog of tool X. Ask the maintainer if unsure.", False),
    ("Run safo audit --board board.yaml and report drift.", False),
    ("See docs/gemini.md and src/safo/gemini.py for how the wrapper works.", False),
    ("Edit tests/test_gemini_guard.py to add a case for the quota line.", False),
    ("The Gemini free tier is for public material only.", False),
    ("Use `safo gemini quota --model gemini-3.6-flash` first.", False),
    ("safo gemini quota --model gemini-3.6-flash 2>&1 | tee quota.txt", False),
    (f"safo gemini ask --model gemini-3.6-flash --material public --prompt-file p.txt\n{PUBLIC}", False),
    (f"gemini: free model=gemini-3.6-flash\n{PUBLIC}", False),
    (f"gemini: paid model=gemini-3.6-flash cap=1.5 approval={OK}\n{PUBLIC}", False),
    ("safo gemini ask --model gemini-3.6-flash --material public --prompt-file p.txt\n", True),
    (f"safo gemini ask --model gemini-3.6-flash --paid --job j --cap 1.5\n{PUBLIC}", True),
    (f"bash -c 'safo gemini ask --paid --model m --cap 1'\n{PUBLIC}", True),
    (f"curl -H x https://generativelanguage.googleapis.com/v1beta\n{PUBLIC}", True),
    (f"doppler run -p image-gen -c prd_paid -- ./job.sh\n{PUBLIC}", True),
    (f"- gemini: paid cap=50\n{PUBLIC}", True),
    (f'safo gemini ask --model m --material "a;b" --paid\n{PUBLIC}', True),
    (f"[safo](x) gemini ask --paid --model m\n{PUBLIC}", True),
]


@pytest.mark.parametrize(("brief", "blocked"), FIXTURE, ids=range(len(FIXTURE)))
def test_the_realistic_brief_fixture(brief: str, blocked: bool) -> None:
    assert len(FIXTURE) == 18
    assert bool(rules(brief, accepts())) is blocked, brief


# -- residual forms, lexer differential, link targets ---------------------------------------------------------------


def test_xargs_and_alias_forms_without_the_action_in_the_span_are_unreadable() -> None:
    assert GEMINI_PAID in rules("echo ask --paid | xargs safo gemini\n" + PUBLIC, accepts())
    assert GEMINI_PAID in rules("alias g='safo gemini'\ng ask --paid --model m\n" + PUBLIC, accepts())
    assert rules("alias ll='ls -l'\n", accepts()) == []


LEXER = [
    "safo gemini ask --model m --material \"a\"';' --paid",
    "safo gemini ask --model m x';'y --paid",
    "safo gemini ask --model m --material 'a' --paid",
    'safo gemini ask --model m --material "a b" --paid',
    "safo gemini ask --model m --material a\;b --paid",
    'safo gemini ask --model m "a"; --paid',
    "safo gemini ask --model m 'a'| cat --paid",
    "safo gemini ask --model m --material 'it'\"'\"'s' --paid",
    "safo gemini ask --model m && echo --paid",
]


@pytest.mark.parametrize("line", LEXER)
def test_the_guard_never_reads_a_quoted_form_freer_than_bash_runs_it(line: str, tmp_path: Path) -> None:
    import subprocess

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    record = tmp_path / "argv.txt"
    stub = bin_dir / "safo"
    stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$RECORD"\n')
    stub.chmod(0o755)
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "RECORD": str(record)}
    subprocess.run(["bash", "-c", line], cwd=tmp_path, env=env, check=False, capture_output=True)  # noqa: S603, S607 - a fixed test command
    paid = record.exists() and "--paid" in record.read_text().split("\n")
    if paid:
        assert GEMINI_PAID in rules(f"{line}\n{PUBLIC}"), line


GLUED = [
    "safo gemini ask --model m --material \"a\"';' --paid",
    "safo gemini ask --model m x';'y --paid",
    'safo gemini ask --model m "a"; --paid',
    "safo gemini ask --model m 'a'| cat --paid",
    "safo gemini ask --model m ge'mini' --paid",
]


@pytest.mark.parametrize("line", GLUED)
def test_a_word_with_a_quote_inside_or_an_operator_glued_to_a_quote_is_unreadable(line: str) -> None:
    assert GEMINI_PAID in rules(f"{line}\n{PUBLIC}", accepts()), line


def test_ordinary_quoting_still_reads_as_the_shell_does() -> None:
    ok = f"safo gemini ask --model m --material \"public\" --prompt-file 'p.txt' --paid --cap 1.5 --approval {OK}"
    assert rules(ok + "\n" + PUBLIC, accepts()) == []
    assert rules("safo gemini ask --model m --material 'public' && echo done\n" + PUBLIC, accepts()) == []


@pytest.mark.parametrize(
    "link",
    [
        "[docs](https://generativelanguage.googleapis.com/v1beta/models)",
        "[x](https://GenerativeLanguage.GoogleAPIs.com/v1)",
        "[sdk](https://pypi.org/project/google-generativeai)",
        "[sdk](https://pypi.org/project/google-genai)",
    ],
)
def test_a_vendor_host_or_sdk_in_a_link_target_is_still_seen(link: str) -> None:
    from safo import geminibrief as gb

    assert gb.relevant(link), link
    assert GEMINI_MATERIAL in rules(f"see {link}\n", accepts())


def test_a_link_to_the_vendor_docs_page_is_a_mention_not_a_call() -> None:
    assert rules("Prices are at [the pricing page](https://ai.google.dev/gemini-api/docs/pricing).\n", accepts()) == []


def test_quote_forms_that_would_otherwise_pass_a_complete_command_are_unreadable() -> None:
    full = f"--model m --material public --paid --cap 1 --approval {OK}"
    assert rules(f"safo gemini ask {full}\n{PUBLIC}", accepts()) == [], "the plain command passes"
    assert GEMINI_PAID in rules(f"safo ge'mini' ask {full}\n{PUBLIC}", accepts()), "a quote inside the gemini word"
    assert GEMINI_PAID in rules(
        f"safo gemini ask --model m --material 'pu'blic --paid --cap 1 --approval {OK}\n{PUBLIC}", accepts()
    )
    glued = f"safo gemini ask --model m --paid --cap 1 --approval {OK} --material 'public'; echo done"
    assert GEMINI_PAID in rules(f"{glued}\n{PUBLIC}", accepts()), "an operator touching a quoted word"
    spaced = glued.replace("'public';", "'public' ;")
    assert rules(f"{spaced}\n{PUBLIC}", accepts()) == [], "the same command with a space before the operator"
    assert GEMINI_PAID in rules(f"sa'f'o gemini ask {full}\n{PUBLIC}", accepts()), "a quote inside the safo word"


# -- round four ------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("count", [11, 12, 13, 30, 200])
def test_the_distance_from_safo_to_gemini_is_not_capped(count: int) -> None:
    flags = "safo " + "--dry-run " * count + "gemini ask --paid --model m"
    pairs = "safo " + "--board X " * count + "gemini ask --paid --model m"
    for line in (flags, pairs):
        assert GEMINI_PAID in rules(line + "\n" + PUBLIC, accepts()), (count, line[:40])
    ok = "safo " + "--dry-run " * count + f"gemini ask --model m --material public --paid --cap 1 --approval {OK}"
    assert rules(ok + "\n" + PUBLIC, accepts()) == [], "a complete command with many flags still passes"


def test_the_named_forms_use_the_same_segment_rule() -> None:
    assert GEMINI_PAID in rules("safo " + "--dry-run " * 30 + "$X gemini ask\n", accepts())
    assert GEMINI_PAID in rules("gemini " + "word " * 30 + "safo $X ask\n", accepts())


def test_fold_maps_uppercase_and_small_cap_confusables_to_latin() -> None:
    from safo.gemini import fold

    cases = {
        "\u0421harles": "Charles",
        "\u0405AFO GEMINI ASK": "SAFO GEMINI ASK",
        "\u0391\u0392\u0395\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7": "ABEHIKMNOPTYX",
        "\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425": "ABEKMHOPCTX",
        "\u0251": "a",
        "\ua731\u1d00\ua730\u1d0f": "safo",
        "\u04bb\u051b\u051d\u04cf\u0443": "hqwly",
        "\u0585\u057d\u0578\u0581": "oung",
    }
    for raw, want in cases.items():
        assert fold(raw) == want, (raw, fold(raw), want)
    assert fold("\u0585\u057d") == "ou"


def test_fold_drops_invisible_letters_and_symbols() -> None:
    from safo.gemini import fold

    for char in ("\u3164", "\u115f", "\u1160", "\uffa0", "\u2800"):
        assert fold(f"sa{char}fo") == "safo", hex(ord(char))


def test_uppercase_confusables_and_fillers_do_not_hide_a_command() -> None:
    for line in (
        "\u0405AFO gemini ask --paid --model m",
        "safo GEMINI ask --paid --model m".replace("GEMINI", "G\u0415MINI"),
        "sa\u3164fo gemini ask --paid --model m",
        "safo gemini ask --paid --model m\u2800",
        "\ua731\u1d00\ua730\u1d0f gemini ask --paid --model m",
    ):
        assert GEMINI_PAID in rules(line + "\n" + PUBLIC, accepts()), repr(line)


CATASTROPHIC = [
    "a?" * 26 + "a" * 26 + "b",
    "(?:a|a)" * 30 + "b",
    "(ab|cd)" * 12 + "c",
    ".{1,99}.{1,99}secret",
    r"\w{1,50}\s{1,50}x",
    r"\S{1,9}\S{1,9}z",
]


@pytest.mark.parametrize("term", CATASTROPHIC)
@hard_timeout(30)
def test_sequences_of_optionals_alternations_and_wildcards_are_refused(term: str, tmp_path: Path) -> None:
    from safo.gemini import load_private_terms

    path = tmp_path / "t.txt"
    path.write_text(f"fine\n{term}\n")
    with pytest.raises(Exception, match=r"line 2"):
        load_private_terms(str(path))


@hard_timeout(30)
def test_a_few_optionals_and_alternations_and_separated_wildcards_still_load(tmp_path: Path) -> None:
    from safo.gemini import load_private_terms

    path = tmp_path / "t.txt"
    path.write_text("colou?r\n(foo|bar)baz\nfoo.{0,50}bar.{0,50}baz\nproject [a-z]{1,30}\n")
    assert len(load_private_terms(str(path))) == 4


@hard_timeout(60)
def test_a_worker_with_no_parent_dies_by_itself_after_its_cpu_limit() -> None:
    import subprocess
    import sys
    import time

    import safo.termsearch as ts

    payload = "0\t" + pathological("nested") + "\n\n" + "a" * 40 + "!"
    worker = subprocess.Popen(  # noqa: S603 - this interpreter and the worker file, no shell
        [sys.executable, "-I", ts.__file__, "1"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        assert worker.stdin is not None
        worker.stdin.write(payload.encode())
        worker.stdin.close()
        started = time.monotonic()
        code = worker.wait(timeout=20)  # nobody kills it: its own CPU limit and alarm do
        assert code != 0 and time.monotonic() - started < 15, code
    finally:
        worker.kill()
        worker.wait()


def test_the_worker_is_found_by_path_and_needs_no_install(tmp_path: Path) -> None:
    import subprocess
    import sys

    import safo.termsearch as ts

    done = subprocess.run(  # noqa: S603 - this interpreter and the worker file, no shell
        [sys.executable, "-I", "-S", ts.__file__, "5"],
        input="0\tacme-internal\n\nsome acme-internal text",
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env={},
        timeout=20,
        check=False,
    )
    assert done.returncode == 0 and done.stdout.strip() == "1", done


def test_private_term_hit_runs_the_worker_by_file_path(monkeypatch: pytest.MonkeyPatch) -> None:
    import re
    import subprocess

    from safo import gemini

    seen: list[list[str]] = []
    real = subprocess.run

    def spy(argv: list[str], **kwargs: Any) -> Any:
        seen.append(argv)
        return real(argv, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    assert gemini.private_term_hit((re.compile("zz"),), ["a zz b"], 5.0)
    assert seen and "-I" in seen[0] and "-m" not in seen[0] and seen[0][2].endswith("termsearch.py")


def test_an_option_far_after_a_pipe_is_not_an_option_of_the_command() -> None:
    line = "safo gemini ask --model m --prompt-file p | tee --append out"
    assert rules(line + "\n" + PUBLIC, accepts()) == []
    assert GEMINI_PAID in rules('safo gemini ask --model m "a"; --paid\n' + PUBLIC, accepts())


def test_a_digit_argument_is_popped_only_when_it_touches_the_redirection() -> None:
    ok = "safo gemini ask --model m --material public --max-output-tokens 1"
    assert rules(f"{ok} > out\n{PUBLIC}", accepts()) == []
    assert rules(f"{ok} >out\n{PUBLIC}", accepts()) == []
    assert rules(f"{ok.replace('--max-output-tokens 1', '')} 2>&1\n{PUBLIC}", accepts()) == []


# -- round four, review pins ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("term", "message"),
    [
        ("(a|aa){1,50}y", "alternation inside a repeat"),
        ("a+b", "unbounded repeat"),
        ("(?:\\b){0,5}foo", "repeat of something that can match nothing"),
        ("(a{1,3}){1,3}", "repeat inside a repeat"),
        ("(a)\\1", "back reference"),
        ("x{0,5}", "match the empty string"),
        ("(ab|cd)" * 12 + "c", "too many optional parts"),
        (".{1,9}.{1,9}z", "two wildcard repeats"),
    ],
)
@hard_timeout(30)
def test_each_loader_rule_has_its_own_message(term: str, message: str, tmp_path: Path) -> None:
    from safo.gemini import RefusedError, load_private_terms

    path = tmp_path / "t.txt"
    path.write_text(f"{term}\n")
    with pytest.raises(RefusedError, match=message):
        load_private_terms(str(path))


def _run_returning(monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: str) -> None:
    import subprocess

    def fake(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, returncode, stdout, "")

    monkeypatch.setattr(subprocess, "run", fake)


@pytest.mark.parametrize(("returncode", "stdout"), [(1, ""), (0, "7"), (0, "")])
def test_a_crashed_or_garbled_worker_is_a_denial(returncode: int, stdout: str, monkeypatch: pytest.MonkeyPatch) -> None:
    import re

    from safo.gemini import TermsCheckError, private_term_hit

    _run_returning(monkeypatch, returncode, stdout)
    with pytest.raises(TermsCheckError):
        private_term_hit((re.compile("x"),), ["y"], 5.0)


def test_a_worker_that_cannot_start_is_a_denial(monkeypatch: pytest.MonkeyPatch) -> None:
    import re
    import sys

    from safo.gemini import TermsCheckError, private_term_hit

    monkeypatch.setattr(sys, "executable", "/nonexistent/python")
    with pytest.raises(TermsCheckError):
        private_term_hit((re.compile("x"),), ["y"], 5.0)


def test_the_guard_denies_when_the_worker_crashes(monkeypatch: pytest.MonkeyPatch) -> None:
    import re

    _run_returning(monkeypatch, 1, "")
    found = findings(f"gemini: free\n{PUBLIC}", accepts(), (re.compile("x"),))
    assert GEMINI_MATERIAL in {r for r, _ in found}


def test_a_paid_config_name_in_a_link_target_is_seen() -> None:
    assert GEMINI_PAID in rules("see [the config](prd_paid) for it\n", accepts())


def test_a_decode_form_that_exists_only_in_a_link_target_is_seen() -> None:
    assert GEMINI_PAID in rules("echo c2FmbyBnZW1pbmk= [x](rev) | sh\n", accepts())


def test_a_precomposed_accent_is_folded_for_the_terms() -> None:
    import re

    from safo.gemini import fold

    assert fold("acm\u00e9-internal") == "acme-internal"
    terms = (re.compile("acme-internal", re.IGNORECASE),)
    assert GEMINI_MATERIAL in {r for r, _ in findings(f"gemini: free\n{PUBLIC}acm\u00e9-internal\n", accepts(), terms)}


def test_a_lone_surrogate_is_a_clean_denial() -> None:
    import re

    from safo.gemini import TermsCheckError, has_secret_shape, private_term_hit

    with pytest.raises(TermsCheckError):
        private_term_hit((re.compile("foo"),), ["x \ud800 foo"], 5.0)
    assert not has_secret_shape("x \ud800 foo")
    found = findings(f"gemini: free\n{PUBLIC}x \ud800 foo\n", accepts(), (re.compile("foo"),))
    assert GEMINI_MATERIAL in {r for r, _ in found}


def test_a_redirection_between_safo_and_gemini_does_not_end_the_command() -> None:
    assert GEMINI_PAID in rules("safo > out gemini ask --paid --model m\n" + PUBLIC, accepts())
    assert GEMINI_PAID in rules("safo 2>/dev/null gemini ask --paid --model m\n" + PUBLIC, accepts())
    assert GEMINI_PAID in rules("$(which safo) gemini ask --paid --model m\n" + PUBLIC, accepts())


@hard_timeout(60)
def test_the_worker_dies_with_its_parent() -> None:
    import os
    import signal
    import subprocess
    import sys
    import time

    import safo.termsearch as ts

    if not sys.platform.startswith("linux"):
        pytest.skip("PR_SET_PDEATHSIG is Linux only")
    spawner = (
        "import subprocess, sys, time\n"
        f"w = subprocess.Popen([sys.executable, '-I', {ts.__file__!r}, '100'], stdin=subprocess.PIPE)\n"
        f"w.stdin.write(b'0\\t{pathological('nested')}\\n\\n' + b'a' * 40 + b'!')\n"
        "w.stdin.close()\n"
        "print(w.pid, flush=True)\n"
        "time.sleep(60)\n"
    )
    parent = subprocess.Popen([sys.executable, "-c", spawner], stdout=subprocess.PIPE, text=True)  # noqa: S603 - this interpreter, a fixed script
    pid = 0
    try:
        assert parent.stdout is not None
        pid = int(parent.stdout.readline())
        time.sleep(0.5)
        os.kill(parent.pid, signal.SIGKILL)
        parent.wait()
        deadline = time.monotonic() + 8
        alive = True
        while alive and time.monotonic() < deadline:
            try:
                state = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0]  # noqa: SIM115
                alive = state != "Z"
            except (FileNotFoundError, ProcessLookupError):
                alive = False
            time.sleep(0.2)
        assert not alive, "the worker outlived its parent"
    finally:
        if pid:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
        parent.kill()


def test_the_hook_blocks_every_paid_step_and_the_broker_commands_but_not_the_free_tier(
    _private_home: Path, tmp_path: Path, gemini_locations: Locations
) -> None:
    agents = agents_file(tmp_path / "agents.yaml")
    _config_with_terms(gemini_locations, tmp_path, "none")
    now = dt.datetime.now(dt.UTC)
    for brief in (
        f"gemini: paid model={MODEL} cap=1.50 approval=abcdefgh12\n{PUBLIC}",
        f"gemini: paid model={MODEL}\n{PUBLIC}",
        f"safo gemini ask --model {MODEL} --paid --job j --cap 1.5 --approval abcdefgh12 --material public\n{PUBLIC}",
        f"safo gemini paid --model {MODEL} --job j --prompt-file p.txt --max-usd 1\n{PUBLIC}",
        f"safo gemini paid-dryrun --prompt-file p.txt\n{PUBLIC}",
    ):
        _, out, _ = hooks("guard", "--agents", str(agents), home=_private_home, stdin=dispatch(prompt=brief), now=now)
        data = json.loads(out)
        assert data["hookSpecificOutput"]["permissionDecision"] == "deny", brief
        assert "only through the broker" in data["hookSpecificOutput"]["permissionDecisionReason"]
    free = f"gemini: free\n{PUBLIC}"
    _, out, _ = hooks("guard", "--agents", str(agents), home=_private_home, stdin=dispatch(prompt=free), now=now)
    assert "deny" not in out


# -- the oversized-event scan holds at least what the brief scan blocks -----------------------------------------------

BLOCKED_SAMPLES = {
    "safo": "safo gemini ask --paid --model m\n",
    "gemini": "safo gemini ask --paid --model m\n",
    "paid config": "doppler -c prd_paid\n",
    "vendor host": "curl https://generativelanguage.googleapis.com/x\n",
    "sdk": "import generativeai\n",
    "decode": "printf '\\x41' | sh\n",
    "conceal": "$'\\x73afo' $'\\x67emini' $'\\x61sk' $'\\x2d\\x2dpaid'\n",
    "broker module": "python3 -I -m safo.broker.client --model m --job j\n",
    "variable flow": "A=safo\nB=gemini\n$A $B ask --paid\n",
    "risk option beside an expansion command": "$X $Y ask --paid\n",
    "a wrapper with options": "env -u FOO $BIN $SUB ask --paid --model m\n",
    "an option built by braces": "$BIN $SUB ask --{p,un}aid --model m\n",
    "printf -v without escapes": "printf -v A %s%s sa fo\nprintf -v B %s%s gem ini\n$A $B ask now\n",
    "printf -v flow": "printf -v A '\\x73afo'\n$A gemini ask --paid\n",
}


def parity_gaps(prefilter: list[tuple[str, re.Pattern[str]]]) -> list[str]:
    """Detectors with no sample here, and samples the brief scan blocks that the event scan does not."""
    import time

    from safo.modes.hooks import EventScan

    gaps = [name for name, _ in prefilter if name not in BLOCKED_SAMPLES]
    for name, sample in BLOCKED_SAMPLES.items():
        assert findings(sample + PUBLIC, accepts(), ()), f"{name}: the brief scan blocks its own sample"
        scan = EventScan(time.monotonic() + 5)
        scan.feed(sample.encode())
        if not scan.hit:
            gaps.append(name)
    return gaps


def test_the_event_scan_denies_whatever_the_brief_scan_blocks() -> None:
    from safo import geminibrief as gb

    assert len(BLOCKED_SAMPLES) >= 13, "something was collected"
    assert parity_gaps(list(gb.PREFILTER)) == []
    assert parity_gaps([*gb.PREFILTER, ("a new detector", re.compile("x"))]) == ["a new detector"], "the check bites"


WIDER_SAMPLES = {
    "inside JSON": '{"tool_input": {"prompt": "$X $Y ask --paid --model m"}}',
    "a bash -c string": 'bash -c "$BIN $SUB ask --paid --model m"\n',
    "an expansion far from the option": "echo $HOME\n" + "word " * 50 + "\napprove it\n",
}


def test_the_event_scan_is_wider_than_the_brief_scan_where_it_has_no_lines() -> None:
    import time

    from safo.modes.hooks import EventScan

    for name, sample in WIDER_SAMPLES.items():
        scan = EventScan(time.monotonic() + 5)
        scan.feed(sample.encode())
        assert scan.hit, name
    quiet = EventScan(time.monotonic() + 5)
    quiet.feed(b"approve it, and echo hi\n")
    assert not quiet.hit, "a risk word with no expansion anywhere is not a marker"


# -- term search chunking hardening (#207) ----------------------------------------------------------------------------


def test_a_term_straddling_a_chunk_boundary_is_found() -> None:
    import re

    from safo.termsearch import TERMS_CHUNK, hit

    step = TERMS_CHUNK - 200
    term = re.compile("a{150}b{40}")  # 190 wide: it fits the overlap
    for offset in range(0, 200, 7):
        text = "x" * (step - 100 + offset) + "a" * 150 + "b" * 40 + "x" * 5000
        assert hit((term,), [text]), offset


def test_a_term_wider_than_the_overlap_is_still_found_by_the_worker() -> None:
    import re

    from safo.termsearch import TERMS_CHUNK, hit

    wide = re.compile("a{99}b{99}cccc")  # 202 wide, built past the loader
    start = TERMS_CHUNK - 200 - 1  # ends one character past the first chunk and starts before the second
    text = "x" * start + "a" * 99 + "b" * 99 + "cccc" + "x" * 9000
    assert hit((wide,), [text])


@pytest.mark.parametrize("term", ["a{99}b{99}cccc", "(?=q{99}r{99}ssss)x", "z{99}www(?<=" + "y" * 99 + ")"])
def test_a_term_wider_than_the_overlap_is_refused_at_load(term: str, tmp_path: Path) -> None:
    from safo.gemini import load_private_terms

    path = tmp_path / "t.txt"
    path.write_text(f"fine\n{term}\n")
    with pytest.raises(Exception, match=r"too wide.*line 2"):
        load_private_terms(str(path))


def test_an_unbounded_term_is_still_refused_at_load(tmp_path: Path) -> None:
    from safo.gemini import load_private_terms

    for term in (".*", "ab+c", "x{2,}"):
        path = tmp_path / "t.txt"
        path.write_text(f"{term}\n")
        with pytest.raises(Exception, match=r"line 1"):
            load_private_terms(str(path))


def test_an_anchored_term_at_the_width_limit_is_found_across_a_boundary() -> None:
    import re

    from safo.termsearch import TERMS_CHUNK, TERMS_OVERLAP, hit

    term = re.compile(r"\Ba{99}b{99}cc\B")  # 200 wide; each anchor needs one character past a chunk edge
    start = TERMS_CHUNK - TERMS_OVERLAP
    text = "x" * start + "a" * 99 + "b" * 99 + "cc" + "x" * 3000
    assert term.search(text)
    assert hit((term,), [text])


@pytest.mark.parametrize("term", [r"\Ba{99}b{99}cc\B", r"^a{99}b{99}cc$", r"\ba{99}b{99}cc\b"])
def test_an_anchored_term_at_the_width_limit_is_refused_at_load(term: str, tmp_path: Path) -> None:
    from safo.gemini import load_private_terms

    path = tmp_path / "t.txt"
    path.write_text(f"{term}\n")
    with pytest.raises(Exception, match=r"too wide.*line 1"):
        load_private_terms(str(path))


def test_an_end_anchor_means_the_end_of_the_text_not_of_a_chunk() -> None:
    import re

    from safo.termsearch import TERMS_CHUNK, hit

    term = re.compile("secret$")
    text = "x" * (TERMS_CHUNK - 6) + "secret" + "not-the-end"  # ends the first chunk, not the text
    assert not term.search(text)
    assert not hit((term,), [text])
    assert hit((term,), [text[:TERMS_CHUNK]]) is True  # it does end this text
    assert not hit((re.compile(r"\Asecret"),), ["x" * (TERMS_CHUNK - 200) + "secret" + "y" * 500])
    assert hit((re.compile(r"\Asecret"),), ["secret" + "y" * 9000])
