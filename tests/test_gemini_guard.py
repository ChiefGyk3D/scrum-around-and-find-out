# SPDX-License-Identifier: Apache-2.0
"""The dispatch guard's Gemini rules (#200): a paid step needs a live approval record and a cap of at most 2 USD, and
nothing private goes to the free tier. These rules deny in every guard mode, warn included: the maintainer's rule is
that no record means the guard blocks, not warns.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from collections.abc import Callable
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
import yaml

from agentsdata import agents_with
from geminidata import MODEL, NOW
from hooksdata import agents_file, dispatch, hooks, read_log, set_mode
from safo.gemini import ApprovalStore, Locations, approval_problem
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


@pytest.mark.parametrize("cap", ["2.01", "10", "0", "-1", "abc", "nan", "inf", "1e9"])
def test_a_cap_over_two_dollars_or_unreadable_is_blocked(cap: str) -> None:
    assert GEMINI_PAID in rules(f"gemini: paid cap={cap} approval={OK}\n{PUBLIC}", accepts())


def test_a_cap_of_exactly_two_dollars_passes() -> None:
    assert rules(f"gemini: paid cap=2.00 approval={OK}\n{PUBLIC}", accepts()) == []


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
    assert "approval record" in data["hookSpecificOutput"]["permissionDecisionReason"]
    row = read_log(_private_home)[-1]
    assert row["decision"] == "deny" and GEMINI_PAID in row["rules"]
    assert brief not in json.dumps(row), "the log never holds the brief"


def test_the_hook_allows_a_paid_brief_whose_record_is_live(
    _private_home: Path, tmp_path: Path, gemini_locations: Locations
) -> None:
    agents = agents_file(tmp_path / "agents.yaml")
    store = ApprovalStore(gemini_locations.approvals)
    now = dt.datetime.now(dt.UTC)
    record = store.issue(
        model=MODEL,
        max_usd=Decimal("1.50"),
        job="j1",
        quote="yes, up to 1.50",
        quoted_at=now - dt.timedelta(minutes=1),
        now=now,
        ttl_minutes=60,
        beyond_ceiling=False,
    )
    _config_with_terms(gemini_locations, tmp_path, "none")
    brief = f"gemini: paid model={MODEL} cap=1.50 approval={record.id}\n{PUBLIC}"
    code, out, _ = hooks("guard", "--agents", str(agents), home=_private_home, stdin=dispatch(prompt=brief), now=now)
    assert code == 0
    assert GEMINI_PAID not in read_log(_private_home)[-1]["rules"]
    assert "deny" not in out
    assert approval_problem(store, record.id, now) is None
    (store.folder / f"{record.id}.used").write_text("")
    assert approval_problem(store, record.id, now) is not None


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


def test_a_complete_command_inside_a_quoted_shell_string_still_passes() -> None:
    inner = f"safo gemini ask --paid --model m --cap 1.5 --approval {OK} --material public"
    assert rules(f"bash -c '{inner}'\n{PUBLIC}", accepts()) == []
    assert rules(f'eval "{inner}"\n{PUBLIC}', accepts()) == []


def test_a_free_step_in_a_shell_form_still_needs_the_public_material_line() -> None:
    assert GEMINI_MATERIAL in rules("bash -c 'safo gemini ask --model m'\n")
    assert rules("bash -c 'safo gemini ask --model m'\n" + PUBLIC) == []


def test_the_paid_config_name_is_checked_on_its_own() -> None:
    assert GEMINI_PAID in rules("use doppler -p image-gen -c prd_paid for it", accepts())
    assert rules("no paid config named here, just prose about prd", accepts()) == []


def test_a_list_item_material_line_counts() -> None:
    assert rules("- gemini: free\n- gemini-material: public\n") == []


def test_a_quadratic_brief_is_blocked_fast() -> None:
    import time

    for brief in ("safo " * 16_000, ("safo gemini ask --paid\n" * 6_000), "safo " * 16_000 + "gemini"):
        started = time.monotonic()
        found = findings(brief + "\n" + PUBLIC, accepts())
        assert time.monotonic() - started < 3.0
        assert [r for r, _ in found if r == GEMINI_PAID], "blocked"


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
    assert rules("safo status" + " word" * 30 + " and then gemini ask --paid\n", accepts()) == []
    assert GEMINI_PAID in rules("safo status" + " word" * 3 + " gemini ask --paid\n", accepts())


def test_a_brief_with_no_gemini_marker_is_untouched_by_a_past_deadline() -> None:
    import time

    assert findings("issue: TEST-1\nrename a variable\n", accepts(), (), time.monotonic() - 1) == []


# -- second review round -------------------------------------------------------------------------------------------

EXAMPLE_MODELS = sorted(
    yaml.safe_load((Path(__file__).parent.parent / "examples" / "gemini.example.yaml").read_text())["paid"]
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
        r"safo gemini (?:ask|approve)|gemini: ?(?:free|paid)|prd_paid|generativelanguage|genai|base64|xxd|openssl",
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


@pytest.mark.parametrize("bad", ["(unclosed\n", "(a+a+)+y\n", "(a|aa)+y\n", ".*secret\n", "x" * 300 + "\n", "(a)\\1\n"])
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
    far = "use gemini and then ask " + "word " * 30 + "$HOME is where it lives"
    assert rules(far + "\n", accepts()) == []
    near = "use gemini and then ask $HOME is where it lives"
    assert GEMINI_PAID in rules(near + "\n", accepts())


def test_each_term_sees_a_bounded_chunk_of_text() -> None:
    from typing import cast

    from safo.gemini import TERMS_CHUNK, private_term_hit

    seen: list[int] = []

    class Spy:
        def search(self, text: str) -> None:
            seen.append(len(text))

    assert not private_term_hit(cast("tuple[re.Pattern[str], ...]", (Spy(),)), "x" * 20_000)
    assert seen and max(seen) <= TERMS_CHUNK and len(seen) >= 5
