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

import pytest

from agentsdata import agents_with
from geminidata import MODEL, NOW
from hooksdata import agents_file, dispatch, hooks, read_log, set_mode
from safo.gemini import ApprovalStore, Locations, approval_problem
from safo.geminibrief import GEMINI_MATERIAL, GEMINI_PAID, findings, load_terms
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


def test_private_terms_come_from_the_named_file_and_a_bad_line_is_skipped(tmp_path: Path) -> None:
    path = tmp_path / "terms.txt"
    path.write_text("# a comment\n\nacme-internal\n(unclosed\n")
    terms = load_terms({"SAFO_PRIVACY_EXTRA_FILE": str(path), "HOME": str(tmp_path)})
    assert len(terms) == 1 and terms[0].search("About ACME-Internal")
    assert load_terms({"SAFO_PRIVACY_EXTRA_FILE": str(tmp_path / "missing"), "HOME": str(tmp_path)}) == ()


def test_the_hook_denies_a_brief_that_matches_the_private_terms(_private_home: Path, tmp_path: Path) -> None:
    agents = agents_file(tmp_path / "agents.yaml")
    terms = tmp_path / "terms.txt"
    terms.write_text("acme-internal\n")
    brief = f"gemini: free\n{PUBLIC}about acme-internal things\n"
    _, out, _ = hooks(
        "guard",
        "--agents",
        str(agents),
        home=_private_home,
        stdin=dispatch(prompt=brief),
        env={"SAFO_PRIVACY_EXTRA_FILE": str(terms)},
    )
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "acme" not in out.lower()


# -- the guard parses a command with the parser the CLI uses --------------------------------------------------------

CMD = "run: safo gemini ask --model m --prompt-file p --material public"


@pytest.mark.parametrize(
    "tail",
    [
        "--pai --cap 1.5 --approval " + OK,  # shortened spellings
        "--paid --ca 1.5 --approval " + OK,
        "--paid --cap 1.5 --appr " + OK,
        "--pa --cap 1.5 --approval " + OK,
        "--PAID --cap 1.5 --approval " + OK,  # mixed case
        "--paid --cap 1.5 --approval=" + OK + " --job",  # a dangling option the CLI rejects
        "--paid --cap 9 --approval " + OK,
        "--paid --cap 1.5 --cap 9 --approval " + OK,  # a repeated flag: the last one wins in the CLI
        "--paid --cap 1.5",  # no record
        "--paid=yes --cap 1.5 --approval " + OK,
    ],
)
def test_a_command_the_parser_rejects_or_reads_as_unsafe_is_blocked(tail: str) -> None:
    assert GEMINI_PAID in rules(f"{CMD} {tail}\n{PUBLIC}", accepts())


@pytest.mark.parametrize(
    "line",
    [
        f"{CMD} --paid --cap 1.5 --approval {OK}",
        f"{CMD} --paid --cap=1.5 --approval={OK}",
        f"{CMD} --paid --cap 9 --cap 1.5 --approval {OK}",  # the last one wins, as in the CLI
        f"safo gemini --paid --model m ask --cap 1.5 --approval {OK}",  # options before the action
        f"{CMD} --paid --cap 1.5 --approval {OK} && echo done",
    ],
)
def test_the_same_forms_the_cli_accepts_pass_with_a_live_record(line: str) -> None:
    assert rules(f"{line}\n{PUBLIC}", accepts()) == []


def test_an_approve_command_in_a_brief_is_a_paid_step_and_is_blocked() -> None:
    assert GEMINI_PAID in rules(f"safo gemini approve --model m --max-usd 1\n{PUBLIC}", accepts())


def test_quota_is_not_a_step() -> None:
    assert rules("safo gemini quota --model m\n", accepts()) == []


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
    assert rules("safo status " + "x" * 500 + " and then gemini ask --paid\n", accepts()) == []
    assert GEMINI_PAID in rules("safo status " + "x" * 100 + " gemini ask --paid\n", accepts())
