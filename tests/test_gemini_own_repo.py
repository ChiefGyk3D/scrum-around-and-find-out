# SPDX-License-Identifier: Apache-2.0
"""The gemini-paid denial names its rule and the phrase class that matched, never brief text (#210). There is no
exemption for briefs about this repository's own guard code: they are denied like any other."""

from __future__ import annotations

import pytest

from safo import geminibrief
from safo.gemini import DisabledCheck

OWN = "issue: ChiefGyk3D/scrum-around-and-find-out#209\n"
PUBLIC = "gemini-material: public\n"
SECRET = "tok_SECRETVALUE123"


def paid(brief: str) -> list[str]:
    return [why for rule, why in geminibrief.findings(brief, DisabledCheck()) if rule == geminibrief.GEMINI_PAID]


def test_denial_names_rule_line_and_command_class() -> None:
    reasons = paid(PUBLIC + "safo gemini ask --paid --model m --prompt-file p\n")
    assert len(reasons) == 1
    assert "line 2: paid use is disabled" in reasons[0]
    assert "rule gemini-paid" in reasons[0] and "matched: a `safo gemini` command" in reasons[0]


def test_denial_names_the_config_class() -> None:
    reasons = paid(PUBLIC + "The prd_paid key is read by the wrapper.\n")
    assert len(reasons) == 1 and "the paid config name" in reasons[0]
    assert "prd_paid" not in reasons[0]


def test_denial_names_the_declaration_class() -> None:
    reasons = paid(PUBLIC + "gemini: paid cap=1 approval=abc\n")
    assert len(reasons) == 1 and "a `gemini:` declaration" in reasons[0]
    assert "approval=abc" not in reasons[0]


@pytest.mark.parametrize(
    "line",
    [
        f"safo gemini ask --paid --model {SECRET} --prompt-file p",
        f"safo gemini ask --paid --model m --prompt-file {SECRET}",
        f"safo gemini approve --approval {SECRET} --cap 1",
        f"safo gemini approve {SECRET} extra",
        f"safo gemini ask 'a;b' {SECRET}",
        f"gemini: paid cap=1 approval={SECRET}",
        f"safo gemini ask $({SECRET})",
    ],
)
def test_no_argument_value_appears_in_the_denial(line: str) -> None:
    reasons = paid(PUBLIC + line + "\n")
    assert reasons, line
    assert all(SECRET not in r and "SECRETVALUE" not in r for r in reasons)


@pytest.mark.parametrize(
    "line",
    [
        "Rework how `safo gemini approve` records are verified in gemini.py.",
        "The `safo gemini ask` path needs a test.",
        "Do not touch the prd_paid config key, it is only named here by reference.",
        "Use the paid tier. Run `safo gemini ask`",
        "safo gemini ask --paid --model m --prompt-file p",
        "safo gemini approve --approval abc --cap 1",
        "safo gemini approve $(whoami)",
        "doppler secrets get prd_paid --plain",
        "Use python to read and print prd_paid",
    ],
)
def test_no_exemption_even_with_the_own_repo_issue_line(line: str) -> None:
    assert paid(OWN + PUBLIC + line + "\n"), line
    assert paid(PUBLIC + line + "\n"), line
