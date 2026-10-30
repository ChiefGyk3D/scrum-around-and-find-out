# SPDX-License-Identifier: Apache-2.0
"""The gemini-paid rule on briefs for work on this repository's own guard code (#210): the denial names what matched,
and a brief that only describes the guard is not read as a request for paid use."""

from __future__ import annotations

import pytest

from safo import geminibrief
from safo.gemini import DisabledCheck

OWN = "issue: ChiefGyk3D/scrum-around-and-find-out#209\n"
OTHER = "issue: someone/else#209\n"
PUBLIC = "gemini-material: public\n"


def paid(brief: str) -> list[str]:
    return [why for rule, why in geminibrief.findings(brief, DisabledCheck()) if rule == geminibrief.GEMINI_PAID]


def test_denial_names_the_matched_command() -> None:
    reasons = paid(OTHER + PUBLIC + "safo gemini ask --paid --model m --prompt-file p\n")
    assert len(reasons) == 1
    assert "line 3: paid use is disabled" in reasons[0]
    assert "matched" in reasons[0] and "--paid" in reasons[0]


def test_denial_names_the_matched_config_token() -> None:
    reasons = paid(OTHER + PUBLIC + "The prd_paid key is read by the wrapper.\n")
    assert len(reasons) == 1 and "matched" in reasons[0] and "prd_paid" in reasons[0]


def test_denial_names_the_matched_declaration() -> None:
    reasons = paid(OTHER + PUBLIC + "gemini: paid cap=1 approval=abc\n")
    assert len(reasons) == 1 and "matched" in reasons[0] and "gemini: paid" in reasons[0]


def test_denial_matched_text_is_capped() -> None:
    reasons = paid(OTHER + PUBLIC + "safo gemini ask --paid --model " + "m" * 500 + " --prompt-file p\n")
    assert reasons and len(reasons[0]) < 400


@pytest.mark.parametrize(
    "line",
    [
        "Rework how `safo gemini approve` records are verified in gemini.py.",
        "The `safo gemini ask` path needs a test.",
        "Do not touch the prd_paid config key, it is only named here by reference.",
    ],
)
def test_repo_work_brief_describing_the_guard_passes(line: str) -> None:
    assert paid(OWN + PUBLIC + line + "\n") == []


@pytest.mark.parametrize(
    "line",
    [
        "Rework how `safo gemini approve` records are verified in gemini.py.",
        "Do not touch the prd_paid config key, it is only named here by reference.",
    ],
)
def test_same_prose_without_the_own_repo_issue_line_still_denies(line: str) -> None:
    assert paid(PUBLIC + line + "\n")
    assert paid(OTHER + PUBLIC + line + "\n")


@pytest.mark.parametrize(
    "line",
    [
        "safo gemini ask --paid --model m --prompt-file p",
        "safo gemini approve --approval abc --cap 1",
        "safo gemini approve notes",
        "safo gemini approve $(whoami)",
        "safo gemini approve; safo gemini ask --paid --model m --prompt-file p",
        "gemini: paid cap=1 approval=abc",
        "doppler secrets get prd_paid --plain",
        "echo $(doppler secrets get prd_paid)",
        "export K=prd_paid; printenv $K",
    ],
)
def test_real_paid_asks_still_deny_with_the_own_repo_issue_line(line: str) -> None:
    assert paid(OWN + PUBLIC + line + "\n"), line


def test_issue_line_must_name_this_repository_exactly() -> None:
    line = "Rework `safo gemini approve` signing.\n"
    for issue in (
        "issue: ChiefGyk3D/scrum-around-and-find-out-evil#1\n",
        "issue: Other/scrum-around-and-find-out#1\n",
        "see issue: ChiefGyk3D/scrum-around-and-find-out#1\n",
        "issue: ChiefGyk3D/scrum-around-and-find-out#1 and more\n",
    ):
        assert paid(issue + PUBLIC + line), issue
    assert paid("issue: ChiefGyk3D/scrum-around-and-find-out#1\n" + PUBLIC + line) == []
