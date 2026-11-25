# SPDX-License-Identifier: Apache-2.0
"""safo-file routing, Daybreak review round 1 (issue #455): the target's visibility is ALWAYS looked up, a public target
takes only positively product work, and nothing the local files say can turn the refusal off."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from safo import idea_gate_routes as routes
from safo.errors import SafoError
from test_idea_gate import WORK, Fakes
from test_idea_gate_real import Box
from test_idea_gate_routes import go_real, ledger_records, run, write_routes


class Looks:
    """A visibility fake that counts its lookups."""

    def __init__(self, public: bool) -> None:
        self.public, self.calls = public, 0

    def __call__(self, repo: str) -> bool:
        self.calls += 1
        return self.public


def file_in(
    f: Fakes,
    look: Callable[[str], bool],
    *extra: str,
    title: str = "hello",
    body: str = "b",
    repo: str = "o/pub",
    working: str = "o/pub",
) -> tuple[int, str, str]:
    argv = ["issue", "--repo", repo, "--working-repo", working, "--title", title, "--body", body, *extra]
    return run(f, *argv, public=look)


def test_every_filing_looks_the_target_up_even_with_no_class(tmp_path: Path) -> None:
    f, look = Fakes(tmp_path), Looks(False)
    assert file_in(f, look)[0] == 0 and look.calls == 2  # once to decide, once right before the create
    assert file_in(f, look, "--class", "product")[0] == 0 and look.calls == 4


def test_unclassified_work_in_a_public_repo_that_is_not_the_working_repo_is_refused(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    code, _, err = file_in(f, Looks(True), repo="o/pub", working="o/other", body="cross-project: because")
    assert code == 1 and "public" in err and f.created == []
    assert ledger_records(f)[-1]["outcome"] == "refused"


def test_unclassified_work_in_a_public_working_repo_is_filed(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    assert file_in(f, Looks(True))[0] == 0 and len(f.created) == 1  # positively product: the working repo


def test_explicit_product_in_a_public_other_repo_is_filed(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    code, _, _ = file_in(f, Looks(True), "--class", "product", repo="o/pub", working="o/other", body="cross-project: x")
    assert code == 0 and len(f.created) == 1


@pytest.mark.parametrize(
    "title",
    [
        "rebuild the side-project box",  # a hyphen is a space
        "rebuild the side_project box",
        "claude.md and settings.json",  # dots
        "REBUILD THE PROXMOX HOST",  # case
        "rebuild the " + "".join(chr(0xFEE0 + ord(c)) for c in "proxmox") + " host",  # fullwidth letters (NFKC)
        "rebuild the prox" + chr(0x200B) + "mox host",  # a zero-width space inside the word
        "rebuild the prox" + chr(0xAD) + "mox host",  # a soft hyphen
        "rebuild the   side \t\n project",  # runs of whitespace
    ],
)
def test_private_wording_is_found_after_normalising(tmp_path: Path, title: str) -> None:
    f = Fakes(tmp_path)
    code, _, err = file_in(f, Looks(True), title=title)
    assert code == 1 and f.created == []
    assert "private-workflow" in err or "cannot be classified" in err  # an invisible character is refused outright
    # the matcher itself still sees through the normalisation, whatever the refusal rule says
    assert any(c.private for c, _ in routes.matching(routes.default_table(), title))


def test_private_wording_after_the_old_cutoff_is_still_found(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    code, _, _ = file_in(f, Looks(True), body="word " * 8_000 + "proxmox")  # past 20,000 characters
    assert code == 1 and f.created == []


def test_text_past_the_hard_limit_is_unclassified_and_refused_for_a_public_target(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    big = "a" * (routes.TEXT_LIMIT + 1)
    code, _, err = file_in(f, Looks(True), body=big)
    assert code == 1 and "too large" in err and f.created == []
    assert file_in(f, Looks(False), body=big)[0] == 0  # a private target does not care


def test_only_whole_words_count_for_the_refusal(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    assert file_in(f, Looks(True), title="hopscotch operations")[0] == 0


def test_explicit_product_never_overrides_private_wording(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    code, _, _ = file_in(f, Looks(True), "--class", "product", title="rebuild the proxmox runner")
    assert code == 1 and f.created == []
    reason = "public-ok: generic tracking only"
    code, _, _ = file_in(f, Looks(True), "--class", "product", "--allow-public", title="proxmox", body=reason)
    assert code == 0 and len(f.created) == 1  # both override elements present


def test_a_public_ok_line_in_a_blockquote_or_indented_is_ignored(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    for body in ("> public-ok: because", "  public-ok: because", "- public-ok: because"):
        assert file_in(f, Looks(True), "--allow-public", "--class", "homelab", body=body)[0] == 1
    assert f.created == []


def test_a_lookup_failure_refuses_even_for_unclassified_work(tmp_path: Path) -> None:
    f = Fakes(tmp_path)

    def broken(repo: str) -> bool:
        raise SafoError("gh api failed: boom")

    assert file_in(f, broken)[0] == 2 and f.created == []


def test_a_repo_that_became_public_between_two_filings_is_caught(tmp_path: Path) -> None:
    f, look = Fakes(tmp_path), Looks(False)
    assert file_in(f, look, "--class", "homelab")[0] == 0
    look.public = True
    assert file_in(f, look, "--class", "homelab")[0] == 1 and look.calls == 4  # 3 for the first, 1 for the refusal


def test_a_routes_file_that_is_a_fifo_or_has_another_owner_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    box = Box(tmp_path, monkeypatch)
    box.agents(tracking_repos=[WORK])
    d = box.home / ".config" / "safo-file"
    d.mkdir(parents=True, mode=0o700)
    os.mkfifo(d / "routes.toml", 0o600)
    code, _, err = go_real(box, "route", "x", "--working-repo", WORK, "--class", "homelab")
    assert code == 2 and "routes file" in err and "regular file" in err
    (d / "routes.toml").unlink()
    write_routes(box, "")
    monkeypatch.setattr("safo.trust.effective_uid", lambda: os.geteuid() + 1)
    code, _, err = go_real(box, "route", "x", "--working-repo", WORK, "--class", "homelab")
    assert code == 2 and "routes file" in err and "owned" in err


def test_a_keyword_with_a_metacharacter_matches_literally(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.agents(tracking_repos=[WORK])
    write_routes(box, '[classes.lang]\nrepo = "o/lang"\nkeywords = ["c++"]\n')
    code, out, _ = go_real(box, "route", "port it to C++ soon", "--working-repo", WORK)
    assert code == 0 and "destination: o/lang" in out
    assert go_real(box, "route", "port it to cc soon", "--working-repo", WORK)[0] == 3


def test_a_custom_class_added_by_config_is_private_and_refused_in_a_public_repo(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    table = routes.default_table()
    with_lang = routes.RouteTable((*table.classes, routes.RouteClass("lang", "o/lang", True, ("zig",), ())))
    code, _, _ = run(
        f,
        *("issue", "--repo", "o/pub", "--working-repo", "o/pub", "--title", "zig things", "--body", "b"),
        public=Looks(True),
        table=with_lang,
    )
    assert code == 1 and f.created == []


def test_a_class_loaded_from_the_file_is_private_whatever_it_says(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    box = Box(tmp_path, monkeypatch)
    write_routes(box, '[classes.lang]\nrepo = "o/lang"\nkeywords = ["zig"]\n')
    table = routes.load_table(str(box.home))
    assert [c.name for c in table.classes if not c.private] == ["product"]
