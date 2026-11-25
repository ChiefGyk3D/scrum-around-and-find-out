# SPDX-License-Identifier: Apache-2.0
"""safo-file routing, Daybreak review round 2 (issue #455): the visibility race, a bounded matcher, real public-ok
reasons."""

from __future__ import annotations

import io
import re
import time
from pathlib import Path

import pytest

from safo import idea_gate
from safo import idea_gate_routes as routes
from safo.errors import SafoError
from test_idea_gate import Fakes
from test_idea_gate_real import NOW, Box
from test_idea_gate_routes import ledger_records, write_routes
from test_idea_gate_routes_round2 import file_in

# ---- 1. the visibility race --------------------------------------------------------------------------------------


class Flips:
    """Visibility answers in call order (the last one repeats); every lookup and the create call are logged."""

    def __init__(self, f: Fakes, *answers: bool | Exception) -> None:
        self.answers, self.events = list(answers), list[str]()
        self.f = f

    def __call__(self, repo: str) -> bool:
        self.events.append("lookup")
        a = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(a, Exception):
            raise a
        return a


def file_with(f: Fakes, flips: Flips, *extra: str, title: str = "hello", body: str = "b") -> tuple[int, str, str]:
    d = f.deps()
    d.is_public = flips
    real_create = d.create_issue

    def create(repo: str, t: str, b: str) -> str:
        flips.events.append("create")
        return real_create(repo, t, b)

    d.create_issue = create
    out, err = io.StringIO(), io.StringIO()
    argv = ["issue", "--repo", "o/pub", "--working-repo", "o/pub", "--title", title, "--body", body, *extra]
    code = idea_gate.main(argv, deps=d, out=out, err=err, now=NOW)
    return code, out.getvalue(), err.getvalue()


def test_the_lookup_comes_immediately_before_the_create_and_again_right_after_for_private_work(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    flips = Flips(f, False)
    assert file_with(f, flips, "--class", "homelab")[0] == 0
    assert flips.events == ["lookup", "lookup", "create", "lookup"]


def test_plain_product_work_is_looked_up_before_the_create_only(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    flips = Flips(f, False)
    assert file_with(f, flips)[0] == 0
    assert flips.events == ["lookup", "lookup", "create"]


def test_a_repo_that_goes_public_between_the_check_and_the_create_is_refused(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    flips = Flips(f, False, True)  # private when decided, public when re-read just before the create
    code, _, err = file_with(f, flips, "--class", "homelab")
    assert code == 1 and "public" in err and f.created == []


def test_a_repo_that_goes_public_during_the_create_is_reported_loudly_and_recorded(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    flips = Flips(f, False, False, True)  # private before the create, public right after it
    code, _, err = file_with(f, flips, "--class", "homelab")
    assert code == 2 and len(f.created) == 1
    assert "EXPOSED" in err and "https://github.com/o/pub/issues/1" in err
    recs = ledger_records(f)
    assert [r["state"] for r in recs][-2:] == ["committed", "routed"]
    assert recs[-1]["outcome"] == "exposed" and recs[-1]["class"] == "homelab"


def test_work_that_is_not_private_workflow_is_not_flagged_when_the_repo_goes_public(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    flips = Flips(f, False)
    assert file_with(f, flips, "--class", "product")[0] == 0
    assert flips.events.count("lookup") == 2  # no look after the create: nothing private could have been exposed


def test_a_failed_lookup_after_the_create_names_the_url_and_exits_2(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    flips = Flips(f, False, False, SafoError("gh api failed: boom"))
    code, _, err = file_with(f, flips, "--class", "homelab")
    assert code == 2 and "issues/1" in err and "could not be checked" in err
    assert ledger_records(f)[-1]["state"] == "committed"


def test_an_override_into_a_public_repo_is_not_an_exposure(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    flips = Flips(f, True)
    body = "public-ok: generic security tracking, no private detail"
    assert file_with(f, flips, "--class", "homelab", "--allow-public", body=body)[0] == 0
    assert "EXPOSED" not in str(ledger_records(f))


# ---- 2. a matcher that is linear in the text -----------------------------------------------------------------------


def reference_matching(table: routes.RouteTable, text: str) -> list[tuple[routes.RouteClass, tuple[str, ...]]]:
    """The round-1 matcher, one regex scan per keyword and a hint-by-token search, kept as the oracle."""
    plain, folded = routes._norm(text), routes._fold(text)
    out = []
    for cls in table.classes:
        seen: dict[str, None] = {}
        for term in cls.keywords:
            word = routes._norm(term)
            if word and re.search(rf"(?<!\w){re.escape(word)}(?!\w)", plain):
                seen[word] = None
        found = [f"keyword {k}" for k in seen]
        toks = [t.strip(routes.PATH_STRIP).rstrip(".") for t in folded.split()]
        shaped = [f"/{t.strip('/')}/" for t in toks if "/" in t or re.search(r"[a-z0-9]\.[a-z0-9]", t)]
        found += [f"path {h}" for h in cls.paths if any(f"/{h}/" in s for s in shaped)]
        if found:
            out.append((cls, tuple(found)))
    return out


SAMPLES = [
    "rebuild the proxmox runner vlan and firewall",
    "update the claude mcp skill and prompts",
    "evaluate and compare two options with a benchmark",
    "random experiment, a side project",
    "fix the parser bug in the cli",
    "buy more coffee",
    "hopscotch operations",
    "PROXMOX Runner",
    "tidy up notes/january.md and take some notes",
    "see infra/main.tf, ansible/roles/x.yml and src/proxmox/foo.py",
    "the claude.md and settings.json files in .claude/hooks/",
    "rebuild the side-project box and the side_project box",
    "what if we used prior art for a docker host spike?",
    "look at (research/papers/a.pdf), then dotfiles/skills.",
    "",
    "docker   host\t\nside \n project k8s",
    "ops ops ops proxmox proxmox",
]


@pytest.mark.parametrize("text", SAMPLES)
def test_the_linear_matcher_agrees_with_the_old_one_on_the_fixtures(text: str) -> None:
    table = routes.default_table()
    assert routes.matching(table, text) == reference_matching(table, text)


def test_the_linear_matcher_agrees_on_a_custom_table() -> None:
    cls = [
        routes.RouteClass("product", "", False, ("bug", "unit test", "a b c"), ("src", "a/b")),
        routes.RouteClass("one", "o/one", True, ("zig", "side project", "a b c d"), ("notes", "x/y/z")),
    ]
    table = routes.RouteTable(tuple(cls))
    for text in ["a b c d zig", "unit   test of a/b and x/y/z/w", "side project, src/notes/x", "a b", "zig-zag"]:
        assert routes.matching(table, text) == reference_matching(table, text)


def word(n: int) -> str:
    return f"w{n % 40_000:05d}"


def big_table() -> routes.RouteTable:
    made = [routes.RouteClass("product", "", False, (), ())]
    for i in range(31):
        kws = tuple(" ".join(word(i * 997 + j * 13 + k * 7919) for k in range(j % 4 + 1)) for j in range(200))
        paths = tuple("/".join(word(i * 31 + j * 17 + k * 101) for k in range(j % 2 + 1)) for j in range(200))
        made.append(routes.RouteClass(f"c{i}", f"o/c{i}", True, kws, paths))
    return routes.RouteTable(tuple(made))


def test_a_full_size_table_on_a_full_size_text_finishes_in_bounded_time() -> None:
    table = big_table()
    assert len(table.classes) == 32 and all(len(c.keywords) == 200 for c in table.classes[1:])
    text = " ".join(f"x{n * 7919 % 10**6}" for n in range(130_000))[: routes.TEXT_LIMIT]
    assert len(text) > 900_000
    start = time.monotonic()
    assert routes.matching(table, text) == []
    assert time.monotonic() - start < 10
    # the worst shape for a gram index: one word repeated, terms that all start with it
    cls = routes.RouteClass("tangent", "o/t", True, tuple(f"a w{n:05d}" for n in range(200)), ())
    start = time.monotonic()
    assert routes.matching(routes.RouteTable((cls,)), "a " * 500_000) == []
    assert time.monotonic() - start < 10


def test_a_matcher_hit_in_a_full_size_text_is_still_found() -> None:
    table = big_table()
    chosen = table.classes[5]
    term = chosen.keywords[0]
    text = ("filler " * 100_000) + term + (" filler" * 100_000)
    hits = routes.matching(table, text)
    assert any(c.name == chosen.name and f"keyword {term}" in m for c, m in hits)


def test_a_keyword_of_more_than_four_words_or_a_hint_of_more_than_four_segments_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    box = Box(tmp_path, monkeypatch)
    for data in ('keywords = ["a b c d e"]', 'paths = ["a/b/c/d/e"]'):
        write_routes(box, f"[classes.homelab]\n{data}\n")
        with pytest.raises(SafoError, match="at most 4"):
            routes.load_table(str(box.home))


# ---- 3. public-ok reasons ---------------------------------------------------------------------------------------


PLACEHOLDERS = [
    "TODO", "TBD", "none", "n/a", "na", "ok", "yes", "-", ".", "test", "xxxxxxxxxxxxxxxx", "x x x x x x x x x",
    "too short", "todo todo todo todo", "ok ok ok ok ok ok", "123456789012 3456", "n/a n/a n/a n/a", "aaaaaaaaaaaa aaa",
]  # fmt: skip


@pytest.mark.parametrize("reason", PLACEHOLDERS)
def test_a_placeholder_public_ok_reason_does_not_count(tmp_path: Path, reason: str) -> None:
    f = Fakes(tmp_path)
    code, _, err = file_in(f, lambda r: True, "--allow-public", "--class", "homelab", body=f"public-ok: {reason}")
    assert code == 1 and f.created == []
    assert "at least 12 characters" in err and "two different words" in err


def test_a_real_public_ok_reason_counts(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    body = "public-ok: generic security tracking, no private detail"
    assert file_in(f, lambda r: True, "--allow-public", "--class", "homelab", body=body)[0] == 0


def test_the_first_valid_reason_line_is_enough(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    body = "public-ok: TODO\npublic-ok: generic security tracking only"
    assert file_in(f, lambda r: True, "--allow-public", "--class", "homelab", body=body)[0] == 0
