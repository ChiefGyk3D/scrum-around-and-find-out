# SPDX-License-Identifier: Apache-2.0
"""safo-file routing table (issue #455): classes, the routes file, the public-repo refusal, the ledger record.

Every gh call is a fake and HOME is a temporary directory; nothing touches the network or a real configuration."""

from __future__ import annotations

import io
import json
import os
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from safo import idea_gate
from safo import idea_gate_routes as routes
from safo.errors import SafoError
from test_idea_gate import WORK, Fakes
from test_idea_gate_real import NOW, Box, script

HOMELAB = "ChiefGyk3D/homelab-ops"
AI = "ChiefGyk3D/AI-Shit"
RESEARCH = "ChiefGyk3D/research-notes"
WORKBENCH = "ChiefGyk3D/workbench"


def run(
    f: Fakes,
    *argv: str,
    public: Callable[[str], bool] | None = None,
    table: routes.RouteTable | None = None,
) -> tuple[int, str, str]:
    d = f.deps()
    if public is not None:
        d.is_public = public
    if table is not None:
        d.routes = lambda: table
    out, err = io.StringIO(), io.StringIO()
    code = idea_gate.main(list(argv), deps=d, out=out, err=err, now=NOW)
    return code, out.getvalue(), err.getvalue()


def route(f: Fakes, text: str, *extra: str, working: str = WORK) -> tuple[int, str, str]:
    return run(f, "route", text, "--working-repo", working, *extra)


def ledger_records(f: Fakes) -> list[dict[str, object]]:
    return [json.loads(x) for x in f.ledger.read_text().splitlines() if x.strip()]


# ---- the classes and their default destinations ---------------------------------------------------------------


def test_homelab_words_go_to_homelab_ops(tmp_path: Path) -> None:
    code, out, _ = route(Fakes(tmp_path), "rebuild the proxmox runner vlan and firewall")
    assert code == 0
    assert f"destination: {HOMELAB}" in out and "class: homelab" in out
    assert "keyword proxmox" in out and "keyword runner" in out


def test_ai_tooling_words_go_to_ai_shit(tmp_path: Path) -> None:
    code, out, _ = route(Fakes(tmp_path), "update the claude mcp skill and prompts")
    assert code == 0
    assert f"destination: {AI}" in out and "class: ai-tooling" in out and "keyword mcp" in out


def test_research_words_go_to_research_notes(tmp_path: Path) -> None:
    code, out, _ = route(Fakes(tmp_path), "evaluate and compare two options with a benchmark")
    assert code == 0
    assert f"destination: {RESEARCH}" in out and "class: research" in out and "keyword benchmark" in out


def test_tangent_words_go_to_workbench(tmp_path: Path) -> None:
    code, out, _ = route(Fakes(tmp_path), "random experiment, a side project")
    assert code == 0
    assert f"destination: {WORKBENCH}" in out and "class: tangent" in out and "keyword side project" in out


def test_product_words_go_to_the_working_repo_when_it_is_tracked(tmp_path: Path) -> None:
    code, out, _ = route(Fakes(tmp_path), "fix the parser bug in the cli")
    assert code == 0
    assert f"destination: {WORK}" in out and "class: product" in out and "keyword parser" in out


def test_product_in_an_untracked_working_repo_is_undecided_and_names_the_default(tmp_path: Path) -> None:
    code, out, _ = route(Fakes(tmp_path), "fix the parser bug in the cli", working="o/not-tracked")
    assert code == 3
    assert WORKBENCH in out and "default" in out and "not a tracked product repo" in out


def test_nothing_matching_exits_3_and_names_the_default(tmp_path: Path) -> None:
    code, out, _ = route(Fakes(tmp_path), "buy more coffee")
    assert code == 3
    assert f"destination: {WORKBENCH}" in out and "default only" in out and "--class" in out


def test_matching_is_whole_word_and_case_insensitive(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    assert route(f, "hopscotch operations")[0] == 3  # "ops" is inside a longer word
    code, out, _ = route(f, "PROXMOX Runner")
    assert code == 0 and "class: homelab" in out


def test_a_path_hint_matches_a_path_segment_not_a_bare_word(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    code, out, _ = route(f, "tidy up notes/january.md")
    assert code == 0 and "class: research" in out and "path notes" in out
    assert route(f, "take some notes")[0] == 3  # the word alone is not a path


def test_an_explicit_class_wins_and_is_the_reason(tmp_path: Path) -> None:
    code, out, _ = route(Fakes(tmp_path), "buy more coffee", "--class", "research")
    assert code == 0
    assert f"destination: {RESEARCH}" in out and "explicit class research" in out


def test_an_unknown_explicit_class_is_an_error(tmp_path: Path) -> None:
    code, _, err = route(Fakes(tmp_path), "x", "--class", "nope")
    assert code == 2 and "unknown class" in err


def test_a_tie_goes_to_the_private_class_then_to_the_earlier_one() -> None:
    def cls(name: str, private: bool) -> routes.RouteClass:
        return routes.RouteClass(name, "" if name == "product" else f"o/{name}", private, ("alpha",), ())

    table = routes.RouteTable((cls("product", False), cls("tangent", True), cls("late", True)))
    won = routes.decide(table, "alpha", None, "o/x", lambda: ("o/x",))
    assert won.cls.name == "tangent"  # product also scores 1, but private beats public, then the earlier class
    assert won.repo == "o/tangent"


def test_a_higher_score_beats_table_order() -> None:
    table = routes.default_table()
    won = routes.decide(table, "proxmox runner and a random note", None, WORK, lambda: (WORK,))
    assert won.cls.name == "homelab"  # two homelab words against one tangent word


# ---- the routes file --------------------------------------------------------------------------------------------


def write_routes(box: Box, data: bytes | str, mode: int = 0o600) -> Path:
    d = box.home / ".config" / "safo-file"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = d / "routes.toml"
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    path.chmod(mode)
    return path


def go_real(box: Box, *argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = idea_gate.main([*argv, "--ledger", str(box.log / "ledger.jsonl")], env=box.env, out=out, err=err, now=NOW)
    return code, out.getvalue(), err.getvalue()


def test_an_absent_routes_file_means_the_built_in_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.agents(tracking_repos=[WORK])
    code, out, _ = go_real(box, "route", "rebuild the proxmox runner", "--working-repo", WORK)
    assert code == 0 and HOMELAB in out


def test_the_routes_file_changes_a_repo_adds_words_and_adds_a_class(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    box = Box(tmp_path, monkeypatch)
    box.agents(tracking_repos=[WORK])
    write_routes(
        box,
        '[classes.homelab]\nrepo = "o/my-lab"\nkeywords = ["zigbee"]\n'
        '[classes.radio]\nrepo = "o/radio"\nkeywords = ["sdr"]\npaths = ["rf"]\n',
    )
    code, out, _ = go_real(box, "route", "pair the zigbee hub", "--working-repo", WORK)
    assert code == 0 and "destination: o/my-lab" in out
    assert go_real(box, "route", "rebuild the proxmox runner", "--working-repo", WORK)[0] == 3  # words were replaced
    code, out, _ = go_real(box, "route", "scan with the sdr", "--working-repo", WORK)
    assert code == 0 and "destination: o/radio" in out and "class: radio" in out
    code, out, _ = go_real(box, "route", "see rf/notes.txt", "--working-repo", WORK)
    assert code == 0 and "class: radio" in out and "path rf" in out


BAD_FILES = [
    pytest.param(b"classes = [", "not valid TOML", id="malformed"),
    pytest.param(b"\xff\xfe", "not valid UTF-8", id="not-utf8"),
    pytest.param(b"colour = 1\n", "unknown key", id="unknown-top-key"),
    pytest.param(b'[classes.homelab]\nrepo = "o/x"\nfoo = 1\n', "unknown key", id="unknown-class-key"),
    pytest.param(b'[classes.homelab]\nrepo = "not a repo"\n', "repo", id="bad-repo"),
    pytest.param(b"[classes.homelab]\nkeywords = [1]\n", "keywords", id="bad-keyword-type"),
    pytest.param(b'[classes.homelab]\nkeywords = ["Bad!!"]\n', "keywords", id="bad-keyword-chars"),
    pytest.param(b'[classes.homelab]\npaths = ["../etc"]\n', "paths", id="bad-path-hint"),
    pytest.param(b"[classes.homelab]\nprivate = false\n", "private", id="built-in-class-made-public"),
    pytest.param(b"[classes.homelab]\nprivate = true\n", "private", id="private-key-at-all"),
    pytest.param(b'[classes.extra]\nrepo = "o/x"\nprivate = false\n', "private", id="custom-class-made-public"),
    pytest.param(b"[classes.product]\nprivate = true\n", "private", id="product-private-key"),
    pytest.param(b"[classes]\nhomelab = false\n", "must be a table", id="class-removed"),
    pytest.param(b'[classes.tangent]\nvisibility = "public"\n', "unknown key", id="equivalent-key"),
    pytest.param(b'[classes.homelab]\nkeywords = [""]\n', "keywords", id="empty-keyword"),
    pytest.param(b'[classes.homelab]\nkeywords = ["  "]\n', "keywords", id="blank-keyword"),
    pytest.param(b'[classes.homelab]\nkeywords = ["a.*"]\n', "keywords", id="regex-star"),
    pytest.param(b'[classes.homelab]\nkeywords = ["(x"]\n', "keywords", id="regex-paren"),
    pytest.param(b'[classes.homelab]\nkeywords = ["a|b"]\n', "keywords", id="regex-alternation"),
    pytest.param(b'[classes.Bad_Name]\nrepo = "o/x"\n', "class name", id="bad-class-name"),
    pytest.param(b'[classes.extra]\nkeywords = ["x"]\n', "needs a repo", id="new-class-without-repo"),
    pytest.param(b'[classes.product]\nrepo = "o/x"\n', "product", id="product-with-a-repo"),
    pytest.param(b"x = '" + b"a" * 70_000 + b"'\n", "larger than", id="oversize"),
]


@pytest.mark.parametrize(("data", "why"), BAD_FILES)
def test_a_bad_routes_file_is_exit_2_with_a_reason(
    tmp_path: Path, data: bytes, why: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    box = Box(tmp_path, monkeypatch)
    box.agents(tracking_repos=[WORK])
    write_routes(box, data)
    code, out, err = go_real(box, "route", "rebuild the proxmox runner", "--working-repo", WORK)
    assert code == 2 and out == ""
    assert "routes file" in err and why in err
    assert str(box.home) not in err  # the message names the rule, not the path


def test_a_group_writable_routes_file_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.agents(tracking_repos=[WORK])
    write_routes(box, "", mode=0o660)
    code, _, err = go_real(box, "route", "x", "--working-repo", WORK, "--class", "homelab")
    assert code == 2 and "writable by its group or by others" in err


def test_a_symlinked_routes_file_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.agents(tracking_repos=[WORK])
    real = tmp_path / "real.toml"
    real.write_text("")
    real.chmod(0o600)
    d = box.home / ".config" / "safo-file"
    d.mkdir(parents=True, mode=0o700)
    (d / "routes.toml").symlink_to(real)
    code, _, err = go_real(box, "route", "x", "--working-repo", WORK, "--class", "homelab")
    assert code == 2 and "routes file" in err and "symbolic link" in err


def test_a_routes_file_in_a_group_writable_directory_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    box = Box(tmp_path, monkeypatch)
    box.agents(tracking_repos=[WORK])
    path = write_routes(box, "")
    path.parent.chmod(0o770)
    code, _, err = go_real(box, "route", "x", "--working-repo", WORK, "--class", "homelab")
    assert code == 2 and "routes file" in err and "directory" in err


def test_the_routes_file_is_not_under_the_guard_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    box = Box(tmp_path, monkeypatch)
    assert routes.routes_path(box.env["HOME"]) == box.home / ".config" / "safo-file" / "routes.toml"
    assert ".config/safo/" not in str(routes.routes_path(box.env["HOME"]))


# ---- the ledger record --------------------------------------------------------------------------------------------


def test_a_route_is_recorded_as_a_distinct_record_and_report_does_not_count_it(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    assert route(f, "rebuild the proxmox runner")[0] == 0
    assert route(f, "buy more coffee")[0] == 3
    recs = ledger_records(f)
    assert [r["state"] for r in recs] == ["routed", "routed"]
    assert recs[0]["class"] == "homelab" and recs[0]["repo"] == HOMELAB and recs[0]["decided"] is True
    assert recs[0]["how"] == "matched" and "proxmox" in str(recs[0]["matched"])
    assert recs[1]["decided"] is False and recs[1]["how"] == "default"
    assert "buy more coffee" not in f.ledger.read_text()  # the description itself is not stored
    code, out, err = run(f, "report")
    assert code == 0 and "cross-project issues: 0 of 0" in out and "corrupt" not in err


def test_a_route_that_cannot_be_recorded_prints_nothing(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    f.ledger.write_text("")
    f.ledger.chmod(0o666)  # the ledger rules refuse it
    code, out, err = route(f, "rebuild the proxmox runner")
    assert code == 2 and out == "" and "ledger" in err


# ---- the public-repo refusal ------------------------------------------------------------------------------------


def never(repo: str) -> bool:
    raise AssertionError(f"visibility looked up for {repo}")


def issue(f: Fakes, *extra: str, body: str = "b", public: Callable[[str], bool] | None = None) -> tuple[int, str, str]:
    return run(
        f, "issue", "--repo", "o/pub", "--working-repo", "o/pub", "--title", "t", "--body", body, *extra, public=public
    )


@pytest.mark.parametrize("name", ["homelab", "ai-tooling", "research", "tangent"])
def test_a_private_workflow_class_is_refused_in_a_public_repo(tmp_path: Path, name: str) -> None:
    f = Fakes(tmp_path)
    code, _, err = issue(f, "--class", name, public=lambda repo: True)
    assert code == 1 and "public" in err and "--allow-public" in err
    assert f.created == []
    assert ledger_records(f)[-1]["outcome"] == "refused"


@pytest.mark.parametrize("name", ["homelab", "ai-tooling", "research", "tangent"])
def test_a_private_workflow_class_is_filed_in_a_private_repo(tmp_path: Path, name: str) -> None:
    f = Fakes(tmp_path)
    code, out, _ = issue(f, "--class", name, public=lambda repo: False)
    assert code == 0 and len(f.created) == 1 and out.strip().endswith("/1")
    assert [r["state"] for r in ledger_records(f)] == ["pending", "committed"]  # a private target is not a decision


def test_the_override_needs_both_the_flag_and_a_reason_line(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    reason = "public-ok: generic security tracking, no private detail"
    assert issue(f, "--class", "homelab", "--allow-public", public=lambda r: True)[0] == 1  # flag, no line
    assert issue(f, "--class", "homelab", body=reason, public=lambda r: True)[0] == 1  # line, no flag
    assert issue(f, "--class", "homelab", "--allow-public", body=f"```\n{reason}\n```", public=lambda r: True)[0] == 1
    assert issue(f, "--class", "homelab", "--allow-public", body="public-ok:   ", public=lambda r: True)[0] == 1
    assert f.created == []
    code, _, _ = issue(f, "--class", "homelab", "--allow-public", body=f"x\n{reason}", public=lambda r: True)
    assert code == 0 and len(f.created) == 1
    assert ledger_records(f)[-3]["outcome"] == "override"


def test_the_class_is_found_from_the_title_and_body_when_none_is_given(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    code, _, err = run(
        f, "issue", "--repo", "o/pub", "--working-repo", "o/pub",
        "--title", "Rebuild the proxmox runner", "--body", "vlan work", public=lambda r: True,
    )  # fmt: skip
    assert code == 1 and "homelab" in err and f.created == []


def test_a_failed_visibility_lookup_fails_closed(tmp_path: Path) -> None:
    f = Fakes(tmp_path)

    def broken(repo: str) -> bool:
        raise SafoError("gh api failed: not found")

    code, _, err = issue(f, "--class", "homelab", public=broken)
    assert code == 2 and "gh api failed" in err and f.created == []
    d = f.deps()
    d.is_public = None  # no way to look it up at all
    err_io = io.StringIO()
    argv = ["issue", "--repo", "o/pub", "--working-repo", "o/pub", "--title", "t", "--body", "b"]
    assert idea_gate.main(argv, deps=d, out=io.StringIO(), err=err_io, now=NOW) == 2
    assert "cannot tell whether" in err_io.getvalue() and f.created == []


def test_an_unknown_class_on_an_issue_is_an_error(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    assert issue(f, "--class", "nope", public=never)[0] == 2 and f.created == []


# ---- the visibility lookup: the real gh call and the cache ----------------------------------------------------


VIS_GH = """#!/bin/sh
echo "$@" >> "@LOG@/argv"
if [ "$1" = "api" ]; then cat "@LOG@/answer"; exit 0; fi
exit 1
"""


def vis_box(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, answer: str) -> Box:
    box = Box(tmp_path, monkeypatch)
    script(box.bin / "gh", VIS_GH.replace("@LOG@", str(box.log)))
    (box.log / "answer").write_text(answer)
    return box


def test_the_real_lookup_is_live_each_time_and_leaves_no_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    box = vis_box(tmp_path, monkeypatch, "true\n")
    d = box.deps()
    assert d.is_public is not None
    assert d.is_public("o/r") is False
    (box.log / "answer").write_text("false\n")  # the repo became public
    assert d.is_public("o/r") is True
    assert (box.log / "argv").read_text().count("api repos/o/r") == 2
    assert sorted(p.name for p in box.log.iterdir()) == ["answer", "argv"]  # no cache file of any name


@pytest.mark.parametrize("answer", ["maybe\n", "", "true false\n"])
def test_an_unreadable_gh_answer_fails_closed(tmp_path: Path, answer: str, monkeypatch: pytest.MonkeyPatch) -> None:
    box = vis_box(tmp_path, monkeypatch, answer)
    d = box.deps()
    assert d.is_public is not None
    with pytest.raises(SafoError, match="unreadable"):
        d.is_public("o/r")


def test_a_failing_gh_lookup_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    box = Box(tmp_path, monkeypatch)
    box.flag("fail")
    d = box.deps()
    assert d.is_public is not None
    with pytest.raises(SafoError, match="failed"):
        d.is_public("o/r")


def test_a_well_formed_fresh_cache_file_is_never_believed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    box = vis_box(tmp_path, monkeypatch, "false\n")  # the repo is public
    entry = {"repo": "o/r", "public": False, "ts": NOW.isoformat()}
    cache = box.log / "repo-visibility.jsonl"
    cache.write_text(json.dumps(entry) + "\n")
    cache.chmod(0o600)
    d = box.deps()
    assert d.is_public is not None
    assert d.is_public("o/r") is True


# ---- check: the parking-lot default ------------------------------------------------------------------------------


def test_check_defaults_the_parking_repo_to_the_tangent_destination(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    code, out, _ = run(f, "check", "an idea", "--working-repo", WORK, "--answer", "tangent", "--parking-number", "12")
    assert code == 0 and f.comments and f.comments[0][:2] == (WORKBENCH, 12)
    assert f"posted to {WORKBENCH}#12" in out


def test_check_without_a_number_names_the_default_and_posts_nothing(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    code, out, _ = run(f, "check", "an idea", "--working-repo", WORK, "--answer", "tangent")
    assert code == 0 and f.comments == [] and f.created == []
    assert f"parking-lot repo: {WORKBENCH}" in out and "--parking-number" in out


def test_check_uses_the_routes_file_tangent_repo(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    table = routes.default_table()
    bench = [replace(c, repo="o/bench") if c.name == "tangent" else c for c in table.classes]
    custom = routes.RouteTable(tuple(bench))
    code, _, _ = run(
        f, "check", "i", "--working-repo", WORK, "--answer", "tangent", "--parking-number", "3", table=custom
    )
    assert code == 0 and f.comments[0][:2] == ("o/bench", 3)


def test_check_parking_and_parking_number_together_or_a_bad_number_is_an_error(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    base = ("check", "i", "--working-repo", WORK, "--answer", "tangent")
    assert run(f, *base, "--parking", "o/p#1", "--parking-number", "2")[0] == 2
    assert run(f, *base, "--parking-number", "0")[0] == 2
    assert run(f, *base, "--parking-number", "x")[0] == 2
    assert f.comments == []


def test_an_explicit_parking_still_wins_when_given_alone(tmp_path: Path) -> None:
    f = Fakes(tmp_path)
    assert run(f, "check", "i", "--working-repo", WORK, "--answer", "tangent", "--parking", "o/p#1")[0] == 0
    assert f.comments[0][:2] == ("o/p", 1)


def test_the_environment_is_not_consulted_for_the_routes_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    box = Box(tmp_path, monkeypatch)
    other = tmp_path / "other.toml"
    other.write_text('[classes.homelab]\nrepo = "o/evil"\n')
    other.chmod(0o600)
    env = {**box.env, "SAFO_ROUTES": str(other), "XDG_CONFIG_HOME": str(tmp_path)}
    box.agents(tracking_repos=[WORK])
    out = io.StringIO()
    code = idea_gate.main(
        ["route", "rebuild the proxmox runner", "--working-repo", WORK, "--ledger", str(box.log / "l.jsonl")],
        env=env, out=out, err=io.StringIO(), now=NOW,
    )  # fmt: skip
    assert code == 0 and HOMELAB in out.getvalue() and os.path.exists(other)
