# SPDX-License-Identifier: Apache-2.0
"""safo-threads against a fake `gh` on PATH (issue #587). Nothing reaches the network."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from safo import threads

REPO = "o/r"

STUB = textwrap.dedent(
    """\
    #!{python}
    import json, os, sys
    path = os.environ["FAKE_STATE"]
    state = json.load(open(path))
    argv = sys.argv[1:]
    state["calls"].append(argv)

    def reply(item):
        json.dump(state, open(path, "w"))
        sys.stdout.write(item.get("out", ""))
        sys.exit(item.get("rc", 0))

    if argv[:2] == ["api", "graphql"]:
        text = " ".join(argv)
        if "resolveReviewThread" in text:
            reply(state["resolve"].pop(0) if len(state["resolve"]) > 1 else state["resolve"][0])
        pages = state["pages"]
        reply(pages.pop(0) if len(pages) > 1 else pages[0])
    reply(state["reply"].pop(0) if len(state["reply"]) > 1 else state["reply"][0])
    """
)


def node(
    cid: int, path: str = "a.py", *, resolved: bool = False, outdated: bool = False, body: str = "fix"
) -> dict[str, Any]:
    return {
        "id": f"PRRT_{cid}",
        "isResolved": resolved,
        "isOutdated": outdated,
        "path": path,
        "line": 7,
        "comments": {"nodes": [{"databaseId": cid, "author": {"login": "rev"}, "body": body}]},
    }


def page(nodes: list[dict[str, Any]], more: bool = False, cursor: str = "") -> dict[str, Any]:
    block = {"nodes": nodes, "pageInfo": {"hasNextPage": more, "endCursor": cursor}}
    return {"data": {"repository": {"pullRequest": {"reviewThreads": block}}}}


OK_RESOLVE = {"out": json.dumps({"data": {"resolveReviewThread": {"thread": {"isResolved": True}}}})}


class Rig:
    def __init__(self, tmp: Path, monkeypatch: pytest.MonkeyPatch):
        self.tmp = tmp
        self.bin = tmp / "bin"
        self.bin.mkdir()
        f = self.bin / "gh"
        f.write_text(STUB.format(python=sys.executable), encoding="utf-8")
        f.chmod(f.stat().st_mode | stat.S_IXUSR)
        self.state_path = tmp / "state.json"
        self.state: dict[str, Any] = {
            "calls": [],
            "pages": [{"out": json.dumps(page([node(1), node(2, "b.py")]))}],
            "reply": [{"rc": 0}],
            "resolve": [OK_RESOLVE],
        }
        monkeypatch.setenv("FAKE_STATE", str(self.state_path))
        (tmp / "work").mkdir()
        monkeypatch.chdir(tmp / "work")  # gh must not live under the working directory

    def go(self, *argv: str) -> tuple[int, str, str, list[list[str]]]:
        self.state_path.write_text(json.dumps(self.state), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        code = threads.main([*argv], env={"PATH": str(self.bin), "FAKE_STATE": str(self.state_path)}, out=out, err=err)
        calls = json.loads(self.state_path.read_text(encoding="utf-8"))["calls"]
        return code, out.getvalue(), err.getvalue(), calls

    def apply(self, rows: Any, raw: str | None = None) -> tuple[int, str, str, list[list[str]]]:
        f = self.tmp / "d.json"
        f.write_text(raw if raw is not None else json.dumps(rows), encoding="utf-8")
        return self.go("apply", REPO, "5", str(f))


@pytest.fixture
def rig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Rig:
    return Rig(tmp_path, monkeypatch)


def writes(calls: list[list[str]]) -> list[list[str]]:
    return [c for c in calls if "POST" in c or any("resolveReviewThread" in a for a in c)]


def pages_of(*nodes_per_page: list[dict[str, Any]]) -> list[dict[str, Any]]:
    last = len(nodes_per_page) - 1
    return [{"out": json.dumps(page(n, i < last, f"c{i}"))} for i, n in enumerate(nodes_per_page)]


# list


def test_list_groups_by_file_and_drops_resolved_and_outdated(rig: Rig) -> None:
    nodes = [node(1, "b.py"), node(2, "a.py"), node(3, "a.py", resolved=True), node(4, "a.py", outdated=True)]
    rig.state["pages"] = pages_of(nodes)
    code, out, _err, calls = rig.go("list", REPO, "5")
    assert code == 0
    lines = out.splitlines()
    assert lines[0] == "a.py" and lines[1].startswith("  2 a.py:7 rev: fix")
    assert lines[2] == "b.py" and lines[3].startswith("  1 ")
    assert "  3 a.py" not in out and "  4 a.py" not in out and "2 unresolved" in out
    assert writes(calls) == []


def test_list_cuts_body_to_200_and_strips_control_characters(rig: Rig) -> None:
    body = chr(27) + "[31m\nline2 ::error::boom " + "y" * 400
    rig.state["pages"] = pages_of([node(1, body=body)])
    _code, out, _err, _calls = rig.go("list", REPO, "5")
    row = out.splitlines()[1]
    assert chr(27) not in out and "::error" not in out and "\\x1b" in row
    assert row.count("y") < 400 and len(row.split(": ", 1)[1]) <= 200 + 20


def test_list_paginates_and_is_bounded(rig: Rig) -> None:
    rig.state["pages"] = pages_of([node(1)], [node(2)], [node(3)])
    code, out, _err, calls = rig.go("list", REPO, "5")
    assert code == 0 and "3 unresolved" in out and len(calls) == 3
    assert any(a == "cursor=c1" for a in calls[2])
    rig.state["calls"] = []
    rig.state["pages"] = [{"out": json.dumps(page([node(1)], True, "again"))}]  # never ends
    code, _out, err, calls = rig.go("list", REPO, "5")
    assert code == threads.EXIT_READ and "not read in full" in err and len(calls) == 20


def test_list_gh_failure_and_bad_shape_are_exit_4(rig: Rig) -> None:
    rig.state["pages"] = [{"rc": 1, "out": ""}]
    assert rig.go("list", REPO, "5")[0] == threads.EXIT_READ
    rig.state["pages"] = [{"out": json.dumps({"data": {"nope": 1}})}]
    assert rig.go("list", REPO, "5")[0] == threads.EXIT_READ
    rig.state["pages"] = [{"out": "not json"}]
    assert rig.go("list", REPO, "5")[0] == threads.EXIT_READ
    rig.state["pages"] = [{"out": json.dumps({"errors": [{"message": "x"}], "data": None})}]
    assert rig.go("list", REPO, "5")[0] == threads.EXIT_READ


@pytest.mark.parametrize("flag", [0, 1, "false", None, "", []])
def test_a_non_boolean_has_next_page_is_exit_4_and_apply_writes_nothing(rig: Rig, flag: Any) -> None:
    bad = page([node(1)])
    bad["data"]["repository"]["pullRequest"]["reviewThreads"]["pageInfo"]["hasNextPage"] = flag
    rig.state["pages"] = [{"out": json.dumps(bad)}]
    assert rig.go("list", REPO, "5")[0] == threads.EXIT_READ
    code, _o, _e, calls = rig.apply([{"comment_id": 1, "action": "reply", "body": "a"}])
    assert code == threads.EXIT_READ and writes(calls) == []


def test_bad_repo_or_number_is_usage_exit_2(rig: Rig) -> None:
    assert rig.go("list", "../x", "5")[0] == threads.EXIT_USAGE
    assert rig.go("list", "o/..", "5")[0] == threads.EXIT_USAGE
    assert rig.go("list", REPO, "0")[0] == threads.EXIT_USAGE


# apply


def test_apply_replies_by_rest_and_resolves_with_one_mutation_per_thread(rig: Rig) -> None:
    code, out, _err, calls = rig.apply(
        [
            {"comment_id": 1, "action": "reply_resolve", "body": "done"},
            {"comment_id": 2, "action": "reply", "body": "see below"},
        ]
    )
    assert code == 0, out
    w = writes(calls)
    assert w[0][:4] == ["api", "-X", "POST", f"repos/{REPO}/pulls/5/comments/1/replies"] and "body=done" in w[0]
    assert w[2][3].endswith("/comments/2/replies")
    mutations = [c for c in calls if any("resolveReviewThread" in a for a in c)]
    assert len(mutations) == 1 and "id=PRRT_1" in mutations[0]
    assert len(w) == 3


def test_skip_makes_no_write(rig: Rig) -> None:
    code, out, _err, calls = rig.apply([{"comment_id": 1, "action": "skip"}])
    assert code == 0 and "skip 1" in out and writes(calls) == []


@pytest.mark.parametrize(
    "rows",
    [
        [{"comment_id": 99, "action": "reply", "body": "x"}],  # unknown id
        [{"comment_id": 1, "action": "reply", "body": "  "}],  # empty body
        [{"comment_id": 1, "action": "reply", "body": "x" * 2001}],
        [{"comment_id": 1, "action": "reply", "body": "a"}, {"comment_id": 1, "action": "skip"}],  # duplicate id
        [{"comment_id": 1, "action": "delete", "body": "a"}],
        [{"comment_id": "1", "action": "reply", "body": "a"}],
        [{"comment_id": True, "action": "reply", "body": "a"}],
        [{"comment_id": 1, "action": "reply", "body": "a", "extra": 1}],
        [{"comment_id": 1, "action": "reply"}],
        [{"comment_id": 1, "action": "skip", "body": "typo"}],  # skip takes no body
        [{"comment_id": 1, "action": "reply", "body": "a" + chr(0) + "b"}],  # NUL cannot go in argv
        [{"comment_id": 1, "action": "reply", "body": "a" + chr(0xD800)}],  # lone surrogate cannot be encoded
        [],
        {"comment_id": 1},
        [{"comment_id": 1, "action": "reply", "body": "ok"}, {"comment_id": 99, "action": "skip"}],  # later bad row
    ],
)
def test_a_refused_file_writes_nothing_and_exits_3(rig: Rig, rows: Any) -> None:
    code, _out, _err, calls = rig.apply(rows)
    assert code == threads.EXIT_FILE and writes(calls) == []


def test_body_of_exactly_2000_is_accepted(rig: Rig) -> None:
    code, *_ = rig.apply([{"comment_id": 1, "action": "reply", "body": "x" * 2000}])
    assert code == 0


def test_duplicate_json_keys_nan_and_depth_are_refused(rig: Rig) -> None:
    dup = '[{"comment_id":1,"action":"reply","body":"a","body":"b"}]'
    for raw in (dup, '[{"comment_id":NaN,"action":"skip"}]', "[" * 100 + "]" * 100):
        code, _o, _e, calls = rig.apply(None, raw)
        assert code == threads.EXIT_FILE and writes(calls) == []


def test_resolved_or_outdated_thread_ids_are_unknown_to_apply(rig: Rig) -> None:
    rig.state["pages"] = pages_of([node(1, resolved=True), node(2, outdated=True)])
    for cid in (1, 2):
        code, _o, _e, calls = rig.apply([{"comment_id": cid, "action": "reply", "body": "a"}])
        assert code == threads.EXIT_FILE and writes(calls) == []


def test_file_must_be_a_regular_file_and_exist(rig: Rig) -> None:
    assert rig.go("apply", REPO, "5", str(rig.tmp / "missing.json"))[0] == threads.EXIT_FILE
    link = rig.tmp / "link.json"
    (rig.tmp / "real.json").write_text(json.dumps([{"comment_id": 1, "action": "skip"}]))
    link.symlink_to(rig.tmp / "real.json")
    assert rig.go("apply", REPO, "5", str(link))[0] == threads.EXIT_FILE
    fifo = rig.tmp / "pipe.json"
    os.mkfifo(fifo)
    assert rig.go("apply", REPO, "5", str(fifo))[0] == threads.EXIT_FILE
    big = rig.tmp / "big.json"
    big.write_text(" " * (threads.FILE_LIMIT + 5))
    assert rig.go("apply", REPO, "5", str(big))[0] == threads.EXIT_FILE


def test_failed_reply_stops_exit_5_never_retries_and_never_resolves(rig: Rig) -> None:
    rig.state["reply"] = [{"rc": 1}]
    code, _out, err, calls = rig.apply(
        [
            {"comment_id": 1, "action": "reply_resolve", "body": "a"},
            {"comment_id": 2, "action": "reply", "body": "b"},
        ]
    )
    assert code == threads.EXIT_WRITE and "not retried" in err
    assert len(writes(calls)) == 1  # one POST, no mutation, no second item


def test_resolve_failure_is_exit_5_and_says_the_reply_posted(rig: Rig) -> None:
    for bad in (
        {"rc": 1},
        {"out": json.dumps({"data": {"resolveReviewThread": {"thread": {"isResolved": False}}}})},
        {"out": json.dumps({"errors": [{"message": "x"}], "data": None})},
        {"out": "junk"},
    ):
        rig.state["calls"] = []
        rig.state["resolve"] = [bad]
        code, out, err, _calls = rig.apply([{"comment_id": 1, "action": "reply_resolve", "body": "a"}])
        assert code == threads.EXIT_WRITE and "posted, but the thread was not resolved" in err and "replied 1" in out


def test_gh_missing_is_exit_4(rig: Rig) -> None:
    out, err = io.StringIO(), io.StringIO()
    code = threads.main(["list", REPO, "5"], env={"PATH": str(rig.tmp / "nowhere")}, out=out, err=err)
    assert code == threads.EXIT_READ


def test_no_token_is_read_or_printed() -> None:
    src = Path(threads.__file__).read_text(encoding="utf-8")
    assert "GH_TOKEN" not in src and "GITHUB_TOKEN" not in src


def test_entry_point_is_declared_and_dispatch_guard_untouched() -> None:
    root = Path(__file__).parent.parent
    assert 'safo-threads = "safo.threads:run"' in (root / "pyproject.toml").read_text(encoding="utf-8")
    assert "threads" not in (root / "src/safo/guard.py").read_text(encoding="utf-8")


def test_an_argument_encoding_error_from_the_subprocess_is_a_controlled_failure() -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise UnicodeEncodeError("utf-8", "x", 0, 1, "surrogate")

    assert threads.Gh("gh", {}, boom).call("api") == (127, "")
