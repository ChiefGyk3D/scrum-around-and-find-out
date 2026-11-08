# SPDX-License-Identifier: Apache-2.0
"""The persisted board map and `safo-card`: a card edit is one REST PATCH, never a listing (#358).

The transport is a stub; nothing here writes to GitHub or reaches the network.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from localcli import tool
from safo import boardmap as bm
from safo import card_cli
from safo import ratebudget as rbmod
from safo.errors import ApiError, ConfigError, MalformedDataError, UnknownOutcomeError

PROJECT = "users/ChiefGyk3D/projectsV2/3"
KEY = "ChiefGyk3D/scrum-around-and-find-out#356"


class Stub:
    """Records every request; answers from a table keyed by (method, path prefix)."""

    def __init__(self, replies: dict[tuple[str, str], bm.Reply] | None = None) -> None:
        self.calls: list[tuple[str, str, str | None]] = []
        self.replies = replies or {}

    def __call__(self, method: str, path: str, body: str | None) -> bm.Reply:
        self.calls.append((method, path, body))
        for (m, prefix), reply in self.replies.items():
            if m == method and path.startswith(prefix):
                return reply
        return bm.Reply(True, b"{}")


def seeded() -> bm.BoardMap:
    board = bm.default_map()
    board.items[KEY] = 99
    return board


# the map


def test_default_map_has_the_known_numeric_field_ids() -> None:
    board = bm.default_map()
    assert board.project == PROJECT
    assert {n: f.id for n, f in board.fields.items()} == {
        "Status": 423617716,
        "Kind": 435739141,
        "Effort": 435739176,
        "Epic": 435739203,
    }
    assert board.fields["Effort"].options == {"S": "4c1e9022", "M": "a22f24ba", "L": "4d2af34c"}


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    board = seeded()
    path = tmp_path / "state" / "boardmap.json"
    bm.save(board, path)
    assert bm.load(path) == board
    assert (path.stat().st_mode & 0o077) == 0


def test_load_missing_file_gives_the_default(tmp_path: Path) -> None:
    assert bm.load(tmp_path / "none.json") == bm.default_map()


@pytest.mark.parametrize(
    "text",
    [
        "{not json",
        "[]",
        '{"project": "users/x/projectsV2/3", "project": "users/y/projectsV2/3"}',  # duplicate key
        '{"project": "../../etc", "fields": {}, "items": {}}',
        '{"project": "users/x/projectsV2/3", "fields": {"A": {"id": "7", "options": {}}}, "items": {}}',
        '{"project": "users/x/projectsV2/3", "fields": {"A": {"id": -7, "options": {}}}, "items": {}}',
        '{"project": "users/x/projectsV2/3", "fields": {}, "items": {"not a key": 5}}',
        '{"project": "users/x/projectsV2/3", "fields": {}, "items": {"a/b#1": true}}',
        '{"project": "users/x/projectsV2/3", "fields": {"A": {"id": 7, "options": {"x": 5}}}, "items": {}}',
        "[" * 500 + "]" * 500,
    ],
)
def test_load_rejects_a_bad_map_with_one_error(tmp_path: Path, text: str) -> None:
    path = tmp_path / "m.json"
    path.write_text(text)
    with pytest.raises(ConfigError):
        bm.load(path)


def test_load_rejects_an_oversized_map(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    valid = json.dumps(bm.to_json(bm.default_map())).encode()
    path.write_bytes(valid + b" " * (bm.MAX_MAP_BYTES - len(valid) + 1))  # valid JSON, one byte too many
    with pytest.raises(ConfigError, match="larger"):
        bm.load(path)


def test_load_rejects_a_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    bm.save(seeded(), real)
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(ConfigError):
        bm.load(link)


def test_load_refuses_a_symlinked_state_directory(tmp_path: Path) -> None:
    attacker = tmp_path / "attacker"
    bm.save(seeded(), attacker / "boardmap.json")
    state = tmp_path / "state"
    state.symlink_to(attacker)
    with pytest.raises(ConfigError):
        bm.load(state / "boardmap.json")


def test_load_refuses_a_hard_linked_map(tmp_path: Path) -> None:
    d = tmp_path / "state"
    bm.save(seeded(), d / "boardmap.json")
    (tmp_path / "second-name.json").hardlink_to(d / "boardmap.json")
    with pytest.raises(ConfigError):
        bm.load(d / "boardmap.json")


def test_load_repairs_a_loose_map_mode_and_a_loose_directory(tmp_path: Path) -> None:
    d = tmp_path / "state"
    bm.save(seeded(), d / "boardmap.json")
    d.chmod(0o777)
    (d / "boardmap.json").chmod(0o666)
    assert bm.load(d / "boardmap.json") == seeded()
    assert (d.stat().st_mode & 0o077) == 0
    assert ((d / "boardmap.json").stat().st_mode & 0o077) == 0


def test_load_with_no_directory_gives_the_default(tmp_path: Path) -> None:
    assert bm.load(tmp_path / "never" / "boardmap.json") == bm.default_map()


def test_load_refuses_a_directory_named_as_the_map(tmp_path: Path) -> None:
    (tmp_path / "boardmap.json").mkdir()
    with pytest.raises(ConfigError):
        bm.load(tmp_path / "boardmap.json")


# building the request


def test_one_edit_is_one_patch_with_numeric_ids() -> None:
    req = bm.build_request(seeded(), KEY, {"Effort": "M", "Status": "abcdef12"})
    assert req.method == "PATCH"
    assert req.path == f"{PROJECT}/items/99"
    assert json.loads(req.body) == {
        "fields": [{"id": 435739176, "value": "a22f24ba"}, {"id": 423617716, "value": "abcdef12"}]
    }


def test_clear_sends_null() -> None:
    req = bm.build_request(seeded(), KEY, {"Epic": None})
    assert json.loads(req.body) == {"fields": [{"id": 435739203, "value": None}]}


def test_a_text_field_takes_the_string() -> None:
    req = bm.build_request(seeded(), KEY, {"Epic": "GitHub hygiene and rate limits"})
    assert json.loads(req.body)["fields"][0]["value"] == "GitHub hygiene and rate limits"


def test_a_known_option_id_passes_through() -> None:
    req = bm.build_request(seeded(), KEY, {"Effort": "4c1e9022"})
    assert json.loads(req.body)["fields"][0]["value"] == "4c1e9022"


def test_a_name_not_in_a_closed_option_list_is_refused() -> None:
    with pytest.raises(ConfigError, match="Effort"):
        bm.build_request(seeded(), KEY, {"Effort": "XXL"})


def test_unknown_field_is_refused() -> None:
    with pytest.raises(ConfigError, match="Nope"):
        bm.build_request(seeded(), KEY, {"Nope": "x"})


def test_unmapped_card_is_a_miss_not_a_listing() -> None:
    with pytest.raises(bm.MapMiss):
        bm.build_request(bm.default_map(), KEY, {"Effort": "S"})


def test_no_edits_is_refused() -> None:
    with pytest.raises(ConfigError):
        bm.build_request(seeded(), KEY, {})


@pytest.mark.parametrize("key", ["", "a/b", "a/b#0", "a/b#x", "../a/b#1", "a/b#1/../..", "a b/c#1", "a/b#1?q=1"])
def test_bad_issue_key(key: str) -> None:
    with pytest.raises(ConfigError):
        bm.parse_key(key)


# editing: the measured number


def test_edit_known_card_is_exactly_one_call() -> None:
    stub = Stub()
    bm.edit_card(seeded(), stub, KEY, {"Effort": "M"})
    assert len(stub.calls) == 1
    method, path, body = stub.calls[0]
    assert (method, path) == ("PATCH", f"{PROJECT}/items/99")
    assert body is not None
    assert "/items?" not in path


def test_edit_never_lists_the_board() -> None:
    stub = Stub()
    for effort in ("S", "M", "L"):
        bm.edit_card(seeded(), stub, KEY, {"Effort": effort})
    assert all(m == "PATCH" for m, _, _ in stub.calls)
    assert len(stub.calls) == 3


def test_edit_error_reply_is_an_api_error() -> None:
    stub = Stub({("PATCH", PROJECT): bm.Reply(False, b'{"message":"nope"}', "HTTP 422")})
    with pytest.raises(ApiError):
        bm.edit_card(seeded(), stub, KEY, {"Effort": "M"})
    assert len(stub.calls) == 1  # not replayed


def test_edit_transport_failure_is_unknown_outcome_and_not_replayed() -> None:
    calls = []

    def boom(method: str, path: str, body: str | None) -> bm.Reply:
        calls.append(path)
        raise TimeoutError("slow")

    with pytest.raises(UnknownOutcomeError):
        bm.edit_card(seeded(), boom, KEY, {"Effort": "M"})
    assert len(calls) == 1


# resolving an item once


def issue_reply(title: str = "Persist ids") -> bm.Reply:
    return bm.Reply(True, json.dumps({"number": 356, "title": title}).encode())


def items_reply(*items: dict[str, Any]) -> bm.Reply:
    return bm.Reply(True, json.dumps(list(items)).encode())


def item(item_id: int, number: int, title: str, repo: str = "ChiefGyk3D/scrum-around-and-find-out") -> dict[str, Any]:
    return {
        "id": item_id,
        "content": {"number": number, "title": title, "repository_url": f"https://api.github.com/repos/{repo}"},
    }


def test_resolve_costs_two_reads_once_then_the_map_remembers() -> None:
    stub = Stub(
        {
            ("GET", "repos/"): issue_reply(),
            ("GET", f"{PROJECT}/items"): items_reply(item(7, 12, "other"), item(99, 356, "Persist ids")),
        }
    )
    board = bm.default_map()
    assert bm.resolve_item(board, stub, KEY) == 99
    assert board.items[KEY] == 99
    assert [m for m, _, _ in stub.calls] == ["GET", "GET"]
    assert "q=Persist%20ids" in stub.calls[1][1]
    assert bm.resolve_item(board, stub, KEY) == 99
    assert len(stub.calls) == 2  # the second resolve was free


def test_resolve_refuses_an_ambiguous_match_and_caches_nothing() -> None:
    stub = Stub(
        {
            ("GET", "repos/"): issue_reply(),
            ("GET", f"{PROJECT}/items"): items_reply(item(1, 356, "Persist ids"), item(2, 356, "Persist ids")),
        }
    )
    board = bm.default_map()
    with pytest.raises(MalformedDataError):
        bm.resolve_item(board, stub, KEY)
    assert board.items == {}


def test_resolve_does_not_take_true_for_issue_number_one() -> None:
    stub = Stub(
        {
            ("GET", "repos/"): bm.Reply(True, b'{"title": "t"}'),
            ("GET", f"{PROJECT}/items"): items_reply({"id": 5, "content": {"number": True}}),
        }
    )
    with pytest.raises(MalformedDataError):
        bm.resolve_item(bm.default_map(), stub, "ChiefGyk3D/scrum-around-and-find-out#1")


def test_resolve_requires_a_positive_repository_match() -> None:
    stub = Stub(
        {
            ("GET", "repos/"): issue_reply(),
            ("GET", f"{PROJECT}/items"): items_reply({"id": 99, "content": {"number": 356, "title": "same"}}),
        }
    )
    board = bm.default_map()
    with pytest.raises(MalformedDataError):
        bm.resolve_item(board, stub, KEY)
    assert board.items == {}


def test_save_repairs_a_group_writable_directory(tmp_path: Path) -> None:
    d = tmp_path / "state"
    d.mkdir()
    d.chmod(0o777)
    bm.save(seeded(), d / "boardmap.json")
    assert (d.stat().st_mode & 0o077) == 0


def test_resolve_ignores_a_same_number_in_another_repo() -> None:
    stub = Stub(
        {
            ("GET", "repos/"): issue_reply(),
            ("GET", f"{PROJECT}/items"): items_reply(item(1, 356, "Persist ids", repo="someone/else")),
        }
    )
    with pytest.raises(MalformedDataError):
        bm.resolve_item(bm.default_map(), stub, KEY)


@pytest.mark.parametrize("body", [b"[[[", b'{"a":1}', b'[{"id": "x"}]', b'[{"id": 1, "id": 2}]', b"[1,2]"])
def test_resolve_malformed_listing_is_one_error(body: bytes) -> None:
    stub = Stub({("GET", "repos/"): issue_reply(), ("GET", f"{PROJECT}/items"): bm.Reply(True, body)})
    with pytest.raises(MalformedDataError):
        bm.resolve_item(bm.default_map(), stub, KEY)


# the real transport goes through ghw and so through the ledger


def test_gh_transport_patches_through_the_budget(tmp_path: Path) -> None:
    seen: list[tuple[list[str], str | None]] = []

    def run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        if argv[1:3] == ["api", "user"]:
            return subprocess.CompletedProcess(argv, 0, "octocat\n", "")
        seen.append((argv, kw.get("input")))
        reply = "HTTP/2.0 200 OK\r\nx-ratelimit-limit: 5000\r\nx-ratelimit-remaining: 4999\r\n"
        reply += "x-ratelimit-reset: 4000000000\r\nx-ratelimit-resource: core\r\n\r\n{}"
        return subprocess.CompletedProcess(argv, 0, reply, "")

    env = {"HOME": str(tmp_path), "SAFO_CALLER": "card", "PATH": "/usr/bin", "GH_TOKEN": "tok"}
    transport = bm.gh_transport(env, run=run, sleep=lambda _s: None, gh="/usr/bin/gh")
    bm.edit_card(seeded(), transport, KEY, {"Effort": "S"})
    argv, stdin = seen[0]
    assert argv == ["/usr/bin/gh", "api", "--include", "-X", "PATCH", f"{PROJECT}/items/99", "--input", "-"]
    assert stdin is not None
    assert json.loads(stdin)["fields"][0]["id"] == 435739176
    ledger = tmp_path / ".local" / "state" / "safo" / "ratebudget" / "ledger.jsonl"
    row = json.loads(ledger.read_text().splitlines()[0])
    assert (row["caller"], row["bucket"], row["write"]) == ("card", "core", True)


# the mode


def test_mode_dry_run_prints_the_request_and_sends_nothing(tmp_path: Path) -> None:
    path = tmp_path / ".local" / "state" / "safo" / "ratebudget" / "boardmap.json"
    bm.save(seeded(), path)
    code, out, _ = tool(card_cli.main, KEY, "Effort=M", "--dry-run", home=tmp_path)
    assert code == 0
    assert f"PATCH {PROJECT}/items/99" in out
    assert "a22f24ba" in out


def test_mode_unmapped_card_says_how_to_map_it(tmp_path: Path) -> None:
    code, out, err = tool(card_cli.main, KEY, "Effort=M", "--dry-run", home=tmp_path)
    assert code == 2
    assert "--resolve" in out + err
    assert "--item-id" in out + err


def test_mode_item_id_is_remembered(tmp_path: Path) -> None:
    code, _, _ = tool(card_cli.main, KEY, "Effort=S", "--item-id", "55", "--dry-run", home=tmp_path)
    assert code == 0
    saved = bm.load(tmp_path / ".local" / "state" / "safo" / "ratebudget" / "boardmap.json")
    assert saved.items[KEY] == 55


def test_mode_learns_an_option(tmp_path: Path) -> None:
    code, out, _ = tool(
        card_cli.main,
        KEY,
        "Status=Done",
        "--item-id",
        "55",
        "--option",
        "Status:Done=deadbeef",
        "--dry-run",
        home=tmp_path,
    )
    assert code == 0
    assert "deadbeef" in out


# round 6: a signal-interrupted PATCH is an unknown outcome, never "GitHub refused"


def stub_main(monkeypatch: pytest.MonkeyPatch, code: int, err_text: str) -> None:
    def fake(argv: Any, *, out: Any, err: Any, **_kw: Any) -> int:
        err.write(err_text)
        return code

    monkeypatch.setattr(rbmod, "main", fake)


UNKNOWN_TEXT = (
    "ghw: interrupted by signal {n}; outcome unknown (the call may or may not have been applied); not retried\n"
)


@pytest.mark.parametrize("code", [124, 129, 130, 143])
def test_a_signal_or_timeout_exit_with_the_wrapper_report_is_an_unknown_outcome(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    stub_main(monkeypatch, code, UNKNOWN_TEXT.format(n=code - 128))
    transport = bm.gh_transport({"HOME": "/nonexistent", "GH_TOKEN": "t"})
    with pytest.raises(UnknownOutcomeError):
        bm.edit_card(seeded(), transport, KEY, {"Effort": "M"})


@pytest.mark.parametrize("code", [1, 2, 4, 128, 131, 137, 255])
def test_other_exit_codes_stay_a_refusal(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    stub_main(monkeypatch, code, UNKNOWN_TEXT.format(n=1))
    transport = bm.gh_transport({"HOME": "/nonexistent", "GH_TOKEN": "t"})
    with pytest.raises(ApiError) as caught:
        bm.edit_card(seeded(), transport, KEY, {"Effort": "M"})
    assert not isinstance(caught.value, UnknownOutcomeError)


@pytest.mark.parametrize("code", [129, 130, 143])
def test_a_plain_gh_exit_that_looks_like_a_signal_is_not_assumed_unknown(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    stub_main(monkeypatch, code, "gh: HTTP 422: Validation Failed\n")  # gh's own exit, no wrapper report
    transport = bm.gh_transport({"HOME": "/nonexistent", "GH_TOKEN": "t"})
    with pytest.raises(ApiError) as caught:
        bm.edit_card(seeded(), transport, KEY, {"Effort": "M"})
    assert not isinstance(caught.value, UnknownOutcomeError)


def test_is_unknown_outcome_exit() -> None:
    from safo import ratebudget as rb

    for code in (124, 129, 130, 143):
        assert rb.is_unknown_outcome_exit(code)
    for code in (0, 1, 75, 127, 128, 131, 137, 255):
        assert not rb.is_unknown_outcome_exit(code)
    assert rb.is_unknown_outcome_exit(130, "ghw: interrupted by signal 2; outcome unknown (x); not retried\n")
    assert not rb.is_unknown_outcome_exit(130, "something else\n")


# round 6: two edits that each learn something both persist


def test_two_stale_copies_saved_in_turn_both_persist(tmp_path: Path) -> None:
    path = tmp_path / "state" / "boardmap.json"
    bm.save(bm.default_map(), path)
    a, b = bm.load(path), bm.load(path)  # both started from the same file
    before = bm.to_json(a)
    a.items["o/r#1"] = 11
    b.items["o/r#2"] = 22
    b.fields["Effort"].options["XL"] = "deadbeef"
    bm.merge_save(path, before, a)
    bm.merge_save(path, before, b)
    final = bm.load(path)
    assert final.items == {"o/r#1": 11, "o/r#2": 22}
    assert final.fields["Effort"].options["XL"] == "deadbeef"


def test_concurrent_threads_all_persist(tmp_path: Path) -> None:
    import threading

    path = tmp_path / "state" / "boardmap.json"
    bm.save(bm.default_map(), path)
    start = threading.Barrier(6)

    def worker(n: int) -> None:
        mine = bm.load(path)
        before = bm.to_json(mine)
        start.wait(5)  # every worker holds a copy loaded before any of them saves
        mine.items[f"o/r#{n}"] = 100 + n
        bm.merge_save(path, before, mine)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(1, 7)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert bm.load(path).items == {f"o/r#{n}": 100 + n for n in range(1, 7)}


def test_merge_save_changes_nothing_when_nothing_changed(tmp_path: Path) -> None:
    path = tmp_path / "state" / "boardmap.json"
    bm.save(seeded(), path)
    mine = bm.load(path)
    other = bm.load(path)
    other.items["o/r#9"] = 9
    bm.save(other, path)
    bm.merge_save(path, bm.to_json(mine), mine)  # no diff: must not roll back the other writer
    assert bm.load(path).items["o/r#9"] == 9


# round 7 (#373): the snapshot must not share option dicts with the live board


def test_a_snapshot_does_not_share_the_option_dicts(tmp_path: Path) -> None:
    board = seeded()
    snapshot = bm.to_json(board)
    assert snapshot["fields"]["Effort"]["options"] is not board.fields["Effort"].options
    board.fields["Effort"].options["XL"] = "deadbeef"
    assert "XL" not in snapshot["fields"]["Effort"]["options"]


def test_an_option_learned_after_the_snapshot_is_saved(tmp_path: Path) -> None:
    path = tmp_path / "state" / "boardmap.json"
    bm.save(bm.default_map(), path)
    mine = bm.load(path)
    before = bm.to_json(mine)  # the snapshot is taken first ...
    mine.fields["Effort"].options["XL"] = "deadbeef"  # ... then an option is learned
    bm.merge_save(path, before, mine)
    assert bm.load(path).fields["Effort"].options["XL"] == "deadbeef"
