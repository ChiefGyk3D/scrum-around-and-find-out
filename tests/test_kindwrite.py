# SPDX-License-Identifier: Apache-2.0
"""The rule-driven Kind writer for a board's open cards (#479, phase 1). A fake API stands behind every call.

Nothing here reaches GitHub: the transport is a stateful fake that answers the REST item PATCH and the field read.
"""

from __future__ import annotations

import io
import json
import stat
from pathlib import Path
from typing import Any

import pytest

from safo import boardmap as bm
from safo import kindwrite as kw
from safo.errors import ApiError, ConfigError, UnknownOutcomeError

PROJECT = "users/ChiefGyk3D/projectsV2/11"
OPTIONS = {
    "Feature": "b7cda51d",
    "Bug": "9fb3c9d5",
    "Decision": "457b1a1b",
    "Lesson": "cb43decd",
    "Chore": "6e9eda69",
    "Docs": "36224434",
    "Release": "17f7140f",
    "Epic": "f3e3315b",
}
ALLOWED = frozenset(OPTIONS)
KIND_FIELD_ID, EPIC_FIELD_ID, EFFORT_FIELD_ID = 431337430, 431337431, 431337432


def card(
    n: int,
    *,
    title: str = "plain words",
    labels: tuple[str, ...] = (),
    state: str = "open",
    kind: str | None = None,
    author: str = "ChiefGyk3D",
    type_: str = "Issue",
) -> kw.Card:
    return kw.Card(f"acme/widgets#{n}", 1000 + n, type_, state, title, labels, author, {"Kind": kind})


def board() -> bm.BoardMap:
    return bm.BoardMap(
        PROJECT,
        {
            "Kind": bm.Field(KIND_FIELD_ID, options=dict(OPTIONS)),
            "Epic": bm.Field(EPIC_FIELD_ID, kind="text"),
            "Effort": bm.Field(EFFORT_FIELD_ID, kind="text"),
        },
        {f"acme/widgets#{n}": 1000 + n for n in range(1, 40)},
    )


# the rules


@pytest.mark.parametrize(
    ("labels", "kind", "rule"),
    [
        (("bug",), "Bug", "label:bug"),
        (("enhancement",), "Feature", "label:enhancement"),
        (("feature",), "Feature", "label:feature"),
        (("documentation",), "Docs", "label:documentation"),
        (("chore",), "Chore", "label:chore"),
        (("dependencies",), "Chore", "label:dependencies"),
        (("ci",), "Chore", "label:ci"),
        (("epic",), "Epic", "label:epic"),
        (("release",), "Release", "label:release"),
        (("Bug",), "Bug", "label:bug"),  # label case does not matter
    ],
)
def test_a_label_gives_its_kind(labels: tuple[str, ...], kind: str, rule: str) -> None:
    assert kw.classify(card(1, labels=labels), ALLOWED) == (kind, rule)


def test_labels_beat_the_title_and_conflicting_labels_follow_a_fixed_order() -> None:
    assert kw.classify(card(1, title="fix: x", labels=("enhancement",)), ALLOWED) == ("Feature", "label:enhancement")
    assert kw.classify(card(1, labels=("documentation", "bug", "epic")), ALLOWED) == ("Epic", "label:epic")
    assert kw.classify(card(1, labels=("chore", "enhancement")), ALLOWED) == ("Feature", "label:enhancement")


@pytest.mark.parametrize(
    ("title", "kind", "rule"),
    [
        ("feat: add a thing", "Feature", "prefix:feat"),
        ("feat(api)!: add a thing", "Feature", "prefix:feat"),
        ("fix: a crash", "Bug", "prefix:fix"),
        ("docs: page", "Docs", "prefix:docs"),
        ("chore: tidy", "Chore", "prefix:chore"),
        ("release: v1", "Release", "prefix:release"),
        ("Epic: board hygiene", "Epic", "prefix:epic"),
        ("EPIC : spaced", "Epic", "prefix:epic"),
        ("lesson: never do x", "Lesson", "prefix:lesson"),
        ("decision: use y", "Decision", "prefix:decision"),
    ],
)
def test_a_title_prefix_gives_its_kind(title: str, kind: str, rule: str) -> None:
    assert kw.classify(card(1, title=title), ALLOWED) == (kind, rule)


def test_dependabot_and_bump_pull_requests_are_chores() -> None:
    assert kw.classify(card(1, author="dependabot[bot]", type_="PullRequest"), ALLOWED) == (
        "Chore",
        "author:dependabot",
    )
    assert kw.classify(card(1, title="Bump foo from 1 to 2", type_="PullRequest"), ALLOWED) == ("Chore", "title:bump")
    # an issue by that author is not a dependency bump
    assert kw.classify(card(1, author="dependabot[bot]", type_="Issue"), ALLOWED) is None


@pytest.mark.parametrize(
    "title", ["plain words", "fixing the thing: yes", "unknownprefix: x", "", "feat without colon"]
)
def test_no_label_and_no_prefix_is_residue(title: str) -> None:
    assert kw.classify(card(1, title=title, labels=("needs-maintainer", "hardware")), ALLOWED) is None


def test_a_rule_whose_kind_the_board_does_not_have_is_residue_not_a_guess() -> None:
    assert kw.classify(card(1, labels=("bug",)), frozenset({"Feature"})) is None
    assert kw.classify(card(1, title="lesson: x"), frozenset({"Feature", "Bug"})) is None


def test_propose_covers_only_open_cards_with_an_empty_kind() -> None:
    cards = [
        card(1, labels=("bug",)),
        card(2, labels=("bug",), state="closed"),
        card(3, labels=("bug",), kind="Feature"),
        card(4, title="nothing here"),
        card(5, title="docs: x"),
    ]
    proposal = kw.propose(cards, ALLOWED)
    assert proposal.hits == {"acme/widgets#1": ("Bug", "label:bug"), "acme/widgets#5": ("Docs", "prefix:docs")}
    assert proposal.residue == ["acme/widgets#4"]
    assert proposal.by_rule() == {"label:bug": 1, "prefix:docs": 1}


# the approved map


def write_map(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "map.json"
    path.write_text(text, encoding="utf-8")
    return path


def test_an_approved_map_loads(tmp_path: Path) -> None:
    path = write_map(tmp_path, json.dumps({"acme/widgets#1": "Bug", "acme/widgets#2": "Docs"}))
    assert kw.load_map(path, ALLOWED) == {"acme/widgets#1": "Bug", "acme/widgets#2": "Docs"}


@pytest.mark.parametrize(
    "text",
    [
        '{"acme/widgets#1": "Bugs"}',  # not a board option
        '{"acme/widgets#1": "bug"}',  # case matters: the option is Bug
        '{"acme/widgets#1": ""}',
        '{"acme/widgets#1": null}',
        '{"acme/widgets#1": "Bug", "acme/widgets#1": "Docs"}',  # duplicate key
        '{"acme/widgets#0": "Bug"}',
        '{"not a key": "Bug"}',
        '["acme/widgets#1"]',
        "{broken",
        "",
    ],
)
def test_a_map_with_any_value_the_board_does_not_allow_is_refused_whole(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        kw.load_map(write_map(tmp_path, text), ALLOWED)


def test_a_refusal_names_the_card_but_never_the_value(tmp_path: Path) -> None:
    path = write_map(tmp_path, '{"acme/widgets#1": "TopSecretWord"}')
    with pytest.raises(ConfigError) as caught:
        kw.load_map(path, ALLOWED)
    assert "acme/widgets#1" in str(caught.value) and "TopSecretWord" not in str(caught.value)


def test_a_symlinked_or_oversized_map_is_refused(tmp_path: Path) -> None:
    real = write_map(tmp_path, "{}")
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(ConfigError):
        kw.load_map(link, ALLOWED)
    big = tmp_path / "big.json"
    big.write_text('{"a": "' + "x" * 2_000_000 + '"}', encoding="utf-8")
    with pytest.raises(ConfigError):
        kw.load_map(big, ALLOWED)


# the writer


class FakeApi:
    """Stateful fake: remembers the Kind of each item id; answers PATCH and the field read."""

    def __init__(self, options: dict[str, str] | None = None) -> None:
        self.options = dict(options or OPTIONS)
        self.kinds: dict[int, str | None] = {}
        self.calls: list[tuple[str, str, str | None]] = []
        self.refuse_next = 0
        self.fail_after_send = False

    def __call__(self, method: str, path: str, body: str | None) -> bm.Reply:
        self.calls.append((method, path, body))
        if method == "GET" and path.startswith(f"{PROJECT}/fields"):
            options = [{"id": i, "name": {"raw": n, "html": n}} for n, i in self.options.items()]
            return bm.Reply(True, json.dumps([{"id": KIND_FIELD_ID, "name": "Kind", "options": options}]).encode())
        if method == "PATCH":
            if self.fail_after_send:
                raise TimeoutError("lost")
            if self.refuse_next:
                self.refuse_next -= 1
                return bm.Reply(False, b"", "exit 1: HTTP 422")
            assert body is not None
            (change,) = json.loads(body)["fields"]
            by_id = {i: n for n, i in self.options.items()}
            if change["value"] not in by_id:
                return bm.Reply(False, b"", "exit 1: HTTP 422 unknown option")
            self.kinds[int(path.rsplit("/", 1)[1])] = by_id[change["value"]]
            return bm.Reply(True, b"{}")
        return bm.Reply(False, b"", "unexpected")

    def patches(self) -> list[tuple[str, str, str | None]]:
        return [c for c in self.calls if c[0] == "PATCH"]

    def cards(self, base: list[kw.Card]) -> list[kw.Card]:
        """The cards as the board holds them now: what a fresh read would show."""
        out = []
        for c in base:
            now = self.kinds.get(c.item_id, c.values.get("Kind"))
            out.append(kw.Card(c.key, c.item_id, c.type, c.state, c.title, c.labels, c.author, {"Kind": now}))
        return out


def run_apply(
    cards: list[kw.Card],
    mapping: dict[str, str],
    api: FakeApi,
    *,
    dry: bool = False,
    cap: int | None = None,
    log: io.StringIO | None = None,
) -> tuple[kw.Result, str]:
    out = io.StringIO()
    result = kw.apply_map(
        cards,
        mapping,
        board(),
        api,
        say=lambda line: print(line, file=out),
        dry_run=dry,
        max_writes=cap,
        journal=log or io.StringIO(),
    )
    return result, out.getvalue()


def test_the_writer_sends_one_patch_per_card_and_only_the_kind_field() -> None:
    api = FakeApi()
    cards = [card(1), card(2)]
    result, text = run_apply(cards, {"acme/widgets#1": "Bug", "acme/widgets#2": "Docs"}, api)
    assert result.written == 2 and not result.capped
    assert api.kinds == {1001: "Bug", 1002: "Docs"}
    for _method, path, body in api.patches():
        assert path.startswith(f"{PROJECT}/items/100")
        assert body is not None
        (change,) = json.loads(body)["fields"]
        assert change["id"] == KIND_FIELD_ID  # never the Epic or the Effort field
        assert change["id"] not in (EPIC_FIELD_ID, EFFORT_FIELD_ID)
    assert "SET acme/widgets#1 Kind = Bug" in text


def test_only_open_cards_with_an_empty_kind_are_written() -> None:
    api = FakeApi()
    cards = [card(1, state="closed"), card(2, kind="Feature"), card(3)]
    mapping = {"acme/widgets#1": "Bug", "acme/widgets#2": "Bug", "acme/widgets#3": "Bug", "acme/widgets#9": "Bug"}
    result, text = run_apply(cards, mapping, api)
    assert api.kinds == {1003: "Bug"}
    assert (result.written, result.skipped_closed, result.skipped_set, result.skipped_unknown) == (1, 1, 1, 1)
    assert "SKIP acme/widgets#2: it already has a Kind" in text


def test_a_dry_run_sends_nothing_and_says_what_it_would_write() -> None:
    api = FakeApi()
    result, text = run_apply([card(1), card(2)], {"acme/widgets#1": "Bug", "acme/widgets#2": "Docs"}, api, dry=True)
    assert api.calls == [] and result.written == 0 and result.would_write == 2
    assert "WOULD SET acme/widgets#1 Kind = Bug" in text


def test_the_write_cap_stops_cleanly_and_a_rerun_continues_then_finds_nothing() -> None:
    api = FakeApi()
    cards = [card(n) for n in range(1, 6)]
    mapping = {c.key: "Chore" for c in cards}
    first, text = run_apply(cards, mapping, api, cap=2)
    assert first.written == 2 and first.capped and len(api.patches()) == 2
    assert "stopped at the write cap (2), re-run to continue" in text
    second, _ = run_apply(api.cards(cards), mapping, api, cap=10)
    assert second.written == 3 and not second.capped
    third, text3 = run_apply(api.cards(cards), mapping, api, cap=10)
    assert third.written == 0 and len(api.patches()) == 5  # idempotent: nothing more was sent
    assert "nothing to write" in text3


def test_the_journal_records_old_and_new_values_for_a_rollback() -> None:
    api, log = FakeApi(), io.StringIO()
    run_apply([card(1)], {"acme/widgets#1": "Bug"}, api, log=log)
    row = json.loads(log.getvalue().splitlines()[0])
    assert row == {"key": "acme/widgets#1", "item": 1001, "field": "Kind", "old": None, "new": "Bug"}


def test_the_writer_refuses_a_value_the_board_does_not_allow_even_if_called_directly() -> None:
    api = FakeApi()
    with pytest.raises(ConfigError):
        run_apply([card(1)], {"acme/widgets#1": "Nonsense"}, api)
    assert api.calls == []


def test_a_stale_option_id_is_refreshed_once_and_the_write_retried_once() -> None:
    api = FakeApi()
    api.options["Bug"] = "aaaaaaaa"  # the board regenerated the option ids; the map still holds the old one
    result, _ = run_apply([card(1)], {"acme/widgets#1": "Bug"}, api)
    assert result.written == 1 and api.kinds == {1001: "Bug"}
    methods = [c[0] for c in api.calls]
    assert methods == ["PATCH", "GET", "PATCH"]


def test_a_refusal_that_a_refresh_does_not_explain_is_not_retried() -> None:
    api = FakeApi()
    api.refuse_next = 5
    with pytest.raises(ApiError):
        run_apply([card(1), card(2)], {"acme/widgets#1": "Bug", "acme/widgets#2": "Bug"}, api)
    assert [c[0] for c in api.calls] == ["PATCH", "GET"]  # one refusal, one refresh (ids unchanged), then stop


def test_a_second_refusal_after_a_refresh_stops_the_run() -> None:
    api = FakeApi()
    api.options["Bug"] = "bbbbbbbb"
    api.refuse_next = 2  # even the retry with the fresh id is refused
    with pytest.raises(ApiError):
        run_apply([card(1), card(2)], {"acme/widgets#1": "Bug", "acme/widgets#2": "Bug"}, api)
    assert [c[0] for c in api.calls] == ["PATCH", "GET", "PATCH"]


def test_a_lost_reply_is_an_unknown_outcome_and_nothing_more_is_sent() -> None:
    api = FakeApi()
    api.fail_after_send = True
    with pytest.raises(UnknownOutcomeError):
        run_apply([card(1), card(2)], {"acme/widgets#1": "Bug", "acme/widgets#2": "Bug"}, api)
    assert len(api.patches()) == 1


# the snapshot


def raw_item(n: int, **over: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": 5000 + n,
        "content_type": "Issue",
        "content": {
            "number": n,
            "state": "open",
            "title": f"feat: thing {n}",
            "labels": [{"name": "enhancement"}],
            "repository_url": "https://api.github.com/repos/acme/widgets",
            "user": {"login": "ChiefGyk3D"},
            "closed_at": None,
        },
        "fields": [
            {"name": "Kind", "value": None},
            {"name": "Status", "value": {"id": "x", "name": {"raw": "Backlog", "html": "Backlog"}}},
            {"name": "Epic", "value": None},
        ],
    }
    item.update(over)
    return item


def test_raw_items_reduce_to_cards() -> None:
    (c,) = kw.cards_from_raw([raw_item(7)])
    assert (c.key, c.item_id, c.type, c.state, c.labels, c.author) == (
        "acme/widgets#7",
        5007,
        "Issue",
        "open",
        ("enhancement",),
        "ChiefGyk3D",
    )
    assert c.values["Kind"] is None and c.values["Status"] == "Backlog"


def test_a_raw_item_that_is_not_shaped_as_expected_is_refused() -> None:
    with pytest.raises(ConfigError):
        kw.cards_from_raw([{"id": "nope"}])
    with pytest.raises(ConfigError):
        kw.cards_from_raw([raw_item(1), raw_item(1)])  # the same card twice


def test_kind_options_are_read_from_the_field_listing() -> None:
    fields = [{"id": KIND_FIELD_ID, "name": "Kind", "options": [{"id": "b7cda51d", "name": {"raw": "Feature"}}]}]
    assert kw.kind_options(fields) == (KIND_FIELD_ID, {"Feature": "b7cda51d"})
    with pytest.raises(ConfigError):
        kw.kind_options([{"id": 1, "name": "Epic"}])


class FakeGh:
    """Stands in for subprocess.run for `gh api -i`: serves pages with a Link header, records every call."""

    def __init__(self, pages: list[list[dict[str, Any]]]) -> None:
        self.pages = pages
        self.argv: list[list[str]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> Any:
        self.argv.append(argv)
        path = argv[-1]
        if "/fields" in path:
            names = ["Status", "Area", "Priority", "Kind", "Epic", "Effort", "Done on", "Title"]
            fields = [{"id": 100 + i, "name": n, "data_type": "text"} for i, n in enumerate(names)]
            done = type("Done", (), {})()
            done.returncode, done.stdout, done.stderr = 0, "HTTP/2.0 200 OK\r\n\r\n" + json.dumps(fields), ""
            return done
        index = int(path.split("after=p")[1].split("&")[0]) if "after=p" in path else 0
        link = (
            f'Link: <https://api.github.com/user/1/projectsV2/11/items?per_page=100&after=p{index + 1}>; rel="next"\r\n'
        )
        head = "HTTP/2.0 200 OK\r\n" + (link if index + 1 < len(self.pages) else "") + "\r\n"
        done = type("Done", (), {})()
        done.returncode, done.stdout, done.stderr = 0, head + json.dumps(self.pages[index]), ""
        return done


def test_the_board_is_read_page_by_page_with_a_pause_and_saved_privately(tmp_path: Path) -> None:
    gh = FakeGh([[raw_item(1), raw_item(2)], [raw_item(3)]])
    pauses: list[float] = []
    target = tmp_path / "snap"
    n = kw.read_board(PROJECT, target, run=gh, gh="gh", sleep=pauses.append, now="2026-11-26T00:00:00+00:00")
    assert n == 3 and len([a for a in gh.argv if "/items" in a[-1]]) == 2 and pauses and all(p >= 1 for p in pauses)
    assert all(a[0] == "gh" and "graphql" not in " ".join(a) for a in gh.argv)
    assert stat.S_IMODE(target.stat().st_mode) == 0o700
    assert stat.S_IMODE((target / "items.json").stat().st_mode) == 0o600
    assert len(kw.load_cards(target)) == 3
    again = kw.read_board(
        PROJECT, target, run=FakeGh([[raw_item(9)]]), gh="gh", sleep=lambda s: None, now="2026-11-26T01:00:00+00:00"
    )
    assert again == 1 and len(kw.load_cards(target)) == 1
    assert len(list(target.glob("items-*.json"))) == 1  # the earlier read is kept for a rollback


def test_a_read_that_fails_or_never_ends_stops_with_nothing_saved(tmp_path: Path) -> None:
    def broken(argv: list[str], **kwargs: Any) -> Any:
        return type("Done", (), {"returncode": 1, "stdout": "", "stderr": "HTTP 502"})()

    with pytest.raises(ApiError):
        kw.read_board(PROJECT, tmp_path / "s", run=broken, gh="gh", sleep=lambda s: None, now="t")
    assert not (tmp_path / "s" / "items.json").exists()
    endless = FakeGh([[raw_item(1)]] * 1000)
    with pytest.raises(ApiError):
        kw.read_board(PROJECT, tmp_path / "e", run=endless, gh="gh", sleep=lambda s: None, now="t", max_pages=5)


# the command line


def snapshot_dir(tmp_path: Path, items: list[dict[str, Any]]) -> Path:
    directory = tmp_path / "snap"
    directory.mkdir(mode=0o700)
    fields = [
        {"id": KIND_FIELD_ID, "name": "Kind", "options": [{"id": i, "name": {"raw": n}} for n, i in OPTIONS.items()]}
    ]
    (directory / "items.json").write_text(json.dumps(items), encoding="utf-8")
    (directory / "fields.json").write_text(json.dumps(fields), encoding="utf-8")
    return directory


def test_the_command_reports_proposes_and_dry_runs_a_map_without_any_write(tmp_path: Path) -> None:
    from localcli import cli

    items = [raw_item(1), raw_item(2, content_type="Issue"), raw_item(3)]
    items[1]["content"]["labels"] = []
    items[1]["content"]["title"] = "no clue"
    directory = snapshot_dir(tmp_path, items)
    proposal, residue = tmp_path / "proposal.json", tmp_path / "residue.json"
    code, out, err = cli(
        "kind", "--snapshot-dir", str(directory), "--propose", str(proposal), "--residue", str(residue), home=tmp_path
    )
    assert code == 0, err
    assert "rule hits 2, residue (no rule, never written) 1" in out and "rule label:enhancement: 2" in out
    assert json.loads(proposal.read_text()) == {"acme/widgets#1": "Feature", "acme/widgets#3": "Feature"}
    assert json.loads(residue.read_text()) == {"acme/widgets#2": "no clue"}
    assert stat.S_IMODE(proposal.stat().st_mode) == 0o600
    code, out, err = cli(
        "--dry-run",
        "kind",
        "--snapshot-dir",
        str(directory),
        "--project",
        PROJECT,
        "--map",
        str(proposal),
        home=tmp_path,
    )
    assert code == 0, err
    assert "WOULD SET acme/widgets#1 Kind = Feature" in out
    assert not (directory / "kind-writes.jsonl").exists()  # a dry run journals nothing


def test_the_command_refuses_a_map_with_a_value_the_board_lacks_before_anything_else(tmp_path: Path) -> None:
    from localcli import cli

    directory = snapshot_dir(tmp_path, [raw_item(1)])
    bad = tmp_path / "bad.json"
    bad.write_text('{"acme/widgets#1": "Bugs"}', encoding="utf-8")
    code, out, err = cli(
        "kind", "--snapshot-dir", str(directory), "--project", PROJECT, "--map", str(bad), home=tmp_path
    )
    assert code == 2 and "refused" in err and "Bugs" not in out + err


def test_the_command_never_overwrites_a_proposal_file(tmp_path: Path) -> None:
    from localcli import cli

    directory = snapshot_dir(tmp_path, [raw_item(1)])
    target = tmp_path / "p.json"
    target.write_text("keep", encoding="utf-8")
    code, _, err = cli("kind", "--snapshot-dir", str(directory), "--propose", str(target), home=tmp_path)
    assert code == 2 and "already exists" in err
    assert target.read_text() == "keep"


def test_the_option_ids_are_refreshed_once_per_run_not_once_per_card() -> None:
    api = FakeApi()
    api.options["Bug"] = "cccccccc"  # stale for the first card only: the refresh fixes it for the rest
    original = api.__call__
    state = {"patches": 0}

    def flaky(method: str, path: str, body: str | None) -> bm.Reply:
        if method == "PATCH":
            state["patches"] += 1
            if state["patches"] == 3:  # the second card is refused for a reason a refresh does not explain
                api.calls.append((method, path, body))
                return bm.Reply(False, b"", "exit 1: HTTP 422")
        return original(method, path, body)

    out = io.StringIO()
    cards = [card(1), card(2)]
    with pytest.raises(ApiError):
        kw.apply_map(
            cards,
            {"acme/widgets#1": "Bug", "acme/widgets#2": "Bug"},
            board(),
            flaky,
            say=lambda line: print(line, file=out),
            dry_run=False,
            max_writes=None,
            journal=io.StringIO(),
        )
    assert [c[0] for c in api.calls] == ["PATCH", "GET", "PATCH", "PATCH"]  # one refresh only


def test_a_pull_request_names_its_repository_through_its_url() -> None:
    item = raw_item(8, content_type="PullRequest")
    del item["content"]["repository_url"]
    item["content"]["url"] = "https://api.github.com/repos/acme/widgets/pulls/8"
    (c,) = kw.cards_from_raw([item])
    assert c.key == "acme/widgets#8" and c.type == "PullRequest"
    del item["content"]["url"]
    with pytest.raises(ConfigError):
        kw.cards_from_raw([item])
