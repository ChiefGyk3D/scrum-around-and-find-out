# SPDX-License-Identifier: Apache-2.0
"""safo-protect-threads against a fake gh/GraphQL layer that behaves like GitHub's updateBranchProtectionRule: the
mutation changes only the fields it is given (issue #541). Nothing reaches the network."""

from __future__ import annotations

import copy
import io
import json
import re
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from safo import protect_threads as pt

REPO = "o/r"
SECRET = "ghp_SECRETSECRETSECRET"


def rule(rule_id: str = "BPR_1", pattern: str = "main", *, flag: bool = False, **over: Any) -> dict[str, Any]:
    """A rule with every field set to something other than its default, as GitHub's GraphQL shows it."""
    base: dict[str, Any] = {
        "id": rule_id,
        "pattern": pattern,
        "allowsDeletions": True,
        "allowsForcePushes": True,
        "blocksCreations": True,
        "dismissesStaleReviews": True,
        "isAdminEnforced": True,
        "lockAllowsFetchAndMerge": True,
        "lockBranch": True,
        "requireLastPushApproval": True,
        "requiresApprovingReviews": True,
        "requiresCodeOwnerReviews": True,
        "requiresCommitSignatures": True,
        pt.FLAG: flag,
        "requiresDeployments": True,
        "requiresLinearHistory": True,
        "requiresStatusChecks": True,
        "requiresStrictStatusChecks": True,
        "restrictsPushes": True,
        "restrictsReviewDismissals": True,
        "requiredApprovingReviewCount": 2,
        "requiredDeploymentEnvironments": ["prod"],
        "requiredStatusCheckContexts": ["ci / CI green", "legacy"],
        "requiredStatusChecks": [
            {"context": "ci / CI green", "app": {"databaseId": 15368}},
            {"context": "legacy", "app": None},
        ],
        "pushAllowances": {"totalCount": 3},
        "bypassPullRequestAllowances": {"totalCount": 2},
        "bypassForcePushAllowances": {"totalCount": 1},
        "reviewDismissalAllowances": {"totalCount": 4},
    }
    base.update(over)
    return base


class Fake:
    """Stands in for `subprocess.run`: answers the `gh api` calls of the tool and records each one."""

    def __init__(self, rules: list[dict[str, Any]], *, ruleset_rules: list[Any] | None = None) -> None:
        self.rules = rules
        self.ruleset_rules: list[Any] = ruleset_rules or []
        self.calls: list[list[str]] = []
        self.envs: list[Any] = []
        self.mutation_rc = 0
        self.mutation_applies = True
        self.after_mutation: Callable[[dict[str, Any]], None] | None = None
        self.read_rc = 0
        self.has_next = False
        self.branch = "main"

    def mutations(self) -> list[list[str]]:
        return [c for c in self.calls if any("mutation" in a for a in c)]

    def __call__(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        self.envs.append(kw.get("env"))
        assert kw.get("timeout"), "every call is bounded"
        assert kw.get("stdin") == subprocess.DEVNULL
        args = argv[1:]
        assert args[0] == "api"
        if args[1] == "graphql":
            fields = dict(a.split("=", 1) for a in args[2:] if "=" in a)
            query = fields["query"]
            if self.read_rc:
                return subprocess.CompletedProcess(argv, self.read_rc, "", "denied " + SECRET)
            if query.startswith("mutation"):
                return self.mutate(argv, query, fields["id"])
            ref = fields["q"]
            nodes = [
                {
                    **{k: v for k, v in r.items()},
                    "matchingRefs": {"nodes": [{"name": ref}] if self.covers(r, ref) else []},
                }
                for r in self.rules
            ]
            data = {
                "repository": {
                    "defaultBranchRef": {"name": self.branch},
                    "branchProtectionRules": {"pageInfo": {"hasNextPage": self.has_next}, "nodes": nodes},
                }
            }
            return subprocess.CompletedProcess(argv, 0, json.dumps({"data": data}), "")
        if args[-1] == f"repos/{REPO}/rules/branches/{self.branch}":
            return subprocess.CompletedProcess(argv, 0, json.dumps(self.ruleset_rules), "")
        raise AssertionError(f"unexpected call {argv}")

    @staticmethod
    def covers(r: dict[str, Any], ref: str) -> bool:
        return bool(ref) and (r["pattern"] == ref or r["pattern"] == "*")

    def mutate(self, argv: list[str], query: str, rule_id: str) -> subprocess.CompletedProcess[str]:
        assert re.fullmatch(
            r"mutation\(\$id:ID!\)\{updateBranchProtectionRule\(input:\{branchProtectionRuleId:\$id,requiresConversationResolution:(true|false)\}\)\{branchProtectionRule\{requiresConversationResolution\}\}\}",
            query,
        ), query
        value = query.split("requiresConversationResolution:")[1].startswith("true")
        if self.mutation_applies:
            target = next(r for r in self.rules if r["id"] == rule_id)
            target[pt.FLAG] = value  # only the one field: that is the property being relied on
            if self.after_mutation:
                self.after_mutation(target)
        return subprocess.CompletedProcess(argv, self.mutation_rc, "{}", "boom " + SECRET)


class Rig:
    def __init__(self, tmp: Path, monkeypatch: pytest.MonkeyPatch, fake: Fake) -> None:
        self.tmp, self.fake = tmp, fake
        (tmp / "bin").mkdir()
        gh = tmp / "bin" / "gh"
        gh.write_text("#!/bin/sh\n", encoding="utf-8")
        gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
        (tmp / "work").mkdir()
        (tmp / "backups").mkdir()
        monkeypatch.chdir(tmp / "work")
        self.backups = tmp / "backups"
        self.on_mutation: Callable[[], None] | None = None

    def go(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        env = {"PATH": str(self.tmp / "bin"), "GH_TOKEN": SECRET}
        code = pt.main([*argv], env=env, out=out, err=err, run=self.fake, now=lambda: "20261127T120000Z")
        return code, out.getvalue(), err.getvalue()

    def apply(self) -> tuple[int, str, str]:
        return self.go(REPO, "--apply", "--backup-dir", str(self.backups))


def make(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rules: list[dict[str, Any]] | None = None, **kw: Any) -> Rig:
    return Rig(tmp_path, monkeypatch, Fake([rule()] if rules is None else rules, **kw))


# -- dry run (the default) ---------------------------------------------------------------------------------------


def test_dry_run_reads_only_and_prints_the_one_field_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rig = make(tmp_path, monkeypatch)
    code, out, err = rig.go(REPO)
    assert code == 0 and err == ""
    assert rig.fake.mutations() == []
    changed = [ln for ln in out.splitlines() if ln[:1] in "+-" and ln[:3] not in ("+++", "---")]
    assert changed == ['-  "requiresConversationResolution": false,', '+  "requiresConversationResolution": true,']
    assert "dry run" in out and "--apply" in out and SECRET not in out
    assert not list(rig.backups.iterdir())


def test_dry_run_names_a_pattern_that_covers_more_than_the_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = make(tmp_path, monkeypatch, [rule(pattern="*")])
    code, out, _ = rig.go(REPO)
    assert code == 0 and "NOTE" in out and "'*'" in out


def test_already_true_changes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rig = make(tmp_path, monkeypatch, [rule(flag=True)])
    code, out, _ = rig.apply()
    assert code == 0 and "already" in out and rig.fake.mutations() == []
    assert not list(rig.backups.iterdir())


# -- refusals ----------------------------------------------------------------------------------------------------


def test_a_ruleset_on_the_default_branch_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rig = make(tmp_path, monkeypatch, ruleset_rules=[{"type": "pull_request", "ruleset_id": 5}])
    for argv in ((REPO,), (REPO, "--apply", "--backup-dir", str(rig.backups))):
        code, _out, err = rig.go(*argv)
        assert code == pt.EXIT_REFUSED and "ruleset" in err
    assert rig.fake.mutations() == [] and not list(rig.backups.iterdir())


def test_no_covering_rule_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rig = make(tmp_path, monkeypatch, [rule(pattern="release")])
    code, _out, err = rig.apply()
    assert code == pt.EXIT_REFUSED and "no branch protection rule" in err and rig.fake.mutations() == []


def test_two_covering_rules_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rig = make(tmp_path, monkeypatch, [rule("BPR_1"), rule("BPR_2", pattern="*")])
    code, _out, err = rig.apply()
    assert code == pt.EXIT_REFUSED and "2 protection rules" in err and rig.fake.mutations() == []


def test_a_second_page_of_rules_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rig = make(tmp_path, monkeypatch)
    rig.fake.has_next = True
    code, _out, err = rig.apply()
    assert code == pt.EXIT_REFUSED and "more protection rules" in err and rig.fake.mutations() == []


UNREADABLE = [
    ("flag missing", lambda r: r.pop("lockBranch"), "lockBranch"),
    ("flag text", lambda r: r.update(lockBranch="yes"), "lockBranch"),
    ("count text", lambda r: r.update(requiredApprovingReviewCount="2"), "requiredApprovingReviewCount"),
    ("count bool", lambda r: r.update(requiredApprovingReviewCount=True), "requiredApprovingReviewCount"),
    ("contexts not list", lambda r: r.update(requiredStatusCheckContexts="x"), "requiredStatusCheckContexts"),
    ("check without context", lambda r: r.update(requiredStatusChecks=[{"app": None}]), "requiredStatusChecks"),
    (
        "check app id text",
        lambda r: r.update(requiredStatusChecks=[{"context": "a", "app": {"databaseId": "1"}}]),
        "requiredStatusChecks",
    ),
    ("allowance count missing", lambda r: r.pop("pushAllowances"), "pushAllowances"),
    ("allowance count text", lambda r: r.update(pushAllowances={"totalCount": "3"}), "pushAllowances"),
    ("id missing", lambda r: r.pop("id"), "id"),
    ("id odd shape", lambda r: r.update(id="a b;c"), "id"),
]


@pytest.mark.parametrize("label,edit,needle", UNREADABLE, ids=[u[0] for u in UNREADABLE])
def test_a_field_that_cannot_be_read_in_full_is_refused_by_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, label: str, edit: Callable[[dict[str, Any]], Any], needle: str
) -> None:
    bad = rule()
    edit(bad)
    rig = make(tmp_path, monkeypatch, [bad])
    code, _out, err = rig.apply()
    assert code == pt.EXIT_REFUSED and needle in err
    assert rig.fake.mutations() == [] and not list(rig.backups.iterdir())


# -- apply -------------------------------------------------------------------------------------------------------


def test_apply_sends_one_field_and_verifies_every_other_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = make(tmp_path, monkeypatch)
    before = copy.deepcopy(rig.fake.rules[0])
    code, out, err = rig.apply()
    assert code == 0 and err == "", (out, err)
    (call,) = rig.fake.mutations()
    assert call[1:] == ["api", "graphql", "-f", "query=" + pt.MUTATION % "true", "-f", "id=BPR_1"]
    after = rig.fake.rules[0]
    assert after[pt.FLAG] is True
    before[pt.FLAG] = True
    assert after == before
    assert "verified" in out


def test_the_whole_rule_is_saved_before_the_write_with_mode_0600(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = make(tmp_path, monkeypatch)
    seen: list[int] = []
    original = rig.fake.mutate

    def watch(argv: list[str], query: str, rule_id: str) -> subprocess.CompletedProcess[str]:
        seen.append(len(list(rig.backups.iterdir())))
        return original(argv, query, rule_id)

    rig.fake.mutate = watch  # type: ignore[method-assign]
    code, out, _ = rig.apply()
    assert code == 0 and seen == [1]
    (saved,) = rig.backups.iterdir()
    assert stat.S_IMODE(saved.stat().st_mode) == 0o600
    data = json.loads(saved.read_text(encoding="utf-8"))
    assert data["id"] == "BPR_1" and data[pt.FLAG] is False and data["requiredApprovingReviewCount"] == 2
    assert str(saved) in out and "20261127T120000Z" in saved.name


def test_a_write_that_fails_with_nothing_changed_exits_5(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rig = make(tmp_path, monkeypatch)
    rig.fake.mutation_rc, rig.fake.mutation_applies = 1, False
    code, out, err = rig.apply()
    assert code == pt.EXIT_WRITE and "nothing changed" in err and SECRET not in out + err


def test_a_flag_that_did_not_take_is_a_failed_verification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rig = make(tmp_path, monkeypatch)
    rig.fake.mutation_applies = False  # exit 0 but nothing happened
    code, out, err = rig.apply()
    assert code == pt.EXIT_VERIFY and pt.FLAG in err
    assert "rollback" in out


def test_another_field_that_changed_prints_the_rollback_and_exits_6(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig = make(tmp_path, monkeypatch)
    old = copy.deepcopy(rig.fake.rules[0])

    def drop(r: dict[str, Any]) -> None:
        r["lockBranch"] = False
        r["pushAllowances"] = {"totalCount": 0}

    rig.fake.after_mutation = drop
    code, out, err = rig.apply()
    assert code == pt.EXIT_VERIFY and "lockBranch" in err and "pushAllowances" in err
    (saved,) = rig.backups.iterdir()
    assert json.loads(saved.read_text(encoding="utf-8")) == pt.snapshot(old)
    line = next(ln for ln in out.splitlines() if ln.startswith("rollback body"))
    assert json.loads(line.split(": ", 1)[1]) == pt.snapshot(old)
    assert pt.MUTATION % "false" in out and "id=BPR_1" in out and str(saved) in out


# -- usage, reads, secrets ---------------------------------------------------------------------------------------


def test_apply_needs_a_backup_dir_that_is_a_real_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rig = make(tmp_path, monkeypatch)
    assert rig.go(REPO, "--apply")[0] == pt.EXIT_USAGE
    assert rig.go(REPO, "--apply", "--backup-dir", str(tmp_path / "missing"))[0] == pt.EXIT_USAGE
    link = tmp_path / "link"
    link.symlink_to(rig.backups)
    assert rig.go(REPO, "--apply", "--backup-dir", str(link))[0] == pt.EXIT_USAGE
    assert rig.fake.calls == []  # refused before any call


def test_a_bad_repository_name_is_a_usage_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rig = make(tmp_path, monkeypatch)
    for bad in ("nope", "a/b/c", "../x/y", "o/r;rm", ".x/y"):
        assert rig.go(bad)[0] == pt.EXIT_USAGE
    assert rig.fake.calls == []


def test_a_failed_read_exits_4_and_does_not_echo_the_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rig = make(tmp_path, monkeypatch)
    rig.fake.read_rc = 1
    code, out, err = rig.go(REPO)
    assert code == pt.EXIT_READ and SECRET not in out + err


def test_no_token_reaches_argv_or_output_and_calls_are_few(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rig = make(tmp_path, monkeypatch)
    code, out, err = rig.apply()
    assert code == 0
    assert all(SECRET not in " ".join(c) for c in rig.fake.calls) and SECRET not in out + err
    assert len(rig.fake.calls) <= 7


def test_the_entry_point_is_declared_and_the_guard_is_untouched() -> None:
    root = Path(__file__).parent.parent
    assert 'safo-protect-threads = "safo.protect_threads:run"' in (root / "pyproject.toml").read_text(encoding="utf-8")
    texts = [
        p.read_text(encoding="utf-8") for p in (root / "src" / "safo").glob("*.py") if p.name != "protect_threads.py"
    ]
    assert not any("protect_threads" in t for t in texts)
