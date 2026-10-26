# SPDX-License-Identifier: Apache-2.0
"""No hidden work, guard side: a brief names an open tracking item, and nothing in it reaches a shell."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from agentsdata import agents_dict
from hooksdata import agents_file, dispatch, hooks, probe_file, read_log, set_mode, set_probe, state_folder
from safo import tracking
from safo.agentsfile import parse_agents
from safo.errors import ConfigError
from safo.hooks import check_dispatch, prune_state, repo_path
from safo.tracking import Ref, State

GOOD = "acme/widgets#12"
OPEN_ISSUE = '{"state":"OPEN","url":"https://github.com/acme/widgets/issues/12"}'
CLOSED_ISSUE = '{"state":"CLOSED","url":"https://github.com/acme/widgets/issues/12"}'
OPEN_PULL = '{"state":"OPEN","url":"https://github.com/acme/widgets/pull/12"}'


def resolver(state: State = "open") -> tuple[tracking.Resolver, list[Ref]]:
    seen: list[Ref] = []

    def resolve(ref: Ref) -> State:
        seen.append(ref)
        return state

    return resolve, seen


# -- the reference on its own line -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "tracker", "ref"),
    [
        ("issue: acme/widgets#12", "github", GOOD),
        ("Do it.\nissue: acme/widgets#12\nmore", "github", GOOD),
        ("  ISSUE:   acme/widgets#12   ", "github", GOOD),
        ("issue: acme/widgets#12\r\n", "github", GOOD),
        ("issue: a-b/c.d_e#1", "github", "a-b/c.d_e#1"),
        ("issue: SAFO-54", "jira", "SAFO-54"),
        ("issue: AB2-7", "jira", "AB2-7"),
        ("issue: nonsense\nissue: acme/widgets#3", "github", "acme/widgets#3"),
    ],
)
def test_a_reference_on_a_line_of_its_own_is_found(text: str, tracker: str, ref: str) -> None:
    found = tracking.parse(text)
    assert found is not None and (found.tracker, found.text) == (tracker, ref)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "no tracking here",
        "see issue: acme/widgets#12",  # not on a line of its own
        "issue: acme/widgets#12 and more",
        "issue: acme/widgets#0",
        "issue: acme/widgets#012",
        "issue: acme/widgets#1234567890",
        "issue: acme/widgets",
        "issue: #12",
        "issue: https://github.com/acme/widgets/issues/12",
        "issue: safo-54",  # a Jira key is upper case
        "issue: S-5",
        "issue: -acme/widgets#1",
        "issue: acme/widgets#12;rm",
        "issue: acme/wid gets#12",
    ],
)
def test_anything_else_names_no_item(text: str) -> None:
    assert tracking.parse(text) is None


@pytest.mark.parametrize(
    "value",
    [
        "acme/widgets#1;touch${IFS}pwned",
        "acme/$(id)#1",
        "acme/`id`#1",
        "acme/widgets#1&&id",
        "acme/widgets#1|id",
        "--repo=evil/x#1",
        "acme/widgets#1\x00",
        "acme/../x#1",
        "$(id)-5",
    ],
)
def test_a_reference_with_shell_metacharacters_never_reaches_the_resolver(value: str) -> None:
    resolve, seen = resolver()
    verdict = tracking.check(f"issue: {value}\n", resolve)
    assert verdict is not None and verdict[0] == "no-issue"
    assert seen == [], "a rejected reference must not be looked up"
    assert value not in verdict[1], "a rejected reference is never echoed back"


# -- the verdicts -----------------------------------------------------------------------------------------


def test_a_brief_without_a_reference_says_how_to_file_one() -> None:
    resolve, seen = resolver()
    verdict = tracking.check("Just do the thing.", resolve)
    assert verdict is not None and verdict[0] == "no-issue" and seen == []
    assert "gh issue create" in verdict[1] and "issue: OWNER/REPO#N" in verdict[1] and "board" in verdict[1]


@pytest.mark.parametrize(
    ("state", "rule", "words"),
    [
        ("closed", "issue-unusable", "is closed"),
        ("missing", "issue-unusable", "does not exist"),
        ("pull_request", "issue-unusable", "is a pull request, not an issue"),
        ("error", "issue-unverified", "could not confirm"),
    ],
)
def test_an_item_that_is_not_open_is_named_and_refused(state: State, rule: str, words: str) -> None:
    resolve, seen = resolver(state)
    verdict = tracking.check(f"issue: {GOOD}", resolve)
    assert verdict is not None and verdict[0] == rule and words in verdict[1] and GOOD in verdict[1]
    assert [r.text for r in seen] == [GOOD]


def test_an_open_item_passes() -> None:
    resolve, seen = resolver("open")
    assert tracking.check(f"issue: {GOOD}", resolve) is None and seen[0].repo == "acme/widgets" and seen[0].number == 12


def test_a_jira_key_is_checked_by_shape_and_never_run_through_gh() -> None:
    calls: list[Any] = []
    resolve = tracking.gh_resolver(lambda *a, **k: calls.append(a), lambda name: "/bin/gh")
    assert tracking.check("issue: SAFO-54", resolve) is None and calls == []


# -- the read-only GitHub lookup -------------------------------------------------------------------------


def fake_run(stdout: str = OPEN_ISSUE, code: int = 0, stderr: str = "") -> tuple[Any, list[Any]]:
    calls: list[Any] = []

    def run(argv: list[str], **kwargs: Any) -> Any:
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)

    return run, calls


def lookup(run: Any, which: Any = lambda name: "/usr/bin/gh") -> State:
    ref = tracking.parse(f"issue: {GOOD}")
    assert ref is not None
    return tracking.gh_resolver(run, which)(ref)


def test_the_lookup_is_an_argument_list_with_no_shell_and_only_reads() -> None:
    run, calls = fake_run()
    assert lookup(run) == "open"
    argv, kwargs = calls[0]
    assert argv == ["/usr/bin/gh", "issue", "view", "12", "--repo", "acme/widgets", "--json", "state,url"]
    assert not kwargs.get("shell") and kwargs["stdin"] == subprocess.DEVNULL and kwargs["timeout"] > 0
    assert not {"create", "edit", "close", "comment", "reopen", "delete"} & set(argv)


@pytest.mark.parametrize(
    ("stdout", "code", "stderr", "state"),
    [
        (CLOSED_ISSUE, 0, "", "closed"),
        ("", 1, "GraphQL: Could not resolve to an issue or pull request with the number of 12.", "missing"),
        ("", 1, "issue not found", "missing"),
        ("", 1, "HTTP 502", "error"),
        ("", 4, "auth required", "error"),
        ("not json", 0, "", "error"),
        ("{}", 0, "", "error"),
        ('{"state":"MERGED","url":"https://github.com/acme/widgets/issues/12"}', 0, "", "error"),
        ('{"state":"OPEN"}', 0, "", "error"),  # no url: the kind of thing it is cannot be told
        ('{"state":"OPEN","url":"https://github.com/acme/widgets/discussions/12"}', 0, "", "error"),
        ('{"state":"OPEN","url":7}', 0, "", "error"),
        ('{"state":"OPEN","url":"https://github.com/acme/widgets/pull/12"}', 0, "", "pull_request"),
        ('{"state":"CLOSED","url":"https://github.com/acme/widgets/pull/12"}', 0, "", "pull_request"),
        ('{"state":7}', 0, "", "error"),
        ("[]", 0, "", "error"),
    ],
)
def test_every_answer_of_gh_maps_to_one_state(stdout: str, code: int, stderr: str, state: State) -> None:
    run, _ = fake_run(stdout, code, stderr)
    assert lookup(run) == state


@pytest.mark.parametrize(
    "error", [OSError("gone"), subprocess.TimeoutExpired("gh", 5), UnicodeDecodeError("utf-8", b"", 0, 1, "x")]
)
def test_a_lookup_that_fails_to_run_is_an_error_not_a_pass(error: Exception) -> None:
    def run(*args: Any, **kwargs: Any) -> Any:
        raise error

    assert lookup(run) == "error"


def test_without_gh_the_lookup_is_an_error() -> None:
    run, calls = fake_run()
    assert lookup(run, lambda name: None) == "error" and calls == []


# -- the opt-out ---------------------------------------------------------------------------------------------


def test_the_opt_out_compares_the_full_owner_and_name_without_case() -> None:
    assert tracking.exempt("acme/scratch", ("acme/scratch",))
    assert tracking.exempt("ACME/Scratch", ("acme/scratch",))
    assert not tracking.exempt("evil/scratch", ("acme/scratch",)), "a fork or namesake is another repository"
    assert not tracking.exempt("acme/scratch-two", ("acme/scratch",))
    assert not tracking.exempt("acme/scratch", ())


def test_a_repository_that_cannot_be_determined_is_never_exempt() -> None:
    assert not tracking.exempt(None, ("acme/scratch",))


@pytest.mark.parametrize(
    ("url", "repo"),
    [
        ("https://github.com/acme/widgets.git\n", "acme/widgets"),
        ("https://github.com/acme/widgets", "acme/widgets"),
        ("https://user@github.com/acme/widgets.git", "acme/widgets"),
        ("git@github.com:acme/widgets.git", "acme/widgets"),
        ("ssh://git@github.com/acme/widgets.git", "acme/widgets"),
        ("https://gitlab.example/acme/widgets.git", None),
        ("https://github.com.evil.example/acme/widgets.git", None),
        ("https://github.com/acme/widgets/extra", None),
        ("/srv/git/widgets.git", None),
        ("", None),
        ("https://github.com/acme/wid gets", None),
    ],
)
def test_the_repository_comes_from_the_origin_url(url: str, repo: str | None) -> None:
    assert tracking.repo_from_remote(url) == repo


def test_the_working_directory_repository_is_read_with_an_argument_list(tmp_path: Path) -> None:
    git = tmp_path / "git"
    git.write_text("#!/bin/sh\n")
    git.chmod(0o755)
    run, calls = fake_run("https://github.com/acme/widgets.git\n")
    assert tracking.cwd_repo(run, {"PATH": str(tmp_path)}, str(tmp_path)) == "acme/widgets"
    argv, kwargs = calls[0]
    assert argv == [str(git), "-C", str(tmp_path), "config", "--get", "remote.origin.url"] and not kwargs.get("shell")


@pytest.mark.parametrize("cwd", ["", "relative/dir", "/no/such/directory/anywhere", "/tmp/\x00x"])
def test_an_unusable_working_directory_has_no_repository(cwd: str) -> None:
    run, calls = fake_run("https://github.com/acme/widgets.git")
    assert tracking.cwd_repo(run, {"PATH": "/usr/bin"}, cwd) is None and calls == []


def test_no_git_or_a_failed_git_means_no_repository(tmp_path: Path) -> None:
    run, calls = fake_run("https://github.com/acme/widgets.git")
    assert tracking.cwd_repo(run, {"PATH": str(tmp_path)}, str(tmp_path)) is None and calls == []
    (tmp_path / "git").write_text("#!/bin/sh\n")
    (tmp_path / "git").chmod(0o755)
    failing, _ = fake_run("", 1)
    assert tracking.cwd_repo(failing, {"PATH": str(tmp_path)}, str(tmp_path)) is None


def test_a_directory_named_like_the_repository_does_not_exempt_it(tmp_path: Path) -> None:
    named = tmp_path / "scratch"
    named.mkdir()
    (tmp_path / "git").write_text("#!/bin/sh\n")
    (tmp_path / "git").chmod(0o755)
    run, _ = fake_run("https://github.com/evil/scratch.git")
    repo = tracking.cwd_repo(run, {"PATH": str(tmp_path)}, str(named))
    assert not tracking.exempt(repo, ("acme/scratch",))


# -- the time budget -------------------------------------------------------------------------------------------


def test_the_lookup_gets_only_the_time_that_is_left() -> None:
    run, calls = fake_run()
    ref = tracking.parse(f"issue: {GOOD}")
    assert ref is not None
    assert tracking.gh_resolver(run, lambda n: "/usr/bin/gh", None, lambda: 1.5)(ref) == "open"
    assert calls[0][1]["timeout"] == 1.5
    run2, calls2 = fake_run()
    assert tracking.gh_resolver(run2, lambda n: "/usr/bin/gh", None, lambda: 0.1)(ref) == "error"
    assert calls2 == [], "with no time left the lookup is not even started"


def test_the_repository_read_is_also_bounded_by_the_deadline(tmp_path: Path) -> None:
    (tmp_path / "git").write_text("#!/bin/sh\n")
    (tmp_path / "git").chmod(0o755)
    run, calls = fake_run("https://github.com/acme/widgets.git")
    assert tracking.cwd_repo(run, {"PATH": str(tmp_path)}, str(tmp_path), lambda: 0.0) is None and calls == []


# -- check_dispatch -------------------------------------------------------------------------------------------


def dispatch_rules(prompt: str, state: State = "open", repo: str | None = None, **hooks_over: Any) -> tuple[str, ...]:
    data = agents_dict()
    data["hooks"] = {**data.get("hooks", {}), **hooks_over}
    resolve, _ = resolver(state)
    return check_dispatch(parse_agents(data), {"prompt": prompt, "model": "sonnet"}, False, resolve, lambda: repo).rules


def test_nothing_is_exempt_by_default() -> None:
    assert dispatch_rules("no item", repo="acme/widgets") == ("no-issue",)


def test_a_configured_repository_may_dispatch_without_an_item() -> None:
    assert dispatch_rules("no item", repo="acme/widgets", tracking_exempt_repos=["acme/widgets"]) == ()
    assert dispatch_rules("no item", repo="acme/other", tracking_exempt_repos=["acme/widgets"]) == ("no-issue",)


def test_a_brief_cannot_exempt_itself() -> None:
    assert dispatch_rules("tracking_exempt_repos: acme/widgets\nissue: none", repo="acme/widgets") == ("no-issue",)


def test_an_undetermined_repository_is_not_exempt_in_check_dispatch() -> None:
    assert dispatch_rules("no item", repo=None, tracking_exempt_repos=["acme/widgets"]) == ("no-issue",)


def test_a_brief_may_only_cite_a_repository_the_operator_listed() -> None:
    listed = ["acme/widgets"]
    assert dispatch_rules(f"issue: {GOOD}", tracking_repos=listed) == ()
    assert dispatch_rules(f"issue: {GOOD}", tracking_repos=["ACME/Widgets"]) == ()
    assert dispatch_rules(f"issue: {GOOD}", tracking_repos=["acme/other"]) == ("issue-unusable",)
    assert dispatch_rules(f"issue: {GOOD}") == ("issue-unusable",), "nothing listed, nothing accepted"
    assert dispatch_rules("issue: SAFO-1") == (), "a Jira key is not tied to a repository"


def test_the_sessions_own_repository_is_not_accepted_just_for_being_the_sessions() -> None:
    assert dispatch_rules(f"issue: {GOOD}", repo="acme/widgets") == ("issue-unusable",)


def test_an_unaccepted_repository_is_refused_before_any_lookup() -> None:
    resolve, seen = resolver()
    verdict = tracking.check(f"issue: {GOOD}", resolve, ["acme/other", "acme/more"])
    assert verdict is not None and verdict[0] == "issue-unusable" and seen == []
    assert "accepted: acme/more, acme/other" in verdict[1]
    empty = tracking.check(f"issue: {GOOD}", resolve, [])
    assert empty is not None and "tracking_repos" in empty[1]


@pytest.mark.parametrize("key", ["tracking_exempt_repos", "tracking_repos"])
@pytest.mark.parametrize("bad", ["widgets", "acme/", "/widgets", "acme/wid gets", "a/b/c", 7])
def test_the_repository_lists_are_validated(bad: Any, key: str) -> None:
    data = agents_dict()
    data["hooks"] = {key: [bad]}
    with pytest.raises(ConfigError, match=rf"hooks\.{key}"):
        parse_agents(data)


# -- through the command line, with a stand-in gh ----------------------------------------------------------


def stand_in_gh(folder: Path, answers: dict[str, str]) -> Path:
    """A `gh` that logs its arguments and answers a read by issue number; it fails for any other command."""
    bin_dir = folder / "bin"
    bin_dir.mkdir()
    log = folder / "gh.log"
    cases = "\n".join(f"  \"{n}\") echo '{out}' ;;" for n, out in answers.items())
    script = (
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{log}"\n'
        'if [ "$1" != issue ] || [ "$2" != view ]; then echo "mutation attempted" >&2; exit 9; fi\n'
        'case "$3" in\n' + cases + '\n  *) echo "Could not resolve to an issue" >&2; exit 1 ;;\nesac\n'
    )
    path = bin_dir / "gh"
    path.write_text(script)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return bin_dir


@pytest.fixture
def agents(tmp_path: Path) -> Path:
    return agents_file(tmp_path / "agents.yaml", tracking_repos=["acme/widgets"])


def run_guard(home: Path, agents: Path, payload: str, path: Path | None = None) -> tuple[str, list[dict[str, Any]]]:
    code, out, _ = hooks(
        "guard", "--agents", str(agents), home=home, stdin=payload, env={"PATH": str(path)} if path else None
    )
    assert code == 0
    return out, read_log(home)


def with_cwd(payload: str, cwd: str) -> str:
    data = json.loads(payload)
    data["cwd"] = cwd
    return json.dumps(data)


def test_block_mode_denies_a_dispatch_with_no_item_and_says_how_to_file(_private_home: Path, agents: Path) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False, agents=agents)
    out, log = run_guard(_private_home, agents, dispatch(tracked=False))
    reason = json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "no hidden work" in reason and "gh issue create" in reason
    assert log[-1]["rules"] == ["no-issue"] and "Summarise" not in json.dumps(log)


def test_warn_mode_reports_and_allows(_private_home: Path, agents: Path) -> None:
    set_probe(_private_home, reachable=False, agents=agents)
    out, log = run_guard(_private_home, agents, dispatch(tracked=False))
    data = json.loads(out)
    assert "warn mode: allowed" in data["systemMessage"] and "permissionDecision" not in data["hookSpecificOutput"]
    assert log[-1]["decision"] == "warn" and log[-1]["rules"] == ["no-issue"]


def test_an_open_github_item_passes_after_one_read_only_lookup(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False, agents=agents)
    bin_dir = stand_in_gh(tmp_path, {"12": OPEN_ISSUE})
    payload = dispatch(prompt=f"issue: {GOOD}\nwork", tracked=False)
    out, log = run_guard(_private_home, agents, payload, bin_dir)
    assert out == "" and log[-1]["decision"] == "allow"
    assert (tmp_path / "gh.log").read_text().splitlines() == ["issue view 12 --repo acme/widgets --json state,url"]


@pytest.mark.parametrize(
    ("answers", "number", "rule"),
    [
        ({"12": CLOSED_ISSUE}, 12, "issue-unusable"),
        ({}, 12, "issue-unusable"),
        ({"12": "garbage"}, 12, "issue-unverified"),
    ],
)
def test_block_mode_denies_a_closed_missing_or_unreadable_item(
    _private_home: Path, agents: Path, tmp_path: Path, answers: dict[str, str], number: int, rule: str
) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False, agents=agents)
    bin_dir = stand_in_gh(tmp_path, answers)
    out, log = run_guard(
        _private_home, agents, dispatch(prompt=f"issue: acme/widgets#{number}", tracked=False), bin_dir
    )
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny" and log[-1]["rules"] == [rule]


def test_block_mode_fails_closed_when_gh_cannot_be_found(_private_home: Path, agents: Path) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False, agents=agents)
    out, log = run_guard(_private_home, agents, dispatch(prompt=f"issue: {GOOD}", tracked=False))
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny" and log[-1]["rules"] == [
        "issue-unverified"
    ]


def test_warn_mode_reports_a_lookup_that_failed_and_allows(_private_home: Path, agents: Path) -> None:
    set_probe(_private_home, reachable=False, agents=agents)
    out, log = run_guard(_private_home, agents, dispatch(prompt=f"issue: {GOOD}", tracked=False))
    assert "could not confirm" in json.loads(out)["systemMessage"] and log[-1]["decision"] == "warn"


def test_a_hostile_reference_runs_nothing(_private_home: Path, agents: Path, tmp_path: Path) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False, agents=agents)
    bin_dir = stand_in_gh(tmp_path, {"1": OPEN_ISSUE})
    marker = tmp_path / "pwned"
    payload = dispatch(prompt=f"issue: acme/widgets#1;touch${{IFS}}{marker}\nissue: $(touch {marker})-1", tracked=False)
    out, log = run_guard(_private_home, agents, payload, bin_dir)
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny" and log[-1]["rules"] == ["no-issue"]
    assert not marker.exists() and not (tmp_path / "gh.log").exists(), "nothing was run for a rejected reference"


def stand_in_git(bin_dir: Path, url: str) -> None:
    path = bin_dir / "git"
    path.write_text(f"#!/bin/sh\necho '{url}'\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def start_session(
    home: Path,
    agents: Path,
    cwd: Path,
    bin_dir: Path | None = None,
    session: str = "session-a",
    source: str = "startup",
) -> tuple[int, str, str]:
    """The SessionStart probe, which is where the session's repository is bound."""
    event = json.dumps({"hook_event_name": "SessionStart", "session_id": session, "cwd": str(cwd), "source": source})
    env = {"PATH": str(bin_dir)} if bin_dir else None
    result = hooks("probe", "--agents", str(agents), home=home, stdin=event, env=env)
    set_probe(home, reachable=False, agents=agents, session=session)  # the test clock is fixed: make the state fresh
    return result


def as_session(payload: str, session: str) -> str:
    data = json.loads(payload)
    data["session_id"] = session
    return json.dumps(data)


def denied(out: str) -> bool:
    return bool(out) and json.loads(out)["hookSpecificOutput"].get("permissionDecision") == "deny"


def test_the_configured_opt_out_lets_the_bound_repository_dispatch_without_an_item(
    _private_home: Path, tmp_path: Path
) -> None:
    exempt = agents_file(tmp_path / "exempt.yaml", tracking_exempt_repos=["acme/scratch"])
    set_mode(_private_home, "block")
    bin_dir = stand_in_gh(tmp_path, {})
    stand_in_git(bin_dir, "git@github.com:Acme/Scratch.git")
    here = tmp_path / "scratch"
    here.mkdir()
    assert start_session(_private_home, exempt, here, bin_dir)[0] == 0
    assert run_guard(_private_home, exempt, with_cwd(dispatch(tracked=False), str(here)), bin_dir)[0] == ""
    stand_in_git(bin_dir, "https://github.com/evil/scratch.git")  # a namesake directory, another repository
    assert start_session(_private_home, exempt, here, bin_dir, "session-b")[0] == 0
    other = as_session(with_cwd(dispatch(tracked=False), str(here)), "session-b")
    assert denied(run_guard(_private_home, exempt, other, bin_dir)[0])


def test_the_guard_never_re_reads_the_working_tree(_private_home: Path, tmp_path: Path) -> None:
    """An agent that runs `git remote set-url` after the session began gains no exemption."""
    exempt = agents_file(tmp_path / "exempt.yaml", tracking_exempt_repos=["acme/scratch"])
    set_mode(_private_home, "block")
    bin_dir = stand_in_gh(tmp_path, {})
    stand_in_git(bin_dir, "https://github.com/evil/other.git")
    here = tmp_path / "work"
    here.mkdir()
    start_session(_private_home, exempt, here, bin_dir)
    stand_in_git(bin_dir, "https://github.com/acme/scratch.git")  # forged after the binding
    assert denied(run_guard(_private_home, exempt, with_cwd(dispatch(tracked=False), str(here)), bin_dir)[0])


def test_a_binding_is_written_once_and_a_later_change_is_refused_and_logged(
    _private_home: Path, tmp_path: Path
) -> None:
    exempt = agents_file(tmp_path / "exempt.yaml", tracking_exempt_repos=["acme/scratch"])
    set_mode(_private_home, "block")
    bin_dir = stand_in_gh(tmp_path, {})
    stand_in_git(bin_dir, "https://github.com/evil/other.git")
    here = tmp_path / "work"
    here.mkdir()
    assert start_session(_private_home, exempt, here, bin_dir)[0] == 0
    stand_in_git(bin_dir, "https://github.com/acme/scratch.git")
    code, out, _ = start_session(_private_home, exempt, here, bin_dir)  # the same session starts again
    assert code == 0 and "degraded" in out
    assert read_log(_private_home)[-1]["diagnostic"] == "repo-changed"
    assert denied(run_guard(_private_home, exempt, with_cwd(dispatch(tracked=False), str(here)), bin_dir)[0])


def repo_file(home: Path, agents: Path, session: str = "session-a") -> Path:
    return repo_path(probe_file(home, agents, session))


def test_the_guard_keeps_an_active_sessions_binding_out_of_the_prune(_private_home: Path, tmp_path: Path) -> None:
    exempt = agents_file(tmp_path / "exempt.yaml", tracking_exempt_repos=["acme/scratch"])
    set_mode(_private_home, "block")
    bin_dir = stand_in_gh(tmp_path, {})
    stand_in_git(bin_dir, "https://github.com/acme/scratch.git")
    here = tmp_path / "work"
    here.mkdir()
    start_session(_private_home, exempt, here, bin_dir)
    binding = repo_file(_private_home, exempt)
    week_old = time.time() - 30 * 86400
    os.utime(binding, (week_old, week_old))
    assert run_guard(_private_home, exempt, with_cwd(dispatch(tracked=False), str(here)), bin_dir)[0] == ""
    assert binding.stat().st_mtime > time.time() - 600, "reading the binding refreshes it"
    prune_state(state_folder(_private_home), time.time())
    assert binding.exists(), "an active session's binding is not pruned"
    assert run_guard(_private_home, exempt, with_cwd(dispatch(tracked=False), str(here)), bin_dir)[0] == ""


@pytest.mark.parametrize("source", ["resume", "clear", "compact", "fork", "", "other"])
def test_only_a_fresh_start_creates_a_binding(_private_home: Path, tmp_path: Path, source: str) -> None:
    """A binding lost to pruning is not re-derived from a working tree the agent may have rewritten."""
    exempt = agents_file(tmp_path / "exempt.yaml", tracking_exempt_repos=["acme/scratch"])
    set_mode(_private_home, "block")
    bin_dir = stand_in_gh(tmp_path, {})
    stand_in_git(bin_dir, "https://github.com/acme/scratch.git")  # forged: this is what a hostile agent would set
    here = tmp_path / "work"
    here.mkdir()
    code, out, _ = start_session(_private_home, exempt, here, bin_dir, source=source)
    assert code == 0 and "degraded" in out and read_log(_private_home)[-1]["diagnostic"] == "repo-unbound"
    assert not repo_file(_private_home, exempt).exists()
    assert denied(run_guard(_private_home, exempt, with_cwd(dispatch(tracked=False), str(here)), bin_dir)[0])


def test_a_resumed_session_finds_the_binding_made_at_startup(_private_home: Path, tmp_path: Path) -> None:
    exempt = agents_file(tmp_path / "exempt.yaml", tracking_exempt_repos=["acme/scratch"])
    set_mode(_private_home, "block")
    bin_dir = stand_in_gh(tmp_path, {})
    stand_in_git(bin_dir, "https://github.com/acme/scratch.git")
    here = tmp_path / "work"
    here.mkdir()
    start_session(_private_home, exempt, here, bin_dir)
    for source in ("resume", "compact", "clear"):
        code, out, _ = start_session(_private_home, exempt, here, bin_dir, source=source)
        assert code == 0 and "degraded" not in out
    assert run_guard(_private_home, exempt, with_cwd(dispatch(tracked=False), str(here)), bin_dir)[0] == ""


def test_a_session_started_again_with_the_same_repository_is_fine(_private_home: Path, tmp_path: Path) -> None:
    exempt = agents_file(tmp_path / "exempt.yaml", tracking_exempt_repos=["acme/scratch"])
    bin_dir = stand_in_gh(tmp_path, {})
    stand_in_git(bin_dir, "https://github.com/acme/scratch.git")
    here = tmp_path / "work"
    here.mkdir()
    for _ in range(2):
        code, out, _ = start_session(_private_home, exempt, here, bin_dir)
        assert code == 0 and "degraded" not in out


def test_the_opt_out_fails_closed_when_the_repository_cannot_be_determined(_private_home: Path, tmp_path: Path) -> None:
    exempt = agents_file(tmp_path / "exempt.yaml", tracking_exempt_repos=["acme/scratch"])
    set_mode(_private_home, "block")
    here = tmp_path / "scratch"
    here.mkdir()
    assert denied(run_guard(_private_home, exempt, with_cwd(dispatch(tracked=False), str(here)))[0])  # never bound
    start_session(_private_home, exempt, here)  # bound to "undetermined": no git on PATH
    assert denied(run_guard(_private_home, exempt, with_cwd(dispatch(tracked=False), str(here)))[0])


def test_a_brief_citing_an_unrelated_open_issue_is_denied_without_a_lookup(_private_home: Path, tmp_path: Path) -> None:
    listed = agents_file(tmp_path / "a.yaml", tracking_repos=["acme/widgets"])
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False, agents=listed)
    bin_dir = stand_in_gh(tmp_path, {"7": OPEN_ISSUE})
    foreign = dispatch(prompt="issue: other/elsewhere#7", tracked=False)
    out, log = run_guard(_private_home, listed, foreign, bin_dir)
    assert denied(out) and log[-1]["rules"] == ["issue-unusable"]
    assert "accepted: acme/widgets" in out and not (tmp_path / "gh.log").exists()
    assert run_guard(_private_home, listed, dispatch(prompt="issue: acme/widgets#7", tracked=False), bin_dir)[0] == ""


def test_a_session_repository_that_is_not_listed_is_not_accepted_for_citing(
    _private_home: Path, tmp_path: Path
) -> None:
    unlisted = agents_file(tmp_path / "a.yaml")
    set_mode(_private_home, "block")
    bin_dir = stand_in_gh(tmp_path, {"7": OPEN_ISSUE})
    stand_in_git(bin_dir, "https://github.com/acme/widgets.git")
    here = tmp_path / "work"
    here.mkdir()
    start_session(_private_home, unlisted, here, bin_dir)
    own = with_cwd(dispatch(prompt="issue: acme/widgets#7", tracked=False), str(here))
    assert denied(run_guard(_private_home, unlisted, own, bin_dir)[0]) and not (tmp_path / "gh.log").exists()


def test_a_guard_out_of_time_denies_in_block_mode_and_skips_the_append_and_the_next_dispatch_says_so(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    import io

    from meterdata import NOW
    from safo.context import LocalContext
    from safo.modes import hooks as hooks_mode

    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False, agents=agents)
    calls: list[Any] = []

    def run(*a: Any, **k: Any) -> Any:
        calls.append(a)
        return SimpleNamespace(returncode=0, stdout=OPEN_ISSUE, stderr="")

    out = io.StringIO()
    ctx = LocalContext(
        out,
        {"HOME": str(_private_home), "PATH": ""},
        NOW,
        run=run,
        which_override=lambda n: "/usr/bin/gh",
        stdin=io.StringIO(dispatch(prompt=f"issue: {GOOD}", tracked=False)),
    )
    import time

    hooks_mode.guard(ctx, argparse.Namespace(agents=str(agents), agents_local=""), started=time.monotonic() - 60)
    assert calls == [], "no process is started once the deadline has passed"
    assert json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"] == "deny"
    # New contract: out of time, the append is skipped (it is never stretched past the hook's budget), and the
    # next dispatch reports the gap through the marker.
    assert read_log(_private_home) == [], "the decision is printed; the log write was skipped, not attempted late"
    pending = hooks_mode.log_failure_pending(state_folder(_private_home))
    assert pending is not None and pending[0] == hooks_mode.LOG_FAILED_NOTICE


def test_the_shipped_agents_file_exempts_nothing() -> None:
    doc = parse_agents(yaml.safe_load((Path(__file__).parent.parent / "agents.yaml").read_text()))
    assert doc.hooks.tracking_exempt_repos == ()


def test_a_pull_request_reference_is_refused_even_though_gh_issue_view_resolves_it(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False, agents=agents)
    bin_dir = stand_in_gh(tmp_path, {"12": OPEN_PULL})
    out, log = run_guard(_private_home, agents, dispatch(prompt=f"issue: {GOOD}", tracked=False), bin_dir)
    assert denied(out) and log[-1]["rules"] == ["issue-unusable"] and "pull request" in out
