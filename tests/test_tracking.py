# SPDX-License-Identifier: Apache-2.0
"""No hidden work, guard side: a brief names an open tracking item, and nothing in it reaches a shell."""

from __future__ import annotations

import json
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from agentsdata import agents_dict
from hooksdata import agents_file, dispatch, hooks, read_log, set_mode, set_probe
from safo import tracking
from safo.agentsfile import parse_agents
from safo.errors import ConfigError
from safo.hooks import check_dispatch
from safo.tracking import Ref, State

GOOD = "acme/widgets#12"


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


def fake_run(stdout: str = '{"state":"OPEN"}', code: int = 0, stderr: str = "") -> tuple[Any, list[Any]]:
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
    assert argv == ["/usr/bin/gh", "issue", "view", "12", "--repo", "acme/widgets", "--json", "state"]
    assert not kwargs.get("shell") and kwargs["stdin"] == subprocess.DEVNULL and kwargs["timeout"] > 0
    assert not {"create", "edit", "close", "comment", "reopen", "delete"} & set(argv)


@pytest.mark.parametrize(
    ("stdout", "code", "stderr", "state"),
    [
        ('{"state":"CLOSED"}', 0, "", "closed"),
        ("", 1, "GraphQL: Could not resolve to an issue or pull request with the number of 12.", "missing"),
        ("", 1, "issue not found", "missing"),
        ("", 1, "HTTP 502", "error"),
        ("", 4, "auth required", "error"),
        ("not json", 0, "", "error"),
        ("{}", 0, "", "error"),
        ('{"state":"MERGED"}', 0, "", "error"),
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


def test_the_opt_out_matches_a_repository_name_in_the_working_directory_only() -> None:
    assert tracking.exempt("/home/me/src/scratch/sub", ("acme/scratch",))
    assert not tracking.exempt("/home/me/src/other", ("acme/scratch",))
    assert not tracking.exempt("", ("acme/scratch",))
    assert not tracking.exempt("/home/me/src/scratch", ())
    assert not tracking.exempt("/home/me/src/scratch-two", ("acme/scratch",))


# -- check_dispatch -------------------------------------------------------------------------------------------


def dispatch_rules(prompt: str, state: State = "open", cwd: str = "", **hooks_over: Any) -> tuple[str, ...]:
    data = agents_dict()
    data["hooks"] = {**data.get("hooks", {}), **hooks_over}
    resolve, _ = resolver(state)
    return check_dispatch(parse_agents(data), {"prompt": prompt, "model": "sonnet"}, False, resolve, cwd).rules


def test_nothing_is_exempt_by_default() -> None:
    assert dispatch_rules("no item", cwd="/home/me/src/widgets") == ("no-issue",)


def test_a_configured_repository_may_dispatch_without_an_item() -> None:
    assert dispatch_rules("no item", cwd="/home/me/src/widgets", tracking_exempt_repos=["acme/widgets"]) == ()
    assert dispatch_rules("no item", cwd="/home/me/src/other", tracking_exempt_repos=["acme/widgets"]) == ("no-issue",)


def test_a_brief_cannot_exempt_itself() -> None:
    assert dispatch_rules("tracking_exempt_repos: acme/widgets\nissue: none", cwd="/x/widgets") == ("no-issue",)


@pytest.mark.parametrize("bad", ["widgets", "acme/", "/widgets", "acme/wid gets", "a/b/c", 7])
def test_the_opt_out_list_is_validated(bad: Any) -> None:
    data = agents_dict()
    data["hooks"] = {"tracking_exempt_repos": [bad]}
    with pytest.raises(ConfigError, match=r"hooks\.tracking_exempt_repos"):
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
    return agents_file(tmp_path / "agents.yaml")


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
    set_probe(_private_home, reachable=False)
    out, log = run_guard(_private_home, agents, dispatch(tracked=False))
    reason = json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "no hidden work" in reason and "gh issue create" in reason
    assert log[-1]["rules"] == ["no-issue"] and "Summarise" not in json.dumps(log)


def test_warn_mode_reports_and_allows(_private_home: Path, agents: Path) -> None:
    set_probe(_private_home, reachable=False)
    out, log = run_guard(_private_home, agents, dispatch(tracked=False))
    data = json.loads(out)
    assert "warn mode: allowed" in data["systemMessage"] and "permissionDecision" not in data["hookSpecificOutput"]
    assert log[-1]["decision"] == "warn" and log[-1]["rules"] == ["no-issue"]


def test_an_open_github_item_passes_after_one_read_only_lookup(
    _private_home: Path, agents: Path, tmp_path: Path
) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False)
    bin_dir = stand_in_gh(tmp_path, {"12": '{"state":"OPEN"}'})
    payload = dispatch(prompt=f"issue: {GOOD}\nwork", tracked=False)
    out, log = run_guard(_private_home, agents, payload, bin_dir)
    assert out == "" and log[-1]["decision"] == "allow"
    assert (tmp_path / "gh.log").read_text().splitlines() == ["issue view 12 --repo acme/widgets --json state"]


@pytest.mark.parametrize(
    ("answers", "number", "rule"),
    [
        ({"12": '{"state":"CLOSED"}'}, 12, "issue-unusable"),
        ({}, 12, "issue-unusable"),
        ({"12": "garbage"}, 12, "issue-unverified"),
    ],
)
def test_block_mode_denies_a_closed_missing_or_unreadable_item(
    _private_home: Path, agents: Path, tmp_path: Path, answers: dict[str, str], number: int, rule: str
) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False)
    bin_dir = stand_in_gh(tmp_path, answers)
    out, log = run_guard(
        _private_home, agents, dispatch(prompt=f"issue: acme/widgets#{number}", tracked=False), bin_dir
    )
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny" and log[-1]["rules"] == [rule]


def test_block_mode_fails_closed_when_gh_cannot_be_found(_private_home: Path, agents: Path) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False)
    out, log = run_guard(_private_home, agents, dispatch(prompt=f"issue: {GOOD}", tracked=False))
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny" and log[-1]["rules"] == [
        "issue-unverified"
    ]


def test_warn_mode_reports_a_lookup_that_failed_and_allows(_private_home: Path, agents: Path) -> None:
    set_probe(_private_home, reachable=False)
    out, log = run_guard(_private_home, agents, dispatch(prompt=f"issue: {GOOD}", tracked=False))
    assert "could not confirm" in json.loads(out)["systemMessage"] and log[-1]["decision"] == "warn"


def test_a_hostile_reference_runs_nothing(_private_home: Path, agents: Path, tmp_path: Path) -> None:
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False)
    bin_dir = stand_in_gh(tmp_path, {"1": '{"state":"OPEN"}'})
    marker = tmp_path / "pwned"
    payload = dispatch(prompt=f"issue: acme/widgets#1;touch${{IFS}}{marker}\nissue: $(touch {marker})-1", tracked=False)
    out, log = run_guard(_private_home, agents, payload, bin_dir)
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny" and log[-1]["rules"] == ["no-issue"]
    assert not marker.exists() and not (tmp_path / "gh.log").exists(), "nothing was run for a rejected reference"


def test_the_configured_opt_out_lets_that_repository_dispatch_without_an_item(
    _private_home: Path, tmp_path: Path
) -> None:
    exempt = agents_file(tmp_path / "exempt.yaml", tracking_exempt_repos=["acme/scratch"])
    set_mode(_private_home, "block")
    set_probe(_private_home, reachable=False, agents=exempt)
    inside = with_cwd(dispatch(tracked=False), "/home/me/src/scratch")
    outside = with_cwd(dispatch(tracked=False), "/home/me/src/widgets")
    assert run_guard(_private_home, exempt, inside)[0] == ""
    assert (
        json.loads(run_guard(_private_home, exempt, outside)[0])["hookSpecificOutput"]["permissionDecision"] == "deny"
    )


def test_the_shipped_agents_file_exempts_nothing() -> None:
    doc = parse_agents(yaml.safe_load((Path(__file__).parent.parent / "agents.yaml").read_text()))
    assert doc.hooks.tracking_exempt_repos == ()
