# SPDX-License-Identifier: MIT
"""scripts/apply-baseline.sh against a fake gh: plan mode touches nothing, --apply makes exactly the baseline calls."""

from __future__ import annotations

import json
import re
import stat
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "apply-baseline.sh"
REPO = "ChiefGyk3D/scrum-around-and-find-out"


def make_fake_gh(fail_on_cmd: str = "", graphql_response: str = "") -> str:
    """Build a fake gh script that can fail on a specific command or return custom GraphQL responses."""
    script_lines = [
        "#!/bin/sh",
        'echo "$*" >> "$LOG"',
        'case "$*" in',
        '*"--input -"*) cat >> "$LOG.stdin" ;;',
        "esac",
    ]
    if fail_on_cmd:
        script_lines.append(f'[ "$*" = "{fail_on_cmd}" ] && exit 1')
    if graphql_response:
        script_lines.extend(
            [
                'case "$*" in',
                f"*graphql*) printf \"%s\" '{graphql_response}' ;;",
                "esac",
            ]
        )
    script_lines.extend(
        [
            'case "$*" in',
            '"api user"*) echo maintainer ;;',
            "*selected-actions.json?ref=*) printf '%s' 'eyJnaXRodWJfb3duZWRfYWxsb3dlZCI6IHRydWV9' ;;",
            "esac",
            "exit 0",
        ]
    )
    return "\n".join(script_lines)


def run(
    tmp_path: Path,
    *args: str,
    fail_on_cmd: str = "",
    graphql_response: str = "",
) -> tuple[subprocess.CompletedProcess[str], list[str], str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    gh = bin_dir / "gh"
    gh.write_text(make_fake_gh(fail_on_cmd=fail_on_cmd, graphql_response=graphql_response))
    gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "gh.log"
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "LOG": str(log)}
    done = subprocess.run(["bash", str(SCRIPT), *args], env=env, capture_output=True, text=True, check=False)  # noqa: S603, S607
    calls = log.read_text().splitlines() if log.exists() else []
    stdin = Path(f"{log}.stdin").read_text() if Path(f"{log}.stdin").exists() else ""
    return done, calls, stdin


def required_contexts() -> list[str]:
    """The gates ci.yml produces, derived the way GYST's audit does: one per job calling a shared *-ci.yml."""
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    return [
        f"{job} / CI green"
        for job, spec in workflow["jobs"].items()
        if re.search(r"/\.github/workflows/[a-z-]+-ci\.yml@", spec.get("uses", ""))
    ]


def test_without_apply_it_prints_the_plan_and_calls_gh_not_once(tmp_path: Path) -> None:
    done, calls, _ = run(tmp_path)
    assert done.returncode == 0 and calls == []
    assert "plan only (nothing is changed)" in done.stdout
    assert f"+ gh api -X PUT repos/{REPO}/branches/main/protection" in done.stdout


def test_with_apply_it_makes_the_baseline_calls_and_nothing_destructive(tmp_path: Path) -> None:
    done, calls, stdin = run(tmp_path, "--apply")
    assert done.returncode == 0, done.stderr
    joined = "\n".join(calls)
    for expected in (
        f"api -X PUT repos/{REPO}/branches/main/protection --input -",
        f"api -X PUT repos/{REPO}/actions/permissions/fork-pr-contributor-approval "
        "-f approval_policy=all_external_contributors",
        f"api -X PUT repos/{REPO}/actions/permissions -F enabled=true -f allowed_actions=selected",
        f"api -X PUT repos/{REPO}/private-vulnerability-reporting",
        f"api -X PATCH repos/{REPO} -F allow_auto_merge=true",
        f"api -X POST repos/{REPO}/rulesets --input -",
    ):
        assert expected in joined, expected
    assert "-X DELETE" not in joined
    assert re.search(
        r"api repos/ChiefGyk3D/git-your-ship-together/contents/baseline/selected-actions.json\?ref=[0-9a-f]{40} ",
        joined,
    )
    assert "selected-actions --input /" in joined, "the list from GYST is sent as a file"
    assert "applying the baseline to " + REPO + " as maintainer" in done.stdout
    assert '"refs/tags/v*"' in stdin


def test_branch_protection_requires_a_pull_request_and_both_ci_gates(tmp_path: Path) -> None:
    _, _, stdin = run(tmp_path, "--apply")
    body, _ = json.JSONDecoder().raw_decode(stdin)  # the protection document is sent first
    contexts = [c["context"] for c in body["required_status_checks"]["checks"]]
    assert contexts == required_contexts() == ["ci / CI green", "shell / CI green"]
    assert body["required_pull_request_reviews"] == {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews": True,
    }
    assert body["allow_force_pushes"] is False and body["allow_deletions"] is False


def test_it_reads_the_force_push_bypass_back_over_graphql(tmp_path: Path) -> None:
    _, calls, _ = run(tmp_path, "--apply")
    graphql = [c for c in calls if c.startswith("api graphql")]
    assert graphql and "bypassForcePushAllowances" in graphql[0]


def test_the_pin_matches_the_one_ci_uses(tmp_path: Path) -> None:
    pin = re.search(r'^GYST_SHA="([0-9a-f]{40})"', SCRIPT.read_text(), re.MULTILINE)
    assert pin
    assert f"python-ci.yml@{pin[1]} # v" in (ROOT / ".github" / "workflows" / "ci.yml").read_text()


def test_an_unknown_option_and_a_bad_repository_are_refused(tmp_path: Path) -> None:
    done, calls, _ = run(tmp_path, "--bogus")
    assert done.returncode == 1 and "unknown option" in done.stderr and calls == []
    done, _, _ = run(tmp_path, "--repo", "no-slash")
    assert done.returncode == 1 and "OWNER/NAME" in done.stderr


def test_apply_with_graphql_showing_bypass_exits_nonzero_and_prints_refusal(tmp_path: Path) -> None:
    """GraphQL response showing a bypassForcePushAllowances entry forces exit non-zero."""
    graphql_response = '{"data":{"repository":{"branchProtectionRules":{"nodes":[{"pattern":"main","allowsForcePushes":false,"bypassForcePushAllowances":{"totalCount":1}}]}}}}'  # noqa: E501
    done, _, _ = run(tmp_path, "--apply", graphql_response=graphql_response)
    assert done.returncode != 0, "should exit non-zero when bypasses exist"
    assert "force pushes are still possible" in done.stderr


def test_apply_with_failing_gh_call_exits_nonzero_before_any_put(tmp_path: Path) -> None:
    """A failing gh call (e.g. 'api user') under --apply exits non-zero before any PUT/POST/PATCH."""
    done, calls, _ = run(tmp_path, "--apply", fail_on_cmd="api user --jq .login")
    assert done.returncode != 0, "should exit non-zero when gh call fails"
    # No PUT, POST, or PATCH should be logged before the gh failure
    joined = "\n".join(calls)
    assert "-X PUT" not in joined and "-X POST" not in joined and "-X PATCH" not in joined


def test_apply_with_allow_list_fetch_failure_exits_nonzero_and_skips_allowed_actions(
    tmp_path: Path,
) -> None:
    """A failing allow-list fetch under --apply exits non-zero and no 'allowed_actions=selected' call is logged."""
    fail_cmd = (
        "api repos/ChiefGyk3D/git-your-ship-together/contents/baseline/"
        "selected-actions.json?ref=a5b834a6e03e0bf7187eeebfa84685498d73b139 --jq .content"
    )
    done, calls, _ = run(tmp_path, "--apply", fail_on_cmd=fail_cmd)
    assert done.returncode != 0, "should exit non-zero when allow-list fetch fails"
    joined = "\n".join(calls)
    assert "allowed_actions=selected" not in joined, "allowed_actions should not be set if fetch fails"
