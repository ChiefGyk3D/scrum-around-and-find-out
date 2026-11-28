# SPDX-License-Identifier: Apache-2.0
"""apply-baseline.sh --mode standard|basic|secret-scanning and the generated plan script, against a stateful fake gh.

The fake keeps each repository's settings in a JSON file, answers GET, PUT, PATCH and DELETE like GitHub's REST API
(a rule is read back in GET shape) and logs every call. Nothing here reaches the network.
"""

from __future__ import annotations

import json
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "apply-baseline.sh"
GEN = ROOT / "scripts" / "gen-protection-plan.py"
OWNER = "ChiefGyk3D"

FAKE_GH = """#!{python}
import json, os, sys
args = sys.argv[1:]
with open(os.environ["LOG"], "a") as log:
    log.write(" ".join(args) + "\\n")
state_path = os.environ["FAKE_STATE"]
with open(state_path) as handle:
    state = json.load(handle)
method, path, fields, jq_filter = "GET", None, {{}}, False
i = 1
while i < len(args):
    a = args[i]
    if a == "-X":
        method = args[i + 1]; i += 2
    elif a in ("-f", "-F"):
        key, _, value = args[i + 1].partition("="); fields[key] = value; i += 2
    elif a in ("--jq", "--input"):
        jq_filter = jq_filter or a == "--jq"; i += 2
    elif a.startswith("-"):
        i += 1
    else:
        path = path or a; i += 1
if args[:2] == ["api", "user"]:
    print("maintainer"); sys.exit(0)
if path == "graphql":
    sys.exit(0)  # the script filters with --jq; an empty answer means no bypass allowance
parts = path.split("/")
name = "/".join(parts[1:3])
repo = state["repos"].get(name)
if repo is None:
    sys.stderr.write("gh: Not Found (HTTP 404)\\n"); sys.exit(1)
def save():
    with open(state_path, "w") as handle:
        json.dump(state, handle)
if len(parts) == 3:
    if method == "PATCH":
        for key, value in fields.items():
            feature = key.split("[")[1].rstrip("]")
            repo["security_and_analysis"][feature]["status"] = value
        if os.environ.get("FAKE_CORRUPT") == name:
            repo["security_and_analysis"]["secret_scanning"]["status"] = "disabled"
        save(); sys.exit(0)
    print(json.dumps({{
        "private": repo["private"], "default_branch": repo["default_branch"], "archived": repo["archived"],
        "fork": repo["fork"], "owner": {{"type": repo["owner_type"], "login": parts[1]}},
        "security_and_analysis": repo["security_and_analysis"],
    }}))
    sys.exit(0)
assert parts[3] == "branches" and parts[5] == "protection", path
if method == "PUT":
    if os.environ.get("FAKE_FAIL_PUT") == name:
        sys.stderr.write("gh: Validation Failed (HTTP 422)\\n"); sys.exit(1)
    body = json.load(sys.stdin)
    rsc = body["required_status_checks"]
    strict = rsc["strict"] if rsc else None
    if os.environ.get("FAKE_CORRUPT") == name and rsc:
        strict = False
    repo["rule"] = {{
        "required_status_checks": None if rsc is None else {{
            "strict": strict, "checks": [{{"context": c["context"], "app_id": c.get("app_id")}} for c in rsc["checks"]],
        }},
        "enforce_admins": {{"enabled": body["enforce_admins"]}},
        "required_pull_request_reviews": body["required_pull_request_reviews"],
        "restrictions": None,
        "required_linear_history": {{"enabled": body.get("required_linear_history", False)}},
        "allow_force_pushes": {{"enabled": body["allow_force_pushes"]}},
        "allow_deletions": {{"enabled": body["allow_deletions"]}},
        "required_conversation_resolution": {{"enabled": body["required_conversation_resolution"]}},
    }}
    save(); sys.exit(0)
if method == "DELETE":
    repo["rule"] = None; save(); sys.exit(0)
if repo["rule"] is None:
    sys.stderr.write("gh: Branch not protected (HTTP 404)\\n"); sys.exit(1)
print(json.dumps(repo["rule"]))
"""


def rule(
    contexts: list[str],
    *,
    strict: bool = False,
    conv: bool = False,
    admins: bool = False,
    reviews: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "required_status_checks": {"strict": strict, "checks": [{"context": c, "app_id": 15368} for c in contexts]},
        "enforce_admins": {"enabled": admins},
        "required_pull_request_reviews": reviews,
        "restrictions": None,
        "required_linear_history": {"enabled": False},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "required_conversation_resolution": {"enabled": conv},
    }


def repo_state(
    *,
    private: bool = False,
    branch: str = "main",
    rule_: dict[str, Any] | None = None,
    archived: bool = False,
    fork: bool = False,
    owner_type: str = "User",
    ss: str = "disabled",
) -> dict[str, Any]:
    return {
        "private": private,
        "default_branch": branch,
        "archived": archived,
        "fork": fork,
        "owner_type": owner_type,
        "rule": rule_,
        "security_and_analysis": {"secret_scanning": {"status": ss}, "secret_scanning_push_protection": {"status": ss}},
    }


class Sandbox:
    def __init__(self, tmp_path: Path, repos: dict[str, dict[str, Any]]) -> None:
        self.tmp = tmp_path
        self.state = tmp_path / "state.json"
        self.state.write_text(json.dumps({"repos": {f"{OWNER}/{n}": r for n, r in repos.items()}}))
        self.log = tmp_path / "gh.log"
        self.backups = tmp_path / "backups"
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(FAKE_GH.format(python=sys.executable))
        gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
        self.env = {
            "PATH": f"{bin_dir}:/usr/bin:/bin",
            "LOG": str(self.log),
            "FAKE_STATE": str(self.state),
            "HOME": str(tmp_path),
        }

    def repo(self, name: str) -> dict[str, Any]:
        state = json.loads(self.state.read_text())
        found: dict[str, Any] = state["repos"][f"{OWNER}/{name}"]
        return found

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []

    def writes(self) -> list[str]:
        return [c for c in self.calls() if any(f"-X {m}" in c for m in ("PUT", "PATCH", "DELETE", "POST"))]

    def run(self, script: Path, *args: str, **extra: str) -> subprocess.CompletedProcess[str]:
        env = {**self.env, **extra}
        cmd = ["/bin/bash", str(script), *args]
        return subprocess.run(  # noqa: S603 - fixed script path, fake gh on PATH
            cmd, env=env, capture_output=True, text=True, check=False, timeout=60
        )

    def apply_one(self, name: str, mode: str, *args: str, **extra: str) -> subprocess.CompletedProcess[str]:
        return self.run(
            SCRIPT,
            "--repo",
            f"{OWNER}/{name}",
            "--mode",
            mode,
            "--backup-dir",
            str(self.backups),
            *args,
            **extra,
        )


def test_standard_dry_run_reads_but_writes_nothing_and_prints_plan_and_rollback(tmp_path: Path) -> None:
    box = Sandbox(tmp_path, {"r1": repo_state(rule_=rule(["ci / CI green"]))})
    done = box.apply_one("r1", "standard")
    assert done.returncode == 0, done.stderr
    assert box.writes() == [] and not box.backups.exists()
    assert "plan only" in done.stdout and '"strict":true' in done.stdout
    assert '"required_conversation_resolution":true' in done.stdout
    assert "ROLLBACK:" in done.stdout
    assert box.repo("r1")["rule"]["required_status_checks"]["strict"] is False


def test_standard_apply_orders_calls_keeps_checks_and_reads_back(tmp_path: Path) -> None:
    contexts = ["ci / CI green", "shell / CI green", "security / Semgrep"]
    reviews = {"required_approving_review_count": 1, "dismiss_stale_reviews": True, "require_code_owner_reviews": False}
    box = Sandbox(tmp_path, {"r1": repo_state(rule_=rule(contexts, admins=True, reviews=reviews))})
    done = box.apply_one("r1", "standard", "--apply")
    assert done.returncode == 0, done.stderr
    calls = box.calls()
    kinds = [
        "GET-repo"
        if c == f"api repos/{OWNER}/r1"
        else "PUT"
        if "-X PUT" in c
        else "GET-rule"
        if "protection" in c
        else c
        for c in calls
        if not c.startswith("api user") and "graphql" not in c
    ]
    assert kinds == ["GET-repo", "GET-rule", "PUT", "GET-rule"], calls
    assert any("graphql" in c for c in calls), "the force-push bypass read-back still runs"
    after = box.repo("r1")["rule"]
    assert after["required_status_checks"]["strict"] is True
    assert after["required_conversation_resolution"]["enabled"] is True
    assert sorted(c["context"] for c in after["required_status_checks"]["checks"]) == sorted(contexts)
    assert after["enforce_admins"]["enabled"] is True, "admin enforcement is kept as it was"
    assert after["required_pull_request_reviews"]["required_approving_review_count"] == 1
    assert after["allow_force_pushes"]["enabled"] is False and after["allow_deletions"]["enabled"] is False


def test_standard_turns_force_push_and_deletion_off_and_the_restore_file_keeps_them_as_they_were(
    tmp_path: Path,
) -> None:
    open_rule = rule(["CI green"])
    open_rule["allow_force_pushes"] = {"enabled": True}
    open_rule["allow_deletions"] = {"enabled": True}
    box = Sandbox(tmp_path, {"r1": repo_state(rule_=open_rule)})
    done = box.apply_one("r1", "standard", "--apply")
    assert done.returncode == 0, done.stderr
    after = box.repo("r1")["rule"]
    assert after["allow_force_pushes"]["enabled"] is False and after["allow_deletions"]["enabled"] is False
    restore = next(f for f in box.backups.iterdir() if f.name.endswith(".restore.json"))
    body = json.loads(restore.read_text())
    assert body["allow_force_pushes"] is True and body["allow_deletions"] is True


def test_standard_backup_is_private_and_the_rollback_line_restores_it(tmp_path: Path) -> None:
    box = Sandbox(tmp_path, {"r1": repo_state(rule_=rule(["CI green"], conv=True))})
    done = box.apply_one("r1", "standard", "--apply")
    assert done.returncode == 0, done.stderr
    files = sorted(box.backups.iterdir())
    assert len(files) == 2 and all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in files)
    assert stat.S_IMODE(box.backups.stat().st_mode) == 0o700
    restore = next(f for f in files if f.name.endswith(".restore.json"))
    body = json.loads(restore.read_text())
    assert body["required_status_checks"]["strict"] is False and body["required_conversation_resolution"] is True
    line = next(ln for ln in done.stdout.splitlines() if ln.startswith("ROLLBACK:"))
    assert f"gh api -X PUT repos/{OWNER}/r1/branches/main/protection --input {restore}" in line


def test_standard_without_a_ci_green_check_is_refused_with_no_write(tmp_path: Path) -> None:
    box = Sandbox(tmp_path, {"r1": repo_state(rule_=rule(["security / Semgrep"]))})
    done = box.apply_one("r1", "standard", "--apply")
    assert done.returncode != 0 and "CI green" in done.stderr and "--mode basic" in done.stderr
    assert box.writes() == []


def test_standard_never_drops_restrictions_or_bypass_it_cannot_carry(tmp_path: Path) -> None:
    withrestr = rule(["CI green"])
    withrestr["restrictions"] = {"users": [], "teams": [], "apps": []}
    box = Sandbox(tmp_path, {"r1": repo_state(rule_=withrestr)})
    done = box.apply_one("r1", "standard", "--apply")
    assert done.returncode != 0 and "restrictions" in done.stderr and box.writes() == []


def test_basic_on_an_unprotected_branch_blocks_force_push_and_deletion_only(tmp_path: Path) -> None:
    box = Sandbox(tmp_path, {"r1": repo_state()})
    dry = box.apply_one("r1", "basic", "--expect-protection", "none")
    assert dry.returncode == 0 and box.writes() == []
    assert f"ROLLBACK: gh api -X DELETE repos/{OWNER}/r1/branches/main/protection" in dry.stdout
    done = box.apply_one("r1", "basic", "--expect-protection", "none", "--apply")
    assert done.returncode == 0, done.stderr
    after = box.repo("r1")["rule"]
    assert after["required_status_checks"] is None, "BASIC requires no checks"
    assert after["allow_force_pushes"]["enabled"] is False and after["allow_deletions"]["enabled"] is False
    assert after["required_pull_request_reviews"] is None
    assert after["required_conversation_resolution"]["enabled"] is False


def test_basic_on_a_protected_branch_keeps_the_rule_as_it_was(tmp_path: Path) -> None:
    box = Sandbox(tmp_path, {"r1": repo_state(rule_=rule(["security / Semgrep"], strict=False))})
    done = box.apply_one("r1", "basic", "--apply")
    assert done.returncode == 0, done.stderr
    after = box.repo("r1")["rule"]
    assert after["required_status_checks"]["strict"] is False and len(after["required_status_checks"]["checks"]) == 1


@pytest.mark.parametrize(
    ("repo", "extra", "reason"),
    [
        (repo_state(branch="trunk"), ["--expect-branch", "main"], "default branch"),
        (repo_state(private=True), ["--expect-visibility", "public"], "visibility"),
        (repo_state(archived=True), [], "archived"),
        (repo_state(fork=True), [], "fork"),
        (repo_state(owner_type="Organization"), [], "owner"),
        (repo_state(rule_=rule(["CI green"])), ["--expect-protection", "none"], "protection"),
        (repo_state(), ["--expect-protection", "rule"], "protection"),
    ],
)
def test_a_repository_that_changed_since_the_snapshot_is_refused_without_a_write(
    tmp_path: Path, repo: dict[str, Any], extra: list[str], reason: str
) -> None:
    box = Sandbox(tmp_path, {"r1": repo})
    done = box.apply_one("r1", "basic", *extra, "--apply")
    assert done.returncode == 3 and f"REFUSED {OWNER}/r1" in done.stderr and reason in done.stderr
    assert box.writes() == []


def test_a_read_back_mismatch_stops_with_exit_4_and_prints_the_rollback(tmp_path: Path) -> None:
    box = Sandbox(tmp_path, {"r1": repo_state(rule_=rule(["CI green"]))})
    done = box.apply_one("r1", "standard", "--apply", FAKE_CORRUPT=f"{OWNER}/r1")
    assert done.returncode == 4 and "MISMATCH" in done.stderr
    assert "ROLLBACK:" in done.stdout + done.stderr
    assert not any("graphql" in c for c in box.calls()), "nothing runs after the mismatch"


def test_a_failed_write_exits_nonzero_before_any_read_back(tmp_path: Path) -> None:
    box = Sandbox(tmp_path, {"r1": repo_state(rule_=rule(["CI green"]))})
    done = box.apply_one("r1", "standard", "--apply", FAKE_FAIL_PUT=f"{OWNER}/r1")
    assert done.returncode != 0 and "MISMATCH" not in done.stderr
    assert [c for c in box.calls() if "protection" in c].count(f"api repos/{OWNER}/r1/branches/main/protection") == 1


def test_secret_scanning_enables_both_reads_back_and_prints_a_rollback(tmp_path: Path) -> None:
    box = Sandbox(tmp_path, {"r1": repo_state()})
    dry = box.apply_one("r1", "secret-scanning")
    assert dry.returncode == 0 and box.writes() == []
    done = box.apply_one("r1", "secret-scanning", "--apply")
    assert done.returncode == 0, done.stderr
    sa = box.repo("r1")["security_and_analysis"]
    assert sa["secret_scanning"]["status"] == "enabled" and sa["secret_scanning_push_protection"]["status"] == "enabled"
    assert "secret_scanning][status]=disabled" in done.stdout and "ROLLBACK:" in done.stdout
    assert box.calls()[-1] == f"api repos/{OWNER}/r1", "the last call is the read-back"


def test_secret_scanning_refuses_a_private_repository_and_skips_what_is_already_on(tmp_path: Path) -> None:
    box = Sandbox(tmp_path, {"p": repo_state(private=True), "on": repo_state(ss="enabled")})
    done = box.apply_one("p", "secret-scanning", "--apply")
    assert done.returncode == 3 and "private" in done.stderr
    done = box.apply_one("on", "secret-scanning", "--apply")
    assert done.returncode == 0 and "already enabled" in done.stdout and box.writes() == []


def test_secret_scanning_mismatch_stops_with_exit_4(tmp_path: Path) -> None:
    box = Sandbox(tmp_path, {"r1": repo_state()})
    done = box.apply_one("r1", "secret-scanning", "--apply", FAKE_CORRUPT=f"{OWNER}/r1")
    assert done.returncode == 4 and "MISMATCH" in done.stderr


def test_an_unknown_mode_and_a_bad_expectation_are_refused(tmp_path: Path) -> None:
    box = Sandbox(tmp_path, {"r1": repo_state()})
    assert box.apply_one("r1", "bogus").returncode == 1
    assert box.apply_one("r1", "basic", "--expect-visibility", "internal").returncode == 1
    assert box.calls() == []


HEADER_LINE = "repo|vis|branch|prot|ctx|strict|conv|rev|force|del|adm|ss|pp|drift"
AUDIT = """total 7 public 5 private 2
header junk line
repo|vis|branch|prot|ctx|strict|conv|rev|force|del|adm|ss|pp|drift
nope1|PUBLIC|main|NONE|-|-|-|-|-|-|-|enabled|enabled|NOPROT
nope2|PRIVATE|master|NONE|-|-|-|-|-|-|-|unreadable|unreadable|NOPROT
skipme|PRIVATE|main|NONE|-|-|-|-|-|-|-|unreadable|unreadable|NOPROT
empty1|PUBLIC||EMPTY|-|-|-|-|-|-|-|-|-|
prot1|PUBLIC|main|YES|['ci / CI green', 'shell / CI green']|False|False|0|F|F|F|disabled|disabled|strict,conv
prot2|PUBLIC|main|YES|['ci / CI green']|True|True|0|False|False|False|enabled|enabled|
nogate|PRIVATE|main|YES|['security / Semgrep']|False|False|0|False|False|False|unreadable|unreadable|strict,conv
"""


def make_plan(tmp_path: Path, *extra: str) -> Path:
    audit = tmp_path / "audit.txt"
    audit.write_text(AUDIT)
    out = tmp_path / "plan.sh"
    done = subprocess.run(  # noqa: S603 - fixed interpreter and script path
        [
            sys.executable,
            "-I",
            str(GEN),
            "--audit",
            str(audit),
            "--out",
            str(out),
            "--apply-script",
            str(SCRIPT),
            "--skip",
            "skipme=an active ruleset protects it",
            "--secret",
            "prot1",
            *extra,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert done.returncode == 0, done.stderr
    return out


def plan_repos() -> dict[str, dict[str, Any]]:
    return {
        "nope1": repo_state(),
        "nope2": repo_state(private=True, branch="master"),
        "skipme": repo_state(private=True),
        "empty1": repo_state(),
        "prot1": repo_state(rule_=rule(["ci / CI green", "shell / CI green"]), ss="disabled"),
        "prot2": repo_state(rule_=rule(["ci / CI green"], strict=True, conv=True), ss="enabled"),
        "nogate": repo_state(private=True, rule_=rule(["security / Semgrep"])),
    }


def test_the_generator_lists_every_action_and_marks_the_script_owner_only(tmp_path: Path) -> None:
    plan = make_plan(tmp_path)
    assert stat.S_IMODE(plan.stat().st_mode) == 0o700
    text = plan.read_text()
    for row in (
        "nope1|public|main|basic|none",
        "nope2|private|master|basic|none",
        "prot1|public|main|standard|rule",
        "nogate|private|main|basic|rule",
        "prot1|public|main|secret-scanning|-",
    ):
        assert row in text, row
    assert "skipme" in text and "an active ruleset protects it" in text
    for absent in ("empty1|public", "prot2|public", "skipme|private"):
        assert absent not in text, f"{absent} must not be a planned action"
    assert "empty1|empty repository" in text, "an empty repository is listed as skipped"


def test_the_plan_dry_run_writes_nothing(tmp_path: Path) -> None:
    box = Sandbox(tmp_path, plan_repos())
    done = box.run(make_plan(tmp_path))
    assert done.returncode == 0, done.stderr
    assert box.writes() == [] and not box.backups.exists()
    assert "dry run" in done.stdout and "apply" in done.stdout
    assert "SKIP" in done.stdout and "skipme" in done.stdout


def test_the_plan_applies_in_order_reads_back_and_never_touches_skipped_repos(tmp_path: Path) -> None:
    box = Sandbox(tmp_path, plan_repos())
    plan = make_plan(tmp_path)
    done = box.run(plan, "apply", SAFO_BACKUP_DIR=str(box.backups))
    assert done.returncode == 0, done.stderr
    puts = [c.split()[3] for c in box.writes() if "-X PUT" in c]
    assert puts == [
        f"repos/{OWNER}/{n}/branches/{b}/protection"
        for n, b in (("nope1", "main"), ("nope2", "master"), ("prot1", "main"), ("nogate", "main"))
    ]
    assert any("-X PATCH" in c and c.split()[3] == f"repos/{OWNER}/prot1" for c in box.writes())
    touched = " ".join(box.calls())
    assert "skipme" not in touched and "empty1" not in touched and "prot2" not in touched
    assert box.repo("prot1")["rule"]["required_status_checks"]["strict"] is True
    assert box.repo("nope1")["rule"]["required_status_checks"] is None
    assert box.repo("nogate")["rule"]["required_status_checks"]["strict"] is False
    assert done.stdout.count("ROLLBACK:") == 5, done.stdout


def test_the_plan_stops_at_the_first_mismatch_and_leaves_the_rest_alone(tmp_path: Path) -> None:
    box = Sandbox(tmp_path, plan_repos())
    plan = make_plan(tmp_path)
    box.env["FAKE_CORRUPT"] = f"{OWNER}/prot1"
    done = box.run(plan, "apply")
    assert done.returncode == 4 and "MISMATCH" in done.stderr and "STOP" in done.stdout + done.stderr
    assert box.repo("nope1")["rule"] is not None and box.repo("nope2")["rule"] is not None
    assert box.repo("nogate")["rule"]["required_status_checks"]["strict"] is False, "later repos are untouched"


def test_the_plan_refuses_a_repository_that_changed_since_the_snapshot_and_goes_on(tmp_path: Path) -> None:
    repos = plan_repos()
    repos["nope1"] = repo_state(branch="trunk")
    box = Sandbox(tmp_path, repos)
    done = box.run(make_plan(tmp_path), "apply")
    assert done.returncode == 1, done.stderr
    assert f"REFUSED {OWNER}/nope1" in done.stderr and "refused: nope1" in done.stdout
    assert box.repo("nope1")["rule"] is None
    assert box.repo("nope2")["rule"] is not None, "the other repositories still get their change"


def test_the_generator_refuses_a_hostile_name_and_a_missing_audit(tmp_path: Path) -> None:
    audit = tmp_path / "audit.txt"
    audit.write_text(HEADER_LINE + "\nx;rm -rf|PUBLIC|main|NONE|-|-|-|-|-|-|-|-|-|NOPROT\n")
    out = tmp_path / "plan.sh"
    cmd = [sys.executable, "-I", str(GEN), "--audit", str(audit), "--out", str(out), "--apply-script", str(SCRIPT)]
    done = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)  # noqa: S603
    assert done.returncode != 0 and not out.exists()
    cmd[4] = str(tmp_path / "missing.txt")
    done = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)  # noqa: S603
    assert done.returncode != 0
