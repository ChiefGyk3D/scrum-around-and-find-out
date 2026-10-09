# SPDX-License-Identifier: MIT
"""action.yml: structural rules the Action must keep. A change that breaks one is a security regression."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from safo import action_preflight

ROOT = Path(__file__).parent.parent
TEXT = (ROOT / "action.yml").read_text()
ACTION: dict[str, Any] = yaml.safe_load(TEXT)
INPUTS: dict[str, Any] = ACTION["inputs"]
STEPS: list[dict[str, Any]] = ACTION["runs"]["steps"]
SHA_PIN = re.compile(r"^\s*(?:- )?uses:\s+(\S+)@([0-9a-f]{40})\s+#\s+v\d+\.\d+\.\d+\s*$")
EXPRESSION = re.compile(r"^\$\{\{\s*(.*?)\s*\}\}$", re.DOTALL)

# project-sync.yml's inputs in git-your-ship-together, which this Action must keep accepting by the same name.
GYST_INPUTS = (
    "project-url",
    "status-field",
    "status-open-issue",
    "status-open-pr",
    "status-draft-pr",
    "status-done",
    "done-date-field",
    "default-area-field",
    "default-area",
    "dry-run",
    "client-id",
    "app-id",
    "doppler-project",
    "doppler-config",
    "doppler-identity-id",
)


def step(name_part: str) -> dict[str, Any]:
    found = [s for s in STEPS if name_part.lower() in str(s.get("name", "")).lower()]
    assert len(found) == 1, (name_part, [s.get("name") for s in found])
    return found[0]


def index(name_part: str) -> int:
    return STEPS.index(step(name_part))


def mint_steps() -> list[dict[str, Any]]:
    return [s for s in STEPS if str(s.get("uses", "")).startswith("actions/create-github-app-token@")]


def _walk(node: ast.AST, scope: dict[str, str]) -> object:
    if isinstance(node, ast.Expression):
        return _walk(node.body, scope)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return scope[node.id]
    if isinstance(node, ast.BoolOp):
        value: object = None
        for operand in node.values:  # the expression language returns an operand, like Python's and/or
            value = _walk(operand, scope)
            if isinstance(node.op, ast.And) and not value:
                return value
            if isinstance(node.op, ast.Or) and value:
                return value
        return value
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq | ast.NotEq):
        same = _walk(node.left, scope) == _walk(node.comparators[0], scope)
        return same if isinstance(node.ops[0], ast.Eq) else not same
    raise AssertionError(f"not in the subset the Action uses: {ast.dump(node)}")


def evaluate(expression: str, **names: str) -> object:
    """Evaluate the small subset of the expression language the Action uses: == != && || and string literals."""
    match = EXPRESSION.match(expression.strip())
    assert match, expression
    code = re.sub(r"inputs\.([a-z-]+)", lambda m: "inputs_" + m[1].replace("-", "_"), match[1])
    code = code.replace("&&", " and ").replace("||", " or ")
    return _walk(ast.parse(code, mode="eval"), dict(names))


# -- shape ---------------------------------------------------------------------------------------------------------


def test_it_is_a_composite_action_with_documented_inputs() -> None:
    assert ACTION["runs"]["using"] == "composite"
    assert INPUTS["mode"]["required"] is True
    assert INPUTS["allow-token-for-org"]["default"] == "false"
    assert all(spec.get("description") for spec in INPUTS.values())


@pytest.mark.parametrize("name", GYST_INPUTS)
def test_the_gyst_project_sync_input_names_are_accepted(name: str) -> None:
    assert name in INPUTS


def test_the_remaining_inputs_the_docs_name_exist() -> None:
    for name in ("mode", "board-file", "private-key", "token", "allow-token-for-org", "app-owner", "repositories"):
        assert name in INPUTS, name


def test_the_gyst_defaults_are_kept() -> None:
    expected = {
        "status-field": "Status",
        "status-open-issue": "Backlog",
        "status-open-pr": "In progress",
        "status-draft-pr": "Backlog",
        "status-done": "Done",
        "done-date-field": "Done on",
        "dry-run": "false",
        "default-area-field": "",
        "default-area": "",
        "app-owner": "",
    }
    assert {k: INPUTS[k]["default"] for k in expected} == expected


def test_no_input_defaults_to_a_credential() -> None:
    for name in ("private-key", "token", "client-id", "app-id"):
        assert INPUTS[name]["default"] == ""


# -- pins ----------------------------------------------------------------------------------------------------------


def test_every_action_is_pinned_to_a_commit_with_a_version_comment() -> None:
    uses = [line for line in TEXT.splitlines() if re.match(r"^\s*(- )?uses:", line)]
    assert len(uses) >= 4
    for line in uses:
        assert SHA_PIN.match(line), line


def test_the_pins_match_the_ones_gyst_runs() -> None:
    pins = dict(re.findall(r"uses:\s+(\S+)@([0-9a-f]{40})", TEXT))
    assert pins == {
        "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
        "actions/create-github-app-token": "bcd2ba49218906704ab6c1aa796996da409d3eb1",
        "dopplerhq/secrets-fetch-action": "451892f16195f9ac360e1a5bcbf0b5fd0e957534",
    }


# -- least privilege -----------------------------------------------------------------------------------------------


def test_both_mint_steps_name_every_permission_they_get() -> None:
    steps = mint_steps()
    assert len(steps) == 2
    for s in steps:
        permissions = {k: v for k, v in s["with"].items() if k.startswith("permission-")}
        assert set(permissions) == {"permission-organization-projects", "permission-issues", "permission-pull-requests"}
        assert permissions["permission-issues"] == "read" and permissions["permission-pull-requests"] == "read"


@pytest.mark.parametrize("mode", ["audit", "bootstrap", "reconcile", "sync", "status", "validate"])
@pytest.mark.parametrize("dry", ["true", "false"])
def test_projects_write_is_requested_only_for_a_run_that_writes(mode: str, dry: str) -> None:
    """Audit and any dry run only read, so their token is read-only; the rest need Projects write."""
    for s in mint_steps():
        got = evaluate(s["with"]["permission-organization-projects"], inputs_mode=mode, inputs_dry_run=dry)
        assert got == ("read" if mode in ("audit", "validate") or dry == "true" else "write")


def test_the_token_is_scoped_to_what_the_preflight_resolved_and_nothing_else() -> None:
    """The scope is computed and validated in Python (board.yaml's repositories, or the calling one), never inline."""
    for s in mint_steps():
        assert s["with"]["repositories"].replace(" ", "") == "${{steps.preflight.outputs.repositories}}"
    assert step("Preflight").get("id") == "preflight"


def test_the_owner_is_the_app_owner_input_else_the_repository_owner() -> None:
    for s in mint_steps():
        assert s["with"]["owner"].replace(" ", "") == "${{inputs.app-owner||github.repository_owner}}"


def test_the_mint_does_not_keep_a_job_wide_permission_by_default() -> None:
    """actions/create-github-app-token revokes the token when the job ends (skip-token-revoke defaults to false)."""
    for s in mint_steps():
        assert "skip-token-revoke" not in s["with"]


# -- secrets and injection -----------------------------------------------------------------------------------------


def test_no_input_is_expanded_into_a_script() -> None:
    for s in STEPS:
        if "run" in s:
            assert "${{" not in s["run"], s.get("name")
            assert s["shell"] == "bash"


def test_every_script_is_strict_and_quotes_what_it_expands() -> None:
    for s in STEPS:
        if "run" in s:
            assert "set -euo pipefail" in s["run"], s["name"]
            assert re.findall(r'(?<![="])\$[A-Z_]+', s["run"]) == [], s["name"]


def test_no_secrets_context_and_no_literal_key_anywhere() -> None:
    assert "secrets." not in TEXT
    assert "BEGIN" not in TEXT and "ghp_" not in TEXT and "github_pat_" not in TEXT


def test_the_credentials_are_masked_before_anything_else_can_print_them() -> None:
    first_use = min(index("preflight"), STEPS.index(next(s for s in STEPS if s.get("id") == "app")))
    mask = index("Mask the credentials")
    assert mask < first_use
    env = step("Mask the credentials")["env"]
    assert env["PRIVATE_KEY"].replace(" ", "") == "${{inputs.private-key}}"
    assert env["TOKEN"].replace(" ", "") == "${{inputs.token}}"
    assert '"$VENV/bin/python" -I -m safo.action_mask' in step("Mask the credentials")["run"]


def test_the_minted_token_and_a_doppler_key_are_masked_again_when_they_appear() -> None:
    after_doppler = [s for s in STEPS if "mask" in s.get("name", "").lower()]
    assert len(after_doppler) == 3
    names = [s["name"].lower() for s in after_doppler]
    assert any("doppler" in n for n in names) and any("installation token" in n for n in names)
    key_step = next(s for s in after_doppler if "doppler" in s["name"].lower())
    assert "steps.doppler.outputs.PROJECTS_APP_PRIVATE_KEY" in key_step["env"]["PRIVATE_KEY"]
    token_step = next(s for s in after_doppler if "installation token" in s["name"].lower())
    assert "steps.app.outputs.token" in token_step["env"]["MINTED_TOKEN"]
    assert "steps.app_legacy.outputs.token" in token_step["env"]["MINTED_TOKEN"]
    assert STEPS.index(token_step) > max(STEPS.index(s) for s in mint_steps())
    assert STEPS.index(token_step) < index("Run safo")


def test_the_credential_check_runs_before_doppler_and_before_any_mint() -> None:
    check = index("preflight")
    assert check < index("Doppler (OIDC)") < min(STEPS.index(s) for s in mint_steps())
    assert '"$VENV/bin/python" -I -m safo.action_preflight' in STEPS[check]["run"]


def test_preflight_is_handed_the_environment_it_reads_and_no_secret_value() -> None:
    env = step("preflight")["env"]
    assert set(action_preflight.READS) <= set(env), sorted(set(action_preflight.READS) - set(env))
    for name, value in env.items():
        assert "inputs.private-key" not in value.replace(" != ''", "") or name == "HAS_PRIVATE_KEY"
        assert "inputs.token" not in value.replace(" != ''", "") or name == "HAS_TOKEN"
    assert env["HAS_PRIVATE_KEY"].replace(" ", "") == "${{inputs.private-key!=''}}"
    assert env["HAS_TOKEN"].replace(" ", "") == "${{inputs.token!=''}}"


def test_the_board_less_inputs_reach_preflight_and_run_identically() -> None:
    pre, run = step("preflight")["env"], step("Run safo")["env"]
    names = [n for n in run if n.startswith("SAFO_") and n not in {"SAFO_TOKEN", "SAFO_TOKEN_KIND"}]
    assert {
        "SAFO_BOARD",
        "SAFO_PROJECT_URL",
        "SAFO_DEFAULT_AREA",
        "SAFO_STATUS_DONE",
        "SAFO_ALLOW_TOKEN_FOR_ORG",
    } <= set(names)
    for name in names:
        assert pre[name] == run[name], name
    assert {"SAFO_MODE", "SAFO_DRY_RUN", "SAFO_STATUS_STATE", "SAFO_STATUS_BODY_FILE"} <= set(names)


def test_the_token_goes_to_python_in_the_environment_with_its_kind() -> None:
    run = step("Run safo")
    assert "SAFO_TOKEN" in run["env"] and "SAFO_TOKEN_KIND" in run["env"]
    assert "app_legacy" in run["env"]["SAFO_TOKEN"] and "inputs.token" in run["env"]["SAFO_TOKEN"]
    assert "SAFO_TOKEN" not in run["run"].replace('"$SAFO_MODE"', "")


def test_the_minted_token_is_never_passed_on_a_command_line_or_written_to_an_output_file() -> None:
    for s in STEPS:
        script = s.get("run", "")
        assert "GITHUB_ENV" not in script, s.get("name")
        assert ("GITHUB_OUTPUT" in script) == (s.get("name", "").startswith("Install SAFO")), s.get("name")


def test_nothing_builds_a_python_path_and_every_python_is_isolated_in_the_actions_own_venv() -> None:
    assert "PYTHONPATH" not in TEXT and "PYTHONHOME" not in TEXT
    for s in STEPS:
        for line in s.get("run", "").splitlines():
            if "python" in line:
                assert '"$VENV/bin/python" -I ' in line or line.strip().startswith("python -I "), (
                    s["name"],
                    line,
                )
    for part in (
        "Mask the credentials",
        "Preflight",
        "Mask the Doppler",
        "Mask the installation",
        "Run safo",
    ):
        assert step(part)["env"]["VENV"] == "${{ steps.install.outputs.venv }}", part


def test_safo_is_installed_into_a_fresh_unpredictable_venv_checked_before_and_after() -> None:
    install = step("Install SAFO")
    script = install["run"]
    assert install.get("id") == "install"
    assert 'D="$(mktemp -d "$RUNNER_TEMP/safo.XXXXXXXXXX")"' in script and 'VENV="$D/venv"' in script
    assert 'python -I -m venv --clear "$VENV"' in script
    assert "safo-venv" not in TEXT
    assert '"$VENV/bin/python" -I -m pip install --disable-pip-version-check --no-deps --require-hashes' in script
    assert '-r "$ACTION_PATH/requirements.txt"' in script
    assert '"$ACTION_PATH/src/safo" "$purelib/safo"' in script
    created = 'python -I "$ACTION_PATH/src/safo/venv_check.py" created "$VENV"'
    installed = 'python -I "$ACTION_PATH/src/safo/venv_check.py" installed "$VENV"'
    publish = 'echo "venv=$VENV" >> "$GITHUB_OUTPUT"'
    assert script.index("-m venv") < script.index(created) < script.index("-m pip install")
    assert script.index("-m pip install") < script.index("cp -R") < script.index(installed) < script.index(publish)
    assert install["env"]["ACTION_PATH"] == "${{ github.action_path }}"
    assert install["env"]["RUNNER_TEMP"] == "${{ runner.temp }}"
    # nothing in the venv runs before the first check: the check itself uses the interpreter that made the venv
    assert script.index(created) < script.index('"$VENV/bin/python"')


def test_the_status_and_mode_arguments_are_quoted_array_elements() -> None:
    script = step("Run safo")["run"]
    assert 'args+=("$SAFO_MODE")' in script and '"${args[@]}"' in script


# -- Doppler -------------------------------------------------------------------------------------------------------


def test_doppler_runs_only_with_an_identity_and_never_with_a_literal_key_or_a_fork() -> None:
    s = step("Doppler (OIDC)")
    condition = s["if"].replace(" ", "")
    assert "inputs.doppler-identity-id!=''" in condition
    assert "inputs.private-key==''" in condition
    assert "inputs.mode!='validate'" in condition
    assert "github.event.pull_request.head.repo.full_name" in condition
    assert s["with"]["auth-method"] == "oidc" and s.get("id") == "doppler"
    assert s["with"]["doppler-identity-id"] == "${{ inputs.doppler-identity-id }}"


def test_no_doppler_secret_but_the_app_key_reaches_the_job_environment() -> None:
    """The fetch action exports every secret in the config when inject-env-vars is true; it must stay off, and the
    one secret needed is read from the step's output by name."""
    s = step("Doppler (OIDC)")
    assert "inject-env-vars" not in s["with"] and "inject-env-vars" not in TEXT
    assert "GITHUB_ENV" not in TEXT and "PROJECTS_APP_PRIVATE_KEY" in TEXT
    assert "env.PROJECTS_APP_PRIVATE_KEY" not in TEXT
    referenced = set(re.findall(r"steps\.doppler\.outputs\.([A-Za-z0-9_]+)", TEXT))
    assert referenced == {"PROJECTS_APP_PRIVATE_KEY"}


def test_there_is_no_doppler_token_fallback() -> None:
    assert "doppler-token" not in TEXT and "DOPPLER_TOKEN" not in TEXT


def test_the_mint_reads_the_key_from_the_input_or_the_doppler_environment() -> None:
    for s in mint_steps():
        assert (
            s["with"]["private-key"].replace(" ", "")
            == "${{inputs.private-key||steps.doppler.outputs.PROJECTS_APP_PRIVATE_KEY}}"
        )


def test_the_mint_steps_are_exclusive_and_skipped_for_validate_and_for_a_token() -> None:
    primary = next(s for s in STEPS if s.get("id") == "app")
    legacy = next(s for s in STEPS if s.get("id") == "app_legacy")
    for s in (primary, legacy):
        condition = s["if"].replace(" ", "")
        assert "inputs.mode!='validate'" in condition and "inputs.token==''" in condition
    assert "inputs.client-id!=''" in primary["if"].replace(" ", "")
    legacy_condition = legacy["if"].replace(" ", "")
    assert "inputs.client-id==''" in legacy_condition and "inputs.app-id!=''" in legacy_condition
    assert "client-id" in primary["with"] and "app-id" in legacy["with"]


# -- installing ----------------------------------------------------------------------------------------------------


def test_pyyaml_is_installed_from_the_hash_lock_only() -> None:
    install = step("Install SAFO")
    assert "--require-hashes" in install["run"] and "--no-deps" in install["run"]
    assert '-r "$ACTION_PATH/requirements.txt"' in install["run"]
    assert "pip install" in install["run"] and "git+" not in install["run"] and "http" not in install["run"]


def test_the_lock_is_hashed_and_pinned() -> None:
    lock = (ROOT / "requirements.txt").read_text()
    requirements = re.findall(r"^([A-Za-z0-9_.-]+)==\S+ \\$", lock, re.MULTILINE)
    assert [r.lower() for r in requirements] == ["pyyaml"]
    assert lock.count("--hash=sha256:") >= 5


def test_python_is_set_up_before_anything_runs_it() -> None:
    setup = next(i for i, s in enumerate(STEPS) if str(s.get("uses", "")).startswith("actions/setup-python@"))
    assert setup < index("Install SAFO") < index("Mask the credentials") < index("preflight")
