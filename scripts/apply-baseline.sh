#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Apply GYST's BASELINE.md settings to this repository: branch protection (a pull request and both CI
# gates required), the tag ruleset, private vulnerability reporting, fork-PR approval for every outside
# contributor, the Actions allow-list from GYST's baseline/selected-actions.json, and auto-merge.
#
# THE MAINTAINER RUNS THIS, from a machine whose active `gh` account owns the repository. An agent that
# implements this project writes it and never runs it.
#
#   scripts/apply-baseline.sh                 print every command it would run; changes nothing
#   scripts/apply-baseline.sh --apply         run them
#   scripts/apply-baseline.sh --repo OWNER/NAME [--apply]
#   scripts/apply-baseline.sh --repo OWNER/NAME --mode standard|basic|secret-scanning [--apply] [options]
#
# The default mode (full) is this repository's whole baseline. The other modes change one setting group of any
# repository you own (the branch standard, issue #541): `standard` keeps the rule as it is and turns on up-to-date
# (strict) and conversation resolution, with force push and deletion off; `basic` is the gate for a repository with no
# CI green check (force push and deletion off, nothing required); `secret-scanning` turns on secret scanning and push
# protection on a public repository. They read the live state first (GET only, also without --apply), write a backup of
# the old rule (mode 0600), read the result back, stop at the first mismatch (exit 4) and print ROLLBACK lines.
# Options: --backup-dir DIR, --expect-branch B, --expect-visibility public|private, --expect-protection none|rule.
# A repository that no longer matches an expectation, is archived, is a fork or is not user-owned is refused (exit 3).
#
# Re-running is safe: every call is a PUT/PATCH to a fixed state, and the tag ruleset is added only when
# the repository has none. The same commands are in GYST's BASELINE.md, which `scripts/audit_baseline.py`
# there checks weekly.
set -euo pipefail

GYST="ChiefGyk3D/git-your-ship-together"
GYST_SHA="9e0d7b2e7e8530e2b1bb200ecb4fbf6de021881f" # v1.38.0, the pin .github/workflows/ci.yml uses
repo="ChiefGyk3D/scrum-around-and-find-out"
branch="main"
apply=false
mode="full"
backup_dir=""
expect_branch=""
expect_visibility=""
expect_protection=""
# One required check per shared CI workflow ci.yml calls: the job name, then the gate `CI green`.
checks=("ci / CI green" "shell / CI green")

die() {
    echo "error: $*" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case $1 in
        --apply)
            apply=true
            shift
            ;;
        --repo)
            [ $# -ge 2 ] || die "--repo needs OWNER/NAME"
            repo=$2
            shift 2
            ;;
        --mode | --backup-dir | --expect-branch | --expect-visibility | --expect-protection)
            [ $# -ge 2 ] || die "$1 needs a value"
            case $1 in
                --mode) mode=$2 ;;
                --backup-dir) backup_dir=$2 ;;
                --expect-branch) expect_branch=$2 ;;
                --expect-visibility) expect_visibility=$2 ;;
                --expect-protection) expect_protection=$2 ;;
            esac
            shift 2
            ;;
        -h | --help)
            sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "unknown option $1" ;;
    esac
done
case $repo in */*) ;; *) die "repository must be OWNER/NAME" ;; esac
case $mode in full | standard | basic | secret-scanning) ;; *) die "unknown --mode $mode" ;; esac
case $expect_visibility in "" | public | private) ;; *) die "--expect-visibility is public or private" ;; esac
case $expect_protection in "" | none | rule) ;; *) die "--expect-protection is none or rule" ;; esac

checks_json=""
for context in "${checks[@]}"; do
    checks_json+="${checks_json:+, }{\"context\": \"$context\"}"
done

# Print the command; run it only with --apply. JSON for --input comes on stdin.
call() {
    local method=$1 path=$2 body=${3-}
    shift 3
    echo "+ gh api -X $method $path $*${body:+ --input - <<'JSON'}"
    [ -z "$body" ] || printf '%s\n' "$body"
    [ -z "$body" ] || echo "JSON"
    if $apply; then
        if [ -n "$body" ]; then
            printf '%s' "$body" | gh api -X "$method" "$path" "$@" --input -
        else
            gh api -X "$method" "$path" "$@" >/dev/null
        fi
    fi
}


refuse() {
    echo "REFUSED $repo: $*" >&2
    exit 3
}

mismatch() {
    echo "MISMATCH $repo: $* (stopping; nothing after this change was run)" >&2
    [ -z "${rollback_line-}" ] || echo "$rollback_line" >&2
    exit 4
}

# The jq program that turns a rule as GET returns it (or {} for none) into the body PUT takes. $mode picks the change:
# standard sets strict and conversation resolution, basic and restore keep what is there; force push and deletion are
# off for every mode but restore. A required check keeps its app. Restrictions and bypass lists cannot be carried and
# are refused before this runs.
body_jq='
def checks: if ((.required_status_checks.checks // []) | length) > 0 then .required_status_checks.checks
  else [(.required_status_checks.contexts // [])[] | {context: .}] end;
(.required_pull_request_reviews) as $pr
| {
    required_status_checks: (if .required_status_checks == null then null else
      {strict: (if $mode == "standard" then true else (.required_status_checks.strict // false) end),
       checks: [checks[] | {context: .context} + (if .app_id != null then {app_id: .app_id} else {} end)]} end),
    enforce_admins: (.enforce_admins.enabled // false),
    required_pull_request_reviews: (if $pr == null then null else
      {dismiss_stale_reviews: ($pr.dismiss_stale_reviews // false),
       require_code_owner_reviews: ($pr.require_code_owner_reviews // false),
       required_approving_review_count: ($pr.required_approving_review_count // 0),
       require_last_push_approval: ($pr.require_last_push_approval // false)} end),
    restrictions: null,
    required_linear_history: (.required_linear_history.enabled // false),
    allow_force_pushes: (if $mode == "restore" then (.allow_force_pushes.enabled // false) else false end),
    allow_deletions: (if $mode == "restore" then (.allow_deletions.enabled // false) else false end),
    required_conversation_resolution: (if $mode == "standard" then true else (.required_conversation_resolution.enabled // false) end),
    block_creations: (.block_creations.enabled // false),
    lock_branch: (.lock_branch.enabled // false),
    allow_fork_syncing: (.allow_fork_syncing.enabled // false)
  }'

repo_json=""
live_branch=""

# Read the repository and refuse anything the owner did not plan: archived, a fork, not user-owned, or different from
# the snapshot the plan was made from (default branch, visibility).
check_target() {
    repo_json=$(gh api "repos/$repo") || die "cannot read $repo"
    jq -e '.archived == false' <<<"$repo_json" >/dev/null || refuse "the repository is archived"
    jq -e '.fork == false' <<<"$repo_json" >/dev/null || refuse "the repository is a fork"
    jq -e '.owner.type == "User"' <<<"$repo_json" >/dev/null || refuse "the owner is not a user account"
    live_branch=$(jq -r '.default_branch // empty' <<<"$repo_json")
    [ -n "$live_branch" ] || refuse "no default branch (an empty repository)"
    [ -z "$expect_branch" ] || [ "$live_branch" = "$expect_branch" ] ||
        refuse "the default branch is '$live_branch', the snapshot said '$expect_branch'"
    local vis=public
    jq -e '.private == true' <<<"$repo_json" >/dev/null && vis=private
    [ -z "$expect_visibility" ] || [ "$vis" = "$expect_visibility" ] ||
        refuse "the visibility is $vis, the snapshot said $expect_visibility"
    live_visibility=$vis
}

# Print the rule as JSON, or the word NONE when the branch has no rule; any other failure stops.
read_rule() {
    local out
    if out=$(gh api "repos/$repo/branches/$branch/protection" 2>&1); then
        printf '%s' "$out"
    else
        case $out in
            *"Branch not protected"*) echo NONE ;;
            *) die "cannot read the protection of $repo: $out" ;;
        esac
    fi
}

stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_base() {
    local dir=${backup_dir:-${SAFO_BACKUP_DIR:-${XDG_STATE_HOME:-${HOME:?HOME is not set; pass --backup-dir}/.local/state}/safo/protection-backups}}
    echo "$dir/${repo//\//__}-$stamp"
}

write_private() { # file, content; the file is created 0600 in a 0700 directory
    local dir
    dir=$(dirname "$1")
    (umask 077 && mkdir -p "$dir" && chmod 700 "$dir" && printf '%s\n' "$2" >"$1")
}

run_branch_mode() {
    check_target
    branch=$live_branch
    local rule current req_json
    rule=$(read_rule)
    case $expect_protection in
        none) [ "$rule" = NONE ] || refuse "the snapshot said no protection rule, one exists now" ;;
        rule) [ "$rule" != NONE ] || refuse "the snapshot said a protection rule exists, there is none now" ;;
    esac
    current=$rule
    [ "$rule" != NONE ] || current='{}'
    jq -e '.restrictions == null' <<<"$current" >/dev/null ||
        die "$repo has push restrictions on $branch; this script cannot carry them (restrictions)"
    jq -e '(.required_pull_request_reviews.dismissal_restrictions // null) == null and
        (.required_pull_request_reviews.bypass_pull_request_allowances // null) == null' <<<"$current" >/dev/null ||
        die "$repo has review dismissal or bypass lists on $branch; this script cannot carry them"
    if [ "$mode" = standard ]; then
        jq -e '[((.required_status_checks.checks // [])[] | .context), ((.required_status_checks.contexts // [])[])]
            | any(. == "CI green" or endswith(" / CI green"))' <<<"$current" >/dev/null ||
            die "$repo has no CI green check on $branch; use --mode basic for it (never guessed)"
    fi
    req_json=$(jq -c --arg mode "$mode" "$body_jq" <<<"$current")
    local want
    want=$(jq -c '{strict: (.required_status_checks.strict // false), conv: .required_conversation_resolution,
        admins: .enforce_admins, contexts: ([.required_status_checks.checks[]?.context] | sort)}' <<<"$req_json")

    local base restore_file rule_file
    base=$(backup_base)
    rule_file="$base.rule.json"
    restore_file="$base.restore.json"
    if [ "$rule" = NONE ]; then
        rollback_line="ROLLBACK: gh api -X DELETE repos/$repo/branches/$branch/protection"
    else
        rollback_line="ROLLBACK: gh api -X PUT repos/$repo/branches/$branch/protection --input $restore_file"
    fi
    if $apply; then echo "applying --mode $mode to $repo ($live_visibility, branch $branch)"; else
        echo "plan only (nothing is changed); add --apply to run it against $repo ($live_visibility, branch $branch, mode $mode)"
    fi
    [ "$rule" = NONE ] && echo "current rule: none" || echo "current rule: backed up to $rule_file at apply"
    echo "$rollback_line"
    if $apply; then
        write_private "$rule_file" "$rule"
        write_private "$restore_file" "$(jq -c --arg mode restore "$body_jq" <<<"$current")"
    fi
    call PUT "repos/$repo/branches/$branch/protection" "$req_json"
    if $apply; then
        local got
        got=$(read_rule)
        [ "$got" != NONE ] || mismatch "the rule is gone after the write"
        jq -e --argjson want "$want" '
            (.allow_force_pushes.enabled == false) and (.allow_deletions.enabled == false)
            and ((.required_status_checks.strict // false) == $want.strict)
            and ((.required_conversation_resolution.enabled // false) == $want.conv)
            and ((.enforce_admins.enabled // false) == $want.admins)
            and (([.required_status_checks.checks[]?.context] | sort) == $want.contexts)' <<<"$got" >/dev/null ||
            mismatch "the rule read back differs from the one written"
        force_bypass_check
        echo "OK $repo: $mode applied and read back"
    fi
}

# REST folds a GraphQL bypass-force-push list into allow_force_pushes and a PUT of false cannot clear it
# (pfsense-siem-stack, 2026-10-07). Read the rule back over GraphQL and fail if force pushes are still possible.
force_bypass_check() {
    local owner=${repo%%/*} name=${repo#*/} bad
    # shellcheck disable=SC2016 # GraphQL variables, not shell expansions
    local verify='query($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { branchProtectionRules(first: 20) { nodes { pattern allowsForcePushes bypassForcePushAllowances(first: 10) { totalCount } } } } }'
    echo "+ gh api graphql -f query='$verify' -f owner=$owner -f name=$name   # then: refuse if force pushes are allowed"
    if $apply; then
        bad=$(gh api graphql -f query="$verify" -f owner="$owner" -f name="$name" \
            --jq ".data.repository.branchProtectionRules.nodes[] | select(.pattern == \"$branch\" and (.allowsForcePushes or .bypassForcePushAllowances.totalCount > 0)) | .pattern")
        [ -z "$bad" ] || die "force pushes are still possible on $branch: clear bypassForcePushAllowances with updateBranchProtectionRule"
    fi
}

run_secret_scanning() {
    check_target
    [ "$live_visibility" = public ] || refuse "the repository is private; secret scanning here is for public repositories"
    local ss pp
    ss=$(jq -r '.security_and_analysis.secret_scanning.status // empty' <<<"$repo_json")
    pp=$(jq -r '.security_and_analysis.secret_scanning_push_protection.status // empty' <<<"$repo_json")
    [ -n "$ss" ] && [ -n "$pp" ] || die "cannot read the secret scanning state of $repo"
    if [ "$ss" = enabled ] && [ "$pp" = enabled ]; then
        echo "secret scanning and push protection are already enabled on $repo; nothing to do"
        return 0
    fi
    local fields=() undo=()
    if [ "$ss" != enabled ]; then
        fields+=(-f 'security_and_analysis[secret_scanning][status]=enabled')
        undo+=("-f 'security_and_analysis[secret_scanning][status]=$ss'")
    fi
    if [ "$pp" != enabled ]; then
        fields+=(-f 'security_and_analysis[secret_scanning_push_protection][status]=enabled')
        undo+=("-f 'security_and_analysis[secret_scanning_push_protection][status]=$pp'")
    fi
    rollback_line="ROLLBACK: gh api -X PATCH repos/$repo ${undo[*]}"
    if $apply; then echo "applying --mode secret-scanning to $repo"; else
        echo "plan only (nothing is changed); add --apply to run it against $repo (mode secret-scanning)"
    fi
    echo "current: secret_scanning=$ss push_protection=$pp"
    echo "$rollback_line"
    if $apply; then
        write_private "$(backup_base).security.json" "$(jq -c '.security_and_analysis' <<<"$repo_json")"
    fi
    call PATCH "repos/$repo" "" "${fields[@]}"
    if $apply; then
        local got
        got=$(gh api "repos/$repo") || die "cannot read $repo back"
        jq -e '.security_and_analysis.secret_scanning.status == "enabled"
            and .security_and_analysis.secret_scanning_push_protection.status == "enabled"' <<<"$got" >/dev/null ||
            mismatch "secret scanning or push protection is not enabled after the write"
        echo "OK $repo: secret scanning and push protection enabled and read back"
    fi
}

rollback_line=""
live_visibility=""

if [ "$mode" != full ]; then
    command -v jq >/dev/null || die "jq is not installed"
    command -v gh >/dev/null || die "gh is not installed"
    case $mode in
        standard | basic) run_branch_mode ;;
        secret-scanning) run_secret_scanning ;;
    esac
    exit 0
fi

if $apply; then
    command -v gh >/dev/null || die "gh is not installed"
    login=$(gh api user --jq .login)
    echo "applying the baseline to $repo as $login"
else
    echo "plan only (nothing is changed); add --apply to run it against $repo"
fi

protection=$(
    cat <<JSON
{"required_status_checks": {"strict": true, "checks": [$checks_json]},
 "enforce_admins": false,
 "required_pull_request_reviews": {"required_approving_review_count": 0, "dismiss_stale_reviews": true},
 "restrictions": null, "required_linear_history": false,
 "allow_force_pushes": false, "allow_deletions": false, "required_conversation_resolution": true}
JSON
)
if $apply; then
    command -v jq >/dev/null || die "jq is not installed"
    old_rule=$(read_rule)
    base=$(backup_base)
    write_private "$base.rule.json" "$old_rule"
    if [ "$old_rule" = NONE ]; then
        rollback_line="ROLLBACK: gh api -X DELETE repos/$repo/branches/$branch/protection"
    else
        write_private "$base.restore.json" "$(jq -c --arg mode restore "$body_jq" <<<"$old_rule")"
        rollback_line="ROLLBACK: gh api -X PUT repos/$repo/branches/$branch/protection --input $base.restore.json"
    fi
    echo "$rollback_line"
else
    echo "an --apply run backs up the current rule (mode 0600) and prints a ROLLBACK line first"
fi
call PUT "repos/$repo/branches/$branch/protection" "$protection"
if $apply; then
    got=$(read_rule)
    [ "$got" != NONE ] || mismatch "the rule is gone after the write"
    jq -e --argjson want "$(jq -c '{contexts: ([.required_status_checks.checks[].context] | sort)}' <<<"$protection")" '
        .required_status_checks.strict == true and .required_conversation_resolution.enabled == true
        and .allow_force_pushes.enabled == false and .allow_deletions.enabled == false
        and (([.required_status_checks.checks[]?.context] | sort) == $want.contexts)' <<<"$got" >/dev/null ||
        mismatch "the rule read back is not the baseline that was written"
fi

# The force-push bypass read-back (see force_bypass_check).
force_bypass_check

call PUT "repos/$repo/actions/permissions/workflow" "" -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
call PUT "repos/$repo/actions/permissions/fork-pr-contributor-approval" "" -f approval_policy=all_external_contributors

selected="repos/$GYST/contents/baseline/selected-actions.json?ref=$GYST_SHA"
echo "+ gh api $selected --jq .content | base64 -d > selected-actions.json   # GYST's list, at the pinned commit"
echo "+ gh api -X PUT repos/$repo/actions/permissions/selected-actions --input selected-actions.json"
if $apply; then
    list=$(mktemp)
    trap 'rm -f "$list"' EXIT
    gh api "$selected" --jq .content | base64 -d >"$list"
    jq -e . >"$list.jq" <"$list" || die "allow-list is not valid JSON"
    mv "$list.jq" "$list"
    gh api -X PUT "repos/$repo/actions/permissions/selected-actions" --input "$list" >/dev/null
fi

call PUT "repos/$repo/actions/permissions" "" -F enabled=true -f allowed_actions=selected

call PATCH "repos/$repo" "" -f 'security_and_analysis[secret_scanning][status]=enabled' \
    -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
call PUT "repos/$repo/private-vulnerability-reporting" ""
call PUT "repos/$repo/automated-security-fixes" ""
call PATCH "repos/$repo" "" -F allow_auto_merge=true

ruleset='{"name": "Version tags are immutable", "target": "tag", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
 "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "update"}]}'
has_tag_ruleset=""
if $apply; then
    has_tag_ruleset=$(gh api "repos/$repo/rulesets" --jq '.[] | select(.target == "tag") | .id')
fi
if [ -n "$has_tag_ruleset" ]; then
    echo "a tag ruleset exists already; not adding another"
else
    call POST "repos/$repo/rulesets" "$ruleset"
fi

echo "done. Next: run GYST's audit (python scripts/audit_baseline.py) with $repo in baseline/repos.txt."
