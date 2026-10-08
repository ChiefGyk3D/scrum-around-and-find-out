#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
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
#
# Re-running is safe: every call is a PUT/PATCH to a fixed state, and the tag ruleset is added only when
# the repository has none. The same commands are in GYST's BASELINE.md, which `scripts/audit_baseline.py`
# there checks weekly.
set -euo pipefail

GYST="ChiefGyk3D/git-your-ship-together"
GYST_SHA="804400181a9d3e2f78dfcda5161e2bd960bc011a" # v1.15.0, the pin .github/workflows/ci.yml uses
repo="ChiefGyk3D/scrum-around-and-find-out"
branch="main"
apply=false
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
        -h | --help)
            sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "unknown option $1" ;;
    esac
done
case $repo in */*) ;; *) die "repository must be OWNER/NAME" ;; esac

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

if $apply; then
    command -v gh >/dev/null || die "gh is not installed"
    login=$(gh api user --jq .login)
    echo "applying the baseline to $repo as $login"
else
    echo "plan only (nothing is changed); add --apply to run it against $repo"
fi

protection=$(
    cat <<JSON
{"required_status_checks": {"strict": false, "checks": [$checks_json]},
 "enforce_admins": false,
 "required_pull_request_reviews": {"required_approving_review_count": 0, "dismiss_stale_reviews": true},
 "restrictions": null, "required_linear_history": false,
 "allow_force_pushes": false, "allow_deletions": false, "required_conversation_resolution": false}
JSON
)
call PUT "repos/$repo/branches/$branch/protection" "$protection"

# REST folds a GraphQL bypass-force-push list into allow_force_pushes and a PUT of false cannot clear it
# (pfsense-siem-stack, 2026-10-07). Read the rule back over GraphQL and fail if force pushes are still possible.
owner=${repo%%/*}
name=${repo#*/}
# shellcheck disable=SC2016 # GraphQL variables, not shell expansions
verify='query($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { branchProtectionRules(first: 20) { nodes { pattern allowsForcePushes bypassForcePushAllowances(first: 10) { totalCount } } } } }'
echo "+ gh api graphql -f query='$verify' -f owner=$owner -f name=$name   # then: refuse if force pushes are allowed"
if $apply; then
    bad=$(gh api graphql -f query="$verify" -f owner="$owner" -f name="$name" \
        --jq ".data.repository.branchProtectionRules.nodes[] | select(.pattern == \"$branch\" and (.allowsForcePushes or .bypassForcePushAllowances.totalCount > 0)) | .pattern")
    [ -z "$bad" ] || die "force pushes are still possible on $branch: clear bypassForcePushAllowances with updateBranchProtectionRule"
fi

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
