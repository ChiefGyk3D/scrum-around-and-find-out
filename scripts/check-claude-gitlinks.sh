#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fail when the index holds a gitlink (mode 160000, an embedded repository or submodule) under .claude/.
# An agent worktree under .claude/worktrees/ looks like a nested repository, so `git add -A` records it as a
# gitlink (#86). A legitimate submodule outside .claude/ is not flagged.
#
#   scripts/check-claude-gitlinks.sh                  run in a checkout; 0 clean, 1 gitlink found, 2 cannot tell
#   scripts/check-claude-gitlinks.sh --require-ignore also fail when .claude/worktrees/ is not git-ignored
#
# Reads the index of the current directory's repository, which in CI is the pull request's tree. No network.
set -euo pipefail

require_ignore=false
case ${1-} in
    "") ;;
    --require-ignore) require_ignore=true ;;
    -h | --help)
        sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        echo "error: unknown option $1" >&2
        exit 2
        ;;
esac

root=$(git rev-parse --show-toplevel 2>/dev/null) || {
    echo "error: not inside a git checkout" >&2
    exit 2
}
cd "$root"

status=0
# -z: NUL-separated, so a path with spaces or newlines is named whole. Format: "<mode> <sha> <stage>\t<path>".
while IFS= read -r -d '' entry; do
    mode=${entry%% *}
    path=${entry#*$'\t'}
    if [ "$mode" = "160000" ]; then
        case $path in
            .claude/*)
                echo "error: gitlink (embedded repository) staged at $path; remove it with 'git rm --cached' and ignore .claude/worktrees/" >&2
                status=1
                ;;
        esac
    fi
done < <(git ls-files -s -z)

if $require_ignore && ! git check-ignore -q .claude/worktrees/probe; then
    echo "error: .claude/worktrees/ is not ignored; add '.claude/worktrees/' to .gitignore" >&2
    status=1
fi

[ "$status" -ne 0 ] || echo "ok: no gitlink under .claude/"
exit "$status"
