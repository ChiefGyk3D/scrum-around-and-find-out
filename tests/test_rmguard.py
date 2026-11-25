# SPDX-License-Identifier: Apache-2.0
"""The shared-directory deletion guard (#422): the command that did the damage, its cousins, and what stays allowed."""

from __future__ import annotations

import io
import json
import time
from pathlib import Path
from typing import Any

import pytest

from safo import rmguard

HOME = "/home/u"
DEV = f"{HOME}/.local/share/reach-around-dev"
AGENT = f"{DEV}/agents/422-reviewer"
LEAD = ".local/share/reach-around-lead"
PAD = "/tmp/claude-1000/-home-u-src/abc123/scratchpad"

# The exact command that deleted another session's logs and helper scripts on 2026-11-23.
DAMAGE = f"cd {DEV} && rm -rf build *.py *.log"
DAMAGE_TILDE = "rm -rf ~/.local/share/reach-around-dev/*.py ~/.local/share/reach-around-dev/*.log"

BLOCKED = [
    pytest.param(DAMAGE, "/home/u", id="damage-cd-glob"),
    pytest.param("rm -rf *.py *.log", DEV, id="damage-cwd-glob"),
    pytest.param(DAMAGE_TILDE, "/home/u", id="damage-tilde-glob"),
    pytest.param(f"rm -rf {DEV}/*.py", "/", id="absolute-glob"),
    pytest.param(f"rm -f {DEV}/logs/?.log", "/", id="question-glob"),
    pytest.param(f"rm {DEV}/x[12].log", "/", id="bracket-glob"),
    pytest.param(f"rm -rf {DEV}/{{a,b}}", "/", id="brace-list"),
    pytest.param(f"find {DEV} -name '*.log' -delete", "/", id="find-delete"),
    pytest.param("find . -name '*.pyc' -delete", DEV, id="find-delete-cwd"),
    pytest.param(f"find {DEV} -type f -exec rm {{}} +", "/", id="find-exec-rm"),
    pytest.param(f"find {DEV} -execdir rm -f {{}} \\;", "/", id="find-execdir-rm"),
    pytest.param(f"rm -rf {DEV}", "/", id="parent-shared-root"),
    pytest.param(f"rm -r {DEV}/", "/", id="parent-trailing-slash"),
    pytest.param(f"rm -rf {DEV}/agents", "/", id="parent-agents-folder"),
    pytest.param(f"rm -rf {DEV}/agents/../other", "/", id="dotdot-out-of-agent"),
    pytest.param("rm -rf ~/.local/share", "/", id="ancestor-share"),
    pytest.param("rm -rf $HOME/.local/share/*-dev", "/", id="ancestor-glob-all-dev"),
    pytest.param("rm -rf ~", "/", id="ancestor-home"),
    pytest.param(f"rm -rf {HOME}/.local/share/other-dev/x", "/", id="other-dev-dir"),
    pytest.param(f"rm {DEV}/session.log", "/", id="exact-file-outside-agent"),
    pytest.param("rm -rf ..", f"{DEV}/agents", id="relative-parent"),
    pytest.param("cd agents && rm -rf ../*", DEV, id="cd-then-parent-glob"),
    pytest.param("rm -rf /tmp/claude-1000", "/", id="scratchpad-parent"),
    pytest.param("rm -rf /tmp/claude-1000/*", "/", id="scratchpad-parent-glob"),
    pytest.param(f"rm -rf {PAD}/../other", "/", id="scratchpad-dotdot"),
    pytest.param(f"rm -rf {PAD}", "/", id="scratchpad-itself"),
    pytest.param(f"rm -rf {PAD}/*", "/", id="scratchpad-glob"),
    pytest.param(f"sudo rm -rf {DEV}/*.log", "/", id="sudo-wrapper"),
    pytest.param(f"env FOO=1 nice -n 5 rm -rf {DEV}/*.log", "/", id="env-nice-wrapper"),
    pytest.param(f"/bin/rm -rf {DEV}/*.log", "/", id="absolute-rm"),
    pytest.param(f"\\rm -rf {DEV}/*.log", "/", id="backslash-rm"),
    pytest.param(f"r''m -rf {DEV}/*.log", "/", id="quoted-rm-word"),
    pytest.param(f"echo ok; true && rm -rf {DEV}/*.log", "/", id="after-separator"),
    pytest.param(f"(rm -rf {DEV}/*.log)", "/", id="subshell"),
    pytest.param(f"bash -c 'rm -rf {DEV}/*.log'", "/", id="bash-c"),
    pytest.param(f'sh -c "cd {DEV} && rm -rf *.log"', "/", id="sh-c-cd"),
    pytest.param(f"eval 'rm -rf {DEV}/*.log'", "/", id="eval"),
    pytest.param(f"echo $(rm -rf {DEV}/*.log)", "/", id="substitution"),
    pytest.param(f"echo `rm -rf {DEV}/*.log`", "/", id="backticks"),
    pytest.param(f"cat <<EOF\n$(rm -rf {DEV}/*.log)\nEOF", "/", id="heredoc-substitution"),
    pytest.param(f"ls {DEV}/*.log | xargs rm", "/", id="xargs-rm-mentions-zone"),
    pytest.param("ls | xargs rm -f", DEV, id="xargs-rm-in-zone"),
    pytest.param("unlink ~/.local/share/reach-around-dev/x.log", "/", id="unlink"),
    pytest.param(f"shred -u {DEV}/*.log", "/", id="shred-glob"),
    pytest.param(f"rm -rf {AGENT}/*.log", "/", id="glob-even-in-own-folder"),
    pytest.param(f"sudo -u root rm -rf {DEV}/*.log", "/", id="sudo-option-value"),
    pytest.param(f"timeout 5 rm -rf {DEV}/*.log", "/", id="timeout-duration"),
    pytest.param(f"flock /tmp/l rm -rf {DEV}/*.log", "/", id="flock-operand"),
    pytest.param("find . -print0 | xargs -0 -n1 rm -rf", DEV, id="xargs-options"),
    pytest.param(f"rm -rf {DEV}/*.log >/dev/null 2>&1", "/", id="redirects-dont-hide-targets"),
    # round 2 (#423 review): redirects glued to or ahead of the command word
    pytest.param(f"rm>/dev/null -rf {DEV}/*.log", "/", id="r2-redirect-glued"),
    pytest.param(f"2>&1 rm -rf {DEV}/*.log", "/", id="r2-leading-fd-redirect"),
    pytest.param(f">/dev/null rm -rf {DEV}/*.log", "/", id="r2-leading-redirect"),
    pytest.param(f"&>/dev/null rm -rf {DEV}/*.log", "/", id="r2-leading-amp-redirect"),
    pytest.param(f"FOO=1 </dev/null rm -rf {DEV}/*.log", "/", id="r2-assignment-then-redirect"),
    pytest.param(f"rm -rf {DEV}/*.log>x", "/", id="r2-redirect-glued-to-target"),
    # round 2: ANSI-C and locale quoting, unknown expansions
    pytest.param(f"$'rm' -rf {DEV}/*.log", "/", id="r2-ansi-c-command"),
    pytest.param(f"$'r\\x6d' -rf {DEV}/*.log", "/", id="r2-ansi-c-hex-command"),
    pytest.param(f'$"rm" -rf {DEV}/*.log', "/", id="r2-locale-quoted-command"),
    pytest.param(f"rm -rf $'{DEV}'", "/", id="r2-ansi-c-target"),
    pytest.param(f"rm -rf $'{DEV}'/*.log", "/", id="r2-ansi-c-target-glob"),
    pytest.param("rm -rf $+x", "/", id="r2-unrecognized-expansion"),
    # round 2: leading double slash names the same file
    pytest.param(f"rm -rf /{DEV}/*.log", "/", id="r2-double-slash-glob"),
    pytest.param(f"rm -rf //{DEV}", "/", id="r2-triple-slash-root"),
    pytest.param(f"rm -rf /{AGENT}/../../x", "/", id="r2-double-slash-dotdot"),
    # round 2: a quoted non-recursive expansion with a zone in sight, or no cwd to judge by
    pytest.param(f'for f in {DEV}/*.log; do rm "$f"; done', "/work", id="r2-loop-over-zone-glob"),
    pytest.param('cd "$X"; rm "$f"', "/work", id="r2-unknown-cwd-quoted"),
    pytest.param('rm "$f"', DEV, id="r2-cwd-in-zone-quoted"),
    # round 2: the shell's cwd is not what a naive cd tracker says
    pytest.param("cd ~/.local/share/reach-around-dev && (cd /work); rm *.log", "/", id="r2-subshell-cd"),
    pytest.param("cd ~/.local/share/reach-around-dev; cd /work & rm *.log", "/", id="r2-background-cd"),
    pytest.param("cd ~/.local/share/reach-around-dev || true; rm *.log", "/", id="r2-cd-or"),
    pytest.param("pushd ~/.local/share/reach-around-dev; pushd /work; popd; rm *.log", "/", id="r2-popd"),
    pytest.param("env -C ~/.local/share/reach-around-dev rm -rf *.log", "/", id="r2-env-C"),
    pytest.param(f"env --chdir={DEV} rm -rf *.log", "/", id="r2-env-chdir-eq"),
    pytest.param(f"env --chdir {DEV} rm -rf *.log", "/", id="r2-env-chdir"),
    pytest.param("env -S 'rm -rf *.log'", DEV, id="r2-env-S"),
    pytest.param(f"env -S'rm -rf {DEV}/*.log'", "/", id="r2-env-S-attached"),
    pytest.param(f"env --split-string='rm -rf {DEV}/*.log'", "/", id="r2-env-split-string"),
    pytest.param(f"env -S 'rm -rf' {DEV}/*.log", "/", id="r2-env-S-rest"),
    # round 2: find -exec through wrappers and unknown tools
    pytest.param(f"find {DEV} -exec env rm -rf {{}} +", "/", id="r2-find-exec-env"),
    pytest.param(f"find {DEV} -exec xargs rm {{}} \\;", "/", id="r2-find-exec-xargs"),
    pytest.param(f"find {DEV} -exec eval rm {{}} \\;", "/", id="r2-find-exec-eval"),
    pytest.param(f"find {DEV} -exec nice rm {{}} +", "/", id="r2-find-exec-nice"),
    pytest.param(f"find {DEV} -exec sudo -u root rm {{}} +", "/", id="r2-find-exec-sudo"),
    pytest.param(f"find {DEV} -exec sometool {{}} +", "/", id="r2-find-exec-unknown-tool"),
    # round 2: HOME redefined, so ~ and $HOME are unknown
    pytest.param("HOME=/x rm -rf ~/.local/share/reach-around-dev/agents/422-reviewer", "/", id="r2-home-prefix"),
    pytest.param("export HOME=/x; rm -rf $HOME/.local/share/reach-around-dev/agents/a", "/", id="r2-home-export"),
    pytest.param("HOME=/x; rm -rf ~/y", "/", id="r2-home-assign-tilde"),
    pytest.param('rm -rf "${HOME:=/x}/y"', "/", id="r2-home-default-assign"),
    pytest.param("S=~/.local/share/reach-around-dev; rm -rf $S/x", "/", id="variable-names-zone"),
    pytest.param("S=/work; for S in ~/.local/share/reach-around-dev; do rm -rf $S/x; done", "/", id="loop-retaints"),
    pytest.param("S=/work; S+=/../x; rm -rf $S", "/", id="append-taints"),
    pytest.param("S=/work rm -rf $S/y; rm -rf $S/z", "/", id="prefix-assignment-is-not-bound-yet"),
    # round 3: a delete word the gate's text search cannot see, against a zone target
    pytest.param(f"r\\\nm -rf {DEV}/*.log", "/", id="r3-backslash-newline-in-word"),
    pytest.param(f"r$'m' -rf {DEV}/*.log", "/", id="r3-ansi-c-piece"),
    pytest.param(f"r? -rf {DEV}/*.log", "/", id="r3-question-glob-command"),
    pytest.param(f"r[m] -rf {DEV}/*.log", "/", id="r3-bracket-glob-command"),
    pytest.param(f"/bin/r* -rf {DEV}/*.log", "/", id="r3-star-glob-command"),
    pytest.param(f"unli[n]k {DEV}/a.log", "/", id="r3-bracket-unlink"),
    pytest.param(f"r{{m,}} -rf {DEV}/*.log", "/", id="r3-brace-command"),
    pytest.param(f"$RM -rf {DEV}/*.log", "/", id="r3-expansion-command"),
    pytest.param(f"${{RM}} -rf {DEV}/a.log", "/", id="r3-braced-expansion-command"),
    pytest.param(f"`echo rm` -rf {DEV}/*.log", "/", id="r3-backtick-command"),
    pytest.param(f'"$RM" -rf {DEV}/*.log', "/", id="r3-quoted-expansion-command"),
    pytest.param("$RM -rf *.log", DEV, id="r3-expansion-command-cwd-in-zone"),
    # round 4 (Daybreak): D3 agent folder roots are removed by the owner in a batch
    pytest.param(f"rm -rf {AGENT}", "/", id="d3-agent-root-recursive"),
    pytest.param(f"rm -r {AGENT}/", "/", id="d3-agent-root-trailing-slash"),
    pytest.param(f"rm -rf {DEV}/agents/other-session", "/", id="d3-other-agent-root"),
    pytest.param(f"rmdir {AGENT}", "/", id="d3-agent-root-rmdir"),
    pytest.param("rm -rf ~/.local/share/reach-around-dev/agents/422-reviewer", "/", id="d3-agent-root-tilde"),
    pytest.param("rm -rf $HOME/.local/share/reach-around-dev/agents/422-reviewer", "/", id="d3-agent-root-home-var"),
    pytest.param(f"find {AGENT} -name '*.pyc' -delete", "/", id="d3-find-start-at-agent-root"),
    pytest.param("find . -delete", AGENT, id="d3-find-cwd-agent-root"),
    pytest.param("rm -rf ../../other", f"{AGENT}/work", id="d3-dotdot-out-of-agent-folder"),
    # D1: every command is evaluated when the cwd is inside a zone; other destructive programs
    pytest.param("git clean -fdx", DEV, id="d1-git-clean-cwd-zone"),
    pytest.param("git clean -fdx", f"{DEV}/repo", id="d1-git-clean-cwd-zone-subdir"),
    pytest.param(f"git -C {DEV} clean -fd", "/", id="d1-git-clean-dash-C"),
    pytest.param(f"git clean -fdx -- {DEV}/x", "/", id="d1-git-clean-pathspec"),
    pytest.param(f"truncate -s 0 {DEV}/a.log", "/", id="d1-truncate"),
    pytest.param("truncate -s0 *.log", DEV, id="d1-truncate-glob-cwd"),
    pytest.param(f"rsync -a --delete /work/src/ {DEV}/dest/", "/", id="d1-rsync-delete"),
    pytest.param(f"rsync --remove-source-files {DEV}/a.log /work/", "/", id="d1-rsync-remove-source"),
    pytest.param(f"tar --remove-files -cf /work/x.tar -C {DEV} .", "/", id="d1-tar-remove-files-C"),
    pytest.param("tar --remove-files -cf /work/x.tar .", DEV, id="d1-tar-remove-files-cwd"),
    pytest.param(f"mv {DEV}/a.log /work/", "/", id="d1-mv-source-in-zone"),
    pytest.param(f"mv /work/x {DEV}/a.log", "/", id="d1-mv-onto-zone"),
    pytest.param(f"mv -t {DEV} /work/x", "/", id="d1-mv-target-dir"),
    pytest.param(f"cp /dev/null {DEV}/a.log", "/", id="d1-cp-dev-null"),
    pytest.param(f"dd if=/dev/null of={DEV}/a.log", "/", id="d1-dd-of"),
    # D2: GNU find global options before the start path
    pytest.param(f"find -H {DEV} -delete", "/work", id="d2-find-H"),
    pytest.param(f"find -L {DEV} -delete", "/work", id="d2-find-L"),
    pytest.param(f"find -P {DEV} -delete", "/work", id="d2-find-P"),
    pytest.param(f"find -O3 {DEV} -delete", "/work", id="d2-find-O3"),
    pytest.param(f"find -D tree {DEV} -delete", "/work", id="d2-find-D-tree"),
    pytest.param(f"find -H -L -P -O2 -D opt,exec {DEV} -name x -delete", "/work", id="d2-find-all-options"),
    pytest.param("find -H -delete", DEV, id="d2-find-option-then-default-start"),
    pytest.param("find -files0-from /work/list -delete", "/work", id="d2-find-files0-from"),
    pytest.param(f"find -H {DEV} -exec rm {{}} +", "/work", id="d2-find-H-exec"),
    # A1: arithmetic bodies are scanned for substitutions
    pytest.param(f"echo $(( $(rm -rf {DEV}/*.log) + 1 ))", "/", id="a1-arith-substitution"),
    pytest.param(f"echo $(( `rm -rf {DEV}/*.log` ))", "/", id="a1-arith-backtick"),
    pytest.param(f"echo $(( 1 + $(( $(rm -rf {DEV}/*.log) )) ))", "/", id="a1-arith-nested"),
    # A2: evaluated, so a syntax error is a deny
    pytest.param(f'ls {DEV}/*.log "unterminated', "/", id="a2-zone-syntax-error"),
    pytest.param("echo $'unterminated", "/", id="a2-ansi-unterminated"),
    pytest.param('echo "x $HOME', "/", id="a2-suspect-unterminated"),
    # A3: HOME changed by means the first scan missed
    pytest.param('export H""OME=/x; rm -rf ~/y', "/", id="a3-home-quoted-name"),
    pytest.param("export H\\OME=/x; rm -rf ~/y", "/", id="a3-home-backslash-name"),
    pytest.param("read HOME <<< /x; rm -rf ~/y", "/", id="a3-home-read"),
    pytest.param("declare HOME=/x; rm -rf ~/y", "/", id="a3-home-declare"),
    pytest.param("printf -v HOME %s /x; rm -rf ~/y", "/", id="a3-home-printf-v"),
    pytest.param("source ./env.sh; rm -rf ~/y/z", "/", id="a3-home-source"),
    pytest.param("eval 'x=1'; rm -rf ~/y", "/", id="a3-home-eval"),
    pytest.param("bash -c 'HOME=/x rm -rf ~/y'", "/", id="a3-home-nested"),
    # A4: a variable assigned conditionally, in a pipe, a subshell, the background or eval is unknown afterwards
    pytest.param("S=~/.local/share/reach-around-dev; false && S=/work; rm -rf $S/y", "/", id="a4-and-assignment"),
    pytest.param("S=~/.local/share/reach-around-dev; false || S=/work; rm -rf $S/y", "/", id="a4-or-assignment"),
    pytest.param("S=~/.local/share/reach-around-dev; S=/work | cat; rm -rf $S/y", "/", id="a4-pipe-assignment"),
    pytest.param("S=~/.local/share/reach-around-dev; (S=/work); rm -rf $S/y", "/", id="a4-subshell-assignment"),
    pytest.param("S=~/.local/share/reach-around-dev; S=/work & rm -rf $S/y", "/", id="a4-background-assignment"),
    pytest.param("S=~/.local/share/reach-around-dev; eval 'S=/work'; rm -rf $S/y", "/", id="a4-eval-assignment"),
    pytest.param(
        "f() { S=/work; }; S=~/.local/share/reach-around-dev; f; rm -rf $S/y", "/", id="a4-function-assignment"
    ),
    pytest.param('bash -c "rm -rf $D/*.log"', "/", id="a2-bash-c-with-unknown-piece-and-delete"),
    pytest.param('bash -c "$CMD"', DEV, id="a2-bash-c-whole-body-unknown"),
    # fail closed: it cannot tell where these point
    pytest.param('rm -rf "$SOMEDIR"', "/", id="unknown-expansion-recursive"),
    pytest.param("rm -f $SOMEFILE", "/", id="unknown-expansion-unquoted"),
    pytest.param('cd "$X" && rm -rf *.log', "/", id="cd-unknown-glob"),
    pytest.param(f"rm -rf {DEV}/*.log 'unterminated", "/", id="unterminated-quote"),
    pytest.param(f'bash -c "bash -c \\"bash -c \'bash -c \\\\\\"rm -rf {DEV}/*.log\\\\\\"\'\\""', "/", id="deep"),
]

ALLOWED = [
    pytest.param(f"rm -rf {AGENT}/venv", "/", id="own-subfolder-exact"),
    pytest.param(f"rm {AGENT}/old.log {AGENT}/old.py", "/", id="own-files-exact"),
    pytest.param("rm -rf venv", AGENT, id="relative-exact-in-own-folder"),
    pytest.param("cd ~/.local/share/reach-around-dev/agents/422-reviewer && rm -rf repo", "/", id="cd-then-exact"),
    pytest.param(f"find {AGENT}/work -name '*.pyc' -delete", "/", id="find-delete-in-own-folder"),
    pytest.param("find . -name '*.pyc' -delete", f"{AGENT}/work", id="find-delete-cwd-own-folder"),
    pytest.param(f"rm -rf {PAD}/work", "/", id="scratchpad-exact"),
    pytest.param(f"ls {AGENT}/work | xargs rm", f"{AGENT}/work", id="xargs-in-own-folder"),
    pytest.param("rm -rf build dist *.egg-info", "/work/repo", id="outside-glob"),
    pytest.param("rm -rf ~/src/project/node_modules", "/", id="outside-exact"),
    pytest.param("rm -f /tmp/safo-test.log", "/", id="tmp-file-outside-claude"),
    pytest.param('rm -f "$f"', "/work", id="quoted-nonrecursive-expansion"),
    pytest.param("find /var/log -name '*.old' -print", "/", id="find-without-delete"),
    pytest.param(f"find {DEV} -name '*.log'", "/", id="find-read-only-in-zone"),
    pytest.param(f"ls {DEV}/*.log", "/", id="ls-glob-in-zone"),
    pytest.param(f"echo rm -rf {DEV}/*.log", "/", id="echo-is-data"),
    pytest.param(f"git commit -m 'rm -rf {DEV}/*.log is blocked'", "/", id="commit-message-is-data"),
    pytest.param(f"cat <<'EOF'\nrm -rf {DEV}/*.log\nEOF", "/", id="quoted-heredoc-is-data"),
    pytest.param(f"echo hi # rm -rf {DEV}/*.log", "/", id="comment-is-data"),
    pytest.param('git commit -m "it\'s fine"', "/", id="apostrophe-in-double-quotes"),
    pytest.param("echo 'unterminated", "/", id="unterminated-no-delete-word"),
    pytest.param("ls", "/", id="plain"),
    pytest.param('bash -c "$CMD"', "/work", id="a2-bash-c-whole-body-unknown-outside-zone"),
    pytest.param(
        'timeout 4 bash -c "echo > /dev/tcp/$h/$p"', "/work", id="d1-bash-c-with-unknown-pieces-and-no-delete"
    ),
    # round 4: what stays allowed
    pytest.param(f"rm -rf {AGENT}/sub/dir", "/", id="d3-recursive-subdir-below-agent-root"),
    pytest.param(f"rm {AGENT}/f.log", "/", id="d3-file-below-agent-root"),
    pytest.param("git clean -fdx", f"{AGENT}/work", id="d1-git-clean-in-agent-folder"),
    pytest.param("git clean -n", DEV, id="d1-git-clean-dry-run"),
    pytest.param("git clean -fdx", "/work/repo", id="d1-git-clean-outside"),
    pytest.param("git status", DEV, id="d1-evaluated-and-harmless"),
    pytest.param(f"echo hi >> {DEV}/a.log", "/", id="d1-append-is-not-truncation"),
    pytest.param(f"echo x > {AGENT}/out.log", "/", id="d1-redirect-into-agent-folder"),
    pytest.param("echo x > /work/o 2>/dev/null", "/", id="d1-redirect-outside"),
    pytest.param(f"truncate -s 0 {AGENT}/a.log", "/", id="d1-truncate-in-agent-folder"),
    pytest.param(f"mv /work/x {AGENT}/y", "/", id="d1-mv-into-agent-folder"),
    pytest.param(f"cp /dev/null {AGENT}/a.log", "/", id="d1-cp-dev-null-agent-folder"),
    pytest.param(f"cp /work/a {DEV}/b", "/", id="d1-cp-is-not-judged"),
    pytest.param("rsync -a /work/a/ /work/b/", "/", id="d1-rsync-no-delete"),
    pytest.param("find -H . -delete", "/work", id="d2-find-H-outside"),
    pytest.param(f"find -H {AGENT}/work -name x -delete", "/work", id="d2-find-H-agent-folder"),
    pytest.param(f"find -D tree {AGENT}/work -delete", "/work", id="d2-find-D-agent-folder"),
    pytest.param("S=/work/x; rm -rf $S/y", "/", id="a4-unconditional-assignment-binds"),
    pytest.param("S=/work/x\nrm -rf $S/y", "/", id="a4-newline-assignment-binds"),
    pytest.param(f'cd {DEV}; echo "$(( $(cat t) / 1000 ))C"', "/", id="r3-arithmetic-is-not-a-command"),
    pytest.param(f"$VENV/bin/python {AGENT}/t.py", "/", id="r3-unknown-command-in-agent-folder"),
    pytest.param("$VENV/bin/python -m pytest tests", "/work", id="r3-unknown-command-outside-zone"),
    # the glob offset counts characters, not the pieces a `~` or `$HOME` expands into
    pytest.param("rm -rf ~/.local/share/other/prof.*", "/", id="glob-offset-after-tilde"),
    pytest.param('S=/work/x; rm -f "$S"/a*.o $S/b.o', "/", id="glob-offset-after-variable"),
    pytest.param("S=/tmp/claude-1000/p/s/scratchpad; rm -f $S/one $S/two/three", "/", id="variable-names-scratchpad"),
    # round 2: these must stay allowed
    pytest.param("rm -rf venv >/dev/null 2>&1", AGENT, id="r2-redirect-after-exact"),
    pytest.param(f"2>/dev/null rm -rf {AGENT}/x", "/", id="r2-redirect-ahead-exact"),
    pytest.param(f"rm -rf $'{AGENT}/x'", "/", id="r2-ansi-c-exact-agent"),
    pytest.param(f"find {DEV} -exec ls -l {{}} \\;", "/", id="r2-find-exec-readonly"),
    pytest.param(f"find {DEV} -exec env grep -l x {{}} +", "/", id="r2-find-exec-env-readonly"),
    pytest.param(f"(cd {DEV}); rm -rf build", "/work/repo", id="r2-subshell-cd-restores"),
    pytest.param("env -C /work/repo rm -rf build", "/", id="r2-env-C-outside"),
    pytest.param("env -S 'rm -rf build'", "/work/repo", id="r2-env-S-outside"),
    pytest.param('for f in a b; do rm "$f"; done', "/work/repo", id="r2-loop-outside-zone"),
    # the narrowing: no delete word means no parsing at all, so an odd command is never in the way
    pytest.param("$RM -rf x", "/", id="r2-no-delete-word-expansion-command"),
    pytest.param('git commit -m "it\'s the HOME dir"; HOME=/x ls', "/", id="r2-no-delete-word-home"),
]


@pytest.mark.parametrize(("command", "cwd"), BLOCKED)
def test_blocked(command: str, cwd: str) -> None:
    assert rmguard.check(command, HOME, cwd) is not None, command


@pytest.mark.parametrize(("command", "cwd"), ALLOWED)
def test_allowed(command: str, cwd: str) -> None:
    assert rmguard.check(command, HOME, cwd) is None, command


def test_the_tables_are_not_empty() -> None:
    # collect loosely, assert strictly: a parametrization typo cannot make the guard tests pass by collecting nothing
    assert len(BLOCKED) > 140
    assert len(ALLOWED) > 20


def event(command: str, cwd: str = "/", tool: str = "Bash") -> str:
    return json.dumps({"tool_name": tool, "cwd": cwd, "tool_input": {"command": command}})


def run_hook(raw: str, capsys: pytest.CaptureFixture[str], argv: list[str] | None = None, home: str = HOME) -> str:
    """The deny reason the hook printed, or "" when it allowed."""
    assert rmguard.main(argv or [], io.StringIO(raw), home) == 0
    out = capsys.readouterr().out
    if not out:
        return ""
    parsed: dict[str, Any] = json.loads(out)
    assert parsed["hookSpecificOutput"]["permissionDecision"] == "deny"
    return str(parsed["hookSpecificOutput"]["permissionDecisionReason"])


def test_hook_denies_the_damage_command_with_a_message_that_says_what_to_do(capsys: pytest.CaptureFixture[str]) -> None:
    reason = run_hook(event(DAMAGE, "/home/u"), capsys)
    assert "per-agent folder" in reason
    assert "agents/<issue>-<role>" in reason
    assert "EXACT path" in reason
    assert "owner" in reason and "batch" in reason
    assert "—" not in reason  # no em dash


def test_hook_allows_the_own_folder_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_hook(event(f"rm -rf {AGENT}/venv"), capsys) == ""


def test_hook_ignores_other_tools_and_missing_commands(capsys: pytest.CaptureFixture[str]) -> None:
    assert run_hook(event(DAMAGE, tool="Write"), capsys) == ""
    assert run_hook(json.dumps({"tool_name": "Bash", "tool_input": {}}), capsys) == ""


@pytest.mark.parametrize("raw", ["rm -rf /x {", "not json rm", "[1, 2] unlink", "\x00 find . -delete"])
def test_hook_fails_closed_on_an_unreadable_event_with_a_delete_word(
    raw: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert "could not be read" in run_hook(raw, capsys)


@pytest.mark.parametrize("raw", ["", "not json", "[1, 2]", "\x00"])
def test_hook_allows_an_unreadable_event_without_a_delete_word(
    raw: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    assert run_hook(raw, capsys, home=str(tmp_path)) == ""
    assert "unreadable" in (tmp_path / LEAD / "rmguard-error.log").read_text()


def test_hook_fails_closed_on_an_internal_error_with_a_delete_word(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*_: object) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(rmguard, "check", boom)
    assert "internal error" in run_hook(event("rm -rf x"), capsys)


def test_hook_allows_and_logs_a_crash_when_there_is_no_delete_word(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    def boom(*_: object) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(rmguard, "has_delete_word", boom)
    assert run_hook(event("ls -l"), capsys, home=str(tmp_path)) == ""
    assert "internal error" in (tmp_path / LEAD / "rmguard-error.log").read_text()
    # the same crash on a command that names a delete word (by plain substring) still blocks
    assert "internal error" in run_hook(event("rm -rf x"), capsys, home=str(tmp_path))


def test_hook_blocks_on_a_timeout_with_a_delete_word_and_never_parses_without_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def slow(*_: object) -> None:
        time.sleep(5)

    monkeypatch.setattr(rmguard, "check", slow)
    monkeypatch.setattr(rmguard, "TIMEOUT_SECONDS", 0.05)
    assert "internal error" in run_hook(event("rm -rf x"), capsys)
    assert run_hook(event("echo hi"), capsys) == ""  # check() is not even called


def test_a_crash_on_an_evaluated_command_blocks_even_without_a_delete_word(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*_: object) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(rmguard, "check", boom)
    assert "internal error" in run_hook(event("echo $HOME"), capsys)
    assert run_hook(event("echo hi"), capsys) == ""  # never evaluated, so nothing to crash


def test_a_timeout_on_an_evaluated_command_blocks_even_without_a_delete_word(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def slow(*_: object) -> None:
        time.sleep(5)

    monkeypatch.setattr(rmguard, "check", slow)
    monkeypatch.setattr(rmguard, "TIMEOUT_SECONDS", 0.05)
    assert "internal error" in run_hook(event("ls *.log"), capsys)


def test_no_delete_word_returns_before_any_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: object) -> None:
        raise AssertionError("parsed")

    monkeypatch.setattr(rmguard.Scanner, "run", boom)
    for command in ("ls -l", "git status", "echo 'unterminated", "echo hi", "find . -name x -print"):
        assert rmguard.check(command, HOME, "/") is None, command


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("rm -rf x", True),
        ("r''m x", True),
        ("\\rm x", True),
        ("sudo unlink x", True),
        ("find . -delete", True),
        ("find . -exec ls {} +", True),
        ("xargs shred", True),
        ("r? x", True),
        ("r[m] x", True),
        ("/bin/r* x", True),
        ("$RM x", True),
        ("r\\\nm x", True),
        ("ls ~/.local/share/reach-around-dev/a", True),
        ("ls /tmp/claude-1000/x", True),
        ("find . -name x", False),
        ("gh pr merge 3 --squash --delete-branch", False),
        ("git push --delete origin x", False),
        ("ls ; echo format", False),
        ("echo firmware", False),
        ("git status", False),
    ],
)
def test_the_delete_word_gate(command: str, expected: bool) -> None:
    assert rmguard.has_delete_word(command) is expected


def read_log(home: Path, name: str) -> list[str]:
    return (home / LEAD / name).read_text().splitlines()


def test_warn_mode_never_blocks_and_logs_one_redacted_line(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    home = str(tmp_path)
    dev = f"{home}/.local/share/reach-around-dev"
    command = f"TOKEN=abc123secret rm -rf {dev}/*.log ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 --password=hunter2"
    assert run_hook(event(command), capsys, ["--mode", "warn"], home) == ""
    (line,) = read_log(tmp_path, "rmguard-warn.log")
    stamp, mode, reason, shown = line.split("\t", 3)
    assert stamp.endswith("Z") and mode == "warn" and "glob" in reason
    assert home not in shown and "~/.local/share/reach-around-dev" in shown
    for secret in ("abc123secret", "ghp_ABCDEF", "hunter2"):
        assert secret not in line
    assert (tmp_path / LEAD / "rmguard-warn.log").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / LEAD).stat().st_mode & 0o777 == 0o700


def test_warn_mode_equals_form_and_allowed_commands_leave_no_line(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    home = str(tmp_path)
    assert run_hook(event(f"rm -rf {home}/.local/share/x-dev/*.py"), capsys, ["--mode=warn"], home) == ""
    assert run_hook(event("ls"), capsys, ["--mode=warn"], home) == ""
    assert len(read_log(tmp_path, "rmguard-warn.log")) == 1


@pytest.mark.parametrize(
    "argv", [[], ["--mode", "enforce"], ["--mode=enforce"], ["--mode", "wran"], ["--mode"], ["warn"]]
)
def test_enforce_is_the_default_and_a_bad_mode_is_enforce(
    argv: list[str], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    home = str(tmp_path)
    command = f"cd {home}/.local/share/reach-around-dev && rm -rf build *.py *.log"
    assert "per-agent folder" in run_hook(event(command, home), capsys, argv, home)
    assert not (tmp_path / LEAD / "rmguard-warn.log").exists()


def test_the_mode_is_not_read_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SAFO_RMGUARD_MODE", "warn")
    assert "per-agent folder" in run_hook(event(DAMAGE, "/home/u"), capsys)


def test_warn_mode_does_not_block_a_crash_either(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    def boom(*_: object) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(rmguard, "check", boom)
    assert run_hook(event("rm -rf x"), capsys, ["--mode", "warn"], str(tmp_path)) == ""
    assert "internal error" in read_log(tmp_path, "rmguard-warn.log")[0]


def test_redact() -> None:
    out = rmguard.redact(
        "tool -H 'Authorization: Bearer abcdefgh12345' https://u:pw@h/x A_B=secret1 sk-"
        + "a" * 30
        + " /home/u/x\nnext",
        "/home/u",
    )
    for gone in ("abcdefgh12345", "u:pw", "secret1", "a" * 30, "/home/u"):
        assert gone not in out
    assert "~/x" in out
    assert "\n" not in out


def test_the_guard_bites_a_negative_control() -> None:
    # the same command moved outside every zone passes, so the rule is about the zone, not about `rm`
    assert rmguard.check("rm -rf *.py *.log", HOME, "/work/repo") is None
    assert rmguard.check("rm -rf *.py *.log", HOME, DEV) is not None
