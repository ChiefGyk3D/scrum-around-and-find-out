# safo-rmguard: guard the shared dev directories against deletes, truncation and moves

Issue #422. On 2026-11-23 a reviewer agent ran `rm -rf ... *.py *.log` inside `~/.local/share/reach-around-dev` and
deleted another session's logs and helper scripts. A brief is instruction only, so this is a check on the command.

## What it covers, exactly

The hook judges these program families, and only these. It is a check on the text of one Bash command, a speed bump,
not a sandbox.

| Family | What is judged |
| :- | :- |
| `rm`, `rmdir`, `unlink`, `shred` | every target (also through `sudo`, `env`, `nice`, `timeout`, `bash -c`, `eval`, `$(...)`, backticks, `xargs`, `parallel`) |
| `find` | `-delete`, or `-exec`/`-execdir`/`-ok`/`-okdir` of anything that is not a known read-only tool; the start paths, after the GNU global options `-H -L -P -Olevel -D opt` |
| `git clean` | the working tree it runs in (the cwd, `git -C dir`, `--work-tree`) or its pathspecs; `-n`/`--dry-run` is allowed |
| `truncate` | every target file |
| `rsync` with `--delete*`, `--remove-source-files` or `--remove-sent-files` | every source and destination operand |
| `tar --remove-files` | every member operand, after any `-C dir` |
| `mv` | every source, the destination and `-t dir` (moving out of, or onto, a protected path) |
| `cp /dev/null` and `cp /dev/zero` | the destination |
| `dd` | the `of=` target |
| `tee` without `-a` | every target |
| a truncating redirection | the target of `>`, `>|`, `&>`, `: > file`, `echo x > file`; `>>` (append) is not judged |

Not covered: any other program (a script, `python -c "shutil.rmtree(...)"`, `perl -e unlink`, `sed -i`, `git reset
--hard`, `git checkout -- .`, `git stash`, a container with a bind mount, `cp` onto a file that is not `/dev/null`, an
alias or a function that hides one of the above); a symlink that points into a zone (paths are compared as text); and
`xargs` input the command does not show. If you need one of those covered, it is a change to this file, not a setting.

## What is protected

Shared zones: `~/.local/share/<anything>-dev` (and everything below), the parents above them (`~/.local/share`,
`~/.local`, `~`, `/tmp`, `/`), and `/tmp/claude-*` (the harness scratchpad parent).

Allowed, for the families above: an exact path (no glob, no expansion) STRICTLY BELOW `<dev>/agents/<name>/`, for
files and for recursive removal of a subfolder, and strictly below `/tmp/claude-*/<project>/<session>/scratchpad`.
Everything outside the zones is untouched.

Denied, inside a zone: any glob; a zone or one of its parents; any path that is not strictly below `agents/<name>/`;
and **the agent folder root `<dev>/agents/<name>` itself**, recursive or not, whoever owns it. The hook cannot tell
whose folder `agents/<name>` is (it has no session identity), so no agent may remove a root; the owner removes agent
folder roots in a batch. The deny message says so and gives the command that prints the exact name:
`ls -d -- '<path>'`.

A target that cannot be resolved (an expansion other than `$HOME`/`~` or a variable assigned a plain literal by an
unconditional `;`/newline command, in a recursive delete or unquoted; a quoted one when the command mentions a zone or
the working directory is inside one; a relative or globbed target after a `cd` it could not follow) is denied.

## What is evaluated, and what can block

When the working directory is inside a zone, every command is evaluated. Elsewhere a command is evaluated when its text
(backslash-newline pairs removed) holds a delete word, a character that can build one (`$`, a backtick, `?`, `*`, `[`,
`{`), or a shared zone (`-dev`, `/tmp/claude`, `.local`). Only a command with none of these (`ls`, `git status`) is
allowed at once with no parsing, so a tokenizer bug cannot lock the shell for it.

For an evaluated command, whatever the hook cannot read is a deny: a syntax error, nesting deeper than three levels, a
timeout (3 seconds, a signal timer) or an internal error. For a command that was never evaluated, a crash is an allow
and one line goes to `~/.local/share/reach-around-lead/rmguard-error.log`.

How the shell is read: redirections are dropped before the command word is chosen; `$'...'` is decoded and `$"..."` read
as double quotes; a leading `//` is the same path as `/`; `cd`, `pushd` and `popd` are followed in order, a subshell
`( ... )` gets its own working directory, and a `cd` in a pipeline stage, in the background or either side of `||` makes
the directory unknown; `$(( ))` arithmetic is scanned for substitutions (`$(...)`, backticks, `<(...)`); a variable
assigned a plain literal binds only in an unconditional `;`/newline sequence at the top level (not after `&&`, `||`,
`|`, `&`, not in a subshell, and not at all when the text uses `eval`, `source`, `. file` or defines a function);
if `HOME` is assigned, exported, unset, read or defaulted anywhere in the command, written plainly or with quotes and
backslashes in the name, or the command uses `eval`, `declare`, `typeset`, `printf -v`, `read`, `source`, `mapfile`,
then `~` and `$HOME` are unknown.

## Mode: warn first, then enforce

The mode is an argument of the hook command, never an environment variable (an agent could set one). It lives in the
settings entry the owner controls.

- `safo-rmguard --mode enforce` (the default; any other value means enforce) blocks.
- `safo-rmguard --mode warn` never blocks, not even on a crash. It appends one tab-separated line per would-be block
  (UTC timestamp, mode, reason, the command with home paths shortened) to
  `~/.local/share/reach-around-lead/rmguard-warn.log`. The command is redacted first: anything after `=` in an
  assignment word, `Bearer`/`token` values, URL credentials, well-known token prefixes, values of
  `--password`/`--token`/`--key` style options, any 32-or-more character token, newlines escaped, 500 characters at most.
- Both logs are written through directory descriptors: no symlink is followed, every directory component and the file
  must belong to the current user, the file must be a regular file with one link, the folder is repaired to 0700 and the
  file to 0600. A log that cannot be written that way is skipped, never followed.

## Install: owner steps, nothing here changes a config file

Take a timestamped backup first and look at the diff before editing: `cp -p ~/.claude/settings.json
~/.claude/settings.json.bak-$(date +%Y%m%d-%H%M%S)`.

**Warn mode** is the entry to start with. It has no `onFailure`, so it can only log and never blocks, whatever happens:

```json
{
  "matcher": "Bash",
  "hooks": [{ "type": "command", "command": "safo-rmguard --mode warn", "timeout": 10 }]
}
```

Read `~/.local/share/reach-around-lead/rmguard-warn.log` for a period (a week is the suggestion) and run the replay
below. **The owner chooses enforce only after that warn-mode period**, by their own decision.

**Enforce mode** blocks, and it also blocks when the program cannot start, so it must not point into the pipx
environment (a pipx upgrade can remove the script and would then lock every Bash call). Use `"onFailure": "block"` and a
launcher the owner owns, kept outside the pipx environment, for example `~/.config/safo/rmguard-hook` (mode 0755, owned
by the owner, not writable by the agents' tools if the owner can arrange it):

```sh
#!/bin/sh
# Owner-owned launcher for the enforce hook, outside the pipx environment.
exe="$HOME/.local/bin/safo-rmguard"
if [ -x "$exe" ]; then
  exec "$exe" --mode enforce
fi
echo "safo-rmguard is missing, so Bash is blocked. Restore it or follow the recovery steps in docs/rmguard.md." >&2
exit 2
```

```json
{
  "matcher": "Bash",
  "hooks": [{ "type": "command", "command": "\"$HOME/.config/safo/rmguard-hook\"", "timeout": 10, "onFailure": "block" }]
}
```

With `"onFailure": "block"` a start failure, a non-zero exit other than a verdict, a timeout or unreadable output blocks
the Bash call; exit 2 with a message on stderr (the launcher's) blocks it with that message. The launcher only covers
the program going missing; a broken interpreter or a crash before Python starts is blocked by `onFailure` too, which is
the point and also the cost: that is why recovery below must work from a plain terminal.

Files that change on install: `~/.claude/settings.json` (one new hook entry), the launcher script (enforce only), and
the pipx `safo` environment (new console script `safo-rmguard`). `~/.config/safo/*`, `agents.yaml`,
`~/dotfiles/claude/tools/*` and the existing `safo-guard` entries do not change.

## Recovery, from a plain terminal outside the session

```
cp -p ~/.claude/settings.json.bak-<timestamp> ~/.claude/settings.json
```

with the timestamped backup taken before the install. `cp` writes through a symlink, so a symlinked settings file is
restored in place. Or delete the one `safo-rmguard` entry by hand. A new session reads the file at start.

The hook matches the Bash tool only. The Edit and Write tools do not pass through it, so even when enforce mode has
locked Bash, an agent session can still repair `~/.claude/settings.json` with Edit or Write (other guards on those
tools, such as the no-weakening guard, apply as they do today). One-run escape at session start:
`claude --settings '{"disableAllHooks": true}'` turns off all hooks for that run, every other guard included.

## What Claude Code's hook documentation says (read 2026-11-23)

Sources: https://code.claude.com/docs/en/hooks.md, https://code.claude.com/docs/en/cli-reference.md and
https://code.claude.com/docs/en/settings.md, all read on 2026-11-23. VERIFIED means the page says it; INFERRED means it
follows from the pages but was not run; UNTESTED means no live session was started for this.

- VERIFIED: a command hook that exits 2 blocks a PreToolUse tool call and its stderr is the reason. A PreToolUse hook
  that exits 0 and prints JSON with `permissionDecision: "deny"` also blocks (this module prints that). Exit 1 or any
  other code is a non-blocking error: the action goes ahead, except for hooks whose failure blocks (`onFailure`).
- VERIFIED: a command hook has a `timeout` in seconds (default 600 for `command`). On PreToolUse a timed-out hook does
  not block the tool call unless `onFailure` is `"block"`; the docs say not to count on a stalled hook as a gate. This
  module therefore keeps its own 3 second limit and answers before Claude Code's.
- VERIFIED: `onFailure` is `"continue"` or `"block"`; with `"block"` a failure (non-2 exit, start failure, timeout,
  invalid JSON output) does what exit code 2 does on that event. Requires Claude Code 2.1.295 or later. Without it a
  missing script is a non-blocking error and the command runs.
- VERIFIED: hook entries merge across settings levels (managed, command line, project local, shared project, user),
  and `disableAllHooks` cannot disable managed hooks. A project `.claude/settings.local.json` (not committed) or a
  `--settings <file-or-json>` for one session can therefore carry a hook that adds to the user's. The CLI page says
  `--settings` takes a path to a settings JSON file or an inline JSON string, for that session only.
- INFERRED: a throwaway session started with `claude --settings /path/to/test-settings.json`, where that file holds the
  warn entry above, tests the hook without touching `~/.claude/settings.json`. UNTESTED here.
- VERIFIED: `--settings '{"disableAllHooks": true}'` turns hooks off for one run and takes precedence over project and
  local settings.

## Known limits

A tokenizer for common shapes, not a shell parser. Beyond the families listed under "Not covered": a command word built
from an expansion whose own arguments name no zone is allowed; a variable set by `read`, a loop, `+=`, `declare` or
`export` is treated as unknown, not tracked; a `HOME` change by means the text does not show; an `xargs` input the
command does not show is denied only when the cwd or another word is in a zone; and a hook cannot see which agent is
running, which is why agent folder roots are never removable by an agent.

## Tests and replay

`tests/test_rmguard_sentinel.py` runs destructive commands under real bash and the real tools (`find`, `git clean`,
`rsync`, `tar`, `truncate`, `dd`, `mv`, `cp`, redirections, wrappers, variable tricks) against disposable sentinel
files and asserts: if real bash removed or emptied a sentinel in a shared zone, rmguard denied the command text. A
missing tool fails under CI instead of skipping. `tools/rmguard_replay.py` (not run in CI) reads the Bash commands in
`~/.claude/projects/*/*.jsonl`, runs each through the rule in dry run, and prints counts and every blocked command,
redacted. Run it before switching from warn to enforce, and after a change to the rule.
