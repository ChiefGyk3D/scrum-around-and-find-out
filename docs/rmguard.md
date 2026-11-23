# safo-rmguard: no wildcard or parent deletes in shared dev directories

Issue #422. On 2026-11-23 a reviewer agent ran `rm -rf ... *.py *.log` inside `~/.local/share/reach-around-dev` and
deleted another session's logs and helper scripts. A brief is instruction only, so this is a check on the command.

## Where it lives, and why

`src/safo/rmguard.py`, with the console script `safo-rmguard`. It is its own module and entry point because the
dispatch guard (`safo.guard`, `safo.modes.hooks`, `safo.geminibrief`) is frozen (owner decision 2026-10-30: bug fixes
and false-positive exceptions only, new protections elsewhere). The `safo gemini` wrapper holds the Gemini gates and
has no Bash path to extend, so a separate hook is the place for a Bash-command rule. Nothing in the guard changes.

## What is evaluated, and what can block

A command is evaluated (tokenized and checked) when its text, after backslash-newline pairs are removed, holds a delete
word, a character that can build one, or a shared zone:

- a delete word: `rm`, `rmdir`, `unlink` or `shred` (quotes and backslashes removed first, so `r''m` counts), a
  whole-word `-delete`, or `find` with `-exec`, `-execdir`, `-ok` or `-okdir` (`xargs` and `parallel` feeding these hold
  the word anyway);
- a building character: `$`, a backtick, `?`, `*`, `[` or `{` anywhere (`r?`, `r[m]`, `/bin/r*`, `unli[n]k`, `r{m,}`,
  `r$'m'`, `$RM`, a backtick command);
- a zone: `-dev` as a name ending, `/tmp/claude`, or `.local`.

Only a command with none of these (`ls`, `git status`, `echo hi`) is allowed at once with no parsing. `--delete-branch`
and `git push --delete` are not delete words. Evaluating is not blocking: a command that holds no delete word as
written is blocked only when its command word is built from an expansion or a pattern (`$RM`, `r?`, `/bin/r*`) and one
of its own arguments names a shared zone (or a path in a working directory that is inside one). A syntax error the
tokenizer cannot read blocks only when a delete word was written out.

Failures follow the same line. For a command that holds a delete word, a crash, a timeout (3 seconds, a signal timer) or
an unreadable event is a block; for any other command it is an allow, and one line goes to
`~/.local/share/reach-around-lead/rmguard-error.log`. If the gate itself crashes, a plain substring test for `rm`,
`unlink`, `shred`, `-delete`, `-exec` or `-ok` decides.

## The rule

Shared zones: `~/.local/share/<anything>-dev` (and everything below), the parents above them (`~/.local/share`,
`~/.local`, `~`, `/tmp`, `/`), and `/tmp/claude-*` (the harness scratchpad parent).

Blocked when a target is in a zone (or cannot be shown to be outside one): `rm`, `unlink`, `shred`, `rmdir`, these
through `sudo`, `env` (including `env -C`, `--chdir` and `-S`), `nice`, `timeout`, `bash -c`, `eval`, `$(...)`,
backticks and heredoc substitutions, `xargs` or `parallel` running them, and `find` with `-delete` or an `-exec` of
anything that is not a known read-only tool (after any wrapper). A target is refused when it

- holds an unquoted glob (`*`, `?`, `[`, `{a,b}`), even inside an agent folder;
- is a zone or a parent of one (a recursive or plain removal of the parent);
- is any other path in a zone that is not under a per-agent folder;
- cannot be resolved: an expansion other than `$HOME`/`~` or a variable assigned a plain literal earlier in the same
  command, in a recursive delete or unquoted; a quoted one when the command mentions a zone or the working directory is
  unknown or inside one; or a relative or globbed target after a `cd` it could not follow.

Allowed: an exact path (no glob, no expansion) at or under `<dev>/agents/<name>` (so an agent removes its own folder by
its exact path), or strictly under `/tmp/claude-*/<project>/<session>/scratchpad`. Everything outside the zones is
untouched.

How the shell is read: redirections (`rm>x`, `2>&1 rm`, `&>x`, `<x rm`) are dropped before the command word is chosen;
`$'...'` is decoded and `$"..."` read as double quotes; a leading `//` is the same path as `/`; `cd`, `pushd` and
`popd` are followed in order, a subshell `( ... )` gets its own working directory, and a `cd` in a pipeline stage, in
the background (`&`) or either side of `||` makes the directory unknown; if `HOME` is assigned, exported, unset, read
or defaulted anywhere in the command, `~` and `$HOME` are unknown too.

The deny message states the reason and what to do instead (own folder, exact paths, list then remove by name).

## Mode: warn first, then enforce

The mode is an argument of the hook command, never an environment variable (an agent could set one). It lives in the
settings entry the owner controls.

- `safo-rmguard --mode enforce` (the default; any other value means enforce) blocks.
- `safo-rmguard --mode warn` never blocks, not even on a crash. It appends one tab-separated line per would-be block
  (UTC timestamp, mode, reason, the command with home paths shortened) to
  `~/.local/share/reach-around-lead/rmguard-warn.log`. The folder is created 0700 and the file 0600. The command is
  redacted first: anything after `=` in an assignment word, `Bearer`/`token` values, URL credentials, well-known token
  prefixes (`ghp_`, `github_pat_`, `sk-`, `xox*-`, `AKIA`, `AIza`, `glpat-`), values of `--password`/`--token`/`--key`
  style options, any 32-or-more character token, newlines escaped, 500 characters at most.

## Settings entries (owner step, not done by this change)

Add one PreToolUse entry for Bash to `~/.claude/settings.json`, after a timestamped backup
(`cp -p ~/.claude/settings.json ~/.claude/settings.json.bak-$(date +%Y%m%d-%H%M%S)`) and with the diff shown first.
Start in warn mode, read the log for a week, then switch to enforce.

Warn mode:

```json
{
  "matcher": "Bash",
  "hooks": [{ "type": "command", "command": "safo-rmguard --mode warn", "timeout": 10 }]
}
```

Enforce mode:

```json
{
  "matcher": "Bash",
  "hooks": [{ "type": "command", "command": "safo-rmguard --mode enforce", "timeout": 10 }]
}
```

Do NOT add `"onFailure": "block"`. The hook already blocks, by itself and inside its own check, every failure that
matters (a delete word it cannot read, a crash, a timeout). `onFailure: "block"` would also block EVERY Bash call when
the program cannot start (a pipx upgrade that drops the script from the path, a mistyped command), which is the lock
this design avoids. Without it, a start failure lets the command through, as it does for any other hook.

Files that change on install: `~/.claude/settings.json` (one new hook entry) and the pipx `safo` environment (new
console script `safo-rmguard`). `~/.config/safo/*`, `agents.yaml`, `~/dotfiles/claude/tools/*` and the existing
`safo-guard` entries do not change. (If `~/.claude/settings.json` is a symlink into the dotfiles repo, the change lands
there and `dotsync` will carry it.)

## Remove it, or recover from a lock, from a plain terminal

Outside the Claude session, in any terminal:

```
cp -p ~/.claude/settings.json.bak-<timestamp> ~/.claude/settings.json
```

with the timestamped backup taken before the install. `cp` writes through a symlink, so a symlinked settings file is
restored in place. Or delete the one `safo-rmguard` entry from the file by hand. A new session reads the file at start.

The hook matches the Bash tool only. The Edit and Write tools do not pass through it, so even if Bash were locked, an
agent session could still change the settings file with Edit or Write (and the other guards on those tools, such as the
no-weakening guard, apply as they do today). That is also why the lock design is "narrow what can block", not "trust the
escape hatch".

One-run escape from a session start: `claude --settings '{"disableAllHooks": true}'` turns off all hooks for that run,
every other guard included; see the status of each claim below.

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
  `--settings` takes a path to a settings JSON file or an inline JSON string, for that session only, and that most lists
  merge with the file-based values.
- INFERRED: a throwaway session started with `claude --settings /path/to/test-settings.json`, where that file holds the
  `safo-rmguard --mode warn` entry above, tests the hook without touching `~/.claude/settings.json`. UNTESTED here.
- VERIFIED: `--settings '{"disableAllHooks": true}'` turns hooks off for one run and takes precedence over project and
  local settings.

## Known limits

A tokenizer for common shapes, not a shell parser. Not covered: an alias or function that hides `rm`; a script or
`python -c "shutil.rmtree(...)"`; a symlink into a zone (paths are compared as text); `xargs` input the command does
not show (denied only when the cwd or another word is in a zone); a command word built from an expansion whose own
arguments name no zone (allowed); command substitution inside `$(( ))` arithmetic (not scanned); a variable set by `read`, a loop, `+=`,
`declare` or `export` (treated as unknown, not tracked); a `HOME` change by means the text does not show; and whether
the agent folder is the one a brief named (a hook cannot see the brief; the shape `agents/<name>` is the convention).
It is a speed bump, like the other guards, not a sandbox.

## Replay over real history

`tools/rmguard_replay.py` (not run in CI) reads the Bash commands in `~/.claude/projects/*/*.jsonl`, runs each through
the rule in dry run, and prints the counts and every blocked command, redacted. Run it before switching from warn to
enforce, and after a change to the rule.
