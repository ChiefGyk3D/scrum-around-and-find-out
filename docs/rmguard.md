# safo-rmguard: no wildcard or parent deletes in shared dev directories

Issue #422. On 2026-11-23 a reviewer agent ran `rm -rf ... *.py *.log` inside `~/.local/share/reach-around-dev` and
deleted another session's logs and helper scripts. A brief is instruction only, so this is a check on the command.

## Where it lives, and why

`src/safo/rmguard.py`, with the console script `safo-rmguard`. It is its own module and entry point because the
dispatch guard (`safo.guard`, `safo.modes.hooks`, `safo.geminibrief`) is frozen (owner decision 2026-10-30: bug fixes
and false-positive exceptions only, new protections elsewhere). The `safo gemini` wrapper holds the Gemini gates and
has no Bash path to extend, so a separate hook is the place for a Bash-command rule. Nothing in the guard changes.

## The rule

Shared zones: `~/.local/share/<anything>-dev` (and everything below), the parents above them (`~/.local/share`,
`~/.local`, `~`, `/tmp`, `/`), and `/tmp/claude-*` (the harness scratchpad parent).

Blocked when a target is in a zone (or cannot be shown to be outside one): `rm`, `unlink`, `shred`, `rmdir`, these
through `sudo`, `env`, `nice`, `timeout`, `bash -c`, `eval`, `$(...)`, backticks and heredoc substitutions, `xargs` or
`parallel` running them, and `find` with `-delete` or an `-exec`/`-execdir`/`-ok` of them. A target is refused when it

- holds an unquoted glob (`*`, `?`, `[`, `{a,b}`), even inside an agent folder;
- is a zone or a parent of one (a recursive or plain removal of the parent);
- is any other path in a zone that is not under a per-agent folder;
- cannot be resolved: an expansion other than `$HOME`/`~` in a recursive delete or unquoted, or a relative or globbed
  target after a `cd` it could not follow.

Allowed: an exact path (no glob, no expansion) at or under `<dev>/agents/<name>` (so an agent removes its own folder by
its exact path), or strictly under `/tmp/claude-*/<project>/<session>/scratchpad`. Everything outside the zones is
untouched.

Fail closed: an unterminated quote, nesting beyond three levels, an oversized command or a command word built from an
expansion is denied when the text mentions a delete word or a shared zone; an unreadable event or any internal error is
a deny. Not Bash, or no command: allowed. The message states the reason and what to do instead (own folder, exact
paths, list then remove by name).

## Known limits

A tokenizer for common shapes, not a shell parser. Not covered: an alias or function that hides `rm`; a script or
`python -c "shutil.rmtree(...)"`; a symlink into a zone (paths are compared as text); `xargs` input the command does
not show (it is denied only when the cwd or another word is in a zone); and whether the agent folder is the one a brief
named (a hook cannot see the brief; the shape `agents/<name>` is the convention). It is a speed bump, like the other
guards, not a sandbox.

## Installing (owner step, not done by this change)

Add one PreToolUse entry for Bash to `~/.claude/settings.json` after `pipx install` or upgrade of this build, with a
timestamped backup and a diff shown first:

```json
{
  "matcher": "Bash",
  "hooks": [{ "type": "command", "command": "safo-rmguard", "timeout": 5, "onFailure": "block" }]
}
```

Files that change on install: `~/.claude/settings.json` (one new hook entry) and the pipx `safo` environment (new
console script). `~/.config/safo/*`, `agents.yaml`, `~/dotfiles/claude/tools/*` and the existing `safo-guard` entries
do not change. Remove the entry to turn it off.
