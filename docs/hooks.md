# safo hooks

`safo hooks` turns the routing rules in `agents.yaml` into two Claude Code hooks, so they are enforced and not
remembered. The guard is a speed bump and an audit trail, not a security boundary: whoever writes a brief can type the
approval token, and that includes a model that a prompt injection has talked into it.

| Command | Claude Code event | What it does |
|---|---|---|
| `safo hooks install [--settings PATH] [--mode warn\|block] [--command safo]` | none | Merges the two hooks into a `settings.json` (default `~/.claude/settings.json`). Keeps every other hook and setting, is a no-op when run again, keeps a private backup before it replaces the file, and refuses to overwrite a file that changed while it worked (bytes, or the file itself: device, inode, size and modification time are checked again just before the replace, so a rename-over with identical bytes is caught too, with `settings changed while installing`). `--dry-run` writes nothing. |
| `safo hooks probe` | SessionStart | Asks each Ollama endpoint in `agents.yaml` which models are loaded (two bounded GETs, never a generate), saves the answer and tells the session whether the local LLM is reachable. |
| `safo hooks guard` | PreToolUse, matcher `Agent\|Task\|Bash` | Checks each subagent brief against four rules (below), and each Bash call of the lead against the lead-never-waits rule (the fifth). A rerun of `install` moves an older `Agent\|Task` matcher to this one. |
| `safo hooks mode warn\|block` | none | `warn` reports a broken rule and allows the dispatch (the default); `block` denies it. |
| `safo hooks status [--session ID --agents PATH]` | none | The mode, the retained counts, the health of the hooks and of the last probe. |

## The four rules

1. **An explicit, known model.** A brief with no `model` is flagged (`no-model`). A model counts as explicit only when it
   is an exact id or model name of an agent in `agents.yaml` (or a full `claude-<family>-<version>` id of one). `inherit`,
   any unrecognised name and a fork with no model resolve to a parent model the hook cannot see, so they are flagged as
   `unknown-model` unless the approval token is in the brief, the same as Opus; in `block` mode that is a denial. The log
   records the model as `unknown`, never the value that was sent.
2. **The approval token.** A known model that `agents.yaml` marks `approval_required` needs `hooks.approval_token` in the
   brief, found however it is cased or wrapped. Put it there only with the maintainer's recorded OK. **The token is a
   speed bump against accidents, not proof of the maintainer's approval**: it travels in model-written text, so a
   prompt-injected model, or any quoted source material, can forge it. `block` mode therefore does not prove a human said
   yes; it only makes forgetting visible.
3. **A local step or a reason for none**, while the last probe is fresh and found the local LLM reachable: a marker from
   `hooks.local_step_markers`, or `hooks.na_marker` followed by a reason.
4. **No hidden work.** A brief carries a line of its own, `issue: owner/repo#N` or `issue: KEY-N`, naming an issue that
   exists and is open (`no-issue`, `issue-unusable`, `issue-unverified`). A GitHub issue is checked with a read-only `gh issue
   view`; in `block` mode a lookup that fails denies. Nothing is exempt unless `hooks.tracking_exempt_repos` lists the
   repository. See [No hidden work](no-hidden-work.md).

## The fifth rule: the lead never waits

The lead session is a project manager; every wait is delegated ([The orchestrator](orchestrator.md)). A Bash call in the
lead session that waits in the foreground is flagged (`warn`) or denied (`block`) with `lead-waits` in the log and a
message that says to rerun it with `run_in_background` or hand it to a Sonnet monitor agent. The message and the log carry
the rule name only, never the command.

A small tokenizer splits the call into simple commands, and a wait counts only at **command position**: the first word
after leading `VAR=value` assignments, the shell keywords `do`, `then`, `else`, `if`, `!` and `{`, and these transparent
wrappers (with their options and operands): `time`, `nohup`, `command`, `exec`, `nice`, `env`, `sudo`, `timeout`,
`stdbuf`, `setsid`, `flock` (its lock operand, or `-c 'command line'`), `ionice`, `taskset`, `chrt`, `unbuffer`,
`xargs` and `parallel` (its command ends at `:::`). Commands are
separated by `;`, `&&`, `||`, `|`, `&`, a newline and subshell parentheses. Arguments are data, so `echo gh run watch`
and `echo sleep 60` are not waits.

| Found | Example |
|---|---|
| `gh run watch` | `gh run watch 123 --exit-status` |
| `gh pr checks` with `--watch` or `-w` | `gh pr checks 12 --watch` |
| `watch` at command position (it re-runs a command until stopped; `watch -g` too) | `watch -n 5 gh pr checks 1` |
| a `sleep`, of any length, in the condition or the body (`do` ... `done`) of a `while`, `until` or `for` loop | `until gh run view 9 \| grep -q completed; do sleep 10; done` |
| `sleep` at or above the **threshold** (10 seconds by default; the sleeps of one command add up; an argument the hook cannot read, such as `sleep $n`, counts as over) | `sleep 120`, `sleep 5; sleep 6` |

A sleep counts for a loop only when it is in that loop, its condition (`while sleep 1; do :; done`) or its body:
`while read l; do echo "$l"; done < f; sleep 1` is a one-second pause after a loop, not a poll.

Quoting decides what is code. Single-quoted text, double-quoted text, quoted heredoc bodies and comments are data.
Code inside `$(...)`, backticks, `${...}` (for example `${value:-$(sleep 60)}`), the body of an unquoted heredoc
(`cat <<EOF` followed by a line `$(sleep 60)`) and the word of a here-string (`cat <<< "$(sleep 60)"`; `<<<'...'`
is data) is scanned, also inside double quotes. The body of `$((...))` and `$[...]` is arithmetic and not a command;
only a substitution nested in it runs (`$(( $(sleep 60) + 1 ))`). Before anything else the scanner removes every
backslash-newline the way bash does: not inside single quotes or `$'...'`, not in a comment (which ends at its
newline), not in the body of a heredoc whose delimiter is quoted; it does inside double quotes and in an unquoted
heredoc body, where a line ending in a backslash is joined to the next one BEFORE it is compared with the delimiter. A heredoc delimiter is read as the
complete shell word, quote-removed, the way bash reads it: `<<EOF`, `<<'EOF'`, `<<"EOF"`, `<<\EOF`, `<<E'OF'`,
`<<$'EOF'` and `<<-EOF` all end at a line that is exactly `EOF`. If any part of the delimiter is quoted the body is
opaque data; otherwise its substitutions run and are scanned. The following also count as code the call runs, so they
are scanned: the string given to `bash -c`, `sh -c`, `zsh -c` (also `-lc`), the arguments of `eval`, the split string
of `env -S` / `env --split-string`, and the command that `xargs` and `find -exec` (also `-execdir`, `-ok`, `-okdir`)
run. The same words as arguments to any other command are data.

A function defined in the call (`name() { ... }`, `function name { ... }`) does not wait by being defined. Its body is
scanned only if the same call later invokes the name at command position; `echo name` does not. A function nested in
another is dormant until ITS OWN name is invoked (`outer() { inner() { sleep 60; }; }; outer` only defines `inner`). A
function body that is not a brace group, such as `name() ( ... )`, is read as live code. A marker comment inside a
dormant body exempts nothing (see below).

**Constructs the scanner will not guess at are their own verdicts.** Each is denied by `block` mode and shown as a
warning by `warn` mode, with a content-free message that names only the kind, and a real marker can exempt it like
any flagged call. All the kinds the rule emits: `gh-run-watch`, `gh-pr-checks-watch`, `watch`, `sleep-loop`,
`long-sleep`, and the fail-closed `unscannable-depth`, `unscannable-brace`, `unscannable-indirect`,
`unscannable-timeout`:

- `unscannable-brace`: an unquoted brace expansion (`{a,b}` with a comma, or `{1..3}`) in a COMMAND word builds the
  command at run time (`{sleep,60}`, `sl{e..e}ep 60`). In an argument (`echo {a,b}`), a group (`{ cmd; }`), `${var}` or
  quotes it is not an expansion of the command and is fine.
- `unscannable-indirect`: the call defines a function AND runs a variable- or substitution-expanded word at command
  position (`f() { sleep 60; }; x=f; $x`). A call that defines no function and uses `$x` stays a documented limit.
- `unscannable-timeout`: the scan ran past the guard's own deadline (the same budget as the other lookups). Inputs of
  at most 8 KiB are cached (16 entries); a larger input is scanned once per call and not kept.
- `unscannable-depth`: see next.

**Nesting beyond three levels is its own verdict.** Executable syntax (`$(...)`, backticks, `${...}`, `bash -c` and
`eval` strings) nested deeper than 3 cannot be checked here, so the hook does not pass it silently: it reports
`unscannable-depth`, which `block` mode denies and `warn` mode shows as a warning. The message names the rule and the
limit and never echoes the command. The same applies to a call so deeply nested that the scanner runs out of stack. A
`# lead-wait: ok - <reason>` marker can exempt it, like any other flagged call. Simplify the command, or run it with
`run_in_background`.

Not flagged: `sleep 1` or `sleep 9` in a one-shot command (below the threshold, a pause and not a wait); the words
`gh run watch` in a commit message, a quoted string, a comment, an `echo` or a `cat <<'EOF'` heredoc body.

What the hook reads from the event, and what it does not:

- **Lead or sub-agent.** An event raised inside a sub-agent carries an `agent_id`; the event of the lead's own thread does
  not. The rule skips any event with an `agent_id`, because a monitor agent is allowed to watch. This relies on the host
  adding the field. Evidence that it does: an official Claude Code plugin's hook skips sub-agent events with
  `"agent_id" in data`. It was not observed from a live SAFO session here (see Known limits).
- **Background or not.** The Bash tool's input carries `run_in_background`, which the hook reads from `tool_input`. Only the
  boolean `true` counts: `"true"`, `1` and `"yes"` do not. A command that backgrounds itself in the shell (`sleep 60 &`) is
  not the same thing and is not treated as background (`nohup sleep 60 &` is still flagged; only the payload flag exempts).

Configuration, in `agents.yaml` (everything is optional):

```yaml
hooks:
  lead_wait:
    mode: follow                 # follow (use `safo hooks mode`), off, warn or block, for this rule alone
    sleep_threshold_seconds: 10  # 1 to 3600
    exempt_repos:                # a repository whose lead may wait, with the reason it may
      - repo: owner/scratch-repo
        reason: a throwaway repository where nobody waits on the lead
```

Exemptions are never silent:

- A repository entry without a `reason` (at least 12 characters after trimming) makes `agents.yaml` fail to load, so a
  reasonless exemption is refused outright. It applies to the repository bound at SessionStart, the same binding the
  tracking opt-out uses, and to no other.
- A single call can carry a comment, `# lead-wait: ok - <reason>`, with a stated reason: at least 12 characters, of
  which at least 8 are letters (any script) or ASCII digits, counted after combining marks and zero-width or other
  format characters are removed. `!!!!!!!!!!!!` is twelve characters and no reason; neither is padding with
  zero-width joiners or combining marks, nor full-width, Arabic-Indic or circled digits. The marker counts only in a real shell comment: a `#` that begins a word outside quotes. The same text
  inside a quoted string (`echo 'lead-wait: ok - ...'`, a commit message), inside any heredoc body whatever the
  spelling of its delimiter, after an escaped `\#`, or as plain arguments is data and exempts nothing. The call is one
  decision, so the comment may sit on the wait's line or on another line of the same call. A comment in a function
  body counts only if that function is invoked in the call; in a dormant body it exempts nothing. A marker with no reason, or a
  placeholder, is ignored and the call is flagged; the message says a reason is required. An exempted call is allowed
  and logged as `allow` with the `lead-waits` rule, so exemptions can be counted. The reason itself stays in the
  transcript and is never written to the log.
- A repository exemption in `agents.yaml` follows the same reason rule, or the file fails to load.
- Like the approval token, both are speed bumps: an agent with shell access can type a marker. Their job is to make a
  deliberate wait a written decision. The rule is a speed bump against accidents, not a sandbox: an actor who can
  already run arbitrary Bash as the same user can also edit the guard's config, mode file and logs.

## Failing safe

A hook sits inside someone's session, so every error lets the work through, visibly.

- Malformed, oversized (over 1 MiB), non-object or missing-field input, a standard input that never arrives (5 s), an
  unreadable or invalid `agents.yaml`, a corrupt mode file, a failed state or log write, an unexpected exception and a
  command line the hook cannot parse (read from the real command line, so `python -m safo hooks guard --no-such-flag` too) all exit 0, print the fixed line `SAFO routing guard degraded: enforcement may be
  incomplete; inspect safo hooks status.` as hook JSON, and add an enum-only record to the log. No exception text, input
  value or prompt is echoed or stored.
- What a failure switches off: input or configuration failures switch off every rule; a state failure (missing, invalid,
  future-dated or other-session state, or a re-probe that failed) switches off only the local-step rule; a mode failure
  falls back to `warn`.
- A denial that was computed survives a log failure.
- stdout is exactly one JSON line or nothing. `probe` and `guard` never exit 2 (a host reads that as a denial), even for a bad flag.
- The host's own timeout (15 s for the probe, 10 s for the guard in the installed settings) is the last backstop. How a
  given Claude Code version treats a timed-out or crashed hook is not verified here.

## What is stored

Under `$XDG_STATE_HOME/safo/hooks` (default `~/.local/state/safo/hooks`), mode 0600: `log.jsonl` (decision, mode, model
identifier or `unknown`, booleans, rule names, health, diagnostic enum; at most 2048 bytes a record, 4 MiB, one archive)
and per-session probe files named by a hash of the session id and the merged configuration, holding a completion time,
booleans and role flags. No prompt, description, address, endpoint name or loaded-model name is stored. Probe files
untouched for a week are removed when a session starts. The mode lives in `~/.config/safo/mode`.

SAFO creates its own state and config directories mode 0700. Before it uses one, the directory must be owned by the
effective user and not group- or world-writable; otherwise the feature degrades visibly instead of trusting it: the
guard allows with the degraded notice and writes no log, lock or state there, the probe reports a state-write
failure, and an untrusted config directory means the mode file is ignored (`warn`, health degraded). The reason is
that a lock is a pathname's inode: anyone who can write the directory can unlink a held lock and make a second one, or
replace the mode, state and log files.

## Installing safely

Run `safo hooks install --dry-run --settings /tmp/try.json` first. Start in `warn`, read `safo hooks status`, then
switch to `block`. Before recommending `block`, run the disposable real-session smoke test listed in the plan (Task
T9h, step 5): fixture tests cannot show that a real Claude Code session displays the warning or honours a denial.

## Where the local files may live

Under GitHub Actions the agents file, the local override and the outcomes log are refused when they lie inside
`$GITHUB_WORKSPACE`, by the path as written or after following links, and every explicit path is refused when
`GITHUB_WORKSPACE` is unset; only the home defaults remain. Accepted residual: outside Actions, an explicit `--agents`,
`--log` or `$SAFO_AGENTS` naming a file in the current directory is the user's own deliberate choice and is allowed
(the current directory is never searched on its own).

## Endpoint destinations

An Ollama endpoint may be loopback or a private LAN address. Link-local, unspecified, multicast and cloud-metadata
addresses (including IPv4-mapped IPv6 and decimal, octal and hex spellings) are refused when `agents.yaml` is loaded
and again at connect time. A name is resolved once, every address it returns is checked, and the connection goes to the
checked address with the original `Host` header, so a DNS answer that changes between the check and the connection has
no effect.

## Known limits

- The lead-never-waits rule is a tokenizer, not a shell parser. It is a speed bump against accidents, not a sandbox:
  an actor who can already run arbitrary Bash as the same user can also edit the guard's config, mode file and logs.
  These cannot be decided from the text of one call. Each is allowed, and each has a test that asserts exactly that, so
  the docs and the code cannot drift:
  - [limit: variable-built command] `cmd='sleep 60'; $cmd`.
  - [limit: variable passed to a shell] `c='sleep 60'; bash -c "$c"`: the string is a variable, not text.
  - [limit: encoded payload piped to a shell] `echo c2xlZXAgNjA= | base64 -d | sh`.
  - [limit: interpreter] `python3 -c` or `perl -e` with a sleep call inside, and any other language's sleep or poll.
  - [limit: script file] `bash poll.sh`: the file is not read, so a loop in it is not seen.
  - [limit: alias] `alias w='sleep 60'; w`: an alias defined earlier or in a startup file.
  - [limit: remote command] `ssh host 'sleep 60'`: the wait runs elsewhere (and still holds the thread).
  Also not seen: `timeout ... tail -f`, a function defined in an earlier call, and a wait inside a function body that
  is not a brace group. Shell grammar is approximated: `case` arms are read as plain commands, and `${...}` is read for
  its substitutions only. `parallel` options are a fixed list: an option this scanner does not know that takes a
  value hides the command behind it. Executable syntax nested deeper than 3 levels, a brace-built command, an
  indirect call next to a function definition and a scan that runs out of time are reported as `unscannable-*`
  rather than guessed at. The cheap pre-check tokenizes any call that contains a quote, backslash, `$`, backtick or
  `{`, so a word built from pieces (`sl''eep 60`, `sl{e,e}p`) is not missed; a call with none of those and
  none of `sleep`, `watch`, `checks` reads no configuration and logs nothing. It would rather miss the cases above
  than flag text. Whether a given Claude Code version puts `agent_id` on sub-agent events was not verified in a live
  SAFO session; if it did not, a sub-agent's watch would be flagged as the lead's (a warning in `warn` mode, a denial in
  `block`). Test that in a disposable session before `block`.

- The approval token is forgeable (see rule 2). A channel the model cannot write to, such as a signed or
  session-bound approval the maintainer issues outside the conversation, is future work; v0.1.0 has none, and nothing in
  `block` mode should be read as proof of approval.
- Directory checks look at the SAFO directory itself, not the path above it, and the installer's own lock and temp file
  sit beside the settings file you name (for example `/tmp`), which it does not require to be private.
- The installer narrows the replace race but pathname operations cannot close it: an external writer can still land
  between the final identity check and the rename.
