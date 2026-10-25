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

What waits, after quoted strings, heredoc bodies and comments are removed:

| Found | Example |
|---|---|
| `gh run watch` | `gh run watch 123 --exit-status` |
| `gh pr checks` with `--watch` or `-w` | `gh pr checks 12 --watch` |
| a `while`, `until` or `for` loop that contains a `sleep`, of any length | `until gh run view 9 \| grep -q completed; do sleep 10; done` |
| `sleep` at or above the **threshold** (10 seconds by default; the sleeps of one command add up; an argument the hook cannot read, such as `sleep $n`, counts as over) | `sleep 120`, `sleep 5; sleep 6` |

Not flagged: `sleep 1` or `sleep 9` in a one-shot command (below the threshold, a pause and not a wait); the words
`gh run watch` in a commit message, a quoted string, a comment or a `cat <<'EOF'` heredoc body.

What the hook reads from the event, and what it does not:

- **Lead or sub-agent.** An event raised inside a sub-agent carries an `agent_id`; the event of the lead's own thread does
  not. The rule skips any event with an `agent_id`, because a monitor agent is allowed to watch. This relies on the host
  adding the field. Evidence that it does: an official Claude Code plugin's hook skips sub-agent events with
  `"agent_id" in data`. It was not observed from a live SAFO session here (see Known limits).
- **Background or not.** The Bash tool's input carries `run_in_background`, which the hook reads from `tool_input`. Only the
  boolean `true` counts: `"true"`, `1` and `"yes"` do not. A command that backgrounds itself in the shell (`sleep 60 &`) is
  not the same thing and is not treated as background.

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
- A single call can carry a comment, `# lead-wait: ok - <reason>`, with a reason of at least 12 characters. A marker with
  no reason, or a placeholder, is ignored and the call is flagged; the message says the reason is required. An exempted call
  is allowed and logged as `allow` with the `lead-waits` rule, so exemptions can be counted. The reason itself stays in the
  transcript and is never written to the log.
- Like the approval token, both are speed bumps: an agent with shell access can type a marker. Their job is to make a
  deliberate wait a written decision.

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

- The lead-never-waits rule is a scanner, not a shell parser. It does not see a wait built by a variable or an `eval`, a
  loop in a script file the call merely runs, `watch`, `timeout ... tail -f`, a `$(...)` in an unquoted heredoc body, or
  `sleep` inside a function defined earlier. It would rather miss these than flag text. Whether a given Claude Code
  version puts `agent_id` on sub-agent events was not verified in a live SAFO session; if it did not, a sub-agent's
  watch would be flagged as the lead's (a warning in `warn` mode, a denial in `block`). Test that in a disposable session
  before `block`.

- The approval token is forgeable (see rule 2). A channel the model cannot write to, such as a signed or
  session-bound approval the maintainer issues outside the conversation, is future work; v0.1.0 has none, and nothing in
  `block` mode should be read as proof of approval.
- Directory checks look at the SAFO directory itself, not the path above it, and the installer's own lock and temp file
  sit beside the settings file you name (for example `/tmp`), which it does not require to be private.
- The installer narrows the replace race but pathname operations cannot close it: an external writer can still land
  between the final identity check and the rename.
