# safo hooks

`safo hooks` turns the routing rules in `agents.yaml` into two Claude Code hooks, so they are enforced and not
remembered. The guard is a speed bump and an audit trail, not a security boundary: whoever writes a brief can type the
approval token, and that includes a model that a prompt injection has talked into it.

| Command | Claude Code event | What it does |
|---|---|---|
| `safo hooks install [--settings PATH] [--mode warn\|block] [--command safo]` | none | Merges the two hooks into a `settings.json` (default `~/.claude/settings.json`). Keeps every other hook and setting, is a no-op when run again, keeps a private backup before it replaces the file, and refuses to overwrite a file that changed while it worked (bytes, or the file itself: device, inode, size and modification time are checked again just before the replace, so a rename-over with identical bytes is caught too, with `settings changed while installing`). `--dry-run` writes nothing. |
| `safo hooks probe` | SessionStart | Asks each Ollama endpoint in `agents.yaml` which models are loaded (two bounded GETs, never a generate), saves the answer and tells the session whether the local LLM is reachable. |
| `safo hooks guard` | PreToolUse, matcher `Agent\|Task` | Checks each subagent brief against three rules (below). |
| `safo hooks mode warn\|block` | none | `warn` reports a broken rule and allows the dispatch (the default); `block` denies it. |
| `safo hooks status [--session ID --agents PATH]` | none | The mode, the retained counts, the health of the hooks and of the last probe. |

## The three rules

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

- The approval token is forgeable (see rule 2). A channel the model cannot write to, such as a signed or
  session-bound approval the maintainer issues outside the conversation, is future work; v0.1.0 has none, and nothing in
  `block` mode should be read as proof of approval.
- Directory checks look at the SAFO directory itself, not the path above it, and the installer's own lock and temp file
  sit beside the settings file you name (for example `/tmp`), which it does not require to be private.
- The installer narrows the replace race but pathname operations cannot close it: an external writer can still land
  between the final identity check and the rename.
