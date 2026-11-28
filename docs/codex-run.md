# safo-codex-run: repository checks

Before codex starts, the wrapper checks the worktree it is pointed at.

What is checked and closed:

- The worktree and its linked git directory must be ours, below the account home, and not writable by others.
- The repository config, and the config of every submodule (nested ones too, to a fixed depth), may set only keys on an
  allowlist of known-inert settings (core layout flags, user name and email, remote and branch bookkeeping). Any other
  key is refused, so a setting nobody listed never passes. Values are checked too: no control byte, no `::` helper form, no leading `-`; URLs must use the https or ssh scheme, or the scp-style `user at host, colon, path` form (no local paths, no file scheme); refspecs and refs have a plain `refs/...` shape. A submodule's the `worktree` key of the `core` section must resolve to the submodule's own folder. git 2.32 or newer is required (checked at start; older or unreadable fails closed). A symlinked submodule path is refused.
- For the implementer class the tree must be clean. The check runs `git status` against a private git directory that
  holds only a copy of the index, the object store and a fixed config, so nothing the repository can change after the
  config check is read by that call. An index that marks files assume-unchanged or skip-worktree is refused, because
  git never compares those files with the working tree.
- Codex itself starts with a scrubbed git environment: no system or global config, and command-scope settings that
  turn off fsmonitor and hooks, forbid network and `ext::` transports, and force signing and program settings off.
  These settings are a default, not an absolute: a more specific repository key could override them, which is why the
  pre-run check allows only listed keys, and a key written after that check is the residual risk below.

What is NOT closed (residual risk):

- The repository config is read by the git that codex runs, at run time. Environment settings cannot forbid a
  `filter.*` or `diff.*.textconv` program by name in advance. A process that can write the repository config while
  codex runs, together with a `.gitattributes` that names the filter, can get a program started when codex runs git.
- Attacker model for this residual: write access to the repository's config files during the run. An attacker with
  only the ability to change the working tree before the run is covered by the checks above. Keep other writers away
  from the repository while a run is in progress. A test (`test_documented_boundary_...`) documents the boundary and
  must be changed together with this text if the boundary ever moves.

## Partial clones and lazy fetch

Every git call this wrapper makes (and `safo-digest`, which shares the config check in the `gitconfig` module of the safo package) runs with
`GIT_NO_LAZY_FETCH=1`. A partial clone is also refused: its config carries the partial-clone extension and a promisor
remote, which are not on the allowlist. The behavior change from earlier versions: a worktree whose objects are
missing and would have been fetched on demand now fails the check instead of reaching for the network. That is
deliberate: a repository must not be able to make this wrapper contact a remote of its choosing.

## A clean exit is not a finished review

Exit 0 from codex means the process ended, not that a review happened (#577: a deep scan that never started still
printed `exit=0 status=ok`). After a clean exit the wrapper reads the result file and exits 60 (`INCOMPLETE`, also the
ledger `exit`) when it is empty or missing, or when it is short (600 bytes or less) and says the run `failed to start`,
`did not start`, `could not start` or `unable to start`. A longer result is a real answer and may quote those words.

Consumers follow the same rule. The marker line `exit=N status=WORD` that the separate `daybreak-run` wrapper appends is
produced outside this repository and cannot prove completeness: count a review as complete only when its verdict
parser says so (for example a recognized `VERDICT:` line, see [handoff](handoff.md)) or this exit code is 0. A missing
or unparseable verdict is not reviewed, never a pass.
