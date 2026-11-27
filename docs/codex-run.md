# safo-codex-run: repository checks

Before codex starts, the wrapper checks the worktree it is pointed at.

What is checked and closed:

- The worktree and its linked git directory must be ours, below the account home, and not writable by others.
- The repository config, and the config of every submodule (nested ones too, to a fixed depth), must not set a key that
  starts a program (a filter, a textconv, an alias, an include, an ssh command and the like). A symlinked submodule
  path is refused.
- For the implementer class the tree must be clean. The check runs `git status` against a private git directory that
  holds only a copy of the index, the object store and a fixed config, so nothing the repository can change after the
  config check is read by that call. An index that marks files assume-unchanged or skip-worktree is refused, because
  git never compares those files with the working tree.
- Codex itself starts with a scrubbed git environment: no system or global config, and command-scope settings that
  turn off fsmonitor and hooks and forbid network and `ext::` transports.

What is NOT closed (residual risk):

- The repository config is read by the git that codex runs, at run time. Environment settings cannot forbid a
  `filter.*` or `diff.*.textconv` program by name in advance. A process that can write the repository config while
  codex runs, together with a `.gitattributes` that names the filter, can get a program started when codex runs git.
- Attacker model for this residual: write access to the repository's config files during the run. An attacker with
  only the ability to change the working tree before the run is covered by the checks above. Keep other writers away
  from the repository while a run is in progress. A test (`test_documented_boundary_...`) documents the boundary and
  must be changed together with this text if the boundary ever moves.
