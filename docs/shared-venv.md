# Shared read-only venv (`safo-shared-venv`)

Agents that each build their own venv spend minutes and disk on the same packages (#534, epic #518). This command
builds one venv per lockfile and shares it.

```
safo-shared-venv requirements.lock            # prints the interpreter path
safo-shared-venv --gc --max-age-days 30       # lists venvs unused for 30 days
safo-shared-venv --gc --max-age-days 30 --delete
```

- Location: `--root`, else `$SAFO_SHARED_VENV_ROOT`, else `~/.local/share/safo-venvs`. The root must be a real
  directory owned by you and not writable by others. A venv lives at `ROOT/<sha256 of the lockfile>`.
- Build: `pip install --require-hashes --no-deps --only-binary=:all: -r LOCKFILE` into a new venv without system
  site-packages. Every requirement must carry a `--hash=sha256:...`; an option line in the lockfile (an index, `-r`,
  `-e`) is refused. The index is whatever pip is configured with; `--index-url`, `--find-links` and `--no-index`
  narrow it. Nothing else is fetched.
- Read-only: after the build every file and directory loses its write bit, then the venv is renamed into place in one
  step. Agents run it and never install into it. A changed lockfile is a new key and a new venv.
- Lock: `ROOT/.lock` (flock) so two callers never build the same venv; the second waits (`--lock-timeout`) and reuses.
- GC: age is the later of the venv's build time and the last use stamp `ROOT/<key>.used`. Without `--delete` it only
  lists. Symbolic links are skipped, never followed.
- Exit codes: 0 done, 1 build or lock failure, 2 refusal or bad usage. Only the interpreter path goes to stdout.

Tests: `tests/test_sharedvenv.py` (a local wheel built in the test, no network, two concurrent processes).
