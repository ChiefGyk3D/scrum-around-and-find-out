# Shared read-only venv (`safo-shared-venv`)

Agents that each build their own venv spend minutes and disk on the same packages (#534, epic #518). This command
builds one venv per lockfile and shares it.

```
safo-shared-venv requirements.lock            # prints the interpreter path
safo-shared-venv --gc --max-age-days 30       # lists venvs unused for 30 days
safo-shared-venv --gc --max-age-days 30 --delete
```

## Trust boundary

- The shared root must be owned by the current user and must not be writable by any other account. The command
  refuses a root that is not. A hostile process running as the same user is out of scope: it can already do anything
  that user can, and filesystem modes cannot authenticate against it.
- The lockfile content is trusted input: its hashes are the trust anchor. The strict grammar below defends against
  parser smuggling and malformed input. It does not defend against a hostile but valid lockfile, so review a lockfile
  change like any dependency change.
- The owner, mode and manifest checks on reuse detect accidental or cross-account damage (a pre-created or edited
  entry). A same-user attacker can rewrite the marker as well; that is the boundary above.

## Behavior

- Location: `--root`, else `$SAFO_SHARED_VENV_ROOT`, else `~/.local/share/safo-venvs`. Every existing ancestor of the
  root must be a real directory (no symbolic link) owned by you or root and not writable by group or others (a sticky
  directory owned by root, such as `/tmp`, is the one allowed exception). Missing components are created one at a
  time with mode 0700, each verified by lstat, and the whole chain is checked again before the root is returned. The root is held by descriptor and re-checked before the lock work, the build,
  the publish rename (done relative to that descriptor) and each GC deletion; a root replaced in between is refused.
- Key: the sha256 of a canonical record of the lockfile hash, the interpreter (resolved `--python` path,
  implementation, major.minor, cache tag, platform, ABI flags, bundled pip version, and the sha256 of the interpreter
  file and of its base interpreter, re-verified together with inode and mtime before the build, on every reuse and
  again just before the path is printed). The interpreter is resolved once to its final real path, opened once without
  following links, and only that resolved path is ever executed. The file and every ancestor directory must belong to
  root or you and not be writable by group or others (a root-owned sticky directory such as `/tmp` excepted). On
  reuse the venv's `bin/python` must still resolve to the recorded base interpreter. and the acquisition policy
  (`--no-index`, `--index-url`, `--find-links`). A different interpreter or policy never returns an existing entry. A
  `--python` that does not exist is refused.
- Build: `pip --isolated install --require-hashes --no-deps --only-binary=:all: -r FILE` into a new venv without
  system site-packages. The lockfile must follow a strict grammar: `name==version` plus one or more
  `--hash=sha256:...`, optionally split by trailing backslashes, with `# comment` lines at column 0; anything else is
  refused. pip reads a private copy of the checked bytes from a fresh random-named 0700 build directory, through an
  open descriptor (`/proc/self/fd/N`) where available, and the bytes are re-hashed from that descriptor after the
  install. The children run with an allowlisted environment (PATH, LANG, LC_ALL, a private HOME, `PIP_CONFIG_FILE` set
  to the null device) and pip runs isolated, so no pip configuration file is read. The index is `--index-url`,
  `--find-links` and `--no-index` only; nothing else is fetched.
- Read-only: after the build every file and directory loses its write bit, a manifest (sha256 over the sorted relative
  path, size and mode of every member) is stored in the marker, and the venv is renamed into place in one step. Agents
  run it and never install into it. A changed lockfile is a new key and a new venv.
- Reuse: the entry directory, `pyvenv.cfg` and the marker must be plain files and directories owned by the current
  user and not group or world writable, `bin/python` must exist and its link be owned by the current user, and the
  manifest must match. Anything else is refused and reported.
- Lock: `ROOT/.lock` (flock) so two callers never build the same venv; the second waits (`--lock-timeout`) and reuses.
  After taking the lock the descriptor is compared with the path and retaken if the file was replaced; this narrows the
  race for a same-user writer and does not remove it.
- Use stamp: `ROOT/<key>.used` is opened without following links; it must be a regular single-link file of the current
  user.
- GC: age is the later of the venv's last change and the use stamp. Without `--delete` it only lists. Only entries with
  a valid marker, manifest and layout are deleted; anything else (and any link) is reported as skipped and left alone.
  Leftover build directories are removed only when their name matches the random build-name pattern and they carry this
  tool's build marker.
- Credentials: acquisition arguments are limited to `--no-index`, `--index-url URL` and `--find-links URL`, each URL
  parsed with urllib (scp-like and bare `user@host` forms included; whitespace, control characters and unparsable
  values refused). Userinfo, the whole query and the fragment are secret: such a URL is refused unless
  `--allow-url-credentials` is given, at the function boundary as well as on the command line (the value is then
  visible in the process list while pip runs). The exact values supplied, and the secret parts of any other URL in the
  text, are replaced in every message and in pip's captured output.
- Age and timeout: `--max-age-days` must be finite, from 0 to 36500, and `--lock-timeout` finite, from 0 to 7 days, checked in `ensure`, `gc` and `Lock` themselves, not only on the command line;
  anything else (nan, inf, negative, absurd) is refused and nothing is deleted. GC also never selects an entry whose
  age does not compare as at least the threshold.
- Writable entries: reuse validation refuses a venv, marker or member with any write bit; a failure after the
  publish rename removes the entry.
- Exit codes: 0 done, 1 build or lock failure, 2 refusal or bad usage. Only the interpreter path goes to stdout.

Tests: `tests/test_sharedvenv.py` (a local wheel built in the test, no network, two concurrent processes).
