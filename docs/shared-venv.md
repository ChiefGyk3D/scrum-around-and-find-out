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
- Read-only: after the build every file and directory loses its write bit (the top directory too, before the rename
  publishes it; the venv is staged as `ROOT/.stage-RANDOM` so that rename needs no write access), a manifest (sha256 over the sorted relative
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
- Acquisition values: the only arguments accepted are `--no-index`, `--index-url SOURCE` and `--find-links SOURCE`, and
  a SOURCE must match one of two whitelisted forms or it is refused before anything is used or printed (nothing is
  parsed or rewritten): (a) `https://HOST[:PORT]/PATH` with HOST a lowercase DNS name or IPv4 address, PORT 1 to
  65535 and PATH from `[A-Za-z0-9._~/+-]`; (b) an absolute local directory path from `[A-Za-z0-9._/+-]`. Neither may
  hold a `..` segment or `//`, and no value may exceed 1024 characters. So no userinfo, `@`, query, fragment,
  percent-encoding, backslash, whitespace, control character, non-ASCII name, IPv6 address, zone id, trailing dot,
  uppercase scheme or host, other scheme (`http`, `file`, `ssh`), scp-like form, relative path or colon in a path. The
  refusal text is fixed and never echoes the value. Credentials are never accepted in any form: an index that needs
  them needs a different mechanism than a command-line URL (the old `--allow-url-credentials` option is gone). As
  defense in depth, any text holding `://` that is not an allowed SOURCE is masked whole as `<redacted-url>` in the
  command's own messages.
- Messages: every message is a fixed string plus numbers (a line number, an exit status, a count) and at most a name this
  tool generated (a key, a log file name). No caller-supplied value (a path, an interpreter, a URL, a lockfile line)
  is ever echoed in a message, exception text or log line; the one thing printed from the caller's input is the
  interpreter path of the venv on success, which is the result. The lockfile, `--root` and `--python` arguments are
  refused up front, with a fixed message, if they hold whitespace, a control character or a non-printable character
  (so a `--python` under a directory with a space in its name is refused; use a path without one). The earlier
  redaction helper is gone: nothing is parsed and scrubbed, nothing is echoed.
- Errors at the boundaries: `ensure`, `gc`, `open_root`, `Lock` and `valid` raise only `Refused` or `Failed`, with fixed
  text and no `__cause__` or `__context__`. A filesystem error becomes `Failed` with the errno number only, any other
  unexpected error becomes `Failed` with its class name only. The command line adds a last boundary: anything else
  prints one line, `unexpected error (CLASS, errno N); nothing from the input is shown`, exit 1, with no traceback and
  never `str(exc)`; an interrupt prints `interrupted` and exits 130.
- Child output: the output of pip and of the venv step is never relayed (credentials can appear in any shape, for
  example a redirect line or a bare token). On success nothing from pip is printed. On failure only a fixed message
  with pip's exit status and the build step is printed. With `--keep-pip-log`, a failed install's full output is
  written to `ROOT/pip-<key prefix>-<random>.log` (mode 0600, exclusive create) and its path is named in the message; it
  may contain credentials, so delete it after reading. Without the flag the output is discarded. A child that times out or fails is reported by a fixed message with no
  exception chain, so the captured output cannot be reached through `__cause__`, `__context__` or exception
  attributes. Argument errors from the command line are a fixed message too: argparse's own text, which would echo
  the offending arguments, is never shown.
- Age and timeout: `--max-age-days` must be finite, from 0 to 36500, and `--lock-timeout` finite, from 0 to 7 days, checked in `ensure`, `gc` and `Lock` themselves, not only on the command line;
  anything else (nan, inf, negative, absurd) is refused and nothing is deleted. GC also never selects an entry whose
  age does not compare as at least the threshold.
- Interrupted builds: a leftover `.build-RANDOM` or `.stage-RANDOM` is removed only when it matches the random name,
  is owned by you, carries one of this tool's exactly formed markers (the build marker text, or for a stage the
  complete lock marker) and holds no symbolic link or special file (a stage may hold a venv's own links under `bin/`
  and a top-level `lib64`, which are unlinked and never followed). The removal is done relative to the root
  descriptor, so it cannot leave the root. Anything else is left alone and counted in one fixed line on stderr.
  Deviation noted: a stage cannot be required to hold no symbolic link at all, because every venv has some. An entry named by a key whose top directory has only the owner write bit and holds this
  tool's complete marker is rebuilt over (the marker is exactly two 64-hex lines, each ending in a newline, nothing
  after; any extra byte, NUL or line makes it not ours); group or world write, a missing or foreign marker, or any other mismatch is
  refused and never deleted.
- Writable entries: reuse validation refuses a venv, marker or member with any write bit (except the rebuild case
  above).
- Exit codes: 0 done, 1 build or lock failure, 2 refusal or bad usage. Only the interpreter path goes to stdout.

Tests: `tests/test_sharedvenv.py` (a local wheel built in the test, no network, two concurrent processes).
