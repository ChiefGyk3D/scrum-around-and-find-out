# SPDX-License-Identifier: Apache-2.0
"""Test driver for safo-digest (#531): the real entry point with the executable policy relaxed.

The production tool runs only git and gh, native, root-owned, under root-owned directories. To exercise the process
machinery (output capture, caps, timeouts, signals, detached descendants, directory checks) with small synthetic
programs, this driver replaces exactly three policy hooks and nothing else, in this test process only:

- `_check_supported`: which programs may be listed (git and gh only in production);
- `check_executable`: the native-ELF-only rule;
- `open_verified_exe(..., root_only=True)`: the root-ownership rule (the no-symlink walk and the owner and
  write-bit checks still run, as for any user-owned file).

Everything about git and gh itself is tested through the real entry point, not through this driver.
"""

import sys

from safo import digest

_real_open = digest.open_verified_exe


def _open(path: str, *, root_only: bool = True) -> int:
    return _real_open(path, root_only=False)


digest.open_verified_exe = _open


def _any_program(base: str, cmd: list[str], options: dict[str, str]) -> None:
    return None


def _any_file(efd: int) -> None:
    return None


digest._check_supported = _any_program
digest.check_executable = _any_file

if __name__ == "__main__":
    sys.exit(digest.main())
