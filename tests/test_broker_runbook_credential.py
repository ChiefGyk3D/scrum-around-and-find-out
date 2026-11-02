# SPDX-License-Identifier: Apache-2.0
"""The credential step of the runbook, run for real against a temporary directory with a stub encrypter.

No real encrypter, no real key, no /etc: the script text is taken from the runbook, the remote shell parse is done by a
local shell, and the paths are redirected into pytest's temporary directory.
"""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from safo.broker import runbook


def credential_script(directory: Path) -> str:
    doc = runbook.render(maintainer="MAINTAINER_LOGIN")
    line = next(x for x in doc.splitlines() if x.startswith("ssh ") and "systemd-creds encrypt" in x)
    remote = shlex.split(line)[3].removeprefix(f"sudo {runbook.ENV} bash -c ")
    done = subprocess.run(  # noqa: S603 - fixed argv, a local shell evaluating the runbook text, no secret
        ["/bin/sh", "-c", "printf %s " + remote],
        capture_output=True,
        text=True,
        check=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
    )
    return done.stdout.replace("/etc/safo/broker", str(directory))


def stub_creds(bin_dir: Path, *, encrypt_ok: bool, decrypt_ok: bool) -> None:
    bin_dir.mkdir()
    encrypt = 'for last; do :; done; cat > "$last"' if encrypt_ok else "cat > /dev/null; exit 1"
    decrypt = "exit 0" if decrypt_ok else "exit 1"
    stub = bin_dir / "systemd-creds"
    stub.write_text(f'#!/bin/sh\ncase "$1" in\n  encrypt) {encrypt} ;;\n  decrypt) {decrypt} ;;\nesac\n')
    stub.chmod(0o755)


def run_credential(tmp_path: Path, *, encrypt_ok: bool, decrypt_ok: bool) -> tuple[int, Path]:
    broker = tmp_path / "broker"
    broker.mkdir(parents=True)
    (broker / "paid-key").write_text("OLD-CREDENTIAL")
    stub_creds(tmp_path / "bin", encrypt_ok=encrypt_ok, decrypt_ok=decrypt_ok)
    done = subprocess.run(  # noqa: S603 - fixed argv, a stub encrypter in a temporary directory, a fake key on stdin
        ["/bin/bash", "-c", credential_script(broker)],
        input="not-a-real-key\n",
        capture_output=True,
        text=True,
        env={"PATH": f"{tmp_path / 'bin'}:/usr/bin:/bin"},
        timeout=30,
        check=False,
    )
    return done.returncode, broker


def test_the_old_credential_is_replaced_only_after_the_new_one_decrypts(tmp_path: Path) -> None:
    code, broker = run_credential(tmp_path, encrypt_ok=True, decrypt_ok=True)
    assert code == 0
    assert (broker / "paid-key").read_text() == "not-a-real-key"
    assert not (broker / "paid-key.new").exists()
    assert oct((broker / "paid-key").stat().st_mode & 0o777) == "0o600"


def test_a_failing_encrypter_keeps_the_old_credential_and_fails_the_command(tmp_path: Path) -> None:
    code, broker = run_credential(tmp_path, encrypt_ok=False, decrypt_ok=True)
    assert code != 0
    assert (broker / "paid-key").read_text() == "OLD-CREDENTIAL"


def test_a_new_credential_that_does_not_decrypt_is_never_moved_into_place(tmp_path: Path) -> None:
    code, broker = run_credential(tmp_path, encrypt_ok=True, decrypt_ok=False)
    assert code != 0
    assert (broker / "paid-key").read_text() == "OLD-CREDENTIAL"
