# SPDX-License-Identifier: Apache-2.0
"""scripts/sshsig_flags.py reads the user-present and user-verified flags from an armored SSH signature (#339).

The signatures here are synthetic (built byte by byte, never signed by a key); the helper does not verify anything
cryptographically, it only parses the layout of PROTOCOL.sshsig and PROTOCOL.u2f.
"""

from __future__ import annotations

import base64
import importlib.util
import struct
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
SK_ED25519 = b"sk-ssh-ed25519@openssh.com"


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sshsig_flags", ROOT / "scripts" / "sshsig_flags.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["sshsig_flags"] = module
    spec.loader.exec_module(module)
    return module


def s(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def armor(blob: bytes) -> str:
    b64 = base64.b64encode(blob).decode()
    body = "\n".join(b64[i : i + 70] for i in range(0, len(b64), 70))
    return f"-----BEGIN SSH SIGNATURE-----\n{body}\n-----END SSH SIGNATURE-----\n"


def make_blob(
    flags: int, alg: bytes = SK_ED25519, counter: int = 2, trailing: bytes = b"", sig_extra: bytes = b""
) -> bytes:
    pub = s(SK_ED25519) + s(b"\x01" * 32) + s(b"ssh:safo-gemini-a")
    inner = s(alg) + s(b"\x02" * 64) + bytes([flags]) + struct.pack(">I", counter) + sig_extra
    blob = b"SSHSIG" + struct.pack(">I", 1) + s(pub) + s(b"safo-gemini-approval-dryrun") + s(b"") + s(b"sha512")
    return blob + s(inner) + trailing


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "msg.sig"
    p.write_text(text)
    return p


def test_user_present_and_verified_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    mod = load()
    assert mod.main(["x", str(write(tmp_path, armor(make_blob(0x05))))]) == 0
    out = capsys.readouterr().out
    assert "flags=0x05 counter=2" in out
    assert "user-present=True user-verified=True" in out
    assert "namespace=safo-gemini-approval-dryrun" in out


def test_without_user_verified_exits_one(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    mod = load()
    assert mod.main(["x", str(write(tmp_path, armor(make_blob(0x01))))]) == 1
    assert "user-present=True user-verified=False" in capsys.readouterr().out


def test_not_a_security_key_signature_exits_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    mod = load()
    assert mod.main(["x", str(write(tmp_path, armor(make_blob(0x05, alg=b"ssh-ed25519"))))]) == 2
    assert "not a security-key signature" in capsys.readouterr().err


def test_truncated_signature_exits_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    mod = load()
    assert mod.main(["x", str(write(tmp_path, armor(make_blob(0x05)[:-20])))]) == 2
    assert "truncated" in capsys.readouterr().err


def test_trailing_data_exits_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    mod = load()
    assert mod.main(["x", str(write(tmp_path, armor(make_blob(0x05, trailing=b"\x00"))))]) == 2
    assert "trailing data" in capsys.readouterr().err
    assert mod.main(["x", str(write(tmp_path, armor(make_blob(0x05, sig_extra=b"\x00"))))]) == 2
    assert "trailing data in signature" in capsys.readouterr().err


def test_not_armored_missing_file_and_wrong_argument_count_exit_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mod = load()
    assert mod.main(["x", str(write(tmp_path, "hello\n"))]) == 2
    assert "not an armored SSH signature" in capsys.readouterr().err
    assert mod.main(["x"]) == 2
    assert mod.main(["x", str(tmp_path / "missing")]) == 2
