# SPDX-License-Identifier: Apache-2.0
"""#534: the shared read-only hash-locked venv. Real subprocesses, a tiny local wheel, no network."""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest

from safo import sharedvenv

ENV = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parent.parent / "src")}


def make_wheel(directory: Path, name: str = "tinydemo", version: str = "1.0", requires: str = "") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    dist = f"{name}-{version}.dist-info"
    files = {
        f"{name}.py": b"VALUE = 534\n",
        f"{dist}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n{requires}".encode(),
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record = [f"{n},sha256={base64.urlsafe_b64encode(hashlib.sha256(b).digest()).rstrip(b'=').decode()},{len(b)}"
              for n, b in files.items()]  # fmt: skip
    files[f"{dist}/RECORD"] = ("\n".join([*record, f"{dist}/RECORD,,"]) + "\n").encode()
    path = directory / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as z:
        for n, b in files.items():
            z.writestr(n, b)
    return path


def lock_for(wheel: Path, directory: Path, name: str = "req.txt", extra: str = "") -> Path:
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    stem = wheel.name.split("-")
    lock = directory / name
    lock.write_text(f"# pinned\n{stem[0]}=={stem[1]} \\\n    --hash=sha256:{digest}\n{extra}")
    return lock


def cli(*args: object, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv in a test helper, no shell
        [sys.executable, "-m", "safo.sharedvenv", *map(str, args)],
        capture_output=True,
        text=True,
        env={**ENV, **(env or {})},
        timeout=300,
    )


@pytest.fixture
def wheels(tmp_path: Path) -> Path:
    make_wheel(tmp_path / "wheels")
    return tmp_path / "wheels"


@pytest.fixture
def lock(tmp_path: Path, wheels: Path) -> Path:
    return lock_for(next(wheels.glob("*.whl")), tmp_path)


def build_args(lock: Path, root: Path, wheels: Path) -> list[object]:
    return [lock, "--root", root, "--no-index", "--find-links", wheels]


def test_builds_keyed_venv_installs_pinned_wheel_prints_interpreter(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    done = cli(*build_args(lock, root, wheels))
    assert done.returncode == 0, done.stderr
    python = Path(done.stdout.strip())
    key = hashlib.sha256(lock.read_bytes()).hexdigest()
    assert python == root / key / "bin" / "python"
    out = subprocess.run(  # noqa: S603 - fixed argv in a test helper, no shell
        [python, "-c", "import tinydemo;print(tinydemo.VALUE)"], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "534"
    cfg = (root / key / "pyvenv.cfg").read_text().lower()
    assert "include-system-site-packages = false" in cfg


def test_venv_is_read_only_and_reuse_does_not_rebuild(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    first = cli(*build_args(lock, root, wheels))
    key = hashlib.sha256(lock.read_bytes()).hexdigest()
    writable = [p for p in (root / key).rglob("*") if not p.is_symlink() and p.stat().st_mode & 0o222]
    assert writable == []
    assert not (root / key).stat().st_mode & 0o222
    inode = (root / key).stat().st_ino
    second = cli(*build_args(lock, root, tmp_path / "no-such-wheels"))  # a rebuild would fail without wheels
    assert (second.returncode, second.stdout) == (0, first.stdout)
    assert (root / key).stat().st_ino == inode
    with pytest.raises(PermissionError):
        (root / key / "lib" / "evil.txt").write_text("x")


def test_changed_lockfile_is_a_new_venv(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    a = cli(*build_args(lock, root, wheels)).stdout
    other = make_wheel(wheels, version="2.0")
    b = cli(*build_args(lock_for(other, tmp_path, "req2.txt"), root, wheels)).stdout
    assert a != b and a and b


def test_refuses_lockfile_without_hashes(tmp_path: Path, wheels: Path) -> None:
    bad = tmp_path / "bad.txt"
    bad.write_text("tinydemo==1.0\n")
    done = cli(*build_args(bad, tmp_path / "root", wheels))
    assert done.returncode == 2 and "with sha256 hashes" in done.stderr and done.stdout == ""
    assert not (tmp_path / "root").exists()


def test_refuses_partly_hashed_and_option_lines(tmp_path: Path, wheels: Path, lock: Path) -> None:
    mixed = lock_for(next(wheels.glob("*.whl")), tmp_path, "mixed.txt", extra="other==1.0\n")
    assert cli(*build_args(mixed, tmp_path / "root", wheels)).returncode == 2
    opt = lock_for(next(wheels.glob("*.whl")), tmp_path, "opt.txt", extra="--index-url https://example.invalid/\n")
    done = cli(*build_args(opt, tmp_path / "root", wheels))
    assert done.returncode == 2 and "refused" in done.stderr
    empty = tmp_path / "empty.txt"
    empty.write_text("# nothing\n")
    assert cli(*build_args(empty, tmp_path / "root", wheels)).returncode == 2


def test_refuses_symlinked_lockfile_root_and_venv_entry(tmp_path: Path, wheels: Path, lock: Path) -> None:
    link = tmp_path / "link.txt"
    link.symlink_to(lock)
    assert cli(*build_args(link, tmp_path / "root", wheels)).returncode == 2
    real = tmp_path / "realroot"
    real.mkdir(mode=0o700)
    (tmp_path / "rootlink").symlink_to(real)
    done = cli(*build_args(lock, tmp_path / "rootlink", wheels))
    assert done.returncode == 2 and "symbolic link" in done.stderr
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    (root / hashlib.sha256(lock.read_bytes()).hexdigest()).symlink_to(real)
    done = cli(*build_args(lock, root, wheels))
    assert done.returncode == 2 and "symbolic link" in done.stderr


def test_refuses_root_writable_by_others(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    root.chmod(0o777)
    assert cli(*build_args(lock, root, wheels)).returncode == 2


def test_refuses_venv_with_system_site_packages(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    cli(*build_args(lock, root, wheels))
    cfg = root / hashlib.sha256(lock.read_bytes()).hexdigest() / "pyvenv.cfg"
    cfg.chmod(0o600)
    cfg.write_text(
        cfg.read_text().replace("include-system-site-packages = false", "include-system-site-packages = true")
    )
    assert cli(*build_args(lock, root, wheels)).returncode == 2


def test_hash_mismatch_fails_and_leaves_no_venv(tmp_path: Path, wheels: Path) -> None:
    lock = tmp_path / "wrong.txt"
    lock.write_text(f"tinydemo==1.0 --hash=sha256:{'0' * 64}\n")
    root = tmp_path / "root"
    done = cli(*build_args(lock, root, wheels))
    assert done.returncode == 1
    assert [p.name for p in root.iterdir() if p.name != ".lock"] == []


def test_two_processes_build_once(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    log = tmp_path / "creates.log"
    wrapper = tmp_path / "py.sh"
    wrapper.write_text(f'#!/bin/sh\necho x >> {log}\nsleep 1\nexec {sys.executable} "$@"\n')
    wrapper.chmod(0o755)
    cmd = [sys.executable, "-m", "safo.sharedvenv", *map(str, build_args(lock, root, wheels)), "--python", str(wrapper)]
    procs = [
        subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=ENV)  # noqa: S603 - fixed argv in a test helper, no shell
        for _ in range(2)
    ]
    results = [(*p.communicate(timeout=300), p.returncode) for p in procs]
    assert [r[2] for r in results] == [0, 0], results
    assert results[0][0] == results[1][0] != ""
    assert log.read_text().count("x") == 1
    assert [p.name for p in root.iterdir() if p.name.startswith(".tmp-")] == []


def test_gc_lists_then_deletes_only_old(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    cli(*build_args(lock, root, wheels))
    other = make_wheel(wheels, version="2.0")
    cli(*build_args(lock_for(other, tmp_path, "req2.txt"), root, wheels))
    old_key = hashlib.sha256(lock.read_bytes()).hexdigest()
    new_key = hashlib.sha256((tmp_path / "req2.txt").read_bytes()).hexdigest()
    long_ago = time.time() - 40 * 86400
    for path in (root / old_key, root / f"{old_key}.used"):
        os.utime(path, (long_ago, long_ago))
    listing = cli("--gc", "--max-age-days", 30, "--root", root)
    assert (
        listing.returncode == 0 and f"would delete {root / old_key}" in listing.stdout and new_key not in listing.stdout
    )
    assert (root / old_key).exists()
    done = cli("--gc", "--max-age-days", 30, "--delete", "--root", root)
    assert done.returncode == 0 and f"deleted {root / old_key}" in done.stdout
    assert not (root / old_key).exists() and not (root / f"{old_key}.used").exists()
    assert (root / new_key).exists()


def test_gc_needs_a_threshold_and_delete_needs_gc(tmp_path: Path, lock: Path) -> None:
    assert cli("--gc", "--root", tmp_path / "r").returncode == 2
    assert cli(lock, "--delete", "--root", tmp_path / "r").returncode == 2


def test_check_hashes_unit() -> None:
    ok = b"a==1 \\\n  --hash=sha256:" + b"a" * 64 + b"\n"
    assert sharedvenv.check_hashes(ok) == 1
    with pytest.raises(sharedvenv.Refused):
        sharedvenv.check_hashes(b"a==1 --hash=md5:abc\n")


def test_installs_only_the_locked_wheels_no_dependencies(tmp_path: Path, wheels: Path) -> None:
    needy = make_wheel(wheels, name="needy", requires="Requires-Dist: absent-package\n")
    done = cli(*build_args(lock_for(needy, tmp_path, "needy.txt"), tmp_path / "root", wheels))
    assert done.returncode == 0, done.stderr


def test_source_pins_the_install_flags() -> None:
    src = Path(sharedvenv.__file__).read_text()
    assert '"--require-hashes", "--no-deps"' in src


def test_source_never_enables_system_site_packages() -> None:
    src = Path(sharedvenv.__file__).read_text()
    assert "--system-site-packages" not in src.replace("system site-packages", "")


HASH = "a" * 64


@pytest.mark.parametrize(
    "text",
    [
        f"tinydemo==1.0 \\\n    --hash=sha256:{HASH} \\\n    --index-url https://example.invalid/simple\n",
        f"tinydemo==1.0 \\\n    --hash=sha256:{HASH} # note \\\n    --index-url https://example.invalid/simple\n",
        f"# a comment \\\n--index-url https://example.invalid/simple\ntinydemo==1.0 --hash=sha256:{HASH}\n",
        f"tinydemo==1.0 \\\n# inside \\\n    --hash=sha256:{HASH}\n",
        f"tinydemo==${{TOKEN}} --hash=sha256:{HASH}\n",
        f"tinydemo==1.0 --hash=sha256:{HASH} --find-links=${{TOKEN}}\n",
        f"tinydemo==$TOKEN --hash=sha256:{HASH}\n",
        f"tinydemo @ https://example.invalid/tinydemo-1.0-py3-none-any.whl --hash=sha256:{HASH}\n",
        f"tinydemo@https://example.invalid/t.whl --hash=sha256:{HASH}\n",
        f"https://example.invalid/tinydemo-1.0-py3-none-any.whl --hash=sha256:{HASH}\n",
        f"tinydemo[extra]==1.0 --hash=sha256:{HASH}\n",
        f'tinydemo==1.0; python_version > "3" --hash=sha256:{HASH}\n',
        f"tinydemo==1.0 --hash=sha256:{HASH} --no-binary :all:\n",
        f"tinydemo==1.0 --hash=sha256:{HASH}\r\n",
        f"tinydemo==1.0 \\ \n    --hash=sha256:{HASH}\n",
        f"  tinydemo==1.0 --hash=sha256:{HASH}\n",
        f"tinydemo>=1.0 --hash=sha256:{HASH}\n",
    ],
)
def test_hostile_lockfiles_are_refused_before_anything_is_built(tmp_path: Path, wheels: Path, text: str) -> None:
    bad = tmp_path / "hostile.txt"
    bad.write_bytes(text.encode())
    done = cli(*build_args(bad, tmp_path / "root", wheels))
    assert done.returncode == 2, (done.returncode, done.stderr)
    assert done.stdout == ""
    assert (
        not (tmp_path / "root").exists() or [p.name for p in (tmp_path / "root").iterdir() if p.name != ".lock"] == []
    )


def test_accepts_the_strict_form_with_comments_and_several_hashes() -> None:
    good = (
        f"# header\n\ntinydemo==1.0 \\\n    --hash=sha256:{HASH} \\\n    --hash=sha256:{'b' * 64}\n"
        f"other_pkg==2.1.post1+x --hash=sha256:{HASH}\n"
    )
    assert sharedvenv.check_hashes(good.encode()) == 2


def test_lockfile_swapped_after_the_check_is_not_what_pip_installs(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    log = tmp_path / "creates.log"
    wrapper = tmp_path / "py.sh"
    wrapper.write_text(f'#!/bin/sh\necho x >> {log}\nsleep 2\nexec {sys.executable} "$@"\n')
    wrapper.chmod(0o755)
    original = lock.read_bytes()
    cmd = [sys.executable, "-m", "safo.sharedvenv", *map(str, build_args(lock, root, wheels)), "--python", str(wrapper)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=ENV)  # noqa: S603 - fixed argv in a test helper, no shell
    for _ in range(200):  # the check has passed once the build has started
        if log.exists():
            break
        time.sleep(0.05)
    assert log.exists()
    lock.write_text(f"tinydemo==1.0 --hash=sha256:{'0' * 64}\n")  # a real swap, in place, after the check
    out, err = proc.communicate(timeout=300)
    assert proc.returncode == 0, err
    assert Path(out.strip()).parent.parent.name == hashlib.sha256(original).hexdigest()
    done = subprocess.run([out.strip(), "-c", "import tinydemo"], capture_output=True, text=True)  # noqa: S603 - fixed argv in a test helper, no shell
    assert done.returncode == 0, done.stderr
    assert [p.name for p in root.iterdir() if p.name.startswith(".")] == [".lock"]  # private copy and home removed


def test_pip_never_receives_the_callers_lockfile_path(tmp_path: Path, wheels: Path, lock: Path) -> None:
    seen = tmp_path / "argv.log"
    shim = tmp_path / "pipshim.sh"
    shim.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" >> {seen}\nexec {sys.executable} "$@"\n')
    shim.chmod(0o755)
    # the shim only sees the venv step; the pip step is covered by the swap test, this one checks the venv step is clean
    done = cli(*build_args(lock, tmp_path / "root", wheels), "--python", shim)
    assert done.returncode == 0, done.stderr
    assert str(lock) not in seen.read_text()


def test_rehash_of_the_copy_actually_used_must_match_the_key(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    with pytest.raises(sharedvenv.Refused):
        sharedvenv.build(root, "f" * 64, lock.read_bytes(), sys.executable, ["--no-index", "--find-links", str(wheels)])
    assert [p.name for p in root.iterdir()] == []


def test_child_environment_is_an_allowlist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("TOKEN", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "HOME"):
        monkeypatch.setenv(name, "secret-value")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = sharedvenv._clean_env(tmp_path)
    assert "secret-value" not in env.values()
    assert env["HOME"] == str(tmp_path) and env["PATH"] == "/usr/bin"
    assert set(env) <= {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "PIP_NO_INPUT",
        "PIP_DISABLE_PIP_VERSION_CHECK",
        "PIP_REQUIRE_VIRTUALENV",
    }


def test_secret_in_caller_environment_does_not_reach_the_children(tmp_path: Path, wheels: Path, lock: Path) -> None:
    dump = tmp_path / "env.log"
    shim = tmp_path / "envshim.sh"
    shim.write_text(f'#!/bin/sh\nenv >> {dump}\nexec {sys.executable} "$@"\n')
    shim.chmod(0o755)
    done = cli(*build_args(lock, tmp_path / "root", wheels), "--python", shim, env={"TOKEN": "s3cr3t-xyz"})
    assert done.returncode == 0, done.stderr
    text = dump.read_text()
    assert "s3cr3t-xyz" not in text and "TOKEN" not in text
    assert f"HOME={os.environ.get('HOME', '')}\n" not in text
