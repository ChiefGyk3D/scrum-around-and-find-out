# SPDX-License-Identifier: Apache-2.0
"""#534: the shared read-only hash-locked venv. Real subprocesses, a tiny local wheel, no network."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import math
import os
import re
import shutil
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


def venv_of(done: subprocess.CompletedProcess[str]) -> Path:
    assert done.returncode == 0, done.stderr
    return Path(done.stdout.strip()).parent.parent


def shim(path: Path, body: str) -> Path:
    """An interpreter stand-in: runs `body` (sh), then the real interpreter. `$VENV_STEP` is 1 for `-m venv`."""
    path.write_text(
        f'#!/bin/sh\nVENV_STEP=0\ncase "$*" in *"-m venv"*) VENV_STEP=1;; esac\n{body}\nexec {sys.executable} "$@"\n'
    )
    path.chmod(0o755)
    return path


def build_args(lock: Path, root: Path, wheels: Path) -> list[object]:
    return [lock, "--root", root, "--no-index", "--find-links", wheels]


def test_builds_keyed_venv_installs_pinned_wheel_prints_interpreter(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    done = cli(*build_args(lock, root, wheels))
    assert done.returncode == 0, done.stderr
    python = Path(done.stdout.strip())
    venv = venv_of(done)
    assert python == venv / "bin" / "python" and venv.parent == root
    out = subprocess.run(  # noqa: S603 - fixed argv in a test helper, no shell
        [python, "-c", "import tinydemo;print(tinydemo.VALUE)"], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "534"
    cfg = (venv / "pyvenv.cfg").read_text().lower()
    assert "include-system-site-packages = false" in cfg


def test_venv_is_read_only_and_reuse_does_not_rebuild(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    first = cli(*build_args(lock, root, wheels))
    venv = venv_of(first)
    writable = [p for p in venv.rglob("*") if not p.is_symlink() and p.stat().st_mode & 0o222]
    assert writable == []
    assert not venv.stat().st_mode & 0o222
    inode = venv.stat().st_ino
    second = cli(*build_args(lock, root, wheels))  # a rebuild would give the entry a new inode
    assert (second.returncode, second.stdout) == (0, first.stdout)
    assert venv.stat().st_ino == inode
    with pytest.raises(PermissionError):
        (venv / "lib" / "evil.txt").write_text("x")


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
    (root / venv_of(cli(*build_args(lock, tmp_path / "other", wheels))).name).symlink_to(real)
    done = cli(*build_args(lock, root, wheels))
    assert done.returncode == 2 and "symbolic link" in done.stderr


def test_refuses_root_writable_by_others(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    root.chmod(0o777)
    assert cli(*build_args(lock, root, wheels)).returncode == 2


def test_refuses_venv_with_system_site_packages(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    cfg = venv_of(cli(*build_args(lock, root, wheels))) / "pyvenv.cfg"
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
    wrapper = shim(tmp_path / "py.sh", f'[ "$VENV_STEP" = 1 ] && {{ echo x >> {log}; sleep 1; }}')
    cmd = [sys.executable, "-m", "safo.sharedvenv", *map(str, build_args(lock, root, wheels)), "--python", str(wrapper)]
    procs = [
        subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=ENV)  # noqa: S603 - fixed argv in a test helper, no shell
        for _ in range(2)
    ]
    results = [(*p.communicate(timeout=300), p.returncode) for p in procs]
    assert [r[2] for r in results] == [0, 0], results
    assert results[0][0] == results[1][0] != ""
    assert log.read_text().count("x") == 1
    assert [p.name for p in root.iterdir() if p.name.startswith(".build-")] == []


def test_gc_lists_then_deletes_only_old(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    old_key = venv_of(cli(*build_args(lock, root, wheels))).name
    other = make_wheel(wheels, version="2.0")
    new_key = venv_of(cli(*build_args(lock_for(other, tmp_path, "req2.txt"), root, wheels))).name
    long_ago = time.time() - 40 * 86400
    for path in (root / old_key, root / f"{old_key}.used"):
        os.utime(path, (long_ago, long_ago))
    listing = cli("--gc", "--max-age-days", 30, "--root", root)
    assert listing.returncode == 0 and f"would delete {old_key} " in listing.stdout and new_key not in listing.stdout
    assert (root / old_key).exists()
    done = cli("--gc", "--max-age-days", 30, "--delete", "--root", root)
    assert done.returncode == 0 and f"deleted {old_key} " in done.stdout
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
    wrapper = shim(tmp_path / "py.sh", f'[ "$VENV_STEP" = 1 ] && {{ echo x >> {log}; sleep 2; }}')
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
    args = ["--no-index", "--find-links", str(wheels)]
    with pytest.raises(sharedvenv.Refused):
        sharedvenv.build(root, "a" * 64, lock.read_bytes(), sys.executable, args, expected_sha="f" * 64)
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
        "PIP_CONFIG_FILE",
    }


def test_secret_in_caller_environment_does_not_reach_the_children(tmp_path: Path, wheels: Path, lock: Path) -> None:
    dump = tmp_path / "env.log"
    envshim = shim(tmp_path / "envshim.sh", f"env >> {dump}")
    done = cli(*build_args(lock, tmp_path / "root", wheels), "--python", envshim, env={"TOKEN": "s3cr3t-xyz"})
    assert done.returncode == 0, done.stderr
    text = dump.read_text()
    assert "s3cr3t-xyz" not in text and "TOKEN" not in text
    assert f"HOME={os.environ.get('HOME', '')}\n" not in text


def build_in(tmp_path: Path, wheels: Path, lock: Path, name: str = "root") -> tuple[Path, Path]:
    root = tmp_path / name
    return root, venv_of(cli(*build_args(lock, root, wheels)))


def test_fake_entry_with_a_self_written_marker_is_refused(tmp_path: Path, wheels: Path, lock: Path) -> None:
    _, real = build_in(tmp_path, wheels, lock, "donor")
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    fake = root / real.name
    (fake / "bin").mkdir(parents=True)
    (fake / "bin" / "python").symlink_to(sys.executable)
    (fake / "pyvenv.cfg").write_text("include-system-site-packages = false\n")
    (fake / sharedvenv.MARKER).write_text(real.name + "\n")
    done = cli(*build_args(lock, root, wheels))
    assert done.returncode == 2 and done.stdout == "", done.stderr


def test_entry_changed_after_the_build_is_refused(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root, venv = build_in(tmp_path, wheels, lock)
    venv.chmod(0o755)
    (venv / "extra.txt").write_text("x")
    (venv / "extra.txt").chmod(0o444)
    venv.chmod(0o555)
    done = cli(*build_args(lock, root, wheels))
    assert done.returncode == 2 and "manifest" in done.stderr


def test_group_writable_entry_is_refused(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root, venv = build_in(tmp_path, wheels, lock)
    venv.chmod(0o575)
    done = cli(*build_args(lock, root, wheels))
    assert done.returncode == 2 and "writable" in done.stderr


def test_entry_owned_by_another_account_is_refused(
    tmp_path: Path, wheels: Path, lock: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, venv = build_in(tmp_path, wheels, lock)
    sharedvenv.valid(venv, venv.name)
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(sharedvenv.Refused, match="owned"):
        sharedvenv.valid(venv, venv.name)


def test_requirement_copy_replaced_by_path_during_the_build_is_not_what_pip_reads(
    tmp_path: Path, wheels: Path, lock: Path
) -> None:
    modes = tmp_path / "modes.log"
    zeros = "0" * 64
    body = "\n".join(
        [
            'if [ "$VENV_STEP" = 1 ]; then',
            f'  stat -c "%a %n" "$HOME/.." >> {modes}',
            '  for f in "$HOME"/../.req-* "$HOME"/../req.txt; do',
            f'    if [ -e "$f" ]; then rm -f "$f"; echo "tinydemo==1.0 --hash=sha256:{zeros}" > "$f"; fi',
            "  done",
            "fi",
        ]
    )
    swapper = shim(tmp_path / "swap.sh", body)
    root = tmp_path / "root"
    done = cli(*build_args(lock, root, wheels), "--python", swapper)
    assert done.returncode == 0, done.stderr
    mode, name = modes.read_text().split()[:2]
    assert mode == "700" and Path(os.path.normpath(name)).name.startswith(".build-")
    assert subprocess.run([venv_of(done) / "bin" / "python", "-c", "import tinydemo"]).returncode == 0  # noqa: S603 - fixed argv in a test helper, no shell


def test_key_covers_the_interpreter_and_the_acquisition_policy(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root, first = build_in(tmp_path, wheels, lock)
    assert first.name != hashlib.sha256(lock.read_bytes()).hexdigest()
    other_py = shim(tmp_path / "other-python.sh", "true")
    second = venv_of(cli(*build_args(lock, root, wheels), "--python", other_py))
    assert second != first
    copy = tmp_path / "wheels2"
    copy.mkdir()
    (copy / next(wheels.glob("*.whl")).name).write_bytes(next(wheels.glob("*.whl")).read_bytes())
    third = venv_of(cli(*build_args(lock, root, copy)))
    assert len({first, second, third}) == 3


def test_missing_interpreter_fails_and_builds_nothing(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    done = cli(*build_args(lock, root, wheels), "--python", "/does/not/exist")
    assert done.returncode == 2 and done.stdout == ""
    assert not root.exists() or [p.name for p in root.iterdir() if p.name != ".lock"] == []


def test_lock_file_replaced_while_waiting_is_not_the_lock_we_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    calls: list[int] = []
    real = sharedvenv._after_flock

    def replace_once(path: Path) -> None:
        calls.append(1)
        if len(calls) == 1:
            path.unlink()
            path.write_text("")
        real(path)

    monkeypatch.setattr(sharedvenv, "_after_flock", replace_once)
    with sharedvenv.Lock(root, 5) as held:
        assert os.fstat(held.fd).st_ino == (root / ".lock").stat().st_ino
        other = os.open(root / ".lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(other)
    assert len(calls) == 2


def test_gc_skips_entries_this_tool_did_not_build(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root, venv = build_in(tmp_path, wheels, lock)
    foreign = root / ("c" * 64)
    foreign.mkdir()
    (foreign / "precious.txt").write_text("keep")
    long_ago = time.time() - 90 * 86400
    for path in (foreign, venv, root / f"{venv.name}.used"):
        os.utime(path, (long_ago, long_ago))
    done = cli("--gc", "--max-age-days", 30, "--delete", "--root", root)
    assert done.returncode == 0 and "skipped" in done.stdout and foreign.name in done.stdout
    assert (foreign / "precious.txt").read_text() == "keep"
    assert not venv.exists()  # the valid old one is deleted


def test_stale_cleanup_removes_only_this_tools_build_directories(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    ours = root / ".build-Ab3dEf9h"
    ours.mkdir(mode=0o700)
    (ours / sharedvenv.BUILD_MARK).write_text(sharedvenv.BUILD_MARK_TEXT)
    for name in (".build-NoMark12", ".tmp-keep", ".home-keep", "notes"):
        (root / name).mkdir()
        (root / name / "f").write_text("keep")
    assert cli(*build_args(lock, root, wheels)).returncode == 0
    assert not ours.exists()
    assert all((root / n / "f").exists() for n in (".build-NoMark12", ".tmp-keep", ".home-keep", "notes"))


def test_pip_configuration_files_are_ignored(tmp_path: Path, wheels: Path, lock: Path) -> None:
    target = tmp_path / "elsewhere"
    conf = f"[install]\\ntarget = {target}\\n"
    body = "\n".join(
        [
            'if [ "$VENV_STEP" = 1 ]; then',
            "  for a; do last=$a; done",
            '  mkdir -p "$HOME/.config/pip" "$HOME/.pip"',
            '  for f in "$HOME/.config/pip/pip.conf" "$HOME/.pip/pip.conf" "$HOME/pip.conf"; do',
            f'    printf "{conf}" > "$f"',
            "  done",
            f'  "{sys.executable}" "$@" || exit 1',
            f'  printf "{conf}" > "$last/pip.conf"; exit 0',
            "fi",
        ]
    )
    conf_shim = shim(tmp_path / "conf.sh", body)
    done = cli(*build_args(lock, tmp_path / "root", wheels), "--python", conf_shim)
    assert done.returncode == 0, done.stderr
    assert subprocess.run([venv_of(done) / "bin" / "python", "-c", "import tinydemo"]).returncode == 0  # noqa: S603 - fixed argv in a test helper, no shell
    assert not target.exists()


def test_use_stamp_must_be_a_plain_single_link_file(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root, venv = build_in(tmp_path, wheels, lock)
    stamp = root / f"{venv.name}.used"
    assert stamp.is_file()
    stamp.unlink()
    victim = tmp_path / "victim.txt"
    victim.write_text("v")
    os.link(victim, stamp)
    done = cli(*build_args(lock, root, wheels))
    assert done.returncode == 2 and "stamp" in done.stderr
    stamp.unlink()
    stamp.symlink_to(victim)
    assert cli(*build_args(lock, root, wheels)).returncode == 2
    assert victim.read_text() == "v"


def test_ancestor_writable_by_others_or_a_symlink_is_refused(tmp_path: Path, wheels: Path, lock: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    done = cli(*build_args(lock, shared / "root", wheels))
    assert done.returncode == 2 and "writable" in done.stderr and not (shared / "root").exists()
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    (tmp_path / "link").symlink_to(real)
    done = cli(*build_args(lock, tmp_path / "link" / "root", wheels))
    assert done.returncode == 2 and "symbolic link" in done.stderr and not (real / "root").exists()


def test_only_a_root_owned_sticky_directory_like_tmp_is_an_allowed_writable_ancestor(
    tmp_path: Path, wheels: Path, lock: Path
) -> None:
    sticky = tmp_path / "sticky"
    sticky.mkdir()
    sticky.chmod(0o1777)  # owned by this user, not root: refused (every test also runs under the root-owned /tmp)
    done = cli(*build_args(lock, sticky / "root", wheels))
    assert done.returncode == 2 and "writable" in done.stderr


def test_root_replaced_after_validation_is_detected(tmp_path: Path) -> None:
    root = tmp_path / "root"
    handle = sharedvenv.open_root(root)
    handle.check()
    root.rename(tmp_path / "moved")
    root.mkdir(mode=0o700)
    with pytest.raises(sharedvenv.Refused, match="replaced"):
        handle.check()
    handle.close()


def test_interpreter_changed_after_the_identity_query_is_refused(
    tmp_path: Path, wheels: Path, lock: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    py = shim(tmp_path / "py.sh", "true")
    args = ["--no-index", "--find-links", str(wheels)]

    def tamper(path: Path) -> None:
        py.write_text(py.read_text() + "# changed\n")

    monkeypatch.setattr(sharedvenv, "_after_flock", tamper)
    with pytest.raises(sharedvenv.Refused, match="changed"):
        sharedvenv.ensure(tmp_path / "root", lock, str(py), args, 5)
    assert not any(p.name[0] != "." for p in (tmp_path / "root").iterdir())


def test_interpreter_content_is_part_of_the_key(tmp_path: Path, wheels: Path, lock: Path) -> None:
    py = shim(tmp_path / "py.sh", "true")
    root = tmp_path / "root"
    first = venv_of(cli(*build_args(lock, root, wheels), "--python", py))
    py.write_text(py.read_text() + "# upgraded\n")
    assert venv_of(cli(*build_args(lock, root, wheels), "--python", py)) != first


@pytest.mark.parametrize("age", ["nan", "inf", "-inf", "-1", "1e9", "abc"])
def test_gc_with_a_non_finite_or_absurd_age_deletes_nothing(tmp_path: Path, wheels: Path, lock: Path, age: str) -> None:
    root, venv = build_in(tmp_path, wheels, lock)
    long_ago = time.time() - 400 * 86400
    for path in (venv, root / f"{venv.name}.used"):
        os.utime(path, (long_ago, long_ago))
    done = cli("--gc", "--max-age-days", age, "--delete", "--root", root)
    assert done.returncode == 2 and "deleted" not in done.stdout
    assert venv.exists()


def test_gc_function_refuses_nan_even_when_called_directly(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root, venv = build_in(tmp_path, wheels, lock)
    long_ago = time.time() - 400 * 86400
    for path in (venv, root / f"{venv.name}.used"):
        os.utime(path, (long_ago, long_ago))
    with pytest.raises(sharedvenv.Refused):
        sharedvenv.gc(root, float("nan"), True, 5)
    assert venv.exists()


def test_lock_timeout_must_be_finite(tmp_path: Path, wheels: Path, lock: Path) -> None:
    assert cli(*build_args(lock, tmp_path / "root", wheels), "--lock-timeout", "nan").returncode == 2


def test_writable_member_or_marker_fails_reuse_validation(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root, venv = build_in(tmp_path, wheels, lock)
    marker = venv / sharedvenv.MARKER
    marker.chmod(0o644)
    done = cli(*build_args(lock, root, wheels))
    assert done.returncode == 2 and "writable" in done.stderr


# ---- round 4: structural fixes ----


def test_interpreter_file_writable_by_others_is_refused(tmp_path: Path, wheels: Path, lock: Path) -> None:
    py = shim(tmp_path / "py.sh", "true")
    py.chmod(0o775)
    done = cli(*build_args(lock, tmp_path / "root", wheels), "--python", py)
    assert done.returncode == 2 and "writable" in done.stderr


def test_interpreter_in_a_directory_writable_by_others_is_refused(tmp_path: Path, wheels: Path, lock: Path) -> None:
    open_dir = tmp_path / "open"
    open_dir.mkdir()
    py = shim(open_dir / "py.sh", "true")
    open_dir.chmod(0o777)
    done = cli(*build_args(lock, tmp_path / "root", wheels), "--python", py)
    assert done.returncode == 2 and "writable" in done.stderr


def test_only_the_resolved_interpreter_path_is_executed(tmp_path: Path, wheels: Path, lock: Path) -> None:
    log = tmp_path / "argv0.log"
    real_shim = shim(tmp_path / "real.sh", f'echo "$0" >> {log}')
    link = tmp_path / "link-python"
    link.symlink_to(real_shim)
    done = cli(*build_args(lock, tmp_path / "root", wheels), "--python", link)
    assert done.returncode == 0, done.stderr
    ran = set(log.read_text().split())
    assert ran == {str(real_shim.resolve())}


def test_reuse_branch_refuses_an_interpreter_swapped_after_the_key(
    tmp_path: Path, wheels: Path, lock: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    py = shim(tmp_path / "py.sh", "true")
    root = tmp_path / "root"
    first = venv_of(cli(*build_args(lock, root, wheels), "--python", py))
    args = ["--no-index", "--find-links", str(wheels)]
    monkeypatch.setattr(sharedvenv, "_after_flock", lambda path: py.write_text(py.read_text() + "# swapped\n"))
    with pytest.raises(sharedvenv.Refused, match="changed"):
        sharedvenv.ensure(root, lock, str(py), args, 5)
    assert first.exists()


def test_reuse_refuses_a_venv_whose_python_no_longer_points_at_the_recorded_base(
    tmp_path: Path, wheels: Path, lock: Path
) -> None:
    root, venv = build_in(tmp_path, wheels, lock)
    other = shutil.which("true")
    assert other
    (venv / "bin").chmod(0o755)
    (venv / "bin" / "python").unlink()
    (venv / "bin" / "python").symlink_to(other)
    (venv / "bin").chmod(0o555)
    done = cli(*build_args(lock, root, wheels))
    assert done.returncode == 2 and done.stdout == ""


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1.0, 1e12])
def test_numeric_parameters_are_validated_at_the_function_boundary(
    tmp_path: Path, wheels: Path, lock: Path, bad: float
) -> None:
    root = tmp_path / "root"
    args = ["--no-index", "--find-links", str(wheels)]
    with pytest.raises(sharedvenv.Refused):
        sharedvenv.ensure(root, lock, sys.executable, args, bad)
    with pytest.raises(sharedvenv.Refused):
        sharedvenv.gc(root, 30, True, bad)
    with pytest.raises(sharedvenv.Refused):
        sharedvenv.Lock(root, bad)
    if not math.isfinite(bad):
        with pytest.raises(sharedvenv.Refused):
            sharedvenv.gc(root, 30, False, 5, now=bad)
    assert not root.exists()


def test_pip_arguments_outside_the_allowed_grammar_are_refused(tmp_path: Path, lock: Path) -> None:
    for args in (
        ["--extra-index-url", "https://example.invalid"],
        ["--index-url=https://u:tok3n@h/x"],
        ["--trusted-host", "h"],
    ):
        with pytest.raises(sharedvenv.Refused):
            sharedvenv.ensure(tmp_path / "root", lock, sys.executable, args, 5)


def test_missing_root_components_are_created_one_at_a_time_private(tmp_path: Path) -> None:
    root = tmp_path / "a" / "b" / "root"
    sharedvenv.open_root(root).close()
    for part in (tmp_path / "a", tmp_path / "a" / "b", root):
        assert part.stat().st_mode & 0o777 == 0o700


def test_a_root_component_swapped_for_a_symlink_right_after_creation_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = tmp_path / "elsewhere"
    real.mkdir(mode=0o700)
    root = tmp_path / "a" / "root"

    def swap(created: Path) -> None:
        if created == tmp_path / "a":
            created.rmdir()
            created.symlink_to(real)

    monkeypatch.setattr(sharedvenv, "_after_mkdir", swap)
    with pytest.raises(sharedvenv.Refused):
        sharedvenv.open_root(root)
    assert not (real / "root").exists()


def test_ancestor_made_writable_while_the_root_is_created_is_caught_before_returning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "parent"
    root = parent / "root"

    def open_up(created: Path) -> None:
        if created == root:
            parent.chmod(0o777)

    monkeypatch.setattr(sharedvenv, "_after_mkdir", open_up)
    with pytest.raises(sharedvenv.Refused, match="writable"):
        sharedvenv.open_root(root)


# ---- round 5: fail closed ----


# ---- round 6: whitelist grammar for index and links values ----

VALID_SOURCES = [
    "https://example.invalid/simple",
    "https://example.invalid:8443/simple/",
    "https://127.0.0.1/",
    "https://127.0.0.1:65535/a",
    "https://pypi.example/simple/a+b/c_d~e",
    "https://a.b-c.example/",
    "https://xn--bcher-kva.example/x",
    "/tmp/wheels",
    "/home/u/my-wheels_1.0+x",
    "/",
]

HOSTILE_SOURCES = [
    # userinfo and credentials
    "https://user:tok3n@example.invalid/simple",
    "https://tok3n@example.invalid/",
    "https://example.invalid@evil.invalid/x",
    "https://:@example.invalid/",
    "user:tok3n@example.invalid/simple",
    "tok3n@example.invalid:wheels",
    # at sign in a path
    "https://example.invalid/a@b",
    "/tmp/a@b",
    # query and fragment
    "https://example.invalid/simple?token=tok3n",
    "https://example.invalid/?",
    "/tmp/w?x=1",
    "https://example.invalid/simple#tok3n",
    "/tmp/w#x",
    # whitespace and control characters
    "https://example.invalid/a\tb",
    "https://example.invalid/a\nb",
    "https://example.invalid/a b",
    " https://example.invalid/",
    "https://example.invalid/ ",
    "https://example.invalid/a" + chr(0),
    "https://example.invalid/a" + chr(127),
    # backslash
    "https://example.invalid\\@evil.invalid/x",
    "https://example.invalid/a\\b",
    "/tmp/a\\b",
    # percent-encoding
    "https://example.invalid/a%2Fb",
    "https://example.invalid/%40",
    "https://exa%6Dple.invalid/",
    "https://example.invalid%2f@x/",
    "/tmp/a%20b",
    # non-ASCII and IDNA
    "https://bücher.example/x",
    "https://example.invalid/xé",
    "https://☃.example/",
    # IPv6 and zone ids
    "https://[::1]/simple",
    "https://[2001:db8::1]:8443/x",
    "https://[fe80::1%25eth0]/x",
    "https://[fe80::1%eth0]/",
    # scp-like, bare and relative
    "git@example.invalid:wheels",
    "example.invalid:/wheels",
    "relative/dir",
    "./w",
    "~/w",
    "../w",
    "",
    # scheme without a host, other schemes
    "https:token",
    "https:/example.invalid/x",
    "https:example.invalid/x",
    "file:///tmp/wheels",
    "file:/tmp/w",
    "https:",
    "https://",
    "https:///x",
    "https://example.invalid",
    "http://example.invalid/simple",
    "ftp://example.invalid/",
    "ssh://example.invalid/x",
    # case
    "HTTPS://example.invalid/simple",
    "Https://example.invalid/",
    "https://Example.invalid/simple",
    # trailing and leading dots
    "https://example.invalid./simple",
    "https://example.invalid../x",
    "https://.example.invalid/",
    # dot segments and double slashes
    "https://example.invalid/../x",
    "https://example.invalid/a/../b",
    "/tmp/../etc",
    "/tmp/a/..",
    "https://example.invalid//x",
    "//tmp/w",
    # ports
    "https://example.invalid:0/x",
    "https://example.invalid:99999/x",
    "https://example.invalid:/x",
    "https://example.invalid:80a/x",
    # host shapes
    "https://-bad.example/",
    "https://bad-.example/",
    "https://under_score.example/",
    "https://exa mple/",
    # colon in a local path, length
    "/tmp/a:b",
    "https://example.invalid/" + "a" * 2000,
    "/" + "a" * 2000,
    "https://" + "a" * 64 + ".example/",
    "https://" + ".".join(["a" * 50] * 6) + "/",
]


FIXED_REFUSAL = "an index or links value must be https://HOST[:PORT]/PATH or an absolute local directory path"


def test_the_hostile_table_is_large_enough() -> None:
    assert len(HOSTILE_SOURCES) >= 40 and len(set(HOSTILE_SOURCES)) == len(HOSTILE_SOURCES)


@pytest.mark.parametrize("value", VALID_SOURCES)
def test_the_two_valid_forms_are_accepted(value: str) -> None:
    for flag in ("--index-url", "--find-links"):
        assert sharedvenv.parse_pip_args([flag, value]) == [value]


@pytest.mark.parametrize("value", HOSTILE_SOURCES, ids=lambda v: repr(v)[:50])
def test_every_hostile_or_odd_value_is_refused_without_being_echoed(value: str) -> None:
    for flag in ("--index-url", "--find-links"):
        with pytest.raises(sharedvenv.Refused) as caught:
            sharedvenv.parse_pip_args([flag, value])
        assert str(caught.value) == FIXED_REFUSAL  # one fixed text: the value is never echoed


def test_command_line_refuses_odd_values_and_has_no_credentials_flag(tmp_path: Path, lock: Path) -> None:
    for value in ("https://user:tok3n@example.invalid/s", "file:///tmp/wheels", "/tmp/w?token=tok3n", "HTTPS://h/x"):
        for flag in ("--index-url", "--find-links"):
            done = cli(lock, "--root", tmp_path / "root", flag, value)
            assert done.returncode == 2 and "tok3n" not in done.stdout + done.stderr
    done = cli(lock, "--root", tmp_path / "root", "--index-url", "https://example.invalid/s", "--allow-url-credentials")
    assert done.returncode == 2  # the option no longer exists (argparse usage error)


def test_ensure_refuses_odd_values_for_direct_callers(tmp_path: Path, lock: Path) -> None:
    with pytest.raises(sharedvenv.Refused):
        sharedvenv.ensure(tmp_path / "root", lock, sys.executable, ["--index-url", "https://u:tok3n@h/x"], 5)
    assert not (tmp_path / "root").exists()


@pytest.mark.parametrize("args", [["--extra-index-url"], ["--trusted-host"], ["--index-url"], ["--no-binary"], ["-i"]])
def test_a_bare_unknown_or_incomplete_pip_argument_is_refused(args: list[str]) -> None:
    with pytest.raises(sharedvenv.Refused):
        sharedvenv.parse_pip_args(args)


# ---- round 7: never relay pip's raw output ----

PLANTED = ("PLANTED-REDIRECT-pw", "PLANTED-SCP-user", "PLANTED-MULTILINE-cred", "PLANTED-BARE-token")

FAKE_PIP = """\
import sys
a = "PLANTED-"
sys.stdout.write("Location: user:" + a + "REDIRECT-pw@example.invalid/simple/pkg\\n")
sys.stderr.write("WARNING: retry via " + a + "SCP-user@example.invalid:wheels/pkg\\n")
sys.stderr.write("Authorization: Basic\\n  " + a + "MULTILINE-cred\\n")
sys.stderr.write("ERROR: bad token " + a + "BARE-token done\\n")
st = int(open(__file__ + ".status").read())
sys.stdout.flush()
sys.stderr.flush()
if st < 0:
    import time

    time.sleep(60)
sys.exit(st)
"""


def fake_pip_shim(tmp_path: Path, status: int) -> Path:
    """An interpreter stand-in whose venvs get a fake `pip` that prints planted secrets and exits with `status`."""
    payload = tmp_path / "fake_pip_main.py"
    payload.write_text(FAKE_PIP)
    body = "\n".join(
        [
            'if [ "$VENV_STEP" = 1 ]; then',
            "  for a; do last=$a; done",
            f'  "{sys.executable}" "$@" || exit 1',
            '  for d in "$last"/lib/python*/site-packages/pip; do',
            f'    cp {payload} "$d/__main__.py"; printf "{status}" > "$d/__main__.py.status"',
            "  done",
            "  exit 0",
            "fi",
        ]
    )
    return shim(tmp_path / f"fakepip{status}.sh", body)


def no_planted(*texts: str) -> None:
    for text in texts:
        for needle in PLANTED:
            assert needle not in text, needle


def test_pip_failure_prints_only_a_fixed_message(tmp_path: Path, wheels: Path, lock: Path) -> None:
    done = cli(*build_args(lock, tmp_path / "root", wheels), "--python", fake_pip_shim(tmp_path, 1))
    assert done.returncode == 1 and done.stdout == ""
    no_planted(done.stdout, done.stderr)
    assert "pip exited with status 1" in done.stderr and "install step" in done.stderr
    assert not list((tmp_path / "root").glob("pip-*.log"))  # off by default: discarded


def test_pip_success_prints_nothing_from_pip_and_the_entry_holds_none_of_it(
    tmp_path: Path, wheels: Path, lock: Path
) -> None:
    root = tmp_path / "root"
    done = cli(*build_args(lock, root, wheels), "--python", fake_pip_shim(tmp_path, 0))
    assert done.returncode == 0, done.stderr
    assert len(done.stdout.split()) == 1 and done.stderr == ""
    no_planted(done.stdout, done.stderr)
    venv = venv_of(done)
    no_planted((venv / sharedvenv.MARKER).read_text())


def test_the_in_process_build_error_carries_none_of_pip_output(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    args = ["--no-index", "--find-links", str(wheels)]
    with pytest.raises(sharedvenv.Failed) as caught:
        sharedvenv.build(root, "e" * 64, lock.read_bytes(), str(fake_pip_shim(tmp_path, 1)), args)
    no_planted(str(caught.value), repr(caught.value), repr(caught.value.__cause__))


def test_keep_pip_log_writes_a_private_file_and_still_prints_none_of_it(
    tmp_path: Path, wheels: Path, lock: Path
) -> None:
    root = tmp_path / "root"
    done = cli(*build_args(lock, root, wheels), "--python", fake_pip_shim(tmp_path, 1), "--keep-pip-log")
    assert done.returncode == 1
    no_planted(done.stdout, done.stderr)
    logs = list(root.glob("pip-*.log"))
    assert len(logs) == 1
    assert logs[0].stat().st_mode & 0o777 == 0o600
    assert re.fullmatch(r"pip-[0-9a-f]{12}-[0-9a-f]{8}\.log", logs[0].name)
    assert "PLANTED-MULTILINE-cred" in logs[0].read_text()
    assert logs[0].name in done.stderr and str(logs[0]) not in done.stderr and "may contain credentials" in done.stderr


def test_output_of_the_venv_step_is_not_relayed_either(tmp_path: Path, wheels: Path, lock: Path) -> None:
    noisy = shim(
        tmp_path / "noisy.sh",
        'if [ "$VENV_STEP" = 1 ]; then echo "Location: user:PLANTED-REDIRECT-pw@h/p"; '
        'echo "PLANTED-BARE-token" >&2; fi',
    )
    done = cli(*build_args(lock, tmp_path / "root", wheels), "--python", noisy)
    assert done.returncode == 0, done.stderr
    no_planted(done.stdout, done.stderr)
    assert len(done.stdout.split()) == 1


# ---- round 8: no output-bearing exception chains, fixed argparse errors, seal before publish ----


def walk_chain(exc: BaseException) -> list[BaseException]:
    seen: list[BaseException] = []
    todo: list[BaseException | None] = [exc]
    while todo:
        item = todo.pop()
        if item is None or item in seen:
            continue
        seen.append(item)
        todo += [item.__cause__, item.__context__]
    return seen


def assert_no_output_in_chain(exc: BaseException) -> None:
    assert exc.__cause__ is None and exc.__context__ is None, (exc.__cause__, exc.__context__)
    for item in walk_chain(exc):
        no_planted(str(item), repr(item), repr(getattr(item, "args", "")))
        for attribute in ("stdout", "stderr", "output", "cmd"):
            assert not getattr(item, attribute, None), attribute


NOISY_FAIL = (
    'if [ "$VENV_STEP" = 1 ]; then echo "Location: user:PLANTED-REDIRECT-pw@h/p"; '
    'echo "PLANTED-BARE-token" >&2; {tail}; fi'
)


def test_a_failing_venv_step_raises_an_error_with_no_chain_and_no_output(
    tmp_path: Path, wheels: Path, lock: Path
) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    bad = shim(tmp_path / "bad.sh", NOISY_FAIL.format(tail="exit 1"))
    with pytest.raises(sharedvenv.Failed) as caught:
        sharedvenv.build(root, "a" * 64, lock.read_bytes(), str(bad), ["--no-index", "--find-links", str(wheels)])
    assert_no_output_in_chain(caught.value)


def test_a_timed_out_venv_step_raises_an_error_with_no_chain_and_no_output(
    tmp_path: Path, wheels: Path, lock: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    slow = shim(tmp_path / "slow.sh", NOISY_FAIL.format(tail="exec sleep 30"))
    monkeypatch.setattr(sharedvenv, "VENV_TIMEOUT", 1)
    with pytest.raises(sharedvenv.Failed) as caught:
        sharedvenv.build(root, "a" * 64, lock.read_bytes(), str(slow), ["--no-index", "--find-links", str(wheels)])
    assert_no_output_in_chain(caught.value)


def test_a_timed_out_pip_raises_an_error_with_no_chain_and_no_output(
    tmp_path: Path, wheels: Path, lock: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(sharedvenv, "PIP_TIMEOUT", 2)
    hang = fake_pip_shim(tmp_path, -1)
    with pytest.raises(sharedvenv.Failed) as caught:
        sharedvenv.build(root, "a" * 64, lock.read_bytes(), str(hang), ["--no-index", "--find-links", str(wheels)])
    assert_no_output_in_chain(caught.value)


def test_an_interpreter_that_fails_its_identity_query_raises_an_error_with_no_chain(tmp_path: Path) -> None:
    bad = shim(
        tmp_path / "idbad.sh",
        'if [ "$VENV_STEP" = 0 ]; then echo "PLANTED-BARE-token"; echo PLANTED-BARE-token >&2; exit 1; fi',
    )
    with pytest.raises(sharedvenv.Refused) as caught:
        sharedvenv.identity(str(bad))
    assert_no_output_in_chain(caught.value)


@pytest.mark.parametrize(
    "extra",
    [
        ["--trusted-host", "https://user:PLANTED-REDIRECT-pw@example.invalid/p"],
        ["--bogus", "PLANTED-SCP-user@example.invalid:wheels/pkg"],
        ["--bogus=PLANTED-BARE-token"],
        ["PLANTED-MULTILINE-cred\nsecond PLANTED-MULTILINE-cred"],
        ["--max-age-days", "PLANTED-BARE-token"],
        ["--lock-timeout", "user:PLANTED-REDIRECT-pw@h"],
        ["--index-url"],
        ["--no-ind"],
        ["-x", "PLANTED-BARE-token", "--find-links", "PLANTED-SCP-user@h:p"],
    ],
)
def test_argparse_errors_never_echo_the_offending_arguments(tmp_path: Path, lock: Path, extra: list[str]) -> None:
    done = cli(lock, "--root", tmp_path / "root", *extra)
    assert done.returncode == 2
    no_planted(done.stdout, done.stderr)
    assert "invalid arguments" in done.stderr


def test_help_still_works() -> None:
    done = cli("--help")
    assert done.returncode == 0 and "safo-shared-venv" in done.stdout


def test_the_venv_top_is_sealed_before_the_publish_rename(
    tmp_path: Path, wheels: Path, lock: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    modes: list[int] = []
    real = os.rename

    def watching(src: str, dst: str, *args: object, **kwargs: object) -> None:
        modes.append(os.stat(src, dir_fd=kwargs.get("src_dir_fd")).st_mode)  # type: ignore[arg-type]
        real(src, dst, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "rename", watching)
    handle = sharedvenv.open_root(root)
    sharedvenv.build(
        root, "b" * 64, lock.read_bytes(), sys.executable, ["--no-index", "--find-links", str(wheels)], handle=handle
    )
    handle.close()
    assert len(modes) == 1 and modes[0] & 0o222 == 0


def test_a_kill_right_before_publication_leaves_nothing_published_and_the_next_run_recovers(
    tmp_path: Path, wheels: Path, lock: Path
) -> None:
    root = tmp_path / "root"
    code = "\n".join(
        [
            "import os,sys",
            "sys.path.insert(0, sys.argv[1])",
            "from pathlib import Path",
            "from safo import sharedvenv",
            "sharedvenv.os.rename = lambda *a, **k: os._exit(9)",
            "args = ['--no-index', '--find-links', sys.argv[4]]",
            "sharedvenv.ensure(Path(sys.argv[2]), Path(sys.argv[3]), sys.executable, args, 60)",
        ]
    )
    src = str(Path(sharedvenv.__file__).resolve().parent.parent)
    killed = subprocess.run([sys.executable, "-c", code, src, str(root), str(lock), str(wheels)], capture_output=True)  # noqa: S603 - fixed argv in a test helper, no shell
    assert killed.returncode == 9
    assert not [p for p in root.iterdir() if re.fullmatch("[0-9a-f]{64}", p.name)]
    done = cli(*build_args(lock, root, wheels))
    assert done.returncode == 0, done.stderr
    assert not [p for p in root.iterdir() if p.name.startswith((".build-", ".stage-"))]


def test_a_writable_entry_with_our_marker_is_rebuilt_but_a_foreign_one_is_refused(
    tmp_path: Path, wheels: Path, lock: Path
) -> None:
    root, venv = build_in(tmp_path, wheels, lock)
    inode = venv.stat().st_ino
    venv.chmod(0o755)  # what an interruption after an unsealed publish used to leave behind
    done = cli(*build_args(lock, root, wheels))
    assert done.returncode == 0, done.stderr
    assert venv_of(done) == venv and not venv.stat().st_mode & 0o222
    assert venv.stat().st_ino != inode  # rebuilt, not reused
    marker = venv / sharedvenv.MARKER
    venv.chmod(0o755)
    marker.chmod(0o644)
    marker.write_text("not-our-marker\n")
    assert cli(*build_args(lock, root, wheels)).returncode == 2  # no marker of ours: refused, never deleted
    assert venv.exists()


def test_a_failure_in_work_directory_cleanup_does_not_mask_the_real_error(
    tmp_path: Path, wheels: Path, lock: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    real = sharedvenv._remove_tree

    def flaky(path: Path) -> None:
        if path.name.startswith(".build-"):
            raise OSError("cleanup boom")
        real(path)

    monkeypatch.setattr(sharedvenv, "_remove_tree", flaky)
    with pytest.raises(sharedvenv.Failed, match="pip exited with status 1"):
        sharedvenv.build(
            root,
            "c" * 64,
            lock.read_bytes(),
            str(fake_pip_shim(tmp_path, 1)),
            ["--no-index", "--find-links", str(wheels)],
        )


def test_stale_stage_directories_are_removed_only_with_our_markers(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    ours = root / ".stage-Aa1Bb2Cc"
    ours.mkdir(mode=0o700)
    (ours / sharedvenv.BUILD_MARK).write_text(sharedvenv.BUILD_MARK_TEXT)
    bare = root / ".stage-Zz9yXw8v"
    bare.mkdir()
    (bare / "f").write_text("keep")
    assert cli(*build_args(lock, root, wheels)).returncode == 0
    assert not ours.exists() and (bare / "f").exists()


# ---- round 9: never echo caller values; authenticated cleanup; exact marker ----

SECRET = "PLANTED-ARG-secret"
PATH_SECRET = "PLANTED-PATH-secret"


@pytest.mark.parametrize(
    "bad",
    [f"x\n{SECRET}", f"x\t{SECRET}", f"x {SECRET}", f"x\r{SECRET}", f"x\x0b{SECRET}", f"x\x1b[31m{SECRET}"],
)
def test_arguments_with_whitespace_or_control_characters_are_refused_with_a_fixed_message(
    tmp_path: Path, wheels: Path, lock: Path, bad: str
) -> None:
    for argv in (
        [bad, "--root", tmp_path / "root", "--no-index"],
        [lock, "--root", bad, "--no-index"],
        [lock, "--root", tmp_path / "root", "--no-index", "--python", bad],
        ["--gc", "--max-age-days", "1", "--root", bad],
    ):
        done = cli(*argv)
        assert done.returncode == 2 and SECRET not in done.stdout + done.stderr, argv
        assert "whitespace, control or non-printable" in done.stderr


def test_the_function_boundary_refuses_the_same_characters(tmp_path: Path, lock: Path) -> None:
    bad = f"x\n{SECRET}"
    with pytest.raises(sharedvenv.Refused) as caught:
        sharedvenv.ensure(Path(bad), lock, sys.executable, [], 5)
    assert SECRET not in str(caught.value)
    with pytest.raises(sharedvenv.Refused):
        sharedvenv.gc(Path(bad), 1, False, 5)
    with pytest.raises(sharedvenv.Refused):
        sharedvenv.open_root(Path(bad))
    with pytest.raises(sharedvenv.Refused):
        sharedvenv.ensure(tmp_path / "root", Path(bad), sys.executable, [], 5)
    with pytest.raises(sharedvenv.Refused):
        sharedvenv.ensure(tmp_path / "root", lock, bad, [], 5)


def _scenarios(tmp_path: Path, wheels: Path, lock: Path) -> dict[str, list[object]]:
    base = tmp_path / f"{PATH_SECRET}-base"
    base.mkdir(mode=0o700)
    root = base / "venvs"
    ok = [lock, "--no-index", "--find-links", wheels]
    out: dict[str, list[object]] = {}
    out["lockfile missing"] = [base / "missing.txt", "--root", root, "--no-index"]
    link = base / f"{PATH_SECRET}-link.txt"
    link.symlink_to(lock)
    out["lockfile symlink"] = [link, "--root", root, "--no-index"]
    bad = base / "bad.txt"
    bad.write_text(f"tinydemo==1.0 {PATH_SECRET}\n")
    out["lockfile grammar"] = [bad, "--root", root, "--no-index"]
    afile = base / f"{PATH_SECRET}-rootfile"
    afile.write_text("x")
    out["root is a file"] = [*ok, "--root", afile]
    rlink = base / f"{PATH_SECRET}-rootlink"
    rlink.symlink_to(base)
    out["root symlink"] = [*ok, "--root", rlink]
    out["ancestor symlink"] = [*ok, "--root", rlink / "root"]
    open_dir = base / f"{PATH_SECRET}-open"
    open_dir.mkdir()
    open_dir.chmod(0o777)
    out["ancestor writable"] = [*ok, "--root", open_dir / "root"]
    wroot = base / f"{PATH_SECRET}-wroot"
    wroot.mkdir()
    wroot.chmod(0o777)
    out["root writable"] = [*ok, "--root", wroot]
    out["python missing"] = [*ok, "--root", root, "--python", f"/does/not/exist/{PATH_SECRET}"]
    wpy = shim(base / f"{PATH_SECRET}-py.sh", "true")
    wpy.chmod(0o775)
    out["python writable"] = [*ok, "--root", root, "--python", wpy]
    idfail = shim(base / f"{PATH_SECRET}-idfail.sh", 'if [ "$VENV_STEP" = 0 ]; then exit 1; fi')
    out["identity fails"] = [*ok, "--root", root, "--python", idfail]
    out["gc on a file"] = ["--gc", "--max-age-days", "1", "--root", afile]
    return out


def test_no_caller_supplied_path_is_echoed_by_any_failure_path(tmp_path: Path, wheels: Path, lock: Path) -> None:
    for name, argv in _scenarios(tmp_path, wheels, lock).items():
        done = cli(*argv)
        assert done.returncode in (1, 2), (name, done.returncode, done.stderr)
        assert PATH_SECRET not in done.stdout + done.stderr, (name, done.stderr)


def test_entry_level_failures_do_not_echo_the_root_either(tmp_path: Path, wheels: Path, lock: Path) -> None:
    base = tmp_path / f"{PATH_SECRET}-base"
    base.mkdir(mode=0o700)
    root, venv = build_in(base, wheels, lock)
    stamp = root / f"{venv.name}.used"
    outputs = []
    venv.chmod(0o575)
    outputs.append(cli(*build_args(lock, root, wheels)))  # group-writable top: refused
    venv.chmod(0o555)
    stamp.unlink()
    os.link(lock, stamp)
    outputs.append(cli(*build_args(lock, root, wheels)))  # hard-linked use stamp
    stamp.unlink()
    foreign = root / ("c" * 64)
    foreign.mkdir()
    (venv / sharedvenv.MARKER).chmod(0o644)
    outputs.append(cli(*build_args(lock, root, wheels)))  # writable marker
    outputs.append(cli("--gc", "--max-age-days", "0", "--root", root))  # listing with a skipped foreign entry
    for done in outputs:
        assert PATH_SECRET not in done.stdout + done.stderr, done.stderr
    assert outputs[-1].returncode == 0 and "skipped" in outputs[-1].stdout


def test_a_kept_pip_log_is_named_without_the_root_path(tmp_path: Path, wheels: Path, lock: Path) -> None:
    base = tmp_path / f"{PATH_SECRET}-base"
    base.mkdir(mode=0o700)
    done = cli(*build_args(lock, base / "venvs", wheels), "--python", fake_pip_shim(tmp_path, 1), "--keep-pip-log")
    assert done.returncode == 1 and PATH_SECRET not in done.stderr
    assert re.search(r"pip-[0-9a-f]{12}-[0-9a-f]{8}\.log", done.stderr)


def test_the_redaction_helpers_are_gone() -> None:
    assert not hasattr(sharedvenv, "redact") and not hasattr(sharedvenv, "REDACTED_URL")


def _marker(key: str, manifest: str) -> str:
    return f"{key}\n{manifest}\n"


def _stale_root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    return root


def _good_build_dir(root: Path, name: str) -> Path:
    d = root / name
    d.mkdir(mode=0o700)
    (d / sharedvenv.BUILD_MARK).write_text(sharedvenv.BUILD_MARK_TEXT)
    return d


def test_stale_cleanup_removes_an_authenticated_leftover(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = _stale_root(tmp_path)
    ours = _good_build_dir(root, ".build-Ab3dEf9h")
    stage = root / ".stage-Cc4dDd5e"
    stage.mkdir(mode=0o700)
    (stage / sharedvenv.MARKER).write_text(_marker("a" * 64, "b" * 64))
    (stage / "bin").mkdir()
    (stage / "bin" / "python").symlink_to("/usr/bin/true")  # a venv's own link, allowed under bin
    assert cli(*build_args(lock, root, wheels)).returncode == 0
    assert not ours.exists() and not stage.exists()


def test_stale_cleanup_leaves_unauthenticated_leftovers_alone_and_says_how_many(
    tmp_path: Path, wheels: Path, lock: Path
) -> None:
    root = _stale_root(tmp_path)
    no_marker = root / ".build-NoMark12"
    no_marker.mkdir()
    (no_marker / "f").write_text("keep")
    forged = root / ".build-Forged12"
    forged.mkdir()
    (forged / sharedvenv.BUILD_MARK).write_text("forged\n")
    forged_stage = root / ".stage-Forged34"
    forged_stage.mkdir()
    (forged_stage / sharedvenv.MARKER).write_text("not-hex\nnot-hex\n")
    with_link = _good_build_dir(root, ".build-Linked12")
    (with_link / "evil").symlink_to("/etc")
    stage_link = root / ".stage-Linked34"
    stage_link.mkdir(mode=0o700)
    (stage_link / sharedvenv.MARKER).write_text(_marker("a" * 64, "b" * 64))
    (stage_link / "lib").symlink_to("/etc")  # a link outside bin/ and lib64
    done = cli(*build_args(lock, root, wheels))
    assert done.returncode == 0, done.stderr
    for left in (no_marker, forged, forged_stage, with_link, stage_link):
        assert left.exists(), left
    assert (no_marker / "f").read_text() == "keep" and Path("/etc").is_dir()
    assert re.search(r"left 5 unrecognized leftover", done.stderr)


def test_stale_cleanup_leaves_entries_of_another_owner_alone(
    tmp_path: Path, wheels: Path, lock: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _stale_root(tmp_path)
    mine = _good_build_dir(root, ".build-Ab3dEf9h")
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)  # every entry now looks foreign
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert sharedvenv._own_stale_builds(root, fd) == 1
    finally:
        os.close(fd)
    assert mine.exists()


@pytest.mark.parametrize(
    "text",
    [
        "{k}\n{m}\nextra\n",
        "{k}\n{m}\n\n",
        "{k}\n{m}",
        "{k}\n{m}\n x",
        "{k}\n{m}\r\n",
        "{k}\n{m}\n\x00",
        "{k}\x00\n{m}\n",
        "{k}\n" + "b" * 63 + "\n",
        "{k} \n{m}\n",
        "\n{k}\n{m}\n",
    ],
)
def test_a_marker_with_any_extra_byte_or_line_is_not_ours(text: str) -> None:
    key, man = "a" * 64, "b" * 64
    assert sharedvenv.parse_marker(text.format(k=key, m=man).encode()) is None
    assert sharedvenv.parse_marker(f"{key}\n{man}\n".encode()) == (key, man)


def test_rebuild_over_and_reuse_demand_the_exact_marker(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root, venv = build_in(tmp_path, wheels, lock)
    marker = venv / sharedvenv.MARKER
    good = marker.read_text()
    for bad in (good + "extra\n", good + "\x00", good.rstrip("\n"), good + "\n"):
        venv.chmod(0o755)
        marker.chmod(0o644)
        marker.write_text(bad)
        marker.chmod(0o444)
        done = cli(*build_args(lock, root, wheels))
        assert done.returncode == 2, repr(bad)  # neither reused nor rebuilt over
        assert venv.exists()
    venv.chmod(0o755)
    marker.chmod(0o644)
    marker.write_text(good)
    marker.chmod(0o444)
    done = cli(*build_args(lock, root, wheels))
    assert done.returncode == 0 and not venv.stat().st_mode & 0o222
