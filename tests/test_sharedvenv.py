# SPDX-License-Identifier: Apache-2.0
"""#534: the shared read-only hash-locked venv. Real subprocesses, a tiny local wheel, no network."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import math
import os
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
    assert done.returncode == 0 and "skipped" in done.stdout and str(foreign) in done.stdout
    assert (foreign / "precious.txt").read_text() == "keep"
    assert not venv.exists()  # the valid old one is deleted


def test_stale_cleanup_removes_only_this_tools_build_directories(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    ours = root / ".build-Ab3dEf9h"
    ours.mkdir(mode=0o700)
    (ours / sharedvenv.BUILD_MARK).write_text("x")
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


def test_redact_removes_userinfo_and_query_values() -> None:
    text = "see https://user:tok3n@example.invalid/simple?token=abc123&x=1 and http://bob@h/p"
    out = sharedvenv.redact(text)
    assert "tok3n" not in out and "abc123" not in out and "bob" not in out and "example.invalid" in out


def test_index_url_with_credentials_is_refused_and_never_printed(tmp_path: Path, wheels: Path, lock: Path) -> None:
    done = cli(lock, "--root", tmp_path / "root", "--index-url", "https://user:tok3n@example.invalid/simple")
    assert done.returncode == 2 and "tok3n" not in done.stdout + done.stderr
    assert "credentials" in done.stderr
    done = cli(lock, "--root", tmp_path / "root", "--find-links", "https://example.invalid/x?token=tok3n")
    assert done.returncode == 2 and "tok3n" not in done.stdout + done.stderr


def test_build_error_never_shows_url_credentials_even_when_allowed(tmp_path: Path, lock: Path) -> None:
    url = "http://user:tok3n@127.0.0.1:9/simple"
    done = cli(lock, "--root", tmp_path / "root", "--index-url", url, "--allow-url-credentials")
    assert done.returncode == 1
    assert "tok3n" not in done.stdout + done.stderr


def test_writable_entry_fails_reuse_validation(tmp_path: Path, wheels: Path, lock: Path) -> None:
    root, venv = build_in(tmp_path, wheels, lock)
    venv.chmod(0o755)
    done = cli(*build_args(lock, root, wheels))
    assert done.returncode == 2 and "writable" in done.stderr
    venv.chmod(0o555)
    marker = venv / sharedvenv.MARKER
    marker.chmod(0o644)
    assert cli(*build_args(lock, root, wheels)).returncode == 2


def test_failure_after_publication_removes_the_entry(
    tmp_path: Path, wheels: Path, lock: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    data = lock.read_bytes()
    key = "d" * 64
    real = os.chmod
    calls: list[int] = []

    def failing(path: object, mode: int, *a: object, **k: object) -> None:
        if str(path) == str(root / key) and not calls:
            calls.append(1)
            raise OSError("boom")
        real(path, mode, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "chmod", failing)
    with pytest.raises(sharedvenv.Failed):
        sharedvenv.build(root, key, data, sys.executable, ["--no-index", "--find-links", str(wheels)])
    assert not (root / key).exists()


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


SECRET_URLS = [
    "https://user:tok3n@example.invalid/simple",
    "https://user:p%40ss-tok3n@example.invalid/simple",
    "https://user:p@ss-tok3n@example.invalid:8443/simple",
    "https://user:tok3n@[2001:db8::1]:8443/simple",
    "HTTPS://USER:tok3n@EXAMPLE.invalid/Simple",
    "https://example.invalid/simple?token=tok3n",
    "https://example.invalid/simple#tok3n",
    "//user:tok3n@example.invalid/simple",
    "tok3n@example.invalid:wheels",
    "user:tok3n@example.invalid/simple",
]


@pytest.mark.parametrize("url", SECRET_URLS)
def test_url_forms_with_secrets_are_detected_and_rebuilt_without_them(url: str) -> None:
    assert sharedvenv.url_has_secret(url)
    assert "tok3n" not in sharedvenv.safe_url(url)
    assert "@" not in sharedvenv.safe_url(url) and "?" not in sharedvenv.safe_url(url)


@pytest.mark.parametrize(
    "value", ["/tmp/wheels", "relative/dir", "/home/a@b/wheels", "https://example.invalid:8443/simple", "./x@y"]
)
def test_non_secret_values_pass_through_unchanged(value: str) -> None:
    assert not sharedvenv.url_has_secret(value)
    assert sharedvenv.safe_url(value) == value


@pytest.mark.parametrize("value", ["https://example.invalid/a b", "https://example.invalid/\tx", "https://[::1/x", ""])
def test_unusual_url_values_are_refused(value: str) -> None:
    with pytest.raises(sharedvenv.Refused):
        sharedvenv.url_has_secret(value)


@pytest.mark.parametrize("url", SECRET_URLS)
def test_redaction_removes_the_supplied_values_wherever_they_appear(url: str) -> None:
    sharedvenv.register_secrets(["--index-url", url, "--find-links", url])
    out = sharedvenv.redact(f"Looking in indexes: {url}\nretry {url}/pkg and done")
    assert "tok3n" not in out


def test_unusual_credential_forms_never_reach_output(tmp_path: Path, wheels: Path, lock: Path) -> None:
    for flag in ("--index-url", "--find-links"):
        for url in ("https://user:p@ss-tok3n@example.invalid/s", "HTTPS://u:tok3n@h/x", "u:tok3n@h/x"):
            done = cli(lock, "--root", tmp_path / "root", flag, url)
            assert done.returncode == 2 and "tok3n" not in done.stdout + done.stderr
    args = ["--index-url", "https://user:tok3n@example.invalid/s"]
    with pytest.raises(sharedvenv.Refused):
        sharedvenv.ensure(tmp_path / "root2", lock, sys.executable, args, 5)  # a direct caller cannot skip the refusal


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
