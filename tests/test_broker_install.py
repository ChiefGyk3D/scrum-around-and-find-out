# SPDX-License-Identifier: Apache-2.0
"""The broker installer against a fake release in a temporary tree, with a throwaway signing key. Nothing here touches
/etc, /opt, the real state directory, systemd or the network."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

import safo_broker_install as install
from installdata import SimulatedCrash, World, git, lock_text, make_key, make_wheel, make_world
from safo_broker_install import FAULT_POINTS, InstallError, Layout


@pytest.fixture
def world(tmp_path: Path) -> World:
    return make_world(tmp_path)


def current_name(layout: Layout) -> str | None:
    link = layout.opt_dir / "current"
    return os.readlink(link).rsplit("/", 1)[-1] if link.is_symlink() else None


def do_install(w: World, version: str, **kw: object) -> install.Report:
    return install.install(version, w.layout, w.hooks(), out=lambda s: None, **kw)  # type: ignore[arg-type]


# ---- the happy path and the dry-run default -------------------------------------------------------------------------


def test_dry_run_is_the_default_and_changes_nothing(world: World) -> None:
    world.release("1.0.0")
    before = world.tree_snapshot(world.root)
    report = do_install(world, "1.0.0")
    assert report.applied is False
    assert report.version == "1.0.0"
    assert len(report.commit) == 40
    assert "DRY RUN" in report.review
    assert world.tree_snapshot(world.root) == before
    assert world.calls == []
    assert not (world.layout.version_file).exists()


def test_apply_installs_a_good_signed_tag(world: World) -> None:
    sha = world.release("1.0.0")
    report = do_install(world, "1.0.0", apply=True)
    assert report.applied is True
    assert report.commit == sha
    assert current_name(world.layout) == "1.0.0"
    release = world.layout.opt_dir / "releases" / "1.0.0"
    assert (release / "COMMIT").read_text().strip() == sha
    assert (release / "venv" / "bin" / "python").exists()
    assert list((release / "venv").glob("lib/python*/site-packages/safo/broker/__main__.py"))
    assert list((release / "venv").glob("lib/python*/site-packages/fakedep/__init__.py"))
    assert (release / "units" / "safo-broker.service").read_text() == (
        world.layout.unit_dir / "safo-broker.service"
    ).read_text()
    assert world.layout.version_file.read_text().strip() == "1.0.0"
    assert ("daemon-reload",) in world.calls
    assert world.prompts, "the review gate asked root to type the version"
    # the release is read-only
    assert not os.access(release / "COMMIT", os.W_OK) or os.getuid() == 0
    assert stat.S_IMODE((release / "COMMIT").stat().st_mode) & 0o222 == 0
    log = world.layout.log_file.read_text()
    assert "install 1.0.0" in log


def test_review_shows_versions_signer_commit_and_dependency_changes(world: World) -> None:
    world.release("1.0.0")
    do_install(world, "1.0.0", apply=True)
    make_wheel(world.wheels, "otherdep", "2.0")
    world.release("1.1.0", extra={"packaging/new-build-script.sh": "echo hi\n"})
    report = do_install(world, "1.1.0")
    text = report.review
    assert "1.0.0" in text
    assert "1.1.0" in text
    assert report.commit in text
    assert "SHA256:" in text  # the signer fingerprint
    assert "+otherdep==2.0" in text or "otherdep==2.0" in text
    assert "packaging/new-build-script.sh" in text
    assert "index.example.invalid" in text


def test_wrong_confirmation_stops_before_any_change(world: World) -> None:
    world.release("1.0.0")
    world.answer = "1.0.1"
    before = world.tree_snapshot(world.root)
    with pytest.raises(InstallError, match="not confirmed"):
        do_install(world, "1.0.0", apply=True)
    after = world.tree_snapshot(world.root)
    assert after.pop("var/lib/safo-broker-install/work")[0] == "dir"  # the installer's own, empty, work directory
    after.pop("var/lib/safo-broker-install/install.lock")  # the empty lock file
    assert after == before
    assert list(world.layout.work_dir.iterdir()) == []


# ---- tag and signature refusals ------------------------------------------------------------------------------------


def test_refuses_an_unsigned_annotated_tag(world: World) -> None:
    world.commit_release("1.0.0")
    git(world.repo, "tag", "-a", "-m", "unsigned", "v1.0.0")
    with pytest.raises(InstallError, match="signature"):
        do_install(world, "1.0.0")


def test_refuses_a_lightweight_tag(world: World) -> None:
    world.commit_release("1.0.0")
    git(world.repo, "tag", "v1.0.0")
    with pytest.raises(InstallError, match="annotated"):
        do_install(world, "1.0.0")


def test_refuses_a_tag_signed_by_a_key_not_in_the_signers_file(world: World, tmp_path: Path) -> None:
    other = tmp_path / "otherkey"
    make_key(other)
    world.commit_release("1.0.0")
    world.sign_tag("v1.0.0", key=other)
    with pytest.raises(InstallError, match="signature"):
        do_install(world, "1.0.0")


def test_refuses_a_tag_signed_by_an_approval_key(world: World, tmp_path: Path) -> None:
    """The approval keys live in another file; the release signers file does not list them."""
    approval = tmp_path / "approvalkey"
    approval_pub = make_key(approval)
    (tmp_path / "gemini-allowed-signers").write_text(f'a@example.invalid namespaces="git" {approval_pub}\n')
    world.commit_release("1.0.0")
    world.sign_tag("v1.0.0", key=approval)
    with pytest.raises(InstallError, match="signature"):
        do_install(world, "1.0.0")


def test_refuses_a_tampered_tag_object(world: World) -> None:
    world.release("1.0.0")
    raw = git(world.repo, "cat-file", "tag", "v1.0.0")
    forged = raw.replace("release", "rELEASE", 1)  # change the message but keep the signature block
    oid = git(world.repo, "hash-object", "-t", "tag", "-w", "--stdin", input_text=forged + "\n")
    git(world.repo, "update-ref", "refs/tags/v1.0.0", oid)
    with pytest.raises(InstallError, match="signature"):
        do_install(world, "1.0.0")


def test_refuses_a_signed_tag_object_stored_under_another_name(world: World) -> None:
    """A genuine signed v1.0.0 object replayed as v9.9.9 verifies, but its own name line says v1.0.0."""
    world.release("1.0.0")
    git(world.repo, "update-ref", "refs/tags/v9.9.9", git(world.repo, "rev-parse", "refs/tags/v1.0.0"))
    with pytest.raises(InstallError, match="names"):
        do_install(world, "9.9.9")


def test_refuses_a_tag_whose_name_disagrees_with_the_codes_version(world: World) -> None:
    world.commit_release("1.0.0", code_version="0.9.0")
    world.sign_tag("v1.0.0")
    with pytest.raises(InstallError, match="__version__"):
        do_install(world, "1.0.0")


def test_refuses_a_malformed_version_argument(world: World) -> None:
    for bad in ("1.0", "v1.0.0", "1.0.0-rc1", "../1.0.0", "1.0.0 ", "01.0.0x", ""):
        with pytest.raises(InstallError, match="version"):
            do_install(world, bad)


def test_refuses_a_gpg_signature_block() -> None:
    raw = (
        "object "
        + "a" * 40
        + "\ntype commit\ntag v1.0.0\ntagger t\n\nmsg\n-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----\n"
    )
    with pytest.raises(InstallError, match="SSH"):
        install.parse_tag_object(raw, "v1.0.0")


def test_parse_tag_object_returns_the_commit() -> None:
    raw = (
        "object "
        + "b" * 40
        + "\ntype commit\ntag v1.0.0\ntagger t\n\nmsg\n-----BEGIN SSH SIGNATURE-----\nx\n-----END SSH SIGNATURE-----\n"
    )
    assert install.parse_tag_object(raw, "v1.0.0") == "b" * 40
    with pytest.raises(InstallError, match="commit"):
        install.parse_tag_object(raw.replace("type commit", "type tree"), "v1.0.0")


# ---- the version floor and monotonic rules ------------------------------------------------------------------------


def test_refuses_a_lower_version_and_an_equal_one(world: World) -> None:
    world.release("1.0.0")
    world.release("1.1.0")
    do_install(world, "1.1.0", apply=True)
    with pytest.raises(InstallError, match="lower"):
        do_install(world, "1.0.0", apply=True)
    with pytest.raises(InstallError, match="same"):
        do_install(world, "1.1.0", apply=True)
    assert current_name(world.layout) == "1.1.0"


def test_reinstall_flag_allows_the_same_version_under_a_new_directory(world: World) -> None:
    world.release("1.0.0")
    do_install(world, "1.0.0", apply=True)
    do_install(world, "1.0.0", apply=True, reinstall=True)
    assert current_name(world.layout) == "1.0.0.r1"
    assert (world.layout.opt_dir / "releases" / "1.0.0").is_dir()
    assert os.readlink(world.layout.opt_dir / "previous").endswith("releases/1.0.0")


def test_downgrade_needs_the_explicit_flag_naming_the_version_and_keeps_the_highest(world: World) -> None:
    world.release("1.0.0")
    world.release("1.1.0")
    do_install(world, "1.1.0", apply=True)
    with pytest.raises(InstallError, match="allow-downgrade"):
        do_install(world, "1.0.0", apply=True, allow_downgrade="1.0.1")
    do_install(world, "1.0.0", apply=True, allow_downgrade="1.0.0")
    assert current_name(world.layout) == "1.0.0"
    assert world.layout.version_file.read_text().strip() == "1.1.0"  # the highest ever installed does not fall
    assert "downgrade" in world.layout.log_file.read_text()


def test_the_floor_refuses_even_with_the_downgrade_flag(world: World) -> None:
    world.release("1.0.0")
    world.layout.floor_file.write_text("1.0.1\n")
    with pytest.raises(InstallError, match="floor"):
        do_install(world, "1.0.0", apply=True, allow_downgrade="1.0.0")


def test_a_missing_floor_file_refuses(world: World) -> None:
    world.release("1.0.0")
    world.layout.floor_file.unlink()
    with pytest.raises(InstallError, match="floor"):
        do_install(world, "1.0.0")


def test_a_version_file_missing_with_a_live_install_refuses(world: World) -> None:
    world.release("1.0.0")
    do_install(world, "1.0.0", apply=True)
    world.layout.version_file.unlink()
    world.release("1.1.0")
    with pytest.raises(InstallError, match="version file"):
        do_install(world, "1.1.0")


def test_a_garbled_version_file_refuses(world: World) -> None:
    world.release("1.0.0")
    world.layout.version_file.write_text("banana\n")
    with pytest.raises(InstallError, match="version file"):
        do_install(world, "1.0.0")


# ---- root-owned file rules ----------------------------------------------------------------------------------------


def test_refuses_a_signers_file_writable_by_the_group(world: World) -> None:
    world.release("1.0.0")
    world.layout.signers.chmod(0o664)
    with pytest.raises(InstallError, match="writable"):
        do_install(world, "1.0.0")


def test_refuses_a_signers_file_that_is_a_symlink(world: World, tmp_path: Path) -> None:
    world.release("1.0.0")
    real = tmp_path / "elsewhere"
    shutil.copy(world.layout.signers, real)
    world.layout.signers.unlink()
    world.layout.signers.symlink_to(real)
    with pytest.raises(InstallError, match="symlink"):
        do_install(world, "1.0.0")


def test_refuses_a_file_owned_by_someone_else(world: World) -> None:
    world.release("1.0.0")
    other = Layout(**{**world.layout.__dict__, "uid": os.getuid() + 1})
    with pytest.raises(InstallError, match="owned"):
        install.install("1.0.0", other, world.hooks(), out=lambda s: None)


def test_refuses_a_group_writable_parent_directory(world: World) -> None:
    world.release("1.0.0")
    world.layout.signers.parent.chmod(0o775)
    with pytest.raises(InstallError, match="writable"):
        do_install(world, "1.0.0")


def test_refuses_an_opt_dir_that_is_a_symlink(world: World, tmp_path: Path) -> None:
    world.release("1.0.0")
    real = tmp_path / "realopt"
    shutil.move(str(world.layout.opt_dir), real)
    world.layout.opt_dir.symlink_to(real)
    with pytest.raises(InstallError, match="symlink"):
        do_install(world, "1.0.0", apply=True)


def test_the_caller_cannot_supply_a_source(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    """There is no option and no environment variable that names a repository or a folder."""
    monkeypatch.setenv("SAFO_BROKER_REPO", "/tmp/evil")
    monkeypatch.setenv("GIT_DIR", "/tmp/evil")
    for flag in ("--repo", "--source", "--path", "--url"):
        with pytest.raises(SystemExit):
            install.main(["install", "1.0.0", flag, "/tmp/evil"], layout=world.layout, hooks=world.hooks())
    assert "environ" not in Path(install.__file__).read_text().split("def default_fetch", 1)[1].split("def ", 1)[0]


# ---- wheels only, hashes required ------------------------------------------------------------------------------


def test_lock_parser_accepts_a_hashed_wheel_pin() -> None:
    lock = install.parse_lock(lock_text([("fakedep", "1.0", ["a" * 64, "b" * 64])]))
    assert lock.index_url == "https://index.example.invalid/simple/"
    assert lock.requirements == {"fakedep": ("1.0", frozenset({"a" * 64, "b" * 64}))}


@pytest.mark.parametrize(
    "text",
    [
        "fakedep==1.0\n",  # no hash
        "fakedep>=1.0 \\\n  --hash=sha256:" + "a" * 64 + "\n",  # not a pin
        "fakedep==1.0 \\\n  --hash=sha1:" + "a" * 40 + "\n",
        "fakedep==1.0 \\\n  --hash=sha256:" + "A" * 10 + "\n",  # short hash
        "-e git+https://example.invalid/x.git#egg=x\n",
        "fakedep @ https://example.invalid/fakedep-1.0.tar.gz\n",
        "./local/path\n",
        "--find-links https://example.invalid/\nfakedep==1.0 --hash=sha256:" + "a" * 64 + "\n",
        "--trusted-host example.invalid\nfakedep==1.0 --hash=sha256:" + "a" * 64 + "\n",
        "--index-url http://example.invalid/simple/\nfakedep==1.0 --hash=sha256:" + "a" * 64 + "\n",
        "--index-url https://user:pw@example.invalid/simple/\nfakedep==1.0 --hash=sha256:" + "a" * 64 + "\n",
        "--no-binary :all:\nfakedep==1.0 --hash=sha256:" + "a" * 64 + "\n",
        "fakedep==1.0 --hash=sha256:" + "a" * 64 + " ; python_version > '3'\n",
        "../../evil==1.0 --hash=sha256:" + "a" * 64 + "\n",
        "-r other.txt\n",
        "",
    ],
)
def test_lock_parser_refuses(text: str) -> None:
    with pytest.raises(InstallError, match="lock"):
        install.parse_lock(text)


def test_a_dependency_without_a_hash_refuses_the_release(world: World) -> None:
    make_wheel(world.wheels, "otherdep", "2.0")
    lock = "fakedep==1.0 --hash=sha256:" + "a" * 64 + "\notherdep==2.0\n"
    world.release("1.0.0", lock=lock)
    with pytest.raises(InstallError, match="hash"):
        do_install(world, "1.0.0")


def test_an_sdist_in_the_download_is_refused(world: World) -> None:
    world.release("1.0.0")
    (world.wheels / "fakedep-1.0.tar.gz").write_bytes(b"not a wheel")
    with pytest.raises(InstallError, match="wheel"):
        do_install(world, "1.0.0")


def test_a_wheel_with_the_wrong_hash_is_refused(world: World) -> None:
    world.release("1.0.0")
    wheel = next(world.wheels.iterdir())
    wheel.write_bytes(wheel.read_bytes() + b"x")
    with pytest.raises(InstallError, match="hash"):
        do_install(world, "1.0.0")


def test_a_wheel_the_lock_does_not_name_is_refused(world: World) -> None:
    world.release("1.0.0")
    make_wheel(world.wheels, "surprise", "1.0")
    with pytest.raises(InstallError, match="not in the lock"):
        do_install(world, "1.0.0")


def test_a_locked_package_with_no_wheel_is_refused(world: World) -> None:
    good = hashlib.sha256(next(world.wheels.iterdir()).read_bytes()).hexdigest()
    world.release("1.0.0", lock=lock_text([("fakedep", "1.0", [good]), ("ghost", "1.0", ["b" * 64])]))
    with pytest.raises(InstallError, match="no wheel"):
        do_install(world, "1.0.0")


@pytest.mark.parametrize(
    "bad",
    [
        "../evil-1.0-py3-none-any.whl",
        "..-1.0-py3-none-any.whl",
        "fake dep-1.0-py3-none-any.whl",
        "fakedep-1.0.whl",
        ".hidden-1.0-py3-none-any.whl",
        "fakedep-1.0-py3-none-any.whl.exe",
    ],
)
def test_wheel_filenames_are_strict(bad: str) -> None:
    with pytest.raises(InstallError, match="wheel"):
        install.check_wheel_name(bad)
    install.check_wheel_name("fakedep-1.0-py3-none-any.whl")


def test_a_wheel_member_with_path_traversal_is_refused(world: World) -> None:
    for w in world.wheels.iterdir():
        w.unlink()
    make_wheel(world.wheels, files={"../../escape.py": b"x=1\n"})
    world.release("1.0.0")
    with pytest.raises(InstallError, match=r"traversal|unsafe"):
        do_install(world, "1.0.0")


def test_a_wheel_with_an_absolute_member_is_refused(world: World) -> None:
    for w in world.wheels.iterdir():
        w.unlink()
    make_wheel(world.wheels, files={"/etc/cron.d/x": b"x\n"})
    world.release("1.0.0")
    with pytest.raises(InstallError, match=r"traversal|unsafe"):
        do_install(world, "1.0.0")


def test_a_wheel_with_a_pth_file_is_refused(world: World) -> None:
    for w in world.wheels.iterdir():
        w.unlink()
    make_wheel(world.wheels, files={"evil.pth": b"import os\n"})
    world.release("1.0.0")
    with pytest.raises(InstallError, match=r"\.pth"):
        do_install(world, "1.0.0")


def test_a_wheel_with_console_scripts_or_data_scripts_is_refused(world: World) -> None:
    for files, why in (
        ({"fakedep-1.0.dist-info/entry_points.txt": b"[console_scripts]\nx = fakedep:main\n"}, "entry"),
        ({"fakedep-1.0.data/scripts/x": b"#!/bin/sh\n"}, "scripts"),
    ):
        for w in world.wheels.iterdir():
            w.unlink()
        make_wheel(world.wheels, files=files)
        world.release(f"1.0.{len(why)}")
        with pytest.raises(InstallError, match=why):
            do_install(world, f"1.0.{len(why)}")


def _pip_args(lock: Path, dest: Path, wheels: Path) -> list[str]:
    return install.pip_download_argv(sys.executable, lock, dest, extra=["--no-index", "--find-links", str(wheels)])


def test_the_pip_commands_carry_every_safety_flag() -> None:
    argv = install.pip_download_argv("/usr/bin/python3", Path("/x/lock"), Path("/x/dl"))
    for flag in ("--only-binary=:all:", "--require-hashes", "--no-deps", "--isolated"):
        assert flag in argv
    inst = install.pip_install_argv("/usr/bin/python3", Path("/r/venv/bin/python"), Path("/x/lock"), Path("/x/dl"))
    for flag in ("--only-binary=:all:", "--require-hashes", "--no-deps", "--isolated", "--no-index", "--no-compile"):
        assert flag in inst


def test_real_pip_refuses_an_sdist_only_index(tmp_path: Path) -> None:
    """Real pip, a local folder as the index: with only an sdist present, --only-binary=:all: finds nothing."""
    folder = tmp_path / "idx"
    folder.mkdir()
    (folder / "fakedep-1.0.tar.gz").write_bytes(b"x")
    lock = tmp_path / "lock.txt"
    lock.write_text("fakedep==1.0 --hash=sha256:" + "a" * 64 + "\n")
    dest = tmp_path / "dl"
    dest.mkdir()
    done = subprocess.run(  # noqa: S603 - fixed argv built by the module under test, no shell
        _pip_args(lock, dest, folder),
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=120,
        check=False,
    )
    assert done.returncode != 0
    assert list(dest.iterdir()) == []


def test_real_pip_refuses_an_unhashed_requirement_and_accepts_a_hashed_wheel(tmp_path: Path) -> None:
    folder = tmp_path / "idx"
    wheel, digest = make_wheel(folder)
    dest = tmp_path / "dl"
    dest.mkdir()
    bad = tmp_path / "bad.txt"
    bad.write_text("fakedep==1.0\n")
    done = subprocess.run(  # noqa: S603 - as above
        _pip_args(bad, dest, folder), capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120, check=False
    )
    assert done.returncode != 0
    good = tmp_path / "good.txt"
    good.write_text(f"fakedep==1.0 --hash=sha256:{digest}\n")
    done = subprocess.run(  # noqa: S603 - as above
        _pip_args(good, dest, folder),
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert [p.name for p in dest.iterdir()] == [wheel.name]


# ---- build, self-test with the real venv, units ----------------------------------------------------------------


def test_the_staged_venv_imports_the_broker_and_its_dependency(world: World) -> None:
    world.release("1.0.0")
    hooks = world.hooks(self_test=install.default_self_test(("safo.broker", "fakedep"), use_runuser=False))
    install.install("1.0.0", world.layout, hooks, apply=True, out=lambda s: None)
    assert current_name(world.layout) == "1.0.0"


def test_a_failing_self_test_leaves_nothing_active(world: World) -> None:
    world.release("1.0.0")
    hooks = world.hooks(self_test=install.default_self_test(("safo.broker", "not_a_module"), use_runuser=False))
    with pytest.raises(InstallError, match="self-test"):
        install.install("1.0.0", world.layout, hooks, apply=True, out=lambda s: None)
    assert current_name(world.layout) is None
    assert not world.layout.version_file.exists()
    assert [p.name for p in (world.layout.opt_dir / "releases").iterdir()] == []


def test_the_installed_source_matches_the_verified_commit_and_extras_are_refused(world: World) -> None:
    world.release("1.0.0")
    do_install(world, "1.0.0", apply=True)
    release = world.layout.opt_dir / "releases" / "1.0.0"
    manifest = (release / "MANIFEST.sha256").read_text()
    assert "venv/" in manifest
    assert "COMMIT" in manifest
    assert install.verify_manifest(release) == []
    # tamper with a copy of the tree: the manifest check names the change
    clone = world.root / "clone"
    shutil.copytree(release, clone, symlinks=True)
    for p in clone.rglob("*"):
        if p.is_dir() and not p.is_symlink():
            p.chmod(0o755)
    target = next(clone.glob("venv/lib/python*/site-packages/safo/broker/__main__.py"))
    target.chmod(0o644)
    target.write_text("evil\n")
    assert any("__main__.py" in p for p in install.verify_manifest(clone))


def test_a_tracked_symlink_in_the_release_tree_is_refused(world: World) -> None:
    world.commit_release("1.0.0")
    (world.repo / "src/safo/leak.py").symlink_to("/etc/passwd")
    git(world.repo, "add", "-A")
    git(world.repo, "commit", "-q", "-m", "link")
    world.sign_tag("v1.0.0")
    with pytest.raises(InstallError, match="symlink"):
        do_install(world, "1.0.0")


def test_the_unit_verifier_is_run_on_the_staged_units_and_can_veto(world: World) -> None:
    world.release("1.0.0")

    def veto(unit_dir: Path, release: Path) -> None:
        msg = "systemd-analyze verify failed"
        raise InstallError(msg)

    with pytest.raises(InstallError, match="verify"):
        install.install("1.0.0", world.layout, world.hooks(verify_units=veto), apply=True, out=lambda s: None)
    assert current_name(world.layout) is None


@pytest.mark.skipif(
    shutil.which("systemd-analyze") is None,
    reason="systemd-analyze is not installed; staged unit verification is not run",
)
def test_default_unit_verifier_accepts_the_shipped_units_and_rejects_a_bad_one(world: World, tmp_path: Path) -> None:
    release = tmp_path / "rel"
    (release / "venv" / "bin").mkdir(parents=True)
    py = release / "venv" / "bin" / "python"
    py.write_text("#!/bin/sh\n")
    py.chmod(0o755)
    units = release / "units"
    shutil.copytree(Path(__file__).resolve().parent.parent / "packaging" / "systemd", units)
    install.default_verify_units(units, release)
    (units / "safo-broker.service").write_text((units / "safo-broker.service").read_text() + "\nNotARealOption=yes\n")
    (units / "safo-broker.service").write_text(
        (units / "safo-broker.service").read_text().replace("[Service]", "[Servic]")
    )
    with pytest.raises(InstallError, match="verify"):
        install.default_verify_units(units, release)


# ---- atomic activation and rollback --------------------------------------------------------------------------


@pytest.mark.parametrize("point", FAULT_POINTS)
def test_a_crash_at_every_point_leaves_the_old_or_the_new_release_active(world: World, point: str) -> None:
    world.release("1.0.0")
    world.release("1.1.0")
    do_install(world, "1.0.0", apply=True)
    old_units = (world.layout.unit_dir / "safo-broker.service").read_text()
    world.fault_at = point
    world.fault_exc = SimulatedCrash
    with pytest.raises(SimulatedCrash):
        do_install(world, "1.1.0", apply=True)
    name = current_name(world.layout)
    assert name in ("1.0.0", "1.1.0"), (point, name)
    link = world.layout.opt_dir / "current"
    assert (link / "venv" / "bin" / "python").exists(), "current never dangles"
    assert (link / "COMMIT").is_file()
    # a crash before the version file is written never raises the floor
    recorded = world.layout.version_file.read_text().strip()
    if point != "after_version_write":
        assert recorded == "1.0.0"
    assert world.layout.version_file.parent.joinpath("version").is_file()
    assert old_units  # the unit file is always either old or new, never partial
    unit = (world.layout.unit_dir / "safo-broker.service").read_text()
    assert unit.endswith("RestartSec=2s\n")
    assert not [p for p in world.layout.unit_dir.iterdir() if p.name.startswith(".")] or point in ("units_tmp_written",)
    # the state directory is untouched whatever happened
    assert (world.state_dir / "ledger.jsonl").read_text() == "sentinel\n"
    # a later install cleans up stale temporary names and succeeds
    world.fault_at = None
    do_install(world, "1.1.0", apply=True, reinstall=name == "1.1.0")
    assert current_name(world.layout) in ("1.1.0", "1.1.0.r1")
    assert not [p for p in world.layout.opt_dir.iterdir() if p.name.startswith(".")]


@pytest.mark.parametrize(
    "point", [p for p in FAULT_POINTS if p not in ("before_build", "after_build", "before_swap", "after_version_write")]
)
def test_an_error_after_activation_rolls_back_and_keeps_the_version_file(world: World, point: str) -> None:
    world.release("1.0.0")
    world.release("1.1.0")
    do_install(world, "1.0.0", apply=True)
    world.calls.clear()
    world.fault_at = point
    world.fault_exc = RuntimeError
    with pytest.raises(InstallError, match=r"rolled back|failed"):
        do_install(world, "1.1.0", apply=True)
    assert current_name(world.layout) == "1.0.0"
    assert world.layout.version_file.read_text().strip() == "1.0.0"
    unit = (world.layout.unit_dir / "safo-broker.service").read_text()
    assert unit == (world.layout.opt_dir / "releases" / "1.0.0" / "units" / "safo-broker.service").read_text()


def test_a_health_check_failure_rolls_back(world: World) -> None:
    world.release("1.0.0")
    world.release("1.1.0")
    do_install(world, "1.0.0", apply=True)
    world.health_fails = True
    with pytest.raises(InstallError, match="rolled back"):
        do_install(world, "1.1.0", apply=True)
    assert current_name(world.layout) == "1.0.0"
    assert world.layout.version_file.read_text().strip() == "1.0.0"
    assert ("try-restart", "safo-broker.socket", "safo-broker.service") in world.calls


def test_a_failed_first_install_leaves_no_current_link(world: World) -> None:
    world.release("1.0.0")
    world.health_fails = True
    with pytest.raises(InstallError, match="rolled back"):
        do_install(world, "1.0.0", apply=True)
    assert current_name(world.layout) is None
    assert not world.layout.version_file.exists()


def test_the_swap_is_a_rename_over_a_temporary_link(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    world.release("1.0.0")
    seen: list[tuple[str, str]] = []
    real = os.replace

    def spy(src: object, dst: object, **kw: object) -> None:
        seen.append((str(src), str(dst)))
        real(src, dst, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "replace", spy)
    do_install(world, "1.0.0", apply=True)
    assert any(s.startswith(".current.tmp") and d == "current" for s, d in seen)
    assert (world.layout.opt_dir / "current").is_symlink()
    assert not os.readlink(world.layout.opt_dir / "current").startswith("/")


def test_previous_releases_are_kept_and_old_ones_pruned(world: World) -> None:
    for v in ("1.0.0", "1.1.0", "1.2.0", "1.3.0"):
        world.release(v)
        do_install(world, v, apply=True)
    names = sorted(p.name for p in (world.layout.opt_dir / "releases").iterdir())
    assert names == ["1.1.0", "1.2.0", "1.3.0"]
    assert os.readlink(world.layout.opt_dir / "previous").endswith("releases/1.2.0")


def test_rollback_swaps_back_and_restores_the_units(world: World) -> None:
    world.release("1.0.0")
    world.release("1.1.0", units={"safo-broker.socket": socket_v2()})
    do_install(world, "1.0.0", apply=True)
    do_install(world, "1.1.0", apply=True)
    assert "v2" in (world.layout.unit_dir / "safo-broker.socket").read_text()
    world.calls.clear()
    name = install.rollback(world.layout, world.hooks(), out=lambda s: None)
    assert name == "1.0.0"
    assert current_name(world.layout) == "1.0.0"
    assert "v2" not in (world.layout.unit_dir / "safo-broker.socket").read_text()
    assert world.layout.version_file.read_text().strip() == "1.1.0"
    assert ("daemon-reload",) in world.calls
    assert "rollback" in world.layout.log_file.read_text()
    assert os.readlink(world.layout.opt_dir / "previous").endswith("releases/1.1.0")
    # and back again
    assert install.rollback(world.layout, world.hooks(), out=lambda s: None) == "1.1.0"


def test_rollback_with_nothing_to_roll_back_to_refuses(world: World) -> None:
    world.release("1.0.0")
    do_install(world, "1.0.0", apply=True)
    with pytest.raises(InstallError, match="previous"):
        install.rollback(world.layout, world.hooks(), out=lambda s: None)


def test_rollback_refuses_a_release_below_the_floor(world: World) -> None:
    world.release("1.0.0")
    world.release("1.1.0")
    do_install(world, "1.0.0", apply=True)
    do_install(world, "1.1.0", apply=True)
    world.layout.floor_file.write_text("1.1.0\n")
    with pytest.raises(InstallError, match="floor"):
        install.rollback(world.layout, world.hooks(), out=lambda s: None)
    assert current_name(world.layout) == "1.1.0"


def test_rollback_refuses_a_previous_link_that_points_outside_the_releases(world: World, tmp_path: Path) -> None:
    world.release("1.0.0")
    world.release("1.1.0")
    do_install(world, "1.0.0", apply=True)
    do_install(world, "1.1.0", apply=True)
    (world.layout.opt_dir / "previous").unlink()
    (world.layout.opt_dir / "previous").symlink_to(str(tmp_path))
    with pytest.raises(InstallError, match="previous"):
        install.rollback(world.layout, world.hooks(), out=lambda s: None)
    assert current_name(world.layout) == "1.1.0"


def test_rollback_to_a_named_version(world: World) -> None:
    for v in ("1.0.0", "1.1.0", "1.2.0"):
        world.release(v)
        do_install(world, v, apply=True)
    assert install.rollback(world.layout, world.hooks(), to="1.0.0", out=lambda s: None) == "1.0.0"
    with pytest.raises(InstallError, match="release"):
        install.rollback(world.layout, world.hooks(), to="9.9.9", out=lambda s: None)
    with pytest.raises(InstallError, match="version"):
        install.rollback(world.layout, world.hooks(), to="../1.0.0", out=lambda s: None)


# ---- the state directory is never touched ----------------------------------------------------------------------


def test_the_installer_never_touches_the_state_directory(world: World) -> None:
    world.release("1.0.0")
    world.release("1.1.0")
    before = world.tree_snapshot(world.state_dir)
    do_install(world, "1.0.0", apply=True)
    do_install(world, "1.1.0", apply=True)
    install.rollback(world.layout, world.hooks(), out=lambda s: None)
    assert world.tree_snapshot(world.state_dir) == before


def socket_v2() -> str:
    from unitdata import read

    return read("safo-broker.socket").replace("SAFO Gemini broker socket", "SAFO Gemini broker socket v2")


def test_the_installer_source_never_names_the_state_directory() -> None:
    source = Path(install.__file__).read_text()
    # the unit policy table must name the one writable path the units may grant; no code path uses it
    head, _, rest = source.partition("UNIT_POLICY: dict")
    source = head + rest.partition("FORBIDDEN_UNIT_KEYS")[2]
    assert '"/var/lib/safo-broker"' not in source
    assert "'/var/lib/safo-broker'" not in source
    assert "/var/lib/safo-broker/" not in source


def test_apply_as_a_non_root_user_is_refused_by_the_cli(world: World) -> None:
    world.release("1.0.0")
    if os.geteuid() == 0:
        pytest.skip("running as root")
    real = Layout(**{**world.layout.__dict__, "uid": 0})
    with pytest.raises(SystemExit):
        install.main(["install", "1.0.0", "--apply"], layout=real, hooks=world.hooks())


def test_cli_dry_run_default_and_plan(world: World, capsys: pytest.CaptureFixture[str]) -> None:
    world.release("1.0.0")
    assert install.main(["install", "1.0.0"], layout=world.layout, hooks=world.hooks()) == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert current_name(world.layout) is None
    assert install.main(["plan", "--maintainer", "someone"], layout=world.layout, hooks=world.hooks()) == 0
    assert "ssh -t host 'sudo " in capsys.readouterr().out
    assert install.main(["install", "9.9.9"], layout=world.layout, hooks=world.hooks()) == 1
    assert "refused" in capsys.readouterr().err


# ---- review round 1: state directory, locking, stale policy, self-test sandbox -------------------------------------


def test_refuses_a_work_directory_the_group_can_write(world: World) -> None:
    world.release("1.0.0")
    world.layout.work_dir.mkdir(mode=0o700)
    world.layout.work_dir.chmod(0o770)
    with pytest.raises(InstallError, match="writable"):
        do_install(world, "1.0.0", apply=True)
    assert current_name(world.layout) is None


def test_refuses_a_work_directory_that_is_a_symlink(world: World, tmp_path: Path) -> None:
    world.release("1.0.0")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    world.layout.work_dir.symlink_to(elsewhere)
    with pytest.raises(InstallError, match="symlink"):
        do_install(world, "1.0.0", apply=True)
    assert list(elsewhere.iterdir()) == []


def test_refuses_an_installer_state_directory_the_group_can_write(world: World) -> None:
    world.release("1.0.0")
    world.layout.version_file.parent.chmod(0o775)
    with pytest.raises(InstallError, match="writable"):
        do_install(world, "1.0.0", apply=True)


def test_a_second_install_while_one_holds_the_lock_is_refused(world: World) -> None:
    import fcntl

    world.release("1.0.0")
    fd = os.open(world.layout.version_file.parent / "install.lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(InstallError, match="another install"):
            do_install(world, "1.0.0", apply=True)
        with pytest.raises(InstallError, match="another install"):
            install.rollback(world.layout, world.hooks(), out=lambda s: None)
    finally:
        os.close(fd)
    assert current_name(world.layout) is None
    do_install(world, "1.0.0", apply=True)  # the lock is gone with the holder
    assert current_name(world.layout) == "1.0.0"


def test_a_floor_raised_during_the_review_is_honored_before_the_swap(world: World) -> None:
    world.release("1.0.0")

    def raise_floor_then_confirm(prompt: str) -> str:
        world.layout.floor_file.write_text("1.0.1\n")  # root raises the floor while the review is open
        return "1.0.0"

    with pytest.raises(InstallError, match="floor"):
        install.install(
            "1.0.0", world.layout, world.hooks(confirm=raise_floor_then_confirm), apply=True, out=lambda s: None
        )
    assert current_name(world.layout) is None
    assert not world.layout.version_file.exists()
    assert [p.name for p in (world.layout.opt_dir / "releases").iterdir()] == []


def test_a_version_recorded_during_the_review_is_honored_before_the_swap(world: World) -> None:
    world.release("1.0.0")

    def record_a_higher_version(prompt: str) -> str:
        world.layout.version_file.write_text("2.0.0\n")
        world.layout.version_file.chmod(0o644)
        return "1.0.0"

    with pytest.raises(InstallError, match="lower"):
        install.install(
            "1.0.0", world.layout, world.hooks(confirm=record_a_higher_version), apply=True, out=lambda s: None
        )
    assert current_name(world.layout) is None


def test_the_self_test_runs_as_the_service_user_in_an_empty_network_namespace_when_root() -> None:
    py = Path("/r/venv/bin/python")
    as_root = install.self_test_argv(py, ("safo.broker", "yaml"), as_service_user=True)
    assert as_root[: 1 + len(install.SELF_TEST_NAMESPACES)] == [install.UNSHARE, *install.SELF_TEST_NAMESPACES]
    for flag in ("--net", "--ipc", "--uts", "--pid", "--fork", "--mount-proc"):
        assert flag in as_root
    assert install.RUNUSER in as_root
    assert as_root[as_root.index("-u") + 1] == install.SERVICE_USER
    assert as_root[-4:-1] == [str(py), "-I", "-c"]
    plain = install.self_test_argv(py, ("safo.broker",), as_service_user=False)
    assert plain == [str(py), "-I", "-c", "import safo.broker"]


# ---- review round 2: wheel data schemes, venv bin, rollback state directory ------------------------------------------


@pytest.mark.parametrize(
    "member", ["fakedep-1.0.data/data/bin/python", "fakedep-1.0.data/headers/x.h", "fakedep-1.0.data/data/etc/x"]
)
def test_a_wheel_data_scheme_outside_site_packages_is_refused(world: World, member: str) -> None:
    for w in world.wheels.iterdir():
        w.unlink()
    make_wheel(world.wheels, files={member: b"x"})
    world.release("1.0.0")
    with pytest.raises(InstallError, match="outside site-packages"):
        do_install(world, "1.0.0")


def test_a_wheel_purelib_data_scheme_is_still_accepted(world: World) -> None:
    for w in world.wheels.iterdir():
        w.unlink()
    make_wheel(world.wheels, files={"fakedep-1.0.data/purelib/fakeextra.py": b"X = 1\n"})
    world.release("1.0.0")
    do_install(world, "1.0.0")  # inspection passes (a dry run)


def test_the_venv_bin_check_refuses_extra_files_and_a_regular_interpreter(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "python3.13").symlink_to("/usr/bin/python3")
    (bin_dir / "python").symlink_to("python3.13")
    (bin_dir / "activate").write_text("x")
    install.check_venv_bin(bin_dir)
    (bin_dir / "evil").write_text("x")
    with pytest.raises(InstallError, match="not created by venv"):
        install.check_venv_bin(bin_dir)
    (bin_dir / "evil").unlink()
    (bin_dir / "python").unlink()
    (bin_dir / "python").write_text("#!/bin/sh\n")
    with pytest.raises(InstallError, match="not a symlink"):
        install.check_venv_bin(bin_dir)


def test_rollback_validates_the_installer_state_directory(world: World) -> None:
    world.release("1.0.0")
    world.release("1.1.0")
    do_install(world, "1.0.0", apply=True)
    do_install(world, "1.1.0", apply=True)
    world.layout.version_file.parent.chmod(0o775)
    with pytest.raises(InstallError, match="writable"):
        install.rollback(world.layout, world.hooks(), out=lambda s: None)
    assert current_name(world.layout) == "1.1.0"


def test_a_file_dropped_into_the_venv_bin_by_the_install_step_is_caught(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defense in depth behind the wheel inspection: whatever pip leaves in bin/ is checked before anything runs."""
    world.release("1.0.0")
    real_run = install._run

    def run_and_plant(argv: Sequence[str], **kw: Any) -> Any:
        done = real_run(argv, **kw)
        if "install" in argv and "--python" in argv:
            venv_python = Path(argv[argv.index("--python") + 1])
            (venv_python.parent / "evil").write_text("#!/bin/sh\n")
        return done

    monkeypatch.setattr(install, "_run", run_and_plant)
    with pytest.raises(InstallError, match="not created by venv"):
        do_install(world, "1.0.0", apply=True)
    assert current_name(world.layout) is None
    assert [p.name for p in (world.layout.opt_dir / "releases").iterdir()] == []


# ---- CI finding: the release must not depend on the caller's umask or on the modes of copied files ----------------


def mode_map(release: Path) -> dict[str, int]:
    return {
        str(p.relative_to(release)): stat.S_IMODE(os.lstat(p).st_mode)
        for p in sorted(release.rglob("*"))
        if not p.is_symlink()
    }


@pytest.mark.parametrize("mask", [0o002, 0o077, 0o022, 0o000])
def test_the_activated_release_has_the_same_modes_under_any_caller_umask(world: World, mask: int) -> None:
    world.release("1.0.0")
    old = os.umask(mask)
    try:
        do_install(world, "1.0.0", apply=True)
    finally:
        os.umask(old)
    modes = mode_map(world.layout.opt_dir / "releases" / "1.0.0")
    assert modes, "something was built"
    assert all(m & 0o022 == 0 for m in modes.values())
    reference = world.root.parent / "reference"
    reference.mkdir()
    # the same release built under the reference umask must match file for file
    other = make_world(reference)
    other.release("1.0.0")
    old = os.umask(0o022)
    try:
        do_install(other, "1.0.0", apply=True)
    finally:
        os.umask(old)
    assert modes == mode_map(other.layout.opt_dir / "releases" / "1.0.0")


def test_files_copied_group_writable_by_the_environment_builder_are_normalized(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On a hosted runner the stdlib's own venv scripts are group writable and venv copies their modes."""
    world.release("1.0.0")
    real_run = install._run

    def run_and_widen(argv: Sequence[str], **kw: Any) -> Any:
        done = real_run(argv, **kw)
        if "install" in argv and "--python" in argv:
            bin_dir = Path(argv[argv.index("--python") + 1]).parent
            (bin_dir / "Activate.ps1").chmod(0o666)
            (bin_dir.parent / "pyvenv.cfg").chmod(0o664)
        return done

    monkeypatch.setattr(install, "_run", run_and_widen)
    do_install(world, "1.0.0", apply=True)
    modes = mode_map(world.layout.opt_dir / "releases" / "1.0.0")
    assert modes["venv/bin/Activate.ps1"] == 0o444
    assert all(m & 0o022 == 0 for m in modes.values())


def test_a_file_made_group_writable_after_normalization_is_still_refused(world: World, tmp_path: Path) -> None:
    tree = tmp_path / "stage"
    (tree / "venv" / "bin").mkdir(parents=True)
    f = tree / "venv" / "bin" / "activate"
    f.write_text("x")
    f.chmod(0o666)
    install.normalize_modes(tree)
    assert stat.S_IMODE(f.stat().st_mode) == 0o644
    install.check_tree_owner(tree, world.layout)
    f.chmod(0o664)  # after normalization
    with pytest.raises(InstallError, match="writable"):
        install.check_tree_owner(tree, world.layout)


def test_normalization_never_follows_a_symlink(world: World, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("x")
    outside.chmod(0o666)
    tree = tmp_path / "stage"
    (tree / "venv").mkdir(parents=True)
    (tree / "venv" / "lib64").symlink_to(outside)
    install.normalize_modes(tree)
    assert stat.S_IMODE(outside.stat().st_mode) == 0o666  # untouched
    (tree / "venv" / "evil").symlink_to(outside)
    with pytest.raises(InstallError, match="unexpected symlink"):
        install.check_links(tree)


def test_the_build_runs_under_an_explicit_umask(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    world.release("1.0.0")
    seen: list[int] = []
    real_run = install._run

    def spy(argv: Sequence[str], **kw: Any) -> Any:
        if "install" in argv and "--python" in argv:
            current = os.umask(0)
            os.umask(current)
            seen.append(current)
        return real_run(argv, **kw)

    monkeypatch.setattr(install, "_run", spy)
    old = os.umask(0o002)
    try:
        do_install(world, "1.0.0", apply=True)
        assert os.umask(old) == 0o002  # restored afterward
    finally:
        os.umask(old)
    assert seen == [0o022]


def test_the_log_and_the_version_record_are_root_only(world: World) -> None:
    """Nothing but the installer reads them, so neither is world readable."""
    world.release("1.0.0")
    do_install(world, "1.0.0", apply=True)
    assert stat.S_IMODE(world.layout.log_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(world.layout.version_file.stat().st_mode) == 0o600
    # the unit files stay 0644 on purpose: they hold no secret and `systemctl cat` must work for the maintainer
    assert stat.S_IMODE((world.layout.unit_dir / "safo-broker.service").stat().st_mode) == 0o644
