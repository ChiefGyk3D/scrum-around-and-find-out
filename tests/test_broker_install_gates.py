# SPDX-License-Identifier: Apache-2.0
"""Installer gates added after the whole-build review: a release that cannot start is refused before activation, the
interpreter must be a trusted one, release keys must be hardware keys, and the unit policy is fixed."""

from __future__ import annotations

import dataclasses
import os
import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

import safo_broker_install as install
from installdata import World, make_world, unconfined
from safo_broker_install import InstallError


@pytest.fixture
def world(tmp_path: Path) -> World:
    return make_world(tmp_path)


def current_name(w: World) -> str | None:
    link = w.layout.opt_dir / "current"
    return os.readlink(link).rsplit("/", 1)[-1] if link.is_symlink() else None


def real_self_test(w: World, modules: tuple[str, ...] = ("fakedep",)) -> install.Hooks:
    return w.hooks(self_test=install.default_self_test(modules, use_runuser=False, wrap=unconfined))


# ---- M4: the self-test imports every broker module and runs the entry in its self-test mode ----------------------


def test_a_syntax_error_in_a_broker_module_fails_the_install_before_activation(world: World) -> None:
    world.release("1.0.0", extra={"src/safo/broker/ledger.py": "def broken(:\n"})
    with pytest.raises(InstallError, match="self-test"):
        install.install("1.0.0", world.layout, real_self_test(world), apply=True, out=lambda s: None)
    assert current_name(world) is None
    assert not world.layout.version_file.exists()
    assert [p.name for p in (world.layout.opt_dir / "releases").iterdir()] == []


def test_an_import_error_in_a_broker_module_fails_the_install(world: World) -> None:
    world.release("1.0.0", extra={"src/safo/broker/policy.py": "import a_module_that_is_not_there\n"})
    with pytest.raises(InstallError, match="self-test"):
        install.install("1.0.0", world.layout, real_self_test(world), apply=True, out=lambda s: None)
    assert current_name(world) is None


def test_an_entry_point_that_fails_its_self_test_mode_fails_the_install(world: World) -> None:
    world.release("1.0.0", extra={"src/safo/broker/__main__.py": "import sys\nsys.exit(7)\n"})
    with pytest.raises(InstallError, match="self-test"):
        install.install("1.0.0", world.layout, real_self_test(world), apply=True, out=lambda s: None)
    assert current_name(world) is None


def test_a_release_without_an_entry_point_fails_the_install(world: World) -> None:
    world.release("1.0.0", extra={"src/safo/broker/__main__.py": "raise SystemExit(3)\n"})
    with pytest.raises(InstallError, match="self-test"):
        install.install("1.0.0", world.layout, real_self_test(world), apply=True, out=lambda s: None)


def test_a_release_whose_modules_all_import_passes_the_self_test(world: World) -> None:
    world.release("1.0.0", extra={"src/safo/broker/ledger.py": "X = 1\n", "src/safo/broker/__main__.py": "pass\n"})
    install.install("1.0.0", world.layout, real_self_test(world), apply=True, out=lambda s: None)
    assert current_name(world) == "1.0.0"


def test_the_self_test_lists_the_modules_it_will_import(tmp_path: Path) -> None:
    site = tmp_path / "venv" / "lib" / "python3.13" / "site-packages" / "safo" / "broker"
    site.mkdir(parents=True)
    for name in ("__init__", "__main__", "ledger", "policy", "floor"):
        (site / f"{name}.py").write_text("")
    (site / "notes.txt").write_text("")
    assert install.broker_modules(tmp_path) == [
        "safo.broker",
        "safo.broker.floor",
        "safo.broker.ledger",
        "safo.broker.policy",
    ]


# ---- L2: the release venv may only link to a trusted interpreter ---------------------------------------------------


def test_an_interpreter_that_the_maintainer_account_could_write_is_refused(tmp_path: Path) -> None:
    py = tmp_path / "bin" / "python3"
    py.parent.mkdir()
    py.write_text("x")
    py.chmod(0o755)
    py.parent.chmod(0o755)
    tmp_path.chmod(0o755)
    install.check_interpreter(py, uid=os.getuid(), anchor=tmp_path)
    py.chmod(0o775)
    with pytest.raises(InstallError, match="writable"):
        install.check_interpreter(py, uid=os.getuid(), anchor=tmp_path)
    py.chmod(0o755)
    py.parent.chmod(0o777)
    with pytest.raises(InstallError, match="writable"):
        install.check_interpreter(py, uid=os.getuid(), anchor=tmp_path)
    py.parent.chmod(0o755)
    with pytest.raises(InstallError, match="not owned"):
        install.check_interpreter(py, uid=os.getuid() + 1, anchor=tmp_path)


def test_the_interpreter_is_resolved_through_links_before_it_is_judged(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    real = real_dir / "python3"
    real.write_text("x")
    real.chmod(0o755)
    real_dir.chmod(0o777)  # the real location is writable
    link = tmp_path / "python"
    link.symlink_to(real)
    with pytest.raises(InstallError, match="writable"):
        install.check_interpreter(link, uid=os.getuid(), anchor=tmp_path)


def test_the_default_layout_checks_the_interpreter_and_the_release_must_link_to_it(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.release("1.0.0")
    layout = dataclasses.replace(world.layout, check_python=True)
    # this machine's interpreter is owned by root, the test user is not: the default check must refuse it
    if os.getuid() != 0:
        with pytest.raises(InstallError, match="interpreter"):
            install.install("1.0.0", layout, world.hooks(), apply=True, out=lambda s: None)
    # a venv that points somewhere other than the checked interpreter is refused
    with pytest.raises(InstallError, match="interpreter"):
        install.check_venv_interpreter(Path("/usr/bin/python3"), Path("/bin/true"))
    install.check_venv_interpreter(Path("/usr/bin/python3"), Path("/usr/bin/python3"))


# ---- L3: release signing keys must be hardware keys -------------------------------------------------------------


def test_a_software_release_key_is_refused_by_default(world: World) -> None:
    world.release("1.0.0")
    strict = dataclasses.replace(world.layout, key_types=install.SK_KEY_TYPES)
    with pytest.raises(InstallError, match="hardware"):
        install.install("1.0.0", strict, world.hooks(), out=lambda s: None)


def test_the_default_layout_requires_hardware_key_types() -> None:
    assert install.Layout().key_types == install.SK_KEY_TYPES
    assert all(t.startswith("sk-") for t in install.SK_KEY_TYPES)


def test_a_hardware_key_type_in_the_signers_file_passes_the_type_check(tmp_path: Path) -> None:
    f = tmp_path / "signers"
    f.write_text('# comment\n\nrel namespaces="git" sk-ssh-ed25519@openssh.com AAAAexample comment\n')
    install.check_signer_key_types(f, install.SK_KEY_TYPES)


@pytest.mark.parametrize(
    "line",
    [
        "rel ssh-ed25519 AAAAexample",
        'rel namespaces="git" ssh-rsa AAAAexample',
        "rel ecdsa-sha2-nistp256 AAAAexample",
        "rel cert-authority ssh-ed25519 AAAAexample",
        "rel nothing-recognizable AAAA",
    ],
)
def test_other_key_types_are_refused(tmp_path: Path, line: str) -> None:
    f = tmp_path / "signers"
    f.write_text('good namespaces="git" sk-ssh-ed25519@openssh.com AAAAexample\n' + line + "\n")
    with pytest.raises(InstallError, match="hardware"):
        install.check_signer_key_types(f, install.SK_KEY_TYPES)


# ---- the signers file may not widen trust (issue 288) ------------------------------------------------------------

_SK = "sk-ssh-ed25519@openssh.com"
_BODY = "AAAA" + "example"  # not a key: only the shape the parser looks at


def _signers(tmp_path: Path, line: str) -> Path:
    f = tmp_path / "signers"
    f.write_text(line + "\n")
    return f


@pytest.mark.parametrize(
    "line",
    [
        f'rel cert-authority,namespaces="git" {_SK} {_BODY}',  # the finding: a CA line
        f'rel namespaces="git",cert-authority {_SK} {_BODY}',
        f'rel CERT-AUTHORITY,namespaces="git" {_SK} {_BODY}',
        f"rel cert-authority {_SK} {_BODY}",
        f"rel {_SK} {_BODY}",  # no namespace restriction
        f'rel namespaces="git,file" {_SK} {_BODY}',  # a wider namespace list
        f'rel namespaces="*" {_SK} {_BODY}',
        f'rel namespaces="git" valid-before="20991231" {_SK} {_BODY}',  # any further option widens or confuses
        f'rel namespaces="git",principals="x" {_SK} {_BODY}',
        f'rel namespaces="git",namespaces="file" {_SK} {_BODY}',
        f'* namespaces="git" {_SK} {_BODY}',  # a wildcard principal
        f'a,b namespaces="git" {_SK} {_BODY}',  # a principal list
        f'!a namespaces="git" {_SK} {_BODY}',  # a negated principal
        f'*@example.invalid namespaces="git" {_SK} {_BODY}',
        f'rel namespaces="git" {_SK}-cert-v01@openssh.com {_BODY}',  # a certificate type
        f'rel namespaces="git" {_SK}',  # no key body
        'rel namespaces="git"',
        "rel",
    ],
)
def test_a_line_that_widens_trust_or_is_not_an_exact_hardware_key_line_is_refused(tmp_path: Path, line: str) -> None:
    f = _signers(tmp_path, line)
    with pytest.raises(InstallError, match="signers file"):
        install.check_signer_key_types(f, install.SK_KEY_TYPES)


def test_one_bad_line_among_good_ones_refuses_the_file(tmp_path: Path) -> None:
    good = f'rel namespaces="git" {_SK} {_BODY} laptop key'
    f = _signers(tmp_path, good + f'\nca cert-authority,namespaces="git" {_SK} {_BODY}')
    with pytest.raises(InstallError, match="signers file"):
        install.check_signer_key_types(f, install.SK_KEY_TYPES)
    install.check_signer_key_types(_signers(tmp_path, good), install.SK_KEY_TYPES)  # the good line alone passes


def test_the_installer_refuses_a_ca_line_before_it_fetches_anything(world: World) -> None:
    world.release("1.0.0")
    world.layout.signers.write_text(f'ca cert-authority,namespaces="git" {_SK} {_BODY}\n')
    world.layout.signers.chmod(0o644)
    strict = dataclasses.replace(world.layout, key_types=install.SK_KEY_TYPES)
    with pytest.raises(InstallError, match="signers file"):
        install.install("1.0.0", strict, world.hooks(), out=lambda s: None)


@pytest.mark.parametrize(
    ("reported", "allowed", "ok"),
    [
        ("ED25519-SK", install.SK_KEY_TYPES, True),
        ("ECDSA-SK", install.SK_KEY_TYPES, True),
        ("ED25519-SK-CERT", install.SK_KEY_TYPES, False),
        ("ED25519", install.SK_KEY_TYPES, False),
        ("RSA", install.SK_KEY_TYPES, False),
        ("ED25519", ("ssh-ed25519",), True),
        ("ED25519-CERT", ("ssh-ed25519",), False),
        ("ED25519-SK", ("ssh-ed25519",), False),
    ],
)
def test_the_key_type_that_verified_must_be_a_plain_allowed_key_not_a_certificate(
    reported: str, allowed: tuple[str, ...], ok: bool
) -> None:
    if ok:
        install.check_reported_key_type(reported, allowed)
    else:
        with pytest.raises(InstallError, match="certificate" if "CERT" in reported else "not an allowed"):
            install.check_reported_key_type(reported, allowed)


def test_an_empty_signers_file_is_refused(tmp_path: Path) -> None:
    f = tmp_path / "signers"
    f.write_text("# nothing\n")
    with pytest.raises(InstallError, match="no keys"):
        install.check_signer_key_types(f, install.SK_KEY_TYPES)


def test_root_can_name_the_allowed_key_types_on_the_command_line(world: World) -> None:
    world.release("1.0.0")
    strict = dataclasses.replace(world.layout, key_types=install.SK_KEY_TYPES)
    assert install.main(["install", "1.0.0"], layout=strict, hooks=world.hooks()) == 1
    assert (
        install.main(["install", "1.0.0", "--release-key-type", "ssh-ed25519"], layout=strict, hooks=world.hooks()) == 0
    )


def test_the_runbook_template_installs_a_hardware_key_type() -> None:
    from safo.broker import runbook

    doc = runbook.render(maintainer="MAINTAINER_LOGIN")
    line = next(x for x in doc.splitlines() if "broker-release-signers" in x and "printf" in x)
    assert "sk-ssh-ed25519@openssh.com" in line
    assert "release-signer ssh-ed25519" not in line


# ---- the egress helper is installed once by root, never from a release ------------------------------------------


def test_apply_refuses_when_the_egress_helper_is_missing_or_not_trusted(world: World) -> None:
    world.release("1.0.0")
    helper = world.layout.egress_helper
    helper.chmod(0o775)  # writable by the group
    with pytest.raises(InstallError, match="egress helper"):
        install.install("1.0.0", world.layout, world.hooks(), apply=True, out=lambda s: None)
    helper.chmod(0o644)  # not executable
    with pytest.raises(InstallError, match="not executable"):
        install.install("1.0.0", world.layout, world.hooks(), apply=True, out=lambda s: None)
    helper.unlink()
    with pytest.raises(InstallError, match="egress helper"):
        install.install("1.0.0", world.layout, world.hooks(), apply=True, out=lambda s: None)
    assert current_name(world) is None


def test_a_release_cannot_replace_the_helper_and_the_units_name_it_by_a_fixed_path(world: World) -> None:
    world.release("1.0.0")
    install.install("1.0.0", world.layout, world.hooks(), apply=True, out=lambda s: None)
    release = world.layout.opt_dir / "releases" / "1.0.0"
    assert not list(release.rglob("safo-broker-egress"))  # nothing in the release is the helper
    units = (release / "units" / "safo-broker-egress.service").read_text()
    assert "ExecStart=/usr/local/sbin/safo-broker-egress load" in units
    assert world.layout.egress_helper.read_text() == "#!/bin/sh\n"  # untouched by the install


# ---- rolling back past the egress units stops them first ----------------------------------------------------------


def test_units_that_the_target_lacks_are_stopped_in_dependency_order_before_their_files_go(world: World) -> None:
    old: dict[str, bytes | None] = dict.fromkeys(install.UNIT_NAMES, b"x")
    new = dict(old)
    for name in (
        "safo-broker-egress.service",
        "safo-broker-egress-refresh.service",
        "safo-broker-egress-refresh.timer",
    ):
        new[name] = None
    install.stop_retired_units(world.hooks(), old, new)
    assert world.calls == [
        ("stop", "safo-broker-egress-refresh.timer"),
        ("stop", "safo-broker-egress-refresh.service"),
        ("stop", "safo-broker-egress.service"),
    ]


def test_nothing_is_stopped_when_no_unit_goes_away(world: World) -> None:
    same: dict[str, bytes | None] = dict.fromkeys(install.UNIT_NAMES, b"x")
    install.stop_retired_units(world.hooks(), same, dict(same))
    assert world.calls == []


def test_a_failed_install_on_a_first_install_stops_the_egress_units_it_started(world: World) -> None:
    world.release("1.0.0")
    world.health_fails = True
    with pytest.raises(InstallError, match="rolled back"):
        install.install("1.0.0", world.layout, world.hooks(), apply=True, out=lambda s: None)
    stops = [c for c in world.calls if c[0] == "stop"]
    assert ("stop", "safo-broker-egress-refresh.timer") in stops
    assert ("stop", "safo-broker-egress.service") in stops
    first_stop = world.calls.index(stops[0])
    reload_after = [i for i, c in enumerate(world.calls) if c == ("daemon-reload",) and i > first_stop]
    assert reload_after, "the units are stopped before the reload that forgets them"


def test_verify_tag_refuses_a_signature_that_ssh_keygen_reports_as_made_through_a_certificate(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real verification passes (a software key in the file, types opened for it); only the reported type is changed
    to what a certificate-authority line would print, so this proves verify_tag itself applies the check."""
    world.release("1.0.0")
    real = install._run

    def run(
        argv: Sequence[str], *, env: dict[str, str], cwd: Path | None = None, timeout: int = 300
    ) -> subprocess.CompletedProcess[str]:
        done = real(argv, env=env, cwd=cwd, timeout=timeout)
        if "verify-tag" in argv:
            done.stderr = done.stderr.replace("with ED25519 key", "with ED25519-CERT key")
            done.stdout = done.stdout.replace("with ED25519 key", "with ED25519-CERT key")
        return done

    ok = install.verify_tag(world.repo, "v1.0.0", world.layout, world.root)  # unmodified: passes
    assert ok.signer.split()[1] == "ED25519"
    monkeypatch.setattr(install, "_run", run)
    with pytest.raises(InstallError, match="certificate"):
        install.verify_tag(world.repo, "v1.0.0", world.layout, world.root)
