# SPDX-License-Identifier: Apache-2.0
"""The read-only root-door checks behind `check-install` (issue #293; docs/gemini-broker.md, root-door precondition).

Every test builds a temporary tree and points the checks at it. The tests run as an ordinary user: the "root" files
belong to the test user (the checks take the trusted uid as an argument) and the maintainer is a made-up account whose
primary group is the test user's own group, so group bits can be tested without chown. Nothing here needs root or runs a
program. Hostile cases per check: a symlink, a wrong owner (the trusted uid is set to a different number), a
world-writable or maintainer-writable path, a missing path and an unreadable one.
"""

from __future__ import annotations

import dataclasses
import errno
import os
import shutil
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from safo.broker import doors
from safo.broker.doors import DoorPaths, Finding

UID = os.getuid()
GID = os.getgid()
MAINT = 31337
IS_ROOT = UID == 0
needs_nonroot = pytest.mark.skipif(IS_ROOT, reason="root reads files whatever their mode")


def put(path: Path, text: str = "", mode: int = 0o644) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.chmod(0o600)
    path.write_text(text)
    path.chmod(mode)
    return path


def folder(path: Path, mode: int = 0o755) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)
    return path


class World:
    """A clean fake machine. Every test breaks one thing in it."""

    def __init__(self, tmp: Path, maint: int = MAINT) -> None:
        self.t = folder(tmp / "w")
        self.home = folder(self.t / "home" / "maint")
        self.passwd = put(
            self.t / "passwd", f"root:x:0:0::/root:/bin/sh\nmaint:x:{maint}:{GID}::{self.home}:/bin/bash\n"
        )
        self.group = put(self.t / "group", f"root:x:0:\nmaint:x:{GID}:\nusers:x:100:maint\n")
        sudoers_text = f"Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n#includedir {self.t}/sudoers.d\n"
        self.sudoers = put(self.t / "sudoers", sudoers_text, 0o440)
        self.sudoers_d = folder(self.t / "sudoers.d", 0o750)
        self.nss = put(self.t / "nsswitch.conf", "passwd: files\ngroup: files [NOTFOUND=return]\n")
        self.polkit = folder(self.t / "polkit")
        self.etc = folder(self.t / "etc")
        self.opt = folder(self.t / "opt")
        self.units = folder(self.t / "units")
        self.cron_d = folder(self.t / "cron.d")
        self.crontab = put(self.t / "crontab", "# nothing\n")
        self.preload = self.t / "ld.so.preload"
        self.usr = folder(self.t / "usr")
        self.dpkg = folder(self.t / "dpkg")
        put(self.dpkg / "base.list", f"{self.usr}/ls\n")
        put(self.usr / "ls", "x", 0o755)

    def door(self, **over: Any) -> DoorPaths:
        base = DoorPaths(
            passwd=self.passwd,
            group=self.group,
            sudoers=self.sudoers,
            sudoers_d=self.sudoers_d,
            polkit_dirs=(self.polkit,),
            writable_roots=(self.etc, self.opt),
            unit_dirs=(self.units,),
            cron_files=(self.crontab,),
            cron_dirs=(self.cron_d,),
            ld_preload=self.preload,
            nsswitch=self.nss,
            userdb_dirs=(self.t / "userdb",),
            chain_floor=self.t,
            setuid_roots=(self.usr,),
            dpkg_info=self.dpkg,
            credential_paths=(".doppler", ".config/doppler"),
            merged_dirs=(),
        )
        return dataclasses.replace(base, **over)

    def run(self, *, trust: int = UID, who: int | None = MAINT, **over: Any) -> dict[str, Finding]:
        found = doors.check_doors(self.door(**over), trust, who)
        result = {f.name: f for f in found}
        assert len(result) == len(found), "one finding per check"
        return result


@pytest.fixture(autouse=True)
def _umask() -> Iterator[None]:
    old = os.umask(0o022)
    yield
    os.umask(old)


@pytest.fixture
def w(tmp_path: Path) -> World:
    return World(tmp_path)


def status(found: dict[str, Finding], name: str) -> str:
    return found[name].status


def test_a_clean_machine_passes_every_check(w: World) -> None:
    found = w.run()
    assert set(found) == {"sudo", "groups", "polkit", "writable", "jobs", "preload", "setuid", "credential"}
    assert {f.status for f in found.values()} == {"pass"}, [f.line() for f in found.values() if f.status != "pass"]


def test_every_finding_is_one_plain_sentence(w: World) -> None:
    put(w.sudoers_d / "x", "maint ALL=(ALL) NOPASSWD: ALL\n", 0o440)
    for f in w.run().values():
        assert f.status in ("pass", "warn", "fail")
        assert f.text and "\n" not in f.text and f.line() == f"{f.status}: {f.name}: {f.text}"


# -- the maintainer account ----------------------------------------------------------------------------------------


def test_an_unknown_maintainer_warns_instead_of_passing(w: World) -> None:
    found = w.run(who=None)
    assert {status(found, n) for n in ("sudo", "groups", "writable", "jobs", "setuid", "credential", "polkit")} == {
        "warn"
    }


def test_a_maintainer_missing_from_the_account_database_fails(w: World) -> None:
    found = w.run(who=4040)
    assert status(found, "groups") == "fail" and "not in" in found["groups"].text


def test_the_maintainer_being_uid_zero_fails(w: World) -> None:
    found = w.run(who=0)
    assert status(found, "groups") == "fail" and "root" in found["groups"].text


# -- sudo rules ----------------------------------------------------------------------------------------------------


def test_a_sudo_rule_naming_the_login_fails(w: World) -> None:
    put(w.sudoers_d / "10-maint", "maint ALL=(ALL) NOPASSWD: /usr/bin/vim\n", 0o440)
    found = w.run()
    assert status(found, "sudo") == "fail" and "10-maint" in found["sudo"].text


def test_a_sudo_rule_with_a_command_limit_still_fails(w: World) -> None:
    put(w.sudoers, w.sudoers.read_text() + "maint localhost = /usr/bin/systemctl restart foo\n", 0o440)
    assert status(w.run(), "sudo") == "fail"


@pytest.mark.parametrize("who", ["other,#31337", "ALL", "%users", "%#" + str(GID), "maint,other", "other, maint"])
def test_a_sudo_rule_by_uid_all_group_or_list_fails(w: World, who: str) -> None:
    put(w.sudoers_d / "20", f"{who} ALL=(ALL) ALL\n", 0o440)
    assert status(w.run(), "sudo") == "fail"


def test_a_sudo_rule_through_a_user_alias_fails(w: World) -> None:
    put(w.sudoers_d / "30", "User_Alias ADMINS = other, maint\nADMINS ALL=(ALL) ALL\n", 0o440)
    assert status(w.run(), "sudo") == "fail"


def test_a_continued_sudo_line_is_joined(w: World) -> None:
    put(w.sudoers_d / "40", "maint \\\nALL=(ALL) ALL\n", 0o440)
    assert status(w.run(), "sudo") == "fail"


def test_comments_defaults_negations_and_other_users_do_not_fail(w: World) -> None:
    text = "# maint ALL=(ALL) ALL\nDefaults:maint !authenticate\nother ALL=(ALL) ALL\n!maint ALL=(ALL) ALL\n"
    put(w.sudoers_d / "50", text, 0o440)
    assert status(w.run(), "sudo") == "pass"


def test_sudo_ignores_names_with_a_dot_or_a_tilde_and_so_do_we(w: World) -> None:
    put(w.sudoers_d / "old.disabled", "maint ALL=(ALL) ALL\n", 0o440)
    put(w.sudoers_d / "old~", "maint ALL=(ALL) ALL\n", 0o440)
    assert status(w.run(), "sudo") == "pass"


def test_a_missing_sudoers_file_fails_closed(w: World) -> None:
    w.sudoers.unlink()
    found = w.run()
    assert status(found, "sudo") == "fail" and "cannot be read" in found["sudo"].text


def test_a_sudoers_file_open_to_others_fails(w: World) -> None:
    w.sudoers.chmod(0o666)
    assert status(w.run(), "sudo") == "fail"


def test_a_sudoers_file_with_a_wrong_owner_fails(w: World) -> None:
    assert status(w.run(trust=UID + 1), "sudo") == "fail"


def test_a_symlinked_sudoers_file_fails(w: World) -> None:
    real = put(w.t / "real", w.sudoers.read_text(), 0o440)
    w.sudoers.unlink()
    w.sudoers.symlink_to(real)
    assert status(w.run(), "sudo") == "fail"


def test_a_symlink_inside_sudoers_d_fails_and_is_not_followed(w: World) -> None:
    target = put(w.t / "elsewhere", "other ALL=(ALL) ALL\n", 0o440)
    (w.sudoers_d / "60").symlink_to(target)
    found = w.run()
    assert status(found, "sudo") == "fail" and "symbolic link" in found["sudo"].text


def test_a_writable_sudoers_directory_fails(w: World) -> None:
    w.sudoers_d.chmod(0o777)
    assert status(w.run(), "sudo") == "fail"


@needs_nonroot
def test_an_unreadable_sudoers_file_fails_closed(w: World) -> None:
    put(w.sudoers_d / "70", "other ALL=(ALL) ALL\n", 0o000)
    assert status(w.run(), "sudo") == "fail"


def test_an_include_outside_the_sudoers_directory_fails_closed(w: World) -> None:
    put(w.sudoers, w.sudoers.read_text() + "@include /somewhere/else\n", 0o440)
    assert status(w.run(), "sudo") == "fail"


# -- group membership ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name", ["sudo", "wheel", "admin", "docker", "lxd", "lxc", "libvirt", "disk", "shadow", "root"]
)
def test_a_root_equivalent_supplementary_group_fails(w: World, name: str) -> None:
    put(w.group, w.group.read_text() + f"{name}:x:900:other,maint\n")
    found = w.run()
    assert status(found, "groups") == "fail" and name in found["groups"].text


def test_a_root_equivalent_primary_group_fails(w: World) -> None:
    put(w.group, f"root:x:0:\ndocker:x:{GID}:\n")
    assert status(w.run(), "groups") == "fail"


def test_a_group_the_maintainer_is_not_in_does_not_fail(w: World) -> None:
    put(w.group, w.group.read_text() + "docker:x:900:other\n")
    assert status(w.run(), "groups") == "pass"


def test_a_missing_group_file_fails_closed(w: World) -> None:
    w.group.unlink()
    assert status(w.run(), "groups") == "fail"


def test_a_missing_passwd_file_fails_closed(w: World) -> None:
    w.passwd.unlink()
    assert status(w.run(), "groups") == "fail"


def test_a_group_file_with_a_wrong_owner_or_open_mode_fails(w: World) -> None:
    assert status(w.run(trust=UID + 1), "groups") == "fail"
    w.group.chmod(0o666)
    assert status(w.run(), "groups") == "fail"


def test_a_malformed_group_line_fails_closed(w: World) -> None:
    put(w.group, w.group.read_text() + "this is not a group line\n")
    assert status(w.run(), "groups") == "fail"


# -- polkit --------------------------------------------------------------------------------------------------------


def rule(login: str = "maint", result: str = "YES") -> str:
    return (
        "polkit.addRule(function(action, subject) {\n"
        f'  if (subject.user == "{login}") {{ return polkit.Result.{result}; }}\n'
        "});\n"
    )


def test_a_polkit_rule_granting_the_login_without_a_password_fails(w: World) -> None:
    put(w.polkit / "50-x.rules", rule())
    found = w.run()
    assert status(found, "polkit") == "fail" and "50-x.rules" in found["polkit"].text


def test_a_polkit_rule_granting_the_login_group_fails(w: World) -> None:
    put(w.polkit / "50-x.rules", 'if (subject.isInGroup("users")) { return polkit.Result.YES; }\n')
    assert status(w.run(), "polkit") == "fail"


def test_a_polkit_rule_for_someone_else_only_warns(w: World) -> None:
    put(w.polkit / "50-x.rules", rule("other"))
    assert status(w.run(), "polkit") == "warn"


def test_a_polkit_rule_that_asks_for_authentication_passes(w: World) -> None:
    put(w.polkit / "50-x.rules", rule("maint", "AUTH_ADMIN"))
    assert status(w.run(), "polkit") == "pass"


def test_an_old_style_polkit_file_granting_the_login_fails(w: World) -> None:
    put(w.polkit / "sub" / "50-x.pkla", "[x]\nIdentity=unix-user:maint\nAction=*\nResultActive=yes\n")
    assert status(w.run(), "polkit") == "fail"


def test_a_missing_polkit_directory_passes_but_a_symlinked_one_fails(w: World) -> None:
    missing = w.t / "no-polkit"
    assert status(w.run(polkit_dirs=(missing,)), "polkit") == "pass"
    link = w.t / "polkit-link"
    link.symlink_to(w.polkit)
    assert status(w.run(polkit_dirs=(link,)), "polkit") == "fail"


def test_a_symlinked_polkit_rule_fails_and_is_not_followed(w: World) -> None:
    real = put(w.t / "real.rules", rule("other"))
    (w.polkit / "60.rules").symlink_to(real)
    assert status(w.run(), "polkit") == "fail"


@needs_nonroot
def test_an_unreadable_polkit_rule_fails_closed(w: World) -> None:
    put(w.polkit / "70.rules", rule(), 0o000)
    assert status(w.run(), "polkit") == "fail"


# -- paths the maintainer can write under root-run folders ---------------------------------------------------------


def test_a_world_writable_file_under_a_root_run_folder_fails(w: World) -> None:
    put(w.etc / "tool.conf", "x", 0o666)
    found = w.run()
    assert status(found, "writable") == "fail" and "tool.conf" in found["writable"].text


def test_a_world_writable_directory_fails_even_with_the_sticky_bit(w: World) -> None:
    folder(w.opt / "d", 0o1777)
    assert status(w.run(), "writable") == "fail"


def test_a_group_writable_file_in_the_maintainer_group_fails(w: World) -> None:
    put(w.opt / "tool", "x", 0o664)
    assert status(w.run(), "writable") == "fail"


def test_a_file_owned_by_the_maintainer_fails(w: World) -> None:
    put(w.opt / "tool", "x", 0o644)
    # the file belongs to the test user: make that user the maintainer for this one check
    put(w.passwd, f"maint:x:{UID}:{GID + 7}::{w.home}:/bin/bash\n")
    assert status(w.run(who=UID), "writable") == "fail"


def test_a_group_writable_file_in_a_group_the_maintainer_lacks_passes(w: World) -> None:
    put(w.group, f"root:x:0:\nmaint:x:{GID + 5}:\n")
    put(w.passwd, f"maint:x:{MAINT}:{GID + 5}::{w.home}:/bin/bash\n")
    put(w.opt / "tool", "x", 0o664)
    assert status(w.run(), "writable") == "pass"


def test_a_nested_writable_directory_is_found(w: World) -> None:
    folder(w.etc / "a" / "b" / "c")
    put(w.etc / "a" / "b" / "c" / "deep", "x", 0o666)
    assert status(w.run(), "writable") == "fail"


def test_a_symlink_is_not_followed_out_of_the_root(w: World) -> None:
    outside = folder(w.t / "outside", 0o777)
    put(outside / "f", "x", 0o666)
    (w.etc / "link").symlink_to(outside)
    assert status(w.run(), "writable") == "pass"


def test_a_missing_root_passes_and_a_root_that_is_a_file_or_symlink_fails(w: World) -> None:
    assert status(w.run(writable_roots=(w.t / "nothing",)), "writable") == "pass"
    plain = put(w.t / "plainfile", "x")
    assert status(w.run(writable_roots=(plain,)), "writable") == "fail"
    link = w.t / "etc-link"
    link.symlink_to(w.etc)
    assert status(w.run(writable_roots=(link,)), "writable") == "fail"


@needs_nonroot
def test_an_unreadable_directory_fails_closed(w: World) -> None:
    folder(w.etc / "locked", 0o000)
    try:
        assert status(w.run(), "writable") == "fail"
    finally:
        (w.etc / "locked").chmod(0o755)


def test_the_entry_limit_fails_closed(w: World) -> None:
    for i in range(5):
        put(w.etc / f"f{i}", "x")
    found = w.run(max_entries=3)
    assert status(found, "writable") == "fail" and "limit" in found["writable"].text


def test_the_extra_roots_are_walked_too(w: World) -> None:
    extra = folder(w.t / "extra")
    put(extra / "f", "x", 0o666)
    found = doors.check_doors(w.door(), UID, MAINT, extra_roots=(extra,))
    assert {f.name: f for f in found}["writable"].status == "fail"


# -- root-run units and jobs ---------------------------------------------------------------------------------------


def unit(exec_line: str, user: str | None = None) -> str:
    return "[Service]\n" + (f"User={user}\n" if user else "") + f"ExecStart={exec_line}\n"


def test_a_root_unit_running_a_writable_script_fails(w: World) -> None:
    script = put(w.t / "bin" / "job.sh", "#!/bin/sh\n", 0o777)
    put(w.units / "a.service", unit(str(script)))
    found = w.run()
    assert status(found, "jobs") == "fail" and "a.service" in found["jobs"].text


def test_a_root_unit_whose_script_sits_in_a_writable_folder_fails(w: World) -> None:
    folder(w.t / "bin", 0o777)
    script = put(w.t / "bin" / "job.sh", "#!/bin/sh\n", 0o755)
    put(w.units / "a.service", unit(f"-{script} --flag"))
    assert status(w.run(), "jobs") == "fail"


def test_a_root_unit_running_something_under_the_maintainer_home_fails(w: World) -> None:
    script = put(w.home / "run.sh", "#!/bin/sh\n", 0o755)
    put(w.units / "a.service", unit(str(script)))
    found = w.run()
    assert status(found, "jobs") == "fail" and "home" in found["jobs"].text


def test_a_unit_that_reads_an_environment_file_from_the_home_fails(w: World) -> None:
    put(w.units / "a.service", unit("/bin/true") + f"EnvironmentFile={w.home}/env\n")
    assert status(w.run(), "jobs") == "fail"


def test_a_unit_run_as_another_user_is_not_a_root_job(w: World) -> None:
    script = put(w.t / "bin" / "job.sh", "#!/bin/sh\n", 0o777)
    put(w.units / "a.service", unit(str(script), user="nobody"))
    assert status(w.run(), "jobs") == "pass"


def test_a_symlinked_script_into_a_writable_folder_fails(w: World) -> None:
    writable = folder(w.t / "wr", 0o777)
    target = put(writable / "real.sh", "#!/bin/sh\n", 0o755)
    link = w.t / "bin" / "job.sh"
    link.parent.mkdir()
    link.symlink_to(target)
    put(w.units / "a.service", unit(str(link)))
    assert status(w.run(), "jobs") == "fail"


def test_a_safe_root_unit_passes_and_a_missing_script_is_ignored(w: World) -> None:
    safe = put(w.t / "bin" / "ok.sh", "#!/bin/sh\n", 0o755)
    put(w.units / "a.service", unit(str(safe)))
    put(w.units / "b.service", unit(str(w.t / "bin" / "gone.sh")))
    assert status(w.run(), "jobs") == "pass"


def test_a_cron_job_running_a_writable_script_as_root_fails(w: World) -> None:
    script = put(w.t / "bin" / "cron.sh", "#!/bin/sh\n", 0o666)
    put(w.cron_d / "job", f"SHELL=/bin/sh\n17 * * * * root {script}\n")
    assert status(w.run(), "jobs") == "fail"
    put(w.cron_d / "job", f"@reboot root {script}\n")
    assert status(w.run(), "jobs") == "fail"


def test_a_cron_job_run_by_someone_else_is_not_a_root_job(w: World) -> None:
    script = put(w.t / "bin" / "cron.sh", "#!/bin/sh\n", 0o666)
    put(w.cron_d / "job", f"17 * * * * other {script}\n")
    assert status(w.run(), "jobs") == "pass"


def test_a_symlinked_unit_directory_fails(w: World) -> None:
    link = w.t / "units-link"
    link.symlink_to(w.units)
    assert status(w.run(unit_dirs=(link,)), "jobs") == "fail"


@needs_nonroot
def test_an_unreadable_unit_file_fails_closed(w: World) -> None:
    put(w.units / "a.service", unit("/bin/true"), 0o000)
    assert status(w.run(), "jobs") == "fail"


# -- the dynamic linker's preload file -----------------------------------------------------------------------------


def test_a_missing_preload_file_passes(w: World) -> None:
    assert status(w.run(), "preload") == "pass"


def test_a_writable_preload_file_fails(w: World) -> None:
    put(w.preload, "", 0o666)
    assert status(w.run(), "preload") == "fail"


def test_a_preload_file_with_a_wrong_owner_fails(w: World) -> None:
    put(w.preload, "")
    assert status(w.run(trust=UID + 1), "preload") == "fail"


def test_a_symlinked_preload_file_fails(w: World) -> None:
    real = put(w.t / "real", "")
    w.preload.symlink_to(real)
    assert status(w.run(), "preload") == "fail"


def test_a_preload_file_that_lists_a_library_warns(w: World) -> None:
    put(w.preload, "/usr/lib/libx.so\n")
    assert status(w.run(), "preload") == "warn"


# -- setuid, setgid and capabilities -------------------------------------------------------------------------------


def test_a_package_owned_setuid_file_passes(w: World) -> None:
    (w.usr / "ls").chmod(0o4755)
    assert status(w.run(), "setuid") == "pass"


def test_a_setuid_file_no_package_owns_fails(w: World) -> None:
    put(w.usr / "evil", "x", 0o4755)
    found = w.run()
    assert status(found, "setuid") == "fail" and "evil" in found["setuid"].text


def test_a_setgid_file_no_package_owns_fails(w: World) -> None:
    put(w.usr / "evil", "x", 0o2755)
    assert status(w.run(), "setuid") == "fail"


def test_a_setgid_directory_is_not_a_finding(w: World) -> None:
    folder(w.usr / "shared", 0o2775)
    assert status(w.run(), "setuid") == "pass"


def test_a_package_owned_setuid_file_that_the_maintainer_can_write_fails(w: World) -> None:
    (w.usr / "ls").chmod(0o4775)
    assert status(w.run(), "setuid") == "fail"


def test_a_setuid_file_in_a_nested_folder_is_found(w: World) -> None:
    put(w.usr / "a" / "b" / "evil", "x", 0o4755)
    assert status(w.run(), "setuid") == "fail"


def test_a_setuid_symlink_target_outside_the_roots_is_not_followed(w: World) -> None:
    outside = put(w.t / "outside-evil", "x", 0o4755)
    (w.usr / "link").symlink_to(outside)
    assert status(w.run(), "setuid") == "pass"


def test_merged_directories_match_the_package_list(w: World) -> None:
    put(w.dpkg / "other.list", f"{w.t}/bin/su\n")
    put(w.usr / "bin" / "su", "x", 0o4755)
    assert status(w.run(), "setuid") == "fail"  # without the merge the package list does not match
    assert status(w.run(merged_dirs=((str(w.t / "bin"), str(w.usr / "bin")),)), "setuid") == "pass"


def test_a_missing_package_database_fails_when_a_setuid_file_exists(w: World) -> None:
    (w.usr / "ls").chmod(0o4755)
    shutil.rmtree(w.dpkg)
    found = w.run()
    assert status(found, "setuid") == "fail" and "package" in found["setuid"].text


def test_a_missing_package_database_is_harmless_without_setuid_files(w: World) -> None:
    shutil.rmtree(w.dpkg)
    assert status(w.run(), "setuid") == "pass"


def test_a_symlinked_root_inside_another_root_is_skipped_and_one_outside_fails(w: World) -> None:
    link = w.t / "bin-link"
    link.symlink_to(w.usr)
    assert status(w.run(setuid_roots=(w.usr, link)), "setuid") == "pass"
    assert status(w.run(setuid_roots=(link,)), "setuid") == "fail"


def test_a_missing_setuid_root_passes(w: World) -> None:
    assert status(w.run(setuid_roots=(w.usr, w.t / "nope")), "setuid") == "pass"


@needs_nonroot
def test_an_unreadable_directory_under_a_setuid_root_fails_closed(w: World) -> None:
    folder(w.usr / "locked", 0o000)
    try:
        assert status(w.run(), "setuid") == "fail"
    finally:
        (w.usr / "locked").chmod(0o755)


def test_a_capability_file_no_package_owns_warns_and_a_writable_one_fails(
    w: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    put(w.usr / "capped", "x", 0o755)
    monkeypatch.setattr(doors, "_has_capability", lambda p: p.endswith("capped"))
    assert status(w.run(), "setuid") == "warn"
    (w.usr / "capped").chmod(0o775)
    assert status(w.run(), "setuid") == "fail"


def test_a_capability_read_that_fails_is_unreadable(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(path: str) -> bool:
        raise OSError(errno.EACCES, "denied")

    monkeypatch.setattr(doors, "_has_capability", broken)
    assert status(w.run(), "setuid") == "fail"


# -- the old secret-store credential -------------------------------------------------------------------------------


def test_no_old_credential_passes(w: World) -> None:
    assert status(w.run(), "credential") == "pass"


def test_a_leftover_credential_folder_warns(w: World) -> None:
    folder(w.home / ".doppler")
    found = w.run()
    assert status(found, "credential") == "warn" and ".doppler" in found["credential"].text


def test_a_leftover_credential_symlink_warns_and_is_not_followed(w: World) -> None:
    (w.home / ".config").mkdir()
    (w.home / ".config" / "doppler").symlink_to(w.t / "nowhere")
    assert status(w.run(), "credential") == "warn"


@needs_nonroot
def test_a_home_that_cannot_be_searched_fails_closed(w: World) -> None:
    w.home.chmod(0o000)
    try:
        assert status(w.run(), "credential") == "fail"
    finally:
        w.home.chmod(0o755)


def test_a_maintainer_without_a_home_fails_closed(w: World) -> None:
    put(w.passwd, f"maint:x:{MAINT}:{GID}:::/bin/bash\n")
    assert status(w.run(), "credential") == "fail"


# -- read-only by construction -------------------------------------------------------------------------------------


def snapshot(root: Path) -> dict[str, tuple[int, int, int]]:
    out: dict[str, tuple[int, int, int]] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            out[p] = (stat.S_IMODE(st.st_mode), st.st_mtime_ns, st.st_size)
    return out


def test_the_checks_change_nothing(w: World) -> None:
    put(w.sudoers_d / "10", "maint ALL=(ALL) ALL\n", 0o440)
    put(w.polkit / "a.rules", rule())
    put(w.usr / "evil", "x", 0o4755)
    before = snapshot(w.t)
    w.run()
    assert snapshot(w.t) == before


def test_the_module_cannot_run_a_program_or_ask_for_root() -> None:
    source = Path(doors.__file__).read_text()
    for word in (
        "subprocess",
        "os.system",
        "os.popen",
        "os.exec",
        "os.spawn",
        "setuid(",
        "seteuid(",
        "sudo -",
        "pkexec",
    ):
        assert word not in source, word


def test_the_module_opens_nothing_for_writing() -> None:
    source = Path(doors.__file__).read_text()
    for word in (
        "O_WRONLY",
        "O_RDWR",
        "O_CREAT",
        "O_TRUNC",
        "write_text",
        "write_bytes",
        "os.remove",
        "os.unlink",
        "chmod(",
        "chown(",
    ):
        assert word not in source, word


# -- review round: five fail-open gaps -------------------------------------------------------------------------------


def as_owner(w: World) -> None:
    """Make the test user the maintainer (the files the tests create belong to the test user)."""
    put(w.passwd, f"maint:x:{UID}:{GID + 7}::{w.home}:/bin/bash\n")


def test_a_file_the_maintainer_owns_counts_as_writable_whatever_its_mode(w: World) -> None:
    as_owner(w)
    put(w.opt / "tool", "x", 0o000)
    found = w.run(who=UID)
    assert status(found, "writable") == "fail" and "tool" in found["writable"].text


def test_a_root_script_the_maintainer_owns_with_a_read_only_mode_fails(w: World) -> None:
    as_owner(w)
    script = put(w.t / "bin" / "job.sh", "#!/bin/sh\n", 0o555)
    put(w.units / "a.service", unit(str(script)))
    assert status(w.run(who=UID), "jobs") == "fail"


def test_a_setuid_file_the_maintainer_owns_with_a_closed_mode_fails(w: World) -> None:
    as_owner(w)
    (w.usr / "ls").chmod(0o4555)
    assert status(w.run(who=UID), "setuid") == "fail"


def test_a_missing_script_in_a_folder_the_account_can_write_fails(w: World) -> None:
    folder(w.t / "wr", 0o777)
    put(w.units / "a.service", unit(str(w.t / "wr" / "later.sh")))
    assert status(w.run(), "jobs") == "fail"


def test_a_missing_script_in_a_sticky_world_writable_folder_fails(w: World) -> None:
    folder(w.t / "stk", 0o1777)
    put(w.units / "a.service", unit(str(w.t / "stk" / "later.sh")))
    assert status(w.run(), "jobs") == "fail"


def test_a_root_job_running_an_existing_file_from_a_sticky_folder_fails(w: World) -> None:
    folder(w.t / "stk", 0o1777)
    script = put(w.t / "stk" / "job.sh", "#!/bin/sh\n", 0o755)
    put(w.units / "a.service", unit(str(script)))
    found = w.run()
    assert status(found, "jobs") == "fail" and "stk" in found["jobs"].text
    put(w.cron_d / "job", f"@reboot root {script}\n")
    put(w.units / "a.service", unit("/bin/true"))
    assert status(w.run(), "jobs") == "fail"


def test_a_missing_script_in_a_closed_folder_is_still_ignored(w: World) -> None:
    folder(w.t / "closed", 0o755)
    put(w.units / "a.service", unit(str(w.t / "closed" / "later.sh")))
    assert status(w.run(), "jobs") == "pass"


def test_a_symlinked_unit_to_a_writable_folder_fails(w: World) -> None:
    writable = folder(w.t / "wr", 0o777)
    target = put(writable / "real.service", unit("/bin/true"), 0o644)
    (w.units / "a.service").symlink_to(target)
    found = w.run()
    assert status(found, "jobs") == "fail" and "a.service" in found["jobs"].text


def test_a_symlinked_unit_to_the_home_fails(w: World) -> None:
    target = put(w.home / "real.service", unit("/bin/true"))
    (w.units / "a.service").symlink_to(target)
    found = w.run()
    assert status(found, "jobs") == "fail" and "home" in found["jobs"].text


def test_a_symlinked_unit_to_a_safe_file_is_read_like_any_unit(w: World) -> None:
    safe = put(w.t / "lib" / "ok.service", unit("/bin/true"))
    (w.units / "a.service").symlink_to(safe)
    assert status(w.run(), "jobs") == "pass"
    bad = put(w.t / "lib" / "bad.service", unit(str(w.home / "run.sh")))
    (w.units / "b.service").symlink_to(bad)
    assert status(w.run(), "jobs") == "fail"


def test_a_masked_unit_is_fine_but_a_link_that_does_not_resolve_fails_closed(w: World) -> None:
    (w.units / "masked.service").symlink_to("/dev/null")
    assert status(w.run(), "jobs") == "pass"
    (w.units / "dangling.service").symlink_to(w.t / "nowhere.service")
    found = w.run()
    assert status(found, "jobs") == "fail" and "does not resolve" in found["jobs"].text


def test_a_drop_in_that_runs_a_writable_script_fails(w: World) -> None:
    script = put(w.t / "bin" / "job.sh", "#!/bin/sh\n", 0o777)
    put(w.units / "a.service.d" / "override.conf", unit(str(script)))
    found = w.run()
    assert status(found, "jobs") == "fail" and "override.conf" in found["jobs"].text


def test_a_symlinked_drop_in_folder_fails_and_a_clean_one_passes(w: World) -> None:
    put(w.units / "a.service.d" / "override.conf", "[Service]\nEnvironment=X=1\n")
    assert status(w.run(), "jobs") == "pass"
    real = folder(w.t / "dropins")
    (w.units / "b.service.d").symlink_to(real)
    assert status(w.run(), "jobs") == "fail"


def test_a_polkit_rule_returning_a_quoted_yes_for_the_login_fails(w: World) -> None:
    put(w.polkit / "50-x.rules", 'polkit.addRule(function(a, s) { if (s.user == "maint") { return "yes"; } });\n')
    assert status(w.run(), "polkit") == "fail"


def test_a_polkit_grant_that_names_nobody_by_a_literal_fails_closed(w: World) -> None:
    put(w.polkit / "50-x.rules", "polkit.addRule(function(a, s) { return polkit.Result.YES; });\n")
    assert status(w.run(), "polkit") == "fail"
    put(w.polkit / "50-x.rules", 'var who = lookup(); if (subject.user == who) { return "yes"; }\n')
    assert status(w.run(), "polkit") == "fail"


def test_a_polkit_grant_for_another_named_user_still_only_warns(w: World) -> None:
    put(w.polkit / "50-x.rules", 'if (subject.isInGroup("printers")) { return polkit.Result.YES; }\n')
    assert status(w.run(), "polkit") == "warn"


def second_login(w: World) -> None:
    put(w.passwd, w.passwd.read_text() + f"maint2:x:{MAINT}:{GID}::{w.t / 'home' / 'maint2'}:/bin/sh\n")


def test_a_second_login_for_the_same_uid_is_judged_in_the_group_database(w: World) -> None:
    second_login(w)
    put(w.group, w.group.read_text() + "docker:x:900:maint2\n")
    found = w.run()
    assert status(found, "groups") == "fail" and "docker" in found["groups"].text


def test_a_second_login_for_the_same_uid_is_judged_in_sudoers(w: World) -> None:
    second_login(w)
    put(w.sudoers_d / "10", "maint2 ALL=(ALL) ALL\n", 0o440)
    assert status(w.run(), "sudo") == "fail"


def test_a_second_login_for_the_same_uid_is_judged_in_polkit(w: World) -> None:
    second_login(w)
    put(w.polkit / "50-x.rules", rule("maint2"))
    assert status(w.run(), "polkit") == "fail"


def test_a_second_login_home_is_searched_for_the_old_credential(w: World) -> None:
    second_login(w)
    folder(w.t / "home" / "maint2" / ".doppler")
    assert status(w.run(), "credential") == "warn"


def test_a_second_login_with_a_second_primary_group_is_judged(w: World) -> None:
    put(w.passwd, w.passwd.read_text() + f"maint2:x:{MAINT}:901::{w.t}:/bin/sh\n")
    put(w.group, w.group.read_text() + "disk:x:901:\n")
    assert status(w.run(), "groups") == "fail"


@pytest.mark.parametrize(
    "line", ["passwd: files ldap", "passwd: sss files", "passwd: compat nis", "group: files winbind"]
)
def test_accounts_from_a_source_other_than_files_fail_closed(w: World, line: str) -> None:
    db = line.split(":")[0]
    other = "group" if db == "passwd" else "passwd"
    put(w.nss, f"{line}\n{other}: files\n")
    found = w.run()
    assert {status(found, n) for n in ("sudo", "groups", "writable", "credential")} == {"fail"}
    assert "source other than local files" in found["groups"].text


def test_a_missing_or_incomplete_name_service_file_fails_closed(w: World) -> None:
    put(w.nss, "passwd: files\n")
    assert status(w.run(), "groups") == "fail"
    w.nss.unlink()
    assert status(w.run(), "groups") == "fail"


def test_comments_and_actions_in_the_name_service_file_are_understood(w: World) -> None:
    put(w.nss, "# x\npasswd: compat # trailing\ngroup: files [SUCCESS=merge]\nhosts: dns\ninitgroups: files\n")
    assert status(w.run(), "groups") == "pass"


# -- review round 2 ------------------------------------------------------------


def test_the_systemd_name_service_source_is_not_plain(w: World) -> None:
    put(w.nss, "passwd: files systemd\ngroup: files systemd\n")
    found = w.run()
    assert status(found, "groups") == "fail" and "source other than local files" in found["groups"].text


@pytest.mark.parametrize("name", ["alice.user", "1001.user", "staff.group", "alice.membership"])
def test_a_record_in_a_user_record_folder_fails_closed(w: World, name: str) -> None:
    put(w.t / "userdb" / name, "{}")
    found = w.run()
    assert status(found, "groups") == "fail" and "user record folder" in found["groups"].text


def test_an_empty_or_absent_user_record_folder_passes_and_a_linked_one_fails(w: World) -> None:
    assert status(w.run(), "groups") == "pass"
    folder(w.t / "userdb")
    assert status(w.run(), "groups") == "pass"
    real = folder(w.t / "elsewhere")
    (w.t / "userdb").rmdir()
    (w.t / "userdb").symlink_to(real)
    assert status(w.run(), "groups") == "fail"


@pytest.mark.parametrize("database", ["initgroups", "shadow", "gshadow"])
def test_other_identity_databases_follow_the_same_source_rule(w: World, database: str) -> None:
    put(w.nss, f"passwd: files\ngroup: files\n{database}: sss\n")
    found = w.run()
    assert status(found, "groups") == "fail" and database in found["groups"].text


def test_a_plain_initgroups_line_is_accepted(w: World) -> None:
    put(w.nss, "passwd: files\ngroup: files\ninitgroups: files\nshadow: files\n")
    assert status(w.run(), "groups") == "pass"


def test_a_sudoers_rule_for_a_netgroup_fails_closed(w: World) -> None:
    put(w.sudoers_d / "10", "+admins ALL=(ALL) ALL\n", 0o440)
    found = w.run()
    assert status(found, "sudo") == "fail" and "netgroup" in found["sudo"].text


@pytest.mark.parametrize(
    "body",
    [
        'if (subject.user != "other") { return polkit.Result.YES; }',
        'if (!subject.isInGroup("printers")) { return polkit.Result.YES; }',
        'if (subject.user == "other" || subject.local) { return polkit.Result.YES; }',
        "if (subject.local) { return polkit.Result.YES; }",
        'if (subject.user == "other") { return polkit.Result.YES; }\nreturn polkit.Result.YES;',
        'if (subject.user == "other") { return polkit.Result.NO; }\nif (x) { return "yes"; }',
    ],
)
def test_a_polkit_grant_not_guarded_by_a_positive_literal_test_fails_closed(w: World, body: str) -> None:
    put(w.polkit / "50-x.rules", f"polkit.addRule(function(a, subject) {{\n{body}\n}});\n")
    assert status(w.run(), "polkit") == "fail"


@pytest.mark.parametrize(
    "body",
    [
        'if (subject.user == "other") { return polkit.Result.YES; }',
        'if (action.id == "x.y" && subject.isInGroup("printers")) { return polkit.Result.YES; }',
        'if (subject.user === "other") return polkit.Result.YES;',
    ],
)
def test_a_polkit_grant_guarded_by_a_positive_literal_for_someone_else_only_warns(w: World, body: str) -> None:
    put(w.polkit / "50-x.rules", f"polkit.addRule(function(a, subject) {{\n{body}\n}});\n")
    assert status(w.run(), "polkit") == "warn"
