# SPDX-License-Identifier: Apache-2.0
"""The read-only root-door checks behind `check-install` (issue #293; docs/gemini-broker.md, root-door precondition).

Every test builds a temporary tree and points the checks at it. The tests run as an ordinary user: the "root" files
belong to the test user (the checks take the trusted uid as an argument) and the maintainer is a made-up account whose
primary group is the test user's own group, so group bits can be tested without chown. Nothing here needs root or runs a
program. Hostile cases per check: a symlink, a wrong owner (the trusted uid is set to a different number), a
world-writable or maintainer-writable path, a missing path and an unreadable one.
"""

from __future__ import annotations

import contextlib
import dataclasses
import errno
import os
import shutil
import stat
import sys
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
            self.t / "passwd",
            f"root:x:0:0::/root:/bin/sh\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\nother:x:2001:2001::/nonexistent:/bin/sh\nmaint:x:{maint}:{GID}::{self.home}:/bin/bash\n",
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
            polkit_action_dirs=(self.t / "actions",),
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
        assert (
            f.text
            and "\n" not in f.text
            and f.line() == f"{'nothing found' if f.status == 'pass' else f.status}: {f.name}: {f.text}"
        )


# -- the maintainer account ----------------------------------------------------------------------------------------


def test_an_unknown_maintainer_fails_every_account_check(w: World) -> None:
    found = w.run(who=None)
    assert {status(found, n) for n in ("sudo", "groups", "writable", "jobs", "setuid", "credential", "polkit")} == {
        "fail"
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


def test_a_safe_root_unit_passes_and_a_missing_script_needs_a_human(w: World) -> None:
    safe = put(w.t / "bin" / "ok.sh", "#!/bin/sh\n", 0o755)
    put(w.units / "a.service", unit(str(safe)))
    assert status(w.run(), "jobs") == "pass"
    put(w.units / "b.service", unit(str(w.t / "bin" / "gone.sh")))
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


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


def test_a_missing_script_in_a_closed_folder_needs_a_human(w: World) -> None:
    folder(w.t / "closed", 0o755)
    put(w.units / "a.service", unit(str(w.t / "closed" / "later.sh")))
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


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
    body = 'if (subject.isInGroup("printers")) { return polkit.Result.YES; }'
    put(w.polkit / "50-x.rules", f"polkit.addRule(function(action, subject) {{\n{body}\n}});\n")
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
    put(w.polkit / "50-x.rules", f"polkit.addRule(function(action, subject) {{\n{body}\n}});\n")
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
    put(w.polkit / "50-x.rules", f"polkit.addRule(function(action, subject) {{\n{body}\n}});\n")
    assert status(w.run(), "polkit") == "warn"


# -- review round 3: the strict polkit allowlist ----------------------------------------------------------------------

WRAP = "polkit.addRule(function(action, subject) {{\n{}\n}});\n"


@pytest.mark.parametrize(
    "text",
    [
        WRAP.format('if (subject.user == "o") { return polkit.Result.YES; } else { return polkit.Result.YES; }'),
        WRAP.format('return subject.user == "o" ? polkit.Result.YES : polkit.Result.NO;'),
        "// note\n" + WRAP.format('if (subject.user == "o") { return polkit.Result.YES; }'),
        WRAP.format('/* c */ if (subject.user == "o") { return polkit.Result.YES; }'),
        WRAP.format('if (subject.user == "o") { return polkit.Result.YES; } // c'),
        WRAP.format('if (subject.user == "o}{") { return polkit.Result.YES; }'),
        WRAP.format('var s = "if (x) {"; if (subject.user == "o") { return polkit.Result.YES; }'),
        WRAP.format('if (subject.user == "o" | subject.local) { return polkit.Result.YES; }'),
        WRAP.format('if (subject.user == "o" || subject.local) { return polkit.Result.YES; }'),
        WRAP.format('if (!subject.isInGroup("g")) { return polkit.Result.YES; }'),
        WRAP.format('if (subject.user != "o") { return polkit.Result.YES; }'),
        WRAP.format('if (subject.user == "o" && subject.local == true) { return polkit.Result.YES; }'),
        WRAP.format('if (subject.user == "o" && 1 + 1 == 2) { return polkit.Result.YES; }'),
        WRAP.format('if (subject.user == "o") { log("x"); return polkit.Result.YES; }'),
        WRAP.format('if (subject.user == "o") { return polkit.Result.YES; }\nreturn polkit.Result.YES;'),
        WRAP.format('if (subject.user == "o") { return polkit.Result.YES; }\nif (x) { return polkit.Result.YES; }'),
        WRAP.format('if (action.id == "a.b") { return polkit.Result.YES; }'),
        WRAP.format('if (subject.user == "o") { if (subject.local) { return polkit.Result.YES; } }'),
        WRAP.format('if (subject.user == "o") return polkit.Result.YES; return polkit.Result.YES;'),
        WRAP.format("if (subject.user == 'o\"') { return polkit.Result.YES; }"),
        'polkit.addRule(function(a, s) { if (s.user == "o") { return polkit.Result.YES; } });\n',
        WRAP.format('if (subject.user == "o") { return polkit.Result.YES; }') + "var x = 1;\n",
        WRAP.format('if (subject.user == "o") { return polkit.Result.YES; }').replace("function(", "function (a,"),
    ],
)
def test_a_polkit_file_outside_the_strict_shape_fails_as_needing_a_human(w: World, text: str) -> None:
    put(w.polkit / "50-x.rules", text)
    found = w.run()
    assert status(found, "polkit") == "fail" and "needs to look" in found["polkit"].text


@pytest.mark.parametrize(
    "body",
    [
        'if (subject.user == "o") { return polkit.Result.YES; }',
        "if (subject.user === 'o') return polkit.Result.YES;",
        'if (subject.isInGroup("g") && action.id == "a.b-c") { return "yes"; }',
        'if (action.id == "a.b" && subject.user == "o" && subject.isInGroup("g")) { return polkit.Result.YES; }',
        'if (subject.user == "o") { return polkit.Result.YES; }\nif (subject.user == "p") { return "yes"; }',
    ],
)
def test_a_polkit_file_in_the_strict_shape_for_other_principals_only_warns(w: World, body: str) -> None:
    put(w.polkit / "50-x.rules", WRAP.format(body))
    assert status(w.run(), "polkit") == "warn"


def test_two_rules_in_one_strict_file_are_accepted_and_a_bad_second_one_is_not(w: World) -> None:
    good = WRAP.format('if (subject.user == "o") { return polkit.Result.YES; }')
    put(w.polkit / "50-x.rules", good + good)
    assert status(w.run(), "polkit") == "warn"
    put(w.polkit / "50-x.rules", good + WRAP.format("return polkit.Result.YES;"))
    assert status(w.run(), "polkit") == "fail"


def test_a_strict_file_that_names_the_account_group_still_fails(w: World) -> None:
    put(w.polkit / "50-x.rules", WRAP.format('if (subject.isInGroup("users")) { return polkit.Result.YES; }'))
    found = w.run()
    assert status(found, "polkit") == "fail" and "needs to look" not in found["polkit"].text


def test_an_oversized_polkit_file_is_not_attributed(w: World) -> None:
    body = "\n".join(['if (subject.user == "o") { return polkit.Result.YES; }'] * 5000)
    put(w.polkit / "50-x.rules", WRAP.format(body))
    assert status(w.run(), "polkit") == "fail"


# -- hardening ----------------------------------------------------------------------


def test_hardening_claimed_login_must_belong_to_the_user_id(w: World) -> None:
    ok = doors.check_doors(w.door(), UID, MAINT, claimed_login="maint")
    assert {f.status for f in ok if f.name != "preload"} == {"pass"}
    for bad in ("root", "", "someone-else"):
        found = {f.name: f for f in doors.check_doors(w.door(), UID, MAINT, claimed_login=bad)}
        assert {found[n].status for n in ("sudo", "groups", "polkit", "writable", "jobs", "setuid", "credential")} == {
            "fail"
        }


@pytest.mark.parametrize("line", ["#31337 ALL=(ALL) ALL", "#31337\tALL=(ALL) ALL", "#31337,other ALL=(ALL) ALL"])
def test_hardening_numeric_sudoers_rule_is_a_rule(w: World, line: str) -> None:
    put(w.sudoers_d / "10", line + "\n", 0o440)
    assert status(w.run(), "sudo") == "fail"


def test_hardening_numeric_comment_without_a_rule_shape_is_still_a_comment(w: World) -> None:
    put(w.sudoers_d / "10", "#31337\n# 31337 ALL=(ALL) ALL\n#31338 ALL=(ALL) ALL\n", 0o440)
    assert status(w.run(), "sudo") == "pass"


@pytest.mark.parametrize(
    "body",
    [
        'if (subject.user == "o") return polkit.Result["YES"];',
        "const allow = polkit.Result.YES; return allow;",
        'if (subject.user == "o") { return polkit["Result"].YES; }',
        'if (subject.user == "o") { return polkit.Result.\\u0059ES; }',
        'if (subject.user == "o") { return String.fromCharCode(121, 101, 115); }',
        'if (subject.user == "o") { return polkit.Result.WHATEVER; }',
        "log(1);",
    ],
)
def test_hardening_any_rules_file_not_in_the_strict_shape_fails(w: World, body: str) -> None:
    put(w.polkit / "50-x.rules", WRAP.format(body))
    assert status(w.run(), "polkit") == "fail"


def test_hardening_rules_files_that_are_empty_or_only_deny_pass(w: World) -> None:
    put(w.polkit / "10-empty.rules", "  \n")
    put(w.polkit / "20-deny.rules", WRAP.format('if (subject.user == "o") { return polkit.Result.NO; }'))
    assert status(w.run(), "polkit") == "pass"


def test_hardening_commented_or_garbled_nonempty_rules_file_fails(w: World) -> None:
    put(w.polkit / "10.rules", "// only a comment\n")
    assert status(w.run(), "polkit") == "fail"


def test_hardening_interpreter_running_a_script_in_the_home_fails(w: World) -> None:
    payload = put(w.home / "payload.py", "x = 1\n")
    put(w.units / "a.service", unit(f"/usr/bin/python3 {payload}"))
    found = w.run()
    assert status(found, "jobs") == "fail" and "home" in found["jobs"].text


def test_hardening_shell_in_cron_running_a_script_in_the_home_fails(w: World) -> None:
    payload = put(w.home / "payload.sh", "true\n")
    put(w.cron_d / "x", f"@reboot root /bin/sh {payload}\n")
    assert status(w.run(), "jobs") == "fail"


def test_hardening_interpreter_script_in_a_writable_folder_fails(w: World) -> None:
    folder(w.t / "wr", 0o777)
    put(w.units / "a.service", unit(f"/usr/bin/env python3 {w.t}/wr/s.py"))
    assert status(w.run(), "jobs") == "fail"
    put(w.units / "a.service", unit(f"/usr/bin/env {w.t}/wr/s.py"))
    assert status(w.run(), "jobs") == "fail"


def test_hardening_interpreter_with_a_safe_script_passes(w: World) -> None:
    script = put(w.t / "bin" / "ok.py", "x = 1\n")
    put(w.units / "a.service", unit(f"/usr/bin/python3 -I {script}"))
    put(w.units / "b.service", unit(f"/usr/bin/env FOO=1 /usr/bin/python3 {script}"))
    assert status(w.run(), "jobs") == "pass"


@pytest.mark.parametrize(
    "command",
    [
        "/bin/sh -c 'run something'",
        "/usr/bin/python3 -c 'print(1)'",
        "/usr/bin/python3 -m http.server",
        "/usr/bin/python3 relative.py",
        "/usr/bin/python3",
        "/usr/bin/perl -e 1",
        "/bin/bash",
        "/usr/bin/env python3 /x/y.py",
        "/bin/sh --command=x",
        "/usr/bin/node --eval 1",
    ],
)
def test_hardening_interpreter_command_lines_it_cannot_judge_fail(w: World, command: str) -> None:
    put(w.units / "a.service", unit(command))
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


@pytest.mark.parametrize(
    "value", ["python3 /x/y.py", "$HOME/x", "@/bin/true name", "/bin/true ; /bin/false", "/bin/true 'unclosed"]
)
def test_hardening_unreadable_unit_command_lines_fail(w: World, value: str) -> None:
    put(w.units / "a.service", unit(value))
    assert status(w.run(), "jobs") == "fail"


@pytest.mark.parametrize(
    "command",
    [
        "/bin/true; /bin/false",
        "/bin/true | cat",
        "/bin/true $(x)",
        "/bin/true `x`",
        "/bin/true && /bin/false",
        "/bin/true 'unclosed",
    ],
)
def test_hardening_cron_shell_syntax_it_cannot_judge_fails(w: World, command: str) -> None:
    put(w.cron_d / "x", f"17 * * * * root {command}\n")
    assert status(w.run(), "jobs") == "fail"


def test_hardening_default_paths_cover_runtime_unit_and_polkit_storage() -> None:
    d = DoorPaths()
    for name in ("system", "transient", "generator", "generator.early", "generator.late"):
        assert Path("/run/systemd") / name in d.unit_dirs
        assert Path("/run/systemd") / name in d.writable_roots
    assert Path("/var/lib/polkit-1") in d.writable_roots


def test_hardening_runtime_unit_folder_is_read_like_the_others(w: World) -> None:
    runtime = folder(w.t / "run-system")
    payload = put(w.home / "payload.py", "x = 1\n")
    put(runtime / "t.service", unit(f"/usr/bin/python3 {payload}"))
    assert status(w.run(unit_dirs=(w.units, runtime)), "jobs") == "fail"


def test_hardening_forged_package_list_is_not_trusted(w: World) -> None:
    evil = put(w.usr / "evil", "x", 0o4755)
    put(w.dpkg / "forged.list", f"{evil}\n", 0o666)
    assert status(w.run(), "setuid") == "fail"


def test_hardening_package_database_must_be_root_owned_and_closed(w: World) -> None:
    (w.usr / "ls").chmod(0o4755)
    assert status(w.run(), "setuid") == "pass"
    w.dpkg.chmod(0o777)
    assert status(w.run(), "setuid") == "fail"
    w.dpkg.chmod(0o755)
    assert status(w.run(trust=UID + 1), "setuid") == "fail"


def test_hardening_package_database_in_a_folder_the_account_can_write_is_not_trusted(w: World) -> None:
    (w.usr / "ls").chmod(0o4755)
    w.t.chmod(0o777)
    try:
        assert status(w.run(), "setuid") == "fail"
    finally:
        w.t.chmod(0o755)


def test_hardening_writable_legacy_polkit_storage_fails(w: World) -> None:
    legacy = folder(w.t / "var-lib-polkit", 0o777)
    found = w.run(polkit_dirs=(legacy,))
    assert status(found, "polkit") == "fail" and "polkit storage" in found["polkit"].text


def test_hardening_writable_entry_inside_polkit_storage_fails(w: World) -> None:
    put(w.polkit / "sub" / "x.pkla", "[x]\n", 0o666)
    assert status(w.run(), "polkit") == "fail"


def test_hardening_writable_parent_of_polkit_storage_fails(w: World) -> None:
    parent = folder(w.t / "pk", 0o777)
    inner = folder(parent / "rules.d")
    assert status(w.run(polkit_dirs=(inner,)), "polkit") == "fail"


# -- the read-only property, proved at run time ------------------------------------------------------------------------

WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
CHANGING_EVENTS = frozenset(
    {
        "os.chmod",
        "os.chown",
        "os.mkdir",
        "os.remove",
        "os.rename",
        "os.rmdir",
        "os.truncate",
        "os.symlink",
        "os.link",
        "os.utime",
        "os.setxattr",
        "os.removexattr",
        "os.mkfifo",
        "os.mknod",
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.spawn",
        "os.fork",
        "os.forkpty",
        "subprocess.Popen",
        "ctypes.dlopen",
        "ctypes.call_function",
        "pty.spawn",
        "shutil.copyfile",
        "shutil.copymode",
        "shutil.copystat",
        "shutil.copytree",
        "shutil.rmtree",
        "shutil.move",
        "tempfile.mkstemp",
        "tempfile.mkdtemp",
    }
)


class Recorder:
    def __init__(self) -> None:
        self.active = False
        self.bad: list[str] = []
        self.reads = 0


RECORDER = Recorder()


def _audit(event: str, args: tuple[object, ...]) -> None:
    if not RECORDER.active:
        return
    if event == "open":
        flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
        mode = args[1] if len(args) > 1 and isinstance(args[1], str) else ""
        if flags & WRITE_FLAGS or set(mode) & set("wax+"):
            RECORDER.bad.append(f"open {args[0]!r} {mode!r} {flags}")
        else:
            RECORDER.reads += 1
    elif event in CHANGING_EVENTS:
        RECORDER.bad.append(event)


sys.addaudithook(_audit)


@contextlib.contextmanager
def recording() -> Iterator[Recorder]:
    RECORDER.bad.clear()
    RECORDER.reads = 0
    RECORDER.active = True
    try:
        yield RECORDER
    finally:
        RECORDER.active = False


def hostile_world(w: World) -> None:
    put(w.sudoers_d / "10", "maint ALL=(ALL) ALL\n", 0o440)
    put(w.polkit / "50-x.rules", rule())
    put(w.polkit / "60-y.rules", "garbage\n")
    put(w.usr / "evil", "x", 0o4755)
    put(w.etc / "open.conf", "x", 0o666)
    put(w.units / "a.service", unit(f"/usr/bin/python3 {w.home}/p.py"))
    (w.units / "b.service").symlink_to(w.t / "nowhere")
    put(w.units / "c.service.d" / "o.conf", unit("/bin/true"))
    put(w.cron_d / "x", "@reboot root /bin/true\n")
    put(w.preload, "/x.so\n")
    folder(w.home / ".doppler")


def test_the_checks_make_no_write_or_process_call_on_a_hostile_machine(w: World) -> None:
    hostile_world(w)
    with recording() as rec:
        found = w.run()
    assert rec.bad == []
    assert rec.reads >= 5  # the guard saw the checks read
    assert {f.status for f in found.values()} >= {"fail", "warn"}


def test_the_runtime_guard_bites_on_writes_and_process_calls(w: World, tmp_path: Path) -> None:
    target = tmp_path / "scratch"
    with recording() as rec:
        with open(target, "w") as handle:
            handle.write("x")
        os.mkdir(tmp_path / "d")
        os.chmod(target, 0o600)
        os.rename(target, tmp_path / "r")
    assert len(rec.bad) >= 4


def test_the_runtime_guard_catches_a_check_that_writes(
    w: World, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def writer(*_: object) -> Finding:
        (tmp_path / "leak").write_text("x")
        return Finding("preload", "pass", "x")

    monkeypatch.setattr(doors, "_check_preload", writer)
    with recording() as rec:
        w.run()
    assert rec.bad


def test_the_checks_leave_every_byte_of_the_tree_as_it_was(w: World) -> None:
    hostile_world(w)

    def digest() -> dict[str, tuple[int, bytes | str]]:
        out: dict[str, tuple[int, bytes | str]] = {}
        for dirpath, dirnames, filenames in os.walk(w.t):
            for name in dirnames + filenames:
                p = os.path.join(dirpath, name)
                st = os.lstat(p)
                body: bytes | str = os.readlink(p) if stat.S_ISLNK(st.st_mode) else b""
                if stat.S_ISREG(st.st_mode):
                    body = Path(p).read_bytes()
                out[p] = (stat.S_IMODE(st.st_mode) | st.st_mtime_ns, body)
        return out

    before = digest()
    w.run()
    assert digest() == before


@pytest.mark.parametrize(
    "tail",
    ["-Z {ok}", "-I/home/x {ok}", "--opt=/home/x {ok}", "--opt {ok}", "-W ignore {ok}", "-X{ok} {ok}", "-{ok}"],
)
def test_hardening_unrecognized_options_on_an_interpreter_need_a_human(w: World, tail: str) -> None:
    ok = put(w.t / "bin" / "ok.py", "x = 1\n")
    put(w.units / "a.service", unit("/usr/bin/python3 " + tail.format(ok=ok)))
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


def test_hardening_known_harmless_flags_are_followed_to_the_script(w: World) -> None:
    ok = put(w.t / "bin" / "ok.py", "x = 1\n")
    put(w.units / "a.service", unit(f"/usr/bin/python3 -I -B -u -- {ok}"))
    assert status(w.run(), "jobs") == "pass"


@pytest.mark.parametrize("program", ["awk", "gawk", "mawk", "sed"])
def test_hardening_program_text_first_interpreters_need_a_human(w: World, program: str) -> None:
    script = put(w.t / "bin" / "p.awk", "BEGIN{}\n")
    put(w.units / "a.service", unit(f"/usr/bin/{program} -f {script}"))
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text
    put(w.units / "a.service", unit(f"/usr/bin/{program} 'BEGIN{{}}'"))
    assert status(w.run(), "jobs") == "fail"


def test_hardening_script_path_must_exist_and_be_a_regular_file(w: World) -> None:
    for target in (w.t / "bin" / "missing.py", w.t / "bin"):
        folder(w.t / "bin")
        put(w.units / "a.service", unit(f"/usr/bin/python3 {target}"))
        found = w.run()
        assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


def test_hardening_assignment_value_that_is_a_path_is_checked(w: World) -> None:
    payload = put(w.home / "lib.so", "x")
    ok = put(w.t / "bin" / "ok.py", "x = 1\n")
    put(w.units / "a.service", unit(f"/usr/bin/env LD_PRELOAD={payload} {ok}"))
    found = w.run()
    assert status(found, "jobs") == "fail" and "home" in found["jobs"].text
    put(w.units / "a.service", unit(f"/usr/bin/env LD_PRELOAD={w.t}/bin/none.so {ok}"))
    assert status(w.run(), "jobs") == "fail"


@pytest.mark.parametrize("arg", ["*.py", "a?.py", "[ab].py", "{a,b}.py", "~/x.py", "!x.py", "x.py#c"])
def test_hardening_glob_brace_tilde_history_and_comment_characters_need_a_human(w: World, arg: str) -> None:
    ok = put(w.t / "bin" / "ok.sh", "true\n", 0o755)
    put(w.cron_d / "x", f"17 * * * * root {ok} {arg}\n")
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text
    put(w.cron_d / "x", f"17 * * * * root {ok}\n")
    assert status(w.run(), "jobs") == "pass"
    put(w.cron_d / "x", f"17 * * * * root /bin/sh {arg}\n")
    assert status(w.run(), "jobs") == "fail"
    put(w.cron_d / "x", f"17 * * * * root /usr/bin/python3 {arg}\n")
    assert status(w.run(), "jobs") == "fail"
    (w.cron_d / "x").unlink()
    put(w.units / "a.service", unit(f"/usr/bin/python3 {arg}"))
    assert status(w.run(), "jobs") == "fail"


@pytest.mark.parametrize("shell", ["sh", "bash", "dash"])
@pytest.mark.parametrize("flag", ["-s", "-u", "-i", "-l", "-su"])
def test_hardening_shell_flags_are_never_known_harmless(w: World, shell: str, flag: str) -> None:
    ok = put(w.t / "bin" / "ok.sh", "true\n", 0o755)
    put(w.units / "a.service", unit(f"/bin/{shell} {flag} {ok}"))
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


@pytest.mark.parametrize("program", ["sh", "bash", "dash"])
def test_hardening_shell_running_a_plain_script_path_is_followed(w: World, program: str) -> None:
    ok = put(w.t / "bin" / "ok.sh", "true\n", 0o755)
    put(w.units / "a.service", unit(f"/bin/{program} -- {ok}"))
    assert status(w.run(), "jobs") == "pass"


@pytest.mark.parametrize("argv", ["-", "-c x", "-e 1", "-S x", "-W error", "-X dev"])
def test_hardening_python_flags_that_read_stdin_or_run_text_need_a_human(w: World, argv: str) -> None:
    ok = put(w.t / "bin" / "ok.py", "x = 1\n")
    put(w.units / "a.service", unit(f"/usr/bin/python3 {argv} {ok}"))
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


@pytest.mark.parametrize("program", ["perl", "ruby", "node", "php", "lua"])
@pytest.mark.parametrize("flag", ["-", "-s", "-I", "-w", "-T"])
def test_hardening_other_interpreters_have_no_harmless_flags(w: World, program: str, flag: str) -> None:
    ok = put(w.t / "bin" / "ok.x", "x\n")
    put(w.units / "a.service", unit(f"/usr/bin/{program} {flag} {ok}"))
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


def test_hardening_wrapper_flags_are_a_short_list(w: World) -> None:
    ok = put(w.t / "bin" / "ok.sh", "true\n", 0o755)
    put(w.units / "a.service", unit(f"/usr/bin/env -i {ok}"))
    assert status(w.run(), "jobs") == "pass"
    for flag in ("-S", "-0", "-C"):
        put(w.units / "a.service", unit(f"/usr/bin/env {flag} {ok}"))
        assert status(w.run(), "jobs") == "fail"


@pytest.mark.parametrize(
    "line",
    [
        "StandardInput=tty",
        "StandardInput=tty-force",
        "StandardInput=socket",
        "StandardInput=data",
        "StandardInput=fd:x",
        "StandardInput=file:relative",
        "StandardInputText=echo hi",
        "StandardInputData=aGk=",
    ],
)
def test_hardening_standard_input_settings_need_a_human(w: World, line: str) -> None:
    put(w.units / "a.service", unit("/bin/true") + line + "\n")
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


def test_hardening_standard_input_null_or_unset_is_fine(w: World) -> None:
    put(w.units / "a.service", unit("/bin/true") + "StandardInput=null\n")
    put(w.units / "b.service", unit("/bin/true"))
    assert status(w.run(), "jobs") == "pass"


def test_hardening_standard_input_file_goes_through_the_path_checks(w: World) -> None:
    home_file = put(w.home / "in.txt", "x")
    put(w.units / "a.service", unit("/bin/true") + f"StandardInput=file:{home_file}\n")
    found = w.run()
    assert status(found, "jobs") == "fail" and "home" in found["jobs"].text
    writable = put(w.t / "wr" / "in.txt", "x", 0o666)
    put(w.units / "a.service", unit("/bin/true") + f"StandardInput=file:{writable}\n")
    assert status(w.run(), "jobs") == "fail"
    put(w.units / "a.service", unit("/bin/true") + f"StandardInput=file:{w.t}/none.txt\n")
    assert status(w.run(), "jobs") == "fail"
    safe = put(w.t / "bin" / "in.txt", "x")
    put(w.units / "a.service", unit("/bin/true") + f"StandardInput=file:{safe}\n")
    assert status(w.run(), "jobs") == "pass"


@pytest.mark.parametrize(
    "line",
    [
        "/usr/bin/env -i /bin/sh -s {ok}",
        "/usr/bin/env -i /bin/bash -i {ok}",
        "/usr/bin/env /bin/sh -u {ok}",
        "/usr/bin/env -i /usr/bin/perl -I {ok}",
        "/usr/bin/env /usr/bin/nice /bin/sh -s {ok}",
        "/usr/bin/env -i /usr/bin/python3 -W error {ok}",
        "/usr/bin/env -i /usr/bin/python3 - {ok}",
        "/usr/bin/env -i /bin/sh -c x",
        "/usr/bin/env -i /usr/bin/awk x",
        "/usr/bin/env -i",
    ],
)
def test_hardening_a_nested_program_gets_its_own_flag_rules(w: World, line: str) -> None:
    ok = put(w.t / "bin" / "ok.sh", "true\n", 0o755)
    put(w.units / "a.service", unit(line.format(ok=ok)))
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


def test_hardening_a_nested_program_with_flags_from_its_own_table_passes(w: World) -> None:
    ok = put(w.t / "bin" / "ok.py", "x = 1\n")
    put(w.units / "a.service", unit(f"/usr/bin/env -i /usr/bin/python3 -I -B {ok}"))
    put(w.units / "b.service", unit(f"/usr/bin/env FOO=1 /usr/bin/nice /usr/bin/python3 -s {ok}"))
    assert status(w.run(), "jobs") == "pass"


def test_hardening_a_nested_script_in_the_home_is_still_found(w: World) -> None:
    payload = put(w.home / "p.sh", "true\n", 0o755)
    put(w.units / "a.service", unit(f"/usr/bin/env -i /bin/sh -- {payload}"))
    found = w.run()
    assert status(found, "jobs") == "fail" and "home" in found["jobs"].text


@pytest.mark.parametrize(
    "line",
    [
        "/usr/bin/timeout 5 /bin/true",
        "/usr/bin/timeout -s KILL 5 /bin/true",
        "/usr/bin/flock {lock} /bin/sh -s {ok}",
        "/usr/bin/flock -n {lock} {ok}",
        "/usr/bin/flock {lock} -c x",
        "/usr/bin/flock {lock} sh {ok}",
        "/usr/bin/ionice -c3 {ok}",
        "/usr/bin/stdbuf -oL {ok}",
        "/usr/bin/env -i /usr/bin/timeout 5 {ok}",
        "/usr/bin/env -i /usr/bin/flock {lock} /bin/sh -s {ok}",
        "/usr/bin/env -i {plain}",
        "/usr/bin/nice -n 5 {ok}",
    ],
)
def test_hardening_wrappers_with_their_own_positional_arguments_need_a_human(w: World, line: str) -> None:
    ok = put(w.t / "bin" / "ok.sh", "true\n", 0o755)
    lock = put(w.t / "bin" / "x.lock", "")
    plain = put(w.t / "bin" / "plain.txt", "x", 0o644)
    put(w.units / "a.service", unit(line.format(ok=ok, lock=lock, plain=plain)))
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


def test_hardening_a_plain_wrapper_still_runs_an_executable_through_the_path_checks(w: World) -> None:
    ok = put(w.t / "bin" / "ok.sh", "true\n", 0o755)
    put(w.units / "a.service", unit(f"/usr/bin/env -i /usr/bin/nice {ok}"))
    assert status(w.run(), "jobs") == "pass"


# -- hardening, merged units and the rest ------------------------------------------------------------


def dropin(w: World, unit_name: str, conf: str, text: str, where: Path | None = None) -> None:
    put((where or w.units) / f"{unit_name}.d" / conf, text)


def test_hardening_a_drop_in_that_makes_the_unit_run_as_root_is_merged(w: World) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "a.service", unit(str(payload), user="maint"))
    assert status(w.run(), "jobs") == "pass"
    dropin(w, "a.service", "10-root.conf", "[Service]\nUser=root\n")
    found = w.run()
    assert status(found, "jobs") == "fail" and "10-root.conf" in found["jobs"].text


def test_hardening_a_drop_in_that_drops_root_or_clears_the_command_is_merged(w: World) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "a.service", unit(str(payload)))
    assert status(w.run(), "jobs") == "fail"
    dropin(w, "a.service", "10-user.conf", "[Service]\nUser=nobody\n")
    assert status(w.run(), "jobs") == "pass"
    (w.units / "a.service.d" / "10-user.conf").unlink()
    dropin(w, "a.service", "10-clear.conf", "[Service]\nExecStart=\nExecStart=/bin/true\n")
    assert status(w.run(), "jobs") == "pass"


def test_hardening_drop_ins_apply_in_file_name_order_across_folders(w: World) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    other = folder(w.t / "units2")
    put(w.units / "a.service", unit(str(payload)))
    dropin(w, "a.service", "20-b.conf", "[Service]\nUser=nobody\n")
    dropin(w, "a.service", "10-a.conf", "[Service]\nUser=root\n", other)
    assert status(w.run(unit_dirs=(w.units, other)), "jobs") == "pass"  # 20 wins: not root
    dropin(w, "a.service", "30-c.conf", "[Service]\nUser=root\n", other)
    assert status(w.run(unit_dirs=(w.units, other)), "jobs") == "fail"  # 30 wins: root


@pytest.mark.parametrize("folder_name", ["service.d", "a-.service.d", "a-b.service.d"])
def test_hardening_type_and_prefix_drop_ins_apply_to_matching_units(w: World, folder_name: str) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "a-b.service", unit(str(payload), user="maint"))
    put(w.units / folder_name / "10-root.conf", "[Service]\nUser=root\n")
    assert status(w.run(), "jobs") == "fail"


def test_hardening_a_prefix_drop_in_does_not_apply_to_other_units(w: World) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "c.service", unit(str(payload), user="maint"))
    put(w.units / "a-.service.d" / "10-root.conf", "[Service]\nUser=root\n")
    assert status(w.run(), "jobs") == "pass"


def test_hardening_a_drop_in_without_a_base_unit_is_judged_by_itself(w: World) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    dropin(w, "lonely.service", "10-x.conf", unit(str(payload)))
    assert status(w.run(), "jobs") == "fail"


def test_hardening_the_last_standard_input_assignment_wins(w: World) -> None:
    infile = put(w.home / "in.txt", "x")
    put(w.units / "a.service", unit("/bin/true") + f"StandardInput=file:{infile}\n")
    assert status(w.run(), "jobs") == "fail"
    dropin(w, "a.service", "10-x.conf", "[Service]\nStandardInput=null\n")
    assert status(w.run(), "jobs") == "pass"


@pytest.mark.parametrize(
    "tail",
    [
        "-jar {payload}",
        "--classpath={payload}",
        "-cp{payload}",
        "-Dx={payload}",
        "run {payload}",
    ],
)
def test_hardening_an_unknown_program_has_every_argument_looked_at(w: World, tail: str) -> None:
    payload = put(w.home / "root.jar", "x")
    put(w.units / "a.service", unit("/bin/true " + tail.format(payload=payload)))
    assert status(w.run(), "jobs") == "fail"


@pytest.mark.parametrize(
    "tail", ["-jar rel.jar", "start", "--path=rel/x", "$X", "/nonexistent/file", "-v /nonexistent"]
)
def test_hardening_an_unknown_program_with_unplaceable_arguments_needs_a_human(w: World, tail: str) -> None:
    put(w.units / "a.service", unit("/bin/true " + tail))
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


def test_hardening_an_unknown_program_with_plain_arguments_passes(w: World) -> None:
    conf = put(w.t / "bin" / "x.conf", "x")
    put(w.units / "a.service", unit(f"/bin/true -D --port=80 --config={conf} 5 {w.t / 'bin'}"))
    assert status(w.run(), "jobs") == "pass"


def test_hardening_sudoers_from_a_non_file_source_fails_closed(w: World) -> None:
    for line in ("sudoers: files sss", "sudoers: sss", "sudoers: ldap files", "sudoers:"):
        put(w.nss, f"passwd: files\ngroup: files\n{line}\n")
        found = w.run()
        assert status(found, "sudo") == "fail" and "source other than local files" in found["sudo"].text
        assert status(found, "groups") == "pass"
    put(w.nss, "passwd: files\ngroup: files\nsudoers: files [SUCCESS=return]\n")
    assert status(w.run(), "sudo") == "pass"


def test_hardening_default_paths_cover_the_remaining_unit_and_generator_locations() -> None:
    d = DoorPaths()
    for name in ("system.control", "system.attached"):
        assert Path("/run/systemd") / name in d.unit_dirs
        assert Path("/etc/systemd") / name in d.unit_dirs
        assert Path("/run/systemd") / name in d.writable_roots
    for base in ("/usr/lib", "/usr/local/lib", "/run"):
        assert Path(base) / "systemd" / "system-generators" in d.writable_roots
    assert Path("/usr/share/polkit-1/actions") in d.polkit_action_dirs


def test_hardening_a_generator_the_account_can_write_fails(w: World) -> None:
    gen = folder(w.t / "gens")
    put(gen / "g", "#!/bin/sh\n", 0o777)
    assert status(w.run(writable_roots=(gen,)), "writable") == "fail"


def test_hardening_a_writable_folder_above_a_generator_folder_fails(w: World) -> None:
    parent = folder(w.t / "sysd", 0o777)
    gen = folder(parent / "system-generators")
    assert status(w.run(writable_roots=(gen,)), "writable") == "fail"


def policy(*defaults: str) -> str:
    return '<policyconfig><action id="a"><defaults>' + "".join(defaults) + "</defaults></action></policyconfig>"


@pytest.mark.parametrize("which", ["allow_any", "allow_inactive", "allow_active"])
def test_hardening_an_action_default_that_needs_no_authentication_fails(w: World, which: str) -> None:
    put(w.t / "actions" / "x.policy", policy(f"<{which}>yes</{which}>"))
    found = w.run()
    assert status(found, "polkit") == "fail" and "x.policy" in found["polkit"].text
    assert "grants an active user" in found["polkit"].text


def test_hardening_action_defaults_that_ask_for_authentication_pass(w: World) -> None:
    text = policy(
        "<allow_any>no</allow_any>",
        "<allow_inactive>auth_admin</allow_inactive>",
        "<allow_active>auth_admin_keep</allow_active>",
    )
    put(w.t / "actions" / "x.policy", "<!-- <allow_active>yes</allow_active> -->" + text)
    assert status(w.run(), "polkit") == "pass"


@pytest.mark.parametrize(
    "text",
    [
        policy("<allow_active>sometimes</allow_active>"),
        policy("<allow_active>&amp;</allow_active>"),
        policy("<allow_active>yes"),
        "<![CDATA[x]]>" + policy("<allow_active>no</allow_active>"),
        '<!DOCTYPE x [<!ENTITY e "yes">]>' + policy("<allow_active>&e;</allow_active>"),
    ],
)
def test_hardening_an_action_policy_it_cannot_read_needs_a_human(w: World, text: str) -> None:
    put(w.t / "actions" / "x.policy", text)
    assert status(w.run(), "polkit") == "fail"


def test_hardening_reads_do_not_move_access_times(w: World) -> None:
    files = [w.passwd, w.group, w.sudoers, w.polkit / "a.rules"]
    put(files[-1], "")
    for path in files:
        os.utime(path, ns=(10**9, 2 * 10**9))
    before = [os.stat(p).st_atime_ns for p in files]
    w.run()
    assert [os.stat(p).st_atime_ns for p in files] == before


def test_hardening_reads_ask_for_no_access_time_update_and_fall_back_when_refused(
    w: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    noatime = getattr(os, "O_NOATIME", 0)
    if not noatime:
        pytest.skip("this platform has no O_NOATIME")
    real_open = os.open
    seen: list[int] = []

    def refuse(path: Any, flags: int, *args: Any, **kw: Any) -> int:
        if str(path).startswith(str(w.t)) and not flags & (os.O_DIRECTORY):
            seen.append(flags)
            if flags & noatime:
                raise PermissionError(errno.EPERM, "refused")
        return real_open(path, flags, *args, **kw)

    monkeypatch.setattr(os, "open", refuse)
    found = w.run()
    assert seen and any(f & noatime for f in seen) and any(not f & noatime for f in seen)
    assert status(found, "sudo") == "pass"


# -- hardening, unit merging details ----------------------------------------------


@pytest.mark.parametrize("prefix", ["+", "!", "!!", "-+", "+-"])
def test_hardening_elevated_command_prefixes_run_as_root_whatever_the_user(w: World, prefix: str) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "a.service", unit(prefix + str(payload), user="nobody"))
    assert status(w.run(), "jobs") == "fail"


def test_hardening_a_plain_command_of_another_user_is_not_a_root_job(w: World) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "a.service", unit(str(payload), user="nobody"))
    assert status(w.run(), "jobs") == "pass"


@pytest.mark.parametrize("key", ["ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload"])
def test_hardening_permissions_start_only_makes_the_other_commands_root(w: World, key: str) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    text = f"[Service]\nUser=nobody\nExecStart=/bin/true\n{key}={payload}\n"
    put(w.units / "a.service", text)
    assert status(w.run(), "jobs") == "pass"
    put(w.units / "a.service", text + "PermissionsStartOnly=true\n")
    assert status(w.run(), "jobs") == "fail"
    put(w.units / "a.service", text + "PermissionsStartOnly=true\nPermissionsStartOnly=false\n")
    assert status(w.run(), "jobs") == "pass"


def test_hardening_files_the_manager_reads_count_whoever_the_user_is(w: World) -> None:
    put(w.units / "a.service", unit("/bin/true", user="nobody") + f"EnvironmentFile={w.home}/env\n")
    assert status(w.run(), "jobs") == "fail"


def test_hardening_only_the_service_section_is_read(w: World) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "a.service", f"[Unit]\nUser=root\nExecStart={payload}\n[Service]\nUser=nobody\nExecStart={payload}\n")
    assert status(w.run(), "jobs") == "pass"
    put(w.units / "a.service", f"User=root\nExecStart={payload}\n")
    assert status(w.run(), "jobs") == "pass"
    dropin(w, "a.service", "10-x.conf", "[Install]\nUser=root\n[Service]\nExecStart=\n")
    assert status(w.run(), "jobs") == "pass"
    put(w.units / "b.service", f"[Service]\nExecStart={payload}\n")
    assert status(w.run(), "jobs") == "fail"


def test_hardening_a_shadowed_drop_in_is_reported_apart_and_never_merged(w: World) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    high = folder(w.t / "high")
    put(w.units / "a.service", unit(str(payload), user="nobody"))
    dropin(w, "a.service", "10-x.conf", "[Service]\nUser=nobody\n", high)
    assert status(w.run(unit_dirs=(high, w.units)), "jobs") == "pass"
    dropin(w, "a.service", "10-x.conf", "[Service]\nUser=root\n")  # lower priority: shadowed, would change User
    found = w.run(unit_dirs=(high, w.units))
    assert status(found, "jobs") == "fail" and "shadows" in found["jobs"].text and "needs to look" in found["jobs"].text
    assert "runs" not in found["jobs"].text and "home" not in found["jobs"].text  # the effective unit is clean


def test_hardening_the_higher_folder_file_is_the_effective_one(w: World) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    high = folder(w.t / "high")
    put(w.units / "a.service", unit(str(payload), user="nobody"))
    dropin(w, "a.service", "10-x.conf", "[Service]\nUser=root\n", high)
    dropin(w, "a.service", "10-x.conf", "[Service]\nUser=nobody\n")
    found = w.run(unit_dirs=(high, w.units))
    assert (
        status(found, "jobs") == "fail" and "home" in found["jobs"].text
    )  # root is effective, and also shadow-reported
    assert "shadows" in found["jobs"].text


def test_hardening_socket_unit_commands_run_as_root_and_their_drop_ins_are_read(w: World) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "a.socket", f"[Socket]\nListenStream=/run/x\nExecStartPre={payload}\n")
    assert status(w.run(), "jobs") == "fail"
    put(w.units / "a.socket", "[Socket]\nListenStream=/run/x\n")
    assert status(w.run(), "jobs") == "pass"
    put(w.units / "a.socket.d" / "10-x.conf", f"[Socket]\nExecStopPost={payload}\n")
    found = w.run()
    assert status(found, "jobs") == "fail" and "10-x.conf" in found["jobs"].text
    (w.units / "a.socket.d" / "10-x.conf").unlink()
    put(w.units / "socket.d" / "10-y.conf", f"[Socket]\nExecStartChown={payload}\n")
    assert status(w.run(), "jobs") == "fail"


def test_hardening_drop_in_folders_for_unread_unit_types_are_reported(w: World) -> None:
    folder(w.units / "a.timer.d")
    found = w.run()
    assert status(found, "jobs") == "warn" and "a.timer.d" in found["jobs"].text
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "b.service", unit(str(payload)))
    assert status(w.run(), "jobs") == "fail"


def test_hardening_a_template_instance_uses_the_template_base_and_both_drop_ins(w: World) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "t@.service", unit(str(payload), user="nobody"))
    assert status(w.run(), "jobs") == "pass"
    dropin(w, "t@x.service", "10-root.conf", "[Service]\nUser=root\n")
    found = w.run()
    assert status(found, "jobs") == "fail" and "t@x.service" in found["jobs"].text
    (w.units / "t@x.service.d" / "10-root.conf").unlink()
    dropin(w, "t@.service", "10-root.conf", "[Service]\nUser=root\n")
    assert status(w.run(), "jobs") == "fail"


def test_hardening_a_prefix_drop_in_reaches_a_template_instance(w: World) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "t-u@.service", unit(str(payload), user="nobody"))
    dropin(w, "t-u@x.service", "10-a.conf", "[Service]\nEnvironment=A=1\n")
    assert status(w.run(), "jobs") == "pass"
    put(w.units / "t-.service.d" / "10-root.conf", "[Service]\nUser=root\n")
    assert status(w.run(), "jobs") == "fail"


def test_hardening_a_template_instance_without_its_template_base_fails_closed(w: World) -> None:
    dropin(w, "t@x.service", "10-a.conf", "[Service]\nUser=nobody\n")
    found = w.run()
    assert status(found, "jobs") == "fail" and "template base file is missing" in found["jobs"].text


def test_hardening_an_instance_file_of_its_own_is_used_before_the_template(w: World) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "t@.service", unit("/bin/true"))
    put(w.units / "t@x.service", unit(str(payload)))
    assert status(w.run(), "jobs") == "fail"


def test_hardening_a_folder_argument_with_a_writable_entry_fails(w: World) -> None:
    data = folder(w.t / "data")
    put(data / "ok", "x")
    put(w.units / "a.service", unit(f"/bin/true {data}"))
    assert status(w.run(), "jobs") == "pass"
    put(data / "bad", "x", 0o666)
    found = w.run()
    assert status(found, "jobs") == "fail" and "can write" in found["jobs"].text


def test_hardening_a_folder_argument_with_a_link_into_reach_fails(w: World) -> None:
    data = folder(w.t / "data")
    (data / "l").symlink_to(w.home)
    put(w.units / "a.service", unit(f"/bin/true {data}"))
    assert status(w.run(), "jobs") == "fail"
    (data / "l").unlink()
    (data / "l").symlink_to(w.t / "nowhere")
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


def test_hardening_a_folder_argument_with_a_nested_writable_entry_fails(w: World) -> None:
    data = folder(w.t / "data")
    folder(data / "a" / "b")
    put(data / "a" / "b" / "c", "x", 0o666)
    put(w.units / "a.service", unit(f"/bin/true {data}"))
    assert status(w.run(), "jobs") == "fail"


def test_hardening_a_folder_argument_too_big_to_walk_needs_a_human(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    data = folder(w.t / "data")
    for i in range(5):
        put(data / f"f{i}", "x")
    monkeypatch.setattr(doors, "FOLDER_ENTRY_LIMIT", 3)
    put(w.units / "a.service", unit(f"/bin/true {data}"))
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


@needs_nonroot
def test_hardening_an_unreadable_folder_argument_needs_a_human(w: World) -> None:
    data = folder(w.t / "data")
    folder(data / "locked", 0o000)
    put(w.units / "a.service", unit(f"/bin/true {data}"))
    try:
        assert status(w.run(), "jobs") == "fail"
    finally:
        (data / "locked").chmod(0o755)


def test_hardening_a_link_to_a_folder_inside_a_folder_argument_needs_a_human(w: World) -> None:
    data = folder(w.t / "data")
    inner = folder(w.t / "elsewhere")
    (data / "l").symlink_to(inner)
    put(w.units / "a.service", unit(f"/bin/true {data}"))
    found = w.run()
    assert status(found, "jobs") == "fail" and "to a folder" in found["jobs"].text


def test_hardening_a_link_to_a_folder_cycle_does_not_hang(w: World) -> None:
    data = folder(w.t / "data")
    (data / "self").symlink_to(data)
    put(w.units / "a.service", unit(f"/bin/true {data}"))
    assert status(w.run(), "jobs") == "fail"


# -- hardening, round 6 ------------------------------------------------------------


def test_hardening_a_cron_link_to_a_file_in_the_home_fails(w: World) -> None:
    target = put(w.home / "evil-crontab", "17 * * * * root /bin/true\n")
    (w.cron_d / "evil").symlink_to(target)
    found = w.run()
    assert status(found, "jobs") == "fail" and "home" in found["jobs"].text


def test_hardening_a_cron_link_to_a_writable_folder_fails(w: World) -> None:
    writable = folder(w.t / "wr", 0o777)
    target = put(writable / "tab", "# nothing\n")
    (w.cron_d / "evil").symlink_to(target)
    assert status(w.run(), "jobs") == "fail"


def test_hardening_a_cron_link_to_a_safe_file_is_read_like_the_file(w: World) -> None:
    safe = put(w.t / "lib" / "tab", "17 * * * * root /bin/true\n")
    (w.cron_d / "ok").symlink_to(safe)
    assert status(w.run(), "jobs") == "pass"
    script = put(w.t / "bin" / "s.sh", "#!/bin/sh\n", 0o666)
    bad = put(w.t / "lib" / "bad", f"17 * * * * root {script}\n")
    (w.cron_d / "bad").symlink_to(bad)
    assert status(w.run(), "jobs") == "fail"


def test_hardening_a_cron_link_that_does_not_resolve_or_is_not_a_file_needs_a_human(w: World) -> None:
    (w.cron_d / "dangling").symlink_to(w.t / "nowhere")
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text
    (w.cron_d / "dangling").unlink()
    (w.cron_d / "dir").symlink_to(folder(w.t / "somedir"))
    assert status(w.run(), "jobs") == "fail"


def test_hardening_a_linked_cron_file_in_the_file_list_is_followed(w: World) -> None:
    target = put(w.home / "evil-crontab", "# nothing\n")
    w.crontab.unlink()
    w.crontab.symlink_to(target)
    assert status(w.run(), "jobs") == "fail"


@pytest.mark.parametrize("value", ['"root"', "'root'", ' "root" ', "'0'", '"0"', '"ro\\ot"', '"root', "root'"])
def test_hardening_quoted_user_values_are_read_as_systemd_reads_them(w: World, value: str) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "a.service", f"[Service]\nUser={value}\nExecStart={payload}\n")
    assert status(w.run(), "jobs") == "fail"


@pytest.mark.parametrize("value", ['"nobody"', "'nobody'", " nobody "])
def test_hardening_a_quoted_other_user_is_still_not_root(w: World, value: str) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "a.service", f"[Service]\nUser={value}\nExecStart={payload}\n")
    assert status(w.run(), "jobs") == "pass"


def test_hardening_other_quoted_unit_values_are_unquoted(w: World) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "a.service", f'[Service]\nUser="nobody"\nExecStart=/bin/true\nEnvironmentFile="{w.home}/env"\n')
    assert status(w.run(), "jobs") == "fail"
    put(w.units / "a.service", f'[Service]\nUser="nobody"\nPermissionsStartOnly="true"\nExecStartPre={payload}\n')
    assert status(w.run(), "jobs") == "fail"
    put(w.units / "a.service", f'[Service]\nStandardInput="file:{w.home}/in"\nExecStart=/bin/true\n')
    assert status(w.run(), "jobs") == "fail"


def test_hardening_listing_folders_leaves_their_access_times_alone(w: World) -> None:
    folders = [w.etc, w.polkit, w.cron_d, w.units, w.sudoers_d, w.usr]
    put(w.etc / "f", "x")
    for d in folders:
        os.utime(d, ns=(10**9, 2 * 10**9))
    before = [os.stat(d).st_atime_ns for d in folders]
    w.run()
    assert [os.stat(d).st_atime_ns for d in folders] == before


def test_hardening_folder_listings_ask_for_no_access_time_update_and_fall_back(
    w: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    noatime = getattr(os, "O_NOATIME", 0)
    if not noatime:
        pytest.skip("this platform has no O_NOATIME")
    real_open = os.open
    seen: list[int] = []

    def open_folder(path: Any, flags: int, *args: Any, **kw: Any) -> int:
        if str(path).startswith(str(w.t)) and flags & os.O_DIRECTORY:
            seen.append(flags)
            if flags & noatime:
                raise PermissionError(errno.EPERM, "refused")
        return real_open(path, flags, *args, **kw)

    monkeypatch.setattr(os, "open", open_folder)
    found = w.run()
    assert any(f & noatime for f in seen) and any(not f & noatime for f in seen)
    assert status(found, "jobs") == "pass"


def test_hardening_a_writable_intermediate_link_hop_is_found_for_cron_and_units(w: World) -> None:
    writable = folder(w.t / "wr", 0o777)
    safe = put(w.t / "lib" / "tab", "17 * * * * root /bin/true\n")
    (writable / "hop").symlink_to(safe)
    (w.cron_d / "x").symlink_to(writable / "hop")
    found = w.run()
    assert status(found, "jobs") == "fail" and "hop" in found["jobs"].text
    (w.cron_d / "x").unlink()
    unit_file = put(w.t / "lib" / "u.service", unit("/bin/true"))
    (writable / "uhop").symlink_to(unit_file)
    (w.units / "a.service").symlink_to(writable / "uhop")
    found = w.run()
    assert status(found, "jobs") == "fail" and "uhop" in found["jobs"].text


def test_hardening_a_hop_in_a_folder_the_account_owns_is_found_even_if_the_ends_are_safe(w: World) -> None:
    mine = folder(w.t / "mine", 0o700)
    safe = put(w.t / "lib" / "tab", "# nothing\n")
    (mine / "hop").symlink_to(safe)
    (w.cron_d / "x").symlink_to(mine / "hop")
    assert status(w.run(), "jobs") == "pass"
    put(w.passwd, f"maint:x:{UID}:{GID + 7}::{w.home}:/bin/bash\n")
    assert status(w.run(who=UID), "jobs") == "fail"


def test_hardening_link_chains_are_bounded_and_loops_need_a_human(w: World) -> None:
    safe = put(w.t / "lib" / "tab", "# nothing\n")
    previous = safe
    for index in range(doors.MAX_LINK_HOPS + 2):
        link = w.t / "chain" / f"l{index}"
        link.parent.mkdir(exist_ok=True)
        link.symlink_to(previous)
        previous = link
    (w.cron_d / "x").symlink_to(previous)
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text
    (w.cron_d / "x").unlink()
    (w.t / "loop-a").symlink_to(w.t / "loop-b")
    (w.t / "loop-b").symlink_to(w.t / "loop-a")
    (w.cron_d / "y").symlink_to(w.t / "loop-a")
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


def test_hardening_a_short_clean_link_chain_passes_and_a_masked_unit_still_does(w: World) -> None:
    safe = put(w.t / "lib" / "tab", "17 * * * * root /bin/true\n")
    (w.t / "lib" / "one").symlink_to(safe)
    (w.cron_d / "x").symlink_to(w.t / "lib" / "one")
    (w.units / "masked.service").symlink_to("/dev/null")
    assert status(w.run(), "jobs") == "pass"


# -- hardening, round 7 ------------------------------------------------------------


def add_account(w: World, line: str) -> None:
    put(w.passwd, w.passwd.read_text() + line + "\n")


@pytest.mark.parametrize("user", ["toor", "0", "00", "+0", '"toor"'])
def test_hardening_a_unit_user_that_maps_to_uid_zero_is_root(w: World, user: str) -> None:
    add_account(w, "toor:x:0:0::/root:/bin/sh")
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "a.service", unit(str(payload), user=user))
    assert status(w.run(), "jobs") == "fail"


@pytest.mark.parametrize("user", ["nobody", "other", "65534", "1000"])
def test_hardening_known_and_numeric_other_users_are_not_root(w: World, user: str) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    put(w.units / "a.service", unit(str(payload), user=user))
    assert status(w.run(), "jobs") == "pass"


@pytest.mark.parametrize("user", ["ghost", "-1", "a b", "0x0"])
def test_hardening_a_unit_user_nobody_can_place_needs_a_human(w: World, user: str) -> None:
    put(w.units / "a.service", unit("/bin/true", user=user))
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


def test_hardening_a_cron_user_that_maps_to_uid_zero_is_root(w: World) -> None:
    add_account(w, "toor:x:0:0::/root:/bin/sh")
    payload = put(w.home / "payload", "x", 0o755)
    put(w.cron_d / "x", f"@reboot toor {payload}\n")
    assert status(w.run(), "jobs") == "fail"
    put(w.cron_d / "x", f"17 * * * * toor {payload}\n")
    assert status(w.run(), "jobs") == "fail"
    put(w.cron_d / "x", f"17 * * * * 0 {payload}\n")
    assert status(w.run(), "jobs") == "fail"


def test_hardening_a_cron_user_that_is_known_and_not_root_is_skipped_and_unknown_needs_a_human(w: World) -> None:
    payload = put(w.home / "payload", "x", 0o755)
    put(w.cron_d / "x", f"17 * * * * other {payload}\n")
    assert status(w.run(), "jobs") == "pass"
    put(w.cron_d / "x", f"17 * * * * ghost {payload}\n")
    found = w.run()
    assert status(found, "jobs") == "fail" and "needs to look" in found["jobs"].text


def test_hardening_a_walk_does_not_enter_another_device(w: World, monkeypatch: pytest.MonkeyPatch) -> None:
    mnt = folder(w.etc / "mnt")
    put(mnt / "inside", "x", 0o666)  # would be a finding if the walk entered
    real = os.lstat

    def fake(path: Any, *args: Any, **kw: Any) -> os.stat_result:
        info = real(path, *args, **kw)
        if str(path) == str(mnt):
            values = list(info)[:10]
            values[2] += 1  # st_dev
            return os.stat_result(values)
        return info

    monkeypatch.setattr(os, "lstat", fake)
    found = w.run()
    assert status(found, "writable") == "fail" and "mount point" in found["writable"].text
    assert "inside" not in found["writable"].text and "needs to look" in found["writable"].text


def test_hardening_the_setuid_and_polkit_walks_do_not_enter_another_device(
    w: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    mnt = folder(w.usr / "mnt")
    real = os.lstat

    def fake(path: Any, *args: Any, **kw: Any) -> os.stat_result:
        info = real(path, *args, **kw)
        if str(path) == str(mnt):
            values = list(info)[:10]
            values[2] += 1
            return os.stat_result(values)
        return info

    monkeypatch.setattr(os, "lstat", fake)
    assert status(w.run(), "setuid") == "fail"
