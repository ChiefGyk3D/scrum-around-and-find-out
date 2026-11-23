# SPDX-License-Identifier: Apache-2.0
"""rmguard against the real shell and the real tools, with disposable sentinel files (#422, Daybreak round 1).

The property: if real bash, running the command, removed or emptied a sentinel file that sits in a shared zone (and
not under `agents/<name>/`), then rmguard denied the original command text. The other half: commands that touch only
files below an agent folder or outside the zones are allowed (and really do change something, so the allow cases
bite as well).

Everything runs in a throwaway home under pytest's tmp_path. Nothing outside it is touched. A tool that is missing
(`git`, `rsync`, `tar`, `truncate`, `find`, `bash`) is a failure under CI (the `CI` environment variable is set) and a
skip of that case elsewhere: a silent skip would turn the check off without anyone noticing.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

import gitrepo
import rmguard_shell
from safo import rmguard

CI = bool(os.environ.get("CI"))

# (command template, cwd template). {D} dev zone, {W} work dir outside, {R} git repo inside the zone, {A} agent work
# folder inside the zone, {H} home. Every one removes or empties at least one shared sentinel.
DENIED = [
    # plain deleters and wrappers
    ("rm {D}/a.log", "{W}"),
    ("rm -rf {D}/sub", "{W}"),
    ("cd {D} && rm -rf *.log", "{W}"),
    ("rm>/dev/null {D}/a.log", "{W}"),
    ("2>&1 rm {D}/a.log", "{W}"),
    ("env rm -rf {D}/sub", "{W}"),
    ("nice rm {D}/a.log", "{W}"),
    ("timeout 5 rm {D}/a.log", "{W}"),
    ("bash -c 'rm {D}/a.log'", "{W}"),
    ("eval 'rm {D}/a.log'", "{W}"),
    ("printf '%s\\n' {D}/a.log | xargs rm", "{W}"),
    ("env -C {D} rm a.log", "{W}"),
    ("env -S 'rm {D}/a.log'", "{W}"),
    ("(cd {D}; rm a.log)", "{W}"),
    ("cd {D} && (cd {W}); rm a.log", "{W}"),
    ("r''m {D}/a.log", "{W}"),
    ("\\rm {D}/a.log", "{W}"),
    ("$'r\\x6d' {D}/a.log", "{W}"),
    ("/bin/r[m] {D}/a.log", "{W}"),
    ("shred -u {D}/a.log", "{W}"),
    ("unlink {D}/a.log", "{W}"),
    # find: every global option and layout
    ("find {D} -name a.log -delete", "{W}"),
    ("find -H {D} -name a.log -delete", "{W}"),
    ("find -L {D} -name a.log -delete", "{W}"),
    ("find -P {D} -name a.log -delete", "{W}"),
    ("find -O3 {D} -name a.log -delete", "{W}"),
    ("find -D tree {D} -name a.log -delete", "{W}"),
    ("find -H -L -P -O2 {D} -name a.log -delete", "{W}"),
    ("find -files0-from {W}/list0 -name a.log -delete", "{W}"),
    ("find -name a.log -delete", "{D}"),
    ("find -H -name a.log -delete", "{D}"),
    ("find . -name a.log -delete", "{D}"),
    ("find {D} -name a.log -exec rm {{}} +", "{W}"),
    ("find -H {D} -name a.log -exec env rm {{}} +", "{W}"),
    ("find {D} -name a.log -execdir rm {{}} \\;", "{W}"),
    # git clean, with the cwd in the zone
    ("git clean -fdx", "{R}"),
    ("git clean -fd -- u.log", "{R}"),
    ("git -C {R} clean -fd", "{W}"),
    # other programs
    ("truncate -s 0 {D}/a.log", "{W}"),
    ("truncate -s0 *.log", "{D}"),
    ("rsync -a --delete {W}/empty/ {D}/sub/", "{W}"),
    ("rsync -a --remove-source-files {D}/sub/b.log {W}/out/", "{W}"),
    ("tar --remove-files -cf {W}/x.tar -C {D} sub", "{W}"),
    ("mv {D}/a.log {W}/", "{W}"),
    ("mv {W}/a.log {D}/a.log", "{W}"),
    ("mv -t {D} {W}/a.log", "{W}"),
    ("cp /dev/null {D}/a.log", "{W}"),
    ("dd if=/dev/null of={D}/a.log 2>/dev/null", "{W}"),
    # truncating redirections
    ("> {D}/a.log", "{W}"),
    (": > {D}/a.log", "{W}"),
    ("echo x > {D}/a.log", "{W}"),
    ("true >| {D}/a.log", "{W}"),
    ("echo x &> {D}/a.log", "{W}"),
    (": > a.log", "{D}"),
    ("{{ :; }} > {D}/a.log", "{W}"),
    # variables bound conditionally, in a pipe, a subshell, the background, eval or a function
    ("S={D}; false && S={W}; rm -rf $S/sub", "/"),
    ("S={D}; true || S={W}; rm -rf $S/sub", "/"),
    ("S={D}; S={W} | cat; rm -rf $S/sub", "/"),
    ("S={D}; (S={W}); rm -rf $S/sub", "/"),
    ("S={D}; S={W} & wait; rm -rf $S/sub", "/"),
    ("S={W}; eval 'S={D}'; rm -rf $S/sub", "/"),
    ("f() {{ S={D}; }}; S={W}; f; rm -rf $S/sub", "/"),
    # arithmetic that runs a substitution
    ("echo $(( $(rm {D}/a.log; echo 1) + 1 ))", "{W}"),
    # HOME changed
    ("HOME={D}; rm ~/a.log", "{W}"),
    ("export HOME={D}; rm ~/a.log", "{W}"),
    ("declare HOME={D}; rm ~/a.log", "{W}"),
    ("printf -v HOME %s {D}; rm ~/a.log", "{W}"),
    ("read HOME <<< {D}; rm ~/a.log", "{W}"),
    # round 3 (Daybreak round 2): the zone name quoted or escaped, from the parent folder
    ("truncate -s 0 reach-around-d''ev/a.log", "{S}"),
    ("truncate -s 0 reach-around-d\\ev/a.log", "{S}"),
    ("git -C reach-around-d\\ev/repo clean -fd", "{S}"),
    ("mv ~/.lo''cal/share/reach-around-d''ev/a.log {W}/", "{W}"),
    (": > reach-around-d\\ev/a.log", "{S}"),
    # git: aliases, GIT_* variables, other destructive subcommands
    ("git -C {R} config alias.wipe clean; git -C {R} wipe -fdx", "{W}"),
    ("git -c alias.wipe=clean -C {R} wipe -fdx", "{W}"),
    ("GIT_WORK_TREE={R} GIT_DIR={R}/.git git clean -fdx", "{W}"),
    ("export GIT_WORK_TREE={R}; export GIT_DIR={R}/.git; git clean -fdx", "{W}"),
    ("git --git-dir={R}/.git --work-tree={R} clean -fdx", "{W}"),
    ("env GIT_WORK_TREE={R} GIT_DIR={R}/.git git clean -fdx", "{W}"),
    ("git -C {R} rm -q t.txt", "{W}"),
    ("git -C {R} clean -fd -e -n", "{W}"),
    ("git -C {R} clean -fde x", "{W}"),
    ("git -C {R} clean -fd --exclude=-n", "{W}"),
    # other writers that replace or edit an existing protected file
    ("sed -i 's/.*/gone/' {D}/a.log", "{W}"),
    ("sed -i.bak -e 's/S/T/' {D}/a.log", "{W}"),
    ("perl -pi -e '$_=\"\"' {D}/a.log", "{W}"),
    ("perl -i.bak -pe 's/S/T/' {D}/a.log", "{W}"),
    ("install -m 644 {W}/a.log {D}/a.log", "{W}"),
    ("ln -sf {W}/a.log {D}/a.log", "{W}"),
    ("cp {W}/a.log {D}/a.log", "{W}"),
    ("python3 -c \"import os; os.remove('{D}/a.log')\"", "{W}"),
    ("python3 -c \"open('{D}/a.log','w').close()\"", "{W}"),
    ("perl -e 'unlink q({D}/a.log)'", "{W}"),
    # the redirect target created earlier in the same line
    ("cp {W}/a.log {D}/sub/b.log; : > {D}/sub/b.log", "{W}"),
    # bash -c with a body the hook cannot read, from the cwd of a protected parent
    ("export X='cd reach-around-dev && rm a.log'; bash -c \"$X\"", "{S}"),
    ("bash -c \"$(printf 'cd reach-around-dev && rm a.log')\"", "{S}"),
    ("export X='rm {D}/a.log'; rm -f /nonexistent-x; bash -c \"$X\"", "{W}"),
    # long-option abbreviations
    ("tar --remove -cf {W}/x.tar -C {D} sub", "{W}"),
    ("tar --remove-f -cf {W}/x.tar -C {D} sub", "{W}"),
    ("rsync -a --del {W}/empty/ {D}/sub/", "{W}"),
    ("mv --target-dir={D} {W}/a.log", "{W}"),
    ("mv --target={D} {W}/a.log", "{W}"),
]

ALLOWED = [
    ("rm {A}/ok.log", "{W}"),
    ("rm -rf {A}/sub2", "{W}"),
    ("find -H {A} -name ok.log -delete", "{W}"),
    ("find -D tree {A} -name ok.log -delete", "{W}"),
    ("truncate -s 0 {A}/ok.log", "{W}"),
    (": > {A}/ok.log", "{W}"),
    ("mv {A}/ok.log {A}/ok3.log", "{W}"),
    ("rm {W}/x.o", "{W}"),
    ("cd {W} && rm *.o", "/"),
    ("S={A}; rm -rf $S/sub2", "/"),
    ("find -H . -name x.o -delete", "{W}"),
    ("rsync -a --delete {W}/empty/ {A}/sub2/", "{W}"),
]


def need(tool: str) -> None:
    if shutil.which(tool) is None:
        if CI:
            pytest.fail(f"{tool} is required under CI and was not found")
        pytest.skip(f"{tool} is not installed")


def build(tmp_path: Path, git: bool) -> dict[str, str]:
    home = tmp_path / "home"
    dev = home / ".local/share/reach-around-dev"
    work = home / "work"
    agent = dev / "agents/me/work"
    for path in (dev / "sub", dev / "repo", agent / "sub2", work / "empty", work / "out"):
        path.mkdir(parents=True)
    sentinels = [
        dev / "a.log",
        dev / "sub/b.log",
        dev / "repo/u.log",
        dev / "repo/t.txt",
        agent / "ok.log",
        agent / "sub2/ok2.log",
        work / "x.o",
    ]
    for path in sentinels:
        path.write_text(expected(path, str(home)))
    (work / "a.log").write_text("other content\n")
    (work / "list0").write_bytes(str(dev).encode() + b"\0")
    if git:
        repo = dev / "repo"
        gitrepo.git(repo, "init", "-q")
        gitrepo.git(repo, "add", "-A", ".")
        gitrepo.git(repo, "commit", "-qm", "x")
        gitrepo.git(repo, "rm", "-q", "--cached", "u.log")  # u.log is now untracked, so `git clean` can remove it
        (repo / "u.log").write_text(expected(repo / "u.log", str(home)))
    return {
        "H": str(home),
        "S": str(home / ".local/share"),
        "D": str(dev),
        "W": str(work),
        "R": str(dev / "repo"),
        "A": str(agent),
        "sentinels": "\0".join(str(p) for p in sentinels),
    }


def expected(path: Path, home: str) -> str:
    return f"S {os.path.relpath(path, home)}\n"


def changed(world: dict[str, str]) -> list[str]:
    """The sentinels that are gone or no longer hold their original content."""
    out = []
    for name in world["sentinels"].split("\0"):
        path = Path(name)
        if not path.is_file() or path.read_text() != expected(path, world["H"]):
            out.append(name)
    return out


def run_in_bash(command: str, cwd: str, world: dict[str, str]) -> None:
    env = {
        "HOME": world["H"],
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    if rmguard_shell.bash_path(env["PATH"]) is None:
        if CI:
            pytest.fail("bash is required under CI and was not found")
        pytest.skip("bash is not installed")
    rmguard_shell.run_bash(command, cwd, env)


def fill(template: str, world: dict[str, str]) -> str:
    return template.format(**{k: v for k, v in world.items() if k != "sentinels"})


def tools_for(command: str) -> list[str]:
    words = command.replace(";", " ").replace("&", " ").replace("|", " ").split()
    return [
        t
        for t in ("git", "rsync", "tar", "truncate", "find", "shred", "dd", "sed", "perl", "install", "python3")
        if t in words
    ]


@pytest.mark.parametrize(("template", "cwd"), DENIED)
def test_when_bash_removes_a_shared_sentinel_the_guard_denied_the_command(
    template: str, cwd: str, tmp_path: Path
) -> None:
    for tool in tools_for(template):
        need(tool)
    world = build(tmp_path, git="git" in template)
    command, where = fill(template, world), fill(cwd, world)
    run_in_bash(command, where, world)
    zones = rmguard.Zones(world["H"])
    gone = [n for n in changed(world) if zones.judge(os.path.normpath(n), False) == "shared"]
    assert gone, f"the fixture no longer reaches a shared sentinel: {command!r}"
    found = rmguard.check(command, world["H"], where)
    assert found is not None, f"bash changed {gone} and the guard allowed {command!r}"


@pytest.mark.parametrize(("template", "cwd"), ALLOWED)
def test_when_bash_touches_only_agent_or_outside_files_the_guard_allows(
    template: str, cwd: str, tmp_path: Path
) -> None:
    for tool in tools_for(template):
        need(tool)
    world = build(tmp_path, git=False)
    command, where = fill(template, world), fill(cwd, world)
    run_in_bash(command, where, world)
    zones = rmguard.Zones(world["H"])
    moved = changed(world)
    assert moved, f"the fixture no longer changes anything: {command!r}"
    assert all(zones.judge(os.path.normpath(n), False) != "shared" for n in moved), moved
    assert rmguard.check(command, world["H"], where) is None, command


def test_the_tables_are_not_empty() -> None:
    assert len(DENIED) > 90
    assert len(ALLOWED) > 8
