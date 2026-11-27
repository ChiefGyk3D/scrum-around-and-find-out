# SPDX-License-Identifier: Apache-2.0
"""rmguard, Daybreak round 2 (#422): the gate, git, other writers, creation in the same line, unknown shell bodies,
input size, integrity self-check, long-option abbreviations."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from cputime import cpu_bound
from safo import rmguard

HOME = "/home/u"
DEV = f"{HOME}/.local/share/reach-around-dev"
AGENT = f"{DEV}/agents/me"
SHARE = f"{HOME}/.local/share"
LEAD = (".local", "share", "reach-around-lead")


def deny(command: str, cwd: str = "/") -> bool:
    return rmguard.check(command, HOME, cwd) is not None


# -- 1: the zone name quoted, escaped or split ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "truncate -s 0 reach-around-d''ev/a.log",
        'truncate -s 0 reach-around-d""ev/a.log',
        "truncate -s 0 reach-around-d\\ev/a.log",
        "git -C reach-around-d\\ev clean -fdx",
        "mv ~/.lo''cal/share/reach-around-d''ev/a.log /work/",
        ": > reach-around-d\\ev/a.log",
    ],
)
def test_a_quoted_or_escaped_zone_name_still_opens_the_gate(command: str) -> None:
    assert rmguard.has_delete_word(command, SHARE, HOME)


@pytest.mark.parametrize(
    "command",
    [
        "truncate -s 0 reach-around-d''ev/a.log",
        "truncate -s 0 reach-around-d\\ev/a.log",
        "mv reach-around-d''ev/a.log /w/",
    ],
)
def test_split_zone_names_are_denied_from_the_parent_folder(command: str) -> None:
    assert deny(command, SHARE)


# -- 2, 3: git -----------------------------------------------------------------------------------------------------

GIT_BLOCKED = [
    (f"git -C {DEV}/repo wipe -fdx", "/"),
    (f"git -c alias.wipe=clean -C {DEV}/repo wipe -fdx", "/"),
    (f"git -C {DEV}/repo checkout -f", "/"),
    (f"git -C {DEV}/repo reset --hard", "/"),
    (f"git -C {DEV}/repo rm -q t.txt", "/"),
    (f"git -C {DEV}/repo stash -u", "/"),
    (f"git -C {DEV}/repo restore .", "/"),
    ("git switch -f main", DEV),
    (f"GIT_WORK_TREE={DEV}/repo GIT_DIR=/work/r.git git clean -fdx", "/work"),
    (f"env GIT_WORK_TREE={DEV}/repo git clean -fdx", "/work"),
    (f'export GIT_WORK_TREE="{DEV}/repo"; git clean -fdx', "/work"),
    (f"git --work-tree={DEV}/repo --git-dir=/work/r.git clean -fdx", "/work"),
    (f"git --work-tree {DEV}/repo clean -fdx", "/work"),
    ("git --frobnicate clean -fdx", DEV),  # an unknown global long option fails closed
    ("git clean -fd -e -n", DEV),  # `-n` is the VALUE of -e, so this is not a dry run
    ("git clean -fde -n", DEV),
    ("git clean -fd --dry", DEV),  # an abbreviation is not trusted as a dry run
    ("git clean -fd --exclude=-n", DEV),
    ("git clean -fd -- -n", DEV),
]
GIT_ALLOWED = [
    (f"git -C {DEV}/repo status", "/"),
    ("git status", DEV),
    ("git log --oneline -5", f"{DEV}/repo"),
    ("git diff", DEV),
    ("git add -A", DEV),
    ("git commit -qm x", DEV),
    ("git push -q origin main", DEV),
    ("git fetch -q", DEV),
    ("git branch -a", DEV),
    ("git reset --hard", f"{AGENT}/work"),
    ("git checkout -f", f"{AGENT}/work"),
    ("git clean -fdx", f"{AGENT}/work"),
    ("git clean -n", DEV),
    ("git clean -nd", DEV),
    ("git clean -fdn", DEV),
    ("git clean --dry-run -fd", DEV),
    ("git clean -n -e x", DEV),
    ("git clean -ne x", DEV),
    ("git reset --hard", "/work/repo"),
    (f"GIT_AUTHOR_NAME=x git -C {AGENT}/work commit -qm y", "/"),
]


@pytest.mark.parametrize(("command", "cwd"), GIT_BLOCKED)
def test_git_blocked(command: str, cwd: str) -> None:
    assert deny(command, cwd), command


@pytest.mark.parametrize(("command", "cwd"), GIT_ALLOWED)
def test_git_allowed(command: str, cwd: str) -> None:
    assert not deny(command, cwd), command


# -- 4: other writers, judged on existing zone files ---------------------------------------------------------------


def zone(tmp_path: Path) -> tuple[str, Path, Path]:
    dev = tmp_path / ".local/share/reach-around-dev"
    agent = dev / "agents/me/work"
    agent.mkdir(parents=True)
    (dev / "a.log").write_text("keep")
    (agent / "o.log").write_text("mine")
    return str(tmp_path), dev, agent


WRITERS = [
    "sed -i 's/a/b/' {f}",
    "sed -i.bak -e 's/a/b/' {f}",
    "sed -Ei 's/a/b/' {f}",
    "sed --in-place 's/a/b/' {f}",
    "perl -pi -e 's/a/b/' {f}",
    "perl -i.bak -ne print {f}",
    "ed -s {f}",
    "awk -i inplace '{{next}}' {f}",
    "gawk -i inplace '{{next}}' {f}",
    "install -m 644 /work/src {f}",
    "ln -sf /work/src {f}",
    "ln -sfn /work/src {f}",
    "ln -f /work/src {f}",
    "cp /work/src {f}",
    "cp -f /work/src {f}",
    "mv /work/src {f}",
]


@pytest.mark.parametrize("template", WRITERS)
def test_writers_on_an_existing_shared_file_are_denied(template: str, tmp_path: Path) -> None:
    home, dev, agent = zone(tmp_path)
    assert rmguard.check(template.format(f=dev / "a.log"), home, "/") is not None, template
    assert rmguard.check(template.format(f=agent / "o.log"), home, "/") is None, "agent folder is allowed"
    assert rmguard.check(template.format(f=tmp_path / "elsewhere.txt"), home, "/") is None, "outside is untouched"


@pytest.mark.parametrize("command", ["sed -n p {f}", "perl -ne print {f}", "awk '{{print}}' {f}", "cat {f}"])
def test_readers_of_a_shared_file_are_allowed(command: str, tmp_path: Path) -> None:
    home, dev, _ = zone(tmp_path)
    assert rmguard.check(command.format(f=dev / "a.log"), home, "/") is None


INTERPRETERS = [
    "python3 -c \"open('{z}/a.log','w').close()\"",
    "python -c 'import os; os.remove(\"{z}/a.log\")'",
    "perl -e 'unlink q({z}/a.log)'",
    "ruby -e 'File.delete(\"{z}/a.log\")'",
    'node -e \'require("fs").unlinkSync("{z}/a.log")\'',
    "php -r 'unlink(\"{z}/a.log\");'",
]


@pytest.mark.parametrize("template", INTERPRETERS)
def test_an_inline_interpreter_that_names_a_zone_fails_closed(template: str) -> None:
    assert deny(template.format(z=DEV))
    assert deny(template.format(z="reach-around-d''ev"), SHARE)
    assert not deny("python3 -c 'print(1)'", "/work")
    assert not deny("perl -e 'print 1'", "/work")
    assert deny("python3 -c 'print(1)'", DEV)  # a relative path in a zone cwd


# -- 5: the target created earlier in the same line ----------------------------------------------------------------


def test_a_redirect_target_created_earlier_in_the_line_counts_as_existing(tmp_path: Path) -> None:
    home, dev, _ = zone(tmp_path)
    new = dev / "new.log"
    assert rmguard.check(f"echo a > {new}", home, "/") is None
    assert rmguard.check(f"echo a > {new} && echo b >> {new}", home, "/") is None
    assert rmguard.check(f"echo a > {new}; echo b > {new}", home, "/") is not None
    assert rmguard.check(f"cp /work/valuable {new}; : > {new}", home, "/") is not None
    assert rmguard.check(f"touch {new}; : > {new}", home, "/") is not None
    assert rmguard.check(f"echo a | tee {new}; echo b | tee {new}", home, "/") is not None
    assert rmguard.check(f"echo a > $X; : > {new}", home, "/") is not None  # an earlier write it cannot place


# -- (d) unresolved redirect and tee targets follow the soft rule --------------------------------------------------


def test_an_unresolved_redirect_target_is_judged_when_a_zone_is_in_sight(tmp_path: Path) -> None:
    home, dev, _ = zone(tmp_path)
    assert rmguard.check(f"ls {dev}/*.log; echo x > $LOG", home, "/") is not None
    assert rmguard.check("echo x > $LOG", home, "/work") is None
    assert rmguard.check("echo x > $LOG", home, str(dev)) is not None
    assert rmguard.check('echo x | tee "$LOG"', home, str(dev)) is not None


# -- 6, (a): unknown shell bodies and the parents of a zone --------------------------------------------------------


@pytest.mark.parametrize("cwd", [DEV, SHARE, f"{HOME}/.local", HOME, "/tmp"])
def test_a_wholly_unknown_body_is_denied_in_or_above_a_zone(cwd: str) -> None:
    assert deny('bash -c "$X"', cwd)
    assert deny('bash -c "$(cat /tmp/payload)"', cwd)
    assert deny('sh -c "$X"', cwd)


def test_a_wholly_unknown_body_is_allowed_elsewhere() -> None:
    assert not deny('bash -c "$X"', "/work")


def test_an_unreadable_body_with_a_delete_word_outside_the_body_fails_closed() -> None:
    assert deny('rm -f /work/x; bash -c "$X"', "/work")
    assert deny('find /work -name x -delete; bash -c "$X"', "/work")
    assert deny('rm -f /work/x; bash -c "$(cat /work/p)"', "/work")


def test_an_unknown_command_word_with_unresolved_arguments_is_denied_above_a_zone() -> None:
    assert deny("$TOOL $ARG", SHARE)
    assert not deny("$TOOL $ARG", "/work")


# -- 8: input size and quadratic work ------------------------------------------------------------------------------


def test_a_word_of_many_tildes_is_scanned_in_linear_time() -> None:
    command = "$X " + "~" * 60_000
    with cpu_bound(1.0):  # CPU time: a loaded runner stretches the wall clock only
        assert rmguard.check(command, HOME, "/work") is None


def test_thousands_of_assignment_words_are_scanned_in_linear_time() -> None:
    command = "A=1 " * 12_000 + "echo $A"
    with cpu_bound(1.0):
        assert rmguard.check(command, HOME, "/work") is None


def test_an_oversized_command_is_decided_by_its_head() -> None:
    big = rmguard.MAX_SCAN_CHARS
    filler = "echo " + "x" * (big * 2)
    assert (
        rmguard.check(f"{filler}; rm -rf {DEV}/a", HOME, "/work") is None
    )  # the delete word is past the head: allowed
    assert rmguard.check(f"rm -rf {DEV}/a; {filler}", HOME, "/work") is not None  # in the head: denied
    assert rmguard.check(f"ls {DEV}; {filler}", HOME, "/work") is not None  # a zone word in the head: denied
    assert rmguard.check(filler, HOME, "/work") is None  # nothing in the head: allowed
    assert rmguard.check(filler, HOME, DEV) is not None  # the cwd is in a zone: denied


def test_an_oversized_allow_is_logged(tmp_path: Path) -> None:
    filler = "echo " + "x" * (rmguard.MAX_SCAN_CHARS * 2)
    event = json.dumps({"tool_name": "Bash", "cwd": "/work", "tool_input": {"command": filler + "; rm -rf /x/y"}})
    assert rmguard.main([], io.StringIO(event), str(tmp_path)) == 0
    assert "too large" in tmp_path.joinpath(*LEAD, "rmguard-error.log").read_text()


# -- 7: the integrity self-check in warn mode ----------------------------------------------------------------------


def make_install(home: Path) -> tuple[Path, Path]:
    launcher = home / ".config/safo/rmguard-hook"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("#!/bin/sh\nexec safo-rmguard --mode enforce\n")
    settings = home / ".claude/settings.json"
    settings.parent.mkdir(parents=True)
    entry = {"matcher": "Bash", "hooks": [{"type": "command", "command": "rmguard-hook", "onFailure": "block"}]}
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [entry, {"matcher": "Edit", "hooks": []}]}}))
    return launcher, settings


def warn_run(home: Path) -> None:
    event = json.dumps({"tool_name": "Bash", "cwd": "/", "tool_input": {"command": "ls"}})
    assert rmguard.main(["--mode", "warn"], io.StringIO(event), str(home)) == 0


def errors(home: Path) -> list[str]:
    log = home.joinpath(*LEAD, "rmguard-error.log")
    return log.read_text().splitlines() if log.exists() else []


def test_warn_mode_logs_when_the_launcher_or_the_settings_entry_differ_from_the_record(tmp_path: Path) -> None:
    launcher, settings = make_install(tmp_path)
    assert rmguard.main(["--record-integrity"], io.StringIO(""), str(tmp_path)) == 0
    warn_run(tmp_path)
    assert not [line for line in errors(tmp_path) if "integrity" in line]  # nothing differs
    launcher.write_text("#!/bin/sh\nexit 0\n")
    warn_run(tmp_path)
    warn_run(tmp_path)
    changed = [line for line in errors(tmp_path) if "integrity" in line]
    assert len(changed) == 1 and "launcher" in changed[0]  # logged once, not on every run
    data = json.loads(settings.read_text())
    data["hooks"]["PreToolUse"][0]["hooks"][0].pop("onFailure")
    settings.write_text(json.dumps(data))
    warn_run(tmp_path)
    assert any("settings" in line for line in errors(tmp_path) if "integrity" in line)


def test_unrelated_settings_changes_do_not_trip_the_check(tmp_path: Path) -> None:
    _, settings = make_install(tmp_path)
    rmguard.main(["--record-integrity"], io.StringIO(""), str(tmp_path))
    data = json.loads(settings.read_text())
    data["theme"] = "dark"
    settings.write_text(json.dumps(data))
    warn_run(tmp_path)
    assert not [line for line in errors(tmp_path) if "integrity" in line]


def test_the_check_runs_in_warn_mode_only_and_never_blocks(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    launcher, _ = make_install(tmp_path)
    rmguard.main(["--record-integrity"], io.StringIO(""), str(tmp_path))
    launcher.write_text("changed")
    event = json.dumps({"tool_name": "Bash", "cwd": "/", "tool_input": {"command": "ls"}})
    capsys.readouterr()
    assert rmguard.main([], io.StringIO(event), str(tmp_path)) == 0  # enforce: no check, nothing printed
    assert capsys.readouterr().out == ""
    assert not [line for line in errors(tmp_path) if "integrity" in line]


# -- (c) long-option abbreviations, unknown long options -----------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        f"tar --remove -cf /w/x.tar -C {DEV} sub",
        f"tar --remove-f -cf /w/x.tar -C {DEV} sub",
        f"tar --remove-files -cf /w/x.tar -C {DEV} sub",
        f"tar --recursive-unlink -xf /w/x.tar -C {DEV}/sub .",
        f"tar --frobnicate -cf /w/x.tar -C {DEV} sub",
        f"rsync -a --del /w/e/ {DEV}/sub/",
        f"rsync -a --delete-be /w/e/ {DEV}/sub/",
        f"rsync -a --remove-source {DEV}/sub/b.log /w/o/",
        f"rsync -a --frobnicate /w/e/ {DEV}/sub/",
        f"mv --target-dir={DEV} /w/a.log",
        f"mv --target={DEV} /w/a.log",
        f"mv --target-directory {DEV} /w/a.log",
        f"cp --target-dir={DEV} /dev/null",
        f"find {DEV} --frobnicate -delete",
        f"find {DEV} -name a.log -delete --weird",
    ],
)
def test_abbreviated_and_unknown_long_options_fail_closed(command: str) -> None:
    assert deny(command), command


@pytest.mark.parametrize(
    "command",
    [
        f"tar -cf /w/x.tar -C {DEV} sub",
        f"tar --gzip -cf /w/x.tar -C {DEV} sub",
        f"rsync -a --partial /w/e/ {AGENT}/work/sub/",
        f"mv --target-directory={AGENT}/work /w/a.log",
        f"find {AGENT}/work -name a.log -delete",
        "find /w --version",
    ],
)
def test_known_harmless_long_options_stay_allowed(command: str) -> None:
    assert not deny(command), command


# -- 9: redirects into the agent's own folder and the scratchpad are allowed ---------------------------------------


def test_truncating_redirects_below_an_agent_root_and_in_the_scratchpad_are_allowed(tmp_path: Path) -> None:
    home, dev, agent = zone(tmp_path)
    assert rmguard.check(f"echo x > {agent}/o.log", home, "/") is None
    assert rmguard.check(f": > {agent}/o.log; echo y | tee {agent}/o.log", home, "/") is None
    pad = "/tmp/claude-1000/-home-u/abc/scratchpad"
    assert rmguard.check(f"echo x > {pad}/o.log", home, "/") is None
    assert rmguard.check(f"echo x > {dev}/a.log", home, "/") is not None


def test_a_redirect_target_with_an_unknown_tail_below_the_agent_folder_or_scratchpad_is_allowed() -> None:
    pad = "/tmp/claude-1000/-home-u/abc/scratchpad"
    assert not deny(f"ls {DEV}/x; echo y > {pad}/$NAME", "/work")
    assert not deny(f"ls {DEV}/x; echo y > {AGENT}/work/$NAME", "/work")
    assert deny(f"ls {DEV}/x; echo y > {DEV}/$NAME", "/work")
    assert deny(f"ls {DEV}/x; echo y > $LOG", "/work")
    assert deny(f"ls {DEV}/x; echo y > {AGENT}/../$NAME", "/work")  # a `..` in the written part is never trusted


def test_the_attached_short_forms_of_git_dash_c_and_tar_dash_c_are_followed() -> None:
    assert deny(f"git -C{DEV}/repo clean -fdx", "/work")
    assert deny(f"git -C{DEV}/repo checkout -f", "/work")
    assert deny(f"tar --remove-files -cf /work/x.tar -C{DEV} sub", "/work")
    assert not deny(f"git -C{AGENT}/work clean -fdx", "/work")
    assert not deny(f"tar --remove-files -cf /work/x.tar -C{AGENT}/work sub", "/work")
    assert not deny("git -C/work/repo clean -fdx", "/work")


def test_an_attached_directory_that_cannot_be_resolved_fails_closed() -> None:
    assert deny("git -C$D clean -fdx", "/work")
    assert deny('git -C"$D" clean -fdx', "/work")
    assert deny("tar --remove-files -cf /work/x.tar -C$D sub", "/work")
    assert not deny("git -C/work/repo status", "/work")


def test_a_duplicate_key_in_the_hook_event_is_refused_not_merged(capsys: pytest.CaptureFixture[str]) -> None:
    raw = '{"tool_name": "Bash", "tool_name": "Read", "cwd": "/", "tool_input": {"command": "rm -rf /x/y"}}'
    assert rmguard.main([], io.StringIO(raw), HOME) == 0
    assert "could not be read" in capsys.readouterr().out
