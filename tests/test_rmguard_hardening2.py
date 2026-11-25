# SPDX-License-Identifier: Apache-2.0
"""rmguard hardening (#424): regression cases. Names are generic on purpose; the specifics are tracked privately."""

from __future__ import annotations

from pathlib import Path

import pytest

from safo import rmguard

HOME = "/home/u"
DEV = f"{HOME}/.local/share/reach-around-dev"
AGENT = f"{DEV}/agents/424-impl"
SRC = f"{HOME}/src"


def denied(command: str, cwd: str = SRC, home: str = HOME) -> bool:
    return rmguard.check(command, home, cwd) is not None


# -- case 1: code read from standard input ----------------------------------------------------------

CASE_1_DENIED = [
    pytest.param(f"bash <<'EOF'\nrm -rf {DEV}/*.py\nEOF", id="1a"),
    pytest.param(f"sh <<EOF\nrm -rf {DEV}/*.py\nEOF", id="1b"),
    pytest.param(f"bash <<< 'rm -rf {DEV}/*.py'", id="1c"),
    pytest.param(f"echo 'rm -rf {DEV}/*.py' | bash", id="1d"),
    pytest.param(f"printf '%s\\n' 'rm -rf {DEV}/*.py' | sh -s", id="1e"),
    pytest.param(f"cat <<'EOF' | bash\nrm -rf {DEV}/*.py\nEOF", id="1f"),
    pytest.param(f"bash -s <<'EOF'\nrm -rf {DEV}/*.py\nEOF", id="1g"),
    pytest.param(f"bash - <<'EOF'\nrm -rf {DEV}/*.py\nEOF", id="1h"),
    pytest.param(f"sudo bash <<'EOF'\nrm -rf {DEV}/*.py\nEOF", id="1i"),
    pytest.param(f". /dev/stdin <<'EOF'\nrm -rf {DEV}/*.py\nEOF", id="1j"),
    pytest.param(f"source /dev/stdin <<'EOF'\nrm -rf {DEV}/*.py\nEOF", id="1k"),
    pytest.param(f"bash /dev/stdin <<'EOF'\nrm -rf {DEV}/*.py\nEOF", id="1l"),
    pytest.param(f"bash -o pipefail <<'EOF'\nrm -rf {DEV}/*.py\nEOF", id="1m"),
    pytest.param(f"zsh <<'EOF'\nrm -rf {DEV}/*.py\nEOF", id="1n"),
    pytest.param(f"dash <<'EOF'\nrm -rf {DEV}/*.py\nEOF", id="1o"),
    pytest.param(f"env FOO=1 bash <<'EOF'\nrm -rf {DEV}/*.py\nEOF", id="1p"),
    pytest.param(f"echo start\nbash <<'EOF'\nrm -rf {DEV}/*.py\nEOF\necho done", id="1q"),
    pytest.param(f"(bash <<'EOF'\nrm -rf {DEV}/*.py\nEOF\n)", id="1r"),
    pytest.param(f"cat <<'A'\nhello\nA\nbash <<'B'\nrm -rf {DEV}/*.py\nB", id="1s"),
    pytest.param(f"bash <<-'EOF'\n\trm -rf {DEV}/*.py\n\tEOF", id="1t"),
    pytest.param("bash <<'EOF'\nrm -rf \"$X\"/*\nEOF", id="1u"),
    pytest.param(f"python3 <<'EOF'\nimport shutil\nshutil.rmtree('{DEV}')\nEOF", id="1v"),
    pytest.param(f"echo \"import shutil; shutil.rmtree('{DEV}')\" | python3", id="1w"),
    pytest.param(f"python3 - <<'EOF'\nimport os\nos.remove('{DEV}/a.txt')\nEOF", id="1x"),
    pytest.param(f"perl <<'EOF'\nunlink glob('{DEV}/*');\nEOF", id="1y"),
    pytest.param(f"node <<< \"require('fs').rmSync('{DEV}')\"", id="1z"),
    pytest.param(f"echo 'rm -rf {DEV}/*.py' | bash 2>&1 | tee out.txt", id="1aa"),
    pytest.param(f"echo 'rm -rf {DEV}/*.py' |& bash", id="1ab"),
]


@pytest.mark.parametrize("command", CASE_1_DENIED)
def test_hardening_case_1_denied(command: str) -> None:
    assert denied(command)


CASE_1_ALLOWED = [
    pytest.param("bash <<'EOF'\nls -la\nEOF", SRC, id="1a"),
    pytest.param(f"bash <<'EOF'\nrm -f {AGENT}/work/a.txt\nEOF", SRC, id="1b"),
    pytest.param(f"bash script.sh <<'EOF'\nrm -rf {DEV}/*.py\nEOF", SRC, id="1c-script-operand-stdin-is-data"),
    pytest.param(f"bash -c 'cat' <<'EOF'\nrm -rf {DEV}/*.py\nEOF", SRC, id="1d-c-form-stdin-is-data"),
    pytest.param("echo hi | bash", SRC, id="1e"),
    pytest.param("python3 -m json.tool <<< '{}'", SRC, id="1f-module-run"),
    pytest.param("python3 <<'EOF'\nprint(1)\nEOF", SRC, id="1g-no-zone"),
    pytest.param(f"cat <<'EOF'\nrm -rf {DEV}/*.py\nEOF", SRC, id="1h-data-for-cat"),
    pytest.param(f"echo 'rm -rf {DEV}/*.py' | cat", SRC, id="1i-pipeline-to-cat"),
    pytest.param(f"python3 script.py <<'EOF'\nprint('{DEV}')\nEOF", SRC, id="1j-script-operand"),
    pytest.param(f"python3 <<'EOF'\nprint(open('{DEV}/a.log').read().replace('a', 'b'))\nEOF", SRC, id="1k-reads-only"),
    pytest.param(f"python3 <<'EOF'\nimport os\nos.remove('{AGENT}/work/a.txt')\nEOF", SRC, id="1l-agent-folder"),
    pytest.param(
        f"python3 <<'EOF'\nopen('{HOME}/.local/share/flatpak/x.txt', 'w')\nEOF", SRC, id="1m-not-a-dev-folder"
    ),
]


@pytest.mark.parametrize(("command", "cwd"), CASE_1_ALLOWED)
def test_hardening_case_1_allowed(command: str, cwd: str) -> None:
    assert not denied(command, cwd)


# -- case 2: the gate and a working directory that is the parent of a zone --------------------------

CASE_2_PARENTS = [f"{HOME}/.local/share", f"{HOME}/.local", HOME, "/home", "/", "/tmp"]


@pytest.mark.parametrize("cwd", CASE_2_PARENTS)
def test_hardening_case_2_parent_cwd_opens_the_gate(cwd: str) -> None:
    assert rmguard.has_delete_word("mv . /elsewhere", cwd, HOME)
    assert denied("mv . /elsewhere", cwd)
    assert denied("truncate -s 0 .", cwd)


@pytest.mark.parametrize(
    "command",
    [
        "rsync --delete -a empty/ ./",
        "rsync --delete-after -a empty/ ./",
        "rsync --del -a empty/ ./",
        "tar --remove-files -cf a.tar x",
        "rsync --remove-source-files -a x/ y/",
        "tar --unlink-first -xf a.tar",
    ],
)
def test_hardening_case_2_long_delete_options_open_the_gate(command: str) -> None:
    assert rmguard.has_delete_word(command, SRC, HOME)


def test_hardening_case_2_ordinary_commands_stay_ungated() -> None:
    assert not rmguard.has_delete_word("ls -la", SRC, HOME)
    assert not rmguard.has_delete_word("git log --oneline", SRC, HOME)
    assert not rmguard.has_delete_word("rsync -a x/ y/", SRC, HOME)
    assert not rmguard.has_delete_word("sleep --delay 3", SRC, HOME)
    assert rmguard.check("ls -la", HOME, f"{HOME}/.local/share") is None
    assert rmguard.check("echo hi", HOME, "/") is None


# -- case 3: output-file options of git subcommands on the safe list --------------------------------


@pytest.fixture
def real(tmp_path: Path) -> tuple[str, Path]:
    dev = tmp_path / ".local/share/reach-around-dev"
    (dev / "agents/424-impl/work").mkdir(parents=True)
    (dev / "out").mkdir()
    (dev / "keep.log").write_text("keep")
    (dev / "agents/424-impl/work/mine.log").write_text("mine")
    return str(tmp_path), dev


CASE_3_DENIED = [
    "git archive -o {f} HEAD",
    "git archive -o{f} HEAD",
    "git archive --output={f} HEAD",
    "git archive --output {f} HEAD",
    "git archive --outp={f} HEAD",
    "git log --output={f}",
    "git log -p --output {f}",
    "git diff --output={f}",
    "git show --output={f} HEAD",
    "git format-patch -o {d} -1",
    "git format-patch --output-directory={d} -1",
    "git format-patch --output-directory {d} -1",
    "git format-patch --output-dir={d} -1",
    "git bundle create {f} HEAD",
    "git -C {p} log --output=keep.log",
    "git --no-pager diff --output={f}",
    "git config --file {f} a.b c",
    "git config -f {f} a.b c",
]


@pytest.mark.parametrize("template", CASE_3_DENIED)
def test_hardening_case_3_denied(template: str, real: tuple[str, Path]) -> None:
    home, dev = real
    command = template.format(f=dev / "keep.log", d=dev / "out", p=dev)
    assert denied(command, "/", home)


CASE_3_ALLOWED = [
    "git archive -o {new} HEAD",
    "git archive -o {mine} HEAD",
    "git log --output={mine}",
    "git log --oneline",
    "git archive HEAD",
    "git ls-files -o --exclude-standard",
    "git grep -o foo",
    "git log --output-indicator-new=+",
    "git format-patch -o {agent}/work/patches -1",
    "git bundle create {new} HEAD",
    "git config -f {mine} a.b c",
    "git -C {agent}/work log --output=mine.log",
]


@pytest.mark.parametrize("template", CASE_3_ALLOWED)
def test_hardening_case_3_allowed(template: str, real: tuple[str, Path]) -> None:
    home, dev = real
    command = template.format(
        new=dev / "agents/424-impl/work/new.out",
        mine=dev / "agents/424-impl/work/mine.log",
        agent=dev / "agents/424-impl",
    )
    assert not denied(command, "/", home)
    assert not denied(command, f"{home}/src", home)


CASE_3_PROGRAMS = [
    "git ls-remote --upload-pack='rm -rf {dev}/*.py' .",
    "git fetch --receive-pack='rm -rf {dev}/*.py' .",
    "git archive --exec='rm -rf {dev}/*.py' HEAD",
    "git clone -u 'rm -rf {dev}/*.py' . x",
    "git -c core.pager='rm -rf {dev}/*.py' log",
    "git -c core.fsmonitor='rm -rf {dev}/*.py' status",
    "git -c core.sshCommand='rm -rf {dev}/*.py' fetch",
    "GIT_PAGER='rm -rf {dev}/*.py' git log",
    "GIT_EXTERNAL_DIFF='rm -rf {dev}/*.py' git diff",
    "git -c alias.x='!rm -rf {dev}/*.py' status",
]


@pytest.mark.parametrize("template", CASE_3_PROGRAMS)
def test_hardening_case_3_programs_run_by_a_safe_subcommand(template: str) -> None:
    assert denied(template.format(dev=DEV))
    assert not denied(template.format(dev=AGENT + "/work/x").replace("/*.py", "/a.py"))


def test_hardening_case_3_ordinary_config_values_pass() -> None:
    assert not denied('git -c user.name="O\'Brien" log')
    assert not denied("git -c color.ui=never -c core.quotepath=false log --oneline")
    assert not denied("git --no-pager log --oneline")


# -- neighbouring variants ----------------------------------------------------------------------


NEIGHBOURS = [
    pytest.param(f"busybox rm -rf {DEV}/*.py", id="n1"),
    pytest.param(f"toybox rm -rf {DEV}/*.py", id="n2"),
    pytest.param(f"su -c 'rm -rf {DEV}/*.py'", id="n3"),
    pytest.param(f"su user -c 'rm -rf {DEV}/*.py'", id="n4"),
    pytest.param(f"flock /tmp/l -c 'rm -rf {DEV}/*.py'", id="n5"),
    pytest.param(f"flock -c 'rm -rf {DEV}/*.py' /tmp/l", id="n6"),
    pytest.param(f"script -c 'rm -rf {DEV}/*.py' /dev/null", id="n7"),
    pytest.param(f"watch 'rm -rf {DEV}/*.py'", id="n8"),
    pytest.param(f"watch -n 1 rm -rf {DEV}/*.py", id="n9"),
    pytest.param(f"sudo -s 'rm -rf {DEV}/*.py'", id="n10"),
    pytest.param(f"sudo -i 'rm -rf {DEV}/*.py'", id="n11"),
    pytest.param(f"awk 'BEGIN {{ system(\"rm -rf {DEV}/*.py\") }}'", id="n12"),
    pytest.param(f'gawk \'BEGIN {{ "ls" | getline x; system("rm -rf " "{DEV}") }}\'', id="n13"),
    pytest.param('rm --rec "$X"', id="n14"),
    pytest.param('rm --recu "$X"', id="n15"),
    pytest.param('rm --dir "$X"', id="n16"),
    pytest.param(f"ash -c 'rm -rf {DEV}/*.py'", id="n17"),
    pytest.param(f"fish -c 'rm -rf {DEV}/*.py'", id="n18"),
    pytest.param(f"csh -c 'rm -rf {DEV}/*.py'", id="n19"),
    pytest.param(f"busybox sh -c 'rm -rf {DEV}/*.py'", id="n20"),
    pytest.param(f"awk 'BEGIN {{ system(\"rm -f {AGENT}/work/a.txt\") }}'", id="n21"),
]


@pytest.mark.parametrize("command", NEIGHBOURS)
def test_hardening_neighbouring_variants_denied(command: str) -> None:
    assert denied(command)


NEIGHBOURS_ALLOWED = [
    pytest.param(f"busybox rm -f {AGENT}/work/a.txt", id="a1"),
    pytest.param(f"su -c 'rm -f {AGENT}/work/a.txt'", id="a2"),
    pytest.param(f"flock /tmp/l -c 'rm -f {AGENT}/work/a.txt'", id="a3"),
    pytest.param("watch -n 1 ls", id="a4"),
    pytest.param("awk 'BEGIN { print 1 }'", id="a5"),
    pytest.param("awk '{ print $1 }' file", id="a6"),
    pytest.param(f"rm --rec {AGENT}/work/x", id="a8"),
    pytest.param("busybox ls", id="a9"),
    pytest.param("sudo -s 'ls -la'", id="a10"),
]


@pytest.mark.parametrize("command", NEIGHBOURS_ALLOWED)
def test_hardening_neighbouring_variants_allowed(command: str) -> None:
    assert not denied(command)


def test_hardening_output_file_options_of_find(real: tuple[str, Path]) -> None:
    home, dev = real
    keep = dev / "keep.log"
    for command in (
        f"find . -name x -fprint {keep}",
        f"find . -fprint0 {keep}",
        f"find . -fls {keep}",
        f"find . -fprintf {keep} '%p'",
    ):
        assert denied(command, "/", home), command
    assert not denied(f"find . -fprint {dev}/agents/424-impl/work/new.out", "/", home)
    assert not denied(f"find . -fprint {dev}/agents/424-impl/work/mine.log", "/", home)
    assert not denied("find . -name x -print", "/", home)


QUOTED_ASSIGNMENTS = [
    pytest.param(f"FOO='x' rm -rf {DEV}/*.py", id="q1"),
    pytest.param(f'FOO="a b" rm -rf {DEV}/*.py', id="q2"),
    pytest.param(f"FOO='a b' bash -c 'rm -rf {DEV}/*.py'", id="q3"),
    pytest.param(f"A=1 B='two words' sudo rm -rf {DEV}/*.py", id="q4"),
    pytest.param(f"FOO='a' bash <<'EOF'\nrm -rf {DEV}/*.py\nEOF", id="q5"),
]


@pytest.mark.parametrize("command", QUOTED_ASSIGNMENTS)
def test_hardening_quoted_assignment_before_the_command(command: str) -> None:
    assert denied(command)


def test_hardening_quoted_assignment_does_not_hide_an_allowed_delete() -> None:
    assert not denied(f"FOO='a b' rm -f {AGENT}/work/a.txt")
    assert not denied("FOO='a b' ls")


HIDDEN_PROGRAMS = [
    pytest.param(f"bash <(echo 'rm -rf {DEV}/*.py')", id="h1"),
    pytest.param(f"source <(echo 'rm -rf {DEV}/*.py')", id="h2"),
    pytest.param(f". <(printf 'rm -rf {DEV}/*.py')", id="h3"),
    pytest.param(f"python3 <(echo 'x') && rm -rf {DEV}/*.py", id="h4"),
    pytest.param(f"exec 3<<'EOF'\nrm -rf {DEV}/*.py\nEOF\nbash <&3", id="h5"),
    pytest.param(f"echo 'rm -rf {DEV}/*.py' > {SRC}/x.sh; bash {SRC}/x.sh", id="h6"),
    pytest.param(f"cat > {SRC}/x.sh <<'EOF'\nrm -rf {DEV}/*.py\nEOF\nsh {SRC}/x.sh", id="h7"),
    pytest.param(f"echo 'rm -rf {DEV}/*.py' > {SRC}/x.py; python3 {SRC}/x.py", id="h8"),
    pytest.param(f"printf 'rm -rf {DEV}/*.py' > {SRC}/x.sh; source {SRC}/x.sh", id="h9"),
    pytest.param(f"echo 'rm -rf {DEV}/*.py' > {AGENT}/work/x.sh; bash {AGENT}/work/x.sh", id="h10"),
]


@pytest.mark.parametrize("command", HIDDEN_PROGRAMS)
def test_hardening_programs_the_hook_cannot_read(command: str) -> None:
    assert denied(command)


HIDDEN_ALLOWED = [
    pytest.param("bash <(curl -s https://example.com/install.sh)", id="i1"),
    pytest.param("diff <(ls a) <(ls b)", id="i2"),
    pytest.param(f"echo hi > {SRC}/x.sh; bash {SRC}/x.sh", id="i3"),
    pytest.param("exec 3<<'EOF'\nhello\nEOF\nbash <&3", id="i4"),
    pytest.param(f"bash {SRC}/other.sh; rm -f {AGENT}/work/a.txt", id="i5"),
    pytest.param(f"echo hi > {AGENT}/work/x.sh; bash {AGENT}/work/x.sh", id="i6-own-folder-no-delete-word"),
]


@pytest.mark.parametrize("command", HIDDEN_ALLOWED)
def test_hardening_hidden_program_rule_stays_narrow(command: str) -> None:
    assert not denied(command)
