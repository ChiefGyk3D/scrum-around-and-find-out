# SPDX-License-Identifier: Apache-2.0
"""The research wrapper (`safo gemini ...`) runs in an isolated interpreter with a sanitized environment (#221).

The child here is a fake that dumps what it sees (environment, import path, working directory, an inherited descriptor)
and touches nothing else: no network, no key, no vendor. A hostile environment, a planted `sitecustomize` in the working
directory and an inherited descriptor must not change what the child sees.
"""

from __future__ import annotations

import json
import os
import pwd
import site
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import cast

import pytest

from safo import wrapper

DUMP = """\
import json, os, sys
try:
    os.fstat(__FD__)
    fd_open = True
except OSError:
    fd_open = False
print(json.dumps({
    "env": dict(os.environ),
    "path": sys.path,
    "cwd": os.getcwd(),
    "isolated": sys.flags.isolated,
    "modules": {
        m: getattr(sys.modules[m], "__file__", "") for m in ("sitecustomize", "usercustomize") if m in sys.modules
    },
    "fd_open": fd_open,
}))
"""

HOME = pwd.getpwuid(os.geteuid()).pw_dir


@pytest.fixture
def fake(tmp_path: Path) -> Path:
    script = tmp_path / "fake_child.py"
    script.write_text(DUMP.replace("__FD__", "-1"))
    return script


@pytest.fixture
def planted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """Hostile surroundings: a working directory and a PYTHONPATH directory that each carry a `sitecustomize`."""
    marker = tmp_path / "marker"
    marker.mkdir()
    evil = (
        f"import pathlib\npathlib.Path({str(marker)!r}).joinpath('ran-' + __file__.replace('/', '_')).write_text('x')\n"
    )
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "sitecustomize.py").write_text(evil)
    (cwd / "usercustomize.py").write_text(evil)
    pypath = tmp_path / "pypath"
    pypath.mkdir()
    (pypath / "sitecustomize.py").write_text(evil)
    startup = tmp_path / "startup.py"
    startup.write_text(evil)
    monkeypatch.chdir(cwd)
    return {"marker": marker, "cwd": cwd, "pypath": pypath, "startup": startup}


def hostile_env(planted: dict[str, Path]) -> dict[str, str]:
    return {
        "PATH": f"{planted['cwd']}:relative/bin:/usr/bin",
        "HOME": "/nonexistent-home",
        "PYTHONPATH": str(planted["pypath"]),
        "PYTHONSTARTUP": str(planted["startup"]),
        "PYTHONHOME": "/nonexistent",
        "PYTHONUSERBASE": str(planted["pypath"]),
        "BASH_ENV": str(planted["startup"]),
        "ENV": str(planted["startup"]),
        "LD_PRELOAD": "/nonexistent/evil.so",
        "LD_LIBRARY_PATH": str(planted["pypath"]),
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "http://127.0.0.1:9",
        "NO_PROXY": "",
        "SSL_CERT_FILE": "/nonexistent/ca.pem",
        "REQUESTS_CA_BUNDLE": "/nonexistent/ca.pem",
        "TMPDIR": str(planted["cwd"]),
        "LANG": "tr_TR.ISO-8859-9",
        "LC_ALL": "tr_TR.ISO-8859-9",
        "XDG_CONFIG_HOME": str(planted["cwd"]),
        "XDG_DATA_HOME": str(planted["cwd"]),
        "SAFO_TOKEN": "a-github-secret",
        "GH_TOKEN": "a-github-secret",
        "AWS_SECRET_ACCESS_KEY": "a-cloud-secret",
        "DOPPLER_CONFIG_DIR": str(planted["cwd"]),
        "DOPPLER_API_HOST": "http://127.0.0.1:9",
        "SSH_SK_PROVIDER": "/nonexistent/evil.so",
        "SSH_ASKPASS": "/nonexistent/evil",
        "SSH_ASKPASS_REQUIRE": "force",
    }


def run_fake(fake: Path, env: dict[str, str], action: str) -> dict[str, object]:
    done = wrapper.launch(["gemini", action], env, action=action, entry=(str(fake),), capture=True)
    assert done.returncode == 0, done.stderr
    return cast(dict[str, object], json.loads(done.stdout))


def test_the_child_sees_exactly_the_allow_list_and_nothing_from_a_hostile_environment(
    fake: Path, planted: dict[str, Path]
) -> None:
    seen = run_fake(fake, hostile_env(planted), "quota")
    env = cast(dict[str, str], seen["env"])
    scratch = env["TMPDIR"]
    assert env == {
        "PATH": wrapper.SAFE_PATH,
        "HOME": HOME,
        "LANG": wrapper.LOCALE,
        "LC_ALL": wrapper.LOCALE,
        "TMPDIR": scratch,
    }
    assert scratch != str(planted["cwd"])
    assert seen["cwd"] == scratch


def test_the_one_secret_the_call_needs_is_the_only_secret_that_passes(fake: Path, planted: dict[str, Path]) -> None:
    source = {**hostile_env(planted), "DOPPLER_TOKEN": "the-one-key-reader"}
    ask = cast(dict[str, str], run_fake(fake, source, "ask")["env"])
    assert ask["DOPPLER_TOKEN"] == "the-one-key-reader"
    assert set(ask) == {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "DOPPLER_TOKEN"}
    # no other action reads the key, so no other action receives it
    for action in ("quota", "usage", "keys"):
        other = cast(dict[str, str], run_fake(fake, source, action)["env"])
        assert "DOPPLER_TOKEN" not in other


def test_approve_passes_only_what_the_security_key_signature_needs(fake: Path, planted: dict[str, Path]) -> None:
    source = {**hostile_env(planted), "SSH_AUTH_SOCK": "/run/agent.sock", "TERM": "xterm", "DOPPLER_TOKEN": "k"}
    env = cast(dict[str, str], run_fake(fake, source, "approve")["env"])
    # a provider library or an askpass program named by the caller would be loaded or run by ssh-keygen: never passed
    assert set(env) == {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSH_AUTH_SOCK", "TERM"}
    assert env["SSH_AUTH_SOCK"] == "/run/agent.sock"


def test_the_child_is_isolated_and_no_planted_code_runs(fake: Path, planted: dict[str, Path]) -> None:
    seen = run_fake(fake, hostile_env(planted), "quota")
    assert seen["isolated"] == 1
    for where in cast(
        dict[str, str], seen["modules"]
    ).values():  # a system sitecustomize may exist; a planted one may not
        assert not where.startswith((str(planted["cwd"]), str(planted["pypath"]))), where
    paths = [str(p) for p in cast(list[object], seen["path"])]
    for bad in (planted["cwd"], planted["pypath"], Path(site.getusersitepackages())):
        assert not any(p == str(bad) or p.startswith(str(bad) + os.sep) for p in paths), paths
    assert "" not in paths
    assert list(planted["marker"].iterdir()) == []


def test_an_inherited_descriptor_does_not_reach_the_child(planted: dict[str, Path]) -> None:
    fd = os.open("/dev/null", os.O_RDONLY)
    os.set_inheritable(fd, True)
    try:
        code = DUMP.replace("__FD__", str(fd))
        done = wrapper.launch(
            ["gemini", "quota"], hostile_env(planted), action="quota", entry=("-c", code), capture=True
        )
    finally:
        os.close(fd)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["fd_open"] is False


def test_the_scratch_directory_is_fresh_private_and_removed(fake: Path, planted: dict[str, Path]) -> None:
    seen = run_fake(fake, hostile_env(planted), "quota")
    scratch = Path(str(seen["cwd"]))
    assert str(scratch).startswith(os.path.join(HOME, *wrapper.SCRATCH_PARENT) + os.sep)  # not the caller's own
    assert scratch != planted["cwd"]
    assert not scratch.exists()


def test_the_dump_would_show_a_leak_so_the_checks_above_bite(fake: Path, planted: dict[str, Path]) -> None:
    """Negative case: the same fake, started the naive way, does report the hostile variables and the planted code."""
    env = {k: v for k, v in hostile_env(planted).items() if k not in ("PYTHONHOME", "LD_PRELOAD")}
    done = subprocess.run(  # noqa: S603 - this interpreter and a fake script, no shell
        [sys.executable, str(fake)], env=env, cwd=planted["cwd"], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    seen = json.loads(done.stdout)
    assert seen["env"]["PYTHONPATH"] == str(planted["pypath"])
    assert any(w.startswith((str(planted["cwd"]), str(planted["pypath"]))) for w in seen["modules"].values())
    assert any(planted["marker"].iterdir())


def test_the_real_entry_point_starts_in_an_isolated_interpreter(planted: dict[str, Path]) -> None:
    done = wrapper.launch(["--version"], {"PYTHONPATH": str(planted["pypath"])}, action="", capture=True)
    assert done.returncode == 0, done.stderr
    assert done.stdout.startswith("safo ")
    assert list(planted["marker"].iterdir()) == []


@pytest.mark.parametrize(
    "name",
    [
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONHOME",
        "PYTHONUSERBASE",
        "PYTHONINSPECT",
        "PYTHONWARNINGS",
        "BASH_ENV",
        "ENV",
        "LD_PRELOAD",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "GCONV_PATH",
        "LOCPATH",
        "NLSPATH",
    ],
)
def test_startup_variables_are_refused_by_name_and_nothing_runs(
    name: str, planted: dict[str, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    code = wrapper.enter(["gemini", "quota", "--model", "m"], {"PATH": "/usr/bin", name: "SECRET-VALUE"})
    seen = capsys.readouterr()
    assert code == 2
    assert name in seen.err
    assert "SECRET-VALUE" not in seen.err + seen.out
    assert list(planted["marker"].iterdir()) == []


def test_other_commands_and_clean_environments_are_not_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    def fake_launch(words: list[str], env: object, **kw: object) -> subprocess.CompletedProcess[str]:
        seen.append(words)
        return subprocess.CompletedProcess([], 7)

    monkeypatch.setattr(wrapper, "launch", fake_launch)
    assert wrapper.enter(["--dry-run", "validate"], {"PYTHONPATH": "/x"}) is None  # not the research wrapper
    assert wrapper.enter(["gemini", "quota", "--model", "m"], {"PATH": "/usr/bin", "HTTPS_PROXY": "/x"}) == 7
    assert seen == [["gemini", "quota", "--model", "m"]]


def clean_child(monkeypatch: pytest.MonkeyPatch, action: str) -> dict[str, str]:
    """Become, in this process, what a real isolated child is: its directory, allow-list environment and flag."""
    scratch = tempfile.mkdtemp(prefix="run-", dir=wrapper.scratch_root(wrapper.account_home()))
    monkeypatch.chdir(scratch)
    monkeypatch.setattr(wrapper, "isolated", lambda: True)
    return wrapper.child_env(action, {}, scratch)


def test_the_isolated_child_runs_in_process_and_does_not_start_another(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_launch(*args: object, **kw: object) -> subprocess.CompletedProcess[str]:
        pytest.fail("a child started a child")

    env = clean_child(monkeypatch, "quota")
    monkeypatch.setattr(wrapper, "launch", no_launch)
    assert wrapper.enter(["gemini", "quota", "--model", "m"], env) is None
    # and an isolated process still refuses a startup variable in its own environment
    assert wrapper.enter(["gemini", "quota", "--model", "m"], {**env, "PYTHONPATH": "/x"}) == 2


def test_a_forged_isolation_marker_with_a_dirty_environment_is_refused_not_trusted(
    monkeypatch: pytest.MonkeyPatch, planted: dict[str, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    def no_launch(*args: object, **kw: object) -> subprocess.CompletedProcess[str]:
        pytest.fail("ran with a forged marker")

    monkeypatch.setattr(wrapper, "isolated", lambda: True)  # `python -I -m safo ...` run by hand, in a dirty place
    monkeypatch.setattr(wrapper, "launch", no_launch)
    dirty = {k: v for k, v in hostile_env(planted).items() if k not in wrapper.startup_variables(hostile_env(planted))}
    assert wrapper.enter(["gemini", "quota", "--model", "m"], dirty) == 2
    assert "isolated child" in capsys.readouterr().err


@pytest.mark.parametrize(
    "damage",
    ["extra_key", "path", "home", "lang", "tmpdir", "missing_key", "cwd_elsewhere", "extra_for_other_action"],
)
def test_each_way_the_environment_or_directory_differs_from_the_allow_list_is_refused(
    damage: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    env = clean_child(monkeypatch, "quota")
    if damage == "extra_key":
        env["HTTPS_PROXY"] = "http://127.0.0.1:9"
    elif damage == "path":
        env["PATH"] = "/usr/bin"
    elif damage == "home":
        env["HOME"] = "/elsewhere"
    elif damage == "lang":
        env["LANG"] = "en_US.UTF-8"
    elif damage == "tmpdir":
        env["TMPDIR"] = str(tmp_path)
    elif damage == "missing_key":
        del env["LC_ALL"]
    elif damage == "cwd_elsewhere":
        monkeypatch.chdir(tmp_path)
    elif damage == "extra_for_other_action":
        env["DOPPLER_TOKEN"] = "k"  # only `ask` may carry it
    assert wrapper.enter(["gemini", "quota", "--model", "m"], env) == 2


ARGV_SHAPES = [
    ["gemini", "quota", "--model", "m"],
    ["--dry-run", "gemini", "quota", "--model", "m"],
    ["--board", "b.yaml", "gemini", "quota", "--model", "m"],
    ["--board=b.yaml", "gemini", "quota", "--model", "m"],
    ["--bo", "b.yaml", "gemini", "quota", "--model", "m"],  # an abbreviation of --board
    ["--bo=b.yaml", "gemini", "quota", "--model", "m"],
    ["--gh", "someone", "gemini", "quota", "--model", "m"],  # an abbreviation of --gh-user
    ["--gh-user=someone", "gemini", "quota", "--model", "m"],
    ["--dry", "gemini", "quota", "--model", "m"],  # an abbreviation of --dry-run
    ["--board", "gemini", "validate"],  # a value that looks like the mode
    ["--board=gemini", "validate"],
    ["--bo", "gemini", "validate"],
    ["--gh", "gemini", "validate"],
    ["--board", "x", "validate", "gemini"],
    ["validate", "--board", "gemini"],
    ["gemini", "--help"],
    ["--version"],
    ["--nonsense", "gemini", "quota"],
    ["gemini"],
    ["gemini", "bogus"],
    ["--", "gemini", "quota", "--model", "m"],
    [],
]


@pytest.mark.parametrize("words", ARGV_SHAPES, ids=[" ".join(w) or "empty" for w in ARGV_SHAPES])
def test_the_wrapper_starts_exactly_when_the_real_parser_says_the_mode_is_gemini(
    words: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    import contextlib
    import io

    from safo import cli

    parser, _ = cli.build_parser()
    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
        try:
            real = parser.parse_args(words).mode
        except SystemExit:
            real = None
    launched: list[list[str]] = []

    def fake_launch(w: list[str], env: object, **kw: object) -> subprocess.CompletedProcess[str]:
        launched.append(w)
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(wrapper, "launch", fake_launch)
    monkeypatch.setattr(wrapper, "isolated", lambda: False)
    code = wrapper.enter(words, {"PATH": "/usr/bin", "PYTHONPATH": "/x"})
    if real == "gemini":
        assert code == 2 and launched == [], "a gemini command must be refused here, never run in place"
        assert wrapper.enter(words, {"PATH": "/usr/bin"}) == 0 and len(launched) == 1
    else:
        assert code is None and launched == []


def test_relative_paths_are_made_absolute_before_the_working_directory_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    cwd = str(tmp_path)
    ask = ["gemini", "ask", "--model", "m", "--material", "public", "--prompt-file", "p.txt"]
    assert wrapper.absolutize(ask) == [*ask[:-1], f"{cwd}/p.txt"]
    equals = ["gemini", "ask", "--model", "m", "--prompt-file=sub/p.txt"]
    assert wrapper.absolutize(equals) == [*equals[:-1], f"--prompt-file={cwd}/sub/p.txt"]
    keys = ["--dry-run", "gemini", "keys", "propose", "k.pub", "--label", "k.pub"]
    assert wrapper.absolutize(keys) == ["--dry-run", "gemini", "keys", "propose", f"{cwd}/k.pub", "--label", "k.pub"]
    already = ["gemini", "ask", "--model", "m", "--prompt-file", "/abs/p.txt"]
    assert wrapper.absolutize(already) == already
    broken = ["gemini", "ask", "--nonsense"]  # the child reports the usage error itself
    assert wrapper.absolutize(broken) == broken


def test_a_missing_interpreter_stops_the_call_and_never_falls_back(tmp_path: Path) -> None:
    with pytest.raises(wrapper.WrapperError, match="interpreter"):
        wrapper.launch(["gemini", "quota"], {}, action="quota", python=str(tmp_path / "no-python"))


def test_the_installed_entry_point_refuses_a_startup_variable_before_any_work(planted: dict[str, Path]) -> None:
    env = {"PATH": os.environ["PATH"], "PYTHONSTARTUP": str(planted["startup"])}
    done = subprocess.run(
        [sys.executable, "-m", "safo", "gemini", "quota", "--model", "m"],
        env=env,
        cwd=planted["cwd"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 2
    assert "PYTHONSTARTUP" in done.stderr
    assert "refused" in done.stderr


def test_run_hands_the_gemini_command_to_the_wrapper_first(monkeypatch: pytest.MonkeyPatch) -> None:
    from safo import cli

    monkeypatch.setattr(sys, "argv", ["safo", "gemini", "quota", "--model", "m"])
    monkeypatch.setattr(wrapper, "enter", lambda words, env: 9 if next(iter(words)) == "gemini" else None)
    with pytest.raises(SystemExit) as stop:
        cli.run()
    assert stop.value.code == 9


def test_the_default_entry_pins_the_package_that_launched_it() -> None:
    import safo

    entry = wrapper.default_entry()
    root = entry[2]
    assert entry[0] == "-c" and entry[1] == wrapper.BOOT
    assert os.path.samefile(os.path.join(root, "safo"), os.path.dirname(os.path.abspath(safo.__file__)))


def test_a_real_child_passes_its_own_shape_check(planted: dict[str, Path]) -> None:
    """The real child (no fake) must recognize itself: it reaches the config read, not the refusal."""
    done = wrapper.launch(["gemini", "quota", "--model", "m"], hostile_env(planted), action="quota", capture=True)
    assert "not the isolated child" not in done.stderr
    assert "refused: startup" not in done.stderr


STDIN_DUMP = "import sys; print(repr(sys.stdin.read()))"


def run_with_stdin(action: str, data: str) -> str:
    code = (
        "import subprocess, sys\n"
        "from safo import wrapper\n"
        f"done = wrapper.launch(['x'], {{}}, action={action!r}, entry=('-c', {STDIN_DUMP!r}), capture=True)\n"
        "sys.stdout.write(done.stdout)\n"
    )
    done = subprocess.run(  # noqa: S603 - this interpreter and a fixed program, no shell
        [sys.executable, "-c", code], input=data, capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


def test_only_approve_receives_standard_input() -> None:
    assert run_with_stdin("approve", "yes\n") == repr("yes\n")
    for action in ("quota", "ask", "usage", "keys"):
        assert run_with_stdin(action, "yes\n") == repr("")


def test_a_closed_standard_descriptor_is_replaced_not_left_for_the_next_open() -> None:
    code = (
        "import os, sys\n"
        "from safo import wrapper\n"
        "os.close(2)\n"
        "d = wrapper.launch(['x'], {}, action='quota', entry=('-c', 'import os; print(os.fstat(2).st_rdev != 0)'),"
        " capture=False)\n"
        "sys.exit(d.returncode)\n"
    )
    done = subprocess.run(  # noqa: S603 - this interpreter and a fixed program, no shell
        [sys.executable, "-c", code], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "True"  # fd 2 in the child is /dev/null (a character device), not closed or reused


def test_the_scratch_parent_refuses_a_symlink_in_its_path(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".local").mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (home / ".local" / "state").symlink_to(elsewhere)
    with pytest.raises(wrapper.WrapperError, match="scratch"):
        wrapper.scratch_root(str(home))
    assert list(elsewhere.iterdir()) == []


def test_a_rewrite_that_changes_the_command_is_refused_not_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Option values and positional values that equal `propose` must not move the rewrite onto the action word."""
    monkeypatch.chdir(tmp_path)
    tricky = ["--board", "propose", "gemini", "keys", "propose", "propose", "--label", "x"]
    try:
        out = wrapper.absolutize(tricky)
    except wrapper.WrapperError:
        return  # fail closed is acceptable
    before, after = wrapper.parsed(tricky), wrapper.parsed(out)
    assert before is not None and after is not None
    assert after.keys_action == "propose" and after.board == before.board
    assert after.keys_file == f"{tmp_path}/propose"
