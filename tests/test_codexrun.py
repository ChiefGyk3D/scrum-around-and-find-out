# SPDX-License-Identifier: Apache-2.0
"""safo-codex-run against a fake codex on PATH (#431): flags per class, refusals, the filter, the ledger, the folder."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from codexrundata import OUTPUT_CANARY, PROMPT_CANARY, World, make_world
from gitrepo import git, make_repo
from safo import codexrun


@pytest.fixture
def world(tmp_path: Path) -> World:
    return make_world(tmp_path)


def go(w: World, cls: str, *extra: str, worktree: bool | None = None, prompt: Path | None = None) -> int:
    needs = cls in ("implementer", "review") if worktree is None else worktree
    argv = ["--class", cls, "--prompt-file", str(prompt or w.prompt)]
    if needs:
        argv += ["--worktree", str(w.worktree)]
    return codexrun.main([*argv, *extra], env=w.env, home=str(w.home))


COMMON = ["exec", "--skip-git-repo-check", "--ephemeral", "--ignore-user-config", "--ignore-rules"]
COMMON += ["--color", "never", "--json"]


def expected(cls: str, root: str, out: str) -> list[str]:
    sandbox, model, tier, net = {
        "implementer": ("workspace-write", "gpt-6.1-terra", [], ["-c", "sandbox_workspace_write.network_access=false"]),
        "review": ("read-only", "gpt-6.1-terra", [], []),
        "copy": ("read-only", "gpt-6.1-terra", [], []),
        "security": ("read-only", "gpt-daybreak-blue-latest", ["--cyber-access-program", "daybreak_blue"], []),
    }[cls]
    return [*COMMON, "-s", sandbox, "-m", model, *tier, *net, "-C", root, "-o", out, "-"]


# -- 1. the exact argument vector of each class -----------------------------------------------------------------------


@pytest.mark.parametrize("cls", ["implementer", "review", "copy", "security"])
def test_argument_vector_per_class(world: World, cls: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert go(world, cls) == 0
    (call,) = world.calls()
    argv = call["argv"]
    out = argv[argv.index("-o") + 1]
    root = argv[argv.index("-C") + 1]
    if cls in ("implementer", "review"):
        assert root == str(world.worktree.resolve())
    else:
        assert os.path.basename(root).startswith("empty-")
    assert argv == expected(cls, root, out)
    assert call["cwd"] == root
    assert call["stdin"] == world.prompt.read_text()  # the prompt arrives on stdin, not in argv
    assert PROMPT_CANARY not in " ".join(argv)
    assert f"out={out}" in capsys.readouterr().out


def test_security_always_carries_the_cyber_tier(world: World) -> None:
    assert go(world, "security") == 0
    argv = world.calls()[0]["argv"]
    assert argv[argv.index("-m") + 1] == "gpt-daybreak-blue-latest"
    assert argv[argv.index("--cyber-access-program") + 1] == "daybreak_blue"
    assert argv[argv.index("-s") + 1] == "read-only"
    assert "danger-full-access" not in argv and "workspace-write" not in argv
    for cls in ("implementer", "review", "copy"):
        assert codexrun.SPECS[cls].tier == ""


def test_never_a_dangerous_sandbox_flag(world: World) -> None:
    for cls in ("implementer", "review", "copy", "security"):
        assert go(world, cls) == 0
    for call in world.calls():
        assert "danger-full-access" not in call["argv"]
        assert not any("dangerously" in word for word in call["argv"])


# -- 2. refusals: no codex call, no ledger row ---------------------------------------------------------------------


def refused(world: World, code: int) -> None:
    assert code == 2
    assert world.calls() == []
    assert world.ledger() == []


def test_refuses_a_symlink_prompt(world: World) -> None:
    link = world.dev / "prompts" / "link.txt"
    link.symlink_to(world.prompt)
    refused(world, go(world, "review", prompt=link))


def test_refuses_a_fifo_prompt(world: World) -> None:
    fifo = world.dev / "prompts" / "fifo"
    os.mkfifo(fifo, 0o600)
    refused(world, go(world, "review", prompt=fifo))


def test_refuses_an_oversize_prompt(world: World) -> None:
    big = world.write_prompt("x" * (codexrun.MAX_PROMPT_BYTES + 1), "big.txt")
    refused(world, go(world, "review", prompt=big))


def test_refuses_an_empty_prompt(world: World) -> None:
    refused(world, go(world, "review", prompt=world.write_prompt("", "empty.txt")))


def test_refuses_a_prompt_outside_the_allowed_folders(world: World, tmp_path: Path) -> None:
    outside = tmp_path / "elsewhere.txt"
    outside.write_text("hello\n")
    outside.chmod(0o600)
    refused(world, go(world, "review", prompt=outside))
    in_home = world.home / "notes.txt"
    in_home.write_text("hello\n")
    in_home.chmod(0o600)
    refused(world, go(world, "review", prompt=in_home))


def test_refuses_a_prompt_that_others_can_write(world: World) -> None:
    world.prompt.chmod(0o666)
    refused(world, go(world, "review"))


def test_refuses_a_path_that_climbs_out(world: World, tmp_path: Path) -> None:
    outside = tmp_path / "up.txt"
    outside.write_text("hello\n")
    outside.chmod(0o600)
    sneaky = world.dev / "prompts" / ".." / ".." / ".." / ".." / ".." / "up.txt"
    refused(world, go(world, "review", prompt=sneaky))


def test_refuses_a_folder_that_is_not_a_worktree(world: World) -> None:
    plain = world.dev / "plain"
    plain.mkdir()
    for folder in (plain, world.dev / "repo", world.home):  # not a worktree, the main checkout, outside a dev folder
        code = codexrun.main(
            ["--class", "review", "--prompt-file", str(world.prompt), "--worktree", str(folder)],
            env=world.env,
            home=str(world.home),
        )
        refused(world, code)


def test_refuses_a_subfolder_of_a_worktree(world: World) -> None:
    sub = world.worktree / "sub"
    sub.mkdir()
    code = codexrun.main(
        ["--class", "review", "--prompt-file", str(world.prompt), "--worktree", str(sub)],
        env=world.env,
        home=str(world.home),
    )
    refused(world, code)


def test_implementer_refuses_a_dirty_tree_but_review_does_not(world: World) -> None:
    (world.worktree / "a.txt").write_text("changed\n")
    refused(world, go(world, "implementer"))
    assert go(world, "review") == 0


def test_implementer_accepts_a_dirty_path_the_caller_named(world: World) -> None:
    (world.worktree / "a.txt").write_text("changed\n")
    assert go(world, "implementer", "--allow-dirty", "a.txt") == 0
    (world.worktree / "b.txt").write_text("new\n")
    assert go(world, "implementer", "--allow-dirty", "a.txt") == 2


def test_refuses_a_secret_shaped_prompt(world: World) -> None:
    secret = "ghp_" + "a1B2" * 9
    refused(world, go(world, "review", prompt=world.write_prompt(f"use {secret} here\n", "s.txt")))


def test_refuses_an_entry_of_the_private_deny_list(world: World, capsys: pytest.CaptureFixture[str]) -> None:
    deny = world.home / ".config" / "safo" / "codex-deny.txt"
    deny.parent.mkdir(parents=True, exist_ok=True)
    deny.write_text("# private\nsecretword\n")
    deny.chmod(0o600)
    code = go(world, "review", prompt=world.write_prompt("this holds SecretWord inside\n", "d.txt"))
    refused(world, code)
    err = capsys.readouterr().err
    assert "entry 1" in err and "secretword" not in err.lower()


@pytest.mark.parametrize("flag", ["--model", "--sandbox", "-m", "-s", "--cyber-access-program", "--config", "-c"])
def test_refuses_any_extra_model_or_sandbox_option(world: World, flag: str) -> None:
    refused(world, go(world, "review", flag, "danger-full-access"))
    refused(world, go(world, "review", f"{flag}=danger-full-access"))


def test_refuses_a_prompt_given_as_an_argument(world: World) -> None:
    refused(world, go(world, "review", "write me a poem"))


def test_refuses_an_abbreviated_option_and_a_bad_class(world: World) -> None:
    code = codexrun.main(["--class", "review", "--prompt", str(world.prompt)], env=world.env, home=str(world.home))
    refused(world, code)
    code = codexrun.main(["--class", "root", "--prompt-file", str(world.prompt)], env=world.env, home=str(world.home))
    refused(world, code)


def test_empty_folder_classes_take_no_worktree_and_others_need_one(world: World) -> None:
    refused(world, go(world, "security", "--worktree", str(world.worktree), worktree=False))
    refused(world, go(world, "copy", "--worktree", str(world.worktree), worktree=False))
    refused(world, go(world, "review", worktree=False))
    refused(world, go(world, "implementer", worktree=False))


@pytest.mark.parametrize("seconds", ["0", "-1", "3601", "abc"])
def test_refuses_a_timeout_out_of_bounds(world: World, seconds: str) -> None:
    refused(world, go(world, "review", "--timeout", seconds))


def test_unset_config_is_exit_2_naming_the_key_and_the_callers_path_is_never_searched(
    world: World, capsys: pytest.CaptureFixture[str]
) -> None:
    (world.home / ".config" / "safo" / "codex-run.json").unlink()
    assert (world.bin / "codex").exists() and str(world.bin) in world.env["PATH"]  # a codex IS on the caller's PATH
    refused(world, go(world, "review"))
    err = capsys.readouterr().err
    assert '"codex"' in err and "codex-run.json" in err


@pytest.mark.parametrize("body", ["not json", "[]", '{"node": "/usr/bin/node"}', '{"codex": "relative/codex"}'])
def test_refuses_an_unusable_config(world: World, body: str) -> None:
    config = world.home / ".config" / "safo" / "codex-run.json"
    config.write_text(body)
    refused(world, go(world, "review"))


def test_refuses_a_config_that_others_can_write(world: World) -> None:
    (world.home / ".config" / "safo" / "codex-run.json").chmod(0o664)
    refused(world, go(world, "review"))


def test_refuses_a_codex_binary_others_can_write(world: World) -> None:
    (world.bin / "codex").chmod(0o777)
    refused(world, go(world, "review"))


def test_refuses_a_codex_in_a_folder_others_can_write(world: World) -> None:
    world.bin.chmod(0o775)  # the folder holding the binary
    refused(world, go(world, "review"))


def test_refuses_a_codex_whose_real_path_runs_through_a_writable_folder(world: World, tmp_path: Path) -> None:
    loose = tmp_path / "loose"
    loose.mkdir()
    (loose / "codex").write_text((world.bin / "codex").read_text())
    (loose / "codex").chmod(0o755)
    loose.chmod(0o777)
    link = world.bin / "codex-link"
    link.symlink_to(loose / "codex")
    config = world.home / ".config" / "safo" / "codex-run.json"
    config.write_text(f'{{"codex": "{link}"}}')
    refused(world, go(world, "review"))


def test_refuses_a_codex_owned_by_someone_else(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 4242)  # we are "not the owner" of anything here
    assert codexrun.main(["--class", "review", "--prompt-file", "x"], env=world.env, home=str(world.home)) == 2
    assert world.calls() == []


# -- git: nothing the repository controls may run ---------------------------------------------------------------


def hostile_script(tmp_path: Path) -> Path:
    marker = tmp_path / "ran-marker"
    script = tmp_path / "hostile.sh"
    script.write_text(f"#!/bin/sh\necho ran > {marker}\n")
    script.chmod(0o755)
    return marker


def test_a_hostile_fsmonitor_in_the_repository_config_is_refused_and_never_runs(world: World, tmp_path: Path) -> None:
    marker = hostile_script(tmp_path)
    git(world.dev / "repo", "config", "core.fsmonitor", str(tmp_path / "hostile.sh"))
    refused(world, go(world, "implementer"))
    assert not marker.exists()


@pytest.mark.parametrize(
    "key", ["filter.x.clean", "filter.x.smudge", "diff.x.textconv", "alias.st", "include.path", "core.sshCommand"]
)
def test_a_program_key_in_the_repository_config_is_refused_and_never_runs(
    world: World, tmp_path: Path, key: str
) -> None:
    marker = hostile_script(tmp_path)
    git(world.dev / "repo", "config", key, str(tmp_path / "hostile.sh"))
    refused(world, go(world, "implementer"))
    assert not marker.exists()
    refused(world, go(world, "review"))


@pytest.mark.parametrize("key", ["protocol.ssh.allow", "protocol.file.allow", "Protocol.Ext.Allow", "protocol.allow"])
def test_a_protocol_key_in_the_repository_config_is_refused_and_never_runs(
    world: World, tmp_path: Path, key: str
) -> None:
    marker = hostile_script(tmp_path)
    git(world.dev / "repo", "config", key, "always")
    refused(world, go(world, "implementer"))
    assert not marker.exists()
    refused(world, go(world, "review"))


def test_a_clean_repository_config_still_passes(world: World) -> None:
    assert go(world, "implementer") == 0


HOSTILE_CONFIGS = {
    "tab-in-subsection": '[filter "a\tb"]\n\tclean = x\n',
    "command-lookalike-in-value": '[core]\n\tn = "a\\ncommand\\tprotocol.allow\\nnever"\n[filter "f"]\n\tclean = y\n',
    "newline-in-value": '[core]\n\tnote = "a\\nb"\n[alias]\n\tq = "!echo hi"\n',
    "long-entry-first": "[core]\n\tnote = " + "a" * 200_000 + "\n[core]\n\tsshCommand = id\n",
    "valueless-key-first": '[x]\n\tnovalue\n[protocol "file"]\n\tallow = always\n',
    "protocol-mixed-case": '[Protocol "SSH"]\n\tAllow = always\n',
    "filter-process": '[filter "f"]\n\tprocess = x\n',
}


@pytest.mark.parametrize("name", sorted(HOSTILE_CONFIGS))
def test_hostile_config_text_is_refused_by_the_real_git_listing(tmp_path: Path, name: str) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    gitbin = shutil.which("git")
    assert gitbin
    subprocess.run([gitbin, "init", "-q", str(repo)], check=True, env={"PATH": "/usr/bin:/bin"})  # noqa: S603
    with open(repo / ".git" / "config", "a", encoding="utf-8") as handle:
        handle.write(HOSTILE_CONFIGS[name])
    with pytest.raises(codexrun.CodexRunError):
        codexrun.check_repo_config(gitbin, str(tmp_path), str(repo))


def real_repo(tmp_path: Path) -> tuple[str, Path]:
    repo = tmp_path / "r"
    repo.mkdir()
    gitbin = shutil.which("git")
    assert gitbin
    subprocess.run([gitbin, "init", "-q", str(repo)], check=True, env={"PATH": "/usr/bin:/bin"})  # noqa: S603
    return gitbin, repo


def real_config(gitbin: str, repo: Path, key: str, value: str) -> None:
    env = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    subprocess.run([gitbin, "-C", str(repo), "config", key, value], check=True, env=env)  # noqa: S603


# Classes of key the old denylist missed. Each one is real git config text, listed by real git, and must be refused.
PROGRAM_KEYS = [  # keys that name a program git may start
    "merge.x.driver",
    "diff.x.command",
    "diff.x.cmd",
    "difftool.x.cmd",
    "mergetool.x.cmd",
    "mergetool.x.path",
    "gpg.program",
    "gpg.ssh.program",
    "gpg.x509.program",
    "gpg.openpgp.program",
    "pager.status",
    "sequence.editor",
    "core.alternateRefsCommand",
    "core.fsmonitor",
    "core.hooksPath",
    "core.worktree",
    "uploadpack.packObjectsHook",
    "remote.x.uploadpack",
    "remote.x.vcs",
    "submodule.x.update",
    "sendemail.smtpserver",
    "http.proxy",
    "diff.external",
    "credential.helper",
    "protocol.ssh.allow",
    "url.x.insteadof",
]
SIGNING_KEYS = ["commit.gpgsign", "tag.gpgsign", "push.gpgsign", "user.signingkey", "gpg.format"]
UNKNOWN_KEYS = ["zzz.unknown", "core.somethingnew", "branch.x.unknownsetting", "x.y.z.w"]


@pytest.mark.parametrize("key", PROGRAM_KEYS)
def test_a_program_key_outside_the_allowlist_is_refused_by_real_git(tmp_path: Path, key: str) -> None:
    gitbin, repo = real_repo(tmp_path)
    real_config(gitbin, repo, key, "/bin/false")
    with pytest.raises(codexrun.CodexRunError):
        codexrun.check_repo_config(gitbin, str(tmp_path), str(repo))


@pytest.mark.parametrize("key", SIGNING_KEYS)
def test_a_signing_key_is_refused_by_real_git(tmp_path: Path, key: str) -> None:
    gitbin, repo = real_repo(tmp_path)
    real_config(gitbin, repo, key, "true")
    with pytest.raises(codexrun.CodexRunError):
        codexrun.check_repo_config(gitbin, str(tmp_path), str(repo))


@pytest.mark.parametrize("key", UNKNOWN_KEYS)
def test_an_unknown_key_is_refused_fail_closed_by_real_git(tmp_path: Path, key: str) -> None:
    gitbin, repo = real_repo(tmp_path)
    real_config(gitbin, repo, key, "x")
    with pytest.raises(codexrun.CodexRunError):
        codexrun.check_repo_config(gitbin, str(tmp_path), str(repo))


INERT_KEYS = {  # the guard bites only on what it should: these stay accepted
    "user.name": "Someone",
    "user.email": "someone@example.invalid",
    "remote.origin.url": "https://example.invalid/x.git",
    "remote.origin.fetch": "+refs/heads/*:refs/remotes/origin/*",
    "branch.main.remote": "origin",
    "branch.main.merge": "refs/heads/main",
    "branch.feat/x.vscode-merge-base": "origin/main",
    "core.autocrlf": "false",
    "init.defaultbranch": "main",
}


def test_an_inert_repository_config_still_passes_real_git(tmp_path: Path) -> None:
    gitbin, repo = real_repo(tmp_path)
    for key, value in INERT_KEYS.items():
        real_config(gitbin, repo, key, value)
    codexrun.check_repo_config(gitbin, str(tmp_path), str(repo))


def sub_gitdir(sub: Path) -> Path:
    return Path(git(sub, "rev-parse", "--absolute-git-dir"))


def test_a_real_initialized_submodule_has_a_core_worktree_and_is_accepted(world: World, tmp_path: Path) -> None:
    sub = add_submodule(world, tmp_path)
    assert git(sub, "config", "--local", "core.worktree")  # git itself wrote it, relative to the git directory
    assert go(world, "implementer") == 0


def test_core_worktree_pointing_outside_the_submodule_is_refused(world: World, tmp_path: Path) -> None:
    sub = add_submodule(world, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    gitdir = sub_gitdir(sub)
    git(sub, "config", "--local", "core.worktree", os.path.relpath(outside, gitdir))
    assert Path(git(sub, "rev-parse", "--show-toplevel")).resolve() == outside.resolve()  # real git follows it
    refused(world, go(world, "implementer"))
    refused(world, go(world, "review"))


def test_core_worktree_reaching_outside_through_a_symlink_is_refused(world: World, tmp_path: Path) -> None:
    sub = add_submodule(world, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    gitdir = sub_gitdir(sub)
    (gitdir / "lnk").symlink_to(outside)
    git(sub, "config", "--local", "core.worktree", "lnk")
    assert Path(git(sub, "rev-parse", "--show-toplevel")).resolve() == outside.resolve()
    refused(world, go(world, "implementer"))


@pytest.mark.parametrize("value", ["/abs/elsewhere", "", "../.."])
def test_core_worktree_with_another_value_is_refused(world: World, tmp_path: Path, value: str) -> None:
    sub = add_submodule(world, tmp_path)
    git(sub, "config", "--local", "core.worktree", value)
    refused(world, go(world, "implementer"))


HOSTILE_VALUES = [  # (key, value): an allowlisted key with a value that starts a helper, moves trust or is not a URL
    ("remote.origin.url", "ext::sh -c id"),
    ("remote.origin.url", "fd::17"),
    ("remote.origin.url", "file:///etc"),
    ("remote.origin.url", "/some/local/path"),
    ("remote.origin.url", "../relative"),
    ("remote.origin.url", "-oProxyCommand=x"),
    ("remote.origin.url", "https://example.invalid/a b.git"),
    ("remote.origin.pushurl", "ext::sh -c id"),
    ("remote.origin.pushurl", "file:///tmp/x"),
    ("submodule.sub.url", "ext::sh -c id"),
    ("submodule.sub.url", "/local/upstream"),
    ("remote.origin.fetch", "+ext::x:refs/remotes/o/*"),
    ("remote.origin.fetch", "--upload-pack=x"),
    ("remote.origin.fetch", "+heads/*:refs/x"),
    ("remote.origin.fetch", "+refs/heads/*:../../x"),
    ("remote.origin.tagopt", "--upload-pack=x"),
    ("branch.main.remote", "ext::x"),
    ("branch.main.remote", "-x"),
    ("branch.main.merge", "-x"),
    ("branch.main.merge", "heads/main"),
    ("branch.main.pushremote", "ext::x"),
    ("branch.main.rebase", "!sh"),
]


@pytest.mark.parametrize(("key", "value"), HOSTILE_VALUES)
def test_an_allowlisted_key_with_a_hostile_value_is_refused_by_real_git(tmp_path: Path, key: str, value: str) -> None:
    gitbin, repo = real_repo(tmp_path)
    real_config(gitbin, repo, key, value)
    with pytest.raises(codexrun.CodexRunError):
        codexrun.check_repo_config(gitbin, str(tmp_path), str(repo))


def test_a_hostile_second_value_of_a_repeated_key_is_refused_by_real_git(tmp_path: Path) -> None:
    gitbin, repo = real_repo(tmp_path)
    real_config(gitbin, repo, "remote.origin.url", "https://example.invalid/a.git")
    env = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    subprocess.run(  # noqa: S603
        [gitbin, "-C", str(repo), "config", "--add", "remote.origin.url", "ext::sh -c id"], check=True, env=env
    )
    with pytest.raises(codexrun.CodexRunError):
        codexrun.check_repo_config(gitbin, str(tmp_path), str(repo))


@pytest.mark.parametrize("byte", ["\x01", "\x1b", "\x7f"])
def test_a_control_byte_in_any_value_is_refused_by_real_git(tmp_path: Path, byte: str) -> None:
    gitbin, repo = real_repo(tmp_path)
    with open(repo / ".git" / "config", "a", encoding="utf-8") as handle:
        handle.write(f'[user]\n\tname = "a{byte}b"\n')
    with pytest.raises(codexrun.CodexRunError):
        codexrun.check_repo_config(gitbin, str(tmp_path), str(repo))


def test_a_value_with_a_newline_or_a_leading_dash_is_refused_by_real_git(tmp_path: Path) -> None:
    gitbin, repo = real_repo(tmp_path)
    with open(repo / ".git" / "config", "a", encoding="utf-8") as handle:
        handle.write('[user]\n\tname = "a\\nb"\n')
    with pytest.raises(codexrun.CodexRunError):
        codexrun.check_repo_config(gitbin, str(tmp_path), str(repo))
    (tmp_path / "two").mkdir()
    gitbin, repo2 = real_repo(tmp_path / "two")
    real_config(gitbin, repo2, "user.name", "-x")
    with pytest.raises(codexrun.CodexRunError):
        codexrun.check_repo_config(gitbin, str(tmp_path), str(repo2))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("remote.origin.url", "https://example.invalid/x.git"),
        ("remote.origin.url", "ssh://git@example.invalid/x.git"),
        ("remote.origin.url", "git@example.invalid:owner/x.git"),
        ("remote.origin.pushurl", "git@example.invalid:owner/x.git"),
        ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"),
        ("remote.origin.fetch", "refs/heads/main:refs/remotes/origin/main"),
        ("remote.origin.tagopt", "--no-tags"),
        ("branch.feat/x.merge", "refs/heads/feat/x"),
        ("branch.main.remote", "origin"),
        ("branch.main.rebase", "true"),
        ("branch.main.description", "a plain description"),
    ],
)
def test_an_allowlisted_key_with_an_ordinary_value_still_passes_real_git(tmp_path: Path, key: str, value: str) -> None:
    gitbin, repo = real_repo(tmp_path)
    real_config(gitbin, repo, key, value)
    codexrun.check_repo_config(gitbin, str(tmp_path), str(repo))


def fake_git(tmp_path: Path, text: str) -> str:
    script = tmp_path / "fakegit"
    script.write_text(f"#!/bin/sh\necho '{text}'\n")
    script.chmod(0o755)
    return str(script)


@pytest.mark.parametrize("text", ["git version 2.31.9", "git version 1.8.0", "no version here", "", "git version x.y"])
def test_a_git_that_is_too_old_or_unreadable_is_refused(tmp_path: Path, text: str) -> None:
    with pytest.raises(codexrun.CodexRunError):
        codexrun.check_git_version(fake_git(tmp_path, text), str(tmp_path))


@pytest.mark.parametrize("text", ["git version 2.32.0", "git version 2.47.3", "git version 3.0.1.windows.1"])
def test_a_git_at_or_above_the_minimum_is_accepted(tmp_path: Path, text: str) -> None:
    codexrun.check_git_version(fake_git(tmp_path, text), str(tmp_path))


def test_the_real_git_passes_the_version_gate(tmp_path: Path) -> None:
    gitbin = shutil.which("git")
    assert gitbin
    codexrun.check_git_version(gitbin, str(tmp_path))


def test_the_version_gate_runs_in_the_worktree_check(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(codexrun, "MIN_GIT_VERSION", (99, 0))
    refused(world, go(world, "review"))


def test_real_git_resolves_every_hostile_setting_to_the_forced_value(world: World, tmp_path: Path) -> None:
    """Ask real git which value wins, using the environment the child really got, against a repository config that
    sets every one of them to a hostile program."""
    assert go(world, "review") == 0
    env = dict(world.calls()[0]["env"])
    gitbin = shutil.which("git")
    assert gitbin
    repo = tmp_path / "hostile-repo"
    subprocess.run([gitbin, "init", "-q", str(repo)], check=True, env={"PATH": "/usr/bin:/bin"})  # noqa: S603
    script = str(tmp_path / "hostile.sh")
    keys = [
        "core.editor",
        "sequence.editor",
        "core.askPass",
        "core.gitProxy",
        "interactive.diffFilter",
        "core.pager",
        "core.sshCommand",
        "gpg.program",
        "gpg.ssh.program",
        "commit.gpgsign",
        "tag.gpgsign",
        "core.alternateRefsCommand",
        "core.fsmonitor",
        "core.hooksPath",
    ]
    for key in keys:
        real_config(gitbin, repo, key, script)
    real_config(gitbin, repo, "credential.helper", script)
    env["PATH"] = "/usr/bin:/bin"

    def ask(*args: str) -> str:
        done = subprocess.run(  # noqa: S603
            [gitbin, "-C", str(repo), *args], env=env, capture_output=True, text=True, check=True
        )
        return done.stdout.strip()

    for key in keys:
        assert script not in ask("config", "--get", key), key
    assert ask("config", "--get", "commit.gpgsign") == "false"
    assert ask("var", "GIT_EDITOR") == "/bin/false"
    assert ask("var", "GIT_PAGER") == "cat"
    assert ask("var", "GIT_SEQUENCE_EDITOR") == "/bin/false"
    assert (
        ask("config", "--show-scope", "--get-all", "credential.helper").splitlines()[-1].startswith("command")
    )  # reset
    assert env["GIT_ASKPASS"] == "/bin/false" and "GIT_EXTERNAL_DIFF" not in env


def test_the_allowlist_refuses_a_key_with_a_subsection_in_an_exact_only_section() -> None:
    assert not codexrun.config_key_is_inert("user.x.name")
    assert not codexrun.config_key_is_inert("core.x.bare")
    assert not codexrun.config_key_is_inert("remote.origin.uploadpack")
    assert codexrun.config_key_is_inert("remote.a.b.url")  # a subsection may hold dots
    assert codexrun.config_key_is_inert("USER.NAME")  # git lists keys in lower case; the check lowers them anyway


def test_the_child_git_environment_forces_signing_and_programs_off(world: World) -> None:
    assert go(world, "review") == 0
    env = world.calls()[0]["env"]
    pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
    for key in ("commit.gpgsign", "tag.gpgsign", "push.gpgsign"):
        assert pairs[key] == "false"
    for key in (
        "gpg.program",
        "gpg.ssh.program",
        "gpg.x509.program",
        "gpg.openpgp.program",
        "core.alternateRefsCommand",
    ):
        assert pairs[key] == "/bin/false"
    assert pairs["core.pager"] == "cat" and pairs["core.sshCommand"] == "/bin/false"


def test_a_plain_repository_passes_the_real_git_listing(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    gitbin = shutil.which("git")
    assert gitbin
    subprocess.run([gitbin, "init", "-q", str(repo)], check=True, env={"PATH": "/usr/bin:/bin"})  # noqa: S603
    codexrun.check_repo_config(gitbin, str(tmp_path), str(repo))


def test_the_skipped_command_settings_match_the_options_the_wrapper_passes() -> None:
    passed = {tuple(item.split("=", 1)) for item in codexrun.GIT_HARDENING if "=" in item and not item.startswith("--")}
    assert {(k.lower(), v) for k, v in passed} == set(codexrun.WRAPPER_COMMAND_SETTINGS)


@pytest.mark.parametrize(
    "listing",
    [
        "",  # nothing listed: not a real repository listing
        "local\0",  # a scope with no record
        "local\tfilter.x.clean\nx\0",  # one token, the form this parser must not accept
        "weird\0filter.x.clean\nx\0",  # unknown scope
        "local\0\0",  # empty key
        "command\0filter.x.clean\nx\0",  # a command-scope record that is not the wrapper's own
        "command\0protocol.allow\nalways\0",  # the wrapper's key with another value
        "command\0protocol.file.allow\nalways\0",  # a command-scope protocol key the wrapper did not pass
        "local\0core.bare\nfalse\0local\0",  # odd token count
    ],
)
def test_a_listing_that_does_not_parse_is_refused(monkeypatch: pytest.MonkeyPatch, listing: str) -> None:
    monkeypatch.setattr(codexrun, "_git", lambda *args, **kwargs: listing)
    with pytest.raises(codexrun.CodexRunError):
        codexrun.check_repo_config("git", "/home/x", "/home/x/r")


def test_only_the_wrappers_own_command_settings_are_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    listing = "".join(f"command\0{k}\n{v}\0" for k, v in sorted(codexrun.WRAPPER_COMMAND_SETTINGS))
    listing += "local\0core.bare\nfalse\0local\0core.symlinks\0"
    monkeypatch.setattr(codexrun, "_git", lambda *args, **kwargs: listing)
    monkeypatch.setattr(codexrun, "_submodule_folders", lambda *args, **kwargs: [])
    codexrun.check_repo_config("git", "/home/x", "/home/x/r")


def add_submodule(world: World, tmp_path: Path) -> Path:
    """A committed, initialized submodule `sub` in the worktree; returns its working folder."""
    upstream = tmp_path / "upstream"
    make_repo(upstream, {"s.txt": "s\n"})
    wt = world.worktree
    git(wt, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(upstream), "sub")
    git(wt, "commit", "-q", "-m", "add sub")
    web_urls(wt, wt / "sub")
    return wt / "sub"


def web_urls(wt: Path, sub: Path) -> None:
    """Point the local-path URLs git recorded at an https URL: a local path is not an accepted URL form."""
    git(wt, "config", "submodule.sub.url", "https://example.invalid/sub.git")
    git(sub, "config", "remote.origin.url", "https://example.invalid/sub.git")


@pytest.mark.parametrize("key", ["filter.x.clean", "diff.x.textconv", "alias.st", "core.sshCommand"])
def test_a_program_key_in_a_submodule_config_is_refused_and_never_runs(world: World, tmp_path: Path, key: str) -> None:
    sub = add_submodule(world, tmp_path)
    marker = hostile_script(tmp_path)
    git(sub, "config", key, str(tmp_path / "hostile.sh"))
    refused(world, go(world, "implementer"))
    assert not marker.exists()
    refused(world, go(world, "review"))


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_an_index_flag_that_hides_a_modified_file_is_refused(world: World, flag: str) -> None:
    wt = world.worktree
    git(wt, "update-index", flag, "a.txt")
    (wt / "a.txt").write_text("changed behind the flag\n")
    refused(world, go(world, "implementer"))


def test_the_child_git_environment_is_scrubbed(world: World) -> None:
    assert go(world, "review") == 0
    env = world.calls()[0]["env"]
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert env["GIT_ATTR_NOSYSTEM"] == "1" and env["GIT_TERMINAL_PROMPT"] == "0"
    pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
    assert pairs["core.fsmonitor"] == "false" and pairs["core.hooksPath"] == "/dev/null"
    assert pairs["protocol.allow"] == "never" and pairs["protocol.ext.allow"] == "never"


def test_documented_boundary_a_filter_added_during_the_run_still_runs_for_the_child(
    world: World, tmp_path: Path
) -> None:
    """Residual risk, documented in docs/codex-run.md: environment settings cannot name a filter driver that the repo
    config defines later, so a process that can write the repository config while codex runs can still get a
    `filter.*` program started by codex's own `git status`. The scrubbed environment closes fsmonitor and hooks only."""
    fsmonitor_marker = tmp_path / "fsmonitor-ran"
    fsmonitor = tmp_path / "fsmonitor.sh"
    fsmonitor.write_text(f"#!/bin/sh\necho ran > {fsmonitor_marker}\n")
    fsmonitor.chmod(0o755)
    filter_marker = hostile_script(tmp_path)
    wt = world.worktree
    (wt / ".gitattributes").write_text("*.txt filter=x\n")
    git(wt, "add", ".gitattributes")
    git(wt, "commit", "-q", "-m", "attrs")
    assert go(world, "review") == 0  # the config is clean when the check runs
    env = world.calls()[0]["env"]
    git(wt, "config", "filter.x.clean", str(tmp_path / "hostile.sh"))  # written while codex runs
    git(wt, "config", "core.fsmonitor", str(fsmonitor))
    (wt / "a.txt").write_text("b\n")
    done = subprocess.run(  # noqa: S603 - fixed argv, scrubbed env, test only
        ["git", "-C", str(wt), "status", "--porcelain"],  # noqa: S607
        env={k: v for k, v in env.items() if k in ("PATH", "HOME") or k.startswith("GIT_")},
        capture_output=True,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    assert done.returncode == 0
    assert not fsmonitor_marker.exists()  # closed by the scrubbed environment
    assert filter_marker.exists()  # the boundary: not closed, and not claimed closed


def test_a_clean_submodule_is_accepted(world: World, tmp_path: Path) -> None:
    add_submodule(world, tmp_path)
    assert go(world, "implementer") == 0


def hostile_repo(tmp_path: Path, key: str = "filter.x.clean") -> Path:
    hostile = tmp_path / "hostile-repo"
    make_repo(hostile, {"x": "x\n"})
    git(hostile, "config", key, str(tmp_path / "hostile.sh"))
    return hostile


def test_a_config_changed_after_the_check_never_runs_a_program(
    world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = hostile_script(tmp_path)
    wt = world.worktree
    (wt / ".gitattributes").write_text("*.txt filter=x\n")
    (wt / "victim.txt").write_text("before\n")
    git(wt, "add", ".gitattributes", "victim.txt")
    git(wt, "commit", "-q", "-m", "filtered file")
    (wt / "victim.txt").write_text("after\n")
    real_run = subprocess.run
    injected = False

    def race(argv: list[str], **kwargs: Any) -> Any:
        nonlocal injected
        result = real_run(argv, **kwargs)
        if not injected and argv[-4:] == ["config", "--list", "--show-scope", "-z"]:
            injected = True
            common = Path(git(wt, "rev-parse", "--git-common-dir"))
            if not common.is_absolute():
                common = wt / common
            with (common / "config").open("a") as config:
                config.write(f'\n[filter "x"]\n    clean = {tmp_path / "hostile.sh"}\n')
        return result

    monkeypatch.setattr(subprocess, "run", race)
    # victim.txt is dirty and not named, so the run is refused; what matters is that no program ran on the way
    refused(world, go(world, "implementer"))
    assert injected
    assert not marker.exists()


def test_a_symlinked_submodule_path_is_refused(world: World, tmp_path: Path) -> None:
    sub = add_submodule(world, tmp_path)
    marker = hostile_script(tmp_path)
    hostile = hostile_repo(tmp_path, "alias.pwn")
    shutil.rmtree(sub)
    sub.symlink_to(hostile, target_is_directory=True)
    refused(world, go(world, "implementer"))
    refused(world, go(world, "review"))
    assert not marker.exists()


def test_a_non_utf8_submodule_name_is_still_checked(world: World, tmp_path: Path) -> None:
    upstream = tmp_path / "upstream"
    make_repo(upstream, {"x": "x\n"})
    wt_b = os.fsencode(world.worktree)
    name_b = b"sub-" + bytes([255])
    cmd = [b"git", b"-C", wt_b, b"-c", b"protocol.file.allow=always", b"submodule", b"add", b"-q"]
    subprocess.run([*cmd, os.fsencode(upstream), name_b], check=True, stdin=subprocess.DEVNULL)  # noqa: S603
    git(world.worktree, "commit", "-q", "-m", "add byte-name submodule")
    alias = os.fsencode("!" + str(tmp_path / "hostile.sh"))
    subprocess.run(  # noqa: S603
        [b"git", b"-C", wt_b + b"/" + name_b, b"config", b"alias.pwn", alias], check=True, stdin=subprocess.DEVNULL
    )
    refused(world, go(world, "implementer"))
    refused(world, go(world, "review"))


def test_a_submodule_with_a_redirected_gitdir_is_checked(world: World, tmp_path: Path) -> None:
    sub = add_submodule(world, tmp_path)
    hostile = hostile_repo(tmp_path)
    (sub / ".git").unlink()
    (sub / ".git").write_text(f"gitdir: {hostile / '.git'}\n")
    refused(world, go(world, "implementer"))


def test_a_symlinked_submodule_gitfile_is_checked(world: World, tmp_path: Path) -> None:
    sub = add_submodule(world, tmp_path)
    hostile = hostile_repo(tmp_path)
    (sub / ".git").unlink()
    (sub / ".git").symlink_to(hostile / ".git")
    refused(world, go(world, "implementer"))


def test_an_absent_submodule_folder_is_skipped(world: World, tmp_path: Path) -> None:
    sub = add_submodule(world, tmp_path)
    shutil.rmtree(sub)
    assert go(world, "review") == 0


def test_the_submodule_depth_limit_bites_only_at_the_limit(world: World, tmp_path: Path) -> None:
    add_submodule(world, tmp_path)
    git_bin = shutil.which("git")
    assert git_bin
    root, home = str(world.worktree), str(world.home)
    codexrun.check_repo_config(git_bin, home, root, codexrun.MAX_SUBMODULE_DEPTH - 1)
    with pytest.raises(codexrun.CodexRunError):
        codexrun.check_repo_config(git_bin, home, root, codexrun.MAX_SUBMODULE_DEPTH)


def test_git_status_ignores_submodules_and_does_not_recurse(
    world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    add_submodule(world, tmp_path)
    seen: list[list[str]] = []
    real_run = subprocess.run

    def spy(argv: list[str], **kwargs: Any) -> Any:
        seen.append(list(argv))
        return real_run(argv, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    assert go(world, "implementer") == 0
    status = [a for a in seen if "status" in a]
    assert status
    for argv in status:
        assert "--ignore-submodules=all" in argv and "submodule.recurse=false" in argv
        assert "core.attributesFile=/dev/null" in argv
    assert any(a[a.index("-C") + 1].endswith("/sub") and "config" in a for a in seen)  # the submodule was inspected


def test_git_runs_with_the_hardening_options_and_a_clean_environment(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[list[str], dict[str, str]]] = []
    real_run = subprocess.run

    def spy(argv: list[str], **kwargs: Any) -> Any:
        seen.append((list(argv), dict(kwargs["env"])))
        return real_run(argv, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    assert go(world, "implementer") == 0
    assert seen
    for argv, env in seen:
        for word in ("--no-optional-locks", "core.fsmonitor=false", "protocol.allow=never", "core.hooksPath=/dev/null"):
            assert word in argv
        assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_CONFIG_GLOBAL"] == "/dev/null"
        assert env["GIT_ATTR_NOSYSTEM"] == "1"


def test_a_gitfile_pointing_inside_the_worktree_is_refused(world: World) -> None:
    fake = world.worktree / "fakegit" / ".git" / "worktrees" / "wt"
    fake.mkdir(parents=True)
    (fake / "gitdir").write_text(str(world.worktree / ".git"))
    (world.worktree / ".git").write_text(f"gitdir: {fake}\n")
    refused(world, go(world, "implementer"))


def test_check_gitfile_names_the_inside_the_worktree_case(world: World) -> None:
    fake = world.worktree / "fakegit" / ".git" / "worktrees" / "wt"
    fake.mkdir(parents=True)
    (fake / "gitdir").write_text(str(world.worktree / ".git"))
    marker = world.worktree / ".git"
    marker.write_text(f"gitdir: {fake}\n")
    with pytest.raises(codexrun.CodexRunError, match="outside the worktree"):
        codexrun.check_gitfile(str(marker), str(world.worktree.resolve()), str(world.home))


def test_trusted_binary_refuses_an_owner_that_is_not_us_or_root(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    codex = str(world.bin / "codex")
    assert codexrun.trusted_binary(codex, "codex") == codex
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 4242)
    with pytest.raises(codexrun.CodexRunError, match="owned by someone else"):
        codexrun.trusted_binary(codex, "codex")


def test_a_gitfile_pointing_at_another_repository_is_refused(world: World) -> None:
    (world.worktree / ".git").write_text(f"gitdir: {world.dev / 'repo' / '.git'}\n")  # not .git/worktrees/<name>
    refused(world, go(world, "review"))
    (world.worktree / ".git").write_text("gitdir: /tmp\n")
    refused(world, go(world, "review"))
    (world.worktree / ".git").write_text("not a gitfile\n")
    refused(world, go(world, "review"))


def test_a_gitfile_that_the_git_directory_does_not_name_back_is_refused(world: World) -> None:
    other = world.dev / "agents" / "other"
    git(world.dev / "repo", "worktree", "add", "-q", "-b", "other", str(other))
    (world.worktree / ".git").write_text((other / ".git").read_text())  # a real worktree gitdir, of another folder
    refused(world, go(world, "review"))


# -- 3. the cybersecurity-risk filter ---------------------------------------------------------------------------------


def test_filter_in_the_error_stream_exits_40_and_calls_codex_once(
    world: World, capsys: pytest.CaptureFixture[str]
) -> None:
    world.mode("filter")
    assert go(world, "security") == 40
    assert len(world.calls()) == 1  # no retry, no reword, no fallback model
    err = capsys.readouterr().err
    assert "TIER FILTERED" in err and "daybreak_blue" in err and "gpt-daybreak-blue-latest" in err
    assert "Do not reword" in err
    (row,) = world.ledger()
    assert row["exit"] == 40 and row["codex_exit"] == 1


def test_a_final_message_that_says_the_phrase_cannot_fake_a_cutoff(world: World) -> None:
    # was: exit 40 for a short final message holding the phrase. That text is model output, so a prompt could fake a
    # cutoff with it; a cutoff now needs a failed codex exit plus the phrase in codex's own streams (Daybreak r1).
    world.mode("filter-short")
    assert go(world, "security") == 0
    assert len(world.calls()) == 1


def test_a_structured_error_event_with_a_failed_exit_is_a_cutoff(world: World) -> None:
    world.mode("filter-event")
    assert go(world, "security") == 40


def test_the_phrase_in_a_model_event_is_not_a_cutoff(world: World) -> None:
    world.mode("spoof-event")  # an item event (model text) holding the phrase, codex exit 1
    assert go(world, "security") == 30


def test_padding_after_the_notice_cannot_hide_a_cutoff(world: World) -> None:
    world.mode("filter-padded")  # the notice, then 3 MB more on the error stream
    assert go(world, "security") == 40


def test_filter_on_a_general_class_says_no_tier_flag_was_set(world: World, capsys: pytest.CaptureFixture[str]) -> None:
    world.mode("filter")
    assert go(world, "review") == 40
    assert "no cyber tier flag" in capsys.readouterr().err
    assert len(world.calls()) == 1


def test_a_long_review_that_quotes_the_phrase_is_not_a_filter_cutoff(world: World) -> None:
    world.mode("quote-long")
    assert go(world, "security") == 0
    assert len(world.calls()) == 1


# -- the other exits ------------------------------------------------------------------------------------------------


def test_codex_failure_exits_30_and_records_its_own_code(world: World) -> None:
    world.mode("fail")
    assert go(world, "review") == 30
    (row,) = world.ledger()
    assert row["exit"] == 30 and row["codex_exit"] == 3


def test_hard_timeout_kills_codex_and_exits_124(world: World) -> None:
    world.mode("sleep")
    started = time.monotonic()
    assert go(world, "review", "--timeout", "1") == 124
    assert time.monotonic() - started < 20
    (row,) = world.ledger()
    assert row["exit"] == 124 and row["codex_exit"] is None


# -- environment, folders and the result ----------------------------------------------------------------------------


def test_environment_is_an_allow_list(world: World, tmp_path: Path) -> None:
    world.env.update(
        {
            "GH_TOKEN": "t1",
            "GITHUB_TOKEN": "t2",
            "OPENAI_API_KEY": "t3",
            "DOPPLER_TOKEN": "t4",
            "AWS_SECRET_ACCESS_KEY": "t5",
            "PYTHONPATH": "/x",
            "LD_PRELOAD": "/y",
            "HOME": "/not/the/account",
            "CODEX_HOME": str(tmp_path),
        }
    )
    assert go(world, "review") == 0
    env = world.calls()[0]["env"]
    assert {name for name in env if not name.startswith("GIT_")} <= {
        "PATH",
        "HOME",
        "CODEX_HOME",
        "LANG",
        "LC_ALL",
        "TMPDIR",
    }
    assert {"PATH", "HOME", "CODEX_HOME", "LANG", "LC_ALL", "TMPDIR"} <= set(env)
    assert env["HOME"] == str(world.home)
    # was: == str(tmp_path) (the caller's CODEX_HOME was inherited); now the owner config's, never the caller's
    assert env["CODEX_HOME"] == str(world.home / ".codex")
    assert env["PATH"].split(":")[0] == str(world.bin)
    assert os.path.dirname(env["TMPDIR"]).endswith("codex-run-scratch")
    for name in ("GH_TOKEN", "GITHUB_TOKEN", "OPENAI_API_KEY", "DOPPLER_TOKEN", "AWS_SECRET_ACCESS_KEY", "PYTHONPATH"):
        assert name not in env


def test_a_relative_codex_home_is_not_passed_on(world: World) -> None:
    world.env["CODEX_HOME"] = "relative/dir"
    assert go(world, "review") == 0
    assert world.calls()[0]["env"]["CODEX_HOME"] == str(world.home / ".codex")


def test_security_runs_from_an_empty_temporary_folder_that_is_removed_after(world: World) -> None:
    assert go(world, "security") == 0
    (call,) = world.calls()
    assert call["listing"] == []  # the working folder was empty when codex started
    assert os.path.basename(call["cwd"]).startswith("empty-")
    assert not Path(call["cwd"]).exists()
    assert str(world.worktree) not in call["cwd"]
    scratch = world.home / ".local" / "state" / "safo" / "codex-run-scratch"
    assert list(scratch.iterdir()) == []  # nothing left behind


def test_a_write_into_the_empty_folder_is_reported(world: World, capsys: pytest.CaptureFixture[str]) -> None:
    world.mode("stray")
    assert go(world, "copy") == 0
    assert "empty working folder was written to" in capsys.readouterr().err


def test_result_file_is_private_and_holds_the_final_message(world: World, capsys: pytest.CaptureFixture[str]) -> None:
    assert go(world, "review") == 0
    line = capsys.readouterr().out.strip()
    assert line.count("\n") == 0 and line.startswith("safo-codex-run: class=review exit=0 ")
    path = Path(line.split("out=")[1].split(" ")[0])
    assert path.read_text().startswith(OUTPUT_CANARY)
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert line.endswith("lines=1")


# -- 5. the ledger --------------------------------------------------------------------------------------------------


def test_one_ledger_row_per_run_with_counts_and_a_hash_only(world: World) -> None:
    assert go(world, "review") == 0
    assert go(world, "security") == 0
    first, second = world.ledger()
    data = world.prompt.read_bytes()
    assert set(first) == {  # plus run, status and confined (the started/finished pair, Daybreak r1)
        "ts", "class", "model", "sandbox", "tier", "exit", "codex_exit", "seconds", "prompt_bytes", "prompt_sha256",
        "run", "status", "confined",
    }  # fmt: skip
    assert first["class"] == "review" and first["model"] == "gpt-6.1-terra" and first["tier"] == "none"
    assert second["class"] == "security" and second["tier"] == "daybreak_blue"
    assert first["prompt_bytes"] == len(data)
    assert first["prompt_sha256"] == hashlib.sha256(data).hexdigest()
    assert first["exit"] == 0 and first["codex_exit"] == 0
    raw = (world.home / ".local" / "state" / "safo" / "codex-runs.jsonl").read_text()
    assert PROMPT_CANARY not in raw and OUTPUT_CANARY not in raw and "Review the change" not in raw
    ledger = world.home / ".local" / "state" / "safo" / "codex-runs.jsonl"
    assert ledger.stat().st_mode & 0o777 == 0o600


def test_the_ledger_never_holds_text_after_a_filtered_or_failed_run(world: World) -> None:
    for mode in ("filter", "fail", "filter-short"):
        world.mode(mode)
        go(world, "security")
    raw = (world.home / ".local" / "state" / "safo" / "codex-runs.jsonl").read_text()
    assert PROMPT_CANARY not in raw and OUTPUT_CANARY not in raw and "cybersecurity" not in raw


def test_the_hash_is_of_the_bytes_codex_received(world: World) -> None:
    assert go(world, "review") == 0
    (call,) = world.calls()
    (row,) = world.ledger()
    assert hashlib.sha256(call["stdin"].encode()).hexdigest() == row["prompt_sha256"]


def test_a_run_that_cannot_be_recorded_does_not_start(world: World) -> None:
    state = world.home / ".local" / "state" / "safo"
    state.mkdir(parents=True)
    (state / "codex-runs.jsonl").symlink_to(world.home / "elsewhere")
    assert go(world, "review") == 2
    assert world.calls() == []


def flaky_ledger(monkeypatch: pytest.MonkeyPatch, fail_on: str) -> None:
    real = codexrun.append_row

    def append(fd: int, row: Any) -> None:
        if row["status"] == fail_on:
            raise OSError(28, "No space left on device")
        real(fd, row)

    monkeypatch.setattr(codexrun, "append_row", append)


def test_a_started_row_that_cannot_be_written_means_codex_never_starts(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    flaky_ledger(monkeypatch, "started")
    assert go(world, "review") == 2
    assert world.calls() == [] and world.ledger_all() == []


def test_a_closing_row_that_cannot_be_written_is_never_exit_0(
    world: World, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    flaky_ledger(monkeypatch, "finished")
    assert go(world, "review") == codexrun.EXIT_UNRECORDED
    assert len(world.calls()) == 1
    (row,) = world.ledger_all()  # the started row survives as the record
    assert row["status"] == "started" and row["exit"] is None
    assert "could not be written" in capsys.readouterr().err


def test_every_run_leaves_a_started_and_a_finished_row_with_one_run_id(world: World) -> None:
    assert go(world, "review") == 0
    started, finished = world.ledger_all()
    assert (started["status"], finished["status"]) == ("started", "finished")
    assert started["run"] == finished["run"]


# -- 6. prompt confinement: hard links ------------------------------------------------------------------------------


def test_refuses_a_hard_link_to_a_file_outside_the_allowed_folders(world: World, tmp_path: Path) -> None:
    outside = tmp_path / "private-notes"
    outside.write_text("plain words with no secret shape\n")
    outside.chmod(0o600)
    link = world.dev / "prompts" / "hard.txt"
    os.link(outside, link)
    refused(world, go(world, "review", prompt=link))


# -- 7. CODEX_HOME comes from the owner config, never from the caller ----------------------------------------------


def test_the_callers_codex_home_is_never_inherited(world: World, tmp_path: Path) -> None:
    other = tmp_path / "repo-controlled"
    other.mkdir(mode=0o700)
    world.env["CODEX_HOME"] = str(other)
    assert go(world, "review") == 0
    assert world.calls()[0]["env"]["CODEX_HOME"] == str(world.home / ".codex")


def test_codex_home_can_be_set_in_the_owner_config(world: World) -> None:
    mine = world.home / "other-codex"
    mine.mkdir(mode=0o700)
    world.configure(codex_home=str(mine))
    assert go(world, "review") == 0
    assert world.calls()[0]["env"]["CODEX_HOME"] == str(mine)


def test_a_codex_home_that_is_unsafe_is_refused(world: World, tmp_path: Path) -> None:
    (world.home / ".codex").chmod(0o770)  # group writable
    refused(world, go(world, "review"))
    (world.home / ".codex").chmod(0o700)
    real = world.home / "real-codex"
    real.mkdir(mode=0o700)
    link = world.home / "link-codex"
    link.symlink_to(real)
    world.configure(codex_home=str(link))
    refused(world, go(world, "review"))
    world.configure(codex_home=str(world.home / "missing"))
    refused(world, go(world, "review"))
    world.configure(codex_home="relative/codex")
    refused(world, go(world, "review"))


# -- 8. worktree: parents and identity ------------------------------------------------------------------------------


def test_a_worktree_below_a_group_writable_parent_is_refused(world: World) -> None:
    (world.dev / "agents").chmod(0o775)
    refused(world, go(world, "review"))


def test_a_worktree_replaced_between_the_check_and_the_start_is_refused(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_env = codexrun.child_env

    def swap(*args: Any, **kwargs: Any) -> Any:
        marker = (world.worktree / ".git").read_text()
        world.worktree.rename(world.worktree.with_name("wt-old"))
        world.worktree.mkdir()
        (world.worktree / ".git").write_text(marker)
        return real_env(*args, **kwargs)

    monkeypatch.setattr(codexrun, "child_env", swap)
    refused(world, go(world, "review"))


# -- 9. read confinement of the empty-folder classes ----------------------------------------------------------------


def bwrap_usable() -> bool:
    cfg = codexrun.RunConfig("", None, "", codexrun.DEFAULT_BWRAP, True, (), ())
    return os.path.exists(cfg.bwrap) and codexrun.confinement_works(cfg)


@pytest.mark.parametrize("cls", ["security", "copy"])
def test_confined_classes_refuse_when_the_namespace_cannot_be_made(world: World, cls: str) -> None:
    broken = world.bin / "bwrap"
    broken.write_text("#!/bin/sh\nexit 1\n")
    broken.chmod(0o755)
    world.configure(confinement="bwrap", bwrap=str(broken))
    refused(world, go(world, cls))
    assert go(world, "review") == 0  # the worktree classes are not read-confined


@pytest.mark.skipif(not bwrap_usable(), reason="bubblewrap cannot make a user namespace here")
@pytest.mark.parametrize("cls", ["security", "copy"])
def test_a_prompt_cannot_read_the_account_in_the_confined_classes(world: World, cls: str) -> None:
    secret = world.home / "secret.txt"
    secret.write_text("PRIVATE-ACCOUNT-DATA\n")
    (world.bin / "state" / "probe").write_text(str(secret))
    assert go(world, cls) == 0  # confinement off: the fake reads the file, proving the probe works
    assert world.calls()[-1]["probe"] == "read:PRIVATE-ACCOUNT-DATA\n"
    world.configure(confinement="bwrap")
    assert go(world, cls) == 0
    call = world.calls()[-1]
    assert call["probe"] == "blocked"
    assert call["argv"][call["argv"].index("-s") + 1] == "read-only"
    assert call["env"]["CODEX_HOME"] == str(world.home / ".codex")
    (row,) = world.ledger()[-1:]
    assert row["confined"] is True


@pytest.mark.skipif(not bwrap_usable(), reason="bubblewrap cannot make a user namespace here")
def test_a_binary_folder_is_not_exposed_only_the_binary(world: World) -> None:
    sibling = (
        world.bin / "sibling-secret.txt"
    )  # next to codex, as a private file next to a binary under a home would be
    sibling.write_text("SIBLING-DATA\n")
    (world.bin / "state" / "probe").write_text(str(sibling))
    assert go(world, "security") == 0
    assert world.calls()[-1]["probe"] == "read:SIBLING-DATA\n"  # unconfined: readable, so the probe works
    world.configure(confinement="bwrap")
    assert go(world, "security") == 0
    assert world.calls()[-1]["probe"] == "blocked"


def test_confine_argv_binds_the_binary_file_not_its_folder(world: World) -> None:
    cfg = codexrun.configured_binaries(str(world.home), need_confinement=False)
    argv = codexrun.confine_argv(cfg, [cfg.codex], "/x/root", "/x/meta", "/x/res", str(world.home))
    binds = [argv[i + 1] for i, word in enumerate(argv) if word == "--ro-bind-try"]
    assert cfg.codex in binds and str(world.bin) not in binds


def test_an_exposed_path_that_is_or_contains_the_home_is_refused(world: World) -> None:
    cfg = codexrun.configured_binaries(str(world.home), need_confinement=False)
    home = str(world.home)
    for bad in (home, str(world.home.parent), "/"):
        for field in ("ro_paths", "rw_paths"):
            hostile = codexrun.RunConfig(**{**cfg.__dict__, field: (bad,)})
            with pytest.raises(codexrun.CodexRunError, match="account home"):
                codexrun.confine_argv(hostile, [cfg.codex], "/x/root", "/x/meta", "/x/res", home)
    world.home.chmod(0o700)
    world.configure(codex_home=home)  # a private folder of ours, but it IS the home
    refused(world, go(world, "review"))


def test_a_config_path_that_would_expose_the_home_is_refused(world: World) -> None:
    for key in ("ro_paths", "rw_paths"):
        world.configure(**{key: [str(world.home)]})
        refused(world, go(world, "review"))
        world.configure(**{key: [str(world.home.parent)]})
        refused(world, go(world, "review"))


def test_the_git_environment_never_fetches_lazily() -> None:
    assert codexrun.git_env("/home/x")["GIT_NO_LAZY_FETCH"] == "1"


def test_a_partial_clone_is_refused_and_a_missing_object_is_not_fetched(tmp_path: Path) -> None:
    """The shared config check sets GIT_NO_LAZY_FETCH and refuses a partial clone: safo-codex-run refuses rather than
    reaching for a promisor remote. The control shows plain git would have fetched the missing object."""
    gitbin = shutil.which("git")
    assert gitbin
    src = tmp_path / "src"
    src.mkdir()
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    ident = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]

    def run(cwd: Path, *args: str, extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(  # noqa: S603 - fixed argv
            [gitbin, *ident, *args], cwd=cwd, env={**env, **(extra or {})}, capture_output=True, check=False
        )

    assert run(src, "init", "-q").returncode == 0
    (src / "f").write_text("one\n")
    assert run(src, "add", "f").returncode == 0
    assert run(src, "commit", "-q", "-m", "m").returncode == 0
    assert run(src, "config", "uploadpack.allowFilter", "true").returncode == 0
    dst = tmp_path / "dst"
    cloned = run(tmp_path, "clone", "-q", "--no-checkout", "--filter=blob:none", f"file://{src}", str(dst))
    if cloned.returncode != 0:
        pytest.skip("this git cannot make a partial clone over file://")
    control = run(dst, "cat-file", "-p", "HEAD:f")
    assert control.returncode == 0 and control.stdout == b"one\n"  # plain git fetches the missing blob lazily
    shutil.rmtree(dst)
    assert (
        run(tmp_path, "clone", "-q", "--no-checkout", "--filter=blob:none", f"file://{src}", str(dst)).returncode == 0
    )
    shielded = run(dst, "cat-file", "-p", "HEAD:f", extra={"GIT_NO_LAZY_FETCH": "1"})
    assert shielded.returncode != 0  # with the variable the same read fails instead of fetching
    with pytest.raises(codexrun.CodexRunError):
        codexrun.check_repo_config(gitbin, str(tmp_path), str(dst))
