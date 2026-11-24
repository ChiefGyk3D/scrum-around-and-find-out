# SPDX-License-Identifier: Apache-2.0
"""safo-codex-run against a fake codex on PATH (#431): flags per class, refusals, the filter, the ledger, the folder."""

from __future__ import annotations

import hashlib
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from codexrundata import OUTPUT_CANARY, PROMPT_CANARY, World, make_world
from gitrepo import git
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


def test_a_hostile_fsmonitor_in_the_repository_config_never_runs(world: World, tmp_path: Path) -> None:
    marker = hostile_script(tmp_path)
    git(world.dev / "repo", "config", "core.fsmonitor", str(tmp_path / "hostile.sh"))
    assert go(world, "implementer") == 0
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
    assert set(env) <= {"PATH", "HOME", "CODEX_HOME", "LANG", "LC_ALL", "TMPDIR"}
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
    (world.bin / "probe").write_text(str(secret))
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


def test_a_config_path_that_would_expose_the_home_is_refused(world: World) -> None:
    for key in ("ro_paths", "rw_paths"):
        world.configure(**{key: [str(world.home)]})
        refused(world, go(world, "review"))
        world.configure(**{key: [str(world.home.parent)]})
        refused(world, go(world, "review"))
