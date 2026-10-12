# SPDX-License-Identifier: MIT
"""The drift check (spec 8.14): the tree equals the render; an edit, a deletion, a stray file, a stale digest fails."""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from types import ModuleType

import pytest

from gendata import ROOT, load_script, scratch
from localcli import cli
from renderdata import RENDER_PATHS
from safo.agentsfile import load_agents
from safo.evidence import load_verified_agents
from safo.profile import GENERATED_MARKER
from safo.profile_render import render_harness


def written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[ModuleType, Path]:
    script, out = scratch(tmp_path, monkeypatch)
    assert script.main(["--write"]) == 0
    return script, out


def check(script: ModuleType, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = script.main(["--check"])
    return code, capsys.readouterr().err


def test_the_files_in_the_repository_are_what_agents_yaml_renders() -> None:
    v = load_verified_agents(ROOT / "agents.yaml", trusted=False)
    v.require_clean()
    expected = render_harness(v)
    assert expected, "the shipped agents.yaml profiles render something"
    out = ROOT / "examples" / "harness"
    on_disk = {str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()}
    assert on_disk == set(expected), "run: python scripts/gen_profiles.py --write"
    for rel, r in expected.items():
        assert (out / rel).read_bytes() == r.data, f"{rel}: run: python scripts/gen_profiles.py --write"


def test_the_check_flag_passes_on_the_repository() -> None:
    assert load_script().main(["--check"]) == 0


def test_profiles_verify_passes_on_the_repository_with_its_codeowners(_private_home: Path) -> None:
    code, out, err = cli("profiles", "verify", "--agents", str(ROOT / "agents.yaml"), home=_private_home)
    assert code == 0, out + err
    assert "CODEOWNERS covers" in out


def test_write_then_check_passes_and_writes_the_expected_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = written(tmp_path, monkeypatch)
    assert sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()) == sorted(RENDER_PATHS)
    capsys.readouterr()
    assert script.main(["--check"]) == 0
    seen = capsys.readouterr()
    assert seen.err == "" and "ok: examples/harness matches agents.yaml" in seen.out


def test_the_check_fails_on_a_hand_edit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = written(tmp_path, monkeypatch)
    target = out / "codex" / "codex.prompt.md"
    target.write_text(target.read_text().replace("Prepend", "Skip"))
    capsys.readouterr()
    code, err = check(script, capsys)
    assert code == 1 and "codex/codex.prompt.md" in err and "body digest" in err
    assert "gen_profiles.py --write" in err


def test_the_check_fails_on_a_deleted_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = written(tmp_path, monkeypatch)
    (out / "local" / "ollama.wrapper.txt").unlink()
    capsys.readouterr()
    code, err = check(script, capsys)
    assert code == 1 and "local/ollama.wrapper.txt" in err and "missing" in err


def test_the_check_fails_on_a_stray_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = written(tmp_path, monkeypatch)
    (out / "claude" / "stray.md").write_text("hello\n")
    capsys.readouterr()
    code, err = check(script, capsys)
    assert code == 1 and "claude/stray.md" in err and "unexpected" in err


def test_the_check_fails_on_a_stale_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = written(tmp_path, monkeypatch)
    target = out / "codex" / "codex.prompt.md"
    target.write_text(re.sub(r"manifest sha256:[0-9a-f]{64}", "manifest sha256:" + "0" * 64, target.read_text()))
    capsys.readouterr()
    code, err = check(script, capsys)
    assert code == 1 and "manifest digest" in err and "sources changed" in err


def test_a_changed_source_makes_the_check_fail_with_a_stale_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, _ = written(tmp_path, monkeypatch)
    lessons = tmp_path / "repo" / "docs" / "lessons.md"
    lessons.write_text(lessons.read_text().replace("The measured fact.", "A different fact."))
    capsys.readouterr()
    code, err = check(script, capsys)
    assert code == 1 and "manifest digest" in err
    assert "body digest" not in err  # the files were not edited, only their sources moved


def test_a_renamed_output_is_reported_never_deleted_and_the_tree_is_clean_once_the_owner_removes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = written(tmp_path, monkeypatch)
    old = out / "legacy" / "deep" / "old-name.prompt.md"
    old.parent.mkdir(parents=True)
    old.write_bytes((out / "codex" / "codex.prompt.md").read_bytes())  # a header-bearing generated file, retired path
    (out / "emptied").mkdir()
    capsys.readouterr()
    assert check(script, capsys)[0] == 1
    assert script.main(["--write"]) == 1
    err = capsys.readouterr().err
    assert "legacy/deep/old-name.prompt.md: unexpected file (looks generated but is not expected)" in err
    assert "git rm -- examples/harness/legacy/deep/old-name.prompt.md" in err and "emptied: unexpected directory" in err
    assert old.is_file() and (out / "emptied").is_dir(), "the generator deletes nothing"
    shutil.rmtree(out / "legacy")  # what `git rm -r` does
    (out / "emptied").rmdir()
    assert script.main(["--write"]) == 0 and check(script, capsys)[0] == 0
    assert sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()) == sorted(RENDER_PATHS)


def test_write_repairs_an_edited_file_and_is_a_no_op_on_a_clean_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = written(tmp_path, monkeypatch)
    target = out / "local" / "ollama.wrapper.txt"
    clean = target.read_bytes()
    inode = (out / "codex" / "codex.prompt.md").stat().st_ino
    target.write_text("edited\n")
    assert script.main(["--write"]) == 0
    assert target.read_bytes() == clean
    assert (out / "codex" / "codex.prompt.md").stat().st_ino == inode, "an unchanged file is not rewritten"
    assert check(script, capsys)[0] == 0
    assert not list(out.rglob(".*.tmp"))


def test_the_generated_files_each_carry_the_marker_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _, out = written(tmp_path, monkeypatch)
    for p in out.rglob("*"):
        if p.is_file():
            assert p.read_text().count(GENERATED_MARKER) == 1, p


def test_the_script_reads_only_the_repository_agents_file_not_the_local_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = scratch(tmp_path, monkeypatch)
    home = tmp_path / "home"
    (home / ".config" / "safo").mkdir(parents=True)
    override = "agents:\n  claude-haiku:\n    model: opus\n"
    for place in (home / ".config" / "safo" / "agents.local.yaml", tmp_path / "repo" / "agents.local.yaml"):
        place.write_text(override)
        place.chmod(0o600)
    monkeypatch.setenv("HOME", str(home))
    assert script.main(["--write"]) == 0
    assert "model: haiku" in (out / "claude" / "claude-haiku.md").read_text()
    assert check(script, capsys)[0] == 0
    assert load_agents(tmp_path / "repo" / "agents.yaml").agent("claude-haiku").model == "haiku"


def test_unresolved_evidence_fails_write_and_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, out = scratch(tmp_path, monkeypatch)
    (tmp_path / "repo" / "docs" / "lessons.md").write_text("# Lessons\n")
    for flag in ("--write", "--check"):
        assert script.main([flag]) == 1
        assert "evidence does not resolve" in capsys.readouterr().err
    assert not out.exists(), "nothing is written when the evidence does not resolve"


def test_a_form_error_in_agents_yaml_fails_with_one_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script, _ = scratch(tmp_path, monkeypatch)
    (tmp_path / "repo" / "agents.yaml").write_text("version: 2\n")
    assert script.main(["--check"]) == 1
    assert capsys.readouterr().err.startswith("error:")


def explicit_rules(text: str) -> set[str]:
    """The patterns of the CODEOWNERS lines other than the catch-all, as written."""
    rules = set()
    for line in text.splitlines():
        tokens = line.split("#", 1)[0].split()
        if len(tokens) >= 2 and tokens[0] != "*":
            rules.add(tokens[0])
    return rules


def missing_explicit(text: str, required: set[str]) -> set[str]:
    """The required paths with no explicit CODEOWNERS entry of their own (the catch-all does not count)."""
    return {path for path in required if "/" + path not in explicit_rules(text)}


def listed_paths() -> set[str]:
    """Every path the repository's CODEOWNERS must name: the checker's fixed list, the lessons file, the templates
    directory and the source files that render and write the profiles."""
    from safo.codeowners import REQUIRED

    extra = {
        "docs/lessons.md",
        "templates/",
        "src/safo/profile.py",
        "src/safo/harness_tree.py",
        "scripts/gen_profiles.py",
    }
    return set(REQUIRED) | extra


def test_codeowners_names_every_profile_path_explicitly_not_only_through_the_catch_all() -> None:
    text = (ROOT / ".github" / "CODEOWNERS").read_text()
    assert missing_explicit(text, listed_paths()) == set()
    assert len(listed_paths()) >= 11


def test_the_explicit_codeowners_check_bites_on_a_catch_all_only_file_and_on_each_dropped_entry() -> None:
    assert explicit_rules("* @owner\n") == set()
    assert explicit_rules("* @owner\n/agents.yaml @owner # note\n") == {"/agents.yaml"}
    text = (ROOT / ".github" / "CODEOWNERS").read_text()
    assert missing_explicit("* @owner\n", listed_paths()) == listed_paths()
    for path in listed_paths():
        dropped = "\n".join(x for x in text.splitlines() if x.split("#", 1)[0].split()[:1] != ["/" + path])
        assert missing_explicit(dropped, listed_paths()) == {path}, path
