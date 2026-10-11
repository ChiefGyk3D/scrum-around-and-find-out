# SPDX-License-Identifier: MIT
"""`safo profiles verify`: the side-by-side table, the exit codes and the promotion information."""

from __future__ import annotations

from pathlib import Path

from evdata import repo, rec
from localcli import cli
from profiledata import LESSON, claim, doc, profile, put


def verify(path: Path, home: Path, *extra: str) -> tuple[int, str, str]:
    return cli("profiles", "verify", "--agents", str(path), *extra, home=home)


def test_every_claim_is_printed_with_its_evidence_kind_and_the_resolved_subject(tmp_path: Path, _private_home: Path) -> None:
    code, out, err = verify(repo(tmp_path), _private_home)
    assert code == 0, err
    line = next(x for x in out.splitlines() if x.startswith("agents.codex.profile.dont[0]"))
    assert "Expect it to commit inside a git worktree." in line  # the claim
    assert "[lessons]" in line  # the evidence kind
    assert "Codex's sandbox cannot commit inside a git worktree" in line and "The measured fact." in line  # the subject
    assert out.rstrip().splitlines()[-1].startswith("ok:")


def test_an_unresolved_claim_is_listed_and_the_exit_code_is_one(tmp_path: Path, _private_home: Path) -> None:
    d = doc()
    profile(d, "codex")["dont"] = [claim("Some claim.", "lessons:gone")]
    code, out, _ = verify(repo(tmp_path, d), _private_home)
    assert code == 1 and "codex" in out and "gone" in out and "UNRESOLVED" in out


def test_a_file_that_does_not_parse_is_exit_two(tmp_path: Path, _private_home: Path) -> None:
    d = doc()
    profile(d, "codex")["dont"] = [claim("Some claim.", "nonsense")]
    code, _, err = verify(repo(tmp_path, d), _private_home)
    assert code == 2 and "codex" in err
    code, _, err = verify(tmp_path / "absent.yaml", _private_home)
    assert code == 2 and err.startswith("error:")


def test_qualification_is_information_and_needs_an_outcomes_source(tmp_path: Path, _private_home: Path) -> None:
    code, out, _ = verify(repo(tmp_path), _private_home)
    assert code == 0 and "promotion" not in out
    rows = [rec(i, agent="codex", shape="research", date=f"2026-10-0{1 + i % 4}") for i in range(1, 11)]
    code, out, _ = verify(repo(tmp_path / "b", outcomes=rows), _private_home)
    assert code == 0, out
    assert "promotion: codex: qualifies (10 counted of 10 needed, 4 distinct dates of 3 needed)" in out
    assert "warning: claude-haiku is profiled but does not qualify (0 counted of 10 needed" in out


def test_the_home_default_file_is_checked_without_codeowners(tmp_path: Path, _private_home: Path) -> None:
    config = _private_home / ".config" / "safo"
    config.mkdir(parents=True)
    src = repo(tmp_path)
    put(config, "docs/lessons.md", (tmp_path / "docs" / "lessons.md").read_bytes())
    (config / "agents.yaml").write_bytes(src.read_bytes())
    (config / "agents.yaml").chmod(0o600)
    code, out, err = cli("profiles", "verify", home=_private_home)
    assert code == 0, err
    assert "CODEOWNERS: not checked" in out


def test_a_group_writable_default_file_is_refused_but_an_explicit_checkout_file_is_not(tmp_path: Path, _private_home: Path) -> None:
    config = _private_home / ".config" / "safo"
    config.mkdir(parents=True)
    src = repo(tmp_path)
    (config / "agents.yaml").write_bytes(src.read_bytes())
    (config / "agents.yaml").chmod(0o660)
    code, _, err = cli("profiles", "verify", home=_private_home)
    assert code == 2 and "writable by its group" in err
    src.chmod(0o664)
    assert verify(src, _private_home)[0] == 0


def test_only_the_verify_action_exists() -> None:
    from safo.modes.profiles import ACTIONS

    assert ACTIONS == ("verify",)
    assert LESSON
