# SPDX-License-Identifier: Apache-2.0
"""The paid path exists only through the broker (#287): no module outside `safo.broker` can send a paid request, the
old in-process entry points are gone, and the free tier keeps working.

The guard collects every module under src/safo loosely and asserts strictly: it fails if it collected nothing, and a
negative case proves it reports a module that holds the vendor host."""

from __future__ import annotations

import ast
import io
import re
from pathlib import Path

import pytest

import safo
from safo import gemini
from safo.cli import main
from safo.errors import ConfigError
from safo.gemini import GeminiConfig, RefusedError, Request, parse_config
from safo.modes import gemini as mode

SRC = Path(safo.__file__).resolve().parent
HOST_PART = "generativelanguage"  # the vendor host, kept in pieces so this file does not name it whole
MODEL_SHAPE = re.compile(r"gemini-\d")
KEY_HEADER = "x-goog-" + "api-key"
# The only places a vendor host, a paid model name or the key header may appear in source:
#   safo/broker/            the paid path
#   safo/gemini.py          the free-tier call (it reads the free key only; `ask` refuses a paid request)
#   safo/geminibrief.py     the dispatch guard's DENY patterns that recognize the host in a brief
ALLOWED_DIRS = ("broker",)
ALLOWED_FILES = ("gemini.py", "geminibrief.py")


def strings(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def offenders(root: Path) -> tuple[int, list[str]]:
    """(modules looked at, those outside the allowed places that hold the host, a model name or the key header)."""
    seen, found = 0, []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        if rel.parts[0] in ALLOWED_DIRS or str(rel) in ALLOWED_FILES:
            continue
        seen += 1
        text = "\n".join(strings(path)).lower()
        if HOST_PART in text or MODEL_SHAPE.search(text) or KEY_HEADER in text:
            found.append(str(rel))
    return seen, found


def test_no_module_outside_the_broker_can_name_the_vendor_a_paid_model_or_the_key_header() -> None:
    seen, found = offenders(SRC)
    assert seen > 50  # something was collected
    assert found == []


def test_the_guard_bites(tmp_path: Path) -> None:
    (tmp_path / "broker").mkdir()
    (tmp_path / "broker" / "ok.py").write_text(f'HOST = "{HOST_PART}.example"\n')  # allowed place
    (tmp_path / "other.py").write_text("X = 1\n")
    (tmp_path / "leaky.py").write_text(f'URL = "https://{HOST_PART}.example/v1"\n')
    (tmp_path / "model.py").write_text('M = "gemini-9-pro"\n')
    (tmp_path / "header.py").write_text(f'H = "{KEY_HEADER}"\n')
    seen, found = offenders(tmp_path)
    assert seen == 4 and found == ["header.py", "leaky.py", "model.py"]


REMOVED = {
    "ApprovalStore",
    "Approval",
    "open_store",
    "ledger_problem",
    "approval_problem",
    "_gate_paid",
    "require_paid",
    "paid_enabled",
    "DisabledCheck",
    "paid_quota",
    "estimate_usd",
}


def test_the_in_process_paid_code_is_deleted_from_the_free_tier_module() -> None:
    tree = ast.parse((SRC / "gemini.py").read_text(encoding="utf-8"))
    defined = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.ClassDef)}
    assert defined.isdisjoint(REMOVED), sorted(defined & REMOVED)
    assert not hasattr(mode, "approve_flow")
    assert not hasattr(gemini, "ApprovalStore")
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
    }
    assert "paid_config" not in names and "paid_switch" not in names


def test_the_credential_loader_has_no_paid_key_and_the_config_has_no_paid_key_setting() -> None:
    fields = {f for f in GeminiConfig.__dataclass_fields__}
    assert "paid_config" not in fields and "signing_key" not in fields and "signing_principal" not in fields


def test_ask_refuses_a_paid_request_before_any_gate_or_key() -> None:
    asked: list[str] = []

    def key_for(tier: str) -> str:
        asked.append(tier)
        return "unused"

    cfg = parse_config(
        {
            "version": 1,
            "endpoint": "http://127.0.0.1:9",
            "secrets": {"project": "p", "free_config": "f", "key_name": "K"},
            "free": {"m": {"rpm": 5, "tpm": 1000, "rpd": 5}},
        },
        home=Path("/nonexistent"),
    )
    import datetime as dt

    now = dt.datetime(2026, 10, 30, 12, 0, tzinfo=dt.UTC)
    with pytest.raises(RefusedError, match="broker"):
        gemini.ask(cfg, Request("m", "hello", "paid", "job", "", 10), key_for=key_for, now=now)
    assert asked == []


def test_a_config_that_still_names_a_paid_secret_is_refused() -> None:
    data = {
        "version": 1,
        "endpoint": "http://127.0.0.1:9",
        "secrets": {"project": "p", "free_config": "f", "paid_config": "g", "key_name": "K"},
        "free": {},
    }
    with pytest.raises(ConfigError):
        parse_config(data, home=Path("/nonexistent"))


@pytest.mark.parametrize(
    "argv",
    [
        [
            "--model",
            "m",
            "--material",
            "public",
            "--paid",
            "--job",
            "j",
            "--approval",
            "abcdefgh12",
            "--prompt-file",
            "p",
        ],
        ["--model", "m", "--paid", "--prompt-file", "p"],
        ["approve", "--model", "m", "--max-usd", "1", "--job", "j", "--prompt-file", "p"],
    ],
)
def test_the_old_entries_are_refused_and_point_to_the_broker(tmp_path: Path, argv: list[str]) -> None:
    prompt = tmp_path / "p"
    prompt.write_text("hello")
    words = [str(prompt) if a == "p" else a for a in argv]
    if words[0] != "approve":
        words = ["ask", *words]
    out, err = io.StringIO(), io.StringIO()
    code = main(["gemini", *words], env={"HOME": str(tmp_path), "PATH": "/nonexistent"}, out=out, err=err)
    assert code != 0
    assert "broker" in (out.getvalue() + err.getvalue()).lower()
