# SPDX-License-Identifier: Apache-2.0
"""The SAFO threat model (issue 228): the Threat Dragon file and the readable page agree, name real tests, are linked.

The shape rules the shared workflow in git-your-ship-together enforces on the file are repeated here in small, so a
broken edit fails `make check` before CI. Guards collect loosely and assert strictly: each says that it found something,
and each has a negative case that shows it can fail.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
MODEL = ROOT / "docs" / "threat-model" / "safo.threat-dragon.json"
PAGE = ROOT / "docs" / "safo-threat-model.md"
PAGE_NAME = "safo-threat-model.md"
WIKI_PAGE = "Safo-threat-model"
SECTION_LABELS = ("Abuse case", "Prerequisites", "Mitigation", "Verification", "Residual risk", "Tracking")
SEVERITIES = {"Low", "Medium", "High", "Critical"}
STATUSES = {"Open", "Mitigated", "NotApplicable"}
REQUIRED_TOPICS = ("prompt injection", "data leakage", "tool abuse")


def load_model(text: str | None = None) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(MODEL.read_text(encoding="utf-8") if text is None else text)
    return loaded


def cells_of(model: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for d in model["detail"]["diagrams"] for c in d["cells"]]


def threats_of(model: dict[str, Any]) -> list[dict[str, Any]]:
    return [t for c in cells_of(model) for t in (c.get("data", {}).get("threats") or [])]


def model_problems(model: dict[str, Any]) -> list[str]:
    """What the shared check would refuse, in the rules that matter most; empty means well formed."""
    problems: list[str] = []
    cells = cells_of(model)
    ids = [c["id"] for c in cells]
    if len(ids) != len(set(ids)):
        problems.append("duplicate cell id")
    known = set(ids)
    if not any(c["shape"].startswith("trust-boundary") for c in cells):
        problems.append("no trust boundary")
    for c in cells:
        if c["shape"] == "flow":
            for end in ("source", "target"):
                if c[end].get("cell") not in known:
                    problems.append(f"flow {c['id']} {end} is not a cell")
    threats = threats_of(model)
    if not threats:
        problems.append("no threats")
    numbers = [t["number"] for t in threats]
    if len(numbers) != len(set(numbers)):
        problems.append("threat numbers are not unique")
    if numbers and model["detail"]["threatTop"] < max(numbers):
        problems.append("threatTop is below a threat number")
    for t in threats:
        if t["status"] not in STATUSES or t["severity"] not in SEVERITIES:
            problems.append(f"{t['id']}: status or severity")
        if not t.get("mitigation", "").strip() or not t.get("description", "").strip():
            problems.append(f"{t['id']}: empty mitigation or description")
    text = " ".join(f"{t['title']} {t['type']} {t['description']} {t['mitigation']}".lower() for t in threats)
    problems += [f"topic {topic!r} is in no threat" for topic in REQUIRED_TOPICS if topic not in text]
    return problems


def risk_ids_in_page(page: str) -> list[str]:
    return re.findall(r"^### (S\d+): ", page, re.MULTILINE)


def register_ids(page: str) -> list[str]:
    return re.findall(r"^\| \d+ \| (S\d+) \| ", page, re.MULTILINE)


def section_problems(page: str) -> list[str]:
    """Every risk section carries each labeled part, and a verification that names a test names a file that exists."""
    problems: list[str] = []
    parts = re.split(r"^### (?=S\d+: )", page, flags=re.MULTILINE)[1:]
    for part in parts:
        rid = part[:3].rstrip(":")
        body = part.split("\n## ", 1)[0]
        problems += [f"{rid}: no {label}" for label in SECTION_LABELS if f"**{label}" not in body]
        verification = re.search(r"\*\*Verification:\*\* (.*)", body)
        for name in re.findall(r"tests/(test_\w+)\.py", verification.group(1) if verification else ""):
            if not (ROOT / "tests" / f"{name}.py").exists():
                problems.append(f"{rid}: tests/{name}.py does not exist")
        for name in re.findall(r"\b(test_\w+)\.py", verification.group(1) if verification else ""):
            if not (ROOT / "tests" / f"{name}.py").exists():
                problems.append(f"{rid}: {name}.py does not exist")
        for filename, node in re.findall(
            r"tests/(test_\w+)\.py::(test_\w+)", verification.group(1) if verification else ""
        ):
            path = ROOT / "tests" / f"{filename}.py"
            if not path.exists() or not re.search(rf"^(?:async )?def {node}\(", path.read_text(encoding="utf-8"), re.M):
                problems.append(f"{rid}: {filename}.py::{node} does not exist")
    return problems


def page_metadata(page: str) -> dict[str, tuple[int, str, str]]:
    """id -> (rank, impact, status), from the register table."""
    rows = re.findall(
        r"^\| (\d+) \| (S\d+) \| .*? \| (Critical|High|Medium|Low) \| .*? \| (Open|Mitigated) \| ", page, re.M
    )
    return {rid: (int(rank), impact, status) for rank, rid, impact, status in rows}


def model_metadata(model: dict[str, Any]) -> dict[str, tuple[int, str, str]]:
    """id -> (rank, severity, status), from the Threat Dragon threats (the rank is the one the description states)."""
    out = {}
    for t in threats_of(model):
        found = re.search(r"\bRank (\d+)\.", t["description"])
        rank = int(found.group(1)) if found else -1
        out[t["id"].removeprefix("t-").upper()] = (rank, t["severity"], t["status"])
    return out


def links_problems(readme: str, home: str, rule_page: str) -> list[str]:
    problems = []
    if f"](docs/{PAGE_NAME})" not in readme:
        problems.append("README does not link the page")
    if "](docs/threat-model/safo.threat-dragon.json)" not in readme:
        problems.append("README does not link the Threat Dragon file")
    if f"/wiki/{WIKI_PAGE})" not in readme:
        problems.append("README wiki list does not name the wiki page")
    if f"]({PAGE_NAME})" not in home:
        problems.append("the wiki home does not link the page")
    if f"]({PAGE_NAME})" not in rule_page:
        problems.append("docs/threat-model.md does not link the page")
    return problems


def test_the_model_is_found_and_well_formed() -> None:
    model = load_model()
    assert model["version"].startswith("2.")
    assert len(threats_of(model)) >= 20  # a guard that collected nothing must not pass
    assert model_problems(model) == []


def test_the_model_check_bites() -> None:
    model = load_model()
    broken = json.loads(json.dumps(model))
    flow = next(c for c in cells_of(broken) if c["shape"] == "flow")
    flow["target"]["cell"] = "nowhere"
    assert any("is not a cell" in p for p in model_problems(broken))
    broken = json.loads(json.dumps(model))
    threats_of(broken)[0]["mitigation"] = " "
    assert any("empty mitigation" in p for p in model_problems(broken))
    broken = json.loads(json.dumps(model))
    broken["detail"]["threatTop"] = 1
    assert any("threatTop" in p for p in model_problems(broken))
    stripped = MODEL.read_text(encoding="utf-8").replace("tool abuse", "x").replace("Tool abuse", "x")
    assert any("tool abuse" in p for p in model_problems(load_model(stripped)))


def test_the_page_and_the_file_name_the_same_risks() -> None:
    page = PAGE.read_text(encoding="utf-8")
    in_file = sorted(t["id"].removeprefix("t-").upper() for t in threats_of(load_model()))
    assert len(in_file) >= 20
    assert sorted(risk_ids_in_page(page)) == in_file
    assert sorted(register_ids(page)) == in_file
    titles = {t["id"].removeprefix("t-").upper(): t["title"] for t in threats_of(load_model())}
    for rid, title in titles.items():
        assert f"### {title}" in page, rid


def test_the_page_and_the_file_agree_on_rank_impact_and_status() -> None:
    page = PAGE.read_text(encoding="utf-8")
    from_page = page_metadata(page)
    from_file = model_metadata(load_model())
    assert len(from_page) >= 20 and len(from_file) >= 20
    assert from_page == from_file


def test_the_metadata_check_bites() -> None:
    page = PAGE.read_text(encoding="utf-8")
    model = load_model()
    assert page_metadata(page.replace("| Open |", "| Mitigated |", 1)) != model_metadata(model)
    changed = json.loads(json.dumps(model))
    threats_of(changed)[0]["severity"] = "Low" if threats_of(changed)[0]["severity"] != "Low" else "High"
    assert page_metadata(page) != model_metadata(changed)


def test_the_page_ends_with_one_newline() -> None:
    text = PAGE.read_text(encoding="utf-8")
    assert text.endswith("\n") and not text.endswith("\n\n")


def test_the_register_is_ranked_one_to_n_without_gaps() -> None:
    page = PAGE.read_text(encoding="utf-8")
    ranks = [int(r) for r in re.findall(r"^\| (\d+) \| S\d+ \| ", page, re.MULTILINE)]
    assert ranks == list(range(1, len(ranks) + 1))
    assert len(ranks) >= 20


def test_every_risk_has_its_parts_and_names_only_tests_that_exist() -> None:
    page = PAGE.read_text(encoding="utf-8")
    assert len(risk_ids_in_page(page)) >= 20
    assert section_problems(page) == []


def test_the_section_check_bites() -> None:
    page = PAGE.read_text(encoding="utf-8")
    assert any("no Residual risk" in p for p in section_problems(page.replace("**Residual risk:**", "**Other:**", 1)))
    fake = page.replace("tests/test_handoff_check.py", "tests/test_no_such_file.py", 1)
    assert any("does not exist" in p for p in section_problems(fake))
    node = page.replace("test_a_report_from_an_untrusted_author_is_ignored", "test_no_such_function", 1)
    assert any("test_no_such_function" in p for p in section_problems(node))


def test_every_statement_is_marked_verified_inferred_or_a_gap() -> None:
    page = PAGE.read_text(encoding="utf-8")
    marks = re.findall(r"^  - \*\*([A-Z])\.\*\* ", page, re.MULTILINE)
    assert len(marks) >= 60
    assert set(marks) <= {"V", "I", "G"}


def test_the_page_is_linked_from_the_readme_the_wiki_home_and_the_rule_page() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    home = (ROOT / "docs" / "home.md").read_text(encoding="utf-8")
    rule_page = (ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
    assert links_problems(readme, home, rule_page) == []


def test_the_link_check_bites() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    home = (ROOT / "docs" / "home.md").read_text(encoding="utf-8")
    rule_page = (ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
    assert links_problems(readme.replace(f"](docs/{PAGE_NAME})", "](x)"), home, rule_page) == [
        "README does not link the page"
    ]
    assert links_problems(readme, home.replace(f"]({PAGE_NAME})", "](x)"), rule_page) == [
        "the wiki home does not link the page"
    ]
    assert links_problems(readme, home, rule_page.replace(f"]({PAGE_NAME})", "](x)")) == [
        "docs/threat-model.md does not link the page"
    ]
    assert links_problems(readme.replace(f"/wiki/{WIKI_PAGE})", "/wiki/x)"), home, rule_page) == [
        "README wiki list does not name the wiki page"
    ]


def test_the_wiki_publishes_the_page_under_its_name_and_in_the_sidebar(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location("gen_wiki_for_tm", ROOT / "scripts" / "gen_wiki.py")
    assert spec and spec.loader
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    repo = tmp_path / "repo"
    shutil.copytree(ROOT / "docs", repo / "docs")
    shutil.copytree(ROOT / "examples", repo / "examples")
    out = repo / "wiki-out"
    gen.generate(repo, out, None)
    names = {p.name for p in out.iterdir()}
    assert f"{WIKI_PAGE}.md" in names
    sidebar = (out / "_Sidebar.md").read_text(encoding="utf-8")
    assert f"]({WIKI_PAGE})" in sidebar
    # The Threat Dragon file is not a docs page: it must not become one, and the page must not link it as one.
    assert not any(n.endswith(".json") for n in names)


# --- public safety: an Open risk states ownership and guarantees, never a weakness recipe -----------------------------

# Built from pieces so this file holds none of the strings it forbids.
PRIVATE_NAME = "claude" + "-shit"
EVENT_NAMES = ("pull_request" + "_target", "workflow" + "_dispatch", "workflow" + "_call", "issue" + "_comment")
LINE_POINTER = re.compile(r"\.py:\d+")
OPEN_LEVELS = ("Critical", "High", "Medium")


def open_sections(page: str) -> list[tuple[str, str]]:
    """(id, text) of each Open Critical, High or Medium risk section of the page."""
    out = []
    for part in re.split(r"^### (?=S\d+: )", page, flags=re.MULTILINE)[1:]:
        body = part.split("\n## ", 1)[0]
        if "**Status:** Open" in body and any(f"**Impact:** {level}." in body for level in OPEN_LEVELS):
            out.append((part[:3].rstrip(":"), body))
    return out


def public_safety_problems(page: str, model_text: str, readme_section: str) -> list[str]:
    problems = []
    sections = open_sections(page)
    if len(sections) < 10:
        problems.append("fewer than ten Open High, Critical or Medium sections were found")
    for rid, body in sections:
        if LINE_POINTER.search(body):
            problems.append(f"{rid}: a source file-and-line pointer in an Open risk")
        if "**G.**" in body:
            problems.append(f"{rid}: a gap statement in an Open risk (those stay private)")
        if "Actor class" not in body or "Tracked in" not in body:
            problems.append(f"{rid}: missing the actor class or the tracking line")
    for name, text in (("page", page), ("model", model_text), ("README section", readme_section)):
        problems += [f"{name}: names the event {e}" for e in EVENT_NAMES if e in text]
    return problems


def readme_threat_section() -> str:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    return readme.split("## Threat model", 1)[1].split("\n## ", 1)[0]


def test_open_risks_carry_no_recipe_pointer_event_name_or_gap_statement() -> None:
    page = PAGE.read_text(encoding="utf-8")
    assert public_safety_problems(page, MODEL.read_text(encoding="utf-8"), readme_threat_section()) == []


def test_the_open_risk_check_bites() -> None:
    page = PAGE.read_text(encoding="utf-8")
    model_text = MODEL.read_text(encoding="utf-8")
    section = readme_threat_section()
    first = open_sections(page)[0][1]
    assert any(
        "file-and-line" in p
        for p in public_safety_problems(page.replace(first, first + " x.py:12"), model_text, section)
    )
    assert any(
        "gap statement" in p
        for p in public_safety_problems(page.replace(first, first + "\n  - **G.** x"), model_text, section)
    )
    assert any("names the event" in p for p in public_safety_problems(page, model_text + EVENT_NAMES[0], section))
    assert any("names the event" in p for p in public_safety_problems(page, model_text, section + EVENT_NAMES[1]))
    assert any(
        "missing the actor class" in p
        for p in public_safety_problems(page.replace(first, first.replace("Actor class", "Who")), model_text, section)
    )


def test_no_public_file_names_the_private_configuration_repository() -> None:
    files = [ROOT / "README.md", ROOT / "CHANGELOG.md", MODEL, *sorted((ROOT / "docs").glob("*.md"))]
    assert len(files) > 20
    hits = [str(f.relative_to(ROOT)) for f in files if PRIVATE_NAME in f.read_text(encoding="utf-8").lower()]
    assert hits == []
    assert PRIVATE_NAME in ("x" + PRIVATE_NAME)  # the guard looks for what it says it looks for


def test_the_credential_wording_is_scoped_to_the_app_path() -> None:
    page = PAGE.read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "On the App credential path SAFO mints a one-hour installation token" in page
    assert "the token is read-only then" not in page and "the token is read-only then" not in MODEL.read_text(
        encoding="utf-8"
    )
    assert "retains its existing authority" in page
    assert "a one-hour App token," not in readme
