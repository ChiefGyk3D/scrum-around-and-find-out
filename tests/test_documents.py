# SPDX-License-Identifier: MIT
"""Static rules over every GraphQL document in the package (module constants named Q_* and M_*)."""

from __future__ import annotations

import importlib
import pkgutil
import re

import safo
from safo.graphql import operation_name

FIRST = re.compile(r"first:\s*(\d+)([^)]*)\)")


def check_document(name: str, doc: str) -> list[str]:
    """The reasons a document breaks a rule safo learned the hard way; empty means it is fine."""
    problems = []
    try:
        operation_name(doc)
    except Exception:
        problems.append(f"{name}: no named operation")
    if "updateProjectV2Field" in doc:
        problems.append(f"{name}: updateProjectV2Field regenerates option ids and wipes values")
    if "createProjectV2View" in doc and "filter" in doc:
        problems.append(f"{name}: createProjectV2View takes no filter; use updateProjectV2View(viewId, filter)")
    for size, rest in FIRST.findall(doc):
        if int(size) >= 50 and "after: $endCursor" not in rest:
            problems.append(f"{name}: a connection of {size} must paginate with after: $endCursor")
    if "after: $endCursor" in doc and not ("$endCursor: String" in doc and "hasNextPage endCursor" in doc):
        problems.append(f"{name}: after: $endCursor needs the $endCursor: String variable and pageInfo")
    if "after:" in doc and "after: $endCursor" not in doc:
        problems.append(f"{name}: pagination must go through $endCursor")
    return problems


def all_documents() -> dict[str, str]:
    found: dict[str, str] = {}
    for info in pkgutil.walk_packages(safo.__path__, "safo."):
        module = importlib.import_module(info.name)
        for attr, value in vars(module).items():
            if re.match(r"^[QM]_[A-Z_]+$", attr) and isinstance(value, str):
                found[f"{info.name}.{attr}"] = value
    return found


def test_every_document_follows_the_rules() -> None:
    problems = [p for name, doc in all_documents().items() for p in check_document(name, doc)]
    assert problems == []


def test_the_checker_catches_each_mistake() -> None:
    assert check_document("a", "query A { x }") == []
    assert check_document("b", "{ x }")
    assert check_document("c", "mutation C($i: X!) { updateProjectV2Field(input: $i) { id } }")
    assert check_document("d", "mutation D($i: X!) { createProjectV2View(input: {filter: $i}) { id } }")
    assert check_document("e", "query E { a(first: 100) { nodes { id } } }")
    assert check_document("f", "query F($after: String) { a(first: 100, after: $after) { nodes { id } } }")
    assert (
        check_document(
            "g",
            "query G($endCursor: String) { a(first: 100, after: $endCursor) "
            "{ pageInfo { hasNextPage endCursor } nodes { id } } }",
        )
        == []
    )
