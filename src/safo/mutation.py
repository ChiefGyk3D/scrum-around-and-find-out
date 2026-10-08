# SPDX-License-Identifier: MIT
"""Delegate mutation classification to the client, and refuse a success that carries no object.

The client already treats a null payload as an unknown outcome. `returns` goes one step further for a
caller that needs the written object: the reply must hold a non-empty `id` at that path, or the outcome
is unknown (the write may have landed) and the caller must re-read, never carry on.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from safo.errors import UnknownOutcomeError
from safo.graphql import JSON, Client, operation_name


def mutate(
    client: Client,
    document: str,
    variables: Mapping[str, Any],
    *,
    dry_result: JSON | None = None,
    returns: Sequence[str] | None = None,
) -> JSON:
    data = client.execute(document, variables, dry_result=dry_result)
    if returns and not client.dry_run:
        node: Any = data
        for key in returns:
            node = node.get(key) if isinstance(node, dict) else None
        if not isinstance(node, dict) or not isinstance(node.get("id"), str) or not node["id"]:
            raise UnknownOutcomeError(
                f"{operation_name(document)}: the reply carried no {'.'.join(returns)}.id, so it is not known "
                "whether the write landed; re-read state before retrying, do not simply resend it",
                data=data,
                errors=[],
                status=200,
            )
    return data
