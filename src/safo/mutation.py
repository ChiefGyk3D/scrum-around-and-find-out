# SPDX-License-Identifier: MIT
"""Delegate mutation classification and bounded pre-execution waits to the built client."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from safo.graphql import JSON, Client


def mutate(client: Client, document: str, variables: Mapping[str, Any], *, dry_result: JSON | None = None) -> JSON:
    return client.execute(document, variables, dry_result=dry_result)
