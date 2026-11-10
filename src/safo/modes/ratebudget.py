# SPDX-License-Identifier: Apache-2.0
"""`safo ratebudget`: the same report as the `safo-ratebudget` script (#357 follow-up; see docs/ratebudget.md)."""

from __future__ import annotations

from safo.modes import LocalMode, register_local
from safo.ratebudget_cli import add_arguments, run

register_local(
    LocalMode(
        "ratebudget", "the shared GitHub API budget and who spent it (same as safo-ratebudget)", add_arguments, run
    )
)
