# SPDX-License-Identifier: Apache-2.0
"""`safo card`: the same edit as the `safo-card` script (#357 follow-up; see docs/ratebudget.md)."""

from __future__ import annotations

from safo.card_cli import add_arguments, run
from safo.modes import LocalMode, register_local

register_local(LocalMode("card", "edit one project card with one REST PATCH (same as safo-card)", add_arguments, run))
