# SPDX-License-Identifier: MIT
"""Modes register themselves on import; `load_all()` imports every module in this package."""

from __future__ import annotations

import argparse
import importlib
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass

from safo.context import Context


@dataclass(frozen=True)
class Mode:
    name: str
    help: str
    add_arguments: Callable[[argparse.ArgumentParser], None]
    run: Callable[[Context, argparse.Namespace], int]


REGISTRY: dict[str, Mode] = {}


def register(mode: Mode) -> Mode:
    REGISTRY[mode.name] = mode
    return mode


def load_all() -> dict[str, Mode]:
    for info in pkgutil.iter_modules(__path__):
        importlib.import_module(f"{__name__}.{info.name}")
    return dict(sorted(REGISTRY.items()))
