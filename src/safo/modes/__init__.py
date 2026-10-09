# SPDX-License-Identifier: MIT
"""Modes register themselves on import; `load_all()` imports every module in this package."""

from __future__ import annotations

import argparse
import importlib
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass

from safo.context import Context, LocalContext


@dataclass(frozen=True)
class Mode:
    name: str
    help: str
    add_arguments: Callable[[argparse.ArgumentParser], None]
    run: Callable[[Context, argparse.Namespace], int]


@dataclass(frozen=True)
class LocalMode:
    """A mode that reads local files and needs neither board.yaml nor a token: usage, route, outcome."""

    name: str
    help: str
    add_arguments: Callable[[argparse.ArgumentParser], None]
    run: Callable[[LocalContext, argparse.Namespace], int]


REGISTRY: dict[str, Mode] = {}
LOCAL: dict[str, LocalMode] = {}


def register(mode: Mode) -> Mode:
    REGISTRY[mode.name] = mode
    return mode


def register_local(mode: LocalMode) -> LocalMode:
    LOCAL[mode.name] = mode
    return mode


def load_all() -> dict[str, Mode | LocalMode]:
    for info in pkgutil.iter_modules(__path__):
        importlib.import_module(f"{__name__}.{info.name}")
    every: dict[str, Mode | LocalMode] = {**REGISTRY, **LOCAL}
    return dict(sorted(every.items()))
