# SPDX-License-Identifier: MIT
"""A fake GitHub GraphQL server for the tests: loopback only, records every mutation.

`core` holds the server and the in-memory board; every other module in this package adds the
handlers for the operations one mode uses, and is imported here so a test only imports `fakegh`.
"""

from __future__ import annotations

import importlib
import pkgutil

from fakegh.core import FakeGitHub, GqlError, Mutation, handler

for _info in pkgutil.iter_modules(__path__):
    if _info.name != "core":
        importlib.import_module(f"{__name__}.{_info.name}")

__all__ = ["FakeGitHub", "GqlError", "Mutation", "handler"]
