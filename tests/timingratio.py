# SPDX-License-Identifier: Apache-2.0
"""Find test functions that assert on a ratio of two measured times (#539).

A measured time is a call to a clock (time.perf_counter, monotonic, process_time, time, their _ns forms, timeit), a call
to a helper whose name contains "elapsed" or "duration", an attribute with such a name, or arithmetic and min/max/sum
over those. Two shapes are flagged inside a test_* function, only when an assert compares them with < <= > >=:

* a division whose operands are both measured times (directly or through a name assigned from one);
* a comparison with a measured time on both sides and a multiplication on one side (big < 15 * small).

A time against a constant, or a ratio of counted work, is not flagged.
"""

from __future__ import annotations

import ast
import itertools
import warnings

CLOCKS = frozenset(
    {
        "perf_counter",
        "perf_counter_ns",
        "monotonic",
        "monotonic_ns",
        "process_time",
        "process_time_ns",
        "time",
        "time_ns",
        "thread_time",
        "thread_time_ns",
        "default_timer",
    }
)
TIMEIT = frozenset({"timeit", "repeat", "default_timer"})
FOLDS = frozenset({"min", "max", "sum", "median", "mean", "fmean"})
INEQUALITIES = (ast.Lt, ast.LtE, ast.Gt, ast.GtE)


def _name_of(func: ast.expr) -> str:
    if isinstance(func, ast.Attribute):
        return func.attr
    return func.id if isinstance(func, ast.Name) else ""


def _helper_name(name: str) -> bool:
    low = name.lower()
    return "elapsed" in low or "duration" in low


def _is_clock_call(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        if func.value.id == "time":
            return func.attr in CLOCKS
        if func.value.id == "timeit":
            return func.attr in TIMEIT
        return False
    # A bare name only counts for the unambiguous clocks (a bare time() or repeat() could be anything).
    return isinstance(func, ast.Name) and func.id in CLOCKS - {"time", "time_ns"}


class _Scope:
    def __init__(self) -> None:
        self.timed: set[str] = set()
        self.ratios: set[str] = set()

    def is_timed(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.timed
        if isinstance(node, ast.Attribute):
            return _helper_name(node.attr) or self.is_timed(node.value)
        if isinstance(node, ast.Call):
            name = _name_of(node.func)
            if _is_clock_call(node) or _helper_name(name):
                return True
            if name in FOLDS:
                return any(self.is_timed(a) for a in node.args)
            return False
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Add, ast.Sub)):
                return self.is_timed(node.left) or self.is_timed(node.right)
            if isinstance(node.op, ast.Mult):  # a scaled time is still a time; time * time is not one
                return self.is_timed(node.left) != self.is_timed(node.right)
            return False
        if isinstance(node, ast.Subscript):
            return self.is_timed(node.value)
        if isinstance(node, (ast.List, ast.Tuple)):
            return any(self.is_timed(e) for e in node.elts)
        return False

    def is_ratio(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.ratios
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Div, ast.FloorDiv)) and self.is_timed(node.left) and self.is_timed(node.right):
                return True
            return self.is_ratio(node.left) or self.is_ratio(node.right)
        if isinstance(node, ast.Call):
            return any(self.is_ratio(a) for a in node.args)
        return False

    def learn(self, func: ast.AST) -> None:
        # Fixpoint over assignments, so order and chained names do not matter.
        while True:
            before = (len(self.timed), len(self.ratios))
            for node in ast.walk(func):
                targets: list[ast.expr]
                if isinstance(node, ast.Assign):
                    targets, value = node.targets, node.value
                elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
                    targets, value = [node.target], node.value
                else:
                    continue
                names = [n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)]
                if self.is_timed(value):
                    self.timed.update(names)
                if self.is_ratio(value):
                    self.ratios.update(names)
            if before == (len(self.timed), len(self.ratios)):
                return

    def bad_compare(self, cmp: ast.Compare) -> bool:
        if not any(isinstance(op, INEQUALITIES) for op in cmp.ops):
            return False
        sides = [cmp.left, *cmp.comparators]
        if any(self.is_ratio(s) for s in sides):
            return True
        for a, b in itertools.pairwise(sides):
            if self.is_timed(a) and self.is_timed(b) and any(_has_mult(s) for s in (a, b)):
                return True
        return False


def _has_mult(node: ast.expr) -> bool:
    return any(isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mult) for n in ast.walk(node))


def find_timing_ratio_asserts(source: str, filename: str) -> list[str]:
    """Return "file:test" for every test_* function asserting on a ratio of two measured times."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)  # scanned files may hold odd escapes in strings
        tree = ast.parse(source, filename=filename)
    hits: list[str] = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)) or not func.name.startswith("test"):
            continue
        scope = _Scope()
        scope.learn(func)
        for node in ast.walk(func):
            if isinstance(node, ast.Assert) and any(
                isinstance(c, ast.Compare) and scope.bad_compare(c) for c in ast.walk(node.test)
            ):
                hits.append(f"{filename}:{func.name}")
                break
    return hits
