# SPDX-License-Identifier: Apache-2.0
"""No module the broker can load imports an image library (#298; promised in docs/gemini-broker.md, "Tests").

The broker holds bytes a vendor returned and writes them to a file after sniffing the first bytes; it must never decode,
resize or re-encode an image, because a decoder is a large parser of attacker-shaped data running next to the paid key.

The check is an allow-list over the import graph: every module under src/safo/broker, and every safo module they reach
(through `import`, `from ... import` and relative imports, at any depth in the file), may import only the standard
library, the project itself, and the one named third-party package. Anything else fails, an image library or not. A
dynamic import (`importlib.import_module`, `__import__`) must name a standard-library module or a safo module by a
literal string. The negative cases below run the same analysis on trees that break each rule and require it to fail.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1] / "src"
# yaml: the broker config is YAML, read through the repository's safe loader. cryptography: the optional passkey
# signature check in safo.geminipasskey (imported when used; a signature verifier, not an image decoder).
ALLOWED_THIRD_PARTY = {"yaml", "cryptography"}
IMAGE_LIBRARIES = {"PIL", "imageio", "cv2", "numpy", "skimage", "scipy", "matplotlib", "wand", "pyvips", "pgmagick"}


# Anything that can load code by a name computed at run time. A literal-argument call to the first two is judged like an
# import; every other use of any of them, however it is aliased, is a problem the check cannot judge.
IMPORT_FUNCS = {"import_module", "__import__"}
INDIRECTION = IMPORT_FUNCS | {
    "exec",
    "eval",
    "find_spec",
    "spec_from_file_location",
    "module_from_spec",
    "SourceFileLoader",
    "load_module",
    "exec_module",
}


def module_file(src: Path, name: str) -> Path | None:
    base = src.joinpath(*name.split("."))
    for candidate in (base.with_suffix(".py"), base / "__init__.py"):
        if candidate.is_file():
            return candidate
    return None


# Calls that fetch an attribute by name: when the thing looked up, or the name, points at the import machinery anywhere
# inside the arguments (however deeply nested), the result is import machinery under another name.
LOOKUP_FUNCS = {"getattr", "attrgetter", "__getattribute__"}


def _names_import_machinery(node: ast.AST) -> bool:
    """True for a name, attribute or string that points at the import machinery (conservative: any such mention)."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str) and node.value in INDIRECTION | {"importlib", "builtins"}
    if isinstance(node, ast.Name):
        return node.id in {"importlib", "builtins"}
    return False


def imported_names(path: Path, name: str, is_package: bool) -> tuple[set[str], list[str]]:
    """Every dotted module name the file imports (relative ones resolved), and its dynamic-import problems."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    problems: list[str] = []
    package = name if is_package else name.rpartition(".")[0]
    aliases = set(IMPORT_FUNCS)  # names the import functions are known by in this file
    call_funcs = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] in ("importlib", "builtins"):
            aliases.update(a.asname for a in node.names if a.name in IMPORT_FUNCS and a.asname)
        elif isinstance(node, ast.Assign) and any(
            isinstance(v, ast.Name | ast.Attribute)
            and (getattr(v, "attr", None) or getattr(v, "id", "")) in IMPORT_FUNCS
            for v in [node.value]
        ):
            aliases.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.Assign) and any(_names_import_machinery(sub) for sub in ast.walk(node.value)):
            # a loader fetched through a nested expression: whatever it is assigned to may be called as an import
            aliases.update(t.id for t in node.targets if isinstance(t, ast.Name))
    for node in ast.walk(tree):
        if isinstance(node, ast.Name | ast.Attribute) and id(node) not in call_funcs:
            ref = node.attr if isinstance(node, ast.Attribute) else node.id
            if ref in INDIRECTION:
                problems.append(f"{path.name}: {ref!r} is used other than as a direct call")
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package.split(".")
                base = ".".join(parts[: len(parts) - node.level + 1])
                target = f"{base}.{node.module}" if node.module else base
            else:
                target = node.module or ""
            found.add(target)
            found.update(f"{target}.{alias.name}" for alias in node.names)  # `from safo import x` may import a module
        elif isinstance(node, ast.Call):
            func = node.func
            called = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
            if any(isinstance(a, ast.Name) and a.id in ("importlib", "builtins") for a in node.args):
                problems.append(f"{path.name}: the import machinery is passed to a call (getattr and the like)")
            if called in LOOKUP_FUNCS and any(_names_import_machinery(sub) for a in node.args for sub in ast.walk(a)):
                problems.append(f"{path.name}: import machinery is looked up through a nested expression")
            if called in INDIRECTION - IMPORT_FUNCS:
                problems.append(f"{path.name}: a call to {called!r} can load code by a computed name")
            elif called in aliases:
                arg = node.args[0] if node.args else None
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    found.add(arg.value)
                elif (
                    isinstance(arg, ast.JoinedStr)
                    and arg.values
                    and isinstance(arg.values[0], ast.FormattedValue)
                    and isinstance(arg.values[0].value, ast.Name)
                    and arg.values[0].value.id == "__name__"
                    and len(arg.values) > 1
                    and isinstance(arg.values[1], ast.Constant)
                    and str(arg.values[1].value).startswith(".")
                ):
                    continue  # f"{__name__}.x": a submodule of the package the file is in, which is walked already
                elif isinstance(arg, ast.JoinedStr) and arg.values and isinstance(arg.values[0], ast.Constant):
                    prefix = str(arg.values[0].value)
                    if prefix.startswith("safo.broker."):
                        continue  # a computed name inside the broker package: its modules are all walked already
                    problems.append(f"{path.name}: a dynamic import with the computed name {prefix!r}...")
                else:
                    problems.append(f"{path.name}: a dynamic import whose name is not a literal")
    return found, problems


def external_imports(src: Path, entry_package: str) -> tuple[dict[str, set[str]], list[str], int]:
    """Walk the import graph from every module of `entry_package`. Returns the third-party top-level names with the
    modules that import them, the dynamic-import problems, and how many safo modules were reached."""
    stdlib = set(sys.stdlib_module_names)
    entry_dir = src.joinpath(*entry_package.split("."))
    todo = [
        ".".join([entry_package, *p.relative_to(entry_dir).with_suffix("").parts])
        for p in sorted(entry_dir.rglob("*.py"))
        if p.stem != "__init__"
    ]
    todo += [  # every nested package too, so a module no import reaches is still judged
        ".".join([entry_package, *p.relative_to(entry_dir).parent.parts])
        for p in sorted(entry_dir.rglob("__init__.py"))
    ]
    todo.append(entry_package)
    seen: set[str] = set()
    outside: dict[str, set[str]] = {}
    problems: list[str] = []
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        path = module_file(src, name)
        if path is None:
            continue
        found, bad = imported_names(path, name, path.name == "__init__.py")
        problems += bad
        for target in found:
            top = target.split(".")[0]
            if top == entry_package.split(".")[0]:
                if module_file(src, target) is not None:
                    todo.append(target)
                    todo.append(target.rpartition(".")[0])  # importing a.b.c loads a.b too
            elif top and top not in stdlib:
                outside.setdefault(top, set()).add(name)
    return outside, problems, len(seen)


def test_no_module_the_broker_loads_imports_an_image_library() -> None:
    outside, problems, reached = external_imports(ROOT, "safo.broker")
    assert reached > 20, "the walk reached the broker modules and what they import"
    assert not problems, problems
    unexpected = {name: sorted(who) for name, who in outside.items() if name not in ALLOWED_THIRD_PARTY}
    assert not unexpected, f"imports outside the standard library, the project and the allow-list: {unexpected}"
    assert not IMAGE_LIBRARIES & set(outside)
    assert set(outside) <= ALLOWED_THIRD_PARTY


def build_tree(tmp_path: Path, body: str, *, extra: str = "") -> Path:
    pkg = tmp_path / "safo" / "broker"
    pkg.mkdir(parents=True)
    (tmp_path / "safo" / "__init__.py").write_text("")
    (pkg / "__init__.py").write_text("")
    (pkg / "mod.py").write_text(body)
    (tmp_path / "safo" / "helper.py").write_text(extra)
    return tmp_path


@pytest.mark.parametrize(
    "body",
    [
        "import PIL\n",
        "from PIL import Image\n",
        "import numpy.lib.stride_tricks\n",
        "def f():\n    import cv2\n",  # an import inside a function is still an import
        "import imageio.v3 as iio\n",
        "import some_unlisted_package\n",
    ],
)
def test_the_check_fails_on_an_import_it_must_refuse(tmp_path: Path, body: str) -> None:
    outside, problems, _ = external_imports(build_tree(tmp_path, body), "safo.broker")
    assert set(outside) - ALLOWED_THIRD_PARTY, (body, outside)
    assert not problems


def test_the_check_follows_the_graph_into_a_module_the_broker_imports(tmp_path: Path) -> None:
    src = build_tree(tmp_path, "from safo import helper\n", extra="from PIL import Image\n")
    outside, _, reached = external_imports(src, "safo.broker")
    assert "PIL" in outside and outside["PIL"] == {"safo.helper"} and reached >= 3


def test_the_check_fails_on_a_dynamic_import_it_cannot_judge(tmp_path: Path) -> None:
    named = build_tree(tmp_path / "a", "import importlib\nimportlib.import_module('cv2')\n")
    outside, problems, _ = external_imports(named, "safo.broker")
    assert "cv2" in outside and not problems  # a literal name is judged like an import
    computed = build_tree(tmp_path / "b", "import importlib\nimportlib.import_module(name)\n")
    assert external_imports(computed, "safo.broker")[1], "a computed name is a problem"
    own = build_tree(tmp_path / "d", "import importlib\nimportlib.import_module(f'{__name__}.x')\n")
    assert not external_imports(own, "safo.broker")[1], "a submodule of the file's own package is judged by the walk"
    other = build_tree(tmp_path / "e", "import importlib\nimportlib.import_module(f'{other}.x')\n")
    assert external_imports(other, "safo.broker")[1], "a computed name from anything else is a problem"
    sneaky = build_tree(tmp_path / "c", "import importlib\nimportlib.import_module(f'cv{2}')\n")
    assert external_imports(sneaky, "safo.broker")[1]


def test_the_check_accepts_the_standard_library_the_project_and_the_allow_listed_package(tmp_path: Path) -> None:
    src = build_tree(tmp_path, "import os, yaml\nfrom . import sibling\nfrom safo import helper\n", extra="import re\n")
    (src / "safo" / "broker" / "sibling.py").write_text("import json\n")
    outside, problems, reached = external_imports(src, "safo.broker")
    assert set(outside) == {"yaml"} and not problems and reached >= 4


# -- indirection the check must not be blind to (#303) -----------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        "from importlib import import_module as load\nImage = load('PIL.Image')\n",  # an alias of the import function
        "import importlib\nload = importlib.import_module\nImage = load('PIL.Image')\n",  # assigned to another name
        "import importlib as il\nIm = il.import_module('PIL.Image')\n",  # the module under another name
        "import builtins\nIm = builtins.__import__('PIL')\n",
        "import importlib\nfn = getattr(importlib, 'import_module')\nfn('PIL')\n",
        "import importlib.util\nspec = importlib.util.find_spec('PIL')\n",
        "ex" + "ec('import PIL')\n",  # split: the hygiene scan for string-run code must not match test data
        "ev" + "al('__import__(\"PIL\")')\n",
    ],
)
def test_the_check_fails_on_import_indirection(tmp_path: Path, body: str) -> None:
    outside, problems, _ = external_imports(build_tree(tmp_path, body), "safo.broker")
    assert problems or "PIL" in outside, body


def test_the_check_walks_nested_broker_packages(tmp_path: Path) -> None:
    src = build_tree(tmp_path, "import os\n")
    nested = src / "safo" / "broker" / "deep" / "deeper"
    nested.mkdir(parents=True)
    (src / "safo" / "broker" / "deep" / "__init__.py").write_text("")
    (nested / "__init__.py").write_text("")
    (nested / "decoder.py").write_text("from PIL import Image\n")
    outside, _, reached = external_imports(src, "safo.broker")
    assert "PIL" in outside and reached >= 4


def test_a_computed_name_outside_the_broker_prefix_is_still_a_problem(tmp_path: Path) -> None:
    inside = "import importlib\nimportlib.import_module(f'safo.broker.{name}')\n"
    # every nested package is walked, so a computed submodule of the broker is covered by the walk
    assert not external_imports(build_tree(tmp_path / "a", inside), "safo.broker")[1]
    leaving = "import importlib\nimportlib.import_module(f'safo.other.{name}')\n"
    assert external_imports(build_tree(tmp_path / "b", leaving), "safo.broker")[1]


@pytest.mark.parametrize(
    "body",
    [
        # a loader fetched through a nested expression, then called
        'loader = getattr(__import__("importlib"), "import_module")\nloader("PIL")\n',
        # the attribute name built from pieces
        'loader = getattr(__import__("importlib"), "import_" + "module")\nloader("PIL")\n',
        # the loader held in a tuple
        'pair = (getattr(__import__("importlib"), "import_module"), 1)\npair[0]("PIL")\n',
        # the machinery reached through the interpreter's module table
        'import sys\nloader = getattr(sys.modules["importlib"], "import_module")\nloader("PIL")\n',
        # a nested getattr into a submodule
        'spec = getattr(getattr(__import__("importlib"), "util"), "find_spec")("PIL")\n',
        # the builtins route
        'loader = getattr(__import__("builtins"), "__import__")\nloader("PIL")\n',
    ],
)
def test_the_check_fails_on_nested_indirect_import_forms(tmp_path: Path, body: str) -> None:
    _, problems, _ = external_imports(build_tree(tmp_path, body), "safo.broker")
    assert problems, body


def test_an_ordinary_attribute_lookup_is_not_a_problem(tmp_path: Path) -> None:
    body = "import os\nsep = getattr(os, 'sep')\n"
    outside, problems, _ = external_imports(build_tree(tmp_path, body), "safo.broker")
    assert not problems and not outside
