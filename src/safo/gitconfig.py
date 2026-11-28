# SPDX-License-Identifier: Apache-2.0
"""The git config ALLOWLIST shared by safo-codex-run and safo-digest.

A repository's own config can make git start a program (a filter, a textconv, an alias, an include, a helper, a proxy,
an upload-pack command, a submodule's own config). Instead of a list of bad keys that someone has to keep complete, the
config is read with `git config --list --show-scope -z` and EVERY key must be on a short list of inert ones, with the
values that move trust or traffic held to exact shapes; a key nobody thought of is refused (fail closed). The same
check runs in every submodule, because a submodule keeps its own config.

The callers run git themselves (their own binary, environment and hardening) and pass `run(folder, *args, errors=...)`,
a function that returns git's stdout for `git -C folder *args` and raises on any failure. This module never starts a
process. The settings a wrapper forces at command scope are passed in as `skip`, the exact (key, value) pairs the
listing may show for them; nothing else in command scope is skipped.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Container

from safo import output
from safo.errors import SafoError

Runner = Callable[..., str]

CONFIG_SCOPES = frozenset({"system", "global", "local", "worktree", "command", "submodule"})
# Keys are compared in lower case.
INERT_CONFIG_KEYS = frozenset(
    {
        "core.repositoryformatversion",
        "core.filemode",
        "core.bare",
        "core.logallrefupdates",
        "core.ignorecase",
        "core.precomposeunicode",
        "core.symlinks",
        "core.autocrlf",
        "core.safecrlf",
        "core.eol",
        "extensions.worktreeconfig",
        "extensions.objectformat",
        "user.name",
        "user.email",
        "init.defaultbranch",
        "pull.rebase",
        "fetch.prune",
        "submodule.active",
    }
)
# Section -> names allowed under any subsection (remote.<name>.url). A subsection may hold dots.
INERT_SUBSECTION_NAMES = {
    "remote": frozenset({"url", "pushurl", "fetch", "tagopt", "prune"}),
    "branch": frozenset({"remote", "merge", "rebase", "description", "pushremote", "vscode-merge-base"}),
    "submodule": frozenset({"url", "active"}),
}

URL_FORMS = (
    re.compile(r"^https://[\w.-]+(:\d+)?(/[\w.~%+@:/-]*)?$"),
    re.compile(r"^ssh://([\w.-]+@)?[\w.-]+(:\d+)?/[\w.~%+/-]*$"),
    re.compile(r"^[\w.-]+@[\w.-]+:(?!-)[\w.~/-]+$"),  # scp-like user@host:path
)
REFSPEC_FORM = re.compile(r"^\+?refs/[\w./*-]+:refs/[\w./*-]+$")
REF_FORM = re.compile(r"^refs/[\w./-]+$")
NAME_FORM = re.compile(r"^[\w./-]+$")

MIN_GIT_VERSION = (2, 32)  # `config --list --show-scope -z` (2.26), GIT_CONFIG_COUNT (2.31), GIT_CONFIG_GLOBAL (2.32)
MAX_SUBMODULE_DEPTH = 4


class GitConfigRefused(SafoError):
    """The repository's config is not acceptable; the message names why (no value is echoed beyond a short key)."""


def base_git_env(home: str) -> dict[str, str]:
    """The git settings in the environment that every caller forces: no system or global config, no attributes from
    the system, no terminal prompt, and no lazy fetch from a promisor remote."""
    return {
        "HOME": home,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
    }


def config_key_is_inert(key: str) -> bool:
    key = key.lower()
    if key in INERT_CONFIG_KEYS:
        return True
    section, _, rest = key.partition(".")
    subsection, dot, name = rest.rpartition(".")
    return bool(dot and subsection and name in INERT_SUBSECTION_NAMES.get(section, ()))


def config_value_is_inert(key: str, value: str) -> bool:
    """A value must not carry a control byte or newline, name a helper (`::`) or look like an option (leading `-`,
    except the two tag options), and the subsection keys that move trust or traffic must have their exact shape.
    Local paths and file:// are not accepted as URLs."""
    key = key.lower()
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value) or "::" in value or ".." in value.split("/"):
        return False
    section, _, rest = key.partition(".")
    name = rest.rpartition(".")[2] if "." in rest else rest
    subsectioned = "." in rest
    if section in INERT_SUBSECTION_NAMES and subsectioned:
        if name in {"url", "pushurl"}:
            return any(form.match(value) for form in URL_FORMS)
        if name == "fetch":
            return bool(REFSPEC_FORM.match(value))
        if name == "tagopt":
            return value in {"--tags", "--no-tags"}
        if name in {"prune", "active"}:
            return value in {"true", "false"}
        if name == "rebase":
            return value in {"true", "false", "merges", "interactive"}
        if name == "merge":
            return bool(REF_FORM.match(value))
        if name in {"remote", "pushremote", "vscode-merge-base"}:
            return bool(NAME_FORM.match(value)) and not value.startswith("-")
    return not value.startswith("-")


def check_git_version(version_output: str, minimum: tuple[int, int] = MIN_GIT_VERSION) -> None:
    """Fail closed unless git reports a version that has the config listing form and the environment config settings
    the callers rely on."""
    found = re.match(r"^git version (\d+)\.(\d+)", version_output)
    if not found or (int(found.group(1)), int(found.group(2))) < minimum:
        needed = ".".join(str(n) for n in minimum)
        raise GitConfigRefused(f"git is missing or older than {needed}; nothing was run")


def check_config_keys(run: Runner, folder: str, skip: Container[tuple[str, str]], submodule: bool = False) -> None:
    """Git prints `scope NUL key [NEWLINE value] NUL` per setting. Anything that does not fit that shape is refused, and
    only the (key, value) pairs in `skip`, in command scope, are passed over."""
    listing = run(folder, "config", "--list", "--show-scope", "-z")
    tokens = listing.split("\0")
    if tokens and tokens[-1] == "":
        tokens.pop()
    if not tokens or len(tokens) % 2:
        raise GitConfigRefused("the repository config listing is not in the expected form; nothing was run")
    for scope, record in zip(tokens[0::2], tokens[1::2], strict=True):
        key, _, value = record.partition("\n")
        key = key.lower()
        if scope not in CONFIG_SCOPES or not key:
            raise GitConfigRefused("the repository config listing is not in the expected form; nothing was run")
        if scope == "command" and (key, value) in skip:
            continue
        if submodule and key == "core.worktree":
            # git writes a relative path from the submodule's git directory to its working folder. Resolve it the way
            # git does and require it to be exactly that folder; anything else moves the worktree somewhere unchecked.
            gitdir = run(folder, "rev-parse", "--absolute-git-dir").strip()
            if value and os.path.realpath(os.path.join(gitdir, value)) == os.path.realpath(folder):
                continue
            raise GitConfigRefused(
                "a submodule's core.worktree does not name the submodule's own folder; nothing was run"
            )
        if not config_key_is_inert(key):
            raise GitConfigRefused(
                f"the repository config sets {output.line(key[:60])}, which is not on the list of inert settings; "
                "nothing was run"
            )
        if not config_value_is_inert(key, value):
            raise GitConfigRefused(
                f"the repository config sets {output.line(key[:60])} to a value that is not an accepted form; "
                "nothing was run"
            )


def submodule_folders(run: Runner, folder: str) -> list[str]:
    """The folders of the gitlinks (mode 160000) in the index of `folder`. Listing the index runs nothing."""
    raw = run(folder, "ls-files", "--stage", "-z", errors="surrogateescape")
    found: list[str] = []
    for entry in raw.split("\0"):
        meta, _, name = entry.partition("\t")
        if meta.startswith("160000 ") and name:
            found.append(os.path.join(folder, name))
    return found


def check_repo_config(
    run: Runner,
    root: str,
    skip: Container[tuple[str, str]],
    depth: int = 0,
    max_depth: int = MAX_SUBMODULE_DEPTH,
    submodules: Callable[[str], list[str]] | None = None,
) -> None:
    """Refuse a repository whose own config has any key that is not known to be inert. The same check runs on every
    submodule, nested ones too, because a submodule keeps its own config. Listing config runs nothing."""
    find = submodules or (lambda folder: submodule_folders(run, folder))
    check_config_keys(run, root, skip, submodule=depth > 0)
    if depth >= max_depth:
        if find(root):
            raise GitConfigRefused("the repository nests submodules too deeply to check; nothing was run")
        return
    for folder in find(root):
        if os.path.islink(folder):
            raise GitConfigRefused("a submodule path is a symbolic link; nothing was run")
        if not os.path.lexists(folder):
            continue  # not checked out: git has no repository of its own there
        if not os.path.isdir(folder):
            raise GitConfigRefused("a submodule path is not a folder; nothing was run")
        if os.path.realpath(folder) != os.path.join(os.path.realpath(root), os.path.relpath(folder, root)):
            raise GitConfigRefused("a submodule folder resolves outside its place in the worktree; nothing was run")
        check_repo_config(run, folder, skip, depth + 1, max_depth, submodules)
