# SPDX-License-Identifier: Apache-2.0
"""A fake broker release world for the installer tests: a throwaway git repository with signed tags, hand-built wheels,
a temporary layout standing in for the root-owned trees, and a record of every command the installer would run."""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import zipfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from safo_broker_install import Hooks, Layout, default_fetch, default_self_test, make_hooks
from unitdata import UNIT_DIR

GIT_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def run(argv: Sequence[str], cwd: Path | None = None, *, input_text: str | None = None) -> str:
    done = subprocess.run(  # noqa: S603 - fixed argv in a test helper, no shell
        list(argv),
        cwd=cwd,
        env=GIT_ENV,
        capture_output=True,
        text=True,
        check=True,
        input=input_text if input_text is not None else None,
        stdin=None if input_text is not None else subprocess.DEVNULL,
    )
    return done.stdout.strip()


def git(repo: Path, *args: str, input_text: str | None = None) -> str:
    return run(["git", "-C", str(repo), *args], input_text=input_text)


def make_key(path: Path) -> str:
    """Create a throwaway ed25519 key pair at `path`; return the public key text (type and key)."""
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "throwaway", "-f", str(path)])
    return " ".join(Path(f"{path}.pub").read_text().split()[:2])


def make_wheel(
    dest: Path,
    name: str = "fakedep",
    version: str = "1.0",
    *,
    files: dict[str, bytes] | None = None,
    filename: str | None = None,
) -> tuple[Path, str]:
    """Write a minimal valid pure-Python wheel; return its path and sha256."""
    dist = f"{name}-{version}.dist-info"
    body: dict[str, bytes] = {
        f"{name}/__init__.py": b"VALUE = 1\n",
        f"{dist}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode(),
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    body.update(files or {})
    record = []
    for member_path, data in body.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        record.append(f"{member_path},sha256={digest},{len(data)}")
    record.append(f"{dist}/RECORD,,")
    body[f"{dist}/RECORD"] = ("\n".join(record) + "\n").encode()
    path = dest / (filename or f"{name}-{version}-py3-none-any.whl")
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        for member, data in body.items():
            z.writestr(member, data)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def lock_text(
    reqs: Sequence[tuple[str, str, Sequence[str]]], *, index: str | None = "https://index.example.invalid/simple/"
) -> str:
    lines = [] if index is None else [f"--index-url {index}"]
    for name, version, hashes in reqs:
        parts = [f"{name}=={version}", *(f"--hash=sha256:{h}" for h in hashes)]
        lines.append(" \\\n    ".join(parts))
    return "\n".join(lines) + "\n"


class SimulatedCrash(BaseException):
    """Raised by the fault hook to model the process dying at a named point."""


@dataclass
class World:
    root: Path
    layout: Layout
    repo: Path
    key: Path
    pub: str
    wheels: Path
    state_dir: Path
    calls: list[tuple[str, ...]] = field(default_factory=list)
    prompts: list[str] = field(default_factory=list)
    answer: str | None = None  # None: type the version asked for
    fault_at: str | None = None
    fault_exc: type[BaseException] = SimulatedCrash
    health_fails: bool = False
    systemctl_rc: int = 0

    def hooks(self, **override: object) -> Hooks:
        def fault(point: str) -> None:
            if point == self.fault_at:
                raise self.fault_exc(point)

        def systemctl(args: Sequence[str]) -> int:
            self.calls.append(tuple(args))
            return self.systemctl_rc

        def health() -> str:
            if self.health_fails:
                msg = "status did not answer"
                raise RuntimeError(msg)
            return "answered"

        def confirm(prompt: str) -> str:
            self.prompts.append(prompt)
            return self.answer if self.answer is not None else prompt.rsplit(" ", 1)[-1]

        def download(lock: Path, dest: Path) -> None:
            for w in sorted(self.wheels.iterdir()):
                (dest / w.name).write_bytes(w.read_bytes())

        base = make_hooks(
            fetch=default_fetch(f"file://{self.repo}"),
            download=download,
            systemctl=systemctl,
            verify_units=lambda unit_dir, release: None,
            self_test=lambda release: None,
            health=health,
            fault=fault,
            confirm=confirm,
        )
        from dataclasses import replace

        return replace(base, **override)  # type: ignore[arg-type]

    # -- release authoring -------------------------------------------------------------------------------------
    def commit_release(
        self,
        version: str,
        *,
        code_version: str | None = None,
        lock: str | None = None,
        extra: dict[str, str] | None = None,
        units: dict[str, str] | None = None,
    ) -> str:
        files: dict[str, str] = {
            "src/safo/__init__.py": f'__version__ = "{code_version or version}"\n',
            "src/safo/broker/__init__.py": "",
            "src/safo/broker/__main__.py": f"# release {version}\n",
            "pyproject.toml": f'[project]\nname = "safo"\nversion = "{version}"\n',
            "packaging/broker-requirements.txt": lock if lock is not None else self.default_lock(),
        }
        for unit in sorted(UNIT_DIR.iterdir()):
            files[f"packaging/systemd/{unit.name}"] = (units or {}).get(unit.name) or unit.read_text()
        files["packaging/nftables/safo-broker.nft"] = (UNIT_DIR.parent / "nftables" / "safo-broker.nft").read_text()
        files["packaging/etc/nsswitch.conf"] = (UNIT_DIR.parent / "etc" / "nsswitch.conf").read_text()
        files.update(extra or {})
        for rel, text in files.items():
            target = self.repo / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "--allow-empty", "-m", f"release {version}")
        return git(self.repo, "rev-parse", "HEAD")

    def default_lock(self) -> str:
        reqs = []
        for w in sorted(self.wheels.iterdir()):
            name, version = w.name.split("-")[:2]
            reqs.append((name, version, [hashlib.sha256(w.read_bytes()).hexdigest()]))
        return lock_text(reqs)

    def sign_tag(self, tag: str, *, key: Path | None = None, message: str = "release") -> None:
        git(
            self.repo,
            "-c",
            "gpg.format=ssh",
            "-c",
            f"user.signingkey={key or self.key}",
            "tag",
            "-s",
            "-m",
            message,
            tag,
        )

    def release(self, version: str, **kw: object) -> str:
        sha = self.commit_release(version, **kw)  # type: ignore[arg-type]
        self.sign_tag(f"v{version}")
        return sha

    def authorize(self, *pubs: str) -> None:
        lines = [f'release{i}@example.invalid namespaces="git" {p}' for i, p in enumerate(pubs)]
        self.layout.signers.write_text("\n".join(lines) + "\n")
        self.layout.signers.chmod(0o644)

    def tree_snapshot(self, base: Path) -> dict[str, tuple[str, int]]:
        out: dict[str, tuple[str, int]] = {}
        for p in sorted(base.rglob("*")):
            rel = str(p.relative_to(base))
            if p.is_symlink():
                out[rel] = ("link:" + os.readlink(p), 0)
            elif p.is_file():
                out[rel] = (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mode)
            else:
                out[rel] = ("dir", p.stat().st_mode)
        return out


def make_world(tmp_path: Path, *, with_wheel: bool = True) -> World:
    root = tmp_path / "root"
    etc = root / "etc" / "safo"
    layout = Layout(
        opt_dir=root / "opt" / "safo-broker",
        signers=etc / "broker-release-signers",
        floor_file=etc / "broker-min-version",
        version_file=root / "var" / "lib" / "safo-broker-install" / "version",
        work_dir=root / "var" / "lib" / "safo-broker-install" / "work",
        log_file=root / "var" / "lib" / "safo-broker-install" / "install.log",
        unit_dir=root / "etc" / "systemd" / "system",
        anchor=root,
        uid=os.getuid(),
        key_types=("ssh-ed25519",),  # the throwaway signing key is a software key
        egress_helper=root / "usr" / "local" / "sbin" / "safo-broker-egress",
        check_python=False,  # this machine's interpreter is root-owned, the test user is not
    )
    layout.egress_helper.parent.mkdir(parents=True)
    layout.egress_helper.parent.chmod(0o755)
    layout.egress_helper.write_text("#!/bin/sh\n")
    layout.egress_helper.chmod(0o755)
    for d in (etc, layout.opt_dir, layout.version_file.parent, layout.unit_dir):
        d.mkdir(parents=True)
        d.chmod(0o755)
    (layout.opt_dir / "releases").mkdir(mode=0o755)
    layout.floor_file.write_text("0.0.0\n")
    layout.floor_file.chmod(0o644)
    state_dir = root / "var" / "lib" / "safo-broker"
    state_dir.mkdir(parents=True, mode=0o700)
    (state_dir / "ledger.jsonl").write_text("sentinel\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    key = tmp_path / "relkey"
    pub = make_key(key)
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    if with_wheel:
        make_wheel(wheels)
    world = World(root, layout, repo, key, pub, wheels, state_dir)
    world.authorize(pub)
    return world


__all__ = [
    "Callable",
    "SimulatedCrash",
    "World",
    "default_self_test",
    "git",
    "lock_text",
    "make_key",
    "make_wheel",
    "make_world",
    "run",
]


def unconfined(argv: list[str]) -> list[str]:
    """The test seam: the staged fake release runs as itself. The installer never passes this."""
    return argv
