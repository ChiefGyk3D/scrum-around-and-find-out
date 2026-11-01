#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A rootless rehearsal of the phase 7 root setup of the paid Gemini broker (#263).

It walks the root runbook (src/safo/broker/runbook.py, rows R1 to R13) and the maintainer runbook
(docs/gemini-enrollment.md, rows E0, Ea to Ee, Epf) against a throwaway PREFIX folder, so the maintainer finds the
mistakes in them before the real run:

  * /etc/safo, /opt/safo-broker, /var/lib/... and /usr/local/sbin become folders under PREFIX; the runbook's own command
    lines run through bash with those path words moved and `sudo` and `-o root -g root` removed (nothing else changes);
  * the keys are test-only software keys made here; the approvals are dry-run approvals signed with them;
  * the broker is the real start-up code (`safo.broker.__main__.run`) given a listening socket the way systemd gives
    one, the config the runbook wrote, a fake vendor that records requests, and a placeholder credential;
  * the preflight runs against PREFIX with its host checks (ssh, libfido2, udev, authenticators, the service user)
    answered by stand-ins inside PREFIX, and the dry run runs through the real client and server.

CONTAINMENT. The runbook text is repository-controlled and is run by bash, so by default the whole rehearsal re-runs
itself inside `bwrap` (bubblewrap, rootless) with: a new user, network, IPC, PID and UTS namespace; a new empty root
that holds only read-only copies of /usr, /etc, this checkout and the Python environment; a writable PREFIX and a
private /tmp; the real home folder NOT present; and a scrubbed environment (HOME and TMPDIR inside PREFIX).

What that does contain: writes anywhere but PREFIX and its private /tmp; every network connection (the only interface
is a down loopback); reads of your home folder (~/.ssh, ~/.config/safo and the rest), the other processes and the
environment variables of the caller.
What it does NOT contain: it is no defence against a kernel or bubblewrap flaw; the same account runs it (no seccomp
filter, no resource limit); /usr and /etc, including a real /etc/safo, stay readable (read-only); and the safety
transform of the command lines (path words moved, `sudo` removed) is not a sandbox, only the namespaces are.
If `bwrap` or user namespaces are missing the tool REFUSES to run. `--no-containment` runs it anyway, in this process
with your own rights and network; every output line then ends with [NO CONTAINMENT].

A step that needs root, systemd, nftables or a hardware key is reported SKIPPED with the reason, never as passed, and so
is a step whose human review the tool cannot do (R3's `less` lines). Command lines are also checked with `bash -n`.
The preflight's host checks never read the real udev rules, linker cache, authenticators or agent keys: they are
stand-ins, and a row that depends on them says so.

    python scripts/rehearse_broker_setup.py [--prefix DIR] [--keep] [--no-containment]

Prints one row per step (PASS, FAIL or SKIPPED) and a total; exits 1 when a row failed, 2 for a refused setup. The
default PREFIX is a new folder under ~/.local/share/safo-rehearsal/.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import dataclasses
import datetime as dt
import getpass
import hashlib
import importlib
import io
import os
import re
import shlex
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, TextIO

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "gemini-enrollment.md"
LABEL = "yubikey-a"
FAKE_HOST = "api.vendor.example"
FAKE_CREDENTIAL = "rehearsal-placeholder-not-a-key-0123456789"  # the right plain shape, worth nothing
PATH_WORDS = (
    "/var/lib/safo-broker-install",
    "/var/lib/safo-broker",
    "/opt/safo-broker",
    "/etc/safo",
    "/usr/local/sbin",
)
STATUSES = ("PASS", "FAIL", "SKIPPED")
RELEASE_KEY_TYPES = ("sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
TITLE_WORDS = (
    "user",
    "directories",
    "installer",
    "credential",
    "signing key",
    "dry run",
    "vendor host",
    "turn the egress",
    "broker configuration",
    "socket",
    "socket permissions",
    "drop mode",
    "enable switch",
)


def helpers() -> SimpleNamespace:
    """The test fake vendor and the two packaging programs live outside the installed package: put their folders on the
    path once, then hand the modules back as one namespace."""
    for folder in (ROOT / "tests", ROOT / "packaging"):
        if str(folder) not in sys.path:
            sys.path.append(str(folder))
    return SimpleNamespace(
        fakevendor=importlib.import_module("fakevendor"),
        pipedata=importlib.import_module("pipedata"),
        egress=importlib.import_module("safo_broker_egress"),
        installer=importlib.import_module("safo_broker_install"),
    )


@dataclasses.dataclass(frozen=True)
class Row:
    step: str  # R1..R13 are the root runbook's step numbers; E0, Ea4, ... the enrollment page's; DRYRUN the dry run
    title: str
    status: str
    detail: str


def sort_key(step: str) -> tuple[int, int, str]:
    if step.startswith("E"):
        return (0, 0, step)
    m = re.fullmatch(r"R(\d+)(.*)", step)
    if m:
        return (1, int(m[1]), m[2])
    return (2, 0, step)


NO_CONTAINMENT = "[NO CONTAINMENT]"


def render(rows: Sequence[Row], *, contained: bool = True) -> str:
    lines = [f"{'STEP':<8}{'STATUS':<9}{'WHAT':<46}DETAIL"]
    for r in sorted(rows, key=lambda x: sort_key(x.step)):
        lines.append(f"{r.step:<8}{r.status:<9}{r.title[:44]:<46}{r.detail}")
    counts = {s: sum(1 for r in rows if r.status == s) for s in STATUSES}
    lines.append(f"total: {counts['PASS']} pass, {counts['FAIL']} fail, {counts['SKIPPED']} skipped")
    if not contained:
        lines = [f"{x}  {NO_CONTAINMENT}" for x in lines]
    return "\n".join(lines)


class Bad(Exception):
    """A step's check failed; the message becomes the row's detail."""


class Partial(Exception):
    """Everything the tool can check in the step passed, but part of the step is a human or root act it cannot do:
    the row is SKIPPED, never PASS."""


def run(argv: Sequence[str], *, env: dict[str, str], cwd: Path | None = None, timeout: int = 120) -> tuple[int, str]:
    done = subprocess.run(  # noqa: S603 - a fixed argv built here, no shell, closed stdin, bounded time
        list(argv),
        env=env,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return done.returncode, done.stdout + done.stderr


def move_paths(text: str, pathmap: dict[str, Path]) -> str:
    """Move the machine path words under the prefix in one pass, so a path already moved is never moved again."""
    pattern = "|".join(re.escape(w) for w in PATH_WORDS)  # longest first: a prefix word never hides a longer one
    return re.sub(rf"(?:{pattern})(?![\w-])", lambda m: str(pathmap[m[0]]), text)


def string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def fake_sk_blob(key_type: str) -> str:
    """The shape of a security-key public key blob, filled with filler bytes: it parses, it is nobody's key."""
    if key_type == "sk-ssh-ed25519@openssh.com":
        body = string(key_type.encode()) + string(b"\x07" * 32) + string(b"ssh:")
    else:
        body = string(key_type.encode()) + string(b"nistp256") + string(b"\x04" + b"\x07" * 64) + string(b"ssh:")
    return base64.b64encode(body).decode()


def blob_type(b64: str) -> str:
    raw = base64.b64decode(b64)
    (size,) = struct.unpack(">I", raw[:4])
    return raw[4 : 4 + size].decode()


class Rehearsal:
    def __init__(self, prefix: Path, doc: str) -> None:
        self.h = helpers()
        self.prefix = prefix
        self.doc = doc
        self.login = getpass.getuser()
        self.uid = os.geteuid()
        self.home = prefix / "home"
        self.rows: dict[str, Row] = {}
        self.env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.home),
            "LC_ALL": "C",
            "TERM": "dumb",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        self.pathmap = {w: prefix / w.lstrip("/") for w in PATH_WORDS}
        self.etc = prefix / "etc/safo"
        self.signers = self.etc / "gemini-allowed-signers"
        self.revoked = self.etc / "gemini-revoked-signers"
        self.switch = self.etc / "gemini-paid-enabled"
        self.egress_conf = self.etc / "broker-egress.conf"
        self.broker_yaml = self.etc / "broker.yaml"
        self.state = prefix / "var/lib/safo-broker"
        self.sock = prefix / "run/safo-broker.sock"
        self.key_a = self.home / ".ssh/safo/safo_gemini_a"
        self.key_release = self.home / ".ssh/safo-release/safo_release"
        self.client_yaml = self.home / ".config/safo/broker-client.yaml"
        self.a4_dir = prefix / "a4"
        self.broker: BrokerThread | None = None
        self.vendor = self.h.fakevendor.FakeVendor(self.h.fakevendor.FakeClock())
        self.dryruns: dict[str, tuple[int, str, str]] = {}
        self.service_user_standin = False

    # -- reporting
    def add(self, step: str, title: str, status: str, detail: str) -> None:
        self.rows[step] = Row(step, title, status, detail)

    def attempt(self, step: str, title: str, body: Callable[[], str]) -> None:
        try:
            self.add(step, title, "PASS", body())
        except Partial as part:
            self.add(step, title, "SKIPPED", str(part))
        except Bad as why:
            self.add(step, title, "FAIL", str(why))
        except Exception as err:  # a crash in a step is a finding about that step, not a reason to stop the rehearsal
            self.add(step, title, "FAIL", f"{type(err).__name__}: {err}")

    def skip(self, step: str, title: str, why: str, lines: Sequence[str] = ()) -> None:
        """SKIPPED, with the reason. The lines the step would run are still parsed with `bash -n`."""
        for line in lines:
            try:
                problem = self.syntax(self.remote(line))
            except Bad as err:
                problem = str(err)
            if problem:
                self.add(step, title, "FAIL", f"shell syntax error in a runbook line: {problem}")
                return
        checked = f"; its {len(lines)} line(s) parse" if lines else ""
        self.add(step, title, "SKIPPED", why + checked)

    # -- running the runbook's own lines
    def remote(self, line: str, *, fill: dict[str, str] | None = None) -> str:
        """The command the remote shell would run, from `ssh -t host '...'`, with the machine paths moved under the
        prefix and root's `sudo` and `-o root -g root` removed. Nothing else is changed."""
        parts = shlex.split(line)
        if parts[:3] != ["ssh", "-t", "host"] or len(parts) != 4:
            raise Bad("a runbook command is not exactly one ssh -t host 'command' line")
        text = parts[3]
        for word, value in (fill or {}).items():
            text = text.replace(word, value)
        text = re.sub(r"^sudo ", "", text)
        text = re.sub(r" -o root -g root", "", text)
        text = move_paths(text, self.pathmap)
        return text.replace("/path/to/reviewed/checkout", str(ROOT))

    def syntax(self, text: str) -> str | None:
        code, out = run(["/usr/bin/bash", "-n", "-c", text], env=self.env)
        return None if code == 0 else (out.strip().splitlines() or ["syntax error"])[-1][:160]

    def sh(self, line: str, *, fill: dict[str, str] | None = None) -> tuple[int, str]:
        text = self.remote(line, fill=fill)
        why = self.syntax(text)
        if why:
            raise Bad(f"shell syntax error in a runbook line: {why}")
        return run(["/usr/bin/bash", "-c", text], env=self.env, cwd=self.prefix)

    def must(self, line: str, *, fill: dict[str, str] | None = None) -> str:
        code, out = self.sh(line, fill=fill)
        if code != 0:
            raise Bad(f"a runbook line exited {code}: {line[:90]}... {out.strip()[-120:]}")
        return out

    # -- the prefix
    def lay_out(self) -> None:
        for folder in (self.home / ".ssh/safo", self.home / ".ssh/safo-release", self.home / ".config/safo"):
            folder.mkdir(parents=True, exist_ok=True)
        for folder in (
            self.home / ".ssh",
            self.home / ".ssh/safo",
            self.home / ".ssh/safo-release",
            self.home / ".config",
            self.home / ".config/safo",
        ):
            folder.chmod(0o700)
        (self.prefix / "run").mkdir(exist_ok=True)
        self.pathmap["/usr/local/sbin"].mkdir(parents=True, exist_ok=True)  # the real folder exists already
        for key in (self.key_a, self.key_release):
            argv = [
                self.h.installer.SSH_KEYGEN,
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "rehearsal test key",
                "-f",
                str(key),
            ]
            code, out = run(argv, env=self.env)
            if code != 0:
                raise Bad(f"ssh-keygen could not make the test key: {out.strip()[-100:]}")

    def runbook_steps(self) -> tuple[Any, ...]:
        from safo.broker import runbook

        steps = runbook.steps(self.login)
        if len(steps) != len(TITLE_WORDS):
            raise Bad(
                f"the runbook has {len(steps)} steps; the rehearsal was written for {len(TITLE_WORDS)}: update it"
            )
        for n, word in enumerate(TITLE_WORDS, 1):
            if word not in steps[n - 1].title.lower():
                raise Bad(f"runbook step {n} is {steps[n - 1].title!r}, not the {word} step: update the rehearsal")
        return steps

    # -- the preflight, with every host check answered from inside the prefix
    def fake_runner(self, argv: Sequence[str]) -> Any:
        from safo import gemini_preflight

        answers = {
            ("ssh", "-Q", "key"): (0, "\n".join(RELEASE_KEY_TYPES) + "\n"),
            ("ldconfig", "-p"): (0, "\tlibfido2.so.1 (libc6,x86-64) => /rehearsal/libfido2.so.1\n"),
            ("fido2-token", "-L"): (0, ""),
            ("ssh-add", "-L"): (1, "The agent has no identities.\n"),
        }
        code, text = answers.get(tuple(argv), (127, ""))
        return gemini_preflight.RunResult(code, text)

    def fake_lookup(self, name: str) -> int | None:
        """No service user exists (step R1 is skipped) until the enabling step, which stands this account in."""
        return self.uid if self.service_user_standin and name == "safo-broker" else None

    def locations(self) -> Any:
        from safo import gemini_preflight

        fake = self.prefix / "hostfake"
        (fake / "udev").mkdir(parents=True, exist_ok=True)
        (fake / "ssh").mkdir(parents=True, exist_ok=True)
        (fake / "ssh/ssh-sk-helper").write_text("")

        return gemini_preflight.Locations(
            allowed_signers=self.signers,
            switch=self.switch,
            egress_conf=self.egress_conf,
            broker_config=self.broker_yaml,
            client_config=self.client_yaml,
            maintainer_uid=self.uid,
            state_dir=self.state,
            service_user="safo-broker",
            trust_uid=self.uid,
            udev_dirs=(fake / "udev",),
            sk_helper_dirs=(fake / "ssh",),
        )

    def preflight(self, *, enabling: bool = False) -> list[Any]:
        from safo import gemini_preflight

        return gemini_preflight.run_preflight(self.locations(), self.fake_runner, self.fake_lookup, enabling=enabling)

    def enabling_exit(self) -> tuple[int, str]:
        """The exit status of the real enabling preflight: the same `main_with` the command line uses, so the exit
        policy is production's, with the host answers above."""
        from safo import gemini_preflight

        out = io.StringIO()
        code = gemini_preflight.main_with(self.locations(), self.fake_runner, self.fake_lookup, out=out, enabling=True)
        failed = ", ".join(x.split(":")[0][5:] for x in out.getvalue().splitlines() if x.startswith("FAIL "))
        return code, failed


def statuses(checks: Sequence[Any]) -> dict[str, str]:
    return {c.name: c.status for c in checks}


# -- the broker, started the way systemd would start it ----------------------------------------------------------------


class BrokerThread:
    """The real `safo.broker.__main__.run` on a socket made here and handed over as an inherited descriptor."""

    def __init__(self, rh: Rehearsal) -> None:
        self.rh = rh
        self.server: Any = None
        self.code: int | None = None
        self.error: BaseException | None = None
        self.ready = threading.Event()
        rh.state.mkdir(mode=0o700, parents=True, exist_ok=True)  # StateDirectory=safo-broker, StateDirectoryMode=0700
        credentials = rh.prefix / "run/credentials/safo-broker.service"
        credentials.mkdir(mode=0o700, parents=True, exist_ok=True)
        (credentials / "paid-key").write_text(FAKE_CREDENTIAL + "\n")
        (credentials / "paid-key").chmod(0o600)
        path = str(rh.sock)
        if len(path) > 100:
            raise Bad("the socket path is too long for a Unix socket; use a shorter --prefix")
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(path)
        rh.sock.chmod(0o660)  # SocketMode=0660
        self.listener.listen(16)
        self.handed = os.dup(self.listener.fileno())  # the descriptor the broker adopts; the listener stays ours
        self.environ = {
            "LISTEN_PID": str(os.getpid()),
            "LISTEN_FDS": "1",
            "STATE_DIRECTORY": str(rh.state),
            "CREDENTIALS_DIRECTORY": str(credentials),
        }
        self.thread = threading.Thread(target=self.main, name="rehearsal-broker")

    def main(self) -> None:
        from safo.broker import __main__ as broker_main

        try:
            self.code = broker_main.run(
                self.environ,
                pid=os.getpid(),
                config=self.rh.broker_yaml,
                signers=self.rh.signers,
                revoked=self.rh.revoked,
                switch=self.rh.switch,
                trust_uid=self.rh.uid,
                require_hardware=False,  # the seams: the test key is a software key, so the broker is told so, and the
                verifier=self.rh.h.pipedata.as_hardware,  # the touch is stood in (a file key cannot show it)
                first_fd=self.handed,
                transport=self.rh.vendor,
                on_ready=self.on_ready,
                handle_signals=False,
            )
        except BaseException as err:
            self.error = err
            self.ready.set()

    def on_ready(self, server: Any) -> None:
        self.server = server
        self.ready.set()

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(30) or self.error is not None:
            raise Bad(f"the broker did not start: {type(self.error).__name__}: {self.error}")

    def stop(self) -> int | None:
        if self.server is not None:
            self.server.stop()
        if self.thread.is_alive():
            self.thread.join(30)
        with contextlib.suppress(OSError):
            self.listener.close()
        return self.code


def dryrun(rh: Rehearsal, label: str) -> tuple[int, str, str]:
    from safo import geminisign
    from safo.broker import client

    cfg = client.ClientConfig(
        socket=str(rh.sock), signing_key=str(rh.key_a), principal=LABEL, image_dir=str(rh.home / "safo-images")
    )
    started = dt.datetime.now(dt.UTC)

    def no_call_signature(_payload: bytes) -> str:
        raise Bad("the dry run asked for a call signature")

    deps = client.Deps(
        connect=lambda: client.connect_unix(str(rh.sock), owner=rh.uid),
        sign=no_call_signature,
        now=lambda: started,
        mono=time.monotonic,
        writer=client.adapter_write_image,
        sidecar=client.adapter_write_sidecar,
        check_dir=client.check_image_dir,
        terms=lambda _text: None,
        confirm=lambda prompt: "dryrun signer-check" if "dryrun" in prompt else "",
        interactive=True,
        dry_sign=lambda payload: geminisign.sign(str(rh.key_a), payload, geminisign.DRYRUN_NAMESPACE, {}),
    )
    out, err = io.StringIO(), io.StringIO()
    code = client.run_dryrun(cfg, deps, out, err)
    rh.dryruns[label] = (code, out.getvalue(), err.getvalue())
    return rh.dryruns[label]


# -- the enrollment page -----------------------------------------------------------------------------------------------


def section(doc: str, heading: str) -> str:
    """The text from the heading whose line starts with `heading` to the next heading of the same or a higher level."""
    lines = doc.splitlines()
    start = next((i for i, x in enumerate(lines) if x.startswith(heading)), None)
    if start is None:
        raise Bad(f"the page has no section {heading!r}")
    level = len(lines[start]) - len(lines[start].lstrip("#"))
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if re.match(rf"#{{1,{level}}} ", lines[i]):
            end = i
            break
    return "\n".join(lines[start:end])


def blocks(text: str, kind: str = "bash") -> list[str]:
    return [m.group(1) for m in re.finditer(rf"^ *```{kind}\n(.*?)^ *```", text, re.MULTILINE | re.DOTALL)]


def dedent(text: str) -> str:
    lines = text.splitlines()
    pad = min((len(x) - len(x.lstrip()) for x in lines if x.strip()), default=0)
    return "\n".join(x[pad:] for x in lines) + "\n"


def doc_script(rh: Rehearsal, text: str) -> str:
    """A command block of the page, made safe for the prefix: `sudo` and `-o root -g root` removed, the machine paths
    moved under the prefix. `~` is the prefix's home through HOME. Nothing else changes."""
    out = dedent(text)
    out = re.sub(r"\bsudo ", "", out)
    out = re.sub(r" -o root -g root", "", out)
    return move_paths(out, rh.pathmap)


def run_script(rh: Rehearsal, script: str) -> tuple[str, list[int]]:
    _code, out = run(["/usr/bin/bash", "-c", "set +e\n" + script], env=rh.env, cwd=rh.prefix)
    return out, [int(x) for x in re.findall(r"rc=(\d+)", out)]


def block_with(found: Sequence[str], word: str) -> str:
    for b in found:
        if word in b:
            return b
    raise Bad(f"the page has no command block with {word!r}")


# -- the steps ---------------------------------------------------------------------------------------------------------


def step_e0(rh: Rehearsal) -> str:
    """Step 0.4: the page's sample preflight output against the real checks, and the page's own counting."""
    text = section(rh.doc, "## Step 0.")
    block = next((b for b in blocks(text, "text") if "summary:" in b), None)
    if block is None:
        raise Bad("step 0.4 of the page has no sample preflight output")
    sample = [(m[0], m[1]) for m in re.findall(r"^\s*(PASS|WARN|FAIL) ([a-z0-9-]+):", block, re.MULTILINE)]
    summary = re.search(r"summary: (\d+) pass, (\d+) warn, (\d+) fail; exit (\d)", block)
    if summary is None:
        raise Bad("the sample output has no summary line")
    for kind, want in zip(("PASS", "WARN", "FAIL"), summary.groups(), strict=False):
        have = sum(1 for k, _ in sample if k == kind)
        if have != int(want):
            raise Bad(f"the sample shows {have} {kind} lines but its own summary says {want}")
    words = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7}
    said = re.search(r"The (\w+) `FAIL` lines", text)
    fails = int(summary.group(3))
    if said and words.get(said.group(1).lower()) != fails:
        raise Bad(f"the page says 'The {said.group(1)} FAIL lines' but its sample shows {fails}")
    checks = rh.preflight()
    names = [n for _, n in sample]
    if names != [c.name for c in checks]:
        raise Bad(f"the sample lists the checks {names}; the preflight runs {[c.name for c in checks]}")
    got = statuses(checks)
    wrong = {n: (k, got[n]) for k, n in sample if k.lower() != got[n]}
    if wrong:
        raise Bad(f"on an empty prefix the sample and the real preflight disagree (sample, real): {wrong}")
    return f"the sample matches the {len(names)} real checks and the page's own counts agree"


def step_ea4(rh: Rehearsal) -> str:
    """Step a4 as written, with the test key: sign, verify, and the three refusals."""
    found = blocks(section(rh.doc, "### a4."))
    if len(found) < 2:
        raise Bad("step a4 has fewer than two command blocks")
    pre = f'export TMPDIR="{rh.prefix}"\n'
    out, rcs = run_script(rh, pre + doc_script(rh, found[0]) + 'echo "T=$T"\n')
    where = re.search(r"^T=(.+)$", out, re.MULTILINE)
    if rcs != [0] or where is None:
        raise Bad(f"the sign and verify commands of a4 gave rc {rcs}, expected [0]: {out.strip()[-160:]}")
    rh.a4_dir = Path(where.group(1))
    out2, rcs2 = run_script(rh, f'cd "{rh.a4_dir}"\n' + doc_script(rh, found[1]))
    if rcs2 != [255, 255, 255]:
        raise Bad(f"the three refusals of a4 gave rc {rcs2}, expected [255, 255, 255]: {out2.strip()[-160:]}")
    promised = ("namespace does not match", "incorrect signature", "Could not verify signature")
    missing = [words for words in promised if words not in out2]
    if missing:
        raise Bad(f"the page promises the messages {missing} for the refusals; ssh-keygen did not print them")
    return (
        "sign and verify rc 0; wrong namespace, changed text, revoked key each refused rc 255 with the promised words"
    )


def step_ec(rh: Rehearsal) -> str:
    """Step c: a signed annotated tag in a throw-away repository, the namespace refusal, the installer's parse."""
    found = blocks(section(rh.doc, "## Step c."))
    tag = block_with(found, "git tag -s")
    wrong = block_with(found, "wrong-signers")
    pre = f'export TMPDIR="{rh.prefix}"\n'
    out, rcs = run_script(rh, pre + doc_script(rh, tag) + doc_script(rh, wrong))
    if rcs != [0, 1]:
        raise Bad(f"the signed tag checks gave rc {rcs}, expected [0, 1]: {out.strip()[-200:]}")
    if not re.search(r"^tag$", out, re.MULTILINE):
        raise Bad("git cat-file did not say the tag is an annotated tag object")
    if rh.h.installer.GOOD_RE.search(out) is None:
        raise Bad("the installer's own pattern does not match what git printed for the verified tag")
    if "is not permitted for use in signature namespace" not in out:
        raise Bad("the wrong-namespace file was not refused with the words the page promises")
    return "annotated tag verified (the installer's pattern matches git's line); the approval namespace was refused"


def step_ed(rh: Rehearsal) -> str:
    """Step d: print the line, create the root files, add the line with a backup and a diff, check it with OpenSSH."""
    from safo import geminisign

    stale = re.findall(r"unmerged|keys command is merged|not yet available|phases 2 and 5 are merged", rh.doc)
    if stale:
        raise Bad(
            f"the page still says {sorted(set(stale))}, but `keys propose` and `paid-dryrun` are merged and run here"
        )
    found = blocks(section(rh.doc, "## Step d."))
    # d1: the page prints the line before it creates any file, so `keys propose` must work with no file yet
    trust = geminisign.Trust(rh.signers, rh.revoked, rh.uid, False, False)
    try:
        proposed = geminisign.propose_line(trust, Path(f"{rh.key_a}.pub"), LABEL)
    except Exception as err:
        raise Bad(f"d1: `safo gemini keys propose` fails before step d2 has made the files: {err}") from None
    line = next(x for x in proposed if x.startswith(f'{LABEL} namespaces="'))
    out, _ = run_script(rh, doc_script(rh, block_with(found, "printf '%s namespaces=")))
    if out.strip() != line:
        raise Bad("d1: the printf cross-check prints a different line from `keys propose`")
    # d2: the root-owned folder and the two empty files
    out, _ = run_script(rh, doc_script(rh, block_with(found, "/dev/null")))
    for path in (rh.signers, rh.revoked):
        if not path.is_file() or path.stat().st_size or (path.stat().st_mode & 0o777) != 0o644:
            raise Bad(f"d2: {path.name} was not made as an empty 0644 file: {out.strip()[-120:]}")
    # d3: backup, add the line, diff (sudoedit is an editor: the rehearsal appends the line instead)
    edit = doc_script(rh, block_with(found, "sudoedit"))
    edit = re.sub(r"^sudoedit (\S+)$", lambda m: f"printf '%s\\n' '{line}' >> {m[1]}", edit, flags=re.MULTILINE)
    out, _ = run_script(rh, edit)
    if f"> {line}" not in out:
        raise Bad(f"d3: the diff does not show only the added line: {out.strip()[-160:]}")
    # d4: find-principals and the namespace restriction, with the signature from step a4
    check = "\n".join(
        x for x in doc_script(rh, block_with(found, "find-principals")).splitlines() if "gemini_preflight" not in x
    )
    out, _ = run_script(rh, f'T="{rh.a4_dir}"\n' + check)
    if LABEL not in out.splitlines():
        raise Bad(f"d4: find-principals did not print the enrolled label: {out.strip()[-160:]}")
    verify = doc_script(rh, block_with(found, "-n safo-gemini-approval-dryrun -s"))
    out, rcs = run_script(rh, f'T="{rh.a4_dir}"\n' + verify)
    if rcs != [255] or "is not permitted for use in signature namespace" not in out:
        raise Bad(f"d4: the dry-run signature was not refused by the real file as the page says: rc {rcs}")
    return "the line printed two ways agrees; files, diff, find-principals and the namespace refusal behave as written"


def step_ee2(rh: Rehearsal) -> str:
    """Step e2: add a fingerprint to the revocation list; the broker must refuse the key; the rollback restores it."""
    found = blocks(section(rh.doc, "### e2."))
    out, _ = run_script(rh, doc_script(rh, block_with(found, "ssh-keygen -lf")))
    fingerprint = (out.split() or ["", ""])[1]
    if not fingerprint.startswith("SHA256:"):
        raise Bad(f"e2.1: ssh-keygen -lf did not print a SHA256 fingerprint: {out.strip()[-100:]}")
    edit = doc_script(rh, block_with(found, "sudoedit"))
    edit = re.sub(r"^sudoedit (\S+)$", lambda m: f"printf '%s\\n' '{fingerprint}' >> {m[1]}", edit, flags=re.MULTILINE)
    out, _ = run_script(rh, edit)
    if f"> {fingerprint}" not in out:
        raise Bad(f"e2.2: the diff does not show one added line: {out.strip()[-160:]}")
    if rh.broker is not None:
        code, said, err = dryrun(rh, "revoked")
        if code == 0 or "revoked" not in said + err:
            raise Bad(f"e2: the broker still accepted a revoked key (exit {code}): {(said + err).strip()[-120:]}")
    cross = doc_script(rh, block_with(found, "-r ~/.ssh/safo/safo_gemini_a.pub"))
    _out, rcs = run_script(rh, f'cd "{rh.a4_dir}"\n' + cross)
    if rcs != [255]:
        raise Bad(f"e2.3: the OpenSSH cross-check gave rc {rcs}, expected [255]")
    shutil.copy2(rh.etc / "gemini-revoked-signers-backup", rh.revoked)  # the page's rollback: restore the backup
    if rh.broker is not None:
        code, said, err = dryrun(rh, "unrevoked")
        if code != 0:
            raise Bad(f"e2: the restored revocation list still refuses the key: {(said + err).strip()[-120:]}")
    return "a revoked key is refused by the broker and by OpenSSH (rc 255); restoring the backup lets it sign again"


def step_epf(rh: Rehearsal) -> str:
    """The preflight over the finished prefix (ordering step 7 of the page): what each check must say."""
    got = statuses(rh.preflight())
    want = {
        "allowed-signers": "pass",
        "switch": "pass",
        "egress-mode": "warn",
        "broker-config": "pass",
        "client-config": "pass",
        "state-dir": "warn",
    }
    wrong = {n: (want[n], got.get(n)) for n in want if got.get(n) != want[n]}
    if wrong:
        raise Bad(f"after the setup the preflight disagrees (expected, real): {wrong}")
    return (
        "allowed-signers, broker-config, client-config pass; switch absent; egress observe warns "
        "(the ssh, libfido2, udev and authenticator checks are stand-ins, not this machine)"
    )


# -- the root runbook --------------------------------------------------------------------------------------------------


def apply_with_rollback(
    rh: Rehearsal, step: Any, apply: Callable[[], None], gone: Sequence[Path], fill: dict[str, str] | None = None
) -> None:
    """Apply the step, run its rollback lines, check what they remove, then apply it again."""
    apply()
    for line in step.rollback:
        rh.must(line, fill=fill)
    left = [p.name for p in gone if os.path.lexists(p)]
    if left:
        raise Bad(f"the rollback lines of this step left {left} behind")
    apply()


def r2(rh: Rehearsal, step: Any) -> str:
    opt = rh.pathmap["/opt/safo-broker"]
    modes = {
        rh.etc: 0o755,
        rh.etc / "egress": 0o755,
        rh.etc / "broker": 0o700,
        opt: 0o755,
        opt / "releases": 0o755,
        rh.pathmap["/var/lib/safo-broker-install"]: 0o755,
    }

    def apply() -> None:
        for line in step.commands:
            rh.must(line)
        for path, mode in modes.items():
            if not path.is_dir() or (path.stat().st_mode & 0o777) != mode:
                raise Bad(f"{path.name} is missing or has the wrong mode (want {mode:04o})")

    apply_with_rollback(rh, step, apply, [p for p in modes if p != rh.etc])
    return (
        f"{len(modes)} folders made with the modes the page lists; the rollback line removes them and the step reruns"
    )


def r3(rh: Rehearsal, step: Any) -> str:
    ran = 0
    stage = rh.pathmap["/var/lib/safo-broker-install"] / "stage"
    for line in step.commands:
        out = rh.must(line)  # the `less` lines print the file (no terminal); they do not review it
        ran += 1
        if "sha256sum" in line:
            staged = stage / "safo-broker-install"
            for name in ("safo-broker-install", "safo-broker-egress"):
                if name not in out:
                    raise Bad(f"sha256sum did not list {name}")
            if hashlib.sha256(staged.read_bytes()).hexdigest() not in out:
                raise Bad("the hash printed does not match the staged installer")
            if staged.read_bytes() != (ROOT / "packaging" / "safo_broker_install.py").read_bytes():
                raise Bad("the staged installer is not the checkout's file")
    sbin = rh.pathmap["/usr/local/sbin"]
    for name, src in (
        ("safo-broker-install", "safo_broker_install.py"),
        ("safo-broker-egress", "safo_broker_egress.py"),
    ):
        target = sbin / name
        if not target.is_file() or (target.stat().st_mode & 0o777) != 0o755:
            raise Bad(f"{name} was not installed with mode 0755")
        if target.read_bytes() != (ROOT / "packaging" / src).read_bytes():
            raise Bad(f"{name} is not the file that was staged")
    if stage.exists():
        raise Bad("the stage folder was not removed")
    raise Partial(
        f"{ran} lines ran and both files are 0755 and match; SKIPPED as a pass because the mandatory root review "
        "(the two `less` lines, a person reading the programs root will run) cannot be done by this tool"
    )


def r5(rh: Rehearsal, step: Any) -> str:
    signers = rh.etc / "broker-release-signers"
    ed = RELEASE_KEY_TYPES[0]
    fill = {"PASTE_RELEASE_PUBLIC_KEY_HERE": fake_sk_blob(ed), "PASTE_RELEASE_KEY_TYPE_HERE": ed}

    def apply() -> None:
        rh.must(step.commands[0], fill=fill)
        rh.must(step.commands[1])

    apply_with_rollback(rh, step, apply, [signers, rh.etc / "broker-min-version"], fill)
    try:
        rh.h.installer.check_signer_key_types(signers, rh.h.installer.SK_KEY_TYPES)
    except Exception as err:
        raise Bad(f"the installer refuses the signers file the step wrote: {err}") from None
    if (signers.stat().st_mode & 0o777) != 0o644:
        raise Bad("the release signers file is not mode 0644")
    floor = rh.h.installer.parse_version((rh.etc / "broker-min-version").read_text().strip())
    if floor != (0, 0, 0):
        raise Bad(f"the floor file reads {floor}, not 0.0.0")
    # enrollment step c lets the maintainer use ecdsa-sk on old firmware: the step must make a line that fits that key
    ecdsa = RELEASE_KEY_TYPES[1]
    other = rh.etc / "release-signers-ecdsa"
    rh.must(
        step.commands[0],
        fill={
            "PASTE_RELEASE_PUBLIC_KEY_HERE": fake_sk_blob(ecdsa),
            "PASTE_RELEASE_KEY_TYPE_HERE": ecdsa,
            "/etc/safo/broker-release-signers": "/etc/safo/release-signers-ecdsa",
        },
    )
    words = other.read_text().split()
    if len(words) < 4 or words[2] != blob_type(words[3]):
        named = words[2] if len(words) > 2 else "?"
        raise Bad(
            f"for an ecdsa-sk release key (enrollment step c allows one) the line names the key type {named}, "
            "so it could never verify a tag"
        )
    other.unlink()
    return "line passes the installer's own parser (0644), floor 0.0.0, rollback works; an ecdsa-sk key fits the line"


def r7(rh: Rehearsal, step: Any) -> str:
    fill = {"PASTE_VENDOR_API_HOST_HERE": FAKE_HOST}

    def apply() -> None:
        rh.must(step.commands[0], fill=fill)

    apply_with_rollback(rh, step, apply, [rh.egress_conf], fill)
    try:
        config = rh.h.egress.read_config(rh.egress_conf, uid=rh.uid, anchor=rh.prefix)
    except Exception as err:
        raise Bad(f"the egress helper's own reader refuses the file the step wrote: {err}") from None
    if config.mode != "observe" or config.host != FAKE_HOST:
        raise Bad(f"the helper reads mode {config.mode!r}, host {config.host!r}; the step promises observe mode")
    return "the egress helper's own reader accepts the file: observe mode, the host named; rollback works"


def r9(rh: Rehearsal, step: Any) -> str:
    from safo.broker.config import load_broker_config

    new = rh.broker_yaml.with_name("broker.yaml.new")

    def apply() -> None:
        rh.must(step.commands[0])

    apply_with_rollback(rh, step, apply, [rh.broker_yaml, new])
    shown = rh.must(step.commands[1])
    if f"allowed_uids: [{rh.uid}]" not in shown:
        raise Bad("the file does not hold this account's numeric id from `id -u`")
    loaded = load_broker_config(rh.broker_yaml, rh.uid)
    if not loaded.server.allowed_uids:
        raise Bad("the broker's own loader reads no allowed uid")
    if (rh.broker_yaml.stat().st_mode & 0o777) != 0o644:
        raise Bad("broker.yaml is not mode 0644")
    before = rh.broker_yaml.read_bytes()
    code, _ = rh.sh(step.commands[0])
    if code == 0 or rh.broker_yaml.read_bytes() != before:
        raise Bad("the step replaced or accepted an existing broker.yaml; it promises to refuse")
    if new.exists():
        raise Bad("a .new file is left beside broker.yaml")
    models = len(loaded.policy.prices.models)
    return f"loads through the broker's own loader ({models} models); refuses to replace; rollback works"


def r9b(rh: Rehearsal) -> str:
    from safo.broker import client

    example = (ROOT / "examples" / "broker-client.example.yaml").read_text()
    images = rh.home / "safo-images"
    images.mkdir(mode=0o700, exist_ok=True)
    text = example.replace("/path/to/your/home/.ssh/id_ed25519_sk", str(rh.key_a))
    text = text.replace("/path/to/your/home/safo-images", str(images))
    rh.client_yaml.write_text(text)
    rh.client_yaml.chmod(0o600)
    cfg = client.load_client_config(home=rh.home, root_path=rh.etc / "broker-client.yaml")
    if cfg.principal != LABEL or cfg.signing_key != str(rh.key_a):
        raise Bad("the client config did not load the key and principal that were set")
    return "examples/broker-client.example.yaml with the paths replaced loads (0600 file, 0700 folder)"


def r12(rh: Rehearsal, step: Any) -> str:
    sed, rollback = step.commands[0], step.rollback[0]

    def mode() -> str:
        return str(rh.h.egress.read_config(rh.egress_conf, uid=rh.uid, anchor=rh.prefix).mode)

    rh.must(sed)
    if mode() != "drop":
        raise Bad("after the sed line the egress helper's reader does not say drop")
    rh.must(rollback)
    if mode() != "observe":
        raise Bad("the rollback sed line does not put observe mode back")
    rh.must(sed)
    if mode() != "drop":
        raise Bad("the sed line does not work a second time")
    return (
        "the sed line switches the file to drop, the rollback line back to observe, and again to drop (file edit only)"
    )


def r13_line(rh: Rehearsal, step: Any) -> tuple[int, str, int]:
    """Run the switch line with its preflight head replaced by `true` or `false`, taken from the exit status of the
    real preflight code path (`main_with --enabling`, production's exit policy): the quoting, the `&&` chain, the file
    content and the mode are the line's own. Returns the line's status, its output and the preflight's status."""
    from safo.broker import runbook

    line = step.commands[0]
    head = f"{runbook.RELEASE_PYTHON} -I -m safo.gemini_preflight --enabling --maintainer-uid $(id -u {rh.login})"
    if head not in shlex.split(line)[3]:
        raise Bad("the switch line no longer has the preflight head the rehearsal replaces")
    preflight_code, _failed = rh.enabling_exit()
    code, out = rh.sh(line, fill={head: "true" if preflight_code == 0 else "false"})
    if (code == 0) != (preflight_code == 0):
        raise Bad(f"the line exited {code} but the real enabling preflight exited {preflight_code}")
    return code, out, preflight_code


# -- the whole walk ----------------------------------------------------------------------------------------------------


def rehearse(prefix: Path, *, doc: str | None = None) -> list[Row]:
    prefix.mkdir(parents=True, exist_ok=True)
    prefix.chmod(0o755)
    old_umask = os.umask(0o077)
    rh = Rehearsal(prefix.resolve(), DOC.read_text() if doc is None else doc)
    try:
        rh.lay_out()
        walk(rh, rh.runbook_steps())
    except Bad as why:
        rh.add("SETUP", "the rehearsal itself", "FAIL", str(why))
    finally:
        if rh.broker is not None:
            code = rh.broker.stop()
            if code not in (0, None):
                rh.add("R10stop", "the broker stops on request", "FAIL", f"exit status {code}")
        os.umask(old_umask)
    return list(rh.rows.values())


def walk(rh: Rehearsal, steps: Sequence[Any]) -> None:
    def lines(n: int) -> Sequence[str]:
        return list(steps[n - 1].commands)

    root = "needs root"
    rh.attempt("E0", "Step 0.4: the sample preflight on an empty prefix", lambda: step_e0(rh))
    rh.skip("R1", steps[0].title, f"{root} (groupadd, useradd, usermod); the service-user check stays FAIL", lines(1))
    rh.attempt("R2", steps[1].title, lambda: r2(rh, steps[1]))
    rh.attempt("R3", steps[2].title, lambda: r3(rh, steps[2]))
    rh.skip(
        "R4", steps[3].title, f"{root}, systemd-creds with the host key, and a hidden prompt for the paid key", lines(4)
    )
    rh.attempt("R5", steps[4].title, lambda: r5(rh, steps[4]))
    rh.skip(
        "R6",
        steps[5].title,
        f"{root}, a tag signed by a hardware key and a fetch from the fixed repository URL",
        lines(6),
    )
    rh.attempt("R7", steps[6].title, lambda: r7(rh, steps[6]))
    rh.skip("R8", steps[7].title, f"{root}, systemd and nftables (the egress units and the firewall table)", lines(8))
    rh.attempt("R9", steps[8].title, lambda: r9(rh, steps[8]))
    rh.attempt("R9b", "R9 note: your own broker-client.yaml", lambda: r9b(rh))
    rh.skip("Ea2", "Steps a1 to a3: PIN and hardware keys A and B", "needs a hardware key, its PIN and touches")
    rh.attempt("Ea4", "Step a4: sign and verify, with the refusals", lambda: step_ea4(rh))
    rh.skip("Eb", "Step b: the second device", "needs the Immurok device and a person's gestures")
    rh.attempt("Ec", "Step c: a signed release tag", lambda: step_ec(rh))
    rh.attempt("Ed", "Step d: the allowed-signers lines", lambda: step_ed(rh))
    rh.attempt("Epf", "The preflight over the finished prefix", lambda: step_epf(rh))
    rh.skip("R10", steps[9].title, f"{root} and systemd (socket activation, the unit's sandbox)", lines(10))
    try:
        rh.broker = BrokerThread(rh)
        rh.broker.start()
    except Bad as why:
        rh.add("R10e", "R10 emulated: the broker starts from a socket", "FAIL", str(why))
        return
    rh.add(
        "R10e",
        "R10 emulated: the broker starts from a socket",
        "PASS",
        "run() adopted an inherited listener and read the config the runbook wrote; this is not the systemd unit",
    )
    rh.skip(
        "R11",
        steps[10].title,
        f"{root}: the socket must be owned by the client group, which only root can set",
        lines(11),
    )
    code, said, err = dryrun(rh, "off")
    if code != 0 or "DISABLED" not in said:
        detail = f"switch absent: exit {code}: {(said + err).strip()[-140:]}"
        rh.add("DRYRUN", "The dry run through the real client and broker", "FAIL", detail)
        return
    # R13 in observe mode: the preflight must refuse and the line must not write the switch
    rh.service_user_standin = True  # stands in for step R1 (skipped); the enabling preflight fails without a user
    observe_failed = rh.enabling_exit()[1]
    try:
        code, _, observe_rc = r13_line(rh, steps[12])
    except Bad as why:
        code, observe_rc, observe_failed = 0, 0, str(why)
    refused = "egress-mode" in observe_failed and code != 0 and observe_rc != 0 and not rh.switch.exists()
    rh.skip("R12a", "R12: restart, blocked probe and drop log", f"{root}, systemd, nftables and runuser", lines(12)[1:])
    rh.attempt("R12", steps[11].title, lambda: r12(rh, steps[11]))

    def r13() -> str:
        if not refused:
            raise Bad(f"in observe mode the switch line was not refused by egress-mode: {observe_failed}")
        rc, out, drop_rc = r13_line(rh, steps[12])
        if drop_rc != 0:
            raise Bad(f"in drop mode the real enabling preflight still exits {drop_rc}: {rh.enabling_exit()[1]}")
        if rc != 0 or rh.switch.read_text() != "enabled\n" or (rh.switch.stat().st_mode & 0o777) != 0o644:
            raise Bad(f"the switch line did not write 'enabled' with mode 0644: rc {rc} {out.strip()[-100:]}")
        from safo.broker import runtime

        if not runtime.switch_reader(rh.switch, rh.uid)():
            raise Bad("the broker's own switch reader does not read the file as enabled")
        return (
            "refused in observe mode (egress-mode FAIL, no file); after drop wrote 'enabled' 0644, read by the broker; "
            "the service user and host checks are stand-ins (R1 skipped), the exit policy is the real one"
        )

    rh.attempt("R13", steps[12].title, r13)
    dryrun(rh, "on")
    rh.attempt("Ee2", "Step e2: revoke a key", lambda: step_ee2(rh))
    rh.attempt("DRYRUN", "The dry run through the real client and broker", lambda: finish_dryrun(rh))


def finish_dryrun(rh: Rehearsal) -> str:
    on = rh.dryruns["on"]
    if on[0] != 0 or "paid use is enabled" not in on[1]:
        raise Bad(f"with the switch on the dry run did not say enabled: exit {on[0]}: {(on[1] + on[2]).strip()[-120:]}")
    if f"principal {LABEL}" not in on[1] or "hardware key" not in on[1]:
        raise Bad("the dry run did not name the principal and report the key the verifier stands in for")
    requests = len(rh.vendor.requests)
    if requests:
        raise Bad(f"the fake vendor received {requests} request(s); a dry run must send none")
    ledger = rh.state / "ledger.jsonl"
    text = ledger.read_text() if ledger.exists() else ""
    used = list((rh.state / "used").glob("*")) if (rh.state / "used").exists() else []
    if "approval" in text or used:
        raise Bad("the dry run left an approval record in the broker's state")
    state = statuses(rh.preflight()).get("state-dir")
    if state != "pass":
        raise Bad(f"after the broker ran, the preflight's state-dir check says {state}")
    return (
        "switch off: DISABLED; switch on: enabled, principal named; the touch and PIN flags are the test verifier's "
        "stand-in (a software key cannot show them); 0 vendor requests, no approval recorded; state-dir check passes"
    )


# -- the command line --------------------------------------------------------------------------------------------------


def check_prefix(prefix: Path) -> str | None:
    if prefix.exists() and (not prefix.is_dir() or any(prefix.iterdir())):
        return f"{prefix} exists and is not an empty folder; give a new path"
    parent = prefix.parent
    if not parent.is_dir() or parent.stat().st_uid != os.geteuid():
        return f"the parent of {prefix} must be an existing folder you own"
    if str(prefix.resolve()).startswith(("/etc", "/usr", "/var", "/opt", "/root", "/boot")):
        return "the prefix must not be inside a system folder"
    for above in prefix.resolve().parents:  # the broker's own trust rule, applied to the rehearsal's folders too
        info = above.stat()
        sticky = bool(info.st_mode & stat.S_ISVTX) and info.st_uid == 0
        if info.st_uid not in (os.geteuid(), 0) or (info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not sticky):
            return (
                f"{above} is writable by group or others (or not yours): the broker's trust rule refuses files below it"
            )
    return None


CONTAINED_MARK = "SAFO_REHEARSAL_CONTAINED"


def contained_argv(prefix: Path, argv: Sequence[str], *, bwrap: str | None = None) -> list[str]:
    """`argv` wrapped to run under bubblewrap: new user, network, IPC, PID and UTS namespaces; a new empty root with
    read-only /usr, /etc, this checkout and the Python environment; a writable PREFIX; a private /tmp; the real home
    folder absent; a scrubbed environment with HOME and TMPDIR inside PREFIX."""
    tool = bwrap or shutil.which("bwrap")
    if tool is None:
        raise Bad("bubblewrap (bwrap) is not installed")
    out = [tool, "--unshare-all", "--die-with-parent", "--new-session", "--clearenv"]
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(prefix / "home"),
        "TMPDIR": str(prefix / "tmp"),
        "LC_ALL": "C",
        "TERM": "dumb",
        "PYTHONDONTWRITEBYTECODE": "1",
        CONTAINED_MARK: "1",
    }
    for key, value in env.items():
        out += ["--setenv", key, value]
    for folder in ("/bin", "/sbin", "/lib", "/lib64"):  # merged-usr systems link these into /usr
        link = Path(folder)
        if link.is_symlink():
            out += ["--symlink", os.readlink(link), folder]
        elif link.is_dir():
            out += ["--ro-bind", folder, folder]
    shown = {"/usr", "/etc"}
    for folder in (Path("/usr"), Path("/etc"), ROOT, Path(sys.prefix), Path(sys.base_prefix)):
        if str(folder) not in shown and not any(str(folder).startswith(x + "/") for x in shown):
            out += ["--ro-bind", str(folder), str(folder)]
            shown.add(str(folder))
        elif str(folder) in shown and folder in (Path("/usr"), Path("/etc")):
            out += ["--ro-bind", str(folder), str(folder)]
    out += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", str(Path("/") / "tmp"), "--bind", str(prefix), str(prefix)]
    return [*out, "--", *argv]


def containment_problem() -> str | None:
    """Why the rehearsal cannot be contained here, or None when a rootless bubblewrap sandbox starts."""
    tool = shutil.which("bwrap")
    if tool is None:
        return "bubblewrap (bwrap) is not installed"
    with tempfile.TemporaryDirectory(prefix="rhp") as folder:
        probe = contained_argv(Path(folder), ["/usr/bin/true"], bwrap=tool)
        try:
            done = subprocess.run(  # noqa: S603 - a fixed probe argv built here, no shell, bounded time
                probe, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as err:
            return f"bubblewrap could not start: {type(err).__name__}"
        if done.returncode != 0:
            return "user namespaces are not available to bubblewrap here: " + done.stderr.strip()[-100:]
        return None


def inside_problem() -> str | None:
    """Checks, from inside, that the sandbox really holds: the checkout is read-only and the only network interface is
    the (down) loopback."""
    try:
        (ROOT / ".rehearsal-probe").write_text("x")
    except OSError:
        pass
    else:
        (ROOT / ".rehearsal-probe").unlink()
        return "the checkout is writable inside the sandbox"
    try:
        names = {x.split(":")[0].strip() for x in Path("/proc/net/dev").read_text().splitlines()[2:]}
    except OSError:
        return "the network interfaces cannot be listed"
    if names - {"lo"}:
        return f"the sandbox has a network interface besides loopback: {sorted(names - {'lo'})}"
    return None


def main(argv: Sequence[str] | None = None, *, out: TextIO | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rootless rehearsal of the phase 7 root setup (#263)")
    parser.add_argument(
        "--prefix", help="a new folder to rehearse in (default: a new one under ~/.local/share/safo-rehearsal)"
    )
    parser.add_argument("--keep", action="store_true", help="keep the prefix folder afterwards")
    parser.add_argument(
        "--no-containment",
        action="store_true",
        help="run without the bubblewrap sandbox, with your own rights and network (every output line says so)",
    )
    args = parser.parse_args(argv)
    stream = out if out is not None else sys.stdout
    if os.geteuid() == 0:
        parser.exit(2, "refused: this rehearsal is rootless on purpose; run it as your own account\n")
    inside = os.environ.get(CONTAINED_MARK) == "1"
    if args.no_containment and inside:
        parser.exit(2, "refused: --no-containment inside the sandbox\n")
    if inside:
        problem = inside_problem()
        if problem:
            parser.exit(2, f"refused: the sandbox does not hold: {problem}\n")
    elif not args.no_containment:
        problem = containment_problem()
        if problem:
            parser.exit(
                2,
                f"refused: cannot contain the rehearsal ({problem}). Install bubblewrap, or pass --no-containment "
                "to run "
                "it with your own rights and network (every output line then says so)\n",
            )
    if args.prefix:
        prefix = Path(args.prefix).absolute()
    else:
        base = Path.home() / ".local/share/safo-rehearsal"
        base.mkdir(parents=True, exist_ok=True)
        prefix = base / time.strftime("%Y%m%d-%H%M%S")
    if not inside:
        problem = check_prefix(prefix)
        if problem:
            parser.exit(2, f"refused: {problem}\n")
    contained = not args.no_containment
    try:
        if inside or args.no_containment:
            rows = rehearse(prefix)
            stream.write(render(rows, contained=contained) + "\n")
            return 1 if any(r.status == "FAIL" for r in rows) else 0
        prefix.mkdir(parents=True, exist_ok=True)
        prefix.chmod(0o755)
        (prefix / "tmp").mkdir(mode=0o700, exist_ok=True)
        child = contained_argv(prefix, [sys.executable, str(Path(__file__).resolve()), "--prefix", str(prefix)])
        done = subprocess.run(  # noqa: S603 - the bubblewrap argv built above, no shell, stdin closed
            child, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True, timeout=1800, check=False
        )
        stream.write(done.stdout)
        return done.returncode
    finally:
        if not args.keep and not inside:
            shutil.rmtree(prefix, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
