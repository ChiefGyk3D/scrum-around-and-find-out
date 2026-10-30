# SPDX-License-Identifier: Apache-2.0
"""Signed approvals for paid Gemini calls (#200): who may authorize spend, checked against PUBLIC keys only.

A paid approval is an OpenSSH signature (`ssh-keygen -Y sign`, namespace `safo-gemini-approval`) over a canonical JSON
payload. This module verifies it. There is no secret anywhere here: the wrapper reads an allowed-signers file of public
keys, a revocation list, and the signature. The private half lives on a hardware security key that needs a touch (an
`ed25519-sk` or `ecdsa-sk` key) and the code never opens a private key file; it passes the path to `ssh-keygen`.

The trust files (`allowed-signers`, the revocation list) are maintainer-edited, at fixed locations that must be owned by
root (or by `trust_uid` in a test) and not writable by anyone else, so an agent running as the maintainer cannot enroll
its own key. Nothing in this module ever writes to them.

What `ssh-keygen -Y verify` does not tell us, the code reads itself from the signature, which is public data: the
embedded public key (so the signer is looked up by key, then revoked keys are refused), the namespace, and for a
hardware key the authenticator flags (user presence, user verification). Those flags are part of what the
authenticator signs, so once the signature verifies they are authentic.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from safo.errors import ConfigError
from safo.gemini import RefusedError

NAMESPACE = "safo-gemini-approval"
DRYRUN_NAMESPACE = "safo-gemini-approval-dryrun"
HARDWARE_TYPES = ("sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
SOFTWARE_TYPES = ("ssh-ed25519",)
KEY_TYPES = HARDWARE_TYPES + SOFTWARE_TYPES
LABEL = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04
TRUST_FILE_BYTES = 65_536
SIGNATURE_BYTES = 4096
DIRECTIVE_FLAGS = ("allow-software", "require-pin")
_TOKEN = re.compile(r'(?:[^\s"]|"[^"]*")+')
_DIRECTIVE = re.compile(r"#\s*safo:\s*(\S+)\s+(\S+)\s*$")
_SIGNING_ENV = (
    "HOME",
    "SSH_AUTH_SOCK",
    "SSH_SK_PROVIDER",
    "SSH_ASKPASS",
    "SSH_ASKPASS_REQUIRE",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "TERM",
)
_SSH_KEYGEN = ("/usr/bin/ssh-keygen", "/bin/ssh-keygen", "/usr/local/bin/ssh-keygen")


@dataclasses.dataclass(frozen=True)
class Trust:
    """Where the public trust files are and how strict to be. Fixed by the code; a test builds its own."""

    signers: Path
    revoked: Path
    uid: int = 0  # the owner the trust files must have: root, in production
    require_hardware: bool = True  # only sk keys unless a key carries the written opt-in
    revocation_required: bool = True  # a missing revocation list refuses verification (a test may turn this off)


@dataclasses.dataclass(frozen=True)
class Enrolled:
    label: str
    key_type: str
    blob: bytes
    b64: str
    fingerprint: str
    allow_software: bool = False
    require_pin: bool = False
    options: str = ""
    valid_after: dt.datetime | None = None  # inclusive, UTC
    valid_before: dt.datetime | None = None  # inclusive, UTC

    @property
    def hardware(self) -> bool:
        return self.key_type in HARDWARE_TYPES


@dataclasses.dataclass(frozen=True)
class Verified:
    label: str
    fingerprint: str
    key_type: str
    hardware: bool
    user_present: bool | None  # None: a software key reports nothing
    user_verified: bool | None


@dataclasses.dataclass(frozen=True)
class SigInfo:
    namespace: str
    hashalg: str
    blob: bytes
    key_type: str
    flags: int | None


def canonical(obj: Mapping[str, Any]) -> str:
    """The one byte string that is signed: sorted keys, no whitespace, ASCII only."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fingerprint_of(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


# -- reading the trust files ------------------------------------------------------------------------------------------


def read_trust_file(path: Path, uid: int, what: str) -> bytes:
    """A maintainer-edited file: a regular file owned by `uid`, no group or other write, every directory above it owned
    by `uid` or root and not group- or other-writable (a sticky root directory is allowed), no symlink at the end."""
    real = Path(os.path.realpath(path))
    try:
        for parent in real.parents:
            info = os.stat(parent)
            sticky = bool(info.st_mode & stat.S_ISVTX) and info.st_uid == 0
            if info.st_uid not in (uid, 0) or (info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not sticky):
                raise RefusedError(f"the {what} sits under a directory that is not owned by root or is writable")
        fd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise RefusedError(f"the {what} does not exist, so nothing can be approved") from None
    except OSError:
        raise RefusedError(f"the {what} cannot be opened") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RefusedError(f"the {what} is not a regular file")
        if info.st_uid != uid:
            raise RefusedError(f"the {what} is not owned by the account that must own it (root, in production)")
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise RefusedError(f"the {what} is writable by its group or by others")
        chunks: list[bytes] = []
        total = 0
        while total <= TRUST_FILE_BYTES:  # a read may return less than the whole file: go on until the end
            part = os.read(fd, TRUST_FILE_BYTES + 1 - total)
            if not part:
                break
            chunks.append(part)
            total += len(part)
        data = b"".join(chunks)
    except OSError:
        raise RefusedError(f"the {what} cannot be read") from None
    finally:
        os.close(fd)
    if len(data) > TRUST_FILE_BYTES:
        raise RefusedError(f"the {what} is larger than {TRUST_FILE_BYTES} bytes")
    return data


def _split_options(text: str) -> list[str]:
    parts: list[str] = []
    current = ""
    quoted = False
    for char in text:
        if char == '"':
            quoted = not quoted
        if char == "," and not quoted:
            parts.append(current)
            current = ""
        else:
            current += char
    parts.append(current)
    return parts


_WINDOW_TIME = re.compile(r"(\d{4})(\d{2})(\d{2})(?:(\d{2})(\d{2})(\d{2})?)?Z")


def _window_time(value: str, name: str, number: int) -> dt.datetime:
    """OpenSSH reads these in the local time zone unless they end in Z; only the UTC form is accepted here, so the
    window means the same thing on every machine."""
    found = _WINDOW_TIME.fullmatch(value)
    if found is None:
        raise RefusedError(
            f"allowed-signers line {number}: {name} must be a UTC time ending in Z "
            "(YYYYMMDDZ, YYYYMMDDHHMMZ or YYYYMMDDHHMMSSZ)"
        )
    year, month, day, hour, minute, second = (int(x or 0) for x in found.groups())
    try:
        return dt.datetime(year, month, day, hour, minute, second, tzinfo=dt.UTC)
    except ValueError:
        raise RefusedError(f"allowed-signers line {number}: {name} is not a real time") from None


def _check_options(options: str, number: int) -> tuple[dt.datetime | None, dt.datetime | None]:
    namespaces_ok = False
    after: dt.datetime | None = None
    before: dt.datetime | None = None
    for part in filter(None, _split_options(options)):
        name, _, value = part.partition("=")
        name = name.lower()
        if name == "no-touch-required":
            raise RefusedError(
                f"allowed-signers line {number}: the key carries no-touch-required, so a signature would not need a "
                "touch; it is refused"
            )
        if name == "namespaces":
            if value.strip('"') != NAMESPACE:
                raise RefusedError(f'allowed-signers line {number}: namespaces must be exactly "{NAMESPACE}"')
            namespaces_ok = True
        elif name == "valid-after":
            after = _window_time(value.strip('"'), name, number)
        elif name == "valid-before":
            before = _window_time(value.strip('"'), name, number)
        else:
            raise RefusedError(f"allowed-signers line {number}: the option {name[:30]!r} is not allowed")
    if after is not None and before is not None and before <= after:
        raise RefusedError(f"allowed-signers line {number}: valid-before must be later than valid-after")
    if not namespaces_ok:
        raise RefusedError(f'allowed-signers line {number}: the key must be bound with namespaces="{NAMESPACE}"')
    return after, before


def _blob_type(blob: bytes) -> str | None:
    try:
        return _Reader(blob).text()
    except ValueError:
        return None


def _valid_blob(blob: bytes, key_type: str) -> bool:
    """The public key blob is exactly the shape of its type: a truncated or padded key is not a key."""
    try:
        r = _Reader(blob)
        if r.text() != key_type:
            return False
        if key_type == "ssh-ed25519":
            ok = len(r.string()) == 32
        elif key_type == "sk-ssh-ed25519@openssh.com":
            ok = len(r.string()) == 32 and r.text().startswith("ssh:")
        elif key_type == "sk-ecdsa-sha2-nistp256@openssh.com":
            ok = r.text() == "nistp256" and len(r.string()) == 65 and r.text().startswith("ssh:")
        else:
            return False
        return ok and r.done()
    except ValueError:
        return False


def parse_signers(text: str) -> list[Enrolled]:
    """Strict: one principal label per key, only the namespace and validity options, only ed25519 and sk key types, no
    `no-touch-required`, no certificate authority, no duplicate label or key. A `# safo: <label> <flag>` comment line
    is the written opt-in for a software key (`allow-software`) or a PIN requirement (`require-pin`)."""
    keys: list[Enrolled] = []
    flags: dict[str, set[str]] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            found = _DIRECTIVE.fullmatch(line)
            if found:
                if found.group(2) not in DIRECTIVE_FLAGS:
                    raise RefusedError(f"allowed-signers line {number}: unknown safo directive")
                flags.setdefault(found.group(1), set()).add(found.group(2))
            continue
        tokens = _TOKEN.findall(line)
        if len(tokens) < 3:
            raise RefusedError(f"allowed-signers line {number}: expected label, [options,] key type, key")
        label = tokens[0]
        if not LABEL.fullmatch(label):
            raise RefusedError(f"allowed-signers line {number}: the label is one plain lowercase name (no commas, @)")
        options = ""
        rest = tokens[1:]
        if not re.fullmatch(r"(?:sk-|ssh-|ecdsa-)[a-z0-9@.-]+", rest[0]):
            options, rest = rest[0], rest[1:]
        if len(rest) < 2:
            raise RefusedError(f"allowed-signers line {number}: expected key type and key")
        key_type, b64 = rest[0], rest[1]
        after, before = _check_options(options, number)
        if key_type not in KEY_TYPES:
            raise RefusedError(f"allowed-signers line {number}: key type {key_type[:40]!r} is not accepted")
        try:
            blob = base64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError):
            raise RefusedError(f"allowed-signers line {number}: the key is not base64") from None
        if not _valid_blob(blob, key_type):
            raise RefusedError(f"allowed-signers line {number}: the key does not match its type")
        if any(k.label == label for k in keys):
            raise RefusedError(f"allowed-signers line {number}: the label {label} is used twice")
        if any(k.blob == blob for k in keys):
            raise RefusedError(f"allowed-signers line {number}: this key is enrolled twice")
        keys.append(
            Enrolled(
                label,
                key_type,
                blob,
                b64,
                fingerprint_of(blob),
                options=options,
                valid_after=after,
                valid_before=before,
            )
        )
    known = {k.label for k in keys}
    for label in flags:
        if label not in known:
            raise RefusedError("a safo directive names a label that is not enrolled")
    return [
        dataclasses.replace(
            k,
            allow_software="allow-software" in flags.get(k.label, ()),
            require_pin="require-pin" in flags.get(k.label, ()),
        )
        for k in keys
    ]


def parse_revoked(text: str) -> tuple[frozenset[bytes], frozenset[str]]:
    """Revoked keys: a line is a public key (`type base64 [comment]`) or a `SHA256:` fingerprint. A line that is neither
    stops everything, because a list that was half read could let a revoked key through."""
    blobs: set[bytes] = set()
    prints: set[str] = set()
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if FINGERPRINT.fullmatch(line):
            prints.add(line)
            continue
        parts = line.split()
        try:
            blob = base64.b64decode(parts[1], validate=True) if len(parts) >= 2 else b""
        except (binascii.Error, ValueError):
            blob = b""
        if not blob or not _valid_blob(blob, parts[0]):
            raise RefusedError(f"revocation list line {number}: expected a public key or a SHA256: fingerprint")
        blobs.add(blob)
        prints.add(fingerprint_of(blob))
    return frozenset(blobs), frozenset(prints)


@dataclasses.dataclass(frozen=True)
class Roster:
    keys: tuple[Enrolled, ...]
    revoked_prints: frozenset[str]
    revoked_file_present: bool

    def is_revoked(self, key: Enrolled) -> bool:
        return key.fingerprint in self.revoked_prints


def load_roster(trust: Trust) -> Roster:
    keys = parse_signers(read_trust_file(trust.signers, trust.uid, "allowed-signers file").decode("utf-8", "replace"))
    present = os.path.lexists(trust.revoked)
    prints: frozenset[str] = frozenset()
    if present or trust.revocation_required:  # required: a missing list is read, and refused, not treated as empty
        text = read_trust_file(trust.revoked, trust.uid, "revocation list").decode("utf-8", "replace")
        _, prints = parse_revoked(text)
    return Roster(tuple(keys), prints, present)


def _window_problem(key: Enrolled, now: dt.datetime) -> str | None:
    if key.valid_before is not None and now > key.valid_before:
        return f"expired (valid-before {key.valid_before:%Y-%m-%dT%H:%M:%SZ})"
    if key.valid_after is not None and now < key.valid_after:
        return f"not yet valid (valid-after {key.valid_after:%Y-%m-%dT%H:%M:%SZ})"
    return None


def unusable_reason(key: Enrolled, trust: Trust, roster: Roster, now: dt.datetime | None = None) -> str | None:
    if roster.is_revoked(key):
        return "revoked"
    problem = _window_problem(key, now or dt.datetime.now(dt.UTC))
    if problem:
        return problem
    if not key.hardware and trust.require_hardware and not key.allow_software:
        return "not a hardware key and no written opt-in"
    return None


# -- reading a signature ----------------------------------------------------------------------------------------------


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.at + n > len(self.data):
            raise ValueError("short")
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def string(self) -> bytes:
        return self.take(self.u32())

    def text(self) -> str:
        return self.string().decode("ascii")

    def done(self) -> bool:
        return self.at == len(self.data)


def parse_signature(armor: str) -> SigInfo:
    """The public parts of an SSHSIG armor: namespace, hash, signer's public key and, for a hardware key, the flags."""
    if len(armor) > SIGNATURE_BYTES:
        raise RefusedError("the signature is too large")
    lines = armor.strip().splitlines()
    if len(lines) < 3 or lines[0] != "-----BEGIN SSH SIGNATURE-----" or lines[-1] != "-----END SSH SIGNATURE-----":
        raise RefusedError("the approval has no SSH signature")
    try:
        raw = base64.b64decode("".join(lines[1:-1]), validate=True)
        r = _Reader(raw)
        if r.take(6) != b"SSHSIG" or r.u32() != 1:
            raise ValueError("magic")
        blob = r.string()
        namespace = r.text()
        r.string()  # reserved
        hashalg = r.text()
        sig = _Reader(r.string())
        if not r.done():
            raise ValueError("trailing")
        key_type = sig.text()
        sig.string()
        flags: int | None = None
        if key_type in HARDWARE_TYPES:
            flags = sig.take(1)[0]
            sig.u32()  # the authenticator's counter
        if not sig.done() or _blob_type(blob) != key_type:
            raise ValueError("shape")
    except (ValueError, binascii.Error, UnicodeError):
        raise RefusedError("the approval's signature is not a readable SSH signature") from None
    return SigInfo(namespace, hashalg, blob, key_type, flags)


# -- ssh-keygen -------------------------------------------------------------------------------------------------------


def ssh_keygen() -> str:
    for candidate in _SSH_KEYGEN:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise RefusedError("ssh-keygen was not found in a system directory")


_SEALS = (
    getattr(fcntl, "F_SEAL_SEAL", 1) | getattr(fcntl, "F_SEAL_SHRINK", 2) | getattr(fcntl, "F_SEAL_GROW", 4)
    | getattr(fcntl, "F_SEAL_WRITE", 8)
)  # fmt: skip
_GOOD = re.compile(rb'Good "([^"\n]{1,100})" signature for (\S{1,100}) with \S{1,40} key (SHA256:[A-Za-z0-9+/]{43})\n?')


def _sealed(data: bytes) -> int:
    """An in-memory file that nobody, this process and the same account included, can change any more: its contents
    are fixed before ssh-keygen opens it. Fails closed where sealed memory is not available."""
    try:
        fd = os.memfd_create("safo", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    except (OSError, AttributeError):
        raise RefusedError("sealed memory (memfd) is not available, so nothing was verified") from None
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        fcntl.fcntl(fd, getattr(fcntl, "F_ADD_SEALS", 1033), _SEALS)
    except OSError:
        os.close(fd)
        raise RefusedError("sealed memory (memfd) could not be sealed, so nothing was verified") from None
    return fd


def _ssh_keygen_verify(
    exe: str, line: str, payload: bytes, armor: str, namespace: str, label: str, now: dt.datetime
) -> str | None:
    """The cryptographic check, by OpenSSH itself, against ONE allowed-signers line built here from the key that was
    already looked up. The line and the signature are sealed in memory before ssh-keygen starts and reach it as
    /dev/fd paths; the message is on its standard input. Returns the key fingerprint OpenSSH says it verified (for the
    caller to compare with the key it looked up), or None when the signature does not verify."""
    fds = [_sealed((line + "\n").encode()), _sealed(armor.encode())]
    try:
        done = subprocess.run(  # noqa: S603 - absolute system ssh-keygen, fixed argument list, no shell
            [
                exe,
                "-Y",
                "verify",
                f"-Overify-time={now.astimezone(dt.UTC):%Y%m%d%H%M%S}Z",
                "-f",
                f"/dev/fd/{fds[0]}",
                "-I",
                label,
                "-n",
                namespace,
                "-s",
                f"/dev/fd/{fds[1]}",
            ],
            input=payload,
            capture_output=True,
            check=False,
            timeout=20,
            env={"PATH": "/usr/bin:/bin"},
            pass_fds=tuple(fds),
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RefusedError("ssh-keygen could not verify the signature") from None
    finally:
        for fd in fds:
            os.close(fd)
    found = _GOOD.fullmatch(done.stdout)
    if done.returncode != 0 or found is None:
        return None
    if found.group(1).decode() != namespace or found.group(2).decode() != label:
        raise RefusedError("ssh-keygen verified a signature that does not match the one that was checked")
    return found.group(3).decode()


def verify(
    trust: Trust, payload: bytes, armor: str, *, namespace: str = NAMESPACE, now: dt.datetime | None = None
) -> Verified:
    """Who signed `payload`, or why nobody who counts did. Every refusal is a RefusedError."""
    info = parse_signature(armor)
    if info.namespace != namespace:
        raise RefusedError("the signature was made for another purpose (wrong namespace)")
    if info.hashalg not in ("sha256", "sha512"):
        raise RefusedError("the signature uses a hash that is not accepted")
    roster = load_roster(trust)
    key = next((k for k in roster.keys if k.blob == info.blob), None)
    if key is None:
        raise RefusedError("the approval was not signed by an enrolled key")
    now = now or dt.datetime.now(dt.UTC)
    problem = unusable_reason(key, trust, roster, now)
    if problem:
        raise RefusedError(f"the signing key {key.label} cannot approve: {problem}")
    present = verified = None
    if key.hardware:
        flags = info.flags or 0
        present = bool(flags & FLAG_USER_PRESENT)
        verified = bool(flags & FLAG_USER_VERIFIED)
        if not present:
            raise RefusedError(f"the signature by {key.label} does not show a touch (user presence)")
        if key.require_pin and not verified:
            raise RefusedError(f"the signature by {key.label} does not show a PIN check (user verification)")
    options = f'namespaces="{namespace}"'
    for name, when in (("valid-after", key.valid_after), ("valid-before", key.valid_before)):
        if when is not None:  # OpenSSH enforces the window too, against the time it is told (below)
            options += f',{name}="{when:%Y%m%d%H%M%S}Z"'
    line = f"{key.label} {options} {key.key_type} {key.b64}"
    named = _ssh_keygen_verify(ssh_keygen(), line, payload, armor, namespace, key.label, now)
    if named is None:
        raise RefusedError("the approval's signature does not verify")
    if named != key.fingerprint:
        raise RefusedError("the key ssh-keygen verified does not match the enrolled key that was looked up")
    return Verified(key.label, key.fingerprint, key.key_type, key.hardware, present, verified)


def sign(key_path: str, payload: bytes, namespace: str, env: Mapping[str, str]) -> str:
    """Ask ssh-keygen to sign. The private key (or sk key handle) is named by path and never opened here. The message
    goes in on standard input and the signature comes back on standard output, so no file stands between the text that
    was decided and the text that is signed. For a hardware key this is where the key blinks and waits for a touch."""
    if not key_path.startswith("/") or "\x00" in key_path:
        raise ConfigError("signing.key must be an absolute path to a key file (or a public key held by an agent)")
    child = {k: v for k, v in env.items() if k in _SIGNING_ENV}
    child["PATH"] = "/usr/bin:/bin"
    try:
        done = subprocess.run(  # noqa: S603 - absolute system ssh-keygen, fixed argument list, no shell
            [ssh_keygen(), "-Y", "sign", "-f", key_path, "-n", namespace],
            input=payload,
            stdout=subprocess.PIPE,
            check=False,
            timeout=300,
            env=child,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RefusedError("ssh-keygen could not sign (is the key attached, and was it touched in time?)") from None
    if done.returncode != 0:
        raise RefusedError("ssh-keygen did not sign; no approval was written")
    try:
        armor = done.stdout.decode("ascii")
    except UnicodeError:
        armor = ""
    if len(armor) > SIGNATURE_BYTES or not armor.startswith("-----BEGIN SSH SIGNATURE-----"):
        raise RefusedError("ssh-keygen wrote no signature")
    return armor


# -- the keys subcommands (read-only) ---------------------------------------------------------------------------------


def key_rows(trust: Trust, now: dt.datetime | None = None) -> list[str]:
    roster = load_roster(trust)
    rows = []
    for k in roster.keys:
        why = unusable_reason(k, trust, roster, now)
        rows.append(
            f"{k.label}  {k.key_type}  {k.fingerprint}  "
            f"{'hardware (touch required)' if k.hardware else 'SOFTWARE'}  "
            f"{'PIN required' if k.require_pin else 'PIN not required'}  "
            f"{'software opt-in written' if k.allow_software else 'no software opt-in'}  "
            f"{'REVOKED' if roster.is_revoked(k) else 'not revoked'}  "
            f"{'usable' if why is None else 'NOT usable: ' + why}"
        )
    return rows


def check_report(trust: Trust, now: dt.datetime | None = None) -> tuple[list[str], list[str]]:
    """(problems, warnings). A file that does not load raises; a key that is fine but weak is a warning."""
    roster = load_roster(trust)
    problems: list[str] = []
    warnings: list[str] = []
    usable = [k for k in roster.keys if unusable_reason(k, trust, roster, now) is None]
    if not usable:
        problems.append("no usable key is enrolled, so nothing can be approved")
    if len(usable) == 1:
        warnings.append("only one usable key is enrolled: if it is lost there is no way to approve; enroll a second")
    for k in roster.keys:
        if not k.hardware:
            warnings.append(
                f"{k.label} is a software key ({k.key_type}): anything running as the account that holds it can sign "
                "with it, so it is not a hardware approval; use it only on purpose"
                + ("" if k.allow_software else " (it has no opt-in, so it is NOT usable)")
            )
        elif not k.require_pin:
            warnings.append(
                f"{k.label} needs a touch but no PIN (add `# safo: {k.label} require-pin` if its key was made with "
                "verify-required)"
            )
        if roster.is_revoked(k):
            warnings.append(f"{k.label} is revoked and cannot approve")
    from safo import geminipasskey  # tier 2 lives beside tier 1 in the same trust file

    text = read_trust_file(trust.signers, trust.uid, "allowed-signers file").decode("utf-8", "replace")
    warnings.extend(
        geminipasskey.check_warnings(geminipasskey.parse_passkeys(text), geminipasskey.passkeys_allowed(text))
    )
    if not roster.revoked_file_present:
        warnings.append("there is no revocation list file; create an empty one so a lost key can be added to it")
    return problems, warnings


def propose_line(trust: Trust, pubkey_file: Path, label: str) -> list[str]:
    """What the maintainer should add by hand. Reads the public key file, prints, writes nothing."""
    if not LABEL.fullmatch(label):
        raise ConfigError("--label: one plain lowercase name such as yubikey-a, backup-1 (letters, digits, . _ -)")
    try:
        text = pubkey_file.read_text()
    except (OSError, UnicodeError):
        raise ConfigError("cannot read the public key file") from None
    parts = text.strip().split()
    if len(text) > 2048 or len(parts) < 2 or "PRIVATE" in text:
        raise ConfigError("expected one OpenSSH public key line (the .pub file), never a private key")
    key_type, b64 = parts[0], parts[1]
    try:
        blob = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise ConfigError("the public key is not base64") from None
    if key_type not in KEY_TYPES or not _valid_blob(blob, key_type):
        raise ConfigError(f"key type {key_type[:40]!r} is not accepted; use sk-ssh-ed25519@openssh.com")
    roster = load_roster(trust)
    if any(k.label == label for k in roster.keys):
        raise ConfigError(f"the label {label} is already enrolled")
    if any(k.blob == blob for k in roster.keys):
        raise ConfigError("this key is already enrolled")
    lines = [
        f"fingerprint: {fingerprint_of(blob)}",
        "add this line to the allowed-signers file by hand (nothing was written):",
        f'{label} namespaces="{NAMESPACE}" {key_type} {b64}',
    ]
    if key_type not in HARDWARE_TYPES:
        lines.append(
            f"WARNING: this is a software key. It is refused unless you also add `# safo: {label} allow-software`; "
            "any process running as the account that holds it can sign, so it is not a hardware approval"
        )
    else:
        lines.append(f"if its key was made with -O verify-required, also add `# safo: {label} require-pin`")
    return lines
