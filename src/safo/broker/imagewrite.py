# SPDX-License-Identifier: Apache-2.0
"""The client's safe image writer (#260, phase 4a; docs/gemini-broker.md, "Safe writing by the client").

An image that comes back from the paid path is untrusted output. This module is the only place the client puts one on
disk, and it decides everything about the file itself:

* the type comes from the first bytes, against an allow-list (PNG, JPEG, WebP by default); a name or a type the caller
  or the server supplied has no say. The bytes are never decoded, previewed or parsed here;
* the file name is built here: a stem cut down to ``[A-Za-z0-9_-]`` (at most 48 characters), a fixed suffix of 8 random
  hex digits and an extension from a fixed map. No path or name from a reply can reach the file system;
* the output directory is reached one component at a time from ``/`` with ``O_NOFOLLOW | O_DIRECTORY`` (so a symlink in
  any component, the last one included, is refused), and the last component must belong to the caller and be mode 0700
  EXACTLY (no group or world access of any kind, no sticky bit; #287); the file is then created relative to that
  descriptor, so swapping the path afterwards changes nothing;
* when the caller passes the digest the broker's receipt names (``expected_sha256``), the bytes are hashed and compared
  BEFORE the file system is touched; a mismatch writes nothing;
* ``write_receipt_file`` writes the receipt sidecar beside the image (``NAME.receipt.json``): the same directory rules,
  an exclusive create with mode 0600, never a replacement, and only for a small JSON object whose ``reviewed`` is
  exactly ``false``;
* the bytes go to a temporary name (``O_CREAT | O_EXCL | O_NOFOLLOW``, mode 0600, fixed with ``fchmod`` so the umask has
  no say), are flushed with ``fsync``, and are linked to the final name (``link`` never replaces an existing name),
  then the temporary name is removed and the directory is flushed. On any failure, ``BaseException`` included, nothing
  is left at the final name or at the temporary name.

Limits are parameters with documented defaults, so this module depends on no other broker code: ``ALLOWED_TYPES`` and
``MAX_IMAGE_BYTES`` match the broker's own image checks (png, jpeg and webp; 24 MiB decoded).
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import hmac
import os
import re
import secrets
import stat
import sys
from collections.abc import Callable, Collection
from typing import TextIO

from safo.bounded import loads
from safo.broker.errors import BrokerError
from safo.output import write

ALLOWED_TYPES: tuple[str, ...] = ("png", "jpeg", "webp")
MAX_IMAGE_BYTES = 24 * 1024 * 1024
EXTENSIONS = {"png": "png", "jpeg": "jpg", "webp": "webp"}
MAX_STEM = 48
DEFAULT_STEM = "image"
# The points at which the writer can be interrupted, in order. The hook ``_step`` is called at each; tests use it to
# swap a directory for a symlink between two steps and to raise at every point.
STEPS = (
    "start",
    "dir-resolved",
    "dir-opened",
    "tmp-created",
    "written",
    "synced",
    "tmp-closed",
    "linked",
    "unlinked",
    "dir-synced",
)
DIR_STEPS = ("dir-resolved", "dir-opened")
_ATTEMPTS = 16
_PNG = b"\x89PNG\r\n\x1a\n"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_UNSAFE_STEM = re.compile(r"[^A-Za-z0-9_-]")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_IMAGE_NAME = re.compile(r"[A-Za-z0-9_-]{1,48}-[0-9a-f]{8}\.(?:png|jpg|webp)|[A-Za-z0-9_-]{1,64}\.(?:png|jpg|webp)")
MAX_RECEIPT_FILE = 65_536

Step = Callable[[str], None]


class ImageWriteError(BrokerError):
    """The image was not written. The message is a fixed sentence: it never quotes a name, a path or the bytes."""


class ImageRejected(ImageWriteError):
    """The bytes are not an image this writer accepts (empty, too big, or not on the allow-list)."""


class UnsafeDirectory(ImageWriteError):
    """The output directory is a link, belongs to someone else, is writable by others or cannot be opened."""


def _no_step(name: str) -> None:
    return None


def _random_suffix() -> str:
    return secrets.token_hex(4)


def sniff_image_type(data: bytes) -> str | None:
    """The type the first bytes name (``png``, ``jpeg`` or ``webp``), or None. Nothing else about the file is read."""
    if not isinstance(data, bytes):
        return None
    if data.startswith(_PNG):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def _clean_stem(stem: object) -> str:
    if not isinstance(stem, str):
        raise ImageWriteError("the file name stem must be text")
    cleaned = _UNSAFE_STEM.sub("_", stem)[:MAX_STEM].lstrip("-")
    return cleaned or DEFAULT_STEM


def _check_config(max_bytes: object, allowed: object) -> Collection[str]:
    if not isinstance(allowed, tuple | list | set | frozenset) or not all(
        isinstance(kind, str) and kind in EXTENSIONS for kind in allowed
    ):
        raise ImageWriteError("the allowed image types are not a list of known types")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ImageWriteError("the size cap must be a positive whole number")
    return frozenset(allowed)


def _check_digest(data: bytes, expected: object) -> None:
    if type(expected) is not str or _DIGEST.fullmatch(expected) is None:
        raise ImageRejected("the expected digest is not a lowercase SHA-256")
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected):
        raise ImageRejected("the image does not match the digest in the receipt")


def _accept(data: object, max_bytes: int, allowed: Collection[str]) -> str:
    if not isinstance(data, bytes):
        raise ImageRejected("the image is not a byte string")
    if len(data) == 0:
        raise ImageRejected("the image is empty")
    if len(data) > max_bytes:
        raise ImageRejected("the image is over the size cap")
    kind = sniff_image_type(data)
    if kind is None or kind not in allowed:
        raise ImageRejected("the image is not one of the allowed types")
    return kind


def _unsafe() -> UnsafeDirectory:
    return UnsafeDirectory("the output directory is not a safe directory")


def _split(path: object) -> list[str]:
    """The components of an absolute path with no dot-dot. Anything else is refused, not repaired."""
    if not isinstance(path, str | os.PathLike):
        raise _unsafe()
    text = os.fspath(path)
    if not isinstance(text, str) or "\x00" in text or not text.startswith("/"):
        raise _unsafe()
    parts = [part for part in text.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise _unsafe()
    return parts


def _mine(st: os.stat_result) -> bool:
    return st.st_uid == os.geteuid()


def _check_write_dir(st: os.stat_result) -> None:
    """Owned by the caller and mode 0700 exactly: the documented contract, the stricter reading (#287)."""
    if not _mine(st) or stat.S_IMODE(st.st_mode) != 0o700:
        raise _unsafe()


def _check_lenient(st: os.stat_result) -> None:
    if not _mine(st) or st.st_mode & 0o022:
        raise _unsafe()


def _check_private(st: os.stat_result) -> None:
    if not _mine(st) or st.st_mode & 0o077:
        raise _unsafe()


def _open_chain(parts: list[str], *, create: bool, check: Callable[[int, int, os.stat_result], None]) -> int:
    """Open ``/`` and then each component relative to the one before, never following a link. Returns the last fd.

    ``check(index, last_index, stat)`` is called for every component; it raises UnsafeDirectory to refuse. With
    ``create``, a missing component is made with mode 0700 (and fixed with ``fchmod``, so the umask has no say).
    """
    try:
        fd = os.open("/", _DIR_FLAGS)
    except OSError:
        raise _unsafe() from None
    try:
        for index, part in enumerate(parts):
            try:
                child = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise _unsafe() from None
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                except OSError:
                    raise _unsafe() from None
                try:
                    child = os.open(part, _DIR_FLAGS, dir_fd=fd)
                except OSError:
                    raise _unsafe() from None
                try:
                    # 0o700 is owner-only, and a directory needs the x bit.
                    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
                    os.fchmod(child, 0o700)
                except BaseException as exc:
                    os.close(child)
                    if isinstance(exc, OSError):
                        raise _unsafe() from None
                    raise
            except OSError:
                raise _unsafe() from None  # a link (ELOOP), a file or FIFO (ENOTDIR), or no access
            os.close(fd)
            fd = child
            check(index, len(parts) - 1, os.fstat(fd))
        return fd
    except BaseException:
        os.close(fd)
        raise


def _same(st: os.stat_result, ident: tuple[int, int]) -> bool:
    return stat.S_ISREG(st.st_mode) and (st.st_dev, st.st_ino) == ident


def _unlink_if_same(dirfd: int, name: str, ident: tuple[int, int]) -> None:
    """Remove ``name`` only if it is still the very file this call made."""
    try:
        if _same(os.lstat(name, dir_fd=dirfd), ident):
            os.unlink(name, dir_fd=dirfd)
    except OSError:
        pass


def _io_error(exc: OSError) -> ImageWriteError:
    return ImageWriteError(f"the image could not be written ({errno.errorcode.get(exc.errno or 0, 'unknown')})")


def write_image(
    data: bytes,
    directory: str | os.PathLike[str],
    stem: str,
    max_bytes: int = MAX_IMAGE_BYTES,
    *,
    allowed: Collection[str] = ALLOWED_TYPES,
    expected_sha256: str | None = None,
    _step: Step | None = None,
) -> str:
    """Write ``data`` into ``directory`` under a name made here, and return the final path.

    ``stem`` is cut down to ``[A-Za-z0-9_-]``; the extension follows the sniffed type. ``max_bytes`` and ``allowed``
    default to the broker's own limits. Raises ImageRejected for bytes it will not write, UnsafeDirectory for a
    directory it will not trust and ImageWriteError for anything the disk refuses. A failure leaves no file behind.

    ``expected_sha256`` (lowercase hex) is the digest the broker's receipt names: when given, the bytes must hash to it
    exactly or ImageRejected is raised before the file system is touched.
    """
    step = _step or _no_step
    kinds = _check_config(max_bytes, allowed)
    kind = _accept(data, max_bytes, kinds)
    if expected_sha256 is not None:
        _check_digest(data, expected_sha256)
    clean = _clean_stem(stem)
    extension = EXTENSIONS[kind]
    parts = _split(directory)
    step("start")
    step("dir-resolved")
    dirfd = _open_chain(parts, create=False, check=lambda i, last, st: _check_write_dir(st) if i == last else None)
    fd = -1
    tmp_name: str | None = None
    tmp_ident: tuple[int, int] | None = None
    final_name: str | None = None
    try:
        step("dir-opened")
        for _ in range(_ATTEMPTS):
            candidate = ".tmp-" + _random_suffix()
            try:
                fd = os.open(candidate, _FILE_FLAGS, 0o600, dir_fd=dirfd)
            except FileExistsError:
                continue
            tmp_name = candidate
            break
        if tmp_name is None:
            raise ImageWriteError("no free temporary name in the output directory")
        st = os.fstat(fd)
        tmp_ident = (st.st_dev, st.st_ino)
        step("tmp-created")
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(fd, view[offset:])
            if written <= 0:
                raise ImageWriteError("the disk accepted no more bytes")
            offset += written
        step("written")
        os.fsync(fd)
        step("synced")
        closing, fd = fd, -1
        os.close(closing)
        step("tmp-closed")
        for _ in range(_ATTEMPTS):
            candidate = f"{clean}-{_random_suffix()}.{extension}"
            try:
                os.link(tmp_name, candidate, src_dir_fd=dirfd, dst_dir_fd=dirfd, follow_symlinks=False)
            except FileExistsError:
                continue
            final_name = candidate
            break
        if final_name is None:
            raise ImageWriteError("no free file name in the output directory")
        step("linked")
        os.unlink(tmp_name, dir_fd=dirfd)
        step("unlinked")
        os.fsync(dirfd)
        step("dir-synced")
    except BaseException as exc:
        if fd >= 0:
            with contextlib.suppress(OSError):
                os.close(fd)
        if tmp_ident is not None and final_name is not None:
            _unlink_if_same(dirfd, final_name, tmp_ident)
        if tmp_name is not None:
            if tmp_ident is not None:
                _unlink_if_same(dirfd, tmp_name, tmp_ident)
            else:  # the descriptor could not be examined; the name was made a moment ago with O_EXCL
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name, dir_fd=dirfd)
        # Make the removal durable too, best effort, so a power loss cannot bring a rolled-back file back. A failure
        # here or in close must not replace the error being reported.
        with contextlib.suppress(OSError):
            os.fsync(dirfd)
        with contextlib.suppress(OSError):
            os.close(dirfd)
        if isinstance(exc, OSError):
            raise _io_error(exc) from None
        raise
    with contextlib.suppress(OSError):  # the file is complete and durable; a close error says nothing about it
        os.close(dirfd)
    return os.path.join("/" + "/".join(parts), final_name)


def write_receipt_file(image_path: str, data: bytes) -> str:
    """Write ``<image_path>.receipt.json`` beside an image this module wrote, and return its path.

    ``data`` must be a JSON object of at most 64 KiB whose ``reviewed`` is exactly ``false``: the file is a reminder
    that nobody has looked at the image yet, and a sidecar that says otherwise is refused. The directory rules are the
    image's (reached from ``/`` without a link, ours, mode 0700); the create is exclusive with mode 0600, an existing
    name or a planted link is an error and nothing is replaced. A failure leaves no sidecar.
    """
    if not isinstance(image_path, str) or "\x00" in image_path or not image_path.startswith("/"):
        raise ImageWriteError("the image path is not an absolute path")
    parts = _split(os.path.dirname(image_path))
    name = os.path.basename(image_path)
    if _IMAGE_NAME.fullmatch(name) is None or os.path.dirname(image_path).rstrip("/") != "/" + "/".join(parts):
        raise ImageWriteError("the image path is not a file this writer made")
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_RECEIPT_FILE:
        raise ImageWriteError("the receipt file is empty or too large")
    try:
        document = loads(data)
    except (ValueError, RecursionError):
        raise ImageWriteError("the receipt file is not JSON") from None
    if not isinstance(document, dict) or document.get("reviewed") is not False:
        raise ImageWriteError("the receipt file must be a JSON object that says reviewed: false")
    dirfd = _open_chain(parts, create=False, check=lambda i, last, st: _check_write_dir(st) if i == last else None)
    target = name + ".receipt.json"
    made: tuple[int, int] | None = None
    fd = -1
    try:
        try:
            fd = os.open(target, _FILE_FLAGS, 0o600, dir_fd=dirfd)
        except FileExistsError:
            raise ImageWriteError("a receipt file with that name already exists; nothing was replaced") from None
        st = os.fstat(fd)
        made = (st.st_dev, st.st_ino)
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            written = os.write(fd, view[offset:])
            if written <= 0:
                raise ImageWriteError("the disk accepted no more bytes")
            offset += written
        os.fsync(fd)
        closing, fd = fd, -1
        os.close(closing)
        os.fsync(dirfd)
    except BaseException as exc:
        if fd >= 0:
            with contextlib.suppress(OSError):
                os.close(fd)
        if made is not None:
            _unlink_if_same(dirfd, target, made)
        with contextlib.suppress(OSError):
            os.close(dirfd)
        if isinstance(exc, OSError):
            raise _io_error(exc) from None
        raise
    with contextlib.suppress(OSError):
        os.close(dirfd)
    return os.path.join("/" + "/".join(parts), target)


def default_output_dir(*, state_home: str | None = None, home: str | None = None, _step: Step | None = None) -> str:
    """A private directory for generated images, made if missing: ``<state>/safo/gemini-images``.

    ``<state>`` is ``state_home``, else ``$XDG_STATE_HOME`` when it is an absolute path, else ``<home>/.local/state``.
    The state directory is deliberately not the pictures directory: desktop environments index and thumbnail that one,
    and a generated image must not be opened by anything the maintainer did not choose. Missing directories are made
    with mode 0700 whatever the umask. A symlink anywhere in the path, a directory owned by someone else, a state
    directory writable by group or world, or ``safo`` / ``gemini-images`` with any group or world access is refused
    (UnsafeDirectory), never repaired.
    """
    step = _step or _no_step
    if state_home is None:
        env = os.environ.get("XDG_STATE_HOME", "")
        state_home = env if env.startswith("/") else None
    if state_home is not None:
        base = _split(state_home)
    else:
        base = [*_split(home if home is not None else os.path.expanduser("~")), ".local", "state"]
    parts = [*base, "safo", "gemini-images"]
    first_private = len(base)

    def check(index: int, last: int, st: os.stat_result) -> None:
        if index >= first_private:
            _check_private(st)
        elif index == first_private - 1:
            _check_lenient(st)

    step("dir-resolved")
    os.close(_open_chain(parts, create=True, check=check))
    return "/" + "/".join(parts)


def print_summary(path: str, data: bytes, *, file: TextIO | None = None) -> str:
    """Print and return a one-line summary: the byte count and the type the first bytes name.

    It reads nothing from disk: it never opens, previews or parses the image. The path is escaped so a control or
    bidirectional character in it cannot rewrite the terminal.
    """
    kind = sniff_image_type(data) or "unknown"
    line = f"saved {len(data)} bytes, type {kind}: {ascii(path)[1:-1]}"
    write(file if file is not None else sys.stdout, line)
    return line
