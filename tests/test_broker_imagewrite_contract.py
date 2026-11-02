# SPDX-License-Identifier: Apache-2.0
"""The writer's documented contract (#287, finding D2): a private 0700 directory, a digest check before anything is
written, and a receipt file beside the image that is exclusive, mode 0600 and says `reviewed: false`."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from safo.broker.imagewrite import ImageRejected, ImageWriteError, UnsafeDirectory, write_image, write_receipt_file

PNG = b"\x89PNG\r\n\x1a\n" + b"p" * 24
ANY: Any = None  # the writer is called with deliberately wrong types below


@pytest.fixture
def out(tmp_path: Path) -> Path:
    d = tmp_path / "out"
    d.mkdir()
    d.chmod(0o700)
    return d


def sidecar(reviewed: object = False) -> bytes:
    return json.dumps({"reviewed": reviewed, "receipt": {"actual_usd": "0.01"}}).encode("ascii")


def test_a_matching_digest_is_written(out: Path) -> None:
    digest = hashlib.sha256(PNG).hexdigest()
    path = write_image(PNG, str(out), "cat", expected_sha256=digest)
    assert Path(path).read_bytes() == PNG


@pytest.mark.parametrize("digest", ["0" * 64, "", "abc", hashlib.sha256(PNG).hexdigest().upper(), b"0" * 64, 7])
def test_a_wrong_digest_writes_nothing(out: Path, digest: Any) -> None:
    with pytest.raises(ImageRejected):
        write_image(PNG, str(out), "cat", expected_sha256=digest)
    assert list(out.iterdir()) == []


def test_the_receipt_file_is_exclusive_private_and_beside_the_image(out: Path) -> None:
    image = write_image(PNG, str(out), "cat")
    side = write_receipt_file(image, sidecar())
    assert side == image + ".receipt.json"
    assert stat.S_IMODE(os.stat(side).st_mode) == 0o600
    assert json.loads(Path(side).read_text())["reviewed"] is False
    first = Path(side).read_bytes()
    with pytest.raises(ImageWriteError):
        write_receipt_file(image, sidecar())  # never overwrites
    assert Path(side).read_bytes() == first


@pytest.mark.parametrize("reviewed", [True, None, "false", 0])
def test_a_receipt_file_that_does_not_say_reviewed_false_is_refused(out: Path, reviewed: object) -> None:
    image = write_image(PNG, str(out), "cat")
    with pytest.raises(ImageWriteError):
        write_receipt_file(image, sidecar(reviewed))
    assert [p.name for p in out.iterdir()] == [Path(image).name]


@pytest.mark.parametrize("data", [b"", b"not json", b"[]", b"\xff", b'{"reviewed": false}' + b" " * 70000])
def test_a_receipt_file_that_is_not_a_small_json_object_is_refused(out: Path, data: bytes) -> None:
    image = write_image(PNG, str(out), "cat")
    with pytest.raises(ImageWriteError):
        write_receipt_file(image, data)
    assert [p.name for p in out.iterdir()] == [Path(image).name]


def test_the_receipt_file_refuses_a_loose_directory_and_a_foreign_name(out: Path) -> None:
    image = write_image(PNG, str(out), "cat")
    out.chmod(0o750)
    with pytest.raises(UnsafeDirectory):
        write_receipt_file(image, sidecar())
    out.chmod(0o700)
    for bad in (str(out / "../out/cat.png"), "relative.png", str(out / "..hidden"), str(out / "a b.png")):
        with pytest.raises(ImageWriteError):
            write_receipt_file(bad, sidecar())
    assert [p.name for p in out.iterdir()] == [Path(image).name]


def test_the_receipt_file_does_not_follow_a_planted_link(out: Path, tmp_path: Path) -> None:
    image = write_image(PNG, str(out), "cat")
    target = tmp_path / "elsewhere"
    target.write_text("keep")
    os.symlink(target, image + ".receipt.json")
    with pytest.raises(ImageWriteError):
        write_receipt_file(image, sidecar())
    assert target.read_text() == "keep"
