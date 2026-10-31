# SPDX-License-Identifier: Apache-2.0
"""Image bytes from the vendor: allow-list, magic bytes, size and dimension caps, polyglots, canonical base64."""

from __future__ import annotations

import base64
from typing import Any, cast

import pytest

from fakevendor import b64, chunk, jpeg, png, webp
from safo.broker import images
from safo.broker.images import ImageRefused, decode_part, sniff

GOOD = [("image/png", png()), ("image/jpeg", jpeg()), ("image/webp", webp())]


@pytest.mark.parametrize(("mime", "data"), GOOD)
def test_each_allowed_format_is_read_by_its_first_bytes(mime: str, data: bytes) -> None:
    info = sniff(data)
    assert (info.mime, info.width, info.height) == (mime, 1, 1)
    image = decode_part(0, mime, b64(data))
    assert image.data == data and image.mime == mime and len(image.sha256) == 64


def test_the_declared_size_is_read_from_each_header() -> None:
    assert (sniff(png(640, 480)).width, sniff(png(640, 480)).height) == (640, 480)
    assert (sniff(jpeg(300, 200)).width, sniff(jpeg(300, 200)).height) == (300, 200)
    assert (sniff(webp(512, 256)).width, sniff(webp(512, 256)).height) == (512, 256)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"GIF89a" + b"\x00" * 40,
        b"%PDF-1.7" + b"\x00" * 40,
        b"<svg xmlns='x'></svg>",
        b"\x89PNG\r\n\x1a\n",  # a signature and nothing else
        b"\xff\xd8\xff",
        b"RIFF\x00\x00\x00\x00WEBP",
        b"MZ" + b"\x00" * 60,
    ],
)
def test_anything_that_is_not_one_of_the_three_formats_is_refused(data: bytes) -> None:
    with pytest.raises(ImageRefused):
        sniff(data)


def test_a_format_is_decided_by_the_bytes_not_by_the_name_the_vendor_gave() -> None:
    for claimed in ("image/jpeg", "image/webp"):
        with pytest.raises(ImageRefused, match="not the type"):
            decode_part(0, claimed, b64(png()))
    with pytest.raises(ImageRefused, match="not the type"):
        decode_part(0, "image/png", b64(jpeg()))


@pytest.mark.parametrize(
    "mime", ["image/gif", "image/svg+xml", "IMAGE/PNG", "image/png; charset=x", "", None, 7, b"image/png"]
)
def test_a_mime_type_off_the_allow_list_is_refused_even_with_good_bytes(mime: object) -> None:
    with pytest.raises(ImageRefused, match="allow-list"):
        decode_part(0, mime, b64(png()))


def test_data_that_is_not_canonical_base64_is_refused() -> None:
    good = b64(png())
    for bad in (
        good + "\n",
        " " + good,
        good[:-1],
        good + "=",
        good.replace("A", "-", 1),
        good[:10] + " " + good[10:],
        "",
        None,
        5,
    ):
        with pytest.raises(ImageRefused):
            decode_part(0, "image/png", bad)


def test_trailing_bits_hidden_in_padding_are_refused() -> None:
    data = png() + b"\x00"  # pick a length with padding, then flip a bit that decodes to the same bytes
    raw = base64.b64encode(data).decode()
    assert raw.endswith("=")
    last = raw.rstrip("=")[-1]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    twin = raw.rstrip("=")[:-1] + alphabet[(alphabet.index(last) + 1) % 64] + "=" * (len(raw) - len(raw.rstrip("=")))
    assert base64.b64decode(twin) == base64.b64decode(raw)  # the same bytes under a different text
    with pytest.raises(ImageRefused, match="canonical"):
        decode_part(0, "image/png", twin)


def test_a_declared_canvas_over_the_limit_is_refused() -> None:
    for data in (png(8193, 1), png(1, 8193), png(8192, 8192), jpeg(9000, 10), webp(8193, 2), png(0, 5), png(5, 0)):
        with pytest.raises(ImageRefused, match=r"size|well formed"):
            sniff(data)
    sniff(png(8192, 4096))  # exactly the pixel limit
    with pytest.raises(ImageRefused):
        sniff(png(8192, 4097))


def test_a_polyglot_with_data_appended_is_refused() -> None:
    zipish = b"PK\x03\x04" + b"\x00" * 30
    for data in (png() + zipish, jpeg() + zipish, webp() + zipish, png() + b"\x00", jpeg() + b"\x00"):
        with pytest.raises(ImageRefused):
            sniff(data)


def test_a_chunk_hidden_after_the_png_end_marker_or_inside_is_not_followed() -> None:
    # data between IHDR and IEND is the format's own business; nothing after IEND is allowed
    assert sniff(png(extra=chunk(b"tEXt", b""))).mime == "image/png"
    with pytest.raises(ImageRefused):
        sniff(png() + png())


def test_a_jpeg_with_a_scan_before_its_frame_header_or_no_frame_is_refused() -> None:
    scan_first = b"\xff\xd8\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\xff\xd9"
    with pytest.raises(ImageRefused):
        sniff(scan_first)
    many = b"\xff\xd8\xff" + b"\xe1\x00\x02" * 100 + b"\xff\xd9"
    with pytest.raises(ImageRefused):
        sniff(many)


def test_a_webp_whose_riff_length_lies_is_refused() -> None:
    data = bytearray(webp())
    data[4:8] = (len(data) + 10).to_bytes(4, "little")
    with pytest.raises(ImageRefused):
        sniff(bytes(data))


def test_the_byte_limit_applies_before_anything_is_decoded() -> None:
    big = png(extra=b"\x00" * (images.MAX_IMAGE_BYTES))
    with pytest.raises(ImageRefused, match="size limit"):
        sniff(big)
    with pytest.raises(ImageRefused, match="size limit"):
        decode_part(0, "image/png", "A" * (images.MAX_IMAGE_B64 + 4))
    with pytest.raises(ImageRefused):
        sniff(cast(Any, bytearray(png())))  # a bytearray is not exact bytes


def test_a_name_or_path_cannot_reach_the_result() -> None:
    image = decode_part(3, "image/png", b64(png()))
    assert set(vars(image)) == {"index", "mime", "data", "sha256", "width", "height"}
    assert image.index == 3


def test_characters_outside_the_base64_alphabet_are_named_as_such_not_silently_dropped() -> None:
    good = b64(png())
    for bad in (good.replace("A", "-", 1), good[:10] + " " + good[10:], good + "\n", "!" + good):
        with pytest.raises(ImageRefused, match="not base64"):
            decode_part(0, "image/png", bad)


def test_the_byte_limit_is_exactly_twenty_four_mebibytes() -> None:
    limit = 24 * 1024 * 1024
    assert limit == images.MAX_IMAGE_BYTES
    with pytest.raises(ImageRefused, match="size limit"):
        sniff(png(extra=b"\x00" * limit))
