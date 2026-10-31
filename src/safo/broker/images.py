# SPDX-License-Identifier: Apache-2.0
"""Image bytes from the vendor: base64 inline data, accepted only as one of three formats within hard limits.

The bytes are untrusted output (docs/gemini-broker.md, "Images"). Nothing here decodes pixels, reads metadata or
re-encodes. What it does read is a handful of fixed header bytes, so that a decompression bomb (a small file that
declares a huge canvas) and a polyglot (a real image with another format appended) are refused before anything
downstream sees them:

* the format comes from the first bytes, never from a name or from what the vendor says, and must match the MIME type
  the vendor named; the MIME type must be on the allow-list;
* the declared width and height are read from the header (PNG `IHDR`, JPEG `SOF`, WebP `VP8X`, `VP8L` or `VP8 `) and
  capped, both per side and in pixels;
* the file must end where its format ends (the PNG `IEND` chunk, the JPEG `EOI` marker, the RIFF length of a WebP), so
  nothing is appended;
* the base64 text must be canonical (the encoding of the bytes it decodes to), so no bit is hidden in padding.

A refusal is `ImageRefused` with a fixed sentence that never quotes the bytes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass

MAX_IMAGE_BYTES = 24 * 1024 * 1024  # decoded
MAX_IMAGE_B64 = 4 * ((MAX_IMAGE_BYTES + 2) // 3)
MAX_SIDE = 8192
MAX_PIXELS = 2**25  # 33,554,432: 8192 x 4096; the largest listed size (4K) is 4096 x 4096
MIME_EXT = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_SOF = frozenset({0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF})
_MAX_SEGMENTS = 64
_MAX_CHUNKS = 4096


class ImageRefused(Exception):
    """The image is not one the broker hands on. The message is a fixed sentence."""


@dataclass(frozen=True)
class ImageInfo:
    mime: str
    width: int
    height: int


@dataclass(frozen=True)
class Image:
    index: int
    mime: str
    data: bytes
    sha256: str
    width: int
    height: int


def _no(why: str) -> ImageRefused:
    return ImageRefused(why)


def _check_dims(mime: str, width: int, height: int) -> ImageInfo:
    if not (1 <= width <= MAX_SIDE and 1 <= height <= MAX_SIDE and width * height <= MAX_PIXELS):
        raise _no("the image declares a size over the limit")
    return ImageInfo(mime, width, height)


def _png(data: bytes) -> ImageInfo:
    if len(data) < 8 + 25 + 12 or data[8:16] != b"\x00\x00\x00\rIHDR":
        raise _no("the image is not a well formed PNG")
    pos = 8
    for _ in range(_MAX_CHUNKS):  # walk the chunks: IEND must be the last one and end exactly at the end of the data
        if pos + 12 > len(data):
            raise _no("the image does not end where a PNG ends")
        size = int.from_bytes(data[pos : pos + 4], "big")
        kind = data[pos + 4 : pos + 8]
        pos += 12 + size
        if kind == b"IEND":
            if pos != len(data) or size != 0:
                raise _no("the image does not end where a PNG ends")
            break
    else:
        raise _no("the image does not end where a PNG ends")
    return _check_dims("image/png", int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big"))


def _jpeg(data: bytes) -> ImageInfo:
    if len(data) < 4 or data[-2:] != b"\xff\xd9":
        raise _no("the image does not end where a JPEG ends")
    pos = 2
    for _ in range(_MAX_SEGMENTS):
        while pos < len(data) and data[pos] == 0xFF and pos + 1 < len(data) and data[pos + 1] == 0xFF:
            pos += 1  # fill bytes before a marker
        if pos + 4 > len(data) or data[pos] != 0xFF:
            raise _no("the image is not a well formed JPEG")
        marker = data[pos + 1]
        size = int.from_bytes(data[pos + 2 : pos + 4], "big")
        if size < 2 or pos + 2 + size > len(data):
            raise _no("the image is not a well formed JPEG")
        if marker in _SOF:
            if size < 8:
                raise _no("the image is not a well formed JPEG")
            height = int.from_bytes(data[pos + 5 : pos + 7], "big")
            width = int.from_bytes(data[pos + 7 : pos + 9], "big")
            return _check_dims("image/jpeg", width, height)
        if marker == 0xDA:  # the scan starts before any frame header: no size was declared
            raise _no("the image is not a well formed JPEG")
        pos += 2 + size
    raise _no("the image is not a well formed JPEG")


def _webp(data: bytes) -> ImageInfo:
    if len(data) < 30 or int.from_bytes(data[4:8], "little") != len(data) - 8:
        raise _no("the image does not end where a WebP ends")
    chunk = data[12:16]
    if chunk == b"VP8X":
        width = 1 + int.from_bytes(data[24:27], "little")
        height = 1 + int.from_bytes(data[27:30], "little")
    elif chunk == b"VP8L" and data[20] == 0x2F:
        bits = int.from_bytes(data[21:25], "little")
        width, height = (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    elif chunk == b"VP8 " and data[23:26] == b"\x9d\x01\x2a":
        width = int.from_bytes(data[26:28], "little") & 0x3FFF
        height = int.from_bytes(data[28:30], "little") & 0x3FFF
    else:
        raise _no("the image is not a well formed WebP")
    return _check_dims("image/webp", width, height)


def sniff(data: bytes) -> ImageInfo:
    """The format and declared size of image bytes, or ImageRefused. The format is decided by the first bytes alone."""
    if type(data) is not bytes or not 1 <= len(data) <= MAX_IMAGE_BYTES:
        raise _no("the image is empty or over the size limit")
    if data.startswith(PNG_SIGNATURE):
        return _png(data)
    if data.startswith(b"\xff\xd8\xff"):
        return _jpeg(data)
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return _webp(data)
    raise _no("the image is not a PNG, a JPEG or a WebP")


def decode_part(index: int, mime: object, text: object) -> Image:
    """One inline image: the MIME type on the allow-list, canonical base64, and bytes that are that format."""
    if type(mime) is not str or mime not in MIME_EXT:
        raise _no("the image type is not on the allow-list")
    if type(text) is not str or not 1 <= len(text) <= MAX_IMAGE_B64:
        raise _no("the image data is empty or over the size limit")
    try:
        encoded = str.encode(text, "ascii")
        raw = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error):
        raise _no("the image data is not base64") from None
    if base64.b64encode(raw) != encoded:
        raise _no("the image data is not canonical base64")
    info = sniff(raw)
    if info.mime != mime:
        raise _no("the image bytes are not the type the vendor named")
    return Image(index, info.mime, raw, hashlib.sha256(raw).hexdigest(), info.width, info.height)
