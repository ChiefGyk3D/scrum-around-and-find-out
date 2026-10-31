# SPDX-License-Identifier: Apache-2.0
"""Image bytes from the vendor: base64 inline data, accepted only as one of three formats within hard limits.

The bytes are untrusted output (docs/gemini-broker.md, "Images"). Nothing here decodes pixels, reads metadata or
re-encodes. What it does do is walk the container of the file from its first byte to its last, using only the lengths
and markers the format puts there, so that what was checked is what a viewer would draw:

* the format comes from the first bytes, never from a name or from what the vendor says, and must match the MIME type
  the vendor named; the MIME type must be on the allow-list;
* the walk must land exactly on the end of the data: a JPEG on its end marker (found by skipping segment lengths and
  the entropy-coded data, never by looking at the last two bytes), a PNG on a zero-length `IEND` chunk, a WebP on the
  RIFF length. Anything after it, a second image, a second frame header or a segment whose length overruns is refused;
* a segment or chunk that is not on the format's allow-list is refused (a JPEG marker nobody needs, a PNG critical
  chunk we do not know, an animation, a WebP chunk that is not metadata or the one image), and so is a PNG chunk with
  a wrong checksum;
* the width and height are read from the one frame header the walk accepted (PNG `IHDR`, the JPEG frame header, the
  WebP image chunk, which must agree with the `VP8X` canvas) and capped, per side and in pixels;
* the base64 text must be canonical (the encoding of the bytes it decodes to), so no bit is hidden in padding.

A refusal is `ImageRefused` with a fixed sentence that never quotes the bytes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import zlib
from dataclasses import dataclass

MAX_IMAGE_BYTES = 24 * 1024 * 1024  # decoded
MAX_IMAGE_B64 = 4 * ((MAX_IMAGE_BYTES + 2) // 3)
MAX_SIDE = 8192
MAX_PIXELS = 2**25  # 33,554,432: 8192 x 4096; the largest listed size (4K) is 4096 x 4096
MIME_EXT = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_MAX_SEGMENTS = 1024
_MAX_CHUNKS = 100_000
_JPEG_SOF = frozenset({0xC0, 0xC1, 0xC2})  # baseline, extended sequential, progressive (Huffman, 8 bit)
_JPEG_TABLES = frozenset(
    {0xDB, 0xC4, 0xDD, 0xFE, *range(0xE0, 0xF0)}
)  # quantization, Huffman, restart interval, comment, APPn
_JPEG_SCAN = 0xDA
_JPEG_EOI = 0xD9
_JPEG_NEXT_MARKER = re.compile(
    rb"\xff[^\x00\xd0-\xd7]"
)  # in entropy data: FF 00 is a stuffed byte, FF D0..D7 a restart
_PNG_DEPTHS = {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}
_PNG_NEVER = frozenset({b"acTL", b"fcTL", b"fdAT", b"IHDR"})  # animation, and a second header
_WEBP_META = frozenset({b"ICCP", b"ALPH", b"EXIF", b"XMP "})


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


# -- PNG -----------------------------------------------------------------------------------------------------------


def _png(data: bytes) -> ImageInfo:
    size_all = len(data)
    pos = len(PNG_SIGNATURE)
    dims: tuple[int, int] | None = None
    run = 0  # 0: no image data yet, 1: inside the run of IDAT chunks, 2: the run is over
    for _ in range(_MAX_CHUNKS):
        if pos + 12 > size_all:
            raise _no("the image does not end where a PNG ends")
        size = int.from_bytes(data[pos : pos + 4], "big")
        kind = data[pos + 4 : pos + 8]
        end = pos + 8 + size
        if size > 0x7FFFFFFF or end + 4 > size_all or not kind.isalpha() or kind[2] & 0x20:
            raise _no("the image is not a well formed PNG")
        if int.from_bytes(data[end : end + 4], "big") != zlib.crc32(data[pos + 4 : end]):
            raise _no("the image has a chunk with a wrong checksum")
        if dims is None:  # the first chunk is the header and nothing else may be first
            dims = _png_header(kind, data[pos + 8 : end])
        elif kind in _PNG_NEVER:
            raise _no("the image has a second header or is an animation")
        elif kind == b"IDAT":
            if run == 2:
                raise _no("the image data of the PNG is not in one run")
            run = 1
        else:
            run = 2 if run else 0
            if kind == b"IEND":
                if size or run != 2 or end + 4 != size_all:
                    raise _no("the image does not end where a PNG ends")
                return _check_dims("image/png", *dims)
            if not kind[0] & 0x20 and kind != b"PLTE":  # a critical chunk this code does not know
                raise _no("the image has a chunk this program does not accept")
        pos = end + 4
    raise _no("the image has too many chunks")


def _png_header(kind: bytes, body: bytes) -> tuple[int, int]:
    if kind != b"IHDR" or len(body) != 13:
        raise _no("the image is not a well formed PNG")
    depth, color, method, filtering, interlace = body[8], body[9], body[10], body[11], body[12]
    if depth not in _PNG_DEPTHS.get(color, ()) or method != 0 or filtering != 0 or interlace not in (0, 1):
        raise _no("the image is not a well formed PNG")
    return int.from_bytes(body[0:4], "big"), int.from_bytes(body[4:8], "big")


# -- JPEG ----------------------------------------------------------------------------------------------------------


def _jpeg(data: bytes) -> ImageInfo:
    """Walk SOI, segments, scans (entropy-coded data skipped by its markers) up to the end marker, which must be the
    last two bytes. One frame header only; every marker must be on the allow-list."""
    total = len(data)
    pos = 2
    frame: tuple[int, int] | None = None
    scans = 0
    for _ in range(_MAX_SEGMENTS):
        if pos + 2 > total or data[pos] != 0xFF:
            raise _no("the image is not a well formed JPEG")
        marker = data[pos + 1]
        if marker == _JPEG_EOI:
            if frame is None or not scans or pos + 2 != total:
                raise _no("the image does not end where a JPEG ends")
            return _check_dims("image/jpeg", *frame)
        if marker not in _JPEG_TABLES and marker not in _JPEG_SOF and marker != _JPEG_SCAN:
            raise _no("the image has a segment this program does not accept")
        size = int.from_bytes(data[pos + 2 : pos + 4], "big")
        end = pos + 2 + size
        if pos + 4 > total or size < 2 or end > total:
            raise _no("the image is not a well formed JPEG")
        if marker in _JPEG_SOF:
            components = data[pos + 9] if size >= 8 else 0
            if frame is not None or data[pos + 4] != 8 or not 1 <= components <= 4 or size != 8 + 3 * components:
                raise _no("the image has a second or malformed frame header")
            frame = (int.from_bytes(data[pos + 7 : pos + 9], "big"), int.from_bytes(data[pos + 5 : pos + 7], "big"))
        if marker == _JPEG_SCAN:
            if frame is None:
                raise _no("the image is not a well formed JPEG")
            scans += 1
            found = _JPEG_NEXT_MARKER.search(data, end)
            if found is None:
                raise _no("the image does not end where a JPEG ends")
            end = found.start()
        pos = end
    raise _no("the image has too many segments")


# -- WebP ----------------------------------------------------------------------------------------------------------


def _webp(data: bytes) -> ImageInfo:
    total = len(data)
    if total < 20 or int.from_bytes(data[4:8], "little") != total - 8:
        raise _no("the image does not end where a WebP ends")
    pos = 12
    chunks: list[tuple[bytes, bytes]] = []
    while pos < total:
        if len(chunks) >= 64 or pos + 8 > total:
            raise _no("the image is not a well formed WebP")
        size = int.from_bytes(data[pos + 4 : pos + 8], "little")
        end = pos + 8 + size
        pad = size & 1
        if end + pad > total or (pad and data[end] != 0):
            raise _no("the image is not a well formed WebP")
        chunks.append((data[pos : pos + 4], data[pos + 8 : end]))
        pos = end + pad
    images = [body for kind, body in chunks if kind in (b"VP8 ", b"VP8L")]
    if len(images) != 1:
        raise _no("the image is not a WebP with exactly one image")
    image_kind = next(kind for kind, _ in chunks if kind in (b"VP8 ", b"VP8L"))
    width, height = _webp_image(image_kind, images[0])
    first, head = chunks[0]
    if first == b"VP8X":
        if len(head) != 10 or head[0] & 0x02:
            raise _no("the image is an animation or has a malformed header")
        if any(kind not in _WEBP_META and kind not in (b"VP8 ", b"VP8L") for kind, _ in chunks[1:]):
            raise _no("the image has a chunk this program does not accept")
        canvas = (1 + int.from_bytes(head[4:7], "little"), 1 + int.from_bytes(head[7:10], "little"))
        if canvas != (width, height):
            raise _no("the image canvas does not match the image")
    elif len(chunks) != 1:
        raise _no("the image is not a plain WebP")
    return _check_dims("image/webp", width, height)


def _webp_image(kind: bytes, body: bytes) -> tuple[int, int]:
    if kind == b"VP8L" and len(body) >= 5 and body[0] == 0x2F:
        bits = int.from_bytes(body[1:5], "little")
        if bits >> 29:  # the version field must be zero
            raise _no("the image is not a well formed WebP")
        return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    if kind == b"VP8 " and len(body) >= 10 and body[3:6] == b"\x9d\x01\x2a":
        return int.from_bytes(body[6:8], "little") & 0x3FFF, int.from_bytes(body[8:10], "little") & 0x3FFF
    raise _no("the image is not a well formed WebP")


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
