# SPDX-License-Identifier: Apache-2.0
"""Image bytes from the vendor: base64 inline data, accepted only as one of three formats within hard limits.

The bytes are untrusted output (docs/gemini-broker.md, "Images"). Nothing here decodes pixels or re-encodes. What it
does do is walk the container of the file from its first byte to its last, using the lengths and markers the format puts
there, so that what was checked is what a viewer would draw. The rule is an allow-list per format: every segment or
chunk must be a known type whose body has exactly the shape that type has, and anything else is refused.

* the format comes from the first bytes, never from a name or from what the vendor says, and must match the MIME type
  the vendor named; the MIME type must be on the allow-list;
* the walk must land exactly on the end of the data: a JPEG on its end marker (found by skipping segment lengths and
  the entropy-coded data, never by looking at the last two bytes), a PNG on a zero-length `IEND` chunk, a WebP on the
  RIFF length. Anything after it, a second image, a second frame header or a segment whose length overruns is refused;
* JPEG: frame header, scan header, quantization and Huffman tables, restart interval, a plain JFIF header, an Adobe
  flag and a short plain-text comment are each parsed to the byte; Exif, XMP, Photoshop, ICC and every other
  application segment are refused;
* PNG: every chunk has a checksum and a body of its type's exact shape, in the order the format requires, once only
  where it may appear once; the palette and transparency agree with the colour type; text is short plain ASCII;
  compressed text, profiles, Exif, animations and unknown chunks are refused. The image data is inflated in small
  steps, and thrown away, to check that it is exactly the rows the header declares;
* WebP: a plain lossless or lossy image, or the extended header (alpha flag only) and the one image; no metadata chunk
  of any kind, and a lossy frame header must be a key frame whose first partition fits;
* bytes in a table or palette that the walk skips by its length are also searched for the start of another image;
* the width and height are read from the one frame header the walk accepted and capped, per side and in pixels;
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
MAX_INFLATED = 128 * 1024 * 1024  # PNG rows the data may inflate to (4096 x 4096 at 8 bytes a pixel)
MAX_PIXELS = 2**25  # 33,554,432: 8192 x 4096; the largest listed size (4K) is 4096 x 4096
MAX_TEXT = 65_536  # a PNG text chunk
MAX_COMMENT = 4096  # a JPEG comment
MIME_EXT = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_MAX_SEGMENTS = 1024
_MAX_CHUNKS = 100_000
_JPEG_SOF = frozenset({0xC0, 0xC1, 0xC2})  # baseline, extended sequential, progressive (Huffman, 8 bit)
_JPEG_DQT, _JPEG_DHT, _JPEG_DRI, _JPEG_SCAN, _JPEG_EOI = 0xDB, 0xC4, 0xDD, 0xDA, 0xD9
_JPEG_JFIF, _JPEG_ADOBE, _JPEG_COMMENT = 0xE0, 0xEE, 0xFE
_JPEG_KNOWN = _JPEG_SOF | {_JPEG_DQT, _JPEG_DHT, _JPEG_DRI, _JPEG_SCAN, _JPEG_JFIF, _JPEG_ADOBE, _JPEG_COMMENT}
_JPEG_NEXT_MARKER = re.compile(
    rb"\xff[^\x00\xd0-\xd7]"
)  # in entropy data: FF 00 is a stuffed byte, FF D0..D7 a restart
_PNG_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
_PNG_DEPTHS = {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}
_PNG_SBIT_LEN = {0: 1, 2: 3, 3: 3, 4: 2, 6: 4}
_PNG_BEFORE_DATA = frozenset({b"PLTE", b"tRNS", b"bKGD", b"sBIT", b"gAMA", b"cHRM", b"sRGB", b"pHYs", b"cICP"})
_PNG_AFTER_OK = frozenset({b"tEXt", b"tIME"})
_PNG_NEVER = frozenset({b"acTL", b"fcTL", b"fdAT", b"IHDR"})  # animation, and a second header


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


def _shape() -> ImageRefused:
    return _no("the image has a segment or chunk that is not the shape its type has")


def _embeds_image(body: bytes) -> bool:
    """Does a table or palette carry the start of another image? The walk skips such bytes by their length, so a second
    image hidden in them would not be checked: it is refused instead."""
    return b"\xff\xd8\xff" in body or PNG_SIGNATURE in body or (b"RIFF" in body and b"WEBP" in body)


def _plain_text(body: bytes, extra: bytes = b"") -> bool:
    return all(32 <= c <= 126 or c in extra for c in body)


def _check_dims(mime: str, width: int, height: int) -> ImageInfo:
    if not (1 <= width <= MAX_SIDE and 1 <= height <= MAX_SIDE and width * height <= MAX_PIXELS):
        raise _no("the image declares a size over the limit")
    return ImageInfo(mime, width, height)


# -- PNG -----------------------------------------------------------------------------------------------------------


class _PngState:
    def __init__(self, color: int, depth: int) -> None:
        self.color = color
        self.depth = depth
        self.palette = 0
        self.seen: set[bytes] = set()


def _png(data: bytes) -> ImageInfo:
    size_all = len(data)
    pos = len(PNG_SIGNATURE)
    dims: tuple[int, int] | None = None
    rows = 0  # the bytes the image data must inflate to
    state = _PngState(0, 0)
    data_parts: list[bytes] = []
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
        body = data[pos + 8 : end]
        if dims is None:  # the first chunk is the header and nothing else may be first
            dims, rows, state = _png_header(kind, body)
            _check_dims("image/png", *dims)  # before any image data is inflated
        elif kind in _PNG_NEVER:
            raise _no("the image has a second header or is an animation")
        elif kind == b"IDAT":
            if run == 2:
                raise _no("the image data of the PNG is not in one run")
            run = 1
            data_parts.append(body)
        else:
            run = 2 if run else 0
            if kind == b"IEND":
                if size or run != 2 or end + 4 != size_all:
                    raise _no("the image does not end where a PNG ends")
                if state.color == 3 and not state.palette:
                    raise _shape()
                _check_rows(data_parts, rows, rows // dims[1])
                return _check_dims("image/png", *dims)
            _png_chunk(kind, body, state, before_data=run == 0)
        pos = end + 4
    raise _no("the image has too many chunks")


def _png_header(kind: bytes, body: bytes) -> tuple[tuple[int, int], int, _PngState]:
    """The size, the number of bytes the image data must inflate to (one filter byte and the packed samples for each
    row; an interlaced image is refused, so the figure is exact), and the state the other chunks are checked against."""
    if kind != b"IHDR" or len(body) != 13:
        raise _no("the image is not a well formed PNG")
    depth, color, method, filtering, interlace = body[8], body[9], body[10], body[11], body[12]
    if depth not in _PNG_DEPTHS.get(color, ()) or method != 0 or filtering != 0 or interlace != 0:
        raise _no("the image is not a well formed PNG, or is interlaced")
    width, height = int.from_bytes(body[0:4], "big"), int.from_bytes(body[4:8], "big")
    rows = height * (1 + (width * _PNG_CHANNELS[color] * depth + 7) // 8)
    if rows > MAX_INFLATED:  # bounds the work of the check below: nothing larger is ever inflated
        raise _no("the image declares a size over the limit")
    return (width, height), rows, _PngState(color, depth)


def _png_chunk(kind: bytes, body: bytes, st: _PngState, *, before_data: bool) -> None:
    """One non-image chunk: a known type, in its place, once if it may appear once, with a body of exactly its shape."""
    if kind not in _PNG_BEFORE_DATA and kind not in _PNG_AFTER_OK:
        raise _no("the image has a chunk this program does not accept")
    if kind in _PNG_BEFORE_DATA and not before_data:
        raise _shape()
    if kind != b"tEXt" and kind in st.seen:
        raise _shape()
    st.seen.add(kind)
    size, color = len(body), st.color
    if kind == b"PLTE":
        count = size // 3
        limit = 2**st.depth if color == 3 else 256
        if color not in (2, 3, 6) or size % 3 or not 1 <= count <= min(256, limit) or _embeds_image(body):
            raise _shape()
        st.palette = count
    elif kind == b"tRNS":
        want = {0: 2, 2: 6}.get(color)
        if not (size == want if want is not None else color == 3 and 1 <= size <= st.palette):
            raise _shape()
    elif kind == b"bKGD":
        ok = size == {0: 2, 4: 2, 2: 6, 6: 6, 3: 1}[color]
        if ok and color == 3:
            ok = body[0] < st.palette
        if not ok:
            raise _shape()
    elif kind == b"sBIT":
        most = 8 if color == 3 else st.depth
        if size != _PNG_SBIT_LEN[color] or not all(1 <= c <= most for c in body):
            raise _shape()
    elif kind in (b"gAMA", b"cICP"):
        if size != 4:
            raise _shape()
    elif kind == b"cHRM":
        if size != 32:
            raise _shape()
    elif kind == b"sRGB":
        if size != 1 or body[0] > 3:
            raise _shape()
    elif kind == b"pHYs":
        if size != 9 or body[8] > 1:
            raise _shape()
    elif kind == b"tIME":
        if size != 7 or not (
            1 <= body[2] <= 12 and 1 <= body[3] <= 31 and body[4] <= 23 and body[5] <= 59 and body[6] <= 60
        ):
            raise _shape()
    else:  # tEXt: a keyword of 1 to 79 plain characters, one NUL, then plain text
        keyword, nul, text = body.partition(b"\x00")
        ok = bool(nul) and 1 <= len(keyword) <= 79 and len(body) <= MAX_TEXT
        ok = ok and _plain_text(keyword) and keyword == keyword.strip(b" ") and _plain_text(text, b"\n")
        if not ok:
            raise _shape()


def _check_rows(parts: list[bytes], expected: int, row_length: int) -> None:
    """Inflate the image data in small steps, throwing the output away, and stop at once if it passes the size the
    header declares: a small file that inflates to a huge buffer is refused here, not in whatever draws it later.
    The first byte of every row is its filter type, which is 0 to 4; anything else is not a PNG row."""
    stream = zlib.decompressobj()
    total = 0
    try:
        for part in parts:
            if stream.eof and part:
                raise _no("the image data is not the size the image declares")
            buffer = part
            while buffer and not stream.eof:
                out = stream.decompress(buffer, 65536)
                first = -total % row_length  # where the next row starts in this piece
                if out[first::row_length] and max(out[first::row_length]) > 4:
                    raise _no("the image data has a row with a filter type that does not exist")
                total += len(out)
                if total > expected:
                    raise _no("the image data is larger than the image declares")
                buffer = stream.unconsumed_tail
    except zlib.error:
        raise _no("the image data is not a deflate stream") from None
    if not stream.eof or stream.unused_data or total != expected:
        raise _no("the image data is not the size the image declares")


# -- JPEG ----------------------------------------------------------------------------------------------------------


def _jpeg_quantization(body: bytes) -> bool:
    pos = 0
    while pos < len(body):
        precision, number = body[pos] >> 4, body[pos] & 15
        if precision > 1 or number > 3:
            return False
        pos += 1 + 64 * (1 + precision)
    return bool(body) and pos == len(body)


def _jpeg_huffman(body: bytes) -> bool:
    pos = 0
    while pos < len(body):
        if pos + 17 > len(body) or body[pos] >> 4 > 1 or body[pos] & 15 > 3:
            return False
        symbols = sum(body[pos + 1 : pos + 17])
        if symbols > 256:
            return False
        pos += 17 + symbols
    return bool(body) and pos == len(body)


def _jpeg_scan_header(body: bytes) -> bool:
    count = body[0] if body else 0
    if not 1 <= count <= 4 or len(body) != 1 + 2 * count + 3:
        return False
    if any(body[2 + 2 * i] >> 4 > 3 or body[2 + 2 * i] & 15 > 3 for i in range(count)):
        return False
    start, stop = body[-3], body[-2]
    return start <= stop <= 63


def _jpeg_frame_header(body: bytes) -> bool:
    count = body[5] if len(body) > 5 else 0
    if body[:1] != b"\x08" or not 1 <= count <= 4 or len(body) != 6 + 3 * count:
        return False
    return all(
        1 <= body[7 + 3 * i] >> 4 <= 4 and 1 <= body[7 + 3 * i] & 15 <= 4 and body[8 + 3 * i] <= 3 for i in range(count)
    )


def _jpeg_jfif(body: bytes) -> bool:
    """The plain header: version 1.0 to 1.2, a density, and no thumbnail."""
    density = int.from_bytes(body[8:10], "big") and int.from_bytes(body[10:12], "big")
    return (
        len(body) == 14
        and body[:6] == b"JFIF\x00\x01"
        and body[6] <= 2
        and body[7] <= 2
        and bool(density)
        and body[12:] == b"\x00\x00"
    )


def _jpeg_segment(marker: int, body: bytes) -> bool:
    if marker == _JPEG_DQT:
        return _jpeg_quantization(body)
    if marker == _JPEG_DHT:
        return _jpeg_huffman(body)
    if marker == _JPEG_DRI:
        return len(body) == 2
    if marker == _JPEG_SCAN:
        return _jpeg_scan_header(body)
    if marker == _JPEG_JFIF:
        return _jpeg_jfif(body)
    if marker == _JPEG_ADOBE:
        return len(body) == 12 and body[:5] == b"Adobe" and body[11] <= 2
    if marker == _JPEG_COMMENT:
        return len(body) <= MAX_COMMENT and _plain_text(body, b"\t\n\r")
    return _jpeg_frame_header(body)


def _jpeg(data: bytes) -> ImageInfo:
    """Walk SOI, segments, scans (entropy-coded data skipped by its markers) up to the end marker, which must be the
    last two bytes. One frame header only; every marker must be on the allow-list and every body its exact shape."""
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
        if marker not in _JPEG_KNOWN:
            raise _no("the image has a segment this program does not accept")
        size = int.from_bytes(data[pos + 2 : pos + 4], "big")
        end = pos + 2 + size
        if pos + 4 > total or size < 2 or end > total:
            raise _no("the image is not a well formed JPEG")
        body = data[pos + 4 : end]
        if not _jpeg_segment(marker, body) or _embeds_image(body):
            raise _shape()
        if marker in _JPEG_SOF:
            if frame is not None:
                raise _no("the image has a second frame header")
            frame = (int.from_bytes(body[3:5], "big"), int.from_bytes(body[1:3], "big"))
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
        if len(chunks) >= 4 or pos + 8 > total:
            raise _no("the image is not a well formed WebP")
        size = int.from_bytes(data[pos + 4 : pos + 8], "little")
        end = pos + 8 + size
        pad = size & 1
        if end + pad > total or (pad and data[end] != 0):
            raise _no("the image is not a well formed WebP")
        chunks.append((data[pos : pos + 4], data[pos + 8 : end]))
        pos = end + pad
    first, head = chunks[0]
    if first == b"VP8X":  # the extended header and the one image, nothing else
        if len(chunks) != 2 or len(head) != 10 or head[0] & ~0x10 or head[1:4] != b"\x00\x00\x00":
            raise _no("the image has a header or a chunk this program does not accept")
        kind, image = chunks[1]
    else:
        if len(chunks) != 1:
            raise _no("the image is not a plain WebP")
        kind, image = first, head
    width, height = _webp_image(kind, image)
    if first == b"VP8X":
        canvas = (1 + int.from_bytes(head[4:7], "little"), 1 + int.from_bytes(head[7:10], "little"))
        if canvas != (width, height):
            raise _no("the image canvas does not match the image")
    return _check_dims("image/webp", width, height)


def _webp_image(kind: bytes, body: bytes) -> tuple[int, int]:
    if kind == b"VP8L" and len(body) >= 5 and body[0] == 0x2F:
        bits = int.from_bytes(body[1:5], "little")
        if bits >> 29:  # the version field must be zero
            raise _no("the image is not a well formed WebP")
        return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    if kind == b"VP8 " and len(body) >= 10 and body[3:6] == b"\x9d\x01\x2a":
        tag = int.from_bytes(body[0:3], "little")  # key frame bit, version, shown bit, size of the first partition
        if tag & 1 or (tag >> 1) & 7 > 3 or tag >> 5 > len(body) - 10:
            raise _no("the image is not a well formed WebP")
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
