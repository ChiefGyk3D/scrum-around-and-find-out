# SPDX-License-Identifier: Apache-2.0
"""Every segment and chunk of an image must be a known type with a body of exactly the shape that type has, and nothing
the walk skips by its length may carry another image. An allow-list per format, not a list of things to look for."""

from __future__ import annotations

import struct
import zlib

import pytest

from fakevendor import (
    IEND,
    JPEG_APP0,
    SOS,
    chunk,
    idat,
    ihdr,
    jpeg_of,
    jseg,
    png_of,
    riff,
    sof,
    vp8l_payload,
    vp8x,
    wchunk,
)
from safo.broker.images import ImageRefused, sniff

HIDDEN = b"\xff\xd8\xff\xd9"
QUANT = b"\x00" + b"\x01" * 64
HUFF = b"\x00" + bytes([2] + [0] * 15) + b"ab"
TIME = (2026).to_bytes(2, "big") + bytes([10, 31, 12, 0, 0])


def refuses(data: bytes) -> None:
    with pytest.raises(ImageRefused):
        sniff(data)


def jpeg_with(*segments: bytes) -> bytes:
    return jpeg_of(JPEG_APP0, *segments, sof(3, 2), SOS)


# -- JPEG tables and headers ---------------------------------------------------------------------------------------


def test_exact_tables_a_restart_interval_and_the_two_plain_metadata_segments_pass() -> None:
    adobe = jseg(0xEE, b"Adobe\x00\x64\x00\x00\x00\x00\x00")
    data = jpeg_with(jseg(0xDB, QUANT), jseg(0xDB, b"\x11" + b"\x02" * 128), jseg(0xC4, HUFF), jseg(0xDD, b"\x00\x08"))
    assert sniff(data).width == 3
    assert sniff(jpeg_with(adobe, jseg(0xFE, b"made by a test\n"))).width == 3


@pytest.mark.parametrize(
    "body",
    [
        b"",
        QUANT[:-1],  # a short table
        QUANT + b"\x00",  # a table and one stray byte
        b"\x10" + b"\x01" * 64,  # sixteen-bit entries need 128 bytes
        b"\x04" + b"\x01" * 64,  # table number 4 does not exist
        b"\x20" + b"\x01" * 64,  # precision 2 does not exist
        QUANT + QUANT[:30],
        b"\x00" + b"\x01" * 20 + HIDDEN + b"\x01" * 40,  # a second image in the table values
    ],
)
def test_a_quantization_table_that_is_not_exactly_whole_or_carries_an_image_is_refused(body: bytes) -> None:
    refuses(jpeg_with(jseg(0xDB, body)))


@pytest.mark.parametrize(
    "body",
    [
        b"",
        HUFF[:-1],  # fewer symbols than the counts say
        HUFF + b"c",  # one more
        b"\x40" + HUFF[1:],  # class 4 does not exist
        b"\x04" + HUFF[1:],  # table number 4 does not exist
        b"\x00" + bytes([255] * 16) + b"x" * 4080,  # more than 256 symbols
        b"\x00" + bytes([4] + [0] * 15) + HIDDEN,  # a second image as the symbols
        b"\x00" + bytes([1] * 8),  # counts cut short
    ],
)
def test_a_huffman_table_that_is_not_exactly_whole_or_carries_an_image_is_refused(body: bytes) -> None:
    refuses(jpeg_with(jseg(0xC4, body)))


@pytest.mark.parametrize("body", [b"", b"\x00", b"\x00\x08\x00", b"\x00\x08\xff\xd8"])
def test_a_restart_interval_is_exactly_two_bytes(body: bytes) -> None:
    refuses(jpeg_with(jseg(0xDD, body)))


@pytest.mark.parametrize(
    "header",
    [
        b"",
        b"\x00\x00\x3f\x00",  # no components
        b"\x05" + b"\x01\x00" * 5 + b"\x00\x3f\x00",  # five components
        b"\x01\x01\x00\x00\x3f\x00\x00",  # a stray byte after the header
        b"\x01\x01\x00\x00\x3f",  # one byte short
        b"\x01\x01\x44\x00\x3f\x00",  # table numbers 4
        b"\x01\x01\x00\x20\x10\x00",  # spectral start above the end
        b"\x01\x01\x00\x00\x40\x00",  # spectral end above 63
        b"\x02\x01\x00\x02\x00\x3f\x00",  # two components declared, bytes for one and a half
    ],
)
def test_a_scan_header_is_exactly_the_shape_its_component_count_says(header: bytes) -> None:
    refuses(jpeg_of(JPEG_APP0, sof(3, 2), jseg(0xDA, header)))


@pytest.mark.parametrize(
    "spec",
    [b"\x01\x00\x00", b"\x01\x55\x00", b"\x01\x11\x09", b"\x01\x05\x00", b"\x01\x50\x00"],
)
def test_a_frame_component_with_an_impossible_sampling_or_table_is_refused(spec: bytes) -> None:
    refuses(jpeg_of(JPEG_APP0, jseg(0xC0, struct.pack(">BHHB", 8, 2, 3, 1) + spec), SOS))


@pytest.mark.parametrize(
    "app0",
    [
        b"JFIF\x00",  # no header fields
        b"JFXX\x00\x10" + HIDDEN,  # the thumbnail extension
        b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x01\x01\xff\xff\xff",  # a thumbnail of one pixel
        b"JFIF\x00\x01\x01\x03\x00\x01\x00\x01\x00\x00",  # unit 3
        b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\x00",  # a trailing byte
        b"Exif\x00\x00",
        b"JFIF\x00\x02\x01\x00\x00\x01\x00\x01\x00\x00",  # a version that does not exist
    ],
)
def test_the_jfif_segment_is_exactly_the_plain_header(app0: bytes) -> None:
    refuses(jpeg_of(jseg(0xE0, app0), sof(), SOS))


@pytest.mark.parametrize(
    "adobe",
    [
        b"Adobe\x00\x64\x00\x00\x00\x00",
        b"Adobe\x00\x64\x00\x00\x00\x00\x00\x00",
        b"Adoby\x00\x64\x00\x00\x00\x00\x00",
        b"Adobe\x00\x64\x00\x00\x00\x00\x09",
    ],
)
def test_the_adobe_segment_is_exactly_twelve_bytes_with_a_known_transform(adobe: bytes) -> None:
    refuses(jpeg_with(jseg(0xEE, adobe)))


@pytest.mark.parametrize("comment", [b"\x80binary", b"\xff\xd9", b"a\x00b", b"x" * 5000, "café".encode()])
def test_a_comment_is_short_plain_text(comment: bytes) -> None:
    refuses(jpeg_with(jseg(0xFE, comment)))


# -- PNG chunks ----------------------------------------------------------------------------------------------------


def png_with(*chunks: bytes, color: int = 0, depth: int = 8) -> bytes:
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]
    return png_of(ihdr(2, 2, color=color, depth=depth), *chunks, idat(2, 2, channels=channels, depth=depth), IEND)


def png_after(*chunks: bytes) -> bytes:
    return png_of(ihdr(2, 2), idat(2, 2), *chunks, IEND)


GOOD_BEFORE = {
    b"gAMA": b"\x00\x01\x86\xa0",
    b"cHRM": b"\x00" * 32,
    b"sRGB": b"\x00",
    b"pHYs": b"\x00\x00\x0b\x13\x00\x00\x0b\x13\x01",
    b"sBIT": b"\x08",
    b"cICP": b"\x01\x0d\x00\x01",
}


@pytest.mark.parametrize("kind", sorted(GOOD_BEFORE))
def test_each_listed_chunk_passes_with_a_body_of_exactly_its_shape(kind: bytes) -> None:
    assert sniff(png_with(chunk(kind, GOOD_BEFORE[kind]))).width == 2


@pytest.mark.parametrize(
    ("kind", "body"),
    [
        (b"gAMA", b"\x00" * 3),
        (b"gAMA", b"\x00" * 5),
        (b"cHRM", b"\x00" * 31),
        (b"cHRM", b"\x00" * 33),
        (b"sRGB", b""),
        (b"sRGB", b"\x04"),
        (b"sRGB", b"\x00\x00"),
        (b"pHYs", b"\x00" * 8),
        (b"pHYs", b"\x00" * 8 + b"\x02"),
        (b"cICP", b"\x00" * 3),
        (b"sBIT", b""),
        (b"sBIT", b"\x00"),  # zero significant bits
        (b"sBIT", b"\x09"),  # more than the depth
        (b"sBIT", b"\x08\x08"),  # two values for a grey image
        (b"tIME", TIME[:-1]),
        (b"tIME", TIME + b"\x00"),
        (b"tIME", (2026).to_bytes(2, "big") + bytes([13, 1, 0, 0, 0])),  # month 13
        (b"tIME", (2026).to_bytes(2, "big") + bytes([0, 1, 0, 0, 0])),  # month 0
        (b"tIME", (2026).to_bytes(2, "big") + bytes([1, 32, 0, 0, 0])),  # day 32
        (b"tIME", (2026).to_bytes(2, "big") + bytes([1, 1, 24, 0, 0])),  # hour 24
        (b"tIME", (2026).to_bytes(2, "big") + bytes([1, 1, 0, 60, 0])),  # minute 60
        (b"tIME", (2026).to_bytes(2, "big") + bytes([1, 1, 0, 0, 61])),  # second 61
    ],
)
def test_a_chunk_whose_body_is_not_the_shape_of_its_type_is_refused(kind: bytes, body: bytes) -> None:
    refuses(png_with(chunk(kind, body)))


def test_the_time_chunk_may_come_after_the_image_data_and_the_others_may_not() -> None:
    assert sniff(png_after(chunk(b"tIME", TIME))).width == 2
    assert sniff(png_after(chunk(b"tEXt", b"k\x00v"))).width == 2
    for kind in sorted(GOOD_BEFORE):
        refuses(png_after(chunk(kind, GOOD_BEFORE[kind])))


def test_a_chunk_that_may_appear_once_appears_once() -> None:
    for kind in sorted(GOOD_BEFORE):
        refuses(png_with(chunk(kind, GOOD_BEFORE[kind]), chunk(kind, GOOD_BEFORE[kind])))
    refuses(png_with(chunk(b"tIME", TIME), chunk(b"tIME", TIME)))
    assert sniff(png_with(chunk(b"tEXt", b"a\x00b"), chunk(b"tEXt", b"c\x00d"))).width == 2


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"no separator",
        b"\x00value",  # an empty keyword
        b"k\x00v\x00w",  # a second separator
        b"k" * 80 + b"\x00v",  # a keyword of 80
        b"k\x00" + HIDDEN,
        b"k\x00\x80\x81",
        b" k\x00v",
        b"k \x00v",
        b"k\x00" + b"v" * 70_000,
    ],
)
def test_a_text_chunk_is_a_short_plain_keyword_and_text(body: bytes) -> None:
    refuses(png_with(chunk(b"tEXt", body)))


def palette(n: int) -> bytes:
    return chunk(b"PLTE", b"\x01\x02\x03" * n)


def test_a_palette_is_whole_triples_at_most_two_hundred_fifty_six_and_only_for_a_colour_type_that_has_one() -> None:
    assert sniff(png_with(palette(4), color=3, depth=2)).width == 2
    assert sniff(png_with(palette(256), color=3, depth=8)).width == 2
    assert sniff(png_with(palette(2), color=2)).width == 2  # an optional palette on a colour image
    refuses(png_with(color=3, depth=8))  # indexed colour needs one
    refuses(png_with(palette(1), color=0))
    refuses(png_with(palette(1), color=4))
    refuses(png_with(chunk(b"PLTE", b""), color=3))
    refuses(png_with(chunk(b"PLTE", b"\x01\x02"), color=3))
    refuses(png_with(chunk(b"PLTE", b"\x01\x02\x03\x04"), color=3))
    refuses(png_with(chunk(b"PLTE", b"\x01\x02\x03" * 257), color=3))
    refuses(png_with(palette(5), color=3, depth=2))  # more colours than the depth has indexes
    refuses(png_with(palette(1), palette(1), color=3))
    refuses(png_with(chunk(b"PLTE", HIDDEN + b"\x01\x02"), color=3))
    refuses(png_of(ihdr(2, 2, color=3), idat(2, 2), palette(1), IEND))  # after the image data


def test_transparency_and_background_follow_the_colour_type() -> None:
    assert sniff(png_with(chunk(b"tRNS", b"\x00\x01"), color=0)).width == 2
    assert sniff(png_with(chunk(b"tRNS", b"\x00" * 6), color=2)).width == 2
    assert sniff(png_with(palette(4), chunk(b"tRNS", b"\xff\x80"), color=3, depth=2)).width == 2
    assert sniff(png_with(chunk(b"bKGD", b"\x00\x01"), color=0)).width == 2
    assert sniff(png_with(chunk(b"bKGD", b"\x00" * 6), color=2)).width == 2
    assert sniff(png_with(palette(4), chunk(b"bKGD", b"\x01"), color=3, depth=2)).width == 2
    refuses(png_with(chunk(b"tRNS", b"\x00"), color=0))
    refuses(png_with(chunk(b"tRNS", b"\x00" * 6), color=0))
    refuses(png_with(chunk(b"tRNS", b"\x00\x01"), color=4))  # a colour type that has alpha already
    refuses(png_with(chunk(b"tRNS", b"\x00"), color=6))
    refuses(png_with(palette(2), chunk(b"tRNS", b"\x00" * 3), color=3, depth=2))  # more entries than colours
    refuses(png_with(chunk(b"tRNS", b"\x00"), color=3, depth=8))  # transparency before the palette
    refuses(png_with(chunk(b"bKGD", b"\x00"), color=0))
    refuses(png_with(chunk(b"bKGD", b"\x00\x01"), color=2))
    refuses(png_with(palette(2), chunk(b"bKGD", b"\x05"), color=3, depth=2))  # an index past the palette


def test_the_obsolete_histogram_and_the_other_chunks_are_not_listed() -> None:
    for kind in (b"hIST", b"sPLT", b"oFFs", b"pCAL", b"sCAL", b"gIFg", b"eXIf", b"iCCP"):
        refuses(png_with(chunk(kind, b"\x00\x00")))


# -- WebP chunks ---------------------------------------------------------------------------------------------------


def lossless(width: int = 1, height: int = 1) -> bytes:
    return wchunk(b"VP8L", vp8l_payload(width, height))


LOSSY = b"\x90\x00\x00\x9d\x01\x2a" + (1).to_bytes(2, "little") + (1).to_bytes(2, "little") + b"\x00" * 6


def test_the_plain_forms_of_a_webp_pass() -> None:
    assert sniff(riff(lossless())).width == 1
    assert sniff(riff(wchunk(b"VP8 ", LOSSY))).width == 1
    assert sniff(riff(vp8x(1, 1), lossless())).width == 1
    assert sniff(riff(vp8x(1, 1, flags=0x10), lossless())).width == 1  # the alpha flag on a lossless image


@pytest.mark.parametrize("kind", [b"ALPH", b"ICCP", b"EXIF", b"XMP ", b"ANIM", b"ANMF", b"JUNK"])
def test_no_extra_chunk_is_passed_on(kind: bytes) -> None:
    refuses(riff(vp8x(1, 1), wchunk(kind, b"\x00\x01\x02\x03"), lossless()))
    refuses(riff(vp8x(1, 1), wchunk(kind, HIDDEN), lossless()))


@pytest.mark.parametrize("flags", [0x01, 0x02, 0x04, 0x08, 0x20, 0x40, 0x80])
def test_the_extended_header_sets_no_flag_for_a_feature_that_was_refused(flags: int) -> None:
    refuses(riff(vp8x(1, 1, flags=flags), lossless()))


def test_the_reserved_bytes_of_the_extended_header_are_zero() -> None:
    body = bytearray(10)
    body[1] = 1
    refuses(riff(wchunk(b"VP8X", bytes(body)), lossless()))


@pytest.mark.parametrize(
    "frame",
    [
        b"\x91\x00\x00\x9d\x01\x2a" + b"\x01\x00\x01\x00" + b"\x00" * 6,  # an inter frame, not a key frame
        b"\x90\x00\x00\x9d\x01\x2a" + b"\x01\x00\x01\x00",  # no data at all after the header
        b"\xff\xff\xff\x9d\x01\x2a" + b"\x01\x00\x01\x00" + b"\x00" * 6,  # a first partition longer than the chunk
        b"\x98\x00\x00\x9d\x01\x2a" + b"\x01\x00\x01\x00" + b"\x00" * 6,  # a version that does not exist
    ],
)
def test_a_lossy_frame_header_must_be_a_key_frame_with_a_partition_that_fits(frame: bytes) -> None:
    refuses(riff(wchunk(b"VP8 ", frame)))


# -- PNG filter bytes ----------------------------------------------------------------------------------------------


def rows_png(width: int, height: int, bad_row: int | None = None, bad_value: int = 5) -> bytes:
    row = b"\x00" * (1 + width)
    raw = bytearray(row * height)
    if bad_row is not None:
        raw[bad_row * (1 + width)] = bad_value
    return png_of(ihdr(width, height), chunk(b"IDAT", zlib.compress(bytes(raw), 1)), IEND)


def test_every_row_starts_with_a_filter_byte_that_exists() -> None:
    assert sniff(rows_png(3, 3)).width == 3
    for value in (5, 6, 17, 255):
        refuses(rows_png(1, 1, 0, value))
        refuses(rows_png(3, 3, 2, value))


def test_a_bad_filter_byte_is_found_in_a_row_that_straddles_the_inflation_steps() -> None:
    assert sniff(rows_png(5000, 100)).width == 5000
    for row in (0, 12, 13, 57, 99):  # 64 KiB steps do not line up with 5001-byte rows
        refuses(rows_png(5000, 100, row))


def test_all_five_filter_types_pass() -> None:
    for value in range(5):
        assert sniff(rows_png(2, 2, 1, value)).width == 2


# -- things that only a second look catches ------------------------------------------------------------------------


def test_a_frame_header_of_a_kind_that_is_not_accepted_is_refused_even_after_a_good_one() -> None:
    refuses(jpeg_of(JPEG_APP0, sof(3, 2), sof(3, 2, marker=0xC3), SOS))
    refuses(jpeg_of(JPEG_APP0, sof(3, 2), sof(3, 2, marker=0xCA), SOS))
    refuses(jpeg_of(JPEG_APP0, sof(3, 2), sof(3, 2, marker=0xC9), SOS))


def test_an_unknown_segment_is_refused_even_when_its_body_looks_like_a_frame_header() -> None:
    body = sof(3, 2)[4:]
    for marker in (0xF0, 0xDC, 0xC8, 0xCC, 0xE1, 0xE2):
        refuses(jpeg_of(JPEG_APP0, sof(3, 2), jseg(marker, body), SOS))


def test_a_jfif_header_of_the_right_length_with_a_thumbnail_size_is_refused() -> None:
    plain = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01"
    assert sniff(jpeg_of(jseg(0xE0, plain + b"\x00\x00"), sof(), SOS)).width == 1
    refuses(jpeg_of(jseg(0xE0, plain + b"\x01\x00"), sof(), SOS))
    refuses(jpeg_of(jseg(0xE0, plain + b"\x00\x01"), sof(), SOS))


def test_junk_after_the_end_of_the_deflate_stream_in_a_later_data_chunk_is_refused() -> None:
    refuses(png_of(ihdr(), idat(), chunk(b"IDAT", b"junk"), IEND))
    refuses(png_of(ihdr(), idat(), chunk(b"IDAT", zlib.compress(b"\x00\x00")), IEND))


def test_image_data_split_by_another_chunk_is_refused_even_when_the_stream_is_whole() -> None:
    whole = zlib.compress(b"\x00\x00")
    first, second = chunk(b"IDAT", whole[:4]), chunk(b"IDAT", whole[4:])
    assert sniff(png_of(ihdr(), first, second, IEND)).width == 1
    refuses(png_of(ihdr(), first, chunk(b"tEXt", b"k\x00v"), second, IEND))


def test_the_check_on_the_image_data_stops_inflating_at_the_declared_size(monkeypatch: pytest.MonkeyPatch) -> None:
    """A bomb is not inflated to the end and then found too big: the work stops within a step of the declared size."""
    made: list[Counting] = []
    real = zlib.decompressobj

    class Counting:
        def __init__(self) -> None:
            self.inner = real()
            self.produced = 0
            made.append(self)

        def decompress(self, data: bytes, max_length: int = 0) -> bytes:
            out = self.inner.decompress(data, max_length)
            self.produced += len(out)
            return out

        @property
        def eof(self) -> bool:
            return self.inner.eof

        @property
        def unconsumed_tail(self) -> bytes:
            return self.inner.unconsumed_tail

        @property
        def unused_data(self) -> bytes:
            return self.inner.unused_data

    monkeypatch.setattr("safo.broker.images.zlib.decompressobj", Counting)
    bomb = chunk(b"IDAT", zlib.compress(b"\x00" * 40_000_000, 9))
    refuses(png_of(ihdr(), bomb, IEND))
    assert len(made) == 1 and made[0].produced <= 2 + 65536


def test_a_padding_byte_after_an_odd_webp_chunk_is_zero() -> None:
    payload = vp8l_payload(1, 1)
    assert len(payload) == 5
    body = b"WEBP" + b"VP8L" + struct.pack("<I", 5) + payload
    assert sniff(b"RIFF" + struct.pack("<I", len(body) + 1) + body + b"\x00").width == 1
    refuses(b"RIFF" + struct.pack("<I", len(body) + 1) + body + b"\x01")
