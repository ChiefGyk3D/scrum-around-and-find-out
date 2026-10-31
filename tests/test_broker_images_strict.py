# SPDX-License-Identifier: Apache-2.0
"""Polyglots and look-alikes: each format is walked to its real end, and what a viewer would draw is what was checked.

A valid file passes; a file with data appended, a second frame or image, a hidden segment, a wrong checksum or a length
that lies is refused. The shapes come from an automated review of the first image check (which only looked at the last
two bytes of a JPEG and read the first frame header)."""

from __future__ import annotations

import struct
import zlib

import pytest

from fakevendor import (
    IDAT,
    IEND,
    JPEG_APP0,
    SOS,
    chunk,
    idat,
    ihdr,
    jpeg,
    jpeg_of,
    jseg,
    png,
    png_of,
    riff,
    sof,
    vp8l_payload,
    vp8x,
    wchunk,
    webp,
)
from safo.broker.images import ImageRefused, sniff

EOI = b"\xff\xd9"


def refuses(data: bytes) -> None:
    with pytest.raises(ImageRefused):
        sniff(data)


# -- JPEG ----------------------------------------------------------------------------------------------------------


def test_a_plain_jpeg_passes_with_the_size_of_its_frame_header() -> None:
    info = sniff(jpeg(300, 200))
    assert (info.width, info.height) == (300, 200)


def test_stuffed_bytes_restart_markers_and_several_scans_are_part_of_a_valid_jpeg() -> None:
    scan = b"\x12\xff\x00\x34" + b"\xff\xd0" + b"\x56\xff\x00" + b"\xff\xd7" + b"\x78"
    assert sniff(jpeg_of(JPEG_APP0, sof(7, 9), SOS, scan=scan)).width == 7
    progressive = jpeg_of(JPEG_APP0, jseg(0xDB, b"\x00" + b"\x01" * 64), sof(5, 6, 0xC2), SOS, scan=b"\x01\x02")
    two_scans = progressive[:-2] + jseg(0xC4, b"\x00" + b"\x00" * 16) + SOS + b"\x03" + EOI
    assert (sniff(two_scans).width, sniff(two_scans).height) == (5, 6)


def test_a_thumbnail_inside_a_segment_does_not_end_the_image_and_is_not_read_as_the_frame() -> None:
    thumb = b"\xff\xd8" + sof(4000, 4000) + b"\xff\xd9"  # a whole small JPEG inside an APP1 payload, EOI and all
    data = jpeg_of(jseg(0xE1, b"Exif\x00\x00" + thumb), sof(3, 2), SOS)
    info = sniff(data)
    assert (info.width, info.height) == (3, 2)


def test_data_hidden_after_a_real_end_marker_is_refused_even_when_the_file_still_ends_in_an_end_marker() -> None:
    thumb = b"\xff\xd8" + b"\xff\xd9"
    payload = b"PK\x03\x04 a zip lives here " + EOI
    refuses(jpeg_of(jseg(0xE1, thumb), sof(), SOS) + payload)
    refuses(jpeg() + payload)
    refuses(jpeg() + jpeg())  # two whole images back to back
    refuses(jpeg() + b"\x00")
    refuses(jpeg() + EOI)


def test_a_second_frame_header_with_other_dimensions_is_refused() -> None:
    refuses(jpeg_of(sof(10, 10), sof(8000, 4000), SOS))
    refuses(jpeg_of(sof(1, 1), sof(1, 1), SOS))


def test_a_second_image_started_inside_the_entropy_data_is_refused() -> None:
    refuses(jpeg_of(sof(), SOS, scan=b"\x01\xff\xd8" + sof(9, 9) + SOS + b"\x02"))


def test_a_truncated_entropy_stream_is_refused() -> None:
    refuses(jpeg_of(sof(), SOS, scan=b"\x01\x02\x03", end=b""))
    refuses(jpeg_of(sof(), SOS, scan=b"\x01\x02\xff", end=b""))
    refuses(jpeg_of(sof(), SOS, scan=b"\x01\x02", end=b"\xff"))


def test_a_marker_segment_after_the_scan_whose_length_overruns_is_refused() -> None:
    overrun = b"\xff\xdb\xff\xf0" + b"\x00" * 4 + EOI
    refuses(jpeg_of(sof(), SOS, scan=b"\x01" + overrun, end=b""))
    refuses(jpeg_of(sof(), SOS, scan=b"\x01\xff\xc4\x00\x01", end=EOI))


def test_a_segment_length_that_overruns_or_is_too_short_is_refused() -> None:
    refuses(b"\xff\xd8\xff\xe1\xff\xff" + b"A" * 50 + EOI)
    refuses(b"\xff\xd8\xff\xe1\x00\x01" + sof() + SOS + b"\x00" + EOI)
    refuses(b"\xff\xd8" + sof()[:-3] + SOS + b"\x00" + EOI)


def test_unknown_or_unsupported_marker_segments_are_refused() -> None:
    for marker in (0xF0, 0xDC, 0xCC, 0xDF, 0x01, 0xD8, 0xD0, 0xD9, 0x02, 0xFD, 0xC8):
        refuses(jpeg_of(jseg(marker, b"hidden"), sof(), SOS))
    for lossless_or_arithmetic in (0xC3, 0xC5, 0xC9, 0xCA, 0xCB, 0xCF):
        refuses(jpeg_of(sof(marker=lossless_or_arithmetic), SOS))


def test_a_file_with_no_scan_or_no_frame_is_refused() -> None:
    refuses(b"\xff\xd8" + sof() + EOI)
    refuses(b"\xff\xd8" + SOS + b"\x00" + EOI)
    refuses(b"\xff\xd8" + EOI)
    refuses(b"\xff\xd8\xff")


def test_fill_bytes_before_a_marker_are_not_accepted() -> None:
    refuses(b"\xff\xd8\xff" + JPEG_APP0 + sof() + SOS + b"\x00" + EOI)


# -- PNG -----------------------------------------------------------------------------------------------------------


def test_a_plain_png_and_one_with_ancillary_chunks_pass() -> None:
    assert sniff(png(11, 12)).height == 12
    with_text = png_of(ihdr(2, 3), chunk(b"tEXt", b"k\x00v"), idat(2, 3), chunk(b"tIME", b"\x00" * 7), IEND)
    assert (sniff(with_text).width, sniff(with_text).height) == (2, 3)


def test_a_wrong_checksum_anywhere_is_refused() -> None:
    refuses(png_of(chunk(b"IHDR", ihdr(1, 1)[8:-4], crc=1), IDAT, IEND))
    refuses(png_of(ihdr(), chunk(b"IDAT", b"x", crc=0), IEND))
    refuses(png_of(ihdr(), IDAT, chunk(b"tEXt", b"a", crc=5), IEND))
    refuses(png_of(ihdr(), IDAT, chunk(b"IEND", b"", crc=0)))


def test_a_second_header_with_other_dimensions_is_refused() -> None:
    refuses(png_of(ihdr(1, 1), ihdr(8000, 4000), IDAT, IEND))
    refuses(png_of(ihdr(1, 1), IDAT, ihdr(8000, 4000), IEND))


def test_the_header_must_come_first_be_thirteen_bytes_and_use_the_only_defined_methods() -> None:
    refuses(png_of(IDAT, ihdr(), IEND))
    refuses(png_of(chunk(b"IHDR", b"\x00" * 12), IDAT, IEND))
    refuses(png_of(ihdr(comp=1), IDAT, IEND))
    refuses(png_of(ihdr(filt=1), IDAT, IEND))
    refuses(png_of(ihdr(inter=2), IDAT, IEND))
    refuses(png_of(ihdr(color=1), IDAT, IEND))
    refuses(png_of(ihdr(depth=3), IDAT, IEND))


def test_an_animation_or_an_unknown_critical_chunk_is_refused() -> None:
    refuses(png_of(ihdr(), chunk(b"acTL", b"\x00" * 8), IDAT, IEND))
    refuses(png_of(ihdr(), IDAT, chunk(b"fcTL", b"\x00" * 26), chunk(b"fdAT", b"\x00" * 8), IEND))
    refuses(png_of(ihdr(), chunk(b"ABCD", b"hidden"), IDAT, IEND))
    refuses(png_of(ihdr(), IDAT, chunk(b"IHDR", b"\x00" * 13), IEND))


def test_image_data_must_be_present_and_in_one_run() -> None:
    refuses(png_of(ihdr(), IEND))
    refuses(png_of(ihdr(), IDAT, chunk(b"tEXt", b"a"), IDAT, IEND))
    assert sniff(png_of(ihdr(), idat(1, 1, split=3), IEND)).width == 1


def test_a_chunk_name_must_be_letters_and_a_length_must_fit() -> None:
    refuses(png_of(ihdr(), chunk(b"t\x00XT", b"a"), IDAT, IEND))
    refuses(png_of(ihdr(), IDAT, b"\xff\xff\xff\xffIDAT" + b"\x00" * 8, IEND))
    refuses(png_of(ihdr(), IDAT, b"\x00\x00\x00\x40tEXt" + b"\x00" * 8, IEND))


def test_a_png_with_anything_after_the_end_chunk_or_a_second_png_is_refused() -> None:
    refuses(png() + b"\x00")
    refuses(png() + png())
    refuses(png_of(ihdr(), IDAT, IEND, IEND))
    refuses(png_of(ihdr(), IDAT, chunk(b"IEND", b"x")))


# -- WebP ----------------------------------------------------------------------------------------------------------


def lossless(width: int = 1, height: int = 1) -> bytes:
    return wchunk(b"VP8L", vp8l_payload(width, height))


def test_plain_and_extended_webp_pass_with_their_metadata_chunks() -> None:
    assert (sniff(riff(lossless(20, 30))).width, sniff(riff(lossless(20, 30))).height) == (20, 30)
    full = riff(vp8x(4, 5), wchunk(b"ICCP", b"icc"), lossless(4, 5), wchunk(b"EXIF", b"e"), wchunk(b"XMP ", b"xy"))
    assert (sniff(full).width, sniff(full).height) == (4, 5)
    assert sniff(webp(64, 32)).mime == "image/webp"


def test_the_canvas_and_the_image_must_agree() -> None:
    refuses(riff(vp8x(1, 1), lossless(8192, 4096)))
    refuses(riff(vp8x(8000, 4000), lossless(1, 1)))


def test_an_animation_is_refused() -> None:
    refuses(riff(vp8x(1, 1, flags=0x02), lossless()))
    refuses(riff(vp8x(1, 1), wchunk(b"ANIM", b"\x00" * 6), wchunk(b"ANMF", b"\x00" * 16)))


def test_two_images_or_none_are_refused() -> None:
    refuses(riff(vp8x(1, 1), lossless(), lossless()))
    refuses(riff(vp8x(1, 1), wchunk(b"EXIF", b"e")))
    refuses(riff(lossless(), lossless()))


def test_an_unknown_chunk_a_missing_pad_or_a_length_that_overruns_is_refused() -> None:
    refuses(riff(vp8x(1, 1), lossless(), wchunk(b"JUNK", b"zip data")))
    refuses(riff(lossless(), wchunk(b"JUNK", b"zip data")))
    odd_without_pad = b"EXIF" + (3).to_bytes(4, "little") + b"abc"
    refuses(riff(vp8x(1, 1), lossless(), odd_without_pad))
    refuses(riff(vp8x(1, 1), lossless(), b"EXIF" + (900).to_bytes(4, "little") + b"abc"))
    refuses(riff(vp8x(1, 1), lossless(), b"EXIF" + (3).to_bytes(4, "little") + b"abc" + b"\x01"))


def test_a_webp_with_data_after_the_riff_end_or_a_lying_riff_length_is_refused() -> None:
    refuses(webp() + b"zip")
    refuses(webp() + webp())
    data = bytearray(webp())
    data[4:8] = (len(data) - 10).to_bytes(4, "little")
    refuses(bytes(data))


def test_the_lossy_header_is_read_and_its_start_code_is_checked() -> None:
    frame = b"\x00\x00\x00\x9d\x01\x2a" + (64).to_bytes(2, "little") + (32).to_bytes(2, "little") + b"\x00" * 4
    ok = riff(wchunk(b"VP8 ", frame))
    assert (sniff(ok).width, sniff(ok).height) == (64, 32)
    refuses(riff(wchunk(b"VP8 ", frame.replace(b"\x9d\x01\x2a", b"\x00\x00\x00"))))


def test_a_frame_header_whose_length_does_not_match_its_component_count_is_refused() -> None:
    body = struct.pack(">BHHB", 8, 1, 1, 1) + b"\x01\x11\x00"
    refuses(jpeg_of(jseg(0xC0, body + b"extra"), SOS))  # longer than one component needs
    refuses(jpeg_of(jseg(0xC0, body[:-3] + b"\x00" * 6 + b""), SOS))  # says one component, carries two
    refuses(jpeg_of(jseg(0xC0, struct.pack(">BHHB", 8, 1, 1, 0)), SOS))  # no components
    refuses(jpeg_of(jseg(0xC0, struct.pack(">BHHB", 12, 1, 1, 1) + b"\x01\x11\x00"), SOS))  # precision 12


def test_a_lossless_header_with_a_nonzero_version_is_refused() -> None:
    versioned = b"\x2f" + (1 << 29).to_bytes(4, "little")
    refuses(riff(wchunk(b"VP8L", versioned)))
    assert sniff(riff(wchunk(b"VP8L", vp8l_payload(2, 2)))).width == 2


@pytest.mark.parametrize("kind", [b"zTXt", b"iTXt", b"iCCP", b"abCD", b"prVt"])
def test_compressed_metadata_and_unknown_ancillary_chunks_are_refused(kind: bytes) -> None:
    """A tiny chunk can expand to a huge buffer in whatever reads the metadata later, so it is never passed on."""
    refuses(png_of(ihdr(), chunk(kind, b"k\x00\x00" + zlib.compress(b"\x00" * 1_000_000)), IDAT, IEND))
    refuses(png_of(ihdr(), IDAT, chunk(kind, b"x"), IEND))


@pytest.mark.parametrize(
    "kind",
    [
        b"tEXt",
        b"tIME",
        b"pHYs",
        b"sRGB",
        b"gAMA",
        b"cHRM",
        b"sBIT",
        b"bKGD",
        b"tRNS",
        b"hIST",
        b"eXIf",
        b"cICP",
        b"caBX",
    ],
)
def test_the_listed_plain_ancillary_chunks_are_accepted(kind: bytes) -> None:
    assert sniff(png_of(ihdr(), chunk(kind, b"abc"), IDAT, IEND)).width == 1


# -- PNG image data must be what the header says --------------------------------------------------------------------


def test_image_data_that_inflates_far_beyond_the_declared_size_is_refused() -> None:
    bomb = chunk(b"IDAT", zlib.compress(b"\x00" * 64_000_000, 9))  # a 1x1 header over sixty-four megabytes of rows
    refuses(png_of(ihdr(1, 1), bomb, IEND))


def test_image_data_with_too_few_rows_or_too_many_is_refused() -> None:
    refuses(png_of(ihdr(4, 4), idat(4, 3), IEND))
    refuses(png_of(ihdr(4, 4), idat(4, 5), IEND))
    refuses(png_of(ihdr(4, 4), idat(5, 4), IEND))
    assert sniff(png_of(ihdr(4, 4), idat(4, 4), IEND)).width == 4


def test_a_truncated_or_padded_deflate_stream_is_refused() -> None:
    whole = zlib.compress(b"\x00\x00")
    refuses(png_of(ihdr(), chunk(b"IDAT", whole[:-3]), IEND))  # cut short: no end of stream
    refuses(png_of(ihdr(), chunk(b"IDAT", whole + b"junk"), IEND))  # data after the end of the stream
    refuses(png_of(ihdr(), chunk(b"IDAT", b"not deflate at all"), IEND))
    refuses(png_of(ihdr(), chunk(b"IDAT", b""), IEND))


def test_the_rows_are_sized_by_colour_type_and_depth_and_may_span_several_chunks() -> None:
    assert sniff(png_of(ihdr(3, 2, depth=16, color=6), idat(3, 2, channels=4, depth=16), IEND)).width == 3
    assert sniff(png_of(ihdr(5, 2, depth=1, color=0), idat(5, 2, channels=1, depth=1), IEND)).width == 5
    assert sniff(png_of(ihdr(3, 2, depth=8, color=2), idat(3, 2, channels=3, depth=8), IEND)).width == 3
    assert sniff(png_of(ihdr(3, 2, depth=8, color=4), idat(3, 2, channels=2, depth=8), IEND)).width == 3
    assert sniff(png_of(ihdr(30, 20), idat(30, 20, split=7), IEND)).height == 20
    refuses(png_of(ihdr(3, 2, depth=16, color=6), idat(3, 2, channels=3, depth=16), IEND))


def test_an_interlaced_png_is_refused() -> None:
    refuses(png_of(ihdr(inter=1), IDAT, IEND))


def test_a_declared_size_over_the_limit_is_refused_before_the_data_is_looked_at() -> None:
    refuses(png_of(ihdr(8193, 1), chunk(b"IDAT", b"x"), IEND))
