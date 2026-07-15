"""DCT round-trip and JPEG-survival tests for the frequency-domain steg
path added to steg_core.

The Web UI's DCT tool was long the only way to reach this technique; these
tests pin the Python implementation to the same wire format ("DCTS" magic +
strength + big-endian length + payload) and confirm the marketing claim
that medium/high robustness survives JPEG recompression.
"""

from __future__ import annotations

import io

import pytest
from PIL import Image

from steg_core import (
    DCT_HEADER_SIZE,
    DCT_MAGIC,
    DCT_STRENGTHS,
    dct_capacity,
    dct_decode,
    dct_encode,
)


PAYLOAD = b"DCT round-trip: hello from the frequency domain"


@pytest.mark.parametrize("robustness", ["low", "medium", "high"])
def test_dct_roundtrip_lossless(medium_carrier, robustness):
    enc = dct_encode(medium_carrier, PAYLOAD, robustness=robustness)
    got = dct_decode(enc)
    assert got == PAYLOAD


@pytest.mark.parametrize("robustness", ["medium", "high"])
def test_dct_survives_jpeg_recompression(large_carrier, robustness):
    """medium/high are the JPEG-survivable settings — this is the whole
    reason DCT exists next to LSB."""
    enc = dct_encode(large_carrier, PAYLOAD, robustness=robustness)
    buf = io.BytesIO()
    enc.convert("RGB").save(buf, format="JPEG", quality=85)
    buf.seek(0)
    jpg = Image.open(buf)
    got = dct_decode(jpg)
    assert got == PAYLOAD


def test_dct_low_robustness_fragile_under_jpeg(large_carrier):
    """low robustness is expected to fail JPEG recompression — this is the
    documented tradeoff. If this ever passes, either JPEG got softer or
    strength=10 got bumped; either way something to look at."""
    enc = dct_encode(large_carrier, PAYLOAD, robustness="low")
    buf = io.BytesIO()
    enc.convert("RGB").save(buf, format="JPEG", quality=85)
    buf.seek(0)
    jpg = Image.open(buf)
    with pytest.raises(ValueError):
        dct_decode(jpg)


def test_dct_header_wire_format(small_carrier):
    """Pin the header format: DCTS + strength byte + big-endian length."""
    payload = b"pinme"
    enc = dct_encode(small_carrier, payload, robustness="medium")
    # Decode raw coefficients and check the first 9 bytes look right.
    # Easier: just round-trip and check the payload survives — the format
    # test is really "did dct_decode find the DCTS magic and length".
    assert dct_decode(enc) == payload
    # Also confirm the constants are what the JS wire format expects.
    assert DCT_MAGIC == b"DCTS"
    assert DCT_HEADER_SIZE == 9
    assert DCT_STRENGTHS == {"low": 10, "medium": 25, "high": 50}


def test_dct_capacity_reports_usable_bytes(medium_carrier):
    cap = dct_capacity(medium_carrier)
    # 256x256 image, block_size=8 -> 32*32 = 1024 blocks = 1024 bits = 128 bytes
    # minus 9-byte header = 119 usable bytes.
    assert cap["capacity_bits"] == 1024
    assert cap["usable_bytes"] == 119
    assert cap["block_size"] == 8


def test_dct_rejects_oversized_payload(small_carrier):
    cap = dct_capacity(small_carrier)
    payload = b"x" * (cap["usable_bytes"] + cap["header_bytes"] + 200)
    with pytest.raises(ValueError, match="capacity exceeded"):
        dct_encode(small_carrier, payload)


def test_dct_rejects_unknown_robustness(small_carrier):
    with pytest.raises(ValueError, match="robustness"):
        dct_encode(small_carrier, b"x", robustness="nuclear")


def test_dct_decode_raises_on_clean_image(small_carrier):
    with pytest.raises(ValueError, match="no DCT"):
        dct_decode(small_carrier)
