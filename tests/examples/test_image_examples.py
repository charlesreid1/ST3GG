"""Image-example decoding: STEG v3 header PNG + tEXt-chunk PNG + trailing-data PNG.

The other image examples (BMP LSB with 32-bit length prefix, GIF palette LSB,
PPM/PGM raw LSB, ICO with 16-bit length prefix, WebP EXIF) each use a
different encoding scheme — see test_examples.py for the format-specific
recipes. Those live in `test_bespoke_image_formats.py`.
"""

from __future__ import annotations

import pytest
from PIL import Image

from analysis_tools import (
    detect_file_type,
    png_detect_appended_data,
    png_extract_text_chunks,
)
from img_core import decode, detect_encoding


# ---------- STEG v3 header PNG ----------

def test_lsb_rgb_png_detects_and_decodes(examples_dir, original_secret):
    img = Image.open(examples_dir / "example_lsb_rgb.png")
    detection = detect_encoding(img)
    assert detection is not None
    assert detection["config"]["channels"] == ["R", "G", "B"]
    assert detection["config"]["bits_per_channel"] == 1

    payload = decode(img)
    assert original_secret.encode("utf-8") == payload


# ---------- PNG tEXt chunks ----------

def test_png_chunks_expose_secret(examples_dir, original_secret):
    data = (examples_dir / "example_png_chunks.png").read_bytes()
    result = png_extract_text_chunks(data)
    all_text = " ".join(
        f"{c.get('keyword', '')} {c.get('text', '')}"
        for c in result.get("chunks", result.get("text_chunks", []))
    )
    assert original_secret in all_text or result.get("found")


# ---------- Trailing data ----------

def test_trailing_data_png_detected(examples_dir):
    data = (examples_dir / "example_trailing_data.png").read_bytes()
    result = png_detect_appended_data(data)
    assert result.get("found") or result.get("has_appended_data")


# ---------- File-type detection sanity across image examples ----------

IMAGE_TYPE_CASES = [
    ("example_lsb_rgb.png", "png"),
    ("example_png_chunks.png", "png"),
    ("example_trailing_data.png", "png"),
    ("example_metadata.png", "png"),
    ("example_polyglot.png.zip", "png"),  # polyglot: PNG magic first, ZIP appended after IEND
    ("example_lsb.bmp", "bmp"),
    ("example_bmp_dib.bmp", "bmp"),
    ("example_comment.gif", "gif"),
    ("example_lsb.gif", "gif"),
    ("example_gif_disposal.gif", "gif"),
    ("example_lsb.tiff", "tiff"),
    ("example_metadata.tiff", "tiff"),
    ("example_metadata.webp", "webp"),
    ("example_lsb.webp", "webp"),
    ("example_lsb.ico", "ico"),
    ("example_jpeg_app.jpg", "jpeg"),
    ("example_jpeg_restart.jpg", "jpeg"),
    ("example_hidden.svg", "svg"),
]


@pytest.mark.parametrize("filename,expected_type", IMAGE_TYPE_CASES,
                         ids=[c[0] for c in IMAGE_TYPE_CASES])
def test_image_example_file_type(examples_dir, filename, expected_type):
    path = examples_dir / filename
    if not path.exists():
        pytest.skip(f"{filename} not present")
    data = path.read_bytes()
    detected = detect_file_type(data)
    assert detected.value == expected_type
