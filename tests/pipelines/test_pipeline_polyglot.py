"""Pipeline #3 — Polyglot PNG+ZIP.

  carrier.png (with LSB payload)
      + <ZIP archive appended after IEND>
      = polyglot bytes

Both decoders (steg_core.decode + zipfile) must see their halves.
"""

from __future__ import annotations

import io
import zipfile

import pytest
from PIL import Image

from steg_core import create_config, decode, encode

pytestmark = pytest.mark.pipeline

LSB_SECRET = b"polyglot: this half lives in the LSBs"
ZIP_FILE_NAME = "trailing.txt"
ZIP_FILE_CONTENT = b"polyglot: this half lives in the appended ZIP"


def _build_zip_bytes(name, content):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(name, content)
    return buf.getvalue()


def test_polyglot_png_zip_both_readable(medium_carrier, pipelines_dir):
    config = create_config(channels="RGB", bits=1)

    # 1. Encode LSB payload into PNG.
    stego = encode(medium_carrier, LSB_SECRET, config)
    png_buf = io.BytesIO()
    stego.save(png_buf, format="PNG")
    png_bytes = png_buf.getvalue()
    assert png_bytes.endswith(b"IEND") or b"IEND" in png_bytes[-16:]

    # 2. Append ZIP bytes after IEND.
    zip_bytes = _build_zip_bytes(ZIP_FILE_NAME, ZIP_FILE_CONTENT)
    polyglot = png_bytes + zip_bytes

    # 3. Persist artifact.
    out_path = pipelines_dir / "pipeline_polyglot.png"
    out_path.write_bytes(polyglot)

    # 4a. LSB half readable via steg_core.decode(). PIL happily ignores
    #     the trailing junk after IEND.
    img_from_polyglot = Image.open(io.BytesIO(polyglot))
    assert decode(img_from_polyglot, config) == LSB_SECRET

    # 4b. ZIP half readable — zipfile scans backward for the EOCD signature.
    with zipfile.ZipFile(io.BytesIO(polyglot), "r") as zf:
        assert ZIP_FILE_NAME in zf.namelist()
        assert zf.read(ZIP_FILE_NAME) == ZIP_FILE_CONTENT

    # 5. Magic-byte type detection reports PNG (the first-match wins).
    assert polyglot.startswith(b"\x89PNG\r\n\x1a\n")
