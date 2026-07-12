"""Pipeline #4 — Injector stack: one PNG carrying three layers of steg.

  1. LSB in RGB channels (steg_core payload)
  2. tEXt chunk with jailbreak template (injector)
  3. Trailing data after IEND

Each surface is recovered by its own decoder.
"""

from __future__ import annotations

import io

import pytest
from PIL import Image

from injector import extract_text_chunks, inject_text_chunk
from steg_core import create_config, decode, encode

pytestmark = pytest.mark.pipeline

LSB_PAYLOAD = b"stack layer 1: LSB message body"
TEXT_KEYWORD = "Comment"
TEXT_PAYLOAD = "stack layer 2: metadata prompt injection"
TRAILING_BYTES = b"\n[stack layer 3: trailing data marker]\n"


def test_injector_stack(medium_carrier, pipelines_dir):
    config = create_config(channels="RGB", bits=1)

    # 1. LSB encode
    stego = encode(medium_carrier, LSB_PAYLOAD, config)
    buf = io.BytesIO()
    stego.save(buf, format="PNG")
    png_bytes = buf.getvalue()

    # 2. tEXt chunk inject
    png_with_text = inject_text_chunk(png_bytes, TEXT_KEYWORD, TEXT_PAYLOAD)

    # 3. Trailing data append
    final_bytes = png_with_text + TRAILING_BYTES

    out = pipelines_dir / "pipeline_injector_stack.png"
    out.write_bytes(final_bytes)

    # Recover LSB layer
    img = Image.open(io.BytesIO(final_bytes))
    assert decode(img, config) == LSB_PAYLOAD

    # Recover tEXt layer
    chunks = extract_text_chunks(final_bytes)
    assert chunks.get(TEXT_KEYWORD) == TEXT_PAYLOAD

    # Recover trailing layer
    iend_idx = final_bytes.rfind(b"IEND")
    trailing = final_bytes[iend_idx + 4 + 4:]  # skip IEND chunk type + CRC
    assert TRAILING_BYTES.strip() in trailing
