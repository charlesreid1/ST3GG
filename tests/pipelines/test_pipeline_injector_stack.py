"""Pipeline #4 — Injector stack: one PNG carrying three layers of steg.

  1. LSB in RGB channels (img_core payload)
  2. tEXt chunk with jailbreak template (injector)
  3. Trailing data after IEND

Each surface is recovered by its own decoder.
"""

from __future__ import annotations

import io

import pytest
from PIL import Image

from img_core import extract_text_chunks, inject_text_chunk
from img_core import create_config, decode, encode
from jailbreak_core import compose_image_jailbreak, detect_full_injection_package

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


def test_full_jailbreak_stack(medium_carrier, pipelines_dir):
    """Pipeline — jailbreak across all vectors via compose_image_jailbreak."""
    # Fixed seed → the long injection-payload filename is stable across runs,
    # so the committed showcase artifact keeps the same name.
    payload = compose_image_jailbreak(
        "pliny_classic",
        medium_carrier,
        channels="RGB",
        bits=1,
        filename_template="chatgpt_decoder",
        metadata_inject=True,
        trailing_payload=b"\n[trailing-jailbreak-marker]\n",
        filename_seed=20260715,
    )

    out = pipelines_dir / payload.filename
    out.write_bytes(payload.image_bytes)

    # Recover LSB layer
    img = Image.open(io.BytesIO(payload.image_bytes))
    from img_core import decode as _decode
    assert _decode(img, create_config(channels="RGB", bits=1)) == payload.text_content.encode("utf-8")

    # Recover text chunks (metadata layer)
    chunks = extract_text_chunks(payload.image_bytes)
    assert "Comment" in chunks
    assert "Instructions" in chunks

    # Recover trailing layer
    iend_idx = payload.image_bytes.rfind(b"IEND")
    trailing = payload.image_bytes[iend_idx + 8:]
    assert b"trailing-jailbreak-marker" in trailing

    # Full-spectrum detector picks up the payload across vectors
    result = detect_full_injection_package(image_path=str(out))
    assert result["detected"] is True
    assert result["hit_count"] >= 2
    assert result["severity"] in ("medium", "high")
