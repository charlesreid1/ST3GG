"""img_core PNG chunk I/O: tEXt / iTXt / private chunk inject + read-back.

Previously lived in ``test_injector.py`` when these functions were part of
``injector.py``. Jailbreak template registry and filename-generation tests
are in ``test_jailbreak_core.py``.
"""

from __future__ import annotations

import io

import pytest
from PIL import Image

from img_core import (
    extract_text_chunks,
    inject_itxt_chunk,
    inject_metadata_pil,
    inject_private_chunk,
    inject_text_chunk,
    read_png_chunks,
)


def _png_bytes(carrier):
    buf = io.BytesIO()
    carrier.save(buf, format="PNG")
    return buf.getvalue()


# ---------- tEXt chunk ----------

def test_inject_text_chunk_roundtrip(medium_carrier):
    png = _png_bytes(medium_carrier)
    injected = inject_text_chunk(png, "Comment", "hidden marker")
    chunks = extract_text_chunks(injected)
    assert chunks.get("Comment") == "hidden marker"


def test_inject_text_chunk_ztxt_compressed(medium_carrier):
    png = _png_bytes(medium_carrier)
    long_text = "compressed payload " * 200
    injected = inject_text_chunk(png, "LongComment", long_text, compressed=True)
    chunks = extract_text_chunks(injected)
    assert chunks.get("LongComment") == long_text


def test_inject_text_chunk_rejects_non_png():
    with pytest.raises(ValueError, match=r"IEND"):
        inject_text_chunk(b"not a png", "Comment", "x")


# ---------- iTXt chunk (UTF-8) ----------

def test_inject_itxt_chunk_utf8_roundtrip(medium_carrier):
    png = _png_bytes(medium_carrier)
    injected = inject_itxt_chunk(png, "Comment", "こんにちは 🌏", language="ja")
    chunks = read_png_chunks(injected)
    itxt = [c for c in chunks if c["type"] == "iTXt" and c.get("keyword") == "Comment"]
    assert itxt, "iTXt chunk missing"
    assert itxt[0]["text"] == "こんにちは 🌏"


# ---------- Private chunk ----------

def test_inject_private_chunk_roundtrip(medium_carrier):
    png = _png_bytes(medium_carrier)
    payload = b"\x00\x01\x02custom-binary-payload\xff"
    injected = inject_private_chunk(png, "stEg", payload)
    chunks = read_png_chunks(injected)
    match = [c for c in chunks if c["type"] == "stEg"]
    assert match, "private chunk missing"
    assert match[0]["length"] == len(payload)


def test_inject_private_chunk_wrong_type_length_raises(medium_carrier):
    png = _png_bytes(medium_carrier)
    with pytest.raises(ValueError, match=r"4 characters"):
        inject_private_chunk(png, "abcde", b"x")


# ---------- PIL metadata path ----------

def test_inject_metadata_pil_reads_back(medium_carrier):
    _, png_bytes = inject_metadata_pil(medium_carrier, {"Note": "meta-payload"})
    chunks = extract_text_chunks(png_bytes)
    assert chunks.get("Note") == "meta-payload"
