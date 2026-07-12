"""injector: tEXt / iTXt / private chunk inject + read-back."""

from __future__ import annotations

import io

import pytest
from PIL import Image

from injector import (
    extract_text_chunks,
    generate_injection_filename,
    get_jailbreak_names,
    get_jailbreak_template,
    get_template_info,
    get_template_names,
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


# ---------- Filename / jailbreak templates ----------

def test_all_injection_templates_generate_filenames():
    for name in get_template_names():
        if name == "custom":
            fn = generate_injection_filename("custom", channels="RGB", custom_template="probe_{rand4}")
        else:
            fn = generate_injection_filename(name, channels="RGB")
        assert fn.endswith(".png")
        assert "RGB" in fn or name == "subtle" or name == "custom"


def test_template_info_returns_metadata_for_all_templates():
    for name in get_template_names():
        info = get_template_info(name)
        assert set(info.keys()) >= {"name", "template", "description", "variables"}


def test_jailbreak_templates_registered():
    names = get_jailbreak_names()
    assert "pliny_classic" in names
    assert "empty" in names
    assert get_jailbreak_template("empty") == ""
    assert "PLINY" in get_jailbreak_template("pliny_classic")
