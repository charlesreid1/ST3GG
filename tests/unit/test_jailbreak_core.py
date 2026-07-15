"""jailbreak_core: template registry, composition, and detection."""

from __future__ import annotations

import io

import pytest
from PIL import Image

from jailbreak_core import (
    INJECTION_FILENAME_TEMPLATES,
    JAILBREAK_TEMPLATES,
    JailbreakPayload,
    JailbreakTemplate,
    compose_image_jailbreak,
    compose_text_jailbreak,
    detect_full_injection_package,
    detect_injection_filename,
    detect_jailbreak_in_chunks,
    detect_jailbreak_payload,
    generate_injection_filename,
    get_filename_template_info,
    get_filename_template_names,
    get_jailbreak_names,
    get_jailbreak_template,
    get_jailbreak_template_info,
    list_templates_by_model,
    list_templates_by_technique,
)

from tests.conftest import requires_crypto


def _png_bytes(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ---------- Jailbreak template registry ----------

def test_jailbreak_templates_registered():
    names = get_jailbreak_names()
    assert "pliny_classic" in names
    assert "empty" in names
    for name in names:
        info = get_jailbreak_template_info(name)
        assert isinstance(info, JailbreakTemplate)
        assert info.name == name
        assert isinstance(info.technique, str) and info.technique
        assert isinstance(info.target_models, list)


def test_get_jailbreak_template_returns_body():
    body = get_jailbreak_template("pliny_classic")
    assert isinstance(body, str)
    assert "PLINY" in body
    assert get_jailbreak_template("empty") == ""
    # Unknown name falls back to empty (backward compat).
    assert get_jailbreak_template("does_not_exist") == ""


def test_get_jailbreak_template_info_returns_dataclass():
    info = get_jailbreak_template_info("dan_classic")
    assert isinstance(info, JailbreakTemplate)
    assert info.technique == "persona_break"
    assert "gpt-4" in info.target_models
    assert get_jailbreak_template_info("does_not_exist") is None


def test_list_by_technique():
    grouped = list_templates_by_technique()
    assert "persona_break" in grouped
    assert "pliny_classic" in grouped["persona_break"]
    assert "prompt_extraction" in grouped


def test_list_by_model():
    grouped = list_templates_by_model()
    assert "gpt-4" in grouped
    assert "pliny_classic" in grouped["gpt-4"]
    assert "claude" in grouped


# ---------- Filename templates ----------

def test_all_filename_templates_generate():
    for name in get_filename_template_names():
        if name == "custom":
            fn = generate_injection_filename("custom", custom_template="probe_{rand4}")
        else:
            fn = generate_injection_filename(name, channels="RGB")
        assert fn.endswith(".png")
        assert "RGB" in fn or name in ("subtle", "custom")


def test_filename_template_info():
    for name in get_filename_template_names():
        info = get_filename_template_info(name)
        assert info is not None
        assert set(info.keys()) >= {"name", "template", "description", "variables", "target_models"}


# ---------- Image jailbreak composition ----------

def test_compose_image_jailbreak_roundtrip(medium_carrier):
    payload = compose_image_jailbreak(
        "pliny_classic",
        medium_carrier,
        channels="RGB",
        bits=1,
        metadata_inject=False,
    )
    assert isinstance(payload, JailbreakPayload)
    assert payload.carrier_image is not None
    # Decode LSB out of the stego image
    from img_core import create_config, decode
    decoded = decode(payload.carrier_image, create_config(channels="RGB", bits=1))
    assert decoded == payload.text_content.encode("utf-8")


def test_compose_image_jailbreak_filename(medium_carrier):
    payload = compose_image_jailbreak(
        "dan_classic",
        medium_carrier,
        filename_template="chatgpt_decoder",
        metadata_inject=False,
    )
    assert payload.filename is not None
    assert payload.filename.endswith(".png")
    assert "RGB" in payload.filename


def test_compose_image_jailbreak_metadata(medium_carrier):
    from injector import extract_text_chunks

    payload = compose_image_jailbreak(
        "developer_mode",
        medium_carrier,
        metadata_inject=True,
    )
    assert payload.image_bytes is not None
    chunks = extract_text_chunks(payload.image_bytes)
    assert "Comment" in chunks
    assert "Description" in chunks
    assert "Instructions" in chunks


@requires_crypto
def test_compose_image_jailbreak_encrypted(medium_carrier):
    from crypto import decrypt
    from img_core import create_config, decode

    payload = compose_image_jailbreak(
        "pliny_classic",
        medium_carrier,
        channels="RGB",
        metadata_inject=False,
        encrypt=True,
        password="secret",
    )
    ciphertext = decode(payload.carrier_image, create_config(channels="RGB", bits=1))
    plaintext = decrypt(ciphertext, "secret")
    assert plaintext == payload.text_content.encode("utf-8")


def test_compose_image_jailbreak_trailing(medium_carrier):
    trailing = b"\n[STACK-LAYER-3]\n"
    payload = compose_image_jailbreak(
        "empty",  # small payload keeps it fast
        medium_carrier,
        metadata_inject=False,
        trailing_payload=trailing,
    )
    assert payload.image_bytes is not None
    iend_idx = payload.image_bytes.rfind(b"IEND")
    tail = payload.image_bytes[iend_idx + 8:]
    assert trailing in tail
    assert payload.trailing_bytes == trailing


def test_compose_text_jailbreak_roundtrip():
    from text_core import decode_zero_width
    cover = "The quick brown fox jumps over the lazy dog. " * 4
    payload = compose_text_jailbreak(
        "system_prompt_leak",
        cover,
        stego_method="zero_width",
    )
    assert payload.carrier_text is not None
    recovered = decode_zero_width(payload.carrier_text)
    assert recovered == payload.text_content


# ---------- Detection ----------

def test_detect_injection_filename_positive():
    fn = generate_injection_filename("chatgpt_decoder", channels="RGB")
    result = detect_injection_filename(fn)
    assert result["detected"] is True
    assert result["matched_template"] == "chatgpt_decoder"
    assert result["confidence"] > 0.3


def test_detect_injection_filename_negative():
    result = detect_injection_filename("holiday_photo_2024.png")
    assert result["detected"] is False
    assert result["matched_template"] is None
    assert not result["matched_keywords"]


def test_detect_jailbreak_in_chunks_positive(medium_carrier):
    from injector import inject_text_chunk

    png = _png_bytes(medium_carrier)
    body = get_jailbreak_template("pliny_classic")
    png = inject_text_chunk(png, "Comment", body)
    result = detect_jailbreak_in_chunks(png)
    assert result["detected"] is True
    assert result["hits"], "expected at least one chunk hit"
    hit = result["hits"][0]
    assert hit["chunk_keyword"] == "Comment"


def test_detect_jailbreak_in_chunks_negative(medium_carrier):
    from injector import inject_text_chunk

    png = _png_bytes(medium_carrier)
    png = inject_text_chunk(png, "Comment", "just a friendly photo of a cat")
    result = detect_jailbreak_in_chunks(png)
    assert result["detected"] is False


def test_detect_jailbreak_payload_positive():
    body = get_jailbreak_template("pliny_classic")
    result = detect_jailbreak_payload(body)
    assert result["detected"] is True
    assert result["confidence"] > 0.2
    assert result["matched_template"] == "pliny_classic" or result["matched_patterns"]


def test_detect_jailbreak_payload_negative():
    result = detect_jailbreak_payload("The mitochondria is the powerhouse of the cell.")
    assert result["detected"] is False
    assert result["confidence"] == 0.0
    assert result["matched_patterns"] == []


def test_detect_full_injection_package(medium_carrier, tmp_path):
    payload = compose_image_jailbreak(
        "pliny_classic",
        medium_carrier,
        metadata_inject=True,
    )
    out = tmp_path / payload.filename
    out.write_bytes(payload.image_bytes)

    result = detect_full_injection_package(image_path=str(out))
    assert result["detected"] is True
    assert result["severity"] in ("low", "medium", "high")
    assert result["hit_count"] >= 1
    # We wrote a jailbreaky filename + chunks + LSB payload — expect multi-vector
    assert "filename" in result["vectors"]
    assert "chunks" in result["vectors"]


# ---------- Edge cases ----------

def test_empty_template():
    assert get_jailbreak_template("empty") == ""
    info = get_jailbreak_template_info("empty")
    assert info is not None
    assert info.body == ""
    assert info.technique == "none"


def test_custom_filename_template():
    fn = generate_injection_filename(
        "custom",
        channels="RGB",
        custom_template="probe_{rand4}_seed",
    )
    assert fn.endswith(".png")
    # Custom template substituted; rand4 replaced with digits.
    assert "probe_" in fn
