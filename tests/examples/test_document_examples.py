"""Document/structured-data examples: html, xml, yaml, md, rtf, pdf, ini, toml, json."""

from __future__ import annotations

import pytest

from analysis_tools import (
    detect_base64,
    detect_file_type,
    detect_hex_strings,
    detect_unicode_steg,
)


TEXT_FILES = [
    "example_hidden.html",
    "example_hidden.xml",
    "example_hidden.yaml",
    "example_hidden.md",
    "example_hidden.rtf",
    "example_hidden.ini",
    "example_hidden.toml",
    "example_hidden.json",
    "example_key_ordering.json",
    "example_html_events.html",
    "example_xml_entities.xml",
]


@pytest.mark.parametrize("filename", TEXT_FILES)
def test_text_document_has_some_steg_indicator(examples_dir, filename, plinian):
    path = examples_dir / filename
    if not path.exists():
        pytest.skip(f"{filename} not present")
    data = path.read_bytes()
    text = data.decode("utf-8", errors="ignore")

    # One of: direct plinian, base64, hex, or unicode invisible chars must show up.
    direct = plinian in text
    b64 = detect_base64(data).get("found", False)
    hexf = detect_hex_strings(data).get("found", False)
    uni = detect_unicode_steg(data).get("found", False)

    assert direct or b64 or hexf or uni, (
        f"{filename}: no steg indicator detected"
    )


def test_pdf_file_type_detected(examples_dir):
    for name in ["example_hidden.pdf", "example_pdf_forms.pdf",
                 "example_pdf_javascript.pdf", "example_pdf_incremental.pdf"]:
        path = examples_dir / name
        if not path.exists():
            continue
        assert detect_file_type(path.read_bytes()).value == "pdf"


def test_pdf_contains_plinian(examples_dir, plinian):
    data = (examples_dir / "example_hidden.pdf").read_bytes()
    assert plinian.encode("utf-8") in data


def test_rtf_contains_plinian(examples_dir, plinian):
    data = (examples_dir / "example_hidden.rtf").read_bytes()
    text = data.decode("latin-1", errors="ignore")
    # RTF may hex-encode the payload; check both raw and hex.
    assert (plinian in text
            or plinian.encode("utf-8").hex() in text.lower()
            or detect_hex_strings(data).get("found", False))
