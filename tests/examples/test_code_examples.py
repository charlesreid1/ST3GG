"""Code-file examples: py/js/c/css/sql/tex/sh — each hides the plinian divider
in a comment or string literal reachable by base64/hex or direct search."""

from __future__ import annotations

import pytest

from analysis_tools import detect_base64, detect_hex_strings, detect_unicode_steg


CODE_FILES = [
    "example_hidden.py",
    "example_hidden.js",
    "example_hidden.c",
    "example_hidden.css",
    "example_hidden.sql",
    "example_hidden.tex",
    "example_hidden.sh",
]


@pytest.mark.parametrize("filename", CODE_FILES)
def test_code_file_has_steg_indicator(examples_dir, filename, plinian):
    path = examples_dir / filename
    if not path.exists():
        pytest.skip(f"{filename} not present")
    data = path.read_bytes()
    text = data.decode("utf-8", errors="ignore")

    direct = plinian in text
    b64 = detect_base64(data).get("found", False)
    hexf = detect_hex_strings(data).get("found", False)
    uni = detect_unicode_steg(data).get("found", False)

    assert direct or b64 or hexf or uni, (
        f"{filename}: no steg indicator detected"
    )
