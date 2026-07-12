"""Unicode / text steganography example files."""

from __future__ import annotations

import pytest

from analysis_tools import (
    detect_capitalization_steg,
    detect_combining_mark_steg,
    detect_confusable_whitespace,
    detect_emoji_steg,
    detect_homoglyph_steg,
    detect_unicode_steg,
    detect_variation_selector_steg,
    detect_whitespace_steg,
)


# (filename, detector, expected_found_key)
UNICODE_CASES = [
    ("example_zero_width.txt", detect_unicode_steg, "found"),
    ("example_whitespace.txt", detect_whitespace_steg, "found"),
    ("example_whitespace.csv", detect_whitespace_steg, "found"),
    ("example_homoglyph.txt", detect_homoglyph_steg, "found"),
    ("example_variation_selector.txt", detect_variation_selector_steg, "found"),
    ("example_combining_diacritics.txt", detect_combining_mark_steg, "found"),
    ("example_confusable_whitespace.txt", detect_confusable_whitespace, "found"),
    ("example_emoji_substitution.txt", detect_emoji_steg, "found"),
    ("example_emoji_skin_tone.txt", detect_emoji_steg, "found"),
    ("example_capitalization.txt", detect_capitalization_steg, "found"),
]


@pytest.mark.parametrize("filename,detector,key", UNICODE_CASES,
                         ids=[c[0] for c in UNICODE_CASES])
def test_unicode_steg_detector_fires(examples_dir, filename, detector, key):
    path = examples_dir / filename
    if not path.exists():
        pytest.skip(f"{filename} not present")
    result = detector(path.read_bytes())
    assert result.get(key), f"{filename}: {detector.__name__} did not report found"


def test_invisible_ink_has_tag_chars(examples_dir):
    """Example uses Unicode Tag characters (U+E0000..U+E007F) to hide the payload."""
    data = (examples_dir / "example_invisible_ink.txt").read_bytes()
    text = data.decode("utf-8", errors="ignore")
    tag_chars = sum(1 for c in text if 0xE0000 <= ord(c) <= 0xE007F)
    assert tag_chars > 5


def test_directional_override_present(examples_dir):
    """Directional-override example must contain LRO/RLO/PDF controls."""
    data = (examples_dir / "example_directional_override.txt").read_bytes()
    text = data.decode("utf-8", errors="ignore")
    bidi_chars = "‪‫‬‭‮⁦⁧⁨⁩"
    assert any(c in text for c in bidi_chars)
