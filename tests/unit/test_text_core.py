"""text_core encode/decode round-trip, capacity, and detector composition."""

from __future__ import annotations

import pytest

import analysis_tools as at
import text_core


PREAMBLE = (
    "We the People of the United States, in Order to form a more perfect Union, "
    "establish Justice, insure domestic Tranquility, provide for the common defence, "
    "promote the general Welfare, and secure the Blessings of Liberty to ourselves "
    "and our Posterity, do ordain and establish this Constitution for the United "
    "States of America."
)
LINES_COVER = "\n".join(f"line {i} contains some text" for i in range(64))

# Per-method covers with adequate capacity.
COVERS = {
    "zero_width":    PREAMBLE,
    "homoglyph":     PREAMBLE + " " + PREAMBLE + " " + PREAMBLE,
    "whitespace":    LINES_COVER,
    "invisible_ink": PREAMBLE,
}

SECRET = "flag{4m3r1c4n_sp1r1t}"


# --- round-trip --------------------------------------------------------------

@pytest.mark.parametrize("method", text_core.METHODS)
def test_round_trip(method):
    cover = COVERS[method]
    stego = text_core.encode(cover, SECRET, method)
    assert text_core.decode(stego, method) == SECRET


@pytest.mark.parametrize("method", text_core.METHODS)
def test_stego_differs_from_cover(method):
    cover = COVERS[method]
    stego = text_core.encode(cover, SECRET, method)
    assert stego != cover


# --- capacity failures -------------------------------------------------------

def test_homoglyph_capacity_error():
    with pytest.raises(text_core.TextStegCapacityError) as exc:
        text_core.encode("abc", SECRET, "homoglyph")
    assert "cover too small" in str(exc.value)


def test_whitespace_capacity_error():
    with pytest.raises(text_core.TextStegCapacityError) as exc:
        text_core.encode("just one line", SECRET, "whitespace")
    assert "cover too small" in str(exc.value)


def test_capacity_reports_bytes_max():
    rep = text_core.capacity(PREAMBLE, "homoglyph")
    assert rep["method"] == "homoglyph"
    assert rep["payload_bytes_max"] >= 0
    assert rep["carrier_bits"] >= 0


def test_capacity_unknown_method_raises():
    with pytest.raises(ValueError):
        text_core.capacity(PREAMBLE, "bogus")


# --- detector composition — the whole point of the plan ----------------------

def test_zero_width_detector_composes():
    stego = text_core.encode(COVERS["zero_width"], SECRET, "zero_width")
    r = at.detect_unicode_steg(stego.encode("utf-8"))
    assert r["found"] is True


def test_homoglyph_detector_composes():
    stego = text_core.encode(COVERS["homoglyph"], SECRET, "homoglyph")
    r = at.detect_homoglyph_steg(stego.encode("utf-8"))
    assert r["found"] is True


def test_whitespace_detector_composes():
    stego = text_core.encode(COVERS["whitespace"], SECRET, "whitespace")
    r = at.detect_whitespace_steg(stego.encode("utf-8"))
    assert r["found"] is True


def test_invisible_ink_detector_composes():
    stego = text_core.encode(COVERS["invisible_ink"], SECRET, "invisible_ink")
    r = at.detect_unicode_steg(stego.encode("utf-8"))
    assert r["found"] is True
    assert r["invisible_chars"] > 0


# --- corruption tolerance ----------------------------------------------------

def test_zero_width_missing_delimiters_returns_empty():
    # No ZWJ anywhere -> nothing to decode, must not crash.
    assert text_core.decode("plain text with no zero-width chars", "zero_width") == ""


def test_homoglyph_short_input_returns_empty():
    # Under 16 carrier bits -> length prefix cannot be read; no crash.
    assert text_core.decode("abc", "homoglyph") == ""


def test_whitespace_no_trailing_returns_empty():
    assert text_core.decode("no trailing space here\nnor here", "whitespace") == ""


def test_invisible_ink_no_tags_returns_empty():
    assert text_core.decode("plain cover only", "invisible_ink") == ""


def test_zero_width_stripped_chars_does_not_crash():
    stego = text_core.encode(COVERS["zero_width"], SECRET, "zero_width")
    # Rip out roughly half of the zero-width payload bits.
    mangled = "".join(
        ch for i, ch in enumerate(stego)
        if ch not in (text_core.ZWSP, text_core.ZWNJ) or i % 2 == 0
    )
    # Should return a string (possibly wrong) without raising.
    got = text_core.decode(mangled, "zero_width")
    assert isinstance(got, str)


# --- generic dispatcher ------------------------------------------------------

def test_encode_unknown_method_raises():
    with pytest.raises(ValueError):
        text_core.encode(PREAMBLE, SECRET, "bogus")


def test_decode_unknown_method_raises():
    with pytest.raises(ValueError):
        text_core.decode(PREAMBLE, "bogus")


def test_methods_tuple_is_the_four():
    assert set(text_core.METHODS) == {
        "zero_width", "homoglyph", "whitespace", "invisible_ink",
    }
