"""text_core encode/decode round-trip, capacity, and detector composition."""

from __future__ import annotations

from pathlib import Path

import pytest

import analysis_tools as at
import text_core

FIXTURES = Path(__file__).parent / "fixtures" / "text_core"


PREAMBLE = (
    "We the People of the United States, in Order to form a more perfect Union, "
    "establish Justice, insure domestic Tranquility, provide for the common defence, "
    "promote the general Welfare, and secure the Blessings of Liberty to ourselves "
    "and our Posterity, do ordain and establish this Constitution for the United "
    "States of America."
)
LINES_COVER = "\n".join(f"line {i} contains some text" for i in range(64))

# Per-method covers with adequate capacity.
#
# Sizing notes for the advanced techniques (SECRET = 21 bytes; framing =
# 16 + 21*8 = 184 bits):
#   variation  needs >=184 ASCII alnum carriers; PREAMBLE has ~262 -> 1x fine
#   combining  needs >=184 ASCII alpha carriers;  PREAMBLE has ~250 -> 1x fine
#   confusable needs >=92 ASCII spaces (2 bits/space); PREAMBLE has ~46 -> 3x
#   directional cover is a splice site only
#   hangul     needs >=184 ASCII spaces (1 bit/space); PREAMBLE has ~46 -> 5x
COVERS = {
    "zero_width":    PREAMBLE,
    "homoglyph":     PREAMBLE + " " + PREAMBLE + " " + PREAMBLE,
    "whitespace":    LINES_COVER,
    "invisible_ink": PREAMBLE,
    "variation":     PREAMBLE + " " + PREAMBLE,
    "combining":     PREAMBLE + " " + PREAMBLE,
    "confusable":    (PREAMBLE + " ") * 3 + PREAMBLE,
    "directional":   PREAMBLE,
    "hangul":        (PREAMBLE + " ") * 5 + PREAMBLE,
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


def test_variation_capacity_error():
    with pytest.raises(text_core.TextStegCapacityError) as exc:
        text_core.encode("abc", SECRET, "variation")
    assert "cover too small" in str(exc.value)


def test_combining_capacity_error():
    with pytest.raises(text_core.TextStegCapacityError) as exc:
        text_core.encode("abc", SECRET, "combining")
    assert "cover too small" in str(exc.value)


def test_confusable_capacity_error():
    with pytest.raises(text_core.TextStegCapacityError) as exc:
        text_core.encode("no spaces here", SECRET, "confusable")
    assert "cover too small" in str(exc.value)


def test_hangul_capacity_error():
    with pytest.raises(text_core.TextStegCapacityError) as exc:
        text_core.encode("noSpacesHere", SECRET, "hangul")
    assert "cover too small" in str(exc.value)


def test_directional_empty_cover_error():
    with pytest.raises(text_core.TextStegCapacityError) as exc:
        text_core.encode("", SECRET, "directional")
    assert "empty" in str(exc.value)


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


def test_variation_detector_composes():
    stego = text_core.encode(COVERS["variation"], SECRET, "variation")
    r = at.detect_variation_selector_steg(stego.encode("utf-8"))
    assert r["found"] is True


def test_combining_detector_composes():
    stego = text_core.encode(COVERS["combining"], SECRET, "combining")
    r = at.detect_combining_mark_steg(stego.encode("utf-8"))
    assert r["found"] is True


def test_confusable_detector_composes():
    stego = text_core.encode(COVERS["confusable"], SECRET, "confusable")
    r = at.detect_confusable_whitespace(stego.encode("utf-8"))
    assert r["found"] is True


def test_directional_detector_composes():
    stego = text_core.encode(COVERS["directional"], SECRET, "directional")
    r = at.detect_directional_override_steg(stego.encode("utf-8"))
    assert r["found"] is True


def test_hangul_detector_composes():
    stego = text_core.encode(COVERS["hangul"], SECRET, "hangul")
    r = at.detect_hangul_filler_steg(stego.encode("utf-8"))
    assert r["found"] is True


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


def test_variation_stripped_chars_does_not_crash():
    stego = text_core.encode(COVERS["variation"], SECRET, "variation")
    mangled = "".join(
        ch for i, ch in enumerate(stego) if ch != text_core.VS1 or i % 2 == 0
    )
    assert isinstance(text_core.decode(mangled, "variation"), str)


def test_combining_stripped_chars_does_not_crash():
    stego = text_core.encode(COVERS["combining"], SECRET, "combining")
    mangled = "".join(
        ch for i, ch in enumerate(stego) if ch != text_core.CGJ or i % 2 == 0
    )
    assert isinstance(text_core.decode(mangled, "combining"), str)


def test_confusable_stripped_chars_does_not_crash():
    stego = text_core.encode(COVERS["confusable"], SECRET, "confusable")
    mangled = stego.replace(text_core.EN_SPACE, " ").replace(text_core.EM_SPACE, " ")
    assert isinstance(text_core.decode(mangled, "confusable"), str)


def test_directional_stripped_chars_does_not_crash():
    stego = text_core.encode(COVERS["directional"], SECRET, "directional")
    mangled = "".join(
        ch for i, ch in enumerate(stego)
        if ch not in (text_core.RLO, text_core.LRO) or i % 2 == 0
    )
    assert isinstance(text_core.decode(mangled, "directional"), str)


def test_hangul_stripped_chars_does_not_crash():
    stego = text_core.encode(COVERS["hangul"], SECRET, "hangul")
    mangled = "".join(
        ch for i, ch in enumerate(stego) if ch != text_core.HANGUL_FILLER or i % 2 == 0
    )
    assert isinstance(text_core.decode(mangled, "hangul"), str)


# --- generic dispatcher ------------------------------------------------------

def test_encode_unknown_method_raises():
    with pytest.raises(ValueError):
        text_core.encode(PREAMBLE, SECRET, "bogus")


def test_decode_unknown_method_raises():
    with pytest.raises(ValueError):
        text_core.decode(PREAMBLE, "bogus")


def test_methods_tuple_is_the_nine():
    assert set(text_core.METHODS) == {
        "zero_width", "homoglyph", "whitespace", "invisible_ink",
        "variation", "combining", "confusable", "directional", "hangul",
    }


# --- cross-language fixtures (browser Text Lab in index.html) ----------------
#
# Each fixture is a stego text produced by the browser encoder for a known
# (cover, secret) pair. Two assertions per technique:
#   1. text_core.decode(fixture) == secret   (Python reads what the browser wrote)
#   2. text_core.encode(cover, secret) == fixture  (Python writes the same bytes)
# Divergence is a Python port bug; the JS is the source of truth.

def test_zero_width_fixture_from_browser():
    cover = (
        "We the People of the United States, in Order to form a more perfect Union, "
        "establish Justice, insure domestic Tranquility, provide for the common defence, "
        "promote the general Welfare, and secure the Blessings of Liberty to ourselves "
        "and our Posterity, do ordain and establish this Constitution for the United "
        "States of America."
    )
    secret = "flag{zer0_w1dth}"
    fixture = (FIXTURES / "zero_width_stego.txt").read_text(encoding="utf-8")

    assert text_core.decode(fixture, "zero_width") == secret
    assert text_core.encode(cover, secret, "zero_width") == fixture


def test_homoglyph_fixture_from_browser():
    cover = (FIXTURES / "homoglyph_cover.txt").read_text(encoding="utf-8")
    secret = "flag{h0m0glyphs_l00k_alik3}"
    fixture = (FIXTURES / "homoglyph_stego.txt").read_text(encoding="utf-8")

    assert text_core.decode(fixture, "homoglyph") == secret
    assert text_core.encode(cover, secret, "homoglyph") == fixture


def test_whitespace_fixture_from_browser():
    cover = (FIXTURES / "whitespace_cover.txt").read_text(encoding="utf-8")
    secret = "flag{wh1t3sp4c3_is_f0r_all_c0l0rz}"
    fixture = (FIXTURES / "whitespace_stego.txt").read_text(encoding="utf-8")

    assert text_core.decode(fixture, "whitespace") == secret
    assert text_core.encode(cover, secret, "whitespace") == fixture


def _skip_if_missing(*names: str) -> None:
    missing = [n for n in names if not (FIXTURES / n).exists()]
    if missing:
        pytest.skip(
            f"missing browser-produced fixture(s): {missing}. "
            "Regen per M4 in plan-advanced-text-encoders.md: open index.html Text Lab, "
            "encode the (cover, secret) pair listed in that plan, save the output to "
            "the named file with no added trailing whitespace."
        )


def test_variation_fixture_from_browser():
    _skip_if_missing("variation_cover.txt", "variation_stego.txt")
    cover = (FIXTURES / "variation_cover.txt").read_text(encoding="utf-8")
    secret = "flag{v4r14t10n_s3l3ct0r5}"
    fixture = (FIXTURES / "variation_stego.txt").read_text(encoding="utf-8").rstrip("\n")
    assert text_core.decode(fixture, "variation") == secret
    assert text_core.encode(cover, secret, "variation") == fixture


def test_combining_fixture_from_browser():
    _skip_if_missing("combining_cover.txt", "combining_stego.txt")
    cover = (FIXTURES / "combining_cover.txt").read_text(encoding="utf-8")
    secret = "flag{c0mb1n1ng_m4rk5}"
    fixture = (FIXTURES / "combining_stego.txt").read_text(encoding="utf-8").rstrip("\n")
    assert text_core.decode(fixture, "combining") == secret
    assert text_core.encode(cover, secret, "combining") == fixture


def test_confusable_fixture_from_browser():
    _skip_if_missing("confusable_cover.txt", "confusable_stego.txt")
    cover = (FIXTURES / "confusable_cover.txt").read_text(encoding="utf-8")
    secret = "flag{c0nfu54bl3_5p4c35}"
    fixture = (FIXTURES / "confusable_stego.txt").read_text(encoding="utf-8").rstrip("\n")
    assert text_core.decode(fixture, "confusable") == secret
    assert text_core.encode(cover, secret, "confusable") == fixture


def test_directional_fixture_from_browser():
    _skip_if_missing("directional_cover.txt", "directional_stego.txt")
    cover = (FIXTURES / "directional_cover.txt").read_text(encoding="utf-8").rstrip("\n")
    secret = "flag{r1gh7_70_l3f7_0v3rr1d3}"
    fixture = (FIXTURES / "directional_stego.txt").read_text(encoding="utf-8").rstrip("\n")
    assert text_core.decode(fixture, "directional") == secret
    assert text_core.encode(cover, secret, "directional") == fixture


def test_hangul_fixture_from_browser():
    _skip_if_missing("hangul_cover.txt", "hangul_stego.txt")
    cover = (FIXTURES / "hangul_cover.txt").read_text(encoding="utf-8")
    secret = "flag{h4ngul_f1ll3r_1n_pl41n_51gh7}"
    fixture = (FIXTURES / "hangul_stego.txt").read_text(encoding="utf-8").rstrip("\n")
    assert text_core.decode(fixture, "hangul") == secret
    assert text_core.encode(cover, secret, "hangul") == fixture


def test_invisible_ink_fixture_from_browser():
    cover = (
        "It is essential to such a government, that it be derived from the great body "
        "of the society, not from an inconsiderable proportion, or a favoured class of "
        "it; otherwise a handful of tyrannical nobles, exercising their oppressions by "
        "a delegation of their powers, might aspire to the rank of republicans, and "
        "claim for their government the honourable title of republic."
    )
    secret = "flag{invi5ibi7ity_c70ak_4ctiv4t3d}"
    # rstrip("\n") because writing the stego to a text file adds a
    # POSIX-conventional trailing newline that the encoder itself doesn't emit.
    fixture = (FIXTURES / "invisible_ink_stego.txt").read_text(encoding="utf-8").rstrip("\n")

    assert text_core.decode(fixture, "invisible_ink") == secret
    assert text_core.encode(cover, secret, "invisible_ink") == fixture
