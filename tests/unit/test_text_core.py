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
    "zero_width":         PREAMBLE,
    "cyrillic_homoglyph": PREAMBLE + " " + PREAMBLE + " " + PREAMBLE,
    # cjk_homoglyph needs punctuation carriers: fabricate a punctuation-dense
    # cover by repeating a punctuation-heavy sentence. Each repetition has 5
    # ASCII punctuation carriers (, . ; : ?); 40 reps -> 200 carriers,
    # comfortably above the 184 bits needed for SECRET.
    "cjk_homoglyph":      ("Hello, world; goodbye: really? Yes." * 40),
    "whitespace":         LINES_COVER,
    "invisible_ink": PREAMBLE,
    "variation":     PREAMBLE + " " + PREAMBLE,
    "combining":     PREAMBLE + " " + PREAMBLE,
    "confusable":    (PREAMBLE + " ") * 3 + PREAMBLE,
    "directional":   PREAMBLE,
    "hangul":        (PREAMBLE + " ") * 5 + PREAMBLE,
    # Extended techniques (SECRET = 21 bytes; framing = 184 bits where a
    # length prefix applies):
    #   mathbold       needs >=184 ASCII letter carriers; PREAMBLE has ~250 -> 1x is fine but 2x for headroom
    #   braille        payload is its own block; cover only needs to be non-empty
    #   emoji          payload is its own block; cover only needs to be non-empty
    #   skintone       payload is its own block; cover only needs to be non-empty
    #   capitalization needs >=184 word-initial ASCII letter carriers; PREAMBLE has ~52 -> 4x
    "mathbold":       PREAMBLE + " " + PREAMBLE,
    "braille":        PREAMBLE,
    "emoji":          PREAMBLE,
    "skintone":       PREAMBLE,
    "capitalization": (PREAMBLE + " ") * 4,
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

def test_cyrillic_homoglyph_capacity_error():
    with pytest.raises(text_core.TextStegCapacityError) as exc:
        text_core.encode("abc", SECRET, "cyrillic_homoglyph")
    assert "cover too small" in str(exc.value)


def test_cjk_homoglyph_capacity_error():
    with pytest.raises(text_core.TextStegCapacityError) as exc:
        text_core.encode("abc", SECRET, "cjk_homoglyph")
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


def test_mathbold_capacity_error():
    with pytest.raises(text_core.TextStegCapacityError) as exc:
        text_core.encode("abc", SECRET, "mathbold")
    assert "cover too small" in str(exc.value)


def test_capitalization_capacity_error():
    with pytest.raises(text_core.TextStegCapacityError) as exc:
        text_core.encode("a b c d", SECRET, "capitalization")
    assert "cover too small" in str(exc.value)


def test_capacity_reports_bytes_max():
    rep = text_core.capacity(PREAMBLE, "cyrillic_homoglyph")
    assert rep["method"] == "cyrillic_homoglyph"
    assert rep["payload_bytes_max"] >= 0
    assert rep["carrier_bits"] >= 0


def test_capacity_reports_bytes_max_cjk():
    rep = text_core.capacity(COVERS["cjk_homoglyph"], "cjk_homoglyph")
    assert rep["method"] == "cjk_homoglyph"
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


def test_cyrillic_homoglyph_detector_composes():
    stego = text_core.encode(COVERS["cyrillic_homoglyph"], SECRET, "cyrillic_homoglyph")
    r = at.detect_cyrillic_homoglyph_steg(stego.encode("utf-8"))
    assert r["found"] is True


def test_cjk_homoglyph_detector_composes():
    stego = text_core.encode(COVERS["cjk_homoglyph"], SECRET, "cjk_homoglyph")
    r = at.detect_cjk_homoglyph_steg(stego.encode("utf-8"))
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


def test_mathbold_detector_composes():
    stego = text_core.encode(COVERS["mathbold"], SECRET, "mathbold")
    r = at.detect_math_bold_steg(stego.encode("utf-8"))
    assert r["found"] is True


def test_braille_detector_composes():
    stego = text_core.encode(COVERS["braille"], SECRET, "braille")
    r = at.detect_braille_steg(stego.encode("utf-8"))
    assert r["found"] is True


def test_emoji_substitution_detector_composes():
    stego = text_core.encode(COVERS["emoji"], SECRET, "emoji")
    r = at.detect_emoji_substitution_steg(stego.encode("utf-8"))
    assert r["found"] is True


def test_skintone_detector_composes():
    stego = text_core.encode(COVERS["skintone"], SECRET, "skintone")
    r = at.detect_skintone_steg(stego.encode("utf-8"))
    assert r["found"] is True


def test_capitalization_detector_composes():
    stego = text_core.encode(COVERS["capitalization"], SECRET, "capitalization")
    r = at.detect_capitalization_steg(stego.encode("utf-8"))
    assert r["found"] is True


# --- reconciliation: analysis_tools decoders wrap text_core ------------------

def test_reconcile_decode_braille():
    stego = text_core.encode(COVERS["braille"], SECRET, "braille")
    wrapper = at.decode_braille(stego.encode("utf-8"))
    core = text_core.decode(stego, "braille")
    assert wrapper["found"] is True
    assert wrapper["message"] == core


def test_reconcile_decode_directional_override():
    stego = text_core.encode(COVERS["directional"], SECRET, "directional")
    wrapper = at.decode_directional_override(stego.encode("utf-8"))
    core = text_core.decode(stego, "directional")
    assert wrapper["found"] is True
    assert wrapper["message"] == core


def test_reconcile_decode_hangul_filler():
    stego = text_core.encode(COVERS["hangul"], SECRET, "hangul")
    wrapper = at.decode_hangul_filler(stego.encode("utf-8"))
    core = text_core.decode(stego, "hangul")
    assert wrapper["found"] is True
    assert wrapper["message"] == core


def test_reconcile_decode_math_alphanumeric():
    stego = text_core.encode(COVERS["mathbold"], SECRET, "mathbold")
    wrapper = at.decode_math_alphanumeric(stego.encode("utf-8"))
    core = text_core.decode(stego, "mathbold")
    assert wrapper["found"] is True
    assert wrapper["message"] == core


def test_reconcile_decode_emoji_skin_tone():
    stego = text_core.encode(COVERS["skintone"], SECRET, "skintone")
    wrapper = at.decode_emoji_skin_tone(stego.encode("utf-8"))
    core = text_core.decode(stego, "skintone")
    assert wrapper["found"] is True
    assert wrapper["message"] == core


# --- corruption tolerance ----------------------------------------------------

def test_zero_width_missing_delimiters_returns_empty():
    # No ZWJ anywhere -> nothing to decode, must not crash.
    assert text_core.decode("plain text with no zero-width chars", "zero_width") == ""


def test_cyrillic_homoglyph_short_input_returns_empty():
    # Under 16 carrier bits -> length prefix cannot be read; no crash.
    assert text_core.decode("abc", "cyrillic_homoglyph") == ""


def test_cjk_homoglyph_short_input_returns_empty():
    # Under 16 carrier bits -> length prefix cannot be read; no crash.
    assert text_core.decode("abc", "cjk_homoglyph") == ""


def test_whitespace_no_trailing_returns_empty():
    assert text_core.decode("no trailing space here\nnor here", "whitespace") == ""


def test_invisible_ink_no_tags_returns_empty():
    assert text_core.decode("plain cover only", "invisible_ink") == ""


def test_invisible_ink_still_byte_identical():
    # Regression around the unicode_tags refactor: invisible_ink must produce
    # byte-for-byte identical stego output for a known (cover, secret) pair.
    cover = COVERS["invisible_ink"]
    secret = SECRET
    stego = text_core.encode(cover, secret, "invisible_ink")

    # Reconstruct the pre-refactor output shape explicitly.
    TAG_BASE = 0xE0000
    TAG_END = TAG_BASE + 0x7F
    expected_payload = (
        chr(TAG_BASE)
        + ''.join(chr(TAG_BASE + ord(ch)) for ch in secret if ord(ch) < 128)
        + chr(TAG_END)
    )
    expected = cover[0] + expected_payload + cover[1:]
    assert stego == expected
    assert text_core.decode(stego, "invisible_ink") == secret


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


def test_mathbold_stripped_chars_does_not_crash():
    stego = text_core.encode(COVERS["mathbold"], SECRET, "mathbold")
    # Strip roughly half of the math-bold codepoints.
    mangled = "".join(
        ch for i, ch in enumerate(stego)
        if not (0x1D400 <= ord(ch) <= 0x1D433) or i % 2 == 0
    )
    assert isinstance(text_core.decode(mangled, "mathbold"), str)


def test_braille_stripped_chars_does_not_crash():
    stego = text_core.encode(COVERS["braille"], SECRET, "braille")
    mangled = "".join(
        ch for i, ch in enumerate(stego)
        if not (0x2800 <= ord(ch) <= 0x28FF) or i % 2 == 0
    )
    assert isinstance(text_core.decode(mangled, "braille"), str)


def test_emoji_stripped_chars_does_not_crash():
    stego = text_core.encode(COVERS["emoji"], SECRET, "emoji")
    mangled = "".join(
        ch for i, ch in enumerate(stego)
        if ch not in (text_core.EMOJI_ONE, text_core.EMOJI_ZERO) or i % 2 == 0
    )
    assert isinstance(text_core.decode(mangled, "emoji"), str)


def test_skintone_stripped_chars_does_not_crash():
    stego = text_core.encode(COVERS["skintone"], SECRET, "skintone")
    mangled = "".join(
        ch for i, ch in enumerate(stego)
        if ch not in text_core.SKINTONE_REVERSE or i % 2 == 0
    )
    assert isinstance(text_core.decode(mangled, "skintone"), str)


def test_capitalization_no_carriers_returns_empty():
    # No word-initial ASCII letters -> nothing to decode.
    assert text_core.decode("123 456 789", "capitalization") == ""


# --- generic dispatcher ------------------------------------------------------

def test_encode_unknown_method_raises():
    with pytest.raises(ValueError):
        text_core.encode(PREAMBLE, SECRET, "bogus")


def test_decode_unknown_method_raises():
    with pytest.raises(ValueError):
        text_core.decode(PREAMBLE, "bogus")


def test_methods_tuple_is_the_fifteen():
    assert set(text_core.METHODS) == {
        "zero_width", "cyrillic_homoglyph", "cjk_homoglyph",
        "whitespace", "invisible_ink",
        "variation", "combining", "confusable", "directional", "hangul",
        "mathbold", "braille", "emoji", "skintone", "capitalization",
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


def test_cyrillic_homoglyph_fixture_from_browser():
    cover = (FIXTURES / "cyrillic_homoglyph_cover.txt").read_text(encoding="utf-8")
    secret = "flag{h0m0glyphs_l00k_alik3}"
    fixture = (FIXTURES / "cyrillic_homoglyph_stego.txt").read_text(encoding="utf-8")

    assert text_core.decode(fixture, "cyrillic_homoglyph") == secret
    assert text_core.encode(cover, secret, "cyrillic_homoglyph") == fixture


def test_cjk_homoglyph_fixture_round_trip():
    # Python-only fixture (no browser reference for cjk_homoglyph).
    _skip_if_missing("cjk_homoglyph_cover.txt", "cjk_homoglyph_stego.txt")
    cover = (FIXTURES / "cjk_homoglyph_cover.txt").read_text(encoding="utf-8")
    secret = "flag{cjk-punct-steg}"
    fixture = (FIXTURES / "cjk_homoglyph_stego.txt").read_text(encoding="utf-8").rstrip("\n")

    assert text_core.decode(fixture, "cjk_homoglyph") == secret
    assert text_core.encode(cover, secret, "cjk_homoglyph") == fixture


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


def test_mathbold_fixture_from_browser():
    _skip_if_missing("mathbold_cover.txt", "mathbold_stego.txt")
    cover = (FIXTURES / "mathbold_cover.txt").read_text(encoding="utf-8")
    secret = "flag{b0ld_1s_1_pl41n_1s_0}"
    fixture = (FIXTURES / "mathbold_stego.txt").read_text(encoding="utf-8").rstrip("\n")
    assert text_core.decode(fixture, "mathbold") == secret
    assert text_core.encode(cover, secret, "mathbold") == fixture


def test_braille_fixture_from_browser():
    _skip_if_missing("braille_cover.txt", "braille_stego.txt")
    cover = (FIXTURES / "braille_cover.txt").read_text(encoding="utf-8")
    secret = "flag{brl_p47t3rn}"
    fixture = (FIXTURES / "braille_stego.txt").read_text(encoding="utf-8").rstrip("\n")
    assert text_core.decode(fixture, "braille") == secret
    assert text_core.encode(cover, secret, "braille") == fixture


def test_emoji_fixture_from_browser():
    _skip_if_missing("emoji_cover.txt", "emoji_stego.txt")
    cover = (FIXTURES / "emoji_cover.txt").read_text(encoding="utf-8")
    secret = "flag{r3d_1_blu3_0}"
    fixture = (FIXTURES / "emoji_stego.txt").read_text(encoding="utf-8").rstrip("\n")
    assert text_core.decode(fixture, "emoji") == secret
    assert text_core.encode(cover, secret, "emoji") == fixture


def test_skintone_fixture_from_browser():
    _skip_if_missing("skintone_cover.txt", "skintone_stego.txt")
    cover = (FIXTURES / "skintone_cover.txt").read_text(encoding="utf-8")
    secret = "flag{4_t0n35_2_b1t5_34ch}"
    fixture = (FIXTURES / "skintone_stego.txt").read_text(encoding="utf-8").rstrip("\n")
    assert text_core.decode(fixture, "skintone") == secret
    assert text_core.encode(cover, secret, "skintone") == fixture


def test_capitalization_fixture_python_source_of_truth():
    # NB: capitalization has no JS reference in index.html Text Lab, so this
    # fixture is Python-produced (round-trip only; not a cross-language check).
    _skip_if_missing("capitalization_cover.txt", "capitalization_stego.txt")
    cover = (FIXTURES / "capitalization_cover.txt").read_text(encoding="utf-8")
    secret = "flag{c4p1t4l1z4t10n_15_1}"
    fixture = (FIXTURES / "capitalization_stego.txt").read_text(encoding="utf-8").rstrip("\n")
    assert text_core.decode(fixture, "capitalization") == secret
    assert text_core.encode(cover, secret, "capitalization") == fixture


# --- MCP end-to-end smoke ----------------------------------------------------

@pytest.mark.parametrize("method", [
    "mathbold", "braille", "emoji", "skintone", "capitalization",
])
def test_mcp_round_trip(method):
    """encode/decode/capacity land through the MCP dispatcher for each new method."""
    import asyncio, json
    from st3ggmcp.tools import execute_text_encode, execute_text_decode, execute_text_capacity

    cover = COVERS[method]

    async def run():
        enc = json.loads(await execute_text_encode(method=method, secret=SECRET, cover_text=cover))
        assert "stego" in enc, enc
        dec = json.loads(await execute_text_decode(method=method, stego_text=enc["stego"]))
        assert dec["recovered"] == SECRET
        cap = json.loads(await execute_text_capacity(method=method, cover_text=cover))
        assert cap["method"] == method
        assert "carrier_bits" in cap and "payload_bytes_max" in cap

    asyncio.run(run())


def test_mcp_text_steg_fires_new_detectors():
    """After encoding via each new technique, the MCP fan-out should surface a hit
    from the framing-aware detector we added for it."""
    import asyncio, json
    from st3ggmcp.tools import execute_text_steg_message

    expectations = [
        ("mathbold",       "detect_math_bold_steg"),
        ("braille",        "detect_braille_steg"),
        ("emoji",          "detect_emoji_substitution_steg"),
        ("skintone",       "detect_skintone_steg"),
        ("capitalization", "detect_capitalization_steg"),
    ]

    async def run():
        for method, detector in expectations:
            stego = text_core.encode(COVERS[method], SECRET, method)
            report = json.loads(await execute_text_steg_message(text=stego))
            hit_detectors = {h["detector"] for h in report["hits"]}
            assert detector in hit_detectors, (
                f"{method}: expected {detector} in hits, got {hit_detectors}"
            )

    asyncio.run(run())
