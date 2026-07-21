"""transforms_core: zalgo, leetspeak, fullwidth + registry."""

from __future__ import annotations

import pytest

from transforms_core import (
    _TRANSFORMS,
    fullwidth_text,
    get_transform,
    leetspeak,
    list_transforms,
    zalgo_text,
)


# ---------- fullwidth ----------

def test_fullwidth_maps_printable_ascii():
    assert fullwidth_text("A") == "Ａ"
    assert fullwidth_text("z") == "ｚ"
    assert fullwidth_text("!") == "！"
    assert fullwidth_text("~") == "～"


def test_fullwidth_space_maps_to_ideographic_space():
    assert fullwidth_text(" ") == "　"


def test_fullwidth_passes_through_non_ascii():
    # Codepoints outside 0x20..0x7E are unchanged.
    assert fullwidth_text("héllo") == "ｈéｌｌｏ"
    assert fullwidth_text("\n") == "\n"


def test_fullwidth_roundtrip_via_ascii_arithmetic():
    original = "Hello, World! 123"
    fw = fullwidth_text(original)
    # Each printable-ASCII char shifted by 0xFEE0; space by U+3000-0x20.
    assert len(fw) == len(original)
    for ch_orig, ch_fw in zip(original, fw):
        if ch_orig == " ":
            assert ch_fw == "　"
        else:
            assert ord(ch_fw) == ord(ch_orig) + 0xFEE0


# ---------- registry ----------

def test_registry_has_builtins():
    names = list_transforms()
    assert "zalgo" in names
    assert "fullwidth" in names
    assert "leetspeak" in names


def test_get_transform_returns_callable():
    fn = get_transform("fullwidth")
    assert fn is fullwidth_text
    assert fn("A") == "Ａ"


def test_get_transform_unknown_raises():
    with pytest.raises(KeyError):
        get_transform("does_not_exist")


# ---------- smoke: zalgo/leetspeak still work ----------

def test_zalgo_adds_combining_marks():
    out = zalgo_text("hi", intensity=3)
    # zalgo output is always at least as long as input.
    assert len(out) >= 2
    # Should contain codepoints in the combining-marks block.
    assert any(0x0300 <= ord(c) <= 0x036F for c in out)


def test_leetspeak_substitutes_letters():
    # With p=0.7 per char and intensity=2 across many chars, at least one
    # substitution is overwhelmingly likely.
    out = leetspeak("aeiost" * 5, intensity=2)
    assert any(c in "34105782890" for c in out)
