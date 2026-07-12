"""All 15 channel presets resolve and match their name."""

from __future__ import annotations

import pytest

from steg_core import CHANNEL_PRESETS, Channel, get_channel_preset

EXPECTED_PRESETS = {
    "R", "G", "B", "A",
    "RG", "RB", "RA", "GB", "GA", "BA",
    "RGB", "RGA", "RBA", "GBA",
    "RGBA",
}


def test_registry_has_all_15_presets():
    assert set(CHANNEL_PRESETS.keys()) == EXPECTED_PRESETS


@pytest.mark.parametrize("preset_name", sorted(EXPECTED_PRESETS))
def test_preset_channels_match_name(preset_name):
    channels = get_channel_preset(preset_name)
    names = "".join(c.name for c in channels)
    assert names == preset_name


def test_preset_case_insensitive():
    assert get_channel_preset("rgb") == get_channel_preset("RGB")


def test_unknown_preset_falls_back_to_rgb():
    fallback = get_channel_preset("XYZ")
    assert fallback == [Channel.R, Channel.G, Channel.B]
