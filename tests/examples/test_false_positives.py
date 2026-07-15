"""Clean-image false-positive tests: freshly-generated noise must NOT trigger
STEG detection or LSB decoding."""

from __future__ import annotations

import io

import numpy as np
import pytest
from PIL import Image

from img_core import decode, detect_encoding


def _clean_noise_image(size=200, seed=99):
    rng = np.random.default_rng(seed)
    px = rng.integers(0, 256, size=(size, size, 4), dtype=np.uint8)
    px[:, :, 3] = 255
    return Image.fromarray(px, "RGBA")


def test_clean_noise_not_detected_as_steg():
    img = _clean_noise_image()
    assert detect_encoding(img) is None


def test_clean_noise_decode_raises():
    img = _clean_noise_image()
    with pytest.raises(ValueError):
        decode(img)


def test_solid_color_not_detected_as_steg():
    img = Image.new("RGBA", (200, 200), (128, 128, 128, 255))
    assert detect_encoding(img) is None
