"""calculate_capacity edge cases."""

from __future__ import annotations

import pytest
from PIL import Image

from steg_core import HEADER_SIZE, calculate_capacity, create_config


@pytest.mark.parametrize("preset,bits,expected_bpp", [
    ("R", 1, 1),
    ("RGB", 1, 3),
    ("RGB", 2, 6),
    ("RGBA", 1, 4),
    ("RGBA", 8, 32),
])
def test_bits_per_pixel(preset, bits, expected_bpp, medium_carrier):
    config = create_config(channels=preset, bits=bits)
    cap = calculate_capacity(medium_carrier, config)
    assert cap["config"]["bits_per_pixel"] == expected_bpp


def test_capacity_scales_linearly_with_pixels():
    config = create_config(channels="RGB", bits=1)
    small = Image.new("RGBA", (100, 100), (0, 0, 0, 255))
    big = Image.new("RGBA", (200, 200), (0, 0, 0, 255))
    small_cap = calculate_capacity(small, config)["bytes_total"]
    big_cap = calculate_capacity(big, config)["bytes_total"]
    assert big_cap == 4 * small_cap  # 4x pixel count


def test_capacity_accounts_for_header():
    config = create_config(channels="RGB", bits=1)
    img = Image.new("RGBA", (100, 100), (0, 0, 0, 255))
    cap = calculate_capacity(img, config)
    assert cap["usable_bytes"] == cap["bytes_total"] - HEADER_SIZE


def test_capacity_zero_for_tiny_image():
    config = create_config(channels="R", bits=1)
    img = Image.new("RGBA", (1, 1), (0, 0, 0, 255))
    cap = calculate_capacity(img, config)
    assert cap["usable_bytes"] == 0  # 1 pixel * 1 channel * 1 bit = 1 bit; can't hold header
