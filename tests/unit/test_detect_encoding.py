"""detect_encoding must reconstruct the config used to encode."""

from __future__ import annotations

import pytest

from img_core import (
    create_config,
    detect_encoding,
    encode,
)

# detect_encoding sweeps 15 x 8 combos — that's slow. Sample the popular ones.
DETECTION_CASES = [
    ("R", 1), ("G", 1), ("B", 1), ("A", 1),
    ("RGB", 1), ("RGB", 2),
    ("RGBA", 1), ("RGBA", 2),
    ("RG", 1), ("BA", 1),
]

PAYLOAD = b"detect_encoding round-trip probe"


@pytest.mark.parametrize("preset,bits", DETECTION_CASES)
def test_detect_encoding_reports_correct_config(medium_carrier, preset, bits):
    config = create_config(channels=preset, bits=bits)
    encoded = encode(medium_carrier, PAYLOAD, config)

    detected = detect_encoding(encoded)
    assert detected is not None, f"failed to detect {preset}/{bits}"
    assert detected["config"]["bits_per_channel"] == bits
    assert sorted(detected["config"]["channels"]) == sorted(list(preset))


def test_detect_encoding_returns_none_on_clean_image(medium_carrier):
    assert detect_encoding(medium_carrier) is None


def test_detect_encoding_reports_payload_length(medium_carrier):
    config = create_config(channels="RGB", bits=1)
    encoded = encode(medium_carrier, PAYLOAD, config)
    detected = detect_encoding(encoded)
    assert detected["original_length"] == len(PAYLOAD)
