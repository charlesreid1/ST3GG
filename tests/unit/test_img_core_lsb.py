"""LSB round-trip across preset x bits.

The old monolith looped 15 presets x 8 bit depths inside a single try/except,
so any failure hid every downstream failure. Here each combination is its
own test — the report shows exactly which combos are broken.
"""

from __future__ import annotations

import pytest

from img_core import (
    CHANNEL_PRESETS,
    create_config,
    decode,
    detect_encoding,
    encode,
)

# Reasonable subset: 15 presets x bits (1,2,4). Full 1-8 is available via
# the `slow` marker. Compression=True everywhere (the encode default).
PRESETS = list(CHANNEL_PRESETS.keys())
FAST_BITS = [1, 2, 4]
ALL_BITS = list(range(1, 9))

PAYLOAD_TEXT = b"round-trip probe: preset+bits sweep across the encoder"


def _capacity_ok(carrier, config, payload: bytes) -> bool:
    """Cheap capacity gate — skip combos where the payload can't fit."""
    from img_core import calculate_capacity
    cap = calculate_capacity(carrier, config)
    return cap["bytes_total"] >= len(payload) + 128


@pytest.mark.parametrize("preset", PRESETS)
@pytest.mark.parametrize("bits", FAST_BITS)
def test_roundtrip_fast(medium_carrier, preset, bits):
    config = create_config(channels=preset, bits=bits)
    if not _capacity_ok(medium_carrier, config, PAYLOAD_TEXT):
        pytest.skip(f"capacity too small for {preset}/{bits}")

    encoded = encode(medium_carrier, PAYLOAD_TEXT, config)
    decoded = decode(encoded, config)
    assert decoded == PAYLOAD_TEXT


@pytest.mark.slow
@pytest.mark.parametrize("preset", PRESETS)
@pytest.mark.parametrize("bits", ALL_BITS)
def test_roundtrip_full_matrix(medium_carrier, preset, bits):
    config = create_config(channels=preset, bits=bits)
    if not _capacity_ok(medium_carrier, config, PAYLOAD_TEXT):
        pytest.skip(f"capacity too small for {preset}/{bits}")

    encoded = encode(medium_carrier, PAYLOAD_TEXT, config)
    decoded = decode(encoded, config)
    assert decoded == PAYLOAD_TEXT


def test_roundtrip_preserves_all_byte_values(large_carrier):
    all_bytes = bytes(range(256)) * 4
    config = create_config(channels="RGB", bits=1)
    encoded = encode(large_carrier, all_bytes, config)
    assert decode(encoded, config) == all_bytes


def test_roundtrip_empty_payload(medium_carrier):
    config = create_config(channels="RGB", bits=1)
    encoded = encode(medium_carrier, b"", config)
    assert decode(encoded, config) == b""


def test_roundtrip_single_byte(medium_carrier):
    config = create_config(channels="RGB", bits=1)
    encoded = encode(medium_carrier, b"X", config)
    assert decode(encoded, config) == b"X"


def test_encode_rejects_oversize_payload(small_carrier):
    """Encoder should raise when the payload can't fit.

    Uses incompressible random bytes; a repeating payload would be shrunk
    to nothing by zlib and slip through the capacity gate.
    """
    import os
    config = create_config(channels="R", bits=1)
    # 100x100 * 1 channel * 1 bit = 1250 bytes total; header eats 32.
    huge = os.urandom(4000)
    with pytest.raises(ValueError, match=r"too large|exceeds"):
        encode(small_carrier, huge, config)


@pytest.mark.parametrize("strategy", ["sequential", "interleaved", "spread", "randomized"])
def test_strategies_roundtrip(medium_carrier, strategy):
    config = create_config(channels="RGB", bits=1, strategy=strategy, seed=42)
    encoded = encode(medium_carrier, PAYLOAD_TEXT, config)
    assert decode(encoded, config) == PAYLOAD_TEXT
