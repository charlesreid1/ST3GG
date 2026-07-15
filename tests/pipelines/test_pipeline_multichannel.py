"""Pipeline #5 — Multi-channel split.

Two independent payloads: one into R-only, another into G-only. Decoding each
channel yields exactly its payload, and neither leaks the other.
"""

from __future__ import annotations

import io

import pytest
from PIL import Image

from img_core import create_config, decode, encode

pytestmark = pytest.mark.pipeline

PAYLOAD_A = b"channel A: this belongs in the red LSBs"
PAYLOAD_B = b"channel B: this belongs in the green LSBs"


def test_multichannel_split(large_carrier, pipelines_dir):
    config_r = create_config(channels="R", bits=1)
    config_g = create_config(channels="G", bits=1)

    # Encode into R then G. Each config only touches its own channel, so writes
    # to G do not clobber the R payload.
    step1 = encode(large_carrier, PAYLOAD_A, config_r)
    step2 = encode(step1, PAYLOAD_B, config_g)

    out = pipelines_dir / "pipeline_multichannel.png"
    step2.save(out, format="PNG")

    # Recover each half independently.
    assert decode(step2, config_r) == PAYLOAD_A
    assert decode(step2, config_g) == PAYLOAD_B


def test_multichannel_r_config_does_not_yield_g_payload(large_carrier):
    config_r = create_config(channels="R", bits=1)
    config_g = create_config(channels="G", bits=1)

    step1 = encode(large_carrier, PAYLOAD_A, config_r)
    step2 = encode(step1, PAYLOAD_B, config_g)

    # If you decode with config_r you must not accidentally see PAYLOAD_B.
    r_output = decode(step2, config_r)
    assert PAYLOAD_B not in r_output
    assert r_output == PAYLOAD_A
