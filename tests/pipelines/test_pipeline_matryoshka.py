"""Pipeline #2 — Matryoshka (nested PNG-in-PNG-in-PNG).

  secret ── encode(inner) ── PNG ── encode(middle) ── PNG ── encode(outer) ── outer.png
                                                                                 │
                                                                                 ▼
                                                            (recursive decode) ── secret

Note: `test_matryoshka.py` (repo root) already covers the plumbing extensively.
This test only walks one 3-layer end-to-end and writes the artifact.
"""

from __future__ import annotations

import io

import pytest
from PIL import Image

from img_core import create_config, decode, encode

pytestmark = pytest.mark.pipeline

SECRET = b"innermost matryoshka payload"


def _encode_png(carrier, data, config):
    stego = encode(carrier, data, config)
    buf = io.BytesIO()
    stego.save(buf, format="PNG")
    return stego, buf.getvalue()


def test_three_layer_matryoshka_roundtrip(pipelines_dir):
    inner_carrier = Image.new("RGBA", (150, 150), (128, 128, 128, 255))
    middle_carrier = Image.new("RGBA", (350, 350), (100, 150, 200, 255))
    outer_carrier = Image.new("RGBA", (600, 600), (64, 128, 192, 255))

    config = create_config(channels="RGB", bits=1)

    # Layer 1: hide SECRET inside inner.
    _, inner_png = _encode_png(inner_carrier, SECRET, config)
    assert inner_png.startswith(b"\x89PNG\r\n\x1a\n")

    # Layer 2: hide inner.png inside middle.
    _, middle_png = _encode_png(middle_carrier, inner_png, config)
    assert middle_png.startswith(b"\x89PNG\r\n\x1a\n")

    # Layer 3: hide middle.png inside outer.
    outer_stego, outer_png = _encode_png(outer_carrier, middle_png, config)

    out_path = pipelines_dir / "pipeline_matryoshka.png"
    outer_stego.save(out_path, format="PNG")

    # Recursive decode
    l1 = decode(outer_stego, config)
    assert l1[:8] == b"\x89PNG\r\n\x1a\n"
    l2 = decode(Image.open(io.BytesIO(l1)), config)
    assert l2[:8] == b"\x89PNG\r\n\x1a\n"
    l3 = decode(Image.open(io.BytesIO(l2)), config)
    assert l3 == SECRET
