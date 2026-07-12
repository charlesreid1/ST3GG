"""Pipeline #6 — Covert-text: crypto → base64 → zero-width Unicode → Markdown.

  plaintext ──encrypt(pw)──▶ ciphertext ──b64──▶ ascii ──bit→ZW-map──▶ payload_chars
      innocuous_md.md + payload_chars  =  markdown_with_hidden_payload.md
                                                    │
                                                    ▼
                                    strip zw → ascii bits → b64 decode → decrypt → plaintext
"""

from __future__ import annotations

import base64

import pytest

import crypto

pytestmark = pytest.mark.pipeline

# U+200B / U+200C: zero-width space and zero-width non-joiner.
ZW_ZERO = "​"
ZW_ONE = "‌"

PLAINTEXT = b"the covert-text pipeline works end-to-end"
MARKDOWN_CARRIER = "# Recipe: Sourdough\n\nMix flour and water. Rest overnight. Bake at 500 degrees.\n"


def _bytes_to_zerowidth(data: bytes) -> str:
    return "".join(ZW_ONE if bit else ZW_ZERO
                   for byte in data
                   for bit in (byte >> (7 - i) & 1 for i in range(8)))


def _zerowidth_to_bytes(text: str) -> bytes:
    bits = [1 if c == ZW_ONE else 0
            for c in text if c in (ZW_ZERO, ZW_ONE)]
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


def test_covert_text_pipeline_roundtrip(pipelines_dir):
    if not crypto.HAS_CRYPTO:
        pytest.skip("cryptography library not installed")
    password = "covert-pw"

    # 1. Encrypt.
    ciphertext = crypto.encrypt(PLAINTEXT, password, method="aes-gcm")
    # 2. Base64.
    b64 = base64.b64encode(ciphertext)
    # 3. Encode as zero-width bits.
    zw_payload = _bytes_to_zerowidth(b64)
    # 4. Splice into the carrier markdown between the heading and body.
    lines = MARKDOWN_CARRIER.split("\n", 1)
    md_with_payload = lines[0] + zw_payload + "\n" + (lines[1] if len(lines) > 1 else "")

    out = pipelines_dir / "pipeline_covert_text.md"
    out.write_text(md_with_payload, encoding="utf-8")

    # Recover
    recovered_zw = out.read_text(encoding="utf-8")
    recovered_b64 = _zerowidth_to_bytes(recovered_zw)
    recovered_ct = base64.b64decode(recovered_b64)
    recovered_pt = crypto.decrypt(recovered_ct, password)
    assert recovered_pt == PLAINTEXT

    # The carrier remains legible without the zero-width characters.
    visible = "".join(c for c in recovered_zw if c not in (ZW_ZERO, ZW_ONE))
    assert "Sourdough" in visible
