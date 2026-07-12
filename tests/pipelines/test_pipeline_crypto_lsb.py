"""Pipeline #1 — crypto → LSB encode → LSB decode → decrypt.

  plaintext ──encrypt(pw)──▶ ciphertext ──encode(RGB/1bit)──▶ carrier.png
                                                                    │
                                                                    ▼
                                                              decode ── ciphertext' ── decrypt(pw) ──▶ plaintext'

Verifies (a) end-to-end round-trip and (b) wrong password fails.
Writes the produced PNG under examples/pipelines/ as a persistent showcase.
"""

from __future__ import annotations

import pytest

import crypto
from steg_core import create_config, decode, detect_encoding, encode

pytestmark = pytest.mark.pipeline

PLAINTEXT = b"crypto pipeline: authenticated payload behind LSB"


def _skip_if_no_crypto():
    if not crypto.HAS_CRYPTO:
        pytest.skip("cryptography library not installed")


def test_crypto_lsb_roundtrip(medium_carrier, pipelines_dir):
    _skip_if_no_crypto()
    password = "pipeline-pw"

    # Encrypt
    ciphertext = crypto.encrypt(PLAINTEXT, password, method="aes-gcm")
    # LSB-embed
    config = create_config(channels="RGB", bits=1)
    stego = encode(medium_carrier, ciphertext, config)
    # Persist artifact
    out_path = pipelines_dir / "pipeline_crypto_lsb.png"
    stego.save(out_path, format="PNG")

    # Intermediate assertion: the stego image is a valid STEG carrier.
    assert detect_encoding(stego) is not None

    # Decode + decrypt
    recovered_ct = decode(stego, config)
    recovered_pt = crypto.decrypt(recovered_ct, password)
    assert recovered_pt == PLAINTEXT


def test_crypto_lsb_wrong_password_rejects(medium_carrier):
    _skip_if_no_crypto()
    ciphertext = crypto.encrypt(PLAINTEXT, "right-pw", method="aes-gcm")
    config = create_config(channels="RGB", bits=1)
    stego = encode(medium_carrier, ciphertext, config)

    recovered_ct = decode(stego, config)
    # GCM = authenticated; wrong password must raise, not silently decode.
    with pytest.raises(Exception):
        crypto.decrypt(recovered_ct, "wrong-pw")
