"""crypto module: AES-CBC / AES-GCM / XOR round-trip + wrong-password behavior."""

from __future__ import annotations

import pytest

import crypto

# The XOR path is always available; AES paths need the cryptography package.
AES_METHODS = ["aes-cbc", "aes-gcm"]
ALL_METHODS = AES_METHODS + ["xor"]


PLAINTEXT = b"crypto round-trip: hidden inside steg"
LONG_PLAINTEXT = bytes(range(256)) * 8  # exercise padding boundary


@pytest.mark.parametrize("method", ALL_METHODS)
def test_encrypt_decrypt_roundtrip(method):
    if method.startswith("aes-") and not crypto.HAS_CRYPTO:
        pytest.skip("cryptography library not installed")
    packed = crypto.encrypt(PLAINTEXT, "s3cret-pw", method=method)
    assert packed != PLAINTEXT
    assert crypto.decrypt(packed, "s3cret-pw") == PLAINTEXT


@pytest.mark.parametrize("method", ALL_METHODS)
def test_long_payload_roundtrip(method):
    if method.startswith("aes-") and not crypto.HAS_CRYPTO:
        pytest.skip("cryptography library not installed")
    packed = crypto.encrypt(LONG_PLAINTEXT, "another-pw", method=method)
    assert crypto.decrypt(packed, "another-pw") == LONG_PLAINTEXT


def test_wrong_password_aes_gcm_raises():
    if not crypto.HAS_CRYPTO:
        pytest.skip("cryptography library not installed")
    packed = crypto.encrypt(PLAINTEXT, "right-pw", method="aes-gcm")
    # GCM is authenticated — wrong key MUST fail loudly.
    with pytest.raises(Exception):
        crypto.decrypt(packed, "wrong-pw")


def test_wrong_password_aes_cbc_produces_wrong_output():
    if not crypto.HAS_CRYPTO:
        pytest.skip("cryptography library not installed")
    packed = crypto.encrypt(PLAINTEXT, "right-pw", method="aes-cbc")
    # CBC has no auth tag. Either the unpadder raises, or we get garbage.
    try:
        recovered = crypto.decrypt(packed, "wrong-pw")
    except Exception:
        return
    assert recovered != PLAINTEXT


def test_wrong_password_xor_produces_wrong_output():
    packed = crypto.encrypt(PLAINTEXT, "right-pw", method="xor")
    recovered = crypto.decrypt(packed, "wrong-pw")
    assert recovered != PLAINTEXT


def test_auto_method_picks_gcm_when_available():
    packed = crypto.encrypt(PLAINTEXT, "pw", method="auto")
    payload = crypto.unpack_payload(packed)
    if crypto.HAS_CRYPTO:
        assert payload.method == "aes-256-gcm"
    else:
        assert payload.method == "xor"


def test_unknown_method_raises():
    with pytest.raises(ValueError, match=r"Unknown encryption method"):
        crypto.encrypt(PLAINTEXT, "pw", method="rot13")


def test_available_methods_contains_xor():
    assert "xor" in crypto.get_available_methods()


def test_crypto_status_shape():
    status = crypto.crypto_status()
    assert set(status.keys()) == {"cryptography_available", "available_methods", "recommended"}
    assert status["recommended"] in {"aes-gcm", "xor"}
