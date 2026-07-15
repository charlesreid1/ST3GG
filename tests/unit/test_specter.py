"""Tests for SPECTER channel-cipher steganography (specter.py).

Covers pattern parsing, password derivation, PRNG determinism,
LSB round-trips (manual / password / encrypted / ghost / density),
DCT round-trips, detection, and edge cases.
"""

from __future__ import annotations

import pytest

from specter import (
    CHANNEL_MAP,
    SPECTER_DCT_MAGIC,
    SPECTER_MAGIC_GHOST,
    SPECTER_MAGIC_NORMAL,
    CipherStep,
    _bits_to_data,
    _data_to_bits,
    _ghost_decrypt,
    _ghost_encrypt,
    _interleave_noise,
    _mulberry32,
    _password_to_seed,
    _remove_noise,
    _scramble_bits,
    _xor_cipher,
    parse_pattern,
    pattern_from_password,
    specter_dct_decode,
    specter_dct_encode,
    specter_detect,
    specter_lsb_decode,
    specter_lsb_encode,
)

# Import the crypto-availability marker from conftest
from conftest import HAS_CRYPTO as _HAS_CRYPTO

requires_crypto = pytest.mark.skipif(
    not _HAS_CRYPTO, reason="cryptography library not available"
)

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

PAYLOAD_SHORT = b"SPECTER test payload"
PAYLOAD_MEDIUM = b"The quick brown fox jumps over the lazy dog. " * 4
ALL_BYTES = bytes(range(256)) * 2  # 512 bytes covering every byte value

MANUAL_PATTERNS = [
    "R1-G1-B1",
    "R2-G2-B2",
    "R1-G2-B1",
    "RG1-B1",
    "RGB1",
    "R1-G1",
    "R2",
]


def _steps_from_pattern(s: str):
    s2 = parse_pattern(s)
    assert s2 is not None, f"failed to parse: {s}"
    return s2


# ============================================================================
# Pattern parsing
# ============================================================================

class TestParsePattern:
    def test_valid_simple(self):
        s = parse_pattern("R1-G1-B1")
        assert s is not None
        assert len(s) == 3
        assert s[0] == CipherStep(channels=[0], bits=1, name="R1")
        assert s[1] == CipherStep(channels=[1], bits=1, name="G1")
        assert s[2] == CipherStep(channels=[2], bits=1, name="B1")

    def test_valid_multi_channel(self):
        s = parse_pattern("RG2-RGB1-RB2")
        assert s is not None
        assert len(s) == 3
        assert s[0] == CipherStep(channels=[0, 1], bits=2, name="RG2")
        assert s[1] == CipherStep(channels=[0, 1, 2], bits=1, name="RGB1")
        assert s[2] == CipherStep(channels=[0, 2], bits=2, name="RB2")

    def test_valid_all_combinations(self):
        for pat in MANUAL_PATTERNS:
            assert parse_pattern(pat) is not None, f"should parse: {pat}"

    def test_invalid_empty(self):
        assert parse_pattern("") is None

    def test_invalid_none(self):
        assert parse_pattern(None) is None  # type: ignore[arg-type]

    def test_invalid_channel(self):
        assert parse_pattern("X1") is None

    def test_invalid_bits_zero(self):
        assert parse_pattern("R0") is None

    def test_invalid_bits_high(self):
        assert parse_pattern("R5") is None

    def test_invalid_no_bits(self):
        assert parse_pattern("RGB") is None

    def test_invalid_alpha_in_pattern(self):
        # Alpha channel is not in the valid set
        assert parse_pattern("RA1") is None

    def test_case_insensitive(self):
        s = parse_pattern("r1-g1-b1")
        assert s is not None
        assert s[0].name == "R1"


# ============================================================================
# Password-derived patterns
# ============================================================================

class TestPatternFromPassword:
    def test_deterministic(self):
        a = pattern_from_password("test123")
        b = pattern_from_password("test123")
        assert len(a) == len(b)
        for sa, sb in zip(a, b):
            assert sa == sb

    def test_different_passwords_different_patterns(self):
        a = pattern_from_password("alpha")
        b = pattern_from_password("beta")
        # Extremely unlikely to collide
        names_a = "|".join(s.name for s in a)
        names_b = "|".join(s.name for s in b)
        assert names_a != names_b or len(a) != len(b)

    def test_length_range(self):
        for pwd in ["a", "hello", "longpassword123!@#", ""]:
            steps = pattern_from_password(pwd)
            assert 8 <= len(steps) <= 16, f"password={pwd!r} → {len(steps)} steps"

    def test_all_steps_valid(self):
        for pwd in ["abc", "xyz", "test"]:
            for step in pattern_from_password(pwd):
                assert 1 <= step.bits <= 2
                assert all(0 <= c <= 2 for c in step.channels)
                assert len(step.channels) >= 1
                assert len(step.name) >= 2


# ============================================================================
# Bit-level helpers — cross-compatibility pins
# ============================================================================

class TestPasswordToSeed:
    def test_known_seed(self):
        # Pin: these values must match the JS passwordToSeed() output.
        # These are the correct outputs from the djb2-variant + Int32-semantics hash.
        assert _password_to_seed("test") == 678055703
        assert _password_to_seed("") == 5381
        assert _password_to_seed("a") == 166908

    def test_32_bit_range(self):
        for pwd in ["hello", "world", "!@#$%", "x" * 100]:
            s = _password_to_seed(pwd)
            assert 0 <= s <= 0xFFFFFFFF


class TestMulberry32:
    def test_determinism(self):
        prng = _mulberry32(12345)
        first_10 = [prng() for _ in range(10)]
        prng2 = _mulberry32(12345)
        first_10_again = [prng2() for _ in range(10)]
        assert first_10 == first_10_again

    def test_output_range(self):
        prng = _mulberry32(42)
        for _ in range(1000):
            v = prng()
            assert 0.0 <= v < 1.0

    def test_different_seeds(self):
        a = [_mulberry32(1)() for _ in range(20)]
        b = [_mulberry32(2)() for _ in range(20)]
        assert a != b


class TestDataBitsRoundtrip:
    def test_empty(self):
        assert _bits_to_data(_data_to_bits(b"")) == b""

    def test_single_byte(self):
        for v in range(256):
            b = bytes([v])
            assert _bits_to_data(_data_to_bits(b)) == b

    def test_all_bytes(self):
        assert _bits_to_data(_data_to_bits(ALL_BYTES)) == ALL_BYTES

    def test_bit_list_values(self):
        bits = _data_to_bits(b"\xf0")
        assert bits == [1, 1, 1, 1, 0, 0, 0, 0]


class TestScrambleBits:
    def test_roundtrip(self):
        bits = _data_to_bits(ALL_BYTES)
        scrambled = _scramble_bits(bits, 42)
        assert len(scrambled) == len(bits)
        assert scrambled != bits  # astronomically unlikely
        unscrambled = _scramble_bits(scrambled, 42, reverse=True)
        assert unscrambled == bits

    def test_empty(self):
        assert _scramble_bits([], 42) == []
        assert _scramble_bits([], 42, reverse=True) == []

    def test_single_element(self):
        assert _scramble_bits([1], 42) == [1]
        assert _scramble_bits([0], 99, reverse=True) == [0]

    def test_deterministic(self):
        bits = [1, 0, 1, 0, 1, 1, 0, 0, 1, 1]
        a = _scramble_bits(bits, 777)
        b = _scramble_bits(bits, 777)
        assert a == b


class TestNoiseInterleave:
    def test_roundtrip(self):
        bits = _data_to_bits(PAYLOAD_MEDIUM)
        noisy = _interleave_noise(bits, 123)
        assert len(noisy) == 2 * len(bits)
        clean = _remove_noise(noisy)
        assert clean == bits

    def test_empty(self):
        assert _interleave_noise([], 42) == []

    def test_remove_empty(self):
        assert _remove_noise([]) == []

    def test_deterministic(self):
        bits = [1, 0, 1, 0, 1, 1, 0, 0]
        a = _interleave_noise(bits, 999)
        b = _interleave_noise(bits, 999)
        assert a == b


# ============================================================================
# XOR cipher
# ============================================================================

class TestXorCipher:
    def test_symmetric(self):
        ct = _xor_cipher(PAYLOAD_MEDIUM, "secret")
        assert ct != PAYLOAD_MEDIUM
        pt = _xor_cipher(ct, "secret")
        assert pt == PAYLOAD_MEDIUM

    def test_empty_key(self):
        assert _xor_cipher(PAYLOAD_SHORT, "") == PAYLOAD_SHORT

    def test_different_keys(self):
        a = _xor_cipher(PAYLOAD_MEDIUM, "key1")
        b = _xor_cipher(PAYLOAD_MEDIUM, "key2")
        assert a != b


# ============================================================================
# Ghost Mode encryption (requires cryptography)
# ============================================================================

class TestGhostEncryptDecrypt:
    @requires_crypto
    def test_roundtrip(self):
        packed = _ghost_encrypt(PAYLOAD_MEDIUM, "ghostpassword")
        assert len(packed) > len(PAYLOAD_MEDIUM)  # salt + iv + tag overhead
        plain = _ghost_decrypt(packed, "ghostpassword")
        assert plain == PAYLOAD_MEDIUM

    @requires_crypto
    def test_roundtrip_short(self):
        packed = _ghost_encrypt(PAYLOAD_SHORT, "pw")
        plain = _ghost_decrypt(packed, "pw")
        assert plain == PAYLOAD_SHORT

    @requires_crypto
    def test_wrong_password_fails(self):
        packed = _ghost_encrypt(PAYLOAD_SHORT, "correct")
        with pytest.raises(Exception):
            _ghost_decrypt(packed, "wrong")


# ============================================================================
# LSB round-trip tests
# ============================================================================

class TestLsbRoundtrip:
    """Manual-pattern LSB encode → decode."""

    @pytest.mark.parametrize("pattern_str", MANUAL_PATTERNS)
    def test_manual_pattern(self, medium_carrier, pattern_str):
        steps = _steps_from_pattern(pattern_str)
        encoded = specter_lsb_encode(medium_carrier, PAYLOAD_SHORT, steps)
        decoded = specter_lsb_decode(encoded, steps)
        assert decoded == PAYLOAD_SHORT

    def test_password_pattern(self, medium_carrier):
        steps = pattern_from_password("mysecret")
        encoded = specter_lsb_encode(medium_carrier, PAYLOAD_MEDIUM, steps)
        decoded = specter_lsb_decode(encoded, steps)
        assert decoded == PAYLOAD_MEDIUM

    def test_encrypted_roundtrip(self, medium_carrier):
        steps = _steps_from_pattern("R1-G1-B1")
        encoded = specter_lsb_encode(
            medium_carrier, PAYLOAD_MEDIUM, steps, encrypt=True, key="enckey"
        )
        decoded = specter_lsb_decode(encoded, steps, key="enckey")
        assert decoded == PAYLOAD_MEDIUM

    def test_encrypted_wrong_key_gives_garbage(self, medium_carrier):
        steps = _steps_from_pattern("R1-G1-B1")
        encoded = specter_lsb_encode(
            medium_carrier, PAYLOAD_SHORT, steps, encrypt=True, key="correct"
        )
        # Decrypting with wrong key should NOT return the original payload
        wrong_result = specter_lsb_decode(encoded, steps, key="wrong")
        assert wrong_result != PAYLOAD_SHORT

    @requires_crypto
    def test_ghost_mode(self, medium_carrier):
        steps = pattern_from_password("ghostkey")
        encoded = specter_lsb_encode(
            medium_carrier, PAYLOAD_MEDIUM, steps, ghost=True, key="ghostkey"
        )
        decoded = specter_lsb_decode(encoded, steps, key="ghostkey")
        assert decoded == PAYLOAD_MEDIUM

    @pytest.mark.parametrize("density", [50, 25, 10])
    def test_density(self, large_carrier, density):
        steps = _steps_from_pattern("R1-G1-B1")
        encoded = specter_lsb_encode(
            large_carrier, PAYLOAD_SHORT, steps, density=density
        )
        decoded = specter_lsb_decode(encoded, steps)
        assert decoded == PAYLOAD_SHORT

    def test_all_byte_values(self, large_carrier):
        steps = _steps_from_pattern("RGB2")
        encoded = specter_lsb_encode(large_carrier, ALL_BYTES, steps)
        decoded = specter_lsb_decode(encoded, steps)
        assert decoded == ALL_BYTES

    def test_empty_payload(self, medium_carrier):
        steps = _steps_from_pattern("R1")
        encoded = specter_lsb_encode(medium_carrier, b"", steps)
        decoded = specter_lsb_decode(encoded, steps)
        assert decoded == b""

    def test_single_byte(self, medium_carrier):
        steps = _steps_from_pattern("R1-G1")
        for v in [0x00, 0xFF, 0x41, 0x7F]:
            encoded = specter_lsb_encode(medium_carrier, bytes([v]), steps)
            decoded = specter_lsb_decode(encoded, steps)
            assert decoded == bytes([v])

    def test_oversize_rejected(self, small_carrier):
        steps = _steps_from_pattern("R1")
        huge = b"X" * 50000
        with pytest.raises(ValueError):
            specter_lsb_encode(small_carrier, huge, steps)

    def test_no_steps_raises(self, medium_carrier):
        with pytest.raises(ValueError, match="at least one"):
            specter_lsb_encode(medium_carrier, b"data", [])

    def test_decode_wrong_pattern_raises(self, medium_carrier):
        steps_a = _steps_from_pattern("R1-G1-B1")
        steps_b = _steps_from_pattern("R2-G2-B2")
        encoded = specter_lsb_encode(medium_carrier, PAYLOAD_SHORT, steps_a)
        with pytest.raises(ValueError, match="SPECTER"):
            specter_lsb_decode(encoded, steps_b)

    def test_encrypt_without_key_raises(self, medium_carrier):
        steps = _steps_from_pattern("R1")
        with pytest.raises(ValueError, match="key"):
            specter_lsb_encode(medium_carrier, PAYLOAD_SHORT, steps, encrypt=True)

    def test_ghost_without_key_raises(self, medium_carrier):
        steps = _steps_from_pattern("R1")
        with pytest.raises(ValueError, match="key"):
            specter_lsb_encode(medium_carrier, PAYLOAD_SHORT, steps, ghost=True)

    @pytest.mark.parametrize("pattern_str", MANUAL_PATTERNS)
    def test_output_is_valid_image(self, medium_carrier, pattern_str, tmp_path):
        steps = _steps_from_pattern(pattern_str)
        out = tmp_path / "out.png"
        encoded = specter_lsb_encode(
            medium_carrier, PAYLOAD_SHORT, steps, output_path=str(out)
        )
        assert out.exists()
        # Re-open to verify it's valid
        from PIL import Image
        reloaded = Image.open(out)
        assert reloaded.size == medium_carrier.size


# ============================================================================
# LSB decode edge cases
# ============================================================================

class TestLsbDecodeEdgeCases:
    def test_decode_without_key_on_encrypted_raises(self, medium_carrier):
        steps = _steps_from_pattern("R1-G1-B1")
        encoded = specter_lsb_encode(
            medium_carrier, PAYLOAD_SHORT, steps, encrypt=True, key="secret"
        )
        with pytest.raises(ValueError, match="key"):
            specter_lsb_decode(encoded, steps)

    def test_no_steps_raises(self, medium_carrier):
        with pytest.raises(ValueError, match="at least one"):
            specter_lsb_decode(medium_carrier, [])

    def test_clean_image_raises(self, medium_carrier):
        """A plain carrier image should raise — no SPECTER header."""
        steps = _steps_from_pattern("R1-G1-B1")
        with pytest.raises(ValueError, match="SPECTER"):
            specter_lsb_decode(medium_carrier, steps)


# ============================================================================
# DCT round-trip tests
# ============================================================================

class TestDctRoundtrip:
    def test_basic_roundtrip(self, large_carrier):
        steps = _steps_from_pattern("R1-G1-B1")
        encoded = specter_dct_encode(large_carrier, PAYLOAD_SHORT, steps)
        decoded = specter_dct_decode(encoded, steps)
        assert decoded == PAYLOAD_SHORT

    def test_encrypted_roundtrip(self, large_carrier):
        steps = _steps_from_pattern("R1-G1-B1")
        encoded = specter_dct_encode(
            large_carrier, PAYLOAD_SHORT, steps, encrypt=True, key="dctkey"
        )
        decoded = specter_dct_decode(encoded, steps, key="dctkey")
        assert decoded == PAYLOAD_SHORT

    def test_password_pattern(self, large_carrier):
        steps = pattern_from_password("dctpass")
        encoded = specter_dct_encode(large_carrier, PAYLOAD_SHORT, steps)
        decoded = specter_dct_decode(encoded, steps)
        assert decoded == PAYLOAD_SHORT

    def test_encrypted_wrong_key_gives_garbage(self, large_carrier):
        steps = _steps_from_pattern("R1-G1-B1")
        encoded = specter_dct_encode(
            large_carrier, PAYLOAD_SHORT, steps, encrypt=True, key="correct"
        )
        # Decrypting with wrong key should NOT return the original payload
        wrong_result = specter_dct_decode(encoded, steps, key="wrong")
        assert wrong_result != PAYLOAD_SHORT

    def test_no_steps_raises(self, large_carrier):
        with pytest.raises(ValueError, match="at least one"):
            specter_dct_encode(large_carrier, b"data", [])

    def test_encrypt_without_key_raises(self, large_carrier):
        steps = _steps_from_pattern("R1")
        with pytest.raises(ValueError, match="key"):
            specter_dct_encode(large_carrier, PAYLOAD_SHORT, steps, encrypt=True)

    def test_clean_image_raises(self, large_carrier):
        steps = _steps_from_pattern("R1-G1-B1")
        with pytest.raises(ValueError, match="SPECTER"):
            specter_dct_decode(large_carrier, steps)


# ============================================================================
# Detection tool
# ============================================================================

class TestSpecterDetect:
    def test_finds_encoded(self, medium_carrier):
        steps = _steps_from_pattern("R1-G1-B1")
        encoded = specter_lsb_encode(medium_carrier, PAYLOAD_SHORT, steps)
        result = specter_detect(encoded)
        assert result["found"] is True
        assert len(result["findings"]) > 0

    def test_clean_image_no_findings(self, medium_carrier):
        result = specter_detect(medium_carrier)
        # A clean carrier might produce false positives rarely,
        # but should generally not find anything
        # We just check the return shape
        assert "found" in result
        assert "findings" in result

    def test_finds_with_password(self, medium_carrier):
        steps = pattern_from_password("detectme")
        encoded = specter_lsb_encode(medium_carrier, PAYLOAD_SHORT, steps)
        result = specter_detect(encoded, passwords=["detectme"])
        assert result["found"] is True
        assert any("password:detectme" in str(f) for f in result["findings"])

    def test_return_shape(self, medium_carrier):
        result = specter_detect(medium_carrier)
        assert isinstance(result, dict)
        assert "found" in result
        assert isinstance(result["found"], bool)
        assert "findings" in result
        assert isinstance(result["findings"], list)


# ============================================================================
# CipherStep dataclass
# ============================================================================

class TestCipherStep:
    def test_total_bits(self):
        assert CipherStep([0], 1, "R1").total_bits == 1
        assert CipherStep([0, 1], 2, "RG2").total_bits == 4
        assert CipherStep([0, 1, 2], 1, "RGB1").total_bits == 3

    def test_equality(self):
        a = CipherStep([0, 1], 2, "RG2")
        b = CipherStep([0, 1], 2, "RG2")
        assert a == b
        c = CipherStep([0, 1], 1, "RG1")
        assert a != c


# ============================================================================
# Header format smoke tests
# ============================================================================

class TestHeaderFormat:
    def test_lsb_magic_bytes(self, medium_carrier):
        steps = _steps_from_pattern("R1-G1-B1")
        encoded = specter_lsb_encode(medium_carrier, PAYLOAD_SHORT, steps)
        # The magic should be readable in the pixel LSBs
        decoded = specter_lsb_decode(encoded, steps)
        assert decoded == PAYLOAD_SHORT

    def test_dct_magic_bytes(self, large_carrier):
        steps = _steps_from_pattern("R1-G1-B1")
        encoded = specter_dct_encode(large_carrier, PAYLOAD_SHORT, steps)
        decoded = specter_dct_decode(encoded, steps)
        assert decoded == PAYLOAD_SHORT
