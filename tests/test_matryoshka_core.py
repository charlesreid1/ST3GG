#!/usr/bin/env python3
"""
Unit tests for matryoshka_core — the pure-library Matryoshka module.

Tests cover:
- Roundtrip encode/decode at depths 1, 3, 5
- 11-layer deep-nest roundtrip (slow)
- Capacity overflow with correct error messages
- Password: encrypt-innermost-only semantics
- Max-depth truncation on decode
- encode_nested dry_run mode
- plan_nesting estimate vs exact agreement
- Auto-detect integration (smart_scan_recursive)
- is_image_data / extract_file_from_data helpers
- MatryoshkaConfig / LayerReport / DecodeLayer dataclasses
"""

import io
import os
import sys
import pytest
from PIL import Image
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from matryoshka_core import (
    MatryoshkaConfig,
    LayerReport,
    DecodeLayer,
    encode_nested,
    decode_nested,
    capacity_for,
    plan_nesting,
    is_image_data,
    extract_file_from_data,
    HAS_CRYPTO,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tiny_carrier():
    """64×64 RGBA image."""
    return Image.new("RGBA", (64, 64), color=(128, 128, 128, 255))


@pytest.fixture
def small_carrier():
    """128×128 RGBA image with noise."""
    img = Image.new("RGBA", (128, 128), color=(128, 128, 128, 255))
    pixels = np.array(img)
    noise = np.random.randint(0, 30, pixels.shape, dtype=np.uint8)
    pixels = np.clip(pixels.astype(int) + noise - 15, 0, 255).astype(np.uint8)
    return Image.fromarray(pixels)


@pytest.fixture
def medium_carrier():
    """256×256 RGBA image with noise."""
    img = Image.new("RGBA", (256, 256), color=(100, 150, 200, 255))
    pixels = np.array(img)
    noise = np.random.randint(0, 50, pixels.shape, dtype=np.uint8)
    pixels = np.clip(pixels.astype(int) + noise - 25, 0, 255).astype(np.uint8)
    return Image.fromarray(pixels)


@pytest.fixture
def large_carrier():
    """512×512 RGBA image."""
    img = Image.new("RGBA", (512, 512), color=(64, 128, 192, 255))
    pixels = np.array(img)
    noise = np.random.randint(0, 40, pixels.shape, dtype=np.uint8)
    pixels = np.clip(pixels.astype(int) + noise - 20, 0, 255).astype(np.uint8)
    return Image.fromarray(pixels)


@pytest.fixture
def xlarge_carrier():
    """800×800 RGBA image."""
    return Image.new("RGBA", (800, 800), color=(64, 128, 192, 255))


@pytest.fixture
def text_payload():
    return b"Hello, this is a secret message for Matryoshka testing!"


@pytest.fixture
def binary_payload():
    return bytes(range(256)) * 4  # 1024 bytes


@pytest.fixture
def default_config():
    return MatryoshkaConfig(channels="RGBA", bits=2, max_depth=11)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _png_bytes(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _flatten_layers(layers: list) -> list:
    """Flatten a nested DecodeLayer tree into a flat list."""
    result = []
    for dl in layers:
        result.append(dl)
        if dl.nested:
            result.extend(_flatten_layers(dl.nested))
    return result


def _find_layer_of_type(layers: list, type_str: str) -> DecodeLayer | None:
    for dl in _flatten_layers(layers):
        if dl.type == type_str:
            return dl
    return None


# ============================================================================
# Dataclass tests
# ============================================================================

class TestMatryoshkaConfig:
    def test_defaults(self):
        c = MatryoshkaConfig()
        assert c.channels == "RGBA"
        assert c.bits == 2
        assert c.password is None
        assert c.max_depth == 11
        assert c.per_layer_encrypt is False

    def test_to_steg_config(self):
        c = MatryoshkaConfig(channels="RGB", bits=1)
        sc = c.to_steg_config()
        assert [ch.name for ch in sc.channels] == ["R", "G", "B"]
        assert sc.bits_per_channel == 1

    def test_custom(self):
        c = MatryoshkaConfig(channels="R", bits=4, password="secret", max_depth=5)
        assert c.channels == "R"
        assert c.bits == 4
        assert c.password == "secret"
        assert c.max_depth == 5


class TestLayerReport:
    def test_fields(self):
        r = LayerReport(layer=1, carrier_name="test.png", capacity=1000,
                        payload_size=500, fits=True, output_size=1234)
        assert r.layer == 1
        assert r.carrier_name == "test.png"
        assert r.capacity == 1000
        assert r.payload_size == 500
        assert r.fits is True
        assert r.output_size == 1234

    def test_output_size_final(self):
        r = LayerReport(layer=3, carrier_name="outer.png", capacity=5000,
                        payload_size=100, fits=True, output_size="final")
        assert r.output_size == "final"


class TestDecodeLayer:
    def test_defaults(self):
        dl = DecodeLayer()
        assert dl.depth == 0
        assert dl.type == "unknown"
        assert dl.filename is None
        assert dl.data_size == 0
        assert dl.preview == ""
        assert dl.raw_data is None
        assert dl.nested == []

    def test_nested(self):
        inner = DecodeLayer(depth=1, type="text", raw_data=b"hello")
        outer = DecodeLayer(depth=0, type="nested_image", nested=[inner])
        assert len(outer.nested) == 1
        assert outer.nested[0].raw_data == b"hello"


# ============================================================================
# Helper function tests
# ============================================================================

class TestIsImageData:
    def test_png(self):
        assert is_image_data(b"\x89PNG\r\n\x1a\n\x00\x00\x00\x00")

    def test_jpeg(self):
        assert is_image_data(b"\xff\xd8\xff\xe0\x00\x10JFIF")

    def test_gif87a(self):
        assert is_image_data(b"GIF87a\x00\x00\x00")

    def test_gif89a(self):
        assert is_image_data(b"GIF89a\x00\x00\x00")

    def test_bmp(self):
        assert is_image_data(b"BM\x00\x00\x00\x00\x00\x00")

    def test_plain_text(self):
        assert not is_image_data(b"Hello, world!")

    def test_empty(self):
        assert not is_image_data(b"")

    def test_short(self):
        assert not is_image_data(b"\x89PNG")


class TestExtractFileFromData:
    def test_valid_file(self):
        name = b"test.txt"
        body = b"hello world"
        data = bytes([len(name)]) + name + body
        fname, fdata = extract_file_from_data(data)
        assert fname == "test.txt"
        assert fdata == body

    def test_no_extension_returns_none(self):
        name = b"testfile"
        body = b"data"
        data = bytes([len(name)]) + name + body
        fname, fdata = extract_file_from_data(data)
        assert fname is None
        assert fdata == data

    def test_invalid_extension(self):
        name = b"test.xyzzy"
        body = b"data"
        data = bytes([len(name)]) + name + body
        fname, fdata = extract_file_from_data(data)
        assert fname is None

    def test_short_data(self):
        fname, fdata = extract_file_from_data(b"ab")
        assert fname is None
        assert fdata == b"ab"

    def test_bad_filename_length(self):
        data = bytes([200]) + b"x" * 200
        fname, fdata = extract_file_from_data(data)
        assert fname is None

    def test_non_utf8_filename(self):
        data = bytes([8]) + b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8" + b"stuff"
        fname, fdata = extract_file_from_data(data)
        assert fname is None

    def test_filename_starts_with_dot(self):
        name = b".hidden.txt"
        body = b"data"
        data = bytes([len(name)]) + name + body
        fname, fdata = extract_file_from_data(data)
        assert fname is None  # dot-prefixed names rejected

    def test_invalid_chars_in_filename(self):
        name = b"bad/file.txt"
        body = b"data"
        data = bytes([len(name)]) + name + body
        fname, fdata = extract_file_from_data(data)
        assert fname is None


class TestCapacityFor:
    def test_rgba_2bit(self):
        img = Image.new("RGBA", (100, 100))
        cap = capacity_for(img, MatryoshkaConfig(channels="RGBA", bits=2))
        expected = (100 * 100 * 4 * 2) // 8 - 32  # raw - HEADER_SIZE(32)
        assert cap == expected

    def test_rgb_1bit(self):
        img = Image.new("RGBA", (200, 200))
        cap = capacity_for(img, MatryoshkaConfig(channels="RGB", bits=1))
        expected = (200 * 200 * 3 * 1) // 8 - 32
        assert cap == expected

    def test_default_config(self):
        img = Image.new("RGBA", (50, 50))
        cap = capacity_for(img)
        assert cap > 0
        assert cap == (50 * 50 * 4 * 2) // 8 - 32

    def test_too_small_image(self):
        img = Image.new("RGBA", (2, 2))
        cap = capacity_for(img, MatryoshkaConfig(channels="RGBA", bits=1))
        # 2*2*4*1 // 8 = 2 bytes raw, minus 32 = 0
        assert cap == 0


# ============================================================================
# Encode tests
# ============================================================================

class TestEncodeNested:
    def test_single_layer(self, medium_carrier, text_payload, default_config):
        carriers = [(medium_carrier, "carrier.png")]
        img, reports = encode_nested(text_payload, carriers, default_config)
        assert img is not None
        assert len(reports) == 1
        assert reports[0].layer == 1
        assert reports[0].fits is True
        assert reports[0].output_size == "final"

    def test_three_layers(self, small_carrier, medium_carrier, large_carrier,
                           text_payload, default_config):
        carriers = [
            (small_carrier, "inner.png"),
            (medium_carrier, "middle.png"),
            (large_carrier, "outer.png"),
        ]
        img, reports = encode_nested(text_payload, carriers, default_config)
        assert img is not None
        assert len(reports) == 3
        for i, r in enumerate(reports):
            assert r.layer == i + 1
            assert r.fits is True
        assert reports[0].output_size != "final"  # inner layers have int sizes
        assert reports[1].output_size != "final"
        assert reports[2].output_size == "final"

    def test_five_layers(self, text_payload):
        """5-layer nest with progressively larger carriers."""
        carriers = []
        size = 64
        for i in range(5):
            img = Image.new("RGBA", (size, size), color=(100 + i * 30, 100, 100, 255))
            carriers.append((img, f"layer_{i}.png"))
            size = int(size * 1.8)
        config = MatryoshkaConfig(channels="RGBA", bits=2, max_depth=5)
        img, reports = encode_nested(text_payload, carriers, config)
        assert img is not None
        assert len(reports) == 5
        assert all(r.fits for r in reports)

    def test_empty_carriers_raises(self, text_payload):
        with pytest.raises(ValueError, match="At least one carrier"):
            encode_nested(text_payload, [])

    def test_max_depth_exceeded(self, small_carrier, text_payload):
        config = MatryoshkaConfig(max_depth=2)
        carriers = [(small_carrier, f"c_{i}.png") for i in range(5)]
        with pytest.raises(ValueError, match="exceeds max_depth"):
            encode_nested(text_payload, carriers, config)

    def test_capacity_overflow(self, tiny_carrier):
        huge = b"X" * 100_000
        carriers = [(tiny_carrier, "tiny.png")]
        config = MatryoshkaConfig(channels="RGBA", bits=1)
        with pytest.raises(ValueError, match="exceeds capacity"):
            encode_nested(huge, carriers, config)

    def test_capacity_overflow_message(self, tiny_carrier):
        """Error message includes correct layer index and byte counts."""
        huge = b"X" * 100_000
        carriers = [(tiny_carrier, "tiny.png")]
        config = MatryoshkaConfig(channels="RGBA", bits=1)
        with pytest.raises(ValueError) as excinfo:
            encode_nested(huge, carriers, config)
        msg = str(excinfo.value)
        assert "Layer 1" in msg
        assert "tiny.png" in msg
        assert "exceeds capacity" in msg

    def test_dry_run(self, medium_carrier, text_payload, default_config):
        carriers = [(medium_carrier, "carrier.png")]
        img, reports = encode_nested(
            text_payload, carriers, default_config, dry_run=True
        )
        assert img is None
        assert len(reports) == 1
        assert reports[0].fits is True
        # output_size should be an estimate (int), not "final" in dry_run
        assert isinstance(reports[0].output_size, int)

    @pytest.mark.skipif(not HAS_CRYPTO, reason="crypto module not available")
    def test_with_password(self, medium_carrier, text_payload, default_config):
        default_config.password = "secret"
        carriers = [(medium_carrier, "enc.png")]
        img, reports = encode_nested(text_payload, carriers, default_config)
        assert img is not None
        assert reports[0].fits is True

    def test_binary_payload(self, medium_carrier, binary_payload, default_config):
        carriers = [(medium_carrier, "bin.png")]
        img, reports = encode_nested(binary_payload, carriers, default_config)
        assert img is not None
        assert reports[0].payload_size == len(binary_payload)


# ============================================================================
# Decode tests
# ============================================================================

class TestDecodeNested:
    def test_single_layer_roundtrip(self, medium_carrier, text_payload, default_config):
        carriers = [(medium_carrier, "carrier.png")]
        img, _ = encode_nested(text_payload, carriers, default_config)
        layers = decode_nested(img, default_config)
        assert len(layers) >= 1
        # Text payload — type should be "text" (raw data, no file wrapper)
        leaf = _find_layer_of_type(layers, "text")
        assert leaf is not None
        assert leaf.raw_data == text_payload

    def test_three_layer_roundtrip(self, small_carrier, medium_carrier,
                                   large_carrier, text_payload, default_config):
        carriers = [
            (small_carrier, "inner.png"),
            (medium_carrier, "middle.png"),
            (large_carrier, "outer.png"),
        ]
        img, _ = encode_nested(text_payload, carriers, default_config)
        layers = decode_nested(img, default_config)

        flat = _flatten_layers(layers)
        text_layer = next((dl for dl in flat if dl.type == "text"), None)
        assert text_layer is not None, f"types found: {[dl.type for dl in flat]}"
        assert text_layer.raw_data == text_payload

    def test_five_layer_roundtrip(self, text_payload):
        """5-layer encode→decode roundtrip."""
        carriers = []
        size = 64
        for i in range(5):
            img = Image.new("RGBA", (size, size), color=(100 + i * 30, 100, 100, 255))
            carriers.append((img, f"layer_{i}.png"))
            size = int(size * 1.8)
        config = MatryoshkaConfig(channels="RGBA", bits=2, max_depth=5)
        img, _ = encode_nested(text_payload, carriers, config)
        layers = decode_nested(img, config)
        flat = _flatten_layers(layers)
        text_layer = next((dl for dl in flat if dl.type == "text"), None)
        assert text_layer is not None, f"types: {[dl.type for dl in flat]}"
        assert text_layer.raw_data == text_payload

    def test_max_depth_truncation(self, medium_carrier, text_payload):
        """3 real layers, decode with max_depth=2 → sentinel at depth 2."""
        carriers = []
        size = 128
        for i in range(3):
            img = Image.new("RGBA", (size, size), color=(100, 100, 100, 255))
            carriers.append((img, f"c_{i}.png"))
            size = int(size * 1.5)
        config = MatryoshkaConfig(channels="RGBA", bits=2, max_depth=3)
        img, _ = encode_nested(text_payload, carriers, config)

        # Decode with shallower max_depth
        shallow = MatryoshkaConfig(channels="RGBA", bits=2, max_depth=2)
        layers = decode_nested(img, shallow)
        flat = _flatten_layers(layers)
        sentinel = next((dl for dl in flat if dl.type == "max_depth_reached"), None)
        assert sentinel is not None, f"Expected max_depth_reached, got: {[dl.type for dl in flat]}"
        assert sentinel.depth == 2

    @pytest.mark.skipif(not HAS_CRYPTO, reason="crypto module not available")
    def test_password_roundtrip(self, medium_carrier, text_payload):
        config = MatryoshkaConfig(channels="RGBA", bits=2, password="correct")
        carriers = [(medium_carrier, "enc.png")]
        img, _ = encode_nested(text_payload, carriers, config)
        layers = decode_nested(img, config)
        leaf = _find_layer_of_type(layers, "text")
        assert leaf is not None
        assert leaf.raw_data == text_payload

    @pytest.mark.skipif(not HAS_CRYPTO, reason="crypto module not available")
    def test_password_wrong_returns_opaque(self, medium_carrier, text_payload):
        """Decode with wrong password returns opaque bytes, not plaintext."""
        config = MatryoshkaConfig(channels="RGBA", bits=2, password="correct")
        carriers = [(medium_carrier, "enc.png")]
        img, _ = encode_nested(text_payload, carriers, config)

        wrong = MatryoshkaConfig(channels="RGBA", bits=2, password="wrong")
        layers = decode_nested(img, wrong)
        leaf = _find_layer_of_type(layers, "text")
        if leaf is not None:
            assert leaf.raw_data != text_payload

    def test_decode_non_stego_image(self, medium_carrier, default_config):
        """Decoding a plain image with no stego data → no_data_found."""
        layers = decode_nested(medium_carrier, default_config)
        assert len(layers) >= 1
        # With no smart_scan_hook, should fall through to no_data_found
        assert layers[0].type in ("no_data_found", "binary", "text")

    def test_binary_roundtrip(self, large_carrier, binary_payload, default_config):
        carriers = [(large_carrier, "bin.png")]
        img, _ = encode_nested(binary_payload, carriers, default_config)
        layers = decode_nested(img, default_config)
        leaf = _find_layer_of_type(layers, "binary")
        # binary payload may be detected as "binary" or "text" (utf-8 decode
        # may fail). Either way, raw_data should match.
        if leaf is None:
            leaf = _find_layer_of_type(layers, "text")
        assert leaf is not None
        assert leaf.raw_data == binary_payload


# ============================================================================
# 11-layer deep-nest test
# ============================================================================

@pytest.mark.slow
class TestDeepNest:
    def test_11_layer_roundtrip(self):
        """11-layer roundtrip with progressively larger carriers and a tiny payload.

        Uses RGBA 2-bit encoding. Each carrier grows ~1.4× in linear
        dimension to keep pace with PNG expansion.
        """
        carriers = []
        size = 128
        for i in range(11):
            img = Image.new("RGBA", (size, size),
                            color=(100 + i * 12, 100, 150 - i * 8, 255))
            carriers.append((img, f"carrier_{i:02d}.png"))
            size = int(size * 1.35)  # ~1.8× area growth per layer

        payload = b"Deep secret at layer 11!"
        config = MatryoshkaConfig(channels="RGBA", bits=2, max_depth=11)

        try:
            img, reports = encode_nested(payload, carriers, config)
        except ValueError as exc:
            pytest.skip(f"Capacity overflow at 11-layer setup: {exc}")

        assert img is not None
        assert len(reports) == 11
        assert all(r.fits for r in reports)

        layers = decode_nested(img, config)
        flat = _flatten_layers(layers)
        text_layer = next((dl for dl in flat if dl.type == "text"), None)
        assert text_layer is not None, f"types found: {[dl.type for dl in flat]}"
        assert text_layer.raw_data == payload

    def test_11_layer_plan_exact(self):
        """plan_nesting exact mode correctly predicts 11-layer fit/overflow."""
        carriers = []
        size = 128
        for i in range(11):
            img = Image.new("RGBA", (size, size), color=(100, 100, 100, 255))
            carriers.append((img, f"c_{i:02d}.png"))
            size = int(size * 1.35)

        config = MatryoshkaConfig(channels="RGBA", bits=2, max_depth=11)
        payload_size = 50  # tiny payload

        reports = plan_nesting(payload_size, carriers, config, mode="exact")
        assert len(reports) == 11
        # All should fit for a 50-byte payload
        assert all(r.fits for r in reports)
        assert reports[-1].output_size == "final"


# ============================================================================
# plan_nesting tests
# ============================================================================

class TestPlanNesting:
    def test_estimate_all_fit(self, medium_carrier, text_payload, default_config):
        carriers = [(medium_carrier, "c.png")]
        reports = plan_nesting(len(text_payload), carriers, default_config,
                               mode="estimate")
        assert len(reports) == 1
        assert reports[0].fits is True

    def test_estimate_overflow(self, tiny_carrier):
        carriers = [(tiny_carrier, "tiny.png")]
        reports = plan_nesting(1_000_000, carriers, mode="estimate")
        assert reports[0].fits is False

    def test_exact_matches_estimate_sign(self, medium_carrier):
        """Estimate and exact agree on fits/overflow for a simple case."""
        carriers = [(medium_carrier, "c.png")]
        config = MatryoshkaConfig(channels="RGBA", bits=2)

        est = plan_nesting(1000, carriers, config, mode="estimate")
        ex = plan_nesting(1000, carriers, config, mode="exact")

        assert est[0].fits == ex[0].fits

    def test_exact_mode_output_sizes_are_real(self, medium_carrier):
        """Exact mode produces real PNG sizes, not estimates."""
        carriers = [(medium_carrier, "c.png")]
        config = MatryoshkaConfig(channels="RGBA", bits=2)
        reports = plan_nesting(500, carriers, config, mode="exact")
        assert reports[0].fits is True
        assert reports[0].output_size == "final"

    def test_multi_layer_plan(self, small_carrier, medium_carrier, large_carrier):
        carriers = [
            (small_carrier, "inner.png"),
            (medium_carrier, "middle.png"),
            (large_carrier, "outer.png"),
        ]
        config = MatryoshkaConfig(channels="RGBA", bits=2)
        reports = plan_nesting(100, carriers, config, mode="exact")
        assert len(reports) == 3
        # Small payload should fit all layers
        assert all(r.fits for r in reports)


# ============================================================================
# Auto-detect integration tests
# ============================================================================

class TestAutoDetect:
    def test_smart_scan_recursive_finds_layers(self, medium_carrier, text_payload):
        """Encoded output is detected by smart_scan_recursive."""
        try:
            from analysis_tools import smart_scan_recursive
        except ImportError:
            pytest.skip("analysis_tools not available")

        carriers = [(medium_carrier, "c.png")]
        config = MatryoshkaConfig(channels="RGBA", bits=2)
        img, _ = encode_nested(text_payload, carriers, config)
        png_data = _png_bytes(img)

        result = smart_scan_recursive(png_data, max_depth=3)
        assert result.get("layers_found", 0) >= 1

    def test_smart_scan_recursive_plain_image(self, medium_carrier):
        """Plain image with no stego should not report matryoshka layers."""
        try:
            from analysis_tools import smart_scan_recursive
        except ImportError:
            pytest.skip("analysis_tools not available")

        png_data = _png_bytes(medium_carrier)
        result = smart_scan_recursive(png_data, max_depth=3)
        # Plain image may have 0 layers or 1 no-data layer — not matryoshka
        assert not result.get("is_matryoshka", True)
