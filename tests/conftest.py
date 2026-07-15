"""Shared pytest fixtures and constants for the st3gg suite.

The project keeps its module code at the repo root (no `src/` layout), so
this file also ensures the repo root is on `sys.path` for every collected
test — without it, `import img_core` fails when pytest is invoked from a
different working directory.
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

# Repo root: parent of the tests/ dir.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


EXAMPLES_DIR = REPO_ROOT / "examples"
PIPELINES_DIR = EXAMPLES_DIR / "pipelines"

# These constants live in examples/generate_examples.py. We copy them here
# rather than importing so the test suite doesn't drag generate_examples'
# heavy imports (PIL plugins, wave, etc.) into every collection.
PLINIAN_DIVIDER = "⊰•-•✧•-•-⦑/L\\O/V\\E/\\P/L\\I/N\\Y/⦒-•-•✧•-•⊱"
ORIGINAL_SECRET = "STEGOSAURUS WRECKS - Hidden message found! 🦕"


# ---------- Crypto availability probe ----------

def _crypto_available() -> bool:
    try:
        import crypto  # noqa: F401
        from crypto import HAS_CRYPTO
        return bool(HAS_CRYPTO)
    except Exception:
        return False


HAS_CRYPTO = _crypto_available()


# ---------- Session-scoped path fixtures ----------

@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def examples_dir() -> Path:
    return EXAMPLES_DIR


@pytest.fixture(scope="session")
def pipelines_dir() -> Path:
    PIPELINES_DIR.mkdir(parents=True, exist_ok=True)
    return PIPELINES_DIR


@pytest.fixture
def tmp_out(tmp_path: Path) -> Path:
    return tmp_path


# ---------- Constants exposed as fixtures ----------

@pytest.fixture(scope="session")
def plinian() -> str:
    return PLINIAN_DIVIDER


@pytest.fixture(scope="session")
def original_secret() -> str:
    return ORIGINAL_SECRET


# ---------- Carrier-image factories ----------

def _make_noisy_carrier(size: int, base: tuple[int, int, int, int], jitter: int, seed: int) -> Image.Image:
    """Create a carrier PNG image with a bit of realistic noise.

    Deterministic per (size, base, jitter, seed) so tests remain reproducible.
    """
    rng = np.random.default_rng(seed)
    img = Image.new("RGBA", (size, size), color=base)
    pixels = np.array(img, dtype=np.int16)
    noise = rng.integers(-jitter, jitter + 1, size=pixels.shape, dtype=np.int16)
    pixels = np.clip(pixels + noise, 0, 255).astype(np.uint8)
    return Image.fromarray(pixels, "RGBA")


@pytest.fixture
def small_carrier() -> Image.Image:
    return _make_noisy_carrier(100, (128, 128, 128, 255), 15, seed=1)


@pytest.fixture
def medium_carrier() -> Image.Image:
    return _make_noisy_carrier(256, (100, 150, 200, 255), 25, seed=2)


@pytest.fixture
def large_carrier() -> Image.Image:
    return _make_noisy_carrier(512, (64, 128, 192, 255), 20, seed=3)


# ---------- PNG bytes helpers ----------

def image_to_png_bytes(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def png_bytes_to_image(data: bytes) -> Image.Image:
    return Image.open(io.BytesIO(data))


# ---------- Skip markers ----------

requires_crypto = pytest.mark.skipif(
    not HAS_CRYPTO, reason="cryptography library not available"
)


# ---------- Legacy ad-hoc scripts ----------
# `test_examples.py` and `test_comprehensive.py` are runnable audit scripts,
# not pytest tests — they execute at import time and call `sys.exit()`.
# Skip them during pytest collection; run them directly via `python`.
collect_ignore = [
    "test_examples.py",
    "test_comprehensive.py",
]
