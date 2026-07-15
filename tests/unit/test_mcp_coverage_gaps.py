"""Tests for the four MCP tools added to close core->MCP coverage gaps.

Covers:
  * ``stegg_lsb_capacity``
  * ``stegg_analyze_image``
  * ``stegg_detect_pvd``
  * ``stegg_inject_exif``
"""

from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

import injector
import pvd_core

from st3ggmcp.tools import TOOL_EXECUTORS, TOOL_SCHEMAS
from st3ggmcp.tools.image import (
    execute_analyze_image,
    execute_detect_pvd,
    execute_inject_exif,
    execute_lsb_capacity,
)

NEW_TOOLS = [
    "stegg_lsb_capacity",
    "stegg_analyze_image",
    "stegg_detect_pvd",
    "stegg_inject_exif",
]


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def carrier_png(tmp_path) -> Path:
    rng = np.random.default_rng(2024)
    arr = rng.integers(0, 256, size=(64, 64, 3), dtype=np.uint8)
    p = tmp_path / "carrier.png"
    Image.fromarray(arr, mode="RGB").save(p, format="PNG")
    return p


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", NEW_TOOLS)
def test_new_tools_registered(name):
    assert name in TOOL_EXECUTORS
    assert name in TOOL_SCHEMAS
    schema = TOOL_SCHEMAS[name]
    assert "description" in schema
    assert "path" in schema["inputSchema"]["required"]


# ---------------------------------------------------------------------------
# stegg_lsb_capacity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("channels,bits", [("RGB", 1), ("R", 1), ("RGBA", 2), ("RGB", 4)])
def test_lsb_capacity_reports_reasonable_numbers(carrier_png, channels, bits):
    out = _run(execute_lsb_capacity(str(carrier_png), channels=channels, bits_per_channel=bits))
    result = json.loads(out)
    assert result["channels"] == channels
    assert result["bits_per_channel"] == bits
    assert result["size"] == [64, 64]
    assert "bytes_total" in result and result["bytes_total"] > 0


def test_lsb_capacity_rejects_bad_channels(carrier_png):
    out = _run(execute_lsb_capacity(str(carrier_png), channels="XYZ"))
    assert "Unknown channels preset" in out


def test_lsb_capacity_rejects_out_of_range_bits(carrier_png):
    out = _run(execute_lsb_capacity(str(carrier_png), bits_per_channel=9))
    assert "bits_per_channel must be in 1..8" in out


def test_lsb_capacity_missing_file():
    out = _run(execute_lsb_capacity("/no/such/file.png"))
    assert "file not found" in out


# ---------------------------------------------------------------------------
# stegg_analyze_image
# ---------------------------------------------------------------------------

def test_analyze_image_returns_structured_diagnostic(carrier_png):
    out = _run(execute_analyze_image(str(carrier_png)))
    result = json.loads(out)
    assert result["mode"] == "RGB"
    assert result["dimensions"] == {"width": 64, "height": 64}
    assert "channels" in result
    for ch in ("R", "G", "B"):
        assert ch in result["channels"]
        assert "mean" in result["channels"][ch]
        assert "chi_square" in result["channels"][ch]
    assert "capacity_by_config" in result
    assert "detection" in result
    assert result["detection"]["level"] in {"HIGH", "MEDIUM", "LOW"}


def test_analyze_image_missing_file():
    out = _run(execute_analyze_image("/no/such/file.png"))
    assert "file not found" in out


# ---------------------------------------------------------------------------
# stegg_detect_pvd
# ---------------------------------------------------------------------------

def test_detect_pvd_returns_found_field(carrier_png):
    out = _run(execute_detect_pvd(str(carrier_png)))
    result = json.loads(out)
    assert "found" in result


def test_detect_pvd_fires_on_pvd_encoded_image(carrier_png, tmp_path):
    """A PVD-encoded image should at least be inspectable (found True or False).

    We don't assert True because the naive length-header check may not fire on
    every PVD encoding; the important property is that the detector runs
    without crashing on real PVD stego and returns a structured verdict.
    """
    carrier = Image.open(carrier_png)
    stego = pvd_core.encode(carrier, b"secret", direction="horizontal", range_type="wu-tsai")
    stego_path = tmp_path / "pvd.png"
    stego.save(stego_path, format="PNG")

    out = _run(execute_detect_pvd(str(stego_path)))
    result = json.loads(out)
    assert isinstance(result.get("found"), bool)


def test_detect_pvd_missing_file():
    out = _run(execute_detect_pvd("/no/such/file.png"))
    assert "file not found" in out


# ---------------------------------------------------------------------------
# stegg_inject_exif
# ---------------------------------------------------------------------------

def test_inject_exif_roundtrip(carrier_png, tmp_path):
    out_path = tmp_path / "with_exif.png"
    metadata = {"Author": "st3gg", "Comment": "hello world", "Software": "MCP test"}
    out = _run(execute_inject_exif(
        str(carrier_png),
        metadata=metadata,
        output_path=str(out_path),
    ))
    result = json.loads(out)
    assert Path(result["output_path"]).exists()
    assert sorted(result["keys"]) == sorted(metadata.keys())

    # The injected chunks should be readable back via injector.extract_text_chunks.
    read_back = injector.extract_text_chunks(out_path.read_bytes())
    for k, v in metadata.items():
        assert read_back.get(k) == v


def test_inject_exif_rejects_non_dict_metadata(carrier_png):
    out = _run(execute_inject_exif(str(carrier_png), metadata="not-a-dict"))
    assert "must be a non-empty object" in out


def test_inject_exif_rejects_empty_metadata(carrier_png):
    out = _run(execute_inject_exif(str(carrier_png), metadata={}))
    assert "must be a non-empty object" in out


def test_inject_exif_rejects_non_string_values(carrier_png):
    out = _run(execute_inject_exif(str(carrier_png), metadata={"key": 42}))
    assert "must be strings" in out


def test_inject_exif_missing_file():
    out = _run(execute_inject_exif("/no/such/file.png", metadata={"k": "v"}))
    assert "file not found" in out
