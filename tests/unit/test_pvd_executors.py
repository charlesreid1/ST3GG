"""Integration tests for the PVD MCP tool executors.

Covers the three executors exposed by ``st3ggmcp.tools.image``:
  * ``stegg_pvd_capacity``
  * ``stegg_pvd_encode``
  * ``stegg_pvd_decode``

These tests exercise the executors the way the MCP server does -- via
``await`` on the async entry points, with real files on disk. They also
confirm the tools are wired into the top-level registry.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from st3ggmcp.tools import TOOL_EXECUTORS, TOOL_SCHEMAS
from st3ggmcp.tools.image import (
    execute_pvd_capacity,
    execute_pvd_decode,
    execute_pvd_encode,
)

DIRECTIONS = ["horizontal", "vertical", "both"]
RANGE_TYPES = ["wu-tsai", "wide", "narrow"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def carrier_png(tmp_path) -> Path:
    """A noisy 64x64 RGB PNG on disk."""
    rng = np.random.default_rng(1234)
    arr = rng.integers(0, 256, size=(64, 64, 3), dtype=np.uint8)
    img = Image.fromarray(arr, mode="RGB")
    p = tmp_path / "carrier.png"
    img.save(p, format="PNG")
    return p


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["stegg_pvd_capacity", "stegg_pvd_encode", "stegg_pvd_decode"])
def test_pvd_tools_are_registered(name):
    assert name in TOOL_EXECUTORS, f"{name} missing from TOOL_EXECUTORS"
    assert name in TOOL_SCHEMAS, f"{name} missing from TOOL_SCHEMAS"
    schema = TOOL_SCHEMAS[name]
    assert "description" in schema
    assert "inputSchema" in schema
    assert schema["inputSchema"]["type"] == "object"
    assert "path" in schema["inputSchema"]["required"]


# ---------------------------------------------------------------------------
# stegg_pvd_capacity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("direction", DIRECTIONS)
@pytest.mark.parametrize("range_type", RANGE_TYPES)
def test_capacity_reports_reasonable_numbers(carrier_png, direction, range_type):
    out = _run(execute_pvd_capacity(str(carrier_png), direction=direction, range_type=range_type))
    result = json.loads(out)
    assert result["direction"] == direction
    assert result["range_type"] == range_type
    assert result["capacity_bits"] > 0
    assert result["capacity_bytes"] > 0
    # capacity_bytes = capacity_bits // 8 - 4 header bytes
    assert result["capacity_bytes"] == (result["capacity_bits"] // 8) - 4
    assert result["size"] == [64, 64]


def test_capacity_rejects_bad_direction(carrier_png):
    out = _run(execute_pvd_capacity(str(carrier_png), direction="diagonal"))
    assert "direction must be one of" in out


def test_capacity_rejects_bad_range_type(carrier_png):
    out = _run(execute_pvd_capacity(str(carrier_png), range_type="unicorn"))
    assert "range_type must be one of" in out


def test_capacity_missing_file():
    out = _run(execute_pvd_capacity("/no/such/file.png"))
    assert "file not found" in out


# ---------------------------------------------------------------------------
# Encode / decode round-trip via the executors
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("direction", DIRECTIONS)
@pytest.mark.parametrize("range_type", RANGE_TYPES)
def test_executor_roundtrip(carrier_png, tmp_path, direction, range_type):
    message = "PVD via MCP executors 🐉"  # UTF-8 with a non-ASCII char
    out_path = tmp_path / f"stego_{direction}_{range_type}.png"

    enc_json = _run(execute_pvd_encode(
        str(carrier_png),
        message=message,
        direction=direction,
        range_type=range_type,
        output_path=str(out_path),
    ))
    enc = json.loads(enc_json)
    assert enc["config"]["method"] == "PVD"
    assert enc["config"]["direction"] == direction
    assert enc["config"]["range_type"] == range_type
    assert Path(enc["output_path"]).exists()
    assert enc["output_bytes"] > 0

    dec_json = _run(execute_pvd_decode(
        str(out_path),
        direction=direction,
        range_type=range_type,
    ))
    dec = json.loads(dec_json)
    assert dec["decoded"] is True
    assert dec["utf8"] == message


# ---------------------------------------------------------------------------
# Encode failure modes
# ---------------------------------------------------------------------------

def test_encode_rejects_non_string_message(carrier_png):
    out = _run(execute_pvd_encode(str(carrier_png), message=12345))
    assert "must be a string" in out


def test_encode_rejects_bad_direction(carrier_png):
    out = _run(execute_pvd_encode(str(carrier_png), message="x", direction="sideways"))
    assert "direction must be one of" in out


def test_encode_reports_capacity_shortfall(tmp_path):
    """Payload too large -> friendly error mentioning the capacity, no crash."""
    tiny = tmp_path / "tiny.png"
    Image.fromarray(np.zeros((6, 6, 3), dtype=np.uint8), mode="RGB").save(tiny, format="PNG")
    out = _run(execute_pvd_encode(
        str(tiny),
        message="X" * 5000,
        direction="horizontal",
        range_type="wu-tsai",
    ))
    assert "stegg_pvd_encode" in out
    assert "usable bytes" in out


# ---------------------------------------------------------------------------
# Decode failure modes
# ---------------------------------------------------------------------------

def test_decode_wrong_config_fails_gracefully(carrier_png, tmp_path):
    """Decoding a PVD stego with the wrong config yields decoded=False, not a crash."""
    stego = tmp_path / "stego.png"
    _run(execute_pvd_encode(
        str(carrier_png),
        message="secret",
        direction="horizontal",
        range_type="wu-tsai",
        output_path=str(stego),
    ))
    # Decode with a mismatched range table.
    dec_json = _run(execute_pvd_decode(str(stego), direction="horizontal", range_type="wide"))
    dec = json.loads(dec_json)
    # Two acceptable outcomes: either decode failed loudly, or it returned
    # bytes that aren't the plaintext.
    if dec["decoded"] is False:
        assert "error" in dec
    else:
        assert dec.get("utf8") != "secret"


def test_decode_rejects_bad_max_payload(carrier_png):
    out = _run(execute_pvd_decode(str(carrier_png), max_payload=0))
    assert "max_payload" in out


def test_decode_rejects_non_integer_max_payload(carrier_png):
    out = _run(execute_pvd_decode(str(carrier_png), max_payload="banana"))
    assert "max_payload" in out


def test_decode_missing_file():
    out = _run(execute_pvd_decode("/no/such/file.png"))
    assert "file not found" in out
