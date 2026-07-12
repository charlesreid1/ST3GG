"""TOOL_REGISTRY: every registered analysis action is callable."""

from __future__ import annotations

import pytest

from analysis_tools import TOOL_REGISTRY, execute_action, list_available_tools


# Tools we expect to be registered — from `_register_all_tools` and the
# initial constructor registration.
EXPECTED_TOOLS = {
    "detect_base64",
    "detect_hex_strings",
    "detect_unicode_steg",
    "detect_whitespace_steg",
    "detect_xor_patterns",
    "detect_repeated_patterns",
    "analyze_entropy",
    "analyze_bit_planes",
    "detect_homoglyph_steg",
    "detect_variation_selector_steg",
    "detect_combining_mark_steg",
    "detect_confusable_whitespace",
    "detect_emoji_steg",
    "detect_capitalization_steg",
    "rs_analysis",
    "sample_pairs_analysis",
    "audio_lsb_decode",
    "pcap_decode",
    "zip_decode",
    "tar_decode",
    "gzip_decode",
    "sqlite_decode",
    "pdf_decode",
    "jpeg_decode",
    "svg_decode",
    "generic_image_lsb_decode",
    "decode_braille",
    "decode_directional_override",
    "decode_hangul_filler",
    "decode_math_alphanumeric",
    "decode_emoji_skin_tone",
}


def test_registry_contains_expected_tools():
    registered = set(list_available_tools())
    missing = EXPECTED_TOOLS - registered
    assert not missing, f"missing tools: {sorted(missing)}"


@pytest.mark.parametrize("action", sorted(EXPECTED_TOOLS))
def test_tool_executes_without_crashing(action):
    """Every tool should handle a benign short input without raising through
    the registry — errors are meant to surface as `AnalysisResult(success=False)`."""
    result = execute_action(action, b"hello world " * 10)
    # A tool may legitimately return success=False (e.g. wrong format),
    # but it must not crash the registry.
    assert result.action == action


def test_unknown_action_returns_failure_result():
    result = execute_action("does-not-exist", b"x")
    assert result.success is False
    assert "Unknown action" in (result.error or "")
