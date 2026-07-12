"""Edge cases: empty / truncated / all-null inputs must not crash decoders."""

from __future__ import annotations

import pytest

from analysis_tools import (
    detect_base64,
    detect_file_type,
    detect_hex_strings,
    detect_unicode_steg,
    detect_whitespace_steg,
    execute_action,
    list_available_tools,
)


EDGE_INPUTS = [
    ("empty", b""),
    ("single-null", b"\x00"),
    ("all-nulls", b"\x00" * 512),
    ("all-ff", b"\xff" * 512),
    ("single-char", b"A"),
    ("no-newline-text", b"the quick brown fox"),
]


@pytest.mark.parametrize("label,data", EDGE_INPUTS, ids=[c[0] for c in EDGE_INPUTS])
def test_file_type_detector_handles_edge(label, data):
    # Should return something (UNKNOWN is fine) and not raise.
    result = detect_file_type(data)
    assert result is not None


@pytest.mark.parametrize("label,data", EDGE_INPUTS, ids=[c[0] for c in EDGE_INPUTS])
def test_content_detectors_handle_edge(label, data):
    detect_base64(data)
    detect_hex_strings(data)
    detect_unicode_steg(data)
    detect_whitespace_steg(data)


@pytest.mark.parametrize("action", sorted(list_available_tools()))
def test_registry_handles_empty_input(action):
    result = execute_action(action, b"")
    # An action may fail (success=False), but the registry must not crash.
    assert result.action == action
