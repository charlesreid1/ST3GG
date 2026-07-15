"""PCAP examples: 8 protocols each carrying steg via a different network vector."""

from __future__ import annotations

import pytest

from analysis_tools import detect_file_type

PCAP_FILES = [
    "example_hidden.pcap",
    "example_covert_timing.pcap",
    "example_dns_tunnel.pcap",
    "example_dns_txt.pcap",
    "example_http_headers.pcap",
    "example_icmp_steg.pcap",
    "example_ipid_covert.pcap",
    "example_tcp_covert.pcap",
    "example_tcp_urgent.pcap",
    "example_tcp_window.pcap",
    "example_ttl_covert.pcap",
]


@pytest.mark.parametrize("filename", PCAP_FILES)
def test_pcap_file_type_detected(examples_dir, filename):
    path = examples_dir / filename
    if not path.exists():
        pytest.skip(f"{filename} not present")
    assert detect_file_type(path.read_bytes()).value == "pcap"


@pytest.mark.parametrize("filename", PCAP_FILES)
def test_pcap_decode_via_registry(examples_dir, filename):
    """The `pcap_decode` tool should return a result (success or failure) for
    every PCAP without raising."""
    from analysis_tools import execute_action
    path = examples_dir / filename
    if not path.exists():
        pytest.skip(f"{filename} not present")
    result = execute_action("pcap_decode", path.read_bytes())
    assert result.action == "pcap_decode"


# ---------- per-method decoder coverage ----------
#
# Each example PCAP maps to the per-method decoder tool in analysis_tools.
# The decoder should extract the Plinian divider payload we seeded via
# examples/generate_examples.py.  covert_timing is xfail'd because the
# encoder doesn't yet inject inter-packet delays into PCAP timestamps.

PCAP_METHOD_MAP = [
    ("example_hidden.pcap",        "pcap_decode_ip_ttl"),
    ("example_covert_timing.pcap", "pcap_decode_covert_timing"),
    ("example_dns_tunnel.pcap",    "pcap_decode_dns_label"),
    ("example_dns_txt.pcap",       "pcap_decode_dns_txt"),
    ("example_http_headers.pcap",  "pcap_decode_http_header"),
    ("example_icmp_steg.pcap",     "pcap_decode_icmp_payload"),
    ("example_ipid_covert.pcap",   "pcap_decode_ip_id"),
    ("example_tcp_covert.pcap",    "pcap_decode_tcp_isn"),
    ("example_tcp_urgent.pcap",    "pcap_decode_tcp_urgent"),
    ("example_tcp_window.pcap",    "pcap_decode_tcp_window"),
    ("example_ttl_covert.pcap",    "pcap_decode_ip_ttl"),
]

_XFAIL_TOOLS = {"pcap_decode_covert_timing"}


@pytest.mark.parametrize(("filename", "tool"), PCAP_METHOD_MAP)
def test_pcap_per_method_decoder_extracts_plinian(examples_dir, plinian, filename, tool):
    from analysis_tools import execute_action

    path = examples_dir / filename
    if not path.exists():
        pytest.skip(f"{filename} not present")
    if tool in _XFAIL_TOOLS:
        pytest.xfail("covert_timing encoder does not yet write inter-packet delays")

    result = execute_action(tool, path.read_bytes())
    assert result.action == tool
    assert result.data.get("found"), (
        f"{tool} failed to decode {filename}: {result.data}"
    )
    assert plinian in result.data.get("payload", "")
