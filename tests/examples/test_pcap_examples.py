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
