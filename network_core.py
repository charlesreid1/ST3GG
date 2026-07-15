"""
STEGOSAURUS WRECKS - Network Steganography Core Engine
Encode arbitrary payloads into PCAP files and decode them back.

Wire formats (protocol stacks) and stego methods (which field carries data)
are orthogonal. Add a new wire format: 1 enum value + 1 builder function.
Add a new stego method: 1 enum value + 1 encode function + 1 decode function
+ 1 row in the compatibility mapping.

Built on scapy for correct checksums, length fields, and PCAP I/O.
"""

from __future__ import annotations

import base64
import io
import math
import random
import re
import struct
import zlib
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# scapy is the only hard dependency beyond the stdlib.  It is listed in
# pyproject.toml as a core dependency so we import it unconditionally.
# ---------------------------------------------------------------------------
from scapy.all import (
    DNS,
    DNSQR,
    Ether,
    ICMP,
    IP,
    Raw,
    TCP,
    UDP,
    rdpcap,
    wrpcap,
)
from scapy.packet import Packet

# ---------------------------------------------------------------------------
# Synthetic-only — never touch real hardware.  MACs are random but seedable
# so test fixtures are reproducible.  Zero identifying details, zero real
# interfaces.  Every Ether() frame gets explicit fake MACs.
# ---------------------------------------------------------------------------
_MAC_RNG = random.Random(0x57366)  # fixed seed for reproducible tests

def _fake_ether() -> Ether:
    """Return an Ether layer with random unicast MACs — not a real OUI."""
    mac = ":".join(f"{_MAC_RNG.randint(0, 255):02x}" for _ in range(6))
    return Ether(dst=mac, src=mac)


# ============== ENUMS ==============


class WireFormat(Enum):
    """Protocol stack — what bytes go on the wire.

    To add a new wire format (e.g. IP6_UDP, IP4_QUIC):
        1. Add one value to this enum.
        2. Add a ``_wf_<name>(config)`` builder function below (~10 lines).
        3. Update METHOD_WIRE_FORMATS for any methods that support it.
        4. Update METHOD_BYTES_PER_PACKET if the capacity changes.
    No changes to encode/decode functions are needed.
    """

    IP4_UDP = "ip4_udp"             # Ether / IP / UDP
    IP4_TCP = "ip4_tcp"             # Ether / IP / TCP
    IP4_ICMP = "ip4_icmp"           # Ether / IP / ICMP
    IP4_UDP_DNS = "ip4_udp_dns"     # Ether / IP / UDP / DNS
    IP4_TCP_HTTP = "ip4_tcp_http"   # Ether / IP / TCP / HTTP


class StegoMethod(Enum):
    """What field carries the hidden data.

    To add a new stego method (e.g. IP fragment offset, TCP ACK number):
        1. Add one value to this enum.
        2. Add ``_encode_<name>(data, config) -> list[Packet]`` below.
        3. Add ``_decode_<name>(packets) -> bytes`` below.
        4. Add its row to METHOD_WIRE_FORMATS.
        5. Add its row to METHOD_BYTES_PER_PACKET.
        6. Add entries to _ENCODERS and _DECODERS dispatch tables.
    No changes to wire format builders or other methods are needed.
    """

    IP_TTL = "ip_ttl"               # 1 byte/pkt, any IP-carrying format
    IP_ID = "ip_id"                 # 2 bytes/pkt, any IP-carrying format
    TCP_ISN = "tcp_isn"             # 4 bytes/SYN pkt, TCP formats only
    TCP_TIMESTAMP = "tcp_timestamp" # 4 bytes/pkt in TCP timestamp option
    TCP_WINDOW = "tcp_window"       # 2 bytes/pkt in TCP window field
    TCP_URGENT = "tcp_urgent"       # 2 bytes/pkt in TCP urgent pointer
    ICMP_PAYLOAD = "icmp_payload"   # variable bytes/pkt in echo payload
    DNS_LABEL = "dns_label"         # base32 in QNAME labels, ~48 raw bytes/label
    DNS_TXT = "dns_txt"             # base64 in TXT record RDATA, 255 bytes/record
    HTTP_HEADER = "http_header"     # hex in custom X- headers, single-packet
    COVERT_TIMING = "covert_timing" # 1 bit per inter-packet delay


# ============== METADATA ==============


#: Which stego methods work on which wire formats.
#: This is the ONLY place that couples the two enums.
METHOD_WIRE_FORMATS: dict[StegoMethod, list[WireFormat]] = {
    # IP-layer methods — valid on any format with an IP header
    StegoMethod.IP_TTL: [
        WireFormat.IP4_UDP, WireFormat.IP4_TCP, WireFormat.IP4_ICMP,
        WireFormat.IP4_UDP_DNS, WireFormat.IP4_TCP_HTTP,
    ],
    StegoMethod.IP_ID: [
        WireFormat.IP4_UDP, WireFormat.IP4_TCP, WireFormat.IP4_ICMP,
        WireFormat.IP4_UDP_DNS, WireFormat.IP4_TCP_HTTP,
    ],
    # TCP-layer methods — only on TCP-carrying formats
    StegoMethod.TCP_ISN:       [WireFormat.IP4_TCP, WireFormat.IP4_TCP_HTTP],
    StegoMethod.TCP_TIMESTAMP: [WireFormat.IP4_TCP, WireFormat.IP4_TCP_HTTP],
    StegoMethod.TCP_WINDOW:    [WireFormat.IP4_TCP, WireFormat.IP4_TCP_HTTP],
    StegoMethod.TCP_URGENT:    [WireFormat.IP4_TCP, WireFormat.IP4_TCP_HTTP],
    # ICMP
    StegoMethod.ICMP_PAYLOAD:  [WireFormat.IP4_ICMP],
    # DNS — only on DNS-carrying format
    StegoMethod.DNS_LABEL:     [WireFormat.IP4_UDP_DNS],
    StegoMethod.DNS_TXT:       [WireFormat.IP4_UDP_DNS],
    # HTTP — only on HTTP-carrying format
    StegoMethod.HTTP_HEADER:   [WireFormat.IP4_TCP_HTTP],
    # Timing — protocol-agnostic, works on any UDP format
    StegoMethod.COVERT_TIMING: [WireFormat.IP4_UDP, WireFormat.IP4_UDP_DNS],
}


#: Bytes per packet — used for capacity calculation and chunking.
#: Methods with 0 bytes/pkt are variable-length or single-packet.
METHOD_BYTES_PER_PACKET: dict[StegoMethod, int] = {
    StegoMethod.IP_TTL: 1,
    StegoMethod.IP_ID: 2,
    StegoMethod.TCP_ISN: 4,
    StegoMethod.TCP_TIMESTAMP: 4,
    StegoMethod.TCP_WINDOW: 2,
    StegoMethod.TCP_URGENT: 2,
    StegoMethod.ICMP_PAYLOAD: 32,
    StegoMethod.DNS_LABEL: 48,
    StegoMethod.DNS_TXT: 255,
    StegoMethod.HTTP_HEADER: 0,    # single-packet, unlimited
    StegoMethod.COVERT_TIMING: 0,  # 1 bit/packet
}


# ============== FRAMING ==============


# 12-byte NETH header — smaller than STEG v3's 32 bytes because network
# channels are low-bandwidth.  The header bytes themselves travel through
# the same stego method as the payload, so the decoder reads them the
# same way.  64 KB max payload is consistent with IP's 16-bit total
# length field.

NETH_MAGIC = b'NETH'
NETH_HEADER_SIZE = 12

#: Map each enum member to a stable uint8 ID for the framing header.
_METHOD_ID: dict[StegoMethod, int] = {
    m: i for i, m in enumerate(StegoMethod)
}
_WIRE_FORMAT_ID: dict[WireFormat, int] = {
    wf: i for i, wf in enumerate(WireFormat)
}
#: Reverse lookup for decoding.
_ID_TO_METHOD: dict[int, StegoMethod] = {v: k for k, v in _METHOD_ID.items()}
_ID_TO_WIRE_FORMAT: dict[int, WireFormat] = {v: k for k, v in _WIRE_FORMAT_ID.items()}


@dataclass
class NetworkFrameHeader:
    """Compact 12-byte framing header prepended to every payload.

    Bytes 0-3:   b'NETH' magic
    Byte  4:     StegoMethod enum value (uint8)
    Byte  5:     WireFormat enum value (uint8)
    Bytes 6-7:   payload length (uint16 BE, max 65535)
    Bytes 8-11:  CRC32 of payload (uint32 BE)
    """

    method: int       # StegoMethod enum value
    wire_format: int  # WireFormat enum value
    payload_length: int
    crc32: int

    def to_bytes(self) -> bytes:
        return struct.pack(
            '>4sBBHI',
            NETH_MAGIC,
            self.method,
            self.wire_format,
            self.payload_length,
            self.crc32,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> NetworkFrameHeader:
        if len(data) < NETH_HEADER_SIZE:
            raise ValueError(
                f"Need at least {NETH_HEADER_SIZE} bytes for NETH header, "
                f"got {len(data)}"
            )
        magic, method, wf, plen, crc = struct.unpack('>4sBBHI', data[:NETH_HEADER_SIZE])
        if magic != NETH_MAGIC:
            raise ValueError(
                f"Bad NETH magic: expected {NETH_MAGIC!r}, got {magic!r}"
            )
        return cls(method=method, wire_format=wf, payload_length=plen, crc32=crc)


# ============== CONFIGURATION ==============


@dataclass
class NetworkStegConfig:
    """Configuration for network steganography operations.

    The __post_init__ validator enforces that the chosen method is
    compatible with the chosen wire format.
    """

    method: StegoMethod
    wire_format: WireFormat
    # IP layer
    src_ip: str = "192.168.1.100"
    dst_ip: str = "8.8.8.8"
    # Transport
    sport: int = 12345
    dport: int = 53
    # DNS-specific
    cover_domain: str = "steg.example.com"
    # Timing-specific
    bit0_delay_us: int = 10000   # 10 ms = bit 0
    bit1_delay_us: int = 50000   # 50 ms = bit 1
    # Compression
    use_compression: bool = True

    def __post_init__(self):
        valid = METHOD_WIRE_FORMATS.get(self.method, [])
        if self.wire_format not in valid:
            raise ValueError(
                f"{self.method.value} requires one of "
                f"{[w.value for w in valid]}, got {self.wire_format.value}"
            )


# ============== WIRE FORMAT BUILDERS ==============
#
# Each builder returns a scapy packet (or list of packets for complex
# formats like HTTP that need a handshake).  Builders are private;
# encoders call them to get a template, then modify the relevant fields.
#
# To add a new wire format (e.g. IP6_UDP):
#   def _wf_ip6_udp(config: NetworkStegConfig) -> Packet:
#       return _fake_ether() / IPv6(src=..., dst=...) / UDP(...)
#   Then add it to the WireFormat enum and METHOD_WIRE_FORMATS.
# ---------------------------------------------------------------------------


def _wf_ip4_udp(config: NetworkStegConfig) -> Packet:
    """Ether / IP / UDP template."""
    return (
        _fake_ether()
        / IP(src=config.src_ip, dst=config.dst_ip)
        / UDP(sport=config.sport, dport=config.dport)
    )


def _wf_ip4_tcp(config: NetworkStegConfig, flags: int = 0x02) -> Packet:
    """Ether / IP / TCP template.  *flags* defaults to SYN."""
    return (
        _fake_ether()
        / IP(src=config.src_ip, dst=config.dst_ip)
        / TCP(sport=config.sport, dport=config.dport, flags=flags)
    )


def _wf_ip4_icmp(config: NetworkStegConfig) -> Packet:
    """Ether / IP / ICMP echo-request template."""
    return (
        _fake_ether()
        / IP(src=config.src_ip, dst=config.dst_ip)
        / ICMP(type=8, code=0)  # Echo request
    )


def _wf_ip4_udp_dns(config: NetworkStegConfig) -> Packet:
    """Ether / IP / UDP / DNS template with empty question section."""
    return (
        _fake_ether()
        / IP(src=config.src_ip, dst=config.dst_ip)
        / UDP(sport=config.sport, dport=53)
        / DNS(qd=DNSQR(qname=config.cover_domain, qtype="A"))
    )


def _wf_ip4_tcp_http(config: NetworkStegConfig) -> list[Packet]:
    """Build a minimal TCP 3-way handshake + HTTP GET, returning all packets.

    Returns a list so the encoder can append the data-carrying HTTP
    request as the final packet.
    """
    packets: list[Packet] = []
    client_isn = 1000
    server_isn = 2000

    # SYN
    syn = (
        _fake_ether()
        / IP(src=config.src_ip, dst=config.dst_ip)
        / TCP(sport=config.sport, dport=config.dport, flags="S", seq=client_isn)
    )
    packets.append(syn)

    # SYN-ACK (server -> client)
    synack = (
        _fake_ether()
        / IP(src=config.dst_ip, dst=config.src_ip)
        / TCP(sport=config.dport, dport=config.sport, flags="SA",
              seq=server_isn, ack=client_isn + 1)
    )
    packets.append(synack)

    # ACK
    ack = (
        _fake_ether()
        / IP(src=config.src_ip, dst=config.dst_ip)
        / TCP(sport=config.sport, dport=config.dport, flags="A",
              seq=client_isn + 1, ack=server_isn + 1)
    )
    packets.append(ack)

    return packets


#: Lookup table for wire format builders.
_WF_BUILDERS: dict[WireFormat, Callable] = {
    WireFormat.IP4_UDP:      _wf_ip4_udp,
    WireFormat.IP4_TCP:      _wf_ip4_tcp,
    WireFormat.IP4_ICMP:     _wf_ip4_icmp,
    WireFormat.IP4_UDP_DNS:  _wf_ip4_udp_dns,
    WireFormat.IP4_TCP_HTTP: _wf_ip4_tcp_http,
}


# ============== STEGO METHOD ENCODERS ==============
#
# Each encoder takes (data: bytes, config: NetworkStegConfig) and returns
# a list of scapy Packets.  The data already includes the NETH framing
# header and optional zlib compression applied by the top-level encode().
#
# To add a new stego method:
#   1. Add a StegoMethod enum value.
#   2. Write _encode_<name>(data, config) -> list[Packet]
#   3. Write _decode_<name>(packets) -> bytes
#   4. Add to METHOD_WIRE_FORMATS, METHOD_BYTES_PER_PACKET,
#      _ENCODERS, and _DECODERS.
# ---------------------------------------------------------------------------


def _encode_ip_ttl(data: bytes, config: NetworkStegConfig) -> list[Packet]:
    """Encode one byte per packet in the IP TTL field."""
    pkt_template = _WF_BUILDERS[config.wire_format](config)
    packets: list[Packet] = []
    for i, byte_val in enumerate(data):
        pkt = pkt_template.copy()
        pkt[IP].ttl = byte_val
        # Vary source port so packets are distinguishable
        if UDP in pkt:
            pkt[UDP].sport = config.sport + i
        elif TCP in pkt:
            pkt[TCP].sport = config.sport + i
        packets.append(pkt)
    return packets


def _encode_ip_id(data: bytes, config: NetworkStegConfig) -> list[Packet]:
    """Encode two bytes per packet in the IP Identification field."""
    pkt_template = _WF_BUILDERS[config.wire_format](config)
    packets: list[Packet] = []
    for i in range(0, len(data), 2):
        chunk = data[i:i + 2]
        if len(chunk) < 2:
            chunk = chunk + b'\x00' * (2 - len(chunk))
        ip_id = struct.unpack('>H', chunk)[0]
        pkt = pkt_template.copy()
        pkt[IP].id = ip_id
        if UDP in pkt:
            pkt[UDP].sport = config.sport + i
        elif TCP in pkt:
            pkt[TCP].sport = config.sport + i
        packets.append(pkt)
    return packets


def _encode_tcp_isn(data: bytes, config: NetworkStegConfig) -> list[Packet]:
    """Encode 4 bytes per SYN packet in the TCP Initial Sequence Number."""
    packets: list[Packet] = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4].ljust(4, b'\x00')
        isn = struct.unpack('>I', chunk)[0]
        pkt = _wf_ip4_tcp(config, flags=0x02)  # SYN
        pkt[TCP].seq = isn
        pkt[TCP].sport = config.sport + (i // 4)
        packets.append(pkt)
    return packets


def _encode_tcp_timestamp(data: bytes, config: NetworkStegConfig) -> list[Packet]:
    """Encode 4 bytes per packet in the TCP timestamp option (TSval)."""
    packets: list[Packet] = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4].ljust(4, b'\x00')
        ts_val = struct.unpack('>I', chunk)[0]
        pkt = _wf_ip4_tcp(config, flags=0x02)  # SYN
        # scapy TCP options: list of (kind, value) tuples
        pkt[TCP].options = [('Timestamp', (ts_val, 0))]
        pkt[TCP].sport = config.sport + (i // 4)
        packets.append(pkt)
    return packets


def _encode_tcp_window(data: bytes, config: NetworkStegConfig) -> list[Packet]:
    """Encode 2 bytes per packet in the TCP window field."""
    packets: list[Packet] = []
    for i in range(0, len(data), 2):
        chunk = data[i:i + 2].ljust(2, b'\x00')
        win = struct.unpack('>H', chunk)[0]
        pkt = _wf_ip4_tcp(config, flags=0x02)
        pkt[TCP].window = win
        pkt[TCP].sport = config.sport + (i // 2)
        packets.append(pkt)
    return packets


def _encode_tcp_urgent(data: bytes, config: NetworkStegConfig) -> list[Packet]:
    """Encode 2 bytes per packet in the TCP urgent pointer field."""
    packets: list[Packet] = []
    for i in range(0, len(data), 2):
        chunk = data[i:i + 2].ljust(2, b'\x00')
        urg = struct.unpack('>H', chunk)[0]
        pkt = _wf_ip4_tcp(config, flags=0x02)
        # Use URG flag so the urgent pointer is meaningful
        pkt[TCP].flags = "US"
        pkt[TCP].urgptr = urg
        pkt[TCP].sport = config.sport + (i // 2)
        packets.append(pkt)
    return packets


def _encode_icmp_payload(data: bytes, config: NetworkStegConfig) -> list[Packet]:
    """Encode up to 32 bytes per packet in the ICMP echo payload."""
    packets: list[Packet] = []
    chunk_size = METHOD_BYTES_PER_PACKET[StegoMethod.ICMP_PAYLOAD]
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        # Build ICMP echo request with payload via scapy's / operator
        icmp_layer = ICMP(type=8, code=0)
        pkt = (
            _fake_ether()
            / IP(src=config.src_ip, dst=config.dst_ip)
            / icmp_layer
            / Raw(chunk)
        )
        packets.append(pkt)
    return packets


def _encode_dns_label(data: bytes, config: NetworkStegConfig) -> list[Packet]:
    """Encode data in DNS query-name labels using base32."""
    encoded = base64.b32encode(data).decode().lower().rstrip('=')
    # Split into DNS-safe labels (max 63 chars each)
    labels = [encoded[i:i + 60] for i in range(0, len(encoded), 60)]
    packets: list[Packet] = []
    for i, label in enumerate(labels):
        pkt = _wf_ip4_udp_dns(config)
        pkt[DNS].qd = DNSQR(qname=f"{label}.{config.cover_domain}", qtype="A")
        pkt[UDP].sport = config.sport + i
        packets.append(pkt)
    return packets


def _encode_dns_txt(data: bytes, config: NetworkStegConfig) -> list[Packet]:
    """Encode data in DNS TXT record RDATA using base64."""
    encoded = base64.b64encode(data).decode()
    packets: list[Packet] = []
    max_label = METHOD_BYTES_PER_PACKET[StegoMethod.DNS_TXT]
    for i in range(0, len(encoded), max_label):
        chunk = encoded[i:i + max_label]
        pkt = (
            _fake_ether()
            / IP(src=config.src_ip, dst=config.dst_ip)
            / UDP(sport=config.sport + (i // max_label), dport=53)
            / DNS(
                qr=1,  # Response
                qd=DNSQR(qname=config.cover_domain, qtype="TXT"),
                an=None,  # We fill this below
            )
        )
        # scapy doesn't handle TXT RDATA easily via constructor args,
        # so build the DNS answer section raw.  For simplicity we write
        # the whole DNS layer as a Raw payload over UDP.
        labels_encoded = b''.join(
            bytes([len(p)]) + p.encode('ascii')
            for p in config.cover_domain.split('.')
        )
        dns_payload = (
            b'\x00\x01'           # Transaction ID
            b'\x81\x80'           # Flags: response, no error
            b'\x00\x01'           # QDCOUNT = 1
            b'\x00\x01'           # ANCOUNT = 1
            b'\x00\x00'           # NSCOUNT = 0
            b'\x00\x00'           # ARCOUNT = 0
            + labels_encoded + b'\x00'  # QNAME
            + b'\x00\x10'         # QTYPE = TXT
            + b'\x00\x01'         # QCLASS = IN
            # Answer: pointer to QNAME, TYPE=TXT, CLASS=IN, TTL=300
            + b'\xc0\x0c'
            + b'\x00\x10'
            + b'\x00\x01'
            + b'\x00\x00\x01\x2c'  # TTL = 300
            + struct.pack('>H', len(chunk) + 1)  # RDLENGTH
            + bytes([len(chunk)])  # TXT string length
            + chunk.encode('ascii')
        )
        pkt = (
            _fake_ether()
            / IP(src=config.src_ip, dst=config.dst_ip)
            / UDP(sport=config.sport + (i // max_label), dport=53)
            / Raw(dns_payload)
        )
        packets.append(pkt)
    return packets


def _encode_http_header(data: bytes, config: NetworkStegConfig) -> list[Packet]:
    """Encode all data in a single HTTP request with a hex-encoded X- header.

    The handshake packets come from the wire format builder; the final
    data-carrying HTTP GET is appended.
    """
    # Start with the 3-way handshake
    handshake = _wf_ip4_tcp_http(config)
    client_isn = 1000
    server_isn = 2000

    # Build HTTP request with hex-encoded data in a custom header
    hex_data = data.hex()
    http_req = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {config.dst_ip}\r\n"
        f"X-Steg-Data: {hex_data}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    http_pkt = (
        _fake_ether()
        / IP(src=config.src_ip, dst=config.dst_ip)
        / TCP(sport=config.sport, dport=config.dport, flags="PA",
              seq=client_isn + 1, ack=server_isn + 1)
        / Raw(http_req.encode('ascii'))
    )
    return handshake + [http_pkt]


def _encode_covert_timing(data: bytes, config: NetworkStegConfig) -> list[Packet]:
    """Encode 1 bit per inter-packet delay gap.

    The timing information is NOT stored in the PCAP packets themselves —
    it lives in the inter-packet arrival times recorded in the PCAP
    per-packet headers.  The encode function returns packets without
    timestamps; the top-level encode() injects the timing by adjusting
    the PCAP timestamps after packet generation.
    """
    # Convert data to bit string
    bits = ''.join(f'{b:08b}' for b in data)
    pkt_template = _WF_BUILDERS[config.wire_format](config)
    packets: list[Packet] = []
    for i, bit_char in enumerate(bits):
        pkt = pkt_template.copy()
        if UDP in pkt:
            pkt[UDP].sport = config.sport + i
        packets.append(pkt)
    return packets


# ============== STEGO METHOD DECODERS ==============
#
# Each decoder takes a list of scapy Packets and returns the raw bytes
# that were encoded (including the NETH header and optional compression).
# The top-level decode() strips the framing and decompresses.
# ---------------------------------------------------------------------------


def _decode_ip_ttl(packets: list[Packet]) -> bytes:
    """Decode IP TTL stego: one byte per packet."""
    result = bytearray()
    for pkt in packets:
        if IP in pkt:
            result.append(pkt[IP].ttl)
    return bytes(result)


def _decode_ip_id(packets: list[Packet]) -> bytes:
    """Decode IP ID stego: two bytes per packet."""
    result = bytearray()
    for pkt in packets:
        if IP in pkt:
            result.extend(struct.pack('>H', pkt[IP].id))
    return bytes(result)


def _decode_tcp_isn(packets: list[Packet]) -> bytes:
    """Decode TCP ISN stego: 4 bytes per SYN packet."""
    result = bytearray()
    for pkt in packets:
        if TCP in pkt and (pkt[TCP].flags & 0x02):  # SYN flag
            result.extend(struct.pack('>I', pkt[TCP].seq))
    return bytes(result)


def _decode_tcp_timestamp(packets: list[Packet]) -> bytes:
    """Decode TCP timestamp stego: 4 bytes per packet from TSval."""
    result = bytearray()
    for pkt in packets:
        if TCP in pkt:
            for opt in (pkt[TCP].options or []):
                if isinstance(opt, tuple) and opt[0] == 'Timestamp':
                    ts_val, _ = opt[1]
                    result.extend(struct.pack('>I', ts_val))
                    break
    return bytes(result)


def _decode_tcp_window(packets: list[Packet]) -> bytes:
    """Decode TCP window stego: 2 bytes per packet."""
    result = bytearray()
    for pkt in packets:
        if TCP in pkt:
            result.extend(struct.pack('>H', pkt[TCP].window))
    return bytes(result)


def _decode_tcp_urgent(packets: list[Packet]) -> bytes:
    """Decode TCP urgent pointer stego: 2 bytes per URG packet."""
    result = bytearray()
    for pkt in packets:
        if TCP in pkt and (pkt[TCP].flags & 0x20):  # URG flag
            result.extend(struct.pack('>H', pkt[TCP].urgptr))
    return bytes(result)


def _decode_icmp_payload(packets: list[Packet]) -> bytes:
    """Decode ICMP payload stego: variable bytes per echo packet."""
    result = bytearray()
    chunk_size = METHOD_BYTES_PER_PACKET[StegoMethod.ICMP_PAYLOAD]
    for pkt in packets:
        if ICMP in pkt and Raw in pkt:
            result.extend(bytes(pkt[Raw])[:chunk_size])
    return bytes(result)


def _decode_dns_label(packets: list[Packet]) -> bytes:
    """Decode DNS label stego: base32-encoded data from QNAME labels."""
    encoded_parts: list[str] = []
    for pkt in packets:
        if DNS in pkt and pkt[DNS].qd:
            qname = pkt[DNS].qd.qname
            if isinstance(qname, bytes):
                qname = qname.decode('ascii', errors='replace')
            # The first label (before the first dot) carries the data
            first_label = qname.split('.')[0] if '.' in qname else qname
            encoded_parts.append(first_label)
    if not encoded_parts:
        return b''
    combined = ''.join(encoded_parts).upper()
    # Add padding for base32 decode
    pad = (8 - len(combined) % 8) % 8
    combined += '=' * pad
    try:
        return base64.b32decode(combined)
    except Exception:
        return b''


def _decode_dns_txt(packets: list[Packet]) -> bytes:
    """Decode DNS TXT stego: base64-encoded data from TXT response records."""
    encoded_parts: list[str] = []
    for pkt in packets:
        if DNS in pkt:
            dns = pkt[DNS]
            # Collect TXT RDATA from answer records
            for rr in (dns.an or []):
                if getattr(rr, 'type', None) == 16:  # TXT
                    rdata = getattr(rr, 'rdata', None)
                    if rdata:
                        for item in rdata:
                            if isinstance(item, bytes):
                                encoded_parts.append(item.decode('ascii', errors='ignore'))
                            elif isinstance(item, str):
                                encoded_parts.append(item)
    if not encoded_parts:
        return b''
    combined = ''.join(encoded_parts)
    try:
        return base64.b64decode(combined)
    except Exception:
        return b''


def _decode_http_header(packets: list[Packet]) -> bytes:
    """Decode HTTP header stego: hex-encoded data from X-Steg-Data header."""
    for pkt in packets:
        if Raw in pkt:
            raw = bytes(pkt[Raw])
            try:
                text = raw.decode('ascii', errors='ignore')
            except Exception:
                continue
            # Look for X-Steg-Data: <hex>
            import re as _re
            m = _re.search(r'X-Steg-Data:\s*([0-9a-fA-F]+)', text)
            if m:
                try:
                    return bytes.fromhex(m.group(1))
                except Exception:
                    continue
    return b''


def _decode_covert_timing(packets: list[Packet]) -> bytes:
    """Decode covert timing stego: 1 bit per inter-packet delay.

    Requires the packets to have their original timestamps (from PCAP).
    """
    if len(packets) < 16:
        return b''
    times = [float(pkt.time) for pkt in packets if hasattr(pkt, 'time')]
    if len(times) < 16:
        return b''
    delays = [times[i + 1] - times[i] for i in range(len(times) - 1)]
    median = sorted(delays)[len(delays) // 2]
    bits = ['1' if d > median else '0' for d in delays]
    return _bits_to_bytes(bits)


# ============== DISPATCH TABLES ==============


_ENCODERS: dict[StegoMethod, Callable] = {
    StegoMethod.IP_TTL:        _encode_ip_ttl,
    StegoMethod.IP_ID:         _encode_ip_id,
    StegoMethod.TCP_ISN:       _encode_tcp_isn,
    StegoMethod.TCP_TIMESTAMP:  _encode_tcp_timestamp,
    StegoMethod.TCP_WINDOW:    _encode_tcp_window,
    StegoMethod.TCP_URGENT:    _encode_tcp_urgent,
    StegoMethod.ICMP_PAYLOAD:  _encode_icmp_payload,
    StegoMethod.DNS_LABEL:     _encode_dns_label,
    StegoMethod.DNS_TXT:       _encode_dns_txt,
    StegoMethod.HTTP_HEADER:   _encode_http_header,
    StegoMethod.COVERT_TIMING: _encode_covert_timing,
}


_DECODERS: dict[StegoMethod, Callable] = {
    StegoMethod.IP_TTL:        _decode_ip_ttl,
    StegoMethod.IP_ID:         _decode_ip_id,
    StegoMethod.TCP_ISN:       _decode_tcp_isn,
    StegoMethod.TCP_TIMESTAMP:  _decode_tcp_timestamp,
    StegoMethod.TCP_WINDOW:    _decode_tcp_window,
    StegoMethod.TCP_URGENT:    _decode_tcp_urgent,
    StegoMethod.ICMP_PAYLOAD:  _decode_icmp_payload,
    StegoMethod.DNS_LABEL:     _decode_dns_label,
    StegoMethod.DNS_TXT:       _decode_dns_txt,
    StegoMethod.HTTP_HEADER:   _decode_http_header,
    StegoMethod.COVERT_TIMING: _decode_covert_timing,
}


# ============== HELPERS ==============


def _bits_to_bytes(bits: list[str]) -> bytes:
    """Convert a list of '0'/'1' strings to bytes (big-endian bits)."""
    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte_val = 0
        for j in range(8):
            if i + j < len(bits):
                byte_val = (byte_val << 1) | int(bits[i + j])
        result.append(byte_val)
    return bytes(result)


# ============== PUBLIC API ==============


def encode(payload: bytes, config: NetworkStegConfig) -> bytes:
    """Encode *payload* into a PCAP file using the given config.

    Returns the complete PCAP file as bytes.
    """
    # Build framing header (use stable uint8 IDs, not enum string values)
    header = NetworkFrameHeader(
        method=_METHOD_ID[config.method],
        wire_format=_WIRE_FORMAT_ID[config.wire_format],
        payload_length=len(payload),
        crc32=zlib.crc32(payload) & 0xFFFFFFFF,
    )
    framed = header.to_bytes() + payload

    # Optional compression
    if config.use_compression:
        framed = zlib.compress(framed)

    # Encode via the selected method
    encoder = _ENCODERS.get(config.method)
    if encoder is None:
        raise ValueError(f"No encoder for method {config.method.value}")
    packets = encoder(framed, config)

    # Write PCAP to a temp file (wrpcap closes its handle; BytesIO breaks)
    import tempfile, os as _os
    tmpdir = tempfile.mkdtemp()
    try:
        tmppath = _os.path.join(tmpdir, "steg.pcap")
        wrpcap(tmppath, packets)
        with open(tmppath, "rb") as _f:
            return _f.read()
    finally:
        import shutil as _shutil
        _shutil.rmtree(tmpdir, ignore_errors=True)


def decode(pcap_data: bytes, method: Optional[StegoMethod] = None) -> dict:
    """Decode a PCAP file and extract the hidden payload.

    If *method* is None, auto-detection is attempted by trying each
    known decoder.  Returns a dict with keys:

    * ``found`` — bool
    * ``payload`` — bytes (if found)
    * ``method`` — stego method used (if detected)
    * ``wire_format`` — wire format used (if detected)
    * ``packets`` — number of packets in the PCAP
    * ``error`` — error message (if not found)
    """
    import tempfile, os as _os
    tmpdir = tempfile.mkdtemp()
    try:
        tmppath = _os.path.join(tmpdir, "steg.pcap")
        with open(tmppath, "wb") as _f:
            _f.write(pcap_data)
        all_packets = rdpcap(tmppath)
    except Exception as exc:
        import shutil as _shutil
        _shutil.rmtree(tmpdir, ignore_errors=True)
        return {'found': False, 'error': f'Failed to read PCAP: {exc}', 'packets': 0}

    if method is not None:
        decoders = {method: _DECODERS.get(method)}
    else:
        decoders = _DECODERS

    for meth, decoder_fn in decoders.items():
        if decoder_fn is None:
            continue
        try:
            raw = decoder_fn(all_packets)
            if not raw or len(raw) < NETH_HEADER_SIZE:
                continue
            # Try to parse the NETH header
            try:
                header = NetworkFrameHeader.from_bytes(raw)
            except ValueError:
                continue
            # Extract and verify payload
            payload = raw[NETH_HEADER_SIZE:NETH_HEADER_SIZE + header.payload_length]
            if len(payload) != header.payload_length:
                # Possibly compressed — try decompress first
                try:
                    decompressed = zlib.decompress(raw)
                    header = NetworkFrameHeader.from_bytes(decompressed)
                    payload = decompressed[NETH_HEADER_SIZE:NETH_HEADER_SIZE + header.payload_length]
                except Exception:
                    continue
            # Verify CRC32
            computed_crc = zlib.crc32(payload) & 0xFFFFFFFF
            if computed_crc != header.crc32:
                continue
            meth_enum = _ID_TO_METHOD.get(header.method)
            wf_enum = _ID_TO_WIRE_FORMAT.get(header.wire_format)
            return {
                'found': True,
                'payload': payload,
                'method': meth_enum.value if meth_enum else str(header.method),
                'wire_format': wf_enum.value if wf_enum else str(header.wire_format),
                'packets': len(all_packets),
            }
        except Exception:
            continue

    # If we get here, try decompressing first, then re-scan
    for meth, decoder_fn in decoders.items():
        if decoder_fn is None:
            continue
        try:
            raw = decoder_fn(all_packets)
            if not raw:
                continue
            decompressed = zlib.decompress(raw)
            if len(decompressed) < NETH_HEADER_SIZE:
                continue
            try:
                header = NetworkFrameHeader.from_bytes(decompressed)
            except ValueError:
                continue
            payload = decompressed[NETH_HEADER_SIZE:NETH_HEADER_SIZE + header.payload_length]
            computed_crc = zlib.crc32(payload) & 0xFFFFFFFF
            if computed_crc == header.crc32:
                meth_id = header.method
                wf_id = header.wire_format
                meth_enum = _ID_TO_METHOD.get(meth_id)
                wf_enum = _ID_TO_WIRE_FORMAT.get(wf_id)
                return {
                    'found': True,
                    'payload': payload,
                    'method': meth_enum.value if meth_enum else str(meth_id),
                    'wire_format': wf_enum.value if wf_enum else str(wf_id),
                    'packets': len(all_packets),
                }
        except Exception:
            continue

    return {'found': False, 'packets': len(all_packets)}


def decode_neth_framed_payload(pcap_data: bytes) -> dict:
    """Auto-detect and decode NETH-framed network steganography in a PCAP file.

    Tries all known decoders in sequence; returns the first payload whose
    NETH magic + CRC32 validates.  This is NOT statistical detection — it
    looks for the explicit NETH framing header, not anomalous field
    distributions.

    Convenience wrapper around ``decode()`` with method=None.
    Returns the same dict shape as ``decode()``.
    """
    return decode(pcap_data, method=None)


def calculate_capacity(config: NetworkStegConfig, max_packets: int = 1000) -> dict:
    """Calculate how many bytes can be encoded with the given config.

    Returns a dict with:
    * ``bytes_per_packet`` — raw capacity per packet
    * ``max_payload_bytes`` — max payload (after framing + compression overhead)
    * ``packets_needed`` — packets needed for a hypothetical 256-byte payload
    """
    bpp = METHOD_BYTES_PER_PACKET.get(config.method, 0)
    if bpp == 0:
        # Variable / single-packet methods
        overhead = NETH_HEADER_SIZE
        return {
            'bytes_per_packet': 0,
            'max_payload_bytes': 65535 - overhead,
            'packets_needed': 1,
            'note': 'variable-length method — single or few packets',
        }
    overhead = NETH_HEADER_SIZE  # framing header
    if config.use_compression:
        overhead += 16  # rough estimate for zlib wrapper
    capacity = max_packets * bpp - overhead
    return {
        'bytes_per_packet': bpp,
        'max_payload_bytes': max(0, capacity),
        'packets_needed': max(1, (256 + overhead + bpp - 1) // bpp),
    }


def list_methods() -> list[dict]:
    """List all available stego methods with their capacities and valid wire formats.

    Each entry also includes a ``detectable`` flag indicating whether a
    statistical detector exists for that method.
    """
    # _DETECTORS is defined later in this module; resolved at call time.
    detectable = set(_DETECTORS.keys())

    result: list[dict] = []
    for method in StegoMethod:
        bpp = METHOD_BYTES_PER_PACKET.get(method, 0)
        wire_formats = METHOD_WIRE_FORMATS.get(method, [])
        result.append({
            'method': method.value,
            'bytes_per_packet': bpp,
            'wire_formats': [wf.value for wf in wire_formats],
            'detectable': method.value in detectable,
        })
    return result


# ============== STATISTICAL DETECTION ==============
#
# Per-method statistical detectors that examine protocol field distributions
# and flag anomalies regardless of framing.  Each detector takes a list of
# scapy Packets and a DetectionConfig, and returns a StegDetectResult.
# ---------------------------------------------------------------------------


@dataclass
class StegDetectResult:
    """Verdict from a single per-method statistical detector.

    Attributes:
        method: Stego method name, e.g. ``"ip_ttl"``.
        suspicious: Whether the detection threshold was exceeded.
        confidence: Estimated confidence that stego is present (0.0 – 1.0).
        score: Raw test statistic (higher = more anomalous).
        threshold: Decision boundary used for this test.
        test_name: Name of the statistical test applied.
        details: Per-test breakdown with intermediate values.
    """

    method: str
    suspicious: bool
    confidence: float  # 0.0 – 1.0
    score: float       # raw test statistic
    threshold: float   # decision boundary
    test_name: str
    details: dict = field(default_factory=dict)


@dataclass
class DetectionConfig:
    """Tunable thresholds for each detector.

    All thresholds are module-level defaults, overridable per-call.
    Thresholds are calibrated against common OS / protocol behaviour;
    raising a threshold reduces false positives, lowering it increases
    sensitivity.
    """

    # IP TTL — chi-square against expected OS TTL distribution.
    # Normal OS TTLs cluster at 64, 128, 255; stego TTLs spread uniformly.
    ttl_chi_square_threshold: float = 50.0

    # IP ID — runs-test p-value.  OS counters are sequential (few runs);
    # stego values are structured byte chunks (many runs).
    ip_id_runs_p_value: float = 0.01

    # TCP ISN / timestamp — entropy threshold in bits per byte.
    # Crypto-random ISNs have entropy near 8; stego ISNs carry payload
    # bytes whose entropy depends on content (compressed ≈ 8, text ≈ 4–6).
    isn_entropy_threshold: float = 6.5

    # TCP window — standard deviation threshold.  Normal windows cluster
    # around OS defaults (65535, 29200, 8192); stego windows span 16 bits.
    window_stdev_threshold: float = 20000

    # ICMP payload — entropy threshold.  Normal ICMP payloads are
    # structured (timestamps, fixed patterns); stego payloads look like
    # compressed / encrypted data.
    icmp_entropy_threshold: float = 7.0

    # DNS label — entropy threshold in bits per character.
    # Normal labels are dictionary words (low entropy); base32 stego
    # labels approach 5 bits/char uniformly.
    dns_label_entropy_threshold: float = 4.5

    # DNS TXT — minimum fraction of packets carrying TXT records.
    # TXT records are rare outside SPF / DKIM; >2 % is suspicious.
    dns_txt_freq_threshold: float = 0.02

    # Covert timing — bimodality score threshold.
    # Normal jitter is unimodal; stego timing has two distinct peaks.
    timing_bimodality_threshold: float = 0.5

    # TCP URG — fraction of TCP packets with URG flag set.
    # URG is almost never used in normal traffic.
    tcp_urg_freq_threshold: float = 0.1

    # HTTP — minimum fraction of packets with custom X- headers.
    http_custom_header_threshold: float = 0.5

    # Minimum number of relevant packets before a detector runs.
    # Fewer than this and the statistical signal is too weak.
    min_packets: int = 8


# ============== STATISTICAL HELPERS ==============


def _detect_entropy(data: bytes | list[int]) -> float:
    """Shannon entropy in bits per element.  Returns 0.0 for empty input."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum(
        (c / total) * math.log2(c / total) for c in counts.values() if c > 0
    )


def _detect_normal_cdf(x: float) -> float:
    """Standard normal CDF via ``math.erf``."""
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2)))


def _detect_chi_square_statistic(
    observed: dict[int, int],
    expected_probs: dict[int, float],
    total: int,
) -> float:
    """Compute Pearson chi-square statistic.

    *observed* maps bin → count.  *expected_probs* maps bin → probability
    (must sum to ≤ 1.0; remaining mass is treated as uniform across
    unlisted bins).  *total* is the sum of observed counts.
    """
    if total == 0:
        return 0.0
    chi2 = 0.0
    listed_mass = sum(expected_probs.values())
    all_bins = set(observed.keys()) | set(expected_probs.keys())
    remaining_bins = max(len(all_bins) - len(expected_probs), 1)
    remaining_mass = max(1.0 - listed_mass, 0.0)
    for b in all_bins:
        o = observed.get(b, 0)
        if b in expected_probs:
            e = total * expected_probs[b]
        else:
            e = total * remaining_mass / remaining_bins
        if e > 0:
            chi2 += (o - e) ** 2 / e
        elif o > 0:
            chi2 += float('inf')
    return chi2


def _detect_runs_test_pvalue(values: list[int]) -> float:
    """Wald–Wolfowitz runs test p-value (two-tailed, normal approximation).

    Low p-value → sequence is *more* random than expected by chance.
    The test detects serial dependence: sequential OS counters produce
    fewer runs than random data.
    """
    n = len(values)
    if n < 2:
        return 1.0
    median = sorted(values)[n // 2]
    binary = [1 if v > median else 0 for v in values]
    runs = 1
    for i in range(1, n):
        if binary[i] != binary[i - 1]:
            runs += 1
    n1 = sum(binary)
    n0 = n - n1
    if n1 == 0 or n0 == 0:
        return 0.0
    expected = 2.0 * n1 * n0 / n + 1.0
    var = (
        2.0 * n1 * n0 * (2.0 * n1 * n0 - n)
        / (n * n * (n - 1))
    )
    if var <= 0:
        return 0.0
    z = (runs - expected) / math.sqrt(var)
    return 2.0 * (1.0 - _detect_normal_cdf(abs(z)))


def _detect_frequency_test_pvalue(values: list[int], bits: int = 8) -> float:
    """NIST SP 800-22 monobit frequency test (approximate)."""
    if not values:
        return 1.0
    ones = 0
    total_bits = 0
    for v in values:
        for j in range(bits):
            if v & (1 << j):
                ones += 1
            total_bits += 1
    if total_bits == 0:
        return 1.0
    proportion = ones / total_bits
    s_obs = abs(proportion - 0.5) / math.sqrt(0.25 / total_bits)
    return math.erfc(s_obs / math.sqrt(2))


def _detect_bimodality_score(values: list[float]) -> float:
    """Score bimodality on [0, 1].  0 = unimodal, 1 = clearly bimodal.

    Splits values at median, then compares within-cluster variance to
    total variance.  Two tight, well-separated clusters produce a high
    score.
    """
    n = len(values)
    if n < 10:
        return 0.0
    sorted_vals = sorted(values)
    median = sorted_vals[n // 2]
    lower = [v for v in values if v <= median]
    upper = [v for v in values if v > median]
    if len(lower) < 3 or len(upper) < 3:
        return 0.0
    total_mean = sum(values) / n
    total_var = sum((v - total_mean) ** 2 for v in values) / n
    if total_var == 0:
        return 0.0
    lower_mean = sum(lower) / len(lower)
    upper_mean = sum(upper) / len(upper)
    lower_var = sum((v - lower_mean) ** 2 for v in lower) / len(lower)
    upper_var = sum((v - upper_mean) ** 2 for v in upper) / len(upper)
    within_var = (lower_var * len(lower) + upper_var * len(upper)) / n
    ratio = 1.0 - (within_var / total_var)
    return max(0.0, min(1.0, ratio))


def _detect_confidence_from_ratio(score: float, threshold: float, direction: str = 'above') -> float:
    """Map a score + threshold to a [0, 1] confidence.

    *direction*: ``'above'`` means suspicious when score > threshold;
    ``'below'`` means suspicious when score < threshold.
    """
    if direction == 'above':
        if threshold == 0:
            return 1.0 if score > 0 else 0.0
        ratio = score / threshold
    else:
        if threshold == 0:
            return 1.0 if score < float('inf') else 0.0
        ratio = threshold / max(score, 1e-10)
    if ratio <= 0:
        return 0.0
    return 1.0 - math.exp(-ratio)


def _detect_confidence_from_pvalue(p_value: float, alpha: float) -> float:
    """Map a p-value to confidence.  p < alpha → high confidence."""
    if p_value <= 0:
        return 1.0
    if p_value >= alpha:
        return 0.0
    return 1.0 - (p_value / alpha)


# ============== PER-METHOD DETECTORS ==============
#
# Each detector takes (packets: list[Packet], config: DetectionConfig)
# and returns a StegDetectResult.
# ---------------------------------------------------------------------------


#: Expected TTL distribution for common OS traffic (RFC 1700 / empirical).
_DETECT_EXPECTED_TTL_PROBS: dict[int, float] = {
    64:  0.45,
    128: 0.30,
    255: 0.15,
    32:  0.03,
    60:  0.02,
}


def _detect_ip_ttl(packets: list[Packet], config: DetectionConfig) -> StegDetectResult:
    """Detect IP TTL stego: chi-square against expected OS TTL distribution."""
    ttls: list[int] = []
    for pkt in packets:
        if IP in pkt:
            ttls.append(pkt[IP].ttl)
    if len(ttls) < config.min_packets:
        return StegDetectResult(
            method='ip_ttl', suspicious=False, confidence=0.0,
            score=0.0, threshold=config.ttl_chi_square_threshold,
            test_name='chi_square_expected_os',
            details={'ttl_count': len(ttls),
                     'note': f'need ≥{config.min_packets} IP packets'},
        )
    observed: dict[int, int] = {}
    for t in ttls:
        observed[t] = observed.get(t, 0) + 1
    chi2 = _detect_chi_square_statistic(observed, _DETECT_EXPECTED_TTL_PROBS, len(ttls))
    suspicious = chi2 > config.ttl_chi_square_threshold
    confidence = _detect_confidence_from_ratio(chi2, config.ttl_chi_square_threshold, 'above')
    entropy_val = _detect_entropy(ttls)
    return StegDetectResult(
        method='ip_ttl', suspicious=suspicious,
        confidence=min(confidence, 1.0), score=chi2,
        threshold=config.ttl_chi_square_threshold,
        test_name='chi_square_expected_os',
        details={
            'ttl_count': len(ttls), 'chi_square': round(chi2, 2),
            'entropy': round(entropy_val, 3), 'unique_ttls': len(set(ttls)),
            'most_common': Counter(ttls).most_common(4),
        },
    )


def _detect_ip_id(packets: list[Packet], config: DetectionConfig) -> StegDetectResult:
    """Detect IP ID stego: runs test for serial randomness."""
    ip_ids: list[int] = []
    for pkt in packets:
        if IP in pkt:
            ip_ids.append(pkt[IP].id)
    if len(ip_ids) < config.min_packets:
        return StegDetectResult(
            method='ip_id', suspicious=False, confidence=0.0,
            score=0.0, threshold=config.ip_id_runs_p_value,
            test_name='runs_test',
            details={'ip_id_count': len(ip_ids),
                     'note': f'need ≥{config.min_packets} IP packets'},
        )
    p_value = _detect_runs_test_pvalue(ip_ids)
    suspicious = p_value < config.ip_id_runs_p_value
    confidence = _detect_confidence_from_pvalue(p_value, config.ip_id_runs_p_value)
    bytes_data = b''.join(struct.pack('>H', v) for v in ip_ids)
    entropy_val = _detect_entropy(bytes_data)
    return StegDetectResult(
        method='ip_id', suspicious=suspicious,
        confidence=min(confidence, 1.0), score=p_value,
        threshold=config.ip_id_runs_p_value,
        test_name='runs_test',
        details={
            'ip_id_count': len(ip_ids), 'runs_p_value': round(p_value, 6),
            'entropy': round(entropy_val, 3), 'unique_ids': len(set(ip_ids)),
        },
    )


def _detect_tcp_isn(packets: list[Packet], config: DetectionConfig) -> StegDetectResult:
    """Detect TCP ISN stego: entropy + frequency test."""
    isns: list[int] = []
    for pkt in packets:
        if TCP in pkt and (pkt[TCP].flags & 0x02):
            isns.append(pkt[TCP].seq)
    if len(isns) < config.min_packets:
        return StegDetectResult(
            method='tcp_isn', suspicious=False, confidence=0.0,
            score=0.0, threshold=config.isn_entropy_threshold,
            test_name='entropy_frequency',
            details={'syn_count': len(isns),
                     'note': f'need ≥{config.min_packets} SYN packets'},
        )
    bytes_data = b''.join(struct.pack('>I', v) for v in isns)
    entropy_val = _detect_entropy(bytes_data)
    p_value = _detect_frequency_test_pvalue(list(bytes_data), bits=8)
    suspicious = entropy_val < config.isn_entropy_threshold
    confidence = _detect_confidence_from_ratio(
        config.isn_entropy_threshold - entropy_val,
        config.isn_entropy_threshold * 0.5, 'above',
    )
    return StegDetectResult(
        method='tcp_isn', suspicious=suspicious,
        confidence=min(max(confidence, 0.0), 1.0),
        score=entropy_val, threshold=config.isn_entropy_threshold,
        test_name='entropy_frequency',
        details={
            'syn_count': len(isns), 'entropy': round(entropy_val, 3),
            'frequency_p_value': round(p_value, 6), 'unique_isns': len(set(isns)),
        },
    )


def _detect_tcp_timestamp(packets: list[Packet], config: DetectionConfig) -> StegDetectResult:
    """Detect TCP timestamp stego: monotonicity check + entropy."""
    ts_vals: list[int] = []
    for pkt in packets:
        if TCP in pkt:
            for opt in (pkt[TCP].options or []):
                if isinstance(opt, tuple) and opt[0] == 'Timestamp':
                    ts_vals.append(opt[1][0])
                    break
    if len(ts_vals) < config.min_packets:
        return StegDetectResult(
            method='tcp_timestamp', suspicious=False, confidence=0.0,
            score=0.0, threshold=config.isn_entropy_threshold,
            test_name='monotonicity_entropy',
            details={'ts_count': len(ts_vals),
                     'note': f'need ≥{config.min_packets} timestamp packets'},
        )
    increases = sum(1 for i in range(1, len(ts_vals)) if ts_vals[i] > ts_vals[i - 1])
    monotonic_ratio = increases / max(len(ts_vals) - 1, 1)
    bytes_data = b''.join(struct.pack('>I', v) for v in ts_vals)
    entropy_val = _detect_entropy(bytes_data)
    suspicious = monotonic_ratio < 0.6 or entropy_val < config.isn_entropy_threshold
    confidence = min(max(
        1.0 - monotonic_ratio,
        _detect_confidence_from_ratio(
            config.isn_entropy_threshold - entropy_val,
            config.isn_entropy_threshold * 0.5, 'above',
        ),
    ), 1.0)
    return StegDetectResult(
        method='tcp_timestamp', suspicious=suspicious,
        confidence=confidence, score=1.0 - monotonic_ratio,
        threshold=0.4,
        test_name='monotonicity_entropy',
        details={
            'ts_count': len(ts_vals), 'monotonic_ratio': round(monotonic_ratio, 3),
            'entropy': round(entropy_val, 3),
            'min_ts': min(ts_vals), 'max_ts': max(ts_vals),
        },
    )


def _detect_tcp_window(packets: list[Packet], config: DetectionConfig) -> StegDetectResult:
    """Detect TCP window stego: standard deviation + outlier ratio."""
    windows: list[int] = []
    for pkt in packets:
        if TCP in pkt:
            windows.append(pkt[TCP].window)
    if len(windows) < config.min_packets:
        return StegDetectResult(
            method='tcp_window', suspicious=False, confidence=0.0,
            score=0.0, threshold=config.window_stdev_threshold,
            test_name='stdev_outlier',
            details={'window_count': len(windows),
                     'note': f'need ≥{config.min_packets} TCP packets'},
        )
    mean_w = sum(windows) / len(windows)
    variance = sum((w - mean_w) ** 2 for w in windows) / len(windows)
    stdev = math.sqrt(variance)
    common_windows = {65535, 29200, 8192, 16384, 32768, 64240, 14600}
    outlier_ratio = sum(1 for w in windows if w not in common_windows) / len(windows)
    suspicious = stdev > config.window_stdev_threshold
    confidence = _detect_confidence_from_ratio(stdev, config.window_stdev_threshold, 'above')
    return StegDetectResult(
        method='tcp_window', suspicious=suspicious,
        confidence=min(confidence, 1.0), score=stdev,
        threshold=config.window_stdev_threshold,
        test_name='stdev_outlier',
        details={
            'window_count': len(windows), 'stdev': round(stdev, 1),
            'mean': round(mean_w, 1), 'outlier_ratio': round(outlier_ratio, 3),
            'range': f'{min(windows)}–{max(windows)}',
        },
    )


def _detect_tcp_urgent(packets: list[Packet], config: DetectionConfig) -> StegDetectResult:
    """Detect TCP urgent pointer stego: URG flag frequency."""
    tcp_count = 0
    urg_count = 0
    urg_vals: list[int] = []
    for pkt in packets:
        if TCP in pkt:
            tcp_count += 1
            if pkt[TCP].flags & 0x20:
                urg_count += 1
                urg_vals.append(pkt[TCP].urgptr)
    if tcp_count < config.min_packets:
        return StegDetectResult(
            method='tcp_urgent', suspicious=False, confidence=0.0,
            score=0.0, threshold=config.tcp_urg_freq_threshold,
            test_name='urg_frequency',
            details={'tcp_count': tcp_count,
                     'note': f'need ≥{config.min_packets} TCP packets'},
        )
    urg_ratio = urg_count / tcp_count if tcp_count > 0 else 0.0
    suspicious = urg_ratio > config.tcp_urg_freq_threshold
    confidence = _detect_confidence_from_ratio(urg_ratio, config.tcp_urg_freq_threshold, 'above')
    entropy_val = _detect_entropy(urg_vals) if urg_vals else 0.0
    return StegDetectResult(
        method='tcp_urgent', suspicious=suspicious,
        confidence=min(confidence, 1.0), score=urg_ratio,
        threshold=config.tcp_urg_freq_threshold,
        test_name='urg_frequency',
        details={
            'tcp_count': tcp_count, 'urg_count': urg_count,
            'urg_ratio': round(urg_ratio, 4),
            'urg_entropy': round(entropy_val, 3) if urg_vals else None,
        },
    )


def _detect_icmp_payload(packets: list[Packet], config: DetectionConfig) -> StegDetectResult:
    """Detect ICMP payload stego: payload entropy + printable ratio."""
    payloads: list[bytes] = []
    for pkt in packets:
        if ICMP in pkt and Raw in pkt:
            payloads.append(bytes(pkt[Raw]))
    if len(payloads) < config.min_packets:
        return StegDetectResult(
            method='icmp_payload', suspicious=False, confidence=0.0,
            score=0.0, threshold=config.icmp_entropy_threshold,
            test_name='payload_entropy',
            details={'icmp_count': len(payloads),
                     'note': f'need ≥{config.min_packets} ICMP payload packets'},
        )
    all_bytes = b''.join(payloads)
    entropy_val = _detect_entropy(all_bytes)
    printable = sum(1 for b in all_bytes if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    printable_ratio = printable / len(all_bytes) if all_bytes else 0.0
    suspicious = entropy_val > config.icmp_entropy_threshold
    confidence = _detect_confidence_from_ratio(entropy_val, config.icmp_entropy_threshold, 'above')
    return StegDetectResult(
        method='icmp_payload', suspicious=suspicious,
        confidence=min(confidence, 1.0), score=entropy_val,
        threshold=config.icmp_entropy_threshold,
        test_name='payload_entropy',
        details={
            'icmp_packet_count': len(payloads),
            'total_payload_bytes': len(all_bytes),
            'entropy': round(entropy_val, 3),
            'printable_ratio': round(printable_ratio, 3),
            'avg_payload_len': len(all_bytes) / len(payloads) if payloads else 0,
        },
    )


def _detect_dns_label(packets: list[Packet], config: DetectionConfig) -> StegDetectResult:
    """Detect DNS label stego: subdomain entropy + label length."""
    labels: list[str] = []
    for pkt in packets:
        if DNS in pkt and pkt[DNS].qd:
            qname = pkt[DNS].qd.qname
            if isinstance(qname, bytes):
                qname = qname.decode('ascii', errors='replace')
            first_label = qname.split('.')[0] if '.' in qname else qname
            if first_label:
                labels.append(first_label)
    if len(labels) < config.min_packets:
        return StegDetectResult(
            method='dns_label', suspicious=False, confidence=0.0,
            score=0.0, threshold=config.dns_label_entropy_threshold,
            test_name='label_entropy_length',
            details={'label_count': len(labels),
                     'note': f'need ≥{config.min_packets} DNS query packets'},
        )
    entropies = [_detect_entropy(l.encode('ascii', errors='replace')) for l in labels]
    avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
    max_entropy = max(entropies) if entropies else 0.0
    avg_length = sum(len(l) for l in labels) / len(labels) if labels else 0.0
    max_length = max(len(l) for l in labels) if labels else 0
    suspicious = avg_entropy > config.dns_label_entropy_threshold
    confidence = _detect_confidence_from_ratio(avg_entropy, config.dns_label_entropy_threshold, 'above')
    return StegDetectResult(
        method='dns_label', suspicious=suspicious,
        confidence=min(confidence, 1.0), score=avg_entropy,
        threshold=config.dns_label_entropy_threshold,
        test_name='label_entropy_length',
        details={
            'label_count': len(labels), 'avg_entropy': round(avg_entropy, 3),
            'max_entropy': round(max_entropy, 3),
            'avg_length': round(avg_length, 1), 'max_length': max_length,
            'sample_labels': labels[:5],
        },
    )


def _detect_dns_txt(packets: list[Packet], config: DetectionConfig) -> StegDetectResult:
    """Detect DNS TXT stego: TXT record frequency + RDATA entropy."""
    dns_count = 0
    txt_count = 0
    txt_data: list[bytes] = []
    for pkt in packets:
        if DNS in pkt:
            dns_count += 1
            dns_layer = pkt[DNS]
            for rr_list in (dns_layer.an, dns_layer.ns, dns_layer.ar):
                if rr_list is None:
                    continue
                for rr in (rr_list if isinstance(rr_list, list) else [rr_list]):
                    rr_type = getattr(rr, 'type', None)
                    if rr_type == 16:
                        txt_count += 1
                        rdata = getattr(rr, 'rdata', None)
                        if rdata:
                            for item in (rdata if isinstance(rdata, list) else [rdata]):
                                if isinstance(item, bytes):
                                    txt_data.append(item)
                                elif isinstance(item, str):
                                    txt_data.append(item.encode('utf-8', errors='replace'))
    if dns_count < config.min_packets:
        return StegDetectResult(
            method='dns_txt', suspicious=False, confidence=0.0,
            score=0.0, threshold=config.dns_txt_freq_threshold,
            test_name='txt_frequency_entropy',
            details={'dns_count': dns_count,
                     'note': f'need ≥{config.min_packets} DNS packets'},
        )
    txt_ratio = txt_count / dns_count if dns_count > 0 else 0.0
    all_txt = b''.join(txt_data)
    entropy_val = _detect_entropy(all_txt) if all_txt else 0.0
    suspicious = txt_ratio > config.dns_txt_freq_threshold or entropy_val > 6.0
    confidence = min(max(
        _detect_confidence_from_ratio(txt_ratio, config.dns_txt_freq_threshold, 'above'),
        _detect_confidence_from_ratio(entropy_val, 6.0, 'above'),
    ), 1.0)
    return StegDetectResult(
        method='dns_txt', suspicious=suspicious,
        confidence=confidence, score=txt_ratio,
        threshold=config.dns_txt_freq_threshold,
        test_name='txt_frequency_entropy',
        details={
            'dns_count': dns_count, 'txt_count': txt_count,
            'txt_ratio': round(txt_ratio, 4),
            'txt_entropy': round(entropy_val, 3), 'total_txt_bytes': len(all_txt),
        },
    )


#: Common HTTP header names (lowercase) — anything NOT in this set is
#: flagged as custom.  Based on RFC 7230 + common practice.
_DETECT_COMMON_HTTP_HEADERS: set[str] = {
    'host', 'user-agent', 'accept', 'accept-encoding', 'accept-language',
    'accept-charset', 'authorization', 'cache-control', 'connection',
    'content-type', 'content-length', 'content-encoding', 'content-language',
    'content-location', 'content-range', 'cookie', 'date', 'dnt', 'expect',
    'forwarded', 'from', 'if-match', 'if-modified-since', 'if-none-match',
    'if-range', 'if-unmodified-since', 'keep-alive', 'last-modified',
    'location', 'max-forwards', 'origin', 'pragma', 'proxy-authorization',
    'range', 'referer', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site',
    'sec-fetch-user', 'sec-websocket-key', 'sec-websocket-protocol',
    'sec-websocket-version', 'server', 'set-cookie', 'te', 'trailer',
    'transfer-encoding', 'upgrade', 'upgrade-insecure-requests', 'via',
    'warning', 'www-authenticate', 'x-forwarded-for', 'x-forwarded-host',
    'x-forwarded-proto', 'x-real-ip', 'x-requested-with',
}


def _detect_http_header(packets: list[Packet], config: DetectionConfig) -> StegDetectResult:
    """Detect HTTP header stego: custom header presence + value entropy."""
    http_count = 0
    custom_header_count = 0
    header_entropies: list[float] = []
    for pkt in packets:
        if Raw in pkt and TCP in pkt:
            raw = bytes(pkt[Raw])
            try:
                text = raw.decode('ascii', errors='replace')
            except Exception:
                continue
            if 'HTTP/' not in text and 'GET ' not in text and 'POST ' not in text:
                continue
            http_count += 1
            for line in text.split('\r\n'):
                m = re.match(r'^([A-Za-z][A-Za-z0-9-]*):\s*(.+)', line)
                if not m:
                    continue
                name, value = m.group(1), m.group(2)
                is_custom = (
                    name.lower().startswith('x-')
                    or name.lower() not in _DETECT_COMMON_HTTP_HEADERS
                )
                if is_custom:
                    custom_header_count += 1
                    header_entropies.append(_detect_entropy(value.encode('ascii', errors='replace')))
    if http_count < max(config.min_packets // 2, 2):
        return StegDetectResult(
            method='http_header', suspicious=False, confidence=0.0,
            score=0.0, threshold=config.http_custom_header_threshold,
            test_name='custom_header',
            details={'http_count': http_count,
                     'note': f'need ≥{max(config.min_packets // 2, 2)} HTTP packets'},
        )
    custom_ratio = custom_header_count / max(http_count, 1)
    avg_entropy = sum(header_entropies) / len(header_entropies) if header_entropies else 0.0
    suspicious = (
        custom_ratio > config.http_custom_header_threshold
        or avg_entropy > 5.0
    )
    confidence = min(max(
        _detect_confidence_from_ratio(custom_ratio, config.http_custom_header_threshold, 'above'),
        _detect_confidence_from_ratio(avg_entropy, 5.0, 'above'),
    ), 1.0)
    return StegDetectResult(
        method='http_header', suspicious=suspicious,
        confidence=confidence, score=custom_ratio,
        threshold=config.http_custom_header_threshold,
        test_name='custom_header',
        details={
            'http_count': http_count, 'custom_header_count': custom_header_count,
            'custom_ratio': round(custom_ratio, 3),
            'avg_header_value_entropy': round(avg_entropy, 3),
        },
    )


def _detect_covert_timing(packets: list[Packet], config: DetectionConfig) -> StegDetectResult:
    """Detect covert timing stego: inter-packet delay bimodality."""
    times: list[float] = []
    for pkt in packets:
        if hasattr(pkt, 'time'):
            times.append(float(pkt.time))
    if len(times) < config.min_packets + 1:
        return StegDetectResult(
            method='covert_timing', suspicious=False, confidence=0.0,
            score=0.0, threshold=config.timing_bimodality_threshold,
            test_name='bimodality',
            details={'packet_count': len(times),
                     'note': f'need ≥{config.min_packets + 1} timestamped packets'},
        )
    delays = [times[i + 1] - times[i] for i in range(len(times) - 1)]
    delays = [d for d in delays if d > 0]
    if len(delays) < config.min_packets:
        return StegDetectResult(
            method='covert_timing', suspicious=False, confidence=0.0,
            score=0.0, threshold=config.timing_bimodality_threshold,
            test_name='bimodality',
            details={'delay_count': len(delays),
                     'note': f'need ≥{config.min_packets} non-zero delays'},
        )
    bimodality = _detect_bimodality_score(delays)
    suspicious = bimodality > config.timing_bimodality_threshold
    confidence = _detect_confidence_from_ratio(bimodality, config.timing_bimodality_threshold, 'above')
    sorted_d = sorted(delays)
    median_d = sorted_d[len(sorted_d) // 2]
    lower = [d for d in delays if d <= median_d]
    upper = [d for d in delays if d > median_d]
    lower_cv = math.sqrt(
        sum((d - sum(lower) / len(lower)) ** 2 for d in lower) / len(lower)
    ) / (sum(lower) / len(lower)) if lower and sum(lower) / len(lower) > 0 else 0
    upper_cv = math.sqrt(
        sum((d - sum(upper) / len(upper)) ** 2 for d in upper) / len(upper)
    ) / (sum(upper) / len(upper)) if upper and sum(upper) / len(upper) > 0 else 0
    return StegDetectResult(
        method='covert_timing', suspicious=suspicious,
        confidence=min(confidence, 1.0), score=bimodality,
        threshold=config.timing_bimodality_threshold,
        test_name='bimodality',
        details={
            'delay_count': len(delays),
            'bimodality_score': round(bimodality, 4),
            'mean_delay': round(sum(delays) / len(delays), 6),
            'min_delay': round(min(delays), 6),
            'max_delay': round(max(delays), 6),
            'lower_cluster_cv': round(lower_cv, 4),
            'upper_cluster_cv': round(upper_cv, 4),
        },
    )


# ============== DETECTION DISPATCH TABLE ==============


_DETECTORS: dict[str, Callable[[list[Packet], DetectionConfig], StegDetectResult]] = {
    'ip_ttl':          _detect_ip_ttl,
    'ip_id':           _detect_ip_id,
    'tcp_isn':         _detect_tcp_isn,
    'tcp_timestamp':   _detect_tcp_timestamp,
    'tcp_window':      _detect_tcp_window,
    'tcp_urgent':      _detect_tcp_urgent,
    'icmp_payload':    _detect_icmp_payload,
    'dns_label':       _detect_dns_label,
    'dns_txt':         _detect_dns_txt,
    'http_header':     _detect_http_header,
    'covert_timing':   _detect_covert_timing,
}


# ============== DETECTION PUBLIC API ==============


def analyze_pcap(
    pcap_data: bytes,
    detection_config: Optional[DetectionConfig] = None,
) -> list[StegDetectResult]:
    """Run all statistical detectors on a PCAP file.

    Examines protocol field distributions (TTL, IP ID, TCP ISN, DNS labels,
    timing delays, etc.) and flags anomalies regardless of framing.  This is
    a *statistical* detector — it answers "does this PCAP look like it has
    something hidden?" without needing to know the encoding scheme.

    Args:
        pcap_data: Raw PCAP file bytes.
        detection_config: Optional ``DetectionConfig`` with tuned thresholds.

    Returns:
        A ``StegDetectResult`` per stego method, sorted by confidence
        (most suspicious first).
    """
    cfg = detection_config or DetectionConfig()

    # Parse PCAP via scapy
    import tempfile, os as _os
    tmpdir = tempfile.mkdtemp()
    try:
        tmppath = _os.path.join(tmpdir, 'detect.pcap')
        with open(tmppath, 'wb') as f:
            f.write(pcap_data)
        packets = rdpcap(tmppath)
    except Exception:
        import shutil as _shutil
        _shutil.rmtree(tmpdir, ignore_errors=True)
        return []
    finally:
        import shutil as _shutil
        _shutil.rmtree(tmpdir, ignore_errors=True)

    if not packets:
        return []

    results: list[StegDetectResult] = []
    for method_name, detector_fn in _DETECTORS.items():
        try:
            result = detector_fn(packets, cfg)
            results.append(result)
        except Exception:
            results.append(StegDetectResult(
                method=method_name, suspicious=False, confidence=0.0,
                score=0.0, threshold=0.0, test_name='error',
                details={'error': 'detector raised an exception'},
            ))

    results.sort(key=lambda r: r.confidence, reverse=True)
    return results


def analyze_pcap_summary(
    pcap_data: bytes,
    detection_config: Optional[DetectionConfig] = None,
) -> dict:
    """Run all detectors and return an overall verdict.

    Args:
        pcap_data: Raw PCAP file bytes.
        detection_config: Optional ``DetectionConfig`` with tuned thresholds.

    Returns:
        A dict with keys:

        * ``suspicious`` — bool, whether ANY method flagged
        * ``overall_confidence`` — float, max confidence across methods
        * ``findings`` — list of per-method result dicts
        * ``packets`` — total packet count in the PCAP
    """
    raw_results = analyze_pcap(pcap_data, detection_config)

    if not raw_results:
        return {
            'suspicious': False,
            'overall_confidence': 0.0,
            'findings': [],
            'packets': 0,
        }

    # Count packets for the summary
    import tempfile, os as _os
    pkt_count = 0
    tmpdir = tempfile.mkdtemp()
    try:
        tmppath = _os.path.join(tmpdir, 'count.pcap')
        with open(tmppath, 'wb') as f:
            f.write(pcap_data)
        pkt_count = len(rdpcap(tmppath))
    except Exception:
        pass
    finally:
        import shutil as _shutil
        _shutil.rmtree(tmpdir, ignore_errors=True)

    any_suspicious = any(r.suspicious for r in raw_results)
    max_confidence = max((r.confidence for r in raw_results), default=0.0)

    return {
        'suspicious': any_suspicious,
        'overall_confidence': round(max_confidence, 4),
        'findings': [
            {
                'method': r.method,
                'suspicious': r.suspicious,
                'confidence': round(r.confidence, 4),
                'score': r.score,
                'test_name': r.test_name,
                'details': r.details,
            }
            for r in raw_results
        ],
        'packets': pkt_count,
    }
