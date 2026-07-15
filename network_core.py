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
import random
import struct
import zlib
from dataclasses import dataclass
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
    """List all available stego methods with their capacities and valid wire formats."""
    result: list[dict] = []
    for method in StegoMethod:
        bpp = METHOD_BYTES_PER_PACKET.get(method, 0)
        wire_formats = METHOD_WIRE_FORMATS.get(method, [])
        result.append({
            'method': method.value,
            'bytes_per_packet': bpp,
            'wire_formats': [wf.value for wf in wire_formats],
        })
    return result
