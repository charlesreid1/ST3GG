"""Network-carrier tools: PCAP stego encode, decode, and method listing."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ._common import (
    TOOL_TIMEOUT,
    default_output_path,
    read_bytes,
    resolve_text_input,
    run_sync,
    truncate_json,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# stegg_network_encode
# ---------------------------------------------------------------------------
async def execute_network_encode(
    message: str | None = None,
    message_path: str | None = None,
    method: str = "ip_ttl",
    wire_format: str = "ip4_udp",
    src_ip: str = "192.168.1.100",
    dst_ip: str = "8.8.8.8",
    sport: int = 12345,
    dport: int = 53,
    cover_domain: str = "steg.example.com",
    use_compression: bool = True,
    output_path: str | None = None,
    **_kw,
) -> str:
    """Encode a payload into a PCAP file using network steganography.

    Args:
        message: Payload string to hide (inline).
        message_path: Path to a UTF-8 file containing the payload.
        method: Stego method name (default ip_ttl).
        wire_format: Wire format name (default ip4_udp).
        src_ip, dst_ip: IP addresses for the cover traffic.
        sport, dport: Source/destination ports.
        cover_domain: Cover domain for DNS methods.
        use_compression: zlib-compress the payload before encoding.
        output_path: Where to write the PCAP (auto-generated if omitted).
    """
    text, err = resolve_text_input(message, message_path, "payload")
    if err:
        return err

    def work():
        from network_core import (
            NetworkStegConfig,
            StegoMethod,
            WireFormat,
            encode,
        )

        try:
            meth = StegoMethod(method)
        except ValueError:
            valid = [m.value for m in StegoMethod]
            raise ValueError(f"Unknown method '{method}'. Valid: {valid}")

        try:
            wf = WireFormat(wire_format)
        except ValueError:
            valid = [w.value for w in WireFormat]
            raise ValueError(f"Unknown wire_format '{wire_format}'. Valid: {valid}")

        config = NetworkStegConfig(
            method=meth,
            wire_format=wf,
            src_ip=src_ip,
            dst_ip=dst_ip,
            sport=int(sport),
            dport=int(dport),
            cover_domain=cover_domain,
            use_compression=bool(use_compression),
        )

        payload = text.encode("utf-8")
        pcap_bytes = encode(payload, config)

        # Determine output path
        if output_path:
            out = Path(output_path)
        else:
            out = Path(default_output_path(None, "pcap"))
            # Make it more descriptive
            out = Path(f"stegg_{method}_{wire_format}.pcap")

        out.write_bytes(pcap_bytes)

        from network_core import calculate_capacity

        cap = calculate_capacity(config, max_packets=1000)
        return {
            "output_path": str(out.resolve()),
            "size": len(pcap_bytes),
            "method": method,
            "wire_format": wire_format,
            "payload_bytes": len(payload),
            "compressed": bool(use_compression),
            "bytes_per_packet": cap["bytes_per_packet"],
            "max_payload_bytes": cap["max_payload_bytes"],
        }

    try:
        result = await run_sync(work)
    except Exception as exc:
        logger.exception("network_encode failed")
        return f"stegg_network_encode error: {exc}"
    return truncate_json(result)


# ---------------------------------------------------------------------------
# stegg_network_decode
# ---------------------------------------------------------------------------
async def execute_network_decode(
    path: str,
    method: str | None = None,
    **_kw,
) -> str:
    """Decode a PCAP file and extract any hidden NETH-framed payload.

    Args:
        path: Filesystem path to the PCAP file.
        method: Optional stego method name to restrict decoding to one method.
                If omitted, all methods are tried (auto-detect).
    """
    data, meta, err = read_bytes(path)
    if err:
        return err

    def work():
        from network_core import StegoMethod, decode

        meth = None
        if method is not None:
            try:
                meth = StegoMethod(method)
            except ValueError:
                valid = [m.value for m in StegoMethod]
                raise ValueError(f"Unknown method '{method}'. Valid: {valid}")

        result = decode(data, method=meth)
        result["file"] = meta
        if result.get("found"):
            payload = result.get("payload", b"")
            try:
                result["payload_utf8"] = payload.decode("utf-8", errors="replace")[:2000]
            except Exception:
                result["payload_hex_head"] = payload[:64].hex()
            # Don't serialize raw bytes
            result.pop("payload", None)
        return result

    try:
        result = await run_sync(work)
    except Exception as exc:
        logger.exception("network_decode failed")
        return f"stegg_network_decode error: {exc}"
    return truncate_json(result)


# ---------------------------------------------------------------------------
# stegg_network_methods
# ---------------------------------------------------------------------------
async def execute_network_methods(**_kw) -> str:
    """List all available network stego methods with their capacities and
    compatible wire formats."""

    def work():
        from network_core import list_methods
        return {"methods": list_methods()}

    try:
        result = await run_sync(work)
    except Exception as exc:
        logger.exception("network_methods failed")
        return f"stegg_network_methods error: {exc}"
    return truncate_json(result)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
EXECUTORS = {
    "stegg_network_encode": execute_network_encode,
    "stegg_network_decode": execute_network_decode,
    "stegg_network_methods": execute_network_methods,
}


SCHEMAS = {
    "stegg_network_encode": {
        "description": (
            "Encode a payload into a PCAP file using network steganography. "
            "Choose a stego method (ip_ttl, dns_label, tcp_isn, ...) and a "
            "wire format (ip4_udp, ip4_udp_dns, ip4_tcp_http, ...). Writes "
            "the PCAP to output_path (auto-generated if omitted)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Payload string to hide (inline). Use message_path for binary/large payloads.",
                },
                "message_path": {
                    "type": "string",
                    "description": "Path to a UTF-8 file containing the payload.",
                },
                "method": {
                    "type": "string",
                    "description": (
                        "Stego method: ip_ttl, ip_id, tcp_isn, tcp_timestamp, "
                        "tcp_window, tcp_urgent, icmp_payload, dns_label, "
                        "dns_txt, http_header, covert_timing."
                    ),
                },
                "wire_format": {
                    "type": "string",
                    "description": (
                        "Wire format: ip4_udp, ip4_tcp, ip4_icmp, "
                        "ip4_udp_dns, ip4_tcp_http."
                    ),
                },
                "src_ip": {"type": "string", "description": "Source IP for cover traffic."},
                "dst_ip": {"type": "string", "description": "Destination IP for cover traffic."},
                "sport": {"type": "integer", "description": "Source port."},
                "dport": {"type": "integer", "description": "Destination port."},
                "cover_domain": {"type": "string", "description": "Cover domain for DNS methods."},
                "use_compression": {"type": "boolean", "description": "zlib-compress before encoding (default true)."},
                "output_path": {"type": "string", "description": "Where to write the PCAP file."},
            },
            "required": [],
        },
    },
    "stegg_network_decode": {
        "description": (
            "Decode a PCAP file and extract any hidden NETH-framed payload. "
            "Set method to force a specific decoder; omit to auto-detect by "
            "trying all known methods."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Filesystem path to the PCAP file."},
                "method": {
                    "type": "string",
                    "description": "Optional: force a specific stego method (e.g. ip_ttl, dns_label).",
                },
            },
            "required": ["path"],
        },
    },
    "stegg_network_methods": {
        "description": (
            "List all available network stego methods, their bytes-per-packet "
            "capacities, and compatible wire formats. Use this to discover what "
            "combinations are valid before calling stegg_network_encode."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
}
