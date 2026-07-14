"""Image-carrier tools: metadata, LSB scan/decode/encode, PNG chunks, carve."""

from __future__ import annotations

import asyncio
import io
import logging
from pathlib import Path
from typing import Any

from PIL import Image

import analysis_tools as at
import injector
import steg_core

from ._common import (
    CHANNEL_PRESETS,
    TOOL_TIMEOUT,
    default_output_path,
    read_bytes,
    run_sync,
    truncate_json,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# stegg_read_metadata
# ---------------------------------------------------------------------------
async def execute_read_metadata(path: str, **_kw) -> str:
    data, meta, err = read_bytes(path)
    if err:
        return err

    def work():
        result: dict[str, Any] = {"file": meta}
        try:
            img = Image.open(io.BytesIO(data))
            result["pil_info"] = {k: str(v)[:500] for k, v in (img.info or {}).items()}
            result["mode"] = img.mode
            result["format"] = img.format
            result["size"] = list(img.size)
        except Exception as exc:
            result["pil_error"] = str(exc)

        try:
            chunks = injector.extract_text_chunks(data)
            if chunks:
                result["png_text_chunks"] = chunks
        except Exception as exc:
            result["png_text_chunks_error"] = str(exc)

        try:
            atc = at.png_extract_text_chunks(data)
            if atc and atc != result.get("png_text_chunks"):
                result["png_text_chunks_analysis"] = atc
        except Exception:
            pass

        return result

    try:
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_read_metadata timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("read_metadata failed")
        return f"stegg_read_metadata error: {exc}"
    return truncate_json(result)


# ---------------------------------------------------------------------------
# stegg_lsb_smart_scan
# ---------------------------------------------------------------------------
async def execute_lsb_smart_scan(path: str, max_bytes: int = 4096, **_kw) -> str:
    data, meta, err = read_bytes(path)
    if err:
        return err

    def work():
        img = Image.open(io.BytesIO(data))
        result = steg_core.smart_extract(img, max_bytes=int(max_bytes))
        if not result:
            return {"found": False}

        payload = result.pop("data", None)
        summary = dict(result)
        summary["found"] = True
        if payload is not None:
            summary["payload_length"] = len(payload)
            try:
                text = payload.decode("utf-8")
                summary["payload_utf8"] = text[:2000]
            except UnicodeDecodeError:
                summary["payload_hex_head"] = payload[:64].hex()
        return summary

    try:
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_lsb_smart_scan timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("lsb_smart_scan failed")
        return f"stegg_lsb_smart_scan error: {exc}"
    return truncate_json(result)


# ---------------------------------------------------------------------------
# stegg_detect_trailing
# ---------------------------------------------------------------------------
async def execute_detect_trailing(path: str, **_kw) -> str:
    data, meta, err = read_bytes(path)
    if err:
        return err

    def work():
        return at.png_detect_appended_data(data)

    try:
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_detect_trailing timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("detect_trailing failed")
        return f"stegg_detect_trailing error: {exc}"
    return truncate_json(result)


# ---------------------------------------------------------------------------
# stegg_read_png_chunks
# ---------------------------------------------------------------------------
async def execute_read_png_chunks(path: str, **_kw) -> str:
    data, meta, err = read_bytes(path)
    if err:
        return err

    def work():
        chunks = injector.read_png_chunks(data)
        summary = []
        for c in chunks:
            entry = {
                "type": c.get("type"),
                "length": c.get("length"),
                "offset": c.get("offset"),
            }
            raw = c.get("data")
            if isinstance(raw, (bytes, bytearray)):
                if c.get("type") in {"tEXt", "iTXt", "zTXt"}:
                    try:
                        entry["text"] = raw.decode("utf-8", errors="replace")[:500]
                    except Exception:
                        entry["hex_head"] = raw[:32].hex()
                else:
                    entry["hex_head"] = raw[:32].hex()
            elif raw is not None:
                entry["value"] = str(raw)[:500]
            summary.append(entry)
        return {"chunk_count": len(summary), "chunks": summary}

    try:
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_read_png_chunks timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("read_png_chunks failed")
        return f"stegg_read_png_chunks error: {exc}"
    return truncate_json(result)


# ---------------------------------------------------------------------------
# stegg_decode_manual
# ---------------------------------------------------------------------------
async def execute_decode_manual(
    path: str,
    channels: str,
    bits_per_channel: int,
    strategy: str = "interleaved",
    **_kw,
) -> str:
    data, meta, err = read_bytes(path)
    if err:
        return err

    channels = channels.upper()
    if channels not in CHANNEL_PRESETS:
        return f"Unknown channels preset '{channels}'. Try: {', '.join(sorted(CHANNEL_PRESETS))}"
    if not (1 <= int(bits_per_channel) <= 8):
        return "bits_per_channel must be in 1..8"

    def work():
        img = Image.open(io.BytesIO(data))
        config = steg_core.create_config(
            channels=channels,
            bits=int(bits_per_channel),
            strategy=strategy,
        )
        try:
            payload = steg_core.decode(img, config=config)
        except Exception as exc:
            return {"decoded": False, "error": str(exc)}

        out: dict[str, Any] = {"decoded": True, "length": len(payload)}
        try:
            out["utf8"] = payload.decode("utf-8")[:2000]
        except UnicodeDecodeError:
            out["hex_head"] = payload[:64].hex()
        return out

    try:
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_decode_manual timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("decode_manual failed")
        return f"stegg_decode_manual error: {exc}"
    return truncate_json(result)


# ---------------------------------------------------------------------------
# stegg_carve
# ---------------------------------------------------------------------------
_CARVE_DECODERS = {
    "zip": "zip_decode",
    "gzip": "gzip_decode",
    "tar": "tar_decode",
    "pdf": "pdf_decode",
    "sqlite": "sqlite_decode",
    "svg": "svg_decode",
    "pcap": "pcap_decode",
    "jpeg": "jpeg_decode",
    "audio_lsb": "audio_lsb_decode",
}


def _carve_hit_rank(out: Any) -> int:
    if not isinstance(out, dict):
        return 0
    score = 0
    if out.get("found") is True:
        score += 100
    if out.get("suspicious") is True:
        score += 10
    findings = out.get("findings")
    if isinstance(findings, (list, tuple)):
        score += len(findings)
    return score


async def execute_carve(
    path: str,
    offset: int = 0,
    length: int | None = None,
    decoders: list[str] | None = None,
    **_kw,
) -> str:
    data, meta, err = read_bytes(path)
    if err:
        return err

    try:
        offset = int(offset or 0)
    except (TypeError, ValueError):
        return "stegg_carve: 'offset' must be an integer"
    if offset < 0 or offset > len(data):
        return f"stegg_carve: offset {offset} out of range for file of size {len(data)}"

    if length is None:
        segment = data[offset:]
    else:
        try:
            length = int(length)
        except (TypeError, ValueError):
            return "stegg_carve: 'length' must be an integer"
        if length < 0:
            return "stegg_carve: 'length' must be non-negative"
        segment = data[offset : offset + length]

    if not segment:
        return truncate_json({
            "offset": offset,
            "length": 0,
            "message": "empty byte range, nothing to carve",
        })

    if decoders is None:
        selected = list(_CARVE_DECODERS.keys())
    else:
        unknown = [d for d in decoders if d not in _CARVE_DECODERS]
        if unknown:
            available = ", ".join(sorted(_CARVE_DECODERS.keys()))
            return f"stegg_carve: unknown decoder(s) {unknown}. Available: {available}"
        selected = list(decoders)

    def work():
        raw: dict[str, Any] = {}
        errors: dict[str, str] = {}
        for name in selected:
            fn_name = _CARVE_DECODERS[name]
            fn = getattr(at, fn_name, None)
            if fn is None:
                errors[name] = f"{fn_name} not available in analysis_tools"
                continue
            try:
                raw[name] = fn(segment)
            except Exception as exc:
                errors[name] = f"{type(exc).__name__}: {exc}"

        ranked = sorted(raw.items(), key=lambda kv: _carve_hit_rank(kv[1]), reverse=True)
        parsed = [name for name, out in ranked if _carve_hit_rank(out) > 0]

        return {
            "offset": offset,
            "carved_bytes": len(segment),
            "parsed": parsed,
            "results": {name: out for name, out in ranked},
            **({"errors": errors} if errors else {}),
        }

    try:
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_carve timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("carve failed")
        return f"stegg_carve error: {exc}"
    return truncate_json(result)


# ---------------------------------------------------------------------------
# stegg_encode_manual
# ---------------------------------------------------------------------------
async def execute_encode_manual(
    path: str,
    message: str,
    channels: str,
    bits_per_channel: int,
    strategy: str = "interleaved",
    seed: int | None = None,
    compress: bool = True,
    output_path: str | None = None,
    **_kw,
) -> str:
    data, meta, err = read_bytes(path)
    if err:
        return err

    if not isinstance(message, str):
        return "stegg_encode_manual error: 'message' must be a string"
    payload = message.encode("utf-8")

    ch_upper = channels.upper() if isinstance(channels, str) else ""
    if ch_upper not in CHANNEL_PRESETS:
        return f"Unknown channels preset '{channels}'. Try: {', '.join(sorted(CHANNEL_PRESETS))}"
    try:
        bits = int(bits_per_channel)
    except (TypeError, ValueError):
        return "stegg_encode_manual error: 'bits_per_channel' must be an integer"
    if not (1 <= bits <= 8):
        return "bits_per_channel must be in 1..8"

    def work():
        img = Image.open(io.BytesIO(data))
        cfg = steg_core.create_config(
            channels=ch_upper,
            bits=bits,
            strategy=strategy,
            seed=(int(seed) if seed is not None else None),
            compress=bool(compress),
        )
        cap = steg_core.calculate_capacity(img, cfg)
        usable = int(cap.get("usable_bytes") or 0)
        if len(payload) > usable and not compress:
            return {"__err__": (
                f"payload is {len(payload)} bytes but carrier has only "
                f"{usable} usable bytes for channels={ch_upper}, bits={bits}, "
                f"strategy={strategy}."
            )}
        encoded_img = steg_core.encode(img, payload, config=cfg)
        buf = io.BytesIO()
        encoded_img.save(buf, format="PNG")
        return {
            "encoded_bytes": buf.getvalue(),
            "capacity_bytes": usable,
            "payload_bytes": len(payload),
            "mode": encoded_img.mode,
            "size": list(encoded_img.size),
        }

    try:
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_encode_manual timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("encode_manual failed")
        return f"stegg_encode_manual error: {exc}"

    if isinstance(result, dict) and "__err__" in result:
        return f"stegg_encode_manual: {result['__err__']}"

    out_path = output_path or default_output_path(meta)
    try:
        Path(out_path).write_bytes(result["encoded_bytes"])
    except Exception as exc:
        return f"stegg_encode_manual: failed to write {out_path}: {exc}"

    cfg_out = {
        "channels": ch_upper,
        "bits_per_channel": bits,
        "strategy": strategy,
        "compress": bool(compress),
    }
    if seed is not None:
        cfg_out["seed"] = int(seed)
    summary = {
        "output_path": str(Path(out_path).resolve()),
        "output_bytes": len(result["encoded_bytes"]),
        "config": cfg_out,
        "capacity_bytes": result["capacity_bytes"],
        "payload_bytes": result["payload_bytes"],
        "size": result["size"],
        "mode": result["mode"],
        "text": (
            f"stashed {result['payload_bytes']} bytes into {result['size']} {result['mode']} "
            f"carrier via LSB (channels={ch_upper}, bits={bits}, strategy={strategy}"
            + (f", seed={int(seed)}" if seed is not None else "")
            + f"). wrote {out_path}."
        ),
    }
    return truncate_json(summary)


# ---------------------------------------------------------------------------
# stegg_encode_metadata
# ---------------------------------------------------------------------------
_TEXT_CHUNK_TYPES = {"tEXt", "iTXt", "zTXt"}


async def execute_encode_metadata(
    path: str,
    chunk_type: str,
    value: str,
    keyword: str = "",
    private_chunk_name: str = "",
    output_path: str | None = None,
    **_kw,
) -> str:
    data, meta, err = read_bytes(path)
    if err:
        return err

    if not isinstance(value, str):
        return "stegg_encode_metadata error: 'value' must be a string"

    ct = chunk_type

    def work():
        if ct == "tEXt":
            if not keyword:
                return {"__err__": "tEXt chunks require a 'keyword' argument"}
            return injector.inject_text_chunk(data, keyword, value, compressed=False)
        if ct == "zTXt":
            if not keyword:
                return {"__err__": "zTXt chunks require a 'keyword' argument"}
            return injector.inject_text_chunk(data, keyword, value, compressed=True)
        if ct == "iTXt":
            if not keyword:
                return {"__err__": "iTXt chunks require a 'keyword' argument"}
            return injector.inject_itxt_chunk(data, keyword, value)
        if ct == "private":
            if not private_chunk_name or len(private_chunk_name) != 4:
                return {"__err__": "private chunks require a 4-character 'private_chunk_name'"}
            return injector.inject_private_chunk(data, private_chunk_name, value.encode("utf-8"))
        return {"__err__": f"unknown chunk_type '{ct}'. Use one of: tEXt, iTXt, zTXt, private."}

    try:
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_encode_metadata timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("encode_metadata failed")
        return f"stegg_encode_metadata error: {exc}"

    if isinstance(result, dict) and "__err__" in result:
        return f"stegg_encode_metadata: {result['__err__']}"
    if not isinstance(result, (bytes, bytearray)):
        return f"stegg_encode_metadata: unexpected library return type {type(result).__name__}"

    out_path = output_path or default_output_path(meta)
    try:
        Path(out_path).write_bytes(bytes(result))
    except Exception as exc:
        return f"stegg_encode_metadata: failed to write {out_path}: {exc}"

    cfg_out: dict = {"chunk_type": ct, "value_bytes": len(value.encode("utf-8"))}
    if ct in _TEXT_CHUNK_TYPES:
        cfg_out["keyword"] = keyword
    if ct == "private":
        cfg_out["private_chunk_name"] = private_chunk_name
    label = ct if ct != "private" else f"private '{private_chunk_name}'"
    summary = {
        "output_path": str(Path(out_path).resolve()),
        "input_bytes": len(data),
        "output_bytes": len(result),
        "config": cfg_out,
        "text": (
            f"injected {len(value.encode('utf-8'))} bytes into a {label} chunk"
            + (f" keyed '{keyword}'" if keyword and ct in _TEXT_CHUNK_TYPES else "")
            + f". file size before/after: {len(data)} -> {len(result)} bytes. wrote {out_path}."
        ),
    }
    return truncate_json(summary)


# ---------------------------------------------------------------------------
# Registry: colocated executors + schemas
# ---------------------------------------------------------------------------
EXECUTORS = {
    "stegg_read_metadata": execute_read_metadata,
    "stegg_lsb_smart_scan": execute_lsb_smart_scan,
    "stegg_detect_trailing": execute_detect_trailing,
    "stegg_read_png_chunks": execute_read_png_chunks,
    "stegg_decode_manual": execute_decode_manual,
    "stegg_carve": execute_carve,
    "stegg_encode_manual": execute_encode_manual,
    "stegg_encode_metadata": execute_encode_metadata,
}


SCHEMAS = {
    "stegg_read_metadata": {
        "description": (
            "Read image metadata: PNG text chunks (tEXt/zTXt/iTXt), PIL image info. "
            "Cheap and high-signal. Run FIRST for any 'what is in this image' question — "
            "a large fraction of real-world stego hides plainly in text chunks."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Filesystem path to the image."}},
            "required": ["path"],
        },
    },
    "stegg_lsb_smart_scan": {
        "description": (
            "Smart LSB extraction. Tries the ST3GG v3 header first; if not found, "
            "brute-forces channel/bit/strategy combos and returns the best-scoring "
            "extractable payload."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "max_bytes": {"type": "integer", "description": "Cap on extracted payload size (default 4096)."},
            },
            "required": ["path"],
        },
    },
    "stegg_detect_trailing": {
        "description": (
            "Detect data appended after the image container's end marker (PNG IEND / "
            "JPEG EOI). Classic hiding spot."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    "stegg_read_png_chunks": {
        "description": (
            "Full PNG chunk dump: every chunk's type, length, and (for text chunks) content."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    "stegg_decode_manual": {
        "description": (
            "Attempt LSB decode with a specific configuration. Use when the user "
            "provides a recipe (channels + bits) or you want to verify a specific "
            "config from the smart scan."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "channels": {"type": "string", "description": "R, G, B, A, RGB, RGBA, RG, RB, GB."},
                "bits_per_channel": {"type": "integer", "description": "1-8. Most stego uses 1 or 2."},
                "strategy": {"type": "string", "description": "sequential, interleaved (default), spread, randomized."},
            },
            "required": ["path", "channels", "bits_per_channel"],
        },
    },
    "stegg_carve": {
        "description": (
            "Try to parse a file (or a byte range) as one or more container formats: "
            "ZIP, GZip, TAR, PDF, SQLite, SVG, PCAP, JPEG, WAV/audio-LSB. Returns which "
            "decoders produced findings, ranked by hit-strength."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "offset": {"type": "integer", "description": "Optional byte offset to start carving from. Default 0."},
                "length": {"type": "integer", "description": "Optional number of bytes to carve. Default: to end of file."},
                "decoders": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional decoder subset: zip, gzip, tar, pdf, sqlite, svg, pcap, jpeg, audio_lsb.",
                },
            },
            "required": ["path"],
        },
    },
    "stegg_encode_manual": {
        "description": (
            "Hide a payload in an image using LSB steganography with an explicit "
            "channels + bits + strategy recipe. Writes the encoded PNG to output_path "
            "(or a stegg_-prefixed sibling of the input if omitted)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "message": {"type": "string", "description": "The payload to hide, as a UTF-8 string."},
                "channels": {"type": "string", "description": "R, G, B, A, RGB, RGBA, RG, RB, GB."},
                "bits_per_channel": {"type": "integer", "description": "1-8. Most hides use 1 or 2 for stealth."},
                "strategy": {"type": "string", "description": "sequential, interleaved (default), spread, randomized."},
                "seed": {"type": "integer", "description": "Optional PRNG seed for the randomized strategy."},
                "compress": {"type": "boolean", "description": "Compress payload before embedding (default true)."},
                "output_path": {"type": "string", "description": "Where to write the encoded PNG."},
            },
            "required": ["path", "message", "channels", "bits_per_channel"],
        },
    },
    "stegg_encode_metadata": {
        "description": (
            "Hide a payload in a PNG's metadata by injecting a text chunk "
            "(tEXt / iTXt / zTXt) or a private chunk. Writes the modified PNG to "
            "output_path."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "chunk_type": {"type": "string", "description": "tEXt, iTXt, zTXt, or 'private' (requires private_chunk_name)."},
                "keyword": {"type": "string", "description": "Chunk key for tEXt/iTXt/zTXt."},
                "value": {"type": "string", "description": "The payload string to embed as the chunk value."},
                "private_chunk_name": {"type": "string", "description": "4-character chunk name when chunk_type='private'."},
                "output_path": {"type": "string", "description": "Where to write the modified PNG."},
            },
            "required": ["path", "chunk_type", "value"],
        },
    },
}
