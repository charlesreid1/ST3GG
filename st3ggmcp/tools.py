"""
ST3GG tool implementations for the MCP server.

Every tool takes a filesystem `path` (server-local).
Encoder tools take an `output_path` and write their result to disk.
All results are JSON-shaped dicts; the MCP server serializes them for the client.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
from pathlib import Path
from typing import Any

from PIL import Image

import analysis_tools as at
import injector
import steg_core
import text_core

logger = logging.getLogger(__name__)

TOOL_TIMEOUT = 30
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB — reject anything larger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _read_bytes(path: str) -> tuple[bytes | None, dict | None, str | None]:
    """Read a file from disk, capped at MAX_FILE_SIZE. Returns (data, meta, err)."""
    try:
        p = Path(path)
    except Exception as exc:
        return None, None, f"invalid path: {exc}"
    if not p.exists():
        return None, None, f"file not found: {path}"
    if not p.is_file():
        return None, None, f"not a regular file: {path}"
    size = p.stat().st_size
    if size > MAX_FILE_SIZE:
        return None, None, f"file too large: {size} bytes exceeds cap of {MAX_FILE_SIZE}"
    data = p.read_bytes()
    meta = {"name": p.name, "path": str(p.resolve()), "size": size}
    return data, meta, None


def _truncate_json(obj: Any, max_chars: int = 6000) -> str:
    s = json.dumps(obj, default=str, ensure_ascii=False)
    if len(s) > max_chars:
        return s[:max_chars] + '..."[truncated]"'
    return s


def _run_sync(fn, *args, **kwargs):
    return asyncio.wait_for(asyncio.to_thread(fn, *args, **kwargs), timeout=TOOL_TIMEOUT)


def _default_output_path(input_meta: dict | None, ext: str = "png") -> str:
    """Derive a default output path from the input file's directory + a
    stegg_ prefix. Only used when the caller does not specify output_path."""
    original = (input_meta or {}).get("path") if input_meta else None
    if isinstance(original, str) and original:
        p = Path(original)
        return str(p.with_name(f"stegg_{p.stem}.{ext}"))
    return f"stegg_output.{ext}"


# ---------------------------------------------------------------------------
# Tool: stegg_read_metadata
# ---------------------------------------------------------------------------
async def execute_read_metadata(path: str, **_kw) -> str:
    data, meta, err = _read_bytes(path)
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
        result = await _run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_read_metadata timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("read_metadata failed")
        return f"stegg_read_metadata error: {exc}"
    return _truncate_json(result)


# ---------------------------------------------------------------------------
# stegg_triage: signals-expert composer
#
# Ranks stego suspicions across three axes:
#   - structural  (chunks, appended data, embedded PNGs, tool signatures)
#   - statistical (chi-square, RS analysis, sample-pairs)
#   - bit-plane   (per-channel low-plane smoothness)
#
# Severity is NEVER decided from a single probe. HIGH requires corroboration
# across multiple statistical probes; a single-probe hit is MEDIUM at best.
# Reason: on noise-like carriers, individual statistics false-fire in
# opposite directions, and on truly smooth carriers, chi-square false-fires
# on everything. Detection has real failure modes and we own that.
# ---------------------------------------------------------------------------
_STAT_HIGH_EMBEDDING_RATE = 0.25
_STAT_MEDIUM_EMBEDDING_RATE = 0.15


def _triage_carrier_info(data: bytes) -> dict:
    ft = at.detect_file_type(data)
    ft_name = ft.name if hasattr(ft, "name") else str(ft)

    info: dict[str, Any] = {"format": ft_name, "size": len(data)}
    try:
        img = Image.open(io.BytesIO(data))
        info["dims"] = list(img.size)
        info["mode"] = img.mode
        info["pil_format"] = img.format
    except Exception as exc:
        info["pil_error"] = str(exc)
    return info


def _triage_structural(data: bytes, carrier: dict) -> list[dict]:
    findings: list[dict] = []
    if carrier.get("format") != "PNG":
        return findings

    try:
        appended = at.png_detect_appended_data(data)
        if appended.get("found") or (appended.get("appended_size") or 0) > 0:
            size = appended.get("appended_size") or 0
            findings.append({
                "finding": f"{size} byte(s) appended past IEND",
                "severity": "HIGH" if size > 64 else "MEDIUM",
                "next": "stegg_detect_trailing (details) or stegg_carve(offset=<end_of_png>)",
                "detail": {k: v for k, v in appended.items() if k != "data"},
            })
    except Exception as exc:
        findings.append({"finding": "png_detect_appended_data failed", "severity": "INFO", "error": str(exc)})

    try:
        embedded = at.png_detect_embedded_png(data)
        if embedded.get("found") or (embedded.get("count") or 0) > 0:
            findings.append({
                "finding": "PNG-in-PNG detected",
                "severity": "HIGH",
                "next": "stegg_read_png_chunks",
                "detail": embedded,
            })
    except Exception:
        pass

    try:
        sig = at.png_steg_signature_scan(data)
        sigs = sig.get("signatures") or []
        if isinstance(sigs, list) and len(sigs) > 0:
            # Signature scanner uses short magic bytes; single matches false-fire
            # on noisy carriers. Require corroborating signal or multi-match to
            # justify HIGH severity.
            severity = "HIGH" if len(sigs) >= 2 else "MEDIUM"
            tool_names = [s.get("tool") or s.get("signature") for s in sigs if isinstance(s, dict)]
            findings.append({
                "finding": f"steg-tool signature match: {tool_names}",
                "severity": severity,
                "next": "stegg_read_png_chunks or stegg_lsb_smart_scan",
                "detail": {"signatures": sigs},
            })
    except Exception:
        pass

    try:
        text_chunks_result = at.png_extract_text_chunks(data)
        if isinstance(text_chunks_result, dict) and text_chunks_result.get("found"):
            tcs = text_chunks_result.get("text_chunks") or []
            keys = [tc.get("keyword", "") for tc in tcs if isinstance(tc, dict)]
            findings.append({
                "finding": f"{len(tcs)} PNG text chunk(s) present: {keys}",
                "severity": "HIGH",
                "next": "stegg_read_metadata (mandatory — payload may be sitting in a text chunk in plaintext)",
                "detail": {"keys": keys, "types": [tc.get("type") for tc in tcs if isinstance(tc, dict)]},
            })
    except Exception:
        pass

    try:
        chunks = at.png_parse_chunks(data)
        if isinstance(chunks, dict):
            if chunks.get("suspicious"):
                findings.append({
                    "finding": "unusual PNG chunk layout",
                    "severity": "MEDIUM",
                    "next": "stegg_read_png_chunks",
                    "detail": {k: chunks.get(k) for k in ("chunk_type_counts", "data_after_iend", "chunk_count")},
                })
            counts = chunks.get("chunk_type_counts") or {}
            unusual = [c for c in counts if c not in {
                "IHDR", "IDAT", "IEND", "PLTE", "tRNS", "gAMA", "cHRM",
                "sRGB", "iCCP", "tEXt", "zTXt", "iTXt", "bKGD", "pHYs",
                "sBIT", "sPLT", "hIST", "tIME",
            }]
            if unusual:
                findings.append({
                    "finding": f"private / non-standard chunk types: {unusual}",
                    "severity": "MEDIUM",
                    "next": "stegg_read_png_chunks",
                })
    except Exception:
        pass

    return findings


_CHANNEL_NAME_MAP = {"Red": "R", "Green": "G", "Blue": "B", "Alpha": "A"}


def _channel_present(ch_name: str, carrier: dict) -> bool:
    mode = carrier.get("mode") or ""
    short = _CHANNEL_NAME_MAP.get(ch_name, ch_name[:1])
    return short in mode


def _triage_statistical(data: bytes, carrier: dict) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    raw: dict[str, Any] = {}

    try:
        chi = at.png_chi_square_analysis(data)
        raw["chi_square"] = chi
        channels = (chi.get("channels") or {}) if isinstance(chi, dict) else {}
        for ch_name, ch_data in channels.items():
            if not _channel_present(ch_name, carrier):
                continue
            if str(ch_data.get("suspicious")).lower() == "true":
                findings.append({
                    "probe": "chi_square",
                    "channel": ch_name,
                    "severity": "MEDIUM",
                    "detail": {k: ch_data.get(k) for k in ("chi_square_lsb", "lsb_ones_ratio")},
                })
    except Exception as exc:
        raw["chi_square_error"] = str(exc)

    rs_rate_by_channel: dict[str, float] = {}
    try:
        rs = at.rs_analysis(data)
        raw["rs_analysis"] = rs
        rs_channels = (rs.get("channels") or {}) if isinstance(rs, dict) else {}
        for ch_name, ch_data in rs_channels.items():
            if not _channel_present(ch_name, carrier):
                continue
            rate = float(ch_data.get("estimated_embedding_rate") or 0)
            rs_rate_by_channel[ch_name] = rate
            if rate >= _STAT_MEDIUM_EMBEDDING_RATE or ch_data.get("suspicious"):
                findings.append({
                    "probe": "rs_analysis",
                    "channel": ch_name,
                    "severity": "HIGH" if rate >= _STAT_HIGH_EMBEDDING_RATE else "MEDIUM",
                    "detail": {"estimated_embedding_rate": rate},
                })
    except Exception as exc:
        raw["rs_analysis_error"] = str(exc)

    spa_rate_by_channel: dict[str, float] = {}
    try:
        spa = at.sample_pairs_analysis(data)
        raw["sample_pairs"] = spa
        spa_channels = (spa.get("channels") or {}) if isinstance(spa, dict) else {}
        for ch_name, ch_data in spa_channels.items():
            if not _channel_present(ch_name, carrier):
                continue
            rate = float(ch_data.get("estimated_embedding_rate") or 0)
            spa_rate_by_channel[ch_name] = rate
            if rate >= _STAT_MEDIUM_EMBEDDING_RATE or ch_data.get("suspicious"):
                findings.append({
                    "probe": "sample_pairs",
                    "channel": ch_name,
                    "severity": "HIGH" if rate >= _STAT_HIGH_EMBEDDING_RATE else "MEDIUM",
                    "detail": {"estimated_embedding_rate": rate},
                })
    except Exception as exc:
        raw["sample_pairs_error"] = str(exc)

    for ch_name in rs_rate_by_channel:
        rs_r = rs_rate_by_channel.get(ch_name, 0)
        spa_r = spa_rate_by_channel.get(ch_name, 0)
        if rs_r >= _STAT_MEDIUM_EMBEDDING_RATE and spa_r >= _STAT_MEDIUM_EMBEDDING_RATE:
            findings.append({
                "probe": "rs+spa corroborated",
                "channel": ch_name,
                "severity": "HIGH",
                "detail": {"rs_rate": rs_r, "spa_rate": spa_r},
                "next": f"stegg_lsb_smart_scan OR stegg_decode_manual(channels='{ch_name[0]}', bits_per_channel=1)",
            })

    return findings, raw


def _triage_bit_planes(data: bytes, statistical_channels: set[str], carrier: dict) -> list[dict]:
    findings: list[dict] = []
    try:
        bp = at.png_bit_plane_analysis(data)
    except Exception:
        return findings

    channels = (bp.get("channels") or {}) if isinstance(bp, dict) else {}
    for ch_name, planes in channels.items():
        if not _channel_present(ch_name, carrier):
            continue
        if not isinstance(planes, dict):
            continue
        for plane_key, plane_data in planes.items():
            if not plane_key.startswith("bit_"):
                continue
            if not isinstance(plane_data, dict):
                continue
            if str(plane_data.get("suspicious")).lower() == "true":
                corroborated = ch_name in statistical_channels
                findings.append({
                    "probe": "bit_plane",
                    "channel": ch_name,
                    "plane": plane_key,
                    "severity": "MEDIUM" if corroborated else "LOW",
                    "detail": {k: plane_data.get(k) for k in ("entropy", "ones_percentage")},
                    "corroborated_by_statistical": corroborated,
                })
    return findings


def _triage_finding_label(f: dict) -> str:
    if "finding" in f:
        return str(f["finding"])
    parts = []
    if f.get("probe"):
        parts.append(str(f["probe"]))
    if f.get("channel"):
        parts.append(str(f["channel"]))
    if f.get("plane"):
        parts.append(str(f["plane"]))
    return " ".join(parts) or "(unlabeled)"


def _triage_verdict(structural: list, statistical: list, bit_planes: list) -> tuple[str, list[str]]:
    # Verdict philosophy:
    #   STRUCTURAL findings drive the verdict, because they have near-zero
    #   false-positive rates (bytes past IEND either exist or they don't).
    #   STATISTICAL findings are advisory. Both chi-square and RS/SPA have
    #   known carrier-dependent failure modes.
    high_structural = any(f.get("severity") == "HIGH" for f in structural)
    medium_structural = any(f.get("severity") == "MEDIUM" for f in structural)
    any_statistical = bool(statistical)

    stat_high_probes_by_channel: dict[str, set[str]] = {}
    for f in statistical:
        if f.get("severity") == "HIGH" and f.get("channel") and f.get("probe"):
            stat_high_probes_by_channel.setdefault(f["channel"], set()).add(f["probe"])
    stat_high_corroborated = any(len(p) >= 2 for p in stat_high_probes_by_channel.values())

    top: list[str] = []
    for f in structural + statistical + bit_planes:
        if f.get("severity") == "HIGH":
            top.append(_triage_finding_label(f))
    for f in structural + statistical + bit_planes:
        if f.get("severity") == "MEDIUM" and _triage_finding_label(f) not in top:
            top.append(_triage_finding_label(f))
    top = top[:5]

    if high_structural or stat_high_corroborated:
        return "SUSPICIOUS", top
    if medium_structural or any_statistical:
        return "INCONCLUSIVE", top
    return "CLEAN", top


async def execute_triage(path: str, **_kw) -> str:
    data, meta, err = _read_bytes(path)
    if err:
        return err

    def work():
        carrier = _triage_carrier_info(data)
        structural = _triage_structural(data, carrier)

        statistical: list[dict] = []
        stat_raw: dict[str, Any] = {}
        bit_planes: list[dict] = []
        if carrier.get("format") == "PNG":
            statistical, stat_raw = _triage_statistical(data, carrier)
            stat_channels = {f["channel"] for f in statistical if f.get("channel")}
            bit_planes = _triage_bit_planes(data, stat_channels, carrier)
        else:
            stat_raw["skipped"] = f"statistical probes not run: carrier is {carrier.get('format')}, not PNG"

        verdict, top = _triage_verdict(structural, statistical, bit_planes)

        return {
            "carrier": carrier,
            "structural": structural,
            "statistical": statistical,
            "bit_planes": bit_planes,
            "top_suspicions": top,
            "verdict": verdict,
            "raw_stats": stat_raw,
        }

    try:
        result = await _run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_triage timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("triage failed")
        return f"stegg_triage error: {exc}"
    return _truncate_json(result, max_chars=8000)


# ---------------------------------------------------------------------------
# Tool: stegg_lsb_smart_scan
# ---------------------------------------------------------------------------
async def execute_lsb_smart_scan(path: str, max_bytes: int = 4096, **_kw) -> str:
    data, meta, err = _read_bytes(path)
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
        result = await _run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_lsb_smart_scan timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("lsb_smart_scan failed")
        return f"stegg_lsb_smart_scan error: {exc}"
    return _truncate_json(result)


# ---------------------------------------------------------------------------
# Tool: stegg_detect_trailing
# ---------------------------------------------------------------------------
async def execute_detect_trailing(path: str, **_kw) -> str:
    data, meta, err = _read_bytes(path)
    if err:
        return err

    def work():
        return at.png_detect_appended_data(data)

    try:
        result = await _run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_detect_trailing timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("detect_trailing failed")
        return f"stegg_detect_trailing error: {exc}"
    return _truncate_json(result)


# ---------------------------------------------------------------------------
# Tool: stegg_read_png_chunks
# ---------------------------------------------------------------------------
async def execute_read_png_chunks(path: str, **_kw) -> str:
    data, meta, err = _read_bytes(path)
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
        result = await _run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_read_png_chunks timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("read_png_chunks failed")
        return f"stegg_read_png_chunks error: {exc}"
    return _truncate_json(result)


# ---------------------------------------------------------------------------
# Tool: stegg_decode_manual
# ---------------------------------------------------------------------------
_CHANNEL_PRESETS = {"R", "G", "B", "A", "RG", "RB", "GB", "RGB", "RGBA"}


async def execute_decode_manual(
    path: str,
    channels: str,
    bits_per_channel: int,
    strategy: str = "interleaved",
    **_kw,
) -> str:
    data, meta, err = _read_bytes(path)
    if err:
        return err

    channels = channels.upper()
    if channels not in _CHANNEL_PRESETS:
        return f"Unknown channels preset '{channels}'. Try: {', '.join(sorted(_CHANNEL_PRESETS))}"
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
        result = await _run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_decode_manual timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("decode_manual failed")
        return f"stegg_decode_manual error: {exc}"
    return _truncate_json(result)


# ---------------------------------------------------------------------------
# Tool: stegg_carve
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
    data, meta, err = _read_bytes(path)
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
        return _truncate_json({
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
        result = await _run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_carve timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("carve failed")
        return f"stegg_carve error: {exc}"
    return _truncate_json(result)


# ---------------------------------------------------------------------------
# Encoders (write to output_path)
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
    data, meta, err = _read_bytes(path)
    if err:
        return err

    if not isinstance(message, str):
        return "stegg_encode_manual error: 'message' must be a string"
    payload = message.encode("utf-8")

    ch_upper = channels.upper() if isinstance(channels, str) else ""
    if ch_upper not in _CHANNEL_PRESETS:
        return f"Unknown channels preset '{channels}'. Try: {', '.join(sorted(_CHANNEL_PRESETS))}"
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
        result = await _run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_encode_manual timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("encode_manual failed")
        return f"stegg_encode_manual error: {exc}"

    if isinstance(result, dict) and "__err__" in result:
        return f"stegg_encode_manual: {result['__err__']}"

    out_path = output_path or _default_output_path(meta)
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
    return _truncate_json(summary)


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
    data, meta, err = _read_bytes(path)
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
        result = await _run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_encode_metadata timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("encode_metadata failed")
        return f"stegg_encode_metadata error: {exc}"

    if isinstance(result, dict) and "__err__" in result:
        return f"stegg_encode_metadata: {result['__err__']}"
    if not isinstance(result, (bytes, bytearray)):
        return f"stegg_encode_metadata: unexpected library return type {type(result).__name__}"

    out_path = output_path or _default_output_path(meta)
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
    return _truncate_json(summary)


# ---------------------------------------------------------------------------
# Text-steg detectors
# ---------------------------------------------------------------------------
_TEXT_STEG_DETECTORS = (
    "detect_unicode_steg",
    "detect_whitespace_steg",
    "detect_homoglyph_steg",
    "detect_variation_selector_steg",
    "detect_combining_mark_steg",
    "detect_confusable_whitespace",
    "detect_directional_override_steg",
    "detect_hangul_filler_steg",
    "detect_capitalization_steg",
    "detect_emoji_steg",
    "decode_directional_override",
    "decode_hangul_filler",
    "decode_math_alphanumeric",
    "decode_braille",
    "decode_emoji_skin_tone",
)


def _hit_score(detector_output: Any) -> bool:
    if not isinstance(detector_output, dict):
        return False
    for key in ("detected", "found", "has_steg", "positive"):
        if detector_output.get(key):
            return True
    for key in ("hits", "matches", "occurrences", "decoded", "details"):
        val = detector_output.get(key)
        if isinstance(val, (list, tuple, str, bytes)) and len(val) > 0:
            return True
    for key in ("count", "substitutions", "total", "num_hits", "occurrences"):
        val = detector_output.get(key)
        if isinstance(val, int) and val > 0:
            return True
    return False


def _run_text_detectors(data: bytes) -> dict:
    results: dict[str, Any] = {}
    hits: list[dict] = []
    errors: dict[str, str] = {}

    for name in _TEXT_STEG_DETECTORS:
        fn = getattr(at, name, None)
        if fn is None:
            errors[name] = "not available in analysis_tools"
            continue
        try:
            out = fn(data)
        except Exception as exc:
            errors[name] = f"{type(exc).__name__}: {exc}"
            continue
        results[name] = out
        if _hit_score(out):
            hits.append({"detector": name, "summary": out})

    summary: dict[str, Any] = {"hits": hits, "detectors_run": len(results)}
    if errors:
        summary["errors"] = errors
    summary["results"] = results
    return summary


async def execute_text_steg(path: str, **_kw) -> str:
    data, meta, err = _read_bytes(path)
    if err:
        return err

    def work():
        return _run_text_detectors(data)

    try:
        result = await _run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_text_steg timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("text_steg failed")
        return f"stegg_text_steg error: {exc}"
    return _truncate_json(result)


async def execute_text_steg_message(text: str, **_kw) -> str:
    if not isinstance(text, str):
        return "stegg_text_steg_message error: 'text' must be a string"
    if not text:
        return "stegg_text_steg_message: empty text, nothing to scan"

    data = text.encode("utf-8", errors="surrogatepass")

    def work():
        result = _run_text_detectors(data)
        result["input_chars"] = len(text)
        result["input_bytes"] = len(data)
        return result

    try:
        result = await _run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_text_steg_message timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("text_steg_message failed")
        return f"stegg_text_steg_message error: {exc}"
    return _truncate_json(result)


async def execute_list_techniques(**_kw) -> str:
    catalog = {
        "metadata": "PNG tEXt/iTXt/zTXt chunks, PIL image info, EXIF-adjacent key/value data.",
        "trailing_data": "Bytes appended after the image container's end marker (PNG IEND / JPEG EOI).",
        "lsb_smart_scan": "Sweep of common LSB configurations (channel presets x bit depths x strategies).",
        "lsb_manual_decode": "LSB decode with a specific channels/bits recipe.",
        "triage": (
            "Composed signals-expert sweep: carrier ID, structural probes, "
            "statistical LSB probes, per-plane bit-plane smoothness. Returns "
            "ranked findings and a verdict of SUSPICIOUS / INCONCLUSIVE / CLEAN."
        ),
        "png_chunks": "Full PNG chunk dump for deep inspection.",
        "text_steg": (
            "Full text-steg detector suite over file bytes or a pasted string: "
            "zero-width characters, Unicode homoglyphs, variation selectors, "
            "combining marks, confusable whitespace, capitalization patterns, "
            "emoji substitution, directional overrides, hangul filler, math "
            "alphanumerics, braille patterns, emoji skin tones, tab/space whitespace."
        ),
        "carve": (
            "Format-carver dispatch: try to parse the file (or a byte range) as ZIP, "
            "GZip, TAR, PDF, SQLite, SVG, PCAP, JPEG, or WAV audio-LSB."
        ),
        "encode_manual": "Hide a payload via LSB with an explicit channels/bits/strategy recipe.",
        "encode_metadata": "Hide a payload in a PNG text (tEXt/iTXt/zTXt) or private chunk.",
        "text_encode": (
            "Hide a payload in plain text via zero_width, homoglyph, whitespace, "
            "invisible_ink, variation, combining, confusable, directional, or "
            "hangul. Round-trip-compatible with the browser Text Lab."
        ),
        "text_decode": "Recover a payload from a stego text produced by text_encode (or the browser).",
        "text_capacity": "Pre-flight: how many payload bytes a given cover can carry under a text-steg method.",
    }
    return _truncate_json(catalog, max_chars=2000)


# ---------------------------------------------------------------------------
# Text-steg encoders (write UTF-8 text; take cover as inline text OR file path)
# ---------------------------------------------------------------------------
def _resolve_text_input(inline: str | None, path: str | None, label: str) -> tuple[str | None, str | None]:
    """Return (text, err). Prefer inline; else read UTF-8 from path."""
    if inline is not None:
        if not isinstance(inline, str):
            return None, f"{label}: must be a string"
        return inline, None
    if path is not None:
        try:
            p = Path(path)
        except Exception as exc:
            return None, f"{label}: invalid path: {exc}"
        if not p.exists():
            return None, f"{label}: file not found: {path}"
        if not p.is_file():
            return None, f"{label}: not a regular file: {path}"
        if p.stat().st_size > MAX_FILE_SIZE:
            return None, f"{label}: file too large ({p.stat().st_size} bytes)"
        try:
            return p.read_text(encoding="utf-8"), None
        except Exception as exc:
            return None, f"{label}: failed to read as UTF-8: {exc}"
    return None, f"{label}: must supply either inline text or a file path"


async def execute_text_encode(
    method: str,
    secret: str,
    cover_text: str | None = None,
    cover_path: str | None = None,
    output_path: str | None = None,
    **_kw,
) -> str:
    if method not in text_core.METHODS:
        return (
            f"stegg_text_encode error: unknown method '{method}'. "
            f"Try one of: {', '.join(text_core.METHODS)}"
        )
    if not isinstance(secret, str):
        return "stegg_text_encode error: 'secret' must be a string"

    cover, err = _resolve_text_input(cover_text, cover_path, "cover")
    if err:
        return f"stegg_text_encode error: {err}"

    def work():
        try:
            stego = text_core.encode(cover, secret, method)
        except text_core.TextStegCapacityError as exc:
            return {"__err__": str(exc)}
        return {"stego": stego}

    try:
        result = await _run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_text_encode timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("text_encode failed")
        return f"stegg_text_encode error: {exc}"

    if isinstance(result, dict) and "__err__" in result:
        return f"stegg_text_encode: {result['__err__']}"

    stego = result["stego"]
    summary: dict[str, Any] = {
        "method": method,
        "cover_chars": len(cover),
        "stego_chars": len(stego),
        "stego_bytes_utf8": len(stego.encode("utf-8")),
        "payload_bytes": len(secret.encode("utf-8")),
    }
    if output_path:
        try:
            Path(output_path).write_text(stego, encoding="utf-8")
        except Exception as exc:
            return f"stegg_text_encode: failed to write {output_path}: {exc}"
        summary["output_path"] = str(Path(output_path).resolve())
        summary["text"] = (
            f"hid {summary['payload_bytes']} bytes via {method}. wrote {output_path}."
        )
    else:
        summary["stego"] = stego
        summary["text"] = f"hid {summary['payload_bytes']} bytes via {method}."
    return _truncate_json(summary)


async def execute_text_decode(
    method: str,
    stego_text: str | None = None,
    stego_path: str | None = None,
    **_kw,
) -> str:
    if method not in text_core.METHODS:
        return (
            f"stegg_text_decode error: unknown method '{method}'. "
            f"Try one of: {', '.join(text_core.METHODS)}"
        )

    stego, err = _resolve_text_input(stego_text, stego_path, "stego")
    if err:
        return f"stegg_text_decode error: {err}"

    def work():
        return text_core.decode(stego, method)

    try:
        recovered = await _run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_text_decode timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("text_decode failed")
        return f"stegg_text_decode error: {exc}"

    summary = {
        "method": method,
        "recovered": recovered,
        "recovered_bytes": len(recovered.encode("utf-8")),
        "text": (
            f"recovered {len(recovered.encode('utf-8'))} bytes via {method}."
            if recovered
            else f"nothing recovered via {method}."
        ),
    }
    return _truncate_json(summary)


async def execute_text_capacity(
    method: str,
    cover_text: str | None = None,
    cover_path: str | None = None,
    **_kw,
) -> str:
    if method not in text_core.METHODS:
        return (
            f"stegg_text_capacity error: unknown method '{method}'. "
            f"Try one of: {', '.join(text_core.METHODS)}"
        )

    cover, err = _resolve_text_input(cover_text, cover_path, "cover")
    if err:
        return f"stegg_text_capacity error: {err}"

    def work():
        return text_core.capacity(cover, method)

    try:
        report = await _run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_text_capacity timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("text_capacity failed")
        return f"stegg_text_capacity error: {exc}"

    report["cover_chars"] = len(cover)
    return _truncate_json(report)


# ---------------------------------------------------------------------------
# Tool registry — name -> (executor, JSON schema for MCP)
# ---------------------------------------------------------------------------
TOOL_EXECUTORS = {
    "stegg_read_metadata": execute_read_metadata,
    "stegg_triage": execute_triage,
    "stegg_lsb_smart_scan": execute_lsb_smart_scan,
    "stegg_detect_trailing": execute_detect_trailing,
    "stegg_read_png_chunks": execute_read_png_chunks,
    "stegg_decode_manual": execute_decode_manual,
    "stegg_text_steg": execute_text_steg,
    "stegg_text_steg_message": execute_text_steg_message,
    "stegg_text_encode": execute_text_encode,
    "stegg_text_decode": execute_text_decode,
    "stegg_text_capacity": execute_text_capacity,
    "stegg_carve": execute_carve,
    "stegg_encode_manual": execute_encode_manual,
    "stegg_encode_metadata": execute_encode_metadata,
    "stegg_list_techniques": execute_list_techniques,
}


TOOL_SCHEMAS: dict[str, dict] = {
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
    "stegg_triage": {
        "description": (
            "Signals-expert triage: carrier ID, structural probes (chunks, appended data, "
            "embedded PNGs, tool signatures), statistical LSB probes (chi-square, RS, "
            "sample-pairs), and bit-plane smoothness. Returns ranked findings with "
            "severity labels and a verdict of SUSPICIOUS / INCONCLUSIVE / CLEAN."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
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
    "stegg_text_steg": {
        "description": (
            "Full text-steg detector suite over file bytes: zero-width characters, "
            "Unicode homoglyphs, variation selectors, combining marks, confusable "
            "whitespace, capitalization patterns, emoji substitution, directional "
            "overrides, hangul filler, math alphanumerics, braille patterns, emoji "
            "skin tones, tab/space whitespace steg."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    "stegg_text_steg_message": {
        "description": (
            "Same detector suite as stegg_text_steg, on a raw text string. Use when the "
            "user pastes a suspicious message rather than attaching a file."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string", "description": "The text to scan verbatim."}},
            "required": ["text"],
        },
    },
    "stegg_text_encode": {
        "description": (
            "Hide a secret string inside a cover text using a text-steg technique. "
            "Method must be one of: zero_width, homoglyph, whitespace, invisible_ink, "
            "variation, combining, confusable, directional, hangul. "
            "Supply the cover as either inline text (cover_text) or a file path (cover_path). "
            "Returns the stego text inline, or writes it to output_path if given. "
            "Round-trip-compatible with the browser Text Lab in index.html."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "zero_width, homoglyph, whitespace, invisible_ink, variation, combining, confusable, directional, or hangul."},
                "secret": {"type": "string", "description": "The secret string to hide."},
                "cover_text": {"type": "string", "description": "Cover text supplied inline."},
                "cover_path": {"type": "string", "description": "Filesystem path to a UTF-8 cover file (alternative to cover_text)."},
                "output_path": {"type": "string", "description": "Where to write the stego text. If omitted, the stego is returned in the result."},
            },
            "required": ["method", "secret"],
        },
    },
    "stegg_text_decode": {
        "description": (
            "Recover a hidden secret from a stego text produced by stegg_text_encode "
            "(or by the browser Text Lab). Method must be one of: zero_width, homoglyph, "
            "whitespace, invisible_ink, variation, combining, confusable, directional, "
            "hangul. Supply the stego as inline text (stego_text) or a file path "
            "(stego_path)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "zero_width, homoglyph, whitespace, invisible_ink, variation, combining, confusable, directional, or hangul."},
                "stego_text": {"type": "string", "description": "Stego text supplied inline."},
                "stego_path": {"type": "string", "description": "Filesystem path to a UTF-8 stego file (alternative to stego_text)."},
            },
            "required": ["method"],
        },
    },
    "stegg_text_capacity": {
        "description": (
            "Pre-flight: how many payload bytes will fit in this cover under this method. "
            "Use before stegg_text_encode when the cover might be too small. Most methods "
            "(homoglyph, whitespace, variation, combining, confusable, hangul) use a "
            "16-bit length prefix and will raise TextStegCapacityError on undersized covers."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "zero_width, homoglyph, whitespace, invisible_ink, variation, combining, confusable, directional, or hangul."},
                "cover_text": {"type": "string", "description": "Cover text supplied inline."},
                "cover_path": {"type": "string", "description": "Filesystem path to a UTF-8 cover file (alternative to cover_text)."},
            },
            "required": ["method"],
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
    "stegg_list_techniques": {
        "description": "Return a short catalog of the techniques this server can check for.",
        "inputSchema": {"type": "object", "properties": {}},
    },
}
