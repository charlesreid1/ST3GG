"""Signals-expert triage composer.

Ranks stego suspicions across three axes:
  - structural  (chunks, appended data, embedded PNGs, tool signatures)
  - statistical (chi-square, RS analysis, sample-pairs)
  - bit-plane   (per-channel low-plane smoothness)

Severity is NEVER decided from a single probe. HIGH requires corroboration
across multiple statistical probes; a single-probe hit is MEDIUM at best.
Reason: on noise-like carriers, individual statistics false-fire in
opposite directions, and on truly smooth carriers, chi-square false-fires
on everything. Detection has real failure modes and we own that.
"""

from __future__ import annotations

import asyncio
import io
import logging
from typing import Any

from PIL import Image

import analysis_tools as at

from ._common import TOOL_TIMEOUT, read_bytes, run_sync, truncate_json

logger = logging.getLogger(__name__)

_STAT_HIGH_EMBEDDING_RATE = 0.25
_STAT_MEDIUM_EMBEDDING_RATE = 0.15

_CHANNEL_NAME_MAP = {"Red": "R", "Green": "G", "Blue": "B", "Alpha": "A"}


def _carrier_info(data: bytes) -> dict:
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


def _channel_present(ch_name: str, carrier: dict) -> bool:
    mode = carrier.get("mode") or ""
    short = _CHANNEL_NAME_MAP.get(ch_name, ch_name[:1])
    return short in mode


def _structural(data: bytes, carrier: dict) -> list[dict]:
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


def _statistical(data: bytes, carrier: dict) -> tuple[list[dict], dict]:
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


def _bit_planes(data: bytes, statistical_channels: set[str], carrier: dict) -> list[dict]:
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


def _finding_label(f: dict) -> str:
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


def _verdict(structural: list, statistical: list, bit_planes: list) -> tuple[str, list[str]]:
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
            top.append(_finding_label(f))
    for f in structural + statistical + bit_planes:
        if f.get("severity") == "MEDIUM" and _finding_label(f) not in top:
            top.append(_finding_label(f))
    top = top[:5]

    if high_structural or stat_high_corroborated:
        return "SUSPICIOUS", top
    if medium_structural or any_statistical:
        return "INCONCLUSIVE", top
    return "CLEAN", top


async def execute_triage(path: str, **_kw) -> str:
    data, meta, err = read_bytes(path)
    if err:
        return err

    def work():
        carrier = _carrier_info(data)
        structural = _structural(data, carrier)

        statistical: list[dict] = []
        stat_raw: dict[str, Any] = {}
        bit_planes: list[dict] = []
        if carrier.get("format") == "PNG":
            statistical, stat_raw = _statistical(data, carrier)
            stat_channels = {f["channel"] for f in statistical if f.get("channel")}
            bit_planes = _bit_planes(data, stat_channels, carrier)
        else:
            stat_raw["skipped"] = f"statistical probes not run: carrier is {carrier.get('format')}, not PNG"

        verdict, top = _verdict(structural, statistical, bit_planes)

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
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_triage timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("triage failed")
        return f"stegg_triage error: {exc}"
    return truncate_json(result, max_chars=8000)


EXECUTORS = {"stegg_triage": execute_triage}


SCHEMAS = {
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
}
