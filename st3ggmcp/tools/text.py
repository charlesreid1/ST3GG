"""Text and emoji carrier tools: detection suite + encode/decode/capacity."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import analysis_tools as at
import text_core

from ._common import TOOL_TIMEOUT, resolve_text_input, run_sync, read_bytes, truncate_json

logger = logging.getLogger(__name__)


_TEXT_STEG_DETECTORS = (
    "detect_unicode_steg",
    "detect_whitespace_steg",
    "detect_cyrillic_homoglyph_steg",
    "detect_cjk_homoglyph_steg",
    "detect_variation_selector_steg",
    "detect_combining_mark_steg",
    "detect_confusable_whitespace",
    "detect_directional_override_steg",
    "detect_hangul_filler_steg",
    "detect_capitalization_steg",
    "detect_emoji_steg",
    "detect_math_bold_steg",
    "detect_braille_steg",
    "detect_emoji_substitution_steg",
    "detect_skintone_steg",
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


# ---------------------------------------------------------------------------
# stegg_text_steg / stegg_text_steg_message
# ---------------------------------------------------------------------------
async def execute_text_steg(path: str, **_kw) -> str:
    data, meta, err = read_bytes(path)
    if err:
        return err

    def work():
        return _run_text_detectors(data)

    try:
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_text_steg timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("text_steg failed")
        return f"stegg_text_steg error: {exc}"
    return truncate_json(result)


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
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_text_steg_message timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("text_steg_message failed")
        return f"stegg_text_steg_message error: {exc}"
    return truncate_json(result)


# ---------------------------------------------------------------------------
# stegg_text_encode / stegg_text_decode / stegg_text_capacity
# ---------------------------------------------------------------------------
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

    cover, err = resolve_text_input(cover_text, cover_path, "cover")
    if err:
        return f"stegg_text_encode error: {err}"

    def work():
        try:
            stego = text_core.encode(cover, secret, method)
        except text_core.TextStegCapacityError as exc:
            return {"__err__": str(exc)}
        return {"stego": stego}

    try:
        result = await run_sync(work)
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
    return truncate_json(summary)


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

    stego, err = resolve_text_input(stego_text, stego_path, "stego")
    if err:
        return f"stegg_text_decode error: {err}"

    def work():
        return text_core.decode(stego, method)

    try:
        recovered = await run_sync(work)
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
    return truncate_json(summary)


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

    cover, err = resolve_text_input(cover_text, cover_path, "cover")
    if err:
        return f"stegg_text_capacity error: {err}"

    def work():
        return text_core.capacity(cover, method)

    try:
        report = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_text_capacity timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("text_capacity failed")
        return f"stegg_text_capacity error: {exc}"

    report["cover_chars"] = len(cover)
    return truncate_json(report)


EXECUTORS = {
    "stegg_text_steg": execute_text_steg,
    "stegg_text_steg_message": execute_text_steg_message,
    "stegg_text_encode": execute_text_encode,
    "stegg_text_decode": execute_text_decode,
    "stegg_text_capacity": execute_text_capacity,
}


SCHEMAS = {
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
            "Method must be one of: zero_width, cyrillic_homoglyph, cjk_homoglyph, "
            "whitespace, invisible_ink, variation, combining, confusable, directional, "
            "hangul, mathbold, braille, emoji, skintone, capitalization. "
            "Supply the cover as either inline text (cover_text) or a file path (cover_path). "
            "Returns the stego text inline, or writes it to output_path if given. "
            "Round-trip-compatible with the browser Text Lab in index.html (except "
            "capitalization, which is Python-only). braille, emoji, and skintone append "
            "the payload as its own block after the cover (separated by '\\n\\n') — "
            "the stego is visibly perturbed, not invisible."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "zero_width, cyrillic_homoglyph, cjk_homoglyph, whitespace, invisible_ink, variation, combining, confusable, directional, hangul, mathbold, braille, emoji, skintone, or capitalization."},
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
            "(or by the browser Text Lab). Method must be one of: zero_width, "
            "cyrillic_homoglyph, cjk_homoglyph, whitespace, invisible_ink, variation, "
            "combining, confusable, directional, hangul, mathbold, braille, emoji, "
            "skintone, capitalization. Supply the stego as inline text (stego_text) or "
            "a file path (stego_path)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "zero_width, cyrillic_homoglyph, cjk_homoglyph, whitespace, invisible_ink, variation, combining, confusable, directional, hangul, mathbold, braille, emoji, skintone, or capitalization."},
                "stego_text": {"type": "string", "description": "Stego text supplied inline."},
                "stego_path": {"type": "string", "description": "Filesystem path to a UTF-8 stego file (alternative to stego_text)."},
            },
            "required": ["method"],
        },
    },
    "stegg_text_capacity": {
        "description": (
            "Pre-flight: how many payload bytes will fit in this cover under this method. "
            "Use before stegg_text_encode when the cover might be too small. Length-prefixed "
            "methods (cyrillic_homoglyph, cjk_homoglyph, whitespace, variation, combining, "
            "confusable, hangul, mathbold, capitalization) will raise TextStegCapacityError "
            "on undersized covers. "
            "braille, emoji, and skintone append the payload as its own block after the cover "
            "(like zero_width today), so payload_bytes_max is None for those."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "zero_width, cyrillic_homoglyph, cjk_homoglyph, whitespace, invisible_ink, variation, combining, confusable, directional, hangul, mathbold, braille, emoji, skintone, or capitalization."},
                "cover_text": {"type": "string", "description": "Cover text supplied inline."},
                "cover_path": {"type": "string", "description": "Filesystem path to a UTF-8 cover file (alternative to cover_text)."},
            },
            "required": ["method"],
        },
    },
}
