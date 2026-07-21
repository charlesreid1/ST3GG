"""Meta tool: catalog of what the server covers."""

from __future__ import annotations

from ._common import truncate_json


async def execute_list_techniques(**_kw) -> str:
    catalog = {
        "families": {
            "image": "PNG/JPEG/BMP carriers. LSB, chunk smuggling, trailing bytes, metadata, polyglots.",
            "text":  "Prose and source-code carriers. Zero-width, cyrillic_homoglyph, cjk_homoglyph, whitespace, variation, combining, confusable, directional, hangul, mathbold, capitalization, invisible_ink.",
            "emoji": "Emoji carriers. Substitution (🔴/🔵), skin-tone modifiers, braille block, variation selectors piggybacked on emoji.",
            "general_advice": "No tool call needed — ask ST3GG about technique tradeoffs, transport survival, capacity math, or 'how would you hide X in Y'. General questions are a first-class deliverable.",
        },
        "image_detect": {
            "metadata":      "stegg_read_metadata — PNG tEXt/iTXt/zTXt chunks, PIL image info, EXIF-adjacent key/value data.",
            "triage":        "stegg_triage — composed signals-expert sweep: carrier ID, structural probes, statistical LSB probes, per-plane bit-plane smoothness. Verdict of SUSPICIOUS / INCONCLUSIVE / CLEAN.",
            "trailing_data": "stegg_detect_trailing — bytes appended after PNG IEND / JPEG EOI.",
            "png_chunks":    "stegg_read_png_chunks — full PNG chunk dump for deep inspection.",
            "lsb_smart_scan":"stegg_lsb_smart_scan — sweep of common LSB configurations (channel presets x bit depths x strategies).",
            "lsb_manual":    "stegg_decode_manual — LSB decode with a specific channels/bits/strategy recipe.",
            "lsb_capacity":  "stegg_lsb_capacity — pre-flight how many bytes fit under an LSB recipe.",
            "dct_decode":    "stegg_dct_decode — recover a DCT-hidden payload (frequency-domain, survives JPEG recompression). Use this when LSB scans come up empty on a JPEG-round-tripped image.",
            "pvd_detect":    "stegg_detect_pvd — PVD-specific detector; pairs with stegg_pvd_encode/decode/capacity.",
            "analyze":       "stegg_analyze_image — numbers-dense per-channel statistical readout (mean/std, LSB ratios, chi-square, capacity table, HIGH/MEDIUM/LOW verdict).",
            "carve":         "stegg_carve — try ZIP / GZip / TAR / PDF / SQLite / SVG / PCAP / JPEG / audio-LSB decoders on a file or byte range.",
        },
        "text_and_emoji_detect": {
            "text_steg":         "stegg_text_steg — full detector suite over file bytes.",
            "text_steg_message": "stegg_text_steg_message — same suite over an inline pasted string. Use this when the user pastes suspicious text.",
            "text_decode":       "stegg_text_decode — recover a payload from a stego text with a named method.",
            "text_capacity":     "stegg_text_capacity — pre-flight how many bytes fit under a text-steg method for a given cover.",
            "detectors_covered": (
                "zero-width chars (ZWSP/ZWNJ/ZWJ/BOM), Cyrillic + CJK homoglyphs, variation selectors, "
                "combining marks, confusable whitespace, capitalization patterns, emoji "
                "substitution, directional overrides (RLO/LRO/PDF), hangul filler, math "
                "alphanumerics, braille patterns, emoji skin-tone modifiers, tab/space whitespace."
            ),
        },
        "encode": {
            "image_lsb":      "stegg_encode_manual — hide via LSB with explicit channels/bits/strategy recipe.",
            "image_metadata": "stegg_encode_metadata — hide in a PNG text (tEXt/iTXt/zTXt) or private chunk.",
            "image_exif":     "stegg_inject_exif — bulk-inject multiple tEXt key/value pairs via PIL PngInfo (one call, many keys).",
            "image_dct":      "stegg_dct_encode — hide via DCT (frequency-domain). Slower and lower capacity than LSB, but medium/high robustness survives JPEG recompression (which destroys LSB). Use stegg_dct_capacity to pre-flight fit.",
            "text_encode": (
                "stegg_text_encode — hide in text/emoji via one of: zero_width, "
                "cyrillic_homoglyph, cjk_homoglyph, whitespace, invisible_ink, variation, "
                "combining, confusable, directional, hangul, mathbold, braille, emoji, "
                "skintone, or capitalization. Round-trip-"
                "compatible with the browser Text Lab (except capitalization, which is "
                "Python-only). braille/emoji/skintone append the payload as its own block "
                "after the cover — visibly perturbed, not invisible."
            ),
        },
    }
    return truncate_json(catalog, max_chars=3000)


EXECUTORS = {"stegg_list_techniques": execute_list_techniques}


SCHEMAS = {
    "stegg_list_techniques": {
        "description": (
            "Return a catalog of what this server covers: three carrier families "
            "(image, text, emoji) plus a general-advice slot (persona answers "
            "technique-tradeoff and transport-survival questions from knowledge, "
            "no tool call needed). Grouped by detect / encode role."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
}
