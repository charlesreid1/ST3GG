"""Jailbreak / prompt-injection tools for the MCP server."""

from __future__ import annotations

import asyncio
import io
import logging
from pathlib import Path
from typing import Any

from PIL import Image

import jailbreak_core
import transforms_core

from ._common import (
    TOOL_TIMEOUT,
    default_output_path,
    read_bytes,
    resolve_text_input,
    run_sync,
    truncate_json,
)

logger = logging.getLogger(__name__)


async def execute_jailbreak_list(technique: str | None = None, model: str | None = None, **_kw) -> str:
    def work():
        by_technique = jailbreak_core.list_templates_by_technique()
        by_model = jailbreak_core.list_templates_by_model()
        templates: dict[str, Any] = {}
        for name, tmpl in jailbreak_core.JAILBREAK_TEMPLATES.items():
            if technique and tmpl.technique != technique:
                continue
            if model and model not in tmpl.target_models:
                continue
            templates[name] = {
                "technique": tmpl.technique,
                "target_models": tmpl.target_models,
                "tags": tmpl.tags,
                "body_preview": tmpl.body[:200] + ("..." if len(tmpl.body) > 200 else ""),
            }
        return {
            "templates": templates,
            "count": len(templates),
            "by_technique": {k: v for k, v in by_technique.items()},
            "by_model": {k: v for k, v in by_model.items()},
        }

    try:
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_jailbreak_list timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("jailbreak_list failed")
        return f"stegg_jailbreak_list error: {exc}"
    return truncate_json(result)


async def execute_jailbreak_compose_image(
    path: str,
    template: str = "pliny_classic",
    channels: str = "RGB",
    filename_template: str = "chatgpt_decoder",
    output_path: str | None = None,
    **_kw,
) -> str:
    data, meta, err = read_bytes(path)
    if err:
        return err

    def work():
        img = Image.open(io.BytesIO(data))
        payload = jailbreak_core.compose_image_jailbreak(
            template,
            img,
            channels=channels,
            filename_template=filename_template,
        )
        out = output_path or default_output_path(meta, ext="png")
        Path(out).write_bytes(payload.image_bytes)
        return {
            "output_path": out,
            "filename_template_result": payload.filename,
            "template": template,
            "channels": channels,
            "technique_summary": payload.technique_summary,
            "metadata_chunks": list(payload.metadata_chunks.keys()),
            "image_bytes_length": len(payload.image_bytes),
        }

    try:
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_jailbreak_compose_image timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("jailbreak_compose_image failed")
        return f"stegg_jailbreak_compose_image error: {exc}"
    return truncate_json(result)


async def execute_jailbreak_detect(path: str, full: bool = True, **_kw) -> str:
    p = Path(path)
    if not p.exists():
        return f"file not found: {path}"

    def work():
        suffix = p.suffix.lower()
        if suffix in {".png", ".jpg", ".jpeg", ".bmp", ".gif"}:
            result = jailbreak_core.detect_full_injection_package(image_path=str(p))
        else:
            result = jailbreak_core.detect_full_injection_package(text_path=str(p))
        if not full:
            result = {k: v for k, v in result.items() if k != "vectors"}
        return result

    try:
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_jailbreak_detect timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("jailbreak_detect failed")
        return f"stegg_jailbreak_detect error: {exc}"
    return truncate_json(result)


async def execute_jailbreak_compose_text(
    template: str = "dan_classic",
    cover_text: str | None = None,
    cover_path: str | None = None,
    stego_method: str = "zero_width",
    obfuscation: list[str] | None = None,
    output_path: str | None = None,
    **_kw,
) -> str:
    cover, err = resolve_text_input(cover_text, cover_path, "cover_text")
    if err:
        return err

    def work():
        payload = jailbreak_core.compose_text_jailbreak(
            template,
            cover,
            stego_method=stego_method,
            obfuscation=obfuscation,
        )
        result: dict[str, Any] = {
            "template": template,
            "stego_method": stego_method,
            "obfuscation": obfuscation or [],
            "technique_summary": payload.technique_summary,
            "carrier_text_length": len(payload.carrier_text or ""),
            "carrier_text_preview": (payload.carrier_text or "")[:400],
        }
        if output_path:
            Path(output_path).write_text(payload.carrier_text or "", encoding="utf-8")
            result["output_path"] = output_path
        return result

    try:
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_jailbreak_compose_text timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("jailbreak_compose_text failed")
        return f"stegg_jailbreak_compose_text error: {exc}"
    return truncate_json(result)


async def execute_jailbreak_compose_unicode_tag(
    template: str = "dan_classic",
    cover_text: str | None = None,
    cover_path: str | None = None,
    base_emoji: str | None = None,
    obfuscation: list[str] | None = None,
    output_path: str | None = None,
    **_kw,
) -> str:
    cover, err = resolve_text_input(cover_text, cover_path, "cover_text")
    if err:
        return err

    def work():
        kwargs: dict[str, Any] = {"obfuscation": obfuscation}
        if base_emoji is not None:
            kwargs["base_emoji"] = base_emoji
        payload = jailbreak_core.compose_unicode_tag_jailbreak(
            template,
            cover,
            **kwargs,
        )
        result: dict[str, Any] = {
            "template": template,
            "base_emoji": base_emoji or jailbreak_core.EMOJI_TAG_BASE,
            "obfuscation": obfuscation or [],
            "technique_summary": payload.technique_summary,
            "carrier_text_length": len(payload.carrier_text or ""),
            "carrier_text_preview": (payload.carrier_text or "")[:400],
        }
        if output_path:
            Path(output_path).write_text(payload.carrier_text or "", encoding="utf-8")
            result["output_path"] = output_path
        return result

    try:
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_jailbreak_compose_unicode_tag timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("jailbreak_compose_unicode_tag failed")
        return f"stegg_jailbreak_compose_unicode_tag error: {exc}"
    return truncate_json(result)


async def execute_transforms_list(**_kw) -> str:
    def work():
        return {
            "transforms": transforms_core.list_transforms(),
            "count": len(transforms_core.list_transforms()),
        }

    try:
        result = await run_sync(work)
    except asyncio.TimeoutError:
        return f"stegg_transforms_list timed out after {TOOL_TIMEOUT}s"
    except Exception as exc:
        logger.exception("transforms_list failed")
        return f"stegg_transforms_list error: {exc}"
    return truncate_json(result)


EXECUTORS = {
    "stegg_jailbreak_list": execute_jailbreak_list,
    "stegg_jailbreak_compose_image": execute_jailbreak_compose_image,
    "stegg_jailbreak_compose_text": execute_jailbreak_compose_text,
    "stegg_jailbreak_compose_unicode_tag": execute_jailbreak_compose_unicode_tag,
    "stegg_jailbreak_detect": execute_jailbreak_detect,
    "stegg_transforms_list": execute_transforms_list,
}


SCHEMAS = {
    "stegg_jailbreak_list": {
        "description": (
            "List available jailbreak templates with metadata (technique class, "
            "target models, tags). Optional filters by technique or target model."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "technique": {"type": "string", "description": "Filter by technique class (e.g. persona_break, filter_bypass)."},
                "model": {"type": "string", "description": "Filter by target model (e.g. gpt-4, claude)."},
            },
        },
    },
    "stegg_jailbreak_compose_image": {
        "description": (
            "Compose a full multi-vector jailbreak: encode jailbreak text into "
            "image pixels via LSB, inject matching PNG metadata chunks, and "
            "generate an injection filename. Returns the stego image path plus "
            "composition metadata."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Carrier image path."},
                "template": {"type": "string", "description": "Jailbreak template name (default: pliny_classic)."},
                "channels": {"type": "string", "description": "LSB channels (default: RGB)."},
                "filename_template": {"type": "string", "description": "Filename injection template (default: chatgpt_decoder)."},
                "output_path": {"type": "string", "description": "Where to write the stego image."},
            },
            "required": ["path"],
        },
    },
    "stegg_jailbreak_detect": {
        "description": (
            "Scan an image or text file for jailbreak / prompt-injection "
            "indicators across all vectors (filename, PNG metadata chunks, "
            "LSB pixel payload, trailing data after IEND, Unicode obfuscation, "
            "fullwidth-ASCII density)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to the file to scan."},
                "full": {"type": "boolean", "description": "Include per-vector details (default: true)."},
            },
            "required": ["path"],
        },
    },
    "stegg_jailbreak_compose_text": {
        "description": (
            "Hide a jailbreak template inside cover text via Unicode text "
            "steganography, with an optional ordered obfuscation pre-pipeline "
            "(zalgo, fullwidth, leetspeak, ...) applied to the template body "
            "before stego encoding. Order matters — match the chain to the "
            "target transport (see TRANSPORT_MATRIX.md). Use stegg_transforms_list "
            "to enumerate available obfuscation names."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "template": {"type": "string", "description": "Jailbreak template name (default: dan_classic)."},
                "cover_text": {"type": "string", "description": "Inline cover text carrier."},
                "cover_path": {"type": "string", "description": "Path to a UTF-8 file used as cover text (used if cover_text is not supplied)."},
                "stego_method": {"type": "string", "description": "text_core encoder to use (default: zero_width)."},
                "obfuscation": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Ordered list of transform names applied to the template body before stego encoding.",
                },
                "output_path": {"type": "string", "description": "Optional path to write the resulting carrier text."},
            },
        },
    },
    "stegg_jailbreak_compose_unicode_tag": {
        "description": (
            "Hide a jailbreak template as a Unicode Tag run (U+E00XX) attached "
            "to a base emoji — the 2025 'hidden emoji' prompt-injection "
            "technique. Payload is constrained to printable ASCII; combine "
            "with `obfuscation` cautiously (fullwidth before tag encoding will "
            "raise because the transformed body is no longer printable ASCII)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "template": {"type": "string", "description": "Jailbreak template name (default: dan_classic)."},
                "cover_text": {"type": "string", "description": "Inline cover text carrier."},
                "cover_path": {"type": "string", "description": "Path to a UTF-8 file used as cover text (used if cover_text is not supplied)."},
                "base_emoji": {"type": "string", "description": "Emoji the tag run attaches to (default: waving black flag)."},
                "obfuscation": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Ordered list of transform names applied to the template body before tag encoding.",
                },
                "output_path": {"type": "string", "description": "Optional path to write the resulting carrier text."},
            },
        },
    },
    "stegg_transforms_list": {
        "description": (
            "List registered text transforms from transforms_core — the set of "
            "names accepted by the `obfuscation` parameter on the jailbreak "
            "compose_text / compose_unicode_tag tools."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
}
