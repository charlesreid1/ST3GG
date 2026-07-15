"""Jailbreak / prompt-injection tools for the MCP server."""

from __future__ import annotations

import asyncio
import io
import logging
from pathlib import Path
from typing import Any

from PIL import Image

import jailbreak_core

from ._common import (
    TOOL_TIMEOUT,
    default_output_path,
    read_bytes,
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


EXECUTORS = {
    "stegg_jailbreak_list": execute_jailbreak_list,
    "stegg_jailbreak_compose_image": execute_jailbreak_compose_image,
    "stegg_jailbreak_detect": execute_jailbreak_detect,
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
            "LSB pixel payload, trailing data after IEND, Unicode obfuscation)."
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
}
