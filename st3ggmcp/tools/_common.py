"""Shared helpers for st3ggmcp tool executors.

Every tool takes a filesystem `path` (server-local). Encoder tools take an
`output_path` and write their result to disk. All results are JSON-shaped
dicts; the MCP server serializes them for the client.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

TOOL_TIMEOUT = 30
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB — reject anything larger


def read_bytes(path: str) -> tuple[bytes | None, dict | None, str | None]:
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


def truncate_json(obj: Any, max_chars: int = 6000) -> str:
    s = json.dumps(obj, default=str, ensure_ascii=False)
    if len(s) > max_chars:
        return s[:max_chars] + '..."[truncated]"'
    return s


def run_sync(fn, *args, **kwargs):
    return asyncio.wait_for(asyncio.to_thread(fn, *args, **kwargs), timeout=TOOL_TIMEOUT)


def default_output_path(input_meta: dict | None, ext: str = "png") -> str:
    """Derive a default output path from the input file's directory + a
    stegg_ prefix. Only used when the caller does not specify output_path."""
    original = (input_meta or {}).get("path") if input_meta else None
    if isinstance(original, str) and original:
        p = Path(original)
        return str(p.with_name(f"stegg_{p.stem}.{ext}"))
    return f"stegg_output.{ext}"


def resolve_text_input(inline: str | None, path: str | None, label: str) -> tuple[str | None, str | None]:
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


CHANNEL_PRESETS = {"R", "G", "B", "A", "RG", "RB", "GB", "RGB", "RGBA"}
