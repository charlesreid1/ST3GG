"""Tool registry for the st3ggmcp MCP server.

Each per-family submodule exports its own `EXECUTORS` and `SCHEMAS` dicts;
this module merges them into the two dicts server.py consumes. Adding a tool
means editing exactly one submodule.
"""

from __future__ import annotations

from . import image, meta, text, triage

# Re-export individual executors so callers can still do
#   `from st3ggmcp.tools import execute_text_encode`
# the way they did before tools.py was split into a package.
from .image import (  # noqa: F401
    execute_carve,
    execute_decode_manual,
    execute_detect_trailing,
    execute_encode_manual,
    execute_encode_metadata,
    execute_lsb_smart_scan,
    execute_pvd_capacity,
    execute_pvd_decode,
    execute_pvd_encode,
    execute_read_metadata,
    execute_read_png_chunks,
)
from .meta import execute_list_techniques  # noqa: F401
from .text import (  # noqa: F401
    execute_text_capacity,
    execute_text_decode,
    execute_text_encode,
    execute_text_steg,
    execute_text_steg_message,
)
from .triage import execute_triage  # noqa: F401

_MODULES = (image, triage, text, meta)

TOOL_EXECUTORS: dict = {}
TOOL_SCHEMAS: dict = {}

for _m in _MODULES:
    for _name, _fn in _m.EXECUTORS.items():
        if _name in TOOL_EXECUTORS:
            raise RuntimeError(f"duplicate tool executor registered: {_name}")
        TOOL_EXECUTORS[_name] = _fn
    for _name, _schema in _m.SCHEMAS.items():
        if _name in TOOL_SCHEMAS:
            raise RuntimeError(f"duplicate tool schema registered: {_name}")
        TOOL_SCHEMAS[_name] = _schema

# Sanity: every executor should have a schema and vice versa.
_missing_schemas = set(TOOL_EXECUTORS) - set(TOOL_SCHEMAS)
_missing_executors = set(TOOL_SCHEMAS) - set(TOOL_EXECUTORS)
if _missing_schemas or _missing_executors:
    raise RuntimeError(
        f"tool registry mismatch: missing schemas={_missing_schemas}, "
        f"missing executors={_missing_executors}"
    )

__all__ = ["TOOL_EXECUTORS", "TOOL_SCHEMAS"]
