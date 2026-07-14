"""Tool registry for the st3ggmcp MCP server.

Each per-family submodule exports its own `EXECUTORS` and `SCHEMAS` dicts;
this module merges them into the two dicts server.py consumes. Adding a tool
means editing exactly one submodule.
"""

from __future__ import annotations

from . import image, meta, text, triage

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
