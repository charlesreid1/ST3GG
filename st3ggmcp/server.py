"""ST3GG MCP server: HTTP and stdio transports.

Run with:
    stegg-mcp                    # HTTP on port 8765
    stegg-mcp --port 9000        # HTTP on custom port
    stegg-mcp-stdio              # stdio (spawned by MCP clients like Claude Code)

Or:
    python -m st3ggmcp.server           # HTTP
    python -m st3ggmcp.server --stdio   # stdio (same as stegg-mcp-stdio)

HTTP mode: container-to-container use only. No auth. Bind address defaults to 0.0.0.0.
Stdio mode: the client launches this process; JSON-RPC over stdin/stdout, logs on stderr.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import (
    Resource,
    TextContent,
    Tool,
)
import mcp.types as types

import uvicorn
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send

from .tools import TOOL_EXECUTORS, TOOL_SCHEMAS

logger = logging.getLogger(__name__)

FIELD_GUIDE_PATH = Path(__file__).parent / "field_guide.md"
FIELD_GUIDE_URI = "stegg://field-guide"


def build_server() -> Server:
    server: Server = Server("st3ggmcp")

    @server.list_tools()
    async def _list_tools() -> list[Tool]:
        return [
            Tool(
                name=name,
                description=schema["description"],
                inputSchema=schema["inputSchema"],
            )
            for name, schema in TOOL_SCHEMAS.items()
        ]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict) -> list[TextContent]:
        executor = TOOL_EXECUTORS.get(name)
        if executor is None:
            return [TextContent(type="text", text=f"Unknown tool '{name}'")]
        try:
            result = await executor(**(arguments or {}))
        except Exception as exc:
            logger.exception("tool %s crashed", name)
            result = f"tool {name} crashed: {type(exc).__name__}: {exc}"
        if not isinstance(result, str):
            result = str(result)
        return [TextContent(type="text", text=result)]

    @server.list_resources()
    async def _list_resources() -> list[Resource]:
        if not FIELD_GUIDE_PATH.exists():
            return []
        return [
            Resource(
                uri=FIELD_GUIDE_URI,
                name="ST3GG field guide",
                description=(
                    "Complete field guide for the ST3GG steganography analyst persona: "
                    "technique catalog, signal-reading heuristics, extraction workflow, "
                    "verdict semantics, code snippets. Read this before analyzing any file."
                ),
                mimeType="text/markdown",
            )
        ]

    @server.read_resource()
    async def _read_resource(uri) -> str:
        if str(uri) == FIELD_GUIDE_URI:
            if FIELD_GUIDE_PATH.exists():
                return FIELD_GUIDE_PATH.read_text(encoding="utf-8")
            return "field guide not found on server"
        raise ValueError(f"unknown resource: {uri}")

    return server


def build_asgi_app() -> Starlette:
    server = build_server()
    session_manager = StreamableHTTPSessionManager(app=server, stateless=True)

    async def handle(scope: Scope, receive: Receive, send: Send) -> None:
        await session_manager.handle_request(scope, receive, send)

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(app):
        async with session_manager.run():
            yield

    # Accept both /mcp and /mcp/ so clients that omit the trailing slash
    # don't get a 307 redirect they can't POST through.
    return Starlette(
        routes=[
            Mount("/mcp/", app=handle),
            Mount("/mcp", app=handle),
        ],
        lifespan=lifespan,
    )


async def _run_stdio(log_level: str = "info") -> None:
    """Run the MCP server over stdin/stdout using the reference MCP stdio transport.

    Logging is configured to stderr -- the stdio transport reserves stdout
    for JSON-RPC frames, so anything written there corrupts the protocol.
    """
    logging.basicConfig(
        level=log_level.upper(),
        format="%(asctime)s  %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    server = build_server()
    logger.info("st3ggmcp stdio server starting")
    logger.info("tools: %s", ", ".join(TOOL_EXECUTORS.keys()))

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main_stdio() -> None:
    """Entry point for `stegg-mcp-stdio`.

    Small argument surface -- stdio clients typically launch the process
    directly and don't pass configuration. Log level is the one useful knob.
    """
    parser = argparse.ArgumentParser(description="ST3GG MCP stdio server")
    parser.add_argument("--log-level", default="info", help="log level for stderr (default info)")
    args = parser.parse_args()
    asyncio.run(_run_stdio(log_level=args.log_level))


def main() -> None:
    parser = argparse.ArgumentParser(description="ST3GG MCP HTTP server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8765, help="Bind port (default 8765)")
    parser.add_argument("--log-level", default="info", help="uvicorn/log level")
    parser.add_argument(
        "--stdio",
        action="store_true",
        help="Run in stdio mode instead of HTTP (equivalent to stegg-mcp-stdio).",
    )
    args = parser.parse_args()

    if args.stdio:
        asyncio.run(_run_stdio(log_level=args.log_level))
        return

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s  %(levelname)-7s %(name)s: %(message)s",
    )

    logger.info("st3ggmcp starting on %s:%d, endpoint /mcp", args.host, args.port)
    logger.info("tools: %s", ", ".join(TOOL_EXECUTORS.keys()))

    app = build_asgi_app()
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)


if __name__ == "__main__":
    main()
