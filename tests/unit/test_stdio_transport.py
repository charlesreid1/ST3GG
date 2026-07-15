"""End-to-end test for the stdio MCP transport.

The stdio transport reserves stdout for JSON-RPC frames -- anything
else on stdout corrupts the protocol. These tests catch stdout
contamination (from stray print()s, uncaught logger config, etc.) that
unit tests of the executors themselves would miss because they never
exercise the transport.

Approach: spawn the server as a subprocess (the same way an MCP client
would), speak JSON-RPC 2.0 over its stdin/stdout, and assert:
  * initialize succeeds
  * tools/list returns the full registry
  * a real tools/call round-trips
  * every stdout line is valid JSON (no leaked prints or logs)
  * logger output lands on stderr, not stdout, even at --log-level info

We drive the server via `python -m st3ggmcp.server --stdio` rather
than the console script so tests don't require an editable install.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Optional

import pytest

from st3ggmcp.tools import TOOL_EXECUTORS


SPAWN_CMD_BASE = [sys.executable, "-m", "st3ggmcp.server", "--stdio"]


class StdioClient:
    """Minimal JSON-RPC 2.0 client over the subprocess's stdio.

    Not general -- just enough to drive the initialize / tools/list /
    tools/call handshake and read one response per request. Assumes the
    server writes exactly one JSON object per line, which is what the
    reference MCP stdio server does.
    """

    def __init__(self, log_level: str = "warning"):
        self.proc = subprocess.Popen(
            SPAWN_CMD_BASE + ["--log-level", log_level],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._next_id = 1
        self._stdout_lines: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def send(self, method: str, params: dict | None = None, notify: bool = False) -> Optional[int]:
        msg: dict = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        msg_id = None
        if not notify:
            msg_id = self._next_id
            self._next_id += 1
            msg["id"] = msg_id
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        return msg_id

    def recv(self, timeout: float = 5.0) -> dict:
        assert self.proc.stdout is not None
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError(
                f"server closed stdout before responding; stderr tail: "
                f"{self._read_stderr()[-500:]}"
            )
        self._stdout_lines.append(line)
        return json.loads(line)

    def stdout_lines(self) -> list[str]:
        return list(self._stdout_lines)

    def _read_stderr(self) -> str:
        assert self.proc.stderr is not None
        return self.proc.stderr.read()

    def close(self) -> tuple[str, int]:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        stderr = self._read_stderr()
        return stderr, self.proc.returncode


def _handshake(client: StdioClient) -> dict:
    """Do the MCP initialize handshake, return the initialize result."""
    client.send("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "st3gg-test", "version": "0.0.0"},
    })
    resp = client.recv()
    assert "result" in resp, f"initialize failed: {resp}"
    client.send("notifications/initialized", notify=True)
    return resp["result"]


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------

def test_initialize_returns_serverinfo():
    with StdioClient() as client:
        result = _handshake(client)
        assert "serverInfo" in result
        assert result["serverInfo"]["name"] == "st3ggmcp"


def test_tools_list_returns_full_registry():
    with StdioClient() as client:
        _handshake(client)
        client.send("tools/list")
        resp = client.recv()
        assert "result" in resp
        names = {t["name"] for t in resp["result"]["tools"]}
        # Every tool the in-process registry has must be discoverable
        # over stdio -- catches accidental schema-vs-executor drift too.
        assert names == set(TOOL_EXECUTORS.keys())


def test_tools_call_roundtrips():
    """Full tool call over the wire: list_techniques is small, dependency-free.

    Only checks the wire-level round-trip: the JSON-RPC frame parses,
    the content is a text block, and the payload is recognisably the
    catalog. We deliberately do not re-parse the text payload -- the
    tool may truncate its serialised output with a human-readable
    marker (see ``truncate_json`` in ``_common.py``), which is not
    itself valid JSON. The transport contract is that stdout lines
    are valid JSON, not that every embedded string is.
    """
    with StdioClient() as client:
        _handshake(client)
        client.send("tools/call", {
            "name": "stegg_list_techniques",
            "arguments": {},
        })
        resp = client.recv()
        assert "result" in resp, f"tools/call failed: {resp}"
        content = resp["result"]["content"]
        assert len(content) == 1
        assert content[0]["type"] == "text"
        # Catalog contents recognisable in the text block.
        text = content[0]["text"]
        assert '"families"' in text
        assert '"image"' in text


# ---------------------------------------------------------------------------
# Stdout hygiene: the whole point of the stdio transport
# ---------------------------------------------------------------------------

def test_every_stdout_line_is_valid_json():
    """Anything on stdout that is not a JSON-RPC frame corrupts the protocol.

    Drive the server through a small session and assert every line it
    wrote to stdout parses as JSON. A single stray `print()` anywhere in
    the tool dependency graph will fail this test.
    """
    with StdioClient() as client:
        _handshake(client)
        client.send("tools/list")
        client.recv()
        client.send("tools/call", {
            "name": "stegg_list_techniques",
            "arguments": {},
        })
        client.recv()
        # Every line the client observed on stdout parses cleanly.
        for line in client.stdout_lines():
            try:
                json.loads(line)
            except json.JSONDecodeError as exc:
                pytest.fail(f"non-JSON line on stdout: {line!r} ({exc})")


def test_info_level_logs_go_to_stderr_not_stdout():
    """--log-level info must not leak log records into the JSON-RPC stream."""
    with StdioClient(log_level="info") as client:
        _handshake(client)
        stderr, returncode = client.close()

    # The startup log line lands on stderr.
    assert "stdio server starting" in stderr, (
        f"expected startup log on stderr, got:\n{stderr[:500]}"
    )
    # And every stdout line the client saw is still valid JSON.
    for line in client.stdout_lines():
        json.loads(line)  # will raise if it isn't


# ---------------------------------------------------------------------------
# Failure surfaces: server should stay well-behaved on bad input
# ---------------------------------------------------------------------------

def test_unknown_tool_returns_structured_error_not_a_crash():
    with StdioClient() as client:
        _handshake(client)
        client.send("tools/call", {
            "name": "stegg_definitely_not_a_tool",
            "arguments": {},
        })
        resp = client.recv()
        # Whether the server sends an error result or a JSON-RPC error,
        # the important property is: it stays alive and speaks JSON-RPC.
        assert "id" in resp
        assert "result" in resp or "error" in resp
