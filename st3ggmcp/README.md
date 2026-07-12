# st3ggmcp

MCP server exposing the ST3GG steganography toolset over HTTP.

## Install

```bash
pip install -e '.[mcp]'
```

## Run

```bash
stegg-mcp                    # defaults: 0.0.0.0:8765, endpoint /mcp
stegg-mcp --port 9000
```

Or:

```bash
python -m st3ggmcp.server
```

## Client config

Point any MCP client (Claude Code, opencode) at `http://<host>:8765/mcp` as an HTTP MCP server. The server is stateless.

## Tools

Every tool takes a `path` (server-local filesystem path). Encoder tools take an `output_path` to write the encoded file to.

- `stegg_read_metadata`
- `stegg_triage`
- `stegg_lsb_smart_scan`
- `stegg_detect_trailing`
- `stegg_read_png_chunks`
- `stegg_decode_manual`
- `stegg_text_steg`
- `stegg_text_steg_message`
- `stegg_carve`
- `stegg_encode_manual`
- `stegg_encode_metadata`
- `stegg_list_techniques`

## Resources

- `stegg://field-guide` — the full ST3GG persona + technique catalog + signal-reading heuristics + response format. Read this before analyzing files.

## Design notes

- No auth. Meant for container-to-container use on a private docker network.
- No archive unpacking, no execution of any file contents. Tools operate on raw bytes only.
- File size cap: 100 MB per read.
- Per-tool timeout: 30 seconds.
