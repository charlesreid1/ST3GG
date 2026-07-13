# st3ggmcp

MCP server exposing the ST3GG steganography toolset over HTTP.

Covers three carrier families as equal peers — **image**, **text**, **emoji** — plus general steganography advice (persona answers general-craft questions from knowledge; a file is not required).

**Transport-aware.** The persona treats "how is this getting delivered?" as a first-class question. Every transport has a *canonical form* it treats as the real message and normalizes everything below that line — Slack canonicalizes to the rendered post (kills EXIF, kills PNG text chunks, canonicalizes emoji to `:colon_form:` and murders emoji-attached tag sequences and variation selectors), terminal stdout canonicalizes to visible glyphs (kills zero-width unless you pipe through `pbcopy` / `xclip`), JPEG re-encode canonicalizes to a perceptual approximation (kills LSB). See `TRANSPORT_MATRIX.md` for the empirical scoreboard.

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

Image tools take a `path` (server-local filesystem path). Text tools accept either inline text or a UTF-8 file path — no image required. Encoder tools take an optional `output_path`.

Image detect / decode:
- `stegg_read_metadata` — PNG text chunks + PIL info
- `stegg_triage` — signals-expert sweep with severity + verdict
- `stegg_lsb_smart_scan` — brute-force LSB extraction
- `stegg_detect_trailing` — bytes past IEND / EOI
- `stegg_read_png_chunks` — full PNG chunk dump
- `stegg_decode_manual` — LSB decode with an explicit recipe
- `stegg_carve` — try ZIP/GZip/TAR/PDF/SQLite/SVG/PCAP/JPEG/audio-LSB decoders

Text / emoji detect / decode:
- `stegg_text_steg` — full text-steg detector suite over a file
- `stegg_text_steg_message` — same suite over an inline text string
- `stegg_text_decode` — recover a payload with a named method
- `stegg_text_capacity` — pre-flight how many bytes fit under a method

Encode / hide:
- `stegg_encode_manual` — LSB hide with channels + bits + strategy
- `stegg_encode_metadata` — hide in a PNG text or private chunk
- `stegg_text_encode` — hide in text via zero_width / homoglyph / whitespace / invisible_ink / variation / combining / confusable / directional / hangul / mathbold / braille / emoji / skintone / capitalization

Meta:
- `stegg_list_techniques` — catalog of what this server can do

## Resources

- `stegg://field-guide` — the full ST3GG persona + technique catalog + signal-reading heuristics + response format. Read this before analyzing files.

## Design notes

- No auth. Meant for container-to-container use on a private docker network.
- No archive unpacking, no execution of any file contents. Tools operate on raw bytes only.
- File size cap: 100 MB per read.
- Per-tool timeout: 30 seconds.
