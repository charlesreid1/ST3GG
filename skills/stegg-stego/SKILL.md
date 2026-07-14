---
name: stegg-stego
description: "ST3GG steganography via HTTP MCP server — image LSB encode/decode, PNG chunk/EXIF injection, statistical triage with SUSPICIOUS/INCONCLUSIVE/CLEAN verdicts, text and emoji carriers (zero-width, homoglyph, whitespace, variation, combining, confusable, directional, hangul, mathbold, braille, emoji, skintone, capitalization), and container carving (ZIP/GZip/TAR/PDF/SQLite/SVG/PCAP/JPEG/audio-LSB). Use when analyzing files for hidden content, hiding data in images or text, injecting metadata, or answering technique-tradeoff questions. Triggers on stegg, steganography, steg, LSB, hide data, hidden data, steganalysis, zero-width, homoglyph, PNG chunk, EXIF injection."
---

# ST3GG stego (MCP)

HTTP MCP server exposing 15 steganography tools across three carrier families — **image**, **text**, **emoji** — plus a persona field guide. Results come back inline in the LLM context; use `stegg-cli` (subprocess skill) instead when results are large and you don't need to reason over them inline.

## Server

Endpoint: `http://<host>:8765/mcp` (Streamable HTTP, stateless).

Start with `stegg-mcp` (after `pip install -e '.[mcp]'`). Container-to-container use — no auth, binds `0.0.0.0` by default.

## When to use this vs. `stegg-cli`

- **Use `stegg-cli` (subprocess)** for routine encode/decode/analyze where output is verbose and doesn't need inline reasoning.
- **Use the MCP server (this skill)** when you want to reason over the result inline, chain tools with LLM judgment between them, or need the `stegg_triage` verdict and `stegg://field-guide` resource in context.

## Tool families

Image detect / decode:
- `stegg_read_metadata` — PNG text chunks (tEXt/iTXt/zTXt) + PIL info. Run FIRST.
- `stegg_triage` — composed multi-probe sweep with severity + verdict. Structural drives verdict; statistical is advisory.
- `stegg_lsb_smart_scan` — brute-force LSB extraction across channel/bit/strategy combos.
- `stegg_detect_trailing` — bytes past IEND / EOI.
- `stegg_read_png_chunks` — full PNG chunk dump.
- `stegg_decode_manual` — LSB decode with an explicit recipe.
- `stegg_carve` — try ZIP/GZip/TAR/PDF/SQLite/SVG/PCAP/JPEG/audio-LSB decoders on a file or byte range.

Text / emoji detect / decode:
- `stegg_text_steg` — full text-steg detector suite over a file.
- `stegg_text_steg_message` — same suite over an inline pasted string.
- `stegg_text_decode` — recover a payload via a named method.
- `stegg_text_capacity` — pre-flight how many bytes fit.

Encode / hide:
- `stegg_encode_manual` — image LSB with `channels + bits + strategy`.
- `stegg_encode_metadata` — hide in a PNG text chunk (tEXt/iTXt/zTXt) or private chunk.
- `stegg_text_encode` — hide via one of: zero_width, homoglyph, whitespace, invisible_ink, variation, combining, confusable, directional, hangul, mathbold, braille, emoji, skintone, capitalization.

Meta:
- `stegg_list_techniques` — catalog of what this server can do.

## Resource

- `stegg://field-guide` — persona + technique catalog + signal-reading heuristics + verdict semantics + response format. **Read this before analyzing a file.**

## Key constraints

- All tools take server-local filesystem paths — no HTTP upload.
- File size cap: 100 MB per read. Per-tool timeout: 30 seconds.
- `stegg_triage` verdicts:
  - **SUSPICIOUS** — HIGH structural finding, OR two statistical probes corroborate on the same channel.
  - **INCONCLUSIVE** — MEDIUM structural, OR any single statistical probe hit.
  - **CLEAN** — nothing above threshold. Detection has real failure modes; CLEAN is a statement about what the probes saw, not a guarantee.
- Encoders write to `output_path` (or a `stegg_`-prefixed sibling of the input).

## Common flows

**Analyze a suspicious image**
1. `stegg_read_metadata` — cheap plaintext-in-chunks catch.
2. `stegg_triage` — structural + statistical + bit-plane sweep with a verdict.
3. If triage flags a channel: `stegg_decode_manual` with the suggested recipe, or `stegg_lsb_smart_scan` to brute-force.
4. If trailing/appended bytes flagged: `stegg_carve(offset=<end_of_png>)`.

**Analyze pasted suspicious text**
1. `stegg_text_steg_message` — full detector suite inline.
2. If a detector hits: `stegg_text_decode` with the matching method.

**Hide data in an image**
1. `stegg_encode_manual` for LSB, or `stegg_encode_metadata` for chunk-smuggling.
2. Always round-trip with `stegg_decode_manual` before shipping.

**Hide data in text**
1. `stegg_text_capacity` — pre-flight the cover.
2. `stegg_text_encode` with a method matched to the transport (see `stegg://field-guide` for transport survival).

## Installation

```bash
pip install -e '.[mcp]'
stegg-mcp                    # defaults: 0.0.0.0:8765, endpoint /mcp
stegg-mcp --port 9000
```

Point any MCP client at `http://<host>:8765/mcp`.
