# AGENTS.md

Guide for coding agents dropped into this repo. Short intentionally — for depth, follow the pointers.

## What this is

ST3GG is a steganography toolkit covering three carrier families as equal peers: **image** (PNG/JPEG/BMP LSB, chunk smuggling, metadata, polyglots), **text** (zero-width, homoglyph, whitespace, and eleven others), and **emoji** (substitution, skin-tone modifiers, braille block, variation selectors). Python core + CLI, browser-side Text Lab (`index.html`), plus two agent entry points.

## Two agent entry points

Both wrap the same underlying library (`img_core`, `text_core`, `analysis_tools`, `injector`, `crypto`). Pick one:

### `stegg-cli` — subprocess CLI
Skill: `skills/stegg-cli/SKILL.md`. Invoke as `python3 stegg_cli.py <command>` (or `stegg-cli` after install). JSON output. **Prefer this for routine encode/decode/analyze** — output stays out of LLM context.

### `stegg-mcp` — HTTP MCP server
Skill: `skills/stegg-stego/SKILL.md`. Reference: `skills/stegg-stego/REFERENCE.md`. Package: `st3ggmcp/`. Streamable HTTP on `:8765/mcp`. **Use this when you want to reason over results inline**, chain tools with LLM judgment between steps, or need the `stegg://field-guide` resource loaded.

Rule of thumb: CLI first for context hygiene, MCP for inline reasoning.

## Field guide

`st3ggmcp/field_guide.md` — the ST3GG analyst persona, technique catalog, signal-reading heuristics, verdict semantics, transport-survival tables. Read this before analyzing a suspicious file. Also served as MCP resource `stegg://field-guide`.

`st3ggmcp/TRANSPORT_MATRIX.md` — which techniques survive which delivery channels (Slack, terminal stdout, JPEG re-encode, etc.).

## Repo layout

- `img_core.py` — image LSB encode/decode + config + capacity math
- `text_core.py` — text/emoji encode/decode (14 methods)
- `analysis_tools.py` — 264+ detection/analysis functions
- `injector.py` — PNG chunk + EXIF injection
- `crypto.py` — optional AES-256-GCM
- `cli.py`, `stegg_cli.py` — main CLI + subprocess-friendly JSON CLI
- `tui.py`, `webui.py` — optional Textual + NiceGUI UIs
- `st3ggmcp/` — HTTP MCP server package
  - `server.py` — ASGI app + entry point
  - `tools/` — per-family tool modules (`image`, `text`, `triage`, `meta`), each colocating executors with their JSON schemas
  - `field_guide.md`, `TRANSPORT_MATRIX.md` — persona + delivery-channel notes
- `skills/stegg-cli/`, `skills/stegg-stego/` — agent skill definitions
- `index.html`, `f5stego-lib.js` — browser Text Lab + F5 JPEG
- `tests/` — pytest suite (image round-trips, text detectors, cross-language fixtures)
- `examples/` — pre-encoded fixtures

## Install

```bash
pip install -e .              # core CLI
pip install -e '.[mcp]'       # + HTTP MCP server
pip install -e '.[all]'       # everything (TUI, web, crypto, MCP)
```

## Tests

```bash
pytest -q
pytest -q -m "not slow"       # skip round-trip sweeps
```

Markers: `slow`, `crypto`, `pipeline`, `regenerates_examples`. `regenerates_examples` writes under `examples/pipelines/` — don't run casually.

## Ground rules

- Text and emoji are first-class carriers, not afterthoughts. Any change that assumes "steg == image LSB" is wrong.
- Detection has real failure modes. `stegg_triage` verdicts encode this — HIGH severity requires corroboration across multiple probes; a single-probe hit is MEDIUM at best.
- No auth on the MCP server. Container-to-container use only.
- Don't rename `st3ggmcp` casually — it's wired into `pyproject.toml` entry points and the `skills/stegg-stego/` skill.
