# Plan: Classic Text Encoders in ST3GG

## Motivation

ST3GG describes itself as *"a library of encoders, decoders, and detectors you can
compose into workflows."* For image steganography this holds: `steg_core.encode` +
`steg_core.decode` + the detectors in `analysis_tools.py` form a closed loop that
tests exercise (encode → detect → decode round-trip).

For **text steganography** the loop is broken. The 13 text techniques ship as:

| Layer                    | Encode | Decode | Detect |
|--------------------------|--------|--------|--------|
| `index.html` (JS/browser)| ✅     | ✅     | ✅     |
| Python library           | ❌     | ❌     | ✅     |
| `stegg_cli`              | ❌     | ❌     | (n/a)  |
| `st3ggmcp` (MCP server)  | ❌     | ❌     | ✅     |
| `examples/generate_*`    | one-shot, hardcoded payload/cover | ❌ | ❌ |

Concretely today:

- `analysis_tools.py` exposes `detect_unicode_steg`, `detect_whitespace_steg`,
  `detect_homoglyph_steg`, `detect_confusable_whitespace`, and detectors for the
  other nine techniques.
- `examples/generate_examples.py` has `generate_zero_width_text`,
  `generate_homoglyph`, `generate_whitespace_text`, `generate_invisible_ink_text`,
  etc. — but each hardcodes its own payload string and cover text, writes a file
  to disk, and returns nothing importable.
- `index.html` has `encodeZeroWidth`, `decodeZeroWidth`, `encodeHomoglyph`,
  `decodeHomoglyph`, `encodeWhitespace`, `decodeWhitespace`, `encodeInvisibleInk`,
  `decodeInvisibleInk` (lines 7700, 7846, 7905, 7969 and companions). These are
  the *actual* reference implementations — the Python side has no matching API.
- `st3ggmcp/tools.py` exposes `stegg_text_steg` (detect only) and
  `stegg_encode_manual` (image LSB only). There is no MCP tool for text encode.

Round-trip tests, workflow composition, and MCP-driven text steg encode are all
blocked on this gap.

## Goal

Ship a Python + MCP **encode/decode API** for the four "classic" text-in-text
techniques, wired up so that each `encode_*` composes cleanly with the existing
`detect_*` and with a new complementary `decode_*`.

Scope for this plan: **zero-width Unicode, homoglyph substitution, whitespace
encoding, invisible ink (tag chars)**. The other nine techniques
(variation selectors, combining marks, confusable whitespace, emoji substitution,
capitalization, directional override, hangul filler, braille, math alphanumerics)
follow the same pattern and are deliberately deferred to a follow-up plan so we
can lock the API shape on four before generalizing to thirteen.

## Design

### Single new module: `ST3GG/text_core.py`

Everything text-encoder related lives in one module — parallel to how
`steg_core.py` owns the image side. Rationale: keeps `analysis_tools.py`
detector-only (its current role), keeps `injector.py` metadata-only.

Public API (one encode + one decode per technique):

```python
# text_core.py

# --- constants ---
ZWSP, ZWNJ, ZWJ = '​', '‌', '‍'
TAG_BASE        = 0xE0000
HOMOGLYPH_MAP   = { ... }   # 19 Latin→Cyrillic pairs, ported from examples/

# --- exceptions ---
class TextStegCapacityError(ValueError): ...  # raised by encoders when cover too small

# --- carriers info (helps callers pre-flight capacity) ---
def capacity(cover: str, method: str) -> dict:
    """Return {'method', 'carrier_bits', 'payload_bytes_max', 'notes'}."""

# --- per-technique encode/decode ---
def encode_zero_width(cover: str, secret: str) -> str: ...
def decode_zero_width(stego: str) -> str: ...

def encode_homoglyph(cover: str, secret: str) -> str: ...
def decode_homoglyph(stego: str) -> str: ...

def encode_whitespace(cover: str, secret: str) -> str: ...
def decode_whitespace(stego: str) -> str: ...

def encode_invisible_ink(cover: str, secret: str) -> str: ...
def decode_invisible_ink(stego: str) -> str: ...

# --- generic dispatcher ---
METHODS = ('zero_width', 'homoglyph', 'whitespace', 'invisible_ink')
def encode(cover: str, secret: str, method: str) -> str: ...
def decode(stego: str, method: str) -> str: ...
```

Notes on the shape:

- **All four decoders are self-framing** (either a length prefix or
  sentinel chars carry the framing). None require the original cover.
  This matches the JS decoders in `index.html`.
- **Framing is per-technique, matching the browser JS at
  `index.html:7700+`.** We port ST3GG's existing behavior; we do not
  redesign it. Concretely:

  | Technique     | Framing (as shipped in JS)                              | JS ref         |
  |---------------|---------------------------------------------------------|----------------|
  | zero_width    | ZWJ start sentinel + payload bits + ZWJ end sentinel    | 7721–7725      |
  | homoglyph     | 16-bit length prefix + payload bits                     | 7854–7856      |
  | whitespace    | 16-bit length prefix + payload bits (8 bits/line max)   | 7913–7915      |
  | invisible_ink | U+E0000 start tag + ASCII→tag chars + U+E007F end tag   | 7971–7981      |

  Round-trip compatibility with the browser and existing example files is
  a hard requirement — a file encoded in the browser must decode with
  `text_core.decode_*` and vice versa.
- `capacity(cover, method)` is the pre-flight check that turns
  "TextStegCapacityError" from a surprise into a decision. It's what a
  caller uses to decide "do I need to double my cover, switch methods, or
  shorten the payload?" — exactly the failure mode we hit on the Preamble.

### Porting source

Prefer the JS in `index.html` as the source of truth for algorithm details
(bit-per-char scheme, delimiters, carrier walk order), because those functions
were built for round-trip use. The one-shot Python generators in
`examples/generate_examples.py` are close but not identical — we port the JS
semantics and treat any drift as a bug to reconcile.

### CLI surface (`cli.py`)

Add two subcommands under a new `text` group:

```
stegg text encode --method <zero_width|homoglyph|whitespace|invisible_ink> \
                  --cover <path|-> --secret <string> [--out <path>]
stegg text decode --method <...> --stego <path|->
stegg text capacity --method <...> --cover <path|->
```

These are thin wrappers over `text_core.encode`/`decode`/`capacity` — same
error-reporting style as `encode_cmd`/`decode_cmd` at `cli.py:142/284`.

### MCP surface (`st3ggmcp/tools.py`)

Add three async tools, mirroring the existing `stegg_encode_manual` pattern
(`tools.py:707`):

- `stegg_text_encode(cover_path_or_text, secret, method, output_path=None)`
- `stegg_text_decode(stego_path_or_text, method)`
- `stegg_text_capacity(cover_path_or_text, method)`

Register in the tool schema block at `tools.py:~1030` and describe in the tool
description block at `tools.py:~1118`, next to the existing `stegg_text_steg`
entries so the "text steg family" is co-located in the field guide.

Field-guide update: extend `st3ggmcp/field_guide.md` — the current guide only
mentions detect (`stegg_text_steg`). Add an "encode" row to the technique
matrix so agents know which tool to reach for.

### Tests

New file `tests/unit/test_text_core.py` with parametrized round-trip tests:

```python
@pytest.mark.parametrize("method", text_core.METHODS)
def test_round_trip(method):
    cover  = COVERS[method]     # per-method cover with adequate capacity
    secret = "flag{4m3r1c4n_sp1r1t}"
    stego  = text_core.encode(cover, secret, method)
    assert text_core.decode(stego, method) == secret
```

Plus per-technique tests for:

1. **Capacity failure** — `encode` raises `TextStegCapacityError` with a
   diagnostic message when the cover is too small.
2. **Detector composition** — after `encode_*`, the corresponding
   `detect_*` from `analysis_tools.py` returns `found=True`. This is the
   *reason for the whole plan*: the encoder/detector loop must close.
3. **Corruption tolerance** — decode of a partially-mangled stego (e.g.
   zero-width chars randomly stripped) fails gracefully, not with a crash.

Existing example-file tests in `tests/examples/test_unicode_text_examples.py`
should continue to pass unchanged — the generator scripts stay, they just
become one of two ways to produce stego (the other being `text_core.encode`).

## Milestones

1. **M1 — Port + Python API.** Create `text_core.py` with all four
   encode/decode pairs, HOMOGLYPH_MAP, capacity(), and TextStegCapacityError.
   Land `test_round_trip` + capacity + detector-composition tests.

2. **M2 — CLI.** Add `stegg text encode|decode|capacity` subcommands.
   Smoke test: encode Preamble → decode → matches; and doubled-Preamble
   homoglyph round-trip on the CLI.

3. **M3 — MCP.** Add `stegg_text_encode`, `stegg_text_decode`,
   `stegg_text_capacity` async tools; register in schema and executor maps;
   update `field_guide.md` technique matrix.

4. **M4 — Cross-language fixture test.** For each of the four techniques,
   commit a fixture stego file produced by the browser JS and assert
   `text_core.decode_*` reads it correctly. Also assert that encoding
   the same (cover, secret) in Python produces byte-for-byte identical
   output. Anything that diverges is a Python port bug; the JS is the
   source of truth.

5. **M5 — Follow-up plan.** Once M1–M4 are stable, write
   `plan-extended-text-encoders.md` covering the other nine techniques on
   the same API shape.

## Out of scope

**Encryption composition.** `crypto.encrypt` returns bytes; text encoders
take strings. For this plan, callers are responsible for any encryption
and base64-wrapping — pass the resulting ASCII string as the `secret`
argument. No `text_core.encode_encrypted` convenience method. Revisit
after the API and reorganization ship if callers find this painful.
