# Plan: Advanced Unicode Text Encoders in ST3GG

Follow-up to [plan-classic-text-encoders.md](./plan-classic-text-encoders.md),
which shipped `text_core.encode/decode/capacity` for the four classic
techniques (`zero_width`, `homoglyph`, `whitespace`, `invisible_ink`) and the
matching `stegg text …` CLI and `stegg_text_encode|decode|capacity` MCP tools.
The API shape, framing conventions, and JS-as-source-of-truth stance carry
over unchanged; this plan extends them to the next five techniques.

## Motivation

The classic plan closed the encode/detect/decode loop for four techniques. The
same gap still exists for the five "advanced Unicode" techniques listed in the
Text Lab dropdown at `index.html:3059-3063`:

| Layer                          | Encode | Decode | Detect |
|--------------------------------|--------|--------|--------|
| `index.html` (JS/browser)      | ✅     | ✅     | ✅     |
| Python library (`text_core.py`)| ❌     | ❌     | partial |
| `stegg text` CLI               | ❌     | ❌     | (n/a)  |
| `st3ggmcp` MCP server          | ❌     | ❌     | partial |
| `examples/generate_*`          | one-shot, hardcoded payload/cover | ❌ | ❌ |

Concretely today:

- `text_core.METHODS` is `('zero_width', 'homoglyph', 'whitespace', 'invisible_ink')`.
  `encode()`, `decode()`, and `capacity()` all reject the five advanced methods
  as unknown.
- `analysis_tools.py` has `detect_variation_selector_steg` (line 1989),
  `detect_combining_mark_steg` (2009), and `detect_confusable_whitespace`
  (2042) — but **no** detector for directional overrides or hangul filler.
  `grep -nE 'def detect_.*(directional|hangul|bidi)' analysis_tools.py` returns
  nothing. So the "encode → detect → decode round-trip test" pattern the
  classic plan established as the reason-for-being can't be exercised for two
  of the five without new detectors.
- `index.html:8076-8152` has the JS encoders (`variation`, `combining`,
  `confusable`, `directional`, `hangul`); `index.html:8248-8301` has the
  decoders. These remain the reference implementations.
- `examples/generate_examples.py` has `generate_variation_selector` (3065),
  `generate_combining_diacritics` (3131), `generate_confusable_whitespace`
  (3192), `generate_directional_override` (3963), `generate_hangul_filler`
  (4005) — still one-shot hardcoded generators, still returning nothing
  importable.

MCP-driven text steg encode covers 4 of 13 techniques; this plan takes it to
9 of 13.

## Goal

Extend `text_core` with encode/decode/capacity for the five advanced Unicode
techniques, wired up so that each `encode_*` composes cleanly with a
`detect_*` in `analysis_tools.py` and with a complementary `decode_*`. No new
public API shape — just new entries in `METHODS` and the dispatcher tables,
same `TextStegCapacityError`, same `capacity()` report structure.

Scope: **variation selectors, combining marks, confusable whitespace,
directional overrides, hangul filler**. The remaining four techniques (emoji
substitution, capitalization, braille, math alphanumerics) will land in a
final follow-up plan — they diverge from the "modulate the cover in place"
pattern (braille/emoji append the payload as its own block; capitalization
mutates letter case which is lossy across normalization), and are worth
locking API shape on the in-place five first.

## Design

### Same module, new entries

Everything lands in `ST3GG/text_core.py` next to the classic four. Concretely:

```python
# text_core.py — new constants
VS1              = '︁'   # VARIATION SELECTOR-1     -> bit 1 (0 = absence)
CGJ              = '͏'   # COMBINING GRAPHEME JOINER -> bit 1 (0 = absence)
EN_SPACE         = ' '
EM_SPACE         = ' '
THIN_SPACE       = ' '
RLO              = '‮'   # RIGHT-TO-LEFT OVERRIDE   -> bit 1
LRO              = '‭'   # LEFT-TO-RIGHT OVERRIDE   -> bit 0
PDF              = '‬'   # POP DIRECTIONAL FORMATTING
HANGUL_FILLER    = 'ㅤ'   # -> bit 1 (regular space = 0)

CONFUSABLE_SPACE_TABLE = {
    '00': ' ',   '01': EN_SPACE,
    '10': EM_SPACE, '11': THIN_SPACE,
}
CONFUSABLE_REVERSE = {v: k for k, v in CONFUSABLE_SPACE_TABLE.items()}

# new entries in METHODS (order chosen so the tuple reads "classic then advanced"):
METHODS = (
    'zero_width', 'homoglyph', 'whitespace', 'invisible_ink',
    'variation', 'combining', 'confusable', 'directional', 'hangul',
)

# new per-technique encode/decode
def encode_variation(cover: str, secret: str) -> str: ...
def decode_variation(stego: str) -> str: ...

def encode_combining(cover: str, secret: str) -> str: ...
def decode_combining(stego: str) -> str: ...

def encode_confusable(cover: str, secret: str) -> str: ...
def decode_confusable(stego: str) -> str: ...

def encode_directional(cover: str, secret: str) -> str: ...
def decode_directional(stego: str) -> str: ...

def encode_hangul(cover: str, secret: str) -> str: ...
def decode_hangul(stego: str) -> str: ...

# extend the two dispatcher tables (_ENCODERS, _DECODERS) and the capacity()
# switch with the five new branches. No new dispatcher, no new error type.
```

### Framing table (ported verbatim from JS)

Round-trip compatibility with the browser is a hard requirement — the classic
plan's M4 fixture tests established this and the advanced techniques inherit
it. Framing per technique, as shipped in the JS at `index.html:8076-8152` /
`8248-8301`:

| Technique     | Framing (as shipped in JS)                                                          | Carrier positions          | Bits/carrier | JS ref (encode / decode) |
|---------------|-------------------------------------------------------------------------------------|----------------------------|--------------|--------------------------|
| variation     | 16-bit length prefix + payload bits; VS-1 present after carrier = 1, absent = 0     | `[a-zA-Z0-9]`              | 1            | 8077 / 8248              |
| combining     | 16-bit length prefix + payload bits; CGJ present after carrier = 1, absent = 0      | `[a-zA-Z]`                 | 1            | 8093 / 8261              |
| confusable    | 16-bit length prefix + payload bits; each ASCII space → 2 bits via space variant    | ASCII space `' '`          | 2            | 8110 / 8272              |
| directional   | 16-bit length prefix + payload bits; run of RLO/LRO+PDF pairs inserted after cover[0]| n/a (payload is its own run) | 1          | 8127 / 8281              |
| hangul        | 16-bit length prefix + payload bits; ASCII space → HANGUL FILLER (=1) or space (=0) | ASCII space `' '`          | 1            | 8138 / 8292              |

Two porting-fidelity notes worth writing down before implementation:

1. **JS uses `String.fromCharCode(parseInt(bits.slice(i,i+8),2))` on the
   decode side** — that is Latin-1 per byte, not UTF-8. The *encode* side did
   `new TextEncoder().encode(secret)` (UTF-8). So the JS decoder is subtly
   broken for multi-byte payloads: it reconstructs Latin-1 code points from
   UTF-8 bytes, and an emoji secret comes back as mojibake. The classic
   plan's Python port already diverges on this point — `_bits_to_bytes(...)
   .decode('utf-8', errors='replace')` — and the advanced port must stay
   consistent. Document the divergence in the module docstring; do not
   propagate the JS bug.
2. **Variation and combining decoders emit a `0` bit for every unmatched
   carrier char that appears *after* the encoded payload ends.** The tail of
   the cover contributes trailing zero-bits. This is harmless because the
   16-bit length prefix caps consumption at exactly `length * 8` payload
   bits — but the port must not accidentally "fix" this by requiring the
   carrier stream to end after the payload; that would reject legitimate
   browser output that happens to have carrier chars in the cover tail.

### Missing detectors — new work in `analysis_tools.py`

The classic plan asserted "the encoder/detector loop must close" via
`test_*_detector_composes`. To keep the same guarantee for the five advanced
techniques, we need two new detectors:

- `detect_directional_override_steg(data: bytes) -> Dict[str, Any]` — scan
  for `‮` / `‭` / `‬`, `found=True` when the count crosses a
  small threshold (the JS in-browser detector at `index.html:18819-18836`
  requires at least a few pairs and tries to decode; mirror that threshold).
- `detect_hangul_filler_steg(data: bytes) -> Dict[str, Any]` — scan for
  `ㅤ` (HANGUL FILLER). The JS detector at `index.html:18837-18852` uses
  simple presence + a decode-attempt; mirror.

The three existing detectors (`detect_variation_selector_steg`,
`detect_combining_mark_steg`, `detect_confusable_whitespace`) already
`return {'found': True, ...}` on any nontrivial presence. They compose with
our new encoders as-is; no changes required.

Register the two new detectors in whichever runner enumerates the text-family
detectors (search `detect_variation_selector_steg` — the callers there need
to grow the two new names).

### Capacity semantics

Extend `capacity(cover, method)` with the five new branches. Semantics:

| Technique     | `carrier_bits`                                     | `payload_bytes_max`     |
|---------------|----------------------------------------------------|-------------------------|
| variation     | `sum(1 for c in cover if c.isascii() and c.isalnum())` | `max(0, (bits-16)//8)`  |
| combining     | `sum(1 for c in cover if c.isascii() and c.isalpha())` | `max(0, (bits-16)//8)`  |
| confusable    | `2 * cover.count(' ')`                             | `max(0, (bits-16)//8)`  |
| directional   | `None` (payload rides in its own inserted run, cover only needs to be non-empty) | `None`                  |
| hangul        | `cover.count(' ')`                                 | `max(0, (bits-16)//8)`  |

The `directional` case matches how `zero_width` and `invisible_ink` are
reported today — cover is a splice site, not a carrier stream, so the report
is a note rather than a number.

Two of the five encoders (`variation`, `combining`) walk carrier positions
without warning when supply runs short — the JS encoder just stops encoding
mid-payload and shows a "Warning: Need more…" toast in the UI
(`index.html:8067-8068` for whitespace, same pattern for the rest). Python
must not do that: raise `TextStegCapacityError` with the same diagnostic
shape the classic encoders use (`f"variation: cover too small: need {need}
carrier bits, have {have} …"`). Silent truncation of a payload the caller
believed was encoded is a footgun.

### CLI

No new subcommands. `cli.py:636-...` (`text_encode_cmd`, `text_decode_cmd`,
`text_capacity_cmd`) already delegates to `text_core.encode/decode/capacity`
via the method string. Adding the five entries to `METHODS` is enough. The
CLI's `--method` value validation piggybacks on the same dispatcher error
(`unknown method '...'`) so the new names surface automatically.

Verify: `stegg text encode --method variation --cover - --secret 'x' <<< 'a b c'`
should work end-to-end after the `text_core` change, with no CLI edits.

### MCP

Same story: `st3ggmcp/tools.py:1053-1189` (`execute_text_encode`,
`execute_text_decode`, `execute_text_capacity`) dispatches through the same
`text_core` methods dict. No new tool registrations, no schema edits. The
tool description string at `tools.py:1016-1021` should be updated to list
the nine methods rather than four; that is the only doc-tightening in this
plan on the MCP side.

Field-guide update: `st3ggmcp/field_guide.md` currently mentions the classic
four in the encode row. Add the five advanced methods to the same row (or
break advanced onto its own row if the matrix is getting wide) so agents
know they're callable via `stegg_text_encode`.

### Tests

Extend `tests/unit/test_text_core.py` in place — do not fork a new file.
The parametrized `test_round_trip` picks up the new methods automatically
once they're added to `METHODS`, provided `COVERS` gains matching entries:

```python
COVERS = {
    "zero_width":    PREAMBLE,
    "homoglyph":     PREAMBLE + " " + PREAMBLE + " " + PREAMBLE,
    "whitespace":    LINES_COVER,
    "invisible_ink": PREAMBLE,
    # new — each has enough carrier capacity for SECRET:
    "variation":     PREAMBLE + " " + PREAMBLE,       # ~26 alnum chars per PREAMBLE isn't enough for 20-byte secret; double it
    "combining":     PREAMBLE + " " + PREAMBLE,       # same reasoning
    "confusable":    PREAMBLE + " " + PREAMBLE + " " + PREAMBLE + " " + PREAMBLE,  # needs ~90 spaces for 20-byte secret (2 bits/space)
    "directional":   PREAMBLE,                        # cover is splice site
    "hangul":        PREAMBLE + " " + PREAMBLE + " " + PREAMBLE + " " + PREAMBLE + " " + PREAMBLE + " " + PREAMBLE + " " + PREAMBLE,  # 1 bit/space
}
```

Then add per-technique:

1. **Capacity failure** — `encode` raises `TextStegCapacityError` on a
   too-small cover. Test the diagnostic mentions "cover too small".
   `directional` has no capacity limit; skip it or assert only the empty-cover
   guard.

2. **Detector composition** — after `encode_*`, the corresponding detector
   from `analysis_tools.py` returns `found=True`. This is the whole point:

   ```python
   def test_variation_detector_composes():
       stego = text_core.encode(COVERS["variation"], SECRET, "variation")
       r = at.detect_variation_selector_steg(stego.encode("utf-8"))
       assert r["found"] is True

   # …one each for combining, confusable, directional, hangul
   ```

3. **Corruption tolerance** — `decode` of a stego with the diacritics /
   RLO / hangul chars randomly stripped returns a `str` without raising.
   Same pattern as `test_zero_width_stripped_chars_does_not_crash`.

4. **`test_methods_tuple_is_the_four`** — rename to
   `test_methods_tuple_is_the_nine` and assert the full set.

Plus the cross-language fixture tests (M4 of the classic plan carried
forward) — one fixture per new technique, produced by the browser Text Lab,
committed under `tests/unit/fixtures/text_core/`. Byte-for-byte equality is
the pass bar. Any drift is a Python port bug. **Fixture spec** is in the
M4 section below.

The `examples/generate_examples.py` scripts stay as-is; they continue to
produce `examples/example_variation_selector.txt`,
`example_combining_diacritics.txt`, etc. If the JS-faithful `text_core`
output diverges from what the generators emit today, that is a real
divergence: the generators pre-date this plan and reproduce their own
algorithms rather than the JS. We can reconcile them in a follow-up (or
delete the redundant generators), but not in this plan's scope.

## Milestones

1. **M1 — Port + Python API.** Add the five encode/decode functions,
   constants, `capacity()` clauses, and `METHODS` entries to `text_core.py`.
   Extend `test_round_trip` inputs and add capacity + corruption-tolerance
   tests.

2. **M2 — Missing detectors.** Add `detect_directional_override_steg` and
   `detect_hangul_filler_steg` to `analysis_tools.py`. Add their registrations
   wherever the text-family detector list is enumerated. Land the five
   `test_*_detector_composes` tests.

3. **M3 — MCP + CLI surface polish.** Update the tool description strings in
   `st3ggmcp/tools.py:1016-1021` to list all nine methods. Update
   `st3ggmcp/field_guide.md` technique matrix. Smoke-test one encode/decode
   round-trip through the CLI (`stegg text encode --method directional …`).

4. **M4 — Cross-language fixtures.** Commit one browser-produced stego
   fixture per new technique under `tests/unit/fixtures/text_core/`. Assert
   `text_core.decode_*` reads it AND `text_core.encode_*` produces byte-for-byte
   identical output. Anything that diverges is a Python port bug; the JS is
   the source of truth.

   ### M4 fixture spec

   Existing convention (from the classic four) — cover is inlined in the
   test when it's a short literal, otherwise it ships as a `_cover.txt`
   sibling so the test can read both. Follow that same rule.

   Files to add under `tests/unit/fixtures/text_core/`:

   | Technique     | Files                                                | Cover source                   | Secret                              |
   |---------------|------------------------------------------------------|--------------------------------|-------------------------------------|
   | variation     | `variation_cover.txt`, `variation_stego.txt`         | 2× Preamble (enough alnum carriers) | `flag{v4r14t10n_s3l3ct0r5}`     |
   | combining     | `combining_cover.txt`, `combining_stego.txt`         | 2× Preamble (enough alpha carriers) | `flag{c0mb1n1ng_m4rk5}`         |
   | confusable    | `confusable_cover.txt`, `confusable_stego.txt`       | 4× Preamble (needs ~90 spaces) | `flag{c0nfu54bl3_5p4c35}`           |
   | directional   | inline literal in test (cover is short + one splice)  | Preamble                       | `flag{r1gh7_70_l3f7_0v3rr1d3}`      |
   | hangul        | `hangul_cover.txt`, `hangul_stego.txt`               | 7× Preamble (needs ~180 spaces)| `flag{h4ngul_f1ll3r_1n_pl41n_51gh7}`|

   Why the covers get large for `confusable` and `hangul`: framing is 16-bit
   length prefix plus `len(secret) * 8` bits. Confusable is 2 bits per ASCII
   space, hangul is 1 bit per ASCII space. Sized so the browser doesn't hit
   its own "Warning: Need more…" path — a truncated fixture is worse than
   no fixture, because it silently masks Python port bugs past the
   truncation point.

   Directional stays inline: the cover only functions as a one-char splice
   site (`cover[0] + <directional run> + cover[1:]`), so the amount of
   cover text is aesthetically-not-functionally load-bearing, and inlining
   it keeps the test self-contained the way `test_zero_width_fixture_from_browser`
   does today.

   ### M4 test scaffolding

   Extend `tests/unit/test_text_core.py` with the same pattern as the
   classic four:

   ```python
   def test_variation_fixture_from_browser():
       cover   = (FIXTURES / "variation_cover.txt").read_text(encoding="utf-8")
       secret  = "flag{v4r14t10n_s3l3ct0r5}"
       fixture = (FIXTURES / "variation_stego.txt").read_text(encoding="utf-8")
       assert text_core.decode(fixture, "variation") == secret
       assert text_core.encode(cover, secret, "variation") == fixture

   # …one each for combining, confusable, hangul, following the same shape.
   # directional uses the inline-cover form of test_zero_width_fixture_from_browser.
   ```

   Watch out for the trailing-newline gotcha already documented in the
   classic invisible_ink test — writing the stego to a `.txt` file appends
   a POSIX newline the encoder itself does not emit. Use `.rstrip("\n")`
   on any fixture whose encoder does not terminate with `\n`. This bites
   at least `directional` and possibly `variation` / `combining`
   (they all end with whatever the last cover character was, not a
   newline).

   ### How to regenerate the fixtures

   1. Open `index.html` in a browser, scroll to Text Lab.
   2. For each row in the table above: paste the cover into the cover
      textbox, paste the secret into the secret textbox, pick the method
      from the dropdown, hit Encode.
   3. Copy the output textbox contents into the corresponding
      `_stego.txt` file. **Do not add or trim characters** — invisible
      Unicode chars at the boundaries are load-bearing. Save with no
      trailing newline where the encoder didn't add one.
   4. Confirm the browser's Decode roundtrip on the same output before
      committing — this is the "did I accidentally strip the RLO on
      paste" check.

   The regeneration steps live in this plan rather than a README because
   they're a one-time step; if we ever automate fixture generation from
   the JS in headless Chrome, that automation replaces this section
   wholesale.

5. **M5 — Follow-up plan.** Once M1–M4 are stable, write
   `plan-extended-text-encoders.md` covering the last four techniques
   (emoji, capitalization, braille, math alphanumerics). Those diverge from
   the in-place carrier pattern and deserve their own scope call.

## Out of scope

**Encryption composition.** Same policy as the classic plan — callers are
responsible for any encryption + base64-wrap; pass the resulting ASCII
string as `secret`. `confusable` and `hangul` degrade hard on non-ASCII-space
covers (they only carry bits at ASCII space positions), and the classic
policy of "let the caller pre-encode" continues to be the right layering.

**Reconciling `examples/generate_examples.py`.** If the generators drift
from the JS-faithful `text_core` output, that's a real bug in the
generators, but fixing it is a separate cleanup — this plan's job is to
land the encode/decode API, not to unify every legacy path.

**Detector accuracy tuning.** The two new detectors mirror the JS
thresholds; false-positive / false-negative tuning against real-world text
is a separate exercise. The bar here is only "composes with our own
encoder output."
