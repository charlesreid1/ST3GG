# stegg-stego — full tool reference

Every tool takes JSON args and returns a JSON-serialized string. Image/text file inputs are server-local filesystem paths; text tools also accept inline strings.

## Image detect / decode

### `stegg_read_metadata`
Read PNG text chunks (tEXt/iTXt/zTXt), PIL image info. Cheap; high signal.

| arg | type | required | notes |
| --- | --- | --- | --- |
| `path` | string | yes | Filesystem path to the image. |

### `stegg_triage`
Composed multi-probe sweep: carrier ID, structural probes (chunks, appended data, embedded PNGs, tool signatures), statistical LSB probes (chi-square, RS, sample-pairs), bit-plane smoothness. Returns ranked findings + verdict `SUSPICIOUS` / `INCONCLUSIVE` / `CLEAN`.

Verdict rules:
- `SUSPICIOUS` — HIGH structural finding, OR two statistical probes corroborate on the same channel.
- `INCONCLUSIVE` — MEDIUM structural, OR any single statistical probe hit.
- `CLEAN` — nothing above threshold.

| arg | type | required |
| --- | --- | --- |
| `path` | string | yes |

### `stegg_lsb_smart_scan`
Tries the ST3GG v3 header first; if not found, brute-forces channel/bit/strategy combos and returns the best-scoring extractable payload.

| arg | type | required | default |
| --- | --- | --- | --- |
| `path` | string | yes | |
| `max_bytes` | int | no | 4096 |

### `stegg_detect_trailing`
Bytes appended past PNG IEND / JPEG EOI.

| arg | type | required |
| --- | --- | --- |
| `path` | string | yes |

### `stegg_read_png_chunks`
Full PNG chunk dump: every chunk's type, length, and (for text chunks) content.

| arg | type | required |
| --- | --- | --- |
| `path` | string | yes |

### `stegg_decode_manual`
LSB decode with an explicit recipe.

| arg | type | required | notes |
| --- | --- | --- | --- |
| `path` | string | yes | |
| `channels` | string | yes | R, G, B, A, RG, RB, GB, RGB, RGBA. |
| `bits_per_channel` | int | yes | 1-8. |
| `strategy` | string | no | sequential, interleaved (default), spread, randomized. |

### `stegg_carve`
Try container decoders (ZIP/GZip/TAR/PDF/SQLite/SVG/PCAP/JPEG/audio-LSB) on a file or byte range. Results ranked by hit-strength.

| arg | type | required | notes |
| --- | --- | --- | --- |
| `path` | string | yes | |
| `offset` | int | no | Default 0. |
| `length` | int | no | Default: to end of file. |
| `decoders` | list[string] | no | Subset of: zip, gzip, tar, pdf, sqlite, svg, pcap, jpeg, audio_lsb. |

## Text / emoji detect / decode

### `stegg_text_steg`
Full text-steg detector suite over file bytes.

| arg | type | required |
| --- | --- | --- |
| `path` | string | yes |

Detectors run: `detect_unicode_steg`, `detect_whitespace_steg`, `detect_homoglyph_steg`, `detect_variation_selector_steg`, `detect_combining_mark_steg`, `detect_confusable_whitespace`, `detect_directional_override_steg`, `detect_hangul_filler_steg`, `detect_capitalization_steg`, `detect_emoji_steg`, `detect_math_bold_steg`, `detect_braille_steg`, `detect_emoji_substitution_steg`, `detect_skintone_steg`, plus decoders for directional/hangul/math/braille/emoji-skin-tone.

### `stegg_text_steg_message`
Same detector suite on an inline string. Use when the user pastes suspicious text.

| arg | type | required |
| --- | --- | --- |
| `text` | string | yes |

### `stegg_text_decode`
Recover a hidden secret via a named method.

| arg | type | required | notes |
| --- | --- | --- | --- |
| `method` | string | yes | See method list below. |
| `stego_text` | string | no* | Inline stego. |
| `stego_path` | string | no* | UTF-8 file. |

*Exactly one of `stego_text` / `stego_path` required.

### `stegg_text_capacity`
Pre-flight: how many payload bytes fit under a method.

| arg | type | required | notes |
| --- | --- | --- | --- |
| `method` | string | yes | See method list below. |
| `cover_text` | string | no* | Inline cover. |
| `cover_path` | string | no* | UTF-8 file. |

## Encode / hide

### `stegg_encode_manual`
Image LSB encode with an explicit recipe. Writes PNG to `output_path` (or a `stegg_`-prefixed sibling of the input if omitted).

| arg | type | required | notes |
| --- | --- | --- | --- |
| `path` | string | yes | Carrier image. |
| `message` | string | yes | UTF-8 payload. |
| `channels` | string | yes | R, G, B, A, RG, RB, GB, RGB, RGBA. |
| `bits_per_channel` | int | yes | 1-8. |
| `strategy` | string | no | sequential, interleaved (default), spread, randomized. |
| `seed` | int | no | PRNG seed for `randomized`. |
| `compress` | bool | no | Compress before embedding (default `true`). |
| `output_path` | string | no | Default: `stegg_<input_stem>.png` next to input. |

### `stegg_encode_metadata`
Hide in a PNG text chunk (tEXt/iTXt/zTXt) or private chunk.

| arg | type | required | notes |
| --- | --- | --- | --- |
| `path` | string | yes | Carrier PNG. |
| `chunk_type` | string | yes | `tEXt`, `iTXt`, `zTXt`, or `private`. |
| `value` | string | yes | Payload. |
| `keyword` | string | conditional | Required for tEXt/iTXt/zTXt. |
| `private_chunk_name` | string | conditional | 4-char name; required when `chunk_type='private'`. |
| `output_path` | string | no | Default: `stegg_<input_stem>.png`. |

### `stegg_text_encode`
Hide a secret in text via one of the methods below.

| arg | type | required | notes |
| --- | --- | --- | --- |
| `method` | string | yes | See method list below. |
| `secret` | string | yes | UTF-8 payload. |
| `cover_text` | string | no* | Inline cover. |
| `cover_path` | string | no* | UTF-8 file. |
| `output_path` | string | no | If omitted, returns stego inline. |

## Meta

### `stegg_list_techniques`
Catalog of what the server covers, grouped by carrier family and detect/encode role. No args.

## Method list (text tools)

`zero_width`, `homoglyph`, `whitespace`, `invisible_ink`, `variation`, `combining`, `confusable`, `directional`, `hangul`, `mathbold`, `braille`, `emoji`, `skintone`, `capitalization`.

Notes:
- All methods except `capitalization` are round-trip-compatible with the browser Text Lab in `index.html`.
- `braille`, `emoji`, `skintone` append the payload as its own block after the cover (separated by `\n\n`) — visibly perturbed, not invisible.
- Length-prefixed methods (`homoglyph`, `whitespace`, `variation`, `combining`, `confusable`, `hangul`, `mathbold`, `capitalization`) raise `TextStegCapacityError` on undersized covers — use `stegg_text_capacity` first when the cover might be too small.

## Resource

### `stegg://field-guide`
The ST3GG persona document: technique catalog, signal-reading heuristics, extraction workflow, verdict semantics, code snippets, transport-survival tables. Fetch via `read_resource(stegg://field-guide)`.

## Errors

Tools return a plain string on error (not JSON) prefixed with the tool name and the failure mode: `stegg_<tool>: <message>`. Timeouts return `stegg_<tool> timed out after 30s`. Missing files, size caps, and bad enum values return descriptive strings — check for a leading `stegg_` prefix or a substring like `error`, `not found`, `timed out`, or `too large` before parsing as JSON.
