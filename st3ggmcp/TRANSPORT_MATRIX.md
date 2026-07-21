# Steg Transport Survival Matrix

Which steganography techniques survive which consumer messaging / file-transport channels? Real transports strip metadata, re-encode images, canonicalize Unicode, and mangle files in undocumented ways. This matrix records what does and doesn't survive, so that:

- CTF authors picking a distribution channel know what won't survive it.
- Steg tool builders know which techniques are actually usable through a given transport.
- Users trying to smuggle a payload through a channel can pick a technique that arrives intact.
- Defensive teams know what an adversary can still push through sanctioned tools.

## The one principle behind every row

Every transport has a **canonical form** it treats as "the real message." Anything you hid *at or above* the canonical form survives; anything you hid *below* it gets normalized, stripped, or re-encoded out of existence. The rows below are just instances of this one principle:

- **Slack / Discord / iMessage bodies** canonicalize to the *rendered post*. On the way in, they colon-canonicalize emoji, strip image metadata, and re-serve image bytes from their own CDN. → Kills anything living in metadata, emoji-attached data (tag chars, VS on emoji), and often trailing bytes.
- **Terminal stdout + manual mouse-copy** canonicalizes to the *visible glyph stream*. → Kills zero-width, VS, combining marks. `pbcopy` / `xclip` / `clip.exe` bypass the canonicalization by preserving the byte stream directly.
- **JPEG re-encode / WhatsApp photo / Instagram** canonicalize to a *perceptual approximation*. → Kills LSB, high-nibble embed, direct pixel overwrite. May preserve DCT-robust hides and spread-spectrum watermarks.
- **Email SMTP / raw HTTP / GitHub upload / Telegram-as-file** canonicalize to *the file bytes*. → Everything survives; this is the happy path.
- **Aggressive Unicode normalizers** (some search boxes, some DBs, some sanitizers) canonicalize to *NFC/NFKC*. → Kills cyrillic_homoglyph (Cyrillic `а` normalizes to Latin `a`) and cjk_homoglyph (fullwidth `，` normalizes to ASCII `,`), some VS, combining marks.

Read every cell as: "does this transport's canonical form sit above or below the layer this technique hides in?"

## Legend

| Symbol | Meaning |
|--------|---------|
| **✅ SURVIVES** | Confirmed to arrive byte-identical or technique-intact. |
| **❌ STRIPPED** | Confirmed to be removed / destroyed at some point in the transport pipeline. |
| **⚠ RECODED** | File bytes are re-encoded; technique may or may not survive depending on specifics. |
| **❓ UNKNOWN** | Not yet tested. Contributions welcome. |
| **➖ N/A** | Combination is nonsensical (e.g. audio steg on a text-only channel). |

Every confirmed cell should link to or reference the specific test that confirmed it. Every UNKNOWN cell is a testing opportunity.

## Carriers (rows)

- **PNG LSB** — hiding in the least significant bits of PNG pixel data.
- **PNG tEXt/iTXt/zTXt** — payload in PNG ancillary text chunks.
- **PNG private chunks** — payload in caller-defined 4-char private PNG chunks.
- **PNG trailing bytes (after IEND)** — appended data past the PNG end marker.
- **JPEG LSB / DCT (F5, jsteg, outguess)** — payload in JPEG quantized DCT coefficients.
- **JPEG EXIF/XMP/IPTC** — payload in JPEG metadata blocks.
- **JPEG trailing bytes (after EOI)** — appended data past the JPEG end marker.
- **Unicode zero-width / homoglyph** — payload as zero-width chars, Latin↔Cyrillic letter swaps (cyrillic_homoglyph), or ASCII↔CJK-fullwidth punctuation swaps (cjk_homoglyph) in text.
- **Emoji tag sequences (U+E0020–E007F)** — payload as tag characters appended to a base emoji (the "black flag with tags" trick).
- **Emoji variation selectors** — payload as VS characters (U+FE00–FE0F, U+E0100–E01EF) on emoji or letters.
- **Whitespace steg (SNOW)** — payload as trailing spaces / tab-vs-space patterns in text.
- **File-container polyglot (PNG-in-ZIP, etc.)** — payload as a valid second-format prefix/suffix.
- **Audio LSB (PCM WAV/AIFF)** — payload in low bits of PCM samples.
- **Audio spectrogram** — payload as an image encoded into the audio's frequency domain.

## Transport channels (columns)

- **Slack** — file upload via Slack UI, Slack API `files.upload` / `files.completeUploadExternal`, or bot download via `url_private*`.
- **Discord** — attachment upload via Discord client or bot.
- **Telegram** — attachment upload; note that Telegram distinguishes "photo" (recoded) vs "file" (raw).
- **WhatsApp** — attachment upload via the mobile client or WhatsApp Web.
- **Signal** — attachment upload via the Signal client.
- **iMessage** — attachment upload via Messages.app.
- **Email attachment** — SMTP attachment (base64 wrapped in MIME).
- **Gmail (inline)** — image embedded in Gmail message body.
- **GitHub upload** — file uploaded via GitHub web UI to a repo.
- **HTTP raw (curl)** — direct file transfer over HTTP, no intermediate service.

## Matrix

Confirmed cells first, unknown cells left for later.

| Carrier                          | Slack             | Discord | Telegram (photo) | Telegram (file) | WhatsApp | Signal | iMessage | Email attach | Gmail inline | GitHub upload | HTTP raw |
|----------------------------------|-------------------|---------|------------------|-----------------|----------|--------|----------|--------------|--------------|---------------|----------|
| PNG LSB                          | ✅ [1]            | ❓      | ⚠ likely recoded | ❓              | ❓       | ❓     | ❓       | ✅ likely    | ❓           | ✅ likely     | ✅       |
| PNG tEXt/iTXt/zTXt               | ❌ [2]            | ❓      | ❓               | ❓              | ❓       | ❓     | ❓       | ✅ likely    | ❓           | ❓            | ✅       |
| PNG private chunks               | ❓ likely stripped | ❓      | ❓               | ❓              | ❓       | ❓     | ❓       | ❓           | ❓           | ❓            | ✅       |
| PNG trailing bytes (after IEND)  | ❓                | ❓      | ❓               | ❓              | ❓       | ❓     | ❓       | ❓           | ❓           | ❓            | ✅       |
| JPEG LSB / DCT                   | ❓                | ❓      | ⚠ likely recoded | ❓              | ❌ likely | ❓     | ❓       | ❓           | ❓           | ✅ likely     | ✅       |
| JPEG EXIF/XMP/IPTC               | ❌ [3]            | ❓      | ❓               | ❓              | ❌ [4]   | ❓     | ❓       | ✅ likely    | ❓           | ✅ likely     | ✅       |
| JPEG trailing bytes (after EOI)  | ❓                | ❓      | ❓               | ❓              | ❓       | ❓     | ❓       | ❓           | ❓           | ❓            | ✅       |
| Unicode zero-width / homoglyph   | ❓ likely survives | ❓      | ➖ text only     | ❓              | ❓       | ❓     | ❓       | ✅           | ✅           | ✅            | ✅       |
| Emoji tag sequences              | ❌ [5]            | ❓      | ❓               | ❓              | ❓       | ❓     | ❓       | ⚠ client-dep | ⚠ client-dep | ✅            | ✅       |
| Emoji variation selectors        | ❓ likely survives | ❓      | ❓               | ❓              | ❓       | ❓     | ❓       | ✅           | ✅           | ✅            | ✅       |
| Whitespace steg (SNOW)           | ❓                | ❓      | ➖ text only     | ❓              | ❓       | ❓     | ❓       | ✅           | ⚠ maybe     | ✅            | ✅       |
| Polyglot (PNG-in-ZIP, etc.)      | ❓                | ❓      | ❓               | ❓              | ❓       | ❓     | ❓       | ❓           | ❓           | ❓            | ✅       |
| Audio LSB (PCM WAV/AIFF)         | ❓                | ❓      | ❓               | ❓              | ❓       | ❓     | ❓       | ✅ likely    | ➖ inline    | ✅ likely     | ✅       |
| Audio spectrogram                | ❓                | ❓      | ❓               | ❓              | ❓       | ❓     | ❓       | ✅ likely    | ➖ inline    | ✅ likely     | ✅       |

### Slack column: confirmed evidence

**[1] PNG LSB — SURVIVES.** A 150×150 PNG uploaded to Slack came back with its IDAT chunk byte-identical to the source (both 614 bytes). All LSB-based analysis (`stegg_lsb_smart_scan`, `stegg_decode_manual`, chi-square, RS, sample-pairs) works the same on the Slack-served copy as on the original.

**[2] PNG tEXt/iTXt/zTXt chunks — STRIPPED.** Same test file: 884-byte original with 4 text chunks (`Comment`, `Secret`, `Author`, `Flag: CTF{hidden_in_plain_sight}`) came back as 671 bytes with only `IHDR`, `IDAT`, `IEND`. All four text chunks removed. Both `url_private` and `url_private_download` endpoints serve the same stripped bytes. See slackapi/node-slack-sdk#1032 for confirmation this is intended Slack behavior.

**[3] JPEG EXIF — STRIPPED.** Slack announced in May 2020 that it strips EXIF metadata (including GPS coordinates) from uploaded images. Not independently retested for XMP/IPTC/ICC but the announcement scope was "EXIF metadata," suggesting these adjacent metadata containers are also removed.

**[4] WhatsApp JPEG EXIF — STRIPPED.** WhatsApp is well documented as recoding and stripping metadata from photos (not files). Not independently tested here.

**[5] Emoji tag sequences — STRIPPED (canonicalized).** Slack round-trips emoji through their `:colon_syntax:` form. On the wire, an emoji is `:red_circle:`, not the Unicode codepoint. When the receiving client re-renders, it emits a fresh Unicode emoji with no trailing data. Any payload packed onto an emoji as trailing tag characters (U+E0020–E007F) — the "black flag with tags" trick — is stripped, because it never lived in the canonical form Slack preserves. Emoji variation selectors (U+FE00–FE0F, U+E0100–E01EF) attached to emoji ride the same doomed path. Emoji-adjacent metadata steg is DOA on Slack. Text-body zero-width chars may fare better because they don't ride on an emoji — test first. Reported by users testing round-trip fidelity; consistent with Slack's documented "we canonicalize what we render" pipeline.

### Terminal stdout: canonical form is the visible glyph

Terminal windows render bytes to glyphs; the user's mouse selection copies the glyphs, not the bytes. Zero-width chars, VS, and combining marks may not survive that path — the terminal filters them from the copy buffer. Clipboard utilities (`pbcopy` on macOS, `xclip -sel clip` / `xsel --clipboard --input` on Linux, `clip.exe` on Windows) copy the byte stream directly and preserve everything. If a hide is dying between "prints in my terminal" and "pastes into my chat", suspect the terminal's glyph canonicalization and pipe through `pbcopy` instead. Same principle as Slack, different canonical layer.

## Test methodology (for adding rows/cells)

To add a confirmed cell, you need three things:

1. **A minimal test file** with a known payload embedded via the carrier technique.
2. **A byte-level diff or extraction check** on the transport-delivered copy.
3. **Evidence** (log lines, hex dumps, file sizes) attached to the matrix row footnote.

Standard test files ship in `st3ggmcp/tests/transport_probes/` (planned). Each test file has a known-good extractor that reports either "payload recovered" or "carrier mangled beyond recovery."

Rough procedure:

```
1. Take the seed file (e.g. png_lsb_probe.png with LSB payload "TRANSPORT_TEST_v1").
2. Upload through the transport under test.
3. Download the file the transport delivers (from a bot, from Save-As, etc.).
4. Byte-diff against the seed.
5. Run the carrier's extractor on the delivered copy.
6. Cell = ✅ if extractor recovered the payload, ❌ if it didn't, ⚠ if bytes changed but
   the extractor still works, ❓ if the test wasn't run.
```

Cells promoted from ❓ to ✅/❌/⚠ should get a footnote linking to the test evidence.

## Contributing

New rows: propose the carrier + its extractor.
New columns: propose the transport + how to feed test files through it programmatically.
Cell fills: run the seed file through the transport, add the footnote, PR.

The `❓ likely X` cells are guesses based on documented transport behavior, not confirmed measurements. Treat them as testing priorities, not conclusions.
