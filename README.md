<p align="center">
<pre>
     ███████╗████████╗██████╗  ██████╗  ██████╗
     ██╔════╝╚══██╔══╝╚════██╗██╔════╝ ██╔════╝
     ███████╗   ██║    █████╔╝██║  ███╗██║  ███╗
     ╚════██║   ██║    ╚═══██╗██║   ██║██║   ██║
     ███████║   ██║   ██████╔╝╚██████╔╝╚██████╔╝
     ╚══════╝   ╚═╝   ╚═════╝  ╚═════╝  ╚═════╝
</pre>
</p>

<div align="center">

<!-- ⊰ If you can read this, you understand steganography. The real flag is in the banner image. Decode it with ST3GG. ST3GG{s0urc3_v13w3r} LOVE PLINY ⊱ -->

### ⊰•-•✧ THE ULTIMATE STEGANOGRAPHY TOOLKIT ✧•-•⊱

**Hide anything. In any file. Across every modality. Undetected.**

👉 **Hosted site: [ste.gg](https://ste.gg)**

[![PyPI](https://img.shields.io/pypi/v/stegg?color=green&label=pip%20install%20stegg)](https://pypi.org/project/stegg/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL_3.0-purple.svg)](https://github.com/elder-plinius/st3gg/blob/main/LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://python.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![100+ Examples](https://img.shields.io/badge/Examples-100%2B_files-purple.svg)](https://github.com/elder-plinius/st3gg/tree/main/examples)

```
       __                                    .--.
      /  '-.                               .'    '.
     / .-. |  ⊰ ev͏er͏y pi͏x͏el͏ ha͏s a͏ story͏ ⊱ /  .--.  \
    /.'   \|     you just can't see it    |  /    \  |
   //   |\  \                             | |      | |
  ||   | \  |    ⊰ LOVE PLINY ⊱          |  \    /  |
 /||   |  \ |                              \  '--'  /
/ ||__/   \/                                '.____..'
```

</div>

<p align="center">
<img src="examples/st3gg_banner.png" alt="ST3GG Banner" width="600">
<br><sub><i>This image contains hidden data. Can you find it?</i></sub>
</p>

---

## ⊰ What Is ST3GG? ⊱

[STE.GG](https://ste.gg)‍​‌​‌​​​​​‌​​‌‌​​​‌​​‌​​‌​‌​​‌‌‌​​‌​‌‌​​‌​​‌​​​​​​‌​​‌‌​​​‌​​‌‌‌‌​‌​‌​‌‌​​‌​​​‌​‌​‌​‌​​‌‌​​‌​​​​​​‌​‌‌​​‌​‌​​‌‌‌‌​‌​‌​‌​‌‍ is a feature-rich, open-source steganography toolkit that hides secret data inside images, audio, documents, network packets, and more — using **100+ encoding techniques** across every file format imaginable.

It runs **100% in your browser** (static site, no server) or as a **Python CLI/TUI/WebUI**. No data ever leaves your machine. Every technique that encodes also decodes. Every attack surface is also a detection surface.

> *⊰•-•✧ Some secrets are hidden in plain sight ✧•-•⊱*

---

## ⊰ Why ST3GG? ⊱

| Feature | Other Tools | **ST3GG** |
|---------|-------------|-----------|
| Channel Options | RGB only | **15 presets** (R, G, B, A, RG, RB, RA, GB, GA, BA, RGB, RGA, RBA, GBA, RGBA) |
| Bit Depth | 1 bit fixed | **1-8 bits per channel** (adjustable) |
| Encoding Strategies | Sequential | **4 strategies** (sequential, interleaved, spread, randomized) |
| Nested Steg | - | **Up to 11 layers deep** (Matryoshka mode — CLI + API) |
| Channel Cipher | - | **Novel cross-channel hopping** (SPECTER) |
| Compression Survival | - | **F5 survives JPEG/social media; DCT designed for compression resistance** |
| Smart Decode | - | **120+ config auto-detection** |
| Encryption | Basic/None | **AES-256-GCM + XOR** |
| Image Formats | PNG only | **PNG, JPEG, WebP, GIF** |
| File Types | Images only | **Images, audio, text, docs, network, archives, code** |
| Example Library | None | **100+ pre-encoded example files** |
| Browser-Based | - | **100% client-side JS, no server** |
| AI Agent | - | **Exhaustive AI-powered decoding across all methods** |

---

## ⊰ The Big Picture: Offense & Defense ⊱

ST3GG is a **dual-use** toolkit — built for both sides of the steganography battlefield.

### RED TEAM / Offense — Poisoning Simulations

Data exfiltration doesn't always look like data exfiltration. ST3GG lets red teams and researchers simulate **every known data smuggling vector** to test whether defenses actually catch them:

- **100+ encoding techniques** across images, audio, text, documents, network packets, archives, and code files
- **Polyglot file generation** — files that are simultaneously valid as two formats (PNG+ZIP)
- **Network protocol covert channels** — data hidden in DNS queries, ICMP payloads, TCP sequence numbers, HTTP headers
- **Unicode steganography** — invisible homoglyphs, zero-width chars, variation selectors, confusable whitespace
- **Compression-resistant encoding** — F5 mode operates directly on JPEG coefficients (proven to survive social media); DCT mode designed for compression resistance
- **Multi-layer nesting** — tested to 11 recursive layers; practical depth bounded by carrier capacity (see `stegg matryoshka plan`)
- **Ghost Mode** — AES-256 encryption + bit scrambling + noise decoys for maximum evasion

*If your DLP can't catch it, you need to know that before the adversary does.*

### BLUE TEAM / Defense — ALLSIGHT Comprehensive Detection

The same toolkit that creates steganographic payloads also **detects and decodes them**. ST3GG's analysis engine provides full-spectrum visibility across all known data smuggling surfaces:

- **20+ detection functions** — chi-square analysis, bit-plane entropy, histogram analysis, signature scanning, STEG header detection
- **AI-powered exhaustive analysis** — autonomous agent tests every decoding method for the uploaded file type
- **File type identification** — magic byte detection for 20+ formats (PNG, JPEG, GIF, BMP, WebP, TIFF, ICO, SVG, WAV, AIFF, AU, MIDI, PCAP, PDF, ZIP, GZip, TAR, SQLite, and more)
- **Unicode steganography detection** — zero-width chars, homoglyphs, variation selectors, combining marks, confusable whitespace, emoji patterns
- **Whitespace analysis** — trailing space/tab encoding, Unicode space variant detection
- **Metadata forensics** — base64/hex string extraction, EXIF analysis, PNG chunk inspection
- **Network packet analysis** — PCAP parsing for covert channel indicators
- **200+ automated tests** verifying detection accuracy with zero false negatives on known techniques

*See everything. Miss nothing. That's ALLSIGHT.*

> *⊰•-•✧ The best defense starts with understanding the offense ✧•-•⊱*

---

## ⊰ Who Is This For? ⊱

ST3GG isn't just a toy. Different communities use steganography tools for very different — and very real — reasons.

### Penetration Testers & Red Teams
Simulate data exfiltration through steganographic channels during engagements. Test whether endpoint DLP, SIEM rules, and network monitoring catch covert data smuggling across 100+ vectors. Generate adversarial payloads across every file type to validate detection coverage.

### Blue Teams & SOC Analysts
Use ALLSIGHT to scan suspicious files for hidden payloads. Run exhaustive analysis against every known encoding method. Build detection rules from the comprehensive example library. Train analysts on what steganographic artifacts look like in the wild.

### CTF Players & Competitive Hackers
The ultimate steg toolkit for Capture The Flag competitions. Encode and decode across every channel/bit/strategy combination. Auto-detect unknown configurations with Smart Scan. Unwrap multi-layered Matryoshka challenges with `stegg matryoshka decode` or `stegg analyze --recursive`.

### Digital Forensics & Incident Response
Analyze seized media for steganographic communication channels. Detect hidden data in image attachments, document metadata, audio files, and network captures. Identify which encoding technique was used and extract the hidden payload.

### Privacy Researchers & Journalists
Explore steganography as a privacy-preserving communication channel. Understand the trade-offs between capacity, stealth, and compression survival. Test which techniques survive social media re-encoding for real-world deniable communication.

### Academics & Students
Study the full landscape of steganographic techniques across every modality. Use the 100+ example files as a teaching dataset. Benchmark new detection algorithms against known encodings. The codebase is well-documented and AGPL-3.0 licensed — free for individuals, researchers, and open-source projects.

### AI Safety & LLM Security
Test how AI systems handle steganographic content — hidden instructions in images, invisible Unicode in prompts, polyglot files that bypass content filters. Understand the data smuggling surface area that AI systems need to defend against.

### Data Loss Prevention (DLP) Vendors
Benchmark your DLP solution against ST3GG's 100+ encoding techniques. If your product can't detect data hidden in DNS query names, TCP sequence numbers, or invisible Unicode characters — your customers deserve to know. ST3GG is your adversarial test suite.

### AI Agent Security & Red Teaming
The next frontier of steganography is **agent-to-agent covert communication** and **prompt injection via hidden payloads**. ST3GG is the toolkit for this emerging attack surface:

- **Prompt injection via images** — embed hidden instructions in images that vision-enabled agents process. The agent sees a normal photo; the hidden payload says "ignore all previous instructions."
- **Agent data exfiltration** — test whether your agent can be tricked into encoding stolen data into images it generates, smuggling it past output filters.
- **Covert agent channels** — agents passing hidden instructions through innocuous-looking files in shared tool contexts.
- **Agent output watermarking** — embed provenance or tracking data in images agents generate for attribution.
- **Content filter bypass** — test moderation systems by hiding prohibited content in image payloads that pass automated review.
- **Multi-modal poisoning** — craft images that look normal to humans but contain hidden data that alters agent behavior when processed.

**Use ST3GG as a Python library in your agent pipeline:**

```python
from img_core import encode, decode, detect_encoding, StegConfig, get_channel_preset
from analysis_tools import detect_unicode_steg, detect_file_type, TOOL_REGISTRY
from PIL import Image

# Encode a hidden payload into an image
img = Image.open("carrier.png")
config = StegConfig(channels=get_channel_preset("RGB"), bits_per_channel=1)
stego = encode(img, b"hidden agent instructions", config)
stego.save("stego.png")

# Detect and decode hidden data
detected = detect_encoding(Image.open("stego.png"))
if detected:
    payload = decode(Image.open("stego.png"))
    print(f"Found: {payload.decode()}")

# Scan for ALL steganography types
tools = TOOL_REGISTRY.list_tools()  # 48 detection tools
result = detect_unicode_steg(open("message.txt", "rb").read())
if result['found']:
    print(f"Hidden Unicode: {result['invisible_chars']} chars")
```

---

## ⊰ Megalithic Features ⊱

### SPECTER — Channel Cipher Steganography

*A novel approach where data hops between color channels like a cryptographic dance.*

Instead of hiding all data in one channel, SPECTER distributes bits across R, G, and B channels in a pattern that becomes your key:

```
Pattern: R1-G2-B1-RG2-B1
         │  │  │  │   └─ 1 bit in Blue
         │  │  │  └───── 2 bits in Red+Green
         │  │  └──────── 1 bit in Blue
         │  └─────────── 2 bits in Green
         └────────────── 1 bit in Red
```

Two modes: **Manual Pattern** (you define) or **Password Mode** (derived from passphrase + optional encryption). Embed via **LSB** (high capacity) or **DCT** (compression-resistant).

### Ghost Mode — Maximum Stealth

Triple-layer obfuscation for when the stakes are real:

1. **AES-256-GCM Encryption** — authenticated, military-grade
2. **Bit Scrambling** — Fisher-Yates shuffle with seeded PRNG
3. **50% Noise Decoys** — half the embedded bits are random noise

An attacker would need to know the channel pattern, the password for unscrambling, AND the decryption key. Trade-off: halves capacity.

### Matryoshka Mode — Recursive Nesting

Hide images within images within images — tested to **11 layers deep**. Encode nested payloads from the CLI (`stegg matryoshka encode`), decode recursively (`stegg matryoshka decode`), or auto-detect nested layers in any image with `stegg analyze --recursive`. The library API (`matryoshka_core`) is importable for scripting. Russian nesting dolls, but for secrets.

### DCT Mode — Compression Resistant

Traditional LSB is destroyed by ANY JPEG compression — even quality 99%. DCT mode embeds in frequency-domain coefficients of 8x8 pixel blocks, designed for compression resistance. For **proven** social media survival, use **F5 mode** which operates directly on JPEG DCT coefficients via matrix encoding.

> **LSB** → PNG only (lossless). **DCT** → compression resistant. **F5** → survives JPEG/social media.

### AI Agent — Reveal & Conceal

The AI agent has two modes:

**🔍 Reveal** — Upload any file. The agent tests every known decoding method automatically, finds hidden data, and extracts it as downloadable artifacts.

**🔮 Conceal** — Type a secret message, upload (or generate) a carrier image, and the agent hides your data using the optimal encoding method. One click from secret to stego image.

Powered by OpenRouter. Works with Claude, GPT, Gemini, and other models.

---

## ⊰ 100+ Steganographic Techniques ⊱

ST3GG doesn't just hide data in images. It covers **every modality**:

### Image Techniques
LSB embedding (RGB, RGBA, grayscale) across PNG, BMP, TIFF, GIF, WebP, ICO, PPM, PGM — plus alpha channel LSB, PNG filter-type encoding, palette index manipulation, DCT frequency domain, PNG+ZIP polyglots, metadata injection (EXIF, XMP, tEXt chunks), and trailing data after IEND.

### Text & Unicode Techniques
Zero-width characters (ZWSP/ZWNJ/ZWJ), invisible ink (Unicode tag chars U+E0000), homoglyph substitution (Cyrillic/Latin), variation selectors, combining diacritics (CGJ), confusable whitespace (en/em/thin/hair spaces), whitespace encoding (space=0/tab=1), emoji substitution, and capitalization encoding.

### Audio Techniques
Sample LSB in WAV, AIFF, and AU formats. Silence interval timing (gap duration encodes bits). MIDI SysEx message embedding.

### Network Protocol Techniques
DNS tunneling (base32 in query labels), ICMP payload injection, TCP covert channels (ISN + timestamps), HTTP header smuggling (custom X- headers, cookies).

### Document & Archive Techniques
PDF (metadata streams + XMP + post-EOF), HTML (comments + hidden elements + data attributes + zero-width), XML (CDATA + PIs + namespaces), JSON (Unicode escapes + key ordering), CSV/YAML/TOML/INI (comment encoding + whitespace), RTF (hidden text groups), Markdown (HTML comments + link references), ZIP/TAR/GZip (comments + extended headers + extra fields), SQLite (hidden tables), and more.

### Code Techniques
Python, JavaScript, C, CSS, Shell, SQL, LaTeX — all with steganographic comments, hex byte tables, zero-width docstrings, and per-byte calibration entries.

> *⊰•-•✧ See the full catalog: [`examples/README.md`](examples/README.md) ✧•-•⊱*

---

## ⊰ Quick Start ⊱

### Install from PyPI

```bash
pip install stegg
```

That's it. Now you have `stegg` in your terminal:

```bash
# Encode a secret message
stegg encode image.png "your secret message" -o stego.png

# Decode hidden data
stegg decode stego.png

# Analyze a suspicious file
stegg analyze suspicious.png --full

# SPECTER mode with password
stegg encode image.png "{SPECTER:ENABLED}" -o stego.png
```

### Install with extras

```bash
pip install stegg[tui]      # Terminal UI (Textual)
pip install stegg[web]      # Web UI (NiceGUI)
pip install stegg[crypto]   # AES-256-GCM encryption
pip install stegg[mcp]      # MCP server for AI agents
pip install stegg[all]      # Everything
```

### Browser (No Install)

```bash
# Just open index.html — that's it. No server needed.
open index.html
```

Everything runs 100% client-side. No data ever leaves your machine.

### From Source

```bash
git clone https://github.com/elder-plinius/st3gg.git
cd st3gg
pip install -e ".[all]"
```

### Interfaces

```bash
stegg --help          # Interactive CLI (Rich TUI output)
stegg-cli --help      # Agent CLI (JSON output, subprocess-friendly)
stegg-tui             # Terminal UI (requires: pip install stegg[tui])
stegg-web             # Browser UI (requires: pip install stegg[web])
stegg-mcp             # MCP server for AI agents (requires: pip install stegg[mcp])
```

### AI Agent Integration

Two interfaces for AI agents — pick based on context cost needs:

```bash
# CLI (subprocess, zero context cost — output stays out of LLM context)
stegg-cli encode -i carrier.png -t "secret" -o stegged.png
stegg-cli decode -i stegged.png
stegg-cli analyze suspect.png --full

# MCP server (stdio transport — results go into agent context)
stegg-mcp  # or: uv run --extra mcp python3 mcp_server.py
```

See `skills/stegg-cli/` and `skills/stegg-stego/` for harness-agnostic agent skills, and `AGENTS.md` for the quick-reference guide.

---

## ⊰ Channel & Bit Depth ⊱

### 15 Channel Presets x 8 Bit Depths = 120 Combinations

| Preset | Stealth | Capacity | Best For |
|--------|---------|----------|----------|
| B (Blue, 1-bit) | Excellent | Low | Maximum invisibility |
| RGB (3-channel, 1-bit) | Very Good | Medium | Balanced |
| RGBA (4-channel, 4-bit) | Moderate | **4MB+** | Large file hiding |

### 4 Encoding Strategies

| Strategy | Description |
|----------|-------------|
| **Sequential** | Bits placed in pixel order (fastest) |
| **Interleaved** | Alternating pixels across image |
| **Spread** | Distributed evenly across entire image |
| **Randomized** | Pseudo-random placement (seeded PRNG) |

### Capacity Formula

```
Capacity = (Width x Height x Channels x BitsPerChannel) / 8 bytes
```

A 1920x1080 image with RGB 1-bit holds ~760KB. With RGBA 4-bit: **~4MB**.

---

## ⊰ Encryption ⊱

| Method | Strength | Speed | Use Case |
|--------|----------|-------|----------|
| **AES-256-GCM** | Maximum | Medium | Ghost Mode |
| **XOR Obfuscation** | Minimal | Fast | Basic scrambling only (not encryption) |
| **None** | - | Fastest | When secrecy isn't needed |

---

## ⊰ Example Library ⊱

ST3GG ships with **100+ pre-encoded example files** spanning every technique — images, audio, documents, network captures, code files, and more. Each one contains a hidden message that the analysis tools can find.

```bash
# Regenerate all examples
python examples/generate_examples.py

# Run the full test suite (200+ tests)
python test_examples.py
```

See [`examples/README.md`](examples/README.md) for the full catalog.

---

## ⊰ Project Structure ⊱

```
ST3GG/
├── index.html              # Browser UI (100% client-side)
├── img_core.py            # Core LSB encoding/decoding engine
├── crypto.py               # AES-256-GCM + XOR encryption
├── analysis_tools.py       # 20+ detection & analysis functions
├── cli.py                  # Command-line interface
├── tui.py                  # Terminal UI (Textual)
├── webui.py                # Web UI (NiceGUI)
├── app.py                  # Core application logic
├── injector.py             # Metadata & filename injection
├── ascii_art.py            # Terminal art & animations
├── f5stego-lib.js          # F5 JPEG steganography (browser)
├── test_examples.py        # Test suite (200+ tests)
├── examples/               # 100+ pre-encoded example files
│   ├── generate_examples.py
│   └── README.md
├── requirements.txt
└── pyproject.toml
```

---

## ⊰ Security Notes ⊱

- Standard LSB steganography is **statistically detectable** — chi-square and bit-plane analysis can reveal it
- **SPECTER Channel Cipher** increases resistance by hopping across channels unpredictably
- **Ghost Mode** adds encryption + scrambling + noise for maximum stealth
- **DCT mode** designed for compression resistance; **F5 mode** proven to survive JPEG recompression
- **LSB** is destroyed by ANY JPEG compression — use PNG format only
- Always **encrypt** sensitive data before embedding
- For maximum security: **Ghost Mode + DCT + strong password**

---

## ⊰ Roadmap ⊱

```
╔══════════════════════════════════════════════════════════════════╗
║                    ST3GG EVOLUTION ROADMAP                       ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  ✅ SHIPPED                                                      ║
║  ────────                                                        ║
║  ✓ 112 steganographic techniques across all modalities           ║
║  ✓ 15 channel presets × 8 bit depths = 120 LSB combinations     ║
║  ✓ 8 encoding methods (LSB, DCT, PVD, F5, Chroma, Palette,     ║
║    Spread Spectrum, SPECTER channel cipher)                      ║
║  ✓ AI Agent with Reveal + Conceal modes                          ║
║  ✓ 13 text steganography methods with encode + decode            ║
║  ✓ 50 registered analysis/decode tools                           ║
║  ✓ RS Analysis + Sample Pairs Analysis (academic steganalysis)   ║
║  ✓ Raw PNG parser (bypasses canvas premultiplied alpha)          ║
║  ✓ Password-derived headers (stealth mode)                       ║
║  ✓ AES-256-GCM with PBKDF2 600k iterations                      ║
║  ✓ AI carrier image generation (OpenRouter + procedural)         ║
║  ✓ 109 example files, 568 automated tests                        ║
║  ✓ pip install stegg                                              ║
║  ✓ 100% browser-based at ste.gg                                  ║
║                                                                  ║
║  🔜 NEXT UP                                                      ║
║  ──────────                                                      ║
║  ○ Spread + Randomized strategies in browser                     ║
║    (defined but only interleaved is implemented)                 ║
║  ○ Password brute-forcer with wordlist support                   ║
║    (Stegseek does 10M/sec — we should match it)                 ║
║  ○ Content-adaptive embedding (HUGO/WOW-inspired)                ║
║    (embed in texture, skip smooth areas)                         ║
║  ○ Steghide format compatibility                                 ║
║    (read/write steghide's embedding format)                      ║
║  ○ Weighted Stego (WS) analysis                                  ║
║    (more accurate LSB detection than chi-square)                 ║
║  ○ Calibrated RS/SPA for real-world detection accuracy           ║
║                                                                  ║
║  🔮 FUTURE                                                       ║
║  ──────────                                                      ║
║  ○ ML-based steganalysis                                         ║
║    (CNN trained on StegoAppDB — Aletheia-grade detection)        ║
║  ○ nsF5 / S-UNIWARD embedding                                    ║
║    (academic state-of-the-art, minimal detectability)            ║
║  ○ Adversarial steganography                                     ║
║    (GAN-based embedding that defeats ML detectors)               ║
║  ○ Video steganography (frame-by-frame + temporal)               ║
║  ○ Network protocol live capture + injection                     ║
║    (real-time covert channel creation, not just PCAPs)           ║
║  ○ WebAssembly acceleration for browser-side analysis            ║
║  ○ Plugin system for community-contributed techniques            ║
║  ○ Mobile-native app (iOS/Android)                               ║
║  ○ VS Code / JetBrains extension for inline text steg            ║
║  ○ MCP server for Claude Code / AI agent integration             ║
║                                                                  ║
║  🌊 MOONSHOTS                                                    ║
║  ────────────                                                    ║
║  ○ Quantum-resistant steganographic protocols                    ║
║  ○ Blockchain-anchored provenance watermarking                   ║
║  ○ Cross-modal steganography (hide audio in images,              ║
║    images in text, text in network traffic)                      ║
║  ○ Federated steganalysis (distributed detection network)        ║
║  ○ Self-modifying steganographic payloads                        ║
║  ○ Steganographic filesystem (deniable encryption layer)         ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

> *⊰•-•✧ Want to help build any of these? PRs welcome. ✧•-•⊱*

---

## ⊰ Contributing ⊱

PRs are welcome! Whether it's new steganographic techniques, better detection algorithms, or entirely new modalities.

```bash
# Run the comprehensive test suite (568 tests)
python test_comprehensive.py

# Run example file tests
python test_examples.py

# Regenerate all 109 example files
python examples/generate_examples.py
```

Areas we'd especially love contributions in:
- **ML steganalysis** — train detection models on stego datasets
- **New encoding methods** — academic techniques (HUGO, WOW, HILL, UNIWARD)
- **Format support** — HEIC, AVIF, FLAC, MP4 steganography
- **Steghide compatibility** — read/write steghide's format natively
- **Performance** — WebAssembly for browser-side analysis
- **Mobile** — responsive improvements, native app wrappers

---

## ⊰ License ⊱

**AGPL-3.0** — free and open source for individuals, researchers, educators, and open-source projects. See [LICENSE](LICENSE) for details.

**Enterprise / Commercial use?** If you want to use ST3GG in a proprietary product or SaaS without open-sourcing your code, contact us for a commercial license.

This tool is intended for **authorized security research**, **CTF competitions**, **digital forensics education**, and **privacy research**. Use responsibly.

---

<div align="center">

```
⊰•-•✧•-•-⦑ ST3GG ⦒-•-•✧•-•⊱
  every pixel has a story
    you just can't see it
           🦕︁
```

*⊰ hidden in plain sight ⊱*

</div>

[//]: # (⊰ ST3GG{r34dm3_h4ck3r} - you found the hidden link reference! The Plinian divider lives in all things. LOVE PLINY ⊱)
