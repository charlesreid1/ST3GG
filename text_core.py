"""Text steganography encode/decode core (ST3GG-faithful).

Ports the classic + advanced + extended Unicode text-in-text techniques
from `index.html` so that Python callers can encode and decode the same
stego texts the browser produces.

Classic techniques:
  - zero_width:    ZWJ start + ZWSP(0)/ZWNJ(1) payload bits + ZWJ end,
                   spliced after the first cover char.
  - homoglyph:     Latin -> Cyrillic twin substitution. 16-bit length
                   prefix followed by payload bits, ridden on the
                   available Latin carrier positions in cover order.
  - whitespace:    8 trailing bits per line, ' ' = 0 / '\\t' = 1. 16-bit
                   length prefix + payload bits.
  - invisible_ink: U+E0000 start tag, ASCII -> tag-char body (code+base),
                   U+E007F end tag. Spliced after the first cover char.

Advanced Unicode techniques:
  - variation:     16-bit length prefix + payload bits; VS-1 (U+FE01)
                   present after `[a-zA-Z0-9]` carrier = 1, absent = 0.
  - combining:     16-bit length prefix + payload bits; CGJ (U+034F)
                   present after `[a-zA-Z]` carrier = 1, absent = 0.
  - confusable:    16-bit length prefix + payload bits; each ASCII space
                   encodes 2 bits via space variant
                   (' '=00, EN=01, EM=10, THIN=11).
  - directional:   16-bit length prefix + payload bits; each bit encoded
                   as (RLO=1 / LRO=0)+PDF pair, run spliced after
                   cover[0].
  - hangul:        16-bit length prefix + payload bits; each ASCII space
                   -> HANGUL FILLER (U+3164)=1 or space=0.

Extended Unicode techniques:
  - mathbold:      16-bit length prefix + payload bits; ASCII letter ->
                   math-bold codepoint (U+1D400..U+1D433) = 1, plain
                   letter = 0. Carrier positions are ASCII letters in
                   cover order.
  - braille:       No length prefix. Each byte of `secret.encode('utf-8')`
                   -> `chr(0x2800 + byte)`. Payload appended after cover
                   with `"\\n\\n"` separator.
  - emoji:         16-bit length prefix + payload bits; bit 1 -> 🔴,
                   bit 0 -> 🔵. Payload appended after cover with
                   `"\\n\\n"` separator.
  - skintone:      No length prefix. Each byte -> 4 skin-tone digits
                   (2 bits each). Each digit is `👍 + tone modifier`,
                   digits joined with `" "`. Payload appended after cover
                   with `"\\n\\n"` separator.
  - capitalization:16-bit length prefix + payload bits; word-initial
                   ASCII letter uppercase = 1, lowercase = 0. Order is
                   `cover.split(" ")` (Python-only; no JS reference).

Divergence-from-JS notes: the JS in index.html is the intended reference
implementation, but several of its decoders are buggy as written. We treat
JS as an aspiration rather than gospel — Python emits byte-for-byte
compatible STEGO output (so the browser's encoder and any correct decoder
round-trip against Python), but Python's decoders fix the JS bugs on the
read side:

1. Most JS decoders reconstruct payload bytes via
   `String.fromCharCode(parseInt(bits, 2))`, which is Latin-1 per byte —
   the encode side wrote UTF-8. So multi-byte secrets come back as mojibake
   in the browser. Python decodes as UTF-8 (`errors='replace'`). This
   affects: variation, combining, confusable, directional, hangul,
   mathbold, emoji. The braille and skintone JS decoders use
   `new TextDecoder().decode(new Uint8Array(...))` so those are
   UTF-8-correct on the JS side too.

2. The `combining` JS decoder walks chars emitting '0' on every letter and
   '1' on every CGJ, without accounting for the fact that a 1-bit carrier
   produces `<letter><CGJ>` (two chars) while a 0-bit produces `<letter>`
   alone. The result is not a bijection; browser round-trip fails on any
   payload that contains a 1-bit. Python's `decode_combining` uses the
   look-ahead pattern from `decode_variation` instead — see the comment on
   that function for the exact scheme. Fixing the JS side is out of scope
   for this port.

3. `capitalization` has no JS reference — it's Python-only, standardized
   here per the shape in `examples/generate_examples.py`.
"""

from __future__ import annotations

from typing import Dict, Tuple

# --- constants ---------------------------------------------------------------

ZWSP = '​'  # zero-width space         -> bit 0
ZWNJ = '‌'  # zero-width non-joiner    -> bit 1
ZWJ  = '‍'  # zero-width joiner        -> delimiter

TAG_BASE = 0xE0000
TAG_END  = TAG_BASE + 0x7F

# Latin -> Cyrillic homoglyphs, matching index.html:7837
HOMOGLYPH_MAP: Dict[str, str] = {
    'a': 'а', 'c': 'с', 'e': 'е', 'o': 'о',
    'p': 'р', 'x': 'х', 'y': 'у',
    'A': 'А', 'B': 'В', 'C': 'С', 'E': 'Е',
    'H': 'Н', 'K': 'К', 'M': 'М', 'O': 'О',
    'P': 'Р', 'T': 'Т', 'X': 'Х',
}
HOMOGLYPH_REVERSE: Dict[str, str] = {v: k for k, v in HOMOGLYPH_MAP.items()}

# Advanced Unicode constants (ported from index.html:8076-8152).
VS1           = '︁'  # VARIATION SELECTOR-1
CGJ           = '͏'  # COMBINING GRAPHEME JOINER
EN_SPACE      = ' '
EM_SPACE      = ' '
THIN_SPACE    = ' '
RLO           = '‮'  # RIGHT-TO-LEFT OVERRIDE
LRO           = '‭'  # LEFT-TO-RIGHT OVERRIDE
PDF           = '‬'  # POP DIRECTIONAL FORMATTING
HANGUL_FILLER = 'ㅤ'

CONFUSABLE_SPACE_TABLE: Dict[str, str] = {
    '00': ' ',      '01': EN_SPACE,
    '10': EM_SPACE, '11': THIN_SPACE,
}
CONFUSABLE_REVERSE: Dict[str, str] = {v: k for k, v in CONFUSABLE_SPACE_TABLE.items()}

# Extended technique constants (ported from index.html:8154-8203).
MATH_BOLD_A_UPPER = 0x1D400   # 𝐀
MATH_BOLD_A_LOWER = 0x1D41A   # 𝐚
MATH_BOLD_UPPER_END = 0x1D419  # 𝐙
MATH_BOLD_LOWER_END = 0x1D433  # 𝐳

BRAILLE_BASE = 0x2800          # ⠀ empty pattern; +byte gives dot pattern

EMOJI_ZERO = '\U0001F535'      # 🔵
EMOJI_ONE  = '\U0001F534'      # 🔴

SKINTONE_BASE = '\U0001F44D'   # 👍 thumbs up
SKINTONE_TABLE = ('\U0001F3FB', '\U0001F3FC', '\U0001F3FE', '\U0001F3FF')  # 00,01,10,11
SKINTONE_REVERSE = {t: i for i, t in enumerate(SKINTONE_TABLE)}

METHODS: Tuple[str, ...] = (
    'zero_width', 'homoglyph', 'whitespace', 'invisible_ink',
    'variation', 'combining', 'confusable', 'directional', 'hangul',
    'mathbold', 'braille', 'emoji', 'skintone', 'capitalization',
)


# --- exceptions --------------------------------------------------------------

class TextStegCapacityError(ValueError):
    """Raised when the cover has too little carrier capacity for the payload."""


# --- helpers -----------------------------------------------------------------

def _bits_of(payload: bytes) -> str:
    return ''.join(format(b, '08b') for b in payload)


def _bits_to_bytes(bits: str, nbytes: int) -> bytes:
    out = bytearray()
    for i in range(0, min(len(bits), nbytes * 8), 8):
        chunk = bits[i:i + 8]
        if len(chunk) < 8:
            break
        out.append(int(chunk, 2))
    return bytes(out)


# --- zero-width --------------------------------------------------------------

def encode_zero_width(cover: str, secret: str) -> str:
    if not cover:
        raise TextStegCapacityError("zero_width: cover is empty")
    bits = _bits_of(secret.encode('utf-8'))
    payload = ZWJ + ''.join(ZWSP if b == '0' else ZWNJ for b in bits) + ZWJ
    if len(cover) > 1:
        return cover[0] + payload + cover[1:]
    return payload + cover


def decode_zero_width(stego: str) -> str:
    start = stego.find(ZWJ)
    if start == -1:
        return ''
    end = stego.find(ZWJ, start + 1)
    if end == -1:
        return ''
    body = stego[start + 1:end]
    bits = ''.join('0' if c == ZWSP else '1' if c == ZWNJ else '' for c in body)
    nbytes = len(bits) // 8
    return _bits_to_bytes(bits, nbytes).decode('utf-8', errors='replace')


# --- homoglyph ---------------------------------------------------------------

def _homoglyph_carriers(cover: str) -> int:
    return sum(1 for ch in cover if ch in HOMOGLYPH_MAP)


def encode_homoglyph(cover: str, secret: str) -> str:
    payload = secret.encode('utf-8')
    bits = format(len(payload), '016b') + _bits_of(payload)
    have = _homoglyph_carriers(cover)
    need = len(bits)
    if need > have:
        raise TextStegCapacityError(
            f"homoglyph: cover too small: need {need} carrier bits, have {have} "
            f"({need - have} short; payload = {len(payload)} bytes)"
        )
    out = []
    bit_idx = 0
    for ch in cover:
        if bit_idx < len(bits) and ch in HOMOGLYPH_MAP:
            out.append(HOMOGLYPH_MAP[ch] if bits[bit_idx] == '1' else ch)
            bit_idx += 1
        else:
            out.append(ch)
    return ''.join(out)


def decode_homoglyph(stego: str) -> str:
    bits = []
    for ch in stego:
        if ch in HOMOGLYPH_REVERSE:
            bits.append('1')
        elif ch in HOMOGLYPH_MAP:
            bits.append('0')
    if len(bits) < 16:
        return ''
    length = int(''.join(bits[:16]), 2)
    if length <= 0 or length > 10000:
        return ''
    data_bits = ''.join(bits[16:16 + 8 * length])
    return _bits_to_bytes(data_bits, length).decode('utf-8', errors='replace')


# --- whitespace --------------------------------------------------------------

def _whitespace_carrier_bits(cover: str) -> int:
    # 8 bits available per line.
    return 8 * (cover.count('\n') + 1)


def encode_whitespace(cover: str, secret: str) -> str:
    payload = secret.encode('utf-8')
    bits = format(len(payload), '016b') + _bits_of(payload)
    have = _whitespace_carrier_bits(cover)
    need = len(bits)
    if need > have:
        raise TextStegCapacityError(
            f"whitespace: cover too small: need {need} carrier bits, have {have} "
            f"({need - have} short; payload = {len(payload)} bytes; "
            f"add more lines or shorten payload)"
        )
    lines = cover.split('\n')
    out_lines = []
    bit_idx = 0
    for line in lines:
        trailing = []
        for _ in range(8):
            if bit_idx >= len(bits):
                break
            trailing.append(' ' if bits[bit_idx] == '0' else '\t')
            bit_idx += 1
        out_lines.append(line + ''.join(trailing))
    return '\n'.join(out_lines)


def decode_whitespace(stego: str) -> str:
    bits = []
    for line in stego.split('\n'):
        stripped = line.rstrip(' \t')
        trailing = line[len(stripped):]
        for ch in trailing:
            if ch == ' ':
                bits.append('0')
            elif ch == '\t':
                bits.append('1')
    if len(bits) < 16:
        return ''
    length = int(''.join(bits[:16]), 2)
    if length <= 0 or length > 10000:
        return ''
    data_bits = ''.join(bits[16:16 + 8 * length])
    return _bits_to_bytes(data_bits, length).decode('utf-8', errors='replace')


# --- invisible ink (tag chars) -----------------------------------------------

def encode_invisible_ink(cover: str, secret: str) -> str:
    if not cover:
        raise TextStegCapacityError("invisible_ink: cover is empty")
    parts = [chr(TAG_BASE)]
    for ch in secret:
        code = ord(ch)
        if code < 128:
            parts.append(chr(TAG_BASE + code))
    parts.append(chr(TAG_END))
    payload = ''.join(parts)
    if len(cover) > 1:
        return cover[0] + payload + cover[1:]
    return payload + cover


def decode_invisible_ink(stego: str) -> str:
    result = []
    in_tag = False
    for ch in stego:
        code = ord(ch)
        if code == TAG_BASE:
            in_tag = True
            continue
        if code == TAG_END:
            if in_tag:
                break
            continue
        if in_tag and TAG_BASE <= code < TAG_BASE + 128:
            result.append(chr(code - TAG_BASE))
    return ''.join(result)


# --- variation selectors -----------------------------------------------------

def _variation_carriers(cover: str) -> int:
    return sum(1 for ch in cover if ch.isascii() and ch.isalnum())


def encode_variation(cover: str, secret: str) -> str:
    payload = secret.encode('utf-8')
    bits = format(len(payload), '016b') + _bits_of(payload)
    have = _variation_carriers(cover)
    need = len(bits)
    if need > have:
        raise TextStegCapacityError(
            f"variation: cover too small: need {need} carrier bits, have {have} "
            f"({need - have} short; payload = {len(payload)} bytes)"
        )
    out = []
    bit_idx = 0
    for ch in cover:
        out.append(ch)
        if bit_idx < len(bits) and ch.isascii() and ch.isalnum():
            if bits[bit_idx] == '1':
                out.append(VS1)
            bit_idx += 1
    return ''.join(out)


def decode_variation(stego: str) -> str:
    bits = []
    i = 0
    n = len(stego)
    while i < n:
        ch = stego[i]
        if ch.isascii() and ch.isalnum():
            nxt = stego[i + 1] if i + 1 < n else ''
            if nxt and '︀' <= nxt <= '️':
                bits.append('1')
                i += 2
                continue
            bits.append('0')
        i += 1
    if len(bits) < 16:
        return ''
    length = int(''.join(bits[:16]), 2)
    if length <= 0 or length > 10000:
        return ''
    data_bits = ''.join(bits[16:16 + 8 * length])
    return _bits_to_bytes(data_bits, length).decode('utf-8', errors='replace')


# --- combining marks (CGJ) ---------------------------------------------------

def _combining_carriers(cover: str) -> int:
    return sum(1 for ch in cover if ch.isascii() and ch.isalpha())


def encode_combining(cover: str, secret: str) -> str:
    payload = secret.encode('utf-8')
    bits = format(len(payload), '016b') + _bits_of(payload)
    have = _combining_carriers(cover)
    need = len(bits)
    if need > have:
        raise TextStegCapacityError(
            f"combining: cover too small: need {need} carrier bits, have {have} "
            f"({need - have} short; payload = {len(payload)} bytes)"
        )
    out = []
    bit_idx = 0
    for ch in cover:
        out.append(ch)
        if bit_idx < len(bits) and ch.isascii() and ch.isalpha():
            if bits[bit_idx] == '1':
                out.append(CGJ)
            bit_idx += 1
    return ''.join(out)


def decode_combining(stego: str) -> str:
    # NB: this DIVERGES from the JS decoder in index.html:8261-8270. The JS
    # decoder walks chars emitting '0' on every ASCII letter and '1' on every
    # CGJ; but the encoder produces `<letter><CGJ>` for bit-1 carriers and
    # `<letter>` for bit-0 carriers. So the JS decoder yields "01" for every
    # 1-bit and "0" for every 0-bit — not a bijection, and the browser
    # round-trip is broken for any secret with a 1-bit in the payload. Python
    # uses the same look-ahead pattern as decode_variation instead: on an
    # ASCII letter, peek at the next char and emit '1' if it's the CGJ (then
    # skip both), else emit '0'. Left as a future fix on the JS side; not our
    # concern here. Same-side round-trip (Python encode -> Python decode) is
    # what these tests exercise.
    bits = []
    i = 0
    n = len(stego)
    while i < n:
        ch = stego[i]
        if ch.isascii() and ch.isalpha():
            nxt = stego[i + 1] if i + 1 < n else ''
            if nxt == CGJ:
                bits.append('1')
                i += 2
                continue
            bits.append('0')
        i += 1
    if len(bits) < 16:
        return ''
    length = int(''.join(bits[:16]), 2)
    if length <= 0 or length > 10000:
        return ''
    data_bits = ''.join(bits[16:16 + 8 * length])
    return _bits_to_bytes(data_bits, length).decode('utf-8', errors='replace')


# --- confusable whitespace ---------------------------------------------------

def _confusable_carrier_bits(cover: str) -> int:
    return 2 * cover.count(' ')


def encode_confusable(cover: str, secret: str) -> str:
    payload = secret.encode('utf-8')
    bits = format(len(payload), '016b') + _bits_of(payload)
    have = _confusable_carrier_bits(cover)
    need = len(bits)
    if need > have:
        raise TextStegCapacityError(
            f"confusable: cover too small: need {need} carrier bits, have {have} "
            f"({need - have} short; payload = {len(payload)} bytes; 2 bits per ASCII space)"
        )
    out = []
    bit_idx = 0
    for ch in cover:
        if ch == ' ' and bit_idx + 1 < len(bits):
            pair = bits[bit_idx] + bits[bit_idx + 1]
            out.append(CONFUSABLE_SPACE_TABLE.get(pair, ' '))
            bit_idx += 2
        else:
            out.append(ch)
    return ''.join(out)


def decode_confusable(stego: str) -> str:
    bits = []
    for ch in stego:
        if ch in CONFUSABLE_REVERSE:
            bits.append(CONFUSABLE_REVERSE[ch])
    joined = ''.join(bits)
    if len(joined) < 16:
        return ''
    length = int(joined[:16], 2)
    if length <= 0 or length > 10000:
        return ''
    data_bits = joined[16:16 + 8 * length]
    return _bits_to_bytes(data_bits, length).decode('utf-8', errors='replace')


# --- directional overrides ---------------------------------------------------

def encode_directional(cover: str, secret: str) -> str:
    if not cover:
        raise TextStegCapacityError("directional: cover is empty")
    payload = secret.encode('utf-8')
    bits = format(len(payload), '016b') + _bits_of(payload)
    run_parts = []
    for bit in bits:
        run_parts.append(RLO if bit == '1' else LRO)
        run_parts.append(PDF)
    run = ''.join(run_parts)
    return cover[0] + run + cover[1:]


def decode_directional(stego: str) -> str:
    bits = []
    for ch in stego:
        if ch == RLO:
            bits.append('1')
        elif ch == LRO:
            bits.append('0')
    if len(bits) < 16:
        return ''
    length = int(''.join(bits[:16]), 2)
    if length <= 0 or length > 10000:
        return ''
    data_bits = ''.join(bits[16:16 + 8 * length])
    return _bits_to_bytes(data_bits, length).decode('utf-8', errors='replace')


# --- hangul filler -----------------------------------------------------------

def _hangul_carrier_bits(cover: str) -> int:
    return cover.count(' ')


def encode_hangul(cover: str, secret: str) -> str:
    payload = secret.encode('utf-8')
    bits = format(len(payload), '016b') + _bits_of(payload)
    have = _hangul_carrier_bits(cover)
    need = len(bits)
    if need > have:
        raise TextStegCapacityError(
            f"hangul: cover too small: need {need} carrier bits, have {have} "
            f"({need - have} short; payload = {len(payload)} bytes; 1 bit per ASCII space)"
        )
    out = []
    bit_idx = 0
    for ch in cover:
        if ch == ' ' and bit_idx < len(bits):
            out.append(HANGUL_FILLER if bits[bit_idx] == '1' else ' ')
            bit_idx += 1
        else:
            out.append(ch)
    return ''.join(out)


def decode_hangul(stego: str) -> str:
    bits = []
    for ch in stego:
        if ch == HANGUL_FILLER:
            bits.append('1')
        elif ch == ' ':
            bits.append('0')
    if len(bits) < 16:
        return ''
    length = int(''.join(bits[:16]), 2)
    if length <= 0 or length > 10000:
        return ''
    data_bits = ''.join(bits[16:16 + 8 * length])
    return _bits_to_bytes(data_bits, length).decode('utf-8', errors='replace')


# --- math bold ---------------------------------------------------------------

def _mathbold_carriers(cover: str) -> int:
    return sum(1 for ch in cover if ch.isascii() and ch.isalpha())


def encode_mathbold(cover: str, secret: str) -> str:
    payload = secret.encode('utf-8')
    bits = format(len(payload), '016b') + _bits_of(payload)
    have = _mathbold_carriers(cover)
    need = len(bits)
    if need > have:
        raise TextStegCapacityError(
            f"mathbold: cover too small: need {need} carrier bits, have {have} "
            f"({need - have} short; payload = {len(payload)} bytes)"
        )
    out = []
    bit_idx = 0
    for ch in cover:
        if bit_idx < len(bits) and ch.isascii() and ch.isalpha():
            if bits[bit_idx] == '1':
                code = ord(ch)
                if 65 <= code <= 90:
                    out.append(chr(MATH_BOLD_A_UPPER + code - 65))
                elif 97 <= code <= 122:
                    out.append(chr(MATH_BOLD_A_LOWER + code - 97))
                else:
                    out.append(ch)
            else:
                out.append(ch)
            bit_idx += 1
        else:
            out.append(ch)
    return ''.join(out)


def decode_mathbold(stego: str) -> str:
    bits = []
    for ch in stego:
        cp = ord(ch)
        if (MATH_BOLD_A_UPPER <= cp <= MATH_BOLD_UPPER_END
                or MATH_BOLD_A_LOWER <= cp <= MATH_BOLD_LOWER_END):
            bits.append('1')
        elif (65 <= cp <= 90) or (97 <= cp <= 122):
            bits.append('0')
    if len(bits) < 16:
        return ''
    length = int(''.join(bits[:16]), 2)
    if length <= 0 or length > 10000:
        return ''
    data_bits = ''.join(bits[16:16 + 8 * length])
    return _bits_to_bytes(data_bits, length).decode('utf-8', errors='replace')


# --- braille -----------------------------------------------------------------

def encode_braille(cover: str, secret: str) -> str:
    payload = secret.encode('utf-8')
    braille = ''.join(chr(BRAILLE_BASE + b) for b in payload)
    return cover + '\n\n' + braille


def decode_braille(stego: str) -> str:
    bytes_out = bytearray()
    for ch in stego:
        cp = ord(ch)
        if BRAILLE_BASE <= cp <= BRAILLE_BASE + 0xFF:
            bytes_out.append(cp - BRAILLE_BASE)
    return bytes(bytes_out).decode('utf-8', errors='replace')


# --- emoji substitution -------------------------------------------------------

def encode_emoji(cover: str, secret: str) -> str:
    payload = secret.encode('utf-8')
    bits = format(len(payload), '016b') + _bits_of(payload)
    emoji = ''.join(EMOJI_ONE if b == '1' else EMOJI_ZERO for b in bits)
    return cover + '\n\n' + emoji


def decode_emoji(stego: str) -> str:
    bits = []
    for ch in stego:
        if ch == EMOJI_ONE:
            bits.append('1')
        elif ch == EMOJI_ZERO:
            bits.append('0')
    if len(bits) < 16:
        return ''
    length = int(''.join(bits[:16]), 2)
    if length <= 0 or length > 10000:
        return ''
    data_bits = ''.join(bits[16:16 + 8 * length])
    return _bits_to_bytes(data_bits, length).decode('utf-8', errors='replace')


# --- skin tone ---------------------------------------------------------------

def encode_skintone(cover: str, secret: str) -> str:
    payload = secret.encode('utf-8')
    digits = []
    for b in payload:
        digits.append((b >> 6) & 3)
        digits.append((b >> 4) & 3)
        digits.append((b >> 2) & 3)
        digits.append(b & 3)
    encoded = ' '.join(SKINTONE_BASE + SKINTONE_TABLE[d] for d in digits)
    return cover + '\n\n' + encoded


def decode_skintone(stego: str) -> str:
    pairs = [SKINTONE_REVERSE[ch] for ch in stego if ch in SKINTONE_REVERSE]
    if len(pairs) < 4:
        return ''
    out = bytearray()
    for i in range(0, len(pairs) - 3, 4):
        out.append((pairs[i] << 6) | (pairs[i + 1] << 4) | (pairs[i + 2] << 2) | pairs[i + 3])
    return bytes(out).decode('utf-8', errors='replace')


# --- capitalization ----------------------------------------------------------

def _capitalization_carriers(cover: str) -> int:
    return sum(1 for w in cover.split(' ') if w and w[0].isascii() and w[0].isalpha())


def encode_capitalization(cover: str, secret: str) -> str:
    payload = secret.encode('utf-8')
    bits = format(len(payload), '016b') + _bits_of(payload)
    have = _capitalization_carriers(cover)
    need = len(bits)
    if need > have:
        raise TextStegCapacityError(
            f"capitalization: cover too small: need {need} carrier bits, have {have} "
            f"({need - have} short; payload = {len(payload)} bytes; 1 bit per word-initial ASCII letter)"
        )
    words = cover.split(' ')
    bit_idx = 0
    for i, w in enumerate(words):
        if not w:
            continue
        first = w[0]
        if bit_idx < len(bits) and first.isascii() and first.isalpha():
            if bits[bit_idx] == '1':
                words[i] = first.upper() + w[1:]
            else:
                words[i] = first.lower() + w[1:]
            bit_idx += 1
    return ' '.join(words)


def decode_capitalization(stego: str) -> str:
    bits = []
    for w in stego.split(' '):
        if not w:
            continue
        first = w[0]
        if first.isascii() and first.isalpha():
            bits.append('1' if first.isupper() else '0')
    if len(bits) < 16:
        return ''
    length = int(''.join(bits[:16]), 2)
    if length <= 0 or length > 10000:
        return ''
    data_bits = ''.join(bits[16:16 + 8 * length])
    return _bits_to_bytes(data_bits, length).decode('utf-8', errors='replace')


# --- capacity ----------------------------------------------------------------

def capacity(cover: str, method: str) -> dict:
    """Return a pre-flight report for `method` against `cover`.

    Fields: method, carrier_bits, payload_bytes_max, notes.
    """
    if method == 'zero_width':
        # zero_width has no length prefix; its capacity is effectively unbounded
        # by the cover (payload rides inside its own delimited span), so we
        # report the practical view: any payload fits as long as cover is
        # non-empty.
        return {
            'method': method,
            'carrier_bits': None,
            'payload_bytes_max': None,
            'notes': (
                "no length prefix; payload rides inside ZWJ delimiters. Cover "
                "just needs to be non-empty."
            ),
        }
    if method == 'homoglyph':
        bits = _homoglyph_carriers(cover)
        max_bytes = max(0, (bits - 16) // 8)
        return {
            'method': method,
            'carrier_bits': bits,
            'payload_bytes_max': max_bytes,
            'notes': (
                f"16-bit length prefix + 8 bits per Latin-carrier char "
                f"(a c e o p x y A B C E H K M O P T X)."
            ),
        }
    if method == 'whitespace':
        bits = _whitespace_carrier_bits(cover)
        max_bytes = max(0, (bits - 16) // 8)
        return {
            'method': method,
            'carrier_bits': bits,
            'payload_bytes_max': max_bytes,
            'notes': (
                f"16-bit length prefix + 8 bits per line ({cover.count(chr(10)) + 1} lines here). "
                "More lines = more capacity."
            ),
        }
    if method == 'invisible_ink':
        return {
            'method': method,
            'carrier_bits': None,
            'payload_bytes_max': None,
            'notes': (
                "ASCII-only payload (chars < 128), one tag char per input char. "
                "Cover only needs to be non-empty."
            ),
        }
    if method == 'variation':
        bits = _variation_carriers(cover)
        return {
            'method': method,
            'carrier_bits': bits,
            'payload_bytes_max': max(0, (bits - 16) // 8),
            'notes': (
                "16-bit length prefix + 1 bit per ASCII alnum carrier "
                "(VS-1 present = 1, absent = 0)."
            ),
        }
    if method == 'combining':
        bits = _combining_carriers(cover)
        return {
            'method': method,
            'carrier_bits': bits,
            'payload_bytes_max': max(0, (bits - 16) // 8),
            'notes': (
                "16-bit length prefix + 1 bit per ASCII alpha carrier "
                "(CGJ present = 1, absent = 0)."
            ),
        }
    if method == 'confusable':
        bits = _confusable_carrier_bits(cover)
        return {
            'method': method,
            'carrier_bits': bits,
            'payload_bytes_max': max(0, (bits - 16) // 8),
            'notes': (
                f"16-bit length prefix + 2 bits per ASCII space "
                f"({cover.count(' ')} spaces here). "
                "Regular=00, EN=01, EM=10, THIN=11."
            ),
        }
    if method == 'directional':
        return {
            'method': method,
            'carrier_bits': None,
            'payload_bytes_max': None,
            'notes': (
                "Payload rides in its own inserted RLO/LRO+PDF run spliced after "
                "cover[0]. Cover only needs to be non-empty."
            ),
        }
    if method == 'hangul':
        bits = _hangul_carrier_bits(cover)
        return {
            'method': method,
            'carrier_bits': bits,
            'payload_bytes_max': max(0, (bits - 16) // 8),
            'notes': (
                f"16-bit length prefix + 1 bit per ASCII space "
                f"({cover.count(' ')} spaces here). "
                "HANGUL FILLER = 1, space = 0."
            ),
        }
    if method == 'mathbold':
        bits = _mathbold_carriers(cover)
        return {
            'method': method,
            'carrier_bits': bits,
            'payload_bytes_max': max(0, (bits - 16) // 8),
            'notes': (
                "16-bit length prefix + 1 bit per ASCII letter carrier "
                "(math-bold codepoint = 1, plain letter = 0)."
            ),
        }
    if method == 'braille':
        return {
            'method': method,
            'carrier_bits': None,
            'payload_bytes_max': None,
            'notes': (
                "Payload appended after cover as its own block, separated by "
                "'\\n\\n'. Each payload byte maps to a braille pattern in "
                "U+2800..U+28FF. Cover only needs to be non-empty."
            ),
        }
    if method == 'emoji':
        return {
            'method': method,
            'carrier_bits': None,
            'payload_bytes_max': None,
            'notes': (
                "Payload appended after cover as its own block, separated by "
                "'\\n\\n'. 16-bit length prefix + 1 bit per emoji "
                "(🔴 = 1, 🔵 = 0). Cover only needs to be non-empty."
            ),
        }
    if method == 'skintone':
        return {
            'method': method,
            'carrier_bits': None,
            'payload_bytes_max': None,
            'notes': (
                "Payload appended after cover as its own block, separated by "
                "'\\n\\n'. Each byte -> 4 skin-tone modifiers (2 bits each), "
                "joined with spaces. Cover only needs to be non-empty."
            ),
        }
    if method == 'capitalization':
        bits = _capitalization_carriers(cover)
        return {
            'method': method,
            'carrier_bits': bits,
            'payload_bytes_max': max(0, (bits - 16) // 8),
            'notes': (
                "16-bit length prefix + 1 bit per word-initial ASCII letter "
                "(uppercase = 1, lowercase = 0)."
            ),
        }
    raise ValueError(f"unknown method '{method}'. Try one of: {', '.join(METHODS)}")


# --- generic dispatchers -----------------------------------------------------

_ENCODERS = {
    'zero_width':    encode_zero_width,
    'homoglyph':     encode_homoglyph,
    'whitespace':    encode_whitespace,
    'invisible_ink': encode_invisible_ink,
    'variation':     encode_variation,
    'combining':     encode_combining,
    'confusable':    encode_confusable,
    'directional':   encode_directional,
    'hangul':        encode_hangul,
    'mathbold':       encode_mathbold,
    'braille':        encode_braille,
    'emoji':          encode_emoji,
    'skintone':       encode_skintone,
    'capitalization': encode_capitalization,
}

_DECODERS = {
    'zero_width':    decode_zero_width,
    'homoglyph':     decode_homoglyph,
    'whitespace':    decode_whitespace,
    'invisible_ink': decode_invisible_ink,
    'variation':     decode_variation,
    'combining':     decode_combining,
    'confusable':    decode_confusable,
    'directional':   decode_directional,
    'hangul':        decode_hangul,
    'mathbold':       decode_mathbold,
    'braille':        decode_braille,
    'emoji':          decode_emoji,
    'skintone':       decode_skintone,
    'capitalization': decode_capitalization,
}


def encode(cover: str, secret: str, method: str) -> str:
    fn = _ENCODERS.get(method)
    if fn is None:
        raise ValueError(f"unknown method '{method}'. Try one of: {', '.join(METHODS)}")
    return fn(cover, secret)


def decode(stego: str, method: str) -> str:
    fn = _DECODERS.get(method)
    if fn is None:
        raise ValueError(f"unknown method '{method}'. Try one of: {', '.join(METHODS)}")
    return fn(stego)
