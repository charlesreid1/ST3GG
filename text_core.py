"""Text steganography encode/decode core (ST3GG-faithful).

Ports the four classic text-in-text techniques from `index.html` so that
Python callers can encode and decode the same stego texts the browser
produces.

Techniques:
  - zero_width:    ZWJ start + ZWSP(0)/ZWNJ(1) payload bits + ZWJ end,
                   spliced after the first cover char.
  - homoglyph:     Latin -> Cyrillic twin substitution. 16-bit length
                   prefix followed by payload bits, ridden on the
                   available Latin carrier positions in cover order.
  - whitespace:    8 trailing bits per line, ' ' = 0 / '\\t' = 1. 16-bit
                   length prefix + payload bits.
  - invisible_ink: U+E0000 start tag, ASCII -> tag-char body (code+base),
                   U+E007F end tag. Spliced after the first cover char.
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

METHODS: Tuple[str, ...] = ('zero_width', 'homoglyph', 'whitespace', 'invisible_ink')


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
    raise ValueError(f"unknown method '{method}'. Try one of: {', '.join(METHODS)}")


# --- generic dispatchers -----------------------------------------------------

_ENCODERS = {
    'zero_width':    encode_zero_width,
    'homoglyph':     encode_homoglyph,
    'whitespace':    encode_whitespace,
    'invisible_ink': encode_invisible_ink,
}

_DECODERS = {
    'zero_width':    decode_zero_width,
    'homoglyph':     decode_homoglyph,
    'whitespace':    decode_whitespace,
    'invisible_ink': decode_invisible_ink,
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
