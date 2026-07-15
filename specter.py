"""
SPECTER Channel Cipher — cross-channel hopping steganography engine.

Port of the browser JavaScript "godmode" implementation to Python.
Provides manual-pattern and password-derived channel ciphers, LSB and DCT
embedding modes, Ghost Mode (AES-256-GCM + scrambling + noise), and a
detection/analysis tool.  Wire-format compatible with the JS side so
messages encoded in one runtime decode in the other.

.. note::
   The JS implementation lives in ``index.html`` under the hidden
   "godmode" easter-egg tab (~33 references).  This module re-implements
   every feature of that tab — pattern system, Mulberry32 PRNG, djb2
   password hash, Fisher-Yates scramble, noise interleave, Ghost Mode
   encryption, and DCT robustness — with bit-identical output.
"""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

import numpy as np
from PIL import Image

from img_core import DCT_EMBED_POS, _dct_matrix, _luminance

# ---------------------------------------------------------------------------
# Cryptography — try the real AES-256-GCM module, fall back gracefully.
# ---------------------------------------------------------------------------
try:
    from crypto import HAS_CRYPTO, decrypt_aes_gcm, encrypt_aes_gcm
except Exception:  # pragma: no cover — broken system install
    HAS_CRYPTO = False
    def encrypt_aes_gcm(*a, **kw): raise RuntimeError("cryptography unavailable")  # noqa: E704
    def decrypt_aes_gcm(*a, **kw): raise RuntimeError("cryptography unavailable")  # noqa: E704


# ============================================================================
# 1. Constants and header format
# ============================================================================

SPECTER_MAGIC_NORMAL = b"GODM"   # plain or XOR-encrypted
SPECTER_MAGIC_GHOST  = b"GODP"   # Ghost Mode (AES-256-GCM + scramble + noise)
SPECTER_HEADER_SIZE  = 12

# DCT variant
SPECTER_DCT_MAGIC      = b"RDCT"
SPECTER_DCT_HEADER_SIZE = 16
SPECTER_DCT_REDUNDANCY  = 5       # blocks per bit (odd, for majority voting)
SPECTER_DCT_STRENGTH    = 50      # matches JS ROBUST_DCT_CONFIG.STRENGTH

# Channel index mapping (matches JS: R=0, G=1, B=2, A=3)
CHANNEL_MAP = {"R": 0, "G": 1, "B": 2, "A": 3}
CHANNEL_NAMES = {0: "R", 1: "G", 2: "B", 3: "A"}

# ---------------------------------------------------------------------------
# LSB Header layout (12 bytes)
#   [0:4]   Magic: GODM or GODP
#   [4:8]   Payload length (uint32 big-endian)
#   [8]     Step count (uint8)
#   [9]     Flags: 0=plain, 1=XOR encrypted, 2=Ghost
#   [10]    Density (uint8, 1-100)
#   [11]    Statistical balancing (uint8, 0 or 1)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# DCT Header layout (16 bytes)
#   [0:4]   Magic: RDCT
#   [4:8]   Payload length (uint32 big-endian)
#   [8]     Step count (uint8)
#   [9]     Flags: 0=plain, 1=XOR encrypted
#   [10]    Redundancy (uint8, default 5)
#   [11]    Strength (uint8, default 50)
#   [12]    Precondition flag (uint8, 0 or 1)
#   [13:16] Reserved
# ---------------------------------------------------------------------------


# ============================================================================
# 2. CipherStep dataclass and pattern system
# ============================================================================

@dataclass
class CipherStep:
    """One step in a SPECTER channel-hopping cipher."""
    channels: List[int]   # e.g. [0, 1] for R+G
    bits: int             # 1-4 bits per channel
    name: str             # e.g. "RG2"

    @property
    def total_bits(self) -> int:
        """Total bits embedded per step across all channels."""
        return len(self.channels) * self.bits


# ---- pattern parsing -------------------------------------------------------

_VALID_CHANNEL_OPTIONS = {
    "R", "G", "B", "RG", "RB", "GB", "RGB",
}


def parse_pattern(pattern: str) -> Optional[List[CipherStep]]:
    """Parse a manual pattern string like ``"R1-G2-B1-RGB2-RG1"``.

    Returns a list of :class:`CipherStep` objects, or ``None`` if the
    pattern is malformed.
    """
    if not pattern or not pattern.strip():
        return None

    steps: List[CipherStep] = []
    for token in pattern.strip().split("-"):
        token = token.strip().upper()
        if not token:
            return None

        # Split into channel letters + trailing digit(s)
        i = 0
        while i < len(token) and token[i].isalpha():
            i += 1
        ch_str = token[:i]
        bits_str = token[i:]

        if ch_str not in _VALID_CHANNEL_OPTIONS:
            return None
        try:
            bits = int(bits_str)
        except ValueError:
            return None
        if bits < 1 or bits > 4:
            return None

        channels = [CHANNEL_MAP[c] for c in ch_str]
        steps.append(CipherStep(channels=channels, bits=bits, name=f"{ch_str}{bits}"))

    return steps if steps else None


# ---- password-derived pattern ----------------------------------------------

# The 7 channel groups the JS picks from (no alpha).
_PASSWORD_CHANNEL_POOL: List[List[int]] = [
    [0],       # R
    [1],       # G
    [2],       # B
    [0, 1],    # RG
    [0, 2],    # RB
    [1, 2],    # GB
    [0, 1, 2], # RGB
]

# Bit options weighted toward 1-bit so most steps are subtle.
_PASSWORD_BIT_POOL = [1, 1, 1, 2, 2]


def pattern_from_password(password: str) -> List[CipherStep]:
    """Deterministic 8–16 step pattern from a password.

    Uses the same djb2-variant hash + Mulberry32 PRNG as the browser JS so
    the same password always produces the same channel-hopping sequence
    across runtimes.
    """
    seed = _password_to_seed(password)
    prng = _mulberry32(seed)

    # 8–16 steps
    num_steps = 8 + int(prng() * 9)

    steps: List[CipherStep] = []
    for _ in range(num_steps):
        ch_idx = int(prng() * len(_PASSWORD_CHANNEL_POOL))
        channels = list(_PASSWORD_CHANNEL_POOL[ch_idx])
        bit_idx = int(prng() * len(_PASSWORD_BIT_POOL))
        bits = _PASSWORD_BIT_POOL[bit_idx]
        name = "".join(CHANNEL_NAMES[c] for c in channels) + str(bits)
        steps.append(CipherStep(channels=channels, bits=bits, name=name))

    return steps


# ============================================================================
# 3. Bit-level helpers (must be bit-identical to JS)
# ============================================================================

def _to_int32(x: int) -> int:
    """Convert an integer to signed 32-bit (JS bitwise-op semantics)."""
    x = x & 0xFFFFFFFF
    if x >= 0x80000000:
        x -= 0x100000000
    return x


def _password_to_seed(password: str) -> int:
    """Hash a password to a 32-bit integer seed (djb2 variant).

    This MUST produce the same output as the JS ``passwordToSeed()``
    function for cross-compatibility.  The JS implementation uses::

        let seed = 5381;
        for (let i = 0; i < password.length; i++) {
            seed = ((seed << 5) - seed) + password.charCodeAt(i);
            seed = seed & seed;  // force 32-bit
        }
        return seed >>> 0;

    The critical detail: in JS, ``<<`` first converts its operand to a
    **signed** 32-bit integer, so ``seed << 5`` wraps at 2³¹.  The
    subtraction and addition are regular Number arithmetic, and ``&``
    converts back to signed 32-bit.  The final ``>>> 0`` yields an
    unsigned 32-bit value.
    """
    seed = 5381
    for ch in password:
        # JS: seed << 5  — operates on Int32, result is Int32
        shifted = _to_int32(_to_int32(seed) << 5)
        seed = shifted - seed + ord(ch)
        # JS: seed & seed  — forces Int32
        seed = _to_int32(seed)
    # JS: seed >>> 0  — unsigned 32-bit
    return seed & 0xFFFFFFFF


def _mulberry32(seed: int) -> Callable[[], float]:
    """Return a Mulberry32 PRNG function, seeded with a 32-bit int.

    The JS implementation::

        function mulberry32(a) {
            return function() {
                a |= 0; a = a + 0x6D2B79F5 | 0;
                var t = Math.imul(a ^ a >>> 15, 1 | a);
                t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
                return ((t ^ t >>> 14) >>> 0) / 4294967296;
            };
        }
    """
    state = seed | 0  # force 32-bit signed

    def prng() -> float:
        nonlocal state
        state = (state + 0x6D2B79F5) & 0xFFFFFFFF  # a = a + 0x6D2B79F5 | 0
        t = (state ^ (state >> 15)) & 0xFFFFFFFF
        # Math.imul(t, 1 | a) — 1|a is always odd, so it's just multiply
        t = (t * (1 | state)) & 0xFFFFFFFF
        t = (t + (t * ((t ^ (t >> 7)) & 0xFFFFFFFF) ^ t)) & 0xFFFFFFFF
        # JS: ((t ^ t >>> 14) >>> 0) / 4294967296
        result = ((t ^ (t >> 14)) & 0xFFFFFFFF)
        return result / 4294967296.0

    return prng


def _data_to_bits(data: bytes) -> List[int]:
    """Convert bytes to a flat list of bits (MSB first per byte)."""
    bits: List[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _bits_to_data(bits: List[int]) -> bytes:
    """Convert a flat list of bits back to bytes (MSB first, zero-padded)."""
    # Pad to multiple of 8
    pad = (8 - len(bits) % 8) % 8
    padded = bits + [0] * pad
    result = bytearray()
    for i in range(0, len(padded), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | padded[i + j]
        result.append(byte)
    return bytes(result)


def _scramble_bits(bits: List[int], seed: int, reverse: bool = False) -> List[int]:
    """Fisher-Yates shuffle on bit *positions*.

    Uses the Mulberry32 PRNG so the shuffle is deterministic and matches
    the JS ``scrambleBits()`` function exactly.

    When ``reverse=True``, unscrambles by applying the inverse permutation.
    """
    n = len(bits)
    if n <= 1:
        return list(bits)

    prng = _mulberry32(seed)

    # Build the permutation indices
    indices = list(range(n))
    for i in range(n - 1, 0, -1):
        j = int(prng() * (i + 1))
        indices[i], indices[j] = indices[j], indices[i]

    if reverse:
        # Invert the permutation
        inv = [0] * n
        for i, p in enumerate(indices):
            inv[p] = i
        indices = inv

    return [bits[idx] for idx in indices]


def _interleave_noise(bits: List[int], seed: int) -> List[int]:
    """Insert a random noise bit before every real bit (doubles length).

    Matches JS ``interleaveNoise()``: for each real bit, prepend a
    PRNG-derived noise bit.
    """
    prng = _mulberry32(seed)
    result: List[int] = []
    for bit in bits:
        noise = int(prng() * 2)  # 0 or 1
        result.append(noise)
        result.append(bit)
    return result


def _remove_noise(bits: List[int]) -> List[int]:
    """Extract every *other* bit starting from index 1 (the real bits).

    Inverse of :func:`_interleave_noise`.
    """
    return [bits[i] for i in range(1, len(bits), 2)]


# ============================================================================
# 4. Ghost Mode encryption wrappers
# ============================================================================

def _xor_cipher(data: bytes, key: str) -> bytes:
    """Simple repeating-key XOR (matches JS ``godmodeEncrypt``)."""
    if not key:
        return data
    key_bytes = key.encode("utf-8")
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = b ^ key_bytes[i % len(key_bytes)]
    return bytes(result)


def _ghost_encrypt(data: bytes, password: str) -> bytes:
    """AES-256-GCM encrypt + pack into bytes (salt + iv + ciphertext + tag).

    Returns the packed blob that gets embedded in the image.
    """
    if not HAS_CRYPTO:
        raise RuntimeError(
            "Ghost Mode requires the cryptography package. "
            "Install with: pip install cryptography"
        )
    from crypto import EncryptedPayload as _EP

    payload: _EP = encrypt_aes_gcm(data, password)
    # Pack: salt (16) + iv (12) + ciphertext_with_tag
    return payload.salt + payload.iv + payload.ciphertext


def _ghost_decrypt(packed: bytes, password: str) -> bytes:
    """Unpack and AES-256-GCM decrypt.

    Expects the format produced by :func:`_ghost_encrypt`.
    """
    if not HAS_CRYPTO:
        raise RuntimeError(
            "Ghost Mode requires the cryptography package. "
            "Install with: pip install cryptography"
        )
    from crypto import EncryptedPayload as _EP

    salt = packed[:16]
    iv = packed[16:28]
    ciphertext_with_tag = packed[28:]

    payload = _EP(
        ciphertext=ciphertext_with_tag,
        iv=iv,
        salt=salt,
        method="aes-256-gcm",
    )
    return decrypt_aes_gcm(payload, password)


# ============================================================================
# 5. SPECTER LSB encode
# ============================================================================

def specter_lsb_encode(
    image: Image.Image,
    data: bytes,
    steps: List[CipherStep],
    *,
    encrypt: bool = False,
    key: str = "",
    density: int = 100,
    balance: bool = True,
    ghost: bool = False,
    output_path: Optional[str] = None,
) -> Image.Image:
    """Embed *data* into *image* using the SPECTER LSB channel cipher.

    Parameters
    ----------
    image:
        Carrier PIL image (converted to RGBA internally).
    data:
        Payload bytes to hide.
    steps:
        Ordered list of :class:`CipherStep` — the channel-hopping pattern.
    encrypt:
        If True, XOR-encrypt the payload with *key* before embedding.
    key:
        Password / key string for XOR encryption or Ghost Mode scrambling.
    density:
        Embedding density 1–100.  Lower values skip more pixels (skipFactor
        = max(1, 100 // density)), making the embedding sparser.
    balance:
        If True, apply ±1 jitter to the alpha channel of unused pixels for
        statistical balancing.
    ghost:
        If True, enable Ghost Mode: AES-256-GCM encrypt the payload,
        scramble payload bits, and interleave noise.
    output_path:
        If given, save the result to this PNG path.

    Returns
    -------
    Image.Image
        The stego image (RGBA).
    """
    if not steps:
        raise ValueError("at least one CipherStep is required")

    # --- prepare payload ----------------------------------------------------
    if ghost:
        if not key:
            raise ValueError("Ghost Mode requires a password/key")
        encrypted = _ghost_encrypt(data, key)
        magic = SPECTER_MAGIC_GHOST
        flags = 2
    elif encrypt:
        if not key:
            raise ValueError("encryption requires a key")
        encrypted = _xor_cipher(data, key)
        magic = SPECTER_MAGIC_NORMAL
        flags = 1
    else:
        encrypted = data
        magic = SPECTER_MAGIC_NORMAL
        flags = 0

    # --- build header -------------------------------------------------------
    header = bytearray(SPECTER_HEADER_SIZE)
    header[0:4] = magic
    struct.pack_into(">I", header, 4, len(data))        # original payload length
    header[8] = len(steps) & 0xFF                         # step count
    header[9] = flags
    header[10] = max(1, min(100, density)) & 0xFF
    header[11] = 1 if balance else 0

    full_payload = bytes(header) + encrypted

    # --- convert to bit stream ----------------------------------------------
    bits = _data_to_bits(full_payload)

    if ghost:
        # Scramble only the payload portion (after header), then interleave
        # all bits (header + scrambled payload) with noise.
        header_bit_count = SPECTER_HEADER_SIZE * 8
        header_bits = bits[:header_bit_count]
        payload_bits = bits[header_bit_count:]

        password_seed = _password_to_seed(key)
        scrambled_payload = _scramble_bits(payload_bits, password_seed)

        # Recombine header (unscrambled) + scrambled payload
        all_bits = header_bits + scrambled_payload

        # Interleave noise throughout (header + payload)
        noise_seed = password_seed ^ 0xFFFFFFFF
        bits = _interleave_noise(all_bits, noise_seed)

    # --- embed into pixels --------------------------------------------------
    img = image.convert("RGBA")
    pixels = np.array(img, dtype=np.uint8)
    height, width = pixels.shape[:2]
    total_pixels = height * width

    skip_factor = max(1, 100 // density)
    flat = pixels.reshape(-1, 4)

    bit_idx = 0
    step_idx = 0
    num_steps = len(steps)

    for pix_idx in range(0, total_pixels, skip_factor):
        if bit_idx >= len(bits):
            break
        step = steps[step_idx]
        for ch in step.channels:
            if bit_idx >= len(bits):
                break
            # Embed step.bits bits into this channel's LSBs
            for b_off in range(step.bits):
                if bit_idx >= len(bits):
                    break
                bit_val = bits[bit_idx]
                # Clear the target bit and set
                mask = ~(1 << b_off) & 0xFF
                flat[pix_idx, ch] = (flat[pix_idx, ch] & mask) | (bit_val << b_off)
                bit_idx += 1
        step_idx = (step_idx + 1) % num_steps

    if bit_idx < len(bits):
        raise ValueError(
            f"Payload too large: {len(bits) - bit_idx} bits could not be embedded "
            f"(image is {width}x{height}, density={density})"
        )

    # --- statistical balancing (alpha-channel jitter) -----------------------
    if balance:
        rng = np.random.default_rng(abs(hash(tuple(step.name for step in steps))) % (2**31))
        # Apply jitter to alpha channel of pixels that were used
        used_mask = np.zeros(total_pixels, dtype=bool)
        for pix_idx in range(0, total_pixels, skip_factor):
            used_mask[pix_idx] = True
        jitter = rng.integers(-1, 2, size=total_pixels, dtype=np.int16)
        jitter[~used_mask] = 0
        new_alpha = flat[:, 3].astype(np.int16) + jitter
        flat[:, 3] = np.clip(new_alpha, 0, 255).astype(np.uint8)

    result = Image.fromarray(pixels, "RGBA")
    if output_path:
        result.save(output_path, format="PNG", optimize=False)
    return result


# ============================================================================
# 6. SPECTER LSB decode
# ============================================================================

def specter_lsb_decode(
    image: Image.Image,
    steps: List[CipherStep],
    *,
    key: str = "",
) -> bytes:
    """Recover data hidden by :func:`specter_lsb_encode`.

    Parameters
    ----------
    image:
        The stego image.
    steps:
        The same channel-hopping pattern used during encoding.
    key:
        Password / key for decryption (XOR or Ghost Mode).

    Returns
    -------
    bytes
        The recovered payload.
    """
    if not steps:
        raise ValueError("at least one CipherStep is required")

    img = image.convert("RGBA")
    pixels = np.array(img, dtype=np.uint8)
    height, width = pixels.shape[:2]
    total_pixels = height * width

    # --- Bit extraction helper ----------------------------------------------
    def _extract_bits(density: int) -> List[int]:
        skip_factor = max(1, 100 // density)
        flat = pixels.reshape(-1, 4)
        bits: List[int] = []
        step_idx = 0
        num_steps = len(steps)

        for pix_idx in range(0, total_pixels, skip_factor):
            step = steps[step_idx]
            for ch in step.channels:
                for b_off in range(step.bits):
                    bit_val = (flat[pix_idx, ch] >> b_off) & 1
                    bits.append(bit_val)
            step_idx = (step_idx + 1) % num_steps

        return bits

    # --- Try to parse a header from a bit list ------------------------------
    def _try_parse(bits: List[int]) -> Optional[bytes]:
        """Try to parse header from bits. Returns payload or None."""
        if len(bits) < SPECTER_HEADER_SIZE * 8:
            return None
        as_bytes = _bits_to_data(bits)
        magic = as_bytes[:4]
        if magic not in (SPECTER_MAGIC_NORMAL, SPECTER_MAGIC_GHOST):
            return None
        payload_len = struct.unpack(">I", as_bytes[4:8])[0]
        if payload_len > 10_000_000:
            return None
        flags = as_bytes[9]
        stored_density = as_bytes[10]
        if stored_density < 1 or stored_density > 100:
            return None

        # Check we have enough data
        header_end = SPECTER_HEADER_SIZE
        needed = header_end + payload_len
        if flags == 2:  # Ghost
            available = len(as_bytes) - header_end
            if available < 44:
                return None
        elif needed > len(as_bytes):
            return None

        raw_payload = as_bytes[header_end:]

        if flags == 2:
            return raw_payload
        elif flags == 1:
            return raw_payload[:payload_len]
        else:
            return raw_payload[:payload_len]

    # --- Try multiple densities in order ------------------------------------
    # When density < 100, bits from skipped pixels pollute the stream at
    # density=100, so we must try progressively sparser extractions.
    _DENSITIES_TO_TRY = [100, 50, 25, 10]

    for try_density in _DENSITIES_TO_TRY:
        raw_bits = _extract_bits(try_density)
        parsed = _try_parse(raw_bits)
        if parsed is None:
            continue

        as_bytes = _bits_to_data(raw_bits)
        flags = as_bytes[9]
        stored_density = as_bytes[10]
        payload_len = struct.unpack(">I", as_bytes[4:8])[0]

        # If the header-reported density differs from what we tried,
        # re-extract at the correct density.
        if stored_density != try_density and stored_density >= 1:
            raw_bits = _extract_bits(stored_density)
            as_bytes = _bits_to_data(raw_bits)
            parsed = as_bytes[SPECTER_HEADER_SIZE:]

        if flags == 2:  # Ghost
            if not key:
                raise ValueError("Ghost Mode payload requires a decryption key")
            # Ghost payload = salt(16) + iv(12) + ciphertext(payload_len) + tag(16)
            encrypted_payload = as_bytes[SPECTER_HEADER_SIZE:SPECTER_HEADER_SIZE + payload_len + 44]
            return _ghost_decrypt(encrypted_payload, key)
        elif flags == 1:  # XOR
            if not key:
                raise ValueError("Encrypted payload requires a decryption key")
            return _xor_cipher(parsed[:payload_len], key)
        else:
            return parsed[:payload_len]

    # --- Ghost Mode fallback: try denoise + unscramble ----------------------
    if key:
        for try_density in _DENSITIES_TO_TRY:
            raw_bits = _extract_bits(try_density)
            denoised = _remove_noise(raw_bits)

            if len(denoised) < SPECTER_HEADER_SIZE * 8:
                continue

            # Parse header from denoised bits (header is never scrambled)
            header_bit_count = SPECTER_HEADER_SIZE * 8
            header_bits = denoised[:header_bit_count]
            header_bytes = _bits_to_data(header_bits)
            if header_bytes[:4] != SPECTER_MAGIC_GHOST:
                continue

            payload_len = struct.unpack(">I", header_bytes[4:8])[0]
            stored_density = header_bytes[10]
            if payload_len > 10_000_000:
                continue

            # If stored density differs, re-extract at that density
            if stored_density != try_density and stored_density >= 1:
                raw_bits = _extract_bits(stored_density)
                denoised = _remove_noise(raw_bits)
                if len(denoised) < SPECTER_HEADER_SIZE * 8:
                    continue
                header_bits = denoised[:header_bit_count]
                header_bytes = _bits_to_data(header_bits)

            # Ghost payload size: salt(16) + iv(12) + ciphertext(payload_len) + tag(16)
            ghost_payload_bytes = payload_len + 44
            ghost_payload_bits_count = ghost_payload_bytes * 8

            # Extract EXACTLY the right number of payload bits for unscrambling
            # (Fisher-Yates permutation depends on array length!)
            payload_bits = denoised[header_bit_count:header_bit_count + ghost_payload_bits_count]
            if len(payload_bits) < ghost_payload_bits_count:
                continue

            password_seed = _password_to_seed(key)
            unscrambled_payload = _scramble_bits(payload_bits, password_seed, reverse=True)

            clean_bits = header_bits + unscrambled_payload
            as_bytes = _bits_to_data(clean_bits)
            encrypted_payload = as_bytes[SPECTER_HEADER_SIZE:SPECTER_HEADER_SIZE + ghost_payload_bytes]
            return _ghost_decrypt(encrypted_payload, key)

    raise ValueError(
        "No SPECTER header found. Verify the cipher key (pattern/password) "
        "matches what was used for encoding."
    )


# ============================================================================
# 7. SPECTER DCT encode
# ============================================================================

def specter_dct_encode(
    image: Image.Image,
    data: bytes,
    steps: List[CipherStep],
    *,
    encrypt: bool = False,
    key: str = "",
    precondition: bool = True,
    redundancy: int = SPECTER_DCT_REDUNDANCY,
    strength: int = SPECTER_DCT_STRENGTH,
    output_path: Optional[str] = None,
) -> Image.Image:
    """Embed *data* into *image* using SPECTER DCT channel-hopping.

    Each payload bit is written to *redundancy* consecutive 8×8 DCT blocks
    (majority-voted at decode).  The cipher steps determine which DCT
    coefficient position to use for each block group.

    Parameters
    ----------
    image:
        Carrier PIL image.
    data:
        Payload bytes.
    steps:
        Channel-hopping pattern (determines embedding position cycling).
    encrypt:
        If True, XOR-encrypt the payload.
    key:
        XOR encryption key.
    precondition:
        If True, JPEG-compress-then-reload at QF 85 to stabilise DCT
        coefficients before embedding (matches JS ``preconditionImage``).
    redundancy:
        Number of DCT blocks per bit (odd for majority vote).  Default 5.
    strength:
        Quantization strength for DCT embedding.  Default 50.
    output_path:
        If given, save result to this PNG path.

    Returns
    -------
    Image.Image
        The stego image.
    """
    if not steps:
        raise ValueError("at least one CipherStep is required")
    if redundancy < 1:
        raise ValueError("redundancy must be >= 1")

    img = image.convert("RGBA")

    # --- precondition -------------------------------------------------------
    if precondition:
        buf = io.BytesIO()
        img.convert("RGB").save(buf, format="JPEG", quality=85)
        buf.seek(0)
        img = Image.open(buf).convert("RGBA")

    # --- prepare payload ----------------------------------------------------
    if encrypt:
        if not key:
            raise ValueError("encryption requires a key")
        encrypted = _xor_cipher(data, key)
        flags = 1
    else:
        encrypted = data
        flags = 0

    # --- build DCT header (16 bytes) ----------------------------------------
    header = bytearray(SPECTER_DCT_HEADER_SIZE)
    header[0:4] = SPECTER_DCT_MAGIC
    struct.pack_into(">I", header, 4, len(data))
    header[8] = len(steps) & 0xFF
    header[9] = flags
    header[10] = redundancy & 0xFF
    header[11] = strength & 0xFF
    header[12] = 1 if precondition else 0
    # bytes 13-15 reserved

    full_payload = bytes(header) + encrypted

    # --- convert to bits ----------------------------------------------------
    bits = _data_to_bits(full_payload)
    block_size = 8

    pixels = np.array(img, dtype=np.uint8)
    height, width = pixels.shape[:2]

    blocks_x = width // block_size
    blocks_y = height // block_size
    total_blocks = blocks_x * blocks_y

    bit_groups = (len(bits) + redundancy - 1) // redundancy  # ceil division
    if bit_groups > total_blocks:
        raise ValueError(
            f"DCT capacity exceeded: need {bit_groups} block groups, "
            f"have {total_blocks} (image is {width}x{height})"
        )

    m = _dct_matrix(block_size)
    m_t = m.T

    # Determine embed positions from steps
    # We cycle through steps; each step contributes (bits * len(channels)) positions.
    # For simplicity, map step index → (row, col) within the 8x8 block.
    # Use a set of mid-frequency positions.
    _DCT_POSITIONS = [
        (0, 1), (1, 0), (1, 1), (0, 2), (2, 0),
        (1, 2), (2, 1), (2, 2), (0, 3), (3, 0),
    ]

    lum = _luminance(pixels)
    bit_idx = 0
    step_idx = 0
    num_steps = len(steps)

    for by in range(blocks_y):
        if bit_idx >= len(bits):
            break
        for bx in range(blocks_x):
            if bit_idx >= len(bits):
                break

            # Determine the DCT embed position from current step
            pos = _DCT_POSITIONS[step_idx % len(_DCT_POSITIONS)]
            cy, cx = pos

            y0 = by * block_size
            x0 = bx * block_size
            block = lum[y0:y0 + block_size, x0:x0 + block_size]

            dct_block = m @ block @ m_t
            coeff = dct_block[cy, cx]
            q = np.floor(coeff / strength)

            # Embed the same bit across all blocks in this group
            bit = bits[bit_idx]
            dct_block[cy, cx] = (q + (0.75 if bit else 0.25)) * strength

            reconstructed = m_t @ dct_block @ m
            new_lum = np.clip(reconstructed, 0.0, 255.0)

            with np.errstate(divide="ignore", invalid="ignore"):
                ratio = np.where(block > 0, new_lum / block, 1.0)

            for ch in range(3):
                scaled = pixels[y0:y0 + block_size, x0:x0 + block_size, ch].astype(
                    np.float64
                ) * ratio
                pixels[y0:y0 + block_size, x0:x0 + block_size, ch] = np.clip(
                    np.round(scaled), 0, 255
                ).astype(np.uint8)

            bit_idx += 1
            step_idx = (step_idx + 1) % num_steps

    result = Image.fromarray(pixels, "RGBA")
    if output_path:
        result.save(output_path, format="PNG", optimize=False)
    return result


# ============================================================================
# 8. SPECTER DCT decode
# ============================================================================

def specter_dct_decode(
    image: Image.Image,
    steps: List[CipherStep],
    *,
    key: str = "",
    redundancy: int = SPECTER_DCT_REDUNDANCY,
) -> bytes:
    """Recover data hidden by :func:`specter_dct_encode`.

    Parameters
    ----------
    image:
        The stego image.
    steps:
        The channel-hopping pattern used during encoding.
    key:
        XOR decryption key (if encryption was used).
    redundancy:
        Number of DCT blocks per bit.  Default 5.

    Returns
    -------
    bytes
        The recovered payload.
    """
    if not steps:
        raise ValueError("at least one CipherStep is required")
    if redundancy < 1:
        raise ValueError("redundancy must be >= 1")

    img = image.convert("RGBA")
    pixels = np.array(img, dtype=np.uint8)
    height, width = pixels.shape[:2]
    block_size = 8

    blocks_x = width // block_size
    blocks_y = height // block_size
    total_blocks = blocks_x * blocks_y

    m = _dct_matrix(block_size)
    m_t = m.T

    _DCT_POSITIONS = [
        (0, 1), (1, 0), (1, 1), (0, 2), (2, 0),
        (1, 2), (2, 1), (2, 2), (0, 3), (3, 0),
    ]

    lum = _luminance(pixels)

    # Extract raw coefficients
    coeffs = []
    for by in range(blocks_y):
        for bx in range(blocks_x):
            y0 = by * block_size
            x0 = bx * block_size
            block = lum[y0:y0 + block_size, x0:x0 + block_size]
            dct_block = m @ block @ m_t
            coeffs.append(dct_block)

    if not coeffs:
        raise ValueError("image too small for DCT decoding")

    # Extract bits using the SAME position cycling as the encoder.
    # The encoder advances step_idx per block, cycling through len(steps).
    num_steps = len(steps)
    step_idx = 0
    extracted_bits: List[int] = []

    for dct_block in coeffs:
        pos = _DCT_POSITIONS[step_idx % len(_DCT_POSITIONS)]
        cy, cx = pos
        coeff = dct_block[cy, cx]
        # Use strength=50 for extraction (the default)
        strength = SPECTER_DCT_STRENGTH
        q = np.floor(coeff / strength)
        remainder = coeff - q * strength
        bit = 1 if remainder >= strength / 2 else 0
        extracted_bits.append(bit)
        step_idx = (step_idx + 1) % num_steps

    # Now search for the RDCT magic by trying different alignments
    # The bits are embedded sequentially across blocks
    as_bytes = _bits_to_data(extracted_bits)

    # Search for magic in the byte stream
    magic_pos = as_bytes.find(SPECTER_DCT_MAGIC)
    if magic_pos == -1:
        raise ValueError("no SPECTER DCT header (RDCT magic) found")

    # Parse header at magic_pos
    if magic_pos + SPECTER_DCT_HEADER_SIZE > len(as_bytes):
        raise ValueError("truncated SPECTER DCT header")

    hdr = as_bytes[magic_pos:magic_pos + SPECTER_DCT_HEADER_SIZE]
    payload_len = struct.unpack(">I", hdr[4:8])[0]
    flags = hdr[9]

    payload_start = magic_pos + SPECTER_DCT_HEADER_SIZE
    payload_end = payload_start + payload_len
    if payload_end > len(as_bytes):
        raise ValueError("truncated SPECTER DCT payload")

    payload = as_bytes[payload_start:payload_end]

    if flags == 1:  # XOR encrypted
        if not key:
            raise ValueError("encrypted payload requires a decryption key")
        return _xor_cipher(payload, key)

    return payload


# ============================================================================
# 9. Detection tool
# ============================================================================

# Common patterns to try during detection
_DETECTION_PATTERNS = [
    "R1-G1-B1",
    "R2-G2-B2",
    "R1-G2-B1",
    "R2-G1-B2",
    "R1-G1-B2",
    "R2-G1-B1",
    "R1-R2-B1",
    "RG1-B1",
    "RGB1",
    "R1-G1",
    "R2",
]


def specter_detect(
    image: Image.Image,
    passwords: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Try common SPECTER patterns against *image*.

    Checks for GODM / GODP magic bytes in LSB-embedded data across 11
    common manual patterns.  If *passwords* is provided, also tries
    password-derived patterns (up to 5 passwords).

    Returns a dict suitable for the ``analysis_tools`` registry::

        {
            "found": bool,
            "findings": [{"pattern": str, "magic": str, "payload_len": int}, ...],
        }
    """
    findings: List[Dict[str, Any]] = []

    # Try manual patterns
    for pattern_str in _DETECTION_PATTERNS:
        steps = parse_pattern(pattern_str)
        if steps is None:
            continue
        try:
            raw_bits = _extract_bits_for_detect(image, steps)
            as_bytes = _bits_to_data(raw_bits)
            if len(as_bytes) >= 4:
                magic = as_bytes[:4]
                if magic in (SPECTER_MAGIC_NORMAL, SPECTER_MAGIC_GHOST):
                    payload_len = struct.unpack(">I", as_bytes[4:8])[0] if len(as_bytes) >= 8 else 0
                    findings.append({
                        "pattern": pattern_str,
                        "magic": magic.decode("ascii", errors="replace"),
                        "payload_len": min(payload_len, 10_000_000),
                        "flags": as_bytes[9] if len(as_bytes) > 9 else 0,
                    })
        except Exception:
            continue

    # Try password-derived patterns
    if passwords:
        for pwd in passwords[:5]:
            try:
                steps = pattern_from_password(pwd)
                raw_bits = _extract_bits_for_detect(image, steps)
                as_bytes = _bits_to_data(raw_bits)
                if len(as_bytes) >= 4:
                    magic = as_bytes[:4]
                    if magic in (SPECTER_MAGIC_NORMAL, SPECTER_MAGIC_GHOST):
                        payload_len = struct.unpack(">I", as_bytes[4:8])[0] if len(as_bytes) >= 8 else 0
                        findings.append({
                            "pattern": f"password:{pwd}",
                            "magic": magic.decode("ascii", errors="replace"),
                            "payload_len": min(payload_len, 10_000_000),
                            "flags": as_bytes[9] if len(as_bytes) > 9 else 0,
                        })
            except Exception:
                continue

    return {
        "found": len(findings) > 0,
        "findings": findings,
    }


def _extract_bits_for_detect(image: Image.Image, steps: List[CipherStep]) -> List[int]:
    """Quick bit extraction at density=100 for detection scanning."""
    img = image.convert("RGBA")
    pixels = np.array(img, dtype=np.uint8)
    height, width = pixels.shape[:2]
    total_pixels = height * width
    flat = pixels.reshape(-1, 4)

    bits: List[int] = []
    step_idx = 0
    num_steps = len(steps)

    for pix_idx in range(total_pixels):
        step = steps[step_idx]
        for ch in step.channels:
            for b_off in range(step.bits):
                bit_val = (flat[pix_idx, ch] >> b_off) & 1
                bits.append(bit_val)
                # Stop early — enough for header detection
                if len(bits) >= 4096:
                    return bits
        step_idx = (step_idx + 1) % num_steps

    return bits
