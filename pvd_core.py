"""Pixel Value Differencing (PVD) steganography for images.

Port of the textbook Wu & Tsai (2003) PVD algorithm implemented in the
HTML/JS UI at ``index.html`` (see the ``pvdEncode`` / ``pvdDecode`` block
around line 8411). The Python behaviour is bit-identical to the JS
version for the ``wu-tsai``, ``wide``, and ``narrow`` range tables so
messages encoded in one can be decoded in the other.

Algorithm summary
-----------------
Given a pixel pair (p1, p2) in a colour channel:

    diff        = p1 - p2                                    (signed)
    range       = the bucket (lower, upper, bits) that contains |diff|
    embed_value = the next ``range.bits`` message bits, MSB first
    new_diff    = lower + embed_value                        (magnitude)
    signed_new  = new_diff if diff >= 0 else -new_diff
    delta       = signed_new - diff                          (how much to shift the pair)

The delta is split between p1 (+ceil(delta/2)) and p2 (-floor(delta/2))
so the pair mean is approximately preserved. If either pixel lands
outside [0, 255], the overflow is transferred to the other pixel so
that the target difference is preserved exactly (a final clamp guards
against edge cases where both pixels would need to move out of range).

Payload framing: 32-bit big-endian length prefix followed by the raw
payload bytes. No compression, no magic bytes -- matches the JS side.

Traversal: horizontal pairs walk row-major as ``(col, col+1)`` for
``col in 0, 2, 4, ...`` per row; vertical pairs walk column-major as
``(row, row+1)`` for ``row in 0, 2, 4, ...``. ``both`` runs horizontal
first then vertical, with the bit stream continuing across the seam.

.. warning::
    ``direction='both'`` inherits a subtle bug from the JS
    implementation: horizontal embedding mutates pixels that the
    vertical pass then re-reads, so when a payload spills into the
    vertical pass the diffs seen at decode differ from the diffs the
    encoder used, and decode fails. Capacity is therefore capped at
    the max of the horizontal-only and vertical-only capacities.
    ``both`` is preserved for cross-compatibility with existing JS
    artifacts; new hides should prefer ``horizontal`` or ``vertical``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, List, Sequence, Tuple

import numpy as np
from PIL import Image


# ---------------------------------------------------------------------------
# Range tables (identical to the JS ``PVD_RANGES`` object)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PvdRange:
    lower: int
    upper: int
    bits: int


PVD_RANGES: dict[str, Tuple[PvdRange, ...]] = {
    "wu-tsai": (
        PvdRange(0, 7, 3),
        PvdRange(8, 15, 3),
        PvdRange(16, 31, 4),
        PvdRange(32, 63, 5),
        PvdRange(64, 127, 6),
        PvdRange(128, 255, 7),
    ),
    "wide": (
        PvdRange(0, 15, 4),
        PvdRange(16, 47, 5),
        PvdRange(48, 111, 6),
        PvdRange(112, 255, 7),
    ),
    "narrow": (
        PvdRange(0, 3, 2),
        PvdRange(4, 7, 2),
        PvdRange(8, 15, 3),
        PvdRange(16, 31, 4),
        PvdRange(32, 63, 5),
        PvdRange(64, 127, 6),
        PvdRange(128, 255, 7),
    ),
}


def find_pvd_range(diff: int, ranges: Sequence[PvdRange]) -> PvdRange:
    """Return the bucket whose [lower, upper] contains ``|diff|``.

    Falls back to the last bucket if nothing matches (matches JS).
    """
    abs_diff = abs(diff)
    for r in ranges:
        if r.lower <= abs_diff <= r.upper:
            return r
    return ranges[-1]


# ---------------------------------------------------------------------------
# Pixel-pair traversal
# ---------------------------------------------------------------------------

def _horizontal_pairs(width: int, height: int) -> Iterator[Tuple[int, int]]:
    """(idx1, idx2) pairs for ``col, col+1`` walking row-major."""
    pairs_per_row = width // 2
    for row in range(height):
        base = row * width
        for k in range(pairs_per_row):
            col = k * 2
            yield base + col, base + col + 1


def _vertical_pairs(width: int, height: int) -> Iterator[Tuple[int, int]]:
    """(idx1, idx2) pairs for ``row, row+1`` walking column-major.

    Matches the JS iteration ``for i in 0..width*floor(h/2)``:
        col = i % width
        row = floor(i / width) * 2
    which visits ``(0,0)-(1,0), (0,1)-(1,1), ..., (0, w-1)-(1, w-1),
    (2,0)-(3,0), ...``.
    """
    row_pairs = height // 2
    for k in range(row_pairs):
        row = k * 2
        for col in range(width):
            yield row * width + col, (row + 1) * width + col


def _pair_iter(direction: str, width: int, height: int) -> Iterator[Tuple[int, int]]:
    if direction == "horizontal":
        yield from _horizontal_pairs(width, height)
    elif direction == "vertical":
        yield from _vertical_pairs(width, height)
    elif direction == "both":
        yield from _horizontal_pairs(width, height)
        yield from _vertical_pairs(width, height)
    else:
        raise ValueError(f"unknown direction '{direction}' (use horizontal|vertical|both)")


# ---------------------------------------------------------------------------
# Bit helpers
# ---------------------------------------------------------------------------

def _bytes_to_bits(data: bytes) -> List[int]:
    bits: List[int] = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: Sequence[int], length: int) -> bytes:
    out = bytearray(length)
    for i in range(length):
        byte = 0
        for b in range(8):
            idx = i * 8 + b
            if idx < len(bits):
                byte = (byte << 1) | (bits[idx] & 1)
            else:
                byte <<= 1
        out[i] = byte
    return bytes(out)


# ---------------------------------------------------------------------------
# Capacity
# ---------------------------------------------------------------------------

def capacity_bits(image: Image.Image, direction: str = "horizontal", range_type: str = "wu-tsai") -> int:
    """Upper-bound capacity in bits for the given carrier and settings.

    Iterates every pair (as the encoder does), sums the per-pair bit
    budgets for the R/G/B channels. Exact for the natural-diff carrier;
    embedding may reduce this slightly by moving pairs across bucket
    boundaries, but the header uses the natural diff so decode is safe.

    For ``direction='both'`` this reports the ``max`` of the horizontal
    and vertical pass capacities (not the sum) because the two passes
    are not independently decodable -- see the module docstring.
    """
    if range_type not in PVD_RANGES:
        raise ValueError(f"unknown range_type '{range_type}'")
    ranges = PVD_RANGES[range_type]
    rgb = np.asarray(image.convert("RGB"), dtype=np.int16)
    height, width = rgb.shape[:2]
    flat = rgb.reshape(-1, 3)

    def _sum(pairs):
        total = 0
        for idx1, idx2 in pairs:
            for c in range(3):
                diff = int(flat[idx1, c]) - int(flat[idx2, c])
                total += find_pvd_range(diff, ranges).bits
        return total

    if direction == "both":
        return max(_sum(_horizontal_pairs(width, height)), _sum(_vertical_pairs(width, height)))
    return _sum(_pair_iter(direction, width, height))


def capacity_bytes(image: Image.Image, direction: str = "horizontal", range_type: str = "wu-tsai") -> int:
    """Usable payload bytes (subtracts the 4-byte length header)."""
    bits = capacity_bits(image, direction=direction, range_type=range_type)
    return max(0, (bits // 8) - 4)


# ---------------------------------------------------------------------------
# Encode / decode
# ---------------------------------------------------------------------------

def encode(
    image: Image.Image,
    payload: bytes,
    direction: str = "horizontal",
    range_type: str = "wu-tsai",
) -> Image.Image:
    """Hide ``payload`` in ``image`` via PVD; return a new RGB PIL image.

    Raises ``ValueError`` if the payload does not fit.
    """
    if range_type not in PVD_RANGES:
        raise ValueError(f"unknown range_type '{range_type}'")
    if len(payload) > 0xFFFFFFFF:
        raise ValueError("payload too large for 32-bit length header")

    ranges = PVD_RANGES[range_type]
    header = len(payload).to_bytes(4, "big")
    bits = _bytes_to_bits(header + payload)

    rgb = np.asarray(image.convert("RGB"), dtype=np.int16).copy()
    height, width = rgb.shape[:2]
    flat = rgb.reshape(-1, 3)

    bit_index = 0
    total_bits = len(bits)

    for idx1, idx2 in _pair_iter(direction, width, height):
        if bit_index >= total_bits:
            break
        for c in range(3):
            if bit_index >= total_bits:
                break
            p1 = int(flat[idx1, c])
            p2 = int(flat[idx2, c])
            diff = p1 - p2
            r = find_pvd_range(diff, ranges)

            bits_to_embed = min(r.bits, total_bits - bit_index)
            embed_value = 0
            for _ in range(bits_to_embed):
                embed_value = (embed_value << 1) | bits[bit_index]
                bit_index += 1
            # Pad tail with zeros exactly like the JS side does.
            embed_value <<= (r.bits - bits_to_embed)

            new_diff = r.lower + embed_value
            signed_new_diff = new_diff if diff >= 0 else -new_diff
            delta = signed_new_diff - diff

            # ceil(delta/2) and floor(delta/2) that match Math.ceil / Math.floor
            # for negative numbers (round toward +/-infinity, not toward zero).
            if delta >= 0:
                inc1 = (delta + 1) // 2   # ceil
                dec2 = delta // 2         # floor
            else:
                inc1 = -((-delta) // 2)   # ceil of negative
                dec2 = -((-delta + 1) // 2)  # floor of negative

            new_p1 = p1 + inc1
            new_p2 = p2 - dec2

            # Shift both pixels back into [0,255] while preserving the diff.
            if new_p1 < 0:
                new_p2 += -new_p1
                new_p1 = 0
            if new_p2 < 0:
                new_p1 += -new_p2
                new_p2 = 0
            if new_p1 > 255:
                new_p2 -= new_p1 - 255
                new_p1 = 255
            if new_p2 > 255:
                new_p1 -= new_p2 - 255
                new_p2 = 255

            # Final safety clamp (matches JS).
            new_p1 = max(0, min(255, new_p1))
            new_p2 = max(0, min(255, new_p2))

            flat[idx1, c] = new_p1
            flat[idx2, c] = new_p2

    if bit_index < total_bits:
        # We exhausted the carrier before writing the whole payload.
        raise ValueError(
            f"payload does not fit: needed {total_bits} bits, embedded {bit_index}. "
            f"Try direction='both' or a wider range table."
        )

    encoded = rgb.astype(np.uint8)
    return Image.fromarray(encoded, mode="RGB")


def decode(
    image: Image.Image,
    direction: str = "horizontal",
    range_type: str = "wu-tsai",
    max_payload: int = 1_000_000,
) -> bytes:
    """Recover the payload hidden by :func:`encode`.

    Reads the 32-bit big-endian length header, then extracts the
    corresponding number of payload bytes. Raises ``ValueError`` when
    the header is missing or the reported length exceeds
    ``max_payload`` (matches the JS defensive cap of 1_000_000).
    """
    if range_type not in PVD_RANGES:
        raise ValueError(f"unknown range_type '{range_type}'")
    ranges = PVD_RANGES[range_type]

    rgb = np.asarray(image.convert("RGB"), dtype=np.int16)
    height, width = rgb.shape[:2]
    flat = rgb.reshape(-1, 3)

    bits: List[int] = []
    header_bits = 32
    length: int | None = None
    needed_bits = header_bits  # will grow once we've read the length

    for idx1, idx2 in _pair_iter(direction, width, height):
        if length is not None and len(bits) >= needed_bits:
            break
        for c in range(3):
            p1 = int(flat[idx1, c])
            p2 = int(flat[idx2, c])
            diff = abs(p1 - p2)
            r = find_pvd_range(diff, ranges)
            embed_value = diff - r.lower
            for b in range(r.bits - 1, -1, -1):
                bits.append((embed_value >> b) & 1)

            if length is None and len(bits) >= header_bits:
                length = 0
                for i in range(header_bits):
                    length = (length << 1) | bits[i]
                if length < 0 or length > max_payload:
                    raise ValueError(
                        f"invalid PVD length header: {length} "
                        f"(max_payload={max_payload}). Wrong direction or range table?"
                    )
                needed_bits = header_bits + length * 8

            if length is not None and len(bits) >= needed_bits:
                break

    if length is None:
        raise ValueError("carrier too small to contain a PVD length header")
    if len(bits) < 32 + length * 8:
        raise ValueError(
            f"carrier ran out of bits before payload finished: "
            f"got {len(bits)} bits, needed {32 + length * 8}"
        )

    payload_bits = bits[header_bits : header_bits + length * 8]
    return _bits_to_bytes(payload_bits, length)


__all__ = [
    "PVD_RANGES",
    "PvdRange",
    "capacity_bits",
    "capacity_bytes",
    "decode",
    "encode",
    "find_pvd_range",
]
