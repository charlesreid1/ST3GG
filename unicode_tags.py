"""Unicode Tag primitive (plane-14 U+E0000..U+E007F).

Shared low-level encoder/decoder for the Unicode Tag character block. Two
callers today:

  - ``text_core.encode_invisible_ink`` — general steg carrier. Framed with a
    ``U+E0000`` start sentinel and ``U+E007F`` terminator, spliced into a
    cover after ``cover[0]``. Accepts any ASCII byte 0x00..0x7F.
  - ``jailbreak_core.compose_unicode_tag_jailbreak`` — the 2025 "hidden
    emoji" prompt-injection technique. Restricts the payload to printable
    ASCII 0x20..0x7E, no start sentinel, terminator conventional, and the
    run is appended after a base emoji so the payload piggybacks on the
    emoji's grapheme cluster.

This module owns *only* the tag primitive. It knows nothing about covers,
jailbreak templates, or steg method dispatch.
"""

from __future__ import annotations


TAG_BASE = 0xE0000
TAG_END = 0xE007F  # CANCEL TAG — the terminator
TAG_PRINTABLE_LO = 0xE0020  # ' '
TAG_PRINTABLE_HI = 0xE007E  # '~'


class TagPayloadError(ValueError):
    """Raised when a payload cannot be encoded under the requested constraints."""


def encode_tag_run(secret: str, *,
                   printable_only: bool,
                   start_sentinel: bool,
                   terminator: bool) -> str:
    """Encode ASCII ``secret`` as a Unicode-tag run. Returns only the run.

    - ``printable_only``: raise :class:`TagPayloadError` on any byte outside
      0x20..0x7E. Otherwise accepts 0x00..0x7F (non-ASCII bytes are always
      rejected).
    - ``start_sentinel``: prepend ``U+E0000``.
    - ``terminator``: append ``U+E007F``.
    """
    parts = []
    if start_sentinel:
        parts.append(chr(TAG_BASE))
    for i, ch in enumerate(secret):
        code = ord(ch)
        if code > 0x7F:
            raise TagPayloadError(
                f"non-ASCII character {ch!r} (U+{code:04X}) at position {i}; "
                f"Unicode Tag payloads must be ASCII"
            )
        if printable_only and not (0x20 <= code <= 0x7E):
            raise TagPayloadError(
                f"non-printable byte 0x{code:02X} at position {i}; "
                f"printable ASCII only (0x20..0x7E) for prompt-injection payloads"
            )
        parts.append(chr(TAG_BASE + code))
    if terminator:
        parts.append(chr(TAG_END))
    return ''.join(parts)


def decode_tag_run(stego: str, *,
                   require_start_sentinel: bool,
                   stop_on_terminator: bool,
                   printable_only: bool) -> str:
    """Extract ASCII from a Unicode-tag run.

    - ``require_start_sentinel``: only begin collecting after seeing
      ``U+E0000``.
    - ``stop_on_terminator``: stop at ``U+E007F``.
    - ``printable_only``: skip tag codepoints outside
      ``U+E0020..U+E007E``.
    """
    result = []
    in_tag = not require_start_sentinel
    for ch in stego:
        code = ord(ch)
        if code == TAG_BASE:
            in_tag = True
            continue
        if code == TAG_END:
            if stop_on_terminator and in_tag:
                break
            continue
        if not in_tag:
            continue
        if printable_only:
            if TAG_PRINTABLE_LO <= code <= TAG_PRINTABLE_HI:
                result.append(chr(code - TAG_BASE))
        else:
            if TAG_BASE <= code < TAG_BASE + 128:
                result.append(chr(code - TAG_BASE))
    return ''.join(result)


def strip_tags(text: str) -> str:
    """Remove every ``U+E0000..U+E007F`` codepoint from ``text``.

    Useful for defenders sanitizing input before feeding it to a model.
    """
    return ''.join(ch for ch in text if not (TAG_BASE <= ord(ch) <= TAG_END))


def count_tags(text: str) -> int:
    """Count ``U+E0000..U+E007F`` codepoints in ``text``.

    Useful for detectors.
    """
    return sum(1 for ch in text if TAG_BASE <= ord(ch) <= TAG_END)
