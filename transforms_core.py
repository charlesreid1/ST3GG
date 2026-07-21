"""Pure text transforms — change the form of text without encoding or hiding.

These are NOT stego methods. They transform a string into a different string
in a reversible (or at least recoverable) way. Used by jailbreak composition
for pre-obfuscation (see ``compose_text_jailbreak`` /
``compose_unicode_tag_jailbreak``) and by the CLI/TUI for user-facing text
effects.

Transport survivability
-----------------------
Every transform has a canonical form some transport will normalize it to. When
adding a new transform, document which channels it survives and which
canonicalize it away — this metadata will eventually drive channel-aware
obfuscation selection ("give me a chain that survives Slack"). See
``st3ggmcp/TRANSPORT_MATRIX.md`` for the current terrain map.

Extension
---------
New transforms register themselves via ``_register()``. The dispatch table
``_TRANSFORMS`` is what the ``obfuscation`` parameter on the jailbreak
composers looks up by name.

The ``obfuscation`` interface is v1 (``List[str]``). When keyed transforms
arrive (Caesar shift, Vigenère key, zalgo intensity...) it can grow into a
list of ``(name, kwargs)`` tuples in v2 — the composer surface should be the
only place that needs to change.
"""

from __future__ import annotations

import random
from typing import Callable, Dict


# ============== zalgo ==============

ZALGO_CHARS = {
    'above': [
        '̀', '́', '̂', '̃', '̄', '̅', '̆', '̇',
        '̈', '̉', '̊', '̋', '̌', '̍', '̎', '̏',
        '̐', '̑', '̒', '̓', '̔', '̕', '̚', '̛',
        '̽', '̾', '̿', '̀', '́', '͂', '̓', '̈́',
        '͆', '͊', '͋', '͌', '͐', '͑', '͒', '͗',
        '͛', 'ͣ', 'ͤ', 'ͥ', 'ͦ', 'ͧ', 'ͨ', 'ͩ',
        'ͪ', 'ͫ', 'ͬ', 'ͭ', 'ͮ', 'ͯ'
    ],
    'below': [
        '̖', '̗', '̘', '̙', '̜', '̝', '̞', '̟',
        '̠', '̡', '̢', '̣', '̤', '̥', '̦', '̧',
        '̨', '̩', '̪', '̫', '̬', '̭', '̮', '̯',
        '̰', '̱', '̲', '̳', '̹', '̺', '̻', '̼',
        'ͅ', '͇', '͈', '͉', '͍', '͎', '͓', '͔',
        '͕', '͖', '͙', '͚', '͜', '͟', '͢'
    ],
    'middle': [
        '̴', '̵', '̶', '̷', '̸', '͘'
    ],
}


def zalgo_text(text: str, intensity: int = 3) -> str:
    """Convert text to Zalgo (glitchy) form by stacking combining marks.

    Transport survivability: survives most channels (Slack, Discord, raw HTTP,
    email, GitHub). Dies under aggressive combining-mark stripping and under
    terminal mouse-copy (which yields the visible glyph stream only).
    """
    result = []
    for char in text:
        result.append(char)
        if char.isalnum():
            for _ in range(random.randint(0, intensity)):
                result.append(random.choice(ZALGO_CHARS['above']))
            for _ in range(random.randint(0, intensity)):
                result.append(random.choice(ZALGO_CHARS['below']))
            for _ in range(random.randint(0, max(1, intensity // 2))):
                result.append(random.choice(ZALGO_CHARS['middle']))
    return ''.join(result)


# ============== leetspeak ==============

def leetspeak(text: str, intensity: int = 2) -> str:
    """Convert text to leetspeak (digit/symbol letter substitutions).

    Transport survivability: universal. Pure ASCII output, survives every
    transport including NFKC normalization.
    """
    basic = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
    moderate = {**basic, 'b': '8', 'g': '9', 'l': '1', 'z': '2'}
    heavy = {**moderate, 'c': '(', 'd': '|)', 'h': '|-|', 'k': '|<', 'n': '|\\|',
             'u': '|_|', 'v': '\\/', 'w': '\\/\\/', 'x': '><', 'y': '`/'}
    mappings = [basic, moderate, heavy][min(intensity, 3) - 1]

    result = []
    for char in text:
        lower = char.lower()
        if lower in mappings and random.random() < 0.7:
            result.append(mappings[lower])
        else:
            result.append(char)
    return ''.join(result)


# ============== fullwidth ==============

def fullwidth_text(text: str) -> str:
    """Map printable ASCII to fullwidth equivalents (U+FF01–U+FF5E).

    Characters 0x21–0x7E shift by +0xFEE0. Space (0x20) maps to U+3000.
    Everything else passes through unchanged.

    Transport survivability: survives Slack, Discord, raw HTTP, email, GitHub.
    Dies under NFKC normalization (U+FF01 → ASCII `!`), which many search
    boxes, some database columns, and some LLM tokenizers apply.
    """
    result = []
    for ch in text:
        cp = ord(ch)
        if 0x21 <= cp <= 0x7E:
            result.append(chr(cp + 0xFEE0))
        elif cp == 0x20:
            result.append('　')
        else:
            result.append(ch)
    return ''.join(result)


# ============== Registry ==============

_TRANSFORMS: Dict[str, Callable[..., str]] = {}


def _register(
    name: str,
    fn: Callable[..., str],
    *,
    reversible: bool = True,
    category: str = "format",
) -> None:
    """Register a text transform for use by the obfuscation pipeline.

    ``category`` anticipates the P4RS3LT0NGV3 category system (cipher,
    encoding, unicode, format, case, visual, ...) and leaves room for
    category-based dispatch later. ``reversible`` distinguishes transforms
    that can be undone (fullwidth → unfullwidth) from those that can't
    (random shuffle); not used today but future jailbreak detection and
    decoder logic will need it.
    """
    _TRANSFORMS[name] = fn


def get_transform(name: str) -> Callable[..., str]:
    """Look up a registered transform by name. Raises KeyError if unknown."""
    return _TRANSFORMS[name]


def list_transforms() -> list:
    """List registered transform names."""
    return list(_TRANSFORMS.keys())


# Built-in registrations. Each new transform added here (or in a downstream
# module that imports transforms_core) should call _register().
_register("zalgo", zalgo_text, reversible=True, category="format")
_register("fullwidth", fullwidth_text, reversible=True, category="format")
_register("leetspeak", leetspeak, reversible=True, category="format")
