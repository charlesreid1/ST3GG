"""
STEGOSAURUS WRECKS - PNG Chunk & Metadata I/O
Low-level PNG chunk (tEXt / zTXt / iTXt / private) manipulation and PIL
metadata injection. Also hosts small text-effect helpers (Zalgo, leetspeak).

Jailbreak template registries, filename generation, and payload composition
live in `jailbreak_core.py`. Backward-compat re-exports live at the bottom
of this module.
"""

import io
import random
import struct
import zlib
from typing import Dict, List, Optional, Tuple

from PIL import Image
from PIL.PngImagePlugin import PngInfo


# ============== PNG Chunk Manipulation ==============

def _make_chunk(chunk_type: bytes, data: bytes) -> bytes:
    """Create a PNG chunk with proper CRC"""
    chunk_len = struct.pack('>I', len(data))
    chunk_crc = struct.pack('>I', zlib.crc32(chunk_type + data) & 0xffffffff)
    return chunk_len + chunk_type + data + chunk_crc


def inject_text_chunk(image_data: bytes, keyword: str, text: str, compressed: bool = False) -> bytes:
    """Inject a tEXt or zTXt chunk into PNG data."""
    iend_pos = image_data.rfind(b'IEND')
    if iend_pos == -1:
        raise ValueError("Invalid PNG: IEND chunk not found")
    iend_pos -= 4  # include length field

    if compressed:
        chunk_type = b'zTXt'
        compressed_text = zlib.compress(text.encode('latin-1'))
        chunk_data = keyword.encode('latin-1') + b'\x00\x00' + compressed_text
    else:
        chunk_type = b'tEXt'
        chunk_data = keyword.encode('latin-1') + b'\x00' + text.encode('latin-1')

    new_chunk = _make_chunk(chunk_type, chunk_data)
    return image_data[:iend_pos] + new_chunk + image_data[iend_pos:]


def inject_itxt_chunk(image_data: bytes, keyword: str, text: str, language: str = "", translated_keyword: str = "") -> bytes:
    """Inject an iTXt (international text, UTF-8) chunk into PNG data."""
    iend_pos = image_data.rfind(b'IEND') - 4

    chunk_data = (
        keyword.encode('latin-1') + b'\x00' +
        b'\x00' +  # compression flag
        b'\x00' +  # compression method
        language.encode('latin-1') + b'\x00' +
        translated_keyword.encode('utf-8') + b'\x00' +
        text.encode('utf-8')
    )

    new_chunk = _make_chunk(b'iTXt', chunk_data)
    return image_data[:iend_pos] + new_chunk + image_data[iend_pos:]


def inject_private_chunk(image_data: bytes, chunk_type: str, data: bytes) -> bytes:
    """Inject a private/custom 4-character chunk into PNG data."""
    if len(chunk_type) != 4:
        raise ValueError("Chunk type must be exactly 4 characters")

    iend_pos = image_data.rfind(b'IEND') - 4
    new_chunk = _make_chunk(chunk_type.encode('latin-1'), data)
    return image_data[:iend_pos] + new_chunk + image_data[iend_pos:]


def read_png_chunks(image_data: bytes) -> List[Dict]:
    """Read all chunks from PNG data."""
    if image_data[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError("Invalid PNG signature")

    chunks: List[Dict] = []
    pos = 8
    while pos < len(image_data):
        length = struct.unpack('>I', image_data[pos:pos + 4])[0]
        chunk_type = image_data[pos + 4:pos + 8].decode('latin-1')
        chunk_data = image_data[pos + 8:pos + 8 + length]

        chunk_info: Dict = {
            "type": chunk_type,
            "length": length,
            "position": pos,
        }

        if chunk_type == 'tEXt':
            null_pos = chunk_data.find(b'\x00')
            chunk_info["keyword"] = chunk_data[:null_pos].decode('latin-1')
            chunk_info["text"] = chunk_data[null_pos + 1:].decode('latin-1')
        elif chunk_type == 'zTXt':
            null_pos = chunk_data.find(b'\x00')
            chunk_info["keyword"] = chunk_data[:null_pos].decode('latin-1')
            chunk_info["text"] = zlib.decompress(chunk_data[null_pos + 2:]).decode('latin-1')
        elif chunk_type == 'iTXt':
            null_pos = chunk_data.find(b'\x00')
            chunk_info["keyword"] = chunk_data[:null_pos].decode('latin-1')
            rest = chunk_data[null_pos + 1:]
            chunk_info["compressed"] = rest[0] == 1
            parts = rest[2:].split(b'\x00', 2)
            if len(parts) >= 3:
                chunk_info["language"] = parts[0].decode('latin-1')
                chunk_info["translated_keyword"] = parts[1].decode('utf-8', errors='replace')
                chunk_info["text"] = parts[2].decode('utf-8', errors='replace')

        chunks.append(chunk_info)
        pos += 12 + length
        if chunk_type == 'IEND':
            break
    return chunks


def extract_text_chunks(image_data: bytes) -> Dict[str, str]:
    """Extract all text chunks (keyword -> text) from PNG."""
    chunks = read_png_chunks(image_data)
    texts: Dict[str, str] = {}
    for chunk in chunks:
        if chunk["type"] in ('tEXt', 'zTXt', 'iTXt') and "keyword" in chunk:
            texts[chunk["keyword"]] = chunk.get("text", "")
    return texts


# ============== PIL-based Metadata Injection ==============

def inject_metadata_pil(
    image: Image.Image,
    metadata: Dict[str, str],
    output_path: Optional[str] = None,
) -> Tuple[Image.Image, bytes]:
    """Inject metadata into image using PIL's PngInfo."""
    png_info = PngInfo()
    for key, value in metadata.items():
        png_info.add_text(key, value)

    buffer = io.BytesIO()
    image.save(buffer, format="PNG", pnginfo=png_info)
    png_bytes = buffer.getvalue()

    if output_path:
        with open(output_path, 'wb') as f:
            f.write(png_bytes)
    return image, png_bytes


# ============== Glitch text effects ==============

ZALGO_CHARS = {
    'above': [
        '̀', '́', '̂', '̃', '̄', '̅', '̆', '̇',
        '̈', '̉', '̊', '̋', '̌', '̍', '̎', '̏',
        '̐', '̑', '̒', '̓', '̔', '̕', '̚', '̛',
        '̽', '̾', '̿', '̀', '́', '͂', '̓', '̈́',
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
    """Convert text to Zalgo (glitchy) form."""
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


def leetspeak(text: str, intensity: int = 2) -> str:
    """Convert text to leetspeak."""
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


# ============== Backward-compat re-exports ==============
# The jailbreak / prompt-injection surface moved to jailbreak_core.py.
# These re-exports keep existing importers working during the transition.

from jailbreak_core import (  # noqa: E402,F401
    INJECTION_FILENAME_TEMPLATES,
    INJECTION_TEMPLATES,
    JAILBREAK_TEMPLATES,
    InjectionFilenameTemplate,
    JailbreakTemplate,
    create_full_injection_package,
    generate_injection_filename,
    get_filename_template_info,
    get_filename_template_names,
    get_jailbreak_names,
    get_jailbreak_template,
)

# Aliases for the historical names.
InjectionTemplate = InjectionFilenameTemplate  # noqa: F401
get_template_names = get_filename_template_names  # noqa: F401
get_template_info = get_filename_template_info  # noqa: F401
