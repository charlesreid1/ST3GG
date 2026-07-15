#!/usr/bin/env python3
"""
🪆 Matryoshka Core — Recursive Nested-Image Steganography

Pure-library module with no webui coupling. Provides encode/decode for
Russian-nesting-doll steganography: hide a payload inside carrier N, then
hide that result inside carrier N+1, recursively up to the configured depth.

Exports:
    MatryoshkaConfig   — dataclass: channels, bits, password, max_depth, …
    LayerReport        — dataclass: per-layer encode metadata
    DecodeLayer        — dataclass: per-layer decode result
    encode_nested()    — recursive encode → (PIL.Image, list[LayerReport])
    decode_nested()    — recursive decode → list[DecodeLayer]
    capacity_for()     — usable byte capacity of an image for a given config
    plan_nesting()     — dry-run capacity walkthrough (no actual encoding)
    is_image_data()    — magic-byte sniff for PNG/JPEG/GIF/BMP
    extract_file_from_data() — unpack <len><name><body> file format

Design constraints:
    - MUST NOT import from webui.py.
    - smart_scan_hook is a module-level callable slot so tests (and
      webui.py) can inject a scan implementation without creating a
      hard dependency on the expensive smart_scan_image.
"""

from __future__ import annotations

import io
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from PIL import Image

import img_core
from img_core import (
    HEADER_SIZE,
    Channel,
    StegConfig,
    EncodingStrategy,
    create_config,
    encode,
    decode,
    detect_encoding,
)

# ---------------------------------------------------------------------------
# Optional crypto import (webui.py uses a hard import; we mirror that but
# guard against missing installations in library contexts).
# ---------------------------------------------------------------------------
try:
    import crypto as _crypto

    HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _crypto = None  # type: ignore[assignment]
    HAS_CRYPTO = False


# ============================================================================
# Smart-scan hook (injectable)
# ============================================================================

# Signature: (image: Image.Image, password: str | None) -> list[dict]
# Each dict should have keys: "name", "status", "raw_data"
smart_scan_hook: Optional[Callable[[Image.Image, Optional[str]], list]] = None


# ============================================================================
# Helpers
# ============================================================================

def _format_size(size_bytes: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


# ============================================================================
# Valid file extensions for extract_file_from_data
# ============================================================================

VALID_FILE_EXTENSIONS: set[str] = {
    # Images
    "png", "jpg", "jpeg", "gif", "bmp", "webp", "ico", "svg", "tiff", "tif",
    # Documents
    "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "rtf",
    # Code
    "py", "js", "ts", "html", "css", "json", "xml", "yaml", "yml", "md", "csv",
    "java", "c", "cpp", "h", "hpp", "rs", "go", "rb", "php", "sh", "bash",
    # Archives
    "zip", "tar", "gz", "bz2", "7z", "rar",
    # Media
    "mp3", "mp4", "wav", "avi", "mkv", "mov", "flac", "ogg",
    # Other
    "bin", "dat", "exe", "dll", "so", "key", "pem", "crt",
}

_TEXT_PREVIEW_EXTENSIONS: set[str] = {
    "txt", "md", "json", "xml", "html", "css", "js", "py", "csv",
}


# ============================================================================
# Dataclasses
# ============================================================================

@dataclass
class MatryoshkaConfig:
    """Configuration for a Matryoshka encode/decode operation.

    Attributes:
        channels: Channel preset string (e.g. ``"RGBA"``, ``"RGB"``).
        bits: Bits per channel (1-8).
        password: Optional encryption password (encrypts innermost payload only).
        max_depth: Maximum nesting depth for decode (default 11).
        per_layer_encrypt: If True, encrypt every layer, not just the innermost.
            Default False matches the historical webui behaviour.
    """

    channels: str = "RGBA"
    bits: int = 2
    password: Optional[str] = None
    max_depth: int = 11
    per_layer_encrypt: bool = False

    def to_steg_config(self) -> StegConfig:
        """Convert to an ``img_core.StegConfig``."""
        return create_config(channels=self.channels, bits=self.bits)


@dataclass
class LayerReport:
    """Per-layer metadata produced during an encode.

    Attributes:
        layer: 1-indexed layer number (1 = innermost).
        carrier_name: Original filename of the carrier image.
        capacity: Usable byte capacity of this carrier.
        payload_size: Size of the data encoded into this layer.
        fits: Whether the payload fit within capacity.
        output_size: Size of the PNG-serialised encoded image, or ``"final"``
            for the outermost layer.
    """

    layer: int
    carrier_name: str
    capacity: int
    payload_size: int
    fits: bool
    output_size: int | str = 0


@dataclass
class DecodeLayer:
    """Per-layer result produced during a decode.

    Attributes:
        depth: 0-indexed recursion depth (0 = outermost).
        type: One of ``"steg_header"``, ``"smart_scan_*"``, ``"no_data_found"``,
            ``"nested_image"``, ``"nested_image_raw"``, ``"file"``, ``"text"``,
            ``"binary"``, ``"max_depth_reached"``, ``"error"``.
        filename: Extracted filename if the payload follows the file convention.
        data_size: Size of the extracted payload in bytes.
        preview: Human-readable preview string.
        raw_data: The raw decoded bytes (may be None).
        nested: Nested ``DecodeLayer`` list when this layer contains another image.
    """

    depth: int = 0
    type: str = "unknown"
    filename: Optional[str] = None
    data_size: int = 0
    preview: str = ""
    raw_data: Optional[bytes] = None
    nested: List[DecodeLayer] = field(default_factory=list)


# ============================================================================
# Public helpers
# ============================================================================

def is_image_data(data: bytes) -> bool:
    """Return True if *data* looks like a supported image format.

    Checks magic bytes for PNG, JPEG, GIF, and BMP.
    """
    if len(data) < 8:
        return False
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return True
    if data[:2] == b"\xff\xd8":
        return True
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return True
    if data[:2] == b"BM":
        return True
    return False


def extract_file_from_data(data: bytes) -> Tuple[Optional[str], bytes]:
    """Unpack ``<length_byte><filename><body>`` file convention.

    Returns ``(filename, file_data)`` or ``(None, data)`` if the leading
    bytes do not match the expected file-wrap format.
    """
    if len(data) < 3:
        return (None, data)

    fname_len = data[0]

    # Filename length must be reasonable (3-100 chars)
    if fname_len < 3 or fname_len > 100:
        return (None, data)

    if len(data) < fname_len + 2:
        return (None, data)

    try:
        filename = data[1 : 1 + fname_len].decode("utf-8")
    except UnicodeDecodeError:
        return (None, data)

    if "." not in filename:
        return (None, data)
    if not re.match(r"^[\w\-. ]+$", filename):
        return (None, data)
    if filename[0] in ". ":
        return (None, data)

    ext = filename.rsplit(".", 1)[-1].lower()
    if ext not in VALID_FILE_EXTENSIONS:
        return (None, data)

    file_data = data[1 + fname_len :]
    return (filename, file_data)


def capacity_for(image: Image.Image, config: MatryoshkaConfig | None = None) -> int:
    """Return usable byte capacity of *image* for the given config.

    Uses the real ``HEADER_SIZE`` constant from ``img_core`` (32 bytes) as
    the header reserve, not the old 64-byte fudge.
    """
    if config is None:
        config = MatryoshkaConfig()
    w, h = image.size
    channels = len(config.channels)
    raw_capacity = (w * h * channels * config.bits) // 8
    return max(0, raw_capacity - HEADER_SIZE)


# ============================================================================
# Core encode / decode
# ============================================================================

def encode_nested(
    payload: bytes,
    carriers: List[Tuple[Image.Image, str]],
    config: MatryoshkaConfig | None = None,
    *,
    dry_run: bool = False,
) -> Tuple[Optional[Image.Image], List[LayerReport]]:
    """Recursively encode *payload* into a stack of carrier images.

    Args:
        payload: The secret data to hide (innermost).
        carriers: List of ``(PIL.Image, filename)`` tuples, **innermost first**.
        config: Encoding configuration.  Defaults to RGBA / 2-bit.
        dry_run: If True, perform capacity checks only and return
            ``(None, layer_reports)`` without producing an image.

    Returns:
        ``(final_image, layer_reports)`` where *final_image* is the
        outermost encoded PIL Image (or None when *dry_run* is True).

    Raises:
        ValueError: If *carriers* is empty, exceeds ``config.max_depth``,
            or any layer overflows capacity.
    """
    if config is None:
        config = MatryoshkaConfig()

    if not carriers:
        raise ValueError("At least one carrier image is required")

    if len(carriers) > config.max_depth:
        raise ValueError(
            f"Carrier count {len(carriers)} exceeds max_depth {config.max_depth}"
        )

    steg_cfg = config.to_steg_config()
    layer_reports: List[LayerReport] = []
    current_data = payload

    for i, (carrier_img, carrier_name) in enumerate(carriers):
        layer_num = i + 1
        cap = capacity_for(carrier_img, config)
        data_size = len(current_data)
        fits = data_size <= cap

        report = LayerReport(
            layer=layer_num,
            carrier_name=carrier_name,
            capacity=cap,
            payload_size=data_size,
            fits=fits,
        )
        layer_reports.append(report)

        if not fits:
            raise ValueError(
                f"Layer {layer_num} ({carrier_name}): "
                f"payload {data_size} bytes exceeds capacity {cap} bytes"
            )

        if dry_run:
            # Estimate output size as raw PNG of the carrier
            # (conservative: assume worst-case PNG expansion)
            w, h = carrier_img.size
            report.output_size = w * h * 4 + 1024  # RGBA raw + PNG overhead
            continue

        # Encrypt innermost payload only (historical behaviour)
        data_to_encode = current_data
        if config.password and (i == 0 or config.per_layer_encrypt):
            if HAS_CRYPTO:
                data_to_encode = _crypto.encrypt(current_data, config.password)  # type: ignore[union-attr]

        encoded_img = encode(carrier_img, data_to_encode, steg_cfg)

        if i < len(carriers) - 1:
            buf = io.BytesIO()
            encoded_img.save(buf, format="PNG")
            current_data = buf.getvalue()
            report.output_size = len(current_data)
        else:
            report.output_size = "final"  # type: ignore[assignment]

    if dry_run:
        return (None, layer_reports)

    return (encoded_img, layer_reports)


def decode_nested(
    image: Image.Image,
    config: MatryoshkaConfig | None = None,
    *,
    current_depth: int = 0,
) -> List[DecodeLayer]:
    """Recursively decode a Matryoshka-encoded image.

    Args:
        image: The image to decode (outermost layer).
        config: Decoding configuration.  Defaults to RGBA / 2-bit / max_depth=11.
        current_depth: Internal recursion counter.

    Returns:
        A (possibly nested) list of ``DecodeLayer`` objects.
    """
    if config is None:
        config = MatryoshkaConfig()

    results: List[DecodeLayer] = []

    if current_depth >= config.max_depth:
        results.append(DecodeLayer(
            depth=current_depth,
            type="max_depth_reached",
            preview=f"⚠️ Max depth ({config.max_depth}) reached",
        ))
        return results

    layer = DecodeLayer(depth=current_depth)

    try:
        # --- 1. Try primary decode via STEG header ---
        try:
            data = decode(image, None)
            layer.type = "steg_header"
        except Exception:
            # --- 2. Fallback: smart-scan ---
            data = None
            if smart_scan_hook is not None:
                scan_results = smart_scan_hook(image, config.password)
                best = None
                for r in scan_results:
                    if r.get("status") in ("STEG_DETECTED", "STEG_HEADER", "TEXT_FOUND"):
                        best = r
                        break
                if best and best.get("raw_data"):
                    data = best["raw_data"]
                    layer.type = f"smart_scan_{best.get('name', 'unknown')}"

            if data is None:
                layer.type = "no_data_found"
                layer.preview = "No hidden data detected"
                results.append(layer)
                return results

        # --- 3. Decrypt if password provided ---
        if config.password and HAS_CRYPTO:
            try:
                data = _crypto.decrypt(data, config.password)  # type: ignore[union-attr]
            except Exception:
                pass  # keep raw data on decrypt failure

        layer.data_size = len(data)
        layer.raw_data = data

        # --- 4. Try file extraction ---
        filename, file_data = extract_file_from_data(data)

        if filename:
            layer.filename = filename
            layer.data_size = len(file_data)
            layer.raw_data = file_data

            if is_image_data(file_data):
                layer.type = "nested_image"
                try:
                    nested_img = Image.open(io.BytesIO(file_data))
                    layer.nested = decode_nested(
                        nested_img,
                        config=config,
                        current_depth=current_depth + 1,
                    )
                    layer.preview = f"🪆 Found nested image: {filename}"
                except Exception as exc:
                    layer.preview = f"📁 Image file: {filename} (failed to recurse: {exc})"
            else:
                layer.type = "file"
                ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                if ext in _TEXT_PREVIEW_EXTENSIONS:
                    try:
                        layer.preview = file_data[:200].decode("utf-8")
                    except Exception:
                        layer.preview = f"📁 Binary file: {filename}"
                else:
                    layer.preview = f"📁 File: {filename} ({_format_size(len(file_data))})"
        else:
            # --- 5. Raw data — image or text/binary ---
            if is_image_data(data):
                layer.type = "nested_image_raw"
                try:
                    nested_img = Image.open(io.BytesIO(data))
                    layer.nested = decode_nested(
                        nested_img,
                        config=config,
                        current_depth=current_depth + 1,
                    )
                    layer.preview = "🪆 Found raw nested image data"
                except Exception as exc:
                    layer.preview = f"Image data (failed to recurse: {exc})"
            else:
                try:
                    text = data.decode("utf-8")
                    layer.type = "text"
                    layer.preview = text[:300]
                except Exception:
                    layer.type = "binary"
                    layer.preview = f"Binary data: {data[:50].hex()}..."

    except Exception as exc:
        layer.type = "error"
        layer.preview = f"Error: {exc}"

    results.append(layer)
    return results


# ============================================================================
# Capacity planning
# ============================================================================

def plan_nesting(
    payload_size: int,
    carriers: List[Tuple[Image.Image, str]],
    config: MatryoshkaConfig | None = None,
    *,
    mode: str = "estimate",
) -> List[LayerReport]:
    """Walk the carrier stack and predict whether each layer will fit.

    Args:
        payload_size: Size of the innermost payload in bytes.
        carriers: ``(image, name)`` tuples, innermost first.
        config: Encoding config.
        mode:
            - ``"estimate"`` — use ``W×H×4 + 1024`` as a PNG-size upper bound.
            - ``"exact"`` — actually encode + PNG-serialize each layer
              (slow but truthful).

    Returns:
        A list of ``LayerReport``, one per carrier.  The last report's
        ``output_size`` is always the string ``"final"``.
    """
    if config is None:
        config = MatryoshkaConfig()

    if mode == "exact":
        # Delegate to encode_nested with dry_run=False but stop one short
        return _plan_exact(payload_size, carriers, config)

    # --- estimate mode ---
    steg_cfg = config.to_steg_config()
    reports: List[LayerReport] = []
    simulated_size = payload_size

    for i, (carrier_img, carrier_name) in enumerate(carriers):
        layer_num = i + 1
        cap = capacity_for(carrier_img, config)
        fits = simulated_size <= cap

        report = LayerReport(
            layer=layer_num,
            carrier_name=carrier_name,
            capacity=cap,
            payload_size=simulated_size,
            fits=fits,
        )

        if not fits:
            report.output_size = 0
            reports.append(report)
            continue

        # Estimate PNG size of the encoded carrier
        w, h = carrier_img.size
        png_estimate = w * h * 4 + 1024  # RGBA raw pixels + PNG overhead

        if i < len(carriers) - 1:
            report.output_size = png_estimate
            simulated_size = png_estimate
        else:
            report.output_size = "final"  # type: ignore[assignment]

        reports.append(report)

    return reports


def _plan_exact(
    payload_size: int,
    carriers: List[Tuple[Image.Image, str]],
    config: MatryoshkaConfig,
) -> List[LayerReport]:
    """Exact-mode planning: actually encode each layer to measure PNG sizes."""
    steg_cfg = config.to_steg_config()
    reports: List[LayerReport] = []

    # Create a tiny dummy payload for the first layer
    dummy = b"\x00" * payload_size
    current_data = dummy

    for i, (carrier_img, carrier_name) in enumerate(carriers):
        layer_num = i + 1
        cap = capacity_for(carrier_img, config)
        data_size = len(current_data)
        fits = data_size <= cap

        report = LayerReport(
            layer=layer_num,
            carrier_name=carrier_name,
            capacity=cap,
            payload_size=data_size,
            fits=fits,
        )

        if not fits:
            report.output_size = 0
            reports.append(report)
            break

        # Actually encode to get real PNG size
        encoded_img = encode(carrier_img, current_data, steg_cfg)

        if i < len(carriers) - 1:
            buf = io.BytesIO()
            encoded_img.save(buf, format="PNG")
            current_data = buf.getvalue()
            report.output_size = len(current_data)
        else:
            report.output_size = "final"  # type: ignore[assignment]

        reports.append(report)

    return reports
