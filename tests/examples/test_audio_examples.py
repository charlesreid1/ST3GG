"""Audio example decoding: WAV / AIFF / AU LSB."""

from __future__ import annotations

import struct
import wave

import pytest

from analysis_tools import detect_file_type


AUDIO_CASES = [
    ("example_audio_lsb.wav", "wav"),
    ("example_lsb.aiff", "aiff"),
    ("example_lsb.au", "au"),
    ("example_echo_hiding.wav", "wav"),
    ("example_phase_coding.wav", "wav"),
    ("example_spread_spectrum.wav", "wav"),
    ("example_quantization_noise.wav", "wav"),
    ("example_silence_interval.wav", "wav"),
]


@pytest.mark.parametrize("filename,expected", AUDIO_CASES, ids=[c[0] for c in AUDIO_CASES])
def test_audio_example_file_type(examples_dir, filename, expected):
    path = examples_dir / filename
    if not path.exists():
        pytest.skip(f"{filename} not present")
    detected = detect_file_type(path.read_bytes())
    assert detected.value == expected


def _decode_lsb_length_prefixed(bits, length_bits=32, max_msg_len=200):
    """Recover a UTF-8 message hidden by generate_examples.py's WAV/AIFF/AU
    convention: N-bit big-endian length prefix, then message body bit-packed."""
    length = 0
    for i in range(length_bits):
        length = (length << 1) | bits[i]
    if not 0 < length < max_msg_len:
        return None
    msg_bits = bits[length_bits:length_bits + length * 8]
    out = bytearray()
    for i in range(0, len(msg_bits), 8):
        v = 0
        for j in range(8):
            if i + j < len(msg_bits):
                v = (v << 1) | msg_bits[i + j]
        out.append(v)
    return out.decode("utf-8", errors="replace")


def test_wav_lsb_decodes_secret(examples_dir, original_secret):
    path = examples_dir / "example_audio_lsb.wav"
    with wave.open(str(path), "r") as w:
        frames = w.readframes(w.getnframes())
        samples = struct.unpack(f"<{w.getnframes()}h", frames)
    bits = [s & 1 for s in samples[:400]]
    decoded = _decode_lsb_length_prefixed(bits)
    assert decoded is not None
    assert original_secret[:20] in decoded


def test_aiff_annotation_holds_plinian(examples_dir, plinian):
    data = (examples_dir / "example_lsb.aiff").read_bytes()
    idx = data.find(b"ANNO")
    if idx < 0:
        pytest.skip("ANNO chunk missing from AIFF example")
    size = struct.unpack(">I", data[idx + 4:idx + 8])[0]
    text = data[idx + 8:idx + 8 + size].decode("utf-8", errors="replace")
    assert plinian[:10] in text


def test_au_annotation_holds_plinian(examples_dir, plinian):
    data = (examples_dir / "example_lsb.au").read_bytes()
    assert data[:4] == b".snd"
    header_size = struct.unpack(">I", data[4:8])[0]
    text = data[24:header_size].decode("utf-8", errors="replace").rstrip("\x00")
    assert plinian[:10] in text
