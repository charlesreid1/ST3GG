"""detect_file_type across common magic-byte signatures."""

from __future__ import annotations

import pytest

from analysis_tools import FileType, detect_file_type

CASES = [
    # (label, header_bytes, expected FileType)
    ("PNG",    b"\x89PNG\r\n\x1a\n" + b"\x00" * 32,           FileType.PNG),
    ("JPEG",   b"\xff\xd8\xff\xe0" + b"\x00" * 32,             FileType.JPEG),
    ("GIF87a", b"GIF87a" + b"\x00" * 32,                       FileType.GIF),
    ("GIF89a", b"GIF89a" + b"\x00" * 32,                       FileType.GIF),
    ("BMP",    b"BM" + b"\x00" * 32,                           FileType.BMP),
    ("WAV",    b"RIFF\x00\x00\x00\x00WAVEfmt ",                FileType.WAV),
    ("AVI",    b"RIFF\x00\x00\x00\x00AVI LIST",                FileType.AVI),
    ("WEBP",   b"RIFF\x00\x00\x00\x00WEBPVP8 ",                FileType.WEBP),
    ("MP3",    b"ID3\x00\x00\x00\x00\x00" + b"\x00" * 32,      FileType.MP3),
    ("FLAC",   b"fLaC" + b"\x00" * 32,                         FileType.FLAC),
    ("OGG",    b"OggS" + b"\x00" * 32,                         FileType.OGG),
    ("PDF",    b"%PDF-1.4\n" + b"\x00" * 32,                   FileType.PDF),
    ("ZIP",    b"PK\x03\x04" + b"\x00" * 32,                   FileType.ZIP),
    ("RAR",    b"Rar!\x1a\x07" + b"\x00" * 32,                 FileType.RAR),
    ("GZIP",   b"\x1f\x8b\x08" + b"\x00" * 32,                 FileType.GZIP),
    ("MIDI",   b"MThd" + b"\x00" * 32,                         FileType.MIDI),
    ("SQLITE", b"SQLite format 3\x00" + b"\x00" * 32,          FileType.SQLITE),
    ("PCAP",   b"\xa1\xb2\xc3\xd4" + b"\x00" * 32,             FileType.PCAP),
]


@pytest.mark.parametrize("label,header,expected", CASES, ids=[c[0] for c in CASES])
def test_detect_file_type_from_magic(label, header, expected):
    assert detect_file_type(header) is expected


def test_detect_unknown_returns_unknown():
    assert detect_file_type(b"\x00" * 32) is FileType.UNKNOWN


def test_detect_short_input_returns_unknown():
    assert detect_file_type(b"\x00") is FileType.UNKNOWN


def test_detect_tiff():
    assert detect_file_type(b"II\x2a\x00" + b"\x00" * 32) is FileType.TIFF
    assert detect_file_type(b"MM\x00\x2a" + b"\x00" * 32) is FileType.TIFF


def test_detect_aiff():
    assert detect_file_type(b"FORM\x00\x00\x00\x08AIFFCOMM") is FileType.AIFF


def test_detect_svg_by_content():
    assert detect_file_type(b'<?xml version="1.0"?><svg xmlns="...">') is FileType.SVG


def test_office_vs_zip_disambiguation():
    # A zip whose contents contain [Content_Types].xml is an Office doc.
    office_data = b"PK\x03\x04" + b"\x00" * 100 + b"[Content_Types].xml" + b"\x00" * 100
    assert detect_file_type(office_data) is FileType.OFFICE
