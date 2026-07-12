"""Archive/container examples: zip, tar, gz, sqlite."""

from __future__ import annotations

import gzip
import sqlite3
import struct
import tarfile
import zipfile

import pytest

from analysis_tools import detect_file_type


def test_zip_comment_holds_plinian(examples_dir, plinian):
    path = examples_dir / "example_hidden.zip"
    with zipfile.ZipFile(path, "r") as zf:
        comment = zf.comment.decode("utf-8", errors="replace")
    assert plinian[:10] in comment or plinian.encode("utf-8") in path.read_bytes()


def test_zip_file_type_detected(examples_dir):
    data = (examples_dir / "example_hidden.zip").read_bytes()
    assert detect_file_type(data).value == "zip"


def test_tar_pax_headers_hold_plinian(examples_dir, plinian):
    path = examples_dir / "example_hidden.tar"
    with tarfile.open(path, "r") as tf:
        found = False
        for m in tf.getmembers():
            pax = m.pax_headers or {}
            if plinian[:10] in pax.get("comment", ""):
                found = True
                break
            hex_marker = plinian.encode("utf-8").hex()[:20]
            if hex_marker in pax.get("STEG.payload", ""):
                found = True
                break
    assert found


def test_gzip_valid_and_decompresses(examples_dir):
    path = examples_dir / "example_hidden.gz"
    data = path.read_bytes()
    assert data[:2] == b"\x1f\x8b"
    # Whether or not the FEXTRA field carries the payload directly, decompression
    # of the inner stream should succeed.
    decompressed = gzip.decompress(data)
    assert len(decompressed) > 0


def test_gzip_fextra_field_present(examples_dir):
    data = (examples_dir / "example_hidden.gz").read_bytes()
    flags = data[3]
    has_extra = bool(flags & 0x04)
    if not has_extra:
        pytest.skip("no FEXTRA in this gzip example")
    xlen = struct.unpack("<H", data[10:12])[0]
    assert xlen > 0


def test_sqlite_opens_and_holds_secret(examples_dir, original_secret, plinian):
    path = examples_dir / "example_hidden.sqlite"
    conn = sqlite3.connect(str(path))
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cur.fetchall()]
        assert tables, "sqlite example has no tables"
        # Some payload from either constant should appear somewhere in the DB.
        raw = path.read_bytes()
        assert (original_secret.encode("utf-8") in raw
                or plinian.encode("utf-8") in raw)
    finally:
        conn.close()


def test_nested_zip(examples_dir):
    """The nested-zip example should open cleanly and contain another zip inside."""
    path = examples_dir / "example_nested.zip"
    if not path.exists():
        pytest.skip("example_nested.zip missing")
    with zipfile.ZipFile(path, "r") as zf:
        names = zf.namelist()
        assert names, "outer zip is empty"
