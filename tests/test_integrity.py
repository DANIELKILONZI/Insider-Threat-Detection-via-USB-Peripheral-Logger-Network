"""Tests for agent integrity checks."""
import hashlib
import os
import tempfile

import pytest

from agent.integrity import compute_binary_hash, verify_integrity


def test_compute_hash_known_file(tmp_path):
    f = tmp_path / "agent.py"
    f.write_bytes(b"print('hello')")
    h = compute_binary_hash(str(f))
    expected = hashlib.sha256(b"print('hello')").hexdigest()
    assert h == expected


def test_compute_hash_empty_file(tmp_path):
    f = tmp_path / "empty.py"
    f.write_bytes(b"")
    h = compute_binary_hash(str(f))
    assert h == hashlib.sha256(b"").hexdigest()


def test_compute_hash_missing_file():
    h = compute_binary_hash("/nonexistent/path/file.py")
    assert h == ""


def test_verify_integrity_match(tmp_path):
    f = tmp_path / "agent.py"
    f.write_bytes(b"real code")
    trusted = hashlib.sha256(b"real code").hexdigest()
    assert verify_integrity(trusted, str(f)) is True


def test_verify_integrity_mismatch(tmp_path):
    f = tmp_path / "agent.py"
    f.write_bytes(b"tampered code")
    trusted = hashlib.sha256(b"original code").hexdigest()
    assert verify_integrity(trusted, str(f)) is False


def test_verify_integrity_empty_trusted(tmp_path):
    f = tmp_path / "agent.py"
    f.write_bytes(b"some code")
    assert verify_integrity("", str(f)) is False
