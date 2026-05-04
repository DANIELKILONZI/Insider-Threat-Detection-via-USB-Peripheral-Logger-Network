"""
tests/test_verify_chain.py – Unit tests for the audit chain verifier CLI.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest

from tools.verify_chain import _compute_hash, verify_chain, _load_from_file


_GENESIS = "0" * 64


def _make_record(prev_hash: str, device_id: str) -> dict:
    rec = {
        "prev_hash": prev_hash,
        "event": {"device_id": device_id, "hostname": "ws-01"},
    }
    rec["record_hash"] = _compute_hash(rec)
    return rec


def _build_chain(n: int) -> list[dict]:
    records = []
    prev = _GENESIS
    for i in range(n):
        rec = _make_record(prev, f"dead:{i:04x}")
        records.append(rec)
        prev = rec["record_hash"]
    return records


class TestVerifyChain:
    def test_empty_chain_is_valid(self):
        assert verify_chain([]) == []

    def test_valid_chain(self):
        records = _build_chain(10)
        errors = verify_chain(records)
        assert errors == []

    def test_tampered_event_detected(self):
        records = _build_chain(5)
        # Tamper with the event payload in record 2
        records[2]["event"]["device_id"] = "ffff:ffff"
        errors = verify_chain(records)
        assert any("tampered" in e for e in errors)

    def test_modified_hash_detected(self):
        records = _build_chain(5)
        records[3]["record_hash"] = "a" * 64  # corrupt the stored hash
        errors = verify_chain(records)
        assert errors  # prev_hash mismatch on record 4 AND hash mismatch on record 3

    def test_deleted_record_detected(self):
        """Removing a record from the middle breaks the chain."""
        records = _build_chain(5)
        del records[2]
        errors = verify_chain(records)
        assert any("gap" in e or "mismatch" in e for e in errors)

    def test_single_valid_record(self):
        records = _build_chain(1)
        assert verify_chain(records) == []


class TestLoadFromFile:
    def test_load_valid_file(self, tmp_path):
        records = _build_chain(3)
        log_file = tmp_path / "agent.log"
        with open(log_file, "w") as fh:
            for rec in records:
                fh.write(json.dumps(rec) + "\n")
        loaded = _load_from_file(str(log_file))
        assert len(loaded) == 3
        assert verify_chain(loaded) == []

    def test_load_skips_blank_lines(self, tmp_path):
        records = _build_chain(2)
        log_file = tmp_path / "agent.log"
        with open(log_file, "w") as fh:
            fh.write(json.dumps(records[0]) + "\n")
            fh.write("\n")  # blank line
            fh.write(json.dumps(records[1]) + "\n")
        loaded = _load_from_file(str(log_file))
        assert len(loaded) == 2

    def test_load_nonexistent_file_exits(self, tmp_path):
        with pytest.raises(SystemExit) as exc_info:
            _load_from_file(str(tmp_path / "no_such_file.log"))
        assert exc_info.value.code == 2
