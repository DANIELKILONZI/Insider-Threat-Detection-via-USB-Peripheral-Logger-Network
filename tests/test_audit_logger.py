"""
tests/test_audit_logger.py – Unit tests for the agent's local audit logger.

Verifies that:
- Records are written as valid JSON lines.
- Each record carries a correct prev_hash → record_hash chain.
- Tampering with any record is detectable by replaying the chain.
- The chain can be resumed across logger instances (persistence).
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile

import pytest


# ---------------------------------------------------------------------------
# Fixture: redirect the audit logger's paths to a temp directory
# ---------------------------------------------------------------------------

@pytest.fixture()
def audit_logger(tmp_path, monkeypatch):
    """Return a freshly initialised LocalAuditLogger writing to *tmp_path*."""
    monkeypatch.setenv("ITDN_LOG_DIR", str(tmp_path))
    # Re-import so the config module picks up the patched env var
    import importlib
    import agent.config as cfg
    importlib.reload(cfg)
    import agent.logger as log_mod
    importlib.reload(log_mod)
    return log_mod.LocalAuditLogger()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

_GENESIS = "0" * 64


def _read_records(log_file: str) -> list[dict]:
    records = []
    with open(log_file, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                records.append(json.loads(line))
    return records


def _recompute_hash(record: dict) -> str:
    copy = {k: v for k, v in record.items() if k != "record_hash"}
    serialized = json.dumps(copy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode()).hexdigest()


def _verify_chain(records: list[dict]) -> bool:
    prev = _GENESIS
    for rec in records:
        if rec["prev_hash"] != prev:
            return False
        computed = _recompute_hash(rec)
        if computed != rec["record_hash"]:
            return False
        prev = rec["record_hash"]
    return True


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_single_write(audit_logger, tmp_path):
    event = {"event_type": "connected", "device_id": "1234:5678", "hostname": "ws-01"}
    record_hash = audit_logger.write(event)

    log_file = os.path.join(str(tmp_path), "agent.log")
    records = _read_records(log_file)
    assert len(records) == 1
    assert records[0]["record_hash"] == record_hash
    assert records[0]["prev_hash"] == _GENESIS
    assert records[0]["event"] == event


def test_chain_integrity_multiple_writes(audit_logger, tmp_path):
    events = [
        {"event_type": "connected", "device_id": f"dead:{i:04x}", "hostname": "ws-01"}
        for i in range(10)
    ]
    for e in events:
        audit_logger.write(e)

    log_file = os.path.join(str(tmp_path), "agent.log")
    records = _read_records(log_file)
    assert len(records) == 10
    assert _verify_chain(records), "Hash chain is broken"


def test_chain_head_property(audit_logger, tmp_path):
    e1 = {"event_type": "connected", "device_id": "aabb:ccdd", "hostname": "ws-02"}
    e2 = {"event_type": "disconnected", "device_id": "aabb:ccdd", "hostname": "ws-02"}
    audit_logger.write(e1)
    h2 = audit_logger.write(e2)
    assert audit_logger.chain_head == h2


def test_tamper_detection(audit_logger, tmp_path):
    """Modifying any stored record should break the chain when re-verified."""
    for i in range(5):
        audit_logger.write({"device_id": f"cafe:{i:04x}", "hostname": "ws-03"})

    log_file = os.path.join(str(tmp_path), "agent.log")
    records = _read_records(log_file)

    # Tamper with the second record's event payload
    records[1]["event"]["device_id"] = "ffff:ffff"

    assert not _verify_chain(records), "Tampered chain should fail verification"


def test_chain_resume_across_instances(tmp_path, monkeypatch):
    """A new logger instance should continue the chain from the existing log."""
    monkeypatch.setenv("ITDN_LOG_DIR", str(tmp_path))

    import importlib
    import agent.config as cfg
    importlib.reload(cfg)
    import agent.logger as log_mod
    importlib.reload(log_mod)

    logger1 = log_mod.LocalAuditLogger()
    h1 = logger1.write({"device_id": "1111:2222", "hostname": "ws-04"})

    # Create a second instance – should pick up the chain head
    importlib.reload(log_mod)
    logger2 = log_mod.LocalAuditLogger()
    h2 = logger2.write({"device_id": "3333:4444", "hostname": "ws-04"})

    log_file = os.path.join(str(tmp_path), "agent.log")
    records = _read_records(log_file)
    assert len(records) == 2
    assert records[1]["prev_hash"] == h1
    assert records[1]["record_hash"] == h2
    assert _verify_chain(records)
