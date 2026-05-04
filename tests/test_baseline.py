"""Tests for device baseline profiler."""
from __future__ import annotations
from unittest.mock import MagicMock
from server.baseline import BaselineProfiler


def test_is_known_false_when_empty():
    mock_db = MagicMock()
    mock_db.get_device_baseline.return_value = []
    bp = BaselineProfiler(mock_db)
    assert bp.is_known("host1", "1234:5678") is False


def test_is_known_true_when_present():
    mock_db = MagicMock()
    mock_db.get_device_baseline.return_value = [
        {"device_id": "1234:5678", "hostname": "host1", "seen_count": 1}
    ]
    bp = BaselineProfiler(mock_db)
    assert bp.is_known("host1", "1234:5678") is True


def test_update_calls_db(full_client):
    import server.database as db
    db.update_device_baseline("testhost", "abcd:1234")
    rows = db.get_device_baseline("testhost")
    assert len(rows) == 1
    assert rows[0]["device_id"] == "abcd:1234"
    # Second update increments count
    db.update_device_baseline("testhost", "abcd:1234")
    rows = db.get_device_baseline("testhost")
    assert rows[0]["seen_count"] == 2
