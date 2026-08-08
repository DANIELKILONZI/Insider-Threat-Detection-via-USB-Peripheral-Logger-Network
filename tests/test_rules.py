"""
tests/test_rules.py – Unit tests for the anomaly detection rules engine.

All database calls are mocked so no real SQLite file is needed.
"""

from __future__ import annotations

import datetime
import types
from unittest.mock import MagicMock, patch

import pytest

from server.detection.rules import (
    Alert,
    evaluate,
    rule_after_hours_device,
    rule_high_volume_transfer,
    rule_rapid_cycle,
    rule_unknown_device,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(**kwargs) -> dict:
    defaults = {
        "event_type": "connected",
        "device_id": "1234:abcd",
        "hostname": "ws-01",
        "serial": "SN12345",
        "manufacturer": "Acme",
        "product": "Flash Drive",
        "timestamp": "2024-01-15T23:30:00Z",  # 23:30 UTC – after hours
        "transfer_bytes": 0,
    }
    defaults.update(kwargs)
    return defaults


def _mock_db(
    device_is_new: bool = False,
    recent_events: list | None = None,
    recent_alert=None,
) -> MagicMock:
    db = MagicMock()
    db.device_is_new.return_value = device_is_new
    db.get_recent_events.return_value = recent_events or []
    db.get_recent_alert.return_value = recent_alert
    return db


# ---------------------------------------------------------------------------
# rule_after_hours_device
# ---------------------------------------------------------------------------

class TestAfterHoursDevice:
    def test_fires_at_night(self):
        event = _make_event(timestamp="2024-01-15T23:30:00Z")
        result = rule_after_hours_device(event, _mock_db())
        assert result is not None
        assert result.rule_name == "after_hours_device"
        assert result.severity == "HIGH"

    def test_fires_early_morning(self):
        event = _make_event(timestamp="2024-01-15T03:00:00Z")
        result = rule_after_hours_device(event, _mock_db())
        assert result is not None

    def test_does_not_fire_during_business_hours(self):
        event = _make_event(timestamp="2024-01-15T14:00:00Z")  # 14:00 UTC
        result = rule_after_hours_device(event, _mock_db())
        assert result is None

    def test_ignores_disconnect_events(self):
        event = _make_event(event_type="disconnected", timestamp="2024-01-15T23:30:00Z")
        result = rule_after_hours_device(event, _mock_db())
        assert result is None

    def test_bad_timestamp_falls_back_gracefully(self):
        event = _make_event(timestamp="not-a-date")
        # Should not raise; result depends on actual current UTC time
        result = rule_after_hours_device(event, _mock_db())
        assert result is None or isinstance(result, Alert)


# ---------------------------------------------------------------------------
# rule_unknown_device
# ---------------------------------------------------------------------------

class TestUnknownDevice:
    def test_fires_for_new_device(self):
        db = _mock_db(device_is_new=True)
        event = _make_event()
        result = rule_unknown_device(event, db)
        assert result is not None
        assert result.rule_name == "unknown_device"
        assert result.severity == "MEDIUM"

    def test_does_not_fire_for_known_device(self):
        db = _mock_db(device_is_new=False)
        result = rule_unknown_device(_make_event(), db)
        assert result is None

    def test_ignores_disconnect(self):
        db = _mock_db(device_is_new=True)
        event = _make_event(event_type="disconnected")
        result = rule_unknown_device(event, db)
        assert result is None


# ---------------------------------------------------------------------------
# rule_high_volume_transfer
# ---------------------------------------------------------------------------

GB = 1024 ** 3


class TestHighVolumeTransfer:
    def test_fires_above_threshold(self):
        # Existing history: 0.9 GB; current event: 0.2 GB → total 1.1 GB > 1 GB
        row = MagicMock()
        row.__getitem__ = lambda self, key: 900 * 1024 * 1024 if key == "transfer_bytes" else ""
        db = _mock_db(recent_events=[row])
        event = _make_event(transfer_bytes=200 * 1024 * 1024)
        result = rule_high_volume_transfer(event, db)
        assert result is not None
        assert result.rule_name == "high_volume_transfer"
        assert result.severity == "CRITICAL"

    def test_does_not_fire_below_threshold(self):
        db = _mock_db(recent_events=[])
        event = _make_event(transfer_bytes=100 * 1024 * 1024)  # 100 MB
        result = rule_high_volume_transfer(event, db)
        assert result is None

    def test_skips_zero_transfer(self):
        db = _mock_db(recent_events=[])
        event = _make_event(transfer_bytes=0)
        result = rule_high_volume_transfer(event, db)
        assert result is None


# ---------------------------------------------------------------------------
# rule_rapid_cycle
# ---------------------------------------------------------------------------

class TestRapidCycle:
    def _make_row(self, etype: str) -> MagicMock:
        row = MagicMock()
        row.__getitem__ = lambda self, key: etype if key == "event_type" else ""
        return row

    def test_fires_at_threshold(self):
        # Threshold is 5 by default; provide 4 existing rows + 1 current = 5
        rows = [self._make_row("connected") for _ in range(4)]
        db = _mock_db(recent_events=rows)
        result = rule_rapid_cycle(_make_event(), db)
        assert result is not None
        assert result.rule_name == "rapid_cycle"

    def test_does_not_fire_below_threshold(self):
        rows = [self._make_row("connected") for _ in range(2)]
        db = _mock_db(recent_events=rows)
        result = rule_rapid_cycle(_make_event(), db)
        assert result is None


# ---------------------------------------------------------------------------
# evaluate (all rules)
# ---------------------------------------------------------------------------

class TestEvaluate:
    def test_returns_list(self):
        db = _mock_db()
        results = evaluate(_make_event(timestamp="2024-01-15T14:00:00Z"), db)
        assert isinstance(results, list)

    def test_multiple_rules_can_fire(self):
        # After-hours + unknown device should both fire
        db = _mock_db(device_is_new=True)
        event = _make_event(timestamp="2024-01-15T23:30:00Z")
        results = evaluate(event, db)
        rule_names = [r.rule_name for r in results]
        assert "after_hours_device" in rule_names
        assert "unknown_device" in rule_names

    def test_rule_exception_does_not_propagate(self):
        """If a rule raises, evaluate should swallow it and continue."""
        db = _mock_db()
        db.device_is_new.side_effect = RuntimeError("DB exploded")
        # Should not raise
        results = evaluate(_make_event(), db)
        assert isinstance(results, list)
