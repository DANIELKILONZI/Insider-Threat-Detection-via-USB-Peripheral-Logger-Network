"""Tests for cross-agent device correlation rule."""
from __future__ import annotations
from unittest.mock import MagicMock
from server.detection.rules import rule_cross_agent_device


def test_no_alert_when_device_only_on_one_host():
    mock_db = MagicMock()
    mock_db.get_recent_events_by_device.return_value = [
        {"hostname": "host1", "device_id": "1234:5678"}
    ]
    event = {"device_id": "1234:5678", "hostname": "host1"}
    result = rule_cross_agent_device(event, mock_db)
    assert result is None


def test_alert_when_device_on_multiple_hosts():
    mock_db = MagicMock()
    mock_db.get_recent_events_by_device.return_value = [
        {"hostname": "host1", "device_id": "1234:5678"},
        {"hostname": "host2", "device_id": "1234:5678"},
    ]
    event = {"device_id": "1234:5678", "hostname": "host1"}
    result = rule_cross_agent_device(event, mock_db)
    assert result is not None
    assert result.severity == "CRITICAL"
    assert "host2" in result.description


def test_no_alert_empty_device_id():
    mock_db = MagicMock()
    event = {"device_id": "", "hostname": "host1"}
    result = rule_cross_agent_device(event, mock_db)
    assert result is None
