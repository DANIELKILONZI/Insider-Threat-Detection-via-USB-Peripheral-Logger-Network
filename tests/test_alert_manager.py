"""
tests/test_alert_manager.py – Unit tests for alert deduplication logic.
"""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from server.rules import Alert


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(hostname="ws-01", device_id="1234:abcd"):
    return {"hostname": hostname, "device_id": device_id, "event_type": "connected"}


def _alert(**kwargs):
    defaults = dict(rule_name="after_hours_device", severity="HIGH", description="test alert")
    defaults.update(kwargs)
    return Alert(**defaults)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestProcessAlerts:
    @patch("server.alert_manager.splunk")
    @patch("server.alert_manager.db")
    def test_new_alert_is_persisted_and_forwarded(self, mock_db, mock_splunk):
        mock_db.get_recent_alert.return_value = None  # no existing alert
        mock_db.insert_alert.return_value = 42

        from server.alert_manager import process_alerts

        event = _event()
        alerts = [_alert()]
        process_alerts(event, alerts)

        mock_db.insert_alert.assert_called_once()
        mock_splunk.forward_alert.assert_called_once()
        call_kwargs = mock_db.insert_alert.call_args
        assert call_kwargs.kwargs["rule_name"] == "after_hours_device"

    @patch("server.alert_manager.splunk")
    @patch("server.alert_manager.db")
    def test_duplicate_alert_is_suppressed(self, mock_db, mock_splunk):
        mock_db.get_recent_alert.return_value = MagicMock()  # existing alert found

        from server.alert_manager import process_alerts

        process_alerts(_event(), [_alert()])

        mock_db.insert_alert.assert_not_called()
        mock_splunk.forward_alert.assert_not_called()

    @patch("server.alert_manager.splunk")
    @patch("server.alert_manager.db")
    def test_multiple_alerts_each_checked_independently(self, mock_db, mock_splunk):
        # First alert: duplicate; second alert: new
        mock_db.get_recent_alert.side_effect = [
            MagicMock(),  # first alert – duplicate
            None,         # second alert – new
        ]
        mock_db.insert_alert.return_value = 1

        from server.alert_manager import process_alerts

        alerts = [_alert(rule_name="after_hours_device"), _alert(rule_name="unknown_device")]
        process_alerts(_event(), alerts)

        assert mock_db.insert_alert.call_count == 1
        assert mock_splunk.forward_alert.call_count == 1
        inserted_rule = mock_db.insert_alert.call_args.kwargs["rule_name"]
        assert inserted_rule == "unknown_device"
