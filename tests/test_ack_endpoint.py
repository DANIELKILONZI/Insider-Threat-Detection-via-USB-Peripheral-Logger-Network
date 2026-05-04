"""
tests/test_ack_endpoint.py – Tests for PATCH /api/v1/alerts/<id>/ack.
"""

from __future__ import annotations

import json

import pytest


def _make_event(**kwargs):
    defaults = {
        "event_type": "connected",
        "device_id": "1234:abcd",
        "hostname": "ws-ack-test",
        "serial": "SN001",
        "manufacturer": "Acme",
        "product": "Flash",
        "timestamp": "2024-01-15T23:30:00Z",  # after-hours → generates an alert
        "transfer_bytes": 0,
    }
    defaults.update(kwargs)
    return defaults


def _post_event(client, **kwargs):
    payload = {"events": [_make_event(**kwargs)]}
    return client.post(
        "/api/v1/events",
        data=json.dumps(payload),
        content_type="application/json",
    )


class TestAlertAck:
    def test_ack_existing_alert(self, full_client):
        """Acknowledging an alert should return 200 and set acknowledged=1."""
        _post_event(full_client)

        # Retrieve the alert id
        resp = full_client.get("/api/v1/alerts?hostname=ws-ack-test")
        alerts = resp.get_json()["alerts"]
        assert alerts, "Expected at least one alert from after-hours event"
        alert_id = alerts[0]["id"]

        # Acknowledge it
        patch_resp = full_client.patch(f"/api/v1/alerts/{alert_id}/ack")
        assert patch_resp.status_code == 200
        body = patch_resp.get_json()
        assert body["ok"] is True
        assert body["alert_id"] == alert_id

    def test_ack_marks_alert_as_acknowledged(self, full_client):
        """After ACK the alert should no longer appear in the open-alerts list."""
        _post_event(full_client)

        open_alerts = full_client.get("/api/v1/alerts?ack=false").get_json()["alerts"]
        assert open_alerts
        alert_id = open_alerts[0]["id"]

        full_client.patch(f"/api/v1/alerts/{alert_id}/ack")

        still_open = full_client.get("/api/v1/alerts?ack=false").get_json()["alerts"]
        open_ids = [a["id"] for a in still_open]
        assert alert_id not in open_ids

        acked = full_client.get("/api/v1/alerts?ack=true").get_json()["alerts"]
        acked_ids = [a["id"] for a in acked]
        assert alert_id in acked_ids

    def test_ack_nonexistent_alert_returns_404(self, full_client):
        """Acknowledging a non-existent alert id should return 404."""
        resp = full_client.patch("/api/v1/alerts/99999/ack")
        assert resp.status_code == 404

    def test_double_ack_returns_404(self, full_client):
        """Acknowledging an already-acknowledged alert returns 404."""
        _post_event(full_client)
        alerts = full_client.get("/api/v1/alerts").get_json()["alerts"]
        alert_id = alerts[0]["id"]

        full_client.patch(f"/api/v1/alerts/{alert_id}/ack")
        second = full_client.patch(f"/api/v1/alerts/{alert_id}/ack")
        assert second.status_code == 404
