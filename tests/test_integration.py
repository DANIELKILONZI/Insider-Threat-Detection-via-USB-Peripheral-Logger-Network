"""
tests/test_integration.py – Full-stack integration tests using a real SQLite DB.

Unlike the unit tests in test_rules.py and test_alert_manager.py (which mock
``db``), these tests wire the real rules engine → real database → real alert
manager together so that cross-layer regressions are caught.

Each test creates an isolated database via the ``full_client`` fixture defined
in conftest.py.
"""

from __future__ import annotations

import json

import pytest


def _event(**kwargs) -> dict:
    defaults = {
        "event_type": "connected",
        "device_id": "cafe:babe",
        "hostname": "ws-integration",
        "serial": "SN-INT-01",
        "manufacturer": "Acme",
        "product": "Test Drive",
        "timestamp": "2024-01-15T14:00:00Z",
        "transfer_bytes": 0,
    }
    defaults.update(kwargs)
    return defaults


def _post(client, events: list) -> dict:
    resp = client.post(
        "/api/v1/events",
        data=json.dumps({"events": events}),
        content_type="application/json",
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()


# ---------------------------------------------------------------------------
# after_hours_device rule – end-to-end
# ---------------------------------------------------------------------------

class TestAfterHoursIntegration:
    def test_after_hours_event_creates_db_alert(self, full_client):
        """An after-hours event ingest must persist a HIGH alert in the DB."""
        _post(full_client, [_event(timestamp="2024-01-15T23:30:00Z")])

        resp = full_client.get("/api/v1/alerts?hostname=ws-integration")
        body = resp.get_json()
        rule_names = [a["rule_name"] for a in body["alerts"]]
        assert "after_hours_device" in rule_names

    def test_business_hours_event_no_after_hours_alert(self, full_client):
        """A daytime event must NOT produce an after_hours_device alert."""
        _post(full_client, [_event(timestamp="2024-01-15T10:00:00Z")])

        resp = full_client.get("/api/v1/alerts?hostname=ws-integration")
        body = resp.get_json()
        rule_names = [a["rule_name"] for a in body["alerts"]]
        assert "after_hours_device" not in rule_names


# ---------------------------------------------------------------------------
# unknown_device rule – end-to-end
# ---------------------------------------------------------------------------

class TestUnknownDeviceIntegration:
    def test_first_connect_triggers_unknown_device_alert(self, full_client):
        """First time a device appears it must trigger an unknown_device alert."""
        _post(full_client, [_event(device_id="dead:beef", hostname="ws-new")])

        resp = full_client.get("/api/v1/alerts?hostname=ws-new")
        body = resp.get_json()
        rule_names = [a["rule_name"] for a in body["alerts"]]
        assert "unknown_device" in rule_names

    def test_known_device_no_alert(self, full_client):
        """After the first event, the same device should not trigger unknown_device again."""
        _post(full_client, [_event(device_id="aaaa:1111", hostname="ws-known")])
        _post(full_client, [_event(device_id="aaaa:1111", hostname="ws-known")])

        resp = full_client.get("/api/v1/alerts?hostname=ws-known")
        body = resp.get_json()
        unknown_alerts = [a for a in body["alerts"] if a["rule_name"] == "unknown_device"]
        # Dedup window should suppress the second alert; at most one
        assert len(unknown_alerts) <= 1


# ---------------------------------------------------------------------------
# high_volume_transfer rule – end-to-end
# ---------------------------------------------------------------------------

class TestHighVolumeIntegration:
    def test_cumulative_transfer_exceeds_threshold_creates_critical_alert(self, full_client):
        """Posting events whose cumulative bytes exceed 1 GB must fire CRITICAL alert."""
        GB = 1024 ** 3
        events = [
            _event(transfer_bytes=int(0.6 * GB), hostname="ws-vol"),
            _event(transfer_bytes=int(0.6 * GB), hostname="ws-vol"),
        ]
        _post(full_client, events)

        resp = full_client.get("/api/v1/alerts?hostname=ws-vol")
        body = resp.get_json()
        vol_alerts = [a for a in body["alerts"] if a["rule_name"] == "high_volume_transfer"]
        assert vol_alerts, "Expected high_volume_transfer alert"
        assert vol_alerts[0]["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Alert acknowledgement – end-to-end
# ---------------------------------------------------------------------------

class TestAckIntegration:
    def test_ack_removes_alert_from_unacked_list(self, full_client):
        """ACKing an alert should mark it so filtering by ack=false excludes it."""
        _post(full_client, [_event(timestamp="2024-01-15T23:30:00Z", hostname="ws-ack")])

        # Get the alert id
        resp = full_client.get("/api/v1/alerts?hostname=ws-ack")
        alerts = resp.get_json()["alerts"]
        assert alerts, "Expected at least one alert"
        alert_id = alerts[0]["id"]

        # ACK it
        ack_resp = full_client.patch(f"/api/v1/alerts/{alert_id}/ack")
        assert ack_resp.status_code == 200
        assert ack_resp.get_json()["ok"] is True

        # Should now appear with ack=true but not with ack=false
        acked = full_client.get("/api/v1/alerts?hostname=ws-ack&ack=true").get_json()
        unacked = full_client.get("/api/v1/alerts?hostname=ws-ack&ack=false").get_json()
        assert any(a["id"] == alert_id for a in acked["alerts"])
        assert not any(a["id"] == alert_id for a in unacked["alerts"])


# ---------------------------------------------------------------------------
# Timeline endpoint – end-to-end
# ---------------------------------------------------------------------------

class TestTimelineIntegration:
    def test_timeline_returns_events_and_alerts(self, full_client):
        """The timeline endpoint must return both raw events and any fired alerts."""
        _post(full_client, [_event(timestamp="2024-01-15T23:00:00Z", hostname="ws-tl")])

        resp = full_client.get("/api/v1/timeline?hostname=ws-tl")
        assert resp.status_code == 200
        body = resp.get_json()
        assert "items" in body
        kinds = {item["_kind"] for item in body["items"]}
        assert "event" in kinds
        assert "alert" in kinds

    def test_timeline_device_id_filter(self, full_client):
        """Filtering the timeline by device_id should exclude other devices."""
        _post(full_client, [
            _event(device_id="aaaa:0001", hostname="ws-tl2"),
            _event(device_id="bbbb:0002", hostname="ws-tl2"),
        ])

        resp = full_client.get("/api/v1/timeline?hostname=ws-tl2&device_id=aaaa:0001")
        body = resp.get_json()
        for item in body["items"]:
            assert item["device_id"] == "aaaa:0001"

    def test_timeline_since_filter(self, full_client):
        """Items before the 'since' cutoff must not appear in the timeline."""
        # Post one early and one late event
        _post(full_client, [
            _event(hostname="ws-tl3", timestamp="2024-01-01T00:00:00Z"),
        ])
        _post(full_client, [
            _event(hostname="ws-tl3", timestamp="2024-06-01T00:00:00Z"),
        ])

        resp = full_client.get("/api/v1/timeline?hostname=ws-tl3&since=2024-03-01")
        body = resp.get_json()
        # All returned events should have ts >= 2024-03-01
        for item in body["items"]:
            assert item["ts"] >= "2024-03-01"

    def test_timeline_empty_host(self, full_client):
        """Timeline for a host with no events should return empty list."""
        resp = full_client.get("/api/v1/timeline?hostname=nonexistent-host")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["count"] == 0
        assert body["items"] == []


# ---------------------------------------------------------------------------
# Audit chain – end-to-end
# ---------------------------------------------------------------------------

class TestAuditChainIntegration:
    def test_audit_chain_length_matches_events(self, full_client):
        """Server-side audit chain must have one record per ingested event."""
        events = [_event(hostname="ws-chain", device_id=f"dead:{i:04x}") for i in range(5)]
        _post(full_client, events)

        resp = full_client.get("/api/v1/audit?hostname=ws-chain")
        body = resp.get_json()
        assert body["count"] == 5
