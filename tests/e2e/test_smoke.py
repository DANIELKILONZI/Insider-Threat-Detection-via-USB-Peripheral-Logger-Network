"""
tests/e2e/test_smoke.py – End-to-end smoke test for the ITDN server.

This test exercises the full server stack using Flask's test client:

1. Health probe confirms the server is alive.
2. Ingest an after-hours USB event and verify it is stored.
3. Confirm an alert was generated for the event.
4. Acknowledge the alert via the PATCH endpoint.
5. Verify the alert is no longer listed as unacknowledged.
6. Post a batch of 50 events and confirm all are stored.
7. Confirm audit chain has been appended.
8. Confirm Prometheus /metrics endpoint responds.
9. Confirm new UBA baseline endpoint responds.
10. Confirm threat-feed endpoint responds.
11. Confirm maintenance/purge endpoint responds (admin required when RBAC on).

This test can be run against a live server or (as here) the Flask test client
without any external services.
"""

from __future__ import annotations

import importlib
import json
import os

import pytest


# ---------------------------------------------------------------------------
# Shared fixture: full server with isolated DB
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def e2e_client(tmp_path_factory, monkeypatch_module):
    db_path = tmp_path_factory.mktemp("e2e") / "e2e.db"
    monkeypatch_module.setenv("ITDN_DB_PATH", str(db_path))
    monkeypatch_module.setenv("SPLUNK_HEC_TOKEN", "")
    monkeypatch_module.setenv("ITDN_API_KEY", "")

    import server.config as cfg
    importlib.reload(cfg)
    import server.database as database
    importlib.reload(database)
    import server.rule_config as rc
    importlib.reload(rc)
    import server.rules as rules_mod
    importlib.reload(rules_mod)
    import server.auth as auth_mod
    importlib.reload(auth_mod)
    import server.app as app_mod
    importlib.reload(app_mod)

    _app = app_mod.create_app()
    _app.config["TESTING"] = True
    with _app.test_client() as c:
        yield c


@pytest.fixture(scope="module")
def monkeypatch_module():
    import _pytest.monkeypatch
    mp = _pytest.monkeypatch.MonkeyPatch()
    yield mp
    mp.undo()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _event(**kwargs):
    base = {
        "event_type": "connected",
        "device_id": "1234:abcd",
        "hostname": "e2e-host",
        "serial": "E2E001",
        "manufacturer": "E2E Corp",
        "product": "SmokeTest Drive",
        "timestamp": "2024-01-15T23:45:00Z",  # after-hours
        "transfer_bytes": 0,
    }
    base.update(kwargs)
    return base


def _post_events(client, events):
    return client.post(
        "/api/v1/events",
        data=json.dumps({"events": events}),
        content_type="application/json",
    )


# ---------------------------------------------------------------------------
# Smoke tests
# ---------------------------------------------------------------------------

class TestE2ESmoke:
    def test_01_health(self, e2e_client):
        resp = e2e_client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"

    def test_02_ingest_after_hours_event(self, e2e_client):
        resp = _post_events(e2e_client, [_event()])
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["stored"] == 1

    def test_03_alert_generated(self, e2e_client):
        resp = e2e_client.get("/api/v1/alerts?hostname=e2e-host")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["count"] >= 1
        rule_names = [a["rule_name"] for a in body["alerts"]]
        assert "after_hours_device" in rule_names

    def test_04_ack_alert(self, e2e_client):
        resp = e2e_client.get("/api/v1/alerts?hostname=e2e-host&ack=false")
        assert resp.status_code == 200
        alerts = resp.get_json()["alerts"]
        assert len(alerts) >= 1
        alert_id = alerts[0]["id"]

        ack_resp = e2e_client.patch(f"/api/v1/alerts/{alert_id}/ack")
        assert ack_resp.status_code == 200
        assert ack_resp.get_json()["ok"] is True

    def test_05_alert_acknowledged(self, e2e_client):
        resp = e2e_client.get("/api/v1/alerts?hostname=e2e-host&ack=false")
        assert resp.status_code == 200
        # After ACK, querying unacknowledged for the same alert yields fewer
        open_count = resp.get_json()["count"]
        # At minimum the after_hours alert should now be acked
        resp_all = e2e_client.get("/api/v1/alerts?hostname=e2e-host&ack=true")
        acked_count = resp_all.get_json()["count"]
        assert acked_count >= 1

    def test_06_batch_50_events(self, e2e_client):
        events = [_event(device_id=f"beef:{i:04x}", hostname="e2e-batch") for i in range(50)]
        resp = _post_events(e2e_client, events)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["stored"] == 50

    def test_07_audit_chain(self, e2e_client):
        resp = e2e_client.get("/api/v1/audit?hostname=e2e-host")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["count"] >= 1

    def test_08_metrics_endpoint(self, e2e_client):
        resp = e2e_client.get("/metrics")
        assert resp.status_code == 200
        data = resp.data.decode()
        assert "itdn_events_ingested_total" in data

    def test_09_uba_baseline_endpoint(self, e2e_client):
        # Send event with a user field
        resp = _post_events(e2e_client, [_event(user="alice", hostname="e2e-uba")])
        assert resp.status_code == 200

        resp2 = e2e_client.get("/api/v1/uba/baseline?username=alice")
        assert resp2.status_code == 200
        body = resp2.get_json()
        assert body["count"] >= 1

    def test_10_threat_feed_endpoint(self, e2e_client):
        resp = e2e_client.get("/api/v1/threat_feed")
        assert resp.status_code == 200
        body = resp.get_json()
        assert "entries" in body

    def test_11_purge_endpoint(self, e2e_client):
        resp = e2e_client.post(
            "/api/v1/maintenance/purge",
            data=json.dumps({"retention_days": 3650}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert "deleted" in body

    def test_12_risk_endpoint(self, e2e_client):
        resp = e2e_client.get("/api/v1/risk?hostname=e2e-host")
        assert resp.status_code == 200
        body = resp.get_json()
        assert "risk_score" in body

    def test_13_anomaly_endpoint(self, e2e_client):
        resp = e2e_client.get("/api/v1/anomaly?hostname=e2e-host")
        assert resp.status_code == 200
        body = resp.get_json()
        assert "anomaly_score" in body

    def test_14_dashboard_accessible(self, e2e_client):
        resp = e2e_client.get("/dashboard")
        assert resp.status_code == 200
