"""
tests/test_api.py – Integration tests for the Flask REST API.

Uses Flask's test client so no real network or database files are needed
(the DB is redirected to a temp directory via environment variables).
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest


# ---------------------------------------------------------------------------
# Fixture: isolated app with a temp DB
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ITDN_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "")  # disable Splunk forwarding

    import importlib
    import server.config as cfg
    importlib.reload(cfg)
    import server.database as database
    importlib.reload(database)
    import server.app as app_mod
    importlib.reload(app_mod)

    _app = app_mod.create_app()
    _app.config["TESTING"] = True
    with _app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# /api/v1/health
# ---------------------------------------------------------------------------

def test_health(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


# ---------------------------------------------------------------------------
# POST /api/v1/events
# ---------------------------------------------------------------------------

def _make_event(**kwargs):
    defaults = {
        "event_type": "connected",
        "device_id": "1234:abcd",
        "hostname": "ws-test",
        "serial": "SN001",
        "manufacturer": "Acme",
        "product": "Flash",
        "timestamp": "2024-01-15T14:00:00Z",
        "transfer_bytes": 0,
    }
    defaults.update(kwargs)
    return defaults


def test_ingest_single_event(client):
    payload = {"events": [_make_event()]}
    resp = client.post(
        "/api/v1/events",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    assert body["stored"] == 1


def test_ingest_multiple_events(client):
    events = [_make_event(device_id=f"cafe:{i:04x}") for i in range(5)]
    resp = client.post(
        "/api/v1/events",
        data=json.dumps({"events": events}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    assert resp.get_json()["stored"] == 5


def test_ingest_missing_payload(client):
    resp = client.post("/api/v1/events", data="{}", content_type="application/json")
    assert resp.status_code == 400


def test_ingest_wrong_type(client):
    resp = client.post(
        "/api/v1/events",
        data=json.dumps({"events": "not-a-list"}),
        content_type="application/json",
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GET /api/v1/alerts
# ---------------------------------------------------------------------------

def test_alerts_empty(client):
    resp = client.get("/api/v1/alerts")
    assert resp.status_code == 200
    body = resp.get_json()
    assert "alerts" in body
    assert body["count"] == 0


def test_alerts_after_hours_event_creates_alert(client):
    # Post an after-hours event – should trigger alert
    event = _make_event(
        hostname="ws-alert-test",
        timestamp="2024-01-15T23:30:00Z",  # 23:30 – after hours
    )
    client.post(
        "/api/v1/events",
        data=json.dumps({"events": [event]}),
        content_type="application/json",
    )
    resp = client.get("/api/v1/alerts?hostname=ws-alert-test")
    body = resp.get_json()
    rule_names = [a["rule_name"] for a in body["alerts"]]
    assert "after_hours_device" in rule_names


# ---------------------------------------------------------------------------
# GET /api/v1/audit
# ---------------------------------------------------------------------------

def test_audit_requires_hostname(client):
    resp = client.get("/api/v1/audit")
    assert resp.status_code == 400


def test_audit_returns_chain(client):
    events = [_make_event(hostname="ws-audit", device_id=f"dead:{i:04x}") for i in range(3)]
    client.post(
        "/api/v1/events",
        data=json.dumps({"events": events}),
        content_type="application/json",
    )
    resp = client.get("/api/v1/audit?hostname=ws-audit")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["count"] == 3
    assert body["hostname"] == "ws-audit"
