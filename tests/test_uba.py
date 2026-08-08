"""
tests/test_uba.py – Tests for user behaviour analytics (UBA) features.
"""

from __future__ import annotations

import importlib
import json

import pytest


@pytest.fixture()
def uba_client(tmp_path, monkeypatch):
    monkeypatch.setenv("ITDN_DB_PATH", str(tmp_path / "uba.db"))
    monkeypatch.setenv("ITDN_API_KEY", "")
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "")

    import server.config as cfg
    importlib.reload(cfg)
    import server.database as database
    importlib.reload(database)
    import server.auth as auth_mod
    importlib.reload(auth_mod)
    import server.app as app_mod
    importlib.reload(app_mod)

    _app = app_mod.create_app()
    _app.config["TESTING"] = True
    with _app.test_client() as c:
        yield c


def _event(**kwargs):
    base = {
        "event_type": "connected",
        "device_id": "cafe:1234",
        "hostname": "uba-host",
        "serial": "UBA001",
        "manufacturer": "UBA Corp",
        "product": "UBADrive",
        "timestamp": "2024-06-15T10:00:00Z",
        "transfer_bytes": 0,
    }
    base.update(kwargs)
    return base


def _post(client, events):
    return client.post(
        "/api/v1/events",
        data=json.dumps({"events": events}),
        content_type="application/json",
    )


# ---------------------------------------------------------------------------
# user_baseline DB functions
# ---------------------------------------------------------------------------

def test_user_baseline_insert_and_retrieve(full_client):
    import server.database as database
    database.update_user_baseline("bob", "ws-1", "0781:5567")
    baseline = database.get_user_baseline("bob")
    assert len(baseline) == 1
    assert baseline[0]["username"] == "bob"
    assert baseline[0]["device_id"] == "0781:5567"
    assert baseline[0]["seen_count"] == 1


def test_user_baseline_increments_seen_count(full_client):
    import server.database as database
    database.update_user_baseline("alice", "ws-1", "cafe:beef")
    database.update_user_baseline("alice", "ws-1", "cafe:beef")
    baseline = database.get_user_baseline("alice")
    assert baseline[0]["seen_count"] == 2


def test_user_device_is_new_true_first_time(full_client):
    import server.database as database
    assert database.user_device_is_new("charlie", "ws-1", "new:device") is True


def test_user_device_is_new_false_after_baseline(full_client):
    import server.database as database
    database.update_user_baseline("dave", "ws-1", "known:dev")
    assert database.user_device_is_new("dave", "ws-1", "known:dev") is False


# ---------------------------------------------------------------------------
# UBA baseline endpoint
# ---------------------------------------------------------------------------

def test_uba_baseline_requires_username(uba_client):
    resp = uba_client.get("/api/v1/uba/baseline")
    assert resp.status_code == 400


def test_uba_baseline_empty_for_unknown_user(uba_client):
    resp = uba_client.get("/api/v1/uba/baseline?username=nobody")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["count"] == 0


def test_uba_baseline_populated_after_event(uba_client):
    _post(uba_client, [_event(user="eve", hostname="uba-host")])
    resp = uba_client.get("/api/v1/uba/baseline?username=eve")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["count"] == 1


# ---------------------------------------------------------------------------
# UBA rule: user_unknown_device
# ---------------------------------------------------------------------------

def test_rule_user_unknown_device_fires_on_new_device():
    import importlib
    import server.detection.rules as rules_mod
    importlib.reload(rules_mod)

    class _MockDB:
        def get_host_timezone(self, h): return None
        def device_is_new(self, h, d): return False
        def get_recent_events(self, h, **kw): return []
        def get_recent_events_by_device(self, d, **kw): return []
        def user_device_is_new(self, u, h, d): return True

    event = {
        "event_type": "connected",
        "device_id": "1234:abcd",
        "hostname": "ws-uba",
        "user": "mallory",
        "timestamp": "2024-06-15T10:00:00Z",
        "transfer_bytes": 0,
    }
    alerts = rules_mod.evaluate(event, _MockDB())
    assert any(a.rule_name == "user_unknown_device" for a in alerts)


def test_rule_user_unknown_device_no_fire_without_user():
    import importlib
    import server.detection.rules as rules_mod
    importlib.reload(rules_mod)

    class _MockDB:
        def get_host_timezone(self, h): return None
        def device_is_new(self, h, d): return False
        def get_recent_events(self, h, **kw): return []
        def get_recent_events_by_device(self, d, **kw): return []
        def user_device_is_new(self, u, h, d): return True

    event = {
        "event_type": "connected",
        "device_id": "1234:abcd",
        "hostname": "ws-uba",
        "timestamp": "2024-06-15T10:00:00Z",
        "transfer_bytes": 0,
    }
    alerts = rules_mod.evaluate(event, _MockDB())
    assert not any(a.rule_name == "user_unknown_device" for a in alerts)


def test_rule_user_unknown_device_no_fire_on_known_device():
    import importlib
    import server.detection.rules as rules_mod
    importlib.reload(rules_mod)

    class _MockDB:
        def get_host_timezone(self, h): return None
        def device_is_new(self, h, d): return False
        def get_recent_events(self, h, **kw): return []
        def get_recent_events_by_device(self, d, **kw): return []
        def user_device_is_new(self, u, h, d): return False  # device is known

    event = {
        "event_type": "connected",
        "device_id": "1234:abcd",
        "hostname": "ws-uba",
        "user": "alice",
        "timestamp": "2024-06-15T10:00:00Z",
        "transfer_bytes": 0,
    }
    alerts = rules_mod.evaluate(event, _MockDB())
    assert not any(a.rule_name == "user_unknown_device" for a in alerts)
