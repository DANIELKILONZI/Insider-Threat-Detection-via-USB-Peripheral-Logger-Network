"""
tests/test_auth.py – Tests for API key authentication and rate limiting.
"""

from __future__ import annotations

import importlib
import json
import time

import pytest


def _make_event(**kwargs):
    defaults = {
        "event_type": "connected",
        "device_id": "aaaa:bbbb",
        "hostname": "ws-auth-test",
        "serial": "",
        "manufacturer": "",
        "product": "",
        "timestamp": "2024-01-15T14:00:00Z",
        "transfer_bytes": 0,
    }
    defaults.update(kwargs)
    return defaults


def _post_event(client, headers=None):
    payload = {"events": [_make_event()]}
    return client.post(
        "/api/v1/events",
        data=json.dumps(payload),
        content_type="application/json",
        headers=headers or {},
    )


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class TestApiKeyAuth:
    @pytest.fixture()
    def secured_client(self, tmp_path, monkeypatch):
        """Client with API key authentication enabled."""
        monkeypatch.setenv("ITDN_DB_PATH", str(tmp_path / "sec.db"))
        monkeypatch.setenv("SPLUNK_HEC_TOKEN", "")
        monkeypatch.setenv("ITDN_API_KEY", "supersecret")

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

    def test_no_key_returns_401(self, secured_client):
        resp = _post_event(secured_client)
        assert resp.status_code == 401

    def test_wrong_key_returns_401(self, secured_client):
        resp = _post_event(secured_client, headers={"Authorization": "Bearer wrongkey"})
        assert resp.status_code == 401

    def test_correct_key_returns_200(self, secured_client):
        resp = _post_event(secured_client, headers={"Authorization": "Bearer supersecret"})
        assert resp.status_code == 200

    def test_health_bypasses_auth(self, secured_client):
        """Health endpoint should not require auth."""
        resp = secured_client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_alerts_bypasses_auth(self, secured_client):
        """GET /api/v1/alerts does not require auth (read-only)."""
        resp = secured_client.get("/api/v1/alerts")
        assert resp.status_code == 200

    def test_no_auth_when_key_not_configured(self, full_client):
        """When ITDN_API_KEY is empty, any request is accepted."""
        resp = _post_event(full_client)  # no Authorization header
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimit:
    @pytest.fixture()
    def tight_rate_client(self, tmp_path, monkeypatch):
        """Client with a very tight rate limit (3 req / 60 s) for testing."""
        monkeypatch.setenv("ITDN_DB_PATH", str(tmp_path / "rate.db"))
        monkeypatch.setenv("SPLUNK_HEC_TOKEN", "")
        monkeypatch.setenv("ITDN_API_KEY", "")
        monkeypatch.setenv("ITDN_RATE_LIMIT_MAX", "3")
        monkeypatch.setenv("ITDN_RATE_LIMIT_WINDOW_SECS", "60")

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

    def test_within_limit_succeeds(self, tight_rate_client):
        for _ in range(3):
            resp = _post_event(tight_rate_client)
            assert resp.status_code == 200

    def test_exceeding_limit_returns_429(self, tight_rate_client):
        for _ in range(3):
            _post_event(tight_rate_client)
        resp = _post_event(tight_rate_client)
        assert resp.status_code == 429

    def test_health_not_rate_limited(self, tight_rate_client):
        """Health endpoint is not wrapped by the rate limiter."""
        for _ in range(10):
            resp = tight_rate_client.get("/api/v1/health")
            assert resp.status_code == 200
