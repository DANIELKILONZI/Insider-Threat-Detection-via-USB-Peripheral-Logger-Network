"""
tests/test_rule_config.py – Tests for the runtime config endpoint and
the rule_config module.
"""

from __future__ import annotations

import importlib
import json

import pytest


class TestRuleConfigModule:
    @pytest.fixture(autouse=True)
    def reset_config(self):
        """Reset rule_config to defaults before each test (in addition to conftest autouse)."""
        import server.detection.rule_config as rc
        rc.reset_to_defaults()
        yield
        rc.reset_to_defaults()

    def test_get_config_returns_defaults(self):
        from server.detection.rule_config import get_config
        cfg = get_config()
        assert cfg["after_hours_start"] == 22
        assert cfg["after_hours_end"] == 6
        assert cfg["rapid_cycle_count"] == 5

    def test_update_valid_key(self):
        from server.detection.rule_config import get_config, update_config
        new_cfg, errors = update_config({"rapid_cycle_count": 3})
        assert not errors
        assert new_cfg["rapid_cycle_count"] == 3
        assert get_config()["rapid_cycle_count"] == 3

    def test_update_unknown_key_returns_error(self):
        from server.detection.rule_config import update_config
        _, errors = update_config({"nonexistent_key": 10})
        assert errors
        assert any("Unknown" in e for e in errors)

    def test_update_non_integer_returns_error(self):
        from server.detection.rule_config import update_config
        _, errors = update_config({"rapid_cycle_count": "five"})
        assert errors

    def test_update_bool_rejected(self):
        """Booleans are ints in Python; ensure they are rejected."""
        from server.detection.rule_config import update_config
        _, errors = update_config({"rapid_cycle_count": True})
        assert errors

    def test_update_hour_out_of_range_returns_error(self):
        from server.detection.rule_config import update_config
        _, errors = update_config({"after_hours_start": 25})
        assert errors

    def test_update_partial_applies_valid_rejects_invalid(self):
        from server.detection.rule_config import get_config, update_config
        new_cfg, errors = update_config({"rapid_cycle_count": 7, "bad_key": 999})
        assert errors  # bad_key rejected
        assert new_cfg["rapid_cycle_count"] == 7  # valid key applied


class TestConfigEndpoint:
    def test_get_config(self, full_client):
        resp = full_client.get("/api/v1/config")
        assert resp.status_code == 200
        body = resp.get_json()
        assert "config" in body
        assert "rapid_cycle_count" in body["config"]

    def test_patch_valid_config(self, full_client):
        resp = full_client.patch(
            "/api/v1/config",
            data=json.dumps({"rapid_cycle_count": 10}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["config"]["rapid_cycle_count"] == 10

    def test_patch_invalid_key_returns_207(self, full_client):
        resp = full_client.patch(
            "/api/v1/config",
            data=json.dumps({"invalid_key": 5}),
            content_type="application/json",
        )
        assert resp.status_code == 207  # partial success
        body = resp.get_json()
        assert body["errors"]

    def test_patch_empty_body_returns_400(self, full_client):
        resp = full_client.patch(
            "/api/v1/config",
            data="not-json",
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_patch_config_affects_rule_evaluation(self, full_client):
        """
        Lower after_hours_start to 8 so a 14:00 event (normally business hours)
        becomes after-hours and triggers an alert.
        """
        full_client.patch(
            "/api/v1/config",
            data=json.dumps({"after_hours_start": 8}),
            content_type="application/json",
        )
        event = {
            "event_type": "connected",
            "device_id": "aaaa:bbbb",
            "hostname": "ws-cfg-test",
            "timestamp": "2024-01-15T14:00:00Z",  # 14:00 – within new after-hours window
            "transfer_bytes": 0,
        }
        full_client.post(
            "/api/v1/events",
            data=json.dumps({"events": [event]}),
            content_type="application/json",
        )
        alerts_resp = full_client.get("/api/v1/alerts?hostname=ws-cfg-test")
        alerts = alerts_resp.get_json()["alerts"]
        rule_names = [a["rule_name"] for a in alerts]
        assert "after_hours_device" in rule_names
