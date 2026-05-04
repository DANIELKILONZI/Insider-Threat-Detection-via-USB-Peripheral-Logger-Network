"""
tests/test_schema.py – Tests for Pydantic event schema validation.
"""

from __future__ import annotations

import json

import pytest


def _post(client, payload):
    return client.post(
        "/api/v1/events",
        data=json.dumps(payload),
        content_type="application/json",
    )


class TestSchemaValidation:
    def test_valid_event_accepted(self, full_client):
        payload = {
            "events": [
                {
                    "event_type": "connected",
                    "device_id": "1234:abcd",
                    "hostname": "ws-01",
                    "timestamp": "2024-01-15T14:00:00Z",
                    "transfer_bytes": 0,
                }
            ]
        }
        resp = _post(full_client, payload)
        assert resp.status_code == 200
        assert resp.get_json()["stored"] == 1

    def test_invalid_event_type_rejected(self, full_client):
        payload = {
            "events": [
                {
                    "event_type": "exploded",   # not a valid event_type
                    "device_id": "1234:abcd",
                    "hostname": "ws-01",
                }
            ]
        }
        resp = _post(full_client, payload)
        assert resp.status_code == 400

    def test_missing_device_id_rejected(self, full_client):
        payload = {
            "events": [
                {
                    "event_type": "connected",
                    # device_id missing
                    "hostname": "ws-01",
                }
            ]
        }
        resp = _post(full_client, payload)
        assert resp.status_code == 400

    def test_missing_hostname_rejected(self, full_client):
        payload = {
            "events": [
                {
                    "event_type": "connected",
                    "device_id": "1234:abcd",
                    # hostname missing
                }
            ]
        }
        resp = _post(full_client, payload)
        assert resp.status_code == 400

    def test_negative_transfer_bytes_rejected(self, full_client):
        payload = {
            "events": [
                {
                    "event_type": "connected",
                    "device_id": "1234:abcd",
                    "hostname": "ws-01",
                    "transfer_bytes": -1,   # must be ≥ 0
                }
            ]
        }
        resp = _post(full_client, payload)
        assert resp.status_code == 400

    def test_extra_fields_allowed(self, full_client):
        """model_config = extra='allow' – extra fields should not cause rejection."""
        payload = {
            "events": [
                {
                    "event_type": "connected",
                    "device_id": "cafe:babe",
                    "hostname": "ws-01",
                    "custom_field": "some_value",
                    "transfer_bytes": 0,
                }
            ]
        }
        resp = _post(full_client, payload)
        assert resp.status_code == 200

    def test_data_transfer_event_type_accepted(self, full_client):
        payload = {
            "events": [
                {
                    "event_type": "data_transfer",
                    "device_id": "1234:abcd",
                    "hostname": "ws-01",
                    "transfer_bytes": 1024,
                }
            ]
        }
        resp = _post(full_client, payload)
        assert resp.status_code == 200

    def test_empty_events_list_accepted(self, full_client):
        resp = _post(full_client, {"events": []})
        assert resp.status_code == 200
        assert resp.get_json()["stored"] == 0
