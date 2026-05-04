"""Tests for normalized event schema."""
from __future__ import annotations
from server.normalized_event import NormalizedEvent, normalize_event


def test_normalize_usb_connect():
    evt = {
        "event_type": "connected",
        "device_id": "1234:5678",
        "hostname": "myhost",
        "timestamp": "2024-01-01T10:00:00Z",
    }
    n = normalize_event(evt)
    assert isinstance(n, NormalizedEvent)
    assert n.actor == "myhost"
    assert n.action == "connected"
    assert n.source_type == "usb"
    assert n.device_id == "1234:5678"


def test_normalize_bluetooth():
    evt = {
        "event_type": "connected",
        "device_id": "aa:bb:cc",
        "hostname": "bthost",
        "source_type": "bluetooth",
        "timestamp": "2024-01-01T10:00:00Z",
    }
    n = normalize_event(evt)
    assert n.source_type == "bluetooth"


def test_normalize_confidence_default():
    n = normalize_event({"event_type": "disconnected", "device_id": "x", "hostname": "h", "timestamp": "2024-01-01T00:00:00Z"})
    assert n.confidence == 1.0
