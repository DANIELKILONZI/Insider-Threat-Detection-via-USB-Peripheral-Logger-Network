"""Tests for NormalizedEvent schema."""
from datetime import datetime, timezone

import pytest

from shared.schema import NormalizedEvent


def test_event_creates_hash():
    ev = NormalizedEvent(
        agent_id="a1",
        actor="user",
        device_id="1234:5678",
        action="connect",
        source_type="usb",
    )
    assert ev.event_hash
    assert len(ev.event_hash) == 64


def test_hash_is_deterministic():
    ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    ev1 = NormalizedEvent(
        event_id="fixed-id",
        agent_id="a1",
        actor="user",
        device_id="1234:5678",
        action="connect",
        source_type="usb",
        timestamp=ts,
    )
    ev2 = NormalizedEvent(
        event_id="fixed-id",
        agent_id="a1",
        actor="user",
        device_id="1234:5678",
        action="connect",
        source_type="usb",
        timestamp=ts,
    )
    assert ev1.event_hash == ev2.event_hash


def test_different_events_have_different_hashes():
    ev1 = NormalizedEvent(
        agent_id="a1", actor="u", device_id="1111:1111", action="connect", source_type="usb"
    )
    ev2 = NormalizedEvent(
        agent_id="a1", actor="u", device_id="2222:2222", action="connect", source_type="usb"
    )
    assert ev1.event_hash != ev2.event_hash


def test_prev_hash_changes_event_hash():
    ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    ev1 = NormalizedEvent(
        event_id="x",
        agent_id="a",
        actor="u",
        device_id="1:1",
        action="connect",
        source_type="usb",
        timestamp=ts,
        prev_hash=None,
    )
    ev2 = NormalizedEvent(
        event_id="x",
        agent_id="a",
        actor="u",
        device_id="1:1",
        action="connect",
        source_type="usb",
        timestamp=ts,
        prev_hash="abc123",
    )
    assert ev1.event_hash != ev2.event_hash


def test_confidence_bounds():
    with pytest.raises(Exception):
        NormalizedEvent(
            agent_id="a",
            actor="u",
            device_id="1:1",
            action="connect",
            source_type="usb",
            confidence=1.5,
        )


def test_raw_defaults_to_empty_dict():
    ev = NormalizedEvent(
        agent_id="a", actor="u", device_id="1:1", action="connect", source_type="usb"
    )
    assert ev.raw == {}
