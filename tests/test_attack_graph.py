"""Tests for the attack graph builder."""
from datetime import datetime, timezone, timedelta

import pytest

pytest.importorskip("networkx", reason="networkx required")

from server.detection.attack_graph import AttackGraphBuilder
from shared.schema import NormalizedEvent


def _ev(agent_id, device_id, action, source_type="usb", actor="user", hour=10, confidence=1.0):
    return NormalizedEvent(
        agent_id=agent_id,
        actor=actor,
        device_id=device_id,
        action=action,
        source_type=source_type,
        confidence=confidence,
        timestamp=datetime(2024, 1, 1, hour, 0, 0, tzinfo=timezone.utc),
    )


def test_add_event_builds_graph():
    builder = AttackGraphBuilder()
    ev = _ev("a1", "0781:5567", "connect")
    builder.add_event(ev)
    G = builder.get_graph()
    assert G.has_node("agent:a1")
    assert G.has_node("device:0781:5567")


def test_exfil_pattern_detected():
    builder = AttackGraphBuilder()
    # Mass storage (0781 = SanDisk), off-hours (2am)
    ev = _ev("a1", "0781:5567", "connect", hour=2)
    builder.add_event(ev)
    patterns = builder.detect_patterns()
    assert any(p["pattern"] == "exfil_pattern" for p in patterns)


def test_enumeration_pattern_detected():
    builder = AttackGraphBuilder()
    base_ts = datetime(2024, 1, 1, 14, 0, 0, tzinfo=timezone.utc)
    for i in range(3):
        ev = NormalizedEvent(
            agent_id="a2",
            actor="scanner",
            device_id=f"cafe:{i:04x}",
            action="connect",
            source_type="usb",
            timestamp=base_ts + timedelta(seconds=i * 30),
        )
        builder.add_event(ev)
    patterns = builder.detect_patterns()
    assert any(p["pattern"] == "enumeration_pattern" for p in patterns)


def test_data_theft_pattern_detected():
    builder = AttackGraphBuilder()
    ev = _ev("a3", "9999:8888", "data_transfer", confidence=0.7)
    builder.add_event(ev)
    patterns = builder.detect_patterns()
    assert any(p["pattern"] == "data_theft_pattern" for p in patterns)


def test_clear_resets_graph():
    builder = AttackGraphBuilder()
    builder.add_event(_ev("a1", "1:1", "connect"))
    builder.clear()
    assert builder.get_graph().number_of_nodes() == 0
    assert builder.detect_patterns() == []


def test_no_patterns_for_normal_events():
    builder = AttackGraphBuilder()
    # Known, daytime, non-mass-storage, non-data-transfer
    ev = _ev("a4", "abcd:1234", "connect", hour=10, confidence=1.0)
    builder.add_event(ev)
    patterns = builder.detect_patterns()
    assert not any(p["pattern"] == "exfil_pattern" for p in patterns)
