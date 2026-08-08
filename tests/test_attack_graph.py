"""Tests for attack graph builder."""
from __future__ import annotations
from unittest.mock import MagicMock
from server.detection.attack_graph import build_attack_graph, detect_exfil_pattern


def _make_mock_db(events=None, alerts=None):
    mock = MagicMock()
    timeline = []
    for e in (events or []):
        timeline.append({"_kind": "event", **e})
    for a in (alerts or []):
        timeline.append({"_kind": "alert", **a})
    mock.get_timeline.return_value = timeline
    return mock


def test_build_graph_empty():
    mock_db = _make_mock_db()
    graph = build_attack_graph("host1", mock_db)
    assert "nodes" in graph
    assert "edges" in graph
    node_types = {n["type"] for n in graph["nodes"]}
    assert "machine" in node_types


def test_build_graph_with_events():
    events = [
        {"event_type": "connected", "device_id": "1234:5678", "hostname": "host1"},
        {"event_type": "disconnected", "device_id": "1234:5678", "hostname": "host1"},
    ]
    mock_db = _make_mock_db(events=events)
    graph = build_attack_graph("host1", mock_db)
    node_ids = {n["id"] for n in graph["nodes"]}
    assert "device:1234:5678" in node_ids


def test_detect_exfil_pattern_empty():
    graph = {"nodes": [], "edges": []}
    findings = detect_exfil_pattern(graph)
    assert isinstance(findings, list)


# ── Exfil pattern detection ──────────────────────────────────────────────────
# The finding must be per-device.  An earlier version tested the graph globally
# (any device connected AND any device disconnected), which is true on almost
# any workstation and so fired on nearly every host.

def _graph_for(events):
    return build_attack_graph("host1", _make_mock_db(events=events))


def test_no_finding_when_a_single_device_only_connects():
    graph = _graph_for([
        {"event_type": "connected", "device_id": "1111:1111", "hostname": "host1"},
    ])
    assert detect_exfil_pattern(graph) == []


def test_no_finding_when_different_devices_connect_and_disconnect():
    """The regression: two distinct devices, neither of which cycled."""
    graph = _graph_for([
        {"event_type": "connected", "device_id": "1111:1111", "hostname": "host1"},
        {"event_type": "disconnected", "device_id": "2222:2222", "hostname": "host1"},
    ])
    assert detect_exfil_pattern(graph) == []


def test_finding_when_one_device_cycles():
    graph = _graph_for([
        {"event_type": "connected", "device_id": "1234:5678", "hostname": "host1"},
        {"event_type": "disconnected", "device_id": "1234:5678", "hostname": "host1"},
    ])
    findings = detect_exfil_pattern(graph)
    assert len(findings) == 1
    assert "1234:5678" in findings[0]
    assert "1 device(s)" in findings[0]


def test_finding_names_every_cycled_device_only():
    graph = _graph_for([
        {"event_type": "connected", "device_id": "aaaa:aaaa", "hostname": "host1"},
        {"event_type": "disconnected", "device_id": "aaaa:aaaa", "hostname": "host1"},
        {"event_type": "connected", "device_id": "bbbb:bbbb", "hostname": "host1"},
        {"event_type": "disconnected", "device_id": "bbbb:bbbb", "hostname": "host1"},
        {"event_type": "connected", "device_id": "cccc:cccc", "hostname": "host1"},
    ])
    findings = detect_exfil_pattern(graph)
    assert len(findings) == 1
    assert "2 device(s)" in findings[0]
    assert "aaaa:aaaa" in findings[0] and "bbbb:bbbb" in findings[0]
    assert "cccc:cccc" not in findings[0]  # connected only, never cycled


def test_detect_handles_graph_without_edges_key():
    assert detect_exfil_pattern({"nodes": []}) == []
