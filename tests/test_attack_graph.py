"""Tests for attack graph builder."""
from __future__ import annotations
from unittest.mock import MagicMock
from server.attack_graph import build_attack_graph, detect_exfil_pattern


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
