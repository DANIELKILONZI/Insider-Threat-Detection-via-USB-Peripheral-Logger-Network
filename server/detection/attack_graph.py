"""
server/detection/attack_graph.py – Attack graph builder for ITDN incident visualization.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def build_attack_graph(hostname: str, db: Any) -> Dict[str, Any]:
    """
    Build a JSON-serializable attack graph for hostname from timeline data.

    Returns:
        {"nodes": [...], "edges": [...]}
    """
    timeline = db.get_timeline(hostname=hostname, limit=500)

    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, str]] = []

    # Machine node
    machine_id = f"machine:{hostname}"
    nodes[machine_id] = {"id": machine_id, "type": "machine", "label": hostname}

    for item in timeline:
        kind = item.get("_kind")
        device_id = item.get("device_id", "")
        event_type = item.get("event_type", "")

        if kind == "event" and device_id:
            device_node_id = f"device:{device_id}"
            if device_node_id not in nodes:
                nodes[device_node_id] = {
                    "id": device_node_id,
                    "type": "device",
                    "label": device_id,
                }
            # machine → device edge
            edge = {"from": machine_id, "to": device_node_id, "relation": "connected"}
            if edge not in edges:
                edges.append(edge)

            # Action node
            if event_type:
                action_id = f"action:{device_id}:{event_type}"
                if action_id not in nodes:
                    nodes[action_id] = {
                        "id": action_id,
                        "type": "action",
                        "label": event_type,
                    }
                action_edge = {"from": device_node_id, "to": action_id, "relation": event_type}
                if action_edge not in edges:
                    edges.append(action_edge)

    return {"nodes": list(nodes.values()), "edges": edges}


def detect_exfil_pattern(graph: Dict[str, Any]) -> List[str]:
    """
    Detect potential exfiltration patterns in the attack graph.

    Returns list of human-readable findings.
    """
    findings: List[str] = []
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    device_ids = {
        n["id"].split(":", 1)[1]
        for n in nodes
        if n.get("type") == "device"
    }

    action_labels = {
        n.get("label", "")
        for n in nodes
        if n.get("type") == "action"
    }

    has_connected = "connected" in action_labels
    has_disconnected = "disconnected" in action_labels

    if device_ids and has_connected and has_disconnected:
        findings.append(
            f"Rapid device cycling detected: {len(device_ids)} device(s) "
            "connected and disconnected."
        )

    return findings
