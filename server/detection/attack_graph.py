"""
server/detection/attack_graph.py – Attack graph builder for ITDN incident visualization.
"""

from __future__ import annotations

import logging
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

    A device is reported only when *that same device* has both a connect and a
    disconnect action.  The previous implementation tested the graph globally —
    any device connected and any device disconnected — which is true on almost
    every workstation and so fired on nearly every host.

    Note this deliberately makes no claim about how *quickly* a device cycled:
    the graph carries no timestamps.  Time-windowed rapid-cycle detection is
    :func:`server.detection.rules.rule_rapid_cycle`, which has the event
    timestamps needed to judge it.
    """
    findings: List[str] = []
    edges = graph.get("edges", [])

    # device node id -> the action relations observed on that device
    actions_by_device: Dict[str, set] = {}
    for edge in edges:
        source = edge.get("from", "")
        if source.startswith("device:"):
            actions_by_device.setdefault(source, set()).add(edge.get("relation", ""))

    cycled = sorted(
        node_id.split(":", 1)[1]
        for node_id, actions in actions_by_device.items()
        if "connected" in actions and "disconnected" in actions
    )

    if cycled:
        findings.append(
            f"Device connect/disconnect cycling on {len(cycled)} device(s): "
            + ", ".join(cycled)
        )

    return findings
