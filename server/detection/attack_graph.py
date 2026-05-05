"""Attack graph builder — directed graph of machine→user→device→action.

Detects insider-threat patterns:
  - exfil_pattern: new_device + mass_storage + off_hours
  - enumeration_pattern: multiple_devices + rapid_succession
  - data_theft_pattern: unknown_device + data_transfer
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from shared.schema import NormalizedEvent

logger = logging.getLogger(__name__)

try:
    import networkx as nx  # type: ignore

    _NX_AVAILABLE = True
except ImportError:
    _NX_AVAILABLE = False

MASS_STORAGE_PIDS = {"0781", "0951", "058f", "1307", "0bda"}


class AttackGraphBuilder:
    def __init__(self) -> None:
        if not _NX_AVAILABLE:
            raise ImportError(
                "networkx is required for attack graph analysis. "
                "Install with: pip install networkx"
            )
        self._graph: "nx.DiGraph" = nx.DiGraph()
        self._events: List[NormalizedEvent] = []

    def add_event(self, event: NormalizedEvent) -> None:
        """Add event to the graph: agent → actor → device_id → action."""
        self._events.append(event)
        agent_node = f"agent:{event.agent_id}"
        actor_node = f"actor:{event.actor}"
        device_node = f"device:{event.device_id}"
        action_node = f"action:{event.action}"

        for src, dst, label in [
            (agent_node, actor_node, "uses"),
            (actor_node, device_node, "accessed"),
            (device_node, action_node, "performed"),
        ]:
            if not self._graph.has_edge(src, dst):
                self._graph.add_edge(src, dst, label=label, events=[])
            self._graph[src][dst]["events"].append(event.event_id)

    def _is_mass_storage(self, device_id: str) -> bool:
        parts = device_id.lower().split(":")
        if len(parts) >= 2:
            return parts[0] in MASS_STORAGE_PIDS or parts[1] in MASS_STORAGE_PIDS
        return False

    def _is_off_hours(self, ts: datetime) -> bool:
        return ts.hour >= 18 or ts.hour < 8

    def detect_patterns(self) -> List[dict]:
        """Scan accumulated events and return detected threat patterns."""
        patterns: List[dict] = []

        # Group by agent + actor
        by_actor: Dict[str, List[NormalizedEvent]] = {}
        for ev in self._events:
            key = f"{ev.agent_id}:{ev.actor}"
            by_actor.setdefault(key, []).append(ev)

        for key, evs in by_actor.items():
            devices = {e.device_id for e in evs}
            agent_id, actor = key.split(":", 1)

            # exfil_pattern: new-ish device + mass storage action + off-hours
            for ev in evs:
                if (
                    self._is_mass_storage(ev.device_id)
                    and self._is_off_hours(ev.timestamp)
                    and ev.action in ("connect", "data_transfer")
                ):
                    patterns.append(
                        {
                            "pattern": "exfil_pattern",
                            "agent_id": agent_id,
                            "actor": actor,
                            "device_id": ev.device_id,
                            "event_id": ev.event_id,
                            "confidence": 0.85,
                            "description": "Mass storage device connected off-hours",
                        }
                    )

            # enumeration_pattern: 3+ distinct devices within 5 minutes by same actor
            if len(devices) >= 3:
                sorted_evs = sorted(evs, key=lambda e: e.timestamp)
                for i in range(len(sorted_evs) - 2):
                    window = sorted_evs[i : i + 3]
                    span = (window[-1].timestamp - window[0].timestamp).total_seconds()
                    if span <= 300:  # 5 min
                        patterns.append(
                            {
                                "pattern": "enumeration_pattern",
                                "agent_id": agent_id,
                                "actor": actor,
                                "devices": list({e.device_id for e in window}),
                                "confidence": 0.75,
                                "description": "3+ devices accessed within 5 minutes",
                            }
                        )
                        break

            # data_theft_pattern: data_transfer on unknown/first-seen device
            for ev in evs:
                if ev.action == "data_transfer" and ev.confidence < 0.9:
                    patterns.append(
                        {
                            "pattern": "data_theft_pattern",
                            "agent_id": agent_id,
                            "actor": actor,
                            "device_id": ev.device_id,
                            "event_id": ev.event_id,
                            "confidence": 0.80,
                            "description": "Data transfer on low-confidence device",
                        }
                    )

        return patterns

    def get_graph(self) -> "nx.DiGraph":
        return self._graph

    def clear(self) -> None:
        self._graph = nx.DiGraph()
        self._events.clear()
